//! The catalogue reader: a strict subset of TOML, and every deviation an error.
//!
//! What it accepts, and nothing else:
//!
//! ```toml
//! # a comment
//! [menu]                       # a table header sets the prefix for the keys that follow
//! open = "Open elasticdms"     # -> key `menu.open`
//! folder.finder = "…"          # a dotted key -> `menu.folder.finder`
//! body = """
//! several lines
//! """
//! ```
//!
//! Bare keys only (`A-Za-z0-9_-`), basic strings only (`"…"` and `"""…"""`), escapes only
//! `\" \\ \n \r \t \uXXXX`. No arrays, no numbers, no dates, no inline tables, no literal strings,
//! no array-of-tables, no key defined twice.
//!
//! **Why a reader of our own and not the `toml` crate:** the catalogues are our own files in our
//! own repository; everything the general parser can read beyond this subset must not stand in a
//! catalogue anyway. The subset is the whole point — a catalogue is a list of sentences, and
//! anything that is not a sentence is a mistake, not a feature. The crate header states the cost
//! side. That the files are nevertheless real TOML is checked from outside, with a second
//! implementation (`scripts/check-catalogs.py`).
//!
//! Every error names the line. A catalogue that does not read is not a warning and not a fallback
//! but the end of the read: whoever ships a broken catalogue is to see it in the test, not in a
//! window with half the sentences missing.

use std::collections::BTreeMap;
use std::fmt;

/// Why a catalogue could not be read. The line number counts from 1, the way an editor does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderError {
    /// Line in the catalogue.
    pub line: usize,
    /// What is wrong there.
    pub reason: String,
}

impl fmt::Display for ReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for ReaderError {}

/// Reads a catalogue into its key-value pairs, sorted by key.
///
/// # Errors
///
/// [`ReaderError`] with the line number for anything outside the subset in the module header, and
/// for a key that stands twice.
pub fn read(source: &str) -> Result<BTreeMap<String, String>, ReaderError> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut prefix = String::new();
    let lines: Vec<&str> = source.lines().map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let mut number = 0;
    while number < lines.len() {
        let line = lines[number];
        let start = number + 1;
        number += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            let name = rest.strip_suffix(']').ok_or_else(|| {
                fault(start, "a table header has to end with `]` and nothing else may follow it")
            })?;
            prefix = check_key(name, start)?;
            continue;
        }
        let (raw_key, rest) = trimmed
            .split_once('=')
            .ok_or_else(|| fault(start, "neither a table header nor `key = \"value\"`"))?;
        let key = check_key(raw_key.trim(), start)?;
        let full = if prefix.is_empty() { key } else { format!("{prefix}.{key}") };
        let value = if rest.trim_start().starts_with(r#"""""#) {
            let (text, last) = multi_line(&lines, number - 1, rest.trim_start(), start)?;
            number = last + 1;
            text
        } else {
            single_line(rest.trim(), start)?
        };
        if out.insert(full.clone(), value).is_some() {
            return Err(fault(start, &format!("the key `{full}` stands twice")));
        }
    }
    Ok(out)
}

/// A bare key or a dotted key: segments of `A-Za-z0-9_-`, no empty segment.
fn check_key(text: &str, line: usize) -> Result<String, ReaderError> {
    if text.is_empty() {
        return Err(fault(line, "a key without a name"));
    }
    for part in text.split('.') {
        if part.is_empty() {
            return Err(fault(line, &format!("`{text}` has an empty part between two dots")));
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(fault(
                line,
                &format!("`{text}` is not a bare key (only letters, digits, `_` and `-`)"),
            ));
        }
    }
    Ok(text.to_owned())
}

/// `"…"` followed by nothing but whitespace and an optional comment.
fn single_line(text: &str, line: usize) -> Result<String, ReaderError> {
    let body = text
        .strip_prefix('"')
        .ok_or_else(|| fault(line, "the value has to be a string in double quotes"))?;
    let mut out = String::new();
    let mut rest = body.chars();
    loop {
        let Some(c) = rest.next() else {
            return Err(fault(line, "the string is not closed"));
        };
        match c {
            '"' => break,
            '\\' => out.push(escape(&mut rest, line)?),
            _ => out.push(c),
        }
    }
    let tail = rest.as_str().trim();
    if !tail.is_empty() && !tail.starts_with('#') {
        return Err(fault(line, &format!("`{tail}` stands after the value")));
    }
    Ok(out)
}

/// `"""` … `"""` over several lines. The newline directly after the opening delimiter does not
/// belong to the text (the TOML rule), so that the first line of a text can start at the margin.
fn multi_line(
    lines: &[&str],
    first: usize,
    head: &str,
    line: usize,
) -> Result<(String, usize), ReaderError> {
    let after = head.trim_start_matches(r#"""""#);
    if !after.trim().is_empty() && !after.trim().starts_with('#') {
        return Err(fault(line, "after `\"\"\"` the line has to end"));
    }
    let mut body = String::new();
    let mut number = first + 1;
    loop {
        let Some(row) = lines.get(number) else {
            return Err(fault(line, "the multi-line string is not closed with `\"\"\"`"));
        };
        if let Some(before) = row.find(r#"""""#) {
            let tail = row[before + 3..].trim();
            if !tail.is_empty() && !tail.starts_with('#') {
                return Err(fault(number + 1, &format!("`{tail}` stands after the value")));
            }
            body.push_str(&row[..before]);
            return Ok((unescape(&body, line)?, number));
        }
        body.push_str(row);
        body.push('\n');
        number += 1;
    }
}

/// The escapes of a basic string, applied to a whole text.
fn unescape(text: &str, line: usize) -> Result<String, ReaderError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text.chars();
    while let Some(c) = rest.next() {
        if c == '\\' {
            out.push(escape(&mut rest, line)?);
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// One escape after the backslash.
fn escape(rest: &mut std::str::Chars<'_>, line: usize) -> Result<char, ReaderError> {
    match rest.next() {
        Some('"') => Ok('"'),
        Some('\\') => Ok('\\'),
        Some('n') => Ok('\n'),
        Some('r') => Ok('\r'),
        Some('t') => Ok('\t'),
        Some('u') => {
            let digits: String = rest.by_ref().take(4).collect();
            let value = u32::from_str_radix(&digits, 16)
                .map_err(|_| fault(line, &format!("`\\u{digits}` is not four hex digits")))?;
            char::from_u32(value)
                .ok_or_else(|| fault(line, &format!("`\\u{digits}` is not a character")))
        }
        Some(other) => Err(fault(line, &format!("`\\{other}` is not one of the escapes"))),
        None => Err(fault(line, "a backslash at the end of the text")),
    }
}

fn fault(line: usize, reason: &str) -> ReaderError {
    ReaderError { line, reason: reason.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_header_prefixes_the_keys_beneath_it() {
        let catalogue = read("[menu]\nopen = \"Open\"\nfolder.finder = \"Finder\"\n").unwrap();
        assert_eq!(catalogue["menu.open"], "Open");
        assert_eq!(catalogue["menu.folder.finder"], "Finder");
    }

    #[test]
    fn comments_and_blank_lines_carry_no_value() {
        let catalogue = read("# head\n\n  # indented\na = \"x\" # after it\n").unwrap();
        assert_eq!(catalogue.len(), 1);
        assert_eq!(catalogue["a"], "x");
    }

    #[test]
    fn a_multi_line_string_keeps_its_line_breaks_and_loses_the_first() {
        let catalogue = read("body = \"\"\"\nfirst\nsecond\n\"\"\"\n").unwrap();
        assert_eq!(catalogue["body"], "first\nsecond\n");
    }

    #[test]
    fn the_escapes_of_a_basic_string_are_applied() {
        let catalogue = read(r#"a = "one\ttwo\nthree \"quoted\" \\ \u00e4""#).unwrap();
        assert_eq!(catalogue["a"], "one\ttwo\nthree \"quoted\" \\ ä");
    }

    #[test]
    fn a_carriage_return_at_the_end_of_a_line_is_not_part_of_the_value() {
        let catalogue = read("a = \"x\"\r\nb = \"y\"\r\n").unwrap();
        assert_eq!((catalogue["a"].as_str(), catalogue["b"].as_str()), ("x", "y"));
    }

    #[test]
    fn a_key_that_stands_twice_is_an_error_and_not_the_last_one_winning() {
        // Two sentences under one key: one of them would disappear silently, and nobody would know
        // which.
        let error = read("a = \"one\"\na = \"two\"\n").unwrap_err();
        assert_eq!(error.line, 2);
        assert!(error.to_string().contains("twice"), "{error}");
    }

    #[test]
    fn everything_outside_the_subset_is_an_error_with_a_line_number() {
        let wrong = [
            ("a = 5\n", 1),
            ("a = true\n", 1),
            ("a = ['x']\n", 1),
            ("a = 'literal'\n", 1),
            ("a = \"unclosed\n", 1),
            ("a = \"x\" y\n", 1),
            ("[table\nb = \"x\"\n", 1),
            ("a.. = \"x\"\n", 1),
            ("a b = \"x\"\n", 1),
            ("nonsense\n", 1),
            ("a = \"\\q\"\n", 1),
            ("\n\nb = \"\"\"\nunclosed\n", 3),
        ];
        for (text, line) in wrong {
            match read(text) {
                Ok(value) => panic!("{text:?} was accepted as {value:?}"),
                Err(error) => assert_eq!(error.line, line, "{text:?}: {error}"),
            }
        }
    }
}
