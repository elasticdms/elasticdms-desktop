//! What a document is called in Explorer and in Finder.
//!
//! Titles are free text from the server: „Rechnung 2026/0412", „Vertrag: Sulzer <Entwurf>",
//! „CON" or twenty times „Lieferschein". A file system takes only part of that, and two file
//! systems take different parts. This file maps every title onto a name that **both** accept,
//! and keeps siblings apart.
//!
//! The rules, each with its reason:
//!
//! 1. **NFC.** APFS compares independently of normalization, NTFS does not. If „Müller" arrived
//!    once as NFC and once as NFD, it would be two files on Windows and one on macOS.
//! 2. **Forbidden characters** `< > : " / \ | ? *` and control characters are replaced, not
//!    removed: „2026/0412" becomes „2026-0412", not „20260412" — the digits are meant to stay
//!    apart, otherwise nobody finds the invoice under its number.
//! 3. **No dot and no space at the end** (Windows silently trims them and then no longer finds
//!    the file), **no dot at the start** (macOS hides the file).
//! 4. **Reserved device names** (`CON`, `NUL`, `COM1` …) get an underscore — even with an
//!    extension, `CON.pdf` cannot be opened on Windows.
//! 5. **At most 180 bytes of UTF-8 for the title.** APFS allows 255 bytes, NTFS 255 UTF-16
//!    units; 180 bytes leave room for the short form and the extension and are never more than
//!    180 units in UTF-16. The cut happens on a character boundary.
//! 6. **Siblings** are compared without regard to upper and lower case (both file systems are
//!    configured that way by default). When names collide, **all** parties involved get the
//!    short form of their identifier — not only the second one: otherwise it would depend on the
//!    order of the server's answer who is called „Lieferschein.pdf", and the name would wander
//!    from one file to another between two fetches.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

/// Upper bound for the title part of a name, in bytes of UTF-8 (rule 5).
pub const MAX_TITLE_BYTES: usize = 180;

/// Name used when nothing of the title is left.
pub const UNNAMED: &str = "Unbenannt";

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A not yet sanitized name, together with what collision resolution needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawName {
    title: String,
    extension: Option<&'static str>,
    short_form: String,
}

impl RawName {
    /// For a folder (case file, search): no extension.
    pub fn folder(title: &str, short_form: String) -> Self {
        Self { title: title.to_owned(), extension: None, short_form }
    }

    /// For a file: the extension follows the media type, never the title.
    pub fn file(title: &str, media_type: &str, short_form: String) -> Self {
        Self { title: title.to_owned(), extension: Some(extension_for(media_type)), short_form }
    }
}

/// The extension for a media type.
///
/// The same table as `RepresentationRole::leaf_name` on the counterpart's side (`pdf`, `png`,
/// `jpg`, `gif`, `webp`, `tif`, `txt`, `xml`, otherwise `bin`). The extension comes from the
/// media type and never from the title: a title „Rechnung.exe" yields `Rechnung.exe.pdf`, not a
/// file that Windows starts as a program.
pub fn extension_for(media_type: &str) -> &'static str {
    let base = media_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match base.as_str() {
        "application/pdf" => "pdf",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/tiff" => "tif",
        "text/plain" => "txt",
        "application/xml" | "text/xml" => "xml",
        _ => "bin",
    }
}

/// Sanitizes a title per rules 1–5. The result is never empty.
pub fn sanitize(title: &str) -> String {
    let normal: String = title.nfc().collect();
    let mut from = String::with_capacity(normal.len());
    let mut space_before = false;
    for character in normal.chars() {
        let fallback = match character {
            '/' | '\\' | ':' | '|' => Some('-'),
            '<' | '>' | '"' | '?' | '*' => Some('_'),
            c if c.is_control() => Some(' '),
            _ => None,
        };
        let character = fallback.unwrap_or(character);
        if character.is_whitespace() {
            if !space_before && !from.is_empty() {
                from.push(' ');
            }
            space_before = true;
        } else {
            from.push(character);
            space_before = false;
        }
    }
    let mut from = from.trim_start_matches('.').trim().to_owned();
    truncate_on_bytes(&mut from, MAX_TITLE_BYTES);
    let mut from = from.trim_end_matches(['.', ' ']).to_owned();
    if from.is_empty() {
        from = UNNAMED.to_owned();
    }
    let stem = from.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.trim()) {
        from.insert(stem.trim().len(), '_');
    }
    from
}

/// Builds the names for siblings, in the order of the input (rule 6).
///
/// `reserved` are names already taken (locally generated hints); an item that would be called
/// that way gets its short form.
pub fn name<I: IntoIterator<Item = RawName>>(raw: I, reserved: &[&str]) -> Vec<String> {
    let raw: Vec<RawName> = raw.into_iter().collect();
    let plain: Vec<String> =
        raw.iter().map(|r| assemble(&sanitize(&r.title), None, r.extension)).collect();
    let mut count: HashMap<String, usize> = HashMap::new();
    for name in &plain {
        *count.entry(comparison_form(name)).or_default() += 1;
    }
    for name in reserved {
        *count.entry(comparison_form(name)).or_default() += 1;
    }
    raw.iter()
        .zip(plain)
        .map(|(r, plain)| {
            if count.get(&comparison_form(&plain)).copied().unwrap_or(0) > 1 {
                assemble(&sanitize(&r.title), Some(&r.short_form), r.extension)
            } else {
                plain
            }
        })
        .collect()
}

fn assemble(title: &str, short_form: Option<&str>, extension: Option<&str>) -> String {
    let mut name = title.to_owned();
    if let Some(k) = short_form {
        name.push_str(" (");
        name.push_str(k);
        name.push(')');
    }
    if let Some(e) = extension {
        name.push('.');
        name.push_str(e);
    }
    name
}

/// The form in which two names count as equal: NFC, lower case.
pub fn comparison_form(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

fn truncate_on_bytes(text: &mut String, limit: usize) {
    if text.len() <= limit {
        return;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slashes_keep_separating_instead_of_vanishing() {
        assert_eq!(sanitize("Rechnung 2026/0412"), "Rechnung 2026-0412");
        assert_eq!(sanitize("Vertrag: Sulzer <Entwurf>"), "Vertrag- Sulzer _Entwurf_");
    }

    #[test]
    fn nfd_and_nfc_yield_the_same_name() {
        let nfd = "Mu\u{0308}ller";
        let nfc = "M\u{00fc}ller";
        assert_eq!(sanitize(nfd), sanitize(nfc));
        assert_eq!(sanitize(nfd), "Müller");
    }

    #[test]
    fn dots_and_spaces_at_the_edges_disappear() {
        assert_eq!(sanitize("  .versteckt  "), "versteckt");
        assert_eq!(sanitize("Protokoll. . "), "Protokoll");
        assert_eq!(sanitize("..."), UNNAMED);
        assert_eq!(sanitize(""), UNNAMED);
    }

    #[test]
    fn control_characters_and_repeated_spaces_become_one() {
        assert_eq!(sanitize("Zeile\n\teins   zwei"), "Zeile eins zwei");
    }

    #[test]
    fn reserved_device_names_get_an_underscore() {
        assert_eq!(sanitize("CON"), "CON_");
        assert_eq!(sanitize("nul"), "nul_");
        assert_eq!(sanitize("com1.bericht"), "com1_.bericht");
        assert_eq!(sanitize("Console"), "Console");
    }

    #[test]
    fn long_titles_are_cut_on_a_character_boundary() {
        let title = "ä".repeat(200); // 400 bytes
        let b = sanitize(&title);
        assert!(b.len() <= MAX_TITLE_BYTES);
        assert_eq!(b.chars().count(), MAX_TITLE_BYTES / 2);
    }

    #[test]
    fn the_extension_follows_the_media_type_never_the_title() {
        let n = name([RawName::file("Rechnung.exe", "application/pdf", "AAAAAAAA".into())], &[]);
        assert_eq!(n, ["Rechnung.exe.pdf"]);
        assert_eq!(extension_for("text/plain; charset=utf-8"), "txt");
        assert_eq!(extension_for("application/x-unknown"), "bin");
    }

    #[test]
    fn on_a_collision_every_party_involved_gets_the_short_form() {
        let n = name(
            [
                RawName::file("Lieferschein", "application/pdf", "AAAAAAAA".into()),
                RawName::file("lieferschein", "application/pdf", "BBBBBBBB".into()),
                RawName::file("Rechnung", "application/pdf", "CCCCCCCC".into()),
            ],
            &[],
        );
        assert_eq!(
            n,
            ["Lieferschein (AAAAAAAA).pdf", "lieferschein (BBBBBBBB).pdf", "Rechnung.pdf"]
        );
    }

    #[test]
    fn the_order_of_the_server_answer_changes_no_name() {
        let a = RawName::file("Lieferschein", "application/pdf", "AAAAAAAA".into());
        let b = RawName::file("Lieferschein", "application/pdf", "BBBBBBBB".into());
        let forward = name([a.clone(), b.clone()], &[]);
        let backward = name([b, a], &[]);
        assert_eq!(forward[0], backward[1]);
        assert_eq!(forward[1], backward[0]);
    }

    #[test]
    fn equal_titles_of_different_kinds_do_not_collide() {
        let n = name(
            [
                RawName::file("Scan", "application/pdf", "AAAAAAAA".into()),
                RawName::file("Scan", "image/png", "BBBBBBBB".into()),
            ],
            &[],
        );
        assert_eq!(n, ["Scan.pdf", "Scan.png"]);
    }

    #[test]
    fn a_reserved_name_forces_the_short_form() {
        let n =
            name([RawName::file("LIESMICH", "text/plain", "AAAAAAAA".into())], &["liesmich.txt"]);
        assert_eq!(n, ["LIESMICH (AAAAAAAA).txt"]);
    }
}
