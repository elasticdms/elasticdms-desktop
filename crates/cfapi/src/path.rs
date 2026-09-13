//! Paths under the root — as text, so that the rules are testable on macOS too.
//!
//! Callbacks deliver `VolumeDosName` and `NormalizedPath` (`C:` and
//! `\Users\n\elasticdms\Archive\…`); our own calls work with the path the app passed, for long
//! paths with `\\?\` in front. Both have to fall onto the same [`PathKey`]. Otherwise the veto
//! refuses our own deletion — and the copy of a document erased under DSGVO (GDPR) would stay
//! behind — or it lets a foreign one through because two spellings of the same path were not
//! recognised as equal.
//!
//! Upper and lower case: NTFS compares without them (default setting). Comparison is done with
//! Unicode lower case; the upper-case table of NTFS differs from it only for characters that do
//! not occur in file names of this program (`edms_core::filename`).

/// The separator on Windows.
pub const SEPARATOR: char = '\\';

/// The prefix for paths beyond `MAX_PATH`.
pub const LONG_PREFIX: &str = r"\\?\";

/// From this length (UTF-16) onwards a path gets the [`LONG_PREFIX`]. 248 instead of 260: for
/// directories Win32 subtracts twelve characters for an 8.3 name (`CreateDirectoryW`).
pub const LONG_PATH_FROM: usize = 248;

/// Takes `\\?\` off the front — but not `\\?\UNC\`, because that is a network path and should stay
/// recognisable as one.
pub fn without_long_prefix(path: &str) -> &str {
    match path.strip_prefix(LONG_PREFIX) {
        Some(rest) if !rest.get(..4).is_some_and(|k| k.eq_ignore_ascii_case("UNC\\")) => rest,
        _ => path,
    }
}

/// `/` becomes `\`, doubled separators collapse, trailing separators fall away.
pub fn unify(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for z in path.chars() {
        let z = if z == '/' { SEPARATOR } else { z };
        if z == SEPARATOR && out.ends_with(SEPARATOR) {
            continue;
        }
        out.push(z);
    }
    while out.ends_with(SEPARATOR) {
        out.pop();
    }
    out
}

/// The path relative to the root, without a leading separator; `""` for the root itself; `None` if
/// `full` does not lie under `root`.
///
/// Comparison ignores case and happens only at path boundaries: `…\elasticdms2` does not lie under
/// `…\elasticdms`.
pub fn relative_to_root(root: &str, full: &str) -> Option<String> {
    let w = unify(without_long_prefix(root));
    let v = unify(without_long_prefix(full));
    let mut full_chars = v.char_indices();
    let mut rest_from = 0;
    for root_ch in w.chars() {
        let (i, full_ch) = full_chars.next()?;
        if !equal_without_case(root_ch, full_ch) {
            return None;
        }
        rest_from = i + full_ch.len_utf8();
    }
    let rest = &v[rest_from..];
    if rest.is_empty() {
        return Some(String::new());
    }
    rest.strip_prefix(SEPARATOR).map(str::to_owned)
}

fn equal_without_case(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

/// Appends a relative path; empty parts fall away.
pub fn connect(base: &str, part: &str) -> String {
    let base = base.trim_end_matches(SEPARATOR);
    let part = part.trim_start_matches(SEPARATOR);
    match (base.is_empty(), part.is_empty()) {
        (true, _) => part.to_owned(),
        (_, true) => base.to_owned(),
        _ => format!("{base}{SEPARATOR}{part}"),
    }
}

/// A full path in the form Win32 accepts beyond `MAX_PATH` as well.
///
/// An archive, a case file (Akte) and a document (each with a title of up to 180 bytes) under
/// `%USERPROFILE%\elasticdms\Archive` easily blow past 260 characters; without the prefix
/// `DeleteFileW` then fails — of all things on the deletion. Shorter paths stay without the prefix,
/// because some calls do not like it. Expects a [`unify`]-ed path: behind `\\?\` Windows no longer
/// converts `/`.
pub fn for_win32(full: &str) -> String {
    if full.starts_with(r"\\") || full.encode_utf16().count() < LONG_PATH_FROM {
        full.to_owned()
    } else {
        format!("{LONG_PREFIX}{full}")
    }
}

/// Assembles the full path from the two fields a callback delivers.
///
/// cldflt passes `VolumeDosName` (`C:`) and `NormalizedPath` (`\Users\n\elasticdms\Archive\…`)
/// separately. Two pitfalls this function stands against: depending on the Windows version
/// `VolumeDosName` carries a trailing separator or does not (otherwise `C:\\Users` would result),
/// and an empty `VolumeDosName` must not lead to a path beginning with `\` — to Win32 that means
/// the current drive, that is to say some drive, just not reliably ours.
/// A third one, easily overlooked: `C:` on its own is **not** an absolute path to Win32 but "the
/// current directory on drive C". The root is called `C:\`, with a separator.
pub fn from_callback(drive: &str, normalized: &str) -> String {
    let drive = drive.trim_end_matches(SEPARATOR);
    let rest = unify(normalized);
    let rest = rest.trim_start_matches(SEPARATOR);
    match (drive.is_empty(), rest.is_empty()) {
        (true, _) => unify(normalized),
        (_, true) => format!("{drive}{SEPARATOR}"),
        _ => format!("{drive}{SEPARATOR}{rest}"),
    }
}

/// Splits a relative path into parent path and last name.
pub fn parent_and_name(relative: &str) -> (&str, &str) {
    match relative.rfind(SEPARATOR) {
        Some(i) => (&relative[..i], &relative[i + 1..]),
        None => ("", relative),
    }
}

/// The comparable form of a path relative to the root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey(String);

impl PathKey {
    /// From a path relative to the root.
    pub fn from_relative(relative: &str) -> Self {
        Self(unify(relative).trim_start_matches(SEPARATOR).to_lowercase())
    }

    /// The key as text (lower case, `\` separated).
    pub fn as_text(&self) -> &str {
        &self.0
    }

    /// Whether this path is `top` or lies below it. The root (`""`) contains everything.
    pub fn is_below(&self, top: &Self) -> bool {
        top.0.is_empty()
            || self.0 == top.0
            || self.0.strip_prefix(top.0.as_str()).is_some_and(|rest| rest.starts_with(SEPARATOR))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r"C:\Users\n\elasticdms";

    #[test]
    fn a_callback_path_and_one_of_our_own_fall_onto_the_same_key() {
        let from_callback = relative_to_root(
            ROOT,
            r"C:\Users\n\elasticdms\Archive\Zentralarchiv\Sulzer\Prüfbericht.pdf",
        )
        .unwrap();
        let from_own = relative_to_root(
            r"\\?\c:\users\N\ELASTICDMS\",
            r"\\?\C:\Users\n\elasticdms\Archive\Zentralarchiv\Sulzer\Prüfbericht.pdf",
        )
        .unwrap();
        assert_eq!(PathKey::from_relative(&from_callback), PathKey::from_relative(&from_own));
        assert_eq!(from_callback, r"Archive\Zentralarchiv\Sulzer\Prüfbericht.pdf");
    }

    #[test]
    fn the_root_itself_is_the_empty_path() {
        assert_eq!(relative_to_root(ROOT, r"C:\Users\n\elasticdms").as_deref(), Some(""));
        assert_eq!(relative_to_root(ROOT, r"c:/users/n/elasticdms/").as_deref(), Some(""));
    }

    #[test]
    fn a_neighbouring_folder_with_the_same_beginning_does_not_lie_under_the_root() {
        assert_eq!(relative_to_root(ROOT, r"C:\Users\n\elasticdms2\x"), None);
        assert_eq!(relative_to_root(ROOT, r"C:\Users\n\elasticdms Backup\x"), None);
        assert_eq!(relative_to_root(ROOT, r"D:\Users\n\elasticdms\x"), None);
        assert_eq!(relative_to_root(ROOT, r"C:\Users"), None);
    }

    #[test]
    fn umlauts_are_compared_without_regard_to_case() {
        let w = r"C:\Users\Müller\elasticdms";
        assert_eq!(
            relative_to_root(w, r"C:\USERS\MÜLLER\ELASTICDMS\Archive").as_deref(),
            Some("Archive")
        );
        assert_eq!(PathKey::from_relative("ÄRGER"), PathKey::from_relative("ärger"));
    }

    #[test]
    fn a_subtree_covers_children_but_no_namesakes() {
        let case = PathKey::from_relative(r"Archive\Nord\Sulzer");
        assert!(PathKey::from_relative(r"Archive\Nord\Sulzer").is_below(&case));
        assert!(PathKey::from_relative(r"archive\nord\sulzer\a.pdf").is_below(&case));
        assert!(!PathKey::from_relative(r"Archive\Nord\Sulzer 2\a.pdf").is_below(&case));
        assert!(!PathKey::from_relative(r"Archive\Nord").is_below(&case));
        assert!(PathKey::from_relative(r"Archive").is_below(&PathKey::from_relative("")));
    }

    #[test]
    fn joining_and_splitting_fit_together() {
        assert_eq!(connect(ROOT, r"Archive\Nord"), r"C:\Users\n\elasticdms\Archive\Nord");
        assert_eq!(connect(r"C:\x\", r"\y"), r"C:\x\y");
        assert_eq!(connect(ROOT, ""), ROOT);
        assert_eq!(connect("", "Archive"), "Archive");
        assert_eq!(parent_and_name(r"Archive\Nord\b.pdf"), (r"Archive\Nord", "b.pdf"));
        assert_eq!(parent_and_name("LIESMICH.txt"), ("", "LIESMICH.txt"));
    }

    #[test]
    fn long_paths_get_the_prefix_short_ones_do_not() {
        let short = connect(ROOT, "Archive");
        assert_eq!(for_win32(&short), short);
        let long = connect(ROOT, &"a".repeat(LONG_PATH_FROM));
        assert_eq!(for_win32(&long), format!(r"\\?\{long}"));
        // Already prefixed: nothing twice.
        assert_eq!(for_win32(&format!(r"\\?\{long}")), format!(r"\\?\{long}"));
    }

    #[test]
    fn the_two_halves_of_a_callback_yield_a_path_with_a_drive() {
        // This is how they arrive from cldflt: drive without a separator, rest with a leading one.
        assert_eq!(
            from_callback("C:", r"\Users\n\elasticdms\Archive"),
            r"C:\Users\n\elasticdms\Archive"
        );
        // Some versions append the separator; it must not become a double one.
        assert_eq!(from_callback(r"C:\", r"\Users\n"), r"C:\Users\n");
        assert_eq!(from_callback("C:", "\\"), r"C:\");
        assert_eq!(from_callback("C:", ""), r"C:\");
    }

    #[test]
    fn without_a_drive_letter_no_path_onto_the_current_drive_arises() {
        // A mounted volume has no `VolumeDosName`. `\Users\n` would be, to Win32, the path on the
        // *current* drive — some drive, just not reliably ours. That is why the path stays as it
        // is, and `relative_to_root` does not find it under the root.
        let full = from_callback("", r"\Users\n\elasticdms\Archive");
        assert_eq!(full, r"\Users\n\elasticdms\Archive");
        assert_eq!(relative_to_root(ROOT, &full), None);
    }

    #[test]
    fn a_network_path_does_not_lose_its_prefix() {
        assert_eq!(without_long_prefix(r"\\?\UNC\server\x"), r"\\?\UNC\server\x");
        assert_eq!(without_long_prefix(r"\\?\C:\x"), r"C:\x");
    }
}
