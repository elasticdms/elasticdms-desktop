//! Checks before a value reaches cloud-filter or Windows.
//!
//! Two concrete reasons; every check serves one of them:
//!
//! 1. **cloud-filter 0.0.6 checks with `assert!`.** `SyncRootIdBuilder::new` aborts on a provider
//!    name over 255 characters or containing `!`, `SecurityId::new` on a `!`,
//!    `PlaceholderFile::blob` on more than 4096 bytes (read in the crate's own source). An abort
//!    inside a callback is the end of the process; so every value has to be checked beforehand.
//! 2. **Windows rejects late and wholesale.** An invalid name fails only in
//!    `CfCreatePlaceholders`, with one HRESULT per entry and without saying what was wrong. Here
//!    the reason stands as a sentence, together with the name.
//!
//! The naming rules are those of NTFS/Win32, not those of `edms_core::filename`: there titles are
//! *sanitised*, here they are only *checked*. If a name got through that the core should have
//! sanitised, that is a bug in the program — and it should show up as one, not as a silent second
//! renaming somewhere else.

use edms_core::namespace::EntryIdentifier;
use edms_core::time::Timestamp;

use crate::error::MirrorError;

/// The provider name, first part of the root identifier `<provider>!<SID>!<account>`.
pub const PROVIDER: &str = "elasticdms";

/// Maximum length of a name in UTF-16 units (NTFS).
pub const MAX_NAME_UTF16: usize = 255;

/// Maximum length of the provider name (`CF_MAX_PROVIDER_NAME_LENGTH`).
pub const MAX_PROVIDER_UTF16: usize = 255;

/// Maximum length of the file identity of a placeholder (`CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH`).
pub const MAX_IDENTITY_BLOB: usize = 4096;

/// Maximum length of the root identifier: it is the name of a registry key under
/// `HKLM\…\SyncRootManager`, and those are limited to 255 characters.
pub const MAX_SYNC_ROOT_IDENTIFIER_UTF16: usize = 255;

/// The separator of the root identifier. If it occurs inside a part, the identifier falls apart
/// into four parts, and cloud-filter's `SyncRootId::to_components` aborts with `panic!`.
pub const SEPARATOR_SYNC_ROOT_IDENTIFIER: char = '!';

/// Characters Win32 does not accept in names.
const FORBIDDEN: [char; 9] = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Device names Win32 intercepts even with an extension (`CON.pdf` opens the console).
const DEVICE_NAME: [&str; 24] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
    "CONOUT$",
];

/// Checks a file or folder name (one path part, not a path).
pub fn check_name(name: &str) -> Result<(), MirrorError> {
    let error = |reason| Err(MirrorError::InvalidName { name: name.to_owned(), reason });
    if name.is_empty() {
        return error("it is empty");
    }
    if name == "." || name == ".." {
        return error("`.` and `..` are references, not names");
    }
    if name.encode_utf16().count() > MAX_NAME_UTF16 {
        return error("it is longer than 255 UTF-16 units");
    }
    if name.chars().any(|z| u32::from(z) < 0x20) {
        return error("it contains control characters");
    }
    if name.chars().any(|z| FORBIDDEN.contains(&z)) {
        return error("it contains one of the characters < > : \" / \\ | ? *");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return error("it ends with a dot or a space, which Windows silently trims");
    }
    let stem = name.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
    if DEVICE_NAME.contains(&stem.as_str()) {
        return error("it is a reserved device name");
    }
    Ok(())
}

/// The file identity of a placeholder: the text of the entry identifier as UTF-8.
///
/// Text instead of a binary form, because it comes along in every callback and should stay
/// readable in logs; the longest identifier (`arc_…/cas_…/doc_…`) is 92 bytes.
pub fn identity_blob(identifier: EntryIdentifier) -> Result<Vec<u8>, MirrorError> {
    let text = identifier.to_string();
    if text.len() > MAX_IDENTITY_BLOB {
        return Err(MirrorError::IdentifierTooLong { length: text.len(), identifier: text });
    }
    Ok(text.into_bytes())
}

/// Reads the file identity of a placeholder back.
pub fn identifier_from_blob(blob: &[u8]) -> Result<EntryIdentifier, MirrorError> {
    if blob.is_empty() {
        return Err(MirrorError::IdentifierUnreadable(
            "the placeholder carries no file identity".into(),
        ));
    }
    let text = std::str::from_utf8(blob).map_err(|_| {
        MirrorError::IdentifierUnreadable("the file identity is not UTF-8 text".into())
    })?;
    text.parse::<EntryIdentifier>().map_err(|e| MirrorError::IdentifierUnreadable(e.to_string()))
}

fn part_of_the_sync_root_identifier(text: &str) -> Result<(), &'static str> {
    if text.is_empty() {
        return Err("it is empty");
    }
    if text.contains(SEPARATOR_SYNC_ROOT_IDENTIFIER) {
        return Err("it contains `!`, the separator of the root identifier");
    }
    if text.chars().any(char::is_control) {
        return Err("it contains control characters");
    }
    if text.contains('\\') {
        return Err("it contains `\\`, the separator of registry keys");
    }
    Ok(())
}

/// Checks the provider name against the rules of cfAPI and cloud-filter.
pub fn check_provider(name: &str) -> Result<(), MirrorError> {
    part_of_the_sync_root_identifier(name)
        .and_then(|()| {
            if name.encode_utf16().count() > MAX_PROVIDER_UTF16 {
                Err("it is longer than 255 characters (CF_MAX_PROVIDER_NAME_LENGTH)")
            } else {
                Ok(())
            }
        })
        .map_err(|reason| MirrorError::InvalidProvider { name: name.to_owned(), reason })
}

/// Checks the account identifier (`sub`) as the last part of the root identifier.
///
/// cloud-filter's `account_name` accepts anything; a `!` in it would yield an identifier with four
/// parts, which Windows accepts and cloud-filter later acknowledges with a `panic!` when it takes
/// it apart.
pub fn check_account(account: &str) -> Result<(), MirrorError> {
    part_of_the_sync_root_identifier(account)
        .map_err(|reason| MirrorError::InvalidAccount { account: account.to_owned(), reason })
}

/// Checks the length of the finished root identifier (known only after building: the SID is in it).
pub fn check_sync_root_identifier_length(length_utf16: usize) -> Result<(), MirrorError> {
    if length_utf16 > MAX_SYNC_ROOT_IDENTIFIER_UTF16 {
        return Err(MirrorError::SyncRootIdentifierTooLong { length: length_utf16 });
    }
    Ok(())
}

/// Checks the display name of the root ("elasticdms – Example GmbH").
pub fn check_display_name(name: &str) -> Result<(), MirrorError> {
    if name.trim().is_empty() {
        return Err(MirrorError::InvalidDisplayName { reason: "it is empty" });
    }
    if name.chars().any(char::is_control) {
        return Err(MirrorError::InvalidDisplayName { reason: "it contains control characters" });
    }
    Ok(())
}

/// Checks the root path the app passes, as Windows path text.
///
/// What is required is a local, absolute path with a drive letter (`C:\Users\n\elasticdms`, with
/// `\\?\` in front as well). Network paths are out, because cldflt works only on local NTFS; a
/// drive root is out, because the root has to be a folder of its own that `clear_everything` may
/// delete completely.
pub fn check_root_path(path: &str) -> Result<(), MirrorError> {
    let error = |reason| Err(MirrorError::InvalidRoot { path: path.to_owned(), reason });
    if path.contains('\0') {
        return error("it contains a null character");
    }
    let unified = path.replace('/', "\\");
    let without = unified.strip_prefix(r"\\?\").unwrap_or(&unified);
    if without.starts_with(r"\\")
        || without.len() >= 4 && without[..4].eq_ignore_ascii_case(r"UNC\")
    {
        return error("it is a network path; the Cloud Filter API works only on local drives");
    }
    let b = without.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return error("it is not an absolute path with a drive letter");
    }
    let mut parts = without[3..].split('\\').filter(|t| !t.is_empty()).peekable();
    if parts.peek().is_none() {
        return error("it is the root of a drive; the mirror needs a folder of its own");
    }
    for part in parts {
        if part == "." || part == ".." {
            return error("it contains `.` or `..`");
        }
        if check_name(part).is_err() {
            return error("it contains a folder name Windows does not accept");
        }
    }
    Ok(())
}

/// Only the file name of the program from `CF_PROCESS_INFO.ImagePath`.
///
/// `ImagePath` is an NT path (`\Device\HarddiskVolume3\Users\n\…\WINWORD.EXE`) and its directory
/// gives away the user name; only `WINWORD.EXE` goes to the server (`edms_core::port::
/// ContentRequest`). Windows writes `UNKNOWN` when it could not determine the path — that is not a
/// program name and becomes `None`, not a header line "UNKNOWN".
pub fn application_name(image_path: &str) -> Option<String> {
    let t = image_path.trim().trim_end_matches(['\\', '/']);
    if t.is_empty() || t.eq_ignore_ascii_case("UNKNOWN") {
        return None;
    }
    let name = t.rsplit(['\\', '/']).next().unwrap_or_default();
    (!name.is_empty()).then(|| name.to_owned())
}

/// Windows 10 1709 (Fall Creators Update): from here on `cldapi.dll` and `CfGetPlatformInfo` exist.
pub const MIN_BUILD: u32 = 16_299;

/// Windows 10 2004: only from here on does `StorageProviderSyncRootManager.IsSupported` exist.
/// Before that the call went nowhere, so it is not made there (research note, hard limits).
pub const BUILD_WITH_IS_SUPPORTED: u32 = 19_041;

/// Checks the build number from `CfGetPlatformInfo`.
pub fn check_build(build: u32) -> Result<(), MirrorError> {
    if build < MIN_BUILD {
        return Err(MirrorError::WindowsTooOld { build });
    }
    Ok(())
}

/// Milliseconds from 1601-01-01 to 1970-01-01.
const MILLIS_1601_UNTIL_1970: i64 = 11_644_473_600_000;

/// A timestamp as a `FILETIME` (100 ns steps since 1601), the way `FILE_BASIC_INFO` wants it.
///
/// Never smaller than 1: `CfUpdatePlaceholder` reads `0` as "do not change", and a timestamp
/// before 1601 would otherwise silently become the instruction to keep the old value.
pub fn filetime(timestamp: Timestamp) -> i64 {
    timestamp.unix_millis().saturating_add(MILLIS_1601_UNTIL_1970).saturating_mul(10_000).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::Identifier;
    use edms_core::namespace::{Container, HintKind, Location};

    #[test]
    fn ordinary_names_go_through() {
        for name in ["Rechnung 2026-0412.pdf", "Müller & Söhne", "CON_.pdf", "Console.txt", "a"] {
            assert!(check_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn forbidden_names_are_rejected_with_a_reason() {
        let cases = [
            ("", "empty"),
            ("..", "references"),
            ("a:b", "characters"),
            ("a\\b", "characters"),
            ("Ende.", "dot"),
            ("Ende ", "space"),
            ("Zeile\nzwei", "control characters"),
            ("con.pdf", "device name"),
            ("LPT1", "device name"),
            ("CONOUT$", "device name"),
        ];
        for (name, part) in cases {
            let f = check_name(name).unwrap_err();
            assert!(f.to_string().contains(part), "{name}: {f}");
        }
    }

    #[test]
    fn the_length_counts_utf16_units_not_bytes() {
        assert!(check_name(&"ä".repeat(255)).is_ok(), "255 umlauts are 510 bytes, but 255 units");
        assert!(check_name(&"a".repeat(256)).is_err());
        // A character outside the BMP counts twice.
        assert!(check_name(&"😀".repeat(128)).is_err());
        assert!(check_name(&"😀".repeat(127)).is_ok());
    }

    #[test]
    fn every_entry_identifier_survives_the_trip_through_the_file_identity() {
        let archive = Identifier::from_value(u128::MAX >> 3);
        let case = Identifier::from_value(u128::MAX >> 5);
        let basket = Identifier::from_value(3);
        let search = Identifier::from_value(7);
        let all = [
            EntryIdentifier::ROOT,
            EntryIdentifier::Container(Container::Baskets),
            EntryIdentifier::Container(Container::Basket(basket)),
            EntryIdentifier::Container(Container::Archives),
            EntryIdentifier::Container(Container::Archive(archive)),
            EntryIdentifier::Container(Container::Case { archive, case }),
            EntryIdentifier::Document {
                location: Location::Case { archive, case },
                document: Identifier::from_value(u128::MAX),
            },
            EntryIdentifier::Document {
                location: Location::Search(search),
                document: Identifier::from_value(u128::MAX),
            },
            EntryIdentifier::Hint {
                location: Container::Search(search),
                kind: HintKind::Truncated,
            },
        ];
        let mut longest = 0;
        for k in all {
            let blob = identity_blob(k).unwrap();
            assert!(blob.len() <= MAX_IDENTITY_BLOB);
            assert_eq!(identifier_from_blob(&blob).unwrap(), k);
            longest = longest.max(blob.len());
        }
        assert_eq!(longest, 92, "the longest identifier is a document in a case file");
    }

    #[test]
    fn a_foreign_file_identity_is_not_reinterpreted() {
        assert!(matches!(identifier_from_blob(b""), Err(MirrorError::IdentifierUnreadable(_))));
        assert!(matches!(
            identifier_from_blob(&[0xff, 0xfe]),
            Err(MirrorError::IdentifierUnreadable(_))
        ));
        // Nextcloud stores UTF-16 including null characters; that is not our identifier.
        assert!(identifier_from_blob("abc\0".as_bytes()).is_err());
        assert!(identifier_from_blob(b"doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB").is_err());
        // A placeholder of the previous version: a case file without its archive, and the
        // container that has gone with it (namespace v2 §1). It is an error, not a guess.
        assert!(identifier_from_blob(b"cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB").is_err());
        assert!(identifier_from_blob(b"cases").is_err());
    }

    #[test]
    fn an_exclamation_mark_in_the_account_is_caught_before_cloud_filter() {
        assert!(check_account("usr_01JK4R7ZQ8M3N5P6T9V0WXYZAB").is_ok());
        let f = check_account("usr!admin").unwrap_err();
        assert!(matches!(f, MirrorError::InvalidAccount { .. }), "{f}");
        assert!(check_account("").is_err());
        assert!(check_account("a\\b").is_err());
        assert!(check_account("a\u{7}b").is_err());
    }

    #[test]
    fn the_provider_name_keeps_within_the_limits_of_cloud_filter() {
        assert!(check_provider(PROVIDER).is_ok());
        assert!(check_provider("elastic!dms").is_err());
        assert!(check_provider(&"a".repeat(256)).is_err());
        assert!(check_provider(&"a".repeat(255)).is_ok());
    }

    #[test]
    fn the_root_identifier_fits_into_a_registry_key() {
        assert!(check_sync_root_identifier_length(255).is_ok());
        assert_eq!(
            check_sync_root_identifier_length(256),
            Err(MirrorError::SyncRootIdentifierTooLong { length: 256 })
        );
    }

    #[test]
    fn the_display_name_must_not_be_empty() {
        assert!(check_display_name("elasticdms – Example GmbH").is_ok());
        assert!(check_display_name("   ").is_err());
        assert!(check_display_name("a\0b").is_err());
    }

    #[test]
    fn only_a_local_absolute_folder_is_good_as_a_root() {
        for good in [
            r"C:\Users\n\elasticdms",
            r"\\?\C:\Users\n\elasticdms",
            "d:/Daten/elasticdms",
            r"C:\Users\n\elasticdms\",
        ] {
            assert!(check_root_path(good).is_ok(), "{good}");
        }
        let cases = [
            (r"\\server\freigabe\elasticdms", "network path"),
            (r"\\?\UNC\server\freigabe", "network path"),
            (r"Users\n\elasticdms", "absolute"),
            (r"C:\", "root of a drive"),
            (r"C:\Users\..\elasticdms", "`..`"),
            ("C:\\Users\\n\0x", "null character"),
            (r"C:\Users\n\elastic?dms", "folder name"),
        ];
        for (path, part) in cases {
            let f = check_root_path(path).unwrap_err();
            assert!(f.to_string().contains(part), "{path}: {f}");
        }
    }

    #[test]
    fn only_the_file_name_is_left_of_the_program_path() {
        assert_eq!(
            application_name(
                r"\Device\HarddiskVolume3\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
            )
            .as_deref(),
            Some("WINWORD.EXE")
        );
        assert_eq!(application_name(r"C:\Windows\explorer.exe").as_deref(), Some("explorer.exe"));
        assert_eq!(application_name("notepad.exe").as_deref(), Some("notepad.exe"));
        assert_eq!(application_name("UNKNOWN"), None);
        assert_eq!(application_name(""), None);
        assert_eq!(application_name(r"\Device\"), Some("Device".to_owned()));
    }

    #[test]
    fn windows_before_1709_is_rejected_with_its_build_number() {
        assert!(check_build(MIN_BUILD).is_ok());
        assert!(check_build(26_100).is_ok());
        assert_eq!(check_build(15_063), Err(MirrorError::WindowsTooOld { build: 15_063 }));
        const { assert!(BUILD_WITH_IS_SUPPORTED > MIN_BUILD) };
    }

    #[test]
    fn filetime_counts_from_1601_and_is_never_zero() {
        assert_eq!(filetime(Timestamp::NULL), 116_444_736_000_000_000);
        let z = Timestamp::from_rfc3339("2026-09-02T07:38:12.118Z").unwrap();
        assert_eq!(filetime(z), (1_788_334_692_118 + MILLIS_1601_UNTIL_1970) * 10_000);
        // Before 1601 it would be negative or zero — zero means "do not change" to
        // CfUpdatePlaceholder.
        assert_eq!(filetime(Timestamp::from_unix_millis(-MILLIS_1601_UNTIL_1970)), 1);
        assert_eq!(filetime(Timestamp::from_unix_millis(i64::MIN)), 1);
        assert_eq!(filetime(Timestamp::from_unix_millis(i64::MAX)), i64::MAX);
    }
}
