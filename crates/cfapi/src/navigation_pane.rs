//! The entry in File Explorer's navigation pane — its registry keys as pure values.
//!
//! Next to OneDrive, in the sidebar of every Explorer window, a cloud provider gets a row of its
//! own. It does not come with `CfRegisterSyncRoot`: the Win32 registration tells cldflt about the
//! root, nothing else. The row hangs off registry keys under
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\<provider>!<SID>!<account>`
//! — the same key name that [`crate::sync_root::SyncRootIdentifier`] already builds and checks.
//!
//! **The folder is fully usable without the row**; it is then opened through its path. That is why
//! a failure here is not fatal: the caller writes a line into the log and carries on with a folder
//! that works.
//!
//! ## Why at runtime and not in the installer
//!
//! The key name carries the SID of the signed-in user and the account identifier, and neither is
//! known before somebody has signed in (`packaging/windows/README.md`, section "Open: the entry in
//! File Explorer's navigation pane"). An MSI runs before the first sign-in and could only guess.
//!
//! ## What is settled here, and what is not
//!
//! Here: the key path, the value names, the shape of every value and the SID as text — as pure
//! functions with tests, because nothing of it can be run on the machine this was written on. The
//! registry calls themselves are in `platform::registry` and have **never been executed**.
//!
//! ## NAMED GAP 1: the second half, under HKCU
//!
//! `packaging/windows/README.md` reports the entry as consisting of two halves and says of the
//! HKCU half (`Software\Classes\CLSID\<GUID>` with its subkeys, `…\Explorer\Desktop\NameSpace\
//! <GUID>`, `HideDesktopIcons`, "roughly a dozen values"): **without it no entry appears in the
//! sidebar.** This module writes the HKLM half only. No source in this repository enumerates the
//! HKCU values, and they are not guessed here. Whether the row appears with the HKLM half alone
//! is therefore open, and a measurement on Windows settles it.
//!
//! ## NAMED GAP 2: `Flags`
//!
//! The same README names `Flags` (`REG_DWORD`) as part of the entry and calls it **undocumented**:
//! "copy it from Nextcloud, do not guess". There is nothing to copy from on this machine, so
//! [`Entry::flags`] is `None` and the value is not written. Whoever has measured the number sets
//! the field; the shaping is ready and tested.

use crate::checks::{check_display_name, check_root_path};
use crate::error::MirrorError;
use crate::path::{unify, without_long_prefix};
use crate::sync_root::SyncRootIdentifier;
use crate::text::nul_terminated;

/// The key under HKLM below which every cloud provider hangs its sync roots.
pub const SYNC_ROOT_MANAGER: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager";

/// The subkey that carries one root path per signed-in user.
pub const USER_SYNC_ROOTS: &str = "UserSyncRoots";

/// What the user reads in the navigation pane.
pub const DISPLAY_NAME_RESOURCE: &str = "DisplayNameResource";

/// Where Explorer takes the icon of the row from: `<program>,<index>`.
pub const ICON_RESOURCE: &str = "IconResource";

/// The CLSID under which the row hangs in the shell's namespace.
pub const NAMESPACE_CLSID: &str = "NamespaceCLSID";

/// The undocumented bit field; see NAMED GAP 2 in the module header.
pub const FLAGS: &str = "Flags";

/// The icon inside the program that Explorer shows on the row.
///
/// Index 0 is the program's first icon — the one Explorer and the taskbar show for the same
/// executable, so the row carries the same picture as the program.
pub const ICON_INDEX: u16 = 0;

/// The CLSID of the namespace entry, in `NamespaceCLSID`.
///
/// [GAP -> PROPOSAL] The same discipline as [`crate::sync_root::PROVIDER_GUID`], and for the same
/// reason: rolled once, written down, never changed again. A different value means a different
/// namespace entry to Windows, and the old one stays behind as a corpse in every profile it was
/// ever written into. The HKCU half (NAMED GAP 1) has to carry **this** number as its key name,
/// otherwise the two halves do not name the same thing.
///
/// One root per user, therefore one CLSID (`packaging/windows/README.md`). A second mirror in the
/// same profile would need a second one.
pub const NAMESPACE_CLSID_VALUE: u128 = 0xb644_fde4_a535_4d98_b0e3_d6be_0666_47f0;

/// A binary SID begins with revision, sub-authority count and six bytes of authority.
const SID_HEADER: usize = 8;

/// The only revision Windows writes (`SID_REVISION`, winnt.h).
const SID_REVISION: u8 = 1;

/// What a registry value carries, and in which of the three types Windows keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_SZ` — a text Windows hands on as it stands.
    Text(String),
    /// `REG_EXPAND_SZ` — a text in which Windows replaces `%ProgramFiles%` and its like when it
    /// reads the value.
    TextWithVariables(String),
    /// `REG_DWORD` — a 32-bit number.
    Number(u32),
}

impl Data {
    /// The bytes as `RegSetValueExW` takes them.
    ///
    /// A text goes as UTF-16 **including its null character**: the registry keeps the length, but
    /// everything that reads a `REG_SZ` reads up to the null. One left off turns the next value in
    /// the key into part of this one. A null character *inside* the text is refused rather than
    /// silently cutting it short ([`crate::text::nul_terminated`]).
    pub fn bytes(&self) -> Result<Vec<u8>, MirrorError> {
        match self {
            Self::Text(text) | Self::TextWithVariables(text) => {
                Ok(nul_terminated(text)?.iter().flat_map(|unit| unit.to_le_bytes()).collect())
            }
            // A DWORD lies in the registry the way it lies in memory, and every Windows this
            // client runs on is little-endian (x86-64 and aarch64). Written out, so that the
            // bytes do not depend on the machine the test runs on.
            Self::Number(number) => Ok(number.to_le_bytes().to_vec()),
        }
    }
}

/// One value of the entry, together with the key it lives under (relative to HKLM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The key under HKLM, without a leading separator.
    pub key: String,
    /// The name of the value inside that key.
    pub name: String,
    /// Its content.
    pub data: Data,
}

/// Everything the entry in the navigation pane is made of.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// The SID of the signed-in user, in the form `S-1-5-21-…`.
    pub sid: &'a str,
    /// The account identifier (`sub`), last part of the root identifier.
    pub account: &'a str,
    /// What the user reads in the sidebar — end-user text, and the only such text here.
    pub display_name: &'a str,
    /// The full path of the root folder, as the user sees it.
    pub root_path: &'a str,
    /// The program whose icon the row carries; usually the running executable.
    pub program: &'a str,
    /// The undocumented `Flags`; `None` writes no such value (NAMED GAP 2).
    pub flags: Option<u32>,
}

/// The key of one root under HKLM.
pub fn key_of(identifier: &SyncRootIdentifier) -> String {
    format!(r"{SYNC_ROOT_MANAGER}\{}", identifier.as_text())
}

/// `<program>,<index>`, the form `IconResource` is read in.
pub fn icon_resource(program: &str, index: u16) -> String {
    format!("{program},{index}")
}

/// A GUID as the registry writes it: in braces, upper case, in the groups 8-4-4-4-12.
pub fn clsid_text(value: u128) -> String {
    let first = (value >> 96) as u32;
    let second = (value >> 80) as u16;
    let third = (value >> 64) as u16;
    let fourth = (value >> 48) as u16;
    let rest = (value & 0xFFFF_FFFF_FFFF) as u64;
    format!("{{{first:08X}-{second:04X}-{third:04X}-{fourth:04X}-{rest:012X}}}")
}

/// How many bytes a SID with this many sub-authorities takes (`GetLengthSid`).
pub const fn sid_length(sub_authority_count: u8) -> usize {
    SID_HEADER + 4 * sub_authority_count as usize
}

/// A binary SID as text (`S-1-5-21-…`), or `None` if the bytes are not one.
///
/// The layout is the one from MS-DTYP §2.4.2.2: revision, number of sub-authorities, six bytes of
/// identifier authority **big-endian** — the only such field in the structure — and then one
/// little-endian `u32` per sub-authority.
///
/// This is done here, and not with `ConvertSidToStringSidW`, because it is arithmetic: arithmetic
/// can be proven on a machine that is not a Windows one, and a Win32 call cannot. What Windows is
/// still asked for is the token — `platform::win::current_user_sid`.
///
/// An authority that does not fit into 32 bits yields `None`: it would have to be written in a
/// hexadecimal form this function does not build, no user of this client has one (a user's SID
/// carries authority 5, `S-1-5-21-…`), and [`crate::sync_root::check_sid`] would reject it. No
/// text is better than a guessed one.
pub fn sid_text(raw: &[u8]) -> Option<String> {
    let header = raw.get(..SID_HEADER)?;
    let revision = header[0];
    if revision != SID_REVISION {
        return None;
    }
    let authority = header[2..SID_HEADER].iter().fold(0_u64, |value, byte| {
        // Six bytes, most significant first.
        (value << 8) | u64::from(*byte)
    });
    let authority = u32::try_from(authority).ok()?;
    let body = raw.get(SID_HEADER..sid_length(header[1]))?;
    let mut text = format!("S-{revision}-{authority}");
    // The length is a multiple of four by construction, so the remainder is always empty.
    let (sub_authorities, _) = body.as_chunks::<4>();
    for sub_authority in sub_authorities {
        let value = u32::from_le_bytes(*sub_authority);
        text.push('-');
        text.push_str(&value.to_string());
    }
    Some(text)
}

/// Every value of the entry, in the order in which it is written.
///
/// Everything is checked before a single key comes into being: a display name without content, a
/// SID that did not come from Windows, a root path on a network drive. A half-written entry in the
/// registry is worse than none — the row would then stand there and point nowhere.
pub fn values(entry: &Entry) -> Result<Vec<Value>, MirrorError> {
    check_display_name(entry.display_name)?;
    check_root_path(entry.root_path)?;
    // Checks provider name, SID and account, and that the three of them together stay inside the
    // 255 characters a registry key name has.
    let identifier = SyncRootIdentifier::new(entry.sid, entry.account)?;
    let key = key_of(&identifier);

    let mut values = vec![
        Value {
            key: key.clone(),
            name: DISPLAY_NAME_RESOURCE.to_owned(),
            // `REG_EXPAND_SZ` as in `packaging/windows/README.md`; the type also carries the
            // `@program,-id` form of a resource inside the program, which this client does not
            // use. Open: what Windows makes of a `%` in a tenant's name, which it would read
            // as the start of a variable.
            data: Data::TextWithVariables(entry.display_name.to_owned()),
        },
        Value {
            key: key.clone(),
            name: ICON_RESOURCE.to_owned(),
            data: Data::TextWithVariables(icon_resource(entry.program, ICON_INDEX)),
        },
        Value {
            key: key.clone(),
            name: NAMESPACE_CLSID.to_owned(),
            data: Data::Text(clsid_text(NAMESPACE_CLSID_VALUE)),
        },
    ];
    if let Some(flags) = entry.flags {
        values.push(Value { key: key.clone(), name: FLAGS.to_owned(), data: Data::Number(flags) });
    }
    values.push(Value {
        key: format!(r"{key}\{USER_SYNC_ROOTS}"),
        name: entry.sid.to_owned(),
        // The path as the user sees it: without the `\\?\` that only the Win32 calls of this
        // crate need, and with single separators.
        data: Data::Text(unify(without_long_prefix(entry.root_path))),
    });
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::PROVIDER;
    use crate::sync_root::check_sid;

    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-512";
    const ACCOUNT: &str = "usr_01JK4R7ZQ8M3N5P6T9V0WXYZAB";
    const ROOT: &str = r"C:\Users\n\elasticdms";
    const PROGRAM: &str = r"C:\Program Files\elasticdms\elasticdms.exe";

    fn entry() -> Entry<'static> {
        Entry {
            sid: SID,
            account: ACCOUNT,
            display_name: "elasticdms – Example GmbH",
            root_path: ROOT,
            program: PROGRAM,
            flags: None,
        }
    }

    fn value_named<'a>(values: &'a [Value], name: &str) -> Option<&'a Value> {
        values.iter().find(|value| value.name == name)
    }

    #[test]
    fn the_key_is_the_root_identifier_under_the_sync_root_manager() {
        let identifier = SyncRootIdentifier::new(SID, ACCOUNT).unwrap();
        let key = key_of(&identifier);
        assert_eq!(key, format!(r"{SYNC_ROOT_MANAGER}\{PROVIDER}!{SID}!{ACCOUNT}"));
        // The key name is one path part more than the manager's own key, never a second tree.
        assert_eq!(key.matches('\\').count(), SYNC_ROOT_MANAGER.matches('\\').count() + 1);
    }

    #[test]
    fn the_entry_carries_the_four_values_the_documentation_names() {
        let values = values(&entry()).unwrap();
        let names: Vec<&str> = values.iter().map(|value| value.name.as_str()).collect();
        assert_eq!(names, [DISPLAY_NAME_RESOURCE, ICON_RESOURCE, NAMESPACE_CLSID, SID]);
        let key = key_of(&SyncRootIdentifier::new(SID, ACCOUNT).unwrap());
        for value in &values[..3] {
            assert_eq!(value.key, key);
        }
        assert_eq!(values[3].key, format!(r"{key}\{USER_SYNC_ROOTS}"));
    }

    #[test]
    fn the_name_in_the_sidebar_is_the_one_the_app_passed() {
        // End-user text, and the only one in this module: it comes from the app through
        // `edms_core::port::Provisioning` and is not built here.
        let values = values(&entry()).unwrap();
        let display = value_named(&values, DISPLAY_NAME_RESOURCE).unwrap();
        assert_eq!(display.data, Data::TextWithVariables("elasticdms – Example GmbH".to_owned()));
    }

    #[test]
    fn the_icon_names_the_program_and_the_index_inside_it() {
        let values = values(&entry()).unwrap();
        let icon = value_named(&values, ICON_RESOURCE).unwrap();
        assert_eq!(icon.data, Data::TextWithVariables(format!("{PROGRAM},0")));
        // The form also carries a path with variables, which is why the type expands them.
        assert_eq!(
            icon_resource(r"%ProgramFiles%\elasticdms\elasticdms.exe", 0),
            r"%ProgramFiles%\elasticdms\elasticdms.exe,0"
        );
    }

    #[test]
    fn the_path_under_user_sync_roots_is_the_one_the_user_sees() {
        let long = format!(r"\\?\{ROOT}\");
        let values = values(&Entry { root_path: &long, ..entry() }).unwrap();
        assert_eq!(value_named(&values, SID).unwrap().data, Data::Text(ROOT.to_owned()));
    }

    #[test]
    fn the_undocumented_flags_value_is_written_only_when_somebody_has_measured_it() {
        // NAMED GAP 2: nobody has, so nothing is written. A guessed bit field is a guessed
        // behaviour of Explorer.
        assert!(value_named(&values(&entry()).unwrap(), FLAGS).is_none());
        let with_flags = values(&Entry { flags: Some(40), ..entry() }).unwrap();
        assert_eq!(value_named(&with_flags, FLAGS).unwrap().data, Data::Number(40));
    }

    #[test]
    fn nothing_that_was_refused_before_reaches_the_registry() {
        let cases = [
            Entry { sid: "1-5-21-4", ..entry() },
            Entry { display_name: "   ", ..entry() },
            Entry { display_name: "with\u{7}bell", ..entry() },
            Entry { root_path: r"\\server\share\elasticdms", ..entry() },
            Entry { root_path: r"C:\", ..entry() },
            Entry { account: "usr!admin", ..entry() },
            Entry { account: &"a".repeat(255), ..entry() },
        ];
        for case in cases {
            assert!(values(&case).is_err(), "{case:?}");
        }
    }

    #[test]
    fn a_text_goes_into_the_registry_as_utf16_with_its_null_character() {
        let bytes = Data::Text("AB".to_owned()).bytes().unwrap();
        assert_eq!(bytes, [0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
        // Two bytes per unit, and the null character is part of the value.
        let long = Data::TextWithVariables("elasticdms – Example GmbH".to_owned()).bytes().unwrap();
        assert_eq!(long.len(), "elasticdms – Example GmbH".encode_utf16().count() * 2 + 2);
        assert_eq!(&long[long.len() - 2..], [0x00, 0x00]);
    }

    #[test]
    fn a_null_character_inside_a_value_is_refused_instead_of_cutting_it_short() {
        assert!(Data::Text("C:\\a\0\\b".to_owned()).bytes().is_err());
    }

    #[test]
    fn a_number_is_four_bytes_the_way_windows_reads_a_dword() {
        assert_eq!(Data::Number(0).bytes().unwrap(), [0, 0, 0, 0]);
        assert_eq!(Data::Number(40).bytes().unwrap(), [40, 0, 0, 0]);
        assert_eq!(Data::Number(u32::MAX).bytes().unwrap(), [0xFF; 4]);
    }

    #[test]
    fn a_clsid_stands_in_the_form_the_registry_writes_it() {
        assert_eq!(
            clsid_text(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            "{01020304-0506-0708-090A-0B0C0D0E0F10}"
        );
        assert_eq!(clsid_text(0), "{00000000-0000-0000-0000-000000000000}");
        assert_eq!(clsid_text(u128::MAX), "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}");
    }

    #[test]
    fn the_namespace_clsid_stays_the_same_across_versions() {
        // Whoever changes this number leaves the entry of every earlier version standing in every
        // profile it was written into. The test is the lock in front of that.
        assert_eq!(NAMESPACE_CLSID_VALUE, 0xb644_fde4_a535_4d98_b0e3_d6be_0666_47f0);
        assert_eq!(clsid_text(NAMESPACE_CLSID_VALUE), "{B644FDE4-A535-4D98-B0E3-D6BE066647F0}");
        assert_ne!(NAMESPACE_CLSID_VALUE, crate::sync_root::PROVIDER_GUID);
    }

    /// The SID of the test cases as Windows keeps it: `S-1-5-21-1004336348-1177238915-682003330-512`.
    fn raw_sid() -> Vec<u8> {
        let mut raw = vec![SID_REVISION, 5, 0, 0, 0, 0, 0, 5];
        for sub_authority in [21_u32, 1_004_336_348, 1_177_238_915, 682_003_330, 512] {
            raw.extend_from_slice(&sub_authority.to_le_bytes());
        }
        raw
    }

    #[test]
    fn a_sid_from_windows_comes_out_as_the_text_the_key_name_carries() {
        assert_eq!(sid_text(&raw_sid()).as_deref(), Some(SID));
        // The local system: one sub-authority, the same authority.
        assert_eq!(
            sid_text(&[SID_REVISION, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).as_deref(),
            Some("S-1-5-18")
        );
        // Everybody: authority 1, and a SID without any sub-authority stays a SID.
        assert_eq!(
            sid_text(&[SID_REVISION, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]).as_deref(),
            Some("S-1-1-0")
        );
        assert_eq!(sid_text(&[SID_REVISION, 0, 0, 0, 0, 0, 0, 5]).as_deref(), Some("S-1-5"));
    }

    #[test]
    fn what_comes_out_of_the_sid_is_what_the_root_identifier_will_take() {
        // The two checks belong to each other: `check_sid` guards the key name, `sid_text` builds
        // what is guarded. A shape only one of them accepts would be a key nobody finds again.
        let text = sid_text(&raw_sid()).unwrap();
        assert!(check_sid(&text).is_ok(), "{text}");
        assert!(SyncRootIdentifier::new(&text, ACCOUNT).is_ok());
    }

    #[test]
    fn bytes_that_are_not_a_sid_yield_no_text_instead_of_a_guessed_one() {
        assert_eq!(sid_text(&[]), None);
        assert_eq!(sid_text(&[SID_REVISION, 5, 0, 0, 0, 0, 0, 5]), None, "sub-authorities missing");
        assert_eq!(sid_text(&[2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]), None, "revision 2");
        // An authority beyond 32 bits: the hexadecimal form is not built here.
        assert_eq!(sid_text(&[SID_REVISION, 1, 1, 0, 0, 0, 0, 5, 18, 0, 0, 0]), None);
    }

    #[test]
    fn the_length_of_a_sid_follows_its_number_of_sub_authorities() {
        assert_eq!(sid_length(0), SID_HEADER);
        assert_eq!(sid_length(5), raw_sid().len());
        // 15 is the most Windows writes (SID_MAX_SUB_AUTHORITIES, winnt.h).
        assert_eq!(sid_length(15), 68);
    }
}
