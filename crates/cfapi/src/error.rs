//! The errors of this layer — values with whole sentences, and their way into the core.
//!
//! [`MirrorError`] is finer-grained than [`PlatformError`]: while setting up, the app shows the
//! exact reason (wrong file system, missing package identity); the engine only needs the
//! distinction "retry / is not here / not set up / operating system". The conversion therefore
//! loses details, never the kind. Where it invents an HRESULT value, it is the one Windows itself
//! reports for the same situation (table at [`MirrorError::hresult`]).

use edms_core::namespace::{Container, EntryIdentifier};
use edms_core::port::{PlatformError, SourceError};

/// `E_INVALIDARG` — Windows' own answer to an invalid parameter.
pub const HRESULT_INVALID: u32 = 0x8007_0057;
/// `E_ACCESSDENIED`.
pub const HRESULT_ACCESS_DENIED: u32 = 0x8007_0005;
/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
pub const HRESULT_ALREADY_PRESENT: u32 = 0x8007_00B7;
/// `E_UNEXPECTED`.
pub const HRESULT_UNEXPECTED: u32 = 0x8000_FFFF;

/// Why the mirror could not do something.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MirrorError {
    /// A file or folder name that NTFS would reject.
    #[error("the name `{name}` is not allowed on Windows: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Why, as a sentence fragment.
        reason: &'static str,
    },
    /// The entry identifier does not fit into the file identity of a placeholder.
    #[error(
        "the identifier `{identifier}` is too long for a file identity ({length} bytes; Windows \
         allows at most 4096, CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH)"
    )]
    IdentifierTooLong {
        /// The identifier as text.
        identifier: String,
        /// Its length in bytes.
        length: usize,
    },
    /// The file identity of a placeholder is not an entry identifier of this program.
    #[error("the file identity of the placeholder cannot be read: {0}")]
    IdentifierUnreadable(String),
    /// The source delivered a child that does not belong in this container.
    #[error("the source delivers `{identifier}` as a child of `{container}`; it belongs elsewhere")]
    WrongLocation {
        /// The entry.
        identifier: EntryIdentifier,
        /// The container whose listing contained it.
        ///
        /// In a box, and only for its size: an entry identifier is 80 bytes and a container 48
        /// since a case file (Akte) carries its archive (namespace v2 §1), and the two together
        /// are exactly the 128 bytes from which on `clippy::result_large_err` counts every
        /// `Result` of this crate as expensive — and every function here returns one. Measured,
        /// `the_error_stays_small_enough_to_travel_in_every_result`.
        container: Box<Container>,
    },
    /// A container as a file, or a document as a folder.
    #[error(
        "the source delivers `{0}` in the wrong kind (a folder instead of a file, or the other \
         way round)"
    )]
    WrongKind(EntryIdentifier),
    /// Two siblings whose names NTFS considers equal.
    #[error(
        "the source delivers the name `{0}` twice in one folder (NTFS does not tell upper and \
         lower case apart)"
    )]
    DuplicateName(String),
    /// The same identifier twice in one listing.
    #[error("the source delivers `{0}` twice in one folder")]
    DuplicateIdentifier(EntryIdentifier),
    /// The provider name is no good as the first part of the root identifier.
    #[error("the provider name `{name}` is no good for the sync root: {reason}")]
    InvalidProvider {
        /// The name.
        name: String,
        /// Why.
        reason: &'static str,
    },
    /// The account identifier is no good as the last part of the root identifier.
    #[error("the account identifier `{account}` is no good for the sync root: {reason}")]
    InvalidAccount {
        /// The account identifier (`sub`).
        account: String,
        /// Why.
        reason: &'static str,
    },
    /// The finished root identifier is too long for a registry key.
    #[error(
        "the sync root identifier is {length} characters long; as the name of a registry key \
         Windows allows at most 255"
    )]
    SyncRootIdentifierTooLong {
        /// Length in UTF-16 units.
        length: usize,
    },
    /// The display name is empty or contains control characters.
    #[error("the display name of the sync root is invalid: {reason}")]
    InvalidDisplayName {
        /// Why.
        reason: &'static str,
    },
    /// The root folder is no good.
    #[error("the folder `{path}` is no good as the root of the mirror: {reason}")]
    InvalidRoot {
        /// The path as the app passed it.
        path: String,
        /// Why.
        reason: &'static str,
    },
    /// The root folder does not sit on NTFS.
    #[error(
        "the folder `{path}` sits on a drive with {file_system}; the Cloud Filter API works \
         only on NTFS"
    )]
    NoNtfs {
        /// The path.
        path: String,
        /// The reported file system.
        file_system: String,
    },
    /// Windows is older than 10 1709.
    #[error(
        "Windows build {build} is too old; the folder client needs Windows 10, version 1709 \
         (build 16299), or newer"
    )]
    WindowsTooOld {
        /// The reported build.
        build: u32,
    },
    /// `StorageProviderSyncRootManager.IsSupported()` says no.
    #[error("Windows reports that sync roots are not supported on this device")]
    NotSupported,
    /// `E_ACCESSDENIED` on registration or `IsSupported` — experience says a missing package
    /// identity (ADR-D06 §7).
    #[error(
        "Windows refuses to register the sync root (E_ACCESSDENIED); a program without a \
         package identity may not do that. elasticdms has to be set up through the sparse \
         package (packaging/windows/README.md)"
    )]
    PackageIdentityMissing,
    /// Another provider's root hangs off the root folder.
    #[error(
        "the folder `{path}` already carries the sync root `{identifier}` of another provider; \
         the folder client does not overwrite it"
    )]
    ForeignRoot {
        /// The folder.
        path: String,
        /// The root identifier found there.
        identifier: String,
    },
    /// A different account is already provisioned.
    #[error(
        "the mirror is set up for a different account; sign out first (clearing everything), \
         then provision again"
    )]
    OtherAccount,
    /// Not yet, or no longer, provisioned.
    #[error("the folder is not set up on this device")]
    NotReadyPosed,
    /// The entry is not on disk.
    #[error("the entry `{0}` is not on this device")]
    NotFound(EntryIdentifier),
    /// A program holds the file open.
    #[error("the file `{0}` is open at the moment; the operation will be retried")]
    InUse(EntryIdentifier),
    /// Dehydrating makes no sense for folders.
    #[error("`{0}` is a folder; folders have no content to free up")]
    FolderNotDehydratable(EntryIdentifier),
    /// The path of the running program is not to be had — only the icon of the navigation pane
    /// entry hangs on it, which is why this never stops a sign-in.
    #[error("the path of the running program cannot be determined: {0}")]
    ProgramPathUnknown(String),
    /// A Windows call failed.
    #[error("Windows reports {code:#010x} at `{flow}`: {text}")]
    OperatingSystem {
        /// Which call, e.g. `CfUpdatePlaceholder`.
        flow: &'static str,
        /// HRESULT.
        code: i32,
        /// The system's message.
        text: String,
    },
    /// The source could not deliver (only in follow-up work that asks it itself).
    #[error(transparent)]
    Source(#[from] SourceError),
    /// A bug in this program.
    #[error("internal error in the Windows platform layer: {0}")]
    Internal(String),
}

impl MirrorError {
    /// The HRESULT value under which the error arrives at the engine.
    ///
    /// | Kind | Value | Why this one |
    /// |---|---|---|
    /// | operating system | the reported one | it is genuine |
    /// | package identity missing | `E_ACCESSDENIED` | that is how Windows reports it |
    /// | foreign root, other account | `ERROR_ALREADY_EXISTS` | there is already a root there |
    /// | internal, source | `E_UNEXPECTED` | no state of this system |
    /// | inputs (names, identifiers, listings) | `E_INVALIDARG` | Windows' answer to the same inputs |
    pub fn hresult(&self) -> u32 {
        match self {
            Self::OperatingSystem { code, .. } => as_u32(*code),
            Self::PackageIdentityMissing => HRESULT_ACCESS_DENIED,
            Self::ForeignRoot { .. } | Self::OtherAccount => HRESULT_ALREADY_PRESENT,
            Self::Internal(_) | Self::Source(_) => HRESULT_UNEXPECTED,
            _ => HRESULT_INVALID,
        }
    }
}

/// An HRESULT as an unsigned number, the way Windows writes it (`0x80070005`, not `-2147024891`).
pub const fn as_u32(code: i32) -> u32 {
    u32::from_ne_bytes(code.to_ne_bytes())
}

impl From<MirrorError> for PlatformError {
    fn from(error: MirrorError) -> Self {
        match error {
            MirrorError::NotReadyPosed => PlatformError::NotReadyPosed,
            MirrorError::NotFound(k) => PlatformError::NotFound(k),
            MirrorError::InUse(k) => PlatformError::InUse(k),
            // The fixed texts lose the build number and the file system; the app shows both
            // while setting up, through `platform_available`, before it ever gets here.
            MirrorError::FolderNotDehydratable(_) => {
                PlatformError::NotSupported("folders on Windows have no content to free up")
            }
            MirrorError::WindowsTooOld { .. } => PlatformError::NotSupported(
                "the folder client needs Windows 10, version 1709, or newer",
            ),
            MirrorError::NotSupported => {
                PlatformError::NotSupported("Windows does not support sync roots on this device")
            }
            MirrorError::NoNtfs { .. } => {
                PlatformError::NotSupported("the Cloud Filter API works only on NTFS drives")
            }
            MirrorError::OperatingSystem { flow, code, text } => PlatformError::OperatingSystem {
                code: i64::from(as_u32(code)),
                text: format!("{flow}: {text}"),
            },
            other => PlatformError::OperatingSystem {
                code: i64::from(other.hresult()),
                text: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::Identifier;
    use edms_core::namespace::Location;

    fn document() -> EntryIdentifier {
        EntryIdentifier::Document {
            location: Location::Case {
                archive: Identifier::from_value(1),
                case: Identifier::from_value(2),
            },
            document: Identifier::from_value(2),
        }
    }

    #[test]
    fn the_error_stays_small_enough_to_travel_in_every_result() {
        // Every function of this crate returns `Result<_, MirrorError>`; from 128 bytes on,
        // `clippy::result_large_err` calls that expensive. Whoever adds a field here should read
        // it in a test and not in the build of the release.
        assert!(
            size_of::<MirrorError>() < 128,
            "the error is {} bytes; the entry identifier alone is {}",
            size_of::<MirrorError>(),
            size_of::<EntryIdentifier>()
        );
    }

    #[test]
    fn in_use_arrives_at_the_engine_as_retryable() {
        let p: PlatformError = MirrorError::InUse(document()).into();
        assert_eq!(p, PlatformError::InUse(document()));
        let p: PlatformError = MirrorError::NotFound(document()).into();
        assert_eq!(p, PlatformError::NotFound(document()));
    }

    #[test]
    fn an_hresult_is_passed_on_unsigned() {
        // E_ACCESSDENIED as an i32 is negative; at the engine 0x80070005 should stand, not a
        // value nobody finds in an error table.
        let f = MirrorError::OperatingSystem {
            flow: "CfConnectSyncRoot",
            code: 0x8007_0005_u32 as i32,
            text: "access denied".into(),
        };
        assert!(f.to_string().contains("0x80070005"), "{f}");
        let PlatformError::OperatingSystem { code, text } = PlatformError::from(f) else {
            panic!("operating system error expected");
        };
        assert_eq!(code, 0x8007_0005);
        assert!(text.starts_with("CfConnectSyncRoot: "));
    }

    #[test]
    fn a_missing_package_identity_names_the_way_out() {
        let f = MirrorError::PackageIdentityMissing;
        assert!(f.to_string().contains("packaging/windows/README.md"));
        assert_eq!(f.hresult(), HRESULT_ACCESS_DENIED);
    }

    #[test]
    fn an_invalid_input_is_not_a_system_state() {
        let f = MirrorError::InvalidName { name: "a:b".into(), reason: "a forbidden character" };
        assert_eq!(f.hresult(), HRESULT_INVALID);
        assert_eq!(MirrorError::Internal("x".into()).hresult(), HRESULT_UNEXPECTED);
    }
}
