//! Which reason arrives in Explorer: `SourceError` → `STATUS_CLOUD_FILE_*`.
//!
//! As a completion status cldflt accepts only `STATUS_CLOUD_FILE_*` and `STATUS_SUCCESS`; any
//! other value becomes `STATUS_CLOUD_FILE_UNSUCCESSFUL` (ns-cfapi-cf_operation_parameters,
//! research note "Windows Cloud Filter API"). A `STATUS_ACCESS_DENIED` would therefore not show
//! "access denied" but "the cloud operation was unsuccessful" — the user would see the same
//! message for an expired sign-in as for revoked access. That is why the mapping lives here, as a
//! pure function, tested.
//!
//! The numbers are the NTSTATUS values from `ntstatus.h` (the same ones are in
//! `windows::Win32::Foundation`); the Windows part checks at compile time that the two agree.

use edms_core::port::SourceError;

/// `STATUS_CLOUD_FILE_ACCESS_DENIED` — "Access to the cloud file is denied."
pub const STATUS_ACCESS_DENIED: i32 = 0xC000_CF18_u32 as i32;
/// `STATUS_CLOUD_FILE_AUTHENTICATION_FAILED` — "The cloud sync provider failed user authentication."
pub const STATUS_LOGIN_FAILED: i32 = 0xC000_CF0F_u32 as i32;
/// `STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE`.
pub const STATUS_NETWORK_NOT_AVAILABLE: i32 = 0xC000_CF11_u32 as i32;
/// `STATUS_CLOUD_FILE_NOT_IN_SYNC` — "The file is not in sync with the cloud."
pub const STATUS_NOT_IN_SYNC: i32 = 0xC000_CF08_u32 as i32;
/// `STATUS_CLOUD_FILE_INVALID_REQUEST` — "The cloud operation is invalid."
pub const STATUS_INVALID_REQUEST: i32 = 0xC000_CF0B_u32 as i32;
/// `STATUS_CLOUD_FILE_REQUEST_CANCELED` — "The cloud operation was canceled by user."
pub const STATUS_CANCELLED: i32 = 0xC000_CF1B_u32 as i32;
/// `STATUS_CLOUD_FILE_IN_USE`.
pub const STATUS_IN_USE: i32 = 0xC000_CF14_u32 as i32;
/// `STATUS_CLOUD_FILE_UNSUCCESSFUL` — "The cloud operation was unsuccessful."
pub const STATUS_UNSUCCESSFUL: i32 = 0xC000_CF12_u32 as i32;

/// The completion reasons this crate reports to cldflt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudStatus {
    /// No access — including the veto against deleting and renaming (requirement 1).
    AccessDenied,
    /// Sign-in required.
    LoginFailed,
    /// Server not reachable.
    NetworkNotAvailable,
    /// The entry is still here locally; on the server it no longer exists.
    NotInSync,
    /// The request makes no sense for this provider (foreign file identity, wrong listing).
    InvalidRequest,
    /// Cancelled.
    Cancelled,
    /// The file is open.
    InUse,
    /// Everything else.
    Unsuccessful,
}

impl CloudStatus {
    /// The NTSTATUS value.
    pub const fn ntstatus(self) -> i32 {
        match self {
            Self::AccessDenied => STATUS_ACCESS_DENIED,
            Self::LoginFailed => STATUS_LOGIN_FAILED,
            Self::NetworkNotAvailable => STATUS_NETWORK_NOT_AVAILABLE,
            Self::NotInSync => STATUS_NOT_IN_SYNC,
            Self::InvalidRequest => STATUS_INVALID_REQUEST,
            Self::Cancelled => STATUS_CANCELLED,
            Self::InUse => STATUS_IN_USE,
            Self::Unsuccessful => STATUS_UNSUCCESSFUL,
        }
    }

    /// The mapping of a source error.
    ///
    /// * `NotFound` → `NOT_IN_SYNC`: there is no status "does not exist any more"; the closest
    ///   documented one is "not in sync with the cloud" — which is exactly the situation: the name
    ///   is still here locally, the server no longer knows the document, and the next
    ///   reconciliation takes the name away. `INVALID_REQUEST` would mean "the provider got its
    ///   arithmetic wrong".
    /// * `Integrity` and `Incomplete` → `UNSUCCESSFUL`, not `VALIDATION_FAILED`: the latter
    ///   belongs to the `VALIDATION_REQUIRED` path, which this crate does not register (the engine
    ///   checks for itself, before the first byte).
    /// * `AnchorExpired` → `UNSUCCESSFUL`: belongs to macOS; if it arrives here it is a bug in the
    ///   source, not a state the user could do anything about.
    pub fn from_source_error(error: &SourceError) -> Self {
        match error {
            SourceError::NotSignedIn => Self::LoginFailed,
            SourceError::NoNetwork => Self::NetworkNotAvailable,
            SourceError::NoAccess => Self::AccessDenied,
            SourceError::NotFound(_) => Self::NotInSync,
            SourceError::Cancelled => Self::Cancelled,
            SourceError::Integrity { .. }
            | SourceError::Incomplete { .. }
            | SourceError::AnchorExpired
            | SourceError::Sink(_)
            | SourceError::Server(_)
            | SourceError::Internal(_) => Self::Unsuccessful,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::checksum::Sha256Value;
    use edms_core::identifier::Identifier;
    use edms_core::namespace::EntryIdentifier;
    use edms_core::port::SinkError;

    #[test]
    fn every_source_error_has_its_status() {
        let cases = [
            (SourceError::NotSignedIn, CloudStatus::LoginFailed),
            (SourceError::NoNetwork, CloudStatus::NetworkNotAvailable),
            (SourceError::NoAccess, CloudStatus::AccessDenied),
            (
                SourceError::NotFound(EntryIdentifier::Container(
                    edms_core::namespace::Container::Case {
                        archive: Identifier::from_value(1),
                        case: Identifier::from_value(2),
                    },
                )),
                CloudStatus::NotInSync,
            ),
            (SourceError::Cancelled, CloudStatus::Cancelled),
            (
                SourceError::Integrity {
                    expected: Sha256Value::from_bytes([1; 32]),
                    actual: Sha256Value::from_bytes([2; 32]),
                },
                CloudStatus::Unsuccessful,
            ),
            (SourceError::Incomplete { expected: 10, actual: 9 }, CloudStatus::Unsuccessful),
            (SourceError::AnchorExpired, CloudStatus::Unsuccessful),
            (SourceError::Sink(SinkError("x".into())), CloudStatus::Unsuccessful),
            (SourceError::Server("x".into()), CloudStatus::Unsuccessful),
            (SourceError::Internal("x".into()), CloudStatus::Unsuccessful),
        ];
        for (error, status) in cases {
            assert_eq!(CloudStatus::from_source_error(&error), status, "{error:?}");
        }
    }

    #[test]
    fn the_values_are_the_ones_from_ntstatus_h() {
        // Copied from ntstatus.h and windows::Win32::Foundation (0.58); the Windows part compares
        // them once more at compile time against the constants of the windows crate.
        assert_eq!(CloudStatus::AccessDenied.ntstatus() as u32, 0xC000_CF18);
        assert_eq!(CloudStatus::LoginFailed.ntstatus() as u32, 0xC000_CF0F);
        assert_eq!(CloudStatus::NetworkNotAvailable.ntstatus() as u32, 0xC000_CF11);
        assert_eq!(CloudStatus::NotInSync.ntstatus() as u32, 0xC000_CF08);
        assert_eq!(CloudStatus::InvalidRequest.ntstatus() as u32, 0xC000_CF0B);
        assert_eq!(CloudStatus::Cancelled.ntstatus() as u32, 0xC000_CF1B);
        assert_eq!(CloudStatus::InUse.ntstatus() as u32, 0xC000_CF14);
        assert_eq!(CloudStatus::Unsuccessful.ntstatus() as u32, 0xC000_CF12);
    }

    #[test]
    fn every_status_is_a_cloud_file_status() {
        // Anything outside 0xC000CFxx would be forced to UNSUCCESSFUL.
        for s in [
            CloudStatus::AccessDenied,
            CloudStatus::LoginFailed,
            CloudStatus::NetworkNotAvailable,
            CloudStatus::NotInSync,
            CloudStatus::InvalidRequest,
            CloudStatus::Cancelled,
            CloudStatus::InUse,
            CloudStatus::Unsuccessful,
        ] {
            assert_eq!((s.ntstatus() as u32) & 0xFFFF_FF00, 0xC000_CF00, "{s:?}");
        }
    }
}
