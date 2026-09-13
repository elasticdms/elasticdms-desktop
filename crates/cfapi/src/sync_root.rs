//! The marks of the sync root — everything `CfRegisterSyncRoot` needs, as pure values.
//!
//! Registration goes through **Win32 `CfRegisterSyncRoot`**, not through WinRT
//! `StorageProviderSyncRootManager.Register` (ADR-D06 §7, corrected there). The reason is measured,
//! not assumed: `Register` from a process **without package identity** is reported to fail with
//! `E_ACCESSDENIED` — Microsoft reproduced that themselves. Nextcloud has shipped unpackaged for
//! years and uses `CfRegisterSyncRoot` together with registry keys; that is the only arrangement
//! demonstrably running in a shipped unpackaged product (02-platform-decision §1.2). **Never both
//! ways for the same root**: Microsoft says explicitly that exactly one registration API is to be
//! used, and two registrations would mean two states over the same folder.
//!
//! What this module settles goes in two directions:
//!
//! * into `CF_SYNC_REGISTRATION` — provider name, provider version, fixed provider GUID and the
//!   **root identity**: the account identifier as bytes. cldflt hands it back in every callback as
//!   `SyncRootIdentity`; by it the process recognises whether the callback belongs to *this*
//!   sign-in or to a root left behind by an earlier session.
//! * into the name of the registry key under
//!   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\<Identifier>` —
//!   [`SyncRootIdentifier`], the three-part `<provider>!<SID>!<account>`. What goes into that key
//!   stands in [`crate::navigation_pane`]: it is written at sign-in and removed again at sign-out.
//!   The half under HKCU is still missing, and without it the row in the navigation pane may stay
//!   away all the same (`packaging/windows/README.md`); the folder is fully usable through its
//!   path either way.

use crate::checks::{
    PROVIDER, SEPARATOR_SYNC_ROOT_IDENTIFIER, check_account, check_provider,
    check_sync_root_identifier_length,
};
use crate::error::MirrorError;

/// The version of the provider, as it stands in `CF_SYNC_REGISTRATION::ProviderVersion`.
///
/// Windows does not compare it, it only displays it; it is a constant here all the same, so that a
/// customer's bug report can say which version created the root.
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The fixed provider identifier in `CF_SYNC_REGISTRATION::ProviderId`.
///
/// [GAP → PROPOSAL] Neither the requirements nor the contract name a GUID; but it has to be **the
/// same** across all versions and all machines, otherwise Windows takes every new version for a
/// different provider and leaves the old root standing as a corpse. So it was rolled once, written
/// down here and never changed again.
pub const PROVIDER_GUID: u128 = 0x7b3a_1f52_9c84_4d6e_8f21_5a0c_6e2b_9d47;

/// The root identity for `CF_SYNC_REGISTRATION::SyncRootIdentity`.
///
/// The account identifier (`sub`) as UTF-8, without a trailing null character: cldflt treats it as
/// an opaque block with a length, not as a string. It is the value by which a callback recognises
/// which sign-in it belongs to — requirement 4 ("view and placeholder listing are bound to the
/// user"): a callback with a foreign identity is answered, but never with data of the signed-in
/// user.
pub fn identity(account: &str) -> Result<Vec<u8>, MirrorError> {
    check_account(account)?;
    Ok(account.as_bytes().to_vec())
}

/// The identifier of the root: `<provider>!<SID>!<account>`.
///
/// The same three-part form that `StorageProviderSyncRootManager` demands too — Windows names the
/// registry key after it, and Explorer reads the user out of it. The value is built and checked
/// here so that a part that is too long, or one shot through with `!`, shows up before anything is
/// written into the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRootIdentifier(String);

impl SyncRootIdentifier {
    /// Builds the identifier from the SID of the signed-in user and the account identifier.
    pub fn new(sid: &str, account: &str) -> Result<Self, MirrorError> {
        check_provider(PROVIDER)?;
        check_sid(sid)?;
        check_account(account)?;
        let text = format!(
            "{PROVIDER}{SEPARATOR_SYNC_ROOT_IDENTIFIER}{sid}{SEPARATOR_SYNC_ROOT_IDENTIFIER}{account}"
        );
        check_sync_root_identifier_length(text.encode_utf16().count())?;
        Ok(Self(text))
    }

    /// The identifier as text.
    pub fn as_text(&self) -> &str {
        &self.0
    }

    /// The three parts: provider, SID, account.
    pub fn parts(&self) -> Option<(&str, &str, &str)> {
        let mut t = self.0.split(SEPARATOR_SYNC_ROOT_IDENTIFIER);
        match (t.next(), t.next(), t.next(), t.next()) {
            (Some(a), Some(b), Some(c), None) => Some((a, b, c)),
            _ => None,
        }
    }
}

/// Checks a Windows SID in text form (`S-1-5-21-…`).
///
/// What is checked is the shape, not the existence: a SID that does not look like this did not
/// come from the access token of the process ([`crate::navigation_pane::sid_text`]) but from a
/// setting or a bug — and a registry key with a guessed name would be a root nobody finds again.
pub fn check_sid(sid: &str) -> Result<(), MirrorError> {
    let error = |reason| Err(MirrorError::InvalidAccount { account: sid.to_owned(), reason });
    let Some(rest) = sid.strip_prefix("S-") else {
        return error("a SID begins with `S-`");
    };
    let mut parts = rest.split('-');
    let enough = parts.clone().count() >= 3;
    if !enough {
        return error("a SID has at least a revision, an authority and one sub-authority");
    }
    if !parts.all(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())) {
        return error("the parts of a SID are decimal numbers");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-512";
    const ACCOUNT: &str = "usr_01JK4R7ZQ8M3N5P6T9V0WXYZAB";

    #[test]
    fn the_root_identifier_has_exactly_three_parts() {
        let k = SyncRootIdentifier::new(SID, ACCOUNT).unwrap();
        assert_eq!(k.as_text(), format!("elasticdms!{SID}!{ACCOUNT}"));
        assert_eq!(k.parts(), Some((PROVIDER, SID, ACCOUNT)));
    }

    #[test]
    fn an_exclamation_mark_in_the_account_does_not_reach_the_registry() {
        // Four parts would be a key name neither Explorer nor this crate can take apart.
        let f = SyncRootIdentifier::new(SID, "usr!admin").unwrap_err();
        assert!(matches!(f, MirrorError::InvalidAccount { .. }), "{f}");
    }

    #[test]
    fn an_identifier_that_is_too_long_is_rejected_before_windows_sees_it() {
        let account = "a".repeat(255);
        let f = SyncRootIdentifier::new(SID, &account).unwrap_err();
        assert!(matches!(f, MirrorError::SyncRootIdentifierTooLong { .. }), "{f}");
    }

    #[test]
    fn only_a_sid_in_the_shape_windows_uses_gets_through() {
        assert!(check_sid(SID).is_ok());
        assert!(check_sid("S-1-5-18").is_ok());
        for bad in ["", "S-1", "1-5-21-1", "S-1-5-x", "S-1-5-21-", "s-1-5-18"] {
            assert!(check_sid(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_root_identity_is_the_account_identifier_without_a_null_character() {
        assert_eq!(identity(ACCOUNT).unwrap(), ACCOUNT.as_bytes());
        assert!(identity("usr!admin").is_err());
        assert!(identity("").is_err());
    }

    #[test]
    fn the_provider_identifier_stays_the_same_across_versions() {
        // If anyone changes this number, Windows takes the next version for a different provider
        // and leaves the old root standing. The test is the lock in front of that.
        assert_eq!(PROVIDER_GUID, 0x7b3a_1f52_9c84_4d6e_8f21_5a0c_6e2b_9d47);
        assert!(!PROVIDER_VERSION.is_empty());
    }
}
