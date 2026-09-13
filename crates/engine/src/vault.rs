//! The vault: where secrets lie — and that is **never** the database.
//!
//! Two things this workstation has to keep across a restart, and both are secrets: the **private
//! device key** (with it the device proves its identity) and the **refresh token** (with it the
//! session lives on). ADR-D03, point 4 says where they belong: in the operating system's keychain.
//! A SQLite file is gone with one copy command; a refresh token inside it would be a session that
//! lives on at any other machine — and that under the name of a human being who knows nothing
//! about it.
//!
//! The engine therefore knows only this trait. The one implementation that really speaks to the
//! operating system (Windows Credential Manager, macOS Keychain) belongs in the app: it is the only
//! process with an identity a keychain hangs off. Here stands the counterpart for tests
//! ([`StoreVault`]) — and it is expressly **no** substitute, because it does not survive the
//! process.

use std::collections::BTreeMap;
use std::fmt;

/// Slot of the private device key (PKCS#8 DER).
pub const SLOT_DEVICE_KEY: &str = "device-key";

/// Slot of the private session key (PKCS#8 DER).
///
/// It survives the restart, because the refresh token is bound to its thumbprint (RFC 9449 §5):
/// with a fresh key every renewal after a restart would be `invalid_grant` — and the human being
/// would have to sign in anew daily without learning why.
pub const SLOT_SESSION_KEY: &str = "session-key";

/// Slot of the refresh token.
pub const SLOT_REFRESH_TOKEN: &str = "refresh-token";

/// All slots a sign-out empties — the device key belongs to the machine and stays.
pub const SESSION_SLOTS: &[&str] = &[SLOT_SESSION_KEY, SLOT_REFRESH_TOKEN];

/// Why the vault does not deliver or does not accept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The keychain is not reachable (locked, service off, no user profile).
    #[error("the operating system's keychain cannot be reached: {0}")]
    NotReachable(String),

    /// The operating system denies access.
    #[error("the operating system denies access to the keychain: {0}")]
    Denied(String),

    /// In the slot stands something the engine cannot read.
    #[error("slot `{slot}` holds no usable value: {reason}")]
    Corrupt {
        /// Which slot.
        slot: String,
        /// What it is down to.
        reason: String,
    },
}

/// Where secrets lie.
///
/// `read` takes `&self`, `write` and `delete` take `&mut self`: a keychain has exactly one writer,
/// and the type says so — the same separation as in `edms_store::Store`.
pub trait Vault: Send + Sync {
    /// The content of a slot; `None` when it is empty.
    ///
    /// # Errors
    ///
    /// When the keychain is not reachable or denies access — **not** when the slot is empty.
    /// "Empty" is a state, not an error.
    fn read(&self, slot: &str) -> Result<Option<Vec<u8>>, VaultError>;

    /// Puts a value into a slot; an existing one is replaced.
    ///
    /// # Errors
    ///
    /// When the keychain is not reachable or denies access.
    fn write(&mut self, slot: &str, value: &[u8]) -> Result<(), VaultError>;

    /// Empties a slot. Called twice it is harmless.
    ///
    /// # Errors
    ///
    /// When the keychain is not reachable or denies access.
    fn delete(&mut self, slot: &str) -> Result<(), VaultError>;
}

/// A vault in memory — for tests and for the demo run without a server.
///
/// It does not survive the process, and that is on purpose: a "substitute vault" that wrote to the
/// disk would be exactly the mistake ADR-D03 forbids, only with a reassuring name.
#[derive(Default)]
pub struct StoreVault {
    slots: BTreeMap<String, Vec<u8>>,
}

/// `Debug` names the occupied slots and never their content: in them lie the private device key
/// and the refresh token, and a log line `{:?}` is not to spread them — the same rule as for
/// [`edms_crypto::key::SoftwareKey`] and `edms_bridge::Rendezvous`. The slot names are the public
/// constants above, so the type stays diagnosable.
impl fmt::Debug for StoreVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreVault").field("occupied_slots", &self.slots.keys()).finish()
    }
}

impl StoreVault {
    /// An empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many slots are occupied — for assertions after the sign-out.
    pub fn occupied_slots(&self) -> usize {
        self.slots.len()
    }

    /// Whether a slot is occupied.
    pub fn has(&self, slot: &str) -> bool {
        self.slots.contains_key(slot)
    }
}

impl Vault for StoreVault {
    fn read(&self, slot: &str) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self.slots.get(slot).cloned())
    }

    fn write(&mut self, slot: &str, value: &[u8]) -> Result<(), VaultError> {
        self.slots.insert(slot.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, slot: &str) -> Result<(), VaultError> {
        self.slots.remove(slot);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_slot_is_not_an_error_but_none() {
        let vault = StoreVault::new();
        assert_eq!(vault.read(SLOT_REFRESH_TOKEN), Ok(None));
    }

    #[test]
    fn written_read_deleted() {
        let mut vault = StoreVault::new();
        vault.write(SLOT_REFRESH_TOKEN, b"rt_1").unwrap();
        assert_eq!(vault.read(SLOT_REFRESH_TOKEN).unwrap().as_deref(), Some(&b"rt_1"[..]));
        vault.write(SLOT_REFRESH_TOKEN, b"rt_2").unwrap();
        assert_eq!(vault.read(SLOT_REFRESH_TOKEN).unwrap().as_deref(), Some(&b"rt_2"[..]));
        vault.delete(SLOT_REFRESH_TOKEN).unwrap();
        vault.delete(SLOT_REFRESH_TOKEN).unwrap();
        assert_eq!(vault.read(SLOT_REFRESH_TOKEN).unwrap(), None);
        assert_eq!(vault.occupied_slots(), 0);
    }

    #[test]
    fn the_debug_line_names_the_slots_and_not_the_secrets() {
        // Not a test double only: `EDMS_VAULT=memory` puts this vault into a shipped build
        // (`crates/app/src/wiring.rs`), and what `KeyBundle::set_up` then writes into it is the
        // private device key and the refresh token. A `{:?}` of it is therefore reachable outside
        // tests, and it has to stay harmless there.
        let mut vault = StoreVault::new();
        vault.write(SLOT_DEVICE_KEY, b"\x30\x81\x87\x02\x01\x00 not a real key").unwrap();
        vault.write(SLOT_REFRESH_TOKEN, b"rt_super_secret_value").unwrap();
        let line = format!("{vault:?}");
        assert!(line.contains(SLOT_DEVICE_KEY), "{line}");
        assert!(line.contains(SLOT_REFRESH_TOKEN), "{line}");
        assert!(!line.contains("rt_super_secret_value"), "{line}");
        // Nor the bytes: a `Vec<u8>` prints as the numbers of its elements, and no slot name
        // carries a digit.
        assert!(!line.chars().any(|c| c.is_ascii_digit()), "{line}");
    }

    #[test]
    fn the_device_key_does_not_belong_to_the_slots_of_the_session() {
        // On a sign-out the device stays set up (edms_store::Session::signed_out): a sign-out that
        // took the device key with it would demand a new enrolment together with a code from the
        // console — for an operation the user sets off himself.
        assert!(!SESSION_SLOTS.contains(&SLOT_DEVICE_KEY));
        assert!(SESSION_SLOTS.contains(&SLOT_REFRESH_TOKEN));
        assert!(SESSION_SLOTS.contains(&SLOT_SESSION_KEY));
    }
}
