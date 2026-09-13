//! Which key proves a call and which token authorises it.
//!
//! The two are kept apart, because they have to be:
//!
//! * At the token fetch there is a proof, but no token yet.
//! * The **device** key proves what runs under the device token — `/v1/devices/me`, `:heartbeat`,
//!   `/v1/server-keys`, `/v1/delivery/*`. An erasure has to reach a device even when nobody is
//!   signed in, and precisely then pinned copies are still lying on the disk (contract §7.0.6).
//! * The **session** key proves everything a human being answers for: listings, content, ingest.
//!   The device key is long-lived and attests the identity of the device; using it for every
//!   request would turn every proof into an opportunity to use it (contract §7.0.9).

use std::fmt;
use std::sync::Arc;

use edms_crypto::key::SigningKey;

use crate::secret::Secret;

/// Which of the two keys is meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyBinding {
    /// The long-lived key of this workstation (enrolment, `private_key_jwt`).
    Device,
    /// The key of the running user session; it is forgotten on sign-out.
    Session,
}

impl fmt::Display for KeyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The two words are spliced into the text of `NetworkError::NoKey` and `NoToken`
        // ("Without the device key …"); they move with those messages.
        f.write_str(match self {
            Self::Device => "device",
            Self::Session => "session",
        })
    }
}

/// Where proof keys and tokens come from.
///
/// This crate holds **no** secrets. On every call it asks where they lie: in the operating system's
/// keychain, never in the database (ADR-D03, point 4). A SQLite file is gone with one copy command;
/// a refresh token inside it would be a session that lives on at any other machine.
pub trait KeySource: Send + Sync {
    /// The proof key of this binding, or `None` when there is none.
    ///
    /// `None` for the device means "not set up", `None` for the session "nobody signed in". Both
    /// are a state, not an error — the call ends with [`crate::NetworkError::NoKey`] and the
    /// interface says what is to be done.
    fn key(&self, binding: KeyBinding) -> Option<Arc<dyn SigningKey>>;

    /// The `kid` of the **device** key, as it was reported at the enrolment.
    ///
    /// It stands in the head of every client assertion (`private_key_jwt`, RFC 7523 §2.2). With it
    /// the server looks up the deposited public key; a wrong or missing `kid` ends in
    /// `400 device-assertion-invalid`, and without any hint as to which of the two keys was
    /// meant.
    fn device_kid(&self) -> Option<String>;

    /// The access token of this binding.
    fn token(&self, binding: KeyBinding) -> Option<Secret>;
}

/// What a single call carries in the way of proof and token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallBinding {
    /// Neither proof nor token.
    ///
    /// Exactly three calls in the whole contract: the enrolment (the enrolment code **is** the
    /// credential, and the server learns the key only with this request — it cannot check a proof
    /// over it beforehand, 03 §6.2.1), the start of the device flow (RFC 9449 §5 binds the future
    /// token over `dpop_jkt`, not over a proof) and the two `.well-known` documents.
    Without,
    /// Proof with the device key, no token — the fetch of the device token.
    DeviceWithoutToken,
    /// Proof with the session key, no token — device-code fetch, renewal, revocation.
    SessionWithoutToken,
    /// Device key and device token.
    Device,
    /// Session key and user token.
    Session,
}

impl CallBinding {
    /// Which key produces the proof; `None` means: no `DPoP` header.
    pub(crate) const fn key(self) -> Option<KeyBinding> {
        match self {
            Self::Without => None,
            Self::DeviceWithoutToken | Self::Device => Some(KeyBinding::Device),
            Self::SessionWithoutToken | Self::Session => Some(KeyBinding::Session),
        }
    }

    /// Which token stands in the `Authorization` header; `None` means: no header.
    pub(crate) const fn token(self) -> Option<KeyBinding> {
        match self {
            Self::Without | Self::DeviceWithoutToken | Self::SessionWithoutToken => None,
            Self::Device => Some(KeyBinding::Device),
            Self::Session => Some(KeyBinding::Session),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enrolment_carries_neither_proof_nor_token() {
        assert_eq!(CallBinding::Without.key(), None);
        assert_eq!(CallBinding::Without.token(), None);
    }

    #[test]
    fn a_token_fetch_proves_without_authorising() {
        assert_eq!(CallBinding::SessionWithoutToken.key(), Some(KeyBinding::Session));
        assert_eq!(CallBinding::SessionWithoutToken.token(), None);
        assert_eq!(CallBinding::DeviceWithoutToken.key(), Some(KeyBinding::Device));
        assert_eq!(CallBinding::DeviceWithoutToken.token(), None);
    }

    #[test]
    fn the_delivery_channel_and_the_listings_hang_off_different_keys() {
        assert_eq!(CallBinding::Device.key(), Some(KeyBinding::Device));
        assert_eq!(CallBinding::Session.key(), Some(KeyBinding::Session));
        assert_ne!(CallBinding::Device.token(), CallBinding::Session.token());
    }
}
