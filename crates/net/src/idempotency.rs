//! The idempotency key of a write attempt (03 §6.0.10, obligation AND-2).
//!
//! Binding is: **one ULID per attempt**, produced when the row that records the attempt is created,
//! stored there, unchanged on every technical retry of the same payload — and **new** as soon as
//! the payload changes.
//!
//! `Idempotency-Key = commandId` would be the obvious mistake: it would block every second
//! acknowledgement of the same command that differs in content with `422 idempotency-key-reuse` —
//! and that is exactly the one needed when `FAILED` later becomes `APPLIED` (contract §7.3.6).
//! Hence the key is a type of its own here, one that does not even accept an identifier with a
//! prefix.

use std::fmt;

use edms_core::identifier::{ALPHABET, LENGTH};
use edms_core::time::Timestamp;
use edms_crypto::{CryptoError, random};

/// Why a string is not an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdempotencyError {
    /// Wrong length.
    #[error("an idempotency key is a ULID of {LENGTH} characters; `{0}` has {n}", n = .0.chars().count())]
    Length(String),

    /// A character outside the Crockford alphabet — or a prefix such as `cmd_`.
    #[error(
        "`{value}` is no ULID: the character `{character}` does not stand in the Crockford \
         alphabet. An idempotency key is a ULID per attempt, not the identifier of the command"
    )]
    Character {
        /// The rejected string.
        value: String,
        /// The first character that does not fit.
        character: char,
    },
}

/// A ULID that names exactly one write attempt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Reads a stored key.
    ///
    /// # Errors
    ///
    /// Everything that is not a 26-character Crockford base32 sequence.
    pub fn read(value: &str) -> Result<Self, IdempotencyError> {
        if value.chars().count() != LENGTH {
            return Err(IdempotencyError::Length(value.to_owned()));
        }
        if let Some(character) =
            value.chars().find(|c| !ALPHABET.contains(&u8::try_from(*c).unwrap_or(b'?')))
        {
            return Err(IdempotencyError::Character { value: value.to_owned(), character });
        }
        Ok(Self(value.to_owned()))
    }

    /// Produces a new key for **this** attempt.
    ///
    /// The time part of the ULID makes the order in the server log readable; the uniqueness is
    /// carried by the random part from `edms-crypto`.
    ///
    /// # Errors
    ///
    /// The operating system's randomness delivers nothing.
    pub fn generate(time: Timestamp) -> Result<Self, CryptoError> {
        Ok(Self(random::ulid(time)?))
    }

    /// The value for the `Idempotency-Key` header.
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ulid_is_accepted() {
        let key =
            IdempotencyKey::read("01JKC6F8G0H2J4K6M8N0P2Q4R6").expect("26 Crockford characters");
        assert_eq!(key.value(), "01JKC6F8G0H2J4K6M8N0P2Q4R6");
        assert_eq!(key.to_string(), "01JKC6F8G0H2J4K6M8N0P2Q4R6");
    }

    #[test]
    fn a_command_identifier_is_not_an_idempotency_key() {
        let error = IdempotencyKey::read("cmd_01JKC4D6E8F0G2H4J6K8M0N2P4")
            .expect_err("the prefix belongs to the identifier, not to the key");
        assert!(matches!(error, IdempotencyError::Length(_)));
    }

    #[test]
    fn lowercase_letters_and_ambiguous_characters_are_rejected() {
        for value in ["01jkc6f8g0h2j4k6m8n0p2q4r6", "01JKC6F8G0H2J4K6M8N0P2Q4RI"] {
            let error = IdempotencyKey::read(value).expect_err("not Crockford");
            assert!(matches!(error, IdempotencyError::Character { .. }), "{value}");
        }
    }

    #[test]
    fn a_produced_key_reads_itself_back_in() {
        let time = Timestamp::from_unix_millis(1_788_336_862_000);
        let first = IdempotencyKey::generate(time).expect("randomness");
        let second = IdempotencyKey::generate(time).expect("randomness");
        assert_eq!(IdempotencyKey::read(first.value()).as_ref(), Ok(&first));
        assert_ne!(second, first, "a key of its own per attempt, not per point in time");
    }
}
