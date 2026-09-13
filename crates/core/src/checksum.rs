//! Checksums as they stand on the wire: `sha256:<64 hex digits>` (03 §6.0).
//!
//! The core computes no checksum (that is `edms-crypto`'s job); it only holds one and compares.
//! The comparison is the place where a hydration must fail when the server delivers a truncated
//! body: `OpenVerified` notices the hash error only at the last `Read`, after `200` and the
//! headers have already been sent (architecture.md, blob path). The client then sees a short
//! body and no error status — and only this comparison turns that into a failed hydration
//! instead of a mutilated file.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Length of a SHA-256 value in bytes.
pub const SHA256_BYTES: usize = 32;

/// The prefix of the wire form.
pub const PREFIX_SHA256: &str = "sha256:";

/// A SHA-256 value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Value([u8; SHA256_BYTES]);

/// Why a string is not a checksum.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{text}` is not a checksum of the form sha256:<64 lower-case hex digits>")]
pub struct ChecksumError {
    text: String,
}

impl Sha256Value {
    /// From the 32 raw bytes.
    pub const fn from_bytes(bytes: [u8; SHA256_BYTES]) -> Self {
        Self(bytes)
    }

    /// The 32 raw bytes.
    pub const fn bytes(&self) -> &[u8; SHA256_BYTES] {
        &self.0
    }

    /// 64 hex digits, lower case, without the prefix — the form kept in the database.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Reads 64 hex digits without the prefix. Lower case only: the wire form is unambiguous.
    pub fn from_hex(text: &str) -> Result<Self, ChecksumError> {
        let error = || ChecksumError { text: text.to_owned() };
        let b = text.as_bytes();
        if b.len() != SHA256_BYTES * 2 || !b.iter().all(|z| matches!(z, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(error());
        }
        let mut from = [0u8; SHA256_BYTES];
        for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
            let high = char::from(pair[0]).to_digit(16).ok_or_else(error)?;
            let low = char::from(pair[1]).to_digit(16).ok_or_else(error)?;
            from[i] = u8::try_from(high * 16 + low).map_err(|_| error())?;
        }
        Ok(Self(from))
    }

    /// `sha256:<hex>` — the form used in JSON.
    pub fn wire_form(&self) -> String {
        format!("{PREFIX_SHA256}{}", self.hex())
    }
}

impl fmt::Display for Sha256Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.wire_form())
    }
}

impl fmt::Debug for Sha256Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.wire_form())
    }
}

impl FromStr for Sha256Value {
    type Err = ChecksumError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let hex = text
            .strip_prefix(PREFIX_SHA256)
            .ok_or_else(|| ChecksumError { text: text.to_owned() })?;
        Self::from_hex(hex).map_err(|_| ChecksumError { text: text.to_owned() })
    }
}

impl Serialize for Sha256Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn the_wire_form_survives_the_round_trip() {
        let w: Sha256Value = format!("sha256:{EMPTY}").parse().unwrap();
        assert_eq!(w.hex(), EMPTY);
        assert_eq!(serde_json::to_string(&w).unwrap(), format!("\"sha256:{EMPTY}\""));
    }

    #[test]
    fn without_the_prefix_or_in_upper_case_it_is_not_a_checksum() {
        assert!(EMPTY.parse::<Sha256Value>().is_err());
        assert!(format!("sha256:{}", EMPTY.to_uppercase()).parse::<Sha256Value>().is_err());
        assert!(format!("sha384:{EMPTY}").parse::<Sha256Value>().is_err());
        assert!("sha256:abc".parse::<Sha256Value>().is_err());
    }
}
