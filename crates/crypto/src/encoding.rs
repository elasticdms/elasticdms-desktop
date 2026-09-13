//! base64url and SHA-256 — the two tools every module here needs.
//!
//! base64url stands in exactly one place, so that no encoding with padding characters appears
//! anywhere in the crate: a `=` at the end of an `ath` or a `jti` is reported by the server only
//! at the signature comparison, and then the search takes a while (RFC 7515 §2, escan
//! `Base64Url`).
//!
//! **Strict when reading.** Padding characters and non-canonical trailing bits are rejected. A
//! JWS header that can be encoded in two ways has two signature inputs — and the server has
//! signed only one of them.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::CryptoError;

/// Encodes to base64url without padding characters.
pub(crate) fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Reads base64url without padding characters, strictly.
pub(crate) fn from_b64u(text: &str, field: &'static str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| CryptoError::Base64 { field })
}

/// SHA-256 as 32 raw bytes.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_encodes_without_padding_and_reads_only_that_way() {
        let encoded = b64u(&[1, 2, 3, 4, 5]);
        assert_eq!(encoded, "AQIDBAU");
        assert_eq!(from_b64u(&encoded, "t").unwrap(), vec![1, 2, 3, 4, 5]);
        // Padding, the standard alphabet and non-canonical trailing bits are not base64url.
        assert!(from_b64u("AQIDBAU=", "t").is_err());
        assert!(from_b64u("+/8", "t").is_err());
        assert!(from_b64u("AQIDBAV", "t").is_err());
    }
}
