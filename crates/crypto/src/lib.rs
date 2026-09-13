//! The folder client's cryptography — the only place where computing and signing happen.
//!
//! In the whole procedure there is exactly one algorithm: ES256 on P-256 (geraete-auth §5.1). A
//! contract with one algorithm has no downgrade surface; `alg: none` and the HMAC confusion
//! attack are not “rejected” here, they cannot even be expressed. That is why every curve
//! computation stands in this crate (architecture rule R6) and nowhere else.
//!
//! The way through the crate:
//!
//! * [`jcs`] — RFC 8785. The bytes that are signed over; a silent change here is the only way a
//!   signature chain can lie.
//! * [`random`] — 128 bits from the operating system: identifiers, `jti`, ULID for
//!   `Idempotency-Key`.
//! * [`checksum`] — SHA-256 in the core's wire form, also chunk by chunk for large content.
//! * [`key`] — the device key, its public part as a JWK, RFC 7638 thumbprint.
//! * [`jws`] — compact and detached JWS per geraete-auth §5.2.
//! * [`dpop`] — proofs per RFC 9449 and the nonce store per origin (03 §6.0.5).
//! * [`assertion`] — `private_key_jwt` per RFC 7523 §2.2.
//! * [`anchor`] — the anchor fingerprint, bit-exact per geraete-auth §5.3.
//! * [`key_set`] — the anchored server key set and its acceptance rules P1–P12
//!   (03 §6.2.4), plus the check of signed delivery commands (ADR-D04).
//! * `forge` (feature `forge`) — the counterpart for the mock and for tests.
//!
//! Boundaries this crate does not cross:
//!
//! 1. No clock. Timestamps are handed in; `iat` and `exp` are computed from them.
//! 2. No network and no file system. The key comes in as PKCS#8 and goes out as PKCS#8; where it
//!    is kept (the operating system's keychain) is the app's decision.
//! 3. No `unsafe`.
//! 4. No silent fallback. What cannot be checked does not count (geraete-auth §5.8).

#![forbid(unsafe_code)]

pub mod anchor;
pub mod assertion;
pub mod checksum;
pub mod dpop;
mod encoding;
mod error;
#[cfg(any(test, feature = "forge"))]
pub mod forge;
pub mod jcs;
pub mod jws;
pub mod key;
pub mod key_set;
pub mod random;

pub use error::CryptoError;

/// The one algorithm of the procedure, spelled exactly as in the JOSE header.
pub const ALG: &str = "ES256";
