//! Errors of the cryptography — values, not exceptions.
//!
//! Every variant names what did not hold and, where possible, the rule behind it (03 §6.2.4
//! P1–P12, geraete-auth §5.2). A check that only says "invalid" sends operations on a search;
//! one that says "key state 6, stored is 7" answers the question before it is asked.
//!
//! The mapping onto the findings from 03 §6.2.4 stands in [`CryptoError::report`]: the same
//! `type` URIs as the server errors, so that there is one error language and not two.

use edms_core::time::Timestamp;

use crate::key_set::{AnchorState, KeyReport};

/// Why a cryptographic operation did not succeed or a check did not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The operating system delivered no randomness.
    #[error(
        "the operating system delivered no randomness ({0}); without randomness neither a key \
         nor an identifier comes about, and a substitute value would be predictable"
    )]
    Random(String),
    /// Key material is unusable (PKCS#8 unreadable, scalar outside the group).
    #[error("the key material is unusable: {0}")]
    KeyMaterial(String),
    /// The signature could not be created.
    #[error("the signature could not be created: {0}")]
    Sign(String),
    /// A JWK is not a public P-256 key of this procedure.
    #[error("the JWK is not a public P-256 key: {0}")]
    Jwk(String),
    /// A number is not representable per RFC 8785.
    #[error("the number {text} is not representable per RFC 8785: {reason}")]
    JcsNumber {
        /// The number as it was read.
        text: String,
        /// Why not.
        reason: &'static str,
    },
    /// A text is not JSON per I-JSON (RFC 7493), for instance because of duplicate names.
    #[error("the text is not JSON per I-JSON (RFC 7493): {0}")]
    JsonUnreadable(String),
    /// A field is not base64url without padding characters.
    #[error("`{field}` is not base64url without padding characters (RFC 7515 §2)")]
    Base64 {
        /// Which field.
        field: &'static str,
    },
    /// The shape of a JWS is wrong.
    #[error("the JWS is unreadable: {0}")]
    JwsUnreadable(String),
    /// The header names an algorithm other than ES256 (P1).
    #[error(
        "the header names alg `{read}`; in the whole procedure only ES256 counts \
         (geraete-auth §5.1, 03 §6.2.4 P1)"
    )]
    WrongAlgorithm {
        /// The value that was read.
        read: String,
    },
    /// The header names a media type other than that of the checked carrier (P11).
    #[error(
        "the header names typ `{read}`, expected was `{expected}`; a signature out of \
         another context does not count here (03 §6.2.4 P11)"
    )]
    WrongTyp {
        /// The media type of the checked carrier.
        expected: String,
        /// The value that was read.
        read: String,
    },
    /// The signature does not match key and bytes.
    #[error("the signature does not hold: {0}")]
    SignatureHoldsNot(String),
    /// The carrier carries no `serverSignature`.
    #[error(
        "the carrier has no field `serverSignature` with a string; unsigned counts for nothing"
    )]
    SignatureMissing,
    /// The `kid` names no stored key (P3).
    #[error(
        "the key `{kid}` is not stored in this set; not checked does not mean valid \
         (03 §6.2.4 P3). A reconciliation of the key set can deliver it"
    )]
    UnknownKid {
        /// The `kid` that was read.
        kid: String,
    },
    /// The key's role does not match the carrier (P6).
    #[error("the key `{kid}` has the role `{read}`, here only `{expected}` signs (03 §6.2.4 P6)")]
    RoleMismatch {
        /// The key concerned.
        kid: String,
        /// The role that is allowed to sign here.
        expected: &'static str,
        /// The role that was read.
        read: String,
    },
    /// A key vouches for itself (P4, T8).
    #[error(
        "the entry `{kid}` is signed by itself; a key does not vouch for itself (03 §6.2.4 P4)"
    )]
    SelfSigned {
        /// The key concerned.
        kid: String,
    },
    /// Issuer or tenant differ (P7).
    #[error("the answer names `{read}`, set up is `{expected}` (03 §6.2.4 P7)")]
    TenantMismatch {
        /// The stored value (`issuer` or `tenantId`).
        expected: String,
        /// The value that was read.
        read: String,
    },
    /// The answer carries a lower key state (P8, T7).
    #[error(
        "the server reported key state {offered}, stored is {stored}; the answer was discarded, \
         state {stored} keeps counting (03 §6.2.4 P8)"
    )]
    StateReset {
        /// The stored state.
        stored: u64,
        /// The offered state.
        offered: u64,
    },
    /// A new anchor without a valid counter-signature waits for the human reconciliation (P10).
    #[error(
        "no stored anchor has validly counter-signed the new anchor `{kid}` ({reason}); it \
         does not take effect and waits for the reconciliation by a human (03 §6.2.4 P10)"
    )]
    AnchorPending {
        /// The new anchor.
        kid: String,
        /// Why the counter-signature did not hold.
        reason: String,
    },
    /// The answer carries no anchor.
    #[error(
        "the answer carries no trust anchor; without an anchor no trust comes about (03 §6.2.4)"
    )]
    NoAnchor,
    /// The fingerprint differs.
    #[error(
        "the fingerprint of the server keys has changed: expected {expected}, computed \
         {computed}. The new keys were not taken over"
    )]
    FingerprintChanged {
        /// The stored or reported fingerprint.
        expected: String,
        /// The fingerprint computed here.
        computed: String,
    },
    /// The thumbprint that came along does not match the coordinates.
    #[error("the entry `{kid}` reports thumbprint {reported}, computed is {computed}")]
    ThumbprintMismatch {
        /// The key concerned.
        kid: String,
        /// The value that came along.
        reported: String,
        /// The value computed here.
        computed: String,
    },
    /// There is no confirmed anchor; no signature holds (geraete-auth §5.8).
    #[error(
        "the key set does not carry (anchor state `{state}`): no confirmed anchor, so no \
         signature holds and nothing is executed (geraete-auth §5.8)"
    )]
    NotAnchored {
        /// The state of the anchor set.
        state: AnchorState,
    },
    /// The signing time is missing from the signed body; P12 cannot be checked.
    #[error(
        "the signed body carries no readable field `{field}`; without the signing time the \
         validity window cannot be checked, so the signature does not count (03 §6.2.4 P12)"
    )]
    SignatureTimeMissing {
        /// The expected field.
        field: &'static str,
    },
    /// The signing time lies before `notBefore` (P12).
    #[error(
        "the key `{kid}` counts only from {deadline} on; signed was {timestamp} (03 §6.2.4 P12)"
    )]
    NotYetValid {
        /// The key concerned.
        kid: String,
        /// The signing time.
        timestamp: Timestamp,
        /// `notBefore`.
        deadline: Timestamp,
    },
    /// The signing time lies at or after `notAfter` (P12).
    #[error("the key `{kid}` counted until {until}; signed was {timestamp} (03 §6.2.4 P12)")]
    Expired {
        /// The key concerned.
        kid: String,
        /// The signing time.
        timestamp: Timestamp,
        /// `notAfter`.
        until: Timestamp,
    },
    /// A revocation on suspicion voids the signature.
    #[error("the key `{kid}` is revoked; its signature no longer carries (03 §6.2.4, revocation)")]
    Revoked {
        /// The key concerned.
        kid: String,
    },
    /// A block or entry does not have the shape from 03 §6.2.4.
    #[error("{what} is unreadable: {reason}")]
    Unreadable {
        /// What was to be read.
        what: &'static str,
        /// Why not.
        reason: String,
    },
    /// A ULID needs a timestamp within 48 bits of milliseconds from 1970 on.
    #[error(
        "the point in time {millis} ms does not fit into the 48 bits of a ULID (1970 to 10889)"
    )]
    UlidTime {
        /// Milliseconds since 1970.
        millis: i64,
    },
    /// A URL is no good as an `htu` or an origin.
    #[error("`{url}` is no good as the target of a proof: {reason}")]
    Url {
        /// The URL that was read.
        url: String,
        /// Why not.
        reason: &'static str,
    },
    /// The HTTP method is not a token made of letters.
    #[error("`{method}` is not an HTTP method")]
    Method {
        /// The method that was read.
        method: String,
    },
    /// An access token contains characters outside US-ASCII; `ath` would be ambiguous.
    #[error(
        "the access token contains characters outside US-ASCII; `ath` is not defined for that (RFC 9449 §4.2)"
    )]
    TokenNotAscii,
    /// A DPoP proof does not hold the shape of RFC 9449 (the forge's server-side check).
    #[error("the DPoP proof is invalid: {0}")]
    DpopInvalid(String),
}

impl CryptoError {
    /// The finding from 03 §6.2.4, when the error is one — for heartbeat, journal and the
    /// security warning in the usage log.
    pub fn report(&self) -> Option<KeyReport> {
        use KeyReport as B;
        Some(match self {
            Self::WrongAlgorithm { .. }
            | Self::WrongTyp { .. }
            | Self::SignatureHoldsNot(_)
            | Self::JwsUnreadable(_)
            | Self::SignatureMissing
            | Self::ThumbprintMismatch { .. }
            | Self::SignatureTimeMissing { .. }
            | Self::Unreadable { .. } => B::StatementInvalid,
            Self::UnknownKid { .. } => B::UnknownKid,
            Self::RoleMismatch { .. } => B::RoleMismatch,
            Self::SelfSigned { .. } => B::SelfSigned,
            Self::TenantMismatch { .. } => B::TenantMismatch,
            Self::StateReset { .. } => B::StateReset,
            Self::NoAnchor => B::AnchorMissing,
            Self::AnchorPending { .. } => B::AnchorUnconfirmed,
            Self::FingerprintChanged { .. } => B::FingerprintChanged,
            Self::NotAnchored { state } => match state {
                AnchorState::NoAnchor => B::AnchorMissing,
                AnchorState::AwaitingConfirmation => B::AnchorUnconfirmed,
                // Confirmed and still not carrying means: no anchor is valid any more.
                AnchorState::Confirmed | AnchorState::Revoked => B::Revoked,
            },
            Self::NotYetValid { .. } => B::NotYetValid,
            Self::Expired { .. } => B::Expired,
            Self::Revoked { .. } => B::Revoked,
            _ => return None,
        })
    }
}
