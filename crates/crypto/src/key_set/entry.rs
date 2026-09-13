//! The shape of the `serverKeys` block — read once, for enrollment and for the distribution path.
//!
//! `[GAP → PROPOSAL]` (digest Q-7): 03 §6.2.4 gives the shape only as an example, never as a
//! schema. What is read is therefore exactly the form the sibling client reads and its forge
//! builds (escan `Serverschluesselleser`, `Schluesselwerkstatt`) — the server delivers both of
//! them the same body. The shape stands in this one module; a rename is a change here and not at
//! every check.
//!
//! **Every entry keeps its raw form.** The signed bytes are `JCS(Entry without serverSignature)`,
//! including every field this client does not know (P2). A type with fixed fields would lose
//! exactly those fields when writing back, and on the next load the signature of an honest server
//! would no longer hold.
//!
//! **Unreadable entries are counted, not passed over in silence** — wrong curve, missing
//! mandatory field, unknown role. An entry silently skipped is the difference between “the server
//! delivers nothing” and “this client does not read it”.

use edms_core::time::Timestamp;
use serde_json::{Map, Value};

use super::{KeyRole, RevocationReason};
use crate::anchor::AnchorFingerprint;
use crate::jws::{self, FIELD_SIGNATURE};
use crate::key::Jwk;
use crate::{ALG, CryptoError};

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

fn required<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    what: &'static str,
) -> Result<&'a str, CryptoError> {
    text(object, name).ok_or_else(|| CryptoError::Unreadable {
        what,
        reason: format!("the field \"{name}\" is missing or is not a string"),
    })
}

fn text_optional(
    object: &Map<String, Value>,
    name: &str,
    what: &'static str,
) -> Result<Option<String>, CryptoError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(t)) => Ok(Some(t.clone())),
        Some(_) => Err(CryptoError::Unreadable {
            what,
            reason: format!("the field \"{name}\" is not a string"),
        }),
    }
}

fn timestamp(
    object: &Map<String, Value>,
    name: &str,
    what: &'static str,
) -> Result<Timestamp, CryptoError> {
    let value = required(object, name, what)?;
    Timestamp::from_rfc3339(value)
        .map_err(|error| CryptoError::Unreadable { what, reason: error.to_string() })
}

fn timestamp_optional(
    object: &Map<String, Value>,
    name: &str,
    what: &'static str,
) -> Result<Option<Timestamp>, CryptoError> {
    match text_optional(object, name, what)? {
        None => Ok(None),
        Some(value) => Timestamp::from_rfc3339(&value)
            .map(Some)
            .map_err(|error| CryptoError::Unreadable { what, reason: error.to_string() }),
    }
}

fn integer_optional(
    object: &Map<String, Value>,
    name: &str,
    what: &'static str,
) -> Result<Option<u64>, CryptoError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| CryptoError::Unreadable {
            what,
            reason: format!("the field \"{name}\" is not a non-negative whole number"),
        }),
    }
}

fn signature_field_check(
    object: &Map<String, Value>,
    what: &'static str,
) -> Result<(), CryptoError> {
    match object.get(FIELD_SIGNATURE) {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(_) => Err(CryptoError::Unreadable {
            what,
            reason: "serverSignature is neither null nor a string".into(),
        }),
    }
}

/// An entry from `trustAnchors[]` or `signingKeys[]`, read and **not yet checked**.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyEntry {
    raw: Value,
    kid: String,
    role: KeyRole,
    jwk: Jwk,
    issuer: String,
    tenant_id: String,
    not_before: Timestamp,
    not_after: Timestamp,
    key_set_version: Option<u64>,
    supersedes: Option<String>,
    thumbprint: Option<String>,
}

impl KeyEntry {
    /// Reads an entry. Mandatory: `kid`, `kty: "EC"`, `crv: "P-256"`, `alg: "ES256"`, `x`, `y`,
    /// `role`, `issuer`, `tenantId`, `notBefore < notAfter`.
    pub fn from_json(entry: &Value) -> Result<Self, CryptoError> {
        const WHAT: &str = "A key entry";
        let object = entry.as_object().ok_or_else(|| CryptoError::Unreadable {
            what: WHAT,
            reason: "it is not a JSON object".into(),
        })?;
        let kid = required(object, "kid", WHAT)?;
        for (name, expected) in [("kty", Jwk::KTY), ("crv", Jwk::CRV), ("alg", ALG)] {
            if text(object, name) != Some(expected) {
                return Err(CryptoError::Unreadable {
                    what: WHAT,
                    reason: format!(
                        "\"{kid}\" names {name} {:?}; in the procedure only {expected} counts",
                        text(object, name)
                    ),
                });
            }
        }
        let jwk = Jwk::new(required(object, "x", WHAT)?, required(object, "y", WHAT)?)?;
        let role_text = required(object, "role", WHAT)?;
        let role =
            KeyRole::from_contract_value(role_text).ok_or_else(|| CryptoError::Unreadable {
                what: WHAT,
                reason: format!("\"{kid}\" names the unknown role \"{role_text}\""),
            })?;
        let not_before = timestamp(object, "notBefore", WHAT)?;
        let not_after = timestamp(object, "notAfter", WHAT)?;
        if not_after <= not_before {
            return Err(CryptoError::Unreadable {
                what: WHAT,
                reason: format!("\"{kid}\" has an empty validity window"),
            });
        }
        signature_field_check(object, WHAT)?;
        Ok(Self {
            raw: entry.clone(),
            kid: kid.to_owned(),
            role,
            jwk,
            issuer: required(object, "issuer", WHAT)?.to_owned(),
            tenant_id: required(object, "tenantId", WHAT)?.to_owned(),
            not_before,
            not_after,
            key_set_version: integer_optional(object, "keySetVersion", WHAT)?,
            supersedes: text_optional(object, "supersedes", WHAT)?,
            thumbprint: text_optional(object, "thumbprint", WHAT)?,
        })
    }

    /// The entry as it arrived — `serverSignature` and unknown fields included.
    pub fn as_json(&self) -> &Value {
        &self.raw
    }

    /// The key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The role, covered by the entry's signature.
    pub fn role(&self) -> KeyRole {
        self.role
    }

    /// The public part.
    pub fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// `issuer` of the entry.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// `tenantId` of the entry.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// `notBefore`.
    pub fn not_before(&self) -> Timestamp {
        self.not_before
    }

    /// `notAfter`.
    pub fn not_after(&self) -> Timestamp {
        self.not_after
    }

    /// The state in which the key was introduced; immutable and signed.
    pub fn key_set_version(&self) -> Option<u64> {
        self.key_set_version
    }

    /// The key that was superseded.
    pub fn supersedes(&self) -> Option<&str> {
        self.supersedes.as_deref()
    }

    /// The thumbprint **claimed** by the server. Authoritative is [`Jwk::thumbprint`].
    pub fn reported_thumbprint(&self) -> Option<&str> {
        self.thumbprint.as_deref()
    }

    /// Whether a thumbprint that came along matches this client's own computation.
    pub(super) fn check_thumbprint(&self) -> Result<(), CryptoError> {
        match &self.thumbprint {
            Some(reported) if *reported != self.jwk.thumbprint() => {
                Err(CryptoError::ThumbprintMismatch {
                    kid: self.kid.clone(),
                    reported: reported.clone(),
                    computed: self.jwk.thumbprint(),
                })
            }
            _ => Ok(()),
        }
    }

    /// The `kid` in the header of the `serverSignature`, if it is readable.
    pub fn signer_kid(&self) -> Option<String> {
        jws::signature_of_the_carrier(&self.raw).ok().map(|s| s.header().kid.clone())
    }

    /// Whether the signing time falls in `[notBefore, notAfter)` (P12).
    pub fn valid_at(&self, signature_time: Timestamp) -> bool {
        self.not_before <= signature_time && signature_time < self.not_after
    }
}

/// An entry from `revocations[]`, read and **not yet checked**.
#[derive(Debug, Clone, PartialEq)]
pub struct Revocation {
    raw: Value,
    kid: String,
    role: Option<KeyRole>,
    issuer: String,
    tenant_id: String,
    revoked_at: Timestamp,
    compromised_since: Option<Timestamp>,
    reason: RevocationReason,
    key_set_version: Option<u64>,
}

impl Revocation {
    /// Reads a revocation. Mandatory: `kid`, `issuer`, `tenantId`, `revokedAt`, `reason`.
    pub fn from_json(entry: &Value) -> Result<Self, CryptoError> {
        const WHAT: &str = "A revocation entry";
        let object = entry.as_object().ok_or_else(|| CryptoError::Unreadable {
            what: WHAT,
            reason: "it is not a JSON object".into(),
        })?;
        let kid = required(object, "kid", WHAT)?;
        let reason_text = required(object, "reason", WHAT)?;
        let reason = RevocationReason::from_contract_value(reason_text).ok_or_else(|| {
            CryptoError::Unreadable {
                what: WHAT,
                reason: format!("the reason \"{reason_text}\" is unknown"),
            }
        })?;
        let role = match text_optional(object, "role", WHAT)? {
            None => None,
            Some(value) => Some(KeyRole::from_contract_value(&value).ok_or_else(|| {
                CryptoError::Unreadable {
                    what: WHAT,
                    reason: format!("the role \"{value}\" is unknown"),
                }
            })?),
        };
        signature_field_check(object, WHAT)?;
        Ok(Self {
            raw: entry.clone(),
            kid: kid.to_owned(),
            role,
            issuer: required(object, "issuer", WHAT)?.to_owned(),
            tenant_id: required(object, "tenantId", WHAT)?.to_owned(),
            revoked_at: timestamp(object, "revokedAt", WHAT)?,
            compromised_since: timestamp_optional(object, "compromisedSince", WHAT)?,
            reason,
            key_set_version: integer_optional(object, "keySetVersion", WHAT)?,
        })
    }

    /// The entry as it arrived.
    pub fn as_json(&self) -> &Value {
        &self.raw
    }

    /// The revoked key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The role of the revoked key, if named.
    pub fn role(&self) -> Option<KeyRole> {
        self.role
    }

    /// `issuer`.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// `tenantId`.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// `revokedAt`.
    pub fn revoked_at(&self) -> Timestamp {
        self.revoked_at
    }

    /// `compromisedSince`; `None` means, depending on the reason, “unknown” or “no suspicion”.
    pub fn compromised_since(&self) -> Option<Timestamp> {
        self.compromised_since
    }

    /// The reason.
    pub fn reason(&self) -> RevocationReason {
        self.reason
    }

    /// The state in which the revocation was published.
    pub fn key_set_version(&self) -> Option<u64> {
        self.key_set_version
    }

    /// Whether this revocation voids a signature made at `signature_time`.
    ///
    /// The distinction rests on the **reason**, not on the empty field: planned reasons void
    /// nothing; suspicion reasons void from `compromisedSince` on — and without a named point in
    /// time they void everything, because a record the attacker could have produced too is none.
    pub fn voided(&self, signature_time: Timestamp) -> bool {
        match (self.reason.retroactive(), self.compromised_since) {
            (false, _) => false,
            (true, None) => true,
            (true, Some(since)) => signature_time >= since,
        }
    }
}

/// What the server offers — the answer as read, but **not yet checked**.
///
/// An offer is not a state. Whether a [`super::KeySet`] arises from it is decided by the rules
/// P1 to P12.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyOffer {
    key_set_version: u64,
    issuer: String,
    tenant_id: String,
    reported_fingerprint: Option<String>,
    anchors: Vec<KeyEntry>,
    signature_signing_key: Vec<KeyEntry>,
    revoke: Vec<Revocation>,
    generated_at: Option<Timestamp>,
    refresh_after: Option<Timestamp>,
    next_rotation_at: Option<Timestamp>,
    unreadable: Vec<CryptoError>,
}

impl KeyOffer {
    /// The `serverKeys` block or the body of `GET /v1/server-keys` — the same shape.
    pub fn from_json(block: &Value) -> Result<Self, CryptoError> {
        const WHAT: &str = "The serverKeys block";
        let object = block.as_object().ok_or_else(|| CryptoError::Unreadable {
            what: WHAT,
            reason: "it is not a JSON object".into(),
        })?;
        let key_set_version =
            object.get("keySetVersion").and_then(Value::as_u64).ok_or_else(|| {
                CryptoError::Unreadable {
                    what: WHAT,
                    reason: "keySetVersion is missing or is not a whole number".into(),
                }
            })?;
        let list = |name: &str| -> Result<&[Value], CryptoError> {
            match object.get(name) {
                None | Some(Value::Null) => Ok(&[]),
                Some(Value::Array(values)) => Ok(values.as_slice()),
                Some(_) => Err(CryptoError::Unreadable {
                    what: WHAT,
                    reason: format!("{name} is not a list"),
                }),
            }
        };
        let mut unreadable = Vec::new();
        let mut read_key = |values: &[Value]| -> Vec<KeyEntry> {
            values
                .iter()
                .filter_map(|value| KeyEntry::from_json(value).map_err(|f| unreadable.push(f)).ok())
                .collect()
        };
        let anchors = read_key(list("trustAnchors")?);
        let signature_signing_key = read_key(list("signingKeys")?);
        let revoke = list("revocations")?
            .iter()
            .filter_map(|value| Revocation::from_json(value).map_err(|f| unreadable.push(f)).ok())
            .collect();
        Ok(Self {
            key_set_version,
            issuer: required(object, "issuer", WHAT)?.to_owned(),
            tenant_id: required(object, "tenantId", WHAT)?.to_owned(),
            reported_fingerprint: text_optional(object, "anchorSetFingerprint", WHAT)?,
            anchors,
            signature_signing_key,
            revoke,
            generated_at: timestamp_optional(object, "generatedAt", WHAT)?,
            refresh_after: timestamp_optional(object, "refreshAfter", WHAT)?,
            next_rotation_at: timestamp_optional(object, "nextRotationAt", WHAT)?,
            unreadable,
        })
    }

    /// The `serverKeys` block from an enrollment answer (from a `412` as well, 03 §6.2.1).
    ///
    /// If the block is missing, that is not a fault of this client but an answer that does not
    /// fulfil §6.2.4 — the device stays without an anchor, and nothing is ever erased.
    pub fn from_enrollment(response: &Value) -> Result<Self, CryptoError> {
        match response.get("serverKeys") {
            Some(block @ Value::Object(_)) => Self::from_json(block),
            _ => Err(CryptoError::Unreadable {
                what: "The enrollment answer",
                reason: "it carries no serverKeys block".into(),
            }),
        }
    }

    /// State of the whole set (P8).
    pub fn key_set_version(&self) -> u64 {
        self.key_set_version
    }

    /// `issuer` of the set.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// `tenantId` of the set.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The fingerprint reported by the server — only for comparison, never as a source.
    pub fn reported_fingerprint(&self) -> Option<&str> {
        self.reported_fingerprint.as_deref()
    }

    /// The self-computed fingerprint over the offered anchors.
    pub fn fingerprint(&self) -> AnchorFingerprint {
        AnchorFingerprint::from_jwks(self.anchors.iter().map(KeyEntry::jwk))
    }

    /// The offered anchors.
    pub fn anchors(&self) -> &[KeyEntry] {
        &self.anchors
    }

    /// The offered signing keys.
    pub fn signature_signing_key(&self) -> &[KeyEntry] {
        &self.signature_signing_key
    }

    /// The offered revocations.
    pub fn revoke(&self) -> &[Revocation] {
        &self.revoke
    }

    /// `generatedAt`.
    pub fn generated_at(&self) -> Option<Timestamp> {
        self.generated_at
    }

    /// `refreshAfter`.
    pub fn refresh_after(&self) -> Option<Timestamp> {
        self.refresh_after
    }

    /// `nextRotationAt`.
    pub fn next_rotation_at(&self) -> Option<Timestamp> {
        self.next_rotation_at
    }

    /// Entries that dropped out while reading, with their reason.
    pub fn unreadable_entries(&self) -> &[CryptoError] {
        &self.unreadable
    }
}
