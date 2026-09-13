//! The anchored server key set and its acceptance rules (03 §6.2.4, geraete-auth §5).
//!
//! **Whoever decides which public key counts decides what this device erases.** For the folder
//! client that is the delivery channel: a signed command releases copies or takes the name of a
//! DSGVO (GDPR) erasure out of the folder (ADR-D04). Delivering these keys is therefore the
//! handover of an authority, and it is treated as one:
//!
//! * **Trust arises only in the enrollment answer** ([`KeySet::anchor`]). There the anchors carry
//!   `serverSignature: null`; their validity comes not from a computation but from a human
//!   comparing the [`AnchorFingerprint`] against the procedure documentation. After that,
//!   [`KeySet::confirm`].
//! * **`GET /v1/server-keys` only redistributes** ([`KeySet::adopt`]). A key statement counts
//!   only when a **stored** anchor counter-signs it that is not the key itself (P3, P4, T8). A
//!   smaller `keySetVersion` is discarded, the state stays (P8, T7) — and because both functions
//!   take `&self`, it really does stay.
//! * **Every check walks the whole chain** ([`KeySet::check_carrier`]): anchor → key statement →
//!   carrier. An anchor that was revoked on suspicion after adoption carries nothing from the
//!   next check onwards — without migration, without a clean-up run.
//!
//! **No confirmed anchor ⇒ no signature holds ⇒ no command is executed** (geraete-auth §5.8).
//! That is the contractual state on day one and not a fault state: listing and opening need no
//! server key and keep running.
//!
//! The rules follow the sibling client (`Schluesselsatzuebernahme`, `ServerSignaturpruefer`), so
//! that both clients reach the same result in front of the same answer.

use edms_core::time::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};

use crate::CryptoError;
use crate::anchor::AnchorFingerprint;
use crate::jws;
use crate::key::PublicKey;

mod entry;
#[cfg(test)]
mod tests;

pub use entry::{KeyEntry, KeyOffer, Revocation};

/// Media type of a key statement, signed by an anchor.
pub const TYP_KEY_STATEMENT: &str = "edms-server-key+jwt";

/// Media type of a revocation, signed by an anchor.
pub const TYP_REVOCATION: &str = "edms-server-key-revocation+jwt";

/// Media type of a delivery command, signed by an evidence key.
///
/// `[GAP → PROPOSAL]` ADR-D04: the counterpart's contract knows no delivery command. The shape
/// follows the one rule from geraete-auth §5.2 — `JCS(Command without serverSignature)`, detached
/// JWS, role `evidence-signing` — so that there is one rule for the procedure and not seven.
pub const TYP_DELIVERY_COMMAND: &str = "edms-delivery-command+jwt";

/// The field of a delivery command that carries the signing time (P12).
///
/// `[GAP → PROPOSAL]` (digest §2.12): `issuedAt`, server time inside the signed body, RFC 3339 —
/// like `clearedAt`, `serverSignedAt` and `issuedAt` in the counterpart's records.
pub const FIELD_COMMAND_TIME: &str = "issuedAt";

/// The version of the local store ([`KeySet::as_storage`]).
const STORE_VERSION: u64 = 1;

/// The two roles, never in one key (geraete-auth §5.1). They stand **inside** the signed bytes:
/// an evidence key cannot redeclare itself an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// `trust-anchor`: ten years, offline; signs only key statements and revocations.
    TrustAnchor,
    /// `evidence-signing`: at most twelve months, KMS; signs records and commands.
    ProofSignature,
}

impl KeyRole {
    /// The value in the `role` field.
    pub const fn contract_value(self) -> &'static str {
        match self {
            Self::TrustAnchor => "trust-anchor",
            Self::ProofSignature => "evidence-signing",
        }
    }

    /// Reads `role`; an unknown value yields `None`.
    pub fn from_contract_value(value: &str) -> Option<Self> {
        [Self::TrustAnchor, Self::ProofSignature].into_iter().find(|r| r.contract_value() == value)
    }
}

/// How far the anchor set has come (`serverKeys.anchorState` in the heartbeat, 03 §6.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AnchorState {
    /// `none` — no anchor stored.
    #[default]
    NoAnchor,
    /// `pending_confirmation` — anchors written, the confirmation by a human is missing.
    AwaitingConfirmation,
    /// `confirmed` — the fingerprint has been read back and confirmed in the console.
    Confirmed,
    /// `revoked` — all anchors revoked; there is no way back online.
    Revoked,
}

impl AnchorState {
    /// The value in the heartbeat.
    pub const fn contract_value(self) -> &'static str {
        match self {
            Self::NoAnchor => "none",
            Self::AwaitingConfirmation => "pending_confirmation",
            Self::Confirmed => "confirmed",
            Self::Revoked => "revoked",
        }
    }

    /// Reads the heartbeat value.
    pub fn from_contract_value(value: &str) -> Option<Self> {
        [Self::NoAnchor, Self::AwaitingConfirmation, Self::Confirmed, Self::Revoked]
            .into_iter()
            .find(|z| z.contract_value() == value)
    }
}

impl std::fmt::Display for AnchorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.contract_value())
    }
}

/// The reason for a revocation — and with it, whether it acts retroactively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// `key_compromise` — retroactive.
    KeyCompromised,
    /// `anchor_compromise` — retroactive; signed by another anchor.
    AnchorCompromised,
    /// `precaution` — retroactive.
    Precautionary,
    /// `superseded` — planned, voids nothing.
    Superseded,
    /// `cessation_of_operation` — out of service, voids nothing.
    OutOfService,
}

impl RevocationReason {
    const ALL: [Self; 5] = [
        Self::KeyCompromised,
        Self::AnchorCompromised,
        Self::Precautionary,
        Self::Superseded,
        Self::OutOfService,
    ];

    /// The value in the `reason` field.
    pub const fn contract_value(self) -> &'static str {
        match self {
            Self::KeyCompromised => "key_compromise",
            Self::AnchorCompromised => "anchor_compromise",
            Self::Precautionary => "precaution",
            Self::Superseded => "superseded",
            Self::OutOfService => "cessation_of_operation",
        }
    }

    /// Reads `reason`; an unknown reason yields `None`.
    pub fn from_contract_value(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.contract_value() == value)
    }

    /// Whether signatures already made lose their effect.
    pub const fn retroactive(self) -> bool {
        matches!(self, Self::KeyCompromised | Self::AnchorCompromised | Self::Precautionary)
    }
}

/// The client's findings from 03 §6.2.4 — the same `type` URIs as the server errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyReport {
    /// No anchor stored.
    AnchorMissing,
    /// Anchors received, confirmation missing.
    AnchorUnconfirmed,
    /// The received anchor set differs from the stored one.
    FingerprintChanged,
    /// P1, P2, P3 or P11 violated.
    StatementInvalid,
    /// P4 or P5 violated.
    SelfSigned,
    /// P6 violated.
    RoleMismatch,
    /// P7 violated.
    TenantMismatch,
    /// P8 violated.
    StateReset,
    /// Unknown `kid`; a reconciliation is triggered.
    UnknownKid,
    /// Signing time at or after `notAfter`.
    Expired,
    /// Signing time before `notBefore`.
    NotYetValid,
    /// Revocation on suspicion.
    Revoked,
}

impl KeyReport {
    /// The last segment of the `type` URI.
    pub const fn short_code(self) -> &'static str {
        match self {
            Self::AnchorMissing => "server-trust-anchor-missing",
            Self::AnchorUnconfirmed => "server-trust-anchor-unconfirmed",
            Self::FingerprintChanged => "server-trust-anchor-fingerprint-changed",
            Self::StatementInvalid => "server-key-statement-invalid",
            Self::SelfSigned => "server-key-self-signed",
            Self::RoleMismatch => "server-key-role-mismatch",
            Self::TenantMismatch => "server-key-tenant-mismatch",
            Self::StateReset => "server-key-set-rollback",
            Self::UnknownKid => "server-key-unknown-kid",
            Self::Expired => "server-key-expired",
            Self::NotYetValid => "server-key-not-yet-valid",
            Self::Revoked => "server-key-revoked",
        }
    }

    /// The complete `type` URI for heartbeat and journal.
    pub fn type_uri(self) -> String {
        format!("https://errors.elasticdms.io/{}", self.short_code())
    }

    /// Whether the finding is to be recorded as a security event (`securityEvent`).
    pub const fn security_event(self) -> bool {
        matches!(
            self,
            Self::FingerprintChanged | Self::SelfSigned | Self::TenantMismatch | Self::StateReset
        )
    }
}

/// The result of an accepted answer: the new state and what was discarded along the way.
///
/// A refused answer is an `Err` and not an `Adoption` — there is no “provisionally accepted”
/// (03 §6.2.4). Only single entries stand here that dropped out while the answer as a whole
/// counted.
#[derive(Debug, Clone, PartialEq)]
pub struct Adoption {
    /// The state afterwards.
    pub set: KeySet,
    /// Discarded entries, each with its reason.
    pub report: Vec<CryptoError>,
}

impl Adoption {
    /// The findings as `type` short codes, without repetition, in order of appearance.
    pub fn report_code(&self) -> Vec<KeyReport> {
        let mut codes = Vec::new();
        for report in self.report.iter().filter_map(CryptoError::report) {
            if !codes.contains(&report) {
                codes.push(report);
            }
        }
        codes
    }

    /// Whether one of the findings is to be recorded as a security event.
    pub fn security_event(&self) -> bool {
        self.report_code().into_iter().any(KeyReport::security_event)
    }
}

/// The locally held key state — the single source of every signature check.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeySet {
    key_set_version: u64,
    issuer: String,
    tenant_id: String,
    anchor_state: AnchorState,
    anchors: Vec<KeyEntry>,
    signature_signing_key: Vec<KeyEntry>,
    revoke: Vec<Revocation>,
    pending_anchors: Vec<KeyEntry>,
    generated_at: Option<Timestamp>,
    refresh_after: Option<Timestamp>,
    next_rotation_at: Option<Timestamp>,
}

/// Checks statements against a set's anchors: P1, P3, P4/P5, P11, revocation, signature.
struct AnchorVerifier<'a> {
    anchors: Vec<(&'a KeyEntry, Option<PublicKey>)>,
    revoke: &'a [Revocation],
}

impl<'a> AnchorVerifier<'a> {
    fn new(anchors: &'a [KeyEntry], revoke: &'a [Revocation]) -> Self {
        let anchors = anchors
            .iter()
            .filter(|a| a.role() == KeyRole::TrustAnchor)
            .map(|a| (a, PublicKey::from_jwk(a.jwk()).ok()))
            .collect();
        Self { anchors, revoke }
    }

    /// Checks the `serverSignature` of a carrier over `affected_kid`; yields the signer.
    fn check_statement(
        &self,
        carrier: &Value,
        affected_kid: &str,
        typ: &str,
    ) -> Result<String, CryptoError> {
        let signature = jws::signature_of_the_carrier(carrier)?;
        let signer = signature.header().kid.clone();
        // P4: a key does not vouch for itself (T8), and an anchor does not revoke itself —
        // otherwise the revocation would be as forgeable as the anchor.
        if signer == affected_kid {
            return Err(CryptoError::SelfSigned { kid: affected_kid.to_owned() });
        }
        if signature.header().typ != typ {
            return Err(CryptoError::WrongTyp {
                expected: typ.to_owned(),
                read: signature.header().typ.clone(),
            });
        }
        // P3 and P5: only a stored anchor signs; an evidence key does not stand here.
        let (_, public) = self
            .anchors
            .iter()
            .find(|(a, _)| a.kid() == signer)
            .ok_or_else(|| CryptoError::UnknownKid { kid: signer.clone() })?;
        if self.revoke.iter().any(|w| w.kid() == signer && w.reason().retroactive()) {
            return Err(CryptoError::Revoked { kid: signer });
        }
        let public = public.as_ref().ok_or_else(|| {
            CryptoError::SignatureHoldsNot(format!("the anchor \"{signer}\" has no point on P-256"))
        })?;
        signature.check(typ, &jws::signed_bytes(carrier)?, public)?;
        Ok(signer)
    }

    /// A key statement: P6, thumbprint, P7, then the signature.
    fn check_key(
        &self,
        entry: &KeyEntry,
        role: KeyRole,
        issuer: &str,
        tenant_id: &str,
    ) -> Result<(), CryptoError> {
        if entry.role() != role {
            return Err(CryptoError::RoleMismatch {
                kid: entry.kid().to_owned(),
                expected: role.contract_value(),
                read: entry.role().contract_value().to_owned(),
            });
        }
        entry.check_thumbprint()?;
        check_tenant(issuer, entry.issuer())?;
        check_tenant(tenant_id, entry.tenant_id())?;
        self.check_statement(entry.as_json(), entry.kid(), TYP_KEY_STATEMENT).map(|_| ())
    }

    /// A revocation: P7, then the signature of another anchor.
    fn check_revocation(
        &self,
        revocation: &Revocation,
        issuer: &str,
        tenant_id: &str,
    ) -> Result<(), CryptoError> {
        check_tenant(issuer, revocation.issuer())?;
        check_tenant(tenant_id, revocation.tenant_id())?;
        self.check_statement(revocation.as_json(), revocation.kid(), TYP_REVOCATION).map(|_| ())
    }
}

fn check_tenant(expected: &str, read: &str) -> Result<(), CryptoError> {
    if expected == read {
        Ok(())
    } else {
        Err(CryptoError::TenantMismatch { expected: expected.to_owned(), read: read.to_owned() })
    }
}

/// Union without removal (P9): what is stored stays, what is new is added by `kid`.
fn merge<T: Clone>(stored: &[T], new: Vec<T>, kid: impl Fn(&T) -> &str) -> Vec<T> {
    let mut from = stored.to_vec();
    for entry in new {
        if !from.iter().any(|a| kid(a) == kid(&entry)) {
            from.push(entry);
        }
    }
    from
}

impl KeySet {
    /// The state without any key — the right beginning and the right answer to every fault
    /// case: no signature holds, nothing is erased.
    pub fn empty() -> Self {
        Self::default()
    }

    /// First anchoring from the `serverKeys` block of the enrollment answer.
    ///
    /// Each of these violations refuses the **whole** answer: a foreign tenant (P7), no anchor,
    /// an anchor with another role (P6) or signed by itself (P4), a thumbprint that does not
    /// match this client's own computation, a reported fingerprint that does not match the
    /// computed one, and — if a set is already anchored — a fingerprint other than the stored
    /// one. The last is the promise “written exactly once”: a network answer does not replace an
    /// anchored set. A `412` with the same set (03 §6.2.1) is, by contrast, a success.
    pub fn anchor(
        &self,
        offer: &KeyOffer,
        expected_tenant: Option<&str>,
    ) -> Result<Adoption, CryptoError> {
        if let Some(tenant) = expected_tenant {
            check_tenant(tenant, offer.tenant_id())?;
        }
        if offer.anchors().is_empty() {
            return Err(CryptoError::NoAnchor);
        }
        for anchors in offer.anchors() {
            if anchors.role() != KeyRole::TrustAnchor {
                return Err(CryptoError::RoleMismatch {
                    kid: anchors.kid().to_owned(),
                    expected: KeyRole::TrustAnchor.contract_value(),
                    read: anchors.role().contract_value().to_owned(),
                });
            }
            if anchors.signer_kid().as_deref() == Some(anchors.kid()) {
                return Err(CryptoError::SelfSigned { kid: anchors.kid().to_owned() });
            }
            anchors.check_thumbprint()?;
            check_tenant(offer.issuer(), anchors.issuer())?;
            check_tenant(offer.tenant_id(), anchors.tenant_id())?;
        }
        let computed = offer.fingerprint();
        if let Some(reported) = offer.reported_fingerprint()
            && reported != computed.display()
        {
            return Err(CryptoError::FingerprintChanged {
                expected: reported.to_owned(),
                computed: computed.display(),
            });
        }
        let already_anchored = !self.anchors.is_empty();
        if already_anchored {
            if !self.fingerprint().agrees_agree(&computed) {
                return Err(CryptoError::FingerprintChanged {
                    expected: self.fingerprint().display(),
                    computed: computed.display(),
                });
            }
            check_tenant(&self.issuer, offer.issuer())?;
            check_tenant(&self.tenant_id, offer.tenant_id())?;
        }

        // The signing keys of the same answer are checked against that answer's anchors. That is
        // right here and wrong in `adopt`: these anchors gain their validity only through the
        // human comparison, and what they cover shares that fate.
        let verifier = AnchorVerifier::new(offer.anchors(), &[]);
        let mut report = Vec::new();
        let new_keys =
            self.accepted_key(offer, &verifier, offer.issuer(), offer.tenant_id(), &mut report);
        let new_revocations =
            self.accepted_revoke(offer, &verifier, offer.issuer(), offer.tenant_id(), &mut report);

        let set = Self {
            key_set_version: self.key_set_version.max(offer.key_set_version()),
            issuer: offer.issuer().to_owned(),
            tenant_id: offer.tenant_id().to_owned(),
            anchor_state: if already_anchored {
                self.anchor_state
            } else {
                AnchorState::AwaitingConfirmation
            },
            anchors: if already_anchored { self.anchors.clone() } else { offer.anchors().to_vec() },
            signature_signing_key: merge(&self.signature_signing_key, new_keys, |e| e.kid()),
            revoke: merge(&self.revoke, new_revocations, |w| w.kid()),
            pending_anchors: self.pending_anchors.clone(),
            generated_at: offer.generated_at(),
            refresh_after: offer.refresh_after(),
            next_rotation_at: offer.next_rotation_at(),
        };
        Ok(Adoption { set: set.with_revocation_state(), report })
    }

    /// The confirmation by the administrator (03 §6.2.4, steps 2 and 3).
    ///
    /// It comes not from a signature but from the server's finding that the device is `active` —
    /// after a human has held the fingerprint against the procedure documentation. The server can
    /// attest that somebody clicked, not what they read (residual risk 17).
    pub fn confirm(&self) -> Result<Self, CryptoError> {
        if self.anchors.is_empty() {
            return Err(CryptoError::NoAnchor);
        }
        if self.anchor_state == AnchorState::Revoked {
            return Err(CryptoError::NotAnchored { state: self.anchor_state });
        }
        Ok(Self { anchor_state: AnchorState::Confirmed, ..self.clone() })
    }

    /// Continuation from `GET /v1/server-keys` — the distribution path that establishes no trust.
    ///
    /// The answer is refused as a whole without a stored anchor (a recovery path without an
    /// anchor would be the attack path), on a foreign `issuer` or `tenantId` (P7) and on a
    /// smaller `keySetVersion` (P8, T7). Discarded individually — with a finding — are entries
    /// whose statement does not hold. Nothing is removed (P9); a new anchor without the
    /// counter-signature of a stored one waits and has no effect (P10).
    pub fn adopt(&self, offer: &KeyOffer) -> Result<Adoption, CryptoError> {
        if self.anchors.is_empty() {
            return Err(CryptoError::NoAnchor);
        }
        check_tenant(&self.issuer, offer.issuer())?;
        check_tenant(&self.tenant_id, offer.tenant_id())?;
        if offer.key_set_version() < self.key_set_version {
            return Err(CryptoError::StateReset {
                stored: self.key_set_version,
                offered: offer.key_set_version(),
            });
        }
        let verifier = AnchorVerifier::new(&self.anchors, &self.revoke);
        let mut report = Vec::new();
        let mut new_anchors = Vec::new();
        let mut pending = Vec::new();
        for anchors in offer.anchors() {
            if let Some(stored) = self.anchors.iter().find(|a| a.kid() == anchors.kid()) {
                // The same kid with another key is no rotation case but a swap.
                if stored.jwk() != anchors.jwk() {
                    report.push(CryptoError::FingerprintChanged {
                        expected: stored.jwk().thumbprint(),
                        computed: anchors.jwk().thumbprint(),
                    });
                }
                continue;
            }
            match verifier.check_key(anchors, KeyRole::TrustAnchor, &self.issuer, &self.tenant_id) {
                Ok(()) => new_anchors.push(anchors.clone()),
                Err(
                    error @ (CryptoError::RoleMismatch { .. }
                    | CryptoError::ThumbprintMismatch { .. }),
                ) => {
                    report.push(error);
                }
                Err(error) => {
                    report.push(CryptoError::AnchorPending {
                        kid: anchors.kid().to_owned(),
                        reason: error.to_string(),
                    });
                    pending.push(anchors.clone());
                }
            }
        }
        let new_keys =
            self.accepted_key(offer, &verifier, &self.issuer, &self.tenant_id, &mut report);
        let new_revocations =
            self.accepted_revoke(offer, &verifier, &self.issuer, &self.tenant_id, &mut report);
        let set = Self {
            key_set_version: offer.key_set_version(),
            anchors: merge(&self.anchors, new_anchors, |e| e.kid()),
            signature_signing_key: merge(&self.signature_signing_key, new_keys, |e| e.kid()),
            revoke: merge(&self.revoke, new_revocations, |w| w.kid()),
            pending_anchors: merge(&self.pending_anchors, pending, |e| e.kid()),
            generated_at: offer.generated_at().or(self.generated_at),
            refresh_after: offer.refresh_after().or(self.refresh_after),
            next_rotation_at: offer.next_rotation_at().or(self.next_rotation_at),
            ..self.clone()
        };
        Ok(Adoption { set: set.with_revocation_state(), report })
    }

    fn accepted_key(
        &self,
        offer: &KeyOffer,
        verifier: &AnchorVerifier<'_>,
        issuer: &str,
        tenant_id: &str,
        report: &mut Vec<CryptoError>,
    ) -> Vec<KeyEntry> {
        offer
            .signature_signing_key()
            .iter()
            .filter(|e| !self.signature_signing_key.iter().any(|g| g.kid() == e.kid()))
            .filter_map(|entry| {
                verifier
                    .check_key(entry, KeyRole::ProofSignature, issuer, tenant_id)
                    .map(|()| entry.clone())
                    .map_err(|error| report.push(error))
                    .ok()
            })
            .collect()
    }

    fn accepted_revoke(
        &self,
        offer: &KeyOffer,
        verifier: &AnchorVerifier<'_>,
        issuer: &str,
        tenant_id: &str,
        report: &mut Vec<CryptoError>,
    ) -> Vec<Revocation> {
        offer
            .revoke()
            .iter()
            .filter(|w| !self.revoke.iter().any(|g| g.kid() == w.kid()))
            .filter_map(|revocation| {
                verifier
                    .check_revocation(revocation, issuer, tenant_id)
                    .map(|()| revocation.clone())
                    .map_err(|error| report.push(error))
                    .ok()
            })
            .collect()
    }

    /// Sets the state to [`AnchorState::Revoked`] when no anchor carries any more.
    fn with_revocation_state(self) -> Self {
        if !self.anchors.is_empty() && !self.anchors.iter().any(|a| self.anchor_applies(a.kid())) {
            Self { anchor_state: AnchorState::Revoked, ..self }
        } else {
            self
        }
    }

    fn anchor_applies(&self, kid: &str) -> bool {
        self.anchors.iter().any(|a| a.kid() == kid)
            && !self.revocation_to(kid).is_some_and(|w| w.reason().retroactive())
    }

    /// Checks a carrier signed by an evidence key, as of the signing time.
    ///
    /// The whole chain, in this order: a confirmed anchor is there; shape and `alg` (P1); media
    /// type (P11); the `kid` is an evidence key of this set, not an anchor (P3, P6); its key
    /// statement holds **now** against the anchors, revocations included; the signing time lies
    /// in `[notBefore, notAfter)` (P12); no revocation on suspicion voids it; the signature holds
    /// over `JCS(carrier without serverSignature)` (P2).
    ///
    /// Yields the `kid` of the signer.
    pub fn check_carrier(
        &self,
        carrier: &Value,
        typ: &str,
        signature_time: Timestamp,
    ) -> Result<String, CryptoError> {
        if !self.carries() {
            return Err(CryptoError::NotAnchored { state: self.anchor_state });
        }
        let signature = jws::signature_of_the_carrier(carrier)?;
        if signature.header().typ != typ {
            return Err(CryptoError::WrongTyp {
                expected: typ.to_owned(),
                read: signature.header().typ.clone(),
            });
        }
        let kid = signature.header().kid.clone();
        if self.anchors.iter().any(|a| a.kid() == kid) {
            return Err(CryptoError::RoleMismatch {
                kid,
                expected: KeyRole::ProofSignature.contract_value(),
                read: KeyRole::TrustAnchor.contract_value().to_owned(),
            });
        }
        let entry = self
            .signature_signing_key
            .iter()
            .find(|e| e.kid() == kid)
            .ok_or_else(|| CryptoError::UnknownKid { kid: kid.clone() })?;
        AnchorVerifier::new(&self.anchors, &self.revoke).check_key(
            entry,
            KeyRole::ProofSignature,
            &self.issuer,
            &self.tenant_id,
        )?;
        if signature_time < entry.not_before() {
            return Err(CryptoError::NotYetValid {
                kid,
                timestamp: signature_time,
                deadline: entry.not_before(),
            });
        }
        if signature_time >= entry.not_after() {
            return Err(CryptoError::Expired {
                kid,
                timestamp: signature_time,
                until: entry.not_after(),
            });
        }
        if self.revocation_to(&kid).is_some_and(|w| w.voided(signature_time)) {
            return Err(CryptoError::Revoked { kid });
        }
        let public = PublicKey::from_jwk(entry.jwk()).map_err(|_| {
            CryptoError::SignatureHoldsNot(format!("the key \"{kid}\" has no point on P-256"))
        })?;
        signature.check(typ, &jws::signed_bytes(carrier)?, &public)?;
        Ok(kid)
    }

    /// Whether anything can be checked at all: confirmed, and at least one anchor counts.
    pub fn carries(&self) -> bool {
        self.anchor_state == AnchorState::Confirmed
            && self.anchors.iter().any(|a| self.anchor_applies(a.kid()))
    }

    /// The self-computed fingerprint of the stored anchor set.
    pub fn fingerprint(&self) -> AnchorFingerprint {
        AnchorFingerprint::from_jwks(self.anchors.iter().map(KeyEntry::jwk))
    }

    /// The stored revocation for `kid`.
    pub fn revocation_to(&self, kid: &str) -> Option<&Revocation> {
        self.revoke.iter().find(|w| w.kid() == kid)
    }

    /// State of the set.
    pub fn key_set_version(&self) -> u64 {
        self.key_set_version
    }

    /// `issuer`, as stored at enrollment.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// `tenantId`, as stored at enrollment.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The state of the anchor set.
    pub fn anchor_state(&self) -> AnchorState {
        self.anchor_state
    }

    /// The anchors.
    pub fn anchors(&self) -> &[KeyEntry] {
        &self.anchors
    }

    /// The evidence keys, expired ones included (they stay checkable for old material).
    pub fn signature_signing_key(&self) -> &[KeyEntry] {
        &self.signature_signing_key
    }

    /// The `kid`s of the evidence keys, ascending — `signingKidsHeld` in the heartbeat.
    pub fn signature_kids(&self) -> Vec<&str> {
        let mut kids: Vec<&str> = self.signature_signing_key.iter().map(KeyEntry::kid).collect();
        kids.sort_unstable();
        kids
    }

    /// The revocations; once stored, never gone again.
    pub fn revoke(&self) -> &[Revocation] {
        &self.revoke
    }

    /// New anchors without a counter-signature; they have no effect (P10).
    pub fn pending_anchors(&self) -> &[KeyEntry] {
        &self.pending_anchors
    }

    /// `generatedAt` of the last accepted answer.
    pub fn generated_at(&self) -> Option<Timestamp> {
        self.generated_at
    }

    /// `refreshAfter` — a hint about when to fetch again, not an expiry of the set.
    pub fn refresh_after(&self) -> Option<Timestamp> {
        self.refresh_after
    }

    /// `nextRotationAt`.
    pub fn next_rotation_at(&self) -> Option<Timestamp> {
        self.next_rotation_at
    }

    /// The local store: every entry in its raw form, so that the signatures go over the same
    /// bytes on the next load. A database row is no proof — the check is redone at every use
    /// ([`KeySet::check_carrier`]).
    pub fn as_storage(&self) -> Value {
        let raw = |list: &[KeyEntry]| -> Vec<Value> {
            list.iter().map(|e| e.as_json().clone()).collect()
        };
        let time = |z: Option<Timestamp>| z.map_or(Value::Null, |z| Value::from(z.rfc3339()));
        json!({
            "version": STORE_VERSION,
            "keySetVersion": self.key_set_version,
            "issuer": self.issuer,
            "tenantId": self.tenant_id,
            "anchorState": self.anchor_state.contract_value(),
            "trustAnchors": raw(&self.anchors),
            "signingKeys": raw(&self.signature_signing_key),
            "revocations": self.revoke.iter().map(|w| w.as_json().clone()).collect::<Vec<_>>(),
            "pendingAnchors": raw(&self.pending_anchors),
            "generatedAt": time(self.generated_at),
            "refreshAfter": time(self.refresh_after),
            "nextRotationAt": time(self.next_rotation_at),
        })
    }

    /// Reads the local store. An unreadable entry is an error, not a silent omission: a damaged
    /// store should be noticed, not yield a smaller set.
    pub fn from_storage(storage: &Value) -> Result<Self, CryptoError> {
        const WHAT: &str = "The store of the key set";
        let unreadable =
            |reason: &str| CryptoError::Unreadable { what: WHAT, reason: reason.to_owned() };
        let object = storage.as_object().ok_or_else(|| unreadable("it is not a JSON object"))?;
        if object.get("version").and_then(Value::as_u64) != Some(STORE_VERSION) {
            return Err(unreadable("the version is unknown"));
        }
        let text = |name: &str| -> Result<String, CryptoError> {
            object
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| unreadable(&format!("{name} is missing")))
        };
        let list = |name: &str| -> Result<&Vec<Value>, CryptoError> {
            object
                .get(name)
                .and_then(Value::as_array)
                .ok_or_else(|| unreadable(&format!("{name} is missing")))
        };
        let key = |name: &str| -> Result<Vec<KeyEntry>, CryptoError> {
            list(name)?.iter().map(KeyEntry::from_json).collect()
        };
        let time = |name: &str| -> Result<Option<Timestamp>, CryptoError> {
            match object.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(t)) => {
                    Timestamp::from_rfc3339(t).map(Some).map_err(|f| unreadable(&f.to_string()))
                }
                Some(_) => Err(unreadable(&format!("{name} is no point in time"))),
            }
        };
        let state = text("anchorState")?;
        Ok(Self {
            key_set_version: object
                .get("keySetVersion")
                .and_then(Value::as_u64)
                .ok_or_else(|| unreadable("keySetVersion is missing"))?,
            issuer: text("issuer")?,
            tenant_id: text("tenantId")?,
            anchor_state: AnchorState::from_contract_value(&state)
                .ok_or_else(|| unreadable("anchorState is unknown"))?,
            anchors: key("trustAnchors")?,
            signature_signing_key: key("signingKeys")?,
            revoke: list("revocations")?
                .iter()
                .map(Revocation::from_json)
                .collect::<Result<_, _>>()?,
            pending_anchors: key("pendingAnchors")?,
            generated_at: time("generatedAt")?,
            refresh_after: time("refreshAfter")?,
            next_rotation_at: time("nextRotationAt")?,
        })
    }
}

impl Serialize for KeySet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_storage().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeySet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_storage(&value).map_err(serde::de::Error::custom)
    }
}

/// Checks the signature of a delivery command against the anchored set (ADR-D04).
///
/// `[GAP → PROPOSAL]`: the command carries `serverSignature` (detached JWS, `typ`
/// [`TYP_DELIVERY_COMMAND`], signed by an `evidence-signing` key) over
/// `JCS(Command without serverSignature)`, and the signing time in [`FIELD_COMMAND_TIME`].
///
/// If the check fails, nothing is executed, the acknowledgement reads `REJECTED`, and the usage
/// log shows a security warning. Without a confirmed anchor it always fails — when in doubt,
/// preserve (geraete-auth §5.8). An unknown `kid` ([`CryptoError::UnknownKid`]) is the occasion
/// to reconcile the key set and then check again.
pub fn check_command_signature(command: &Value, set: &KeySet) -> Result<(), CryptoError> {
    if !set.carries() {
        return Err(CryptoError::NotAnchored { state: set.anchor_state() });
    }
    let timestamp = command
        .get(FIELD_COMMAND_TIME)
        .and_then(Value::as_str)
        .and_then(|text| Timestamp::from_rfc3339(text).ok())
        .ok_or(CryptoError::SignatureTimeMissing { field: FIELD_COMMAND_TIME })?;
    set.check_carrier(command, TYP_DELIVERY_COMMAND, timestamp).map(|_| ())
}
