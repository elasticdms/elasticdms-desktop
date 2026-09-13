//! The forge — the counterpart to the checking, for the mock and for tests.
//!
//! What this crate checks are the acceptance rules P1 to P12 (03 §6.2.4) and the eight steps of
//! the DPoP check (geraete-auth §2.4). Every single one of them hangs on a signature over
//! canonicalized bytes. A mock that returns “valid” would only prove that the test case believes
//! what it claimed itself; the faults that matter — a shifted field, a wrong canonicalization, a
//! self-vouching that slips through — it would not find. That is why the forge computes for real,
//! like the one of the sibling client (escan `Schluesselwerkstatt`).
//!
//! **The forge knows no rule.** On request it builds the anchor with the wrong role, the entry
//! that counter-signs itself, the revocation of a foreign tenant, the signature over bytes other
//! than the checked ones. A fixture that only produces valid material is no good for half the
//! cases that matter here. What a statement **means** is decided by the caller.
//!
//! **Never in a release.** The module hangs on the `forge` feature; only `edms-mock` pulls it in
//! as a normal dependency. This crate's tests compile it anyway (`cfg(test)`).
//!
//! Two halves:
//!
//! * **Building** — [`TestKey`] and [`Forge`]: anchors, key statements (`edms-server-key+jwt`),
//!   revocations (`edms-server-key-revocation+jwt`), the whole `serverKeys` block, the enrollment
//!   answer and signed delivery commands (`edms-delivery-command+jwt`, ADR-D04).
//! * **Checking** — [`DpopVerifier`]: the server side of RFC 9449 in the normative order from
//!   geraete-auth §2.4, with its own sentence per failure. A test rig that only says “invalid”
//!   leaves the client guessing which of the eight steps was meant.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use edms_core::time::Timestamp;
use serde_json::{Map, Value};

use crate::anchor::AnchorFingerprint;
use crate::jws::{self, CompactJws, FIELD_SIGNATURE};
use crate::key::{Jwk, PublicKey, SigningKey, SoftwareKey};
use crate::key_set::{
    FIELD_COMMAND_TIME, KeyRole, RevocationReason, TYP_DELIVERY_COMMAND, TYP_KEY_STATEMENT,
    TYP_REVOCATION,
};
use crate::{ALG, CryptoError, dpop, jcs};

/// The issuer the forge uses without further specification (03 §6.2.4, example).
pub const DEFAULT_ISSUER: &str = "https://api.elasticdms.io";

/// The tenant the forge uses without further specification.
pub const DEFAULT_TENANT: &str = "t_acme";

/// The device identifier of the enrollment answer without further specification (03 §6.2.1,
/// example).
///
// geraete-auth §3.1 / 03 §6.2.1 — the example there reads
// `dev_01JB8Z5K3M4N6P7Q8R9S0T1U2V` and carries a `U` at position 24. The Crockford alphabet from
// §2.2 (`edms_core::identifier::ALPHABET`) knows neither `I`, `L`, `O` nor `U`; the example
// identifier therefore cannot be read. The forge delivers the same sequence ending in `V2W`, so
// that a client which really evaluates the mock's answer does not fail on a typo of the contract
// example.
pub const DEFAULT_DEVICE: &str = "dev_01JB8Z5K3M4N6P7Q8R9S0T1V2W";

/// The device state of the enrollment answer without further specification.
pub const DEFAULT_STATE: &str = "pending_admin_approval";

/// `notBefore` of a test key without further specification: 2020-01-01T00:00:00Z.
pub const DEFAULT_NOT_BEFORE: Timestamp = Timestamp::from_unix_millis(1_577_836_800_000);

/// `notAfter` of a test key without further specification: 2099-01-01T00:00:00Z.
pub const DEFAULT_NOT_AFTER: Timestamp = Timestamp::from_unix_millis(4_070_908_800_000);

/// `generatedAt` of a block without further specification: 2026-09-02T08:14:22Z (as in escan).
pub const DEFAULT_GENERATED_AT: Timestamp = Timestamp::from_unix_millis(1_788_336_862_000);

/// `refreshAfter` of a block without further specification: seven days after
/// [`DEFAULT_GENERATED_AT`].
pub const DEFAULT_REFRESH_AFTER: Timestamp = Timestamp::from_unix_millis(1_788_941_662_000);

/// `nextRotationAt` of a block without further specification: 2027-06-01T00:00:00Z.
pub const DEFAULT_NEXT_ROTATION: Timestamp = Timestamp::from_unix_millis(1_811_808_000_000);

/// `revokedAt` of a revocation without further specification: 2026-08-14T11:02:00Z (as in escan).
pub const DEFAULT_REVOKED_AT: Timestamp = Timestamp::from_unix_millis(1_786_705_320_000);

/// The custody of an anchor without further specification (`custody`).
pub const DEFAULT_CUSTODY: &str = "offline-hsm";

/// How long a `jti` stays in the verifier's replay cache (geraete-auth §2.4 point 6).
pub const REPLAY_WINDOW_MILLIS: i64 = 10 * 60 * 1_000;

// ───────────────────────────── Building: keys and carriers ─────────────────────────────

/// A real P-256 key pair with the labelling the contract gives it.
///
/// [`TestKey::role`] stands **inside** the signed bytes (geraete-auth §5.1). An evidence key
/// therefore cannot redeclare itself an anchor — and a test that tries has to forge the field
/// ([`EntryBuilder::with_role`]) and not merely write an expectation differently.
#[derive(Debug)]
pub struct TestKey {
    kid: String,
    role: KeyRole,
    not_before: Timestamp,
    not_after: Timestamp,
    key_set_version: Option<u64>,
    supersedes: Option<String>,
    custody: String,
    key: SoftwareKey,
}

impl TestKey {
    /// A fresh pair with the named role and the default window.
    pub fn new(kid: &str, role: KeyRole) -> Result<Self, CryptoError> {
        Ok(Self::from_key(kid, role, SoftwareKey::generate()?))
    }

    /// A fresh pair with the role `trust-anchor`.
    pub fn anchor_key(kid: &str) -> Result<Self, CryptoError> {
        Self::new(kid, KeyRole::TrustAnchor)
    }

    /// A fresh pair with the role `evidence-signing`.
    pub fn proof(kid: &str) -> Result<Self, CryptoError> {
        Self::new(kid, KeyRole::ProofSignature)
    }

    /// A pair from existing material — for vectors that have to be reproducible.
    pub fn from_key(kid: &str, role: KeyRole, key: SoftwareKey) -> Self {
        Self {
            kid: kid.to_owned(),
            role,
            not_before: DEFAULT_NOT_BEFORE,
            not_after: DEFAULT_NOT_AFTER,
            key_set_version: None,
            supersedes: None,
            custody: DEFAULT_CUSTODY.to_owned(),
            key,
        }
    }

    /// Sets `notBefore` and `notAfter` — the bounds where P12 bites.
    #[must_use]
    pub fn with_window(mut self, not_before: Timestamp, not_after: Timestamp) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    /// Sets the entry's `keySetVersion`: the state in which the key was introduced.
    #[must_use]
    pub fn with_key_set_version(mut self, state: u64) -> Self {
        self.key_set_version = Some(state);
        self
    }

    /// Sets `supersedes`: the key that was superseded.
    #[must_use]
    pub fn with_supersedes(mut self, kid: &str) -> Self {
        self.supersedes = Some(kid.to_owned());
        self
    }

    /// Sets an anchor's `custody`.
    #[must_use]
    pub fn with_custody(mut self, custody: &str) -> Self {
        self.custody = custody.to_owned();
        self
    }

    /// The key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The role.
    pub fn role(&self) -> KeyRole {
        self.role
    }

    /// `notBefore`.
    pub fn not_before(&self) -> Timestamp {
        self.not_before
    }

    /// `notAfter`.
    pub fn not_after(&self) -> Timestamp {
        self.not_after
    }

    /// The entry's `keySetVersion`, if set.
    pub fn key_set_version(&self) -> Option<u64> {
        self.key_set_version
    }

    /// `supersedes`, if set.
    pub fn supersedes(&self) -> Option<&str> {
        self.supersedes.as_deref()
    }

    /// `custody`.
    pub fn custody(&self) -> &str {
        &self.custody
    }

    /// The public part as a JWK.
    pub fn jwk(&self) -> Jwk {
        self.key.public().jwk().clone()
    }

    /// The public part, checked on the curve.
    pub fn public(&self) -> PublicKey {
        self.key.public()
    }

    /// The RFC 7638 thumbprint — the same value the device computes.
    pub fn thumbprint(&self) -> String {
        self.key.public().thumbprint()
    }

    /// The key as a signer, for instance for [`crate::dpop::proof`].
    pub fn signing_key(&self) -> &dyn SigningKey {
        &self.key
    }

    /// A detached signature over `signed_bytes`: `<b64u(header)>..<b64u(signature)>`.
    ///
    /// Over the whole JWS input, not only over the header (geraete-auth §5.5, pitfall 2). Whoever
    /// takes the shortcut here later checks a verifier that takes the same shortcut.
    pub fn sign(&self, signed_bytes: &[u8], typ: &str) -> Result<String, CryptoError> {
        jws::sign_detached(signed_bytes, typ, &self.kid, &self.key)
    }
}

/// Builds the blocks from 03 §6.2.4 — enrollment answer, `GET /v1/server-keys`, revocations —
/// and the signed delivery commands from ADR-D04.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forge {
    issuer: String,
    tenant_id: String,
}

impl Default for Forge {
    fn default() -> Self {
        Self::new()
    }
}

impl Forge {
    /// A forge for [`DEFAULT_ISSUER`] and [`DEFAULT_TENANT`].
    pub fn new() -> Self {
        Self::for_tenant(DEFAULT_ISSUER, DEFAULT_TENANT)
    }

    /// A forge for a particular issuer and tenant.
    pub fn for_tenant(issuer: &str, tenant_id: &str) -> Self {
        Self { issuer: issuer.to_owned(), tenant_id: tenant_id.to_owned() }
    }

    /// The issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The tenant.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Begins a key entry — anchor or key statement, depending on how it is finished.
    pub fn entry<'a>(&self, key: &'a TestKey) -> EntryBuilder<'a> {
        EntryBuilder {
            key,
            issuer: self.issuer.clone(),
            tenant_id: self.tenant_id.clone(),
            role: key.role().contract_value().to_owned(),
            thumbprint: Some(key.thumbprint()),
            typ: TYP_KEY_STATEMENT.to_owned(),
            tampered: false,
        }
    }

    /// Begins a revocation for `kid`.
    pub fn revocation(&self, kid: &str, reason: RevocationReason) -> RevocationBuilder {
        RevocationBuilder {
            kid: kid.to_owned(),
            issuer: self.issuer.clone(),
            tenant_id: self.tenant_id.clone(),
            role: Some(KeyRole::ProofSignature.contract_value().to_owned()),
            revoked_at: DEFAULT_REVOKED_AT,
            compromised_since: None,
            reason: reason.contract_value().to_owned(),
            key_set_version: None,
            reissued_as: None,
            typ: TYP_REVOCATION.to_owned(),
        }
    }

    /// Begins the `serverKeys` block for the state `key_set_version`.
    pub fn block(&self, key_set_version: u64) -> BlockBuilder {
        BlockBuilder {
            key_set_version,
            issuer: self.issuer.clone(),
            tenant_id: self.tenant_id.clone(),
            anchors: Vec::new(),
            signature_signing_key: Vec::new(),
            revoke: Vec::new(),
            fingerprint: FingerprintChoice::Computed,
            generated_at: Some(DEFAULT_GENERATED_AT),
            refresh_after: Some(DEFAULT_REFRESH_AFTER),
            next_rotation_at: Some(DEFAULT_NEXT_ROTATION),
        }
    }

    /// Begins a delivery command (ADR-D04).
    pub fn command(&self, command_id: &str, kind: &str) -> CommandBuilder {
        CommandBuilder {
            command_id: command_id.to_owned(),
            kind: kind.to_owned(),
            issued_at: Some(DEFAULT_GENERATED_AT),
            payload: Value::Object(Map::new()),
            to_set: Map::new(),
            typ: TYP_DELIVERY_COMMAND.to_owned(),
        }
    }

    /// The enrollment answer from 03 §6.2.1, shortened to the fields that count here.
    pub fn enrollment_response(&self, block: Value) -> Value {
        self.enrollment_response_for(block, DEFAULT_DEVICE, DEFAULT_STATE)
    }

    /// The same answer with its own device identifier and its own state.
    pub fn enrollment_response_for(&self, block: Value, device: &str, state: &str) -> Value {
        let mut response = Map::new();
        response.insert("deviceId".into(), Value::from(device));
        response.insert("state".into(), Value::from(state));
        response.insert("serverKeys".into(), block);
        Value::Object(response)
    }
}

/// The fingerprint over a list of anchor entries — the same computation as in the device.
///
/// A test case needs it in order to **expect** what the device computes; it is never the source
/// the device takes it from (geraete-auth §5.3). An anchor without readable coordinates is an
/// error and not a skipped entry: otherwise the fingerprint would be over fewer anchors than were
/// delivered, and the test case would not notice.
pub fn fingerprint(anchors: &[Value]) -> Result<AnchorFingerprint, CryptoError> {
    let thumbprints: Result<Vec<String>, CryptoError> = anchors.iter().map(thumbprint_of).collect();
    Ok(AnchorFingerprint::from_thumbprint(&thumbprints?))
}

fn thumbprint_of(anchor: &Value) -> Result<String, CryptoError> {
    let coordinate = |name: &str| anchor.get(name).and_then(Value::as_str);
    let (Some(x), Some(y)) = (coordinate("x"), coordinate("y")) else {
        return Err(CryptoError::Unreadable {
            what: "An anchor entry of the forge",
            reason: "x or y is missing; without them the anchor fingerprint cannot be computed"
                .into(),
        });
    };
    Ok(Jwk::new(x, y)?.thumbprint())
}

/// A key entry under construction — [`EntryBuilder::as_anchor`] or [`EntryBuilder::signed_by`]
/// finishes it.
#[derive(Debug, Clone)]
pub struct EntryBuilder<'a> {
    key: &'a TestKey,
    issuer: String,
    tenant_id: String,
    role: String,
    thumbprint: Option<String>,
    typ: String,
    tampered: bool,
}

impl EntryBuilder<'_> {
    /// A foreign issuer — the case P7 rejects.
    #[must_use]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = issuer.to_owned();
        self
    }

    /// A foreign tenant — the case P7 rejects.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = tenant_id.to_owned();
        self
    }

    /// A differing or unknown role in the `role` field — the case P6 rejects.
    #[must_use]
    pub fn with_role(mut self, role: &str) -> Self {
        self.role = role.to_owned();
        self
    }

    /// A reported thumbprint that does not match the own computation.
    #[must_use]
    pub fn with_thumbprint(mut self, thumbprint: &str) -> Self {
        self.thumbprint = Some(thumbprint.to_owned());
        self
    }

    /// No `thumbprint` field — allowed, because the own computation is authoritative.
    #[must_use]
    pub fn without_thumbprint(mut self) -> Self {
        self.thumbprint = None;
        self
    }

    /// Another media type in the protected header — the case P11 rejects.
    #[must_use]
    pub fn with_typ(mut self, typ: &str) -> Self {
        self.typ = typ.to_owned();
        self
    }

    /// Signs over **other** bytes than the ones checked later.
    ///
    /// The signature is real, it just does not cover this entry. That is exactly what the attack
    /// P2 wards off looks like — and exactly what a canonicalization fault that went unnoticed
    /// would look like.
    #[must_use]
    pub fn tampered(mut self) -> Self {
        self.tampered = true;
        self
    }

    /// The entry without the signature field — the bytes that are signed over.
    pub fn unsigned(&self) -> Value {
        let mut field = self.field();
        if let Some(state) = self.key.key_set_version() {
            field.insert("keySetVersion".into(), Value::from(state));
        }
        let supersedes = self.key.supersedes().map_or(Value::Null, Value::from);
        field.insert("supersedes".into(), supersedes);
        Value::Object(field)
    }

    /// An anchor entry. `serverSignature` is **always** `null`: a self-signed anchor attests
    /// only that somebody holds the private part — which the forger holds too
    /// (geraete-auth §5.4).
    pub fn as_anchor(&self) -> Value {
        let mut field = self.field();
        field.insert("custody".into(), Value::from(self.key.custody()));
        field.insert(FIELD_SIGNATURE.into(), Value::Null);
        Value::Object(field)
    }

    /// A key statement, counter-signed by `signer`.
    ///
    /// If `signer` is the same key, a **self-signed** entry arises — the case P4 rejects and
    /// contract test T8 has to be able to present.
    pub fn signed_by(&self, signer: &TestKey) -> Result<Value, CryptoError> {
        let mut entry = self.unsigned();
        let bytes = if self.tampered {
            let mut other = entry.clone();
            other["kid"] = Value::from(format!("{}-other", self.key.kid()));
            jcs::canonicalize_bytes(&other)?
        } else {
            jcs::canonicalize_bytes(&entry)?
        };
        entry[FIELD_SIGNATURE] = Value::from(signer.sign(&bytes, &self.typ)?);
        Ok(entry)
    }

    fn field(&self) -> Map<String, Value> {
        let jwk = self.key.jwk();
        let mut field = Map::new();
        field.insert("kid".into(), Value::from(self.key.kid()));
        field.insert("kty".into(), Value::from(Jwk::KTY));
        field.insert("crv".into(), Value::from(Jwk::CRV));
        field.insert("x".into(), Value::from(jwk.x()));
        field.insert("y".into(), Value::from(jwk.y()));
        field.insert("alg".into(), Value::from(ALG));
        field.insert("use".into(), Value::from("sig"));
        field.insert("role".into(), Value::from(self.role.as_str()));
        field.insert("issuer".into(), Value::from(self.issuer.as_str()));
        field.insert("tenantId".into(), Value::from(self.tenant_id.as_str()));
        field.insert("notBefore".into(), Value::from(self.key.not_before().rfc3339()));
        field.insert("notAfter".into(), Value::from(self.key.not_after().rfc3339()));
        if let Some(thumbprint) = &self.thumbprint {
            field.insert("thumbprint".into(), Value::from(thumbprint.as_str()));
        }
        field
    }
}

/// A revocation under construction.
#[derive(Debug, Clone)]
pub struct RevocationBuilder {
    kid: String,
    issuer: String,
    tenant_id: String,
    role: Option<String>,
    revoked_at: Timestamp,
    compromised_since: Option<Timestamp>,
    reason: String,
    key_set_version: Option<u64>,
    reissued_as: Option<String>,
    typ: String,
}

impl RevocationBuilder {
    /// A foreign issuer (P7).
    #[must_use]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = issuer.to_owned();
        self
    }

    /// A foreign tenant (P7).
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = tenant_id.to_owned();
        self
    }

    /// The role of the revoked key.
    #[must_use]
    pub fn with_role(mut self, role: &str) -> Self {
        self.role = Some(role.to_owned());
        self
    }

    /// No `role` field — allowed; the revocation counts through the `kid`.
    #[must_use]
    pub fn without_role(mut self) -> Self {
        self.role = None;
        self
    }

    /// `revokedAt`.
    #[must_use]
    pub fn at(mut self, timestamp: Timestamp) -> Self {
        self.revoked_at = timestamp;
        self
    }

    /// `compromisedSince` — from when the suspicion acts retroactively (geraete-auth §5.7).
    #[must_use]
    pub fn compromised_since(mut self, timestamp: Timestamp) -> Self {
        self.compromised_since = Some(timestamp);
        self
    }

    /// `keySetVersion` in which the revocation was published.
    #[must_use]
    pub fn with_key_set_version(mut self, state: u64) -> Self {
        self.key_set_version = Some(state);
        self
    }

    /// `reissuedAs` — the successor the key is reissued as.
    #[must_use]
    pub fn reissued_as(mut self, kid: &str) -> Self {
        self.reissued_as = Some(kid.to_owned());
        self
    }

    /// Another media type in the protected header (P11).
    #[must_use]
    pub fn with_typ(mut self, typ: &str) -> Self {
        self.typ = typ.to_owned();
        self
    }

    /// The revocation without the signature field.
    pub fn unsigned(&self) -> Value {
        let mut field = Map::new();
        field.insert("kid".into(), Value::from(self.kid.as_str()));
        if let Some(role) = &self.role {
            field.insert("role".into(), Value::from(role.as_str()));
        }
        field.insert("issuer".into(), Value::from(self.issuer.as_str()));
        field.insert("tenantId".into(), Value::from(self.tenant_id.as_str()));
        field.insert("revokedAt".into(), Value::from(self.revoked_at.rfc3339()));
        let since = self.compromised_since.map_or(Value::Null, |z| Value::from(z.rfc3339()));
        field.insert("compromisedSince".into(), since);
        field.insert("reason".into(), Value::from(self.reason.as_str()));
        if let Some(state) = self.key_set_version {
            field.insert("keySetVersion".into(), Value::from(state));
        }
        if let Some(successor) = &self.reissued_as {
            field.insert("reissuedAs".into(), Value::from(successor.as_str()));
        }
        Value::Object(field)
    }

    /// The revocation, counter-signed by `signer`.
    ///
    /// An anchor does not revoke itself: the revocation would then be just as forgeable as the
    /// anchor (geraete-auth §5.1). The forge builds this case too — rejecting it is the checking's
    /// job.
    pub fn signed_by(&self, signer: &TestKey) -> Result<Value, CryptoError> {
        let mut revocation = self.unsigned();
        let bytes = jcs::canonicalize_bytes(&revocation)?;
        revocation[FIELD_SIGNATURE] = Value::from(signer.sign(&bytes, &self.typ)?);
        Ok(revocation)
    }
}

/// Where the value of `anchorSetFingerprint` in the built block comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FingerprintChoice {
    /// Computed over the anchors itself — the honest server.
    Computed,
    /// A claimed value — the test case in which server and device diverge.
    Reported(String),
    /// The field is missing entirely; the device computes for itself anyway.
    Omitted,
}

/// The `serverKeys` block under construction.
#[derive(Debug, Clone)]
pub struct BlockBuilder {
    key_set_version: u64,
    issuer: String,
    tenant_id: String,
    anchors: Vec<Value>,
    signature_signing_key: Vec<Value>,
    revoke: Vec<Value>,
    fingerprint: FingerprintChoice,
    generated_at: Option<Timestamp>,
    refresh_after: Option<Timestamp>,
    next_rotation_at: Option<Timestamp>,
}

impl BlockBuilder {
    /// The anchors (`trustAnchors`).
    #[must_use]
    pub fn with_anchor(mut self, anchors: impl IntoIterator<Item = Value>) -> Self {
        self.anchors = anchors.into_iter().collect();
        self
    }

    /// The evidence keys (`signingKeys`).
    #[must_use]
    pub fn with_key(mut self, key: impl IntoIterator<Item = Value>) -> Self {
        self.signature_signing_key = key.into_iter().collect();
        self
    }

    /// The revocations (`revocations`); an empty list leaves the field out.
    #[must_use]
    pub fn with_revoked(mut self, revoke: impl IntoIterator<Item = Value>) -> Self {
        self.revoke = revoke.into_iter().collect();
        self
    }

    /// A foreign issuer (P7).
    #[must_use]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = issuer.to_owned();
        self
    }

    /// A foreign tenant (P7).
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = tenant_id.to_owned();
        self
    }

    /// A claimed fingerprint instead of the computed one.
    #[must_use]
    pub fn with_reported_fingerprint(mut self, display: &str) -> Self {
        self.fingerprint = FingerprintChoice::Reported(display.to_owned());
        self
    }

    /// Without the `anchorSetFingerprint` field.
    #[must_use]
    pub fn without_fingerprint(mut self) -> Self {
        self.fingerprint = FingerprintChoice::Omitted;
        self
    }

    /// The three timestamps of the block.
    #[must_use]
    pub fn with_time(
        mut self,
        generated_at: Timestamp,
        refresh_after: Timestamp,
        next_rotation_at: Timestamp,
    ) -> Self {
        self.generated_at = Some(generated_at);
        self.refresh_after = Some(refresh_after);
        self.next_rotation_at = Some(next_rotation_at);
        self
    }

    /// Without the three timestamps.
    #[must_use]
    pub fn without_time(mut self) -> Self {
        self.generated_at = None;
        self.refresh_after = None;
        self.next_rotation_at = None;
        self
    }

    /// The finished block.
    ///
    /// Fails when the fingerprint is to be computed and an anchor has no readable coordinates —
    /// a silent fingerprint over fewer anchors would be worse than an error.
    pub fn builder(&self) -> Result<Value, CryptoError> {
        let mut field = Map::new();
        field.insert("keySetVersion".into(), Value::from(self.key_set_version));
        field.insert("issuer".into(), Value::from(self.issuer.as_str()));
        field.insert("tenantId".into(), Value::from(self.tenant_id.as_str()));
        for (name, timestamp) in [
            ("generatedAt", self.generated_at),
            ("refreshAfter", self.refresh_after),
            ("nextRotationAt", self.next_rotation_at),
        ] {
            if let Some(timestamp) = timestamp {
                field.insert(name.into(), Value::from(timestamp.rfc3339()));
            }
        }
        match &self.fingerprint {
            FingerprintChoice::Computed => {
                let computed = fingerprint(&self.anchors)?;
                field.insert("anchorSetFingerprint".into(), Value::from(computed.display()));
            }
            FingerprintChoice::Reported(display) => {
                field.insert("anchorSetFingerprint".into(), Value::from(display.as_str()));
            }
            FingerprintChoice::Omitted => {}
        }
        field.insert("trustAnchors".into(), Value::Array(self.anchors.clone()));
        field.insert("signingKeys".into(), Value::Array(self.signature_signing_key.clone()));
        if !self.revoke.is_empty() {
            field.insert("revocations".into(), Value::Array(self.revoke.clone()));
        }
        Ok(Value::Object(field))
    }
}

/// A delivery command under construction (ADR-D04).
///
/// `[GAP → PROPOSAL]` (digest §2.12): the counterpart's contract knows no delivery channel. The
/// shape is `{ commandId, kind, issuedAt, payload, serverSignature }`; signing follows the one
/// rule from geraete-auth §5.2 over `JCS(Command without serverSignature)` with
/// [`TYP_DELIVERY_COMMAND`] and an `evidence-signing` key.
#[derive(Debug, Clone)]
pub struct CommandBuilder {
    command_id: String,
    kind: String,
    issued_at: Option<Timestamp>,
    payload: Value,
    to_set: Map<String, Value>,
    typ: String,
}

impl CommandBuilder {
    /// The payload (`payload`).
    #[must_use]
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    /// The signing time (`issuedAt`, [`FIELD_COMMAND_TIME`]).
    #[must_use]
    pub fn from_posed(mut self, timestamp: Timestamp) -> Self {
        self.issued_at = Some(timestamp);
        self
    }

    /// Without `issuedAt` — then P12 cannot be checked, and the signature does not count.
    #[must_use]
    pub fn without_timestamp(mut self) -> Self {
        self.issued_at = None;
        self
    }

    /// One more field. It is part of the signed bytes (P2), even if no reader knows it.
    #[must_use]
    pub fn with_field(mut self, name: &str, value: Value) -> Self {
        self.to_set.insert(name.to_owned(), value);
        self
    }

    /// Another media type in the protected header (P11).
    #[must_use]
    pub fn with_typ(mut self, typ: &str) -> Self {
        self.typ = typ.to_owned();
        self
    }

    /// The command without the signature field.
    pub fn unsigned(&self) -> Value {
        let mut field = Map::new();
        field.insert("commandId".into(), Value::from(self.command_id.as_str()));
        field.insert("kind".into(), Value::from(self.kind.as_str()));
        if let Some(timestamp) = self.issued_at {
            field.insert(FIELD_COMMAND_TIME.into(), Value::from(timestamp.rfc3339()));
        }
        field.insert("payload".into(), self.payload.clone());
        for (name, value) in &self.to_set {
            field.insert(name.clone(), value.clone());
        }
        Value::Object(field)
    }

    /// The command, signed by `signer`.
    pub fn signed_by(&self, signer: &TestKey) -> Result<Value, CryptoError> {
        let mut command = self.unsigned();
        let bytes = jcs::canonicalize_bytes(&command)?;
        command[FIELD_SIGNATURE] = Value::from(signer.sign(&bytes, &self.typ)?);
        Ok(command)
    }
}

// ───────────────────────────── Checking: DPoP, server side ─────────────────────────────

/// What the server knows about the request the proof belongs to.
///
/// **Point 4 is where it goes wrong silently** (geraete-auth §2.4): behind a load balancer the
/// raw path is an internal one. [`DpopCheckRequest::url`] has to be the **externally visible**
/// URL; whoever builds it from the internal host rejects every honest proof, and the fault looks
/// like a client fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpopCheckRequest<'a> {
    /// The method the request really arrived with.
    pub method: &'a str,
    /// The externally visible target URL; query and fragment are cut off for the comparison.
    pub url: &'a str,
    /// The nonce this server issued for this origin. `None` means “none is demanded here”; a
    /// nonce carried along then does not disturb (RFC 9449 §8).
    pub nonce: Option<&'a str>,
    /// The access token from `Authorization: DPoP <token>`, without the prefix.
    pub access_token: Option<&'a str>,
    /// `cnf.jkt` of the access token — the binding to the key (geraete-auth §2.4 point 8).
    pub bound_jkt: Option<&'a str>,
    /// The server time; it enters only the replay cache and an explicitly requested time
    /// window.
    pub now: Timestamp,
    /// The allowed window around `iat`, in seconds.
    ///
    /// `None` is the contractual default: **`iat` is not checked against the server clock**
    /// (geraete-auth §2.4 point 7). In a segmented company network the device clock goes wrong
    /// after every power cut, and a clock check would then refuse every call; the freshness comes
    /// from the nonce. A test case that wants to see the window anyway says so here explicitly.
    pub time_window_second: Option<i64>,
}

impl<'a> DpopCheckRequest<'a> {
    /// A request without nonce, without token and without a time window.
    pub fn new(method: &'a str, url: &'a str, now: Timestamp) -> Self {
        Self {
            method,
            url,
            nonce: None,
            access_token: None,
            bound_jkt: None,
            now,
            time_window_second: None,
        }
    }

    /// This resource demands exactly this nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: &'a str) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// The request carries this access token; `ath` has to match it.
    #[must_use]
    pub fn with_access_token(mut self, token: &'a str) -> Self {
        self.access_token = Some(token);
        self
    }

    /// The access token is bound to this thumbprint (`cnf.jkt`).
    #[must_use]
    pub fn bound_to(mut self, jkt: &'a str) -> Self {
        self.bound_jkt = Some(jkt);
        self
    }

    /// Checks `iat` against the server clock after all, with this window in seconds.
    #[must_use]
    pub fn with_time_window(mut self, second: i64) -> Self {
        self.time_window_second = Some(second);
        self
    }
}

/// What is settled after an accepted proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofReport {
    /// The RFC 7638 thumbprint of the presented key — `dpop_jkt`, `cnf.jkt`.
    pub jkt: String,
    /// The `jti`; it now sits in the replay cache.
    pub jti: String,
    /// `htm`.
    pub htm: String,
    /// `htu`.
    pub htu: String,
    /// `iat` in whole seconds.
    pub iat: i64,
    /// The nonce carried along, if there was one.
    pub nonce: Option<String>,
    /// `ath`, if there was one.
    pub ath: Option<String>,
}

/// Why a DPoP proof does not count — one sentence per step from geraete-auth §2.4.
///
/// A test rig that only says “invalid” leaves the client guessing which of the eight steps was
/// meant; in the field that turns into a ticket instead of a correction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The proof is already unreadable as a JWS, or does not name ES256 (point 2).
    #[error("the proof does not hold the shape of RFC 9449 §4.2: {0}")]
    Form(#[from] CryptoError),
    /// The request to be checked is itself unusable — a fault of the test rig, not of the
    /// client.
    #[error("the request to be checked is itself unusable: {0}")]
    Request(CryptoError),
    /// The header names another media type (point 2).
    #[error("the header names typ `{read}`; a DPoP proof carries `dpop+jwt` (RFC 9449 §4.2)")]
    WrongTyp {
        /// The value that was read.
        read: String,
    },
    /// The header carries no usable public key (point 2).
    #[error("the header carries no usable `jwk`: {reason} (geraete-auth §2.4 point 2)")]
    NoJwk {
        /// Why not.
        reason: String,
    },
    /// The header points outwards through `kid` (point 2).
    #[error(
        "the header carries `kid`; the key of a proof stands in the proof and nowhere else \
         (geraete-auth §2.4 point 2)"
    )]
    KidInHeader,
    /// The signature does not match the key carried along (point 3).
    #[error(
        "the signature does not hold against the jwk carried along (geraete-auth §2.4 point 3)"
    )]
    SignatureHoldsNot,
    /// `htm` differs (point 4).
    #[error("htm is `{read}`, the request came as `{expected}` (geraete-auth §2.4 point 4)")]
    MethodMismatch {
        /// The method of the request.
        expected: String,
        /// The value that was read.
        read: String,
    },
    /// `htu` differs (point 4).
    #[error(
        "htu is `{read}`, requested was `{expected}`; the proof counts only for exactly this \
         target (geraete-auth §2.4 point 4)"
    )]
    TargetMismatch {
        /// The externally visible URL without query and fragment.
        expected: String,
        /// The value that was read.
        read: String,
    },
    /// The proof carries no nonce although one is demanded (point 5).
    #[error(
        "the proof carries no nonce; this resource demands one \
         (geraete-auth §2.4 point 5, 03 §6.0.5)"
    )]
    NonceMissing,
    /// The nonce is not the one that was issued (point 5).
    #[error("the nonce `{read}` is not the one that was issued (geraete-auth §2.4 point 5)")]
    NonceMismatch {
        /// The value that was read.
        read: String,
    },
    /// Without a `jti` no replay can be recognized (point 6).
    #[error("the proof carries no usable `jti`; without it a replay cannot be recognized")]
    JtiMissing,
    /// The `jti` was already inside the replay window (point 6).
    #[error(
        "the jti `{jti}` was already inside the replay window; a proof counts exactly once \
         (geraete-auth §2.4 point 6)"
    )]
    RetryAfter {
        /// The `jti` that was presented again.
        jti: String,
    },
    /// `iat` is missing or is not a whole number (point 7).
    #[error("the proof carries no `iat` in whole seconds (RFC 9449 §4.2)")]
    IatMissing,
    /// `iat` lies outside the explicitly requested window (point 7).
    #[error(
        "the proof lies {age} s away from the request, allowed are ±{window} s; \
         in operation this check is not run (geraete-auth §2.4 point 7)"
    )]
    TimeWindowMissed {
        /// Server time minus `iat`, in seconds.
        age: i64,
        /// The allowed window.
        window: i64,
    },
    /// The request carries an access token, but the proof carries no `ath` (point 8).
    #[error("the proof carries no `ath`, but the request carries an access token (RFC 9449 §4.2)")]
    AthMissing,
    /// `ath` does not match the access token (point 8).
    #[error("ath is `{read}`, computed is `{computed}` (geraete-auth §2.4 point 8)")]
    AthMismatch {
        /// The value computed here.
        computed: String,
        /// The value that was read.
        read: String,
    },
    /// The proof carries `ath`, but the request carries no access token (point 8).
    #[error(
        "the proof carries ath `{read}`, but the request carries no access token; \
         the proof belongs to another request (RFC 9449 §4.2)"
    )]
    AthUnexpected {
        /// The value that was read.
        read: String,
    },
    /// The token belongs to another key (point 8).
    #[error(
        "the access token is bound to the key {bound}, the proof comes from \
         {read} (geraete-auth §2.4 point 8)"
    )]
    KeyBindingMismatch {
        /// `cnf.jkt` of the token.
        bound: String,
        /// The thumbprint of the presented key.
        read: String,
    },
}

impl From<ProofError> for CryptoError {
    fn from(error: ProofError) -> Self {
        Self::DpopInvalid(error.to_string())
    }
}

/// The server-side check of a DPoP proof, replay cache included.
///
/// The order of the eight steps from geraete-auth §2.4 is **normative** and is kept here: header,
/// signature, `htm`/`htu`, nonce, `jti`, `iat`, `ath`. Whoever checks the signature last answers
/// an attacker without a key which nonce currently counts.
///
/// **Exactly one `DPoP` header** (point 1) is the HTTP layer's business: a single proof already
/// arrives here, and two headers the mock itself has to reject with `400`.
///
/// The `jti` moves into the cache only once the proof is **accepted**. A proof that fails at
/// point 8 is not used up; otherwise an attacker with an intercepted proof and a wrong token
/// could void the honest client's `jti`.
#[derive(Debug)]
pub struct DpopVerifier {
    seen: Mutex<HashMap<String, Timestamp>>,
    window_millis: i64,
}

impl Default for DpopVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DpopVerifier {
    /// A verifier with the contract's replay window ([`REPLAY_WINDOW_MILLIS`]).
    pub fn new() -> Self {
        Self::with_replay_window(REPLAY_WINDOW_MILLIS)
    }

    /// A verifier with its own replay window.
    pub fn with_replay_window(millis: i64) -> Self {
        Self { seen: Mutex::new(HashMap::new()), window_millis: millis }
    }

    /// Forgets every `jti` seen — between two independent scenarios of the mock.
    pub fn forget_everything(&self) {
        self.lock().clear();
    }

    /// Checks a proof against a request.
    pub fn check(
        &self,
        proof: &str,
        request: &DpopCheckRequest<'_>,
    ) -> Result<ProofReport, ProofError> {
        // Point 2: header. `read` already rejects every algorithm other than ES256.
        let jws = CompactJws::read(proof)?;
        let header = jws.header();
        let typ = header.get("typ").and_then(Value::as_str).unwrap_or_default();
        if typ != dpop::TYP {
            return Err(ProofError::WrongTyp { read: typ.to_owned() });
        }
        if header.contains_key("kid") {
            return Err(ProofError::KidInHeader);
        }
        let jwk_value = header
            .get("jwk")
            .ok_or_else(|| ProofError::NoJwk { reason: "the header has no member jwk".into() })?;
        let jwk = Jwk::from_json(jwk_value)
            .map_err(|error| ProofError::NoJwk { reason: error.to_string() })?;
        let public = PublicKey::from_jwk(&jwk)
            .map_err(|error| ProofError::NoJwk { reason: error.to_string() })?;

        // Point 3: signature against the embedded key, not against one looked up somewhere.
        jws.check(&public).map_err(|_| ProofError::SignatureHoldsNot)?;
        let jkt = public.thumbprint();
        let claims = jws.payload();
        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);

        // Point 4: method and target.
        let expected_method = dpop::htm(request.method).map_err(ProofError::Request)?;
        let htm = text("htm").unwrap_or_default();
        if htm != expected_method {
            return Err(ProofError::MethodMismatch { expected: expected_method, read: htm });
        }
        let expected_target = dpop::htu(request.url).map_err(ProofError::Request)?;
        let htu = text("htu").unwrap_or_default();
        if htu != expected_target {
            return Err(ProofError::TargetMismatch { expected: expected_target, read: htu });
        }

        // Point 5: the nonce of this origin.
        let nonce = text("nonce");
        if let Some(expected) = request.nonce {
            match nonce.as_deref() {
                None => return Err(ProofError::NonceMissing),
                Some(read) if read != expected => {
                    return Err(ProofError::NonceMismatch { read: read.to_owned() });
                }
                Some(_) => {}
            }
        }

        // Point 6: replay.
        let jti = text("jti").filter(|j| !j.is_empty()).ok_or(ProofError::JtiMissing)?;
        {
            let mut seen = self.lock();
            let limit = self.window_millis;
            seen.retain(|_, since| {
                request.now.unix_millis().saturating_sub(since.unix_millis()) < limit
            });
            if seen.contains_key(&jti) {
                return Err(ProofError::RetryAfter { jti });
            }
        }

        // Point 7: `iat` is in there, but is held against the clock only on explicit request.
        let iat = claims.get("iat").and_then(Value::as_i64).ok_or(ProofError::IatMissing)?;
        if let Some(window) = request.time_window_second {
            let age = dpop::iat(request.now).saturating_sub(iat);
            if age.abs() > window {
                return Err(ProofError::TimeWindowMissed { age, window });
            }
        }

        // Point 8: token binding.
        let ath = text("ath");
        match (request.access_token, ath.as_deref()) {
            (Some(token), Some(read)) => {
                let computed = dpop::ath(token).map_err(ProofError::Request)?;
                if read != computed {
                    return Err(ProofError::AthMismatch { computed, read: read.to_owned() });
                }
            }
            (Some(_), None) => return Err(ProofError::AthMissing),
            (None, Some(read)) => {
                return Err(ProofError::AthUnexpected { read: read.to_owned() });
            }
            (None, None) => {}
        }
        if let Some(bound) = request.bound_jkt
            && bound != jkt
        {
            return Err(ProofError::KeyBindingMismatch { bound: bound.to_owned(), read: jkt });
        }

        self.lock().insert(jti.clone(), request.now);
        Ok(ProofReport { jkt, jti, htm, htu, iat, nonce, ath })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Timestamp>> {
        // A thread that crashed while holding the lock leaves behind at most one stale cache
        // entry; that costs one failed attempt and no wrong acceptance.
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpop::DpopProofRequest;
    use crate::encoding::b64u;
    use crate::key_set::{KeyEntry, KeyOffer};
    use serde_json::json;

    const NOW: Timestamp = Timestamp::from_unix_millis(1_788_334_692_118);
    const URL: &str = "https://api.elasticdms.io/v1/folders";
    const TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

    fn anchor_key(kid: &str) -> TestKey {
        TestKey::anchor_key(kid).unwrap()
    }

    fn evidence_key(kid: &str) -> TestKey {
        TestKey::proof(kid).unwrap()
    }

    fn dpop_proof(key: &TestKey, request: &DpopProofRequest<'_>, jti: &str) -> String {
        crate::dpop::proof_with_jti(key.signing_key(), request, NOW, jti).unwrap()
    }

    fn plain_request<'a>() -> DpopProofRequest<'a> {
        DpopProofRequest { method: "GET", url: URL, nonce: None, access_token: None }
    }

    #[test]
    fn the_default_timestamps_are_the_ones_from_the_template() {
        assert_eq!(DEFAULT_NOT_BEFORE.rfc3339(), "2020-01-01T00:00:00.000Z");
        assert_eq!(DEFAULT_NOT_AFTER.rfc3339(), "2099-01-01T00:00:00.000Z");
        assert_eq!(DEFAULT_GENERATED_AT.rfc3339(), "2026-09-02T08:14:22.000Z");
        assert_eq!(DEFAULT_REFRESH_AFTER.rfc3339(), "2026-09-09T08:14:22.000Z");
        assert_eq!(DEFAULT_NEXT_ROTATION.rfc3339(), "2027-06-01T00:00:00.000Z");
        assert_eq!(DEFAULT_REVOKED_AT.rfc3339(), "2026-08-14T11:02:00.000Z");
    }

    #[test]
    fn an_anchor_never_carries_a_signature_and_always_its_role() {
        let forge = Forge::new();
        let a = anchor_key("edms-anchor-2026-a");
        let entry = forge.entry(&a).as_anchor();
        assert_eq!(entry[FIELD_SIGNATURE], Value::Null);
        assert_eq!(entry["role"], "trust-anchor");
        assert_eq!(entry["custody"], DEFAULT_CUSTODY);
        assert_eq!(entry["thumbprint"], a.thumbprint());
        assert_eq!(entry["issuer"], DEFAULT_ISSUER);
        assert_eq!(entry["tenantId"], DEFAULT_TENANT);
        // And it is readable as a key entry, with nothing missing.
        let read = KeyEntry::from_json(&entry).unwrap();
        assert_eq!(read.kid(), "edms-anchor-2026-a");
        assert_eq!(read.role(), KeyRole::TrustAnchor);
        assert_eq!(read.jwk().thumbprint(), a.thumbprint());
    }

    #[test]
    fn a_key_statement_verifies_against_the_signer_and_against_nobody_else() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let b = anchor_key("anchor-b");
        let s = evidence_key("kms-2026-09").with_key_set_version(7);
        let statement = forge.entry(&s).signed_by(&a).unwrap();
        assert_eq!(statement["keySetVersion"], 7);
        assert_eq!(statement["supersedes"], Value::Null);
        let signature = jws::signature_of_the_carrier(&statement).unwrap();
        assert_eq!(signature.header().kid, "anchor-a");
        assert_eq!(signature.header().typ, TYP_KEY_STATEMENT);
        let bytes = jws::signed_bytes(&statement).unwrap();
        assert!(signature.check(TYP_KEY_STATEMENT, &bytes, &a.public()).is_ok());
        assert!(signature.check(TYP_KEY_STATEMENT, &bytes, &b.public()).is_err());
    }

    #[test]
    fn a_tampered_statement_carries_a_real_signature_over_other_bytes() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let s = evidence_key("kms-2026-09");
        let statement = forge.entry(&s).tampered().signed_by(&a).unwrap();
        let signature = jws::signature_of_the_carrier(&statement).unwrap();
        let bytes = jws::signed_bytes(&statement).unwrap();
        assert!(signature.check(TYP_KEY_STATEMENT, &bytes, &a.public()).is_err());
    }

    #[test]
    fn the_forge_builds_the_invalid_too() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let itself = forge.entry(&a).signed_by(&a).unwrap();
        assert_eq!(jws::signature_of_the_carrier(&itself).unwrap().header().kid, "anchor-a");
        let foreign = forge.entry(&a).with_tenant_id("t_foreign").as_anchor();
        assert_eq!(foreign["tenantId"], "t_foreign");
        let unknown = forge.entry(&a).with_role("token-signing").as_anchor();
        assert!(KeyEntry::from_json(&unknown).is_err());
        let wrong_type = forge.entry(&a).with_typ(TYP_REVOCATION).signed_by(&a).unwrap();
        assert_eq!(
            jws::signature_of_the_carrier(&wrong_type).unwrap().header().typ,
            TYP_REVOCATION
        );
    }

    #[test]
    fn a_revocation_carries_reason_time_and_the_signature_of_another_key() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let revocation = forge
            .revocation("kms-2026-09", RevocationReason::KeyCompromised)
            .compromised_since(Timestamp::from_unix_millis(1_786_000_000_000))
            .with_key_set_version(8)
            .reissued_as("kms-2026-10")
            .signed_by(&a)
            .unwrap();
        assert_eq!(revocation["reason"], "key_compromise");
        assert_eq!(revocation["revokedAt"], DEFAULT_REVOKED_AT.rfc3339());
        assert_eq!(revocation["reissuedAs"], "kms-2026-10");
        assert_eq!(revocation["keySetVersion"], 8);
        let signature = jws::signature_of_the_carrier(&revocation).unwrap();
        assert_eq!(signature.header().typ, TYP_REVOCATION);
        let bytes = jws::signed_bytes(&revocation).unwrap();
        assert!(signature.check(TYP_REVOCATION, &bytes, &a.public()).is_ok());
    }

    #[test]
    fn the_block_carries_the_self_computed_fingerprint_and_is_readable() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let b = anchor_key("anchor-b");
        let s = evidence_key("kms-2026-09");
        let anchor_entries = vec![forge.entry(&a).as_anchor(), forge.entry(&b).as_anchor()];
        let block = forge
            .block(7)
            .with_anchor(anchor_entries.clone())
            .with_key([forge.entry(&s).signed_by(&a).unwrap()])
            .builder()
            .unwrap();
        let expected = AnchorFingerprint::from_thumbprint(&[a.thumbprint(), b.thumbprint()]);
        assert_eq!(block["anchorSetFingerprint"], expected.display());
        assert_eq!(fingerprint(&anchor_entries).unwrap(), expected);
        assert_eq!(block.get("revocations"), None);
        let offer = KeyOffer::from_json(&block).unwrap();
        assert_eq!(offer.key_set_version(), 7);
        assert_eq!(offer.anchors().len(), 2);
        assert_eq!(offer.signature_signing_key().len(), 1);
        assert!(offer.unreadable_entries().is_empty());
        assert_eq!(offer.fingerprint(), expected);
    }

    #[test]
    fn an_anchor_without_coordinates_breaks_the_fingerprint_computation_instead_of_shortening_it() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let mut broken = forge.entry(&a).as_anchor();
        broken.as_object_mut().unwrap().remove("y");
        assert!(fingerprint(&[broken.clone()]).is_err());
        assert!(forge.block(1).with_anchor([broken]).builder().is_err());
    }

    #[test]
    fn the_enrollment_answer_carries_the_block_under_server_keys() {
        let forge = Forge::new();
        let a = anchor_key("anchor-a");
        let block = forge.block(1).with_anchor([forge.entry(&a).as_anchor()]).builder().unwrap();
        let response = forge.enrollment_response(block.clone());
        assert_eq!(response["deviceId"], DEFAULT_DEVICE);
        assert_eq!(response["state"], DEFAULT_STATE);
        assert_eq!(
            KeyOffer::from_enrollment(&response).unwrap(),
            KeyOffer::from_json(&block).unwrap()
        );
    }

    #[test]
    fn a_delivery_command_is_signed_over_jcs_without_the_signature_field() {
        let forge = Forge::new();
        let s = evidence_key("kms-2026-09");
        let command = forge
            .command("job_01JB8Z5K3M4N6P7Q8R9S0T1V2W", "dehydrate")
            .with_payload(json!({"cause": "erasure", "documentIds": ["doc_01", "doc_02"]}))
            .from_posed(NOW)
            .signed_by(&s)
            .unwrap();
        assert_eq!(command["kind"], "dehydrate");
        assert_eq!(command[FIELD_COMMAND_TIME], NOW.rfc3339());
        let signature = jws::signature_of_the_carrier(&command).unwrap();
        assert_eq!(signature.header().typ, TYP_DELIVERY_COMMAND);
        assert_eq!(signature.header().kid, "kms-2026-09");
        let bytes = jws::signed_bytes(&command).unwrap();
        assert!(signature.check(TYP_DELIVERY_COMMAND, &bytes, &s.public()).is_ok());
        // An extra field is part of the signature too, even if no reader knows it (P2).
        let mut bent = command.clone();
        bent["payload"]["documentIds"] = json!(["doc_01"]);
        let bytes = jws::signed_bytes(&bent).unwrap();
        assert!(signature.check(TYP_DELIVERY_COMMAND, &bytes, &s.public()).is_err());
    }

    #[test]
    fn a_command_without_a_time_does_not_carry_the_field() {
        let forge = Forge::new();
        let s = evidence_key("kms");
        let command = forge.command("job_1", "sync").without_timestamp().signed_by(&s).unwrap();
        assert_eq!(command.get(FIELD_COMMAND_TIME), None);
    }

    #[test]
    fn a_valid_proof_is_accepted_and_names_the_thumbprint() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let request = DpopProofRequest {
            method: "GET",
            url: URL,
            nonce: Some("nonce-api"),
            access_token: Some(TOKEN),
        };
        let proof = dpop_proof(&device, &request, "01JB8Z5K3M4N6P7Q8R9S0T1V2W");
        let jkt = device.thumbprint();
        let expectation = DpopCheckRequest::new("GET", URL, NOW)
            .with_nonce("nonce-api")
            .with_access_token(TOKEN)
            .bound_to(&jkt);
        let report = verifier.check(&proof, &expectation).unwrap();
        assert_eq!(report.jkt, device.thumbprint());
        assert_eq!(report.jti, "01JB8Z5K3M4N6P7Q8R9S0T1V2W");
        assert_eq!(report.htm, "GET");
        assert_eq!(report.htu, URL);
        assert_eq!(report.iat, 1_788_334_692);
        assert_eq!(report.nonce.as_deref(), Some("nonce-api"));
    }

    #[test]
    fn the_same_proof_a_second_time_is_a_replay() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let proof = dpop_proof(&device, &plain_request(), "JTI-ONCE");
        let expectation = DpopCheckRequest::new("GET", URL, NOW);
        assert!(verifier.check(&proof, &expectation).is_ok());
        assert_eq!(
            verifier.check(&proof, &expectation),
            Err(ProofError::RetryAfter { jti: "JTI-ONCE".into() })
        );
        // After the window the jti is forgotten — and after `forget_everything` at once.
        let later = DpopCheckRequest::new("GET", URL, NOW.plus_millis(REPLAY_WINDOW_MILLIS));
        assert!(verifier.check(&proof, &later).is_ok());
        verifier.forget_everything();
        assert!(verifier.check(&proof, &expectation).is_ok());
    }

    #[test]
    fn a_proof_that_fails_later_does_not_use_up_its_jti() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let request =
            DpopProofRequest { method: "GET", url: URL, nonce: None, access_token: Some(TOKEN) };
        let proof = dpop_proof(&device, &request, "JTI-ONCE");
        let wrong = DpopCheckRequest::new("GET", URL, NOW).with_access_token("another token");
        assert!(matches!(verifier.check(&proof, &wrong), Err(ProofError::AthMismatch { .. })));
        let right = DpopCheckRequest::new("GET", URL, NOW).with_access_token(TOKEN);
        assert!(verifier.check(&proof, &right).is_ok());
    }

    #[test]
    fn method_target_and_nonce_are_rejected_by_name_one_at_a_time() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let request =
            DpopProofRequest { method: "GET", url: URL, nonce: Some("good"), access_token: None };
        let proof = dpop_proof(&device, &request, "J1");
        assert_eq!(
            verifier.check(&proof, &DpopCheckRequest::new("POST", URL, NOW).with_nonce("good")),
            Err(ProofError::MethodMismatch { expected: "POST".into(), read: "GET".into() })
        );
        let other_target = "https://api.elasticdms.io/v1/documents";
        assert_eq!(
            verifier
                .check(&proof, &DpopCheckRequest::new("GET", other_target, NOW).with_nonce("good")),
            Err(ProofError::TargetMismatch { expected: other_target.into(), read: URL.into() })
        );
        assert_eq!(
            verifier.check(&proof, &DpopCheckRequest::new("GET", URL, NOW).with_nonce("fresh")),
            Err(ProofError::NonceMismatch { read: "good".into() })
        );
        // Query and fragment do not count towards the target (RFC 9449 §4.2).
        let with_query = format!("{URL}?limit=50#top");
        assert!(
            verifier
                .check(&proof, &DpopCheckRequest::new("GET", &with_query, NOW).with_nonce("good"))
                .is_ok()
        );
    }

    #[test]
    fn without_a_nonce_in_the_proof_a_resource_that_demands_one_fails() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let proof = dpop_proof(&device, &plain_request(), "J1");
        assert_eq!(
            verifier.check(&proof, &DpopCheckRequest::new("GET", URL, NOW).with_nonce("n")),
            Err(ProofError::NonceMissing)
        );
        // If the resource demands none, one carried along does not disturb.
        let carrying =
            DpopProofRequest { method: "GET", url: URL, nonce: Some("n"), access_token: None };
        let proof = dpop_proof(&device, &carrying, "J2");
        assert!(verifier.check(&proof, &DpopCheckRequest::new("GET", URL, NOW)).is_ok());
    }

    #[test]
    fn the_token_binding_is_checked_in_both_directions() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let foreign = evidence_key("foreign");
        let with_token =
            DpopProofRequest { method: "GET", url: URL, nonce: None, access_token: Some(TOKEN) };
        let proof = dpop_proof(&device, &with_token, "J1");
        assert_eq!(
            verifier.check(&proof, &DpopCheckRequest::new("GET", URL, NOW)),
            Err(ProofError::AthUnexpected {
                read: "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo".into(),
            })
        );
        let foreign_jkt = foreign.thumbprint();
        let foreign_bound =
            DpopCheckRequest::new("GET", URL, NOW).with_access_token(TOKEN).bound_to(&foreign_jkt);
        assert_eq!(
            verifier.check(&proof, &foreign_bound),
            Err(ProofError::KeyBindingMismatch {
                bound: foreign.thumbprint(),
                read: device.thumbprint(),
            })
        );
        let without_ath = dpop_proof(&device, &plain_request(), "J2");
        assert_eq!(
            verifier.check(
                &without_ath,
                &DpopCheckRequest::new("GET", URL, NOW).with_access_token(TOKEN)
            ),
            Err(ProofError::AthMissing)
        );
    }

    #[test]
    fn iat_is_held_against_the_clock_only_on_explicit_request() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let proof = dpop_proof(&device, &plain_request(), "J1");
        // The device clock is a year wrong — and the call counts all the same (§2.4 point 7).
        let much_later = DpopCheckRequest::new("GET", URL, NOW.plus_millis(365 * 86_400_000));
        assert!(verifier.check(&proof, &much_later).is_ok());
        verifier.forget_everything();
        let with_window = much_later.with_time_window(60);
        assert!(matches!(
            verifier.check(&proof, &with_window),
            Err(ProofError::TimeWindowMissed { window: 60, .. })
        ));
        assert!(
            verifier
                .check(&proof, &DpopCheckRequest::new("GET", URL, NOW).with_time_window(60))
                .is_ok()
        );
    }

    /// Builds a proof with a freely chosen header — for the cases the builder does not build.
    fn proof_with_header(header: &Value, claims: &Value, key: &TestKey) -> String {
        let input = format!(
            "{}.{}",
            b64u(&jcs::canonicalize_bytes(header).unwrap()),
            b64u(&jcs::canonicalize_bytes(claims).unwrap())
        );
        let signature = key.signing_key().sign(input.as_bytes()).unwrap();
        format!("{input}.{}", b64u(&signature))
    }

    #[test]
    fn a_header_without_the_dpop_typ_without_a_jwk_or_with_a_kid_is_rejected_by_name() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let jwk = device.jwk().as_json();
        let claims = json!({"jti": "J1", "htm": "GET", "htu": URL, "iat": 1_788_334_692});
        let expectation = DpopCheckRequest::new("GET", URL, NOW);

        let wrong_type = json!({"typ": "JWT", "alg": ALG, "jwk": jwk});
        assert_eq!(
            verifier.check(&proof_with_header(&wrong_type, &claims, &device), &expectation),
            Err(ProofError::WrongTyp { read: "JWT".into() })
        );

        let without_jwk = json!({"typ": dpop::TYP, "alg": ALG});
        assert!(matches!(
            verifier.check(&proof_with_header(&without_jwk, &claims, &device), &expectation),
            Err(ProofError::NoJwk { .. })
        ));

        let with_kid = json!({"typ": dpop::TYP, "alg": ALG, "jwk": jwk, "kid": "dev-1"});
        assert_eq!(
            verifier.check(&proof_with_header(&with_kid, &claims, &device), &expectation),
            Err(ProofError::KidInHeader)
        );

        let other_alg = json!({"typ": dpop::TYP, "alg": "HS256", "jwk": jwk});
        assert!(matches!(
            verifier.check(&proof_with_header(&other_alg, &claims, &device), &expectation),
            Err(ProofError::Form(CryptoError::WrongAlgorithm { .. }))
        ));
    }

    #[test]
    fn a_planted_key_in_the_header_does_not_hold_the_signature() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let foreign = evidence_key("foreign");
        let header = json!({"typ": dpop::TYP, "alg": ALG, "jwk": foreign.jwk().as_json()});
        let claims = json!({"jti": "J1", "htm": "GET", "htu": URL, "iat": 1_788_334_692});
        let proof = proof_with_header(&header, &claims, &device);
        assert_eq!(
            verifier.check(&proof, &DpopCheckRequest::new("GET", URL, NOW)),
            Err(ProofError::SignatureHoldsNot)
        );
    }

    #[test]
    fn without_a_jti_or_without_an_iat_no_proof_counts() {
        let verifier = DpopVerifier::new();
        let device = evidence_key("dev");
        let header = json!({"typ": dpop::TYP, "alg": ALG, "jwk": device.jwk().as_json()});
        let expectation = DpopCheckRequest::new("GET", URL, NOW);
        let without_jti = json!({"htm": "GET", "htu": URL, "iat": 1_788_334_692});
        assert_eq!(
            verifier.check(&proof_with_header(&header, &without_jti, &device), &expectation),
            Err(ProofError::JtiMissing)
        );
        let empty_jti = json!({"jti": "", "htm": "GET", "htu": URL, "iat": 1_788_334_692});
        assert_eq!(
            verifier.check(&proof_with_header(&header, &empty_jti, &device), &expectation),
            Err(ProofError::JtiMissing)
        );
        let without_iat = json!({"jti": "J1", "htm": "GET", "htu": URL});
        assert_eq!(
            verifier.check(&proof_with_header(&header, &without_iat, &device), &expectation),
            Err(ProofError::IatMissing)
        );
    }

    #[test]
    fn a_proof_error_becomes_a_crypto_error_with_the_same_sentence() {
        let error = ProofError::NonceMissing;
        let text = error.to_string();
        assert_eq!(CryptoError::from(error), CryptoError::DpopInvalid(text));
    }
}
