//! The mock's state: one tenant, its devices, sessions and jobs.
//!
//! Everything lies in memory behind **one** lock. A test harness with two locks has an order
//! nobody wrote down, and the first test that needs both hangs — at a place where one would go
//! looking for the mistake in the client.
//!
//! The way through the module:
//!
//! * [`Origin`] — the two hosts; DPoP nonces are kept per origin (§7.0.9).
//! * [`Basket`], [`Archive`] — the two listings that hold no documents: the mail baskets a file
//!   may be dropped into and the archives the case files stand below (namespace v2 §1).
//! * [`Container`], [`Document`] — case files (Akten), saved searches and their documents (§7.1).
//! * [`Device`], [`Access`], [`Refresh`], [`LoginFlow`] — enrolment, tokens, device flow.
//! * [`CommandItem`] — the delivery channel (§7.3), together with the possibility of signing
//!   deliberately wrongly ([`CommandQuality`]).
//! * [`AccessEntry`] — the **server-side** access log: “every hydration is an access and belongs
//!   in the log” (§7.2.3). Without this entry the archive's statement about who saw a document
//!   would be wrong — and that statement is the one that counts in court.
//! * [`Recording`] — what really arrived, for assertions in a test.
//! * [`Fault`], [`Mangling`] — deliberate failures: 5xx, a delay, a truncated body (contract test
//!   T13).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edms_core::checksum::Sha256Value;
use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CommandIdentifier, DeviceIdentifier, DocumentIdentifier,
    Identifier, Kind, UploadIdentifier, UserIdentifier,
};
use edms_core::namespace::Location;
use edms_core::time::Timestamp;
use edms_crypto::forge::{DpopVerifier, Forge, TestKey};
use edms_crypto::key::Jwk;
use edms_crypto::key_set::{KeyRole, TYP_DELIVERY_COMMAND};
use edms_crypto::{CryptoError, checksum, random};
use serde_json::{Value, json};

use crate::config::Configuration;
use crate::time::now;

/// The first identifier the mock hands out itself.
///
/// A fixed start instead of randomness: two runs with the same steps yield the same identifiers,
/// and a test failure can be found again in the log under the same identifier.
pub const IDENTIFIER_BASE: u128 = 0x0193_4B00_7000_8000_0000_0000_0000_0000;

/// The human as whom every device flow in this mock can be confirmed.
///
/// The same value as in `device_desktop.json` (`enrolledBy.sub`): a test harness that invented a
/// second human would have two names for the same procedure, and a test failure could no longer be
/// held against the golden file.
pub const USER: &str = "usr_01JKE0M2P4R6T8V0X2Z4B6D8F0";

/// The display name for [`USER`].
pub const USER_NAME: &str = "Thomas Berg";

/// The two hosts of the contract (§7.0.1). Separate origins, separate nonces (§7.0.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// The resource API (`api.`).
    Api,
    /// The authorization server (`auth.`).
    Login,
}

impl Origin {
    /// The name as it stands in the log and in messages.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Api => "API",
            Self::Login => "auth",
        }
    }
}

/// A mail basket — the only place a new file may be dropped into (namespace v2 §3, §7.4).
///
/// It holds nothing: the document is filed into an archive by the ingest rule, not by the basket.
/// That is why there is no `content` here and no `changed` — a basket has nothing whose change
/// could be dated.
#[derive(Debug, Clone)]
pub struct Basket {
    /// `bsk_…`.
    pub identifier: BasketIdentifier,
    /// The title as the server delivers it.
    pub title: String,
}

/// An archive. Every case file the user may see stands below exactly one of them (namespace v2
/// §1).
#[derive(Debug, Clone)]
pub struct Archive {
    /// `arc_…`.
    pub identifier: ArchiveIdentifier,
    /// The title as the server delivers it.
    pub title: String,
}

/// A container of the namespace: a case file (Akte) or a saved search (§7.1).
#[derive(Debug, Clone)]
pub struct Container {
    /// Which location — the identifier sits inside it.
    pub location: Location,
    /// The title as the server delivers it.
    pub title: String,
    /// Last changed.
    pub changed: Timestamp,
    /// The documents in the order in which the listing shows them.
    pub content: Vec<DocumentIdentifier>,
    /// Its own display limit; without one the configuration's applies (§7.1.2).
    pub display_limit: Option<u64>,
    /// `refineUrl`, when there is truncation.
    pub refinement: Option<String>,
    /// Set when the saved search is **not runnable**: field name and reason (§7.1.3). An empty
    /// folder would be the third, forbidden answer at this point.
    pub not_runnable: Option<(String, String)>,
    /// Counter for the strong ETag of the listing (§7.1.3).
    pub version: u64,
}

impl Container {
    /// Whether this container is a case file (Akte).
    pub const fn is_case(&self) -> bool {
        matches!(self.location, Location::Case { .. })
    }

    /// The archive this container stands in — a saved search stands in none.
    pub const fn archive(&self) -> Option<ArchiveIdentifier> {
        match self.location {
            Location::Case { archive, .. } => Some(archive),
            Location::Search(_) => None,
        }
    }
}

/// What deliberately goes wrong with the body of a hydration (contract test T13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mangling {
    /// The body arrives complete.
    #[default]
    No,
    /// The body breaks off after `n` bytes — with `200` and all the headers, the way the real
    /// server does it: it notices the hash failure only on the last `Read` (§7.2.1).
    CutOff(usize),
    /// The body has the announced length, but one byte is a different one.
    Tampered,
}

/// A document together with its delivered rendition (§7.1.2, §7.2.1).
#[derive(Debug, Clone)]
pub struct Document {
    /// The identifier.
    pub identifier: DocumentIdentifier,
    /// Title, free text.
    pub title: String,
    /// Media type of the **rendition**, never of the original.
    pub media_type: String,
    /// The bytes of the rendition.
    pub bytes: Vec<u8>,
    /// Checksum over exactly these bytes.
    pub sha256: Sha256Value,
    /// Version marker; it is the strong ETag of the content (§7.1.2).
    pub version: u64,
    /// Created.
    pub created: Timestamp,
    /// Last changed.
    pub changed: Timestamp,
    /// A deliberate failure in the body.
    pub mangling: Mangling,
    /// There is no deliverable rendition (`representation-unavailable`, §7.2.1).
    pub without_rendition: bool,
}

impl Document {
    /// The bytes as the mock sends them — complete or deliberately mangled.
    pub fn sent_bytes(&self) -> Vec<u8> {
        match self.mangling {
            Mangling::No => self.bytes.clone(),
            Mangling::CutOff(n) => self.bytes[..n.min(self.bytes.len())].to_vec(),
            Mangling::Tampered => {
                let mut bytes = self.bytes.clone();
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0xFF;
                }
                bytes
            }
        }
    }
}

/// The state of a device, as the device object reports it (03 §6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// `pending_admin_approval` — the normal case at attestation level `SOFTWARE` (§7.0.5).
    AwaitingApproval,
    /// `active`.
    Active,
    /// `revoked`.
    Locked,
}

impl DeviceState {
    /// The value on the wire.
    pub const fn wire_value(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "pending_admin_approval",
            Self::Active => "active",
            Self::Locked => "revoked",
        }
    }
}

/// An enrolled device (§7.0.5).
#[derive(Debug, Clone)]
pub struct Device {
    /// The identifier the device gave itself.
    pub identifier: DeviceIdentifier,
    /// The public key out of the enrolment; the mock checks every client assertion against it.
    pub jwk: Jwk,
    /// The `kid` of the device key.
    pub kid: String,
    /// The requested name.
    pub name: Option<String>,
    /// Approval state.
    pub state: DeviceState,
    /// When enrolled.
    pub provisioned: Timestamp,
    /// The body of the enrolment request, unchanged — so that a test can check what really
    /// arrived.
    pub request: Value,
}

/// An issued access token (03 §6.0.6). Opaque, bound to a device and a DPoP key.
#[derive(Debug, Clone)]
pub struct Access {
    /// The thumbprint of the key the token is bound to (`cnf.jkt`).
    pub jkt: String,
    /// The device it belongs to.
    pub device: DeviceIdentifier,
    /// The human, if it is a user token.
    pub user: Option<UserIdentifier>,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// When it expires.
    pub expires: Timestamp,
    /// The token family (only for a user token).
    pub family: Option<String>,
}

/// A refresh token with rotation (03 §6.3.3).
#[derive(Debug, Clone)]
pub struct Refresh {
    /// The family; reusing it revokes every member.
    pub family: String,
    /// The device.
    pub device: DeviceIdentifier,
    /// The human.
    pub user: UserIdentifier,
    /// The bound DPoP key.
    pub jkt: String,
    /// The scopes of the session.
    pub scopes: Vec<String>,
    /// When it expires.
    pub expires: Timestamp,
    /// Whether it has already been redeemed — a second redemption is the reuse.
    pub redeemed: bool,
}

/// How far a device flow has got (RFC 8628 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginState {
    /// Nobody has decided yet.
    Pending,
    /// A human confirmed.
    Confirmed(UserIdentifier),
    /// A human rejected.
    Rejected,
    /// The time ran out.
    Lapsed,
}

/// A running device flow (§7.0.7).
#[derive(Debug, Clone)]
pub struct LoginFlow {
    /// The secret code only the device knows.
    pub device_code: String,
    /// The code the human sees in the browser.
    pub user_code: String,
    /// The four-character anchor; the app shows it, the page repeats it.
    pub anchor: String,
    /// The device that asked for it.
    pub device: DeviceIdentifier,
    /// The thumbprint of the **session** key out of `dpop_jkt` (RFC 9449 §5).
    pub jkt: String,
    /// The requested scopes.
    pub scope: String,
    /// The designation that stands on the confirmation page.
    pub designation: String,
    /// When it lapses.
    pub expires: Timestamp,
    /// The state.
    pub state: LoginState,
    /// The next poll is answered with `slow_down`.
    pub slower: bool,
}

/// How a delivery command is signed — deliberately right or deliberately wrong.
///
/// A fixture that only produces valid things is no use for half the cases that matter here: the
/// client has to **reject** a command whose signature does not hold, and only a command that is
/// really signed wrongly proves that.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CommandQuality {
    /// Signed by an anchored `evidence-signing` key.
    #[default]
    Valid,
    /// Signed by a key no anchor covers.
    ForeignSignature,
    /// The signature does not match the canonicalised bytes (a field was changed afterwards).
    BrokenSignature,
    /// The protected header names a different `typ` — the JWS header parameter of RFC 7515
    /// §4.1.9, not a German word (P11, 03 §6.2.4).
    WrongTyp(String),
    /// Entirely without a `serverSignature` — the client may never make a command out of that
    /// (T22).
    WithoutSignature,
}

/// A job in the queue of the delivery channel (§7.3).
#[derive(Debug, Clone)]
pub struct CommandItem {
    /// The sequence number; the cursor comes out of it.
    pub sequence: u64,
    /// The identifier.
    pub identifier: CommandIdentifier,
    /// The device the command is meant for.
    pub device: DeviceIdentifier,
    /// The complete command, exactly as it goes onto the wire.
    pub value: Value,
    /// Whether it has already been acknowledged.
    pub acknowledged: bool,
}

/// A take-over out of a mail basket (§7.4).
#[derive(Debug, Clone)]
pub struct Upload {
    /// The identifier.
    pub identifier: UploadIdentifier,
    /// The basket the file was dropped into; its rule decides where the document lands, so the
    /// submission names it and the mock keeps it (namespace v2 §7).
    pub basket: BasketIdentifier,
    /// The announced file name.
    pub filename: String,
    /// The announced media type.
    pub media_type: String,
    /// The announced size.
    pub size: u64,
    /// The announced checksum.
    pub sha256: Sha256Value,
    /// The transferred bytes, as soon as they are there.
    pub bytes: Option<Vec<u8>>,
    /// When the promise lapses.
    pub expires: Timestamp,
    /// Whether `:complete` has already run.
    pub completed: bool,
}

/// One row of the **server-side** access log (§7.2.3).
///
/// Every `200` on `/v1/documents/{id}/content` writes one. The folder client keeps no audit
/// journal of its own (§7.5.2); this here is the statement that matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEntry {
    /// When.
    pub timestamp: Timestamp,
    /// Who — the human out of the user token.
    pub user: Option<UserIdentifier>,
    /// With what — the device out of the DPoP binding.
    pub device: DeviceIdentifier,
    /// Which document.
    pub document: DocumentIdentifier,
    /// Which version was delivered.
    pub version: String,
    /// The value out of `Elasticdms-Accessing-Application`, decoded (§7.2.4). An observation,
    /// never a permission.
    pub application: Option<String>,
}

/// A recorded request — what really arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// When.
    pub timestamp: Timestamp,
    /// At which host.
    pub origin: Origin,
    /// The method.
    pub method: String,
    /// Path together with the query string.
    pub path: String,
    /// Every header in the order in which they arrived; names lower-cased.
    pub header: Vec<(String, String)>,
    /// The status the mock answered with.
    pub status: u16,
}

impl Recording {
    /// The first value of a header (the name case-insensitively).
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.header.iter().find(|(n, _)| *n == wanted).map(|(_, value)| value.as_str())
    }
}

/// A deliberate failure: a status, a delay or both, for the next `times` calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// The path prefix the fault acts on (`/v1/delivery`).
    pub path: String,
    /// The status that is answered with; `None` means "delay only".
    pub status: Option<u16>,
    /// How long the answer keeps one waiting.
    pub delay_millis: u64,
    /// How many times the fault still bites.
    pub times: u32,
}

impl Fault {
    /// A fault that answers `times` calls under `path` with `status`.
    pub fn status(path: &str, status: u16, times: u32) -> Self {
        Self { path: path.to_owned(), status: Some(status), delay_millis: 0, times }
    }

    /// A fault that only delays `times` calls under `path`.
    pub fn delay(path: &str, millis: u64, times: u32) -> Self {
        Self { path: path.to_owned(), status: None, delay_millis: millis, times }
    }
}

/// A stored idempotency key (03 §6.0.10).
#[derive(Debug, Clone)]
pub struct IdempotencyEntry {
    /// Checksum of the body the key first came with.
    pub body: Sha256Value,
    /// The status of the first answer.
    pub status: u16,
    /// The first answer.
    pub response: Value,
}

/// Everything that lies behind the one lock.
#[derive(Debug)]
pub struct Inner {
    /// The mail baskets, in the order of the listing.
    pub baskets: Vec<Basket>,
    /// The archives, in the order of the listing.
    pub archives: Vec<Archive>,
    /// Case files (Akten) and saved searches, in the order of the listing.
    pub container: Vec<Container>,
    /// Every document.
    pub documents: BTreeMap<DocumentIdentifier, Document>,
    /// Every enrolled device.
    pub devices: BTreeMap<DeviceIdentifier, Device>,
    /// Issued access tokens.
    pub accesses: HashMap<String, Access>,
    /// Issued refresh tokens.
    pub refresh: HashMap<String, Refresh>,
    /// Revoked token families.
    pub revoked_families: Vec<String>,
    /// Running device flows.
    pub login: Vec<LoginFlow>,
    /// The queue of the delivery channel.
    pub commands: Vec<CommandItem>,
    /// The acknowledgements that are already there.
    pub acknowledgement: BTreeMap<CommandIdentifier, Value>,
    /// Stored idempotency keys.
    pub idempotency: HashMap<String, IdempotencyEntry>,
    /// Running take-overs out of a mail basket.
    pub upload: BTreeMap<UploadIdentifier, Upload>,
    /// The currently valid nonce per origin.
    pub nonces: BTreeMap<Origin, String>,
    /// What arrived.
    pub recording: Vec<Recording>,
    /// Who read what when.
    pub access: Vec<AccessEntry>,
    /// Deliberate failures.
    pub fault: Vec<Fault>,
    /// Whether the access log is currently unreachable. Then **no content** is delivered
    /// (§7.2.3) — an access without a log entry is worse than a refused one: the refused one
    /// stands out and gets fixed.
    pub access_log_locked: bool,
    /// Unsigned commands for the next heartbeat answer (§7.0.10).
    pub heartbeat_command: Vec<Value>,
    /// The state of the key set (`keySetVersion`).
    pub key_state: u64,
    /// What the next identifier comes out of.
    pub next_identifier: u128,
    /// The next sequence number of the delivery channel.
    pub next_sequence: u64,
    /// A counter that tokens and codes come out of when randomness fails.
    pub fallback_counter: u128,
}

impl Inner {
    /// A new identifier of kind `A`.
    pub fn new_identifier<A: Kind>(&mut self) -> Identifier<A> {
        self.next_identifier = self.next_identifier.wrapping_add(1);
        Identifier::from_value(self.next_identifier)
    }

    /// 128 random bits as base64url, with a prefix.
    ///
    /// If the operating system's randomness fails, the mock keeps counting instead of breaking
    /// off: a test harness that stopped dead when `getrandom` failed would turn a message into a
    /// hanging test.
    pub fn secret(&mut self, prefix: &str) -> String {
        let value = random::random_128().unwrap_or_else(|_| {
            self.fallback_counter = self.fallback_counter.wrapping_add(0x9E37_79B9_7F4A_7C15);
            self.fallback_counter
        });
        format!("{prefix}{}", URL_SAFE_NO_PAD.encode(value.to_be_bytes()))
    }

    /// The container at a location.
    pub fn container(&self, location: Location) -> Option<&Container> {
        self.container.iter().find(|c| c.location == location)
    }

    /// Whether an archive is there.
    ///
    /// The case listing asks before it answers: an archive nobody has gets a `404`, never an empty
    /// page — an empty page would say "this archive holds no case file" (§7.5.1).
    pub fn has_archive(&self, archive: ArchiveIdentifier) -> bool {
        self.archives.iter().any(|entry| entry.identifier == archive)
    }

    /// Whether a mail basket is there — the ingest asks before it hands out a grant (§7.4).
    pub fn has_basket(&self, basket: BasketIdentifier) -> bool {
        self.baskets.iter().any(|entry| entry.identifier == basket)
    }

    /// The container at a location, mutable.
    pub fn container_mut(&mut self, location: Location) -> Option<&mut Container> {
        self.container.iter_mut().find(|c| c.location == location)
    }

    /// The next state an ETag carries.
    pub fn bump(&mut self, location: Location) {
        if let Some(container) = self.container_mut(location) {
            container.version = container.version.saturating_add(1);
            container.changed = now();
        }
    }

    /// The sign-in flow for a `user_code`.
    pub fn login_mut(&mut self, user_code: &str) -> Option<&mut LoginFlow> {
        self.login.iter_mut().find(|flow| flow.user_code == user_code)
    }

    /// Revokes a whole token family (03 §6.3.3): every access and every refresh token.
    ///
    /// That is the effect that makes the reuse case so expensive — and exactly why a client may
    /// never blindly repeat a refresh attempt (contract test T14).
    pub fn revoke_family(&mut self, family: &str) {
        self.accesses.retain(|_, token| token.family.as_deref() != Some(family));
        self.refresh.retain(|_, token| token.family != family);
        if !self.revoked_families.iter().any(|f| f == family) {
            self.revoked_families.push(family.to_owned());
        }
    }
}

/// The whole state together with the key forge and the DPoP verifier.
#[derive(Debug)]
pub struct State {
    /// The configuration the mock was started with.
    pub configuration: Configuration,
    /// The base address of the resource API, e.g. `http://127.0.0.1:8480`.
    pub api_base: String,
    /// The base address of the authorization server.
    pub auth_base: String,
    /// The base address of the web interface; the mock serves it on the auth listener.
    pub app_base: String,
    /// The forge that signs anchors, key statements and commands.
    pub forge: Forge,
    /// The two trust anchors.
    pub anchor: Vec<TestKey>,
    /// The proof key that delivery commands are signed with.
    pub proof: TestKey,
    /// A second proof key that **no** anchor covers — for deliberately wrong signatures
    /// ([`CommandQuality::ForeignSignature`]).
    pub foreign: TestKey,
    /// The server-side DPoP check together with the replay cache (geraete-auth §2.4).
    pub verifier: DpopVerifier,
    /// The human every confirmed sign-in names.
    pub user: UserIdentifier,
    /// The mutable part.
    inner: Mutex<Inner>,
    /// Wakes the waiting long polls as soon as a command is queued (§7.3.1).
    pub waker: tokio::sync::Notify,
}

impl State {
    /// Builds the state together with the key set; the caller sows the sample tenant afterwards.
    pub fn new(
        configuration: Configuration,
        api_base: String,
        auth_base: String,
    ) -> Result<Self, CryptoError> {
        let app_base = configuration.app_base.clone().unwrap_or_else(|| auth_base.clone());
        let forge = Forge::for_tenant(&api_base, &configuration.tenant);
        let anchor = vec![
            TestKey::anchor_key("edms-anchor-a-2026")?,
            TestKey::anchor_key("edms-anchor-b-2026")?.with_custody("offline-hsm-reserve"),
        ];
        let proof = TestKey::proof("edms-kms-2026-09")?
            .with_key_set_version(configuration.key_state)
            .with_supersedes("edms-kms-2025-09");
        let foreign = TestKey::new("edms-kms-foreign", KeyRole::ProofSignature)?;
        let inner = Inner {
            baskets: Vec::new(),
            archives: Vec::new(),
            container: Vec::new(),
            documents: BTreeMap::new(),
            devices: BTreeMap::new(),
            accesses: HashMap::new(),
            refresh: HashMap::new(),
            revoked_families: Vec::new(),
            login: Vec::new(),
            commands: Vec::new(),
            acknowledgement: BTreeMap::new(),
            idempotency: HashMap::new(),
            upload: BTreeMap::new(),
            nonces: BTreeMap::new(),
            recording: Vec::new(),
            access: Vec::new(),
            fault: Vec::new(),
            access_log_locked: false,
            heartbeat_command: Vec::new(),
            key_state: configuration.key_state,
            next_identifier: IDENTIFIER_BASE,
            next_sequence: 1,
            fallback_counter: IDENTIFIER_BASE,
        };
        let state = Self {
            configuration,
            api_base,
            auth_base,
            app_base,
            forge,
            anchor,
            proof,
            foreign,
            verifier: DpopVerifier::new(),
            // A fixed value, not randomness: the identifier stands that way in the golden file.
            // If against expectation it cannot be read, the mock takes a fixed substitute instead
            // of failing at startup — the identifier is a display, not an assurance.
            user: USER.parse().unwrap_or_else(|_| UserIdentifier::from_value(0x4E75_747A_6572)),
            inner: Mutex::new(inner),
            waker: tokio::sync::Notify::new(),
        };
        {
            let mut inner = state.lock();
            let api = inner.secret("n-");
            let auth = inner.secret("n-");
            inner.nonces.insert(Origin::Api, api);
            inner.nonces.insert(Origin::Login, auth);
        }
        Ok(state)
    }

    /// The lock around the mutable part.
    ///
    /// A poisoned mutex (a thread died holding the lock) is taken over instead of panicking: the
    /// state of a mock is not evidence, and a test harness that answered every further request
    /// with a panic afterwards would hide the first mistake.
    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The human as whom a sign-in can be confirmed.
    pub const fn signed_in_user(&self) -> UserIdentifier {
        self.user
    }

    /// The base address of an origin.
    pub fn base(&self, origin: Origin) -> &str {
        match origin {
            Origin::Api => &self.api_base,
            Origin::Login => &self.auth_base,
        }
    }

    /// The currently valid nonce of an origin.
    pub fn nonce(&self, origin: Origin) -> String {
        self.lock().nonces.get(&origin).cloned().unwrap_or_default()
    }

    /// Sets a new nonce for an origin and returns it.
    pub fn rotate_nonce(&self, origin: Origin) -> String {
        let mut inner = self.lock();
        let new = inner.secret("n-");
        inner.nonces.insert(origin, new.clone());
        new
    }

    /// The `serverKeys` block (03 §6.2.4) in its currently valid state.
    pub fn key_block(&self) -> Result<Value, CryptoError> {
        let state = self.lock().key_state;
        let anchor: Vec<Value> =
            self.anchor.iter().map(|key| self.forge.entry(key).as_anchor()).collect();
        let key = vec![self.forge.entry(&self.proof).signed_by(&self.anchor[0])?];
        self.forge.block(state).with_anchor(anchor).with_key(key).builder()
    }

    /// Builds a delivery command in the requested quality.
    pub fn sign_command(
        &self,
        identifier: CommandIdentifier,
        device: DeviceIdentifier,
        kind: &str,
        payload: Value,
        quality: &CommandQuality,
    ) -> Result<Value, CryptoError> {
        let builder = self
            .forge
            .command(&identifier.to_string(), kind)
            .with_payload(payload)
            .from_posed(now())
            .with_field("deviceId", json!(device.to_string()));
        match quality {
            CommandQuality::Valid => builder.signed_by(&self.proof),
            CommandQuality::ForeignSignature => builder.signed_by(&self.foreign),
            CommandQuality::WrongTyp(typ) => builder.with_typ(typ).signed_by(&self.proof),
            CommandQuality::WithoutSignature => Ok(builder.unsigned()),
            CommandQuality::BrokenSignature => {
                // Sign first, then change the payload: the signature then holds for different
                // canonicalised bytes from the ones delivered — exactly the case a client has to
                // notice, and not merely a garbled string.
                let mut command = builder.signed_by(&self.proof)?;
                command["issuedAt"] = json!(now().plus_millis(1_000).rfc3339());
                Ok(command)
            }
        }
    }

    /// The signature type a delivery command carries (§7.3.4).
    pub const fn command_type() -> &'static str {
        TYP_DELIVERY_COMMAND
    }

    /// Enters a hydration into the server-side access log (§7.2.3).
    pub fn log_access(&self, entry: AccessEntry) {
        self.lock().access.push(entry);
    }

    /// Computes the checksum over bytes — the same place as in the client (`edms-crypto`).
    pub fn checksum(bytes: &[u8]) -> Sha256Value {
        checksum::sha256(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State::new(
            Configuration::default(),
            "http://127.0.0.1:8480".to_owned(),
            "http://127.0.0.1:8481".to_owned(),
        )
        .expect("the forge")
    }

    #[test]
    fn both_origins_have_different_nonces_from_the_start() {
        let state = state();
        let api = state.nonce(Origin::Api);
        let auth = state.nonce(Origin::Login);
        assert!(!api.is_empty() && !auth.is_empty());
        assert_ne!(api, auth, "a shared nonce would let the client circle between two hosts");
    }

    #[test]
    fn rotating_one_origin_leaves_the_other_alone() {
        let state = state();
        let auth_before = state.nonce(Origin::Login);
        let new = state.rotate_nonce(Origin::Api);
        assert_eq!(state.nonce(Origin::Api), new);
        assert_eq!(state.nonce(Origin::Login), auth_before);
    }

    #[test]
    fn every_new_identifier_is_canonical_and_different() {
        let state = state();
        let mut inner = state.lock();
        let a: DocumentIdentifier = inner.new_identifier();
        let b: DocumentIdentifier = inner.new_identifier();
        assert_ne!(a, b);
        assert_eq!(a.to_string().parse::<DocumentIdentifier>().expect("readable"), a);
    }

    #[test]
    fn a_truncated_body_is_shorter_than_the_announced_size() {
        let bytes = b"0123456789".to_vec();
        let mut doc = Document {
            identifier: DocumentIdentifier::from_value(1),
            title: "x".into(),
            media_type: "application/pdf".into(),
            sha256: State::checksum(&bytes),
            bytes,
            version: 1,
            created: Timestamp::NULL,
            changed: Timestamp::NULL,
            mangling: Mangling::CutOff(4),
            without_rendition: false,
        };
        assert_eq!(doc.sent_bytes(), b"0123");
        doc.mangling = Mangling::Tampered;
        let tampered = doc.sent_bytes();
        assert_eq!(tampered.len(), doc.bytes.len());
        assert_ne!(State::checksum(&tampered), doc.sha256);
    }

    #[test]
    fn an_archive_and_a_basket_that_are_not_there_are_not_reported_as_empty() {
        let state = state();
        let mut inner = state.lock();
        let archive = ArchiveIdentifier::from_value(1);
        inner.archives.push(Archive { identifier: archive, title: "Rechnungseingang".into() });
        assert!(inner.has_archive(archive));
        assert!(!inner.has_archive(ArchiveIdentifier::from_value(2)));

        let basket = BasketIdentifier::from_value(3);
        inner.baskets.push(Basket { identifier: basket, title: "Briefkorb Buchhaltung".into() });
        assert!(inner.has_basket(basket));
        assert!(!inner.has_basket(BasketIdentifier::from_value(4)));
    }

    #[test]
    fn a_case_file_names_its_archive_and_a_saved_search_names_none() {
        let case = Container {
            location: Location::Case {
                archive: ArchiveIdentifier::from_value(1),
                case: edms_core::identifier::CaseIdentifier::from_value(2),
            },
            title: "Kreditor 4711 – Eingangsrechnungen".into(),
            changed: Timestamp::NULL,
            content: Vec::new(),
            display_limit: None,
            refinement: None,
            not_runnable: None,
            version: 1,
        };
        assert!(case.is_case());
        assert_eq!(case.archive(), Some(ArchiveIdentifier::from_value(1)));

        let search = Container {
            location: Location::Search(edms_core::identifier::SearchIdentifier::from_value(3)),
            ..case
        };
        assert!(!search.is_case());
        assert_eq!(search.archive(), None, "a saved search stands below no archive");
    }

    #[test]
    fn a_revocation_takes_every_token_from_the_whole_family() {
        let state = state();
        let mut inner = state.lock();
        let device = DeviceIdentifier::from_value(7);
        inner.accesses.insert(
            "at_1".into(),
            Access {
                jkt: "j".into(),
                device,
                user: None,
                scopes: vec![],
                expires: Timestamp::NULL,
                family: Some("f".into()),
            },
        );
        inner.refresh.insert(
            "rt_1".into(),
            Refresh {
                family: "f".into(),
                device,
                user: UserIdentifier::from_value(9),
                jkt: "j".into(),
                scopes: vec![],
                expires: Timestamp::NULL,
                redeemed: true,
            },
        );
        inner.revoke_family("f");
        assert!(inner.accesses.is_empty());
        assert!(inner.refresh.is_empty());
        assert_eq!(inner.revoked_families, vec!["f".to_owned()]);
    }
}
