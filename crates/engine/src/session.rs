//! The sign-in — the state machine everything else hangs off.
//!
//! The folder client is a **human being with a device-like credential** (digest §1.3, C-2): it
//! signs in like a kiosk (its own P-256 key, `PUT /v1/devices/{deviceId}`, DPoP everywhere), but
//! fetches a **user** token over the device flow, so that every listing is evaluated against the
//! human being's rights and not against a service principal (requirement 4).
//!
//! From that follows the way, in exactly this order:
//!
//! 1. **Device key and device identifier** ([`KeyBundle`]). Both come into being once and stay; the
//!    key lies in the vault, the identifier in the session row.
//! 2. **Enrolment** — `PUT` with `If-None-Match: *`. `201` **and** `412` are success (T1–T3): the
//!    call can break off after the server has created the device.
//! 3. **Anchoring** of the key set from `serverKeys`. The anchor is written **once**; a later
//!    network answer never replaces it ([`edms_crypto::key_set::KeySet::anchor`]). The displayed
//!    fingerprint is computed by us, never taken over (03 §6.2.4).
//! 4. **Device token**. `403 device-pending-approval` is the **rule**, not an error: the state
//!    becomes "device is waiting for approval" together with the fingerprint for the comparison by
//!    a human being.
//! 5. **User token** — first the renewal (quiet, without a browser), otherwise the device flow. The
//!    engine **opens no browser**; it reports [`crate::EngineEvent::OpenBrowser`].
//! 6. **Rotation before use.** A new refresh token is written into the vault **before** the access
//!    token belonging to it is used. Otherwise a crash between answer and storing would let the old
//!    token survive — and its next use revokes the whole token family (T14).
//! 7. **`RefreshUncertain` is never repeated** (T14): whether the server has rotated, nobody here
//!    knows. The state becomes [`EngineState::LoginRequired`].
//!
//! Signing out is the way back and runs **completely**, even when a step fails: revoke,
//! `FileSystem::clear_everything`, empty the namespace, erase the secrets, a row into the usage
//! log. The status of the revocation is no proof (RFC 7009 answers `200` for an unknown token too)
//! — clearing up happens in any case (requirement 4).

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use edms_core::identifier::{DeviceIdKind, DeviceIdentifier};
use edms_core::log::{LogEntry, LogKind};
use edms_core::port::Provisioning;
use edms_core::time::Timestamp;
use edms_crypto::key::{SigningKey, SoftwareKey};
use edms_crypto::key_set::{KeyOffer, KeySet};
use edms_net::server::{LoginIntent, LoginOutcome, LoginStep};
use edms_net::{ApiResult, KeyBinding, KeySource, NetworkError, Secret};
use edms_store::{Account, Login, Session, SessionState, Store};
use edms_wire::basics::ErrorKind;
use edms_wire::device::{
    Application, AttestationDetail, DeviceKind, DeviceObject, EnrollmentRequest, OperatingSystem,
    Platform, PublicJwk,
};
use edms_wire::login::TokenResponse;

use crate::device_key::{DeviceKeyOrigin, HardwareKeyStore};
use crate::engine::Shared;
use crate::error::EngineError;
use crate::time::now;
use crate::vault::{SESSION_SLOTS, SLOT_REFRESH_TOKEN, SLOT_SESSION_KEY, Vault, VaultError};

/// Setting key of the anchored server key set.
pub const SETTING_KEY_SET: &str = "key-set";

/// Setting key of the enrolment mark (`yes`, as soon as the server knows the device).
pub const SETTING_ENROLLED: &str = "device.enrolled";

/// Setting key of the mark that the account had to be guessed ([`Identity`]).
pub const SETTING_IDENTITY_GUESSED: &str = "session.identity-guessed";

/// How long before it expires an access token is renewed.
///
/// Renewal happens **before** the expiry, not after: a `401` in the middle of a content fetch costs
/// the user a file he is opening, and the Explorer shows an error for it instead of a progress
/// bar.
pub const REFRESH_LEAD_SECOND: i64 = 120;

/// The display name for as long as the server delivers none.
const NAME_UNKNOWN: &str = "Angemeldet";

// ── State ───────────────────────────────────────────────────────────────────────────────────

/// Where the engine stands — what the app shows.
///
/// Deliberately richer than [`edms_store::SessionState`]: the store holds what has to survive a
/// restart; here stand in addition the fleeting details needed on the screen **right now** — the
/// user code of a running sign-in, the fingerprint for the human comparison, whether the line
/// stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineState {
    /// The engine is starting up; nothing is decided yet.
    Starting,

    /// The device is not set up and there is no enrolment code.
    ///
    /// The app asks for it and passes it on with [`crate::Engine::set_enrollment_code`].
    EnrollmentCodeRequired,

    /// The device is registered and waits for the approval by the administration.
    ///
    /// The fingerprint is **computed by us** (03 §6.2.4) and belongs on the screen: without the
    /// comparison by a human being, anybody who installs the software could enrol a device against
    /// the tenant.
    AwaitingApproval {
        /// The anchor fingerprint in its display form.
        fingerprint: String,
    },

    /// Nobody is signed in.
    SignedOut,

    /// A device flow is running; the human being confirms in the browser.
    LoginRuns {
        /// The code the human being sees on the page (`WQPX-7TRM`).
        user_code: String,
        /// The confirmation page — checked to be below the web interface.
        address: String,
        /// The four-character anchor that app and page both show.
        anchor: Option<String>,
    },

    /// A human being is signed in.
    SignedIn {
        /// "Signed in as …".
        display_name: String,
        /// The tenant from the anchored set or from the token.
        tenant: String,
        /// Since when.
        since: Timestamp,
        /// Whether the server is reachable right now. `false` does **not** mean signed out: the
        /// tree stays visible, and the cache carries it (ADR-D03, consequences).
        connected: bool,
    },

    /// The session is over; the tree stays put, opening fails with a reason.
    LoginRequired {
        /// Why — a whole sentence for the display, already in the user's language (the engine
        /// takes it from the text catalogue or from the server's own words).
        reason: String,
    },

    /// The engine has stopped.
    Stopped,
}

impl EngineState {
    /// Whether a user token is expected in this state.
    pub const fn is_signed_in(&self) -> bool {
        matches!(self, Self::SignedIn { .. })
    }

    /// The state in one line, **for the diagnostic log**.
    ///
    /// Not for the user interface: what the menu and the window show is decided by the app
    /// (`wiring::interpret`), out of the text catalogue and in the user's language. This line
    /// goes into `tracing` and into a bug report, and is therefore English like every other
    /// diagnostic in this house.
    pub fn label(&self) -> String {
        match self {
            Self::Starting => "starting".to_owned(),
            Self::EnrollmentCodeRequired => "enrolment code required".to_owned(),
            Self::AwaitingApproval { fingerprint } => {
                format!("awaiting approval ({fingerprint})")
            }
            Self::SignedOut => "signed out".to_owned(),
            Self::LoginRuns { user_code, .. } => format!("signing in, code {user_code}"),
            Self::SignedIn { display_name, connected: true, .. } => {
                format!("signed in as {display_name}")
            }
            Self::SignedIn { display_name, connected: false, .. } => {
                format!("signed in as {display_name}, offline")
            }
            Self::LoginRequired { .. } => "sign-in required".to_owned(),
            Self::Stopped => "stopped".to_owned(),
        }
    }
}

// ── Key bundle ──────────────────────────────────────────────────────────────────────────────

/// The secrets of this workstation, the way `edms-net` fetches them on every call.
///
/// **The order at the start is not free:** [`edms_net::Connection`] demands the device identifier
/// and [`edms_net::ServerAccess`] the key source — both before there is a server, and the server
/// comes before the engine. Hence the key bundle is set up first, and it is at the same time the
/// handle over which the engine reaches the vault:
///
/// ```ignore
/// let mut store = Store::open(&configuration.data_path)?;
/// let bundle = KeyBundle::set_up(Box::new(vault), &mut store, hardware_key_store)?;
/// let connection = Connection::new(&c.api_base, &c.auth_base, bundle.device(), "1.0.0")?;
/// let server = Arc::new(ServerAccess::new(connection, bundle.as_source())?);
/// let engine = Engine::start(configuration, server, store, bundle)?;
/// ```
pub struct KeyBundle {
    vault: Mutex<Box<dyn Vault>>,
    device: DeviceIdentifier,
    kid: String,
    device_key: Arc<dyn SigningKey>,
    device_key_origin: DeviceKeyOrigin,
    session_key: RwLock<Arc<SoftwareKey>>,
    device_token: RwLock<Option<Secret>>,
    user_token: RwLock<Option<Secret>>,
}

/// Without keys and without tokens: what stands here may go into any log.
impl std::fmt::Debug for KeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyBundle").field("device", &self.device).finish_non_exhaustive()
    }
}

impl KeyBundle {
    /// Sets up device identifier, device key and session key — once each in the life of this
    /// workstation.
    ///
    /// The identifier comes into being **before** the enrolment
    /// (`edms_core::identifier::DeviceIdKind`) and is stored in the session row; it belongs to the
    /// machine and survives every sign-out.
    ///
    /// `hardware` is the key store outside this process, when this build has one for this platform
    /// — the app hands it down ([`crate::HardwareKeyStore`]). `None` and a store that refuses come
    /// to the same thing for everything above: a [`SoftwareKey`] and a
    /// [`DeviceKeyOrigin`] that says which of the two it was. The **session** key is a software key
    /// in every case (ADR-D12 §8): it signs a DPoP proof on every single call, and 4.660 ms per
    /// signature measured in the Secure Enclave would stand in front of every listing and every
    /// hydration.
    ///
    /// # Errors
    ///
    /// When the vault is not reachable, when something unreadable stands in the slot of the device
    /// key (then **nothing** is generated anew — a new key would be a new device and would end in
    /// `409 device-id-conflict`) or when the store does not write.
    pub fn set_up(
        vault: Box<dyn Vault>,
        store: &mut Store,
        hardware: Option<&dyn HardwareKeyStore>,
    ) -> Result<Arc<Self>, EngineError> {
        let mut vault = vault;
        let device = match store.session()? {
            Some(session) => session.device(),
            None => {
                let new: DeviceIdentifier = edms_crypto::random::new_identifier::<DeviceIdKind>()?;
                store.set_session(&Session::signed_out(new))?;
                new
            }
        };
        let (device_key, device_key_origin) = crate::device_key::settle(vault.as_mut(), hardware)?;
        let session_key = load_or_generate(vault.as_mut(), SLOT_SESSION_KEY)?;
        // One line per process, and it is the second of the two places that keep the fallback
        // from being silent (ADR-D12 §3; the first is the `doctor` row). `set_up` runs exactly
        // once in the life of the program, so this line does too.
        tracing::info!(
            device_key = device_key_origin.row(),
            "where the private device key of this workstation lies has been settled."
        );
        Ok(Arc::new(Self {
            vault: Mutex::new(vault),
            device,
            kid: format!("{device}#1"),
            device_key,
            device_key_origin,
            session_key: RwLock::new(session_key),
            device_token: RwLock::new(None),
            user_token: RwLock::new(None),
        }))
    }

    /// Where the private part of the device key lies — for `doctor`.
    pub fn device_key_origin(&self) -> &DeviceKeyOrigin {
        &self.device_key_origin
    }

    /// The identifier of this workstation.
    pub const fn device(&self) -> DeviceIdentifier {
        self.device
    }

    /// The `kid` of the device key, as it was reported at the enrolment.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The bundle as a key source for [`edms_net::ServerAccess`].
    pub fn as_source(self: &Arc<Self>) -> Arc<dyn KeySource> {
        Arc::clone(self) as Arc<dyn KeySource>
    }

    /// The public device key for the enrolment request.
    pub fn public_jwk(&self) -> PublicJwk {
        let public = self.device_key.public();
        PublicJwk::p256(
            public.jwk().x().to_owned(),
            public.jwk().y().to_owned(),
            Some(self.kid.clone()),
        )
    }

    /// Creates a fresh session key — one per sign-in.
    ///
    /// It is stored in the vault, because the refresh token is bound to its thumbprint
    /// (RFC 9449 §5): without it every renewal after a restart would be `invalid_grant`.
    ///
    /// # Errors
    ///
    /// When no key can be produced or it cannot be stored.
    pub(crate) fn new_session_key(&self) -> Result<(), EngineError> {
        let key = SoftwareKey::generate()?;
        let der = key.as_pkcs8_der()?;
        self.with_vault(|vault| vault.write(SLOT_SESSION_KEY, der.as_ref()))?;
        *self.session_key.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(key);
        Ok(())
    }

    /// The refresh token from the vault.
    ///
    /// # Errors
    ///
    /// When the vault is not reachable or contains something that is not text.
    pub(crate) fn refresh_token(&self) -> Result<Option<Secret>, VaultError> {
        let raw = self.with_vault(|vault| vault.read(SLOT_REFRESH_TOKEN))?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                String::from_utf8(bytes).map(|text| Some(Secret::new(text))).map_err(|error| {
                    VaultError::Corrupt {
                        slot: SLOT_REFRESH_TOKEN.to_owned(),
                        reason: error.to_string(),
                    }
                })
            }
        }
    }

    /// Stores the refresh token — **before** the access token belonging to it is used (T14).
    ///
    /// # Errors
    ///
    /// When the vault does not write. Then the new access token is **not** used: a token whose
    /// renewal is lost ends in a session that cannot be continued and whose refresh token revokes
    /// the family at the next attempt.
    pub(crate) fn set_refresh_token(&self, token: &str) -> Result<(), VaultError> {
        self.with_vault(|vault| vault.write(SLOT_REFRESH_TOKEN, token.as_bytes()))
    }

    /// Remembers the device token in memory — never in the vault: it is short-lived and can be
    /// fetched anew at any time.
    pub(crate) fn set_device_token(&self, token: &str) {
        *self.device_token.write().unwrap_or_else(PoisonError::into_inner) =
            Some(Secret::new(token));
    }

    /// Remembers the user token in memory.
    pub(crate) fn set_user_token(&self, token: &str) {
        *self.user_token.write().unwrap_or_else(PoisonError::into_inner) = Some(Secret::new(token));
    }

    /// Whether a user token lies in memory.
    pub(crate) fn has_user_token(&self) -> bool {
        self.user_token.read().unwrap_or_else(PoisonError::into_inner).is_some()
    }

    /// Erases everything belonging to the session: refresh token and session key in the vault, both
    /// tokens in memory. The device key stays — it belongs to the machine.
    ///
    /// # Errors
    ///
    /// When the vault is not reachable. Memory is emptied all the same: what is gone stays gone,
    /// even when the operating system's keychain is jammed right now.
    pub(crate) fn forget_session(&self) -> Result<(), VaultError> {
        *self.user_token.write().unwrap_or_else(PoisonError::into_inner) = None;
        *self.device_token.write().unwrap_or_else(PoisonError::into_inner) = None;
        let mut result = Ok(());
        for slot in SESSION_SLOTS {
            if let Err(error) = self.with_vault(|vault| vault.delete(slot)) {
                result = Err(error);
            }
        }
        result
    }

    fn with_vault<T>(
        &self,
        action: impl FnOnce(&mut dyn Vault) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let mut vault = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        action(vault.as_mut())
    }
}

impl KeySource for KeyBundle {
    fn key(&self, binding: KeyBinding) -> Option<Arc<dyn SigningKey>> {
        Some(match binding {
            KeyBinding::Device => Arc::clone(&self.device_key),
            KeyBinding::Session => {
                Arc::clone(&self.session_key.read().unwrap_or_else(PoisonError::into_inner))
                    as Arc<dyn SigningKey>
            }
        })
    }

    fn device_kid(&self) -> Option<String> {
        Some(self.kid.clone())
    }

    fn token(&self, binding: KeyBinding) -> Option<Secret> {
        let slot = match binding {
            KeyBinding::Device => &self.device_token,
            KeyBinding::Session => &self.user_token,
        };
        slot.read().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

/// The session key out of the vault, or a fresh one.
///
/// Only the session slot goes through here any more; the device slot has a way of its own
/// ([`crate::device_key::settle`]), because it is the only one that can hold a handle instead of a
/// key.
fn load_or_generate(
    vault: &mut dyn Vault,
    slot: &'static str,
) -> Result<Arc<SoftwareKey>, EngineError> {
    if let Some(der) = vault.read(slot)? {
        let key = SoftwareKey::from_pkcs8_der(&der).map_err(|error| {
            // No quiet fresh start: the refresh token is bound to the thumbprint of this key
            // (RFC 9449 §5), so a new one would make every renewal after a restart an
            // `invalid_grant` — and the person would sign in anew daily without learning why.
            VaultError::Corrupt { slot: slot.to_owned(), reason: error.to_string() }
        })?;
        return Ok(Arc::new(key));
    }
    let key = SoftwareKey::generate()?;
    vault.write(slot, key.as_pkcs8_der()?.as_ref())?;
    Ok(Arc::new(key))
}

// ── Identity ────────────────────────────────────────────────────────────────────────────────

/// Who is signed in.
///
/// 03 §7 names **no** way on which the folder client learns who is signed in. The access
/// token is opaque in the contract, and the example `id_token` (§7.0.7) carries no body. The engine
/// therefore reads the identity in this order:
///
/// 1. the claims of the `id_token`, if it is a compact JWS with a readable body;
/// 2. those of the access token, if it is one;
/// 3. failing that, the **device identifier** as the account key.
///
/// Case 3 is a makeshift and stands as such in the [`crate::Report`]
/// ([`crate::Report::identity_guessed`]): usage log and tree hang off the account (ADR-D07,
/// requirement 4), and without a carrier they would not exist at all. A server that delivers `sub`
/// makes the case superfluous — then step 1 already takes hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The account that the usage log and the tree stand under.
    pub account: Account,
    /// The tenant.
    pub tenant: String,
    /// "Signed in as …".
    pub display_name: String,
    /// Whether the account had to be guessed (case 3).
    pub guessed: bool,
}

impl Identity {
    /// Reads the identity from the token response; `tenant_fallback` is the `tenantId` of the
    /// anchored key set.
    ///
    /// # Errors
    ///
    /// Only when no account key can be built from the device identifier — that can only be a bug in
    /// this program, and it stands as a value because a crash in the tray process would take the
    /// whole folder away from the user.
    pub fn from_token_response(
        response: &TokenResponse,
        device: DeviceIdentifier,
        tenant_fallback: &str,
    ) -> Result<Self, EngineError> {
        let claims = response
            .id_token
            .as_deref()
            .and_then(claims_from_jwt)
            .or_else(|| claims_from_jwt(&response.access_token));
        let field = |name: &str| -> Option<String> {
            claims
                .as_ref()
                .and_then(|map| map.get(name))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let sub = field("sub").and_then(|text| Account::new(text).ok());
        let display_name = field("name")
            .or_else(|| field("displayName"))
            .or_else(|| field("preferred_username"))
            .unwrap_or_else(|| NAME_UNKNOWN.to_owned());
        let tenant =
            field("https://elasticdms.io/tenant").unwrap_or_else(|| tenant_fallback.to_owned());
        match sub {
            Some(account) => Ok(Self { account, tenant, display_name, guessed: false }),
            None => Ok(Self {
                account: Account::new(format!("device:{device}"))
                    .map_err(|error| EngineError::Internal(error.to_string()))?,
                tenant,
                display_name,
                guessed: true,
            }),
        }
    }
}

/// The body of a compact JWS as a JSON object; `None` when it is not one.
fn claims_from_jwt(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    edms_crypto::jws::CompactJws::read(token).ok().map(|jws| jws.payload().clone())
}

// ── The flow ────────────────────────────────────────────────────────────────────────────────

/// Signs in: set the device up, fetch the device token, establish the session.
///
/// Idempotent in the user's sense: a second call while the first is running waits for it (the lock
/// in [`Shared`]) and finds the finished session afterwards. Two device flows side by side would be
/// two codes on the screen and one of them wrong.
///
/// # Errors
///
/// Every step that does not reach its goal, with the reason in a whole sentence. The state is set
/// in any case afterwards — the app shows it even without reading the error.
pub(crate) async fn sign_in(shared: &Arc<Shared>) -> Result<(), EngineError> {
    let _lock = shared.login_lock.lock().await;
    if shared.is_stopped() {
        return Err(EngineError::Stopped);
    }
    place_device_safe(shared).await?;
    if !fetch_device_token(shared).await? {
        return Ok(());
    }
    confirm_anchor(shared)?;
    place_session_from(shared).await
}

/// The enrolment, when it has not happened yet.
async fn place_device_safe(shared: &Arc<Shared>) -> Result<(), EngineError> {
    if shared.store().setting(SETTING_ENROLLED)?.as_deref() == Some("yes") {
        return Ok(());
    }
    let Some(code) = shared.enrollment_code() else {
        shared.set_state(EngineState::EnrollmentCodeRequired);
        return Err(EngineError::EnrollmentCodeMissing);
    };
    let request = enrollment_request(shared, &code);
    let report = crate::value_from(
        shared.server.register_device(&request).await,
        "the enrolment",
        shared.catalogue(),
    )?;
    if let Some(device) = &report.value.device {
        anchor_from_device_object(shared, device)?;
    }
    {
        let mut store = shared.store();
        store.set_setting(SETTING_ENROLLED, "yes")?;
    }
    shared.append_log(&LogEntry::plain(
        now(),
        LogKind::DeviceRegistered,
        Some(shared.catalogue().format(
            if report.value.inventory_already {
                edms_i18n::key::NOTICE_DEVICE_REGISTERED_AGAIN
            } else {
                edms_i18n::key::NOTICE_DEVICE_REGISTERED
            },
            &[("device", &shared.bundle.device().to_string())],
        )),
    ));
    Ok(())
}

/// The request for a workstation: `deviceKind: desktop`, no attestation, no factory targets
/// (proposal §7.0, finding Q-2).
fn enrollment_request(shared: &Shared, code: &str) -> EnrollmentRequest {
    EnrollmentRequest {
        enrollment_code: code.to_owned(),
        device_kind: DeviceKind::Desktop,
        public_jwk: shared.bundle.public_jwk(),
        // An invented chain would be worse than none: the honest statement leads to level SOFTWARE
        // and with it to the documented way over the approval by a human being.
        attestation: AttestationDetail::no(),
        platform: Platform {
            os: operating_system(),
            os_version: std::env::consts::FAMILY.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        },
        app: Application {
            package_name: Some("de.elasticdms.folderclient".to_owned()),
            version_name: env!("CARGO_PKG_VERSION").to_owned(),
            build_hash: None,
            signature_sha256: None,
        },
        requested_name: Some(shared.configuration.device_name.clone()),
    }
}

/// The operating system in the spelling of the contract.
fn operating_system() -> OperatingSystem {
    match std::env::consts::OS {
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::MacOs,
        // An open catalogue: the server may know more than this client. An invented value would be
        // worse than the honest name of the operating system.
        other => OperatingSystem::Unknown(other.to_owned()),
    }
}

/// Anchors the key set from the device object — exactly once in the life of the device.
fn anchor_from_device_object(shared: &Shared, device: &DeviceObject) -> Result<(), EngineError> {
    let Some(block) = &device.server_keys else {
        // If `serverKeys` is missing, the device stays without an anchor — and **nothing** is ever
        // removed by order (03 §6.2.4, "when in doubt, preserve").
        tracing::warn!(
            "the enrolment answer carried no serverKeys block; the device stays without an anchor"
        );
        return Ok(());
    };
    let offer = KeyOffer::from_json(&block.0)?;
    anchor(shared, &offer)
}

/// Anchors an offer against the stored set.
fn anchor(shared: &Shared, offer: &KeyOffer) -> Result<(), EngineError> {
    let set = read_key_set(shared)?;
    let adoption = set.anchor(offer, None)?;
    if adoption.security_event() {
        shared.append_log(&LogEntry::plain(
            now(),
            LogKind::SecurityWarning,
            Some(format!("discarded while anchoring: {:?}", adoption.report_code())),
        ));
    }
    write_key_set(shared, &adoption.set)
}

/// The stored key set; an empty one for as long as nothing is anchored.
///
/// # Errors
///
/// When the store does not read or the storage form is corrupt — corrupt does **not** mean "then
/// empty it is": an empty set checks no signature, and the erasure commands would lie there
/// unnoticed.
pub(crate) fn read_key_set(shared: &Shared) -> Result<KeySet, EngineError> {
    let Some(text) = shared.store().setting(SETTING_KEY_SET)? else {
        return Ok(KeySet::empty());
    };
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        EngineError::Internal(format!("the stored key set is not JSON: {error}"))
    })?;
    Ok(KeySet::from_storage(&value)?)
}

/// Stores the key set — the one place where it is written.
pub(crate) fn write_key_set(shared: &Shared, set: &KeySet) -> Result<(), EngineError> {
    let text = set.as_storage().to_string();
    shared.store().set_setting(SETTING_KEY_SET, &text)?;
    Ok(())
}

/// Fetches the device token. `false` means: the device is waiting for approval.
async fn fetch_device_token(shared: &Arc<Shared>) -> Result<bool, EngineError> {
    let result = shared.server.fetch_device_token().await;
    if let ApiResult::SlotError { problem, .. } = &result
        && problem.error_kind() == ErrorKind::DeviceApprovalPending
    {
        let fingerprint = read_key_set(shared)?.fingerprint().display();
        shared.set_state(EngineState::AwaitingApproval { fingerprint });
        let device = shared.bundle.device();
        let mut store = shared.store();
        store.set_session(&Session::awaiting_approval(device))?;
        return Ok(false);
    }
    let success = crate::value_from(result, "the device token", shared.catalogue())?;
    shared.bundle.set_device_token(&success.value.access_token);
    Ok(true)
}

/// The server has listed the device as `active` — with that the anchor counts as confirmed
/// (03 §6.2.4, steps 2 and 3).
fn confirm_anchor(shared: &Shared) -> Result<(), EngineError> {
    let set = read_key_set(shared)?;
    if set.anchors().is_empty() || set.carries() {
        return Ok(());
    }
    let confirmed = set.confirm()?;
    write_key_set(shared, &confirmed)
}

/// Establishes the user session: first renew quietly, otherwise the device flow.
async fn place_session_from(shared: &Arc<Shared>) -> Result<(), EngineError> {
    if let Some(refresh_secret) = shared.bundle.refresh_token()?
        && refresh(shared, &refresh_secret).await?
    {
        return Ok(());
    }
    device_login(shared).await
}

/// Renews the session. `false` means: somebody has to sign in anew.
///
/// # Errors
///
/// Only when the network is away — then the session stays put and the next beat tries again. Every
/// **judgement** of the server leads to `Ok(false)` and a state.
pub(crate) async fn refresh(shared: &Arc<Shared>, refresh: &Secret) -> Result<bool, EngineError> {
    match shared.server.refresh_token(refresh).await {
        ApiResult::Success(success) => {
            adopt_token(shared, &success.value)?;
            Ok(true)
        }
        // T14: **never** repeat blindly. Whether the server has rotated, nobody here knows; a
        // second attempt with the same token would revoke the whole family.
        ApiResult::NetworkError(error @ NetworkError::RefreshUncertain { .. }) => {
            session_stop(shared, &error.to_string(), false)?;
            Ok(false)
        }
        ApiResult::NetworkError(error) => Err(EngineError::NoNetwork(error.to_string())),
        ApiResult::SecurityAbort { notice, .. } => {
            shared.append_log(&LogEntry::plain(
                now(),
                LogKind::SecurityWarning,
                Some(notice.clone()),
            ));
            session_stop(shared, &notice, true)?;
            Ok(false)
        }
        other => {
            let reason = crate::reason_from(&other, shared.catalogue());
            session_stop(shared, &reason, true)?;
            Ok(false)
        }
    }
}

/// The device flow: show the code, let the browser open, wait.
async fn device_login(shared: &Arc<Shared>) -> Result<(), EngineError> {
    shared.bundle.new_session_key()?;
    let intent = LoginIntent::first_login();
    let login = crate::value_from(
        shared.server.start_device_login(&intent).await,
        "the sign-in",
        shared.catalogue(),
    )?
    .value;
    // An address on a foreign host would be the template for a phishing page that decks itself out
    // with a real code and anchor (edms_wire::login::DeviceAuthorization).
    let target = login
        .browser_target(&shared.configuration.app_base)
        .map_err(|error| EngineError::Security(error.to_string()))?
        .to_owned();
    shared.set_state(EngineState::LoginRuns {
        user_code: login.user_code.clone(),
        address: target.clone(),
        anchor: login.anchor.clone(),
    });
    // The engine opens nothing: the app does it (architecture rule R7).
    shared.record(crate::EngineEvent::OpenBrowser(target));

    let observer = |step: LoginStep| match step {
        LoginStep::Slower { interval_second } => {
            tracing::info!(interval_second, "the server demands larger intervals");
        }
        LoginStep::NetworkFault(reason) => tracing::warn!(%reason, "sign-in goes on waiting"),
        LoginStep::Pending | LoginStep::Decided => {}
    };
    let outcome = crate::value_from(
        shared.server.wait_on_token(&login, &observer).await,
        "the sign-in",
        shared.catalogue(),
    )?
    .value;
    match outcome {
        LoginOutcome::Issued(token) => adopt_token(shared, &token),
        LoginOutcome::Expired => {
            let reason = shared.catalogue().text(edms_i18n::key::NOTICE_DEVICE_CODE_EXPIRED);
            shared.set_state(EngineState::SignedOut);
            Err(EngineError::Refused(reason.to_owned()))
        }
        LoginOutcome::Rejected(error) => {
            // The server's own words come first: it knows why, and it writes in the tenant's
            // language. Only where it says nothing does our sentence stand in.
            let reason = error.error_description.clone().unwrap_or_else(|| {
                shared.catalogue().text(edms_i18n::key::NOTICE_LOGIN_REJECTED).to_owned()
            });
            shared.set_state(EngineState::SignedOut);
            Err(EngineError::Refused(reason))
        }
    }
}

/// Takes over a token response: **first** store the rotation, then use the access token.
fn adopt_token(shared: &Arc<Shared>, token: &TokenResponse) -> Result<(), EngineError> {
    if let Some(refresh) = &token.refresh_token {
        shared.bundle.set_refresh_token(refresh)?;
    }
    shared.bundle.set_user_token(&token.access_token);
    let expiry = now().plus_millis(
        i64::try_from(token.expires_in).unwrap_or(i64::MAX / 1_000).saturating_mul(1_000),
    );
    shared.set_token_expiry(Some(expiry));

    let tenant = read_key_set(shared)?.tenant_id().to_owned();
    let identity = Identity::from_token_response(token, shared.bundle.device(), &tenant)?;
    let since = now();
    let session = Session::signed_in(
        shared.bundle.device(),
        Login {
            account: identity.account.clone(),
            tenant: identity.tenant.clone(),
            display_name: identity.display_name.clone(),
            signed_in_since: since,
        },
    );
    {
        let mut store = shared.store();
        store.set_session(&session)?;
        store.set_setting(SETTING_IDENTITY_GUESSED, if identity.guessed { "yes" } else { "no" })?;
    }
    // Only now can the platform name the mirror: display name and account belong to the session,
    // and the root identifier on Windows carries the account (`edms_core::port`).
    if let Some(file_system) = shared.file_system() {
        let provisioning = Provisioning {
            display_name: format!("elasticdms – {}", identity.tenant),
            account: identity.account.as_str().to_owned(),
        };
        if let Err(error) = file_system.place_ready(&provisioning) {
            tracing::error!(%error, "the mirror could not be provisioned");
            shared.record(crate::EngineEvent::Hint { text: error.to_string() });
        }
    }
    shared.append_log(&LogEntry::plain(since, LogKind::SignedIn, None));
    shared.set_state(EngineState::SignedIn {
        display_name: identity.display_name,
        tenant: identity.tenant,
        since,
        connected: true,
    });
    Ok(())
}

/// Ends the session without emptying the tree (ADR-D03, consequences: **never** a quiet emptying —
/// the user goes on seeing his folders, and opening fails with a reason).
pub(crate) fn session_stop(
    shared: &Shared,
    reason: &str,
    erase_secrets: bool,
) -> Result<(), EngineError> {
    if erase_secrets {
        // A refresh token the server no longer accepts is no longer worth a secret — and a second
        // attempt with it would be exactly the reuse from T14.
        let _ = shared.bundle.forget_session();
    }
    shared.set_token_expiry(None);
    let device = shared.bundle.device();
    {
        let mut store = shared.store();
        let session = store.session()?;
        let new = match session.and_then(|row| row.login().cloned()) {
            Some(login) => Session::new(device, SessionState::LoginRequired, Some(login))
                .map_err(|error| EngineError::Internal(error.to_string()))?,
            None => Session::signed_out(device),
        };
        store.set_session(&new)?;
    }
    shared.append_log(&LogEntry::plain(now(), LogKind::LoginRequired, Some(reason.to_owned())));
    shared.set_state(EngineState::LoginRequired { reason: reason.to_owned() });
    Ok(())
}

/// Makes sure a usable access token is at hand — before every call that needs one.
///
/// Renews **before** the expiry ([`REFRESH_LEAD_SECOND`]). `false` means: nobody is signed in, the
/// caller is not even to ask.
///
/// # Errors
///
/// Only on a missing network; a server judgement leads into the state and to `Ok(false)`.
pub(crate) async fn ensure_for_token(shared: &Arc<Shared>) -> Result<bool, EngineError> {
    let signed_in = shared.store().session()?.is_some_and(|row| row.state().carries_login());
    if !signed_in {
        return Ok(false);
    }
    let fresh = shared.token_expiry().is_some_and(|expiry| {
        expiry.unix_millis() - now().unix_millis() > REFRESH_LEAD_SECOND * 1_000
    });
    if fresh && shared.bundle.has_user_token() {
        return Ok(true);
    }
    let _lock = shared.login_lock.lock().await;
    // Under the lock, look again: a second caller may have renewed just now, and redeeming the
    // same refresh token twice is T14.
    let fresh = shared.token_expiry().is_some_and(|expiry| {
        expiry.unix_millis() - now().unix_millis() > REFRESH_LEAD_SECOND * 1_000
    });
    if fresh && shared.bundle.has_user_token() {
        return Ok(true);
    }
    let Some(refresh_secret) = shared.bundle.refresh_token()? else {
        session_stop(shared, "the session is over; please sign in again", false)?;
        return Ok(false);
    };
    refresh(shared, &refresh_secret).await
}

/// Renews at once — the answer to a `401` in mid-operation.
///
/// The lead in [`ensure_for_token`] covers the rule; a device with a clock that goes wrong or a
/// server that lets things expire earlier runs into it all the same. Then it holds: renew **once**
/// and repeat the call — not in a loop, otherwise a rejected token turns into sustained fire at the
/// token endpoint.
///
/// # Errors
///
/// As [`ensure_for_token`].
pub(crate) async fn force_refresh(shared: &Arc<Shared>) -> Result<bool, EngineError> {
    shared.set_token_expiry(None);
    ensure_for_token(shared).await
}

/// Signs out: revoke, clear the mirror, empty the namespace, erase the secrets.
///
/// Every step runs, even when a previous one fails. "Afterwards no name of the old user stands on
/// the disk any more" (requirement 4) is no intention but a promise — and a promise that gave up at
/// the first error would be none.
///
/// # Errors
///
/// The **first** error that occurred, after all steps have been attempted.
pub(crate) async fn sign_out(shared: &Arc<Shared>) -> Result<(), EngineError> {
    let _lock = shared.login_lock.lock().await;
    let refresh = shared.bundle.refresh_token().ok().flatten();
    if let Some(refresh) = refresh {
        // The status is no proof: RFC 7009 answers `200` for an unknown token too. Clearing up
        // happens in any case.
        let result = shared.server.revoke(&refresh).await;
        if !result.is_success() {
            tracing::warn!("the revocation did not go through; clearing up happens all the same");
        }
    }
    clear_after_sign_out(shared)
}

/// The local part of the sign-out — without the network, so that it runs completely after a
/// server-side `SIGN_OUT` command and offline as well.
pub(crate) fn clear_after_sign_out(shared: &Arc<Shared>) -> Result<(), EngineError> {
    let mut first: Option<EngineError> = None;
    let mut remember = |error: EngineError| {
        tracing::error!(%error, "step of the sign-out failed");
        if first.is_none() {
            first = Some(error);
        }
    };

    // The row still belongs to the old account (ADR-D07) — it has to be written before the session
    // is deleted, otherwise it falls into the pot of the device rows.
    shared.append_log(&LogEntry::plain(now(), LogKind::SignedOut, None));

    if let Some(file_system) = shared.file_system()
        && let Err(error) = file_system.clear_everything()
    {
        remember(error.into());
    }
    {
        let mut store = shared.store();
        if let Err(error) = store.empty_namespace() {
            remember(error.into());
        }
        if let Err(error) = store.set_session(&Session::signed_out(shared.bundle.device())) {
            remember(error.into());
        }
    }
    if let Err(error) = shared.bundle.forget_session() {
        remember(error.into());
    }
    shared.set_token_expiry(None);
    shared.set_state(EngineState::SignedOut);
    match first {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// The state the engine starts with — read from the session row.
pub(crate) fn state_on_start(
    store: &Store,
    fingerprint: &str,
    catalogue: &edms_i18n::Catalog,
) -> EngineState {
    match store.session() {
        Ok(Some(session)) => match session.state() {
            SessionState::SignedOut => EngineState::SignedOut,
            SessionState::AwaitingApproval => {
                EngineState::AwaitingApproval { fingerprint: fingerprint.to_owned() }
            }
            // Signed in means here: the last session ended without a sign-out. The access token
            // lives only in memory, so the engine is **not** connected until the first renewal —
            // and the tree stands all the same (ADR-D01, point 8).
            SessionState::SignedIn => {
                session.login().map_or(EngineState::SignedOut, |login| EngineState::SignedIn {
                    display_name: login.display_name.clone(),
                    tenant: login.tenant.clone(),
                    since: login.signed_in_since,
                    connected: false,
                })
            }
            SessionState::LoginRequired => EngineState::LoginRequired {
                reason: catalogue.text(edms_i18n::key::NOTICE_SESSION_ENDED).to_owned(),
            },
        },
        Ok(None) => EngineState::SignedOut,
        Err(error) => {
            tracing::error!(%error, "the session row is not readable");
            EngineState::SignedOut
        }
    }
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;
    use edms_wire::login::DpopTokenKind;

    use super::*;
    use crate::stub_server::{RefreshResponse, StubServer};
    use crate::vault::{SLOT_DEVICE_KEY, StoreVault};

    fn device() -> DeviceIdentifier {
        Identifier::from_value(42)
    }

    fn token_response(id_token: Option<&str>, access: &str) -> TokenResponse {
        TokenResponse {
            access_token: access.to_owned(),
            token_type: DpopTokenKind,
            expires_in: 900,
            refresh_token: None,
            refresh_token_expires_in: None,
            scope: None,
            id_token: id_token.map(ToOwned::to_owned),
        }
    }

    /// A compact JWS with these claims; the signature is never checked here — the identity is
    /// display, the authorisation is done by the server.
    fn jwt(payload: serde_json::Value) -> String {
        let key = SoftwareKey::generate().unwrap();
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT" });
        edms_crypto::jws::sign_jwt(&header, &payload, &key).unwrap()
    }

    #[test]
    fn the_identity_comes_from_the_claims_of_the_id_token() {
        let id = jwt(serde_json::json!({
            "sub": "usr_01JKE0M2P4R6T8V0X2Z4B6D8F0",
            "name": "Thomas Berg",
            "https://elasticdms.io/tenant": "t_acme",
        }));
        let identity = Identity::from_token_response(
            &token_response(Some(&id), "at_opak"),
            device(),
            "t_fallback",
        )
        .unwrap();
        assert_eq!(identity.account.as_str(), "usr_01JKE0M2P4R6T8V0X2Z4B6D8F0");
        assert_eq!(identity.display_name, "Thomas Berg");
        assert_eq!(identity.tenant, "t_acme");
        assert!(!identity.guessed);
    }

    #[test]
    fn without_readable_claims_the_device_carries_the_account_and_says_so() {
        // The mock (and the contract in its example) deliver an opaque token: then the makeshift
        // stands in the report instead of the sign-in quietly using a wrong account.
        let identity = Identity::from_token_response(
            &token_response(Some("idt.usr"), "at_opak"),
            device(),
            "t_acme",
        )
        .unwrap();
        assert!(identity.guessed, "the makeshift has to be visible");
        assert!(identity.account.as_str().contains(&device().to_string()));
        assert_eq!(identity.tenant, "t_acme", "the tenant comes from the anchored set");
        assert_eq!(identity.display_name, NAME_UNKNOWN);
    }

    #[test]
    fn the_key_bundle_creates_device_and_key_exactly_once() {
        let mut store = Store::in_memory().unwrap();
        let vault = StoreVault::new();
        let bundle = KeyBundle::set_up(Box::new(vault), &mut store, None).unwrap();
        let device = bundle.device();
        assert_eq!(bundle.kid(), format!("{device}#1"));

        // A second start on the same state finds the same device and the same key.
        let first_jwk = bundle.public_jwk();
        drop(bundle);
        // The same vault content: the in-memory vault does not survive the process, so the way over
        // a filled vault is reproduced here.
        let mut second_vault = StoreVault::new();
        let der = SoftwareKey::generate().unwrap().as_pkcs8_der().unwrap();
        second_vault.write(SLOT_DEVICE_KEY, der.as_ref()).unwrap();
        let second = KeyBundle::set_up(Box::new(second_vault), &mut store, None).unwrap();
        assert_eq!(second.device(), device, "the identifier belongs to the machine");
        assert_ne!(second.public_jwk().x, first_jwk.x, "the key came out of the vault");
    }

    #[test]
    fn an_unreadable_device_key_is_not_silently_replaced() {
        let mut store = Store::in_memory().unwrap();
        let mut vault = StoreVault::new();
        vault.write(SLOT_DEVICE_KEY, b"not PKCS#8").unwrap();
        let error = KeyBundle::set_up(Box::new(vault), &mut store, None)
            .expect_err("a broken slot is an error, no occasion for a new device");
        assert!(matches!(error, EngineError::Vault(VaultError::Corrupt { .. })), "{error}");
    }

    #[test]
    fn signing_out_takes_the_session_slots_and_leaves_the_device_key() {
        let mut store = Store::in_memory().unwrap();
        let bundle = KeyBundle::set_up(Box::new(StoreVault::new()), &mut store, None).unwrap();
        bundle.set_refresh_token("rt_1").unwrap();
        bundle.set_user_token("at_1");
        assert!(bundle.refresh_token().unwrap().is_some());
        assert!(bundle.has_user_token());

        bundle.forget_session().unwrap();
        assert!(bundle.refresh_token().unwrap().is_none());
        assert!(!bundle.has_user_token());
        assert!(bundle.key(KeyBinding::Device).is_some(), "the device key belongs to the machine");
    }

    #[test]
    fn the_bundle_gives_the_right_key_and_the_right_token_per_binding() {
        let mut store = Store::in_memory().unwrap();
        let bundle = KeyBundle::set_up(Box::new(StoreVault::new()), &mut store, None).unwrap();
        bundle.set_device_token("at_device");
        bundle.set_user_token("at_user");
        assert_eq!(
            bundle.token(KeyBinding::Device).map(|token| token.open().to_owned()),
            Some("at_device".to_owned())
        );
        assert_eq!(
            bundle.token(KeyBinding::Session).map(|token| token.open().to_owned()),
            Some("at_user".to_owned())
        );
        let device = bundle.key(KeyBinding::Device).unwrap().public().thumbprint();
        let session = bundle.key(KeyBinding::Session).unwrap().public().thumbprint();
        assert_ne!(device, session, "two keys, two jobs (03 §6.0.9)");
    }

    #[test]
    fn a_new_session_key_replaces_the_old_one_in_the_vault() {
        let mut store = Store::in_memory().unwrap();
        let bundle = KeyBundle::set_up(Box::new(StoreVault::new()), &mut store, None).unwrap();
        let before = bundle.key(KeyBinding::Session).unwrap().public().thumbprint();
        bundle.new_session_key().unwrap();
        let after = bundle.key(KeyBinding::Session).unwrap().public().thumbprint();
        assert_ne!(before, after);
    }

    /// A works with a server double and a signed-in session in memory.
    fn shared_with(response: RefreshResponse) -> (Arc<crate::engine::Shared>, Arc<StubServer>) {
        let mut store = Store::in_memory().unwrap();
        let bundle = KeyBundle::set_up(Box::new(StoreVault::new()), &mut store, None).unwrap();
        bundle.set_refresh_token("rt_old").unwrap();
        bundle.set_user_token("at_old");
        store
            .set_session(&Session::signed_in(
                bundle.device(),
                Login {
                    account: Account::new("usr_sample").unwrap(),
                    tenant: "t_acme".into(),
                    display_name: "Thomas Berg".into(),
                    signed_in_since: Timestamp::NULL,
                },
            ))
            .unwrap();
        let server = Arc::new(StubServer::new(response));
        let shared = crate::engine::Shared::for_sample(
            Arc::clone(&server) as Arc<dyn crate::ServerObject>,
            bundle,
            store,
            std::env::temp_dir(),
        );
        (shared, server)
    }

    #[tokio::test]
    async fn an_uncertain_renewal_is_not_repeated_but_ends_the_session() {
        // Contract test T14: whether the server has already rotated the refresh token, nobody here
        // knows. A second attempt with the same token would revoke the whole token family across
        // devices — so the human being signs in anew instead of the client guessing.
        let (shared, server) = shared_with(RefreshResponse::Uncertain);
        let further = refresh(&shared, &Secret::new("rt_old")).await.unwrap();
        assert!(!further, "the session does not run on");
        assert_eq!(server.refresh(), 1, "exactly one attempt, never two");
        assert!(
            matches!(shared.state(), EngineState::LoginRequired { .. }),
            "{:?}",
            shared.state()
        );
        assert!(
            shared.bundle.refresh_token().unwrap().is_some(),
            "the token stays put: it may be valid, and deleted the session would be gone for good"
        );
    }

    #[tokio::test]
    async fn a_reused_token_erases_the_secrets_and_warns() {
        let (shared, server) = shared_with(RefreshResponse::Reused);
        let further = refresh(&shared, &Secret::new("rt_old")).await.unwrap();
        assert!(!further);
        assert_eq!(server.refresh(), 1);
        assert!(matches!(shared.state(), EngineState::LoginRequired { .. }));
        assert!(
            shared.bundle.refresh_token().unwrap().is_none(),
            "a token the server no longer accepts does not stay put"
        );
        // The account first, then the lock: `shared.account()` reaches into the store itself, and a
        // std mutex is not re-entrant — together in one line that would be a standstill.
        let account = shared.account();
        let page = shared.store().log_page(account.as_ref(), None, 20).unwrap();
        assert!(
            page.rows.iter().any(|row| row.entry.kind() == LogKind::SecurityWarning),
            "the user's only opportunity to notice it"
        );
    }

    #[tokio::test]
    async fn a_network_fault_leaves_the_session_standing() {
        // No server judgement: the next beat tries again, and the tree stays visible.
        let (shared, server) = shared_with(RefreshResponse::NetworkFault);
        let error = refresh(&shared, &Secret::new("rt_old"))
            .await
            .expect_err("without a network there is no judgement");
        assert!(matches!(error, EngineError::NoNetwork(_)), "{error}");
        assert_eq!(server.refresh(), 1);
        assert!(shared.bundle.refresh_token().unwrap().is_some(), "the token stays");
    }

    #[test]
    fn every_state_has_a_label_for_the_menu_bar() {
        let all = [
            EngineState::Starting,
            EngineState::EnrollmentCodeRequired,
            EngineState::AwaitingApproval { fingerprint: "ABCD-EFGH-IJKL-MNOP".into() },
            EngineState::SignedOut,
            EngineState::LoginRuns {
                user_code: "WQPX-7TRM".into(),
                address: "https://app.example/geraet".into(),
                anchor: Some("K7-M4".into()),
            },
            EngineState::SignedIn {
                display_name: "Thomas Berg".into(),
                tenant: "t_acme".into(),
                since: Timestamp::NULL,
                connected: true,
            },
            EngineState::LoginRequired { reason: "expired".into() },
            EngineState::Stopped,
        ];
        for state in &all {
            assert!(!state.label().is_empty(), "{state:?}");
        }
        assert!(all[5].is_signed_in());
        assert!(!all[3].is_signed_in());
    }
}
