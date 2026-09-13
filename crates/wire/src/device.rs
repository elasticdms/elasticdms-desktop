//! The device: enrollment, device object, heartbeat (03 §6.2.1, §6.2.3, §6.4.1; proposal §7.0).
//!
//! The folder client enrols like a kiosk — its own P-256 key, `PUT` with `If-None-Match: *`, no
//! `Authorization`, no DPoP, `412` is a success (T1–T5) — but with a body for a workstation:
//! `deviceKind: "desktop"`, attestation `{"type":"none"}`, no scanner, card-reader or
//! factory-target blocks (proposal §7.0, finding Q-2). The server therefore classifies it as
//! `SOFTWARE`; `pending_admin_approval` is the normal case.
//!
//! **`serverKeys` is not interpreted here.** The block carries trust (03 §6.2.4) and belongs to
//! `edms-crypto`; here it stands as [`ServerKeyBody`], an unchanged JSON value, so that no field
//! is lost that belongs to the signed bytes (rule P2).
//!
//! **Commands in the heartbeat are unsigned.** There the folder client follows only harmless
//! hints (`resyncServerKeys`, `resyncPolicy` — both a fetch that is checked in its own right).
//! Everything that removes copies or signs out comes signed, and only over the delivery channel
//! (§7.3).

use edms_core::identifier::DeviceIdentifier;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::basics::{WireTimestamp, open_catalogue};

/// `GET` of the device's own device object (03 §6.2.3).
pub const PATH_OWN_IT_DEVICE: &str = "/v1/devices/me";

/// `GET` of the server key set (03 §6.2.4).
pub const PATH_SERVER_KEY: &str = "/v1/server-keys";

/// The attestation type of a workstation: none (proposal §7.0).
pub const ATTESTATION_NO: &str = "none";

/// `PUT /v1/devices/{deviceId}` — enrollment (03 §6.2.1).
pub fn path_device(device: DeviceIdentifier) -> String {
    format!("/v1/devices/{device}")
}

/// `POST /v1/devices/{deviceId}:heartbeat` (03 §6.4.1).
pub fn path_heartbeat(device: DeviceIdentifier) -> String {
    format!("/v1/devices/{device}:heartbeat")
}

open_catalogue!(
    /// Which kind of device is enrolling — server-side it picks the validation schema
    /// (proposal §7.0).
    DeviceKind {
        /// The folder client on a workstation.
        Desktop => "desktop",
        /// The eScan kiosk (03 §6.2.1); the field is absent there, because it was the only case.
        Kiosk => "kiosk",
    }
);

open_catalogue!(
    /// The operating system in `platform.os`.
    OperatingSystem {
        /// Windows 10/11.
        Windows => "Windows",
        /// macOS.
        MacOs => "macOS",
    }
);

open_catalogue!(
    /// `state` of the device object.
    DeviceState {
        /// The normal case after enrollment at level `SOFTWARE`: every token fetch becomes
        /// `403 device-pending-approval` until the administrator confirms the thumbprint.
        AwaitingApproval => "pending_admin_approval",
        /// Confirmed.
        Active => "active",
    }
);

open_catalogue!(
    /// The attestation level — a judgement of the server, not an input (geraete-auth §3.1.1).
    AttestationLevel {
        /// Chain up to the Google root, StrongBox.
        Strongbox => "STRONGBOX",
        /// Chain up to the Google root, TEE.
        Tee => "TEE",
        /// Everything else — for a workstation always.
        Software => "SOFTWARE",
    }
);

open_catalogue!(
    /// A command in the heartbeat answer (03 §6.4.1). Unsigned — see the module header.
    HeartbeatCommand {
        /// Sign out.
        ForceLogout => "forceLogout",
        /// Read the policy again.
        ResyncPolicy => "resyncPolicy",
        /// Fetch the server keys again.
        RefreshKeys => "resyncServerKeys",
        /// Send diagnostics.
        UploadDiagnostics => "uploadDiagnostics",
        /// Lock the device (kiosk).
        LockDevice => "lockDevice",
        /// No new batches (kiosk).
        BlockNewBatches => "blockNewBatches",
    }
);

impl HeartbeatCommand {
    /// Whether the folder client follows this unsigned command: only fetches that are checked in
    /// their own right. An unsigned command that clears the mirror would be a remote-erasure tool
    /// for anyone who holds the load balancer (ADR-D04).
    pub fn is_harmless_hint(&self) -> bool {
        matches!(self, Self::ResyncPolicy | Self::RefreshKeys)
    }
}

/// The public device key as a JWK (03 §6.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk {
    /// `EC`.
    pub kty: String,
    /// `P-256`.
    pub crv: String,
    /// x coordinate, base64url.
    pub x: String,
    /// y coordinate, base64url.
    pub y: String,
    /// `ES256`.
    pub alg: String,
    /// `sig`.
    #[serde(rename = "use")]
    pub usage: String,
    /// `dev_…#1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The private part. **Has to be absent**; if it is there, the request is to be rejected
    /// with `422 validation-failed` (geraete-auth §3.1, step 4). The field exists only so that
    /// the mock can notice it instead of silently discarding it.
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    pub private_part: Option<String>,
}

/// Why a JWK is not a public P-256 signing key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwkError {
    /// A field does not carry the only allowed value.
    #[error(
        "the JWK carries `{value}` in `{field}`; only `{allowed}` is allowed there \
         (geraete-auth §3.1)"
    )]
    Field {
        /// The field.
        field: &'static str,
        /// The value.
        value: String,
        /// The allowed value.
        allowed: &'static str,
    },
    /// The private part came along.
    #[error("the JWK carries a private part; such a key counts as given away (geraete-auth §3.1)")]
    PrivatePart,
}

impl PublicJwk {
    /// A public P-256 key for ES256.
    pub fn p256(x: String, y: String, kid: Option<String>) -> Self {
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y,
            alg: "ES256".into(),
            usage: "sig".into(),
            kid,
            private_part: None,
        }
    }

    /// The check the server makes before creating (`422 validation-failed`).
    pub fn check(&self) -> Result<(), JwkError> {
        let field: [(&'static str, &str, &'static str); 4] = [
            ("kty", &self.kty, "EC"),
            ("crv", &self.crv, "P-256"),
            ("alg", &self.alg, "ES256"),
            ("use", &self.usage, "sig"),
        ];
        for (field, value, allowed) in field {
            if value != allowed {
                return Err(JwkError::Field { field, value: value.to_owned(), allowed });
            }
        }
        if self.private_part.is_some() {
            return Err(JwkError::PrivatePart);
        }
        Ok(())
    }
}

/// The attestation entry of a workstation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationDetail {
    /// `none`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `false` — an invented chain would be worse than none (escan `EnrollmentTest`).
    pub available: bool,
}

impl AttestationDetail {
    /// No attestation: server-side this yields level `SOFTWARE`.
    pub fn no() -> Self {
        Self { kind: ATTESTATION_NO.into(), available: false }
    }
}

/// `platform` in the enrollment and in the heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    /// `Windows` or `macOS`.
    pub os: OperatingSystem,
    /// For instance `10.0.26100` or `26.0`.
    pub os_version: String,
    /// `x86_64` or `aarch64`.
    pub arch: String,
}

/// `app` in the enrollment and in the heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    /// Identifier of the program; in the heartbeat it is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    /// The version.
    pub version_name: String,
    /// `sha256:…` of the program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_hash: Option<String>,
    /// `sha256:…` of the signing certificate; absent on unsigned development builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_sha256: Option<String>,
}

/// `PUT /v1/devices/{deviceId}` for a workstation (proposal §7.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRequest {
    /// Eight characters from the console, valid for fifteen minutes.
    pub enrollment_code: String,
    /// `desktop` — picks the validation schema without factory targets.
    pub device_kind: DeviceKind,
    /// The public device key.
    pub public_jwk: PublicJwk,
    /// `{"type":"none","available":false}`.
    pub attestation: AttestationDetail,
    /// Operating system.
    pub platform: Platform,
    /// Program.
    pub app: Application,
    /// The name in the console; chosen by the user, never the machine name unasked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_name: Option<String>,
}

/// The `serverKeys` block, unchanged (03 §6.2.4). Interpretation and checking: `edms-crypto`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerKeyBody(pub Value);

/// The device object: answer to `PUT` (`201` **and** `412`) and to `GET /v1/devices/me`.
///
/// Only `deviceId` and `state` are mandatory. Everything else is display and diagnostics — what
/// the device may do is decided by the server, and what it believes is decided by the anchored
/// key set. Unknown fields (such as `site` for the kiosk) stay in [`DeviceObject::further`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceObject {
    /// The identifier, read strictly (03 §6.0.3).
    pub device_id: DeviceIdentifier,
    /// State.
    pub state: DeviceState,
    /// The kind, if the server returns it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_kind: Option<DeviceKind>,
    /// Name in the console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantDetail>,
    /// Judgement about the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationReport>,
    /// The OAuth registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OauthDetails>,
    /// The policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<DevicePolicy>,
    /// The key block — if it is missing, the device stays without an anchor, and nothing is ever
    /// removed by order (03 §6.2.4, „kein Schluessel hinterlegt" — no key stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_keys: Option<ServerKeyBody>,
    /// Time of the enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<WireTimestamp>,
    /// Who created the code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<Installer>,
    /// Everything else, unchanged.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

impl DeviceObject {
    /// Whether the administrator has confirmed.
    pub fn is_active(&self) -> bool {
        self.state == DeviceState::Active
    }
}

/// `tenant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantDetail {
    /// Tenant identifier.
    pub id: String,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `attestation` in the device object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationReport {
    /// Level.
    pub tier: AttestationLevel,
    /// The thumbprint computed by the server — only for comparison; what is displayed is the
    /// self-computed value (escan `Enrollmentantwort`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    /// Whether an administrator has to confirm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_confirmation_required: Option<bool>,
    /// Further details (`verdict` …).
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// `oauth` in the device object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthDetails {
    /// Equal to the device identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Token endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    /// `private_key_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// `ES256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// Allowed grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    /// Scopes of the device token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_scopes: Option<Vec<String>>,
    /// Always `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,
    /// Further details.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// `policy` in the device object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePolicy {
    /// Interval between heartbeats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval_seconds: Option<u64>,
    /// Idle limit of the user session (proposal §7.0, finding Q-4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_session_seconds: Option<u64>,
    /// Absolute limit of the user session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_session_seconds: Option<u64>,
    /// `wait` of the delivery channel (proposal §7.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_wait_seconds: Option<u64>,
    /// Further details.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// `enrolledBy`. The only clear-text name in the block; it goes into no evidence object
/// (geraete-auth §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Installer {
    /// Opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Further details.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// The state of the anchor set as the heartbeat reports it (03 §6.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorState {
    /// No anchor stored.
    #[serde(rename = "none")]
    No,
    /// Received, not confirmed.
    #[serde(rename = "pending_confirmation")]
    AwaitingConfirmation,
    /// Confirmed.
    #[serde(rename = "confirmed")]
    Confirmed,
    /// All anchors revoked.
    #[serde(rename = "revoked")]
    Revoked,
}

/// The `serverKeys` block in the heartbeat (03 §6.2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyNotice {
    /// Stored state; absent without an anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_set_version: Option<u64>,
    /// Anchor state.
    pub anchor_state: AnchorState,
    /// Computed here; absent without an anchor — a fingerprint over nothing would be a value that
    /// two devices without an anchor would take for a match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_set_fingerprint: Option<String>,
    /// Signing keys held.
    pub signing_kids_held: Vec<String>,
    /// Revocations stored.
    pub revocations_held: u32,
    /// Findings as `type` URIs.
    pub findings: Vec<String>,
}

/// The `delivery` block in the heartbeat (proposal §7.0): the server sees a device whose
/// acknowledgements are stuck, without asking it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryState {
    /// Commands that were executed but not yet acknowledged.
    pub unacknowledged_commands: u32,
    /// The oldest of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_unacknowledged_at: Option<WireTimestamp>,
    /// The last answered poll of the delivery channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_poll_at: Option<WireTimestamp>,
}

/// `POST /v1/devices/{id}:heartbeat` for a workstation (proposal §7.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Heartbeat {
    /// Device clock with local offset — an observation, never evidence.
    pub sent_at_device: WireTimestamp,
    /// Program.
    pub app: Application,
    /// Operating system.
    pub platform: Platform,
    /// Key state; absent only in a version that does not know it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_keys: Option<KeyNotice>,
    /// Delivery state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryState>,
}

/// A command in the heartbeat answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCommand {
    /// The command.
    pub command: HeartbeatCommand,
    /// Reason, for instance `key_revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Clear text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Further details.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// The heartbeat answer (03 §6.4.1). Kiosk blocks such as `sheetCounterReconciliation` stay in
/// [`HeartbeatResponse::further`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    /// Server time.
    pub server_time: WireTimestamp,
    /// Deviation of the device clock. The clock is never set; the value only corrects displays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_offset_ms: Option<i64>,
    /// State.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_state: Option<DeviceState>,
    /// ETag of the configuration; if it differs, the client reads `GET /v1/devices/me`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_etag: Option<String>,
    /// Commands — unsigned, see the module header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<DeviceCommand>>,
    /// Interval until the next heartbeat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_heartbeat_seconds: Option<u64>,
    /// Everything else, unchanged.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::IdentifierError;

    #[test]
    fn the_example_identifier_from_03_is_itself_not_canonical() {
        // 03 §6.2.1 shows `dev_01JB8Z5K3M4N6P7Q8R9S0T1U2V`; the U at position 24 is not in the
        // Crockford alphabet. A server that passes T17 rejects exactly this identifier.
        let error = "dev_01JB8Z5K3M4N6P7Q8R9S0T1U2V".parse::<DeviceIdentifier>().unwrap_err();
        assert!(
            matches!(error, IdentifierError::Character { character: 'U', place: 24, .. }),
            "{error:?}"
        );
        let body = r#"{"deviceId":"dev_01JB8Z5K3M4N6P7Q8R9S0T1U2V","state":"active"}"#;
        assert!(serde_json::from_str::<DeviceObject>(body).is_err());
    }

    #[test]
    fn an_answer_without_server_keys_is_an_answer_without_an_anchor() {
        let body = r#"{"deviceId":"dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB","state":"pending_admin_approval",
                        "tenant":{"id":"t_acme","name":"ACME GmbH"}}"#;
        let device: DeviceObject = serde_json::from_str(body).unwrap();
        assert!(device.server_keys.is_none());
        assert!(!device.is_active());
    }

    #[test]
    fn an_unknown_state_is_not_active() {
        let body = r#"{"deviceId":"dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB","state":"quarantined"}"#;
        let device: DeviceObject = serde_json::from_str(body).unwrap();
        assert_eq!(device.state, DeviceState::Unknown("quarantined".into()));
        assert!(!device.is_active());
    }

    #[test]
    fn a_jwk_with_a_private_part_or_a_foreign_curve_is_rejected() {
        let mut jwk = PublicJwk::p256("x".into(), "y".into(), None);
        assert_eq!(jwk.check(), Ok(()));
        jwk.private_part = Some("secret".into());
        assert_eq!(jwk.check(), Err(JwkError::PrivatePart));
        let mut jwk = PublicJwk::p256("x".into(), "y".into(), None);
        jwk.crv = "P-384".into();
        assert!(matches!(jwk.check(), Err(JwkError::Field { field: "crv", .. })));
    }

    #[test]
    fn only_harmless_heartbeat_commands_are_followed() {
        assert!(HeartbeatCommand::RefreshKeys.is_harmless_hint());
        assert!(!HeartbeatCommand::ForceLogout.is_harmless_hint());
        assert!(!HeartbeatCommand::Unknown("wipe".into()).is_harmless_hint());
    }
}
