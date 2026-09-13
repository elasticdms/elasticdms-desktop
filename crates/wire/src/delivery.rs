//! The delivery channel on the wire and the strict translation into the command catalogue
//! (proposal §7.3, ADR-D04, ADR-013).
//!
//! Long poll `GET /v1/delivery/commands?wait=25`, outbound only, with the **device** token — an
//! erasure has to reach a device even when the user's session has expired, and precisely then
//! pinned copies are still lying on the disk.
//!
//! Three stages, three kinds of error:
//!
//! 1. [`DeliveryPage`] — the envelope of the answer. The entries stay raw JSON values, so that
//!    **one** broken command does not block the whole page and with it the channel.
//! 2. [`CommandEnvelope`] — a command with identifier, target device, kind, time, payload and
//!    signature. It keeps the **raw value**: the signed bytes are `JCS(command without
//!    serverSignature)` as it arrived, unknown fields included (03 §6.2.4, rule P2). Whoever
//!    translated into a model first and back again would lose them, and the signature of an
//!    honest server would no longer hold. `edms-crypto` does the check itself.
//! 3. [`CommandEnvelope::command`] — the **strict** translation into
//!    [`edms_core::delivery::Command`]. Unknown kind, foreign device, missing signature, unknown
//!    payload field, volume limit: each of these is an error the engine acknowledges as
//!    `REJECTED` ([`CommandReadError::acknowledgement`]). A command whose payload the client does
//!    not fully understand is not half executed.

use std::collections::HashSet;

use edms_core::delivery::{Command, CommandError, CommandOutcome, Reason, check};
use edms_core::identifier::{CommandIdentifier, DeviceIdentifier, DocumentIdentifier};
use edms_core::namespace::Container;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::basics::WireTimestamp;

/// The delivery channel.
pub const PATH_COMMAND: &str = "/v1/delivery/commands";

/// Highest wait time of a poll, in seconds (ADR-013: 25 s).
pub const WAIT_TIME_SECOND: u32 = 25;

/// The media type in the protected header of the command signature — part of the check, so that
/// a signature from another context is not reusable here (03 §6.2.4, P11).
pub const SIGNATURE_TYPE: &str = "edms-delivery-command+jwt";

/// Maximum number of commands per answer (proposal §7.3).
pub const MAX_COMMAND_PER_RESPONSE: usize = 50;

/// Maximum length of `detail` in an acknowledgement, in characters.
pub const MAX_DETAIL_CHARACTER: usize = 500;

/// `POST /v1/delivery/commands/{commandId}:acknowledge`.
pub fn path_acknowledgement(command: CommandIdentifier) -> String {
    format!("{PATH_COMMAND}/{command}:acknowledge")
}

/// The query parameters of the long poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryQuery {
    wait: u32,
    cursor: Option<String>,
}

/// Why a delivery poll is not sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// `wait` above 25 s holds a connection open longer than load balancers bear.
    #[error("wait={0} exceeds the {WAIT_TIME_SECOND} seconds of ADR-013")]
    WaitTime(u32),
    /// An empty cursor is no cursor.
    #[error(
        "an empty cursor is no cursor; without `cursor` the server delivers every open command"
    )]
    EmptyCursor,
}

impl DeliveryQuery {
    /// A poll; without a cursor the server delivers all open commands of this device.
    pub fn new(wait: u32, cursor: Option<String>) -> Result<Self, QueryError> {
        if wait > WAIT_TIME_SECOND {
            return Err(QueryError::WaitTime(wait));
        }
        if cursor.as_deref() == Some("") {
            return Err(QueryError::EmptyCursor);
        }
        Ok(Self { wait, cursor })
    }

    /// The parameters for the query string.
    pub fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q = vec![("wait", self.wait.to_string())];
        if let Some(c) = &self.cursor {
            q.push(("cursor", c.clone()));
        }
        q
    }
}

/// The answer of the long poll: `{items, nextCursor}`. Empty `items` are the normal case of an
/// expired wait, not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryPage {
    /// The commands, raw — see the module header.
    pub items: Vec<Value>,
    /// The cursor of the next poll; opaque.
    pub next_cursor: String,
}

impl DeliveryPage {
    /// Every entry as an envelope or as an error — one at a time, so that one does not hold up
    /// the others.
    pub fn envelopes(&self) -> Vec<Result<CommandEnvelope, EnvelopeError>> {
        self.items.iter().cloned().map(CommandEnvelope::from_value).collect()
    }
}

/// The kinds of the closed catalogue (ADR-D04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandKind {
    /// `DEHYDRATE`.
    Dehydrate,
    /// `RECONCILE`.
    Reconcile,
    /// `SIGN_OUT`.
    SignOut,
    /// `REFRESH_KEYS`.
    RefreshKeys,
}

impl CommandKind {
    /// The wire value.
    pub const fn wire_value(self) -> &'static str {
        match self {
            Self::Dehydrate => "DEHYDRATE",
            Self::Reconcile => "RECONCILE",
            Self::SignOut => "SIGN_OUT",
            Self::RefreshKeys => "REFRESH_KEYS",
        }
    }

    /// Reads a wire value; what is not in the catalogue is not a kind.
    pub fn from_wire_value(text: &str) -> Option<Self> {
        [Self::Dehydrate, Self::Reconcile, Self::SignOut, Self::RefreshKeys]
            .into_iter()
            .find(|a| a.wire_value() == text)
    }
}

/// Why an entry is not a command envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// Without a readable `commandId` it cannot even be acknowledged; the engine reports a
    /// security warning and leaves the entry lying.
    #[error(
        "an entry in the delivery channel has no readable `commandId` ({0}); it cannot be \
         acknowledged"
    )]
    WithoutIdentifier(String),
    /// Identifier readable, the rest not — acknowledgeable as `REJECTED`.
    #[error("the command {command} is unreadable: {cause}")]
    Unreadable {
        /// The identifier.
        command: CommandIdentifier,
        /// What is wrong.
        cause: String,
    },
}

impl EnvelopeError {
    /// The identifier under which the error can be acknowledged.
    pub fn command(&self) -> Option<CommandIdentifier> {
        match self {
            Self::WithoutIdentifier(_) => None,
            Self::Unreadable { command, .. } => Some(*command),
        }
    }
}

/// A command from the delivery channel, read but not yet checked and not yet translated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEnvelope {
    raw: Map<String, Value>,
    command_id: CommandIdentifier,
    device_id: DeviceIdentifier,
    kind: String,
    issued_at: WireTimestamp,
    payload: Value,
    server_signature: Option<String>,
}

fn text_field(raw: &Map<String, Value>, field: &str) -> Result<String, String> {
    match raw.get(field) {
        Some(Value::String(t)) => Ok(t.clone()),
        Some(_) => Err(format!("`{field}` is not a string")),
        None => Err(format!("`{field}` is missing")),
    }
}

impl CommandEnvelope {
    /// Reads an entry of the delivery page.
    pub fn from_value(value: Value) -> Result<Self, EnvelopeError> {
        let Value::Object(raw) = value else {
            return Err(EnvelopeError::WithoutIdentifier("the entry is not an object".into()));
        };
        let command_id: CommandIdentifier = text_field(&raw, "commandId")
            .and_then(|t| {
                t.parse().map_err(|e: edms_core::identifier::IdentifierError| e.to_string())
            })
            .map_err(EnvelopeError::WithoutIdentifier)?;
        let unreadable = |cause: String| EnvelopeError::Unreadable { command: command_id, cause };
        let device_id = text_field(&raw, "deviceId")
            .and_then(|t| t.parse::<DeviceIdentifier>().map_err(|e| e.to_string()))
            .map_err(unreadable)?;
        let kind = text_field(&raw, "kind").map_err(unreadable)?;
        let issued_at = text_field(&raw, "issuedAt")
            .and_then(|t| WireTimestamp::read(&t).map_err(|e| e.to_string()))
            .map_err(unreadable)?;
        let payload =
            raw.get("payload").cloned().ok_or_else(|| unreadable("`payload` is missing".into()))?;
        let server_signature = match raw.get("serverSignature") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(unreadable("`serverSignature` is neither a string nor null".into()));
            }
        };
        Ok(Self { raw, command_id, device_id, kind, issued_at, payload, server_signature })
    }

    /// The identifier — the basis of deduplication (delivered at least once).
    pub const fn command_id(&self) -> CommandIdentifier {
        self.command_id
    }

    /// The target device; it stands in the signed bytes.
    pub const fn device_id(&self) -> DeviceIdentifier {
        self.device_id
    }

    /// The kind as it stands on the wire.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The kind, if it stands in the catalogue.
    pub fn catalogue_kind(&self) -> Option<CommandKind> {
        CommandKind::from_wire_value(&self.kind)
    }

    /// Issued — server time inside the signed body.
    pub fn issued_at(&self) -> &WireTimestamp {
        &self.issued_at
    }

    /// The payload, raw.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// The detached JWS `<b64u(header)>..<b64u(signature)>`; `None` when none came.
    pub fn server_signature(&self) -> Option<&str> {
        self.server_signature.as_deref()
    }

    /// The command as it arrived.
    pub fn raw(&self) -> &Map<String, Value> {
        &self.raw
    }

    /// What is signed: the raw value without `serverSignature`, all other fields unchanged.
    /// `edms-crypto` does the canonicalization (JCS) and the check.
    pub fn signed_content(&self) -> Value {
        let mut without = self.raw.clone();
        without.remove("serverSignature");
        Value::Object(without)
    }

    /// The strict translation into the core's catalogue.
    ///
    /// To be called **only after** the signature check in `edms-crypto` has passed. A command
    /// without a signature still never becomes a [`Command`] here — the second door is locked
    /// too, even when somebody forgets the first.
    pub fn command(&self, own_device: DeviceIdentifier) -> Result<Command, CommandReadError> {
        if self.device_id != own_device {
            return Err(CommandReadError::ForeignDevice {
                expected: own_device,
                actual: self.device_id,
            });
        }
        if self.server_signature.is_none() {
            return Err(CommandReadError::WithoutSignature);
        }
        let catalogue_kind = self
            .catalogue_kind()
            .ok_or_else(|| CommandReadError::UnknownKind(self.kind.clone()))?;
        let payload = |cause: serde_json::Error| CommandReadError::Payload {
            catalogue_kind,
            cause: cause.to_string(),
        };
        let command = match catalogue_kind {
            CommandKind::Dehydrate => {
                let n: DehydratePayload =
                    serde_json::from_value(self.payload.clone()).map_err(payload)?;
                let mut seen = HashSet::new();
                if let Some(duplicate) = n.document_ids.iter().find(|d| !seen.insert(**d)) {
                    return Err(CommandReadError::DuplicateDocument(*duplicate));
                }
                Command::Dehydrate { documents: n.document_ids, reason: n.reason }
            }
            CommandKind::Reconcile => {
                let n: ReconcilePayload =
                    serde_json::from_value(self.payload.clone()).map_err(payload)?;
                // The core decides what a container is; a prefix list repeated here would have
                // gone stale at namespace v2, when `cases` fell away and `arc_…/cas_…` arrived.
                let container = match n.container.as_deref() {
                    None => None,
                    Some(t) => Some(t.parse::<Container>().map_err(|e| {
                        CommandReadError::Payload { catalogue_kind, cause: e.to_string() }
                    })?),
                };
                Command::Reconcile { container }
            }
            CommandKind::SignOut => {
                let _: EmptyPayload =
                    serde_json::from_value(self.payload.clone()).map_err(payload)?;
                Command::SignOut
            }
            CommandKind::RefreshKeys => {
                let _: EmptyPayload =
                    serde_json::from_value(self.payload.clone()).map_err(payload)?;
                Command::RefreshKeys
            }
        };
        check(&command)?;
        Ok(command)
    }
}

impl Serialize for CommandEnvelope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CommandEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_value(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DehydratePayload {
    document_ids: Vec<DocumentIdentifier>,
    reason: Reason,
}

fn required_or_null<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcilePayload {
    // `deserialize_with` without `default` makes the field mandatory: `null` means “all”, a
    // missing field means nothing and is rejected.
    #[serde(deserialize_with = "required_or_null")]
    container: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

/// Why a command that has been read is not executed. Every variant is acknowledged `REJECTED`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandReadError {
    /// The command is meant for another device — a replayed command.
    #[error(
        "the command is meant for device {actual}, this one is {expected}; a foreign command is \
         never executed"
    )]
    ForeignDevice {
        /// This device.
        expected: DeviceIdentifier,
        /// According to the command.
        actual: DeviceIdentifier,
    },
    /// Without a signature, no command (ADR-D04).
    #[error(
        "the command carries no `serverSignature`; unsigned commands are never executed \
         (ADR-D04)"
    )]
    WithoutSignature,
    /// Not in the closed catalogue.
    #[error("the command kind `{0}` is not in this client's catalogue; it is not executed")]
    UnknownKind(String),
    /// The payload does not match the kind — an unknown field included.
    #[error("the payload of the command {} is unreadable: {cause}", catalogue_kind.wire_value())]
    Payload {
        /// The kind.
        catalogue_kind: CommandKind,
        /// What is wrong.
        cause: String,
    },
    /// A document stands twice in the command.
    #[error("the document {0} stands more than once in the command")]
    DuplicateDocument(DocumentIdentifier),
    /// Volume limit of the core.
    #[error(transparent)]
    Amount(#[from] CommandError),
}

impl CommandReadError {
    /// The acknowledgement for it: `REJECTED` with the reason. The reason names identifiers,
    /// never titles.
    pub fn acknowledgement(&self) -> Acknowledgement {
        Acknowledgement::new(CommandOutcome::Rejected, Some(self.to_string()))
    }
}

/// `POST …:acknowledge` — the body (proposal §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledgement {
    /// `APPLIED`, `NOT_APPLICABLE`, `REJECTED` or `FAILED`.
    pub outcome: CommandOutcome,
    /// Reason, shortened to [`MAX_DETAIL_CHARACTER`]. **Never** a document title or file name —
    /// the erasure register is free of content (ADR-011).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Acknowledgement {
    /// An acknowledgement; `detail` is shortened to the maximum length.
    pub fn new(outcome: CommandOutcome, detail: Option<String>) -> Self {
        let detail = detail.map(|d| d.chars().take(MAX_DETAIL_CHARACTER).collect());
        Self { outcome, detail }
    }

    /// Whether the outcome is final. Only `FAILED` is not: the server delivers again, and a
    /// later final acknowledgement replaces it.
    pub fn is_final(&self) -> bool {
        self.outcome != CommandOutcome::Failed
    }
}

/// The answer to `…:acknowledge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgementReceipt {
    /// The command.
    pub command_id: CommandIdentifier,
    /// The stored outcome.
    pub outcome: CommandOutcome,
    /// Server time.
    pub acknowledged_at: WireTimestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DEVICE: &str = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB";
    const FOREIGN: &str = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAC";

    fn device() -> DeviceIdentifier {
        DEVICE.parse().unwrap()
    }

    fn envelope(kind: &str, payload: Value) -> Value {
        json!({
            "commandId": "cmd_01JKC4D6E8F0G2H4J6K8M0N2P4",
            "deviceId": DEVICE,
            "kind": kind,
            "issuedAt": "2026-09-11T07:30:00Z",
            "payload": payload,
            "serverSignature": "eyJhbGciOiJFUzI1NiJ9..c2ln"
        })
    }

    fn read(kind: &str, payload: Value) -> Result<Command, CommandReadError> {
        CommandEnvelope::from_value(envelope(kind, payload)).unwrap().command(device())
    }

    #[test]
    fn a_dehydrate_command_becomes_the_core_command() {
        let c = read(
            "DEHYDRATE",
            json!({"documentIds": ["doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB"], "reason": "ERASURE"}),
        );
        assert!(
            matches!(c, Ok(Command::Dehydrate { reason: Reason::Erasure, ref documents }) if documents.len() == 1)
        );
    }

    #[test]
    fn an_unknown_kind_is_refused_and_not_executed() {
        let error = read("DELETE_EVERYTHING", json!({})).unwrap_err();
        assert_eq!(error, CommandReadError::UnknownKind("DELETE_EVERYTHING".into()));
        let acknowledgement = error.acknowledgement();
        assert_eq!(acknowledgement.outcome, CommandOutcome::Rejected);
        assert!(acknowledgement.detail.unwrap().contains("DELETE_EVERYTHING"));
    }

    #[test]
    fn an_unknown_payload_field_is_not_half_understood() {
        let error = read(
            "DEHYDRATE",
            json!({"documentIds": ["doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB"], "reason": "SPACE_RECLAIM", "includePinned": true}),
        );
        assert!(matches!(
            error,
            Err(CommandReadError::Payload { catalogue_kind: CommandKind::Dehydrate, .. })
        ));
        assert!(matches!(
            read("SIGN_OUT", json!({"reason": "x"})),
            Err(CommandReadError::Payload { .. })
        ));
        assert!(matches!(read("SIGN_OUT", Value::Null), Err(CommandReadError::Payload { .. })));
        assert!(matches!(
            read(
                "DEHYDRATE",
                json!({"documentIds": ["doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB"], "reason": "TIDY_UP"})
            ),
            Err(CommandReadError::Payload { .. })
        ));
    }

    #[test]
    fn the_cores_volume_limit_and_duplicate_documents_bite_while_reading() {
        assert_eq!(
            read("DEHYDRATE", json!({"documentIds": [], "reason": "ERASURE"})),
            Err(CommandReadError::Amount(CommandError::WithoutDocument))
        );
        let duplicate = json!({"documentIds": ["doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB", "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB"], "reason": "ERASURE"});
        assert!(matches!(
            read("DEHYDRATE", duplicate),
            Err(CommandReadError::DuplicateDocument(_))
        ));
    }

    #[test]
    fn reconcile_demands_the_container_explicitly() {
        assert_eq!(
            read("RECONCILE", json!({"container": null})),
            Ok(Command::Reconcile { container: None })
        );
        let case = read(
            "RECONCILE",
            json!({"container": "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3/cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7"}),
        )
        .unwrap();
        assert!(matches!(case, Command::Reconcile { container: Some(Container::Case { .. }) }));
        assert!(matches!(read("RECONCILE", json!({})), Err(CommandReadError::Payload { .. })));
        // The tree before namespace v2: a top-level `cases` folder, and a case file that named
        // no archive. Both are read as nothing at all rather than as some archive's case file.
        for gone in ["cases", "cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7"] {
            assert!(
                matches!(
                    read("RECONCILE", json!({"container": gone})),
                    Err(CommandReadError::Payload { .. })
                ),
                "{gone}"
            );
        }
    }

    #[test]
    fn a_command_for_another_device_is_never_executed() {
        let mut raw = envelope("SIGN_OUT", json!({}));
        raw["deviceId"] = json!(FOREIGN);
        let error = CommandEnvelope::from_value(raw).unwrap().command(device());
        assert!(matches!(error, Err(CommandReadError::ForeignDevice { .. })));
    }

    #[test]
    fn without_a_signature_no_command_arises() {
        let mut raw = envelope("SIGN_OUT", json!({}));
        raw["serverSignature"] = Value::Null;
        assert_eq!(
            CommandEnvelope::from_value(raw).unwrap().command(device()),
            Err(CommandReadError::WithoutSignature)
        );
    }

    #[test]
    fn an_entry_without_an_identifier_cannot_be_acknowledged_one_with_it_can() {
        let error = CommandEnvelope::from_value(json!({"kind": "SIGN_OUT"})).unwrap_err();
        assert_eq!(error.command(), None);
        let mut raw = envelope("SIGN_OUT", json!({}));
        raw["issuedAt"] = json!("2026-09-11T07:30:00");
        let error = CommandEnvelope::from_value(raw).unwrap_err();
        assert!(error.command().is_some());
        assert!(CommandEnvelope::from_value(json!([1, 2])).is_err());
    }

    #[test]
    fn what_is_signed_is_the_raw_value_without_the_signature_unknown_fields_included() {
        let mut raw = envelope("REFRESH_KEYS", json!({}));
        raw["future"] = json!({"field": 1});
        let envelope = CommandEnvelope::from_value(raw.clone()).unwrap();
        let content = envelope.signed_content();
        assert!(content.get("serverSignature").is_none());
        assert_eq!(content.get("future"), Some(&json!({"field": 1})));
        assert_eq!(serde_json::to_value(&envelope).unwrap(), raw);
    }

    #[test]
    fn an_acknowledgement_is_shortened_and_only_failed_is_not_final() {
        let a = Acknowledgement::new(CommandOutcome::Failed, Some("x".repeat(2_000)));
        assert_eq!(a.detail.as_ref().map(|d| d.chars().count()), Some(MAX_DETAIL_CHARACTER));
        assert!(!a.is_final());
        assert!(Acknowledgement::new(CommandOutcome::NotApplicable, None).is_final());
    }

    #[test]
    fn a_poll_above_25_seconds_is_not_sent() {
        assert_eq!(DeliveryQuery::new(26, None), Err(QueryError::WaitTime(26)));
        assert_eq!(DeliveryQuery::new(25, Some(String::new())), Err(QueryError::EmptyCursor));
        let a = DeliveryQuery::new(25, Some("k".into())).unwrap();
        assert_eq!(a.to_query(), vec![("wait", "25".to_owned()), ("cursor", "k".to_owned())]);
    }
}
