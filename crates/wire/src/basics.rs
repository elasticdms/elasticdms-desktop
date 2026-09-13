//! Ground rules for every endpoint (03 §6.0) — what every body and every header share.
//!
//! The way through the module:
//!
//! * Constants: version, error-type base, headers, media types (03 §6.0.1, §6.0.4).
//! * [`WireTimestamp`] — an RFC 3339 timestamp, read strictly and written back unchanged.
//! * [`Page`] — the page envelope `{items, nextCursor, hasMore}` (03 §6.0.8).
//! * [`Problem`] and [`ErrorKind`] — problem details per RFC 9457 and the error catalogue
//!   (03 §6.0.7, §6.17, proposal §7.5). **A problem is never left unread:** an unknown `type`, a
//!   foreign body, an HTML block page from the load balancer — all of it becomes a [`Problem`],
//!   when in doubt with [`ErrorKind::Unknown`].
//! * ETag (03 §6.0.9) and digest headers (RFC 9530) as pure functions.
//!
//! Two error shapes, never smoothed over (03 §6.0.7): resource endpoints answer with
//! `application/problem+json`, `/v1/oauth/*` with RFC 6749 §5.2 — the latter live in
//! [`crate::login::OauthError`]. A client that expects problem+json at the token endpoint breaks;
//! one that knows both is built.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edms_core::checksum::{SHA256_BYTES, Sha256Value};
use edms_core::time::{TimeError, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// The dated minor version every request carries to both hosts (03 §6.0.1, finding Q-6).
pub const API_VERSION: &str = "2026-09-01";

/// Base of every error type. The `type` never changes, even when `title` does (03 §6.17).
pub const ERROR_TYPE_BASE: &str = "https://errors.elasticdms.io/";

/// The `type` of a problem with no meaning beyond the HTTP status (RFC 9457 §4.2.1).
pub const TYP_ABOUT_BLANK: &str = "about:blank";

/// The authentication scheme on both hosts: `Authorization: DPoP <token>` (RFC 9449).
pub const SCHEMA_DPOP: &str = "DPoP";

/// `WWW-Authenticate` error value: the proof needs a server nonce (RFC 9449 §8, 03 §6.0.5).
pub const WWW_ERROR_NONCE: &str = "use_dpop_nonce";

/// `WWW-Authenticate` error value: a stronger sign-in is needed (RFC 9470, 03 §6.3.5).
pub const WWW_ERROR_STEP_UP: &str = "insufficient_user_authentication";

/// `WWW-Authenticate` error value: the token lacks a scope (03 §6.16).
pub const WWW_ERROR_SCOPE: &str = "insufficient_scope";

/// Maximum length of a `detail` built from a foreign body (block page, proxy).
pub const MAX_FOREIGN_DETAIL_CHARACTER: usize = 500;

/// The names of the headers the contract uses — in one place, so that client and mock do not
/// maintain two spellings of the same name.
pub mod header {
    /// Dated minor version (03 §6.0.1).
    pub const ELASTICDMS_VERSION: &str = "Elasticdms-Version";
    /// `DPoP <token>` — never `Bearer` (RFC 9449).
    pub const AUTHORIZATION: &str = "Authorization";
    /// The DPoP proof. Exactly one per request; two are a `400` (geraete-auth §2.4).
    pub const DPOP: &str = "DPoP";
    /// The server nonce, rotated with every answer, remembered per origin (03 §6.0.5).
    pub const DPOP_NONCE: &str = "DPoP-Nonce";
    /// Nonce demand, step-up or missing scope.
    pub const WWW_AUTHENTICATE: &str = "WWW-Authenticate";
    /// One ULID per attempt, not per resource (03 §6.0.10, AND-2).
    pub const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
    /// `true` when the server repeats a stored answer.
    pub const IDEMPOTENCY_REPLAYED: &str = "Idempotency-Replayed";
    /// Conditional read; `*` when creating with `PUT` (03 §6.0.9).
    pub const IF_NONE_MATCH: &str = "If-None-Match";
    /// Conditional read or write against a strong ETag.
    pub const IF_MATCH: &str = "If-Match";
    /// Strong ETag of every metadata resource.
    pub const ETAG: &str = "ETag";
    /// Location of a newly created resource.
    pub const LOCATION: &str = "Location";
    /// Beats every local backoff.
    pub const RETRY_AFTER: &str = "Retry-After";
    /// One ULID per request, for correlation in logs.
    pub const X_REQUEST_ID: &str = "X-Request-Id";
    /// W3C trace context.
    pub const TRACEPARENT: &str = "Traceparent";
    /// Steers `title` and `detail`, never `type` (03 §6.0.4).
    pub const ACCEPT_LANGUAGE: &str = "Accept-Language";
    /// Rate limiting (03 §6.0.11).
    pub const RATE_LIMIT: &str = "RateLimit";
    /// The buckets of the rate limiting (03 §6.0.11).
    pub const RATE_LIMIT_POLICY: &str = "RateLimit-Policy";
    /// Checksum of the content sent (RFC 9530), on upload (proposal §7.4).
    pub const CONTENT_DIGEST: &str = "Content-Digest";
    /// Checksum of the delivered rendition (RFC 9530), on content (proposal §7.2).
    pub const REPR_DIGEST: &str = "Repr-Digest";
    /// File name of the program that opens a file (proposal §7.2).
    pub const REQUESTING_APPLICATION: &str = "Elasticdms-Accessing-Application";
    /// Media type.
    pub const CONTENT_TYPE: &str = "Content-Type";
    /// Length in bytes.
    pub const CONTENT_LENGTH: &str = "Content-Length";
    /// Caching rules.
    pub const CACHE_CONTROL: &str = "Cache-Control";
}

/// Media types of the contract.
pub mod media_type {
    /// Every body of the resource API.
    pub const JSON: &str = "application/json";
    /// Every error answer of the resource API (RFC 9457).
    pub const PROBLEM: &str = "application/problem+json";
    /// Every request to `/v1/oauth/*` (RFC 6749).
    pub const FORM: &str = "application/x-www-form-urlencoded";
}

// ── Open catalogues ─────────────────────────────────────────────────────────────────────────

/// An enumeration type for wire values the server may extend (states, levels, commands in the
/// heartbeat). An unknown value becomes `Unknown(text)` — read, displayed, written back
/// unchanged, **never** reinterpreted as a known value. A client that stopped at a new state with
/// a read error would not be maintainable in the field; one that silently read it as a known
/// state would do the wrong thing.
macro_rules! open_catalogue {
    (
        $(#[$doc:meta])*
        $name:ident {
            $( $(#[$vdoc:meta])* $variant:ident => $wire:literal ),+ $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vdoc])* $variant, )+
            /// A value this client does not know — read and kept unchanged.
            Unknown(String),
        }

        impl $name {
            /// The value as it stands on the wire.
            pub fn wire_value(&self) -> &str {
                match self {
                    $( Self::$variant => $wire, )+
                    Self::Unknown(text) => text,
                }
            }

            /// Reads a wire value; what is not in the catalogue becomes `Unknown`.
            pub fn from_wire_value(text: &str) -> Self {
                match text {
                    $( $wire => Self::$variant, )+
                    _ => Self::Unknown(text.to_owned()),
                }
            }

            /// Whether the value stands in this client's catalogue.
            pub fn is_known(&self) -> bool {
                !matches!(self, Self::Unknown(_))
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.wire_value())
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.wire_value())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Ok(Self::from_wire_value(&text))
            }
        }
    };
}
pub(crate) use open_catalogue;

// ── Timestamps ──────────────────────────────────────────────────────────────────────────────

/// A timestamp as it stands on the wire: RFC 3339 text with a zone (03 §6.0).
///
/// **Read strictly, written back unchanged.** A text without a zone is a wall-clock time
/// somewhere and is rejected (`edms_core::time`). What is written is the text as it arrived —
/// `2026-09-02T08:14:22Z` stays without milliseconds, `+02:00` stays `+02:00`. Otherwise a body
/// read and written again would no longer be the same one, and the golden files check exactly
/// that. For comparisons [`WireTimestamp::timestamp`] counts, not the text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireTimestamp {
    text: String,
    timestamp: Timestamp,
}

impl WireTimestamp {
    /// Reads RFC 3339 text; without a zone or with an impossible date it is an error.
    pub fn read(text: &str) -> Result<Self, TimeError> {
        Ok(Self { text: text.to_owned(), timestamp: Timestamp::from_rfc3339(text)? })
    }

    /// From a timestamp; the text is the UTC form with milliseconds.
    pub fn from_timestamp(timestamp: Timestamp) -> Self {
        Self { text: timestamp.rfc3339(), timestamp }
    }

    /// The instant — the basis of every comparison.
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// The text as it stood on the wire.
    pub fn as_text(&self) -> &str {
        &self.text
    }
}

impl From<Timestamp> for WireTimestamp {
    fn from(timestamp: Timestamp) -> Self {
        Self::from_timestamp(timestamp)
    }
}

impl fmt::Display for WireTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Serialize for WireTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for WireTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::read(&text).map_err(serde::de::Error::custom)
    }
}

// ── Pages ───────────────────────────────────────────────────────────────────────────────────

/// The page envelope of every listing (03 §6.0.8): `{items, nextCursor, hasMore}`.
///
/// `nextCursor` is set exactly when `hasMore` is true (proposal §7.1); otherwise `null` stands
/// there. The cursor is opaque — the client never reads it out, it only hands it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    /// The entries of this page.
    pub items: Vec<T>,
    /// The cursor for the next page; `null` on the last one.
    pub next_cursor: Option<String>,
    /// Whether another page follows.
    pub has_more: bool,
}

impl<T> Page<T> {
    /// The cursor to read on with; `None` means: that was the last page.
    ///
    /// A contradiction between `hasMore` and `nextCursor` is an error, not a matter of
    /// interpretation: resolving it in favour of `hasMore: false` would silently show a
    /// truncated case file.
    pub fn continuation(&self) -> Result<Option<&str>, PageError> {
        check_continuation(self.has_more, self.next_cursor.as_deref())
    }
}

/// The shared rule for `hasMore` and `nextCursor`, for pages with extra fields as well.
pub fn check_continuation(
    has_more: bool,
    next_cursor: Option<&str>,
) -> Result<Option<&str>, PageError> {
    match (has_more, next_cursor) {
        (true, None) => Err(PageError::MoreWithoutCursor),
        (true, Some("")) => Err(PageError::EmptyCursor),
        (true, Some(cursor)) => Ok(Some(cursor)),
        (false, Some(_)) => Err(PageError::CursorWithoutMore),
        (false, None) => Ok(None),
    }
}

/// Why a page cannot be continued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    /// `hasMore: true` without a cursor — the listing could not be read to the end.
    #[error(
        "the page reports further entries but names no `nextCursor`; the listing would be \
         incomplete (03 §6.0.8)"
    )]
    MoreWithoutCursor,
    /// An empty cursor is no cursor.
    #[error("the page reports further entries with an empty `nextCursor` (03 §6.0.8)")]
    EmptyCursor,
    /// A cursor on the last page — one of the two values is lying.
    #[error(
        "the page reports `hasMore: false` and names a `nextCursor` all the same; the \
         contradiction is not guessed (proposal §7.1)"
    )]
    CursorWithoutMore,
}

// ── Addresses from answers ──────────────────────────────────────────────────────────────────

/// Whether `address` lies below `base` — the one check before every address that comes out of an
/// answer (`uploadUrl`, `captureUrl`, `verification_uri_complete`, every discovery endpoint).
///
/// The comparison is against `<base>/`, never against `<base>` alone. Otherwise
/// `https://api.elasticdms.io.example.org/x` would lie “below” `https://api.elasticdms.io`, and
/// whoever can forge an answer would get a document's bytes or the user's browser. A trailing
/// slash in `base` changes nothing.
pub fn is_below(address: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    !base.is_empty() && address.strip_prefix(base).is_some_and(|rest| rest.starts_with('/'))
}

// ── Problem details ─────────────────────────────────────────────────────────────────────────

fn typ_about_blank() -> String {
    TYP_ABOUT_BLANK.to_owned()
}

/// An error answer per RFC 9457 with the contract's extensions (03 §6.0.7).
///
/// Unknown extension fields (`anchorSetFingerprint`, `expectedSeq`, `requiredAcr`,
/// `maxAgeSeconds`, `revokedAt` …) stand in [`Problem::further`] and go along unchanged when
/// written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// Dereferenceable type under [`ERROR_TYPE_BASE`]; if missing, `about:blank` applies.
    #[serde(rename = "type", default = "typ_about_blank")]
    pub typ: String,
    /// Short title, localized per `Accept-Language`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// HTTP status as the server writes it into the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Explanation for the human, localized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The resource concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Tenant — only for correlation, never as input (03 §6.0.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// The trace for the call to IT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Field errors of a validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<FieldError>>,
    /// Which dimension of a check failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_dimension: Option<String>,
    /// The server records the case as a security event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_event: Option<bool>,
    /// What the human can do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<Remedy>,
    /// All remaining extension fields, unchanged.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// One entry in `errors[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldError {
    /// The field concerned, as a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Machine-readable reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Further details (`expected`, `actual`, `detail` …).
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// The `remedy` block: an action the server offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remedy {
    /// Label for a button.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// HTTP method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Target, relative to the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// Further details.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

const CORE_FIELD: [&str; 11] = [
    "type",
    "title",
    "status",
    "detail",
    "instance",
    "tenantId",
    "traceId",
    "errors",
    "failedDimension",
    "securityEvent",
    "remedy",
];

impl Problem {
    /// Reads an error answer — **always**, even when the body is not a problem.
    ///
    /// Three cases occur in the field (escan `ProblemLeser`): a proper problem; a problem with an
    /// extension field of an unexpected shape (then the core fields are salvaged one by one); and
    /// a foreign body — HTML from the load balancer, an empty body. In the last case the type
    /// becomes `about:blank` and the text a shortened `detail`. An error reader that fails itself
    /// would swallow exactly the message somebody needs.
    pub fn read(http_status: u16, body: &[u8]) -> Self {
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(object)) => Self::from_object(http_status, object),
            _ => Self::from_foreign_body(http_status, body),
        }
    }

    fn from_object(http_status: u16, object: Map<String, Value>) -> Self {
        if let Ok(mut problem) = serde_json::from_value::<Self>(Value::Object(object.clone())) {
            problem.status.get_or_insert(http_status);
            return problem;
        }
        let text = |field: &str| object.get(field).and_then(Value::as_str).map(str::to_owned);
        let further = object
            .iter()
            .filter(|(k, _)| !CORE_FIELD.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Self {
            typ: text("type").unwrap_or_else(typ_about_blank),
            title: text("title"),
            status: Some(http_status),
            detail: text("detail"),
            instance: text("instance"),
            tenant_id: text("tenantId"),
            trace_id: text("traceId"),
            errors: None,
            failed_dimension: text("failedDimension"),
            security_event: object.get("securityEvent").and_then(Value::as_bool),
            remedy: None,
            further,
        }
    }

    fn from_foreign_body(http_status: u16, body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        let text = text.trim();
        let detail =
            (!text.is_empty()).then(|| text.chars().take(MAX_FOREIGN_DETAIL_CHARACTER).collect());
        Self {
            typ: typ_about_blank(),
            title: None,
            status: Some(http_status),
            detail,
            instance: None,
            tenant_id: None,
            trace_id: None,
            errors: None,
            failed_dimension: None,
            security_event: None,
            remedy: None,
            further: Map::new(),
        }
    }

    /// A problem from the catalogue, as the mock sends it.
    pub fn from_catalogue(kind: ErrorKind, status: u16, detail: &str) -> Self {
        let mut problem = Self::from_foreign_body(status, b"");
        problem.typ = kind.typ_uri().unwrap_or_else(typ_about_blank);
        problem.title = kind.short_code().map(str::to_owned);
        problem.detail = Some(detail.to_owned());
        problem
    }

    /// The catalogue entry behind `type`; unknown is a value, not a crash.
    pub fn error_kind(&self) -> ErrorKind {
        ErrorKind::from_typ_uri(&self.typ)
    }

    /// Whether the case is to be shown as a security event: when the server says so **or** the
    /// catalogue knows it. A missing marking should not defuse the display.
    pub fn is_security_event(&self) -> bool {
        self.security_event == Some(true) || self.error_kind().security_event()
    }

    /// An extension field outside the core fields.
    pub fn extension(&self, name: &str) -> Option<&Value> {
        self.further.get(name)
    }
}

// ── Error catalogue ─────────────────────────────────────────────────────────────────────────

/// The error catalogue as far as it concerns the folder client: 03 §6.17, the requirements from
/// 06 and the proposals from §7.5. If the client does not know a `type`, that is
/// [`ErrorKind::Unknown`] — a part of the contract, not its failure: the server may introduce new
/// types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// `device-enrollment-code-invalid` (401).
    EnrollmentCodeInvalid,
    /// `device-enrollment-code-expired` (401).
    EnrollmentCodeExpired,
    /// `device-id-conflict` (409) — not an idempotent retry (T5).
    DeviceIdConflict,
    /// `device-network-targets-enabled` (422) — for the kiosk; a workstation reports none.
    DeviceNetworkTargetActive,
    /// `device-pending-approval` (403) — the normal case at level `SOFTWARE`.
    DeviceApprovalPending,
    /// `device-revoked` (403).
    DeviceLocked,
    /// `device-quota-exceeded` (403).
    DeviceQuota,
    /// `device-not-in-network-segment` (403), security event.
    DeviceOutsideNetworkSegment,
    /// `device-signature-mismatch` (403), security event.
    DeviceSignatureDeviation,
    /// `device-assertion-invalid` (400) — always with the same description (geraete-auth §3.2).
    DeviceAssertionInvalid,
    /// `desktop-client-not-permitted` (403) — proposal §7.5.
    FolderClientNotUnlocked,
    /// `server-keys-not-anchored` (403).
    ServerKeyNotAnchored,
    /// `server-keys-unavailable` (503) — the device keeps its state.
    ServerKeyNotAvailable,
    /// `server-key-revoked` (409), security event.
    ServerKeyRevoked,
    /// `server-key-set-stale` (409).
    ServerKeyStateStale,
    /// `dpop-nonce-required` (401) — exactly one retry (T9).
    DpopNonceNeeded,
    /// `token-device-binding-mismatch` (403), security event (03 §6.0.6).
    TokenDeviceBinding,
    /// `refresh-token-reuse` (400 as `error_uri`), security event: the family is gone.
    RefreshTokenReused,
    /// `device-code-expired` (400 as `error_uri`, geraete-auth §2.3).
    DeviceCodeExpired,
    /// `session-expired` (400 as `error_uri`) — proposal §7.5: the session has ended.
    SessionExpired,
    /// `insufficient-authentication` (401) — step-up per RFC 9470.
    AuthenticationTooWeak,
    /// `step-up-subject-mismatch` (403), security event.
    StepUpSubjectMismatch,
    /// `tenant-identity-incomplete` (403).
    TenantIdentityIncomplete,
    /// `invalid-cursor` (400) — proposal §7.5, contract test T16.
    CursorInvalid,
    /// `saved-search-not-executable` (422) — proposal §7.5.
    SearchNotRunnable,
    /// `representation-unavailable` (404) — proposal §7.5: there is no deliverable rendition.
    RenditionNotAvailable,
    /// `access-log-unavailable` (503) — proposal §7.5: without a log, no content.
    AccessLogNotAvailable,
    /// `delivery-command-unknown` (404) — proposal §7.5.
    CommandUnknown,
    /// `delivery-command-already-acknowledged` (409) — proposal §7.5.
    CommandAlreadyAcknowledged,
    /// `ingest-content-digest-mismatch` (422) — proposal §7.5.
    UploadDigestDeviation,
    /// `ingest-upload-incomplete` (409) — proposal §7.5.
    UploadIncomplete,
    /// `ingest-upload-expired` (410) — proposal §7.5.
    UploadExpired,
    /// `ingest-too-large` (413) — proposal §7.5.
    UploadTooLarge,
    /// `unsupported-media-type` (415).
    MediaTypeNotSupported,
    /// `idempotency-in-progress` (409).
    IdempotencyRuns,
    /// `idempotency-key-reuse` (422).
    IdempotencyKeyReused,
    /// `precondition-required` (428).
    PreconditionRequired,
    /// `precondition-failed` (412) — a success at enrollment, a new version for content.
    PreconditionFailed,
    /// `mutually-exclusive-parameters` (400).
    ParameterCloseItselfFrom,
    /// `invalid-resource-id` (400) — contract test T17.
    ResourceIdentifierInvalid,
    /// `validation-failed` (422).
    ValidationFailed,
    /// `insufficient-scope` (403).
    ScopeMissing,
    /// `rate-limited` (429) — `Retry-After` beats every local backoff.
    RateLimit,
    /// `client-version-too-old` (426).
    ClientTooOld,
    /// `not-found` (404) — never „gibt es nicht", always „nicht sichtbar" — never “does not
    /// exist”, always “not visible” (tenant separation).
    NotFound,
    /// A `type` this client does not know, or one outside [`ERROR_TYPE_BASE`].
    Unknown,
}

const CATALOGUE: &[(ErrorKind, &str)] = &[
    (ErrorKind::EnrollmentCodeInvalid, "device-enrollment-code-invalid"),
    (ErrorKind::EnrollmentCodeExpired, "device-enrollment-code-expired"),
    (ErrorKind::DeviceIdConflict, "device-id-conflict"),
    (ErrorKind::DeviceNetworkTargetActive, "device-network-targets-enabled"),
    (ErrorKind::DeviceApprovalPending, "device-pending-approval"),
    (ErrorKind::DeviceLocked, "device-revoked"),
    (ErrorKind::DeviceQuota, "device-quota-exceeded"),
    (ErrorKind::DeviceOutsideNetworkSegment, "device-not-in-network-segment"),
    (ErrorKind::DeviceSignatureDeviation, "device-signature-mismatch"),
    (ErrorKind::DeviceAssertionInvalid, "device-assertion-invalid"),
    (ErrorKind::FolderClientNotUnlocked, "desktop-client-not-permitted"),
    (ErrorKind::ServerKeyNotAnchored, "server-keys-not-anchored"),
    (ErrorKind::ServerKeyNotAvailable, "server-keys-unavailable"),
    (ErrorKind::ServerKeyRevoked, "server-key-revoked"),
    (ErrorKind::ServerKeyStateStale, "server-key-set-stale"),
    (ErrorKind::DpopNonceNeeded, "dpop-nonce-required"),
    (ErrorKind::TokenDeviceBinding, "token-device-binding-mismatch"),
    (ErrorKind::RefreshTokenReused, "refresh-token-reuse"),
    (ErrorKind::DeviceCodeExpired, "device-code-expired"),
    (ErrorKind::SessionExpired, "session-expired"),
    (ErrorKind::AuthenticationTooWeak, "insufficient-authentication"),
    (ErrorKind::StepUpSubjectMismatch, "step-up-subject-mismatch"),
    (ErrorKind::TenantIdentityIncomplete, "tenant-identity-incomplete"),
    (ErrorKind::CursorInvalid, "invalid-cursor"),
    (ErrorKind::SearchNotRunnable, "saved-search-not-executable"),
    (ErrorKind::RenditionNotAvailable, "representation-unavailable"),
    (ErrorKind::AccessLogNotAvailable, "access-log-unavailable"),
    (ErrorKind::CommandUnknown, "delivery-command-unknown"),
    (ErrorKind::CommandAlreadyAcknowledged, "delivery-command-already-acknowledged"),
    (ErrorKind::UploadDigestDeviation, "ingest-content-digest-mismatch"),
    (ErrorKind::UploadIncomplete, "ingest-upload-incomplete"),
    (ErrorKind::UploadExpired, "ingest-upload-expired"),
    (ErrorKind::UploadTooLarge, "ingest-too-large"),
    (ErrorKind::MediaTypeNotSupported, "unsupported-media-type"),
    (ErrorKind::IdempotencyRuns, "idempotency-in-progress"),
    (ErrorKind::IdempotencyKeyReused, "idempotency-key-reuse"),
    (ErrorKind::PreconditionRequired, "precondition-required"),
    (ErrorKind::PreconditionFailed, "precondition-failed"),
    (ErrorKind::ParameterCloseItselfFrom, "mutually-exclusive-parameters"),
    (ErrorKind::ResourceIdentifierInvalid, "invalid-resource-id"),
    (ErrorKind::ValidationFailed, "validation-failed"),
    (ErrorKind::ScopeMissing, "insufficient-scope"),
    (ErrorKind::RateLimit, "rate-limited"),
    (ErrorKind::ClientTooOld, "client-version-too-old"),
    (ErrorKind::NotFound, "not-found"),
];

impl ErrorKind {
    /// All known kinds, in catalogue order.
    pub fn all() -> impl Iterator<Item = ErrorKind> {
        CATALOGUE.iter().map(|(kind, _)| *kind)
    }

    /// The last segment of the `type` URI; `None` for [`ErrorKind::Unknown`].
    pub fn short_code(self) -> Option<&'static str> {
        CATALOGUE.iter().find(|(kind, _)| *kind == self).map(|(_, short)| *short)
    }

    /// The complete `type` URI.
    pub fn typ_uri(self) -> Option<String> {
        self.short_code().map(|short| format!("{ERROR_TYPE_BASE}{short}"))
    }

    /// Maps a `type` URI (or an `error_uri`) onto the catalogue.
    ///
    /// Only URIs under [`ERROR_TYPE_BASE`] count: `https://example.org/device-revoked` is a
    /// foreign type and is not read as a lock on the device. Query and fragment are cut off.
    pub fn from_typ_uri(uri: &str) -> Self {
        let Some(rest) = uri.strip_prefix(ERROR_TYPE_BASE) else {
            return Self::Unknown;
        };
        let short = rest.split(['?', '#']).next().unwrap_or_default().trim_end_matches('/');
        Self::from_short_code(short)
    }

    /// Maps a bare short code.
    pub fn from_short_code(short: &str) -> Self {
        CATALOGUE.iter().find(|(_, k)| *k == short).map_or(Self::Unknown, |(kind, _)| *kind)
    }

    /// Whether the catalogue records the case as a security event (03 §6.17).
    pub const fn security_event(self) -> bool {
        matches!(
            self,
            Self::DeviceOutsideNetworkSegment
                | Self::DeviceSignatureDeviation
                | Self::ServerKeyRevoked
                | Self::TokenDeviceBinding
                | Self::RefreshTokenReused
                | Self::StepUpSubjectMismatch
        )
    }

    /// Whether the type is proposed in this repository (§7.5) and is not in 03 §6.17.
    pub const fn proposed(self) -> bool {
        matches!(
            self,
            Self::FolderClientNotUnlocked
                | Self::SessionExpired
                | Self::CursorInvalid
                | Self::SearchNotRunnable
                | Self::RenditionNotAvailable
                | Self::AccessLogNotAvailable
                | Self::CommandUnknown
                | Self::CommandAlreadyAcknowledged
                | Self::UploadDigestDeviation
                | Self::UploadIncomplete
                | Self::UploadExpired
                | Self::UploadTooLarge
        )
    }
}

// ── ETag ────────────────────────────────────────────────────────────────────────────────────

/// Why a version does not become a strong ETag, or an ETag does not become a version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EtagError {
    /// An empty version marker is none.
    #[error("an empty version marker yields no ETag")]
    Empty,
    /// A character that may not stand in an ETag (RFC 9110 §8.8.3).
    #[error(
        "the version marker `{version}` carries `{character}`; an ETag allows only visible \
         characters without quotation marks (RFC 9110 §8.8.3)"
    )]
    Character {
        /// The version.
        version: String,
        /// The character.
        character: char,
    },
    /// `W/…` — a weak ETag is no proof of the same bytes (03 §6.0.9).
    #[error("`{0}` is a weak ETag; the contract demands strong ETags (03 §6.0.9)")]
    Weak(String),
    /// Without quotation marks it is no ETag.
    #[error("`{0}` is no ETag: the quotation marks are missing (RFC 9110 §8.8.3)")]
    Form(String),
}

/// The strong ETag for a version marker: `"<version>"`.
pub fn strong_etag(version: &str) -> Result<String, EtagError> {
    if version.is_empty() {
        return Err(EtagError::Empty);
    }
    if let Some(character) = version.chars().find(|&c| !(c == '!' || ('#'..='~').contains(&c))) {
        return Err(EtagError::Character { version: version.to_owned(), character });
    }
    Ok(format!("\"{version}\""))
}

/// The version marker from a strong ETag.
pub fn version_from_etag(etag: &str) -> Result<&str, EtagError> {
    let etag = etag.trim();
    if etag.starts_with("W/") {
        return Err(EtagError::Weak(etag.to_owned()));
    }
    let inner = etag
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| EtagError::Form(etag.to_owned()))?;
    if inner.is_empty() {
        return Err(EtagError::Empty);
    }
    Ok(inner)
}

// ── Digest headers (RFC 9530) ───────────────────────────────────────────────────────────────

/// The algorithm key for SHA-256 in `Repr-Digest` and `Content-Digest`.
pub const DIGEST_SHA256: &str = "sha-256";

/// Why a digest header yields no SHA-256 value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    /// No `sha-256` entry — the check must not then silently fall away.
    #[error(
        "the digest header `{0}` names no sha-256 value; without it nothing is adopted \
         (RFC 9530)"
    )]
    WithoutSha256(String),
    /// The value is not a byte sequence of the form `:<base64>:`.
    #[error("the sha-256 entry in `{header}` is unreadable: {reason} (RFC 9530, RFC 8941 §3.3.5)")]
    Form {
        /// The header.
        header: String,
        /// What is wrong.
        reason: String,
    },
    /// Two different `sha-256` values in one header.
    #[error("the digest header `{0}` names two different sha-256 values")]
    Ambiguous(String),
}

/// `sha-256=:<base64>:` — the value for `Repr-Digest` or `Content-Digest`.
pub fn digest_header_value(value: &Sha256Value) -> String {
    format!("{DIGEST_SHA256}=:{}:", STANDARD.encode(value.bytes()))
}

/// Reads the SHA-256 value from `Repr-Digest` or `Content-Digest`; other algorithms in the same
/// value are passed over, a missing SHA-256 entry is an error.
pub fn read_digest_header(header: &str) -> Result<Sha256Value, DigestError> {
    let form =
        |reason: &str| DigestError::Form { header: header.to_owned(), reason: reason.to_owned() };
    let mut found: Option<Sha256Value> = None;
    for entry in header.split(',') {
        let Some((key, value)) = entry.split_once('=') else { continue };
        if key.trim() != DIGEST_SHA256 {
            continue;
        }
        let value = value.split(';').next().unwrap_or_default().trim();
        let inner = value
            .strip_prefix(':')
            .and_then(|rest| rest.strip_suffix(':'))
            .ok_or_else(|| form("the value does not stand between colons"))?;
        let bytes = STANDARD.decode(inner).map_err(|_| form("not base64 with padding"))?;
        let bytes: [u8; SHA256_BYTES] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| form(&format!("{} bytes instead of {SHA256_BYTES}", b.len())))?;
        let value = Sha256Value::from_bytes(bytes);
        if found.is_some_and(|old| old != value) {
            return Err(DigestError::Ambiguous(header.to_owned()));
        }
        found = Some(value);
    }
    found.ok_or_else(|| DigestError::WithoutSha256(header.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HEX: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const TEST_HEADER: &str = "sha-256=:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=:";

    open_catalogue!(
        /// Only for the test.
        Sample {
            /// One.
            One => "one",
        }
    );

    #[test]
    fn an_open_catalogue_keeps_unknown_values_unchanged() {
        let x: Sample = serde_json::from_str("\"two\"").unwrap();
        assert_eq!(x, Sample::Unknown("two".into()));
        assert!(!x.is_known());
        assert_eq!(serde_json::to_string(&x).unwrap(), "\"two\"");
        assert_eq!(serde_json::from_str::<Sample>("\"one\"").unwrap(), Sample::One);
    }

    #[test]
    fn a_timestamp_keeps_its_text_and_compares_the_instant() {
        let local: WireTimestamp = serde_json::from_str("\"2026-09-02T09:38:11+02:00\"").unwrap();
        let utc: WireTimestamp = serde_json::from_str("\"2026-09-02T07:38:11Z\"").unwrap();
        assert_eq!(local.timestamp(), utc.timestamp());
        assert_eq!(serde_json::to_string(&local).unwrap(), "\"2026-09-02T09:38:11+02:00\"");
    }

    #[test]
    fn a_timestamp_without_a_zone_is_rejected() {
        assert!(serde_json::from_str::<WireTimestamp>("\"2026-09-02T07:38:11\"").is_err());
    }

    #[test]
    fn a_prefix_is_not_yet_an_origin() {
        const BASE: &str = "https://api.elasticdms.io";
        assert!(is_below("https://api.elasticdms.io/v1/ingest-uploads/x", BASE));
        assert!(is_below("https://api.elasticdms.io/v1/x", "https://api.elasticdms.io/"));
        // The case this is about: the same leading text, a different host.
        assert!(!is_below("https://api.elasticdms.io.example.org/v1/x", BASE));
        assert!(!is_below("https://api.elasticdms.iox/v1", BASE));
        // The base itself is no target below it, and an empty base covers nothing.
        assert!(!is_below(BASE, BASE));
        assert!(!is_below("https://api.elasticdms.io/v1", ""));
        assert!(!is_below("https://api.elasticdms.io/v1", "/"));
    }

    #[test]
    fn a_page_with_more_but_without_a_cursor_is_an_error() {
        let s: Page<u8> = Page { items: vec![], next_cursor: None, has_more: true };
        assert_eq!(s.continuation(), Err(PageError::MoreWithoutCursor));
        let s: Page<u8> = Page { items: vec![], next_cursor: Some(String::new()), has_more: true };
        assert_eq!(s.continuation(), Err(PageError::EmptyCursor));
    }

    #[test]
    fn a_cursor_on_the_last_page_is_not_guessed() {
        let s: Page<u8> = Page { items: vec![], next_cursor: Some("x".into()), has_more: false };
        assert_eq!(s.continuation(), Err(PageError::CursorWithoutMore));
        let s: Page<u8> = Page { items: vec![], next_cursor: None, has_more: false };
        assert_eq!(s.continuation(), Ok(None));
    }

    #[test]
    fn an_html_block_page_becomes_a_problem_without_meaning() {
        let p = Problem::read(502, b"<html><body>Bad Gateway</body></html>");
        assert_eq!(p.typ, TYP_ABOUT_BLANK);
        assert_eq!(p.status, Some(502));
        assert_eq!(p.error_kind(), ErrorKind::Unknown);
        assert!(p.detail.as_deref().is_some_and(|d| d.contains("Bad Gateway")));
    }

    #[test]
    fn a_long_foreign_body_is_shortened_and_an_empty_one_stays_empty() {
        let long = "x".repeat(MAX_FOREIGN_DETAIL_CHARACTER * 3);
        let p = Problem::read(500, long.as_bytes());
        assert_eq!(p.detail.map(|d| d.chars().count()), Some(MAX_FOREIGN_DETAIL_CHARACTER));
        assert_eq!(Problem::read(503, b"   ").detail, None);
    }

    #[test]
    fn an_extension_field_of_the_wrong_shape_does_not_cost_the_type() {
        let body = br#"{"type":"https://errors.elasticdms.io/device-revoked","status":403,
            "detail":"locked","remedy":"Call us","errors":"broken","contact":"4711"}"#;
        let p = Problem::read(403, body);
        assert_eq!(p.error_kind(), ErrorKind::DeviceLocked);
        assert_eq!(p.detail.as_deref(), Some("locked"));
        assert_eq!(p.extension("contact"), Some(&Value::from("4711")));
    }

    #[test]
    fn a_problem_without_a_type_is_about_blank_and_gets_the_http_status() {
        let p = Problem::read(418, br#"{"title":"Teapot"}"#);
        assert_eq!(p.typ, TYP_ABOUT_BLANK);
        assert_eq!(p.status, Some(418));
    }

    #[test]
    fn an_unknown_or_foreign_type_is_unknown_and_no_crash() {
        assert_eq!(
            ErrorKind::from_typ_uri("https://errors.elasticdms.io/new-2027"),
            ErrorKind::Unknown
        );
        assert_eq!(
            ErrorKind::from_typ_uri("https://example.org/device-revoked"),
            ErrorKind::Unknown
        );
        assert_eq!(
            ErrorKind::from_typ_uri("https://errors.elasticdms.io/device-revoked?lang=de#x"),
            ErrorKind::DeviceLocked
        );
    }

    #[test]
    fn the_catalogue_knows_the_security_even_when_the_server_does_not_report_it() {
        let mut p = Problem::from_catalogue(ErrorKind::TokenDeviceBinding, 403, "foreign device");
        p.security_event = Some(false);
        assert!(p.is_security_event());
    }

    #[test]
    fn every_short_code_stands_exactly_once_in_the_catalogue_and_comes_back() {
        let mut seen = std::collections::HashSet::new();
        for kind in ErrorKind::all() {
            let short = kind.short_code().unwrap();
            assert!(seen.insert(short), "{short} twice");
            assert_eq!(ErrorKind::from_typ_uri(&kind.typ_uri().unwrap()), kind);
        }
        assert_eq!(ErrorKind::Unknown.short_code(), None);
    }

    #[test]
    fn a_digest_header_survives_the_round_trip() {
        let value = Sha256Value::from_hex(TEST_HEX).unwrap();
        assert_eq!(digest_header_value(&value), TEST_HEADER);
        assert_eq!(read_digest_header(TEST_HEADER).unwrap(), value);
        let mixed = format!("sha-512=:AAAA:, {TEST_HEADER}");
        assert_eq!(read_digest_header(&mixed).unwrap(), value);
    }

    #[test]
    fn a_digest_without_sha256_is_an_error_and_not_a_skipped_check() {
        assert!(matches!(read_digest_header("sha-512=:AAAA:"), Err(DigestError::WithoutSha256(_))));
        assert!(matches!(read_digest_header("sha-256=:AAAA:"), Err(DigestError::Form { .. })));
        assert!(matches!(read_digest_header("sha-256=n4bQ"), Err(DigestError::Form { .. })));
        assert!(matches!(read_digest_header("sha-256=:!!:"), Err(DigestError::Form { .. })));
        let two = format!("{TEST_HEADER}, sha-256=:{}:", STANDARD.encode([0u8; 32]));
        assert!(matches!(read_digest_header(&two), Err(DigestError::Ambiguous(_))));
    }

    #[test]
    fn a_weak_etag_is_no_proof_of_the_same_bytes() {
        assert_eq!(strong_etag("3.2").unwrap(), "\"3.2\"");
        assert_eq!(version_from_etag("\"3.2\"").unwrap(), "3.2");
        assert!(matches!(version_from_etag("W/\"3.2\""), Err(EtagError::Weak(_))));
        assert!(matches!(version_from_etag("3.2"), Err(EtagError::Form(_))));
        assert!(matches!(strong_etag("3\"2"), Err(EtagError::Character { character: '"', .. })));
        assert!(matches!(strong_etag(""), Err(EtagError::Empty)));
    }
}
