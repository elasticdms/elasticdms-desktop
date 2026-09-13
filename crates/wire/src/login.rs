//! Sign-in: device flow (RFC 8628), token requests, revocation, OAuth errors
//! (03 §6.2.2, §6.3.1, §6.3.3, §6.3.4; proposal §7.0).
//!
//! **The only way in is the device flow in the system browser** (AND-4): no PAR, no
//! `authorization_endpoint`, no WebView — in a WebView the corporate credentials would flow
//! through our process. The forms here therefore know neither `code_challenge` nor
//! `redirect_uri`.
//!
//! Two keys, deliberately (03 §6.3.1, geraete-auth §3.4): the **device** key signs the client
//! assertion, and the **session** key signs the DPoP proof when the tokens are collected, its
//! thumbprint having been bound beforehand as `dpop_jkt`. `edms-crypto` computes both; only the
//! form fields stand here.
//!
//! Requests to `/v1/oauth/*` are `application/x-www-form-urlencoded`; that is why the request
//! types carry [`TokenRequest::to_form`] and `from_form` instead of JSON. Errors come per
//! RFC 6749 §5.2 ([`OauthError`]), never as problem+json.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::basics::{ErrorKind, is_below, open_catalogue};

/// Token endpoint (all three grants).
pub const PATH_TOKEN: &str = "/v1/oauth/token";
/// RFC 8628.
pub const PATH_DEVICE_AUTHORIZATION: &str = "/v1/oauth/device_authorization";
/// RFC 7009.
pub const PATH_REVOCATION: &str = "/v1/oauth/revoke";

/// Device token (03 §6.2.2).
pub const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";
/// Collect the user token (RFC 8628 §3.4).
pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Renew the user token, with rotation (03 §6.3.3).
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
/// RFC 7523 §2.2 — `private_key_jwt`.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Only the refresh token is revoked (03 §6.3.4).
pub const TOKEN_TYPE_HINT_REFRESH: &str = "refresh_token";

/// The authentication class the folder client asks for — `[GAP → PROPOSAL]` §7.0.
pub const ACR_DESKTOP: &str = "urn:elasticdms:acr:desktop";

/// The scopes of a workstation's device token (proposal §7.0).
pub const DEVICE_SCOPES: [&str; 3] = ["device:self", "desktop:login", "delivery:receive"];

/// The scopes of a workstation's user session (proposal §7.0). `folders:read` and
/// `documents:read` are already in 03 §6.16; `ingest:submit` is new.
pub const USER_SCOPES: [&str; 5] =
    ["openid", "profile", "folders:read", "documents:read", "ingest:submit"];

/// RFC 8628 §3.2: if `interval` is missing, the client **has to** use 5 s.
pub const DEFAULT_INTERVAL_SECOND: u64 = 5;

/// RFC 8628 §3.5: every `slow_down` raises the interval permanently by 5 s.
pub const SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

/// Scopes as space-separated text.
pub fn scope_text(scopes: &[&str]) -> String {
    scopes.join(" ")
}

fn hidden(secret: &str) -> String {
    format!("<hidden, {} characters>", secret.chars().count())
}

// ── Forms ───────────────────────────────────────────────────────────────────────────────────

/// Why a form is not a request of the contract (mock and tests).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormError {
    /// A mandatory field is missing.
    #[error("the field `{0}` is missing from the form (RFC 6749)")]
    FieldMissing(&'static str),
    /// A field appears twice — RFC 6749 §3.2 forbids that.
    #[error("the field `{0}` stands more than once in the form (RFC 6749 §3.2)")]
    Duplicate(String),
    /// A grant the contract does not know.
    #[error("the grant `{0}` does not belong to the folder client's contract")]
    UnknownGrant(String),
    /// A client authentication other than `private_key_jwt`.
    #[error("client_assertion_type `{0}` is not private_key_jwt (RFC 7523)")]
    WrongAssertionType(String),
}

struct Form<'a>(&'a [(String, String)]);

impl Form<'_> {
    fn field(&self, name: &'static str) -> Result<Option<String>, FormError> {
        let mut hits = self.0.iter().filter(|(k, _)| k == name);
        let first = hits.next().map(|(_, v)| v.clone());
        if hits.next().is_some() {
            return Err(FormError::Duplicate(name.to_owned()));
        }
        Ok(first)
    }

    fn required(&self, name: &'static str) -> Result<String, FormError> {
        self.field(name)?.ok_or(FormError::FieldMissing(name))
    }

    fn assertion(&self) -> Result<String, FormError> {
        let typ = self.required("client_assertion_type")?;
        if typ != CLIENT_ASSERTION_TYPE {
            return Err(FormError::WrongAssertionType(typ));
        }
        self.required("client_assertion")
    }
}

/// `POST /v1/oauth/device_authorization` (03 §6.3.1, for the workstation proposal §7.0).
///
/// **No DPoP header** on this request: RFC 9449 §5 binds the future token through `dpop_jkt`, the
/// proof comes only when the token is collected.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationRequest {
    /// Signed with the device key.
    pub client_assertion: String,
    /// [`USER_SCOPES`].
    pub scope: String,
    /// The API, `https://api.elasticdms.io`.
    pub resource: String,
    /// [`ACR_DESKTOP`], on a step-up the value from the challenge.
    pub acr_values: Option<String>,
    /// RFC 7638 thumbprint of the **session** key.
    pub dpop_jkt: String,
    /// Empty the first time; on a step-up the user of the running session.
    pub login_hint: Option<String>,
    /// On a step-up: maximum age of the sign-in (RFC 9470).
    pub max_age: Option<u64>,
    /// On a step-up `login` (BET-11).
    pub prompt: Option<String>,
}

impl DeviceAuthorizationRequest {
    /// The form fields in contract order; empty optional fields are left out.
    pub fn to_form(&self) -> Vec<(&'static str, String)> {
        let mut form = vec![
            ("client_assertion_type", CLIENT_ASSERTION_TYPE.to_owned()),
            ("client_assertion", self.client_assertion.clone()),
            ("scope", self.scope.clone()),
            ("resource", self.resource.clone()),
        ];
        if let Some(acr) = &self.acr_values {
            form.push(("acr_values", acr.clone()));
        }
        form.push(("dpop_jkt", self.dpop_jkt.clone()));
        if let Some(hint) = &self.login_hint {
            form.push(("login_hint", hint.clone()));
        }
        if let Some(max_age) = self.max_age {
            form.push(("max_age", max_age.to_string()));
        }
        if let Some(prompt) = &self.prompt {
            form.push(("prompt", prompt.clone()));
        }
        form
    }

    /// Reads the form (mock).
    pub fn from_form(field: &[(String, String)]) -> Result<Self, FormError> {
        let f = Form(field);
        Ok(Self {
            client_assertion: f.assertion()?,
            scope: f.required("scope")?,
            resource: f.required("resource")?,
            acr_values: f.field("acr_values")?,
            dpop_jkt: f.required("dpop_jkt")?,
            login_hint: f.field("login_hint")?,
            max_age: f.field("max_age")?.and_then(|t| t.parse().ok()),
            prompt: f.field("prompt")?,
        })
    }
}

impl fmt::Debug for DeviceAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorizationRequest")
            .field("client_assertion", &hidden(&self.client_assertion))
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("acr_values", &self.acr_values)
            .field("dpop_jkt", &self.dpop_jkt)
            .field("login_hint", &self.login_hint)
            .field("max_age", &self.max_age)
            .field("prompt", &self.prompt)
            .finish()
    }
}

/// `POST /v1/oauth/token`, one of the contract's three grants.
#[derive(Clone, PartialEq, Eq)]
pub enum TokenRequest {
    /// Device token (03 §6.2.2): no refresh, the device re-asserts with its key.
    ClientCredentials {
        /// Signed with the device key.
        client_assertion: String,
        /// [`DEVICE_SCOPES`].
        scope: String,
        /// The API.
        resource: String,
    },
    /// Collecting after the confirmation in the browser (03 §6.3.1).
    DeviceCode {
        /// From the device authorization.
        device_code: String,
        /// Signed with the device key.
        client_assertion: String,
    },
    /// Renewal with rotation (03 §6.3.3). **Never retry blindly**: reusing a rotated token
    /// revokes the whole family across devices.
    RefreshToken {
        /// The refresh token received last.
        refresh_token: String,
        /// Signed with the device key.
        client_assertion: String,
    },
}

impl TokenRequest {
    /// The grant.
    pub fn grant(&self) -> &'static str {
        match self {
            Self::ClientCredentials { .. } => GRANT_CLIENT_CREDENTIALS,
            Self::DeviceCode { .. } => GRANT_DEVICE_CODE,
            Self::RefreshToken { .. } => GRANT_REFRESH_TOKEN,
        }
    }

    /// The form fields.
    pub fn to_form(&self) -> Vec<(&'static str, String)> {
        let mut form = vec![("grant_type", self.grant().to_owned())];
        let assertion = match self {
            Self::ClientCredentials { client_assertion, .. }
            | Self::DeviceCode { client_assertion, .. }
            | Self::RefreshToken { client_assertion, .. } => client_assertion,
        };
        match self {
            Self::ClientCredentials { .. } => {}
            Self::DeviceCode { device_code, .. } => form.push(("device_code", device_code.clone())),
            Self::RefreshToken { refresh_token, .. } => {
                form.push(("refresh_token", refresh_token.clone()))
            }
        }
        form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE.to_owned()));
        form.push(("client_assertion", assertion.clone()));
        if let Self::ClientCredentials { scope, resource, .. } = self {
            form.push(("scope", scope.clone()));
            form.push(("resource", resource.clone()));
        }
        form
    }

    /// Reads the form (mock).
    pub fn from_form(field: &[(String, String)]) -> Result<Self, FormError> {
        let f = Form(field);
        let grant = f.required("grant_type")?;
        let client_assertion = f.assertion()?;
        match grant.as_str() {
            GRANT_CLIENT_CREDENTIALS => Ok(Self::ClientCredentials {
                client_assertion,
                scope: f.required("scope")?,
                resource: f.required("resource")?,
            }),
            GRANT_DEVICE_CODE => {
                Ok(Self::DeviceCode { device_code: f.required("device_code")?, client_assertion })
            }
            GRANT_REFRESH_TOKEN => Ok(Self::RefreshToken {
                refresh_token: f.required("refresh_token")?,
                client_assertion,
            }),
            _ => Err(FormError::UnknownGrant(grant)),
        }
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest").field("grant_type", &self.grant()).finish_non_exhaustive()
    }
}

/// `POST /v1/oauth/revoke` (RFC 7009) — always `200`, even for an unknown token.
#[derive(Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// The refresh token.
    pub token: String,
    /// Signed with the device key.
    pub client_assertion: String,
}

impl RevocationRequest {
    /// The form fields.
    pub fn to_form(&self) -> Vec<(&'static str, String)> {
        vec![
            ("token", self.token.clone()),
            ("token_type_hint", TOKEN_TYPE_HINT_REFRESH.to_owned()),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE.to_owned()),
            ("client_assertion", self.client_assertion.clone()),
        ]
    }

    /// Reads the form (mock).
    pub fn from_form(field: &[(String, String)]) -> Result<Self, FormError> {
        let f = Form(field);
        Ok(Self { token: f.required("token")?, client_assertion: f.assertion()? })
    }
}

impl fmt::Debug for RevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token", &hidden(&self.token))
            .finish_non_exhaustive()
    }
}

// ── Answers ─────────────────────────────────────────────────────────────────────────────────

/// The answer to `POST /v1/oauth/device_authorization` (RFC 8628 §3.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    /// 256 bits; secret until it is collected.
    pub device_code: String,
    /// `WQPX-7TRM` — shown in the app's window and in the browser.
    pub user_code: String,
    /// The confirmation page.
    pub verification_uri: String,
    /// The same page with code and anchor; this is what the client opens in the system browser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Validity in seconds.
    pub expires_in: u64,
    /// Minimum interval between polls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// The four-character anchor `K7-M4` — the app shows it, the confirmation page repeats it.
    #[serde(rename = "urn:elasticdms:anchor", default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// The device label on the confirmation page.
    #[serde(
        rename = "urn:elasticdms:device_label",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub device_designation: Option<String>,
}

/// Why the client does not open a confirmation page.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the confirmation page `{address}` does not lie below `{base}`; the client opens no foreign \
     host in the user's browser"
)]
pub struct ForeignBrowserTarget {
    /// The address that was delivered.
    pub address: String,
    /// The configured web interface.
    pub base: String,
}

impl DeviceAuthorization {
    /// The interval between polls; if `interval` is missing, RFC 8628 §3.2 prescribes five
    /// seconds.
    pub fn interval_second(&self) -> u64 {
        self.interval.unwrap_or(DEFAULT_INTERVAL_SECOND)
    }

    /// The page that is opened in the system browser — only when it lies below the web
    /// interface. An answer that sends the user to a foreign host would be the template for a
    /// phishing page that decorates itself with a real code and anchor.
    pub fn browser_target(&self, app_base: &str) -> Result<&str, ForeignBrowserTarget> {
        let target = self.verification_uri_complete.as_deref().unwrap_or(&self.verification_uri);
        if is_below(target, app_base) {
            Ok(target)
        } else {
            Err(ForeignBrowserTarget { address: target.to_owned(), base: app_base.to_owned() })
        }
    }
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &hidden(&self.device_code))
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}

/// The only permissible `token_type`: `DPoP`.
///
/// A `Bearer` token would be usable without this device's key — the binding that 03 §6.0.6 rests
/// on would be gone. That is why reading already fails, and not only a check that one can forget.
/// Upper and lower case are equivalent per RFC 6749 §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DpopTokenKind;

impl Serialize for DpopTokenKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("DPoP")
    }
}

impl<'de> Deserialize<'de> for DpopTokenKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.eq_ignore_ascii_case("dpop") {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "token_type `{text}` is not a DPoP-bound token; an unbound token would be \
                 usable without this device's key (RFC 9449 §5, 03 §6.0.6)"
            )))
        }
    }
}

/// The answer of the token endpoint (03 §6.2.2, §6.3.1, §6.3.3).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token; it belongs in the keychain, never in a log.
    pub access_token: String,
    /// Always `DPoP`.
    pub token_type: DpopTokenKind,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Only for the user token; every renewal delivers a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Remaining lifetime of the refresh token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_in: Option<u64>,
    /// The scopes that were granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// OIDC ID token; identity comes from the access token, not from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl TokenResponse {
    /// Whether a granted scope is among them.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.as_deref().is_some_and(|s| s.split(' ').any(|x| x == scope))
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &hidden(&self.access_token))
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &self.refresh_token.as_deref().map(hidden))
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

open_catalogue!(
    /// `error` per RFC 6749 §5.2, RFC 8628 §3.5 and RFC 9449 §8.
    OauthErrorCode {
        /// `invalid_request`.
        InvalidRequest => "invalid_request",
        /// `invalid_client` — for the device always with `device-assertion-invalid` and the same
        /// description; the client does not try to tell them apart (geraete-auth §3.2).
        InvalidClient => "invalid_client",
        /// `invalid_grant`.
        InvalidGrant => "invalid_grant",
        /// `unauthorized_client`.
        UnauthorizedClient => "unauthorized_client",
        /// `unsupported_grant_type`.
        UnsupportedGrantType => "unsupported_grant_type",
        /// `invalid_scope`.
        InvalidScope => "invalid_scope",
        /// `authorization_pending` — the normal case, not an error.
        AuthorizationPending => "authorization_pending",
        /// `slow_down` — raise the interval permanently by 5 s.
        Slower => "slow_down",
        /// `expired_token` — a new code is needed.
        CodeExpired => "expired_token",
        /// `access_denied` — refused is not expired.
        Rejected => "access_denied",
        /// `use_dpop_nonce` — exactly one retry (T9).
        NonceNeeded => "use_dpop_nonce",
        /// `invalid_dpop_proof`.
        InvalidDpopProof => "invalid_dpop_proof",
    }
);

/// An error in OAuth format (RFC 6749 §5.2). The bridge into the catalogue is `error_uri`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OauthError {
    /// The code.
    pub error: OauthErrorCode,
    /// Clear text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// `https://errors.elasticdms.io/…`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

/// What an error while polling in the device flow means — three screens, not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFlowStep {
    /// Keep polling.
    Pending,
    /// Raise the interval by [`SLOW_DOWN_INCREMENT_SECONDS`], permanently.
    Slower,
    /// The code has expired; begin again.
    Expired,
    /// The human refused or is not allowed; that is no expiry.
    Rejected,
    /// Retry once with the new nonce.
    NonceNeeded,
    /// Another error; the flow ends.
    Final,
}

/// What an error during renewal means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshStep {
    /// Retry once with the new nonce.
    NonceNeeded,
    /// The session has ended; sign in again, the tree stays visible (finding Q-4).
    NewSignIn,
    /// A rotated token was reused: the family is revoked across devices, and that is a security
    /// event (03 §6.3.3).
    FamilyRevoked,
    /// Another error (device locked, assertion invalid).
    Final,
}

impl OauthError {
    /// The catalogue entry behind `error_uri`.
    pub fn error_kind(&self) -> ErrorKind {
        self.error_uri.as_deref().map_or(ErrorKind::Unknown, ErrorKind::from_typ_uri)
    }

    /// The meaning while polling in the device flow.
    pub fn in_device_flow(&self) -> DeviceFlowStep {
        match self.error {
            OauthErrorCode::AuthorizationPending => DeviceFlowStep::Pending,
            OauthErrorCode::Slower => DeviceFlowStep::Slower,
            OauthErrorCode::CodeExpired => DeviceFlowStep::Expired,
            OauthErrorCode::InvalidGrant if self.error_kind() == ErrorKind::DeviceCodeExpired => {
                DeviceFlowStep::Expired
            }
            OauthErrorCode::Rejected => DeviceFlowStep::Rejected,
            OauthErrorCode::NonceNeeded => DeviceFlowStep::NonceNeeded,
            _ => DeviceFlowStep::Final,
        }
    }

    /// The meaning during renewal.
    pub fn at_refresh(&self) -> RefreshStep {
        match (&self.error, self.error_kind()) {
            (OauthErrorCode::NonceNeeded, _) => RefreshStep::NonceNeeded,
            (OauthErrorCode::InvalidGrant, ErrorKind::RefreshTokenReused) => {
                RefreshStep::FamilyRevoked
            }
            (OauthErrorCode::InvalidGrant, _) => RefreshStep::NewSignIn,
            _ => RefreshStep::Final,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(form: Vec<(&'static str, String)>) -> Vec<(String, String)> {
        form.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }

    #[test]
    fn every_token_request_survives_the_round_trip_through_the_form() {
        let requests = [
            TokenRequest::ClientCredentials {
                client_assertion: "a".into(),
                scope: scope_text(&DEVICE_SCOPES),
                resource: "https://api.elasticdms.io".into(),
            },
            TokenRequest::DeviceCode { device_code: "d".into(), client_assertion: "a".into() },
            TokenRequest::RefreshToken { refresh_token: "rt".into(), client_assertion: "a".into() },
        ];
        for request in requests {
            assert_eq!(TokenRequest::from_form(&pairs(request.to_form())).unwrap(), request);
        }
    }

    #[test]
    fn collecting_carries_neither_scope_nor_resource() {
        let form =
            TokenRequest::DeviceCode { device_code: "d".into(), client_assertion: "a".into() }
                .to_form();
        assert!(form.iter().all(|(k, _)| *k != "scope" && *k != "resource"));
        assert!(form.contains(&("client_assertion_type", CLIENT_ASSERTION_TYPE.to_owned())));
    }

    #[test]
    fn a_form_with_a_foreign_authentication_or_a_duplicate_field_is_rejected() {
        let mut form = pairs(
            TokenRequest::DeviceCode { device_code: "d".into(), client_assertion: "a".into() }
                .to_form(),
        );
        form.push(("device_code".into(), "second".into()));
        assert_eq!(TokenRequest::from_form(&form), Err(FormError::Duplicate("device_code".into())));
        let foreign = vec![
            ("grant_type".to_owned(), GRANT_REFRESH_TOKEN.to_owned()),
            ("refresh_token".to_owned(), "rt".to_owned()),
            ("client_assertion_type".to_owned(), "client_secret_basic".to_owned()),
            ("client_assertion".to_owned(), "a".to_owned()),
        ];
        assert!(matches!(TokenRequest::from_form(&foreign), Err(FormError::WrongAssertionType(_))));
        let password_grant = vec![("grant_type".to_owned(), "password".to_owned())];
        assert_eq!(
            TokenRequest::from_form(&password_grant),
            Err(FormError::FieldMissing("client_assertion_type"))
        );
    }

    #[test]
    fn the_device_authorization_knows_no_code_flow() {
        let request = DeviceAuthorizationRequest {
            client_assertion: "a".into(),
            scope: scope_text(&USER_SCOPES),
            resource: "https://api.elasticdms.io".into(),
            acr_values: Some(ACR_DESKTOP.into()),
            dpop_jkt: "jkt".into(),
            login_hint: None,
            max_age: None,
            prompt: None,
        };
        let form = request.to_form();
        for forbidden in ["code_challenge", "redirect_uri", "login_hint", "response_type"] {
            assert!(form.iter().all(|(k, _)| *k != forbidden), "{forbidden}");
        }
        assert_eq!(DeviceAuthorizationRequest::from_form(&pairs(form)).unwrap(), request);
    }

    #[test]
    fn a_bearer_token_is_rejected_already_while_reading() {
        let bearer = r#"{"access_token":"x","token_type":"Bearer","expires_in":300}"#;
        let error = serde_json::from_str::<TokenResponse>(bearer).unwrap_err();
        // The message is the reader's only clue: serde names neither the field nor the value.
        assert!(error.to_string().contains("not a DPoP-bound token"), "{error}");
        let lower: TokenResponse =
            serde_json::from_str(r#"{"access_token":"x","token_type":"dpop","expires_in":300}"#)
                .unwrap();
        assert!(serde_json::to_string(&lower).unwrap().contains("\"DPoP\""));
    }

    #[test]
    fn a_token_appears_in_no_debug_output() {
        let t: TokenResponse = serde_json::from_str(
            r#"{"access_token":"SECRET-AT","token_type":"DPoP","expires_in":300,"refresh_token":"SECRET-RT"}"#,
        )
        .unwrap();
        let text = format!("{t:?}");
        assert!(!text.contains("SECRET"), "{text}");
    }

    #[test]
    fn the_intermediate_states_of_the_device_flow_are_different_steps() {
        let read = |json: &str| serde_json::from_str::<OauthError>(json).unwrap().in_device_flow();
        assert_eq!(read(r#"{"error":"authorization_pending"}"#), DeviceFlowStep::Pending);
        assert_eq!(read(r#"{"error":"slow_down"}"#), DeviceFlowStep::Slower);
        assert_eq!(read(r#"{"error":"expired_token"}"#), DeviceFlowStep::Expired);
        assert_eq!(
            read(
                r#"{"error":"invalid_grant","error_uri":"https://errors.elasticdms.io/device-code-expired"}"#
            ),
            DeviceFlowStep::Expired
        );
        assert_eq!(read(r#"{"error":"access_denied"}"#), DeviceFlowStep::Rejected);
        assert_eq!(read(r#"{"error":"use_dpop_nonce"}"#), DeviceFlowStep::NonceNeeded);
        assert_eq!(read(r#"{"error":"server_on_fire"}"#), DeviceFlowStep::Final);
    }

    #[test]
    fn a_reuse_is_something_other_than_the_end_of_a_session() {
        let read = |json: &str| serde_json::from_str::<OauthError>(json).unwrap().at_refresh();
        assert_eq!(
            read(
                r#"{"error":"invalid_grant","error_uri":"https://errors.elasticdms.io/refresh-token-reuse"}"#
            ),
            RefreshStep::FamilyRevoked
        );
        assert_eq!(
            read(
                r#"{"error":"invalid_grant","error_uri":"https://errors.elasticdms.io/session-expired"}"#
            ),
            RefreshStep::NewSignIn
        );
        assert_eq!(read(r#"{"error":"invalid_client"}"#), RefreshStep::Final);
    }

    #[test]
    fn without_interval_five_seconds_apply_and_foreign_browser_targets_are_not_opened() {
        let mut a: DeviceAuthorization = serde_json::from_str(
            r#"{"device_code":"d","user_code":"WQPX-7TRM","verification_uri":"https://app.elasticdms.io/device","expires_in":300}"#,
        )
        .unwrap();
        assert_eq!(a.interval_second(), 5);
        assert_eq!(
            a.browser_target("https://app.elasticdms.io"),
            Ok("https://app.elasticdms.io/device")
        );
        a.verification_uri_complete =
            Some("https://app.elasticdms.io.example.org/device?user_code=WQPX-7TRM".into());
        assert!(a.browser_target("https://app.elasticdms.io").is_err());
    }
}
