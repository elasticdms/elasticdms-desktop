//! Shared parts of the contract tests: a tiny HTTP client and the two ways in.
//!
//! **Why a client of our own.** By house rule R1 `reqwest` belongs in `edms-net` alone
//! (crates/architecture-rules). A test that called the mock through an in-process tower service
//! would also bypass exactly the layer that matters here: the status line, the headers, a real
//! socket. This client speaks HTTP/1.1 with `Connection: close` and reads to end of file — short
//! enough to understand, real enough to prove something.

// A test tool, not production code:
// - `expect`: a failed `expect` here **is** the test message; a result every caller would first
//   have to unwrap would only move the message to a less convenient place.
// - many parameters: they are the parts of an HTTP request (method, path, token, key, headers,
//   body, nonce). A construction around them would make the tests longer, not clearer — and the
//   tests are what gets read here.
#![allow(dead_code, clippy::expect_used, clippy::too_many_arguments)]

use std::collections::HashMap;
use std::sync::Mutex;

use edms_core::identifier::DeviceIdentifier;
use edms_crypto::assertion;
use edms_crypto::dpop::{self, DpopProofRequest};
use edms_crypto::key::{SigningKey, SoftwareKey};
use edms_mock::time::now;
use edms_mock::{Configuration, Mock, Origin};
use edms_wire::basics::{API_VERSION, header, media_type};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The device identifier every test enrols with (out of `device_desktop.json`).
pub const DEVICE: &str = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB";

/// An HTTP answer that has been read.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub header: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// The first value of a header, case-insensitively.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.header.iter().find(|(n, _)| *n == wanted).map(|(_, value)| value.as_str())
    }

    /// The body as JSON; `Value::Null` when it is not JSON.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A running mock together with its keys and the nonces it remembered.
pub struct Harness {
    pub mock: Mock,
    pub api: String,
    pub auth: String,
    pub device: DeviceIdentifier,
    pub device_key: SoftwareKey,
    pub session_key: SoftwareKey,
    pub kid: String,
    nonces: Mutex<HashMap<Origin, String>>,
}

/// Starts a mock with the default configuration.
pub async fn start() -> Harness {
    start_with(Configuration::default()).await
}

/// Starts a mock with a configuration of its own.
pub async fn start_with(configuration: Configuration) -> Harness {
    let mock = Mock::start(configuration).await.expect("the mock starts");
    let api = mock.api_base().to_owned();
    let auth = mock.auth_base().to_owned();
    Harness {
        mock,
        api,
        auth,
        device: DEVICE.parse().expect("a device identifier"),
        device_key: SoftwareKey::generate().expect("a key"),
        session_key: SoftwareKey::generate().expect("a key"),
        kid: format!("{DEVICE}#1"),
        nonces: Mutex::new(HashMap::new()),
    }
}

impl Harness {
    /// The base address of an origin.
    pub fn base(&self, origin: Origin) -> &str {
        match origin {
            Origin::Api => &self.api,
            Origin::Login => &self.auth,
        }
    }

    /// The remembered nonce of an origin.
    pub fn nonce(&self, origin: Origin) -> Option<String> {
        self.nonces.lock().expect("the lock").get(&origin).cloned()
    }

    /// Remembers the nonce out of an answer — the way the client does.
    fn remember(&self, origin: Origin, response: &Response) {
        if let Some(nonce) = response.header_value(header::DPOP_NONCE) {
            self.nonces.lock().expect("the lock").insert(origin, nonce.to_owned());
        }
    }

    /// A request without DPoP — enrolment, discovery, the browser pages.
    pub async fn raw(
        &self,
        origin: Origin,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Response {
        let response = send(self.base(origin), method, path, headers, body).await;
        self.remember(origin, &response);
        response
    }

    /// A request with a DPoP proof and **exactly one** retry after `use_dpop_nonce` (§7.0.9,
    /// contract test T9).
    pub async fn with_dpop(
        &self,
        origin: Origin,
        method: &str,
        path: &str,
        token: Option<&str>,
        key: &dyn SigningKey,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Response {
        let first = self
            .once(origin, method, path, token, key, headers, body.clone(), self.nonce(origin))
            .await;
        if !requires_nonce(&first) {
            return first;
        }
        self.once(origin, method, path, token, key, headers, body, self.nonce(origin)).await
    }

    /// A single attempt with a given nonce.
    pub async fn once(
        &self,
        origin: Origin,
        method: &str,
        path: &str,
        token: Option<&str>,
        key: &dyn SigningKey,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
        nonce: Option<String>,
    ) -> Response {
        let url = format!("{}{}", self.base(origin), path.split('?').next().unwrap_or(path));
        let proof = dpop::proof(
            key,
            &DpopProofRequest { method, url: &url, nonce: nonce.as_deref(), access_token: token },
            now(),
        )
        .expect("a proof");
        let mut all: Vec<(&str, String)> = vec![(header::DPOP, proof)];
        if let Some(token) = token {
            all.push((header::AUTHORIZATION, format!("DPoP {token}")));
        }
        all.extend(headers.iter().map(|(name, value)| (*name, value.clone())));
        let response = send(self.base(origin), method, path, &all, body).await;
        self.remember(origin, &response);
        response
    }

    /// The body of an enrolment request carrying this harness's key.
    pub fn enrollment_body(&self) -> Vec<u8> {
        let jwk = self.device_key.public();
        let body = json!({
            "enrollmentCode": "K7QM-4T2X",
            "deviceKind": "desktop",
            "publicJwk": {
                "kty": "EC", "crv": "P-256",
                "x": jwk.jwk().x(), "y": jwk.jwk().y(),
                "alg": "ES256", "use": "sig", "kid": self.kid,
            },
            "attestation": { "type": "none", "available": false },
            "platform": { "os": "Windows", "osVersion": "10.0.26100", "arch": "x86_64" },
            "app": {
                "packageName": "de.elasticdms.ordnerclient",
                "versionName": "1.0.0",
                "buildHash": "sha256:924fb28aff51ee6e70cf048ac486fcbf9c3fd7a609fbc537f07173fdd5cda441",
                "signatureSha256": "sha256:cd00868ed978944d17c592fd5d711cdb6263f60baa40c7bf6fa4a33ec9996864",
            },
            "requestedName": "Arbeitsplatz Buchhaltung EG",
        });
        serde_json::to_vec(&body).expect("JSON")
    }

    /// `PUT /v1/devices/{deviceId}` — without `Authorization`, without DPoP, with
    /// `If-None-Match: *`.
    pub async fn enroll(&self) -> Response {
        self.raw(
            Origin::Api,
            "PUT",
            &format!("/v1/devices/{}", self.device),
            &[
                (header::IF_NONE_MATCH, "*".to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(self.enrollment_body()),
        )
        .await
    }

    /// A client assertion with the device key.
    pub fn assertion(&self) -> String {
        assertion::client_assertion(&self.device_key, &self.kid, self.device, &self.auth, now())
            .expect("an assertion")
    }

    /// The device token (`client_credentials`, 03 §6.2.2).
    pub async fn device_token(&self) -> String {
        let form = form(&[
            ("grant_type", "client_credentials"),
            ("scope", "device:self desktop:login delivery:receive"),
            ("resource", &self.api),
            ("client_assertion_type", assertion::ASSERTION_TYP),
            ("client_assertion", &self.assertion()),
        ]);
        let response = self
            .with_dpop(
                Origin::Login,
                "POST",
                edms_wire::login::PATH_TOKEN,
                None,
                &self.device_key,
                &[
                    (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                    (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                ],
                Some(form.into_bytes()),
            )
            .await;
        assert_eq!(response.status, 200, "device token: {}", response.text());
        response.json()["access_token"].as_str().expect("access_token").to_owned()
    }

    /// The device flow through to the user token; returns `(access_token, refresh_token)`.
    pub async fn user_token(&self) -> (String, String) {
        let (_, access, refresh) = self.device_flow().await;
        (access, refresh)
    }

    /// The device flow together with the `user_code`.
    pub async fn device_flow(&self) -> (String, String, String) {
        let jkt = self.session_key.public().thumbprint();
        let form = form(&[
            ("client_assertion_type", assertion::ASSERTION_TYP),
            ("client_assertion", &self.assertion()),
            ("scope", "openid profile folders:read documents:read ingest:submit"),
            ("resource", &self.api),
            ("acr_values", edms_wire::login::ACR_DESKTOP),
            ("dpop_jkt", &jkt),
        ]);
        let response = self
            .raw(
                Origin::Login,
                "POST",
                edms_wire::login::PATH_DEVICE_AUTHORIZATION,
                &[
                    (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                    (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                ],
                Some(form.into_bytes()),
            )
            .await;
        assert_eq!(response.status, 200, "device authorization: {}", response.text());
        let value = response.json();
        let device_code = value["device_code"].as_str().expect("device_code").to_owned();
        let user_code = value["user_code"].as_str().expect("user_code").to_owned();
        let (access, refresh) = self.fetch_token(&device_code).await;
        (user_code, access, refresh)
    }

    /// Fetches the user token for a `device_code`.
    pub async fn fetch_token(&self, device_code: &str) -> (String, String) {
        let response = self.fetch_token_raw(device_code).await;
        assert_eq!(response.status, 200, "user token: {}", response.text());
        let value = response.json();
        (
            value["access_token"].as_str().expect("access_token").to_owned(),
            value["refresh_token"].as_str().expect("refresh_token").to_owned(),
        )
    }

    /// The same poll, but without an expectation about the status.
    pub async fn fetch_token_raw(&self, device_code: &str) -> Response {
        let form = form(&[
            ("grant_type", edms_wire::login::GRANT_DEVICE_CODE),
            ("device_code", device_code),
            ("client_assertion_type", assertion::ASSERTION_TYP),
            ("client_assertion", &self.assertion()),
        ]);
        self.with_dpop(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_TOKEN,
            None,
            &self.session_key,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form.into_bytes()),
        )
        .await
    }

    /// Renews with a refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Response {
        let form = form(&[
            ("grant_type", edms_wire::login::GRANT_REFRESH_TOKEN),
            ("refresh_token", refresh_token),
            ("client_assertion_type", assertion::ASSERTION_TYP),
            ("client_assertion", &self.assertion()),
        ]);
        self.with_dpop(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_TOKEN,
            None,
            &self.session_key,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form.into_bytes()),
        )
        .await
    }

    /// Enrolment plus both tokens in one step.
    pub async fn signed_in(&self) -> AccessTokens {
        assert_eq!(self.enroll().await.status, 201);
        let device_token = self.device_token().await;
        let (user, refresh) = self.user_token().await;
        AccessTokens { device: device_token, user, refresh }
    }

    /// A `GET` on the API with the user token.
    pub async fn api_get(&self, path: &str, token: &str) -> Response {
        self.with_dpop(
            Origin::Api,
            "GET",
            path,
            Some(token),
            &self.session_key,
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            None,
        )
        .await
    }

    /// A `GET` on the API with the device token.
    pub async fn device_get(&self, path: &str, token: &str) -> Response {
        self.with_dpop(
            Origin::Api,
            "GET",
            path,
            Some(token),
            &self.device_key,
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            None,
        )
        .await
    }
}

/// The three tokens of a signed-in session.
#[derive(Debug, Clone)]
pub struct AccessTokens {
    pub device: String,
    pub user: String,
    pub refresh: String,
}

/// Whether an answer demands a nonce (401/400 with `use_dpop_nonce`).
pub fn requires_nonce(response: &Response) -> bool {
    let www = response.header_value(header::WWW_AUTHENTICATE).unwrap_or_default();
    let oauth = response.json().get("error").and_then(Value::as_str).unwrap_or_default().to_owned();
    www.contains("use_dpop_nonce") || oauth == "use_dpop_nonce"
}

/// A form body.
pub fn form(field: &[(&str, &str)]) -> String {
    field
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent encoding for form values.
fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(*byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Sends a request and reads the whole answer.
pub async fn send(
    base: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<Vec<u8>>,
) -> Response {
    let target = base.trim_start_matches("http://");
    let mut stream = TcpStream::connect(target).await.expect("a connection to the mock");
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = body.unwrap_or_default();
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(&body);
    stream.write_all(&bytes).await.expect("sending");
    stream.flush().await.expect("flushing");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("reading");
    read_response(&raw)
}

/// Takes an HTTP/1.1 answer apart into status, headers and body.
fn read_response(raw: &[u8]) -> Response {
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no headers in: {}", String::from_utf8_lossy(raw)));
    let header_part = String::from_utf8_lossy(&raw[..separator]).into_owned();
    let mut rows = header_part.lines();
    let status_line = rows.next().unwrap_or_default();
    let status: u16 = status_line.split(' ').nth(1).and_then(|part| part.parse().ok()).unwrap_or(0);
    let header: Vec<(String, String)> = rows
        .filter_map(|row| row.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Response { status, header, body: raw[separator + 4..].to_vec() }
}

/// The protected header of a detached JWS (`alg`, `typ`, `kid`).
pub fn signature_header(compact: &str) -> Value {
    use base64::Engine as _;
    let header = compact.split('.').next().unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}

/// Checks the signature of a delivery command against a key set out of the block.
pub fn command_holds(command: &Value, block: &Value) -> bool {
    use edms_crypto::key_set::{KeyOffer, KeySet};
    let Ok(offer) = KeyOffer::from_json(block) else { return false };
    let Ok(adoption) = KeySet::empty().anchor(&offer, None) else { return false };
    let Ok(set) = adoption.set.confirm() else { return false };
    edms_crypto::key_set::check_command_signature(command, &set).is_ok()
}

/// The structure of a JSON value as a set of key paths — for the comparison with a golden file.
/// Fields holding `null` count: their absence would be a different answer.
pub fn structure(value: &Value) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    collect(value, String::new(), &mut out);
    out
}

fn collect(value: &Value, path: String, out: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(field) => {
            for (name, inner) in field {
                let deeper = if path.is_empty() { name.clone() } else { format!("{path}.{name}") };
                out.insert(deeper.clone());
                collect(inner, deeper, out);
            }
        }
        Value::Array(entries) => {
            for entry in entries {
                collect(entry, format!("{path}[]"), out);
            }
        }
        _ => {}
    }
}

/// The body of a golden file as a value.
pub fn golden(name: &str) -> Value {
    serde_json::from_str(edms_wire::golden(name)).expect("the golden file is JSON")
}
