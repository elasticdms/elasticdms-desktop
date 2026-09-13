//! The contract tests of this crate: what really goes out on the wire.
//!
//! Checked against a **recording test rig** — a tiny HTTP server that records every request and
//! hands out prepared answers —, not against a model of the server. The difference is the point:
//! almost every promise of this crate is a header. Whether a DPoP proof is attached, whether
//! `If-None-Match: *` goes along, whether **exactly one** retry follows `use_dpop_nonce` — a test
//! against a model would only prove that the model fits the model.
//!
//! The test rig moreover lies on request, and that is exactly what this crate needs: a second nonce
//! prompt on the same request, a redirect, an `uploadUrl` on a foreign host, a `412` without a
//! body. The server mock `edms-mock` speaks the contract **correctly** and therefore cannot bring
//! these cases about at all; it is the counterpart for the honest way.
//!
//! The numbers T1, T2, T3, T5, T9, T11, T13, T14, T16, T24 are those of the contract document
//! (`docs/spec/03-api-contract-folder-client.md`, §7.6).
//!
//! The server runs on `127.0.0.1:0` — plaintext, and only for that reason reachable at all:
//! [`Connection`] admits `http` exclusively against the loopback.

// Test code may `unwrap` and `expect` (clippy.toml: allow-unwrap-in-tests,
// allow-expect-in-tests); clippy does not, however, recognise helper functions of an integration
// test file outside #[test] as test code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State as AxumState};
use axum::response::Response as AxumResponse;
use edms_core::checksum::Sha256Value;
use edms_core::delivery::CommandOutcome;
use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, CommandIdentifier, DeviceIdentifier,
    DocumentIdentifier,
};
use edms_core::namespace::Location;
use edms_core::time::Timestamp;
use edms_crypto::forge::{DpopCheckRequest, DpopVerifier};
use edms_crypto::key::{SigningKey, SoftwareKey};
use edms_net::server::{AcknowledgementOutcome, LoginIntent, LoginOutcome, LoginStep, Server};
use edms_net::{
    ApiResult, Clock, Connection, IdempotencyKey, KeyBinding, KeySource, NetworkError, Secret,
    ServerAccess,
};
use edms_wire::basics::{ErrorKind, WireTimestamp, digest_header_value, header};
use edms_wire::delivery::{Acknowledgement, DeliveryQuery};
use edms_wire::device::{EnrollmentRequest, Heartbeat};
use edms_wire::golden;
use edms_wire::ingest::{UploadGrant, UploadRequest};
use edms_wire::login::{DeviceAuthorization, TokenResponse};
use edms_wire::namespace::{DocumentRow, ListQuery};

// ── Fixed values ────────────────────────────────────────────────────────────────────────────

/// The device identifier of this contract's golden files.
const DEVICE: &str = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB";
const ARCHIVE: &str = "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3";
const BASKET: &str = "bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5";
const CASE: &str = "cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7";
const SEARCH: &str = "srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2";
const COMMAND: &str = "cmd_01JKC4D6E8F0G2H4J6K8M0N2P4";
const DOCUMENT: &str = "doc_01JK6T9ZS0P5Q7R8V1X2YZABCD";
const IDEMPOTENCY: &str = "01JKC6F8G0H2J4K6M8N0P2Q4R6";
const USER_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.desktop-user-access-token";
const DEVICE_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.desktop-device-access-token";

/// The same time in client and verifier; otherwise the proof falls out of the time window.
const NOW: Timestamp = Timestamp::from_unix_millis(1_788_336_862_000);

// ── Keys and clock ──────────────────────────────────────────────────────────────────────────

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        NOW
    }
}

/// Two keys and two tokens, each switchable off on its own — the way the operating system's
/// keychain delivers them or precisely does not (ADR-D03, point 4).
struct KeyBundle {
    device: Option<Arc<SoftwareKey>>,
    session: Option<Arc<SoftwareKey>>,
    kid: Option<String>,
    device_token: Option<Secret>,
    user_token: Option<Secret>,
}

impl KeyBundle {
    /// Set up and signed in.
    fn full() -> Self {
        Self {
            device: Some(Arc::new(SoftwareKey::generate().unwrap())),
            session: Some(Arc::new(SoftwareKey::generate().unwrap())),
            kid: Some(format!("{DEVICE}#1")),
            device_token: Some(Secret::new(DEVICE_TOKEN)),
            user_token: Some(Secret::new(USER_TOKEN)),
        }
    }

    /// Set up, but nobody signed in.
    fn without_user_token(mut self) -> Self {
        self.user_token = None;
        self
    }

    fn thumbprint(&self, binding: KeyBinding) -> String {
        let key = match binding {
            KeyBinding::Device => self.device.as_ref(),
            KeyBinding::Session => self.session.as_ref(),
        };
        key.unwrap().public().thumbprint()
    }
}

impl KeySource for KeyBundle {
    fn key(&self, binding: KeyBinding) -> Option<Arc<dyn SigningKey>> {
        let key = match binding {
            KeyBinding::Device => self.device.clone()?,
            KeyBinding::Session => self.session.clone()?,
        };
        Some(key as Arc<dyn SigningKey>)
    }

    fn device_kid(&self) -> Option<String> {
        self.kid.clone()
    }

    fn token(&self, binding: KeyBinding) -> Option<Secret> {
        match binding {
            KeyBinding::Device => self.device_token.clone(),
            KeyBinding::Session => self.user_token.clone(),
        }
    }
}

// ── The test rig ────────────────────────────────────────────────────────────────────────────

/// A recorded request.
#[derive(Debug, Clone)]
struct Call {
    method: String,
    path: String,
    query: String,
    header: HashMap<String, String>,
    body: Vec<u8>,
}

impl Call {
    fn header(&self, name: &str) -> Option<&str> {
        self.header.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// A field of the `application/x-www-form-urlencoded` body.
    fn field(&self, name: &str) -> Option<String> {
        pairs(&self.body_text()).remove(name)
    }

    /// A query parameter.
    fn parameter(&self, name: &str) -> Option<String> {
        pairs(&self.query).remove(name)
    }

    /// The claims of the DPoP proof — for the nonce the verifier expects.
    fn proof_claims(&self) -> serde_json::Map<String, serde_json::Value> {
        let proof = self.header(header::DPOP).expect("this call carries a proof");
        edms_crypto::jws::CompactJws::read(proof).unwrap().payload().clone()
    }
}

fn pairs(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (decode(name), decode(value)))
        .collect()
}

fn decode(text: &str) -> String {
    let bytes = text.replace('+', " ").into_bytes();
    let mut from = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = char::from(bytes[i + 1]).to_digit(16);
            let low = char::from(bytes[i + 2]).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                from.push(u8::try_from(high * 16 + low).unwrap_or(b'?'));
                i += 3;
                continue;
            }
        }
        from.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&from).into_owned()
}

/// A prepared answer.
#[derive(Debug, Clone)]
struct Response {
    status: u16,
    header: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn new(status: u16) -> Self {
        Self { status, header: Vec::new(), body: Vec::new() }
    }

    fn json(status: u16, body: &str) -> Self {
        Self::new(status)
            .with_header(header::CONTENT_TYPE, "application/json")
            .with_body(body.as_bytes())
    }

    fn problem(status: u16, body: &str) -> Self {
        Self::new(status)
            .with_header(header::CONTENT_TYPE, "application/problem+json")
            .with_body(body.as_bytes())
    }

    #[must_use]
    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.header.push((name.to_owned(), value.to_owned()));
        self
    }

    #[must_use]
    fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// The prompt of the resource server (RFC 9449 §8).
    fn nonce_needed(nonce: &str) -> Self {
        Self::problem(401, golden("problem_dpop_nonce_required.json"))
            .with_header(header::WWW_AUTHENTICATE, r#"DPoP error="use_dpop_nonce""#)
            .with_header(header::DPOP_NONCE, nonce)
    }

    /// The same prompt in the form of the authorization server (RFC 9449 §9).
    fn nonce_needed_oauth(nonce: &str) -> Self {
        Self::json(400, golden("oauth_nonce_required.json")).with_header(header::DPOP_NONCE, nonce)
    }
}

#[derive(Clone)]
struct State {
    calls: Arc<Mutex<Vec<Call>>>,
    responses: Arc<Mutex<VecDeque<Response>>>,
}

/// The running test rig.
struct Harness {
    base: String,
    state: State,
}

impl Harness {
    async fn start() -> Self {
        let state = State {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(VecDeque::new())),
        };
        let router = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self { base, state }
    }

    /// Puts answers into the queue; they go out in this order.
    fn answer(&self, responses: impl IntoIterator<Item = Response>) -> &Self {
        let mut line = self.state.responses.lock().unwrap_or_else(|f| f.into_inner());
        line.extend(responses);
        self
    }

    fn calls(&self) -> Vec<Call> {
        self.state.calls.lock().unwrap_or_else(|f| f.into_inner()).clone()
    }

    fn count(&self) -> usize {
        self.calls().len()
    }

    fn call(&self, number: usize) -> Call {
        let all = self.calls();
        assert!(all.len() > number, "there were only {} calls", all.len());
        all[number].clone()
    }
}

async fn handle(AxumState(state): AxumState<State>, request: Request) -> AxumResponse {
    let (share, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap_or_default();
    let call = Call {
        method: share.method.as_str().to_owned(),
        path: share.uri.path().to_owned(),
        query: share.uri.query().unwrap_or_default().to_owned(),
        header: share
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|text| (name.as_str().to_ascii_lowercase(), text.to_owned()))
            })
            .collect(),
        body: body.to_vec(),
    };
    state.calls.lock().unwrap_or_else(|f| f.into_inner()).push(call);

    let response = state.responses.lock().unwrap_or_else(|f| f.into_inner()).pop_front();
    let response = response.unwrap_or_else(|| {
        Response::json(500, r#"{"type":"about:blank","title":"no answer prepared"}"#)
    });
    let mut builder = AxumResponse::builder().status(response.status);
    for (name, value) in &response.header {
        builder = builder.header(name, value);
    }
    builder.body(Body::from(response.body)).unwrap_or_else(|_| AxumResponse::new(Body::empty()))
}

/// An ear that accepts every connection and drops it at once.
///
/// With it, what would otherwise need a cut cable can be reproduced: a request that went out
/// without an answer ever coming (contract test T14).
async fn deaf_ear() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    format!("http://{address}")
}

// ── Set-up ──────────────────────────────────────────────────────────────────────────────────

fn device_identifier() -> DeviceIdentifier {
    DEVICE.parse().unwrap()
}

fn access(state: &Harness) -> ServerAccess {
    access_with(&state.base, &state.base, KeyBundle::full())
}

fn access_with(api: &str, auth: &str, bundle: KeyBundle) -> ServerAccess {
    let connection = Connection::new(api, auth, device_identifier(), "1.0.0").unwrap();
    ServerAccess::with_clock(connection, Arc::new(bundle), Arc::new(TestClock)).unwrap()
}

/// Checks the DPoP proof of a call the way the server would, and delivers the thumbprint of the
/// key that produced it.
fn proof_holds(state: &Harness, call: &Call, token: Option<&str>) -> String {
    let proof = call.header(header::DPOP).expect("without DPoP this call does not go out");
    let url = format!("{}{}", state.base, call.path);
    let claims = call.proof_claims();
    let nonce = claims.get("nonce").and_then(serde_json::Value::as_str).map(ToOwned::to_owned);
    let mut request = DpopCheckRequest::new(&call.method, &url, NOW);
    if let Some(token) = token {
        request = request.with_access_token(token);
    }
    if let Some(nonce) = &nonce {
        request = request.with_nonce(nonce);
    }
    DpopVerifier::new().check(proof, &request).expect("the proof withstands the check").jkt
}

/// The nonce a call brought along.
fn nonce_of(call: &Call) -> Option<String> {
    call.proof_claims().get("nonce").and_then(serde_json::Value::as_str).map(ToOwned::to_owned)
}

/// Replaces the hosts of a golden file with that of the test rig — for discovery and upload, where
/// the addresses in the body are checked against the base.
fn on_harness(template: &str, base: &str) -> String {
    template.replace("https://auth.elasticdms.io", base).replace("https://api.elasticdms.io", base)
}

fn request() -> EnrollmentRequest {
    serde_json::from_str(golden("enrollment_request_desktop.json")).unwrap()
}

fn first_page() -> ListQuery {
    ListQuery::new(None, None).unwrap()
}

/// The archive of the golden files; since namespace v2 a case listing has no other way in.
fn archive() -> ArchiveIdentifier {
    ARCHIVE.parse().unwrap()
}

fn basket() -> BasketIdentifier {
    BASKET.parse().unwrap()
}

fn key() -> IdempotencyKey {
    IdempotencyKey::read(IDEMPOTENCY).unwrap()
}

fn acknowledgement() -> Acknowledgement {
    Acknowledgement::new(CommandOutcome::Applied, None)
}

fn document_row(version: &str, size: u64, sha256: Sha256Value) -> DocumentRow {
    DocumentRow {
        document_id: DOCUMENT.parse::<DocumentIdentifier>().unwrap(),
        title: "Rahmenvertrag 2026".to_owned(),
        media_type: "application/pdf".to_owned(),
        size,
        sha256,
        version: version.to_owned(),
        created_at: WireTimestamp::read("2026-01-08T07:55:00Z").unwrap(),
        updated_at: WireTimestamp::read("2026-08-31T15:41:19Z").unwrap(),
    }
}

/// A sign-in with short times — the tests are not to wait but to check.
fn login(expires_in: u64, interval: u64) -> DeviceAuthorization {
    serde_json::from_str(&format!(
        r#"{{"device_code":"GmRhmhcxhwEzkoEqiMEg","user_code":"WQPX-7TRM",
            "verification_uri":"https://app.elasticdms.io/geraet",
            "expires_in":{expires_in},"interval":{interval}}}"#
    ))
    .unwrap()
}

// ── §7.0.5 Enrolment ────────────────────────────────────────────────────────────────────────

/// Contract test T1.
#[tokio::test]
async fn the_enrolment_goes_out_as_a_put_without_authorization_and_without_dpop() {
    let state = Harness::start().await;
    state.answer([Response::json(201, golden("device_desktop.json"))]);
    let access = access(&state);

    let result = access.register_device(&request()).await;

    let call = state.call(0);
    assert_eq!(call.method, "PUT", "a POST retry would create a second device (03 §6.2.1)");
    assert_eq!(call.path, format!("/v1/devices/{DEVICE}"));
    assert_eq!(
        call.header(header::AUTHORIZATION),
        None,
        "the enrolment code is the credential of this one call"
    );
    assert_eq!(
        call.header(header::DPOP),
        None,
        "the server learns the key only with this request and could check no proof"
    );
    assert_eq!(call.header(header::IF_NONE_MATCH), Some("*"));
    assert!(call.body_text().contains("\"deviceKind\":\"desktop\""));
    let report = result.value().expect("201 is success");
    assert!(!report.inventory_already);
    assert!(report.device.is_some());
}

/// Contract tests T2 and T3.
#[tokio::test]
async fn a_412_is_success_and_the_complete_answer_delivers_the_key_block() {
    let state = Harness::start().await;
    state.answer([Response::json(412, golden("device_desktop.json"))]);
    let access = access(&state);

    let report = access
        .register_device(&request())
        .await
        .value()
        .expect("412 is success, not an error (T2)");

    assert!(report.inventory_already);
    let device = report.device.expect("the complete answer carries the device object");
    assert!(device.server_keys.is_some(), "T3: the key block comes along too");
    assert!(!device.is_active(), "level SOFTWARE waits for the approval of a human being");
}

#[tokio::test]
async fn a_412_without_a_body_demands_reading_it_afterwards_instead_of_guessing() {
    let state = Harness::start().await;
    state.answer([Response::new(412)]);
    let access = access(&state);

    let report = access.register_device(&request()).await.value().unwrap();

    assert!(report.inventory_already);
    assert!(
        report.device.is_none(),
        "without a body there is no device object — the engine reads it with device_status"
    );
}

/// Contract test T5.
#[tokio::test]
async fn a_409_device_id_conflict_is_not_a_retry() {
    let state = Harness::start().await;
    state.answer([Response::problem(409, golden("problem_device_already_exists.json"))]);
    let access = access(&state);

    let result = access.register_device(&request()).await;

    assert!(!result.is_success(), "under that identifier lies a different public key");
    assert_eq!(result.error_kind(), Some(ErrorKind::DeviceIdConflict));
}

// ── §7.0.9 DPoP and nonces ──────────────────────────────────────────────────────────────────

/// Contract test T9.
#[tokio::test]
async fn use_dpop_nonce_leads_to_exactly_one_retry() {
    let state = Harness::start().await;
    state.answer([
        Response::nonce_needed("nonce-one"),
        // A page without a continuation: that way the test counts retries and not pages.
        Response::json(200, golden("searches_page.json")).with_header(header::ETAG, "\"7\""),
    ]);
    let access = access(&state);

    let result = access.list_searches(&first_page(), None).await;

    assert!(result.is_success(), "after the retry the call goes through: {result:?}");
    assert_eq!(state.count(), 2, "exactly one retry, not two");
    assert_eq!(nonce_of(&state.call(0)), None, "the first proof knows no nonce yet");
    assert_eq!(
        nonce_of(&state.call(1)).as_deref(),
        Some("nonce-one"),
        "the retry carries exactly the nonce from the answer"
    );
    proof_holds(&state, &state.call(1), Some(USER_TOKEN));
}

/// Contract test T9, the other half.
#[tokio::test]
async fn a_second_use_dpop_nonce_response_is_final() {
    let state = Harness::start().await;
    state.answer([Response::nonce_needed("nonce-one"), Response::nonce_needed("nonce-two")]);
    let access = access(&state);

    let result = access.list_searches(&first_page(), None).await;

    assert_eq!(state.count(), 2, "a loop would be a self-DoS here");
    assert!(
        matches!(result, ApiResult::NetworkError(NetworkError::NonceLoop { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn without_a_new_nonce_nothing_is_retried() {
    let state = Harness::start().await;
    // The server demands a nonce but sends none along: its error, not the beginning of a
    // loop.
    state.answer([Response::problem(401, golden("problem_dpop_nonce_required.json"))
        .with_header(header::WWW_AUTHENTICATE, r#"DPoP error="use_dpop_nonce""#)]);
    let access = access(&state);

    let result = access.list_searches(&first_page(), None).await;

    assert_eq!(state.count(), 1);
    assert_eq!(result.error_kind(), Some(ErrorKind::DpopNonceNeeded));
}

#[tokio::test]
async fn the_sign_in_server_demands_the_nonce_in_the_body_and_is_served_the_same_way() {
    let state = Harness::start().await;
    state.answer([
        Response::nonce_needed_oauth("as-nonce"),
        Response::json(200, golden("token_device_desktop.json")),
    ]);
    let access = access(&state);

    let result = access.fetch_device_token().await;

    assert_eq!(state.count(), 2, "RFC 9449 §9 means the same as §8 and is treated alike");
    assert_eq!(nonce_of(&state.call(1)).as_deref(), Some("as-nonce"));
    let token: TokenResponse = result.value().expect("after the retry the token comes");
    assert!(token.has_scope("delivery:receive"));
    assert!(token.refresh_token.is_none(), "the device token has none (03 §6.2.2)");
}

#[tokio::test]
async fn a_nonce_from_a_success_answer_goes_into_the_next_request() {
    let state = Harness::start().await;
    state.answer([
        Response::json(200, golden("searches_page.json")).with_header(header::DPOP_NONCE, "fresh"),
        Response::json(200, golden("searches_page.json")),
    ]);
    let access = access(&state);

    let _ = access.list_searches(&first_page(), None).await;
    let _ = access.list_searches(&first_page(), None).await;

    assert_eq!(
        nonce_of(&state.call(1)).as_deref(),
        Some("fresh"),
        "the server may renew the nonce at any time, not only in a 401"
    );
}

#[tokio::test]
async fn nonces_stay_separated_per_origin() {
    let api = Harness::start().await;
    let auth = Harness::start().await;
    api.answer([Response::json(200, golden("searches_page.json"))
        .with_header(header::DPOP_NONCE, "api-nonce")]);
    auth.answer([Response::json(200, golden("token_device_desktop.json"))]);
    let access = access_with(&api.base, &auth.base, KeyBundle::full());

    let _ = access.list_searches(&first_page(), None).await;
    let _ = access.fetch_device_token().await;

    assert_eq!(
        nonce_of(&auth.call(0)),
        None,
        "a nonce from api. is invalid at auth.; whoever takes it along reaps an alternation of \
         two prompts"
    );
}

#[tokio::test]
async fn every_request_carries_version_language_agent_and_a_request_id_of_its_own() {
    let state = Harness::start().await;
    state.answer([
        Response::json(200, golden("searches_page.json")),
        Response::json(200, golden("searches_page.json")),
    ]);
    let access = access(&state);

    let _ = access.list_searches(&first_page(), None).await;
    let _ = access.list_searches(&first_page(), None).await;

    let first = state.call(0);
    assert_eq!(first.header(header::ELASTICDMS_VERSION), Some(edms_wire::basics::API_VERSION));
    assert_eq!(first.header(header::ACCEPT_LANGUAGE), Some("de-DE"));
    assert!(first.header("user-agent").unwrap().starts_with("elasticdms-folder-client/1.0.0 ("));
    let identifier = first.header(header::X_REQUEST_ID).expect("every request carries an id");
    assert_eq!(identifier.len(), 26, "a ULID, not free text");
    assert_ne!(
        identifier,
        state.call(1).header(header::X_REQUEST_ID).unwrap(),
        "one of its own per request — otherwise a screenshot would point at two server lines"
    );
}

#[tokio::test]
async fn listings_prove_with_the_session_key_the_delivery_channel_with_the_device_key() {
    let state = Harness::start().await;
    state.answer([
        Response::json(200, golden("searches_page.json")),
        Response::json(200, golden("delivery_empty.json")),
    ]);
    let bundle = KeyBundle::full();
    let session = bundle.thumbprint(KeyBinding::Session);
    let device = bundle.thumbprint(KeyBinding::Device);
    let access = access_with(&state.base, &state.base, bundle);

    let _ = access.list_searches(&first_page(), None).await;
    let _ = access.delivery_collect(&DeliveryQuery::new(25, None).unwrap()).await;

    let list = state.call(0);
    assert_eq!(list.header(header::AUTHORIZATION), Some(format!("DPoP {USER_TOKEN}").as_str()));
    assert_eq!(
        proof_holds(&state, &list, Some(USER_TOKEN)),
        session,
        "what a human being answers for is proved by the session key"
    );

    let delivery = state.call(1);
    assert_eq!(
        delivery.header(header::AUTHORIZATION),
        Some(format!("DPoP {DEVICE_TOKEN}").as_str())
    );
    assert_eq!(
        proof_holds(&state, &delivery, Some(DEVICE_TOKEN)),
        device,
        "an erasure has to reach the device even without a signed-in human being"
    );
    assert_eq!(delivery.parameter("wait").as_deref(), Some("25"));
}

// ── §7.0.6 and §7.0.7 Sign-in ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_device_token_proves_with_the_device_key_and_carries_no_token_yet() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("token_device_desktop.json"))]);
    let bundle = KeyBundle::full();
    let device = bundle.thumbprint(KeyBinding::Device);
    let access = access_with(&state.base, &state.base, bundle);

    let result = access.fetch_device_token().await;

    let call = state.call(0);
    assert_eq!(call.path, "/v1/oauth/token");
    assert_eq!(call.field("grant_type").as_deref(), Some("client_credentials"));
    assert_eq!(
        call.field("scope").as_deref(),
        Some("device:self desktop:login delivery:receive"),
        "the device token may carry nothing of the domain (contract §7.0.6)"
    );
    assert_eq!(
        call.header(header::AUTHORIZATION),
        None,
        "at the token fetch there is a proof, but no token yet"
    );
    assert_eq!(proof_holds(&state, &call, None), device);
    assert!(result.is_success(), "{result:?}");
}

#[tokio::test]
async fn the_start_of_the_device_flow_carries_dpop_jkt_but_no_dpop_header() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("device_authorization_desktop.json"))]);
    let bundle = KeyBundle::full();
    let session = bundle.thumbprint(KeyBinding::Session);
    let access = access_with(&state.base, &state.base, bundle);

    let result = access.start_device_login(&LoginIntent::first_login()).await;

    let call = state.call(0);
    assert_eq!(call.path, "/v1/oauth/device_authorization");
    assert_eq!(
        call.header(header::DPOP),
        None,
        "RFC 9449 §5 binds over dpop_jkt here; the proof comes only at the collection"
    );
    assert_eq!(
        call.field("dpop_jkt").as_deref(),
        Some(session.as_str()),
        "what is bound is the session key, not the long-lived device key"
    );
    assert_eq!(call.field("acr_values").as_deref(), Some("urn:elasticdms:acr:desktop"));
    assert!(call.field("client_assertion").is_some_and(|jws| jws.matches('.').count() == 2));
    assert!(call.field("scope").unwrap().contains("documents:read"));

    let start: DeviceAuthorization = result.value().unwrap();
    assert_eq!(start.anchor.as_deref(), Some("K7-M4"), "the anchor is compared by a human being");
    assert_eq!(start.interval_second(), 5);
}

#[tokio::test]
async fn a_human_who_refuses_and_an_expired_code_are_two_outcomes() {
    let state = Harness::start().await;
    state.answer([
        Response::json(400, golden("oauth_authorization_pending.json")),
        Response::json(400, golden("oauth_access_denied.json")),
    ]);
    let access = access(&state);

    let result = access.wait_on_token(&login(9, 1), &|_| {}).await;

    assert_eq!(state.count(), 2);
    assert_eq!(state.call(1).field("device_code").as_deref(), Some("GmRhmhcxhwEzkoEqiMEg"));
    assert!(
        matches!(result.value(), Some(LoginOutcome::Rejected(_))),
        "whoever throws them together sends somebody off to wait who was refused"
    );
}

#[tokio::test]
async fn an_issued_token_ends_the_waiting() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("token_user_desktop.json"))]);
    let bundle = KeyBundle::full();
    let session = bundle.thumbprint(KeyBinding::Session);
    let access = access_with(&state.base, &state.base, bundle);

    let result = access.wait_on_token(&login(9, 1), &|_| {}).await;

    let Some(LoginOutcome::Issued(token)) = result.value() else {
        panic!("the token should be issued");
    };
    assert!(token.refresh_token.is_some());
    assert!(token.has_scope("documents:read"));
    assert_eq!(
        proof_holds(&state, &state.call(0), None),
        session,
        "the proof at the token endpoint carries the key the token is bound to"
    );
}

#[tokio::test]
async fn slow_down_raises_the_interval_permanently_by_five_seconds() {
    let state = Harness::start().await;
    state.answer([Response::json(400, golden("oauth_slow_down.json"))]);
    let access = access(&state);
    let steps: Arc<Mutex<Vec<LoginStep>>> = Arc::new(Mutex::new(Vec::new()));
    let collector = Arc::clone(&steps);

    // `expires_in: 1` ends the flow after the first attempt — what is checked is the interval the
    // client would have taken afterwards, not the waiting itself.
    let result = access
        .wait_on_token(&login(1, 1), &move |step| {
            collector.lock().unwrap_or_else(|f| f.into_inner()).push(step);
        })
        .await;

    let seen = steps.lock().unwrap_or_else(|f| f.into_inner()).clone();
    assert_eq!(
        seen,
        vec![LoginStep::Slower { interval_second: 6 }],
        "RFC 8628 §3.5: the supplement holds permanently, not only for the next attempt"
    );
    assert!(matches!(result.value(), Some(LoginOutcome::Expired)));
}

/// Contract test T14.
#[tokio::test]
async fn a_renewal_without_an_answer_is_not_repeated_blindly() {
    let deaf = deaf_ear().await;
    let access = access_with(&deaf, &deaf, KeyBundle::full());

    let result = access.refresh_token(&Secret::new("rt_01JKF2P4R6T8V0X2Z4B6D8F0H2")).await;

    match result {
        ApiResult::NetworkError(error @ NetworkError::RefreshUncertain { .. }) => {
            assert!(!error.may_repeated_become());
            assert!(
                error.to_string().contains("token family"),
                "the sentence has to say why no second attempt follows: {error}"
            );
        }
        other => panic!("expected RefreshUncertain, came: {other:?}"),
    }
}

#[tokio::test]
async fn a_reused_refresh_token_is_a_security_event() {
    let state = Harness::start().await;
    state.answer([Response::json(400, golden("oauth_refresh_reused.json"))]);
    let access = access(&state);

    let result = access.refresh_token(&Secret::new("rt_alt")).await;

    assert!(
        matches!(result, ApiResult::SecurityAbort { .. }),
        "no ordinary end of session: somebody else has used the same token ({result:?})"
    );
    assert!(result.is_security_event());
    assert_eq!(result.error_kind(), Some(ErrorKind::RefreshTokenReused));
}

#[tokio::test]
async fn an_expired_session_is_an_error_on_the_merits_and_not_a_security_event() {
    let state = Harness::start().await;
    state.answer([Response::json(400, golden("oauth_session_expired.json"))]);
    let access = access(&state);

    let result = access.refresh_token(&Secret::new("rt_alt")).await;

    assert_eq!(result.error_kind(), Some(ErrorKind::SessionExpired));
    assert!(!result.is_security_event(), "the tree stays visible, the human signs in anew");
}

#[tokio::test]
async fn a_successful_renewal_delivers_a_new_refresh_token() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("token_user_desktop.json"))]);
    let access = access(&state);

    let result = access.refresh_token(&Secret::new("rt_alt")).await;

    let call = state.call(0);
    assert_eq!(call.field("grant_type").as_deref(), Some("refresh_token"));
    assert_eq!(call.field("refresh_token").as_deref(), Some("rt_alt"));
    let token: TokenResponse = result.value().unwrap();
    assert_eq!(
        token.refresh_token.as_deref(),
        Some("rt_01JKF2P4R6T8V0X2Z4B6D8F0H2"),
        "every renewal rotates the refresh token (03 §6.3.3)"
    );
}

#[tokio::test]
async fn the_revocation_names_the_token_and_the_client_assertion() {
    let state = Harness::start().await;
    state.answer([Response::new(200)]);
    let access = access(&state);

    let result = access.revoke(&Secret::new("rt_alt")).await;

    let call = state.call(0);
    assert_eq!(call.path, "/v1/oauth/revoke");
    assert_eq!(call.field("token").as_deref(), Some("rt_alt"));
    assert_eq!(call.field("token_type_hint").as_deref(), Some("refresh_token"));
    assert!(call.field("client_assertion").is_some());
    assert!(result.is_success(), "{result:?}");
}

// ── §7.1 Namespace ──────────────────────────────────────────────────────────────────────────

/// The two containers namespace v2 added, each on its own address (§7.1.1).
#[tokio::test]
async fn the_basket_listing_and_the_archive_listing_have_addresses_of_their_own() {
    let state = Harness::start().await;
    state.answer([
        Response::json(200, golden("baskets_page.json")),
        Response::json(200, golden("archives_page.json")),
    ]);
    let access = access(&state);

    let baskets = access.list_baskets(&first_page(), None).await.value().unwrap();
    let archives = access.list_archives(&first_page(), None).await.value().unwrap();

    assert_eq!(state.call(0).path, "/v1/mirror/baskets");
    assert_eq!(state.call(1).path, "/v1/mirror/archives");
    assert_eq!(baskets.entries.len(), 2);
    assert_eq!(archives.entries.len(), 2);
    assert_eq!(
        archives.entries[0].archive_id.to_string(),
        ARCHIVE,
        "the archive of this contract's golden files"
    );
}

/// The archive stands in the path, not in the query — `cases` as a top-level container is gone
/// (ADR-D11 §1). A listing that forgot its archive would ask an address that does not exist.
#[tokio::test]
async fn a_case_listing_asks_below_its_archive() {
    let state = Harness::start().await;
    state.answer([Response::json(200, r#"{"items":[],"nextCursor":null,"hasMore":false}"#)]);
    let access = access(&state);

    let list = access.list_cases(archive(), &first_page(), None).await.value().unwrap();

    assert_eq!(state.call(0).path, format!("/v1/mirror/archives/{ARCHIVE}/cases"));
    assert!(list.entries.is_empty(), "an empty archive is an empty folder, not an error");
}

/// Contract test T11: what arrives stands in the folder — the client never filters.
#[tokio::test]
async fn a_listing_is_read_over_all_pages_and_taken_over_unfiltered() {
    let state = Harness::start().await;
    let second = r#"{"items":[{"caseId":"cas_01JKA8N3R0S5T7V9W2X4Y6Z8A1",
        "title":"Bauvorhaben Rothenbaumchaussee 12","updatedAt":"2026-09-09T08:21:03Z"}],
        "nextCursor":null,"hasMore":false}"#;
    state.answer([
        Response::json(200, golden("cases_page.json")).with_header(header::ETAG, "\"7\""),
        Response::json(200, second).with_header(header::ETAG, "\"8\""),
    ]);
    let access = access(&state);

    let list = access.list_cases(archive(), &first_page(), None).await.value().unwrap();

    assert_eq!(list.entries.len(), 3, "two rows of the first page plus one of the second");
    assert_eq!(list.pages, 2);
    assert!(!list.limit_reached);
    assert_eq!(
        list.etag.as_deref(),
        Some("\"7\""),
        "only the ETag of the first page describes the whole listing"
    );
    assert_eq!(state.call(0).parameter("cursor"), None);
    assert_eq!(
        state.call(1).parameter("cursor").as_deref(),
        Some("eyJ0IjoxNzcyNDQ4MjkyfQ"),
        "the cursor is handed back, never read out"
    );
    assert_eq!(state.call(0).header(header::IF_NONE_MATCH), None);
}

#[tokio::test]
async fn a_304_is_unchanged_and_not_an_empty_listing() {
    let state = Harness::start().await;
    state.answer([Response::new(304).with_header(header::ETAG, "\"7\"")]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), Some("\"7\"")).await;

    assert_eq!(state.call(0).header(header::IF_NONE_MATCH), Some("\"7\""));
    match result {
        ApiResult::Unchanged { etag } => assert_eq!(etag.as_deref(), Some("\"7\"")),
        other => panic!("304 means \"you already have it\", not {other:?}"),
    }
}

/// Contract test T16.
#[tokio::test]
async fn an_unreadable_cursor_is_an_error_and_not_a_jump_back_to_page_one() {
    let state = Harness::start().await;
    state.answer([Response::problem(400, golden("problem_cursor_invalid.json"))]);
    let access = access(&state);
    let further = ListQuery::new(Some("stale-cursor".to_owned()), None).unwrap();

    let result = access.list_cases(archive(), &further, None).await;

    assert_eq!(result.error_kind(), Some(ErrorKind::CursorInvalid));
    assert_eq!(state.count(), 1, "a jump back to page 1 would create duplicate entries");
}

#[tokio::test]
async fn a_contradiction_in_the_page_envelope_is_a_breach_of_contract() {
    let state = Harness::start().await;
    // `hasMore: true` without a cursor: the listing could not be read to the end.
    state.answer([Response::json(200, r#"{"items":[],"nextCursor":null,"hasMore":true}"#)]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    assert!(
        matches!(result, ApiResult::NetworkError(NetworkError::ContractBreach { .. })),
        "a quietly truncated case file would be the lie this client must not tell"
    );
}

#[tokio::test]
async fn a_truncated_hit_list_reports_truncation_and_address() {
    let state = Harness::start().await;
    let last = r#"{"items":[],"nextCursor":null,"hasMore":false,"totalCapped":false,
        "displayLimit":5000,"refineUrl":null}"#;
    state.answer([
        Response::json(200, golden("search_documents_truncated.json")),
        Response::json(200, last),
    ]);
    let access = access(&state);
    let location = Location::Search(SEARCH.parse().unwrap());

    let list = access.list_document(location, &first_page(), None).await.value().unwrap();

    assert!(list.total_capped, "once truncated, always truncated");
    let truncation = list.truncation().expect("the hint file needs a number and an address");
    assert_eq!(truncation.displayed, 5000);
    assert!(
        truncation.address.unwrap().starts_with("https://app.elasticdms.io/suche"),
        "without an address the hint would be a dead end"
    );
}

#[tokio::test]
async fn a_search_that_cannot_be_run_is_an_error_and_not_an_empty_folder() {
    let state = Harness::start().await;
    state.answer([Response::problem(422, golden("problem_search_not_executable.json"))]);
    let access = access(&state);
    let location = Location::Search(SEARCH.parse().unwrap());

    let result = access.list_document(location, &first_page(), None).await;

    assert_eq!(result.error_kind(), Some(ErrorKind::SearchNotRunnable));
    assert!(
        result.problem().unwrap().errors.is_some(),
        "ADR-014 knows two outcomes: permitted, or an error with a message"
    );
}

#[tokio::test]
async fn a_case_file_is_read_over_its_own_path() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("case_documents_page.json"))]);
    let access = access(&state);
    let location =
        Location::Case { archive: archive(), case: CASE.parse::<CaseIdentifier>().unwrap() };

    let list = access.list_document(location, &first_page(), None).await.value().unwrap();

    assert_eq!(state.call(0).path, format!("/v1/mirror/archives/{ARCHIVE}/cases/{CASE}/documents"));
    assert_eq!(list.rows.len(), 3);
    assert!(list.truncation().is_none(), "without truncation no hint file");
    assert_eq!(list.in_core().len(), 3, "the rows go into the core unchanged");
}

// ── §7.2 Content ────────────────────────────────────────────────────────────────────────────

/// The four mandatory headers of a content answer.
fn content_response(bytes: &[u8], version: &str, sha256: &Sha256Value) -> Response {
    Response::new(200)
        .with_header(header::CONTENT_TYPE, "application/pdf")
        .with_header(header::ETAG, &format!("\"{version}\""))
        .with_header(header::REPR_DIGEST, &digest_header_value(sha256))
        .with_body(bytes)
}

#[tokio::test]
async fn the_content_is_checked_and_then_written_into_the_sink() {
    let bytes = b"%PDF-1.7 receipt";
    let sha = edms_crypto::checksum::sha256(bytes);
    let state = Harness::start().await;
    state.answer([content_response(bytes, "12", &sha)]);
    let access = access(&state);
    let row = document_row("12", bytes.len() as u64, sha);
    let mut sink: Vec<u8> = Vec::new();

    let report = access
        .load_content(&row, Some("WINWORD.EXE"), &mut sink)
        .await
        .value()
        .expect("the fetch goes through");

    assert_eq!(sink, bytes);
    assert_eq!(report.bytes, bytes.len() as u64);
    assert_eq!(report.header.sha256, sha);
    let call = state.call(0);
    assert_eq!(call.path, format!("/v1/documents/{DOCUMENT}/content"));
    assert_eq!(call.header(header::IF_MATCH), Some("\"12\""));
    assert_eq!(call.header(header::REQUESTING_APPLICATION), Some("WINWORD.EXE"));
    assert_eq!(call.parameter("range"), None, "the client loads whole files, no Range");
}

#[tokio::test]
async fn a_new_version_is_noticed_before_a_single_byte_is_written() {
    let bytes = b"%PDF-1.7 different version";
    let sha = edms_crypto::checksum::sha256(bytes);
    let state = Harness::start().await;
    // The listing knew version 12; the server delivers 13.
    state.answer([content_response(bytes, "13", &sha)]);
    let access = access(&state);
    let row = document_row("12", bytes.len() as u64, sha);
    let mut sink: Vec<u8> = Vec::new();

    let result = access.load_content(&row, None, &mut sink).await;

    assert!(
        matches!(result, ApiResult::NetworkError(NetworkError::ContentHeader(_))),
        "{result:?}"
    );
    assert!(
        sink.is_empty(),
        "the placeholder would otherwise carry size and checksum of a different version"
    );
}

#[tokio::test]
async fn a_missing_checksum_is_not_a_skipped_check() {
    let bytes = b"%PDF-1.7";
    let sha = edms_crypto::checksum::sha256(bytes);
    let state = Harness::start().await;
    state.answer([Response::new(200)
        .with_header(header::CONTENT_TYPE, "application/pdf")
        .with_header(header::ETAG, "\"12\"")
        .with_body(bytes)]);
    let access = access(&state);
    let row = document_row("12", bytes.len() as u64, sha);
    let mut sink: Vec<u8> = Vec::new();

    let result = access.load_content(&row, None, &mut sink).await;

    assert!(matches!(result, ApiResult::NetworkError(NetworkError::ContentHeader(_))));
    assert!(sink.is_empty(), "a fetch without a statement about what arrives is not taken over");
}

/// Contract test T13, in so far as it belongs here: what arrives is counted.
#[tokio::test]
async fn a_mutilated_body_is_a_failed_hydration() {
    let announced = b"%PDF-1.7 complete receipt";
    let delivered = b"%PDF-1.7 short";
    let sha = edms_crypto::checksum::sha256(announced);
    let state = Harness::start().await;
    // The server notices the hash error only at the last `Read` — `200` and the headers are long
    // since out, and the body stays shorter than announced.
    state.answer([content_response(delivered, "12", &sha)
        .with_header(header::CONTENT_LENGTH, &announced.len().to_string())]);
    let access = access(&state);
    let row = document_row("12", announced.len() as u64, sha);
    let mut sink: Vec<u8> = Vec::new();

    let result = access.load_content(&row, None, &mut sink).await;

    assert!(
        matches!(result, ApiResult::NetworkError(_)),
        "a short body arrives with 200; only the comparison turns it into a failed \
         hydration ({result:?})"
    );
    assert!(!result.is_success());
}

#[tokio::test]
async fn a_program_name_that_cannot_be_encoded_costs_the_header_not_the_document() {
    let bytes = b"%PDF-1.7 ok";
    let sha = edms_crypto::checksum::sha256(bytes);
    let state = Harness::start().await;
    state.answer([content_response(bytes, "12", &sha)]);
    let access = access(&state);
    let row = document_row("12", bytes.len() as u64, sha);
    let mut sink: Vec<u8> = Vec::new();

    // A path instead of a file name: it would betray the user name and does not go out.
    let report = access
        .load_content(&row, Some("C:\\Users\\lotzer\\WINWORD.EXE"), &mut sink)
        .await
        .value()
        .expect("the observation falls away, the document comes all the same");

    assert_eq!(report.bytes, bytes.len() as u64);
    assert_eq!(state.call(0).header(header::REQUESTING_APPLICATION), None);
}

#[tokio::test]
async fn a_step_up_challenge_is_not_an_error_but_a_prompt() {
    let state = Harness::start().await;
    state.answer([Response::problem(401, golden("problem_step_up.json")).with_header(
        header::WWW_AUTHENTICATE,
        r#"DPoP error="insufficient_user_authentication", acr_values="urn:elasticdms:acr:desktop", max_age=120"#,
    )]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    match result {
        ApiResult::StepUpNeeded { request, .. } => {
            assert_eq!(request.first_acr(), Some("urn:elasticdms:acr:desktop"));
            assert_eq!(request.max_age_second, Some(120));
            let intent = LoginIntent::step_up(&request, Some("usr_01JKE0M2P4R6T8V0X2Z4B6D8F0"));
            assert_eq!(intent.prompt.as_deref(), Some("login"), "a quiet step-up would be none");
            assert_eq!(
                intent.max_age,
                Some(120),
                "the level comes from the challenge, never from the client"
            );
        }
        other => panic!("expected a step-up prompt, came: {other:?}"),
    }
}

// ── §7.3 Delivery channel ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_empty_delivery_page_is_no_error_and_the_cursor_moves_on() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("delivery_empty.json"))]);
    let access = access(&state);

    let page =
        access.delivery_collect(&DeliveryQuery::new(25, None).unwrap()).await.value().unwrap();

    assert!(page.items.is_empty(), "a quiet day is not a fault");
    assert_eq!(page.next_cursor, "eyJzIjoxODAyfQ");
}

#[tokio::test]
async fn commands_stay_raw_values_so_that_a_broken_one_does_not_hold_up_the_others() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("delivery_commands.json"))]);
    let access = access(&state);

    let page =
        access.delivery_collect(&DeliveryQuery::new(25, None).unwrap()).await.value().unwrap();

    assert_eq!(page.items.len(), 2);
    let envelopes = page.envelopes();
    assert!(envelopes.iter().all(Result::is_ok));
    assert!(
        page.items[0].get("serverSignature").is_some(),
        "the raw value stays put, otherwise the signature of an honest server would no longer hold"
    );
}

#[tokio::test]
async fn an_accepted_acknowledgement_carries_an_idempotency_key_per_attempt() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("acknowledgement_receipt.json"))]);
    let access = access(&state);

    let result = access
        .acknowledge(COMMAND.parse::<CommandIdentifier>().unwrap(), &acknowledgement(), &key())
        .await;

    let call = state.call(0);
    assert_eq!(call.path, format!("/v1/delivery/commands/{COMMAND}:acknowledge"));
    assert_eq!(call.header(header::IDEMPOTENCY_KEY), Some(IDEMPOTENCY));
    assert!(call.body_text().contains("APPLIED"));
    assert!(
        matches!(result.value(), Some(AcknowledgementOutcome::Accepted(_))),
        "the server confirms with a receipt"
    );
}

#[tokio::test]
async fn an_acknowledgement_of_an_already_acknowledged_command_is_success() {
    let state = Harness::start().await;
    state.answer([Response::problem(409, golden("problem_command_already_acknowledged.json"))]);
    let access = access(&state);

    let result = access
        .acknowledge(COMMAND.parse::<CommandIdentifier>().unwrap(), &acknowledgement(), &key())
        .await;

    assert!(
        matches!(result.value(), Some(AcknowledgementOutcome::AlreadyAcknowledged)),
        "otherwise the acknowledgement would lie there forever and the heartbeat would report a \
         fault that is none"
    );
}

// ── §7.4 Ingest ─────────────────────────────────────────────────────────────────────────────

/// Contract test T24.
#[tokio::test]
async fn a_foreign_upload_target_is_a_security_abort() {
    let state = Harness::start().await;
    let access = access(&state);
    // Exactly the address from the golden file: it points at api.elasticdms.io, not at the rig.
    let grant: UploadGrant = serde_json::from_str(golden("ingest_grant.json")).unwrap();
    let file = tokio::fs::File::open("Cargo.toml").await.unwrap();

    let result = access.inbox_high_load(&grant, file, 10, Sha256Value::from_bytes([0; 32])).await;

    assert!(
        matches!(result, ApiResult::SecurityAbort { .. }),
        "a foreign uploadUrl would send the bytes of a receipt there ({result:?})"
    );
    assert_eq!(state.count(), 0, "and that before a single byte goes out");
}

#[tokio::test]
async fn the_ingest_announces_first_and_then_uploads_with_content_digest() {
    let state = Harness::start().await;
    let grant = on_harness(golden("ingest_grant.json"), &state.base);
    state.answer([
        Response::json(201, &grant),
        Response::new(204),
        Response::json(200, golden("ingest_completed.json")),
    ]);
    let access = access(&state);
    let content = b"invoice";
    let sha = edms_crypto::checksum::sha256(content);
    let directory = std::env::temp_dir().join("edms-net-contract");
    tokio::fs::create_dir_all(&directory).await.unwrap();
    let path = directory.join("invoice.pdf");
    tokio::fs::write(&path, content).await.unwrap();
    let request = UploadRequest::new(
        basket(),
        "Rechnung 2026-0412.pdf",
        "application/pdf",
        content.len() as u64,
        sha,
    )
    .unwrap();

    let grant = access.inbox_create(&request, &key()).await.value().unwrap();
    let file = tokio::fs::File::open(&path).await.unwrap();
    let uploaded = access.inbox_high_load(&grant, file, content.len() as u64, sha).await;
    let completion = access.inbox_complete(grant.upload_id, &key()).await.value().unwrap();

    assert!(uploaded.is_success(), "{uploaded:?}");
    let login = state.call(0);
    assert_eq!(login.header(header::IDEMPOTENCY_KEY), Some(IDEMPOTENCY));
    assert!(login.body_text().contains("Rechnung 2026-0412.pdf"));
    let upload = state.call(1);
    assert_eq!(upload.method, "PUT");
    assert_eq!(upload.header(header::CONTENT_DIGEST), Some(digest_header_value(&sha).as_str()));
    assert_eq!(upload.header(header::CONTENT_LENGTH), Some("7"));
    assert_eq!(upload.body, content);
    assert_eq!(state.call(2).path, "/v1/ingest-uploads/upl_01JKD8H0J2K4M6N8P0Q2R4S6T8:complete");
    assert!(
        completion.browser_target("https://app.elasticdms.io").is_ok(),
        "the capture page lies below the web interface"
    );
    assert!(
        login.body_text().contains(BASKET),
        "the submission names the basket whose rule decides where the document lands (§7.4)"
    );
}

/// A basket that is no longer there is a `404` — and nothing is filed somewhere else (§7.4).
#[tokio::test]
async fn an_ingest_into_a_vanished_basket_is_an_error_and_no_quiet_filing() {
    let state = Harness::start().await;
    state.answer([Response::problem(404, golden("problem_basket_unknown.json"))]);
    let access = access(&state);
    let sha = Sha256Value::from_bytes([0; 32]);
    let request =
        UploadRequest::new(basket(), "Rechnung 2026-0412.pdf", "application/pdf", 7, sha).unwrap();

    let result = access.inbox_create(&request, &key()).await;

    assert_eq!(result.error_kind(), Some(ErrorKind::NotFound));
    assert_eq!(state.count(), 1, "no second attempt at another basket — the client does not file");
}

// ── §7.5 Error forms ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unknown_error_type_stays_a_value_and_does_not_crash() {
    let state = Harness::start().await;
    state.answer([Response::problem(
        418,
        r#"{"type":"https://errors.elasticdms.io/exists-tomorrow","title":"New","status":418}"#,
    )]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    assert_eq!(result.error_kind(), Some(ErrorKind::Unknown));
    let problem = result.problem().unwrap();
    assert_eq!(problem.typ, "https://errors.elasticdms.io/exists-tomorrow");
    assert_eq!(problem.status, Some(418), "the value stays readable, it is only not reinterpreted");
}

#[tokio::test]
async fn a_foreign_error_type_is_not_translated_into_the_catalogue() {
    let state = Harness::start().await;
    // A `type` outside errors.elasticdms.io would otherwise suggest a device lock that an attacker
    // could set off (contract §7.5.1).
    state.answer([Response::problem(
        403,
        r#"{"type":"https://example.org/device-revoked","title":"x","status":403}"#,
    )]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    assert_eq!(result.error_kind(), Some(ErrorKind::Unknown));
    assert!(!result.is_security_event());
}

#[tokio::test]
async fn an_html_page_of_the_load_balancer_still_becomes_a_problem() {
    let state = Harness::start().await;
    state.answer([Response::new(503)
        .with_header(header::CONTENT_TYPE, "text/html")
        .with_body(b"<html><body>Service Unavailable</body></html>")]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    let problem = result.problem().expect("a problem comes out of that too");
    assert_eq!(problem.status, Some(503));
    assert_eq!(
        result.error_kind(),
        Some(ErrorKind::Unknown),
        "an error reader that fails itself swallows the message needed for fault-finding"
    );
}

#[tokio::test]
async fn a_throttling_passes_retry_after_through() {
    let state = Harness::start().await;
    state.answer([Response::problem(429, golden("problem_rate_limited.json"))
        .with_header(header::RETRY_AFTER, "30")]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    match result {
        ApiResult::SlotError { repeat_after, .. } => {
            assert_eq!(repeat_after, Some(30), "Retry-After beats every local backoff");
        }
        other => panic!("expected an error on the merits, came: {other:?}"),
    }
}

#[tokio::test]
async fn a_redirect_is_reported_and_not_followed() {
    let state = Harness::start().await;
    state
        .answer([Response::new(302)
            .with_header(header::LOCATION, "https://evil.example/v1/mirror/archives")]);
    let access = access(&state);

    let result = access.list_cases(archive(), &first_page(), None).await;

    assert_eq!(state.count(), 1, "the client follows no redirect");
    match result {
        ApiResult::NetworkError(error @ NetworkError::Redirect { .. }) => {
            assert!(error.to_string().contains("evil.example"));
        }
        other => panic!("expected a reported redirect, came: {other:?}"),
    }
}

#[tokio::test]
async fn without_a_user_token_no_listing_goes_out() {
    let state = Harness::start().await;
    let access = access_with(&state.base, &state.base, KeyBundle::full().without_user_token());

    let result = access.list_cases(archive(), &first_page(), None).await;

    assert_eq!(state.count(), 0, "without a token nothing is sent, not even an attempt");
    assert!(matches!(result, ApiResult::NetworkError(NetworkError::NoToken(KeyBinding::Session))));
}

// ── §7.0.4 Discovery ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn discovery_takes_over_the_endpoints_below_the_issuer() {
    let state = Harness::start().await;
    state.answer([
        Response::json(200, &on_harness(golden("authorization_server_metadata.json"), &state.base)),
        Response::json(200, &on_harness(golden("resource_metadata.json"), &state.base)),
    ]);
    let access = access(&state);

    let discovery = access.discover().await.value().expect("both documents fit the base");

    assert_eq!(state.call(0).path, "/.well-known/oauth-authorization-server");
    assert_eq!(state.call(1).path, "/.well-known/oauth-protected-resource");
    assert_eq!(state.call(0).header(header::DPOP), None, "the documents are public");
    assert_eq!(discovery.endpoint.token, format!("{}/v1/oauth/token", state.base));
    assert_eq!(
        discovery.endpoint.device_authorization,
        format!("{}/v1/oauth/device_authorization", state.base)
    );
}

#[tokio::test]
async fn a_foreign_issuer_is_a_security_abort() {
    let api = Harness::start().await;
    let auth = Harness::start().await;
    // The real document of the contract names `https://auth.elasticdms.io` — against a test rig on
    // the loopback that is a foreign issuer (RFC 8414 §3.3).
    auth.answer([Response::json(200, golden("authorization_server_metadata.json"))]);
    let access = access_with(&api.base, &auth.base, KeyBundle::full());

    let result = access.discover().await;

    assert!(matches!(result, ApiResult::SecurityAbort { .. }), "{result:?}");
    assert_eq!(api.count(), 0, "a foreign issuer stops the start before the resource is asked");
}

// ── §7.0.10 Heartbeat and server keys ───────────────────────────────────────────────────────

#[tokio::test]
async fn the_device_state_and_the_heartbeat_run_on_the_device_token() {
    let state = Harness::start().await;
    state.answer([
        Response::json(200, golden("device_desktop.json")),
        Response::json(200, golden("heartbeat_response_desktop.json")),
    ]);
    let access = access(&state);
    let heartbeat: Heartbeat = serde_json::from_str(golden("heartbeat_desktop.json")).unwrap();

    let device_state = access.device_status().await;
    let response = access.send_heartbeat(&heartbeat).await;

    assert!(device_state.is_success(), "{device_state:?}");
    assert_eq!(state.call(0).path, "/v1/devices/me");
    assert_eq!(state.call(1).path, format!("/v1/devices/{DEVICE}:heartbeat"));
    for number in 0..2 {
        assert_eq!(
            state.call(number).header(header::AUTHORIZATION),
            Some(format!("DPoP {DEVICE_TOKEN}").as_str()),
            "the heartbeat reports even when nobody is signed in"
        );
    }
    let response = response.value().unwrap();
    assert_eq!(response.next_heartbeat_seconds, Some(300));
    assert!(
        response.commands.is_some_and(|commands| !commands.is_empty()),
        "unsigned commands arrive; what the client does with them is decided by the engine"
    );
}

#[tokio::test]
async fn the_server_keys_come_as_an_offer_and_are_not_anchored_here() {
    let state = Harness::start().await;
    state.answer([Response::json(200, golden("server_key_set.json"))]);
    let access = access(&state);

    let offer = access.fetch_server_key().await.value().expect("the block is readable");

    assert_eq!(state.call(0).path, "/v1/server-keys");
    assert_eq!(offer.key_set_version(), 8, "the state from this contract's golden file");
    assert!(!offer.anchors().is_empty());
    assert!(
        !offer.signature_signing_key().is_empty(),
        "whether the set is adopted is decided by edms-crypto against the anchored state"
    );
}

#[tokio::test]
async fn a_listing_without_an_end_is_cut_at_the_page_limit_and_says_so() {
    // The limit is no rule of the domain but the protection against a server that never takes
    // `hasMore` back — through an error or on purpose. Without it the reconcile would run endlessly
    // and the store would fill up. Truncation is **visible**: `limit_reached` carries it upwards,
    // and the folder lays down the hint file (finding Q-12).
    let state = Harness::start().await;
    let endless = r#"{"items":[{"savedSearchId":"srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2",
        "title":"Offene Eingangsrechnungen","updatedAt":"2026-09-08T11:47:52Z"}],
        "nextCursor":"immer-weiter","hasMore":true}"#;
    state.answer(
        (0..=edms_net::server::MAX_PAGE).map(|_| Response::json(200, endless)).collect::<Vec<_>>(),
    );

    let list =
        access(&state).list_searches(&first_page(), None).await.value().expect("the listing");

    assert!(list.limit_reached, "the cut is reported, never passed over in silence");
    assert_eq!(list.pages, edms_net::server::MAX_PAGE);
    assert_eq!(list.entries.len() as u32, edms_net::server::MAX_PAGE);
    assert_eq!(
        state.count() as u32,
        edms_net::server::MAX_PAGE,
        "and after the last page the client does not ask further"
    );
}
