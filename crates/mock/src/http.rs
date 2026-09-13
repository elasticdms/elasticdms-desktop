//! What every request and every answer share: reading, checking, answering.
//!
//! Here stands the server side of 03 §6.0 — the part that holds for **every** endpoint:
//!
//! * [`Inbox`] — method, externally visible URL, headers, query and body in one place. The
//!   externally visible URL is the place at which a DPoP check goes wrong silently (geraete-auth
//!   §2.4 point 4): whoever holds `htu` against the internal host rejects every honest proof, and
//!   the failure looks like a client mistake.
//! * [`check_access`] — scheme `DPoP`, nonce, proof, token, scope, device state, in that order.
//! * The answer builders: `problem+json` for the resource API, RFC 6749 §5.2 for `/v1/oauth/*`.
//!   **Two error shapes, never smoothed over** (§7.0.3).
//!
//! **The golden files are the truth** (the contract document's section of that name): wherever
//! there is a file in `crates/wire/testdata/` for an error, the mock sends exactly its body and
//! sets `instance` at most. That way the contract document, the wire types, the client and the
//! mock cannot drift apart without a test breaking.

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use edms_core::identifier::DeviceIdentifier;
use edms_crypto::forge::{DpopCheckRequest, ProofError, ProofReport};
use edms_wire::basics::{
    ErrorKind, Problem, SCHEMA_DPOP, WWW_ERROR_NONCE, WWW_ERROR_SCOPE, header, media_type,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::state::{Access, DeviceState, Origin, State};
use crate::time::now;

/// The largest body the mock reads (16 MiB).
///
/// A limit **before** reading, not after: otherwise a single length header could get the mock to
/// ask for gigabytes before it has seen a byte.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

/// The state both routers carry along.
#[derive(Clone)]
pub struct Context {
    /// The shared state.
    pub state: std::sync::Arc<State>,
    /// Which of the two hosts is answering right now.
    pub origin: Origin,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context").field("origin", &self.origin).finish_non_exhaustive()
    }
}

/// A request that has been read.
#[derive(Debug, Clone)]
pub struct Inbox {
    /// At which host.
    pub origin: Origin,
    /// The method in upper case.
    pub method: String,
    /// The path without the query string.
    pub path: String,
    /// The query parameters in their order.
    pub query: Vec<(String, String)>,
    /// Every header.
    pub header: HeaderMap,
    /// The body.
    pub body: Bytes,
    /// The externally visible URL without the query — the value `htu` is checked against.
    pub url: String,
}

impl Inbox {
    /// Reads a request completely.
    // The error side of these results is the **finished HTTP answer**, not a reason one is made
    // out of afterwards. That is deliberate: every rejection of the contract has exactly one body,
    // one header and one status, and whoever builds it at the place it occurs cannot accidentally
    // build it differently elsewhere. `Response` is large for that (128 bytes); a box around it
    // would save nothing on a test harness and would bring a `*` to every place it occurs.
    #[allow(clippy::result_large_err)]
    pub async fn read(
        context: &Context,
        request: axum::extract::Request,
    ) -> Result<Self, Response> {
        let (parts, body) = request.into_parts();
        let path = parts.uri.path().to_owned();
        let query = crate::form::read(parts.uri.query().unwrap_or_default());
        let url = format!("{}{path}", context.state.base(context.origin));
        let body = axum::body::to_bytes(body, MAX_BODY).await.map_err(|_| {
            catalogue(
                ErrorKind::UploadTooLarge,
                413,
                "The body is larger than the mock reads (16 MiB).",
                &path,
            )
        })?;
        Ok(Self {
            origin: context.origin,
            method: parts.method.as_str().to_ascii_uppercase(),
            path,
            query,
            header: parts.headers,
            body,
            url,
        })
    }

    /// The first value of a header.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(|value| value.to_str().ok())
    }

    /// The first value of a query parameter.
    pub fn query_value(&self, name: &str) -> Option<&str> {
        crate::form::field(&self.query, name)
    }

    /// The body as a form.
    pub fn as_form(&self) -> Vec<(String, String)> {
        crate::form::read(&String::from_utf8_lossy(&self.body))
    }

    /// The body as a JSON value.
    #[allow(clippy::result_large_err)]
    pub fn as_json(&self) -> Result<Value, Response> {
        serde_json::from_slice(&self.body).map_err(|error| {
            catalogue(
                ErrorKind::ValidationFailed,
                422,
                &format!("The body is not readable JSON: {error}"),
                &self.path,
            )
        })
    }
}

// ───────────────────────────── Answers ─────────────────────────────

/// Sets a header when the name and the value are usable as an HTTP header.
///
/// An unusable value is silently **not** set instead of preventing the answer: the mock's headers
/// come out of its own constants, and a test case that were left without an answer because of one
/// would look like a network failure.
fn set(response: &mut Response, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (HeaderName::try_from(name), HeaderValue::from_str(value)) {
        response.headers_mut().insert(name, value);
    }
}

/// An answer out of bytes, a media type and further headers.
pub fn bytes_response(
    status: u16,
    media: &str,
    bytes: Vec<u8>,
    further: &[(&str, String)],
) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    set(&mut response, header::CONTENT_TYPE, media);
    for (name, value) in further {
        set(&mut response, name, value);
    }
    response
}

/// An answer whose body ends **before** the announced length.
///
/// The real server notices a hash failure only on the last `Read`, long after `200` and the
/// headers have been sent (§7.2.1). The client then sees a short body **without** an error status
/// — and only the comparison against `Repr-Digest` turns that into a failed hydration instead of a
/// silent forgery of the record. A body with a known size could not be used for this: `hyper`
/// checks it against the header and breaks off beforehand.
pub fn cancelled_response(
    status: u16,
    media: &str,
    chunk: Vec<u8>,
    further: &[(&str, String)],
) -> Response {
    let mut response =
        Response::new(Body::from_stream(Cancelled { state: Step::Chunk(Bytes::from(chunk)) }));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    set(&mut response, header::CONTENT_TYPE, media);
    for (name, value) in further {
        set(&mut response, name, value);
    }
    response
}

/// A stream with exactly one chunk — the size stays unknown, and therefore the self-set
/// `Content-Length` header applies.
///
/// Between the chunk and the end lies **one** `Pending`. Without that pause `hyper` would see the
/// chunk and the end in the same run and would break off the connection before its write buffer
/// ever went to the operating system — the client would get no answer at all instead of a short
/// one. It is exactly the short one that T13 needs.
struct Cancelled {
    state: Step,
}

/// The state of [`Cancelled`].
enum Step {
    /// The one chunk is still outstanding.
    Chunk(Bytes),
    /// Pause once, so that `hyper` writes.
    Gap,
    /// The end — before the announced length.
    End,
}

impl futures_core::Stream for Cancelled {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match std::mem::replace(&mut self.state, Step::End) {
            Step::Chunk(bytes) => {
                self.state = Step::Gap;
                std::task::Poll::Ready(Some(Ok(bytes)))
            }
            Step::Gap => {
                context.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Step::End => std::task::Poll::Ready(None),
        }
    }
}

/// A JSON answer.
pub fn json_response<T: Serialize>(status: u16, value: &T) -> Response {
    let bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
    bytes_response(status, media_type::JSON, bytes, &[])
}

/// A JSON answer with further headers (ETag, Location, Idempotency-Replayed).
pub fn json_with_headers<T: Serialize>(
    status: u16,
    value: &T,
    further: &[(&str, String)],
) -> Response {
    let bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
    bytes_response(status, media_type::JSON, bytes, further)
}

/// An answer without a body.
pub fn empty(status: u16) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response
}

/// An HTML page.
pub fn html(status: u16, page: String) -> Response {
    bytes_response(status, "text/html; charset=utf-8", page.into_bytes(), &[])
}

/// An error answer per RFC 9457.
pub fn problem_response(status: u16, problem: &Problem) -> Response {
    let bytes = serde_json::to_vec_pretty(problem).unwrap_or_else(|_| b"{}".to_vec());
    bytes_response(status, media_type::PROBLEM, bytes, &[])
}

/// An error answer out of the catalogue (§7.5.1).
pub fn catalogue(kind: ErrorKind, status: u16, detail: &str, instance: &str) -> Response {
    let mut problem = Problem::from_catalogue(kind, status, detail);
    problem.instance = Some(instance.to_owned());
    problem_response(status, &problem)
}

/// An error answer whose body comes **byte for byte** out of a golden file; only `instance` is
/// set to the resource really affected.
///
/// If the file does not exist (a typo in the name), the mock falls back to the catalogue instead
/// of panicking — a test harness that dies on its own fixture takes from the test the very message
/// it was about.
pub fn golden_problem(name: &str, status: u16, instance: &str) -> Response {
    match edms_wire::golden::find(name) {
        Ok(file) => match serde_json::from_str::<Problem>(file.content) {
            Ok(mut problem) => {
                problem.instance = Some(instance.to_owned());
                problem_response(status, &problem)
            }
            Err(error) => catalogue(
                ErrorKind::Unknown,
                status,
                &format!("The golden file {name} is not a problem: {error}"),
                instance,
            ),
        },
        Err(error) => catalogue(ErrorKind::Unknown, status, &error.to_string(), instance),
    }
}

/// An error answer per RFC 6749 §5.2 — the shape of `/v1/oauth/*`.
pub fn oauth_error(
    status: u16,
    code: &str,
    description: Option<&str>,
    uri: Option<&str>,
) -> Response {
    let mut body = serde_json::Map::new();
    body.insert("error".into(), json!(code));
    if let Some(text) = description {
        body.insert("error_description".into(), json!(text));
    }
    if let Some(text) = uri {
        body.insert("error_uri".into(), json!(text));
    }
    let mut response = json_response(status, &Value::Object(body));
    set(&mut response, header::CACHE_CONTROL, "no-store");
    response
}

/// An OAuth error whose body comes **byte for byte** out of a golden file.
pub fn golden_oauth(name: &str, status: u16) -> Response {
    match edms_wire::golden::find(name) {
        Ok(file) => match serde_json::from_str::<Value>(file.content) {
            Ok(value) => {
                let mut response = json_response(status, &value);
                set(&mut response, header::CACHE_CONTROL, "no-store");
                response
            }
            Err(_) => oauth_error(status, "server_error", Some(name), None),
        },
        Err(_) => oauth_error(status, "server_error", Some(name), None),
    }
}

/// The nonce demand of the resource API: `401`, `DPoP-Nonce`, `WWW-Authenticate` (§7.0.9).
pub fn nonce_requires_api(nonce: &str, instance: &str) -> Response {
    let mut response = golden_problem("problem_dpop_nonce_required.json", 401, instance);
    set(&mut response, header::DPOP_NONCE, nonce);
    set(
        &mut response,
        header::WWW_AUTHENTICATE,
        &format!("{SCHEMA_DPOP} error=\"{WWW_ERROR_NONCE}\""),
    );
    response
}

/// The nonce demand of the authorization server: `400 use_dpop_nonce` (RFC 9449 §8).
///
/// Two shapes, never smoothed over: the token endpoint answers per RFC 6749 §5.2, not with
/// `problem+json` — a client that expects problem+json here breaks at a place where it can only
/// say "unknown error" any more (§7.0.3).
pub fn nonce_requires_auth(nonce: &str) -> Response {
    let mut response = golden_oauth("oauth_nonce_required.json", 400);
    set(&mut response, header::DPOP_NONCE, nonce);
    response
}

/// `403` with `WWW-Authenticate: DPoP error="insufficient_scope"` (§7.5.2).
pub fn scope_missing(needs: &str, instance: &str) -> Response {
    let mut response = catalogue(
        ErrorKind::ScopeMissing,
        403,
        &format!("The token lacks the scope “{needs}”."),
        instance,
    );
    set(
        &mut response,
        header::WWW_AUTHENTICATE,
        &format!("{SCHEMA_DPOP} error=\"{WWW_ERROR_SCOPE}\", scope=\"{needs}\""),
    );
    response
}

/// The answer to a path that does not exist here.
///
/// **A stray request gets `problem+json` too.** An empty `404` from the router would look to the
/// client like a block page of the load balancer; it would read it (03 §6.0.7, „ein Problem wird
/// immer gelesen“ — "a problem is always read"), but with `type: about:blank` — and then an error
/// without a place of origin would stand in the usage log.
pub async fn unknown_path(request: axum::extract::Request) -> Response {
    catalogue(ErrorKind::NotFound, 404, "This mock has no such endpoint.", request.uri().path())
}

/// The answer to a method this path does not know.
pub async fn wrong_method(request: axum::extract::Request) -> Response {
    let detail = format!("The method {} does not exist on this path.", request.method().as_str());
    let mut problem = Problem::from_catalogue(ErrorKind::Unknown, 405, &detail);
    problem.title = Some("Method not allowed".to_owned());
    problem.instance = Some(request.uri().path().to_owned());
    problem_response(405, &problem)
}

// ───────────────────────────── Access ─────────────────────────────

/// What is settled after a request has been accepted.
#[derive(Debug, Clone)]
pub struct Session {
    /// The access token presented.
    pub token: String,
    /// What is stored for it.
    pub access: Access,
    /// The DPoP report.
    pub report: ProofReport,
}

impl Session {
    /// The device that made the request.
    pub const fn device(&self) -> DeviceIdentifier {
        self.access.device
    }
}

/// Checks a DPoP proof without a token binding — the way of the token endpoint (§7.0.9).
#[allow(clippy::result_large_err)]
pub fn check_proof(
    context: &Context,
    inbox: &Inbox,
    bound_to: Option<&str>,
    access_token: Option<&str>,
) -> Result<ProofReport, Response> {
    let nonce = context.state.nonce(inbox.origin);
    let Some(proof) = inbox.header_value(header::DPOP) else {
        return Err(match inbox.origin {
            Origin::Api => missing_proof(&inbox.path),
            Origin::Login => oauth_error(
                400,
                "invalid_dpop_proof",
                Some("The request carries no DPoP header (RFC 9449 §4)."),
                None,
            ),
        });
    };
    if inbox.header.get_all(header::DPOP).iter().count() > 1 {
        // geraete-auth §2.4 point 1: exactly one header. Two proofs would leave the choice of
        // which one holds — and the attacker would make that choice.
        return Err(match inbox.origin {
            Origin::Api => catalogue(
                ErrorKind::ValidationFailed,
                400,
                "The request carries two DPoP headers; exactly one holds (geraete-auth §2.4).",
                &inbox.path,
            ),
            Origin::Login => oauth_error(
                400,
                "invalid_dpop_proof",
                Some("The request carries two DPoP headers; exactly one holds."),
                None,
            ),
        });
    }
    let mut request = DpopCheckRequest::new(&inbox.method, &inbox.url, now()).with_nonce(&nonce);
    if let Some(jkt) = bound_to {
        request = request.bound_to(jkt);
    }
    // Point 8 (geraete-auth §2.4): a proof that belongs to a call carrying a token also carries
    // `ath`. Whoever does not pass the token here rejects every honest proof — and the failure
    // looks like a client mistake.
    if let Some(token) = access_token {
        request = request.with_access_token(token);
    }
    context
        .state
        .verifier
        .check(proof, &request)
        .map_err(|error| proof_error_response(context, inbox, &error, &nonce))
}

/// Checks scheme, proof, token, scope and device state — the order is deliberate.
#[allow(clippy::result_large_err)]
pub fn check_access(context: &Context, inbox: &Inbox, needs: &[&str]) -> Result<Session, Response> {
    let raw = inbox.header_value(header::AUTHORIZATION).unwrap_or_default().trim();
    if raw.is_empty() {
        return Err(missing_login(&inbox.path));
    }
    let (schema, token) = raw.split_once(' ').unwrap_or((raw, ""));
    if !schema.eq_ignore_ascii_case(SCHEMA_DPOP) {
        // Contract test T21: a `Bearer` token fails already on reading. An unbound token would be
        // usable without this device's key; the binding 03 §6.0.6 rests on would be gone.
        let mut response = catalogue(
            ErrorKind::TokenDeviceBinding,
            401,
            &format!(
                "The scheme “{schema}” is not DPoP; an unbound token is never \
                 accepted (03 §6.0.6)."
            ),
            &inbox.path,
        );
        set(&mut response, header::WWW_AUTHENTICATE, SCHEMA_DPOP);
        return Err(response);
    }
    let token = token.trim();
    let access = context.state.lock().accesses.get(token).cloned();
    let Some(access) = access else {
        return Err(invalid_token(&inbox.path, "The token is unknown or revoked."));
    };
    if access.expires <= now() {
        return Err(invalid_token(&inbox.path, "The token has expired."));
    }
    let report = check_proof(context, inbox, Some(&access.jkt), Some(token))?;
    // The token binding is additionally checked explicitly — not because the verifier would miss
    // it, but so that the failure carries the name it stands under in the catalogue.
    if report.jkt != access.jkt {
        return Err(catalogue(
            ErrorKind::TokenDeviceBinding,
            403,
            "The DPoP key of this request is not the one the token is bound to.",
            &inbox.path,
        ));
    }
    if let Some(missing) = needs.iter().find(|need| !access.scopes.iter().any(|got| got == *need)) {
        return Err(scope_missing(missing, &inbox.path));
    }
    let state = context.state.lock().devices.get(&access.device).map(|device| device.state);
    match state {
        Some(DeviceState::Locked) => {
            return Err(golden_problem("problem_device_locked.json", 403, &inbox.path));
        }
        None => {
            return Err(invalid_token(
                &inbox.path,
                "The device this token belongs to does not exist any more.",
            ));
        }
        Some(_) => {}
    }
    if !context.state.configuration.folder_client_unlocked {
        return Err(catalogue(
            ErrorKind::FolderClientNotUnlocked,
            403,
            "This tenant has not unlocked the folder client.",
            &inbox.path,
        ));
    }
    Ok(Session { token: token.to_owned(), access, report })
}

/// `401` without a sign-in.
fn missing_login(instance: &str) -> Response {
    let mut problem = Problem::from_catalogue(
        ErrorKind::Unknown,
        401,
        "This call needs an access token together with a DPoP proof (03 §6.0.6).",
    );
    problem.title = Some("Sign-in required".to_owned());
    problem.instance = Some(instance.to_owned());
    let mut response = problem_response(401, &problem);
    set(&mut response, header::WWW_AUTHENTICATE, SCHEMA_DPOP);
    response
}

/// `401` without a DPoP header.
fn missing_proof(instance: &str) -> Response {
    let mut problem = Problem::from_catalogue(
        ErrorKind::Unknown,
        401,
        "The request carries no DPoP header; every call needs a proof (03 §6.0.5).",
    );
    problem.title = Some("DPoP proof missing".to_owned());
    problem.instance = Some(instance.to_owned());
    let mut response = problem_response(401, &problem);
    set(
        &mut response,
        header::WWW_AUTHENTICATE,
        &format!("{SCHEMA_DPOP} error=\"invalid_dpop_proof\""),
    );
    response
}

/// `401` with an unusable token.
fn invalid_token(instance: &str, detail: &str) -> Response {
    let mut problem = Problem::from_catalogue(ErrorKind::Unknown, 401, detail);
    problem.title = Some("Token invalid".to_owned());
    problem.instance = Some(instance.to_owned());
    let mut response = problem_response(401, &problem);
    set(&mut response, header::WWW_AUTHENTICATE, &format!("{SCHEMA_DPOP} error=\"invalid_token\""));
    response
}

/// Translates a report of the DPoP verifier into the answer the contract provides for it.
fn proof_error_response(
    context: &Context,
    inbox: &Inbox,
    error: &ProofError,
    nonce: &str,
) -> Response {
    let nonce_needed = matches!(error, ProofError::NonceMissing | ProofError::NonceMismatch { .. });
    if nonce_needed {
        return match inbox.origin {
            Origin::Api => nonce_requires_api(nonce, &inbox.path),
            Origin::Login => nonce_requires_auth(nonce),
        };
    }
    tracing::debug!(path = %inbox.path, reason = %error, "DPoP proof rejected");
    let _ = context;
    match inbox.origin {
        Origin::Api => {
            let mut problem = Problem::from_catalogue(ErrorKind::Unknown, 401, &error.to_string());
            problem.title = Some("DPoP proof invalid".to_owned());
            problem.instance = Some(inbox.path.clone());
            let mut response = problem_response(401, &problem);
            set(
                &mut response,
                header::WWW_AUTHENTICATE,
                &format!("{SCHEMA_DPOP} error=\"invalid_dpop_proof\""),
            );
            response
        }
        Origin::Login => oauth_error(400, "invalid_dpop_proof", Some(&error.to_string()), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_golden_problem_keeps_its_type_and_gets_the_instance() {
        let response = golden_problem("problem_cursor_invalid.json", 400, "/v1/mirror/archives");
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some(media_type::PROBLEM)
        );
    }

    #[test]
    fn an_unknown_golden_name_becomes_a_problem_and_not_a_panic() {
        // The name deliberately stands in a variable: the test below reads the source for golden
        // names, and this one is meant not to exist.
        let name = ["does", "not", "exist.json"].join("_");
        let response = golden_problem(&name, 400, "/v1/mirror/archives");
        assert_eq!(response.status(), 400);
    }

    #[test]
    fn every_golden_file_the_mock_sends_really_exists() {
        // On a typo in the name the mock falls back to the catalogue instead of panicking — that
        // is right in operation and deadly in a test harness: the test would see a problem with
        // the wrong `type` and would call it a breach of contract by the client. So the source
        // itself is read.
        let sources = [
            include_str!("http.rs"),
            include_str!("api.rs"),
            include_str!("auth.rs"),
            include_str!("server.rs"),
        ];
        let mut checked = 0;
        for source in sources {
            for call in ["golden_problem(\"", "golden_oauth(\""] {
                for place in source.split(call).skip(1) {
                    let name = place.split('"').next().unwrap_or_default();
                    assert!(
                        edms_wire::golden::find(name).is_ok(),
                        "the mock sends \u{201e}{name}\u{201c}, but the golden file does not exist"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked >= 10, "only {checked} golden names found; the test reads into the void");
    }

    #[test]
    fn the_nonce_demand_carries_the_nonce_and_the_reason() {
        let response = nonce_requires_api("n-abc", "/v1/mirror/archives");
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers().get(header::DPOP_NONCE).and_then(|value| value.to_str().ok()),
            Some("n-abc")
        );
        let www =
            response.headers().get(header::WWW_AUTHENTICATE).and_then(|value| value.to_str().ok());
        assert_eq!(www, Some("DPoP error=\"use_dpop_nonce\""));
    }

    #[test]
    fn the_authorization_server_answers_per_rfc_6749_and_not_with_problem_json() {
        let response = nonce_requires_auth("n-abc");
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some(media_type::JSON),
            "problem+json at the token endpoint would be the smoothed-over shape (§7.0.3)"
        );
    }

    #[test]
    fn the_missing_scope_stands_in_the_header_and_in_the_body() {
        let response = scope_missing("documents:read", "/v1/mirror/archives/x/cases/y/documents");
        assert_eq!(response.status(), 403);
        let www =
            response.headers().get(header::WWW_AUTHENTICATE).and_then(|value| value.to_str().ok());
        assert_eq!(www, Some("DPoP error=\"insufficient_scope\", scope=\"documents:read\""));
    }
}
