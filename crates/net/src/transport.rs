//! The only place where HTTP connections come into being.
//!
//! It encapsulates reqwest completely: no public signature of this crate names a reqwest type.
//! Engine and app build against the contract, not against the library — a change of the HTTP stack
//! would stay a matter of this file.
//!
//! ## What hangs off every request here
//!
//! * `Elasticdms-Version`, `Accept-Language: de-DE`, `User-Agent` — to **both** hosts, to
//!   `/v1/oauth/*` as well (contract §7.0.1).
//! * `X-Request-Id`: one ULID per request. It is the bridge between a screenshot from the
//!   accounting department and the line in the server log.
//! * `DPoP` and `Authorization`, in so far as the [`CallBinding`] says so.
//!
//! ## Two clients, one reason
//!
//! reqwest knows the read limit only per client, not per request. The long poll, however, keeps
//! still for up to 25 seconds before the server answers (contract §7.3.1) — with the ordinary
//! 30-second limit every quiet wait would be close to aborting itself. Hence a second client with
//! `WaitTime + 10 s`. A side effect, and a welcome one: the long poll occupies a connection pool of
//! its own and holds no connection that a content fetch needs.
//!
//! ## No redirect
//!
//! `followRedirects` is off. Every resource of this contract has exactly one place; a redirect is
//! either an error of the counterpart or an attack, and a client that followed it would send token
//! and proof along to the new place. `Location` is reported, never followed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use edms_crypto::dpop::{self, DpopProofRequest, NonceStore};
use edms_crypto::random;
use edms_wire::basics::{SCHEMA_DPOP, header, media_type};
use edms_wire::delivery::WAIT_TIME_SECOND;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Method, Response};

use crate::binding::{CallBinding, KeySource};
use crate::challenge::{body_requires_nonce, requires_nonce};
use crate::clock::Clock;
use crate::connection::{Connection, LANGUAGE, LONG_POLL_INCREMENT};
use crate::error::{ConnectionError, NetworkError};

/// `Accept` — it does not stand in `edms_wire::basics::header`, because no part of the contract
/// evaluates it; it is sent all the same, so that a load balancer does not take an HTML block page
/// for an answer.
pub(crate) const HEADER_ACCEPT: &str = "Accept";

/// The body of a request.
pub(crate) enum Body {
    /// No body.
    No,
    /// `application/json`.
    Json(String),
    /// `application/x-www-form-urlencoded` (RFC 6749 §4.4.2).
    Form(Vec<(&'static str, String)>),
    /// A file that goes out piece by piece instead of having to fit into memory first.
    Stream(Option<tokio::fs::File>),
}

impl Body {
    /// Whether this body can be sent a second time.
    ///
    /// A stream cannot: the file would have to be reopened, and that is a decision of the engine,
    /// not of this file.
    const fn retryable(&self) -> bool {
        !matches!(self, Self::Stream(_))
    }
}

/// A request before it becomes one.
pub(crate) struct Request {
    pub(crate) method: Method,
    /// The full address **without** the query part — exactly the form that goes into the DPoP
    /// proof as `htu` (RFC 9449 §4.2).
    pub(crate) url: String,
    pub(crate) query: Vec<(&'static str, String)>,
    pub(crate) binding: CallBinding,
    pub(crate) header: Vec<(&'static str, String)>,
    pub(crate) body: Body,
    /// Whether the long-poll client with the long read limit is taken.
    pub(crate) long_poll: bool,
}

impl Request {
    /// A request without a body and without additional headers.
    pub(crate) fn new(method: Method, url: String, binding: CallBinding) -> Self {
        Self {
            method,
            url,
            query: Vec::new(),
            binding,
            header: Vec::new(),
            body: Body::No,
            long_poll: false,
        }
    }

    pub(crate) fn with_query(mut self, query: Vec<(&'static str, String)>) -> Self {
        self.query = query;
        self
    }

    pub(crate) fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.header.push((name, value.into()));
        self
    }

    pub(crate) fn with_header_if(
        self,
        name: &'static str,
        value: Option<impl Into<String>>,
    ) -> Self {
        match value {
            Some(value) => self.with_header(name, value),
            None => self,
        }
    }

    pub(crate) fn with_json(mut self, body: String) -> Self {
        self.body = Body::Json(body);
        self
    }

    pub(crate) fn with_form(mut self, field: Vec<(&'static str, String)>) -> Self {
        self.body = Body::Form(field);
        self
    }

    pub(crate) fn with_stream(mut self, file: tokio::fs::File) -> Self {
        self.body = Body::Stream(Some(file));
        self
    }

    pub(crate) fn into_long_poll(mut self) -> Self {
        self.long_poll = true;
        self
    }

    /// `GET /v1/cases` — what stands in an error message. Without a host, without a query: the
    /// host stands in the configuration, and a query parameter can carry a cursor.
    pub(crate) fn target(&self) -> String {
        let path = self
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..]))
            .unwrap_or(&self.url);
        format!("{} {path}", self.method)
    }
}

/// An answer whose body has already been read.
pub(crate) struct RawResponse {
    pub(crate) status: u16,
    pub(crate) header: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

impl RawResponse {
    /// A header, looked up in lowercase.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.header.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    /// The strong ETag of the resource, if one came.
    pub(crate) fn etag(&self) -> Option<String> {
        self.header(header::ETAG).map(ToOwned::to_owned)
    }

    /// `Idempotency-Replayed: true` (03 §6.0.10).
    pub(crate) fn idempotency_repeat(&self) -> bool {
        self.header(header::IDEMPOTENCY_REPLAYED)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }

    /// `Retry-After` in seconds.
    ///
    /// Only the form "number of seconds" is read. The second form after RFC 9110 is an HTTP date,
    /// and reckoning that against a device clock which is allowed to go wrong would yield a waiting
    /// time nobody can trust — then rather no figure and our own backoff.
    pub(crate) fn repeat_after(&self) -> Option<u64> {
        self.header(header::RETRY_AFTER)?.trim().parse().ok()
    }

    /// The place of a redirect.
    pub(crate) fn location(&self) -> Option<String> {
        self.header(header::LOCATION).map(ToOwned::to_owned)
    }
}

/// What comes back when streaming.
pub(crate) enum StreamResponse {
    /// Success: the body is not read yet and is written piece by piece.
    Stream { status: u16, header: HashMap<String, String>, response: Box<Response> },
    /// No success: the body is read, it is a problem and fits into memory.
    Failure(RawResponse),
}

/// The HTTP client together with DPoP, nonce store and the two time limits.
pub(crate) struct Transport {
    client: Client,
    long_poll: Client,
    connection: Connection,
    key: Arc<dyn KeySource>,
    clock: Arc<dyn Clock>,
    nonces: NonceStore,
}

impl Transport {
    /// Builds both clients.
    ///
    /// # Errors
    ///
    /// When the library cannot set the client up — because the platform store delivers no root
    /// certificates, for instance.
    pub(crate) fn build(
        connection: Connection,
        key: Arc<dyn KeySource>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ConnectionError> {
        let long_poll_limit =
            Duration::from_secs(u64::from(WAIT_TIME_SECOND)) + LONG_POLL_INCREMENT;
        Ok(Self {
            client: client(&connection, connection.read_limit())?,
            long_poll: client(&connection, long_poll_limit)?,
            connection,
            key,
            clock,
            nonces: NonceStore::new(),
        })
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn key_source(&self) -> &dyn KeySource {
        self.key.as_ref()
    }

    pub(crate) fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Forgets all nonces.
    ///
    /// After a change of network (Wi-Fi to Ethernet, another access point) remembered nonces point
    /// to a session of the server that may no longer exist. An old nonce dragged along costs only
    /// one additional `401`, but it costs it on every call.
    pub(crate) fn forget_nonces(&self) {
        self.nonces.empty();
    }

    /// Runs the request and reads the body.
    pub(crate) async fn run_from(&self, request: Request) -> Result<RawResponse, NetworkError> {
        let target = request.target();
        match self.run_from_stream(request).await? {
            StreamResponse::Failure(raw) => Ok(raw),
            StreamResponse::Stream { status, header, response } => {
                let body = response.bytes().await.map_err(|error| read_error(&target, &error))?;
                Ok(RawResponse { status, header, body: body.to_vec() })
            }
        }
    }

    /// Runs the request and leaves the success body unread.
    ///
    /// **Exactly one retry** after `use_dpop_nonce`, and only if a new nonce really did arrive
    /// (03 §6.0.5, contract test T9). The server *must* hand out nonces; with that the first call
    /// after every restart of the server is a `401` by design, and without the retry the client
    /// would be unusable after every maintenance. More than one retry would be an endless loop with
    /// a server that does not accept the nonce it sent itself.
    pub(crate) async fn run_from_stream(
        &self,
        mut request: Request,
    ) -> Result<StreamResponse, NetworkError> {
        let target = request.target();
        let mut used = self.nonce(&request.url)?;
        let mut repeated = false;
        loop {
            let response = self.send(&mut request, used.as_deref(), &target).await?;
            let status = response.status().as_u16();
            let header = header_of(&response);
            self.remember_nonce(&request.url, &header);

            if (200..300).contains(&status) {
                return Ok(StreamResponse::Stream { status, header, response: Box::new(response) });
            }
            let body = response.bytes().await.map_err(|error| read_error(&target, &error))?;
            let raw = RawResponse { status, header, body: body.to_vec() };
            tracing::debug!(target = %target, status, "answer without a success status");

            if !requires_new_nonce(&raw) {
                return Ok(StreamResponse::Failure(raw));
            }
            if repeated {
                return Err(NetworkError::NonceLoop { target });
            }
            // Repeat only with a **new** nonce. If the server demands one but sends none along,
            // that is its error and not the beginning of a loop.
            let new = self.nonce(&request.url)?;
            match new {
                Some(new) if Some(&new) != used.as_ref() => used = Some(new),
                _ => return Ok(StreamResponse::Failure(raw)),
            }
            if !request.body.retryable() {
                return Err(NetworkError::NonceInStream { target });
            }
            repeated = true;
        }
    }

    /// Finishes building the request and sends it off.
    async fn send(
        &self,
        request: &mut Request,
        nonce: Option<&str>,
        target: &str,
    ) -> Result<Response, NetworkError> {
        let client = if request.long_poll { &self.long_poll } else { &self.client };
        let mut builder = client.request(request.method.clone(), &request.url);
        if !request.query.is_empty() {
            builder = builder.query(&request.query);
        }
        builder = builder.header(header::X_REQUEST_ID, random::ulid(self.clock.now())?);
        for (name, value) in &request.header {
            builder = builder.header(*name, value);
        }

        if let Some(binding) = request.binding.key() {
            let key = self.key.key(binding).ok_or(NetworkError::NoKey(binding))?;
            let token = match request.binding.token() {
                Some(carrier) => {
                    Some(self.key.token(carrier).ok_or(NetworkError::NoToken(carrier))?)
                }
                None => None,
            };
            let proof = dpop::proof(
                key.as_ref(),
                &DpopProofRequest {
                    method: request.method.as_str(),
                    url: &request.url,
                    nonce,
                    access_token: token.as_ref().map(crate::Secret::open),
                },
                self.clock.now(),
            )?;
            builder = builder.header(header::DPOP, proof);
            if let Some(token) = &token {
                builder = builder
                    .header(header::AUTHORIZATION, format!("{SCHEMA_DPOP} {}", token.open()));
            }
        }

        builder = match &mut request.body {
            Body::No => builder,
            Body::Json(text) => {
                builder.header(header::CONTENT_TYPE, media_type::JSON).body(text.clone())
            }
            Body::Form(field) => builder.form(field),
            Body::Stream(file) => match file.take() {
                Some(file) => builder.body(file),
                // Can only happen when somebody sends the same stream twice; the retry path
                // prevents that above, and here stands the honest message.
                None => return Err(NetworkError::NonceInStream { target: target.to_owned() }),
            },
        };

        tracing::debug!(target = %target, nonce = nonce.is_some(), "request goes out");
        builder.send().await.map_err(|error| translate(target, &error))
    }

    /// The remembered nonce of this origin.
    fn nonce(&self, url: &str) -> Result<Option<String>, NetworkError> {
        Ok(self.nonces.nonce(url)?)
    }

    /// Remembers a nonce from **any** answer of this origin.
    ///
    /// The server may renew it at any time (RFC 9449 §8), not only in a `401`. Whoever reads it
    /// only from errors works with a stale one after every scheduled renewal and reaps an
    /// additional `401` per call.
    fn remember_nonce(&self, url: &str, header: &HashMap<String, String>) {
        let Some(nonce) = header.get(&header::DPOP_NONCE.to_ascii_lowercase()) else {
            return;
        };
        if nonce.is_empty() {
            return;
        }
        if let Err(error) = self.nonces.remember(url, nonce) {
            // An unreadable address cannot occur here — the base is checked. Should it happen all
            // the same, the call has run regardless; only the next one costs an additional round
            // trip.
            tracing::warn!(%error, "nonce could not be remembered");
        }
    }
}

/// Whether this answer demands a new nonce — in both forms.
///
/// The resource server reports `401` with `WWW-Authenticate`, the authorization server `400` with
/// `{"error":"use_dpop_nonce"}` in the body (RFC 9449 §8 as against §9). Both mean the same.
fn requires_new_nonce(raw: &RawResponse) -> bool {
    match raw.status {
        401 => requires_nonce(raw.header(header::WWW_AUTHENTICATE)),
        400 => body_requires_nonce(&raw.body),
        _ => false,
    }
}

/// All headers in lowercase; where one is set several times the last counts.
fn header_of(response: &Response) -> HashMap<String, String> {
    let mut from = HashMap::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            from.insert(name.as_str().to_ascii_lowercase(), value.to_owned());
        }
    }
    from
}

fn client(connection: &Connection, read_limit: Duration) -> Result<Client, ConnectionError> {
    let mut fixed = HeaderMap::new();
    let value = |text: &str| {
        HeaderValue::from_str(text).map_err(|error| ConnectionError::Client(error.to_string()))
    };
    fixed.insert(header::ELASTICDMS_VERSION, value(connection.api_version())?);
    fixed.insert(header::ACCEPT_LANGUAGE, value(LANGUAGE)?);
    // A default, no constraint: reqwest sets a default header only when the request does not carry
    // one of its own. The content fetch sets `*/*` — which representation comes is decided by the
    // server (contract §7.2.1), not by the client.
    fixed.insert(HEADER_ACCEPT, value(media_type::JSON)?);
    Client::builder()
        .user_agent(connection.user_identifier())
        .default_headers(fixed)
        .connect_timeout(connection.connect_timeout())
        .read_timeout(read_limit)
        // See the module head: `Location` is evaluated, never followed.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| ConnectionError::Client(error.to_string()))
}

fn translate(target: &str, error: &reqwest::Error) -> NetworkError {
    if error.is_timeout() {
        NetworkError::Timeout { target: target.to_owned() }
    } else {
        NetworkError::Connection { target: target.to_owned(), reason: error.to_string() }
    }
}

fn read_error(target: &str, error: &reqwest::Error) -> NetworkError {
    if error.is_timeout() {
        NetworkError::Timeout { target: target.to_owned() }
    } else {
        NetworkError::Connection {
            target: target.to_owned(),
            reason: format!("the body broke off: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(status: u16, header: &[(&str, &str)], body: &str) -> RawResponse {
        RawResponse {
            status,
            header: header
                .iter()
                .map(|(name, value)| ((*name).to_ascii_lowercase(), (*value).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn both_forms_of_the_nonce_prompt_are_recognised() {
        assert!(requires_new_nonce(&raw(
            401,
            &[("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#)],
            "",
        )));
        assert!(requires_new_nonce(&raw(400, &[], r#"{"error":"use_dpop_nonce"}"#)));
    }

    #[test]
    fn an_ordinary_error_demands_no_new_nonce() {
        assert!(!requires_new_nonce(&raw(403, &[("WWW-Authenticate", "DPoP")], "")));
        assert!(!requires_new_nonce(&raw(400, &[], r#"{"error":"invalid_grant"}"#)));
        // The same header, but with 400: there the body counts, not the header (RFC 9449 §9).
        assert!(!requires_new_nonce(&raw(
            400,
            &[("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#)],
            "{}",
        )));
    }

    #[test]
    fn headers_are_found_regardless_of_their_spelling() {
        let response = raw(200, &[("ETag", "\"12\""), ("Idempotency-Replayed", "TRUE")], "");
        assert_eq!(response.etag().as_deref(), Some("\"12\""));
        assert!(response.idempotency_repeat());
        assert_eq!(response.header("etag"), Some("\"12\""));
    }

    #[test]
    fn retry_after_is_read_only_as_a_number_of_seconds() {
        assert_eq!(raw(429, &[("Retry-After", " 30 ")], "").repeat_after(), Some(30));
        assert_eq!(
            raw(429, &[("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")], "").repeat_after(),
            None,
            "an HTTP date reckoned against a device clock would yield a waiting time without worth"
        );
    }

    #[test]
    fn a_stream_is_not_repeatable_a_form_is() {
        assert!(!Body::Stream(None).retryable());
        assert!(Body::Json("{}".into()).retryable());
        assert!(Body::Form(vec![("a", "b".into())]).retryable());
        assert!(Body::No.retryable());
    }

    #[test]
    fn the_target_of_a_request_names_method_and_path_without_the_host() {
        let request = Request::new(
            Method::GET,
            "https://api.elasticdms.io/v1/cases".into(),
            CallBinding::Session,
        );
        assert_eq!(request.target(), "GET /v1/cases");
    }
}
