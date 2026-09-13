//! [`ServerAccess`] — the one implementation of [`Server`] that really sends.
//!
//! Here stands, per endpoint, exactly what the contract says about it and nothing beyond: which key
//! proves, which token authorises, which status values are success and what the client does
//! **not** do. The four places at which this crate knows more than "HTTP":
//!
//! 1. **`412` is success at the enrolment** (contract tests T2, T3) — and `409` is not (T5).
//! 2. **A listing is paged through completely**, up to [`MAX_PAGE`]; unfiltered, and a truncation
//!    is reported instead of passed over in silence (contract test T11, finding Q-12).
//! 3. **Before the first byte of a content** four headers are checked against the row of the
//!    listing; afterwards the crate counts the bytes against `Content-Length` (T13).
//! 4. **A renewal is never repeated blindly** (T14).
//!
//! Everything beyond that which is a decision — pin, erase, display, anchor — is made by the
//! engine.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{ArchiveIdentifier, CommandIdentifier, UploadIdentifier};
use edms_core::namespace::Location;
use edms_crypto::assertion;
use edms_crypto::key_set::KeyOffer;
use edms_wire::basics::{ErrorKind, Page, Problem, digest_header_value, header, media_type};
use edms_wire::content::{ContentHeader, encode_application, path_content};
use edms_wire::delivery::{
    Acknowledgement, AcknowledgementReceipt, DeliveryPage, DeliveryQuery, PATH_COMMAND,
    path_acknowledgement,
};
use edms_wire::device::{
    DeviceObject, EnrollmentRequest, Heartbeat, HeartbeatResponse, PATH_OWN_IT_DEVICE,
    PATH_SERVER_KEY, path_device, path_heartbeat,
};
use edms_wire::discovery::{
    AuthorizationServerMetadata, PATH_AS_METADATA, PATH_RESOURCE_METADATA, ResourceMetadata,
};
use edms_wire::ingest::{
    PATH_UPLOAD, UploadCompletion, UploadGrant, UploadRequest, path_completion,
};
use edms_wire::login::{
    DEVICE_SCOPES, DeviceAuthorization, DeviceAuthorizationRequest, DeviceFlowStep, OauthError,
    OauthErrorCode, PATH_DEVICE_AUTHORIZATION, PATH_REVOCATION, PATH_TOKEN, RefreshStep,
    RevocationRequest, SLOW_DOWN_INCREMENT_SECONDS, TokenRequest, TokenResponse, USER_SCOPES,
    scope_text,
};
use edms_wire::namespace::{
    ArchiveRow, BasketRow, CaseRow, DocumentPage, DocumentRow, ListQuery, PATH_ARCHIVES,
    PATH_BASKETS, PATH_SEARCHES, SearchRow, path_cases, path_document,
};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::binding::{CallBinding, KeyBinding, KeySource};
use crate::challenge::step_up;
use crate::clock::{Clock, SystemClock};
use crate::connection::Connection;
use crate::error::{ConnectionError, NetworkError};
use crate::idempotency::IdempotencyKey;
use crate::result::{ApiResult, Success};
use crate::secret::Secret;
use crate::server::{
    AcknowledgementOutcome, ContentReport, Discovery, DocumentList, EnrollmentReport, List,
    LoginIntent, LoginOutcome, LoginStep, MAX_PAGE, Server,
};
use crate::transport::{RawResponse, Request, StreamResponse, Transport};

/// The header name `edms-wire` does not carry, because it is no rule of the contract.
const ACCEPT: &str = "Accept";

/// The HTTP access to the elasticdms server.
pub struct ServerAccess {
    transport: Transport,
}

/// Without secrets, without keys: what stands here may go into any log.
impl fmt::Debug for ServerAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerAccess")
            .field("api", &self.transport.connection().api_base())
            .field("auth", &self.transport.connection().auth_base())
            .field("device", &self.transport.connection().device())
            .finish_non_exhaustive()
    }
}

impl ServerAccess {
    /// An access with the operating system's clock.
    ///
    /// # Errors
    ///
    /// When the HTTP client cannot be set up (see [`ConnectionError::Client`]).
    pub fn new(connection: Connection, key: Arc<dyn KeySource>) -> Result<Self, ConnectionError> {
        Self::with_clock(connection, key, Arc::new(SystemClock))
    }

    /// An access with a clock of its own — for tests and for a time that has been set and checked.
    ///
    /// # Errors
    ///
    /// As [`ServerAccess::new`].
    pub fn with_clock(
        connection: Connection,
        key: Arc<dyn KeySource>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ConnectionError> {
        Ok(Self { transport: Transport::build(connection, key, clock)? })
    }

    /// The connection this access speaks against.
    pub fn connection(&self) -> &Connection {
        self.transport.connection()
    }

    /// Forgets all DPoP nonces — after a change of network.
    pub fn at_network_change(&self) {
        self.transport.forget_nonces();
    }

    // ── Building blocks ─────────────────────────────────────────────────────────────────────

    fn api(&self, path: &str) -> String {
        self.transport.connection().api(path)
    }

    fn auth(&self, path: &str) -> String {
        self.transport.connection().auth(path)
    }

    fn source(&self) -> &dyn KeySource {
        self.transport.key_source()
    }

    /// The device's client assertion (`private_key_jwt`, RFC 7523 §2.2).
    ///
    /// Always with the **device** key, even when the token is bound to the session key: the
    /// assertion proves that this enrolled device is asking — it is the defence against reverse
    /// phishing of the device flow (geraete-auth §2.4).
    fn assertion(&self) -> Result<String, NetworkError> {
        let binding = KeyBinding::Device;
        let key = self.source().key(binding).ok_or(NetworkError::NoKey(binding))?;
        // Without a `kid` the key cannot be named to the server; that is the same as if it did
        // not exist (`400 device-assertion-invalid`).
        let kid = self.source().device_kid().ok_or(NetworkError::NoKey(binding))?;
        Ok(assertion::client_assertion(
            key.as_ref(),
            &kid,
            self.transport.connection().device(),
            self.transport.connection().auth_base(),
            self.transport.clock().now(),
        )?)
    }

    /// The RFC 7638 thumbprint of the **session** key; it goes out as `dpop_jkt`.
    fn session_jkt(&self) -> Result<String, NetworkError> {
        let binding = KeyBinding::Session;
        let key = self.source().key(binding).ok_or(NetworkError::NoKey(binding))?;
        Ok(key.public().thumbprint())
    }

    /// A call whose answer is JSON.
    fn json_request(&self, method: Method, url: String, binding: CallBinding) -> Request {
        Request::new(method, url, binding).with_header(ACCEPT, media_type::JSON)
    }

    /// Fetches a JSON value and reads it into its type.
    async fn fetch<T: DeserializeOwned>(
        &self,
        request: Request,
        success_status: &[u16],
        what: &'static str,
    ) -> ApiResult<T> {
        let raw = match self.transport.run_from(request).await {
            Ok(raw) => raw,
            Err(error) => return error.into(),
        };
        if !success_status.contains(&raw.status) {
            return failure(&raw, what);
        }
        match read(&raw, what) {
            Ok(value) => success(&raw, value),
            Err(error) => error.into(),
        }
    }

    /// A single attempt at the token endpoint.
    ///
    /// The proof carries the **session** key, because the token is bound to it (`dpop_jkt`,
    /// RFC 9449 §5) — the assertion in the form, by contrast, the device key.
    async fn token_attempt(
        &self,
        request: TokenRequest,
        binding: CallBinding,
        what: &'static str,
    ) -> Result<TokenStep, NetworkError> {
        let request = self
            .json_request(Method::POST, self.auth(PATH_TOKEN), binding)
            .with_form(request.to_form());
        let raw = self.transport.run_from(request).await?;
        if raw.status == 200 {
            return Ok(TokenStep::Issued(Box::new(read::<TokenResponse>(&raw, what)?), raw));
        }
        Ok(TokenStep::Error(oauth_error(&raw), raw))
    }

    /// All pages of a listing with a uniform page envelope.
    async fn all_pages<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &ListQuery,
        known_etag: Option<&str>,
        what: &'static str,
    ) -> ApiResult<List<T>> {
        let limit = query.limit();
        let mut cursor = query.cursor().map(ToOwned::to_owned);
        let mut list = List { entries: Vec::new(), etag: None, pages: 0, limit_reached: false };
        loop {
            let page_query = match ListQuery::new(cursor.clone(), Some(limit)) {
                Ok(query) => query,
                Err(error) => return contract_breach(&error),
            };
            let mut request = self
                .json_request(Method::GET, self.api(path), CallBinding::Session)
                .with_query(page_query.to_query());
            // `If-None-Match` applies to the listing, not to the page: only the first request
            // carries it, otherwise the server would answer `304` in the middle of the paging and
            // the listing would have a hole.
            if list.pages == 0 {
                request = request.with_header_if(header::IF_NONE_MATCH, known_etag);
            }
            let raw = match self.transport.run_from(request).await {
                Ok(raw) => raw,
                Err(error) => return error.into(),
            };
            if raw.status != 200 {
                return failure(&raw, what);
            }
            let page: Page<T> = match read(&raw, what) {
                Ok(page) => page,
                Err(error) => return error.into(),
            };
            let continuation = match page.continuation() {
                Ok(continuation) => continuation.map(ToOwned::to_owned),
                Err(error) => return contract_breach(&error),
            };
            if list.pages == 0 {
                list.etag = raw.etag();
            }
            list.pages += 1;
            list.entries.extend(page.items);
            match continuation {
                Some(next) if list.pages < MAX_PAGE => cursor = Some(next),
                Some(_) => {
                    tracing::warn!(what, pages = list.pages, "page limit reached");
                    list.limit_reached = true;
                    break;
                }
                None => break,
            }
        }
        let etag = list.etag.clone();
        ApiResult::Success(Success { value: list, etag, idempotency_repeat: false, status: 200 })
    }
}

/// The intermediate result of a token attempt.
enum TokenStep {
    Issued(Box<TokenResponse>, RawResponse),
    Error(OauthError, RawResponse),
}

impl Server for ServerAccess {
    async fn discover(&self) -> ApiResult<Discovery> {
        let what = "Discovery";
        let login_server: AuthorizationServerMetadata = match self
            .fetch::<AuthorizationServerMetadata>(
                self.json_request(Method::GET, self.auth(PATH_AS_METADATA), CallBinding::Without),
                &[200],
                what,
            )
            .await
            .success_or()
        {
            Ok(success) => success.value,
            Err(other) => return other,
        };
        // Checked **at once**, not only after the second document: if the sign-in document names a
        // foreign issuer, the start is over, and the client does not even ask further
        // (RFC 8414 §3.3).
        let endpoint = match login_server.check(self.transport.connection().auth_base()) {
            Ok(endpoint) => endpoint,
            Err(error) => return security_abort(&error),
        };

        let resource: ResourceMetadata = match self
            .fetch::<ResourceMetadata>(
                self.json_request(
                    Method::GET,
                    self.api(PATH_RESOURCE_METADATA),
                    CallBinding::Without,
                ),
                &[200],
                what,
            )
            .await
            .success_or()
        {
            Ok(success) => success.value,
            Err(other) => return other,
        };
        let connection = self.transport.connection();
        if let Err(error) = resource.check(connection.api_base(), connection.auth_base()) {
            return security_abort(&error);
        }
        ApiResult::success(Discovery { endpoint, authorization_server: login_server, resource })
    }

    async fn register_device(&self, request: &EnrollmentRequest) -> ApiResult<EnrollmentReport> {
        let what = "the enrolment";
        let body = match write(request, what) {
            Ok(body) => body,
            Err(error) => return error.into(),
        };
        let request = self
            .json_request(
                Method::PUT,
                self.api(&path_device(self.transport.connection().device())),
                // Neither `Authorization` nor DPoP (contract test T1).
                CallBinding::Without,
            )
            .with_header(header::IF_NONE_MATCH, "*")
            .with_json(body);
        let raw = match self.transport.run_from(request).await {
            Ok(raw) => raw,
            Err(error) => return error.into(),
        };
        match raw.status {
            // 201: newly created. 200: the device already existed, the server gave it back.
            201 | 200 => match read::<DeviceObject>(&raw, what) {
                Ok(device) => success(
                    &raw,
                    EnrollmentReport { inventory_already: raw.status == 200, device: Some(device) },
                ),
                Err(error) => error.into(),
            },
            // 412: `If-None-Match: *` took hold — the device already stands under this
            // identifier. **Success** (T2): only this way can a retry after a network break be told
            // apart from a real collision (`409`, T5). A body is permitted but not demanded; if it
            // is missing, the engine reads it afterwards with `device_status`.
            412 => success(
                &raw,
                EnrollmentReport { inventory_already: true, device: device_from(&raw) },
            ),
            _ => failure(&raw, what),
        }
    }

    async fn device_status(&self) -> ApiResult<DeviceObject> {
        self.fetch(
            self.json_request(Method::GET, self.api(PATH_OWN_IT_DEVICE), CallBinding::Device),
            &[200],
            "the device status",
        )
        .await
    }

    async fn send_heartbeat(&self, heartbeat: &Heartbeat) -> ApiResult<HeartbeatResponse> {
        let what = "the heartbeat";
        let body = match write(heartbeat, what) {
            Ok(body) => body,
            Err(error) => return error.into(),
        };
        self.fetch(
            self.json_request(
                Method::POST,
                self.api(&path_heartbeat(self.transport.connection().device())),
                CallBinding::Device,
            )
            .with_json(body),
            &[200],
            what,
        )
        .await
    }

    async fn fetch_device_token(&self) -> ApiResult<TokenResponse> {
        let what = "the device token";
        let client_assertion = match self.assertion() {
            Ok(assertion) => assertion,
            Err(error) => return error.into(),
        };
        let request = TokenRequest::ClientCredentials {
            client_assertion,
            scope: scope_text(&DEVICE_SCOPES),
            resource: self.transport.connection().api_base().to_owned(),
        };
        match self.token_attempt(request, CallBinding::DeviceWithoutToken, what).await {
            Err(error) => error.into(),
            Ok(TokenStep::Issued(token, raw)) => success(&raw, *token),
            Ok(TokenStep::Error(error, raw)) => oauth_failure(&error, &raw),
        }
    }

    async fn fetch_server_key(&self) -> ApiResult<KeyOffer> {
        let what = "the server keys";
        let read = match self
            .fetch::<serde_json::Value>(
                self.json_request(Method::GET, self.api(PATH_SERVER_KEY), CallBinding::Device),
                &[200],
                what,
            )
            .await
            .success_or()
        {
            Ok(read) => read,
            Err(other) => return other,
        };
        match KeyOffer::from_json(&read.value) {
            Ok(offer) => ApiResult::Success(Success {
                value: offer,
                etag: read.etag,
                idempotency_repeat: read.idempotency_repeat,
                status: read.status,
            }),
            Err(error) => NetworkError::Crypto(error).into(),
        }
    }

    async fn start_device_login(&self, intent: &LoginIntent) -> ApiResult<DeviceAuthorization> {
        let what = "the start of the sign-in";
        let client_assertion = match self.assertion() {
            Ok(assertion) => assertion,
            Err(error) => return error.into(),
        };
        let dpop_jkt = match self.session_jkt() {
            Ok(jkt) => jkt,
            Err(error) => return error.into(),
        };
        let scope = if intent.scopes.is_empty() {
            scope_text(&USER_SCOPES)
        } else {
            scope_text(&intent.scopes.iter().map(String::as_str).collect::<Vec<_>>())
        };
        let form = DeviceAuthorizationRequest {
            client_assertion,
            scope,
            resource: self.transport.connection().api_base().to_owned(),
            acr_values: intent.acr_values.clone(),
            dpop_jkt,
            login_hint: intent.login_hint.clone(),
            max_age: intent.max_age,
            prompt: intent.prompt.clone(),
        };
        // **No** DPoP header: RFC 9449 §5 binds the future token over `dpop_jkt`; the proof comes
        // only at the collection, and then with the session key.
        let request = self
            .json_request(Method::POST, self.auth(PATH_DEVICE_AUTHORIZATION), CallBinding::Without)
            .with_form(form.to_form());
        let raw = match self.transport.run_from(request).await {
            Ok(raw) => raw,
            Err(error) => return error.into(),
        };
        if raw.status != 200 {
            return oauth_failure(&oauth_error(&raw), &raw);
        }
        match read::<DeviceAuthorization>(&raw, what) {
            Ok(login) => success(&raw, login),
            Err(error) => error.into(),
        }
    }

    async fn wait_on_token(
        &self,
        login: &DeviceAuthorization,
        observer: &(dyn Fn(LoginStep) + Send + Sync),
    ) -> ApiResult<LoginOutcome> {
        let what = "the user token";
        let mut interval = login.interval_second().max(1);
        // Measured over the sum of the waiting times, not over the device clock: that one is
        // allowed to go wrong, and a flow that ended by it would end at the wrong time.
        let mut elapsed = 0_u64;
        while elapsed < login.expires_in {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            elapsed = elapsed.saturating_add(interval);

            let client_assertion = match self.assertion() {
                Ok(assertion) => assertion,
                Err(error) => return error.into(),
            };
            let request = TokenRequest::DeviceCode {
                device_code: login.device_code.clone(),
                client_assertion,
            };
            let attempt = self.token_attempt(request, CallBinding::SessionWithoutToken, what).await;
            let (error, raw) = match attempt {
                Ok(TokenStep::Issued(token, raw)) => {
                    observer(LoginStep::Decided);
                    return success(&raw, LoginOutcome::Issued(token));
                }
                Ok(TokenStep::Error(error, raw)) => (error, raw),
                // The network does not end the flow: the device code stays valid, and the human
                // may be standing in front of the browser right now.
                Err(network) if network.may_repeated_become() => {
                    observer(LoginStep::NetworkFault(network.to_string()));
                    continue;
                }
                Err(network) => return network.into(),
            };

            match error.in_device_flow() {
                DeviceFlowStep::Pending => observer(LoginStep::Pending),
                DeviceFlowStep::Slower => {
                    // **Permanently** by five seconds (RFC 8628 §3.5). Whoever forgets the
                    // supplement after the next attempt throttles himself into an endless loop.
                    interval = interval
                        .saturating_add(SLOW_DOWN_INCREMENT_SECONDS)
                        .max(raw.repeat_after().unwrap_or(0));
                    observer(LoginStep::Slower { interval_second: interval });
                }
                // The nonce lies in the store now; the next attempt carries it.
                DeviceFlowStep::NonceNeeded => {
                    observer(LoginStep::NetworkFault(
                        "The server demanded a new DPoP nonce.".to_owned(),
                    ));
                }
                DeviceFlowStep::Expired => {
                    observer(LoginStep::Decided);
                    return success(&raw, LoginOutcome::Expired);
                }
                DeviceFlowStep::Rejected => {
                    observer(LoginStep::Decided);
                    return success(&raw, LoginOutcome::Rejected(error));
                }
                DeviceFlowStep::Final => {
                    observer(LoginStep::Decided);
                    return oauth_failure(&error, &raw);
                }
            }
        }
        ApiResult::success(LoginOutcome::Expired)
    }

    async fn refresh_token(&self, refresh_token: &Secret) -> ApiResult<TokenResponse> {
        let what = "the renewal";
        let client_assertion = match self.assertion() {
            Ok(assertion) => assertion,
            Err(error) => return error.into(),
        };
        let request = TokenRequest::RefreshToken {
            refresh_token: refresh_token.open().to_owned(),
            client_assertion,
        };
        let attempt = self.token_attempt(request, CallBinding::SessionWithoutToken, what).await;
        let (error, raw) = match attempt {
            Ok(TokenStep::Issued(token, raw)) => return success(&raw, *token),
            Ok(TokenStep::Error(error, raw)) => (error, raw),
            // T14: if the line breaks off, nobody knows whether the server has rotated. A second
            // attempt with the same token would revoke the whole family — so an error of its own
            // that says exactly that, instead of an ordinary network error that somebody repeats.
            Err(network) if network.may_repeated_become() => {
                return NetworkError::RefreshUncertain { reason: network.to_string() }.into();
            }
            Err(network) => return network.into(),
        };
        match error.at_refresh() {
            // The family is revoked across devices: somebody else has used the same token. That is
            // a security event and not an end of session (contract §7.0.8).
            RefreshStep::FamilyRevoked => ApiResult::SecurityAbort {
                notice: format!(
                    "The refresh token has already been redeemed; the token family is revoked. \
                     That means somebody else has used the same token: {}",
                    error.error_description.clone().unwrap_or_else(|| error.error.to_string())
                ),
                problem: Some(oauth_problem(&error, raw.status)),
            },
            _ => oauth_failure(&error, &raw),
        }
    }

    async fn revoke(&self, refresh_token: &Secret) -> ApiResult<()> {
        let what = "the revocation";
        let client_assertion = match self.assertion() {
            Ok(assertion) => assertion,
            Err(error) => return error.into(),
        };
        let form = RevocationRequest { token: refresh_token.open().to_owned(), client_assertion };
        // [GAP → PROPOSAL] The contract says nothing about DPoP for `/v1/oauth/revoke`. A proof
        // with the session key is sent, because 03 §6.0.5 demands it for **every** call and an
        // endpoint that does not check it forgives an additional header — the other way round it
        // does not.
        let request = self
            .json_request(
                Method::POST,
                self.auth(PATH_REVOCATION),
                CallBinding::SessionWithoutToken,
            )
            .with_form(form.to_form());
        let raw = match self.transport.run_from(request).await {
            Ok(raw) => raw,
            Err(error) => return error.into(),
        };
        // RFC 7009: the answer is always `200`, for an unknown token too. The status is therefore
        // no proof — the engine clears up in any case.
        if (200..300).contains(&raw.status) { success(&raw, ()) } else { failure(&raw, what) }
    }

    async fn list_baskets(
        &self,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> ApiResult<List<BasketRow>> {
        self.all_pages(PATH_BASKETS, query, known_etag, "the basket listing").await
    }

    async fn list_archives(
        &self,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> ApiResult<List<ArchiveRow>> {
        self.all_pages(PATH_ARCHIVES, query, known_etag, "the archive listing").await
    }

    async fn list_cases(
        &self,
        archive: ArchiveIdentifier,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> ApiResult<List<CaseRow>> {
        // The archive stands in the path: a case file exists only under one, and there is no
        // listing across archives this crate could ask instead (ADR-D11).
        self.all_pages(&path_cases(archive), query, known_etag, "the case listing").await
    }

    async fn list_searches(
        &self,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> ApiResult<List<SearchRow>> {
        self.all_pages(PATH_SEARCHES, query, known_etag, "the search listing").await
    }

    async fn list_document(
        &self,
        location: Location,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> ApiResult<DocumentList> {
        let what = "the document listing";
        let path = path_document(location);
        let limit = query.limit();
        let mut cursor = query.cursor().map(ToOwned::to_owned);
        let mut list = DocumentList {
            rows: Vec::new(),
            etag: None,
            pages: 0,
            limit_reached: false,
            total_capped: false,
            display_limit: 0,
            refine_url: None,
        };
        loop {
            let page_query = match ListQuery::new(cursor.clone(), Some(limit)) {
                Ok(query) => query,
                Err(error) => return contract_breach(&error),
            };
            let mut request = self
                .json_request(Method::GET, self.api(&path), CallBinding::Session)
                .with_query(page_query.to_query());
            if list.pages == 0 {
                request = request.with_header_if(header::IF_NONE_MATCH, known_etag);
            }
            let raw = match self.transport.run_from(request).await {
                Ok(raw) => raw,
                Err(error) => return error.into(),
            };
            if raw.status != 200 {
                return failure(&raw, what);
            }
            let page: DocumentPage = match read(&raw, what) {
                Ok(page) => page,
                Err(error) => return error.into(),
            };
            // `continuation` checks the whole page: the display limit, every version mark and the
            // contradiction between `hasMore` and `nextCursor`. A listing out of which single rows
            // quietly fell would be an incomplete folder.
            let continuation = match page.continuation() {
                Ok(continuation) => continuation.map(ToOwned::to_owned),
                Err(error) => return contract_breach(&error),
            };
            if list.pages == 0 {
                list.etag = raw.etag();
            }
            list.pages += 1;
            // Once truncated, always truncated: if any page reports the truncation, it holds for
            // the whole listing. And the address for refining stays put even when a later page does
            // not repeat it — otherwise the hint would disappear exactly where the user needs it
            // (finding Q-12).
            list.total_capped |= page.total_capped;
            list.display_limit = page.display_limit;
            if page.refine_url.is_some() {
                list.refine_url = page.refine_url.clone();
            }
            list.rows.extend(page.items);
            match continuation {
                Some(next) if list.pages < MAX_PAGE => cursor = Some(next),
                Some(_) => {
                    tracing::warn!(
                        pages = list.pages,
                        "page limit of the document listing reached"
                    );
                    list.limit_reached = true;
                    break;
                }
                None => break,
            }
        }
        let etag = list.etag.clone();
        ApiResult::Success(Success { value: list, etag, idempotency_repeat: false, status: 200 })
    }

    async fn load_content(
        &self,
        row: &DocumentRow,
        application: Option<&str>,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> ApiResult<ContentReport> {
        let what = "the content";
        let version = match row.etag() {
            Ok(etag) => etag,
            Err(error) => return contract_breach(&error),
        };
        let mut request = Request::new(
            Method::GET,
            self.api(&path_content(row.document_id)),
            CallBinding::Session,
        )
        // The server chooses the representation (redacted before viewing, never the original);
        // hence no narrow `Accept` that would rule a version out.
        .with_header(ACCEPT, "*/*")
        .with_header(header::IF_MATCH, version);
        if let Some(name) = application {
            match encode_application(name) {
                Ok(value) => request = request.with_header(header::REQUESTING_APPLICATION, value),
                // An observation that falls away is no reason to deny the user his document — it
                // stands in the log and the header is left out.
                Err(error) => tracing::warn!(%error, "program name not encodable"),
            }
        }

        let stream = match self.transport.run_from_stream(request).await {
            Ok(stream) => stream,
            Err(error) => return error.into(),
        };
        let (status, header, response) = match stream {
            StreamResponse::Stream { status, header, response } => (status, header, response),
            StreamResponse::Failure(raw) => return failure(&raw, what),
        };
        let fetch = |name: &str| header.get(&name.to_ascii_lowercase()).map(String::as_str);
        let content_header = match ContentHeader::from_header(
            fetch(header::CONTENT_TYPE),
            fetch(header::CONTENT_LENGTH),
            fetch(header::ETAG),
            fetch(header::REPR_DIGEST),
        ) {
            Ok(header) => header,
            Err(error) => return NetworkError::ContentHeader(error).into(),
        };
        // Before the first byte: if version, checksum or size deviate, the document has changed
        // since the listing. The placeholder would otherwise carry the values of a different
        // version, and the file system would later report a corruption instead of a change.
        if let Err(error) = content_header.check_against(row) {
            return NetworkError::ContentHeader(error).into();
        }

        let mut response = *response;
        let mut written = 0_u64;
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(error) => {
                    return NetworkError::Connection {
                        target: format!("GET {}", path_content(row.document_id)),
                        reason: format!("the body broke off: {error}"),
                    }
                    .into();
                }
            };
            written = written.saturating_add(chunk.len() as u64);
            if written > content_header.length {
                // Reading on would be an unbounded body in a bounded file.
                return NetworkError::Incomplete {
                    expected: content_header.length,
                    actual: written,
                }
                .into();
            }
            if let Err(error) = sink.write_all(&chunk).await {
                return NetworkError::Sink { reason: error.to_string() }.into();
            }
        }
        if let Err(error) = sink.flush().await {
            return NetworkError::Sink { reason: error.to_string() }.into();
        }
        // The server notices a hash error only at the last `Read`, long after `200` and the headers
        // have been sent (contract test T13). A short body therefore arrives with `200` — only this
        // comparison turns it into a failed hydration.
        if written != content_header.length {
            return NetworkError::Incomplete { expected: content_header.length, actual: written }
                .into();
        }
        ApiResult::Success(Success {
            value: ContentReport { header: content_header, bytes: written },
            etag: fetch(header::ETAG).map(ToOwned::to_owned),
            idempotency_repeat: false,
            status,
        })
    }

    async fn delivery_collect(&self, query: &DeliveryQuery) -> ApiResult<DeliveryPage> {
        self.fetch(
            self.json_request(Method::GET, self.api(PATH_COMMAND), CallBinding::Device)
                .with_query(query.to_query())
                .into_long_poll(),
            &[200],
            "the delivery",
        )
        .await
    }

    async fn acknowledge(
        &self,
        command: CommandIdentifier,
        acknowledgement: &Acknowledgement,
        key: &IdempotencyKey,
    ) -> ApiResult<AcknowledgementOutcome> {
        let what = "the acknowledgement";
        let body = match write(acknowledgement, what) {
            Ok(body) => body,
            Err(error) => return error.into(),
        };
        let request = self
            .json_request(
                Method::POST,
                self.api(&path_acknowledgement(command)),
                CallBinding::Device,
            )
            .with_header(header::IDEMPOTENCY_KEY, key.value())
            .with_json(body);
        let raw = match self.transport.run_from(request).await {
            Ok(raw) => raw,
            Err(error) => return error.into(),
        };
        match raw.status {
            200 | 201 => match read::<AcknowledgementReceipt>(&raw, what) {
                Ok(receipt) => success(&raw, AcknowledgementOutcome::Accepted(receipt)),
                Err(error) => error.into(),
            },
            // The server has had the acknowledgement for a long time. For the client that is
            // **success**: otherwise it would stay in the queue forever and the heartbeat would
            // permanently report a fault that is none (contract §7.3.6).
            409 if Problem::read(raw.status, &raw.body).error_kind()
                == ErrorKind::CommandAlreadyAcknowledged =>
            {
                success(&raw, AcknowledgementOutcome::AlreadyAcknowledged)
            }
            _ => failure(&raw, what),
        }
    }

    async fn inbox_create(
        &self,
        request: &UploadRequest,
        key: &IdempotencyKey,
    ) -> ApiResult<UploadGrant> {
        let what = "the ingest";
        let body = match write(request, what) {
            Ok(body) => body,
            Err(error) => return error.into(),
        };
        self.fetch(
            self.json_request(Method::POST, self.api(PATH_UPLOAD), CallBinding::Session)
                .with_header(header::IDEMPOTENCY_KEY, key.value())
                .with_json(body),
            &[201, 200],
            what,
        )
        .await
    }

    async fn inbox_high_load(
        &self,
        grant: &UploadGrant,
        file: tokio::fs::File,
        length: u64,
        sha256: Sha256Value,
    ) -> ApiResult<()> {
        let what = "the upload";
        // Contract test T24: an address out of an answer is used only below its base. An
        // `uploadUrl` on a foreign host would send the bytes of a receipt there, and the user would
        // notice nothing, because the operation succeeds.
        let target = match grant.target(self.transport.connection().api_base()) {
            Ok(target) => target.to_owned(),
            Err(error) => return security_abort(&error),
        };
        let request = Request::new(Method::PUT, target, CallBinding::Session)
            .with_header(ACCEPT, media_type::JSON)
            // The server cannot otherwise tell whether a differing file arrived or the line
            // damaged it (contract §7.4.1).
            .with_header(header::CONTENT_DIGEST, digest_header_value(&sha256))
            // The length is settled although the body streams: a `PUT` with an unknown length
            // falls through at some load balancers, and the server is to notice a short upload
            // before it accepts it.
            .with_header(header::CONTENT_LENGTH, length.to_string())
            .with_stream(file);
        let raw = match self.transport.run_from(request).await {
            Ok(raw) => raw,
            Err(error) => return error.into(),
        };
        if (200..300).contains(&raw.status) { success(&raw, ()) } else { failure(&raw, what) }
    }

    async fn inbox_complete(
        &self,
        upload: UploadIdentifier,
        key: &IdempotencyKey,
    ) -> ApiResult<UploadCompletion> {
        // [GAP → PROPOSAL] The contract shows no body for `:complete`. None is sent; the
        // idempotency key names the attempt, and everything else stands in the identifier in the
        // path.
        self.fetch(
            self.json_request(
                Method::POST,
                self.api(&path_completion(upload)),
                CallBinding::Session,
            )
            .with_header(header::IDEMPOTENCY_KEY, key.value()),
            &[200, 201],
            "the completion of the ingest",
        )
        .await
    }
}

// ── Translations ────────────────────────────────────────────────────────────────────────────

/// Packs a value into a success together with what the headers say about it.
fn success<T>(raw: &RawResponse, value: T) -> ApiResult<T> {
    ApiResult::Success(Success {
        value,
        etag: raw.etag(),
        idempotency_repeat: raw.idempotency_repeat(),
        status: raw.status,
    })
}

/// The device object of a `412` answer, in both forms that occur.
///
/// The contract (§7.0.5) leaves open what stands in the body of a `412`, and names
/// `GET /v1/devices/me` as the way afterwards. That way, however, needs a device token, and that is
/// exactly what does not exist before the approval by an administrator — the token fetch then
/// answers `403 device-pending-approval`. `[GAP → PROPOSAL]` Hence **both** are read here: a bare
/// device object, and a problem that brings one along as the extension field `device` (that is how
/// `edms-mock` answers). Neither of the two is invented: if neither the one nor the other comes,
/// the field stays `None` and the engine reads it afterwards as soon as it has a token.
fn device_from(raw: &RawResponse) -> Option<DeviceObject> {
    if let Ok(device) = serde_json::from_slice::<DeviceObject>(&raw.body) {
        return Some(device);
    }
    let from_problem = Problem::read(raw.status, &raw.body).extension("device")?.clone();
    serde_json::from_value(from_problem).ok()
}

/// Reads the body into its type.
fn read<T: DeserializeOwned>(raw: &RawResponse, what: &'static str) -> Result<T, NetworkError> {
    serde_json::from_slice(&raw.body)
        .map_err(|error| NetworkError::UnreadableResponse { what, reason: error.to_string() })
}

/// Writes a request body.
fn write<T: Serialize>(value: &T, what: &'static str) -> Result<String, NetworkError> {
    serde_json::to_string(value)
        .map_err(|error| NetworkError::RequestBody { what, reason: error.to_string() })
}

/// The error branch of an answer without a success status.
///
/// The order **is** the contract: `304` is no error, a redirect is never followed, an RFC 9470
/// challenge is a step-up and no error, a security event is an abort — and only after that is
/// everything an ordinary error on the merits. An unknown `type` becomes [`ErrorKind::Unknown`]
/// along the way, never a known one (contract §7.5.1).
fn failure<T>(raw: &RawResponse, what: &str) -> ApiResult<T> {
    if raw.status == 304 {
        return ApiResult::Unchanged { etag: raw.etag() };
    }
    if (300..400).contains(&raw.status) {
        return NetworkError::Redirect { target: what.to_owned(), location: raw.location() }.into();
    }
    let problem = Problem::read(raw.status, &raw.body);
    if let Some(request) = step_up(raw.header(header::WWW_AUTHENTICATE), &problem) {
        return ApiResult::StepUpNeeded { request, problem };
    }
    if problem.is_security_event() {
        let reason = problem
            .detail
            .clone()
            .or_else(|| problem.title.clone())
            .unwrap_or_else(|| problem.typ.clone());
        return ApiResult::SecurityAbort {
            notice: format!("The server reports a security event for {what}: {reason}"),
            problem: Some(problem),
        };
    }
    ApiResult::SlotError { problem, repeat_after: raw.repeat_after() }
}

/// Reads an error in the OAuth format (RFC 6749 §5.2).
///
/// An unreadable body becomes `server_error` — the call has failed, and an invented cause would be
/// worse than an indefinite one.
fn oauth_error(raw: &RawResponse) -> OauthError {
    serde_json::from_slice(&raw.body).unwrap_or_else(|_| OauthError {
        error: OauthErrorCode::Unknown("server_error".to_owned()),
        error_description: None,
        error_uri: None,
    })
}

/// Builds a problem out of an OAuth error — the bridge into the catalogue is `error_uri`.
fn oauth_problem(error: &OauthError, status: u16) -> Problem {
    let detail = error.error_description.clone().unwrap_or_else(|| error.error.to_string());
    let mut problem = Problem::from_catalogue(error.error_kind(), status, &detail);
    if let Some(uri) = &error.error_uri {
        problem.typ = uri.clone();
    }
    problem.title = Some(error.error.to_string());
    problem
}

fn oauth_failure<T>(error: &OauthError, raw: &RawResponse) -> ApiResult<T> {
    let problem = oauth_problem(error, raw.status);
    if problem.is_security_event() {
        return ApiResult::SecurityAbort {
            notice: format!(
                "The sign-in reports a security event: {}",
                problem.detail.clone().unwrap_or_else(|| problem.typ.clone())
            ),
            problem: Some(problem),
        };
    }
    ApiResult::SlotError { problem, repeat_after: raw.repeat_after() }
}

/// The counterpart does not keep the contract.
fn contract_breach<T>(error: &dyn std::error::Error) -> ApiResult<T> {
    ApiResult::NetworkError(NetworkError::ContractBreach { reason: error.to_string() })
}

/// An answer the client must not quietly take over.
fn security_abort<T>(error: &dyn std::error::Error) -> ApiResult<T> {
    ApiResult::SecurityAbort { notice: error.to_string(), problem: None }
}
