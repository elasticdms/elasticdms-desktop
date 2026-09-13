//! The contract as a trait — and the values it delivers.
//!
//! The engine knows **this** trait, not [`crate::ServerAccess`]. That is no formality: the cases
//! the engine has to handle correctly are almost all error cases — a `412` at the enrolment, a
//! `409` on an acknowledgement, a truncated hit list, an expired device code. Against a real server
//! they are laborious to bring about and against a mock they are one line.
//!
//! All methods deliver `impl Future + Send`: the engine runs them in tokio tasks, and an assurance
//! that does not stand in the signature falls on your feet at the first `tokio::spawn`.

use std::future::Future;

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{ArchiveIdentifier, CommandIdentifier, UploadIdentifier};
use edms_core::namespace::{DocumentItem, Location, Truncation};
use edms_crypto::key_set::KeyOffer;
use edms_wire::content::ContentHeader;
use edms_wire::delivery::{Acknowledgement, AcknowledgementReceipt, DeliveryPage, DeliveryQuery};
use edms_wire::device::{DeviceObject, EnrollmentRequest, Heartbeat, HeartbeatResponse};
use edms_wire::discovery::{AuthorizationServerMetadata, LoginEndpoint, ResourceMetadata};
use edms_wire::ingest::{UploadCompletion, UploadGrant, UploadRequest};
use edms_wire::login::{DeviceAuthorization, OauthError, TokenResponse};
use edms_wire::namespace::{ArchiveRow, BasketRow, CaseRow, DocumentRow, ListQuery, SearchRow};
use tokio::io::AsyncWrite;

use crate::idempotency::IdempotencyKey;
use crate::result::ApiResult;
use crate::secret::Secret;

/// Maximum number of pages a listing fetches before it reports the truncation.
///
/// At the default of 200 rows per page that is 20 000 documents — more than the suggested display
/// limit of 5 000 (contract §7.1.2). The limit is no rule of the domain but the protection against
/// a server that never takes `hasMore` back: without it the reconcile would run endlessly and the
/// folder would fill up quietly. If it is reached, that stands in [`List::limit_reached`] —
/// truncation is **visible**, never quiet.
pub const MAX_PAGE: u32 = 100;

/// What discovery yielded (03 §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The three endpoints, each checked under the issuer.
    pub endpoint: LoginEndpoint,
    /// The complete document of the authorization server.
    pub authorization_server: AuthorizationServerMetadata,
    /// The complete document of the resource.
    pub resource: ResourceMetadata,
}

/// The result of an enrolment (03 §6.2.1, contract tests T1–T3, T5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentReport {
    /// Whether the device already existed: `200` after a `GET` or `412` on `If-None-Match: *`.
    ///
    /// **`412` is success**, not an error: the call can break off after the server has created the
    /// device, and only this way can a retry after a network break be told apart from a real
    /// collision (`409 device-id-conflict`).
    pub inventory_already: bool,
    /// The device object, if the answer carried one.
    ///
    /// On `412` the server may leave the body out; then the client reads it afterwards with
    /// [`Server::device_status`] (contract §7.0.5). `None` means exactly that and **not** "no
    /// device".
    pub device: Option<DeviceObject>,
}

/// What the client demands at the start of the device flow (RFC 8628 §3.1).
///
/// `dpop_jkt` and the client assertion are set by [`crate::ServerAccess`] itself — they hang off
/// the keys, and only it knows those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginIntent {
    /// The requested scopes; empty means [`edms_wire::login::USER_SCOPES`].
    pub scopes: Vec<String>,
    /// At the first sign-in [`edms_wire::login::ACR_DESKTOP`], at the step-up the value from the
    /// challenge. The client never guesses the level itself.
    pub acr_values: Option<String>,
    /// Empty at the first sign-in; at the step-up the user of the running session — otherwise the
    /// strengthening could be fulfilled by a colleague.
    pub login_hint: Option<String>,
    /// At the step-up the maximum age from the challenge.
    pub max_age: Option<u64>,
    /// At the step-up `login`: a step-up that the existing session answers quietly would be
    /// none.
    pub prompt: Option<String>,
}

impl LoginIntent {
    /// The first sign-in at this workstation.
    pub fn first_login() -> Self {
        Self {
            scopes: Vec::new(),
            acr_values: Some(edms_wire::login::ACR_DESKTOP.to_owned()),
            login_hint: None,
            max_age: None,
            prompt: None,
        }
    }

    /// A step-up from the server's challenge (RFC 9470).
    ///
    /// Our own ingredient is `prompt=login` alone, and that follows compellingly from the purpose.
    pub fn step_up(request: &crate::StepUpRequest, user: Option<&str>) -> Self {
        Self {
            scopes: Vec::new(),
            acr_values: request.acr_value(),
            login_hint: user.map(ToOwned::to_owned),
            max_age: request.max_age_second,
            prompt: Some("login".to_owned()),
        }
    }
}

/// What a single poll attempt in the device flow yielded — for the display during the
/// waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStep {
    /// `authorization_pending`: the human has not confirmed yet.
    Pending,
    /// `slow_down`: the interval rises **permanently** by five seconds (RFC 8628 §3.5).
    Slower {
        /// The new interval in seconds.
        interval_second: u64,
    },
    /// The network was away. The flow runs on until the code expires.
    NetworkFault(String),
    /// The server has decided; [`Server::wait_on_token`] returns straight away.
    Decided,
}

/// How the device flow ended.
///
/// Three outcomes, three screens: "the human refused" and "the time has run out" lead to different
/// sentences, and whoever throws them together sends somebody who was refused off to wait
/// (contract §7.0.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The token is there.
    Issued(Box<TokenResponse>),
    /// `expired_token`: the device code has expired, the flow starts from the beginning.
    Expired,
    /// `access_denied`: a human refused or is not allowed.
    Rejected(OauthError),
}

/// A completely read listing (all pages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List<T> {
    /// The rows in server order — **unfiltered** (contract test T11).
    pub entries: Vec<T>,
    /// The strong ETag of the **first** page; only it is any use for the next `If-None-Match`.
    pub etag: Option<String>,
    /// How many pages were fetched.
    pub pages: u32,
    /// Whether [`MAX_PAGE`] was reached and a cursor was still open.
    pub limit_reached: bool,
}

/// A completely read document listing together with the server's visible truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentList {
    /// The rows in server order.
    pub rows: Vec<DocumentRow>,
    /// The strong ETag of the first page.
    pub etag: Option<String>,
    /// How many pages were fetched.
    pub pages: u32,
    /// Whether [`MAX_PAGE`] was reached and a cursor was still open.
    pub limit_reached: bool,
    /// Whether the server truncated of its own accord (`totalCapped`).
    pub total_capped: bool,
    /// The server's display limit.
    pub display_limit: u64,
    /// Where the user can refine the search; only on truncation.
    pub refine_url: Option<String>,
}

impl DocumentList {
    /// The truncation for the core's hint file, if the listing is cut off.
    ///
    /// It comes about for **both** reasons: the server truncated, or [`MAX_PAGE`] was reached. A
    /// folder that shows 5 000 out of 40 000 documents and says nothing leads to the statement "the
    /// document does not exist" — in front of an auditor the most expensive way to be wrong
    /// (finding Q-12).
    pub fn truncation(&self) -> Option<Truncation<'_>> {
        (self.total_capped || self.limit_reached).then_some(Truncation {
            displayed: if self.total_capped { self.display_limit } else { self.rows.len() as u64 },
            address: self.refine_url.as_deref(),
        })
    }

    /// The documents in the core's form.
    pub fn in_core(&self) -> Vec<DocumentItem> {
        self.rows.iter().map(DocumentRow::in_core).collect()
    }
}

/// What is settled after a content fetch.
///
/// The checksum is **checked by the engine**: it writes into a scratch area and compares before a
/// single byte reaches the platform (`edms_core::port`). This crate delivers for that the server's
/// promise and the number of bytes really written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentReport {
    /// Media type, length, version and `Repr-Digest` — checked against the row of the listing.
    pub header: ContentHeader,
    /// How many bytes went into the sink; equal to [`ContentHeader::length`], otherwise there
    /// would be no finding but [`crate::NetworkError::Incomplete`].
    pub bytes: u64,
}

/// What an acknowledgement yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcknowledgementOutcome {
    /// The server has accepted it.
    Accepted(AcknowledgementReceipt),
    /// `409 delivery-command-already-acknowledged` — for the client **success**.
    ///
    /// The command is done, the acknowledgement may leave the queue. Otherwise it would lie there
    /// forever, and `delivery.unacknowledgedCommands` in the heartbeat would permanently report a
    /// fault that is none (contract §7.3.6).
    AlreadyAcknowledged,
}

/// The server as the folder client needs it (contract §7).
pub trait Server: Send + Sync {
    /// Both `.well-known` documents, checked against the start conditions (03 §6.1).
    ///
    /// A foreign issuer or an endpoint outside the issuer is an [`ApiResult::SecurityAbort`], not
    /// an error on the merits: a document that puts the token endpoint on a foreign host would send
    /// every client assertion there.
    fn discover(&self) -> impl Future<Output = ApiResult<Discovery>> + Send;

    /// `PUT /v1/devices/{deviceId}` — the only call **without** `Authorization` and **without**
    /// DPoP, with `If-None-Match: *` (contract tests T1, T2).
    ///
    /// The enrolment code is the credential of this one call; there is no token yet, and the server
    /// cannot check a proof, because it learns the key only with this request.
    fn register_device(
        &self,
        request: &EnrollmentRequest,
    ) -> impl Future<Output = ApiResult<EnrollmentReport>> + Send;

    /// `GET /v1/devices/me` with the device token.
    fn device_status(&self) -> impl Future<Output = ApiResult<DeviceObject>> + Send;

    /// `POST /v1/devices/{deviceId}:heartbeat` (03 §6.4.1).
    ///
    /// The answer carries **unsigned** commands. The folder client follows only `resyncPolicy` and
    /// `resyncServerKeys` there — both are only a fetch, and the fetch checks itself. Everything
    /// that removes copies or signs out comes exclusively signed over the delivery channel
    /// (ADR-D04).
    fn send_heartbeat(
        &self,
        heartbeat: &Heartbeat,
    ) -> impl Future<Output = ApiResult<HeartbeatResponse>> + Send;

    /// The device token (`client_credentials` with `private_key_jwt`, 03 §6.2.2).
    ///
    /// It carries exactly `device:self`, `desktop:login` and `delivery:receive` — nothing of the
    /// domain. Otherwise a stolen workstation would be full access to the archive, without a human
    /// ever having signed in.
    fn fetch_device_token(&self) -> impl Future<Output = ApiResult<TokenResponse>> + Send;

    /// `GET /v1/server-keys` with the device token.
    ///
    /// Delivered is the **offer**, not the adopted state: whether it changes the anchor is decided
    /// by `edms-crypto` against the anchored set, and whether the user sees a warning is decided by
    /// the engine.
    fn fetch_server_key(&self) -> impl Future<Output = ApiResult<KeyOffer>> + Send;

    /// `POST /v1/oauth/device_authorization` — **without** a DPoP header, but with `dpop_jkt`.
    ///
    /// RFC 9449 §5 binds the future token over the thumbprint of the **session** key, while the
    /// client assertion is signed with the **device** key.
    fn start_device_login(
        &self,
        intent: &LoginIntent,
    ) -> impl Future<Output = ApiResult<DeviceAuthorization>> + Send;

    /// Polls for the token in a loop until a decision falls (RFC 8628 §3.4).
    ///
    /// `slow_down` raises the interval **permanently**; a client that forgets the supplement after
    /// the next attempt throttles itself into an endless loop. The overall duration is bounded by
    /// `expires_in`, measured over the sum of the waiting times — not over the device clock, which
    /// is allowed to go wrong.
    ///
    /// **Cancelling means: drop the future.** Whoever puts the call into `tokio::select!` and lets
    /// the other branch win ends the waiting at once; the device code stays valid, and a later
    /// attempt polls on.
    fn wait_on_token(
        &self,
        login: &DeviceAuthorization,
        observer: &(dyn Fn(LoginStep) + Send + Sync),
    ) -> impl Future<Output = ApiResult<LoginOutcome>> + Send;

    /// Renews the user token with rotation (03 §6.3.3).
    ///
    /// **Never repeat blindly.** If the call breaks off before an answer arrived,
    /// [`crate::NetworkError::RefreshUncertain`] is the answer and the human signs in anew: reusing
    /// a rotated refresh token revokes the **whole token family** across devices (contract test
    /// T14). If it is already revoked, that is an [`ApiResult::SecurityAbort`] and not an ordinary
    /// end of session — somebody else has used the same token.
    fn refresh_token(
        &self,
        refresh_token: &Secret,
    ) -> impl Future<Output = ApiResult<TokenResponse>> + Send;

    /// `POST /v1/oauth/revoke` (RFC 7009).
    ///
    /// The status is **no proof**: RFC 7009 answers `200` for an unknown token too. The engine
    /// clears up in any case — afterwards no name of the old user stands on the disk any more
    /// (requirement 4).
    fn revoke(&self, refresh_token: &Secret) -> impl Future<Output = ApiResult<()>> + Send;

    /// `GET /v1/mirror/baskets`, all pages (contract §7.1.1).
    ///
    /// `known_etag` goes as `If-None-Match` to the **first** page; if the server answers `304`,
    /// [`ApiResult::Unchanged`] comes back and no empty listing.
    ///
    /// A basket is listed so that the folder exists to drop a file into; it has no document
    /// listing of its own, because it holds nothing (ADR-D11, §7.1.1).
    fn list_baskets(
        &self,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> impl Future<Output = ApiResult<List<BasketRow>>> + Send;

    /// `GET /v1/mirror/archives`, all pages.
    fn list_archives(
        &self,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> impl Future<Output = ApiResult<List<ArchiveRow>>> + Send;

    /// `GET /v1/mirror/archives/{archiveId}/cases`, all pages.
    ///
    /// The archive stands in the path, because a case file exists only under one: there is no
    /// listing across archives to ask (ADR-D11).
    fn list_cases(
        &self,
        archive: ArchiveIdentifier,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> impl Future<Output = ApiResult<List<CaseRow>>> + Send;

    /// `GET /v1/mirror/searches`, all pages.
    fn list_searches(
        &self,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> impl Future<Output = ApiResult<List<SearchRow>>> + Send;

    /// `GET …/cases/{caseId}/documents` or `GET …/searches/{savedSearchId}/documents`, all pages.
    fn list_document(
        &self,
        location: Location,
        query: &ListQuery,
        known_etag: Option<&str>,
    ) -> impl Future<Output = ApiResult<DocumentList>> + Send;

    /// `GET /v1/documents/{id}/content` — the fetch that is an access (contract §7.2).
    ///
    /// Checked **before** the first byte: the four mandatory headers, then version, checksum and
    /// size against `row`. If something deviates, the document has changed since the listing, and
    /// the placeholder would otherwise carry the values of a different version. Afterwards the body
    /// streams into `sink`; if more or fewer bytes come than announced, that is
    /// [`crate::NetworkError::Incomplete`] and no file.
    ///
    /// `application` is the **file name** of the program that opens the file — never a path that
    /// would betray the user name. If it cannot be encoded, the header is left out: it is an
    /// observation, not a reason to deny the user the document.
    fn load_content(
        &self,
        row: &DocumentRow,
        application: Option<&str>,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> impl Future<Output = ApiResult<ContentReport>> + Send;

    /// `GET /v1/delivery/commands?wait=…` with the **device** token (contract §7.3.1).
    ///
    /// An empty `items` list is the normal case of an expired wait, not an error; the cursor moves
    /// on then too. The entries stay raw JSON values, so that one broken command does not block the
    /// whole page and with it the channel.
    fn delivery_collect(
        &self,
        query: &DeliveryQuery,
    ) -> impl Future<Output = ApiResult<DeliveryPage>> + Send;

    /// `POST /v1/delivery/commands/{id}:acknowledge` (contract §7.3.6).
    ///
    /// `key` is a ULID **per attempt**, not per command: the same key with a differing body is
    /// `422 idempotency-key-reuse`, and it must be possible for `FAILED` to become `APPLIED`
    /// later.
    fn acknowledge(
        &self,
        command: CommandIdentifier,
        acknowledgement: &Acknowledgement,
        key: &IdempotencyKey,
    ) -> impl Future<Output = ApiResult<AcknowledgementOutcome>> + Send;

    /// `POST /v1/ingest-uploads` — the promise before the bytes (contract §7.4.1).
    ///
    /// The request names the mail basket the file was dropped into; the basket's rule decides
    /// where the document lands, never this client (ADR-D11, §7.4).
    fn inbox_create(
        &self,
        request: &UploadRequest,
        key: &IdempotencyKey,
    ) -> impl Future<Output = ApiResult<UploadGrant>> + Send;

    /// `PUT <uploadUrl>` with `Content-Digest` over exactly the bytes sent.
    ///
    /// The address is used **only** if it lies below the API; an `uploadUrl` on a foreign host
    /// would send the bytes of a receipt there, and the user would notice nothing, because the
    /// operation succeeds. A foreign origin is therefore an [`ApiResult::SecurityAbort`]
    /// (contract test T24).
    fn inbox_high_load(
        &self,
        grant: &UploadGrant,
        file: tokio::fs::File,
        length: u64,
        sha256: Sha256Value,
    ) -> impl Future<Output = ApiResult<()>> + Send;

    /// `POST /v1/ingest-uploads/{id}:complete`.
    ///
    /// Afterwards the document lies in the inbox; only **now** may the browser open. In the
    /// reverse order every abort would lose the document — and the user would believe he had
    /// handed it in (ADR-D08).
    fn inbox_complete(
        &self,
        upload: UploadIdentifier,
        key: &IdempotencyKey,
    ) -> impl Future<Output = ApiResult<UploadCompletion>> + Send;
}
