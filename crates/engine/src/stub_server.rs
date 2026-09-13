//! A server double for the cases that cannot be brought about against an honest mock.
//!
//! The mock (`edms-mock`) speaks the contract **correctly**, and precisely for that reason there is
//! something it cannot do: a renewal that breaks off **before** an answer arrives is no server
//! behaviour but a damaged line. The most interesting case of the whole contract hangs off it
//! (contract test T14), so it needs a double.
//!
//! What is implemented is [`edms_net::Server`] and not [`crate::ServerObject`]: the blanket
//! implementation in [`crate::server_object`] makes an object out of it by itself — and with that
//! this path tests the bridge along the way.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{ArchiveIdentifier, CommandIdentifier, UploadIdentifier};
use edms_core::namespace::Location;
use edms_crypto::key_set::KeyOffer;
use edms_net::server::{
    AcknowledgementOutcome, ContentReport, Discovery, DocumentList, EnrollmentReport, List,
    LoginIntent, LoginOutcome, LoginStep, Server,
};
use edms_net::{ApiResult, IdempotencyKey, NetworkError, Secret};
use edms_wire::delivery::{Acknowledgement, DeliveryPage, DeliveryQuery};
use edms_wire::device::{DeviceObject, EnrollmentRequest, Heartbeat, HeartbeatResponse};
use edms_wire::ingest::{UploadCompletion, UploadGrant, UploadRequest};
use edms_wire::login::{DeviceAuthorization, TokenResponse};
use edms_wire::namespace::{ArchiveRow, BasketRow, CaseRow, DocumentRow, ListQuery, SearchRow};
use tokio::io::AsyncWrite;

/// How the stub server answers a renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshResponse {
    /// The call broke off before an answer arrived (03 §6.3.3, T14).
    Uncertain,
    /// The refresh token had already been redeemed; the family is revoked.
    Reused,
    /// The line was away — a repeatable error.
    NetworkFault,
}

/// A server that can do only one thing: say no in a particular way — and count how often it was
/// asked.
#[derive(Debug)]
pub(crate) struct StubServer {
    response: Mutex<RefreshResponse>,
    refresh: AtomicUsize,
}

impl StubServer {
    pub(crate) fn new(response: RefreshResponse) -> Self {
        Self { response: Mutex::new(response), refresh: AtomicUsize::new(0) }
    }

    /// How often the renewal was attempted — the number T14 hangs off.
    pub(crate) fn refresh(&self) -> usize {
        self.refresh.load(Ordering::Acquire)
    }
}

/// Every call not meant here ends as a damaged line — never as a quiet success.
fn not_asked<T>() -> ApiResult<T> {
    ApiResult::NetworkError(NetworkError::Connection {
        target: "the stub server".to_owned(),
        reason: "this call does not belong to this probe".to_owned(),
    })
}

impl Server for StubServer {
    async fn discover(&self) -> ApiResult<Discovery> {
        not_asked()
    }

    async fn register_device(&self, _request: &EnrollmentRequest) -> ApiResult<EnrollmentReport> {
        not_asked()
    }

    async fn device_status(&self) -> ApiResult<DeviceObject> {
        not_asked()
    }

    async fn send_heartbeat(&self, _heartbeat: &Heartbeat) -> ApiResult<HeartbeatResponse> {
        not_asked()
    }

    async fn fetch_device_token(&self) -> ApiResult<TokenResponse> {
        not_asked()
    }

    async fn fetch_server_key(&self) -> ApiResult<KeyOffer> {
        not_asked()
    }

    async fn start_device_login(&self, _intent: &LoginIntent) -> ApiResult<DeviceAuthorization> {
        not_asked()
    }

    async fn wait_on_token(
        &self,
        _login: &DeviceAuthorization,
        _observer: &(dyn Fn(LoginStep) + Send + Sync),
    ) -> ApiResult<LoginOutcome> {
        not_asked()
    }

    async fn refresh_token(&self, _refresh_token: &Secret) -> ApiResult<TokenResponse> {
        self.refresh.fetch_add(1, Ordering::AcqRel);
        let response = *self.response.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match response {
            RefreshResponse::Uncertain => ApiResult::NetworkError(NetworkError::RefreshUncertain {
                reason: "Die Verbindung brach ab.".to_owned(),
            }),
            RefreshResponse::Reused => ApiResult::SecurityAbort {
                notice: "The refresh token has already been redeemed; the token family is \
                         revoked."
                    .to_owned(),
                problem: None,
            },
            RefreshResponse::NetworkFault => ApiResult::NetworkError(NetworkError::Timeout {
                target: "POST /v1/oauth/token".to_owned(),
            }),
        }
    }

    async fn revoke(&self, _refresh_token: &Secret) -> ApiResult<()> {
        not_asked()
    }

    async fn list_baskets(
        &self,
        _query: &ListQuery,
        _known_etag: Option<&str>,
    ) -> ApiResult<List<BasketRow>> {
        not_asked()
    }

    async fn list_archives(
        &self,
        _query: &ListQuery,
        _known_etag: Option<&str>,
    ) -> ApiResult<List<ArchiveRow>> {
        not_asked()
    }

    async fn list_cases(
        &self,
        _archive: ArchiveIdentifier,
        _query: &ListQuery,
        _known_etag: Option<&str>,
    ) -> ApiResult<List<CaseRow>> {
        not_asked()
    }

    async fn list_searches(
        &self,
        _query: &ListQuery,
        _known_etag: Option<&str>,
    ) -> ApiResult<List<SearchRow>> {
        not_asked()
    }

    async fn list_document(
        &self,
        _location: Location,
        _query: &ListQuery,
        _known_etag: Option<&str>,
    ) -> ApiResult<DocumentList> {
        not_asked()
    }

    async fn load_content(
        &self,
        _row: &DocumentRow,
        _application: Option<&str>,
        _sink: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> ApiResult<ContentReport> {
        not_asked()
    }

    async fn delivery_collect(&self, _query: &DeliveryQuery) -> ApiResult<DeliveryPage> {
        not_asked()
    }

    async fn acknowledge(
        &self,
        _command: CommandIdentifier,
        _acknowledgement: &Acknowledgement,
        _key: &IdempotencyKey,
    ) -> ApiResult<AcknowledgementOutcome> {
        not_asked()
    }

    async fn inbox_create(
        &self,
        _request: &UploadRequest,
        _key: &IdempotencyKey,
    ) -> ApiResult<UploadGrant> {
        not_asked()
    }

    async fn inbox_high_load(
        &self,
        _grant: &UploadGrant,
        _file: tokio::fs::File,
        _length: u64,
        _sha256: Sha256Value,
    ) -> ApiResult<()> {
        not_asked()
    }

    async fn inbox_complete(
        &self,
        _upload: UploadIdentifier,
        _key: &IdempotencyKey,
    ) -> ApiResult<UploadCompletion> {
        not_asked()
    }
}
