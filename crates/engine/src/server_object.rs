//! The same contract, only as an object: [`ServerObject`].
//!
//! `edms_net::Server` delivers `impl Future` per method (RPITIT). That is right there — the caller
//! gets the future without an allocation —, but it makes the trait **not object-safe**:
//! `Arc<dyn Server>` does not exist, and the engine holds exactly one server which the app and the
//! later parts (delivery channel, ingest) have to be able to exchange, without `Engine`
//! itself becoming generic and carrying its type parameter through the whole app.
//!
//! This trait is the same interface with boxed futures. It is **never implemented by hand**: the
//! blanket implementation further down holds for every `Server`, and with it an
//! `Arc<ServerAccess>` becomes an `Arc<dyn ServerObject>` by plain assignment.
//!
//! ```ignore
//! let server: Arc<dyn ServerObject> = Arc::new(ServerAccess::new(connection, source)?);
//! ```
//!
//! One allocation per server call — reckoned against a network call that is nothing, and it is the
//! price for there being **one** server type in the whole program and not two.
//!
//! the assignment names `Arc<dyn Server>`. That type does not exist as long as `Server`
//! returns `impl Future`; `Arc<dyn ServerObject>` is the same thing in object-safe form.

use std::future::Future;
use std::pin::Pin;

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{ArchiveIdentifier, CommandIdentifier, UploadIdentifier};
use edms_core::namespace::Location;
use edms_crypto::key_set::KeyOffer;
use edms_net::server::{
    AcknowledgementOutcome, ContentReport, Discovery, DocumentList, EnrollmentReport, List,
    LoginIntent, LoginOutcome, LoginStep, Server,
};
use edms_net::{ApiResult, IdempotencyKey, Secret};
use edms_wire::delivery::{Acknowledgement, DeliveryPage, DeliveryQuery};
use edms_wire::device::{DeviceObject, EnrollmentRequest, Heartbeat, HeartbeatResponse};
use edms_wire::ingest::{UploadCompletion, UploadGrant, UploadRequest};
use edms_wire::login::{DeviceAuthorization, TokenResponse};
use edms_wire::namespace::{ArchiveRow, BasketRow, CaseRow, DocumentRow, ListQuery, SearchRow};
use tokio::io::AsyncWrite;

/// A boxed future that may live over `'a`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// [`edms_net::Server`] as an object-safe interface.
///
/// The meaning of every method stands at [`Server`] and is not repeated here — two descriptions of
/// the same contract drift apart, and then one believes the wrong one.
pub trait ServerObject: Send + Sync {
    /// See [`Server::discover`].
    fn discover(&self) -> BoxFuture<'_, ApiResult<Discovery>>;

    /// See [`Server::register_device`].
    fn register_device<'a>(
        &'a self,
        request: &'a EnrollmentRequest,
    ) -> BoxFuture<'a, ApiResult<EnrollmentReport>>;

    /// See [`Server::device_status`].
    fn device_status(&self) -> BoxFuture<'_, ApiResult<DeviceObject>>;

    /// See [`Server::send_heartbeat`].
    fn send_heartbeat<'a>(
        &'a self,
        heartbeat: &'a Heartbeat,
    ) -> BoxFuture<'a, ApiResult<HeartbeatResponse>>;

    /// See [`Server::fetch_device_token`].
    fn fetch_device_token(&self) -> BoxFuture<'_, ApiResult<TokenResponse>>;

    /// See [`Server::fetch_server_key`].
    fn fetch_server_key(&self) -> BoxFuture<'_, ApiResult<KeyOffer>>;

    /// See [`Server::start_device_login`].
    fn start_device_login<'a>(
        &'a self,
        intent: &'a LoginIntent,
    ) -> BoxFuture<'a, ApiResult<DeviceAuthorization>>;

    /// See [`Server::wait_on_token`].
    fn wait_on_token<'a>(
        &'a self,
        login: &'a DeviceAuthorization,
        observer: &'a (dyn Fn(LoginStep) + Send + Sync),
    ) -> BoxFuture<'a, ApiResult<LoginOutcome>>;

    /// See [`Server::refresh_token`].
    fn refresh_token<'a>(
        &'a self,
        refresh_token: &'a Secret,
    ) -> BoxFuture<'a, ApiResult<TokenResponse>>;

    /// See [`Server::revoke`].
    fn revoke<'a>(&'a self, refresh_token: &'a Secret) -> BoxFuture<'a, ApiResult<()>>;

    /// See [`Server::list_baskets`].
    fn list_baskets<'a>(
        &'a self,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<BasketRow>>>;

    /// See [`Server::list_archives`].
    fn list_archives<'a>(
        &'a self,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<ArchiveRow>>>;

    /// See [`Server::list_cases`].
    fn list_cases<'a>(
        &'a self,
        archive: ArchiveIdentifier,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<CaseRow>>>;

    /// See [`Server::list_searches`].
    fn list_searches<'a>(
        &'a self,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<SearchRow>>>;

    /// See [`Server::list_document`].
    fn list_document<'a>(
        &'a self,
        location: Location,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<DocumentList>>;

    /// See [`Server::load_content`].
    fn load_content<'a>(
        &'a self,
        row: &'a DocumentRow,
        application: Option<&'a str>,
        sink: &'a mut (dyn AsyncWrite + Unpin + Send),
    ) -> BoxFuture<'a, ApiResult<ContentReport>>;

    /// See [`Server::delivery_collect`].
    fn delivery_collect<'a>(
        &'a self,
        query: &'a DeliveryQuery,
    ) -> BoxFuture<'a, ApiResult<DeliveryPage>>;

    /// See [`Server::acknowledge`].
    fn acknowledge<'a>(
        &'a self,
        command: CommandIdentifier,
        acknowledgement: &'a Acknowledgement,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, ApiResult<AcknowledgementOutcome>>;

    /// See [`Server::inbox_create`].
    fn inbox_create<'a>(
        &'a self,
        request: &'a UploadRequest,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, ApiResult<UploadGrant>>;

    /// See [`Server::inbox_high_load`].
    fn inbox_high_load<'a>(
        &'a self,
        grant: &'a UploadGrant,
        file: tokio::fs::File,
        length: u64,
        sha256: Sha256Value,
    ) -> BoxFuture<'a, ApiResult<()>>;

    /// See [`Server::inbox_complete`].
    fn inbox_complete<'a>(
        &'a self,
        upload: UploadIdentifier,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, ApiResult<UploadCompletion>>;
}

impl<S: Server> ServerObject for S {
    fn discover(&self) -> BoxFuture<'_, ApiResult<Discovery>> {
        Box::pin(Server::discover(self))
    }

    fn register_device<'a>(
        &'a self,
        request: &'a EnrollmentRequest,
    ) -> BoxFuture<'a, ApiResult<EnrollmentReport>> {
        Box::pin(Server::register_device(self, request))
    }

    fn device_status(&self) -> BoxFuture<'_, ApiResult<DeviceObject>> {
        Box::pin(Server::device_status(self))
    }

    fn send_heartbeat<'a>(
        &'a self,
        heartbeat: &'a Heartbeat,
    ) -> BoxFuture<'a, ApiResult<HeartbeatResponse>> {
        Box::pin(Server::send_heartbeat(self, heartbeat))
    }

    fn fetch_device_token(&self) -> BoxFuture<'_, ApiResult<TokenResponse>> {
        Box::pin(Server::fetch_device_token(self))
    }

    fn fetch_server_key(&self) -> BoxFuture<'_, ApiResult<KeyOffer>> {
        Box::pin(Server::fetch_server_key(self))
    }

    fn start_device_login<'a>(
        &'a self,
        intent: &'a LoginIntent,
    ) -> BoxFuture<'a, ApiResult<DeviceAuthorization>> {
        Box::pin(Server::start_device_login(self, intent))
    }

    fn wait_on_token<'a>(
        &'a self,
        login: &'a DeviceAuthorization,
        observer: &'a (dyn Fn(LoginStep) + Send + Sync),
    ) -> BoxFuture<'a, ApiResult<LoginOutcome>> {
        Box::pin(Server::wait_on_token(self, login, observer))
    }

    fn refresh_token<'a>(
        &'a self,
        refresh_token: &'a Secret,
    ) -> BoxFuture<'a, ApiResult<TokenResponse>> {
        Box::pin(Server::refresh_token(self, refresh_token))
    }

    fn revoke<'a>(&'a self, refresh_token: &'a Secret) -> BoxFuture<'a, ApiResult<()>> {
        Box::pin(Server::revoke(self, refresh_token))
    }

    fn list_baskets<'a>(
        &'a self,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<BasketRow>>> {
        Box::pin(Server::list_baskets(self, query, known_etag))
    }

    fn list_archives<'a>(
        &'a self,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<ArchiveRow>>> {
        Box::pin(Server::list_archives(self, query, known_etag))
    }

    fn list_cases<'a>(
        &'a self,
        archive: ArchiveIdentifier,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<CaseRow>>> {
        Box::pin(Server::list_cases(self, archive, query, known_etag))
    }

    fn list_searches<'a>(
        &'a self,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<List<SearchRow>>> {
        Box::pin(Server::list_searches(self, query, known_etag))
    }

    fn list_document<'a>(
        &'a self,
        location: Location,
        query: &'a ListQuery,
        known_etag: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<DocumentList>> {
        Box::pin(Server::list_document(self, location, query, known_etag))
    }

    fn load_content<'a>(
        &'a self,
        row: &'a DocumentRow,
        application: Option<&'a str>,
        sink: &'a mut (dyn AsyncWrite + Unpin + Send),
    ) -> BoxFuture<'a, ApiResult<ContentReport>> {
        Box::pin(Server::load_content(self, row, application, sink))
    }

    fn delivery_collect<'a>(
        &'a self,
        query: &'a DeliveryQuery,
    ) -> BoxFuture<'a, ApiResult<DeliveryPage>> {
        Box::pin(Server::delivery_collect(self, query))
    }

    fn acknowledge<'a>(
        &'a self,
        command: CommandIdentifier,
        acknowledgement: &'a Acknowledgement,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, ApiResult<AcknowledgementOutcome>> {
        Box::pin(Server::acknowledge(self, command, acknowledgement, key))
    }

    fn inbox_create<'a>(
        &'a self,
        request: &'a UploadRequest,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, ApiResult<UploadGrant>> {
        Box::pin(Server::inbox_create(self, request, key))
    }

    fn inbox_high_load<'a>(
        &'a self,
        grant: &'a UploadGrant,
        file: tokio::fs::File,
        length: u64,
        sha256: Sha256Value,
    ) -> BoxFuture<'a, ApiResult<()>> {
        Box::pin(Server::inbox_high_load(self, grant, file, length, sha256))
    }

    fn inbox_complete<'a>(
        &'a self,
        upload: UploadIdentifier,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, ApiResult<UploadCompletion>> {
        Box::pin(Server::inbox_complete(self, upload, key))
    }
}
