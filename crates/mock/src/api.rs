//! The resource API: device, keys, namespace, content, delivery channel, ingest.
//!
//! Every endpoint here presupposes 03 §6.0 — version, DPoP with a nonce, problem format, pages,
//! ETag, idempotency — and adds the proposals of §7.1 through §7.4.
//!
//! Three places carry the purpose of this test harness:
//!
//! 1. **Content is an access.** Every `200` on `…/content` writes a row into the server-side
//!    access log ([`crate::Control::access_log`]) — §7.2.3. A byte that comes from a source the
//!    server does not see is an access the log does not know about.
//! 2. **Truncation is visible.** `totalCapped`, `displayLimit` and `refineUrl` belong together
//!    (§7.1.2); a folder that shows 5 of 40,000 documents and says nothing leads to the statement
//!    "that document does not exist".
//! 3. **A mangled body arrives with `200`.** The real server notices the hash failure only on the
//!    last `Read`, after the status and the headers have been sent (§7.2.1). The mock can
//!    reproduce that ([`crate::state::Mangling`]) — otherwise contract test T13 would stay an
//!    assertion.

use axum::Router;
use axum::response::Response;
use axum::routing::{get, post, put};
use edms_core::delivery::CommandOutcome;
use edms_core::identifier::{
    ArchiveIdentifier, CaseIdentifier, CommandIdentifier, DeviceIdentifier, DocumentIdentifier,
    SearchIdentifier, UploadIdentifier,
};
use edms_core::namespace::Location;
use edms_wire::basics::{
    ErrorKind, FieldError, Page, Problem, WireTimestamp, digest_header_value, header, media_type,
    read_digest_header, strong_etag,
};
use edms_wire::delivery::{DeliveryPage, MAX_COMMAND_PER_RESPONSE, PATH_COMMAND};
use edms_wire::device::{PATH_OWN_IT_DEVICE, PATH_SERVER_KEY};
use edms_wire::discovery::{PATH_RESOURCE_METADATA, ResourceMetadata};
use edms_wire::ingest::{
    DuplicateHint, InboxState, PATH_UPLOAD, UploadCompletion, UploadGrant, UploadRequest,
};
use edms_wire::namespace::{
    ArchiveRow, BasketRow, CaseRow, DocumentPage, DocumentRow, LIMIT_MAX, PATH_ARCHIVES,
    PATH_BASKETS, PATH_SEARCHES, SearchRow,
};
use serde_json::{Value, json};

use crate::http::{
    Context, Inbox, Session, bytes_response, cancelled_response, catalogue, check_access, empty,
    golden_problem, json_response, json_with_headers, problem_response,
};
use crate::state::{AccessEntry, CommandItem, CommandQuality, Device, DeviceState, State, Upload};
use crate::time::now;

/// The path of the document content, with a placeholder for axum.
const PATH_CONTENT: &str = "/v1/documents/{document}/content";

/// The case files of one archive, with a placeholder for axum.
///
/// Axum needs the placeholder, `edms_wire::namespace` hands out the finished address — two
/// spellings of one path. A test below fills the placeholder in and compares (`the_routes_…`);
/// without it the mock could serve an endpoint the client never calls.
const PATH_CASES_OF_ARCHIVE: &str = "/v1/mirror/archives/{archive}/cases";

/// The documents of one case file, with placeholders for axum.
const PATH_CASE_DOCUMENT: &str = "/v1/mirror/archives/{archive}/cases/{case}/documents";

/// The documents of one saved search, with a placeholder for axum.
const PATH_SEARCH_DOCUMENT: &str = "/v1/mirror/searches/{search}/documents";

/// The path under which development queues a delivery command with `curl`.
pub const PATH_DEV_COMMAND: &str = "/mock/commands";

/// Builds the router of the resource API.
pub fn router(context: Context) -> Router {
    Router::new()
        .route(PATH_RESOURCE_METADATA, get(resource_metadata))
        .route("/v1/devices/{identifier}", put(enrollment).post(heartbeat))
        .route(PATH_OWN_IT_DEVICE, get(own_device))
        .route(PATH_SERVER_KEY, get(server_key))
        .route(PATH_BASKETS, get(basket_list))
        .route(PATH_ARCHIVES, get(archive_list))
        .route(PATH_CASES_OF_ARCHIVE, get(case_list))
        .route(PATH_SEARCHES, get(search_list))
        .route(PATH_CASE_DOCUMENT, get(case_document))
        .route(PATH_SEARCH_DOCUMENT, get(search_document))
        .route(PATH_CONTENT, get(content))
        .route(PATH_COMMAND, get(command_collect))
        .route("/v1/delivery/commands/{command}", post(acknowledge))
        .route(PATH_UPLOAD, post(upload_apply_for))
        .route("/v1/ingest-uploads/{upload}/content", put(upload_send))
        .route("/v1/ingest-uploads/{upload}", post(upload_complete))
        .route(PATH_DEV_COMMAND, post(dev_command))
        .fallback(crate::http::unknown_path)
        .method_not_allowed_fallback(crate::http::wrong_method)
        .with_state(context)
}

// ───────────────────────────── Discovery ─────────────────────────────

/// `GET /.well-known/oauth-protected-resource` (03 §6.1).
async fn resource_metadata(
    axum::extract::State(context): axum::extract::State<Context>,
) -> Response {
    let metadata = ResourceMetadata {
        resource: context.state.api_base.trim_end_matches('/').to_owned(),
        authorization_servers: vec![context.state.auth_base.trim_end_matches('/').to_owned()],
        bearer_methods_supported: Some(vec!["dpop".to_owned()]),
        scopes_supported: Some(
            ["device:self", "folders:read", "documents:read", "ingest:submit", "delivery:receive"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        ),
        further: serde_json::Map::new(),
    };
    json_response(200, &metadata)
}

// ───────────────────────────── Device and keys ─────────────────────────────

/// `PUT /v1/devices/{deviceId}` — enrolment **without** `Authorization` and **without** DPoP
/// (§7.0.5).
///
/// `412` is a success: the call may have been broken off after the server created the device.
/// `409` is not — there lies a **different** public key.
async fn enrollment(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let Ok(device_identifier) = identifier.parse::<DeviceIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            &format!("“{identifier}” is not a canonical device identifier (03 §6.0.3)."),
            &inbox.path,
        );
    };
    if inbox.header_value(header::IF_NONE_MATCH) != Some("*") {
        return catalogue(
            ErrorKind::PreconditionRequired,
            428,
            "The enrolment demands If-None-Match: * — without it a repeated attempt could not be \
             told apart from a collision (§7.0.5).",
            &inbox.path,
        );
    }
    let body = match inbox.as_json() {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: edms_wire::device::EnrollmentRequest = match serde_json::from_value(body.clone()) {
        Ok(request) => request,
        Err(error) => {
            return catalogue(
                ErrorKind::ValidationFailed,
                422,
                &format!("The enrolment request is incomplete: {error}"),
                &inbox.path,
            );
        }
    };
    if let Err(error) = request.public_jwk.check() {
        // A JWK with `d` is rejected already on reading: a key whose private part once went over
        // the network counts as given away (geraete-auth §3.1).
        return catalogue(ErrorKind::ValidationFailed, 422, &error.to_string(), &inbox.path);
    }
    let jwk = match edms_crypto::key::Jwk::new(&request.public_jwk.x, &request.public_jwk.y) {
        Ok(jwk) => jwk,
        Err(error) => {
            return catalogue(
                ErrorKind::ValidationFailed,
                422,
                &format!("publicJwk is not a usable P-256 key: {error}"),
                &inbox.path,
            );
        }
    };

    let present = context.state.lock().devices.get(&device_identifier).cloned();
    if let Some(device) = present {
        if device.jwk.thumbprint() != jwk.thumbprint() {
            return golden_problem("problem_device_already_exists.json", 409, &inbox.path);
        }
        // `412` is a success. So that the client does not first need a token afterwards to read
        // its own device object, the problem carries it as the extension field `device`.
        // [GAP -> PROPOSAL] §7.0.5 names `GET /v1/devices/me` for that; but the call needs a
        // token, and that is exactly what does not exist before the approval.
        let mut problem = Problem::from_catalogue(
            ErrorKind::PreconditionFailed,
            412,
            "This device is already enrolled; the repeated attempt is a success.",
        );
        problem.instance = Some(inbox.path.clone());
        problem.further.insert("device".into(), device_object(&context.state, &device));
        return problem_response(412, &problem);
    }

    let state = if context.state.configuration.auto_approval {
        DeviceState::Active
    } else {
        DeviceState::AwaitingApproval
    };
    let device = Device {
        identifier: device_identifier,
        jwk,
        kid: request.public_jwk.kid.clone().unwrap_or_else(|| format!("{device_identifier}#1")),
        name: request.requested_name.clone(),
        state,
        provisioned: now(),
        request: body,
    };
    let object = device_object(&context.state, &device);
    context.state.lock().devices.insert(device_identifier, device);
    json_with_headers(
        201,
        &object,
        &[(header::LOCATION, format!("{}/v1/devices/{device_identifier}", context.state.api_base))],
    )
}

/// `GET /v1/devices/me` (03 §6.2.1, scope `device:self`).
async fn own_device(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, session) = match access(&context, request, &["device:self"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let device = context.state.lock().devices.get(&session.device()).cloned();
    match device {
        Some(device) => json_response(200, &device_object(&context.state, &device)),
        None => catalogue(ErrorKind::NotFound, 404, "This device does not exist.", &inbox.path),
    }
}

/// `POST /v1/devices/{deviceId}:heartbeat` (03 §6.4.1, §7.0.10).
async fn heartbeat(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let Some(raw) = identifier.strip_suffix(":heartbeat") else {
        return catalogue(
            ErrorKind::NotFound,
            404,
            "Under /v1/devices/{id} there is only the action :heartbeat.",
            "/v1/devices",
        );
    };
    let (inbox, session) = match access(&context, request, &["device:self"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let Ok(device) = raw.parse::<DeviceIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            "The device identifier in the path is not canonical (03 §6.0.3).",
            &inbox.path,
        );
    };
    if device != session.device() {
        return golden_problem("problem_token_device_binding.json", 403, &inbox.path);
    }
    let commands: Vec<Value> = std::mem::take(&mut context.state.lock().heartbeat_command);
    let mut response = json!({
        "serverTime": now().rfc3339(),
        "clockOffsetMs": 0,
        "deviceState": "active",
        "configEtag": context.state.lock().key_state.to_string(),
        "nextHeartbeatSeconds": 300,
    });
    if !commands.is_empty() {
        response["commands"] = Value::Array(commands);
    }
    json_response(200, &response)
}

/// `GET /v1/server-keys` (03 §6.2.4, scope `device:self`).
async fn server_key(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["device:self"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    match context.state.key_block() {
        Ok(block) => json_response(200, &block),
        Err(error) => catalogue(
            ErrorKind::ServerKeyNotAvailable,
            503,
            &format!("The key set cannot be built right now: {error}"),
            &inbox.path,
        ),
    }
}

// ───────────────────────────── Namespace ─────────────────────────────

/// `GET /v1/mirror/baskets` (§7.1.1, scope `folders:read`).
async fn basket_list(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["folders:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let rows: Vec<(BasketRow, u64)> = context
        .state
        .lock()
        .baskets
        .iter()
        .map(|entry| {
            (
                BasketRow { basket_id: entry.identifier, title: entry.title.clone() },
                identity_state(entry.identifier.value()),
            )
        })
        .collect();
    container_page(&context, &inbox, rows)
}

/// `GET /v1/mirror/archives` (§7.1.1, scope `folders:read`).
async fn archive_list(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["folders:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let rows: Vec<(ArchiveRow, u64)> = context
        .state
        .lock()
        .archives
        .iter()
        .map(|entry| {
            (
                ArchiveRow { archive_id: entry.identifier, title: entry.title.clone() },
                identity_state(entry.identifier.value()),
            )
        })
        .collect();
    container_page(&context, &inbox, rows)
}

/// `GET /v1/mirror/archives/{archiveId}/cases` (§7.1.1, scope `folders:read`).
///
/// The case files of **this** archive and of no other: the entry the client builds out of a row is
/// `Container::Case { archive, case }`, and an archive that delivered a foreign case file would
/// hand it a folder whose parent it does not stand in.
async fn case_list(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["folders:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let Ok(archive) = identifier.parse::<ArchiveIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            "The archive identifier in the path is not canonical (03 §6.0.3).",
            &inbox.path,
        );
    };
    let inner = context.state.lock();
    if !inner.has_archive(archive) {
        drop(inner);
        // An empty page here would say "this archive holds no case file" — a statement about an
        // archive the user may not even be allowed to see (§7.5.1).
        return catalogue(
            ErrorKind::NotFound,
            404,
            "This archive is not visible to you.",
            &inbox.path,
        );
    }
    let rows: Vec<(CaseRow, u64)> = inner
        .container
        .iter()
        .filter_map(|c| match c.location {
            Location::Case { archive: holder, case } if holder == archive => Some((
                CaseRow {
                    case_id: case,
                    title: c.title.clone(),
                    updated_at: WireTimestamp::from_timestamp(c.changed),
                },
                c.version,
            )),
            Location::Case { .. } | Location::Search(_) => None,
        })
        .collect();
    drop(inner);
    container_page(&context, &inbox, rows)
}

/// `GET /v1/mirror/searches` (§7.1.1, scope `folders:read`).
async fn search_list(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["folders:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let rows: Vec<(SearchRow, u64)> = context
        .state
        .lock()
        .container
        .iter()
        .filter_map(|c| match c.location {
            Location::Search(saved_search_id) => Some((
                SearchRow {
                    saved_search_id,
                    title: c.title.clone(),
                    updated_at: WireTimestamp::from_timestamp(c.changed),
                },
                c.version,
            )),
            Location::Case { .. } => None,
        })
        .collect();
    container_page(&context, &inbox, rows)
}

/// What a listing entry without a state of its own contributes to the ETag of its page.
///
/// A basket and an archive carry no `updatedAt`: they hold nothing whose change could be dated
/// (§7.1.1). Their identity is therefore their whole state — folded into [`list_version`], an
/// entry that comes or goes gives the listing a different ETag, and no `304` can hide it.
fn identity_state(identifier: u128) -> u64 {
    (identifier & u128::from(u64::MAX)) as u64
}

/// Page, ETag and `304` for the four container listings.
fn container_page<T: serde::Serialize>(
    context: &Context,
    inbox: &Inbox,
    rows: Vec<(T, u64)>,
) -> Response {
    let etag = match strong_etag(&list_version(rows.iter().map(|(_, v)| *v)).to_string()) {
        Ok(etag) => etag,
        Err(error) => {
            return catalogue(ErrorKind::Unknown, 500, &error.to_string(), &inbox.path);
        }
    };
    if inbox.header_value(header::IF_NONE_MATCH) == Some(etag.as_str()) {
        return bytes_response(304, media_type::JSON, Vec::new(), &[(header::ETAG, etag)]);
    }
    let limit = match page_size(context, inbox) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let offset = match offset_from_cursor(inbox) {
        Ok(offset) => offset,
        Err(response) => return response,
    };
    let all: Vec<T> = rows.into_iter().map(|(row, _)| row).collect();
    let (part, further) = from_cut(all, offset, limit);
    let page = Page {
        items: part,
        next_cursor: further.map(|next| cursor("o", next)),
        has_more: further.is_some(),
    };
    json_with_headers(200, &page, &[(header::ETAG, etag)])
}

/// `GET /v1/mirror/archives/{archiveId}/cases/{caseId}/documents`.
///
/// Both identifiers are read, and both have to fit: the same case file under a different archive
/// is a different location and gets the `404` of §7.5.1, never the documents.
async fn case_document(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path((archive, case)): axum::extract::Path<(String, String)>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["documents:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let location = match (archive.parse::<ArchiveIdentifier>(), case.parse::<CaseIdentifier>()) {
        (Ok(archive), Ok(case)) => Location::Case { archive, case },
        (Err(error), _) | (_, Err(error)) => {
            return catalogue(
                ErrorKind::ResourceIdentifierInvalid,
                400,
                &error.to_string(),
                &inbox.path,
            );
        }
    };
    document_page(&context, &inbox, location)
}

/// `GET /v1/mirror/searches/{savedSearchId}/documents`.
async fn search_document(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["documents:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    match identifier.parse::<SearchIdentifier>() {
        Ok(search) => document_page(&context, &inbox, Location::Search(search)),
        Err(error) => {
            catalogue(ErrorKind::ResourceIdentifierInvalid, 400, &error.to_string(), &inbox.path)
        }
    }
}

/// The document page together with a visible truncation (§7.1.2).
fn document_page(context: &Context, inbox: &Inbox, location: Location) -> Response {
    let inner = context.state.lock();
    let Some(container) = inner.container(location) else {
        // `404` never means "does not exist", always "not visible to you" (§7.5.1).
        return catalogue(
            ErrorKind::NotFound,
            404,
            "This list is not visible to you.",
            &inbox.path,
        );
    };
    if let Some((field, reason)) = container.not_runnable.clone() {
        // An empty folder would be the third, forbidden answer here: it would look like "nothing
        // found" and would mean "not allowed" (ADR-014, §7.1.3).
        let mut response = golden_problem("problem_search_not_executable.json", 422, &inbox.path);
        if let Ok(mut problem) =
            serde_json::from_str::<Problem>(edms_wire::golden("problem_search_not_executable.json"))
        {
            problem.instance = Some(inbox.path.clone());
            problem.detail = Some(reason);
            problem.errors = Some(vec![FieldError {
                field: Some(field),
                code: Some("field-not-readable".to_owned()),
                further: serde_json::Map::new(),
            }]);
            response = problem_response(422, &problem);
        }
        return response;
    }
    let limit = container.display_limit.unwrap_or(context.state.configuration.display_limit);
    let total = container.content.len() as u64;
    let truncated = total > limit;
    let visible = usize::try_from(total.min(limit)).unwrap_or(usize::MAX);
    let refinement = container.refinement.clone();
    let version = container.version;
    let rows: Vec<DocumentRow> = container
        .content
        .iter()
        .take(visible)
        .filter_map(|identifier| inner.documents.get(identifier))
        .map(|doc| DocumentRow {
            document_id: doc.identifier,
            title: doc.title.clone(),
            media_type: doc.media_type.clone(),
            size: doc.bytes.len() as u64,
            sha256: doc.sha256,
            version: doc.version.to_string(),
            created_at: WireTimestamp::from_timestamp(doc.created),
            updated_at: WireTimestamp::from_timestamp(doc.changed),
        })
        .collect();
    drop(inner);

    let etag = match strong_etag(&format!("{version}-{}", rows.len())) {
        Ok(etag) => etag,
        Err(error) => {
            return catalogue(ErrorKind::Unknown, 500, &error.to_string(), &inbox.path);
        }
    };
    if inbox.header_value(header::IF_NONE_MATCH) == Some(etag.as_str()) {
        return bytes_response(304, media_type::JSON, Vec::new(), &[(header::ETAG, etag)]);
    }
    let page_size = match page_size(context, inbox) {
        Ok(size) => size,
        Err(response) => return response,
    };
    let offset = match offset_from_cursor(inbox) {
        Ok(offset) => offset,
        Err(response) => return response,
    };
    let (part, further) = from_cut(rows, offset, page_size);
    let page = DocumentPage {
        items: part,
        next_cursor: further.map(|next| cursor("o", next)),
        has_more: further.is_some(),
        total_capped: truncated,
        display_limit: limit,
        refine_url: truncated.then_some(refinement).flatten(),
    };
    json_with_headers(200, &page, &[(header::ETAG, etag)])
}

// ───────────────────────────── Content ─────────────────────────────

/// `GET /v1/documents/{documentId}/content` — the fetch that is an access (§7.2).
async fn content(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, session) = match access(&context, request, &["documents:read"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let Ok(document) = identifier.parse::<DocumentIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            "The document identifier in the path is not canonical (03 §6.0.3).",
            &inbox.path,
        );
    };
    let application = match inbox.header_value(header::REQUESTING_APPLICATION) {
        None => None,
        Some(raw) => match edms_wire::content::decode_application(raw) {
            Ok(name) => Some(name),
            Err(error) => {
                // The value decides nothing (§7.2.4) — but a value that cannot be decoded is a
                // programming mistake in the client. A test harness that accepted it would write
                // a row into the log that nobody can believe any more.
                return catalogue(
                    ErrorKind::ValidationFailed,
                    400,
                    &format!("{}: {error}", header::REQUESTING_APPLICATION),
                    &inbox.path,
                );
            }
        },
    };
    let inner = context.state.lock();
    if inner.access_log_locked {
        drop(inner);
        // An access without a log entry is worse than a refused access (§7.2.3).
        return golden_problem("problem_access_log_missing.json", 503, &inbox.path);
    }
    let Some(doc) = inner.documents.get(&document).cloned() else {
        drop(inner);
        return catalogue(
            ErrorKind::NotFound,
            404,
            "This document is not visible to you.",
            &inbox.path,
        );
    };
    drop(inner);
    if doc.without_rendition {
        return golden_problem("problem_rendition_missing.json", 404, &inbox.path);
    }
    let etag = match strong_etag(&doc.version.to_string()) {
        Ok(etag) => etag,
        Err(error) => {
            return catalogue(ErrorKind::Unknown, 500, &error.to_string(), &inbox.path);
        }
    };
    if let Some(requires) = inbox.header_value(header::IF_MATCH)
        && requires != etag
    {
        return catalogue(
            ErrorKind::PreconditionFailed,
            412,
            "The document has a new version since the listing; the listing is to be fetched again.",
            &inbox.path,
        );
    }

    // Log first, deliver afterwards. The other order delivers bytes without a row in a failure
    // case — and exactly that only stands out when somebody needs the log.
    context.state.log_access(AccessEntry {
        timestamp: now(),
        user: session.access.user,
        device: session.device(),
        document,
        version: doc.version.to_string(),
        application,
    });

    let bytes = doc.sent_bytes();
    let complete = bytes.len() == doc.bytes.len();
    // Content-Length and Repr-Digest describe the **announced** rendition, not the body that is
    // sent: only that way does the client see, on a mangling, exactly what the real server shows
    // it — `200`, the right headers, too few bytes (§7.2.1, T13).
    let headers = [
        (header::CONTENT_LENGTH, doc.bytes.len().to_string()),
        (header::ETAG, etag),
        (header::REPR_DIGEST, digest_header_value(&doc.sha256)),
        (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ("X-Content-Type-Options", "nosniff".to_owned()),
    ];
    if complete {
        bytes_response(200, &doc.media_type, bytes, &headers)
    } else {
        cancelled_response(200, &doc.media_type, bytes, &headers)
    }
}

// ───────────────────────────── Delivery channel ─────────────────────────────

/// `GET /v1/delivery/commands?wait=…&cursor=…` — long poll, outbound only (§7.3.1).
async fn command_collect(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, session) = match access(&context, request, &["delivery:receive"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let max = context.state.configuration.wait_time_max;
    let wait: u32 = match inbox.query_value("wait") {
        None => 0,
        Some(text) => match text.parse() {
            Ok(value) if value <= max => value,
            _ => {
                return catalogue(
                    ErrorKind::ValidationFailed,
                    400,
                    &format!("wait lies outside 0 to {max} seconds (§7.3.1)."),
                    &inbox.path,
                );
            }
        },
    };
    let since = match offset_from_cursor_with(&inbox, "s") {
        Ok(since) => since as u64,
        Err(response) => return response,
    };

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(u64::from(wait));
    loop {
        let wait = context.state.waker.notified();
        let (item, state) = open_command(&context.state, session.device(), since);
        if !item.is_empty() || tokio::time::Instant::now() >= deadline {
            let page = DeliveryPage {
                items: item.iter().map(|job| job.value.clone()).collect(),
                next_cursor: cursor("s", usize::try_from(state).unwrap_or(usize::MAX)),
            };
            return json_response(200, &page);
        }
        // An elapsed wait with an empty list is the normal case, not a failure (§7.3.1).
        if tokio::time::timeout_at(deadline, wait).await.is_err() {
            let (item, state) = open_command(&context.state, session.device(), since);
            let page = DeliveryPage {
                items: item.iter().map(|job| job.value.clone()).collect(),
                next_cursor: cursor("s", usize::try_from(state).unwrap_or(usize::MAX)),
            };
            return json_response(200, &page);
        }
    }
}

/// The open commands of a device and the state of the cursor.
fn open_command(state: &State, device: DeviceIdentifier, since: u64) -> (Vec<CommandItem>, u64) {
    let inner = state.lock();
    let item: Vec<CommandItem> = inner
        .commands
        .iter()
        .filter(|job| job.device == device && job.sequence > since && !job.acknowledged)
        .take(MAX_COMMAND_PER_RESPONSE)
        .cloned()
        .collect();
    let state = item.last().map_or(since, |job| job.sequence);
    (item, state)
}

/// `POST /v1/delivery/commands/{commandId}:acknowledge` (§7.3.6).
async fn acknowledge(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(path_part): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, session) = match access(&context, request, &["delivery:receive"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let Some(raw) = path_part.strip_suffix(":acknowledge") else {
        return catalogue(
            ErrorKind::NotFound,
            404,
            "Under /v1/delivery/commands/{id} there is only the action :acknowledge.",
            &inbox.path,
        );
    };
    let Ok(command) = raw.parse::<CommandIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            "The command identifier in the path is not canonical (03 §6.0.3).",
            &inbox.path,
        );
    };
    let Some(key) = inbox.header_value(header::IDEMPOTENCY_KEY).map(ToOwned::to_owned) else {
        return catalogue(
            ErrorKind::ValidationFailed,
            400,
            "This acknowledgement needs an Idempotency-Key — one ULID per attempt (03 §6.0.10).",
            &inbox.path,
        );
    };
    // Replay: the same key with the same body gives the same answer; with a differing body it is
    // `422` (AND-2). One key per command would make a second, different acknowledgement
    // impossible.
    let body_checksum = State::checksum(&inbox.body);
    if let Some(entry) = context.state.lock().idempotency.get(&key).cloned() {
        if entry.body == body_checksum {
            return json_with_headers(
                entry.status,
                &entry.response,
                &[(header::IDEMPOTENCY_REPLAYED, "true".to_owned())],
            );
        }
        return catalogue(
            ErrorKind::IdempotencyKeyReused,
            422,
            "The same Idempotency-Key already came with a different body (03 §6.0.10).",
            &inbox.path,
        );
    }
    let acknowledgement = match inbox.as_json() {
        Ok(value) => value,
        Err(response) => return response,
    };
    let outcome = acknowledgement.get("outcome").and_then(Value::as_str).unwrap_or_default();
    if serde_json::from_value::<CommandOutcome>(json!(outcome)).is_err() {
        return catalogue(
            ErrorKind::ValidationFailed,
            422,
            "outcome is none of the four outcomes APPLIED, NOT_APPLICABLE, REJECTED, FAILED.",
            &inbox.path,
        );
    }
    if acknowledgement
        .get("detail")
        .and_then(Value::as_str)
        .is_some_and(|text| text.chars().count() > edms_wire::delivery::MAX_DETAIL_CHARACTER)
    {
        return catalogue(
            ErrorKind::ValidationFailed,
            422,
            "detail is longer than 500 characters (§7.3.6).",
            &inbox.path,
        );
    }

    let mut inner = context.state.lock();
    let Some(item) = inner.commands.iter_mut().find(|job| job.identifier == command) else {
        return catalogue(
            ErrorKind::CommandUnknown,
            404,
            "This command does not exist.",
            &inbox.path,
        );
    };
    if item.device != session.device() {
        return catalogue(
            ErrorKind::NotFound,
            404,
            "This command does not belong to this device.",
            &inbox.path,
        );
    }
    if item.acknowledged {
        // For the client that is a **success**: the command is done, the acknowledgement may
        // leave the queue (§7.3.6).
        return golden_problem("problem_command_already_acknowledged.json", 409, &inbox.path);
    }
    item.acknowledged = true;
    let receipt = json!({
        "commandId": command.to_string(),
        "outcome": outcome,
        "acknowledgedAt": now().rfc3339(),
    });
    inner.acknowledgement.insert(command, acknowledgement);
    inner.idempotency.insert(
        key,
        crate::state::IdempotencyEntry {
            body: body_checksum,
            status: 200,
            response: receipt.clone(),
        },
    );
    drop(inner);
    json_response(200, &receipt)
}

// ───────────────────────────── Ingest out of a mail basket ─────────────────────────────

/// `POST /v1/ingest-uploads` (§7.4.1, scope `ingest:submit`).
///
/// The submission names the basket it came out of; a basket that is gone is a `404` and nothing
/// is filed anywhere else (§7.4, namespace v2 §7).
async fn upload_apply_for(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["ingest:submit"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let body = match inbox.as_json() {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: UploadRequest = match serde_json::from_value(body) {
        Ok(request) => request,
        Err(error) => {
            return catalogue(
                ErrorKind::ValidationFailed,
                422,
                &format!("The upload request is unusable: {error}"),
                &inbox.path,
            );
        }
    };
    if let Err(error) = UploadRequest::new(
        request.basket_id,
        &request.file_name,
        &request.media_type,
        request.size,
        request.sha256,
    ) {
        return catalogue(ErrorKind::ValidationFailed, 422, &error.to_string(), &inbox.path);
    }
    if !context.state.lock().has_basket(request.basket_id) {
        // Before the idempotency key is even looked at: a grant for a basket that is gone would be
        // a promise to file the document somewhere the rule of no basket covers.
        return golden_problem("problem_basket_unknown.json", 404, &inbox.path);
    }
    // An Idempotency-Key is not compulsory here — but when it comes, it applies: a second call
    // with the same key may not produce a second grant, otherwise the same file would lie in the
    // inbox twice after a lost answer packet (03 §6.0.10).
    let key = inbox.header_value(header::IDEMPOTENCY_KEY).map(ToOwned::to_owned);
    let body_checksum = State::checksum(&inbox.body);
    if let Some(key) = &key
        && let Some(entry) = context.state.lock().idempotency.get(key).cloned()
    {
        if entry.body == body_checksum {
            return json_with_headers(
                entry.status,
                &entry.response,
                &[(header::IDEMPOTENCY_REPLAYED, "true".to_owned())],
            );
        }
        return catalogue(
            ErrorKind::IdempotencyKeyReused,
            422,
            "The same Idempotency-Key already came with a different body (03 §6.0.10).",
            &inbox.path,
        );
    }
    let mut inner = context.state.lock();
    let identifier: UploadIdentifier = inner.new_identifier();
    // A duplicate is **marked, not suppressed**: two invoices with an identical PDF can be two
    // separate matters (§7.4.2).
    let duplicate = inner.documents.values().find(|doc| doc.sha256 == request.sha256).map(|doc| {
        DuplicateHint {
            document_id: doc.identifier,
            title: doc.title.clone(),
            created_at: WireTimestamp::from_timestamp(doc.created),
        }
    });
    let expires = now().plus_millis(15 * 60 * 1_000);
    inner.upload.insert(
        identifier,
        Upload {
            identifier,
            basket: request.basket_id,
            filename: request.file_name.clone(),
            media_type: request.media_type.clone(),
            size: request.size,
            sha256: request.sha256,
            bytes: None,
            expires,
            completed: false,
        },
    );
    drop(inner);
    let grant = UploadGrant {
        upload_id: identifier,
        upload_url: format!("{}/v1/ingest-uploads/{identifier}/content", context.state.api_base),
        duplicate_of: duplicate,
        expires_at: WireTimestamp::from_timestamp(expires),
    };
    if let Some(key) = key {
        let response = serde_json::to_value(&grant).unwrap_or(Value::Null);
        context.state.lock().idempotency.insert(
            key,
            crate::state::IdempotencyEntry { body: body_checksum, status: 201, response },
        );
    }
    json_with_headers(201, &grant, &[(header::LOCATION, grant.upload_url.clone())])
}

/// `PUT /v1/ingest-upload/{uploadId}/content` — the bytes together with `Content-Digest`
/// (§7.4.1).
async fn upload_send(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["ingest:submit"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let Ok(upload) = identifier.parse::<UploadIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            "The upload identifier in the path is not canonical.",
            &inbox.path,
        );
    };
    let Some(announced) = context.state.lock().upload.get(&upload).cloned() else {
        return catalogue(ErrorKind::NotFound, 404, "This grant does not exist.", &inbox.path);
    };
    if announced.expires <= now() {
        return catalogue(
            ErrorKind::UploadExpired,
            410,
            "The grant has expired; the upload starts over.",
            &inbox.path,
        );
    }
    let Some(header_value) = inbox.header_value(header::CONTENT_DIGEST) else {
        return catalogue(
            ErrorKind::ValidationFailed,
            400,
            "The PUT carries no Content-Digest; without it a damaged line could not be told apart \
             from a different file (§7.4.1).",
            &inbox.path,
        );
    };
    let reported = match read_digest_header(header_value) {
        Ok(value) => value,
        Err(error) => {
            return catalogue(ErrorKind::ValidationFailed, 400, &error.to_string(), &inbox.path);
        }
    };
    let computed = State::checksum(&inbox.body);
    if reported != computed || computed != announced.sha256 {
        return golden_problem("problem_upload_digest.json", 422, &inbox.path);
    }
    if let Some(entry) = context.state.lock().upload.get_mut(&upload) {
        entry.bytes = Some(inbox.body.to_vec());
    }
    empty(204)
}

/// `POST /v1/ingest-upload/{uploadId}:complete` (§7.4.3).
async fn upload_complete(
    axum::extract::State(context): axum::extract::State<Context>,
    axum::extract::Path(path_part): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response {
    let (inbox, _) = match access(&context, request, &["ingest:submit"]).await {
        Ok(both) => both,
        Err(response) => return response,
    };
    let Some(raw) = path_part.strip_suffix(":complete") else {
        return catalogue(
            ErrorKind::NotFound,
            404,
            "Under /v1/ingest-uploads/{id} there is only the action :complete.",
            &inbox.path,
        );
    };
    let Ok(upload) = raw.parse::<UploadIdentifier>() else {
        return catalogue(
            ErrorKind::ResourceIdentifierInvalid,
            400,
            "The upload identifier in the path is not canonical.",
            &inbox.path,
        );
    };
    let mut inner = context.state.lock();
    let Some(entry) = inner.upload.get_mut(&upload) else {
        return catalogue(ErrorKind::NotFound, 404, "This grant does not exist.", &inbox.path);
    };
    if entry.expires <= now() {
        return catalogue(ErrorKind::UploadExpired, 410, "The grant has expired.", &inbox.path);
    }
    if entry.bytes.is_none() {
        return catalogue(
            ErrorKind::UploadIncomplete,
            409,
            ":complete came before the last byte.",
            &inbox.path,
        );
    }
    entry.completed = true;
    drop(inner);
    let completion = UploadCompletion {
        upload_id: upload,
        state: InboxState::InInbox,
        capture_url: format!(
            "{}{}?upload={upload}",
            context.state.app_base.trim_end_matches('/'),
            crate::auth::PATH_CAPTURE
        ),
    };
    json_response(200, &completion)
}

// ───────────────────────────── Development aid ─────────────────────────────

/// `POST /mock/commands` — a delivery command by `curl`, from 127.0.0.1 only.
///
/// This is **not** part of the contract; the path lies outside `/v1/` and carries the mock's name,
/// so that nobody takes it for an endpoint of the server. It exists because otherwise a developer
/// would have to write a Rust program to trigger an erasure.
async fn dev_command(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let body = match inbox.as_json() {
        Ok(body) => body,
        Err(response) => return response,
    };
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or("RECONCILE").to_owned();
    let payload = body.get("payload").cloned().unwrap_or_else(|| json!({}));
    let quality = match body.get("quality").and_then(Value::as_str).unwrap_or("valid") {
        "foreign-signature" => CommandQuality::ForeignSignature,
        "broken-signature" => CommandQuality::BrokenSignature,
        "without-signature" => CommandQuality::WithoutSignature,
        "wrong-typ" => CommandQuality::WrongTyp("edms-qc-clearance+jwt".to_owned()),
        _ => CommandQuality::Valid,
    };
    let device = match body.get("deviceId").and_then(Value::as_str) {
        Some(text) => match text.parse::<DeviceIdentifier>() {
            Ok(identifier) => Some(identifier),
            Err(error) => {
                return catalogue(
                    ErrorKind::ResourceIdentifierInvalid,
                    400,
                    &error.to_string(),
                    &inbox.path,
                );
            }
        },
        None => context.state.lock().devices.keys().next().copied(),
    };
    let Some(device) = device else {
        return catalogue(
            ErrorKind::ValidationFailed,
            422,
            "No device is enrolled; without a device there is no recipient.",
            &inbox.path,
        );
    };
    let control = crate::Control::new(context.state.clone());
    match control.queue_command(device, &kind, payload, quality) {
        Ok(identifier) => json_response(
            201,
            &json!({ "commandId": identifier.to_string(), "deviceId": device.to_string() }),
        ),
        Err(error) => catalogue(ErrorKind::Unknown, 500, &error.to_string(), &inbox.path),
    }
}

// ───────────────────────────── Shared ─────────────────────────────

/// Reads the request and checks access in one step.
// The error side of these results is the **finished HTTP answer**, not a reason one is made out of
// afterwards. That is deliberate: every rejection of the contract has exactly one body, one header
// and one status, and whoever builds it at the place it occurs cannot accidentally build it
// differently elsewhere. `Response` is large for that (128 bytes); a box around it would save
// nothing on a test harness and would bring a `*` to every place it occurs.
#[allow(clippy::result_large_err)]
async fn access(
    context: &Context,
    request: axum::extract::Request,
    needs: &[&str],
) -> Result<(Inbox, Session), Response> {
    let inbox = Inbox::read(context, request).await?;
    let session = check_access(context, &inbox, needs)?;
    Ok((inbox, session))
}

/// `limit` out of the query, strictly per 03 §6.0.8 (1 to 1000).
#[allow(clippy::result_large_err)]
fn page_size(context: &Context, inbox: &Inbox) -> Result<usize, Response> {
    let default = context.state.configuration.page_size;
    let limit = match inbox.query_value("limit") {
        None => default,
        Some(text) => match text.parse::<u32>() {
            Ok(value) if (1..=LIMIT_MAX).contains(&value) => value,
            _ => {
                return Err(catalogue(
                    ErrorKind::ValidationFailed,
                    400,
                    &format!("limit lies outside 1 to {LIMIT_MAX} (03 §6.0.8)."),
                    &inbox.path,
                ));
            }
        },
    };
    Ok(usize::try_from(limit).unwrap_or(200))
}

/// The offset out of the cursor; an unreadable cursor is a **failure** (§7.1.1, T16).
#[allow(clippy::result_large_err)]
fn offset_from_cursor(inbox: &Inbox) -> Result<usize, Response> {
    offset_from_cursor_with(inbox, "o")
}

/// The same reader for the delivery channel, whose cursor is called `s`.
#[allow(clippy::result_large_err)]
fn offset_from_cursor_with(inbox: &Inbox, field: &str) -> Result<usize, Response> {
    let Some(text) = inbox.query_value("cursor") else { return Ok(0) };
    if text.is_empty() {
        return Err(golden_problem("problem_cursor_invalid.json", 400, &inbox.path));
    }
    read_cursor(text, field)
        .ok_or_else(|| golden_problem("problem_cursor_invalid.json", 400, &inbox.path))
}

/// Builds an opaque cursor. The client never reads it out, it only hands it back.
fn cursor(field: &str, value: usize) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{{\"{field}\":{value}}}").as_bytes())
}

/// Reads a cursor; `None` means "unreadable".
fn read_cursor(text: &str, field: &str) -> Option<usize> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text).ok()?;
    let value: Value = serde_json::from_slice(&raw).ok()?;
    usize::try_from(value.get(field)?.as_u64()?).ok()
}

/// The slice of a list together with the offset of the next page.
fn from_cut<T>(all: Vec<T>, offset: usize, size: usize) -> (Vec<T>, Option<usize>) {
    let total = all.len();
    let part: Vec<T> = all.into_iter().skip(offset).take(size).collect();
    let next = offset.saturating_add(part.len());
    (part, (next < total).then_some(next))
}

/// The version of a whole list: the number of entries and the sum of their states.
fn list_version(states: impl Iterator<Item = u64>) -> u64 {
    states.fold(1, |sum, state| sum.wrapping_mul(31).wrapping_add(state))
}

/// The device object as `device_desktop.json` shows it — with this mock's addresses.
fn device_object(state: &State, device: &Device) -> Value {
    let key = state.key_block().unwrap_or(Value::Null);
    json!({
        "deviceId": device.identifier.to_string(),
        "state": device.state.wire_value(),
        "deviceKind": "desktop",
        "name": device.name.clone(),
        "tenant": {
            "id": state.configuration.tenant,
            "name": state.configuration.tenant_name,
        },
        "attestation": {
            "tier": "SOFTWARE",
            "verdict": {
                "chainRootsInGoogleAttestationRoot": false,
                "verifiedBootState": Value::Null,
                "reason": "attestation_type_none",
            },
            "keyThumbprint": device.jwk.thumbprint(),
            "adminConfirmationRequired": !state.configuration.auto_approval,
        },
        "oauth": {
            "clientId": device.identifier.to_string(),
            "tokenEndpoint": format!("{}{}", state.auth_base, edms_wire::login::PATH_TOKEN),
            "tokenEndpointAuthMethod": "private_key_jwt",
            "tokenEndpointAuthSigningAlg": "ES256",
            "grantTypes": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
                "refresh_token",
            ],
            "deviceScopes": edms_wire::login::DEVICE_SCOPES,
            "dpopBoundAccessTokens": true,
        },
        "policy": {
            "heartbeatIntervalSeconds": 300,
            "idleSessionSeconds": 28_800,
            "absoluteSessionSeconds": 43_200,
            "deliveryWaitSeconds": state.configuration.wait_time_max,
        },
        "serverKeys": key,
        "enrolledAt": device.provisioned.rfc3339(),
        "enrolledBy": {
            "sub": crate::state::USER,
            "displayName": crate::state::USER_NAME,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_survives_the_round_trip_and_a_foreign_one_is_unreadable() {
        let value = cursor("o", 42);
        assert_eq!(read_cursor(&value, "o"), Some(42));
        assert_eq!(read_cursor(&value, "s"), None, "a cursor belongs to exactly one list");
        assert_eq!(read_cursor("not base64 !", "o"), None);
        assert_eq!(read_cursor("", "o"), None);
    }

    #[test]
    fn the_slice_reports_the_next_page_only_when_there_is_one() {
        let (part, further) = from_cut(vec![1, 2, 3, 4, 5], 0, 2);
        assert_eq!(part, vec![1, 2]);
        assert_eq!(further, Some(2));
        let (part, further) = from_cut(vec![1, 2, 3, 4, 5], 4, 2);
        assert_eq!(part, vec![5]);
        assert_eq!(further, None, "hasMore would be a lie about an empty page here");
        let (part, further) = from_cut(Vec::<u8>::new(), 0, 2);
        assert!(part.is_empty() && further.is_none());
    }

    #[test]
    fn the_routes_of_the_namespace_are_the_addresses_the_wire_hands_out() {
        let archive: ArchiveIdentifier =
            "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3".parse().expect("an archive");
        let case: CaseIdentifier = "cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7".parse().expect("a case file");
        let search: SearchIdentifier =
            "srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2".parse().expect("a saved search");
        assert_eq!(
            PATH_CASES_OF_ARCHIVE.replace("{archive}", &archive.to_string()),
            edms_wire::namespace::path_cases(archive),
            "the mock would serve an address the client never calls"
        );
        assert_eq!(
            PATH_CASE_DOCUMENT
                .replace("{archive}", &archive.to_string())
                .replace("{case}", &case.to_string()),
            edms_wire::namespace::path_document(Location::Case { archive, case })
        );
        assert_eq!(
            PATH_SEARCH_DOCUMENT.replace("{search}", &search.to_string()),
            edms_wire::namespace::path_document(Location::Search(search))
        );
    }

    #[test]
    fn an_entry_without_a_state_of_its_own_still_moves_the_etag_of_its_page() {
        let one = identity_state(0x0193_4B00_7000_8000_0000_0000_0000_0101);
        let other = identity_state(0x0193_4B00_7000_8000_0000_0000_0000_0102);
        assert_ne!(one, other, "two baskets with the same state would share one ETag");
        assert_ne!(
            list_version([one, other].into_iter()),
            list_version([other, one].into_iter()),
            "a listing that reorders is a listing that changed"
        );
    }

    #[test]
    fn the_list_version_changes_with_every_state() {
        let a = list_version([1, 2, 3].into_iter());
        let b = list_version([1, 2, 4].into_iter());
        let shorter = list_version([1, 2].into_iter());
        assert_ne!(a, b);
        assert_ne!(a, shorter);
    }
}
