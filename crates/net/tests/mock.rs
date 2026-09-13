//! The honest way: this client against the contract-faithful server mock.
//!
//! `tests/contract.rs` checks with a test rig that lies on request — a second nonce prompt, a
//! redirect, a mutilated body. Here stands the counterpart: [`edms_mock`] speaks the same contract
//! **correctly** and really checks every DPoP proof (key, `htm`, `htu`, `nonce`, `ath`, replay). A
//! client that gets through here has not only set the right headers but also reckoned correctly.
//!
//! That is exactly the purpose of four copies of the same contract (contract document, `edms-wire`,
//! `edms-mock`, `edms-net`): they hold each other fast. A test against one's own idea of the server
//! stays green while the counterpart has long been speaking something else.
//!
//! **The clock goes right here.** The mock checks `iat` against its own now; a client with a fixed
//! test clock falls out of the time window — rightly so.

// Test code may `unwrap` (clippy.toml); helper functions stand outside `#[test]`, and there clippy
// does not recognise them as test code.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use edms_core::delivery::CommandOutcome;
use edms_core::identifier::DeviceIdentifier;
use edms_core::namespace::Location;
use edms_crypto::key::{SigningKey, SoftwareKey};
use edms_mock::{CommandQuality, Configuration, Mock};
use edms_net::server::{AcknowledgementOutcome, LoginIntent, LoginOutcome};
use edms_net::{
    ApiResult, Connection, IdempotencyKey, KeyBinding, KeySource, Secret, Server, ServerAccess,
};
use edms_wire::basics::ErrorKind;
use edms_wire::delivery::{Acknowledgement, DeliveryQuery};
use edms_wire::device::{
    Application, AttestationDetail, DeviceKind, EnrollmentRequest, OperatingSystem, Platform,
    PublicJwk,
};
use edms_wire::ingest::UploadRequest;
use edms_wire::login::DeviceAuthorization;
use edms_wire::namespace::ListQuery;

const DEVICE: &str = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB";

/// The test's key bundle: two keys, two tokens — the tokens come only in the course of the run.
struct Bundle {
    device: Arc<SoftwareKey>,
    session: Arc<SoftwareKey>,
    device_token: Mutex<Option<Secret>>,
    user_token: Mutex<Option<Secret>>,
}

impl Bundle {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            device: Arc::new(SoftwareKey::generate().unwrap()),
            session: Arc::new(SoftwareKey::generate().unwrap()),
            device_token: Mutex::new(None),
            user_token: Mutex::new(None),
        })
    }

    fn set(field: &Mutex<Option<Secret>>, token: &str) {
        *field.lock().unwrap_or_else(|f| f.into_inner()) = Some(Secret::new(token));
    }

    /// The public device key, as it is reported at the enrolment.
    fn jwk(&self) -> PublicJwk {
        let public = self.device.public();
        PublicJwk::p256(
            public.jwk().x().to_owned(),
            public.jwk().y().to_owned(),
            Some(format!("{DEVICE}#1")),
        )
    }
}

impl KeySource for Bundle {
    fn key(&self, binding: KeyBinding) -> Option<Arc<dyn SigningKey>> {
        Some(match binding {
            KeyBinding::Device => Arc::clone(&self.device) as Arc<dyn SigningKey>,
            KeyBinding::Session => Arc::clone(&self.session) as Arc<dyn SigningKey>,
        })
    }

    fn device_kid(&self) -> Option<String> {
        Some(format!("{DEVICE}#1"))
    }

    fn token(&self, binding: KeyBinding) -> Option<Secret> {
        let field = match binding {
            KeyBinding::Device => &self.device_token,
            KeyBinding::Session => &self.user_token,
        };
        field.lock().unwrap_or_else(|f| f.into_inner()).clone()
    }
}

fn device() -> DeviceIdentifier {
    DEVICE.parse().unwrap()
}

fn request(bundle: &Bundle) -> EnrollmentRequest {
    EnrollmentRequest {
        enrollment_code: "K7QM-4T2X".to_owned(),
        device_kind: DeviceKind::Desktop,
        public_jwk: bundle.jwk(),
        // An invented chain would be worse than none; the honest statement leads to level SOFTWARE
        // and with it to the documented way over the confirmation (§7.0.5).
        attestation: AttestationDetail::no(),
        platform: Platform {
            os: OperatingSystem::MacOs,
            os_version: "26.0".to_owned(),
            arch: "aarch64".to_owned(),
        },
        app: Application {
            package_name: Some("de.elasticdms.folderclient".to_owned()),
            version_name: "1.0.0".to_owned(),
            build_hash: None,
            signature_sha256: None,
        },
        requested_name: Some("Arbeitsplatz Buchhaltung EG".to_owned()),
    }
}

fn access(mock: &Mock, bundle: Arc<Bundle>) -> ServerAccess {
    let connection = Connection::new(mock.api_base(), mock.auth_base(), device(), "1.0.0").unwrap();
    // The real clock: the mock checks `iat` against its own now.
    ServerAccess::new(connection, bundle).unwrap()
}

/// An idempotency key **per attempt**, never per operation: the same key with a differing body is
/// `422 idempotency-key-reuse` (03 §6.0.10). The mock holds to exactly that.
fn new_key() -> IdempotencyKey {
    IdempotencyKey::generate(edms_core::time::Timestamp::from_unix_millis(
        i64::try_from(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
        )
        .unwrap(),
    ))
    .unwrap()
}

/// The same sign-in with a shorter interval — the client keeps every interval the server names,
/// and five seconds of waiting per test are nothing here but five seconds.
fn faster(login: &DeviceAuthorization) -> DeviceAuthorization {
    let mut short = login.clone();
    short.interval = Some(1);
    short
}

#[tokio::test]
async fn the_whole_way_from_the_enrolment_to_the_acknowledgement() {
    let mock = Mock::start(Configuration::default()).await.unwrap();
    let control = mock.control();
    let bundle = Bundle::new();
    let access = access(&mock, Arc::clone(&bundle));

    // ── Discovery: the endpoints come from the server, not from the program ────────────────
    let discovery = access.discover().await.value().expect("both .well-known documents");
    assert_eq!(discovery.endpoint.token, format!("{}/v1/oauth/token", mock.auth_base()));

    // ── Enrolment: without Authorization, without DPoP, with If-None-Match: * ──────────────
    let report =
        access.register_device(&request(&bundle)).await.value().expect("the enrolment succeeds");
    assert!(!report.inventory_already);
    let device_object = report.device.expect("the answer carries the device");
    assert_eq!(device_object.device_id, device());
    assert!(device_object.server_keys.is_some(), "and the key block (T3)");

    // A second attempt is the repetition after a network break: `412`, and that is success.
    let second =
        access.register_device(&request(&bundle)).await.value().expect("412 is success (T2)");
    assert!(second.inventory_already);
    assert!(
        second.device.is_some(),
        "the mock encloses the device object; before the approval there would otherwise be no way \
         to it, because /v1/devices/me needs a token (§7.0.5, GAP)"
    );

    // ── Device token: the first call against the sign-in server runs by design into the nonce
    //    prompt and is repeated exactly once (T9). One sees it only by the fact that it
    //    succeeds. ────────────────────────────────────────────────────────────────────────────
    let device_token = access.fetch_device_token().await.value().expect("the device token");
    assert!(device_token.has_scope("delivery:receive"));
    Bundle::set(&bundle.device_token, &device_token.access_token);

    // ── Server keys and heartbeat run on the device token ──────────────────────────────────
    let offer = access.fetch_server_key().await.value().expect("the key set");
    assert!(!offer.anchors().is_empty(), "without an anchor nothing is ever removed by order");

    // ── User sign-in in the device flow ────────────────────────────────────────────────────
    let login = access
        .start_device_login(&LoginIntent::first_login())
        .await
        .value()
        .expect("the start of the device flow");
    assert!(login.anchor.is_some(), "the four-character anchor stands in the app's window");
    let outcome = access
        .wait_on_token(&faster(&login), &|_| ())
        .await
        .value()
        .expect("the mock confirms of its own accord");
    let user_token = match outcome {
        LoginOutcome::Issued(token) => token,
        other => panic!("expected an issued token, came: {other:?}"),
    };
    assert!(user_token.has_scope("documents:read"));
    let refresh = user_token.refresh_token.clone().expect("a refresh token");
    Bundle::set(&bundle.user_token, &user_token.access_token);

    // ── Namespace: baskets, archives, case files (Akten), documents — as they come ─────────
    let baskets = access
        .list_baskets(&ListQuery::new(None, None).unwrap(), None)
        .await
        .value()
        .expect("the basket listing");
    assert!(!baskets.entries.is_empty(), "the example tenant has mail baskets");
    let basket = baskets.entries[0].basket_id;

    let archives = access
        .list_archives(&ListQuery::new(None, None).unwrap(), None)
        .await
        .value()
        .expect("the archive listing");
    assert!(!archives.entries.is_empty(), "the example tenant has archives");
    let archive = archives.entries[0].archive_id;

    let cases = access
        .list_cases(archive, &ListQuery::new(None, None).unwrap(), None)
        .await
        .value()
        .expect("the case listing");
    assert!(!cases.entries.is_empty(), "the first archive has case files");
    assert!(!cases.limit_reached);

    // The same fetch with the ETag is `304` — and not an empty listing.
    let unchanged = access
        .list_cases(archive, &ListQuery::new(None, None).unwrap(), cases.etag.as_deref())
        .await;
    assert!(matches!(unchanged, ApiResult::Unchanged { .. }));

    // The seed puts the two case files into two different archives: a listing that dropped its
    // archive would deliver the other one's case file here, and this comparison would notice.
    let other = archives.entries[1].archive_id;
    let others = access
        .list_cases(other, &ListQuery::new(None, None).unwrap(), None)
        .await
        .value()
        .expect("the case listing of the second archive");
    assert_ne!(
        cases.entries[0].case_id, others.entries[0].case_id,
        "a case file hangs under exactly one archive (ADR-D11 §1)"
    );

    let case = cases.entries[0].case_id;
    let documents = access
        .list_document(Location::Case { archive, case }, &ListQuery::new(None, None).unwrap(), None)
        .await
        .value()
        .expect("the document listing");
    assert!(!documents.rows.is_empty(), "the first case file has documents");
    let row = documents.rows[0].clone();

    // ── Content: the bytes arrive exactly as the listing announced them ────────────────────
    let mut sink = Vec::new();
    let report =
        access.load_content(&row, Some("Preview"), &mut sink).await.value().expect("the content");
    assert_eq!(report.bytes, row.size);
    assert_eq!(
        edms_crypto::checksum::sha256(&sink),
        row.sha256,
        "what arrives is exactly what the listing promised"
    );

    // Every hydration is an access and stands in the server's log (§7.2.3).
    let log = control.access_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].document, row.document_id);
    assert_eq!(log[0].device, device());
    assert_eq!(
        log[0].application.as_deref(),
        Some("Preview"),
        "the program name is an observation, and it arrives"
    );

    // ── Delivery channel: a signed command, collected and acknowledged ─────────────────────
    let command = control
        .queue_command(
            device(),
            "DEHYDRATE",
            serde_json::json!({ "documentIds": [row.document_id.to_string()], "reason": "ERASURE" }),
            CommandQuality::Valid,
        )
        .unwrap();
    let page = access
        .delivery_collect(&DeliveryQuery::new(1, None).unwrap())
        .await
        .value()
        .expect("the delivery page");
    assert_eq!(page.items.len(), 1);
    let envelope = page.envelopes().remove(0).expect("a readable envelope");
    assert_eq!(envelope.command_id(), command);
    assert!(envelope.server_signature().is_some(), "without a signature nothing is ever executed");

    let outcome = access
        .acknowledge(command, &Acknowledgement::new(CommandOutcome::Applied, None), &new_key())
        .await
        .value()
        .expect("the acknowledgement");
    match outcome {
        AcknowledgementOutcome::Accepted(receipt) => assert_eq!(receipt.command_id, command),
        other => panic!("expected a receipt, came: {other:?}"),
    }
    assert!(control.acknowledgement(command).is_some(), "the server has stored it");

    // ── Ingest: upload first, then the browser would be next (ADR-D08) ─────────────────────
    let bytes = b"%PDF-1.7 ingest";
    let sha = edms_crypto::checksum::sha256(bytes);
    let request = UploadRequest::new(
        basket,
        "Rechnung 2026-0412.pdf",
        "application/pdf",
        bytes.len() as u64,
        sha,
    )
    .unwrap();
    let grant = match access.inbox_create(&request, &new_key()).await {
        ApiResult::Success(success) => success.value,
        other => panic!("the grant: {other:?}"),
    };
    let path = std::env::temp_dir().join("edms-net-mock-ingest.pdf");
    tokio::fs::write(&path, bytes).await.unwrap();
    let file = tokio::fs::File::open(&path).await.unwrap();
    let uploaded = access.inbox_high_load(&grant, file, bytes.len() as u64, sha).await;
    let _ = tokio::fs::remove_file(&path).await;
    assert!(uploaded.is_success(), "the upload: {uploaded:?}");
    let completion =
        access.inbox_complete(grant.upload_id, &new_key()).await.value().expect("the completion");
    assert!(
        completion.browser_target(mock.app_base()).is_ok(),
        "the capture page lies below the web interface"
    );

    // ── End of session: renew, then revoke ─────────────────────────────────────────────────
    let renewed = access.refresh_token(&Secret::new(&refresh)).await.value().expect("the renewal");
    let new_refresh = renewed.refresh_token.clone().expect("every renewal rotates");
    assert_ne!(new_refresh, refresh, "the old refresh token is used up");

    assert!(access.revoke(&Secret::new(&new_refresh)).await.is_success());

    mock.stop().await;
}

#[tokio::test]
async fn a_device_without_approval_gets_no_token_and_learns_why() {
    // `state: "pending_admin_approval"` is the rule, not the exception: without the check by a
    // human being, anybody who installs the software could enrol a device against the tenant
    // (§7.0.5).
    let mock = Mock::start(Configuration::default().awaiting_approval()).await.unwrap();
    let bundle = Bundle::new();
    let access = access(&mock, Arc::clone(&bundle));

    let report = access.register_device(&request(&bundle)).await.value().expect("the enrolment");
    assert!(!report.device.expect("the device object").is_active());

    let result = access.fetch_device_token().await;
    assert_eq!(result.error_kind(), Some(ErrorKind::DeviceApprovalPending));
    assert!(!result.is_success());

    // After the approval by the administrator the same call goes through — without a new enrolment.
    assert!(mock.control().approve_device(device()));
    let token = access.fetch_device_token().await.value().expect("now there is a token");
    assert!(token.has_scope("device:self"));

    mock.stop().await;
}

#[tokio::test]
async fn a_human_who_refuses_gets_no_token() {
    // "The human refused" is an outcome of its own, no expiry and no error.
    let configuration = Configuration { auto_confirmation: false, ..Configuration::default() };
    let mock = Mock::start(configuration).await.unwrap();
    let control = mock.control();
    let bundle = Bundle::new();
    let access = access(&mock, Arc::clone(&bundle));

    let _ = access.register_device(&request(&bundle)).await.value().expect("the enrolment");
    let token = access.fetch_device_token().await.value().expect("the device token");
    Bundle::set(&bundle.device_token, &token.access_token);

    let login =
        access.start_device_login(&LoginIntent::first_login()).await.value().expect("the start");
    assert!(control.reject(&login.user_code), "the human says no");

    let outcome = access
        .wait_on_token(&faster(&login), &|_| ())
        .await
        .value()
        .expect("an outcome, not an error");
    assert!(matches!(outcome, LoginOutcome::Rejected(_)));

    mock.stop().await;
}
