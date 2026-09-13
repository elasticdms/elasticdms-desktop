//! Every golden file through its type and back again — and what it says in domain terms.
//!
//! Two questions per file, and both have to be answered yes:
//!
//! 1. **Does the body survive the round trip?** Read, written again, and the result is the same
//!    JSON value. A type that loses a field while reading shows up here — and not only when
//!    `edms-net` passes on a body in which `serverSignature` is missing.
//! 2. **Does the body say what the contract claims?** A truncated folder reports its truncation,
//!    an erasure command becomes a command of the core, a foreign `uploadUrl` is not used. A
//!    round-trip test alone would also pass with a body that is nonsense in domain terms.

// Test code may use `unwrap` (clippy.toml); outside `#[test]` clippy does not recognize that.
#![allow(clippy::unwrap_used)]

use edms_core::delivery::{Command, CommandOutcome, Reason};
use edms_core::identifier::DeviceIdentifier;
use edms_core::namespace::Container;
use edms_wire::basics::{ErrorKind, Page, Problem, digest_header_value};
use edms_wire::content::ContentHeader;
use edms_wire::delivery::{
    Acknowledgement, AcknowledgementReceipt, CommandKind, CommandReadError, DeliveryPage,
};
use edms_wire::device::{
    DeviceKind, DeviceObject, DeviceState, EnrollmentRequest, Heartbeat, HeartbeatCommand,
    HeartbeatResponse, ServerKeyBody,
};
use edms_wire::discovery::{AuthorizationServerMetadata, ResourceMetadata};
use edms_wire::golden::{ALL, golden};
use edms_wire::ingest::{InboxState, UploadCompletion, UploadGrant, UploadRequest};
use edms_wire::login::{
    DeviceAuthorization, DeviceFlowStep, OauthError, RefreshStep, TokenResponse,
};
use edms_wire::namespace::{ArchiveRow, BasketRow, CaseRow, DocumentPage, SearchRow};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

const API: &str = "https://api.elasticdms.io";
const APP: &str = "https://app.elasticdms.io";
const AUTH: &str = "https://auth.elasticdms.io";
const DEVICE: &str = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB";

/// Reads a golden file into its type and checks the round trip while doing so.
fn read<T: DeserializeOwned + Serialize>(name: &str) -> T {
    let text = golden(name);
    let value: Value =
        serde_json::from_str(text).unwrap_or_else(|f| panic!("{name} is not JSON: {f}"));
    let typ: T = serde_json::from_value(value.clone())
        .unwrap_or_else(|f| panic!("{name} does not fit into its type: {f}"));
    let back = serde_json::to_value(&typ).unwrap();
    assert_eq!(back, value, "{name} loses or changes fields in the round trip");
    typ
}

fn device() -> DeviceIdentifier {
    DEVICE.parse().unwrap()
}

// ── The round trip, exactly once per file ───────────────────────────────────────────────────

#[test]
fn every_golden_file_survives_the_round_trip_through_its_type() {
    // The mapping stands here and not in a table inside the crate: a new golden file without a
    // type should make this test red instead of staying silently unread.
    read::<EnrollmentRequest>("enrollment_request_desktop.json");
    read::<DeviceObject>("device_desktop.json");
    read::<DeviceObject>("device_kiosk.json");
    read::<DeviceAuthorization>("device_authorization_desktop.json");
    read::<DeviceAuthorization>("device_authorization_kiosk.json");
    read::<TokenResponse>("token_user_desktop.json");
    read::<TokenResponse>("token_device_desktop.json");
    read::<TokenResponse>("token_user_kiosk.json");
    read::<TokenResponse>("token_device_kiosk.json");
    read::<Heartbeat>("heartbeat_desktop.json");
    read::<HeartbeatResponse>("heartbeat_response_desktop.json");
    read::<HeartbeatResponse>("heartbeat_response_kiosk.json");
    read::<ServerKeyBody>("server_key_set.json");
    read::<AuthorizationServerMetadata>("authorization_server_metadata.json");
    read::<ResourceMetadata>("resource_metadata.json");
    read::<Page<BasketRow>>("baskets_page.json");
    read::<Page<ArchiveRow>>("archives_page.json");
    read::<Page<CaseRow>>("cases_page.json");
    read::<Page<SearchRow>>("searches_page.json");
    read::<DocumentPage>("case_documents_page.json");
    read::<DocumentPage>("search_documents_truncated.json");
    read::<DeliveryPage>("delivery_commands.json");
    read::<DeliveryPage>("delivery_empty.json");
    read::<Acknowledgement>("acknowledgement_rejected.json");
    read::<AcknowledgementReceipt>("acknowledgement_receipt.json");
    read::<UploadRequest>("ingest_request.json");
    read::<UploadGrant>("ingest_grant.json");
    read::<UploadGrant>("ingest_grant_duplicate.json");
    read::<UploadCompletion>("ingest_completed.json");
    for name in [
        "oauth_session_expired.json",
        "oauth_refresh_reused.json",
        "oauth_authorization_pending.json",
        "oauth_slow_down.json",
        "oauth_code_expired.json",
        "oauth_access_denied.json",
        "oauth_nonce_required.json",
        "oauth_device_code_expired.json",
    ] {
        read::<OauthError>(name);
    }
    for g in ALL.iter().filter(|g| g.name.starts_with("problem_")) {
        read::<Problem>(g.name);
    }
}

#[test]
fn the_table_covers_every_file_in_testdata() {
    // include_str! only uncovers what golden.rs names. A file missing there would lie unused in
    // the directory and would be wrong after the next change.
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");
    let mut on_disk: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    on_disk.sort();
    let mut in_table: Vec<String> = ALL.iter().map(|g| g.name.to_owned()).collect();
    in_table.sort();
    assert_eq!(on_disk, in_table, "testdata/ and golden::ALL do not agree");
}

// ── §7.0 Device and sign-in ─────────────────────────────────────────────────────────────────

#[test]
fn the_enrollment_request_of_a_workstation_carries_no_attestation_and_no_private_key() {
    let request: EnrollmentRequest = read("enrollment_request_desktop.json");
    assert_eq!(request.device_kind, DeviceKind::Desktop);
    assert_eq!(request.attestation.kind, "none");
    assert!(!request.attestation.available, "an invented chain would be worse than none");
    assert_eq!(request.public_jwk.check(), Ok(()));
    assert!(request.public_jwk.private_part.is_none());
    // Factory-target block and scanner block belong to the kiosk; they must not appear here.
    let raw: Value = serde_json::from_str(golden("enrollment_request_desktop.json")).unwrap();
    for kiosk in ["networkTargets", "hardware", "badgeReader", "keystoreSelfTest"] {
        assert!(
            raw.get(kiosk).is_none(),
            "{kiosk} does not belong in the request of a workstation"
        );
    }
}

#[test]
fn the_device_object_waits_for_approval_and_carries_the_key_block() {
    let device_object: DeviceObject = read("device_desktop.json");
    assert_eq!(device_object.device_id, device());
    assert_eq!(device_object.state, DeviceState::AwaitingApproval);
    assert!(
        !device_object.is_active(),
        "until the administrator confirms, the device is not active"
    );
    assert!(
        device_object.server_keys.is_some(),
        "without serverKeys the device would stay without an anchor (03 §6.2.4)"
    );
    let policy = device_object.policy.unwrap();
    assert_eq!(policy.idle_session_seconds, Some(28_800));
    assert_eq!(policy.absolute_session_seconds, Some(43_200));
    assert_eq!(policy.delivery_wait_seconds, Some(25));
    let oauth = device_object.oauth.unwrap();
    assert_eq!(
        oauth.device_scopes.as_deref(),
        Some(
            ["device:self".to_owned(), "desktop:login".to_owned(), "delivery:receive".to_owned()]
                .as_slice()
        )
    );
}

#[test]
fn the_kiosk_device_keeps_its_own_blocks_unchanged() {
    let device_object: DeviceObject = read("device_kiosk.json");
    // This client does not know `site` — it goes along unchanged instead of getting lost.
    assert!(device_object.further.contains_key("site"));
    assert_eq!(device_object.device_kind, None, "the kiosk contract does not know deviceKind");
}

#[test]
fn the_key_set_passes_through_this_crate_unchanged() {
    // It is interpreted in edms-crypto; here only this counts: that no field gets lost — every
    // one of them belongs to the signed bytes (03 §6.2.4, rule P2).
    let ServerKeyBody(set) = read::<ServerKeyBody>("server_key_set.json");
    assert_eq!(set["signingKeys"].as_array().map(Vec::len), Some(3));
    assert_eq!(set["revocations"].as_array().map(Vec::len), Some(1));
    for anchor in set["trustAnchors"].as_array().unwrap() {
        assert_eq!(
            anchor["serverSignature"],
            Value::Null,
            "a self-signed anchor proves only that somebody holds the private part — the forger does too"
        );
    }
}

#[test]
fn only_a_target_below_the_web_interface_is_opened_in_the_browser() {
    let a: DeviceAuthorization = read("device_authorization_desktop.json");
    assert_eq!(a.interval_second(), 5);
    assert_eq!(
        a.anchor.as_deref(),
        Some("K7-M4"),
        "without the anchor the code cannot be told apart from a foreign one"
    );
    assert_eq!(
        a.browser_target(APP),
        Ok("https://app.elasticdms.io/geraet?user_code=WQPX-7TRM&anchor=K7M4")
    );
    assert!(a.browser_target("https://app.elasticdms.io.example.org").is_err());
}

#[test]
fn both_token_answers_are_dpop_bound_and_carry_the_scopes_of_their_bearer() {
    let user: TokenResponse = read("token_user_desktop.json");
    assert!(user.has_scope("folders:read") && user.has_scope("documents:read"));
    assert!(user.has_scope("ingest:submit"));
    assert!(!user.has_scope("scan:operate"), "the folder client does not capture");
    assert!(user.refresh_token.is_some());

    let device_token: TokenResponse = read("token_device_desktop.json");
    assert!(device_token.has_scope("delivery:receive"));
    assert!(
        !device_token.has_scope("documents:read"),
        "the device token may do nothing in the domain"
    );
    assert!(device_token.refresh_token.is_none(), "the device re-asserts with its key");
}

#[test]
fn the_intermediate_states_of_the_device_flow_are_different_screens() {
    let step = |name: &str| read::<OauthError>(name).in_device_flow();
    assert_eq!(step("oauth_authorization_pending.json"), DeviceFlowStep::Pending);
    assert_eq!(step("oauth_slow_down.json"), DeviceFlowStep::Slower);
    assert_eq!(step("oauth_code_expired.json"), DeviceFlowStep::Expired);
    assert_eq!(step("oauth_device_code_expired.json"), DeviceFlowStep::Expired);
    assert_eq!(step("oauth_access_denied.json"), DeviceFlowStep::Rejected);
    assert_eq!(step("oauth_nonce_required.json"), DeviceFlowStep::NonceNeeded);
}

#[test]
fn the_end_of_a_session_is_something_other_than_a_reuse() {
    let expired: OauthError = read("oauth_session_expired.json");
    assert_eq!(expired.at_refresh(), RefreshStep::NewSignIn);
    assert_eq!(expired.error_kind(), ErrorKind::SessionExpired);

    let reused: OauthError = read("oauth_refresh_reused.json");
    assert_eq!(reused.at_refresh(), RefreshStep::FamilyRevoked);
    assert!(
        reused.error_kind().security_event(),
        "the family is revoked across devices — that is an incident, not a request"
    );
}

#[test]
fn the_discovery_documents_carry_the_start() {
    let m: AuthorizationServerMetadata = read("authorization_server_metadata.json");
    let e = m.check(AUTH).unwrap();
    assert_eq!(e.token, "https://auth.elasticdms.io/v1/oauth/token");
    assert!(m.further.get("authorization_endpoint").is_none(), "there is none (AND-4)");
    let r: ResourceMetadata = read("resource_metadata.json");
    assert_eq!(r.check(API, AUTH), Ok(()));
}

#[test]
fn the_heartbeat_reports_stuck_acknowledgements_and_follows_only_harmless_hints() {
    let h: Heartbeat = read("heartbeat_desktop.json");
    let delivery_state = h.delivery.unwrap();
    assert_eq!(delivery_state.unacknowledged_commands, 1);
    assert!(
        delivery_state.oldest_unacknowledged_at.is_some(),
        "without an age nobody sees a device whose acknowledgements have been stuck for days"
    );
    assert!(h.server_keys.unwrap().anchor_set_fingerprint.is_some());

    let response: HeartbeatResponse = read("heartbeat_response_desktop.json");
    let commands = response.commands.unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].command, HeartbeatCommand::RefreshKeys);
    assert!(
        commands[0].command.is_harmless_hint(),
        "an unsigned command that does more than fetch would be a remote-erasure tool"
    );
}

// ── §7.1 Namespace ──────────────────────────────────────────────────────────────────────────

#[test]
fn the_two_new_containers_list_an_identifier_and_a_title_and_nothing_else() {
    // Namespace v2: a basket holds nothing and an archive holds case files, which have their own
    // listing — so neither row carries a date. A field more would be one the client would have to
    // keep up to date without ever being able to use it.
    let baskets: Page<BasketRow> = read("baskets_page.json");
    assert_eq!(baskets.items[0].in_core().identifier, baskets.items[0].basket_id);
    let archives: Page<ArchiveRow> = read("archives_page.json");
    assert_eq!(archives.items[0].in_core().title, archives.items[0].title);
    for name in ["baskets_page.json", "archives_page.json"] {
        let raw: Value = serde_json::from_str(golden(name)).unwrap();
        for row in raw["items"].as_array().unwrap() {
            assert_eq!(row.as_object().unwrap().len(), 2, "{name}: {row}");
            assert!(row.get("updatedAt").is_none(), "{name}: nothing here has a change date");
        }
    }
}

#[test]
fn a_page_with_further_entries_names_its_cursor() {
    let cases: Page<CaseRow> = read("cases_page.json");
    assert_eq!(cases.continuation(), Ok(Some("eyJ0IjoxNzcyNDQ4MjkyfQ")));
    assert_eq!(cases.items[0].in_core().title, cases.items[0].title);

    let searches: Page<SearchRow> = read("searches_page.json");
    assert_eq!(searches.continuation(), Ok(None), "on the last page there is no cursor");
}

#[test]
fn a_complete_listing_reports_no_truncation_and_carries_etags() {
    let page: DocumentPage = read("case_documents_page.json");
    assert_eq!(page.continuation(), Ok(None));
    assert!(page.truncation().is_none());
    assert_eq!(page.in_core().len(), page.items.len(), "the client leaves nothing out");
    for row in &page.items {
        assert!(row.etag().is_ok(), "without a strong ETag there would be no If-Match on content");
    }
}

#[test]
fn a_truncated_result_list_says_so_and_names_the_way_to_refine_it() {
    let page: DocumentPage = read("search_documents_truncated.json");
    assert!(page.total_capped);
    let truncation = page.truncation().unwrap();
    assert_eq!(truncation.displayed, 5_000);
    assert!(
        truncation.address.is_some_and(|a| a.starts_with(APP)),
        "a folder that silently shows half is worse than one that shows too much"
    );
    assert_eq!(page.continuation(), Ok(Some("eyJ0IjoxNzcyNDQ4MjkzfQ")));
}

// ── §7.2 Content ────────────────────────────────────────────────────────────────────────────

#[test]
fn the_content_headers_match_the_row_that_announced_them() {
    // In §7.2 the contract shows the answer for the first row of case_documents_page.json. The
    // check happens before the first byte: otherwise the placeholder carries the size and
    // checksum of another version, and the file system later reports damage.
    let page: DocumentPage = read("case_documents_page.json");
    let row = &page.items[0];
    let digest = digest_header_value(&row.sha256);
    let header = ContentHeader::from_header(
        Some(&row.media_type),
        Some(&row.size.to_string()),
        Some(&row.etag().unwrap()),
        Some(&digest),
    )
    .unwrap();
    assert_eq!(header.check_against(row), Ok(()));
    assert_eq!(header.version, row.version);

    // A new version shows up before the loading, not after.
    let new = ContentHeader::from_header(
        Some(&row.media_type),
        Some(&row.size.to_string()),
        Some("\"13\""),
        Some(&digest),
    )
    .unwrap();
    assert!(new.check_against(row).is_err());
}

#[test]
fn without_a_log_entry_no_content_comes_and_without_a_rendition_no_empty_file() {
    let without_log: Problem = read("problem_access_log_missing.json");
    assert_eq!(without_log.error_kind(), ErrorKind::AccessLogNotAvailable);
    assert_eq!(without_log.status, Some(503), "temporary — the client tries again");

    let without_version: Problem = read("problem_rendition_missing.json");
    assert_eq!(without_version.error_kind(), ErrorKind::RenditionNotAvailable);
    assert_eq!(without_version.status, Some(404));
}

#[test]
fn the_content_headers_are_held_against_the_row_of_the_listing() {
    // §7.2.3: the check happens **before** a byte is read. Otherwise the placeholder carries the
    // size and checksum of another version, and a file would lie in the folder that matches no
    // row of the listing.
    let page: DocumentPage = read("case_documents_page.json");
    let row = &page.items[0];
    let etag = row.etag().unwrap();
    let digest = digest_header_value(&row.sha256);

    let header = ContentHeader::from_header(
        Some(&row.media_type),
        Some(&row.size.to_string()),
        Some(&etag),
        Some(&digest),
    )
    .unwrap();
    assert_eq!(header.check_against(row), Ok(()));
    assert_eq!(header.version, row.version);
    assert_eq!(header.sha256, row.sha256);

    // Another row of the same page is another version — and is noticed as such.
    assert!(header.check_against(&page.items[1]).is_err());

    // Without Repr-Digest nothing is loaded: a missing checksum is not a skipped check but the
    // way a truncated body ends up as a complete file.
    assert!(
        ContentHeader::from_header(Some(&row.media_type), Some("284173"), Some(&etag), None)
            .is_err()
    );
}

// ── §7.3 Delivery channel ───────────────────────────────────────────────────────────────────

#[test]
fn every_command_of_the_delivery_page_becomes_a_command_of_the_core() {
    let page: DeliveryPage = read("delivery_commands.json");
    let envelopes: Vec<_> = page.envelopes().into_iter().map(Result::unwrap).collect();
    assert_eq!(envelopes.len(), 2);

    let first = &envelopes[0];
    assert_eq!(first.catalogue_kind(), Some(CommandKind::Dehydrate));
    assert!(
        first.server_signature().is_some(),
        "without a signature no command ever arises (ADR-D04)"
    );
    match first.command(device()).unwrap() {
        Command::Dehydrate { documents, reason } => {
            assert_eq!(documents.len(), 1);
            assert_eq!(reason, Reason::Erasure);
        }
        other => panic!("{other:?}"),
    }
    // What is signed is the raw value without the signature — every field included that this
    // client does not know.
    let signed = first.signed_content();
    assert!(signed.get("serverSignature").is_none());
    assert!(signed.get("commandId").is_some());

    // The case file names its archive; without it the command would point at a container whose
    // place in the tree nobody could compute (namespace v2).
    match envelopes[1].command(device()).unwrap() {
        Command::Reconcile { container: Some(Container::Case { .. }) } => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_command_for_a_foreign_device_is_not_executed_even_with_a_signature() {
    let page: DeliveryPage = read("delivery_commands.json");
    let envelope = page.envelopes().remove(0).unwrap();
    let foreign: DeviceIdentifier = "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAC".parse().unwrap();
    assert!(matches!(envelope.command(foreign), Err(CommandReadError::ForeignDevice { .. })));
}

#[test]
fn an_empty_delivery_page_is_the_normal_case_and_no_error() {
    let page: DeliveryPage = read("delivery_empty.json");
    assert!(page.items.is_empty());
    assert!(!page.next_cursor.is_empty(), "without a cursor the next poll would start over");
    assert!(page.envelopes().is_empty());
}

#[test]
fn the_refusal_acknowledgement_is_exactly_the_one_of_the_read_error() {
    // The golden shows no invented text but the one the client actually sends; the sample kind
    // is the one of `an_unknown_kind_is_refused_and_not_executed`, and it stands in the golden's
    // `detail` verbatim.
    let expected = CommandReadError::UnknownKind("DELETE_EVERYTHING".into()).acknowledgement();
    let golden: Acknowledgement = read("acknowledgement_rejected.json");
    assert_eq!(golden, expected);
    assert_eq!(golden.outcome, CommandOutcome::Rejected);
    assert!(golden.is_final(), "a refusal is not repeated endlessly");
}

#[test]
fn the_acknowledgement_receipt_names_the_command_and_the_stored_outcome() {
    let receipt: AcknowledgementReceipt = read("acknowledgement_receipt.json");
    assert_eq!(receipt.outcome, CommandOutcome::Applied);
    assert_eq!(receipt.command_id.to_string(), "cmd_01JKC4D6E8F0G2H4J6K8M0N2P4");

    let second: Problem = read("problem_command_already_acknowledged.json");
    assert_eq!(second.error_kind(), ErrorKind::CommandAlreadyAcknowledged);
    assert_eq!(second.status, Some(409), "the first acknowledgement arrived — no client fault");
}

// ── §7.4 Inbound folder ─────────────────────────────────────────────────────────────────────

#[test]
fn the_upload_request_carries_a_bare_file_name_and_the_basket_it_came_from() {
    let request: UploadRequest = read("ingest_request.json");
    assert!(!request.file_name.contains(['/', '\\']), "a path would give away the user name");
    // The basket is what the server applies its ingest rule of; the client files nothing itself.
    assert_eq!(request.basket_id.to_string(), "bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5");
    // The same body has to pass the check the client makes before sending.
    let built = UploadRequest::new(
        request.basket_id,
        &request.file_name,
        &request.media_type,
        request.size,
        request.sha256,
    )
    .unwrap();
    assert_eq!(built, request);
}

#[test]
fn a_basket_that_is_gone_is_an_error_and_never_a_filing_somewhere_else() {
    // Namespace v2 §7.4: the drop target can disappear between the drop and the submission — a
    // basket deleted, a permission withdrawn. Filing the document anywhere else would be the
    // client deciding, and the local file is at that moment still the only copy.
    let p: Problem = read("problem_basket_unknown.json");
    assert_eq!(p.error_kind(), ErrorKind::NotFound);
    assert_eq!(p.status, Some(404));
    assert_eq!(p.instance.as_deref(), Some("/v1/ingest-uploads"));
}

#[test]
fn only_an_upload_address_below_the_api_gets_the_bytes() {
    let grant: UploadGrant = read("ingest_grant.json");
    assert!(grant.duplicate_of.is_none());
    assert!(grant.target(API).is_ok());
    assert!(grant.target("https://api.elasticdms.io.example.org").is_err());
}

#[test]
fn a_duplicate_is_marked_and_not_suppressed() {
    let grant: UploadGrant = read("ingest_grant_duplicate.json");
    let hint = grant.duplicate_of.unwrap();
    assert_eq!(hint.document_id.to_string(), "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB");
    assert!(!hint.title.is_empty(), "the human in the browser makes the decision");
}

#[test]
fn after_the_completion_the_document_lies_in_the_inbox_and_the_page_opens() {
    let completion: UploadCompletion = read("ingest_completed.json");
    assert_eq!(completion.state, InboxState::InInbox);
    assert_eq!(completion.browser_target(APP), Ok(completion.capture_url.as_str()));
    assert!(completion.browser_target("https://phish.example.org").is_err());
}

// ── §7.5 Error catalogue ────────────────────────────────────────────────────────────────────

#[test]
fn every_problem_golden_carries_the_error_kind_its_name_promises() {
    let pairs = [
        ("problem_cursor_invalid.json", ErrorKind::CursorInvalid, 400),
        ("problem_search_not_executable.json", ErrorKind::SearchNotRunnable, 422),
        ("problem_rendition_missing.json", ErrorKind::RenditionNotAvailable, 404),
        ("problem_access_log_missing.json", ErrorKind::AccessLogNotAvailable, 503),
        ("problem_command_already_acknowledged.json", ErrorKind::CommandAlreadyAcknowledged, 409),
        ("problem_upload_digest.json", ErrorKind::UploadDigestDeviation, 422),
        ("problem_basket_unknown.json", ErrorKind::NotFound, 404),
        ("problem_dpop_nonce_required.json", ErrorKind::DpopNonceNeeded, 401),
        ("problem_token_device_binding.json", ErrorKind::TokenDeviceBinding, 403),
        ("problem_device_locked.json", ErrorKind::DeviceLocked, 403),
        ("problem_server_key_not_anchored.json", ErrorKind::ServerKeyNotAnchored, 403),
        ("problem_step_up.json", ErrorKind::AuthenticationTooWeak, 401),
        ("problem_device_already_exists.json", ErrorKind::DeviceIdConflict, 409),
        ("problem_rate_limited.json", ErrorKind::RateLimit, 429),
        ("problem_idempotency_in_progress.json", ErrorKind::IdempotencyRuns, 409),
        ("problem_client_too_old.json", ErrorKind::ClientTooOld, 426),
    ];
    for (name, kind, status) in pairs {
        let p: Problem = read(name);
        assert_eq!(p.error_kind(), kind, "{name}");
        assert_eq!(p.status, Some(status), "{name}");
        assert!(p.detail.is_some(), "{name}: without detail the human reads only a code");
    }
}

#[test]
fn the_security_events_can_be_recognized_as_such() {
    let binding: Problem = read("problem_token_device_binding.json");
    assert!(binding.is_security_event());
    // Even if the server forgot the marking, the catalogue knows it.
    let mut without = binding;
    without.security_event = None;
    assert!(without.is_security_event());

    let locked: Problem = read("problem_device_locked.json");
    assert!(!locked.is_security_event(), "a lock is a state, not an incident");
    assert!(locked.extension("revokedAt").is_some(), "extension fields do not get lost");
    assert!(locked.extension("contact").is_some());
}

#[test]
fn a_step_up_names_the_demanded_level_and_the_maximum_age() {
    let p: Problem = read("problem_step_up.json");
    assert_eq!(
        p.extension("requiredAcr").and_then(Value::as_str),
        Some("urn:elasticdms:acr:idp:mfa"),
        "the client never guesses a level — the server says it"
    );
    assert_eq!(p.extension("maxAgeSeconds").and_then(Value::as_u64), Some(120));
}
