//! The remote control: what a test can set up, turn and read back.
//!
//! Every handle here is one a contract test of the client will need. A test harness whose control
//! is never used rots silently: the first test that needs it finds a method that has not done what
//! its name says for weeks.

// The helper functions of this test stand outside the `#[test]` bodies; `expect` is a failed
// assertion there too, and not something a caller could handle.
#![allow(clippy::expect_used)]

mod common;

use std::time::Duration;

use edms_core::namespace::Location;
use edms_mock::{Fault, Origin};
use edms_wire::basics::{API_VERSION, Page, header, media_type};
use edms_wire::namespace::{DocumentPage, path_cases, path_document};
use serde_json::json;

#[tokio::test]
async fn a_saved_search_shows_a_document_that_lies_in_a_case_file() {
    let harness = common::start_with(edms_mock::Configuration::default().without_seed()).await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();

    let archive = control.create_archive("Wartung und Instandhaltung");
    let case = control.create_case(archive, "Sulzer Pumpen – Wartungsvertrag 2026");
    let case = Location::Case { archive, case };
    let search = control.create_search("Prüfberichte Pumpenwerk");
    let document = control.create_document(case, "Prüfbericht Pumpe 7").expect("a document");
    assert!(control.link_document(Location::Search(search), document));
    assert!(
        !control.link_document(Location::Search(search), document)
            || control.documents(Location::Search(search)).len() == 1,
        "linking twice creates nothing twice"
    );

    let path = path_document(Location::Search(search));
    let response = harness.api_get(&path, &tokens.user).await;
    let page: DocumentPage = serde_json::from_slice(&response.body).expect("a page");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].document_id, document);
    assert!(!page.total_capped, "a list below the limit is not truncated");

    // A saved search is a **dynamic** folder: its content changes without anybody doing anything
    // (§7.1.3).
    assert!(control.remove_document(document));
    let response = harness.api_get(&path, &tokens.user).await;
    let page: DocumentPage = serde_json::from_slice(&response.body).expect("a page");
    assert!(page.items.is_empty());

    assert!(control.remove_container(case));
    let response = harness.api_get(&path_cases(archive), &tokens.user).await;
    let page: Page<edms_wire::namespace::CaseRow> =
        serde_json::from_slice(&response.body).expect("a page");
    assert!(page.items.is_empty(), "the archive stays, its one case file is gone");
    let gone = harness.api_get(&path_document(case), &tokens.user).await;
    assert_eq!(gone.status, 404, "\"not visible\", never \"does not exist\" (§7.5.1)");
}

#[tokio::test]
async fn an_archive_lists_its_own_case_files_and_takes_them_with_it_when_it_goes() {
    let harness = common::start_with(edms_mock::Configuration::default().without_seed()).await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    let archive = control.create_archive("Rechnungseingang");
    let other = control.create_archive("Bauvorhaben");
    let case = control.create_case(archive, "Kreditor 4711 – Eingangsrechnungen");
    control.create_case(other, "Bauvorhaben Rothenbaumchaussee 12");

    let response = harness.api_get(&path_cases(archive), &tokens.user).await;
    let page: Page<edms_wire::namespace::CaseRow> =
        serde_json::from_slice(&response.body).expect("a case page");
    assert_eq!(page.items.len(), 1, "the case file of the other archive has no business here");
    assert_eq!(page.items[0].case_id, case);

    assert!(control.remove_archive(archive));
    let gone = harness.api_get(&path_cases(archive), &tokens.user).await;
    assert_eq!(gone.status, 404, "an archive that is gone is not an empty archive (§7.5.1)");
    assert_eq!(
        control.cases().len(),
        1,
        "a case file whose archive is gone would stand under no address at all"
    );
    let remaining = harness.api_get(&path_cases(other), &tokens.user).await;
    assert_eq!(remaining.status, 200, "the other archive is untouched");
}

#[tokio::test]
async fn a_display_limit_can_be_set_and_taken_away_again() {
    let harness = common::start_with(edms_mock::Configuration::default().without_seed()).await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    let search = control.create_search("Offene Rechnungen über 10.000 €");
    for nr in 0..4 {
        control
            .create_document(Location::Search(search), &format!("Rechnung 2026-{nr:04}"))
            .expect("a document");
    }

    let path = path_document(Location::Search(search));
    let page: DocumentPage =
        serde_json::from_slice(&harness.api_get(&path, &tokens.user).await.body).expect("a page");
    assert!(!page.total_capped);

    assert!(control.set_display_limit(
        Location::Search(search),
        Some(2),
        Some("https://app.beispiel.test/suche".to_owned()),
    ));
    let page: DocumentPage =
        serde_json::from_slice(&harness.api_get(&path, &tokens.user).await.body).expect("a page");
    assert!(page.total_capped, "four hits, two allowed");
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.display_limit, 2);
    assert_eq!(page.refine_url.as_deref(), Some("https://app.beispiel.test/suche"));

    assert!(control.set_display_limit(Location::Search(search), None, None));
    let page: DocumentPage =
        serde_json::from_slice(&harness.api_get(&path, &tokens.user).await.body).expect("a page");
    assert!(!page.total_capped);
    assert_eq!(page.items.len(), 4);
}

#[tokio::test]
async fn an_if_match_on_an_old_version_delivers_no_content() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (case, _) = harness.mock.control().cases().into_iter().next().expect("a case file");
    let document = harness.mock.control().documents(case)[0];
    let path = edms_wire::content::path_content(document);

    let with_age = harness
        .with_dpop(
            Origin::Api,
            "GET",
            &path,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::IF_MATCH, "\"1\"".to_owned()),
            ],
            None,
        )
        .await;
    assert_eq!(with_age.status, 200, "the first version is still the current one");

    harness.mock.control().new_version(document).expect("a new version");
    let stale = harness
        .with_dpop(
            Origin::Api,
            "GET",
            &path,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::IF_MATCH, "\"1\"".to_owned()),
            ],
            None,
        )
        .await;
    assert_eq!(
        stale.status, 412,
        "otherwise the placeholder would carry the size and checksum of another version (§7.2.2)"
    );
    assert_eq!(harness.mock.control().access_log().len(), 1, "a 412 is not a hydration");
}

#[tokio::test]
async fn a_delay_really_makes_the_answer_wait() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    harness.mock.control().inject_fault(Fault::delay(edms_wire::namespace::PATH_SEARCHES, 400, 1));

    let beginning = tokio::time::Instant::now();
    let response = harness.api_get(edms_wire::namespace::PATH_SEARCHES, &tokens.user).await;
    assert!(beginning.elapsed() >= Duration::from_millis(350), "the delay bites");
    assert_eq!(response.status, 200, "a delay without a status is not a failure");

    harness.mock.control().inject_fault(Fault::status(edms_wire::namespace::PATH_SEARCHES, 503, 5));
    assert_eq!(
        harness.api_get(edms_wire::namespace::PATH_SEARCHES, &tokens.user).await.status,
        503
    );
    harness.mock.control().clear_faults();
    assert_eq!(
        harness.api_get(edms_wire::namespace::PATH_SEARCHES, &tokens.user).await.status,
        200
    );
}

#[tokio::test]
async fn a_second_upload_request_with_the_same_key_creates_nothing_twice() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let bytes = b"%PDF-1.4\n%%EOF\n".to_vec();
    let sha = edms_crypto::checksum::sha256(&bytes);
    let (basket, _) = harness.mock.control().baskets().into_iter().next().expect("a mail basket");
    let request = json!({
        "basketId": basket.to_string(),
        "fileName": "Lieferschein 88213.pdf",
        "mediaType": "application/pdf",
        "size": bytes.len(),
        "sha256": sha.wire_form(),
    });
    let send = async |key: &str, body: &serde_json::Value| {
        harness
            .with_dpop(
                Origin::Api,
                "POST",
                edms_wire::ingest::PATH_UPLOAD,
                Some(&tokens.user),
                &harness.session_key,
                &[
                    (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                    (header::CONTENT_TYPE, media_type::JSON.to_owned()),
                    (header::IDEMPOTENCY_KEY, key.to_owned()),
                ],
                Some(serde_json::to_vec(body).expect("JSON")),
            )
            .await
    };

    let first = send("01JKD8H0J2K4M6N8P0Q2R4S6T8", &request).await;
    assert_eq!(first.status, 201, "{}", first.text());
    let again = send("01JKD8H0J2K4M6N8P0Q2R4S6T8", &request).await;
    assert_eq!(again.status, 201);
    assert_eq!(again.header_value(header::IDEMPOTENCY_REPLAYED), Some("true"));
    assert_eq!(again.json(), first.json(), "the same grant, no second file");

    let other = json!({ "basketId": basket.to_string(), "fileName": "Anderes.pdf",
                         "mediaType": "application/pdf", "size": bytes.len(),
                         "sha256": sha.wire_form() });
    let refused = send("01JKD8H0J2K4M6N8P0Q2R4S6T8", &other).await;
    assert_eq!(refused.status, 422, "the same key, a different body (AND-2)");
}

#[tokio::test]
async fn the_key_set_can_be_rotated_and_reports_the_new_state() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    let before = edms_crypto::key_set::KeyOffer::from_json(
        &harness.device_get(edms_wire::device::PATH_SERVER_KEY, &tokens.device).await.json(),
    )
    .expect("an offer")
    .key_set_version();

    let new = control.rotate_key_set();
    assert_eq!(new, before + 1);
    let after = edms_crypto::key_set::KeyOffer::from_json(
        &harness.device_get(edms_wire::device::PATH_SERVER_KEY, &tokens.device).await.json(),
    )
    .expect("an offer")
    .key_set_version();
    assert_eq!(after, new, "a smaller keySetVersion never changes the state (T7)");
    assert_eq!(control.key_block().expect("the block")["keySetVersion"], json!(new));
}

#[tokio::test]
async fn the_nonce_and_the_proof_memory_can_be_reset() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    assert_eq!(control.nonce(Origin::Api), harness.nonce(Origin::Api).unwrap_or_default());
    let new = control.rotate_nonce(Origin::Api);
    assert_eq!(control.nonce(Origin::Api), new);

    // After the forgetting the same proof holds again — two independent scenarios in one run.
    control.forget_proofs();
    assert_eq!(
        harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await.status,
        200
    );
    assert!(!control.devices().is_empty());
    assert!(control.commands().is_empty());
    assert!(
        control.acknowledgement(edms_core::identifier::CommandIdentifier::from_value(1)).is_none()
    );
}

#[tokio::test]
async fn every_answer_carries_a_request_identifier_and_the_nonce_of_its_origin() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let response = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    let identifier = response.header_value(header::X_REQUEST_ID).expect("X-Request-Id");
    assert_eq!(identifier.len(), 26, "a ULID has 26 characters: {identifier}");
    assert_eq!(
        response.header_value(header::DPOP_NONCE),
        Some(harness.mock.control().nonce(Origin::Api).as_str())
    );
}
