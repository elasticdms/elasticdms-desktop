//! The mock against the contract: every endpoint, every golden file.
//!
//! Two things are measured. First **structure**: what the mock sends has to read into the wire
//! types out of `edms-wire` and may not carry a field the matching golden file does not know.
//! Second **behaviour**: truncation is visible, an unreadable cursor is a failure, every hydration
//! stands in the access log, and a mangled body arrives with `200` — the way the real server does
//! it.

mod common;

use common::{golden, structure};
use edms_core::namespace::Location;
use edms_mock::state::Mangling;
use edms_mock::{Configuration, Origin};
use edms_wire::basics::{API_VERSION, Page, Problem, header, media_type};
use edms_wire::device::DeviceObject;
use edms_wire::discovery::{
    AuthorizationServerMetadata, PATH_AS_METADATA, PATH_RESOURCE_METADATA, ResourceMetadata,
};
use edms_wire::namespace::{
    ArchiveRow, BasketRow, CaseRow, DocumentPage, SearchRow, path_cases, path_document,
};
use serde_json::json;

#[tokio::test]
async fn the_discovery_names_both_hosts_and_survives_its_own_check() {
    let harness = common::start().await;
    let response = harness.raw(Origin::Login, "GET", PATH_AS_METADATA, &[], None).await;
    assert_eq!(response.status, 200);
    let metadata: AuthorizationServerMetadata =
        serde_json::from_slice(&response.body).expect("AS metadata reads as a wire type");
    let endpoint = metadata.check(&harness.auth).expect("the three starting conditions hold");
    assert!(endpoint.token.starts_with(&harness.auth));
    assert!(endpoint.device_authorization.starts_with(&harness.auth));

    let response = harness.raw(Origin::Api, "GET", PATH_RESOURCE_METADATA, &[], None).await;
    let resource: ResourceMetadata =
        serde_json::from_slice(&response.body).expect("resource metadata");
    resource.check(&harness.api, &harness.auth).expect("resource and issuer fit together");

    assert!(
        structure(&response.json()).is_subset(&structure(&golden("resource_metadata.json"))),
        "the mock invents a field the contract does not know"
    );
}

#[tokio::test]
async fn an_enrolment_is_first_201_then_412_and_409_on_a_foreign_key() {
    let harness = common::start_with(Configuration::default().awaiting_approval()).await;
    let first = harness.enroll().await;
    assert_eq!(first.status, 201, "{}", first.text());
    let object: DeviceObject =
        serde_json::from_slice(&first.body).expect("the device object reads as a wire type");
    assert!(!object.is_active(), "without approval the device is not active");
    assert!(
        object.server_keys.is_some(),
        "without serverKeys the device stays without an anchor (T3)"
    );
    assert!(
        structure(&first.json()).is_subset(&structure(&golden("device_desktop.json"))),
        "the device object carries a field device_desktop.json does not know"
    );

    // The retry after a broken connection: 412 is a success, and the answer carries the device.
    let second = harness.enroll().await;
    assert_eq!(second.status, 412, "{}", second.text());
    let problem: Problem = serde_json::from_slice(&second.body).expect("a problem");
    assert_eq!(problem.error_kind(), edms_wire::basics::ErrorKind::PreconditionFailed);
    assert!(problem.extension("device").is_some(), "a 412 without the device forces a token");

    // Another key under the same identifier is **not** a retry (T5).
    let foreign = common::start_with(Configuration::default()).await;
    let response = harness
        .raw(
            Origin::Api,
            "PUT",
            &format!("/v1/devices/{}", harness.device),
            &[
                (header::IF_NONE_MATCH, "*".to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(foreign.enrollment_body()),
        )
        .await;
    assert_eq!(response.status, 409, "{}", response.text());
    assert_eq!(response.json(), {
        let mut golden = golden("problem_device_already_exists.json");
        golden["instance"] = json!(format!("/v1/devices/{}", harness.device));
        golden
    });
}

#[tokio::test]
async fn without_the_precondition_and_without_the_version_header_no_device_comes_about() {
    let harness = common::start().await;
    let without_precondition = harness
        .raw(
            Origin::Api,
            "PUT",
            &format!("/v1/devices/{}", harness.device),
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            Some(harness.enrollment_body()),
        )
        .await;
    assert_eq!(without_precondition.status, 428, "If-None-Match: * is compulsory (§7.0.5)");

    let without_version = harness
        .raw(
            Origin::Api,
            "PUT",
            &format!("/v1/devices/{}", harness.device),
            &[(header::IF_NONE_MATCH, "*".to_owned())],
            Some(harness.enrollment_body()),
        )
        .await;
    assert_eq!(without_version.status, 400, "Elasticdms-Version belongs on every request (§7.0.1)");
}

#[tokio::test]
async fn the_listings_come_unfiltered_with_a_strong_etag_and_then_answer_304() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (archive, _) = harness
        .mock
        .control()
        .archives()
        .into_iter()
        .find(|(_, title)| title == edms_mock::seed::ARCHIVE_MAINTENANCE)
        .expect("the archive of the maintenance case file");

    let response = harness.api_get(&path_cases(archive), &tokens.user).await;
    assert_eq!(response.status, 200, "{}", response.text());
    let page: Page<CaseRow> = serde_json::from_slice(&response.body).expect("a case page");
    assert_eq!(page.items.len(), 1, "this archive holds one case file of the sample tenant");
    assert_eq!(page.items[0].title, edms_mock::seed::CASE_MAINTENANCE);
    page.continuation().expect("nextCursor and hasMore do not contradict each other");
    assert!(
        structure(&response.json()).is_subset(&structure(&golden("cases_page.json"))),
        "the case page carries a field cases_page.json does not know"
    );
    let etag = response.header_value(header::ETAG).expect("a strong ETag").to_owned();
    assert!(!etag.starts_with("W/"), "a weak ETag carries no If-Match (§7.0.3)");

    let again = harness
        .with_dpop(
            Origin::Api,
            "GET",
            &path_cases(archive),
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::IF_NONE_MATCH, etag.clone()),
            ],
            None,
        )
        .await;
    assert_eq!(again.status, 304, "without a change nobody needs the listing again");
    assert!(again.body.is_empty());

    let searches = harness.api_get(edms_wire::namespace::PATH_SEARCHES, &tokens.user).await;
    let page: Page<SearchRow> = serde_json::from_slice(&searches.body).expect("a search page");
    assert_eq!(page.items.len(), 2);
    assert!(structure(&searches.json()).is_subset(&structure(&golden("searches_page.json"))));
}

#[tokio::test]
async fn the_tree_comes_as_baskets_archives_and_the_case_files_of_one_archive() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;

    let response = harness.api_get(edms_wire::namespace::PATH_BASKETS, &tokens.user).await;
    assert_eq!(response.status, 200, "{}", response.text());
    let baskets: Page<BasketRow> = serde_json::from_slice(&response.body).expect("a basket page");
    assert_eq!(baskets.items.len(), 2, "both mail baskets of the sample tenant");
    assert_eq!(baskets.items[0].title, edms_mock::seed::BASKET_ACCOUNTING);
    assert!(
        structure(&response.json()).is_subset(&structure(&golden("baskets_page.json"))),
        "the basket page carries a field baskets_page.json does not know"
    );

    let response = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    assert_eq!(response.status, 200, "{}", response.text());
    let archives: Page<ArchiveRow> =
        serde_json::from_slice(&response.body).expect("an archive page");
    assert_eq!(archives.items.len(), 2, "both archives of the sample tenant");
    assert!(
        structure(&response.json()).is_subset(&structure(&golden("archives_page.json"))),
        "the archive page carries a field archives_page.json does not know"
    );

    // Every case file stands below exactly one archive, and no archive delivers a foreign one
    // (namespace v2 §1). Both listings together have to yield each case file exactly once.
    let mut seen = Vec::new();
    for row in &archives.items {
        let response = harness.api_get(&path_cases(row.archive_id), &tokens.user).await;
        assert_eq!(response.status, 200, "{}", response.text());
        let page: Page<CaseRow> = serde_json::from_slice(&response.body).expect("a case page");
        assert_eq!(page.items.len(), 1, "{} holds one case file", row.title);
        seen.push(page.items[0].case_id);
    }
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0], seen[1], "one case file under two archives would have two parents");

    // The same case file under the other archive is a different location — and not visible.
    let crossed = harness
        .api_get(
            &path_document(Location::Case { archive: archives.items[0].archive_id, case: seen[1] }),
            &tokens.user,
        )
        .await;
    assert_eq!(crossed.status, 404, "\"not visible\", never \"does not exist\" (§7.5.1)");
}

#[tokio::test]
async fn a_truncated_hit_list_says_so_and_names_the_refinement() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    let (search, _) = control
        .searches()
        .into_iter()
        .find(|(_, title)| title == edms_mock::seed::SEARCH_OPEN)
        .expect("the truncated search");

    let path = path_document(Location::Search(search));
    let response = harness.api_get(&path, &tokens.user).await;
    assert_eq!(response.status, 200, "{}", response.text());
    let page: DocumentPage = serde_json::from_slice(&response.body).expect("a document page");
    assert!(page.total_capped, "a silent truncation is the most expensive way to be wrong");
    assert_eq!(page.display_limit, edms_mock::seed::LIMIT_OPEN);
    assert_eq!(page.items.len() as u64, edms_mock::seed::LIMIT_OPEN);
    assert!(page.refine_url.is_some(), "without a refineUrl the way to refine it is missing");
    assert!(page.truncation().is_some());
    page.continuation().expect("the page agrees with itself");
    assert!(
        structure(&response.json())
            .is_subset(&structure(&golden("search_documents_truncated.json"))),
        "the document page carries an unknown field"
    );
}

#[tokio::test]
async fn an_unreadable_cursor_is_a_failure_and_not_a_jump_back_to_page_one() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let response = harness
        .api_get(
            &format!("{}?cursor=not-base64-%21", edms_wire::namespace::PATH_ARCHIVES),
            &tokens.user,
        )
        .await;
    assert_eq!(response.status, 400, "{}", response.text());
    let problem: Problem = serde_json::from_slice(&response.body).expect("a problem");
    assert_eq!(problem.error_kind(), edms_wire::basics::ErrorKind::CursorInvalid);
    assert_eq!(
        problem.title,
        golden("problem_cursor_invalid.json")["title"].as_str().map(ToOwned::to_owned)
    );
}

#[tokio::test]
async fn the_cursor_leads_through_every_page_and_leaves_out_no_document() {
    let harness = common::start_with(Configuration::default().with_page_size(2)).await;
    let tokens = harness.signed_in().await;
    let (case, _) = harness.mock.control().cases().into_iter().next().expect("a case file");

    let mut seen = Vec::new();
    let mut path = path_document(case);
    loop {
        let response = harness.api_get(&path, &tokens.user).await;
        assert_eq!(response.status, 200, "{}", response.text());
        let page: DocumentPage = serde_json::from_slice(&response.body).expect("a page");
        assert!(page.items.len() <= 2, "the page size applies");
        seen.extend(page.items.iter().map(|row| row.document_id));
        match page.continuation().expect("the page agrees with itself") {
            Some(cursor) => {
                path = format!("{}?cursor={cursor}", path_document(case));
            }
            None => break,
        }
    }
    let expected = harness.mock.control().documents(case);
    assert_eq!(seen, expected, "a missing document in the folder is the forbidden lie");
}

#[tokio::test]
async fn every_hydration_stands_in_the_access_log_of_the_server() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (case, _) = harness.mock.control().cases().into_iter().next().expect("a case file");
    let document = harness.mock.control().documents(case)[1];

    let application = edms_wire::content::encode_application("Übersicht.exe").expect("encodes");
    let response = harness
        .with_dpop(
            Origin::Api,
            "GET",
            &edms_wire::content::path_content(document),
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::REQUESTING_APPLICATION, application),
            ],
            None,
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert!(response.body.starts_with(b"%PDF-1.4"), "the mock delivers a real PDF");
    let header = edms_wire::content::ContentHeader::from_header(
        response.header_value(header::CONTENT_TYPE),
        response.header_value(header::CONTENT_LENGTH),
        response.header_value(header::ETAG),
        response.header_value(header::REPR_DIGEST),
    )
    .expect("the four compulsory headers are there (§7.2.2)");
    assert_eq!(header.length, response.body.len() as u64);
    assert_eq!(header.sha256, edms_crypto::checksum::sha256(&response.body));
    assert_eq!(response.header_value(header::CACHE_CONTROL), Some("private, no-store"));

    let log = harness.mock.control().access_log();
    assert_eq!(log.len(), 1, "one hydration, one row");
    assert_eq!(log[0].document, document);
    assert_eq!(log[0].device, harness.device);
    assert!(log[0].user.is_some(), "without a human the row is worthless");
    assert_eq!(log[0].application.as_deref(), Some("Übersicht.exe"));
}

#[tokio::test]
async fn a_mangled_body_arrives_with_200_and_breaks_on_the_checksum() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (case, _) = harness.mock.control().cases().into_iter().next().expect("a case file");
    let document = harness.mock.control().documents(case)[0];
    assert!(harness.mock.control().mangle(document, Mangling::CutOff(64)));

    let response = harness.api_get(&edms_wire::content::path_content(document), &tokens.user).await;
    assert_eq!(response.status, 200, "the real server notices only on the last Read (§7.2.1)");
    assert_eq!(response.body.len(), 64);
    let announced: u64 =
        response.header_value(header::CONTENT_LENGTH).expect("a length").parse().expect("a number");
    assert!(announced > 64, "the headers describe the whole rendition");
    let reported = edms_wire::basics::read_digest_header(
        response.header_value(header::REPR_DIGEST).expect("a Repr-Digest"),
    )
    .expect("a digest");
    assert_ne!(
        reported,
        edms_crypto::checksum::sha256(&response.body),
        "only this comparison turns the short body into a failed hydration (T13)"
    );
}

#[tokio::test]
async fn without_an_access_log_and_without_a_rendition_no_byte_comes() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (case, _) = harness.mock.control().cases().into_iter().next().expect("a case file");
    let documents = harness.mock.control().documents(case);

    harness.mock.control().lock_access_log(true);
    let response =
        harness.api_get(&edms_wire::content::path_content(documents[0]), &tokens.user).await;
    assert_eq!(response.status, 503);
    assert_eq!(
        response.json()["type"],
        golden("problem_access_log_missing.json")["type"],
        "an access without a log entry is worse than a refused one"
    );
    assert!(harness.mock.control().access_log().is_empty());
    harness.mock.control().lock_access_log(false);

    assert!(harness.mock.control().revoke_rendition(documents[1], true));
    let response =
        harness.api_get(&edms_wire::content::path_content(documents[1]), &tokens.user).await;
    assert_eq!(response.status, 404, "a file with zero bytes would be the wrong statement");
    assert_eq!(response.json()["type"], golden("problem_rendition_missing.json")["type"]);
}

#[tokio::test]
async fn an_unrunnable_search_is_a_failure_with_a_reason_and_not_an_empty_folder() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (search, _) = harness.mock.control().searches().into_iter().next().expect("a search");
    assert!(harness.mock.control().make_search_unrunnable(
        search,
        "gehalt",
        "The saved search filters on the field “gehalt”, which you may not read."
    ));

    let path = path_document(Location::Search(search));
    let response = harness.api_get(&path, &tokens.user).await;
    assert_eq!(response.status, 422, "{}", response.text());
    let problem: Problem = serde_json::from_slice(&response.body).expect("a problem");
    assert_eq!(problem.error_kind(), edms_wire::basics::ErrorKind::SearchNotRunnable);
    let field = problem.errors.expect("errors names the field");
    assert_eq!(field[0].field.as_deref(), Some("gehalt"));
    assert!(
        structure(&response.json())
            .is_subset(&structure(&golden("problem_search_not_executable.json")))
    );
}

#[tokio::test]
async fn a_submission_out_of_a_mail_basket_takes_the_file_and_then_opens_the_capture_page() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let bytes = b"%PDF-1.4\n% Briefkorb\n%%EOF\n".to_vec();
    let sha = edms_crypto::checksum::sha256(&bytes);
    let (basket, _) = harness.mock.control().baskets().into_iter().next().expect("a mail basket");

    let request = json!({
        "basketId": basket.to_string(),
        "fileName": "Rechnung 2026-0412.pdf",
        "mediaType": "application/pdf",
        "size": bytes.len(),
        "sha256": sha.wire_form(),
    });
    let grant = harness
        .with_dpop(
            Origin::Api,
            "POST",
            edms_wire::ingest::PATH_UPLOAD,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
            ],
            Some(serde_json::to_vec(&request).expect("JSON")),
        )
        .await;
    assert_eq!(grant.status, 201, "{}", grant.text());
    let read: edms_wire::ingest::UploadGrant =
        serde_json::from_slice(&grant.body).expect("an upload grant");
    assert!(read.duplicate_of.is_none(), "these bytes do not exist yet");
    let target = read.target(&harness.api).expect("the uploadUrl lies under the API").to_owned();
    assert!(structure(&grant.json()).is_subset(&structure(&golden("ingest_grant.json"))));

    let path = target.trim_start_matches(&harness.api).to_owned();
    let uploaded = harness
        .with_dpop(
            Origin::Api,
            "PUT",
            &path,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_DIGEST, edms_wire::basics::digest_header_value(&sha)),
                (header::CONTENT_TYPE, "application/pdf".to_owned()),
            ],
            Some(bytes.clone()),
        )
        .await;
    assert_eq!(uploaded.status, 204, "{}", uploaded.text());

    let completion = harness
        .with_dpop(
            Origin::Api,
            "POST",
            &edms_wire::ingest::path_completion(read.upload_id),
            Some(&tokens.user),
            &harness.session_key,
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            Some(b"{}".to_vec()),
        )
        .await;
    assert_eq!(completion.status, 200, "{}", completion.text());
    let read: edms_wire::ingest::UploadCompletion =
        serde_json::from_slice(&completion.body).expect("an upload completion");
    let target = read.browser_target(harness.mock.app_base()).expect("a captureUrl under the app");
    assert!(structure(&completion.json()).is_subset(&structure(&golden("ingest_completed.json"))));

    let page = harness
        .raw(Origin::Login, "GET", target.trim_start_matches(&harness.auth), &[], None)
        .await;
    assert_eq!(page.status, 200);
    assert!(page.text().contains("Rechnung 2026-0412.pdf"), "{}", page.text());
}

#[tokio::test]
async fn a_duplicate_is_marked_and_a_wrong_digest_is_rejected() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let (case, _) = harness.mock.control().cases().into_iter().next().expect("a case file");
    let present = harness.mock.control().documents(case)[0];
    let bytes = edms_mock::pdf::generate(
        "Wartungsvertrag 2026 (geschwärzt)",
        &[
            "Mandant: ACME GmbH".to_owned(),
            format!("Ablage: {}", edms_mock::seed::CASE_MAINTENANCE),
            "Ausgelieferte Fassung: geschwärzt (§7.2.1)".to_owned(),
            "Dies ist ein Prüfstand, kein Beleg.".to_owned(),
        ],
    );
    let sha = edms_crypto::checksum::sha256(&bytes);
    let (basket, _) = harness.mock.control().baskets().into_iter().next().expect("a mail basket");
    let request = json!({
        "basketId": basket.to_string(),
        "fileName": "Wartungsvertrag.pdf",
        "mediaType": "application/pdf",
        "size": bytes.len(),
        "sha256": sha.wire_form(),
    });
    let grant = harness
        .with_dpop(
            Origin::Api,
            "POST",
            edms_wire::ingest::PATH_UPLOAD,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
            ],
            Some(serde_json::to_vec(&request).expect("JSON")),
        )
        .await;
    assert_eq!(grant.status, 201, "{}", grant.text());
    let read: edms_wire::ingest::UploadGrant =
        serde_json::from_slice(&grant.body).expect("an upload grant");
    let hint = read.duplicate_of.expect("the duplicate is marked, not suppressed");
    assert_eq!(hint.document_id, present);
    assert!(structure(&grant.json()).is_subset(&structure(&golden("ingest_grant_duplicate.json"))));

    // Bytes other than the ones announced: a breach of integrity, not a silent acceptance
    // (§7.4.1).
    let path = format!("/v1/ingest-uploads/{}/content", read.upload_id);
    let wrong = harness
        .with_dpop(
            Origin::Api,
            "PUT",
            &path,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_DIGEST, edms_wire::basics::digest_header_value(&sha)),
            ],
            Some(b"other bytes".to_vec()),
        )
        .await;
    assert_eq!(wrong.status, 422, "{}", wrong.text());
    assert_eq!(wrong.json()["type"], golden("problem_upload_digest.json")["type"]);
}

#[tokio::test]
async fn a_submission_naming_a_basket_that_is_gone_is_a_404_and_files_nothing_elsewhere() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    let basket = control.create_basket("Briefkorb Aussendienst");
    let bytes = b"%PDF-1.4\n% Briefkorb\n%%EOF\n".to_vec();
    let sha = edms_crypto::checksum::sha256(&bytes);
    // Between the drop and the submission the basket disappears — the case §7.4 names, and the
    // only one in which the client is holding a file it may not put anywhere.
    assert!(control.remove_basket(basket));

    let request = json!({
        "basketId": basket.to_string(),
        "fileName": "Rechnung 2026-0577.pdf",
        "mediaType": "application/pdf",
        "size": bytes.len(),
        "sha256": sha.wire_form(),
    });
    let refused = harness
        .with_dpop(
            Origin::Api,
            "POST",
            edms_wire::ingest::PATH_UPLOAD,
            Some(&tokens.user),
            &harness.session_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
            ],
            Some(serde_json::to_vec(&request).expect("JSON")),
        )
        .await;
    assert_eq!(refused.status, 404, "{}", refused.text());
    let problem: Problem = serde_json::from_slice(&refused.body).expect("a problem");
    assert_eq!(problem.error_kind(), edms_wire::basics::ErrorKind::NotFound);
    assert_eq!(
        refused.json()["title"],
        golden("problem_basket_unknown.json")["title"],
        "the answer comes out of the golden file, not out of a second wording"
    );
    assert!(
        refused.json().get("uploadUrl").is_none(),
        "an answer that still named an uploadUrl would invite the client to send the bytes anyway"
    );
}

#[tokio::test]
async fn the_recording_names_the_method_the_path_and_the_headers() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    harness.mock.control().forget_recording();
    let _ = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;

    let recording = harness.mock.control().recordings_for(edms_wire::namespace::PATH_ARCHIVES);
    let last = recording.last().expect("the request was recorded");
    assert_eq!(last.method, "GET");
    assert_eq!(last.path, edms_wire::namespace::PATH_ARCHIVES);
    assert_eq!(last.status, 200);
    assert_eq!(last.header(header::ELASTICDMS_VERSION), Some(API_VERSION));
    assert!(last.header(header::DPOP).is_some(), "every call carries a proof");
    assert!(
        last.header(header::AUTHORIZATION).is_some_and(|value| value.starts_with("DPoP ")),
        "never Bearer"
    );
}

#[tokio::test]
async fn the_control_creates_changes_and_removes_what_the_listing_then_shows() {
    let harness = common::start_with(Configuration::default().without_seed()).await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();

    let response = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    let page: Page<ArchiveRow> = serde_json::from_slice(&response.body).expect("a page");
    assert!(page.items.is_empty(), "without sowing there is not even an archive");

    let archive = control.create_archive("Rechnungseingang");
    let case = Location::Case {
        archive,
        case: control.create_case(archive, "Kreditor 4711 – Eingangsrechnungen"),
    };
    let document = control.create_document(case, "Rechnung 2026-0412").expect("a document");
    let path = path_document(case);
    let response = harness.api_get(&path, &tokens.user).await;
    let page: DocumentPage = serde_json::from_slice(&response.body).expect("a page");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].version, "1");

    let new = control.new_version(document).expect("a new version");
    assert_eq!(new, "2");
    let response = harness.api_get(&path, &tokens.user).await;
    let page: DocumentPage = serde_json::from_slice(&response.body).expect("a page");
    assert_eq!(page.items[0].version, "2", "the version marker carries the change");

    assert!(control.remove_document(document));
    let response = harness.api_get(&path, &tokens.user).await;
    let page: DocumentPage = serde_json::from_slice(&response.body).expect("a page");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn a_fault_bites_as_often_as_ordered_and_then_no_longer() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    harness.mock.control().inject_fault(edms_mock::Fault::status(
        edms_wire::namespace::PATH_ARCHIVES,
        429,
        1,
    ));

    let disturbed = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    assert_eq!(disturbed.status, 429);
    assert_eq!(
        disturbed.header_value(header::RETRY_AFTER),
        Some("1"),
        "Retry-After beats every backoff"
    );

    let afterwards = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    assert_eq!(afterwards.status, 200, "the fault was ordered for exactly one call");
}

#[tokio::test]
async fn a_stray_request_gets_problem_json_too_and_not_an_empty_page() {
    let harness = common::start().await;
    let unknown = harness
        .raw(
            Origin::Api,
            "GET",
            "/v1/doesnotexist",
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            None,
        )
        .await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.header_value(header::CONTENT_TYPE), Some(media_type::PROBLEM));
    let problem: Problem = serde_json::from_slice(&unknown.body).expect("a problem");
    assert_eq!(problem.error_kind(), edms_wire::basics::ErrorKind::NotFound);
    assert_eq!(problem.instance.as_deref(), Some("/v1/doesnotexist"));

    let wrong_method = harness
        .raw(
            Origin::Api,
            "DELETE",
            edms_wire::namespace::PATH_ARCHIVES,
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            None,
        )
        .await;
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.header_value(header::CONTENT_TYPE), Some(media_type::PROBLEM));
}
