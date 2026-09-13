//! DPoP, the eight steps — and what happens when one of them does not hold.
//!
//! The order of the check is normative (geraete-auth §2.4): header, signature, `htm`/`htu`, nonce,
//! `jti`, `iat`, `ath`. A test harness that merely says yes to that proves nothing; every test here
//! presents a proof that is wrong in **one** place and expects the rejection at exactly that place.

// The helper functions of this test stand outside the `#[test]` bodies; `expect` is a failed
// assertion there too, and not something a caller could handle.
#![allow(clippy::expect_used)]

mod common;

use common::{Harness, Response};
use edms_crypto::dpop::{self, DpopProofRequest};
use edms_crypto::key::{SigningKey, SoftwareKey};
use edms_mock::Origin;
use edms_wire::basics::{API_VERSION, header, media_type};

/// A proof with every detail set by hand.
fn proof(
    key: &dyn SigningKey,
    method: &str,
    url: &str,
    nonce: Option<&str>,
    token: Option<&str>,
) -> String {
    dpop::proof(
        key,
        &DpopProofRequest { method, url, nonce, access_token: token },
        edms_mock::time::now(),
    )
    .expect("a proof")
}

/// A `GET /v1/mirror/archives` with a proof built by hand.
async fn with_proof(harness: &Harness, proof: String, token: &str) -> Response {
    harness
        .raw(
            Origin::Api,
            "GET",
            edms_wire::namespace::PATH_ARCHIVES,
            &[
                (header::DPOP, proof),
                (header::AUTHORIZATION, format!("DPoP {token}")),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            None,
        )
        .await
}

#[tokio::test]
async fn without_a_nonce_a_401_use_dpop_nonce_comes_and_the_retry_succeeds() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);

    let without = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, None, Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(without.status, 401, "{}", without.text());
    assert_eq!(
        without.header_value(header::WWW_AUTHENTICATE),
        Some("DPoP error=\"use_dpop_nonce\""),
        "without the demand the client would not know what is missing"
    );
    let nonce =
        without.header_value(header::DPOP_NONCE).expect("the answer carries the nonce").to_owned();
    assert_eq!(without.json()["type"], common::golden("problem_dpop_nonce_required.json")["type"]);
    assert_eq!(
        without.header_value(header::CONTENT_TYPE),
        Some(media_type::PROBLEM),
        "the resource API answers problem+json (§7.0.3)"
    );

    let second = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, Some(&nonce), Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(second.status, 200, "exactly one retry suffices (T9): {}", second.text());
}

#[tokio::test]
async fn a_rotated_nonce_demands_exactly_one_further_attempt() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);
    let old = harness.nonce(Origin::Api).expect("the first request brought a nonce");
    let new = harness.mock.control().rotate_nonce(Origin::Api);
    assert_ne!(old, new);

    let stale = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, Some(&old), Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(stale.status, 401);
    assert_eq!(stale.header_value(header::DPOP_NONCE), Some(new.as_str()));

    let fresh = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, Some(&new), Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(fresh.status, 200, "{}", fresh.text());
}

#[tokio::test]
async fn the_nonce_of_one_host_does_not_hold_at_the_other() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);
    let foreign = harness.nonce(Origin::Login).expect("the token endpoint gave a nonce");

    let response = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, Some(&foreign), Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(
        response.status, 401,
        "one nonce per origin; otherwise the client circles between two demands (§7.0.9)"
    );
    assert_eq!(
        response.header_value(header::WWW_AUTHENTICATE),
        Some("DPoP error=\"use_dpop_nonce\"")
    );
}

#[tokio::test]
async fn a_proof_for_another_method_or_another_target_does_not_hold() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let nonce = harness.nonce(Origin::Api);
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);

    let wrong_method = with_proof(
        &harness,
        proof(&harness.session_key, "POST", &url, nonce.as_deref(), Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(wrong_method.status, 401);
    assert!(wrong_method.text().contains("htm"), "{}", wrong_method.text());

    let wrong_target = with_proof(
        &harness,
        proof(
            &harness.session_key,
            "GET",
            &format!("{}{}", harness.api, edms_wire::namespace::PATH_SEARCHES),
            harness.nonce(Origin::Api).as_deref(),
            Some(&tokens.user),
        ),
        &tokens.user,
    )
    .await;
    assert_eq!(wrong_target.status, 401);
    assert!(wrong_target.text().contains("htu"), "{}", wrong_target.text());
}

#[tokio::test]
async fn a_replayed_jti_holds_exactly_once() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);
    let nonce = harness.nonce(Origin::Api).expect("a nonce");
    let once_only = dpop::proof_with_jti(
        &harness.session_key,
        &DpopProofRequest {
            method: "GET",
            url: &url,
            nonce: Some(&nonce),
            access_token: Some(&tokens.user),
        },
        edms_mock::time::now(),
        "01JKC6F8G0H2J4K6M8N0P2Q4R6",
    )
    .expect("a proof");

    let first = with_proof(&harness, once_only.clone(), &tokens.user).await;
    assert_eq!(first.status, 200, "{}", first.text());
    let second = with_proof(&harness, once_only, &tokens.user).await;
    assert_eq!(second.status, 401, "a proof holds exactly once");
    assert!(second.text().contains("replay window"), "{}", second.text());
}

#[tokio::test]
async fn a_proof_without_a_matching_ath_does_not_carry_the_token() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);
    let nonce = harness.nonce(Origin::Api);

    // The proof names a different token from the one the Authorization header carries.
    let foreign = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, nonce.as_deref(), Some(&tokens.device)),
        &tokens.user,
    )
    .await;
    assert_eq!(foreign.status, 401);
    assert!(foreign.text().contains("ath"), "{}", foreign.text());

    // Entirely without `ath`: a proof that belonged to a request without a token.
    let without = with_proof(
        &harness,
        proof(&harness.session_key, "GET", &url, harness.nonce(Origin::Api).as_deref(), None),
        &tokens.user,
    )
    .await;
    assert_eq!(without.status, 401);
    assert!(without.text().contains("ath"), "{}", without.text());
}

#[tokio::test]
async fn a_foreign_key_does_not_carry_a_bound_token() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);
    let foreign = SoftwareKey::generate().expect("a key");

    let response = with_proof(
        &harness,
        proof(&foreign, "GET", &url, harness.nonce(Origin::Api).as_deref(), Some(&tokens.user)),
        &tokens.user,
    )
    .await;
    assert_eq!(response.status, 401, "{}", response.text());
    // The wording comes out of `edms-crypto` — `ProofError::KeyBindingMismatch`, which the mock
    // forwards verbatim into the RFC 9457 `detail` (src/http.rs, `Problem::from_catalogue`).
    assert!(response.text().contains("is bound to the key"), "{}", response.text());
}

#[tokio::test]
async fn a_bearer_token_fails_already_on_reading() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let url = format!("{}{}", harness.api, edms_wire::namespace::PATH_ARCHIVES);
    let response = harness
        .raw(
            Origin::Api,
            "GET",
            edms_wire::namespace::PATH_ARCHIVES,
            &[
                (
                    header::DPOP,
                    proof(
                        &harness.session_key,
                        "GET",
                        &url,
                        harness.nonce(Origin::Api).as_deref(),
                        Some(&tokens.user),
                    ),
                ),
                (header::AUTHORIZATION, format!("Bearer {}", tokens.user)),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            None,
        )
        .await;
    assert_eq!(response.status, 401, "{}", response.text());
    assert_eq!(
        response.json()["type"],
        common::golden("problem_token_device_binding.json")["type"],
        "an unbound token would be usable without this device's key (T21)"
    );
}

#[tokio::test]
async fn without_a_proof_and_without_a_sign_in_a_401_comes_with_the_dpop_scheme() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;

    let without_everything = harness
        .raw(
            Origin::Api,
            "GET",
            edms_wire::namespace::PATH_ARCHIVES,
            &[(header::ELASTICDMS_VERSION, API_VERSION.to_owned())],
            None,
        )
        .await;
    assert_eq!(without_everything.status, 401);
    assert_eq!(without_everything.header_value(header::WWW_AUTHENTICATE), Some("DPoP"));

    let without_proof = harness
        .raw(
            Origin::Api,
            "GET",
            edms_wire::namespace::PATH_ARCHIVES,
            &[
                (header::AUTHORIZATION, format!("DPoP {}", tokens.user)),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            None,
        )
        .await;
    assert_eq!(without_proof.status, 401);
    assert!(
        without_proof
            .header_value(header::WWW_AUTHENTICATE)
            .is_some_and(|value| value.contains("invalid_dpop_proof")),
        "{:?}",
        without_proof.header_value(header::WWW_AUTHENTICATE)
    );
}

#[tokio::test]
async fn a_missing_scope_is_a_403_with_the_name_of_the_scope() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    // The device token is allowed nothing of substance (§7.0.6).
    let response = harness.device_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.device).await;
    assert_eq!(response.status, 403, "{}", response.text());
    assert_eq!(
        response.header_value(header::WWW_AUTHENTICATE),
        Some("DPoP error=\"insufficient_scope\", scope=\"folders:read\"")
    );
}
