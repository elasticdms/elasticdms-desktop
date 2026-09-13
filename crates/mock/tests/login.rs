//! Signing in: device token, device flow in the system browser, rotation and revocation.
//!
//! The device authorization grant is the **only** way in (AND-4/A-03): no PAR, no
//! `authorization_endpoint`, no web view. The four intermediate states are four different screens,
//! not one shared error — whoever throws "rejected" and "expired" together sends somebody who was
//! rejected off to wait. And the reuse of a rotated refresh token is a **security event**, not the
//! end of a session.

// The helper functions of this test stand outside the `#[test]` bodies; `expect` is a failed
// assertion there too, and not something a caller could handle.
#![allow(clippy::expect_used)]

mod common;

use common::{Harness, form, golden, structure};
use edms_mock::{Configuration, Origin};
use edms_wire::basics::{API_VERSION, header, media_type};
use edms_wire::login::{DeviceAuthorization, DeviceFlowStep, OauthError, TokenResponse};

/// Starts a device flow and returns the answer of the device authorization.
async fn authorize(harness: &Harness) -> DeviceAuthorization {
    let jkt = edms_crypto::key::SigningKey::public(&harness.session_key).thumbprint();
    let form_body = form(&[
        ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
        ("client_assertion", &harness.assertion()),
        ("scope", "openid profile folders:read documents:read ingest:submit"),
        ("resource", &harness.api),
        ("acr_values", edms_wire::login::ACR_DESKTOP),
        ("dpop_jkt", &jkt),
    ]);
    let response = harness
        .raw(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_DEVICE_AUTHORIZATION,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form_body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert!(
        structure(&response.json())
            .is_subset(&structure(&golden("device_authorization_desktop.json"))),
        "the device authorization carries a field the contract does not know"
    );
    serde_json::from_slice(&response.body).expect("a device authorization")
}

#[tokio::test]
async fn the_device_token_carries_exactly_the_three_device_scopes_and_no_refresh() {
    let harness = common::start().await;
    assert_eq!(harness.enroll().await.status, 201);
    let form_body = form(&[
        ("grant_type", "client_credentials"),
        ("scope", "device:self desktop:login delivery:receive"),
        ("resource", &harness.api),
        ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
        ("client_assertion", &harness.assertion()),
    ]);
    let response = harness
        .with_dpop(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_TOKEN,
            None,
            &harness.device_key,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form_body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.text());
    let token: TokenResponse = serde_json::from_slice(&response.body).expect("a token answer");
    assert!(token.refresh_token.is_none(), "a device re-asserts with its key");
    for scope in edms_wire::login::DEVICE_SCOPES {
        assert!(token.has_scope(scope), "{scope} is missing");
    }
    assert!(!token.has_scope("documents:read"), "the device token is allowed nothing of substance");
    assert!(
        structure(&response.json()).is_subset(&structure(&golden("token_device_desktop.json")))
    );
}

#[tokio::test]
async fn the_device_flow_waits_for_the_human_and_the_page_carries_both_buttons() {
    let harness = common::start_with(Configuration::default().awaiting_confirmation()).await;
    assert_eq!(harness.enroll().await.status, 201);
    let _ = harness.device_token().await;
    let authorization = authorize(&harness).await;
    let anchor = authorization.anchor.clone().expect("the four-character anchor");
    let target = authorization
        .browser_target(harness.mock.app_base())
        .expect("the address lies under the web interface")
        .to_owned();

    let pending = harness.fetch_token_raw(&authorization.device_code).await;
    assert_eq!(pending.status, 400);
    let error: OauthError = serde_json::from_slice(&pending.body).expect("an OAuth error");
    assert_eq!(error.in_device_flow(), DeviceFlowStep::Pending);
    assert_eq!(pending.json(), golden("oauth_authorization_pending.json"));

    let page = harness
        .raw(Origin::Login, "GET", target.trim_start_matches(&harness.auth), &[], None)
        .await;
    assert_eq!(page.status, 200);
    let text = page.text();
    // The two buttons are the whole decision; a page without them leaves the human nothing to
    // do but close the window.
    assert!(text.contains("Confirm"), "{text}");
    assert!(text.contains("Reject"), "{text}");
    assert!(text.contains(&anchor), "the human compares the anchor: {text}");

    let decided = harness
        .raw(
            Origin::Login,
            "POST",
            "/geraet",
            &[(header::CONTENT_TYPE, media_type::FORM.to_owned())],
            Some(
                form(&[("user_code", &authorization.user_code), ("action", "confirm")])
                    .into_bytes(),
            ),
        )
        .await;
    assert_eq!(decided.status, 200);
    assert!(decided.text().contains("Signed in"), "{}", decided.text());

    let fetched = harness.fetch_token_raw(&authorization.device_code).await;
    assert_eq!(fetched.status, 200, "{}", fetched.text());
    assert!(structure(&fetched.json()).is_subset(&structure(&golden("token_user_desktop.json"))));
}

#[tokio::test]
async fn rejected_expired_and_slow_down_are_three_different_screens() {
    let harness = common::start_with(Configuration::default().awaiting_confirmation()).await;
    assert_eq!(harness.enroll().await.status, 201);
    let control = harness.mock.control();

    let rejected = authorize(&harness).await;
    assert!(control.reject(&rejected.user_code));
    let response = harness.fetch_token_raw(&rejected.device_code).await;
    assert_eq!(response.json(), golden("oauth_access_denied.json"));
    let error: OauthError = serde_json::from_slice(&response.body).expect("an error");
    assert_eq!(error.in_device_flow(), DeviceFlowStep::Rejected);

    let expired = authorize(&harness).await;
    assert!(control.let_lapse(&expired.user_code));
    let response = harness.fetch_token_raw(&expired.device_code).await;
    assert_eq!(response.json(), golden("oauth_code_expired.json"));
    let error: OauthError = serde_json::from_slice(&response.body).expect("an error");
    assert_eq!(error.in_device_flow(), DeviceFlowStep::Expired);

    let slow = authorize(&harness).await;
    assert!(control.demand_slower(&slow.user_code));
    let response = harness.fetch_token_raw(&slow.device_code).await;
    assert_eq!(response.json(), golden("oauth_slow_down.json"));
    let again = harness.fetch_token_raw(&slow.device_code).await;
    assert_eq!(
        again.json(),
        golden("oauth_authorization_pending.json"),
        "slow_down comes once; the increment stays the client's business (RFC 8628 §3.5)"
    );
}

#[tokio::test]
async fn a_foreign_session_key_does_not_redeem_the_code() {
    let harness = common::start().await;
    assert_eq!(harness.enroll().await.status, 201);
    let authorization = authorize(&harness).await;

    let foreign = edms_crypto::key::SoftwareKey::generate().expect("a key");
    let form_body = form(&[
        ("grant_type", edms_wire::login::GRANT_DEVICE_CODE),
        ("device_code", &authorization.device_code),
        ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
        ("client_assertion", &harness.assertion()),
    ]);
    let response = harness
        .with_dpop(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_TOKEN,
            None,
            &foreign,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form_body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, 400, "{}", response.text());
    assert_eq!(
        response.json()["error"],
        "invalid_dpop_proof",
        "RFC 9449 §5 binds the token to dpop_jkt"
    );
}

#[tokio::test]
async fn reusing_a_refresh_token_revokes_the_whole_family() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;

    let renewed = harness.refresh(&tokens.refresh).await;
    assert_eq!(renewed.status, 200, "{}", renewed.text());
    let new: TokenResponse = serde_json::from_slice(&renewed.body).expect("a token answer");
    let second = new.refresh_token.clone().expect("every renewal delivers a new one");
    assert_ne!(second, tokens.refresh, "rotation means: a different token");

    // The same token a second time: a security event, not the end of a session.
    let reused = harness.refresh(&tokens.refresh).await;
    assert_eq!(reused.status, 400);
    assert_eq!(reused.json(), golden("oauth_refresh_reused.json"));
    let error: OauthError = serde_json::from_slice(&reused.body).expect("an error");
    assert_eq!(error.at_refresh(), edms_wire::login::RefreshStep::FamilyRevoked);
    assert!(error.error_kind().security_event());

    // The family is gone: even the access token just issued carries nothing any more.
    let afterwards = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &new.access_token).await;
    assert_eq!(afterwards.status, 401, "the family is revoked, not only the one token");
    let again = harness.refresh(&second).await;
    assert_eq!(again.status, 400, "the rotated token is gone too");
}

#[tokio::test]
async fn a_device_without_approval_gets_no_token_and_with_approval_it_does() {
    let harness = common::start_with(Configuration::default().awaiting_approval()).await;
    assert_eq!(harness.enroll().await.status, 201);
    let form_body = form(&[
        ("grant_type", "client_credentials"),
        ("scope", "device:self desktop:login delivery:receive"),
        ("resource", &harness.api),
        ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
        ("client_assertion", &harness.assertion()),
    ]);
    let response = harness
        .with_dpop(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_TOKEN,
            None,
            &harness.device_key,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form_body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, 403, "{}", response.text());
    let error: OauthError = serde_json::from_slice(&response.body).expect("an error");
    assert_eq!(
        error.error_kind(),
        edms_wire::basics::ErrorKind::DeviceApprovalPending,
        "the bridge into the catalogue is error_uri (§7.0.3)"
    );

    assert!(harness.mock.control().approve_device(harness.device));
    let token = harness.device_token().await;
    assert!(!token.is_empty(), "after the confirmation by a human it goes on");
}

#[tokio::test]
async fn a_revoked_device_loses_every_token_at_once() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    assert_eq!(
        harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await.status,
        200
    );

    assert!(harness.mock.control().revoke_device(harness.device));
    let response = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    assert_eq!(response.status, 401, "the token of the revoked device is gone");
}

#[tokio::test]
async fn signing_out_revokes_the_refresh_token_and_always_answers_200() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let form_body = form(&[
        ("token", &tokens.refresh),
        ("token_type_hint", "refresh_token"),
        ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
        ("client_assertion", &harness.assertion()),
    ]);
    let response = harness
        .raw(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_REVOCATION,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form_body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, 200);

    let unknown = harness
        .raw(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_REVOCATION,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(
                form(&[
                    ("token", "rt_doesnotexist"),
                    ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
                    ("client_assertion", &harness.assertion()),
                ])
                .into_bytes(),
            ),
        )
        .await;
    assert_eq!(unknown.status, 200, "RFC 7009: an unknown token is a 200 too");

    let afterwards = harness.api_get(edms_wire::namespace::PATH_ARCHIVES, &tokens.user).await;
    assert_eq!(
        afterwards.status, 401,
        "after signing out no token of the session carries any more"
    );
}

#[tokio::test]
async fn a_client_assertion_for_another_recipient_does_not_hold() {
    let harness = common::start().await;
    assert_eq!(harness.enroll().await.status, 201);
    let foreign = edms_crypto::assertion::client_assertion(
        &harness.device_key,
        &harness.kid,
        harness.device,
        "https://auth.beispiel.invalid",
        edms_mock::time::now(),
    )
    .expect("an assertion");
    let form_body = form(&[
        ("grant_type", "client_credentials"),
        ("scope", "device:self"),
        ("resource", &harness.api),
        ("client_assertion_type", edms_crypto::assertion::ASSERTION_TYP),
        ("client_assertion", &foreign),
    ]);
    let response = harness
        .with_dpop(
            Origin::Login,
            "POST",
            edms_wire::login::PATH_TOKEN,
            None,
            &harness.device_key,
            &[
                (header::CONTENT_TYPE, media_type::FORM.to_owned()),
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
            ],
            Some(form_body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, 400, "{}", response.text());
    let error: OauthError = serde_json::from_slice(&response.body).expect("an error");
    assert_eq!(error.error_kind(), edms_wire::basics::ErrorKind::DeviceAssertionInvalid);
}
