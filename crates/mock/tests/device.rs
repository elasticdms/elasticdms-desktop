//! Device, heartbeat and server keys — the three calls under the device token.
//!
//! The fingerprint of the anchor set is **computed here**, never taken over from
//! `anchorSetFingerprint` (§7.0.5): whoever can forge the answer forges the field too. This test
//! therefore computes it itself and holds it against the reported one — both have to coincide,
//! otherwise the mock does not agree with itself.

mod common;

use common::{golden, structure};
use edms_crypto::key_set::{KeyOffer, KeySet};
use edms_mock::Origin;
use edms_wire::basics::{API_VERSION, header, media_type};
use edms_wire::device::{DeviceObject, PATH_OWN_IT_DEVICE, PATH_SERVER_KEY};
use serde_json::json;

#[tokio::test]
async fn the_own_device_reads_as_a_wire_type_and_carries_the_key_block() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let response = harness.device_get(PATH_OWN_IT_DEVICE, &tokens.device).await;
    assert_eq!(response.status, 200, "{}", response.text());
    let object: DeviceObject = serde_json::from_slice(&response.body).expect("a device object");
    assert_eq!(object.device_id, harness.device);
    assert!(object.is_active());
    assert_eq!(object.oauth.and_then(|oauth| oauth.dpop_bound_access_tokens), Some(true));
    assert!(
        structure(&response.json()).is_subset(&structure(&golden("device_desktop.json"))),
        "the device object carries a field device_desktop.json does not know"
    );

    // The same block reads as a key offer — and anchors itself.
    let offer = KeyOffer::from_enrollment(&response.json()).expect("a key offer");
    let adoption = KeySet::empty().anchor(&offer, Some("t_acme")).expect("the set anchors itself");
    assert!(adoption.report.is_empty(), "{:?}", adoption.report_code());
    assert_eq!(
        offer.reported_fingerprint().map(ToOwned::to_owned),
        Some(offer.fingerprint().display()),
        "the fingerprint computed here coincides with the reported one (§7.0.5)"
    );
}

#[tokio::test]
async fn the_key_set_also_comes_on_its_own_and_carries_both_anchors() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let response = harness.device_get(PATH_SERVER_KEY, &tokens.device).await;
    assert_eq!(response.status, 200, "{}", response.text());
    let offer = KeyOffer::from_json(&response.json()).expect("a key offer");
    assert_eq!(offer.anchors().len(), 2, "two anchors, one in reserve");
    assert_eq!(offer.signature_signing_key().len(), 1);
    assert!(offer.unreadable_entries().is_empty(), "{:?}", offer.unreadable_entries());
    assert_eq!(offer.tenant_id(), "t_acme");
    assert!(
        structure(&response.json()).is_subset(&structure(&golden("server_key_set.json"))),
        "the key block carries a field the contract does not know"
    );

    // An anchor never counter-signs itself (geraete-auth §5.4, contract test T8).
    for anchor in offer.anchors() {
        assert!(anchor.signer_kid().is_none(), "{} is self-signed", anchor.kid());
    }
    let set = KeySet::empty()
        .anchor(&offer, None)
        .expect("the adoption")
        .set
        .confirm()
        .expect("the confirmation");
    assert!(set.carries(), "without an anchor a command is never carried out (§7.3.4)");
}

#[tokio::test]
async fn the_heartbeat_answers_with_the_server_time_and_gives_only_hints() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    harness.mock.control().queue_heartbeat_command(json!({
        "command": "resyncServerKeys",
        "reason": "key_rotated",
        "message": "The server key set has been renewed.",
    }));

    let body = json!({
        "sentAtDevice": edms_mock::time::now().rfc3339(),
        "app": { "versionName": "1.0.0" },
        "platform": { "os": "Windows", "osVersion": "10.0.26100", "arch": "x86_64" },
    });
    let response = harness
        .with_dpop(
            Origin::Api,
            "POST",
            &edms_wire::device::path_heartbeat(harness.device),
            Some(&tokens.device),
            &harness.device_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
            ],
            Some(serde_json::to_vec(&body).expect("JSON")),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.text());
    let read: edms_wire::device::HeartbeatResponse =
        serde_json::from_slice(&response.body).expect("a heartbeat answer");
    let commands = read.commands.expect("one hint");
    assert_eq!(commands.len(), 1);
    assert!(
        commands[0].command.is_harmless_hint(),
        "everything that removes copies comes signed over the delivery channel (§7.0.10)"
    );
    assert!(
        structure(&response.json())
            .is_subset(&structure(&golden("heartbeat_response_desktop.json"))),
        "the heartbeat answer carries an unknown field"
    );
}

#[tokio::test]
async fn a_heartbeat_for_a_foreign_device_is_rejected() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let foreign = "dev_01JB8Z5K3M4N6P7Q8R9S0T1V2W".parse().expect("an identifier");
    let response = harness
        .with_dpop(
            Origin::Api,
            "POST",
            &edms_wire::device::path_heartbeat(foreign),
            Some(&tokens.device),
            &harness.device_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
            ],
            Some(b"{}".to_vec()),
        )
        .await;
    assert_eq!(response.status, 403, "{}", response.text());
    assert_eq!(
        response.json()["type"],
        golden("problem_token_device_binding.json")["type"],
        "the token claim and the device proven by DPoP have to coincide"
    );
}
