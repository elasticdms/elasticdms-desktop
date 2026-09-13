//! The delivery channel: long poll, signed jobs, acknowledgements.
//!
//! The whole channel is invented (§7.3, finding Q-18) — all the more important that the mock
//! speaks it the way the contract describes it: outbound only, at most 25 seconds of waiting,
//! every answer with a cursor, every command **detached-signed** and checkable against the
//! anchored key set. A test harness that only produced valid commands could not show that the
//! client rejects an invalid one — and on that hangs whether a remote erasure stays a tool of the
//! archive or becomes one for whoever holds the load balancer.

// The helper functions of this test stand outside the `#[test]` bodies; `expect` is a failed
// assertion there too, and not something a caller could handle.
#![allow(clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{AccessTokens, Harness, command_holds, signature_header, structure};
use edms_core::identifier::CommandIdentifier;
use edms_mock::{CommandQuality, Origin};
use edms_wire::basics::{API_VERSION, header, media_type};
use edms_wire::delivery::{CommandKind, DeliveryPage};
use serde_json::{Value, json};

/// The key block as `GET /v1/server-keys` delivers it.
async fn block(harness: &Harness, tokens: &AccessTokens) -> Value {
    let response = harness.device_get(edms_wire::device::PATH_SERVER_KEY, &tokens.device).await;
    assert_eq!(response.status, 200, "{}", response.text());
    response.json()
}

/// Collects the open commands.
async fn collect(harness: &Harness, tokens: &AccessTokens, query: &str) -> common::Response {
    harness
        .device_get(&format!("{}{query}", edms_wire::delivery::PATH_COMMAND), &tokens.device)
        .await
}

#[tokio::test]
async fn a_queued_command_ends_the_wait_at_once() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let control = harness.mock.control();
    let device = harness.device;

    let beginning = tokio::time::Instant::now();
    let (response, identifier) = tokio::join!(collect(&harness, &tokens, "?wait=20"), async {
        tokio::time::sleep(Duration::from_millis(120)).await;
        control
            .queue_command(
                device,
                CommandKind::Dehydrate.wire_value(),
                json!({ "documentIds": ["doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB"], "reason": "ERASURE" }),
                CommandQuality::Valid,
            )
            .expect("a command")
    });
    assert!(
        beginning.elapsed() < Duration::from_secs(10),
        "the wait ends as soon as something is there"
    );
    assert_eq!(response.status, 200, "{}", response.text());
    let page: DeliveryPage = serde_json::from_slice(&response.body).expect("a delivery page");
    assert_eq!(page.items.len(), 1);
    assert!(!page.next_cursor.is_empty(), "the cursor always moves on");
    assert!(
        structure(&response.json())
            .is_subset(&structure(&common::golden("delivery_commands.json"))),
        "the delivery body carries a field the contract does not know"
    );

    let envelope = page.envelopes().remove(0).expect("the envelope reads");
    assert_eq!(envelope.command_id(), identifier);
    assert_eq!(envelope.device_id(), harness.device);
    assert_eq!(envelope.catalogue_kind(), Some(CommandKind::Dehydrate));
    let header = signature_header(envelope.server_signature().expect("a signature"));
    assert_eq!(
        header["typ"],
        json!(edms_wire::delivery::SIGNATURE_TYPE),
        "the typ is part of the check"
    );
    assert_eq!(header["alg"], json!("ES256"));
    envelope.command(harness.device).expect("the envelope becomes a command of the core");
}

#[tokio::test]
async fn an_empty_wait_is_not_a_failure_and_the_cursor_moves_on() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let beginning = tokio::time::Instant::now();
    let response = collect(&harness, &tokens, "?wait=1").await;
    assert!(beginning.elapsed() >= Duration::from_millis(900), "it really waited");
    assert_eq!(response.status, 200);
    let page: DeliveryPage = serde_json::from_slice(&response.body).expect("a delivery page");
    assert!(page.items.is_empty(), "a quiet day is not a fault");
    assert!(!page.next_cursor.is_empty());
    assert!(
        structure(&response.json()).is_subset(&structure(&common::golden("delivery_empty.json")))
    );
}

#[tokio::test]
async fn a_wait_time_above_the_limit_is_a_failure() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let response = collect(&harness, &tokens, "?wait=60").await;
    assert_eq!(
        response.status, 400,
        "above 25 s load balancers and corporate proxies do not hold out (§7.3.1)"
    );
}

#[tokio::test]
async fn a_validly_signed_command_holds_against_the_anchored_set() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let set = block(&harness, &tokens).await;
    harness
        .mock
        .control()
        .queue_command(
            harness.device,
            CommandKind::Reconcile.wire_value(),
            json!({ "container": Value::Null }),
            CommandQuality::Valid,
        )
        .expect("a command");

    let response = collect(&harness, &tokens, "?wait=0").await;
    let page: DeliveryPage = serde_json::from_slice(&response.body).expect("a delivery page");
    assert!(command_holds(&page.items[0], &set), "the signature has to hold against the anchor");
}

#[tokio::test]
async fn a_foreign_or_broken_signature_does_not_hold() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let set = block(&harness, &tokens).await;
    let control = harness.mock.control();
    for quality in [
        CommandQuality::ForeignSignature,
        CommandQuality::BrokenSignature,
        CommandQuality::WrongTyp("edms-server-key+jwt".to_owned()),
    ] {
        let name = format!("{quality:?}");
        control
            .queue_command(
                harness.device,
                CommandKind::Reconcile.wire_value(),
                json!({ "container": Value::Null }),
                quality,
            )
            .expect("a command");
        let response = collect(&harness, &tokens, "?wait=0").await;
        let page: DeliveryPage = serde_json::from_slice(&response.body).expect("a delivery page");
        let last = page.items.last().expect("one command");
        assert!(!command_holds(last, &set), "{name} may not hold");
    }

    // Without a `serverSignature` no command comes into being in the core at all (contract test
    // T22).
    control
        .queue_command(
            harness.device,
            CommandKind::SignOut.wire_value(),
            json!({}),
            CommandQuality::WithoutSignature,
        )
        .expect("a command");
    let response = collect(&harness, &tokens, "?wait=0").await;
    let page: DeliveryPage = serde_json::from_slice(&response.body).expect("a delivery page");
    let envelope = page.envelopes().pop().expect("an entry").expect("an envelope");
    assert!(envelope.server_signature().is_none());
    assert!(
        envelope.command(harness.device).is_err(),
        "without a signature no command comes into being"
    );
}

#[tokio::test]
async fn a_command_for_another_device_does_not_reach_this_device() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let foreign = "dev_01JB8Z5K3M4N6P7Q8R9S0T1V2W".parse().expect("an identifier");
    harness
        .mock
        .control()
        .queue_command(foreign, CommandKind::SignOut.wire_value(), json!({}), CommandQuality::Valid)
        .expect("a command");

    let response = collect(&harness, &tokens, "?wait=0").await;
    let page: DeliveryPage = serde_json::from_slice(&response.body).expect("a delivery page");
    assert!(page.items.is_empty(), "every device gets only its own jobs");
}

#[tokio::test]
async fn an_acknowledgement_is_replayed_and_rejected_with_a_different_body() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let identifier = harness
        .mock
        .control()
        .queue_command(
            harness.device,
            CommandKind::Reconcile.wire_value(),
            json!({ "container": Value::Null }),
            CommandQuality::Valid,
        )
        .expect("a command");

    let first =
        acknowledge(&harness, &tokens, identifier, "01JKC6F8G0H2J4K6M8N0P2Q4R6", "APPLIED").await;
    assert_eq!(first.status, 200, "{}", first.text());
    let receipt: edms_wire::delivery::AcknowledgementReceipt =
        serde_json::from_slice(&first.body).expect("an acknowledgement receipt");
    assert_eq!(receipt.command_id, identifier);
    assert!(
        structure(&first.json())
            .is_subset(&structure(&common::golden("acknowledgement_receipt.json")))
    );

    // The same key, the same body: the same answer, marked as a replay.
    let again =
        acknowledge(&harness, &tokens, identifier, "01JKC6F8G0H2J4K6M8N0P2Q4R6", "APPLIED").await;
    assert_eq!(again.status, 200);
    assert_eq!(again.header_value(header::IDEMPOTENCY_REPLAYED), Some("true"));
    assert_eq!(again.json(), first.json());

    // The same key, a different body: `422` (03 §6.0.10, AND-2).
    let other =
        acknowledge(&harness, &tokens, identifier, "01JKC6F8G0H2J4K6M8N0P2Q4R6", "FAILED").await;
    assert_eq!(other.status, 422, "{}", other.text());

    // A second attempt with a key of its own meets a command that is already done.
    let second =
        acknowledge(&harness, &tokens, identifier, "01JKC7G9H1J3K5M7N9P1Q3R5S7", "APPLIED").await;
    assert_eq!(second.status, 409, "for the client that is a success (§7.3.6)");
    assert_eq!(
        second.json()["type"],
        common::golden("problem_command_already_acknowledged.json")["type"]
    );
}

#[tokio::test]
async fn an_acknowledgement_without_an_idempotency_key_is_rejected() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let identifier = harness
        .mock
        .control()
        .queue_command(
            harness.device,
            CommandKind::SignOut.wire_value(),
            json!({}),
            CommandQuality::Valid,
        )
        .expect("a command");
    let response = harness
        .with_dpop(
            Origin::Api,
            "POST",
            &edms_wire::delivery::path_acknowledgement(identifier),
            Some(&tokens.device),
            &harness.device_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
            ],
            Some(br#"{"outcome":"APPLIED"}"#.to_vec()),
        )
        .await;
    assert_eq!(response.status, 400, "one ULID per attempt is compulsory (03 §6.0.10)");
}

#[tokio::test]
async fn the_remote_control_queues_a_command_and_holds_only_from_127_0_0_1() {
    let harness = common::start().await;
    let tokens = harness.signed_in().await;
    let response = harness
        .raw(
            Origin::Api,
            "POST",
            edms_mock::api::PATH_DEV_COMMAND,
            &[(header::CONTENT_TYPE, media_type::JSON.to_owned())],
            Some(
                serde_json::to_vec(&json!({
                    "kind": "RECONCILE",
                    "payload": { "container": Value::Null },
                }))
                .expect("JSON"),
            ),
        )
        .await;
    assert_eq!(response.status, 201, "{}", response.text());
    let identifier: CommandIdentifier =
        response.json()["commandId"].as_str().expect("commandId").parse().expect("an identifier");

    let collected = collect(&harness, &tokens, "?wait=0").await;
    let page: DeliveryPage = serde_json::from_slice(&collected.body).expect("a delivery page");
    let envelope = page.envelopes().remove(0).expect("an envelope");
    assert_eq!(envelope.command_id(), identifier);
    envelope.command(harness.device).expect("the way over curl signs correctly too");
}

/// Acknowledges a command.
async fn acknowledge(
    harness: &Harness,
    tokens: &AccessTokens,
    command: CommandIdentifier,
    key: &str,
    outcome: &str,
) -> common::Response {
    harness
        .with_dpop(
            Origin::Api,
            "POST",
            &edms_wire::delivery::path_acknowledgement(command),
            Some(&tokens.device),
            &harness.device_key,
            &[
                (header::ELASTICDMS_VERSION, API_VERSION.to_owned()),
                (header::CONTENT_TYPE, media_type::JSON.to_owned()),
                (header::IDEMPOTENCY_KEY, key.to_owned()),
            ],
            Some(serde_json::to_vec(&json!({ "outcome": outcome })).expect("JSON")),
        )
        .await
}
