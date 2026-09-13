//! The acceptance rules P1 to P12 (03 §6.2.4) and the contract tests T6 to T8
//! (geraete-auth §9.1).
//!
//! Checking happens against **real** signatures from [`crate::forge`]. A mock that returns
//! “valid” would only prove that the test case believes what it claimed itself; it would find
//! neither a shifted field nor a wrong canonicalization nor a self-vouching that slips through.
//!
//! T6 (the anchor fingerprint for one, two and three anchors and under reordering) stands with
//! the computation itself, in [`crate::anchor`].

use super::*;
use crate::forge::{Forge, TestKey};
use serde_json::json;

/// Inside the default window of every test key (2020 to 2099).
const NOW: Timestamp = Timestamp::from_unix_millis(1_788_336_862_000);

/// 2026-01-01T00:00:00Z — start of a narrow validity window.
const START_2026: Timestamp = Timestamp::from_unix_millis(1_767_225_600_000);

/// 2027-01-01T00:00:00Z — end of a narrow validity window.
const START_2027: Timestamp = Timestamp::from_unix_millis(1_798_761_600_000);

fn anchor_key(kid: &str) -> TestKey {
    TestKey::anchor_key(kid).expect("randomness for a test key pair")
}

fn signer(kid: &str) -> TestKey {
    TestKey::proof(kid).expect("randomness for a test key pair")
}

fn offer(block: &Value) -> KeyOffer {
    KeyOffer::from_json(block).expect("the built block is readable")
}

/// The normal case: two anchors (geraete-auth §5.1: there are always at least two), one evidence
/// key, state 7, confirmed.
struct Stage {
    forge: Forge,
    a: TestKey,
    b: TestKey,
    kms: TestKey,
    set: KeySet,
}

impl Stage {
    fn new() -> Self {
        Self::with_window(crate::forge::DEFAULT_NOT_BEFORE, crate::forge::DEFAULT_NOT_AFTER)
    }

    fn with_window(not_before: Timestamp, not_after: Timestamp) -> Self {
        let forge = Forge::new();
        let a = anchor_key("edms-anchor-2026-a");
        let b = anchor_key("edms-anchor-2026-b");
        let kms =
            signer("edms-kms-2026-09").with_key_set_version(7).with_window(not_before, not_after);
        let block = forge
            .block(7)
            .with_anchor([forge.entry(&a).as_anchor(), forge.entry(&b).as_anchor()])
            .with_key([forge.entry(&kms).signed_by(&a).unwrap()])
            .builder()
            .unwrap();
        let set = KeySet::empty().anchor(&offer(&block), None).unwrap().set.confirm().unwrap();
        Self { forge, a, b, kms, set }
    }

    /// The two anchored anchors, as the server delivers them again.
    fn anchor_entries(&self) -> Vec<Value> {
        vec![self.forge.entry(&self.a).as_anchor(), self.forge.entry(&self.b).as_anchor()]
    }

    /// A signed delivery command from the stage's evidence key.
    fn command(&self, timestamp: Timestamp) -> Value {
        self.command_of(&self.kms, timestamp)
    }

    fn command_of(&self, signer: &TestKey, timestamp: Timestamp) -> Value {
        self.forge
            .command("job_01JB8Z5K3M4N6P7Q8R9S0T1V2W", "dehydrate")
            .with_payload(
                json!({"cause": "erasure", "documentIds": ["doc_01JB8Z5K3M4N6P7Q8R9S0T1V2X"]}),
            )
            .from_posed(timestamp)
            .signed_by(signer)
            .unwrap()
    }
}

// ───────────────────────────── Anchoring (enrollment) ─────────────────────────────

#[test]
fn the_first_anchoring_adopts_anchors_and_keys_and_waits_for_the_human() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let b = anchor_key("edms-anchor-2026-b");
    let kms = signer("edms-kms-2026-09");
    let block = forge
        .block(7)
        .with_anchor([forge.entry(&a).as_anchor(), forge.entry(&b).as_anchor()])
        .with_key([forge.entry(&kms).signed_by(&b).unwrap()])
        .builder()
        .unwrap();
    let adoption = KeySet::empty().anchor(&offer(&block), Some("t_acme")).unwrap();
    let set = adoption.set;
    assert!(adoption.report.is_empty(), "{:?}", adoption.report);
    assert_eq!(set.anchor_state(), AnchorState::AwaitingConfirmation);
    assert_eq!(set.key_set_version(), 7);
    assert_eq!(set.issuer(), "https://api.elasticdms.io");
    assert_eq!(set.tenant_id(), "t_acme");
    assert_eq!(set.anchors().len(), 2);
    assert_eq!(set.signature_kids(), vec!["edms-kms-2026-09"]);
    assert_eq!(
        set.fingerprint(),
        crate::anchor::AnchorFingerprint::from_thumbprint(&[a.thumbprint(), b.thumbprint()])
    );
    assert_eq!(set.generated_at(), Some(crate::forge::DEFAULT_GENERATED_AT));
    assert_eq!(set.refresh_after(), Some(crate::forge::DEFAULT_REFRESH_AFTER));
    assert_eq!(set.next_rotation_at(), Some(crate::forge::DEFAULT_NEXT_ROTATION));
    // Before the confirmation the set does not carry — and that is contractual, not a fault.
    assert!(!set.carries());
    assert_eq!(set.confirm().unwrap().anchor_state(), AnchorState::Confirmed);
}

#[test]
fn an_answer_without_anchors_establishes_no_trust() {
    let forge = Forge::new();
    let block = forge.block(1).builder().unwrap();
    assert_eq!(KeySet::empty().anchor(&offer(&block), None), Err(CryptoError::NoAnchor));
}

#[test]
fn an_anchor_with_the_role_of_an_evidence_key_refuses_the_whole_answer() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let entry = forge.entry(&a).with_role("evidence-signing").as_anchor();
    let block = forge.block(1).with_anchor([entry]).builder().unwrap();
    assert_eq!(
        KeySet::empty().anchor(&offer(&block), None),
        Err(CryptoError::RoleMismatch {
            kid: "edms-anchor-2026-a".into(),
            expected: "trust-anchor",
            read: "evidence-signing".into(),
        })
    );
}

// Contract test T8, first half: an anchor that counter-signs itself (P4).
#[test]
fn t8_an_anchor_that_counter_signs_itself_refuses_the_whole_answer() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let self_signed = forge.entry(&a).signed_by(&a).unwrap();
    let block = forge.block(1).with_anchor([self_signed]).builder().unwrap();
    let error = KeySet::empty().anchor(&offer(&block), None).unwrap_err();
    assert_eq!(error, CryptoError::SelfSigned { kid: "edms-anchor-2026-a".into() });
    assert_eq!(error.report(), Some(KeyReport::SelfSigned));
    assert!(KeyReport::SelfSigned.security_event());
}

// Contract test T8, second half: an evidence key that counter-signs itself (P4/P5).
#[test]
fn t8_a_self_counter_signed_key_is_discarded_and_the_answer_stays_valid() {
    let stage = Stage::new();
    let itself = signer("edms-kms-2026-10");
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_key([stage.forge.entry(&itself).signed_by(&itself).unwrap()])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert_eq!(adoption.report, vec![CryptoError::SelfSigned { kid: "edms-kms-2026-10".into() }]);
    assert_eq!(adoption.report_code(), vec![KeyReport::SelfSigned]);
    assert!(adoption.security_event());
    assert_eq!(adoption.set.signature_kids(), vec!["edms-kms-2026-09"]);
    assert_eq!(adoption.set.key_set_version(), 8);
}

#[test]
fn a_reported_fingerprint_that_does_not_match_the_own_computation_is_refused() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let block = forge
        .block(1)
        .with_anchor([forge.entry(&a).as_anchor()])
        .with_reported_fingerprint("NGJQ-CWV1-AHAR-Z4FJ")
        .builder()
        .unwrap();
    let error = KeySet::empty().anchor(&offer(&block), None).unwrap_err();
    assert!(matches!(error, CryptoError::FingerprintChanged { .. }), "{error:?}");
    assert_eq!(error.report(), Some(KeyReport::FingerprintChanged));
    // Without the field it works: the own computation is authoritative anyway (geraete-auth §5.3).
    let without = forge
        .block(1)
        .with_anchor([forge.entry(&a).as_anchor()])
        .without_fingerprint()
        .builder()
        .unwrap();
    assert!(KeySet::empty().anchor(&offer(&without), None).is_ok());
}

#[test]
fn a_foreign_tenant_refuses_the_answer_wherever_it_stands() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    // The configured tenant does not match the block (P7).
    let block = forge.block(1).with_anchor([forge.entry(&a).as_anchor()]).builder().unwrap();
    assert_eq!(
        KeySet::empty().anchor(&offer(&block), Some("t_other")),
        Err(CryptoError::TenantMismatch { expected: "t_other".into(), read: "t_acme".into() })
    );
    // The entry does not match the block (P7).
    let skewed = forge
        .block(1)
        .with_anchor([forge.entry(&a).with_tenant_id("t_foreign").as_anchor()])
        .builder()
        .unwrap();
    assert_eq!(
        KeySet::empty().anchor(&offer(&skewed), None),
        Err(CryptoError::TenantMismatch { expected: "t_acme".into(), read: "t_foreign".into() })
    );
}

#[test]
fn a_reported_thumbprint_that_does_not_match_the_coordinates_is_refused() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let block = forge
        .block(1)
        .with_anchor([forge
            .entry(&a)
            .with_thumbprint("LAsBA719DG2FA0dsYL6V-xZPqUvH2HX8f1Zu55HYrYc")
            .as_anchor()])
        .without_fingerprint()
        .builder()
        .unwrap();
    let error = KeySet::empty().anchor(&offer(&block), None).unwrap_err();
    assert!(matches!(error, CryptoError::ThumbprintMismatch { .. }), "{error:?}");
}

#[test]
fn a_repeated_anchoring_with_the_same_set_is_a_success_and_changes_nothing() {
    // 03 §6.2.1: a `412` with the same device object is the idempotent retry.
    let stage = Stage::new();
    let block = stage
        .forge
        .block(7)
        .with_anchor(stage.anchor_entries())
        .with_key([stage.forge.entry(&stage.kms).signed_by(&stage.a).unwrap()])
        .builder()
        .unwrap();
    let again = stage.set.anchor(&offer(&block), None).unwrap().set;
    assert_eq!(again.anchor_state(), AnchorState::Confirmed);
    assert_eq!(again.anchors().len(), 2);
    assert_eq!(again.signature_kids(), vec!["edms-kms-2026-09"]);
    assert_eq!(again.fingerprint(), stage.set.fingerprint());
}

#[test]
fn an_anchored_set_is_replaced_by_no_network_answer() {
    // geraete-auth §5.4 step 4: written exactly once.
    let stage = Stage::new();
    let foreign = anchor_key("edms-anchor-foreign");
    let block = stage
        .forge
        .block(9)
        .with_anchor([stage.forge.entry(&foreign).as_anchor()])
        .builder()
        .unwrap();
    let error = stage.set.anchor(&offer(&block), None).unwrap_err();
    assert!(matches!(error, CryptoError::FingerprintChanged { .. }), "{error:?}");
    assert_eq!(stage.set.anchors().len(), 2);
}

#[test]
fn without_anchors_there_is_nothing_to_confirm() {
    assert_eq!(KeySet::empty().confirm(), Err(CryptoError::NoAnchor));
    assert!(!KeySet::empty().carries());
    assert_eq!(KeySet::empty().anchor_state(), AnchorState::NoAnchor);
}

// ──────────────────────── Continuation (GET /v1/server-keys) ────────────────────────

// Contract test T7.
#[test]
fn t7_an_answer_with_a_smaller_key_set_version_does_not_change_the_state() {
    let stage = Stage::new();
    let before = stage.set.clone();
    let block = stage.forge.block(6).with_anchor(stage.anchor_entries()).builder().unwrap();
    let error = stage.set.adopt(&offer(&block)).unwrap_err();
    assert_eq!(error, CryptoError::StateReset { stored: 7, offered: 6 });
    assert_eq!(error.report(), Some(KeyReport::StateReset));
    assert!(KeyReport::StateReset.security_event());
    assert_eq!(
        KeyReport::StateReset.type_uri(),
        "https://errors.elasticdms.io/server-key-set-rollback"
    );
    // The state stays the same, word for word.
    assert_eq!(stage.set, before);
    assert_eq!(stage.set.key_set_version(), 7);
    // The same state is allowed; only a smaller one is not.
    let same = stage.forge.block(7).with_anchor(stage.anchor_entries()).builder().unwrap();
    assert!(stage.set.adopt(&offer(&same)).is_ok());
}

#[test]
fn without_a_stored_anchor_there_is_no_recovery_path_over_the_distribution_way() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let block = forge.block(7).with_anchor([forge.entry(&a).as_anchor()]).builder().unwrap();
    assert_eq!(KeySet::empty().adopt(&offer(&block)), Err(CryptoError::NoAnchor));
}

#[test]
fn an_answer_from_a_foreign_issuer_is_refused_as_a_whole() {
    let stage = Stage::new();
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_issuer("https://api.evil.example")
        .builder()
        .unwrap();
    assert_eq!(
        stage.set.adopt(&offer(&block)),
        Err(CryptoError::TenantMismatch {
            expected: "https://api.elasticdms.io".into(),
            read: "https://api.evil.example".into(),
        })
    );
}

#[test]
fn a_new_evidence_key_counts_as_soon_as_a_stored_anchor_vouches_for_it() {
    let stage = Stage::new();
    let new =
        signer("edms-kms-2027-01").with_key_set_version(8).with_supersedes("edms-kms-2026-09");
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_key([stage.forge.entry(&new).signed_by(&stage.b).unwrap()])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert!(adoption.report.is_empty(), "{:?}", adoption.report);
    // P9: the list grows, it never shrinks — the old key stays checkable.
    assert_eq!(adoption.set.signature_kids(), vec!["edms-kms-2026-09", "edms-kms-2027-01"]);
    assert_eq!(adoption.set.key_set_version(), 8);
}

#[test]
fn an_evidence_key_vouches_for_no_other_key() {
    // P3 and P5: only a stored anchor signs a key statement.
    let stage = Stage::new();
    let new = signer("edms-kms-2027-01");
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_key([stage.forge.entry(&new).signed_by(&stage.kms).unwrap()])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert_eq!(adoption.report, vec![CryptoError::UnknownKid { kid: "edms-kms-2026-09".into() }]);
    assert_eq!(adoption.set.signature_kids(), vec!["edms-kms-2026-09"]);
}

#[test]
fn a_signature_over_other_bytes_does_not_carry_this_entry() {
    // P2: there is no field selection; what is signed is JCS(entry without serverSignature).
    let stage = Stage::new();
    let new = signer("edms-kms-2027-01");
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_key([stage.forge.entry(&new).tampered().signed_by(&stage.a).unwrap()])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert!(
        matches!(adoption.report.as_slice(), [CryptoError::SignatureHoldsNot(_)]),
        "{:?}",
        adoption.report
    );
    assert_eq!(adoption.report_code(), vec![KeyReport::StatementInvalid]);
    assert_eq!(adoption.set.signature_kids(), vec!["edms-kms-2026-09"]);
}

#[test]
fn a_signature_from_another_context_does_not_count_here() {
    // P11: the media type is part of the check.
    let stage = Stage::new();
    let new = signer("edms-kms-2027-01");
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_key([stage.forge.entry(&new).with_typ(TYP_REVOCATION).signed_by(&stage.a).unwrap()])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert_eq!(
        adoption.report,
        vec![CryptoError::WrongTyp {
            expected: TYP_KEY_STATEMENT.into(),
            read: TYP_REVOCATION.into(),
        }]
    );
}

#[test]
fn an_answer_that_leaves_keys_out_removes_none() {
    // P9: nothing is removed; a shortened answer is no erasure command.
    let stage = Stage::new();
    let block = stage.forge.block(8).with_anchor(stage.anchor_entries()).builder().unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert!(adoption.report.is_empty(), "{:?}", adoption.report);
    assert_eq!(adoption.set.signature_kids(), vec!["edms-kms-2026-09"]);
    assert_eq!(adoption.set.anchors().len(), 2);
    assert_eq!(adoption.set.fingerprint(), stage.set.fingerprint());
}

#[test]
fn a_new_anchor_without_a_counter_signature_waits_and_has_no_effect() {
    // P10: the recovery path without an anchor would be the attack path.
    let stage = Stage::new();
    let c = anchor_key("edms-anchor-2027-c");
    let mut entries = stage.anchor_entries();
    entries.push(stage.forge.entry(&c).as_anchor());
    let block = stage.forge.block(8).with_anchor(entries).builder().unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert!(
        matches!(adoption.report.as_slice(), [CryptoError::AnchorPending { .. }]),
        "{:?}",
        adoption.report
    );
    assert_eq!(adoption.report_code(), vec![KeyReport::AnchorUnconfirmed]);
    assert_eq!(adoption.set.anchors().len(), 2);
    assert_eq!(adoption.set.pending_anchors().len(), 1);
    assert_eq!(adoption.set.pending_anchors()[0].kid(), "edms-anchor-2027-c");
    // The fingerprint stays: a waiting anchor is not part of the set.
    assert_eq!(adoption.set.fingerprint(), stage.set.fingerprint());
}

#[test]
fn a_new_anchor_counter_signed_by_a_stored_one_is_adopted() {
    let stage = Stage::new();
    let c = anchor_key("edms-anchor-2027-c");
    let mut entries = stage.anchor_entries();
    entries.push(stage.forge.entry(&c).signed_by(&stage.a).unwrap());
    let block = stage.forge.block(8).with_anchor(entries).builder().unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert!(adoption.report.is_empty(), "{:?}", adoption.report);
    assert_eq!(adoption.set.anchors().len(), 3);
    assert!(adoption.set.pending_anchors().is_empty());
    assert_ne!(adoption.set.fingerprint(), stage.set.fingerprint());
    assert!(adoption.set.carries());
}

#[test]
fn the_same_kid_with_another_key_is_a_swap_and_no_rotation_case() {
    let stage = Stage::new();
    let planted = anchor_key("edms-anchor-2026-a");
    let block = stage
        .forge
        .block(8)
        .with_anchor([
            stage.forge.entry(&planted).as_anchor(),
            stage.forge.entry(&stage.b).as_anchor(),
        ])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert!(
        matches!(adoption.report.as_slice(), [CryptoError::FingerprintChanged { .. }]),
        "{:?}",
        adoption.report
    );
    assert!(adoption.security_event());
    // The stored anchor stays as it is.
    assert_eq!(adoption.set.fingerprint(), stage.set.fingerprint());
}

// ───────────────────────────── Revocation ─────────────────────────────

#[test]
fn a_revocation_on_suspicion_voids_from_the_named_time_on_and_nothing_else() {
    let stage = Stage::new();
    let since = Timestamp::from_unix_millis(1_788_300_000_000);
    let revocation = stage
        .forge
        .revocation("edms-kms-2026-09", RevocationReason::KeyCompromised)
        .compromised_since(since)
        .signed_by(&stage.a)
        .unwrap();
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_revoked([revocation])
        .builder()
        .unwrap();
    let set = stage.set.adopt(&offer(&block)).unwrap().set;
    assert_eq!(set.revoke().len(), 1);
    assert_eq!(
        set.revocation_to("edms-kms-2026-09").map(Revocation::reason),
        Some(RevocationReason::KeyCompromised)
    );
    // Before it the signature still holds, after it no longer.
    let before = stage.command(since.plus_millis(-1));
    assert!(check_command_signature(&before, &set).is_ok());
    let after = stage.command(since);
    assert_eq!(
        check_command_signature(&after, &set),
        Err(CryptoError::Revoked { kid: "edms-kms-2026-09".into() })
    );
}

#[test]
fn a_planned_revocation_voids_no_signature_already_given() {
    let stage = Stage::new();
    let revocation = stage
        .forge
        .revocation("edms-kms-2026-09", RevocationReason::Superseded)
        .signed_by(&stage.b)
        .unwrap();
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_revoked([revocation])
        .builder()
        .unwrap();
    let set = stage.set.adopt(&offer(&block)).unwrap().set;
    assert!(check_command_signature(&stage.command(NOW), &set).is_ok());
    for reason in [RevocationReason::Superseded, RevocationReason::OutOfService] {
        assert!(!reason.retroactive(), "{reason:?}");
    }
    for reason in [
        RevocationReason::KeyCompromised,
        RevocationReason::AnchorCompromised,
        RevocationReason::Precautionary,
    ] {
        assert!(reason.retroactive(), "{reason:?}");
    }
}

#[test]
fn a_revocation_without_a_compromise_time_voids_everything_of_that_key() {
    let stage = Stage::new();
    let revocation = stage
        .forge
        .revocation("edms-kms-2026-09", RevocationReason::Precautionary)
        .signed_by(&stage.a)
        .unwrap();
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_revoked([revocation])
        .builder()
        .unwrap();
    let set = stage.set.adopt(&offer(&block)).unwrap().set;
    // “Everything” means: every point in time at which the key was allowed to sign at all — from
    // the first instant of its window to the last. Before and after that P12 already bites, and
    // the finding then reads `NotYetValid` or `Expired`; that too is a no.
    for timestamp in
        [crate::forge::DEFAULT_NOT_BEFORE, NOW, crate::forge::DEFAULT_NOT_AFTER.plus_millis(-1)]
    {
        assert_eq!(
            check_command_signature(&stage.command(timestamp), &set),
            Err(CryptoError::Revoked { kid: "edms-kms-2026-09".into() }),
            "{timestamp:?}"
        );
    }
}

#[test]
fn an_anchor_does_not_revoke_itself() {
    let stage = Stage::new();
    let revocation = stage
        .forge
        .revocation("edms-anchor-2026-a", RevocationReason::AnchorCompromised)
        .with_role("trust-anchor")
        .signed_by(&stage.a)
        .unwrap();
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_revoked([revocation])
        .builder()
        .unwrap();
    let adoption = stage.set.adopt(&offer(&block)).unwrap();
    assert_eq!(adoption.report, vec![CryptoError::SelfSigned { kid: "edms-anchor-2026-a".into() }]);
    assert!(adoption.set.revoke().is_empty());
    assert!(adoption.set.carries());
}

#[test]
fn when_every_anchor_is_revoked_no_signature_holds_any_more() {
    let stage = Stage::new();
    // Every anchor is revoked by the other one — the only way online (geraete-auth §5.1).
    let revocation_a = stage
        .forge
        .revocation("edms-anchor-2026-a", RevocationReason::AnchorCompromised)
        .with_role("trust-anchor")
        .signed_by(&stage.b)
        .unwrap();
    let revocation_b = stage
        .forge
        .revocation("edms-anchor-2026-b", RevocationReason::AnchorCompromised)
        .with_role("trust-anchor")
        .signed_by(&stage.a)
        .unwrap();
    let block = stage
        .forge
        .block(8)
        .with_anchor(stage.anchor_entries())
        .with_revoked([revocation_a, revocation_b])
        .builder()
        .unwrap();
    let set = stage.set.adopt(&offer(&block)).unwrap().set;
    assert_eq!(set.anchor_state(), AnchorState::Revoked);
    assert!(!set.carries());
    assert_eq!(
        check_command_signature(&stage.command(NOW), &set),
        Err(CryptoError::NotAnchored { state: AnchorState::Revoked })
    );
    // There is no way back online.
    assert_eq!(set.confirm(), Err(CryptoError::NotAnchored { state: AnchorState::Revoked }));
}

// ───────────────────────────── Checking a carrier ─────────────────────────────

#[test]
fn a_signed_delivery_command_is_accepted_and_names_its_signer() {
    let stage = Stage::new();
    let command = stage.command(NOW);
    assert_eq!(
        stage.set.check_carrier(&command, TYP_DELIVERY_COMMAND, NOW).unwrap(),
        "edms-kms-2026-09"
    );
    assert_eq!(check_command_signature(&command, &stage.set), Ok(()));
}

#[test]
fn without_a_confirmed_anchor_no_command_is_executed() {
    // geraete-auth §5.8: no confirmed anchor ⇒ no signature holds ⇒ nothing is erased.
    let stage = Stage::new();
    let forge = &stage.forge;
    let block = forge
        .block(7)
        .with_anchor(stage.anchor_entries())
        .with_key([forge.entry(&stage.kms).signed_by(&stage.a).unwrap()])
        .builder()
        .unwrap();
    let unconfirmed = KeySet::empty().anchor(&offer(&block), None).unwrap().set;
    let error = check_command_signature(&stage.command(NOW), &unconfirmed).unwrap_err();
    assert_eq!(error, CryptoError::NotAnchored { state: AnchorState::AwaitingConfirmation });
    assert_eq!(error.report(), Some(KeyReport::AnchorUnconfirmed));
    assert_eq!(
        check_command_signature(&stage.command(NOW), &KeySet::empty()),
        Err(CryptoError::NotAnchored { state: AnchorState::NoAnchor })
    );
}

#[test]
fn an_anchor_signs_no_delivery_command() {
    // P6: the roles are never in one key (geraete-auth §5.1).
    let stage = Stage::new();
    let command = stage.command_of(&stage.a, NOW);
    assert_eq!(
        check_command_signature(&command, &stage.set),
        Err(CryptoError::RoleMismatch {
            kid: "edms-anchor-2026-a".into(),
            expected: "evidence-signing",
            read: "trust-anchor".into(),
        })
    );
}

#[test]
fn an_unknown_kid_is_the_occasion_to_reconcile_and_not_to_execute() {
    let stage = Stage::new();
    let foreign = signer("edms-kms-2027-01");
    let command = stage.command_of(&foreign, NOW);
    let error = check_command_signature(&command, &stage.set).unwrap_err();
    assert_eq!(error, CryptoError::UnknownKid { kid: "edms-kms-2027-01".into() });
    assert_eq!(error.report(), Some(KeyReport::UnknownKid));
    assert!(!KeyReport::UnknownKid.security_event());
}

#[test]
fn a_signing_time_outside_the_window_does_not_carry() {
    // P12: `[notBefore, notAfter)`.
    let stage = Stage::with_window(START_2026, START_2027);
    assert!(check_command_signature(&stage.command(START_2026), &stage.set).is_ok());
    assert!(
        check_command_signature(&stage.command(START_2027.plus_millis(-1)), &stage.set).is_ok()
    );
    assert_eq!(
        check_command_signature(&stage.command(START_2026.plus_millis(-1)), &stage.set),
        Err(CryptoError::NotYetValid {
            kid: "edms-kms-2026-09".into(),
            timestamp: START_2026.plus_millis(-1),
            deadline: START_2026,
        })
    );
    assert_eq!(
        check_command_signature(&stage.command(START_2027), &stage.set),
        Err(CryptoError::Expired {
            kid: "edms-kms-2026-09".into(),
            timestamp: START_2027,
            until: START_2027,
        })
    );
}

#[test]
fn a_command_without_a_readable_signing_time_does_not_count() {
    let stage = Stage::new();
    let without = stage
        .forge
        .command("job_1", "dehydrate")
        .without_timestamp()
        .signed_by(&stage.kms)
        .unwrap();
    assert_eq!(
        check_command_signature(&without, &stage.set),
        Err(CryptoError::SignatureTimeMissing { field: FIELD_COMMAND_TIME })
    );
    let unreadable = stage
        .forge
        .command("job_1", "dehydrate")
        .without_timestamp()
        .with_field(FIELD_COMMAND_TIME, Value::from("yesterday"))
        .signed_by(&stage.kms)
        .unwrap();
    assert_eq!(
        check_command_signature(&unreadable, &stage.set),
        Err(CryptoError::SignatureTimeMissing { field: FIELD_COMMAND_TIME })
    );
}

#[test]
fn a_command_from_another_context_does_not_count() {
    let stage = Stage::new();
    let command = stage
        .forge
        .command("job_1", "dehydrate")
        .from_posed(NOW)
        .with_typ("edms-release-grant+jwt")
        .signed_by(&stage.kms)
        .unwrap();
    assert_eq!(
        check_command_signature(&command, &stage.set),
        Err(CryptoError::WrongTyp {
            expected: TYP_DELIVERY_COMMAND.into(),
            read: "edms-release-grant+jwt".into(),
        })
    );
}

#[test]
fn a_changed_command_no_longer_carries_the_signature() {
    let stage = Stage::new();
    let mut command = stage.command(NOW);
    command["payload"]["documentIds"] =
        json!(["doc_01JB8Z5K3M4N6P7Q8R9S0T1V2X", "doc_01JB8Z5K3M4N6P7Q8R9S0T1U2X"]);
    assert!(matches!(
        check_command_signature(&command, &stage.set),
        Err(CryptoError::SignatureHoldsNot(_))
    ));
    let mut without = stage.command(NOW);
    without.as_object_mut().unwrap().remove(jws::FIELD_SIGNATURE);
    assert_eq!(check_command_signature(&without, &stage.set), Err(CryptoError::SignatureMissing));
}

// ───────────────────────────── Store and contract values ─────────────────────────────

#[test]
fn the_store_survives_the_round_trip_together_with_the_raw_entries() {
    let stage = Stage::new();
    let revocation = stage
        .forge
        .revocation("edms-kms-2026-09", RevocationReason::Superseded)
        .signed_by(&stage.b)
        .unwrap();
    let c = anchor_key("edms-anchor-2027-c");
    let mut entries = stage.anchor_entries();
    entries.push(stage.forge.entry(&c).as_anchor());
    let block =
        stage.forge.block(8).with_anchor(entries).with_revoked([revocation]).builder().unwrap();
    let set = stage.set.adopt(&offer(&block)).unwrap().set;
    let back = KeySet::from_storage(&set.as_storage()).unwrap();
    assert_eq!(back, set);
    // And the signatures still hold after the round trip — the raw bytes are preserved.
    assert!(check_command_signature(&stage.command(NOW), &back).is_ok());
    // Through serde as well.
    let json = serde_json::to_value(&set).unwrap();
    assert_eq!(serde_json::from_value::<KeySet>(json).unwrap(), set);
    // The empty set too.
    let empty = KeySet::empty();
    assert_eq!(KeySet::from_storage(&empty.as_storage()).unwrap(), empty);
}

#[test]
fn a_damaged_store_is_noticed_instead_of_yielding_a_smaller_set() {
    let stage = Stage::new();
    let mut storage = stage.set.as_storage();
    storage["version"] = json!(99);
    assert!(matches!(KeySet::from_storage(&storage), Err(CryptoError::Unreadable { .. })));
    let mut without_anchor = stage.set.as_storage();
    without_anchor.as_object_mut().unwrap().remove("trustAnchors");
    assert!(KeySet::from_storage(&without_anchor).is_err());
    let mut broken_entry = stage.set.as_storage();
    broken_entry["signingKeys"][0]["notAfter"] = json!("sometime");
    assert!(KeySet::from_storage(&broken_entry).is_err());
    let mut unknown_state = stage.set.as_storage();
    unknown_state["anchorState"] = json!("halfway");
    assert!(KeySet::from_storage(&unknown_state).is_err());
    assert!(KeySet::from_storage(&json!([])).is_err());
}

#[test]
fn the_contract_values_go_in_both_directions() {
    for role in [KeyRole::TrustAnchor, KeyRole::ProofSignature] {
        assert_eq!(KeyRole::from_contract_value(role.contract_value()), Some(role));
    }
    assert_eq!(KeyRole::from_contract_value("token-signing"), None);
    for state in [
        AnchorState::NoAnchor,
        AnchorState::AwaitingConfirmation,
        AnchorState::Confirmed,
        AnchorState::Revoked,
    ] {
        assert_eq!(AnchorState::from_contract_value(state.contract_value()), Some(state));
        assert_eq!(state.to_string(), state.contract_value());
    }
    assert_eq!(AnchorState::from_contract_value("halfway"), None);
    assert_eq!(AnchorState::default(), AnchorState::NoAnchor);
    for reason in [
        RevocationReason::KeyCompromised,
        RevocationReason::AnchorCompromised,
        RevocationReason::Precautionary,
        RevocationReason::Superseded,
        RevocationReason::OutOfService,
    ] {
        assert_eq!(RevocationReason::from_contract_value(reason.contract_value()), Some(reason));
    }
    assert_eq!(RevocationReason::from_contract_value("boredom"), None);
}

#[test]
fn every_finding_carries_the_type_uri_of_the_server_errors() {
    assert_eq!(
        KeyReport::AnchorMissing.type_uri(),
        "https://errors.elasticdms.io/server-trust-anchor-missing"
    );
    assert_eq!(KeyReport::Revoked.short_code(), "server-key-revoked");
    // The security events are exactly the four from 03 §6.2.4.
    let events: Vec<&str> = [
        KeyReport::AnchorMissing,
        KeyReport::AnchorUnconfirmed,
        KeyReport::FingerprintChanged,
        KeyReport::StatementInvalid,
        KeyReport::SelfSigned,
        KeyReport::RoleMismatch,
        KeyReport::TenantMismatch,
        KeyReport::StateReset,
        KeyReport::UnknownKid,
        KeyReport::Expired,
        KeyReport::NotYetValid,
        KeyReport::Revoked,
    ]
    .into_iter()
    .filter(|b| b.security_event())
    .map(KeyReport::short_code)
    .collect();
    assert_eq!(
        events,
        vec![
            "server-trust-anchor-fingerprint-changed",
            "server-key-self-signed",
            "server-key-tenant-mismatch",
            "server-key-set-rollback",
        ]
    );
}

#[test]
fn unreadable_entries_are_counted_and_not_passed_over_in_silence() {
    let forge = Forge::new();
    let a = anchor_key("edms-anchor-2026-a");
    let block = forge
        .block(1)
        .with_anchor([forge.entry(&a).as_anchor(), json!({"kid": "half"})])
        .without_fingerprint()
        .builder()
        .unwrap();
    let read = offer(&block);
    assert_eq!(read.anchors().len(), 1);
    assert_eq!(read.unreadable_entries().len(), 1);
    assert!(matches!(read.unreadable_entries()[0], CryptoError::Unreadable { .. }));
}
