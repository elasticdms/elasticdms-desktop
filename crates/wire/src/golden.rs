//! The golden files — the truth of the contract, as a table.
//!
//! „Spiegeln heisst: dieselben Ruempfe als Golden Files in `testdata/`, nicht als Code."
//! (geraete-auth §9.1) — mirroring means the same bodies as golden files in `testdata/`, not as
//! code. Every file here is read into its type by this crate's tests and written again; every
//! file from a proposal stands byte-identical in the contract document. The mock sends the same
//! bytes, `edms-net` checks against the same bytes — three places, one source.

/// Where a body comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Proposed in `docs/spec/03-api-contract-folder-client.md`, in the section given.
    /// Stands there byte-identical behind `<!-- golden: … -->`.
    Proposal(&'static str),
    /// From the escan contract or its fixtures, with the place it is found.
    Counterpart(&'static str),
}

/// One golden file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoldenFile {
    /// File name in `testdata/`.
    pub name: &'static str,
    /// Content as it stands on the wire.
    pub content: &'static str,
    /// Provenance.
    pub provenance: Provenance,
}

/// The name is not in the table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("there is no golden file `{0}` in crates/wire/testdata/")]
pub struct UnknownGoldenFile(pub String);

macro_rules! file {
    ($name:literal, $provenance:expr) => {
        GoldenFile {
            name: $name,
            content: include_str!(concat!("../testdata/", $name)),
            provenance: $provenance,
        }
    };
}

use Provenance::{Counterpart, Proposal};

/// All golden files.
pub const ALL: &[GoldenFile] = &[
    // ── Proposal §7.0 ──
    file!("enrollment_request_desktop.json", Proposal("§7.0")),
    file!("device_desktop.json", Proposal("§7.0")),
    file!("device_authorization_desktop.json", Proposal("§7.0")),
    file!("token_user_desktop.json", Proposal("§7.0")),
    file!("token_device_desktop.json", Proposal("§7.0")),
    file!("oauth_session_expired.json", Proposal("§7.0")),
    file!("oauth_refresh_reused.json", Proposal("§7.0")),
    file!("heartbeat_desktop.json", Proposal("§7.0")),
    file!("heartbeat_response_desktop.json", Proposal("§7.0")),
    // ── Proposal §7.1 ──
    file!("baskets_page.json", Proposal("§7.1")),
    file!("archives_page.json", Proposal("§7.1")),
    file!("cases_page.json", Proposal("§7.1")),
    file!("searches_page.json", Proposal("§7.1")),
    file!("case_documents_page.json", Proposal("§7.1")),
    file!("search_documents_truncated.json", Proposal("§7.1")),
    file!("problem_cursor_invalid.json", Proposal("§7.1")),
    file!("problem_search_not_executable.json", Proposal("§7.1")),
    // ── Proposal §7.2 ──
    file!("problem_rendition_missing.json", Proposal("§7.2")),
    file!("problem_access_log_missing.json", Proposal("§7.2")),
    // ── Proposal §7.3 ──
    file!("delivery_commands.json", Proposal("§7.3")),
    file!("delivery_empty.json", Proposal("§7.3")),
    file!("acknowledgement_rejected.json", Proposal("§7.3")),
    file!("acknowledgement_receipt.json", Proposal("§7.3")),
    file!("problem_command_already_acknowledged.json", Proposal("§7.3")),
    // ── Proposal §7.4 ──
    file!("ingest_request.json", Proposal("§7.4")),
    file!("ingest_grant.json", Proposal("§7.4")),
    file!("ingest_grant_duplicate.json", Proposal("§7.4")),
    file!("ingest_completed.json", Proposal("§7.4")),
    file!("problem_upload_digest.json", Proposal("§7.4")),
    file!("problem_basket_unknown.json", Proposal("§7.4")),
    // ── Counterpart: discovery and device ──
    file!("authorization_server_metadata.json", Counterpart("geraete-auth §3.0")),
    file!("resource_metadata.json", Counterpart("geraete-auth §3.0")),
    // 03 §6.2.1 shows `dev_…T1U2V` (a `U`) and `usr_01JADMIN…` (24 characters, an `I`); neither
    // passes its own rule from 03 §6.0.3. Canonicalized here, see §7.0.2.
    file!("device_kiosk.json", Counterpart("03 §6.2.1, identifiers canonicalized (§7.0.2)")),
    file!("server_key_set.json", Counterpart("03 §6.2.4")),
    file!("heartbeat_response_kiosk.json", Counterpart("03 §6.4.1")),
    // ── Counterpart: sign-in ──
    file!("device_authorization_kiosk.json", Counterpart("03 §6.3.1")),
    file!("token_user_kiosk.json", Counterpart("03 §6.3.1")),
    file!("token_device_kiosk.json", Counterpart("03 §6.2.2")),
    file!("oauth_authorization_pending.json", Counterpart("03 §6.3.1")),
    file!("oauth_slow_down.json", Counterpart("03 §6.3.1")),
    file!("oauth_code_expired.json", Counterpart("03 §6.3.1")),
    file!("oauth_access_denied.json", Counterpart("03 §6.3.1")),
    file!("oauth_nonce_required.json", Counterpart("geraete-auth §2.4")),
    file!("oauth_device_code_expired.json", Counterpart("geraete-auth §2.3")),
    // ── Counterpart: problems ──
    file!("problem_dpop_nonce_required.json", Counterpart("03 §6.0.5")),
    file!("problem_token_device_binding.json", Counterpart("03 §6.0.6")),
    file!("problem_device_locked.json", Counterpart("03 §6.2.3")),
    file!("problem_server_key_not_anchored.json", Counterpart("03 §6.2.4")),
    file!("problem_step_up.json", Counterpart("03 §6.3.5")),
    file!(
        "problem_device_already_exists.json",
        Counterpart("escan EnrollmentTest, Problemfaelle.problem")
    ),
    file!("problem_rate_limited.json", Counterpart("escan Problemfaelle.rateLimited")),
    file!(
        "problem_idempotency_in_progress.json",
        Counterpart("escan Problemfaelle.idempotenzInArbeit")
    ),
    file!("problem_client_too_old.json", Counterpart("escan Problemfaelle.clientZuAlt")),
];

/// Looks up a golden file.
pub fn find(name: &str) -> Result<&'static GoldenFile, UnknownGoldenFile> {
    ALL.iter().find(|g| g.name == name).ok_or_else(|| UnknownGoldenFile(name.to_owned()))
}

/// The content of a golden file — for tests and for the mock.
///
/// # Panics
///
/// On an unknown name, naming all the ones that exist. A typo in the name is a program fault in
/// the calling test, not a state for which a plausible body would exist; whoever wants to handle
/// the case takes [`find`].
pub fn golden(name: &str) -> &'static str {
    match find(name) {
        Ok(g) => g.content,
        Err(error) => {
            let present: Vec<&str> = ALL.iter().map(|g| g.name).collect();
            panic!("{error}; present: {}", present.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_stands_exactly_once_in_the_table() {
        let mut seen = std::collections::HashSet::new();
        for g in ALL {
            assert!(seen.insert(g.name), "{} twice", g.name);
            assert!(g.content.ends_with('\n'), "{} does not end with a line break", g.name);
        }
    }

    #[test]
    fn an_unknown_name_is_an_error_that_names_it() {
        assert_eq!(
            find("does_not_exist.json"),
            Err(UnknownGoldenFile("does_not_exist.json".into()))
        );
        let error = std::panic::catch_unwind(|| golden("does_not_exist.json")).unwrap_err();
        let text = error.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(text.contains("does_not_exist.json") && text.contains("cases_page.json"), "{text}");
    }
}
