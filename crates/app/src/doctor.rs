//! `elasticdms doctor` — what stands on this workstation, **without the network**.
//!
//! A diagnostic tool that first has to ask the server is useless at exactly the moment it is
//! needed: the phone call comes because nothing works. Everything here is local — configuration,
//! keychain, the anchored key set together with a fingerprint computed here, the key facts of the
//! session, outstanding acknowledgements, leftovers, whether the database is readable. The report
//! itself comes from [`edms_engine::Engine::report`]; only how it looks on screen, and when it is
//! a **report with objections**, stands here.
//!
//! ## The exit code
//!
//! `0` when there is nothing to object to; `1` otherwise — so that a script
//! (`elasticdms doctor || tell_it`) can evaluate the answer without reading text. Every objection
//! is a whole sentence and says what to do.
//!
//! ## Why stdout
//!
//! Unlike the app, `doctor` writes a **result**, and results belong on stdout — a person copies
//! them into an email to IT. The house rule "libraries do not write to the console" applies to the
//! library, not to this subcommand (as with `edms-mock`).

#![allow(clippy::print_stdout, reason = "doctor writes a result, not a log")]

use std::process::ExitCode;

use edms_engine::report::{DatabaseReport, Report};
use edms_engine::{EngineConfiguration, StoreSpace};

use crate::vault::SystemVault;
use crate::wiring::build_engine;

/// Below this much free space the folder becomes unreliable: a hydration first loads completely
/// into the staging area before a single byte reaches the platform (`edms_core::port`).
///
/// 500 MiB is the point at which a large PDF no longer reliably gets through — early enough that
/// somebody can still tidy up.
pub const SPACE_MIN: u64 = 500 * 1024 * 1024;

/// Runs `elasticdms doctor`.
pub fn run() -> ExitCode {
    match gather() {
        Ok(objections) if objections.is_empty() => {
            println!("\nNothing to object to.");
            ExitCode::SUCCESS
        }
        Ok(objections) => {
            println!("\nTo object to ({}):", objections.len());
            for sentence in &objections {
                println!("  • {sentence}");
            }
            ExitCode::FAILURE
        }
        Err(sentence) => {
            println!("{sentence}");
            ExitCode::FAILURE
        }
    }
}

/// Writes the report and returns the objections.
///
/// # Errors
///
/// The sentence that says why there was not even a report — a missing mandatory variable, say.
/// That too is an answer, and precisely the one `doctor` should give.
fn gather() -> Result<Vec<String>, String> {
    println!("elasticdms {} — diagnosis (without the network)", env!("CARGO_PKG_VERSION"));

    let configuration = crate::setup::configuration().map_err(|error| {
        format!("\nThe setup does not stand:\n  • {error}\n\nWithout it there are no findings.")
    })?;
    println!("\n{}", section("Setup"));
    for (feature, value) in setup_row(&configuration) {
        println!("  {feature:<22} {value}");
    }

    let mut objections = Vec::new();
    println!("\n{}", section("Keychain"));
    match SystemVault::new().check() {
        Ok(()) => println!("  {:<22} reachable", "State"),
        Err(error) => {
            println!("  {:<22} NOT reachable: {error}", "State");
            objections.push(format!(
                "The keychain cannot be reached; without it this workstation keeps neither the \
                 device key nor the session. {error}"
            ));
        }
    }

    let engine = build_engine(configuration)
        .map_err(|error| format!("\nThe folder client cannot be built:\n  - {error}"))?;
    let report = engine
        .report()
        .map_err(|error| format!("\nThe findings could not be gathered:\n  - {error}"));
    // Stop first, then evaluate: the engine holds a runtime, and it should not be running while
    // this prints.
    engine.stop();
    let report = report?;

    println!("\n{}", section("Findings"));
    for (feature, value) in report.rows() {
        println!("  {feature:<22} {value}");
    }
    objections.extend(objections_in(&report));
    Ok(objections)
}

/// The setup in rows — without a single secret.
fn setup_row(k: &EngineConfiguration) -> Vec<(String, String)> {
    let path = |p: &std::path::Path| {
        let da = if p.exists() { "" } else { "  (does not exist yet)" };
        format!("{}{da}", p.display())
    };
    vec![
        ("API".to_owned(), k.api_base.clone()),
        ("Sign-in".to_owned(), k.auth_base.clone()),
        ("Web interface".to_owned(), k.app_base.clone()),
        ("Device name".to_owned(), k.device_name.clone()),
        (
            "Enrolment code".to_owned(),
            // The code is a secret with an expiry: only **whether** there is one stands here.
            if k.enrollment_code.is_some() { "present".to_owned() } else { "—".to_owned() },
        ),
        ("Local state".to_owned(), path(&k.data_path)),
        ("Staging area".to_owned(), path(&k.staging)),
        ("Folder".to_owned(), path(&k.mirror_path)),
        ("Holding directory".to_owned(), path(&k.holding)),
    ]
}

/// What is wrong with this report. Empty means: nothing.
fn objections_in(report: &Report) -> Vec<String> {
    let mut sentences = Vec::new();
    if let DatabaseReport::NotReadable(reason) = &report.database {
        sentences.push(format!(
            "The local state cannot be read completely ({reason}). Report this to your IT \
             department; the file can be created afresh, and the folder then builds up again."
        ));
    }
    // An anchor without a key set that carries means: **nothing** is removed on order
    // (03 §6.2.4, "when in doubt, preserve"). That is safe, but somebody has to know.
    if report.key.anchored && !report.key.carries {
        sentences.push(
            "The anchored server key set no longer carries (no valid anchor, or it is not \
             confirmed). Erasure orders are not carried out until that is cleared up - please \
             tell your IT department."
                .to_owned(),
        );
    }
    if report.unacknowledged_command > 0 {
        let since = report
            .oldest_unacknowledged
            .map_or_else(|| "unknown".to_owned(), edms_core::time::Timestamp::rfc3339);
        sentences.push(format!(
            "{} delivery commands that were carried out are not acknowledged yet (oldest \
             arrival: {since}). The server holds them for open and delivers them again.",
            report.unacknowledged_command
        ));
    }
    if let StoreSpace::Bytes(free) = report.free_store
        && free < SPACE_MIN
    {
        sentences.push(format!(
            "Only {free} bytes are free on the disk. Content is loaded and checked completely \
             before it appears in the folder; below that, opening a large file fails."
        ));
    }
    sentences
}

/// A section heading.
fn section(title: &str) -> String {
    format!("{title}\n{}", "─".repeat(title.chars().count()))
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::DeviceIdentifier;
    use edms_crypto::key_set::AnchorState;
    use edms_engine::DeviceKeyOrigin;
    use edms_engine::report::{KeyReport, LeftoversReport, SessionReport, VIEW_SESSION};

    use super::*;

    fn healthy_report() -> Report {
        Report {
            device: DeviceIdentifier::from_value(1),
            device_key: DeviceKeyOrigin::Keychain,
            key: KeyReport {
                anchored: true,
                carries: true,
                anchor_state: AnchorState::Confirmed,
                fingerprint: "K7M4-2TQX".to_owned(),
                state: 7,
                anchor: 1,
                evidence_key: 2,
            },
            session: SessionReport {
                state: None,
                account: None,
                tenant: None,
                display_name: None,
                since: None,
                identity_guessed: false,
                token_in_store: false,
                token_expires: None,
            },
            unacknowledged_command: 0,
            oldest_unacknowledged: None,
            leftovers: LeftoversReport::default(),
            database: DatabaseReport::Readable,
            free_store: StoreSpace::Bytes(SPACE_MIN * 2),
            current_sequence: 0,
            oldest_sequence: 0,
            baskets: 0,
            archives: 0,
            cases: 0,
            searches: 0,
        }
    }

    #[test]
    fn a_healthy_report_has_nothing_to_object_to() {
        assert!(objections_in(&healthy_report()).is_empty());
    }

    #[test]
    fn an_unreadable_database_is_an_objection_and_names_the_view_in_english() {
        // The fixture is built from the very constant `edms_engine` prints, and the assertion
        // then names the whole expected text. Until 2026-09-13 the label read `Sitzung` in the
        // engine while this fixture said `session`, so the test was green either way and read as
        // proof of an English line that was German (ADR-D10, correction of 2026-09-13). Written
        // this way round it goes off the moment the constant stops being the English word.
        let mut report = healthy_report();
        report.database = DatabaseReport::NotReadable(format!("{VIEW_SESSION}: locked"));
        let sentences = objections_in(&report);
        assert_eq!(sentences.len(), 1);
        assert!(sentences[0].contains("(session: locked)"), "{}", sentences[0]);
    }

    #[test]
    fn an_anchor_that_no_longer_carries_is_objected_to_because_then_nothing_is_erased() {
        let mut report = healthy_report();
        report.key.carries = false;
        let sentences = objections_in(&report);
        assert_eq!(sentences.len(), 1);
        assert!(sentences[0].contains("Erasure orders"), "{}", sentences[0]);
    }

    #[test]
    fn without_an_anchor_there_is_no_objection_because_then_nothing_is_set_up() {
        // A freshly installed workstation has no anchor yet; that is not a defect but the
        // beginning.
        let mut report = healthy_report();
        report.key.anchored = false;
        report.key.carries = false;
        assert!(objections_in(&report).is_empty());
    }

    #[test]
    fn outstanding_acknowledgements_and_little_space_are_both_named() {
        let mut report = healthy_report();
        report.unacknowledged_command = 3;
        report.free_store = StoreSpace::Bytes(1024);
        let sentences = objections_in(&report);
        assert_eq!(sentences.len(), 2, "{sentences:?}");
        assert!(sentences.iter().any(|s| s.contains("acknowledged")), "{sentences:?}");
        assert!(sentences.iter().any(|s| s.contains("free")), "{sentences:?}");
    }

    #[test]
    fn unmeasured_space_is_not_an_objection() {
        // "Not determined" is a statement about the app, not about the volume; turning it into a
        // warning would mean inventing a number.
        let mut report = healthy_report();
        report.free_store = StoreSpace::NotDetermined("no space measurer");
        assert!(objections_in(&report).is_empty());
    }

    #[test]
    fn the_enrollment_code_never_stands_in_the_clear_in_the_report() {
        let k = EngineConfiguration::builder(std::path::Path::new("/tmp/probe"))
            .with_enrollment_code(Some("K7QM-4T2X"))
            .finished();
        let text = setup_row(&k)
            .into_iter()
            .map(|(m, w)| format!("{m} {w}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains("K7QM-4T2X"), "{text}");
        assert!(text.contains("present"), "{text}");
    }

    #[test]
    fn the_report_says_where_the_device_key_lies_in_a_row_of_its_own() {
        // ADR-D12 §3, the first of the two places that keep the fallback from being silent. The
        // store's own sentence goes through unshortened: it is what somebody pastes into a ticket.
        for (origin, expected) in [
            (DeviceKeyOrigin::Keychain, "copyable"),
            (DeviceKeyOrigin::KeychainAfterRefusal("TBS_E_TPM_NOT_FOUND".to_owned()), "TBS_E_TPM"),
            (DeviceKeyOrigin::KeychainFromEnrollment("tpm"), "re-enrolment"),
            (DeviceKeyOrigin::Hardware("secure-enclave"), "secure-enclave"),
        ] {
            let mut report = healthy_report();
            report.device_key = origin;
            let rows = report.rows();
            let (_, value) =
                rows.iter().find(|(feature, _)| feature == "Device key").expect("a row of its own");
            assert!(value.contains(expected), "{value}");
        }
    }

    #[test]
    fn a_software_device_key_is_no_objection_because_nobody_at_the_machine_can_act_on_it() {
        // It would turn `doctor` red on every Mac today (no permanent Secure Enclave key can be
        // made from this build at all) and on every workstation without a TPM — for a state the
        // person reading the report cannot change. The row says it; the exit code does not.
        let mut report = healthy_report();
        report.device_key = DeviceKeyOrigin::KeychainAfterRefusal("no TPM".to_owned());
        assert!(objections_in(&report).is_empty());
    }
}
