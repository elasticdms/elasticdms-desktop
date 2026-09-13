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

use edms_engine::StoreSpace;
use edms_engine::config::{Origin, Value};
use edms_engine::report::{DatabaseReport, Report};

use crate::setup::{Counterpart, Resolution};
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

    // The same resolution the app starts from, and it is read **before** it is judged: what the
    // rows show is what this workstation really has, even when one value is missing — the sentence
    // underneath then says which one. A report that printed nothing because one line is missing
    // would be the report nobody can act on.
    let resolution = crate::setup::resolve();
    println!("\n{}", section("Setup"));
    for (feature, value, source) in setup_row(&resolution) {
        println!("  {feature:<22} {value:<44} {source}");
    }

    let configuration = resolution.configuration().map_err(|error| {
        format!("\nThe setup does not stand:\n  • {error}\n\nWithout it there are no findings.")
    })?;

    let mut objections = Vec::new();
    // Not a defect, and it still belongs in the answer: the next start will act on it, and whoever
    // reads this report should know before the folder empties itself.
    if let Counterpart::Changed(old) = resolution.counterpart() {
        objections.push(format!(
            "This device is enrolled against `{}` and is configured for `{}` now. At the next \
             start the client signs out from the old server, clears the folder and asks to be set \
             up afresh (ADR-D13 §4).",
            old.api_base, configuration.api_base
        ));
    }
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

/// What each value is called in the report. English, out of the catalogue's reach: this is the
/// line somebody pastes into a ticket (ADR-D10).
const fn feature(which: Value) -> &'static str {
    match which {
        Value::ApiBase => "API",
        Value::AuthBase => "Sign-in",
        Value::AppBase => "Web interface",
        Value::DeviceName => "Device name",
        Value::Language => "Language",
        Value::DataPath => "Local state",
        Value::Staging => "Staging area",
        Value::MirrorPath => "Folder",
        Value::Holding => "Holding directory",
    }
}

/// The setup in rows — value, and where the value came from. Without a single secret.
///
/// The third column is what ADR-D13 §3 asks for: the set-up tells the **user** only that their IT
/// department has set a value, and names no variable; the variable belongs here, where the support
/// call looks. One place to look, and the user's window is not it.
fn setup_row(resolution: &Resolution) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for which in Value::ALL {
        let (value, source) = match resolution.of(which) {
            None => ("—".to_owned(), format!("not set ({})", which.variable())),
            Some(found) => {
                let mut value = found.text().to_owned();
                if is_path(which) && !std::path::Path::new(found.text()).exists() {
                    value.push_str("  (does not exist yet)");
                }
                let source = match found.origin() {
                    Origin::Environment => {
                        format!("{} ({})", found.origin().label(), which.variable())
                    }
                    Origin::Setting => match which.setting_key() {
                        Some(key) => format!("{} ({key})", found.origin().label()),
                        None => found.origin().label().to_owned(),
                    },
                    Origin::Default => found.origin().label().to_owned(),
                };
                (value, source)
            }
        };
        rows.push((feature(which).to_owned(), value, source));
    }
    rows.push((
        "Enrolment code".to_owned(),
        // The code is a secret with an expiry: only **whether** there is one stands here. It is
        // not a `Value` at all, so no loop over the values can print it by accident.
        if resolution.has_enrollment_code() { "present".to_owned() } else { "—".to_owned() },
        if resolution.has_enrollment_code() {
            "environment (EDMS_ENROLLMENT_CODE)".to_owned()
        } else {
            String::new()
        },
    ));
    rows.push((
        "Set-up".to_owned(),
        if resolution.completed() { "completed".to_owned() } else { "not completed".to_owned() },
        "setting (setup.completed)".to_owned(),
    ));
    rows.push(counterpart_row(resolution));
    rows
}

/// Which of the values is a path, and therefore gets the note that it is not there yet.
const fn is_path(which: Value) -> bool {
    matches!(which, Value::DataPath | Value::Staging | Value::MirrorPath | Value::Holding)
}

/// Which server this device is enrolled against — the row that makes ADR-D13 §4 readable.
fn counterpart_row(resolution: &Resolution) -> (String, String, String) {
    let (value, source) = match resolution.counterpart() {
        Counterpart::NotEnrolled => ("— (not enrolled)".to_owned(), String::new()),
        Counterpart::Enrolled { sealed: true } => {
            ("the API above".to_owned(), "setting (counterpart.api-base)".to_owned())
        }
        // Enrolled before the seal existed: nobody can reconstruct where. It writes the keys at
        // this start, and the comparison holds from the next one (ADR-D13 §4).
        Counterpart::Enrolled { sealed: false } => {
            ("unknown (enrolled before this was remembered)".to_owned(), String::new())
        }
        Counterpart::Changed(old) => (
            old.api_base.clone(),
            "setting (counterpart.api-base) — DIFFERS from the API above".to_owned(),
        ),
    };
    ("Enrolled against".to_owned(), value, source)
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

    /// A resolution over two maps, the way `doctor` will meet one.
    fn resolution(environment: &[(&str, &str)], settings: &[(&str, &str)]) -> Resolution {
        let environment: std::collections::HashMap<String, String> =
            environment.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        let settings: std::collections::HashMap<String, String> =
            settings.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        crate::setup::read(
            &|name| environment.get(name).cloned(),
            &|key| settings.get(key).cloned(),
            edms_i18n::Language::De,
        )
    }

    fn as_text(rows: &[(String, String, String)]) -> String {
        rows.iter().map(|(a, b, c)| format!("{a} {b} {c}")).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn the_enrollment_code_never_stands_in_the_clear_in_the_report() {
        let found = resolution(&[("EDMS_ENROLLMENT_CODE", "K7QM-4T2X")], &[]);
        let text = as_text(&setup_row(&found));
        assert!(!text.contains("K7QM-4T2X"), "{text}");
        assert!(text.contains("present"), "{text}");
    }

    #[test]
    fn every_value_carries_the_channel_it_came_through_and_names_the_variable_that_fixed_it() {
        // ADR-D13 §3: the user's window says only that the IT department set this device up; the
        // variable belongs here, in English, where the support call looks.
        let found = resolution(
            &[("EDMS_API_BASE", "https://api.acme")],
            &[("setup.auth-base", "https://auth.acme")],
        );
        let rows = setup_row(&found);
        let row = |feature: &str| {
            rows.iter().find(|(m, _, _)| m == feature).cloned().expect("a row of its own")
        };
        let (_, value, source) = row("API");
        assert_eq!(value, "https://api.acme");
        assert_eq!(source, "environment (EDMS_API_BASE)");
        let (_, value, source) = row("Sign-in");
        assert_eq!(value, "https://auth.acme");
        assert_eq!(source, "setting (setup.auth-base)");
        let (_, value, source) = row("Web interface");
        assert_eq!(value, "—", "nobody has said anything about it");
        assert_eq!(source, "not set (EDMS_APP_BASE)");
        let (_, _, source) = row("Folder");
        assert_eq!(source, "default", "computed on this machine");
    }

    #[test]
    fn a_counterpart_that_differs_stands_in_a_row_of_its_own_and_says_so() {
        let found = resolution(
            &[
                ("EDMS_API_BASE", "https://api.other"),
                ("EDMS_AUTH_BASE", "https://auth.other"),
                ("EDMS_APP_BASE", "https://app.other"),
            ],
            &[
                ("device.enrolled", "yes"),
                ("counterpart.api-base", "https://api.acme"),
                ("counterpart.auth-base", "https://auth.acme"),
                ("counterpart.app-base", "https://app.acme"),
            ],
        );
        let (feature, value, source) = counterpart_row(&found);
        assert_eq!(feature, "Enrolled against");
        assert_eq!(value, "https://api.acme");
        assert!(source.contains("DIFFERS"), "{source}");
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
