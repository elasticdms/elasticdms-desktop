//! `edms-mock` — the server mock as a program, for `make mock`.
//!
//! It binds two fixed ports (8480 and 8481 by default), sets up the German sample tenant and
//! writes the three environment variables the folder client needs onto the screen. After that it
//! waits for Ctrl-C.
//!
//! **This is a test harness, not a product.** The mock produces anchors and signed delivery
//! commands itself, hands out tokens without a real sign-in and confirms devices without an
//! administrator. None of that may ever go into a release; it therefore listens on 127.0.0.1 only,
//! and `/mock/commands` turns away every peer that does not come from this machine.

// A program with terminal output: the addresses a developer copies belong on stdout and not in a
// log that a filter rule can swallow. The house rule "libraries do not write to the console"
// applies to the library, not to this program (crates/architecture-rules,
// `libraries_do_not_write_to_the_console`).
#![allow(clippy::print_stdout)]

use edms_mock::api::PATH_DEV_COMMAND;
use edms_mock::seed;
use edms_mock::{Configuration, Mock, MockError};

/// Environment variable for the port of the resource API.
const ENVIRONMENT_API_PORT: &str = "EDMS_MOCK_API_PORT";

/// Environment variable for the port of the authorization server.
const ENVIRONMENT_AUTH_PORT: &str = "EDMS_MOCK_AUTH_PORT";

/// Default port of the resource API (README, "Getting started").
const DEFAULT_API_PORT: u16 = 8480;

/// Default port of the authorization server.
const DEFAULT_AUTH_PORT: u16 = 8481;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_env("EDMS_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("edms_mock=info,warn"));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();

    let configuration = match configuration() {
        Ok(configuration) => configuration,
        Err(error) => {
            println!("The mock does not start: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match Mock::start(configuration).await {
        Ok(mock) => {
            println!("{}", instructions(&mock));
            // Ctrl-C is the only ending. A test harness that stops by itself after a while leaves
            // a developer looking for the reason in the client.
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "waiting for Ctrl-C failed");
            }
            println!("\nMock stopped.");
            mock.stop().await;
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            println!("The mock does not start: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Reads the ports out of the environment; an unreadable value aborts the start.
///
/// No silent default for a value somebody set explicitly: whoever writes
/// `EDMS_MOCK_API_PORT=eighty` should be told, and not end up on 8480.
fn configuration() -> Result<Configuration, MockError> {
    Ok(Configuration::default().with_ports(
        port(ENVIRONMENT_API_PORT, DEFAULT_API_PORT)?,
        port(ENVIRONMENT_AUTH_PORT, DEFAULT_AUTH_PORT)?,
    ))
}

/// A port out of the environment.
fn port(name: &str, default: u16) -> Result<u16, MockError> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(text) => text.trim().parse().map_err(|_| {
            MockError::Configuration(format!(
                "{name}=`{text}` is not a port number between 0 and 65535"
            ))
        }),
    }
}

/// The text a developer reads after the start.
///
/// Deliberately a multi-line literal without line continuations: a `\` at the end of a line eats
/// the indentation of the next one, and the indentation is half the readability here.
fn instructions(mock: &Mock) -> String {
    let api = mock.api_base();
    let auth = mock.auth_base();
    let app = mock.app_base();
    format!(
        "
elasticdms — server mock (test harness, never a product)
════════════════════════════════════════════════════════

The folder client needs these settings:

  EDMS_API_BASE={api}
  EDMS_AUTH_BASE={auth}
  EDMS_APP_BASE={app}

The mirror already holds:

  Mail basket     {basket_a}   (files may be dropped in here, and nowhere else)
  Mail basket     {basket_b}
  Archive         {archive_a}
    Case file     {case_b}
  Archive         {archive_b}
    Case file     {case_a}
  Saved search    {search_a}   (more hits than displayLimit — totalCapped)
  Saved search    {search_b}

Signing in runs through the device flow. The mock confirms it by itself; the confirmation page
with the Confirm and Reject buttons lives at

  {app}/geraet?user_code=…

Queueing a signed delivery command (from 127.0.0.1 only, and only after the enrolment):

  curl -sS -X POST {api}{PATH_DEV_COMMAND} \\
    -H 'Content-Type: application/json' \\
    -d '{{\"kind\":\"RECONCILE\",\"payload\":{{\"container\":null}}}}'

\"container\" takes a text form of the namespace — root · baskets · bsk_… · archives · arc_… ·
arc_…/cas_… · searches · srch_… — or null for the whole mirror.

Grades for \"quality\": valid · foreign-signature · broken-signature · without-signature ·
wrong-typ — so that it can be checked that the client does not carry out a command whose
signature does not hold.

Stop with Ctrl-C.
",
        basket_a = seed::BASKET_ACCOUNTING,
        basket_b = seed::BASKET_SCANNER,
        archive_a = seed::ARCHIVE_INVOICE,
        archive_b = seed::ARCHIVE_MAINTENANCE,
        case_a = seed::CASE_MAINTENANCE,
        case_b = seed::CASE_CREDITOR,
        search_a = seed::SEARCH_OPEN,
        search_b = seed::SEARCH_INSPECTION_REPORT,
    )
}
