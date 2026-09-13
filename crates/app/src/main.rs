//! elasticdms — the folder client: an icon in the taskbar or menu bar, a window with the local
//! usage log, and (later) the wiring of all the crates.
//!
//! The way through the crate:
//!
//! * [`cli`] — the command line.
//! * [`display`] — the seam to the engine: what the user interface shows and what a click
//!   triggers.
//! * [`demo`] — sample data behind the same seam, so that the user interface runs without a
//!   server.
//! * [`locale`] — which language this workstation speaks; asked once, then handed down.
//! * [`menu`], [`icon`] — what menu and icon show, as pure functions.
//! * [`tray`], [`window`] — the implementation in `tray-icon` and `wry`.
//! * [`message`] — the typed protocol between window and app.
//! * [`event_loop`] — the event loop, which owns everything.
//! * [`single_instance`] — one instance per user.
//! * [`uninstall`] — `--uninstall`: tidy up without a user interface, called by the MSI.
//!
//! And the wiring — the one place in the workspace where the crates know each other:
//!
//! * [`setup`] — the `EDMS_*` variables; three are mandatory, the rest have defaults.
//! * [`vault`] — the operating system's keychain (ADR-D03, point 4).
//! * [`device_key`] — the device key when a store outside this process holds it (ADR-D12).
//! * [`platform`] — Windows cfAPI or macOS File Provider, and what happens when there is neither.
//! * [`wiring`] — [`display::DisplaySource`] over `edms_engine::Engine`.
//! * [`doctor`] — `elasticdms doctor`, without the network.
//! * [`time`] — the one clock of the program.

mod cli;
mod demo;
mod device_key;
mod display;
mod doctor;
mod event_loop;
mod icon;
mod locale;
mod menu;
mod message;
mod platform;
mod setup;
mod single_instance;
mod time;
mod tray;
mod uninstall;
mod vault;
mod window;
mod wiring;

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::Call;
use crate::single_instance::{Claim, InstanceError};

/// Exit code for a command line that cannot be used (the habit of the Unix tools: 2 = wrong
/// invocation, 1 = the work failed).
const EXIT_CODE_CALL: u8 = 2;

fn main() -> ExitCode {
    let call = match cli::read(std::env::args_os().skip(1)) {
        Ok(call) => call,
        Err(error) => {
            write(&mut std::io::stderr(), &format!("{error}\n\n{}", cli::HELP));
            return ExitCode::from(EXIT_CODE_CALL);
        }
    };
    if call.help {
        write(&mut std::io::stdout(), cli::HELP);
        return ExitCode::SUCCESS;
    }
    diagnostics();
    // `--uninstall` tidies up before the MSI removes the files: as SYSTEM in session 0, without a
    // window, without the keychain, without the single-instance lock and without a single
    // mandatory EDMS_ variable (crates/app/src/uninstall.rs). That is why it comes before
    // everything the app builds up.
    if call.uninstall {
        return uninstall::run();
    }
    // `doctor` is a tool, not an icon: no single-instance lock (it should answer alongside the
    // running app too), no window, an exit code as its result.
    if call.doctor {
        return doctor::run();
    }
    match run(call) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "elasticdms could not start.");
            write(&mut std::io::stderr(), &format!("{error}\n"));
            ExitCode::FAILURE
        }
    }
}

/// Why the start was aborted. Every case names what is missing and what to do.
///
/// This sentence goes to the error output before there is a window at all — it is read by whoever
/// set the workstation up, and it is English like every other diagnostic in this house. What the
/// **user** reads once the app is running comes out of the text catalogue (`crate::locale`).
#[derive(Debug, thiserror::Error)]
enum Abort {
    /// The single instance could not be settled.
    #[error(transparent)]
    Instance(#[from] InstanceError),
    /// The sample data could not be built (a bug, not a user error).
    #[error("the sample data is not consistent: {0}")]
    Demo(#[from] edms_core::log::LogError),
    /// Setup, store, keychain or engine are not up.
    #[error(transparent)]
    Wiring(#[from] wiring::StartupAbort),
    /// The icon or the back channel could not be set up.
    #[error(transparent)]
    Start(#[from] event_loop::StartupError),
}

/// Starts the app: settle the single instance, build the source, hand over to the event loop.
///
/// # Errors
///
/// [`Abort`] with the sentence the user reads on the error output.
#[allow(
    clippy::result_large_err,
    reason = "the error ends the process; an allocation for it would buy nothing"
)]
fn run(call: Call) -> Result<(), Abort> {
    // A demo run and a real run are two instances: otherwise a `make demo` would ask the running
    // real icon for its window (see `single_instance`).
    let name = if call.demo.is_some() { single_instance::NAME_DEMO } else { single_instance::NAME };
    let directory = single_instance::instance_directory()?;
    let guard = match single_instance::claim(&directory, name)? {
        Claim::First(guard) => guard,
        // No second icon: the running instance shows its window, this start is done.
        Claim::RunsAlready => {
            tracing::info!("elasticdms is already running; the running instance shows its window.");
            single_instance::ask_for_window(&directory, name)?;
            return Ok(());
        }
    };

    let catalogue = locale::catalogue();
    let source: Arc<dyn display::DisplaySource> = match call.demo {
        Some(demo_state) => {
            tracing::info!(state = demo_state.name(), "elasticdms is starting with sample data.");
            Arc::new(demo::DemoSource::new(
                time::now(),
                demo_state,
                &std::env::temp_dir(),
                catalogue,
            )?)
        }
        None => {
            // The setup first: a missing mandatory variable is a sentence on the error output,
            // not an icon that later cannot sign in.
            let configuration = setup::configuration().map_err(wiring::StartupAbort::from)?;
            tracing::info!(
                api = configuration.api_base,
                device = configuration.device_name,
                "elasticdms is starting."
            );
            Arc::new(wiring::EngineView::start(configuration)?)
        }
    };

    match event_loop::start(source, call.window, Some(guard), catalogue)? {}
}

/// The diagnostic log on the error output, controlled through `EDMS_LOG`.
///
/// No `println!`: the output of a program with a window belongs on stderr, where a service
/// manager (and `make demo`) records it — stdout would be the place for results, and this program
/// produces no results.
fn diagnostics() {
    // Without a setting: everything from this workspace in a development build, in a shipped
    // build only what is really worth mentioning. Two prefixes, because `EnvFilter` matches a
    // directive's target with `starts_with` (tracing-subscriber 0.3.23,
    // `filter/env/directive.rs:246`) and this workspace spells itself two ways: the binaries are
    // `elasticdms…`, every library is `edms_…`. With `elasticdms` alone every library fell to the
    // bare `warn` — measured with `doctor` on this Mac: the line that ADR-D12 §3 counts as the
    // second of its two places never reached stderr, and neither did the three other
    // `tracing::info!` of the engine.
    let default = if cfg!(debug_assertions) {
        "elasticdms=debug,edms_=debug,warn"
    } else {
        "elasticdms=info,edms_=info,warn"
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("EDMS_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

/// Writes text; a closed output channel (`| head`) is no reason to abort.
fn write(target: &mut impl Write, text: &str) {
    let _ = target.write_all(text.as_bytes());
    let _ = target.flush();
}
