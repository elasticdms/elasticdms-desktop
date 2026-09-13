//! The command line: `--demo[=STATE]`, `--window`, `--uninstall`, `--help`.
//!
//! Strict: an unknown option is an error with exit code 2, not a silent pass. Whoever types
//! `--windwo` and gets no window would otherwise look for the mistake in the wrong place.

use std::ffi::OsString;

use crate::demo::DemoState;

/// The help text for `--help`.
///
/// English, and not out of the text catalogue: the command line is an operator surface. It is
/// typed in a terminal, pasted into a ticket and searched for, its options are English
/// (`--window`, `--demo`), and its variables are English — a German help text over English
/// switches would be half a translation. What a **user** reads is the window, and that speaks the
/// language of the workstation (`crate::locale`).
pub const HELP: &str = "\
elasticdms - folder client: an icon in the taskbar or menu bar, and a usage log.

Usage: elasticdms [--demo[=STATE]] [--window]
       elasticdms doctor
       elasticdms --uninstall

  doctor           Shows the state of this workstation and exits. Needs no network;
                   exit code 1 when there is something to complain about.
  --demo           Sample data instead of a server. STATE is signed-in (the default), login,
                   signed-out, expired, approval, offline or warning.
  --window         Opens the window right at startup (for screenshots, say).
  --uninstall      Signs the synchronisation root of every profile off and removes mirror and
                   local state (Windows). Starts nothing, asks nothing, needs no EDMS_
                   variables: the installer calls it as SYSTEM before it removes the files.
                   The keychain is left untouched.
  --help, -h       This overview.

If elasticdms is already running, a second call creates no second icon but opens the window of
the running instance.

Environment (without the first three, and with nothing stored for them, elasticdms starts into its
set-up and asks for them):
  EDMS_API_BASE        Base address of the elasticdms API.
  EDMS_AUTH_BASE       Base address of the authorization server.
  EDMS_APP_BASE        Base address of the web interface; a browser is opened only there.
  EDMS_ENROLLMENT_CODE Code from the console, only for the first set-up.
  EDMS_DEVICE_NAME     Name of this workstation in the console.
  EDMS_MIRROR_PATH     Root of the folder (default: ~/elasticdms).
  EDMS_HOLDING_DIR     Directory for files handed in until the server confirms them.
  EDMS_DATA_PATH       SQLite file holding the local state.
  EDMS_STAGING_DIR     Directory for content before it is checked.
  EDMS_VAULT           keychain (the default) or memory (development runs only).
  EDMS_LANG            Language of the user interface: de or en. Without it the operating
                       system's choice holds, and English where it names neither.

The three addresses, the device name, the folder's root and the language can also be set in
elasticdms itself, in its set-up; they are then stored in the local state. A value set here wins
over the stored one, for every value and without an exception list: setting a variable is the act
of taking the choice away, and the set-up then shows the value instead of offering it. The other
variables are set here and nowhere else. A variable that is set to something unusable does end the
start, and with a sentence on this output: an administrator's decision is not the set-up's to
overrule.

Diagnostics on the error output: EDMS_LOG=debug (filters as in tracing).
";

/// What the command line asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Call {
    /// Sample data in this state.
    pub demo: Option<DemoState>,
    /// Open the window right at startup.
    pub window: bool,
    /// Only show the help text.
    pub help: bool,
    /// Run the `doctor` subcommand instead of the app.
    pub doctor: bool,
    /// Tidy up instead of starting (`crate::uninstall`); the MSI calls this on uninstall.
    pub uninstall: bool,
}

/// The command line cannot be used. An operator surface, see [`HELP`]: English.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// An option that does not exist.
    #[error("unknown option `{0}`; allowed are --demo[=STATE], --window, --uninstall and --help")]
    Unknown(String),
    /// The same option twice.
    #[error("the option {0} stands there twice")]
    Duplicate(&'static str),
    /// A demo state that does not exist.
    #[error("`{0}` is no demo state; allowed are: {list}", list = DemoState::NAMES.join(", "))]
    DemoState(String),
    /// An argument that is not Unicode.
    #[error("the argument `{0}` is not valid Unicode text")]
    NoText(String),
    /// `doctor` with options it does not know.
    #[error("`doctor` takes no further options; it shows the state of this workstation and exits")]
    DoctorWithOptions,
    /// `--uninstall` next to something that starts instead of tidying up.
    #[error("`--uninstall` takes no further options; it tidies up and starts nothing")]
    UninstallWithOptions,
}

/// Reads the arguments (without the program name).
pub fn read(arguments: impl IntoIterator<Item = OsString>) -> Result<Call, CallError> {
    let mut call = Call::default();
    for raw in arguments {
        let arg = raw
            .into_string()
            .map_err(|raw| CallError::NoText(raw.to_string_lossy().into_owned()))?;
        match arg.as_str() {
            "--window" if call.window => return Err(CallError::Duplicate("--window")),
            "--window" => call.window = true,
            "--help" | "-h" => call.help = true,
            "--demo" => set_demo(&mut call, DemoState::SignedIn)?,
            "--uninstall" if call.uninstall => {
                return Err(CallError::Duplicate("--uninstall"));
            }
            "--uninstall" => call.uninstall = true,
            "doctor" if call.doctor => return Err(CallError::Duplicate("doctor")),
            "doctor" => call.doctor = true,
            // Older macOS versions pass an app started from Finder a process serial number; it
            // is not an option of the user's.
            psn if cfg!(target_os = "macos") && psn.starts_with("-psn_") => {}
            other => match other.strip_prefix("--demo=") {
                Some(name) => {
                    let state = DemoState::from_text(name)
                        .ok_or_else(|| CallError::DemoState(name.to_owned()))?;
                    set_demo(&mut call, state)?;
                }
                None => return Err(CallError::Unknown(other.to_owned())),
            },
        }
    }
    // `doctor` next to `--demo` would mean: one of the two is silently passed over. Whoever
    // types both should be told — the help shows them as two forms of invocation.
    if call.doctor && (call.demo.is_some() || call.window) {
        return Err(CallError::DoctorWithOptions);
    }
    // The same for `--uninstall`, and for the same reason: whoever types "--uninstall --window"
    // would otherwise get a window OR a clean-up, and only one of the two — silently. The MSI
    // calls the switch on its own (`packaging/windows/elasticdms.wxs`).
    if call.uninstall && (call.demo.is_some() || call.window || call.doctor) {
        return Err(CallError::UninstallWithOptions);
    }
    Ok(call)
}

fn set_demo(call: &mut Call, state: DemoState) -> Result<(), CallError> {
    if call.demo.is_some() {
        return Err(CallError::Duplicate("--demo"));
    }
    call.demo = Some(state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_text(arguments: &[&str]) -> Result<Call, CallError> {
        read(arguments.iter().map(OsString::from))
    }

    #[test]
    fn without_arguments_nothing_is_asked_for() {
        assert_eq!(read_text(&[]).unwrap(), Call::default());
    }

    #[test]
    fn demo_and_window_are_read() {
        let a = read_text(&["--demo", "--window"]).unwrap();
        assert_eq!(a, Call { demo: Some(DemoState::SignedIn), window: true, ..Call::default() });
    }

    #[test]
    fn a_demo_state_is_read_after_the_equals_sign() {
        assert_eq!(read_text(&["--demo=login"]).unwrap().demo, Some(DemoState::Login));
        assert_eq!(read_text(&["--demo=offline"]).unwrap().demo, Some(DemoState::Offline));
    }

    #[test]
    fn an_unknown_demo_state_is_an_error_that_names_the_permitted_ones() {
        let f = read_text(&["--demo=broken"]).unwrap_err();
        assert_eq!(f, CallError::DemoState("broken".into()));
        assert!(f.to_string().contains("login"), "{f}");
    }

    #[test]
    fn a_mistyped_option_is_an_error_and_not_a_silent_pass() {
        assert_eq!(read_text(&["--windwo"]).unwrap_err(), CallError::Unknown("--windwo".into()));
        assert_eq!(read_text(&["demo"]).unwrap_err(), CallError::Unknown("demo".into()));
    }

    #[test]
    fn a_duplicated_option_is_an_error() {
        assert_eq!(
            read_text(&["--window", "--window"]).unwrap_err(),
            CallError::Duplicate("--window")
        );
        assert_eq!(
            read_text(&["--demo", "--demo=offline"]).unwrap_err(),
            CallError::Duplicate("--demo")
        );
    }

    #[test]
    fn doctor_is_a_subcommand_and_tolerates_no_options() {
        assert!(read_text(&["doctor"]).unwrap().doctor);
        assert_eq!(read_text(&["doctor", "doctor"]).unwrap_err(), CallError::Duplicate("doctor"));
        assert_eq!(read_text(&["doctor", "--window"]).unwrap_err(), CallError::DoctorWithOptions);
        assert_eq!(read_text(&["--demo", "doctor"]).unwrap_err(), CallError::DoctorWithOptions);
        // With `--help` it is not an execution but a question about the overview.
        assert!(read_text(&["doctor", "--help"]).unwrap().help);
    }

    #[test]
    fn uninstall_is_a_switch_and_tolerates_no_further_options() {
        assert!(read_text(&["--uninstall"]).unwrap().uninstall);
        assert_eq!(
            read_text(&["--uninstall", "--uninstall"]).unwrap_err(),
            CallError::Duplicate("--uninstall")
        );
        for beside_it in [["--uninstall", "--window"], ["--uninstall", "doctor"]] {
            assert_eq!(
                read_text(&beside_it).unwrap_err(),
                CallError::UninstallWithOptions,
                "{beside_it:?}"
            );
        }
        // This is exactly how the MSI calls it: one argument, nothing else.
        assert_eq!(
            read_text(&["--uninstall"]).unwrap(),
            Call { uninstall: true, ..Call::default() }
        );
    }

    #[test]
    fn a_mistyped_uninstall_does_not_start_the_app_instead() {
        // The most expensive typo would be one that `Return="ignore"` in the MSI swallows: exit
        // code 2, nothing tidied up, and the next installation jams.
        assert_eq!(
            read_text(&["--uninstall=yes"]).unwrap_err(),
            CallError::Unknown("--uninstall=yes".into())
        );
        assert_eq!(
            read_text(&["--uninstallation"]).unwrap_err(),
            CallError::Unknown("--uninstallation".into())
        );
    }

    #[test]
    fn help_is_recognised_in_both_spellings() {
        for h in ["--help", "-h"] {
            assert!(read_text(&[h]).unwrap().help, "{h}");
        }
    }
}
