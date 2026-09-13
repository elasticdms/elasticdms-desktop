//! The errors of the line — and how they arrive in the extension as [`SourceError`].
//!
//! The extension knows only [`SourceError`]; [`BridgeError`] is the more precise language beneath
//! it. The mapping stands in exactly one place ([`From`] below), so that client, tests and
//! documentation mean the same table:
//!
//! | Bridge error                          | Source error     | Why |
//! |---------------------------------------|------------------|-----|
//! | `NoRendezvousFile`, `AppUnresponsive` | `NoNetwork`      | the app is not running |
//! | `Refused`                             | `NoNetwork`      | the port is not the app's |
//! | `Torn`, `Timeout`                     | `NoNetwork`      | the app went away or hangs |
//! | all others                            | `Internal(text)` | set-up or program error; stays |

use std::path::PathBuf;

use edms_core::port::SourceError;

/// Why the line does not carry.
///
/// The messages are whole sentences for the **log** and for a diagnostic view; the secret stands
/// in none of them. English, like every other diagnostic in this house: one of them travels into
/// a sentence the user reads (`edms_fileprovider::error`, `ProviderError::AppNotReachable` puts
/// it into `{reason}`), and a German fragment inside an English sentence would be the worst of
/// both. What the user reads around it comes from the text catalogue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// The rendezvous file is missing: the app was not started (or has cleared up).
    #[error("the elasticdms app is not running: there is no rendezvous file at {path}")]
    NoRendezvousFile {
        /// Where the search happened.
        path: PathBuf,
    },
    /// Nobody accepts on the port: the app has ended or crashed.
    #[error("the elasticdms app is not running: nobody accepts on 127.0.0.1:{port} ({reason})")]
    AppUnresponsive {
        /// The port from the rendezvous file.
        port: u16,
        /// The operating system's message.
        reason: String,
    },
    /// The sandbox forbids the connection.
    #[error(
        "the extension may not connect to 127.0.0.1:{port} ({reason}); is the entitlement \
         com.apple.security.network.client missing?"
    )]
    ConnectionForbidden {
        /// The port from the rendezvous file.
        port: u16,
        /// The operating system's message.
        reason: String,
    },
    /// The handshake failed: what answers on the port is not the app that wrote the file.
    #[error(
        "what answers on 127.0.0.1:{port} is not the elasticdms app that wrote the rendezvous \
         file ({reason}); the file is stale, or a foreign program holds the port"
    )]
    Refused {
        /// The port from the rendezvous file.
        port: u16,
        /// What exactly happened.
        reason: String,
    },
    /// The app has sent no byte for too long.
    #[error("the elasticdms app did not answer for {second} seconds")]
    Timeout {
        /// The deadline that passed.
        second: u64,
    },
    /// The line broke off after the handshake.
    #[error("the connection to the elasticdms app broke off ({reason}); the app was probably quit")]
    Torn {
        /// What exactly happened.
        reason: String,
    },
    /// The counterpart violates the protocol (frame too large, unknown message, gap in the
    /// content).
    #[error("the bridge between extension and app violates its protocol: {0}")]
    Log(String),
    /// App and extension speak different versions of the line.
    #[error(
        "app and extension come from different builds: the app speaks bridge version {read}, \
         the extension version {expected}"
    )]
    WrongVersion {
        /// Our own version.
        expected: u32,
        /// The one that was read.
        read: u32,
    },
    /// The rendezvous file cannot be read (as opposed to "missing").
    #[error(
        "the rendezvous file {path} is not readable ({reason}); is the extension's \
         temporary-exception for this path missing?"
    )]
    RendezvousUnreadable {
        /// The file.
        path: PathBuf,
        /// The operating system's message.
        reason: String,
    },
    /// The rendezvous file is not a valid rendezvous file.
    #[error("the rendezvous file {path} is invalid: {reason}")]
    RendezvousInvalid {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// The rendezvous file is readable or writable by others.
    #[error(
        "the rendezvous file {path} is readable or writable by others (mode {mode:o}); the \
         secret in it counts as spent. elasticdms writes it afresh with mode 600 on the next start"
    )]
    PermissionsTooOpen {
        /// The file.
        path: PathBuf,
        /// The permissions (lower nine bits).
        mode: u32,
    },
    /// The rendezvous file cannot be written.
    #[error("the rendezvous file {path} could not be written: {reason}")]
    RendezvousNotWritten {
        /// The file.
        path: PathBuf,
        /// The operating system's message.
        reason: String,
    },
    /// The user's real home directory cannot be determined.
    #[error("the user's home directory cannot be determined: {0}")]
    HomeUnknown(String),
    /// On this operating system the line does not exist.
    #[error("not possible on this operating system: {0}")]
    NotSupported(&'static str),
    /// The secret does not have the demanded form.
    #[error("the bridge's secret is invalid: {0}")]
    Secret(String),
    /// The app cannot listen on 127.0.0.1.
    #[error("the bridge cannot listen on 127.0.0.1: {0}")]
    Listening(String),
}

impl BridgeError {
    /// Whether the error means: the app that wrote the rendezvous file is not (any longer) there.
    ///
    /// Exactly these cases become [`SourceError::NoNetwork`] in the extension; see the table in the
    /// module head.
    pub const fn app_not_reachable(&self) -> bool {
        matches!(
            self,
            Self::NoRendezvousFile { .. }
                | Self::AppUnresponsive { .. }
                | Self::Refused { .. }
                | Self::Timeout { .. }
                | Self::Torn { .. }
        )
    }
}

impl From<BridgeError> for SourceError {
    fn from(error: BridgeError) -> Self {
        if error.app_not_reachable() { Self::NoNetwork } else { Self::Internal(error.to_string()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_that_is_not_running_becomes_no_network() {
        let cases = [
            BridgeError::NoRendezvousFile { path: "/x/bridge.json".into() },
            BridgeError::AppUnresponsive { port: 1, reason: "refused".into() },
            BridgeError::Refused { port: 1, reason: "closed".into() },
            BridgeError::Timeout { second: 90 },
            BridgeError::Torn { reason: "reset".into() },
        ];
        for case in cases {
            assert_eq!(SourceError::from(case.clone()), SourceError::NoNetwork, "{case}");
        }
    }

    #[test]
    fn a_set_up_error_becomes_internal_with_a_whole_sentence() {
        let wrong = BridgeError::WrongVersion { expected: 1, read: 2 };
        let SourceError::Internal(text) = SourceError::from(wrong) else {
            panic!("a wrong version is no network problem but demands a restart");
        };
        assert!(text.contains("different builds"), "{text}");
        let open = BridgeError::PermissionsTooOpen { path: "/x".into(), mode: 0o644 };
        assert!(
            matches!(SourceError::from(open), SourceError::Internal(text) if text.contains("644"))
        );
    }

    #[test]
    fn the_message_without_a_rendezvous_file_says_the_app_is_not_running() {
        let missing = BridgeError::NoRendezvousFile { path: "/x/bridge.json".into() };
        assert!(missing.to_string().starts_with("the elasticdms app is not running"), "{missing}");
    }
}
