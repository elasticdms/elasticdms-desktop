//! The engine's errors — values with two faces.
//!
//! Every variant says the same thing twice, and on purpose:
//!
//! * `Display` (`#[error(…)]`) is the **diagnostic** sentence. It stands in the log, in a bug
//!   report and in a support call, and it is English like everything else developers touch. A
//!   translated diagnosis cannot be found again in a search.
//! * [`EngineError::user_text`] is the sentence for the **person at the machine**, out of the text
//!   catalogue in that person's language. It is what the app's window shows.
//!
//! The two never drift apart unnoticed: a new variant makes the match in `user_text` red.
//!
//! What is a server judgement stays a server judgement ([`edms_net::ApiResult`]) and is carried
//! through untranslated as `{reason}` — the client must not put words into the server's mouth.

use std::path::PathBuf;

use edms_crypto::CryptoError;
use edms_i18n::{Catalog, key};
use edms_store::StoreError;

use crate::config::ConfigurationError;
use crate::vault::VaultError;

/// Why the engine could not carry out an order.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The configuration does not stand.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    /// The operating system's keychain.
    #[error(transparent)]
    Vault(#[from] VaultError),

    /// The local state.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// A computation or a check.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A directory could not be created or read.
    #[error("`{path}` could not be set up: {reason}")]
    Directory {
        /// Which directory.
        path: PathBuf,
        /// What the operating system reports.
        reason: String,
    },

    /// The engine's own runtime could not be started.
    #[error("the engine could not start its runtime: {0}")]
    Runtime(String),

    /// The engine has stopped; it accepts nothing more.
    #[error("the engine has stopped")]
    Stopped,

    /// Nobody is signed in.
    #[error("nobody is signed in")]
    NotSignedIn,

    /// The device is not set up yet and there is no enrolment code.
    #[error(
        "this device is not set up yet; the enrolment code from the elasticdms console is missing"
    )]
    EnrollmentCodeMissing,

    /// The server rejected the operation on the merits.
    #[error("the server refuses: {0}")]
    Refused(String),

    /// The server rejected the access token (`401`).
    ///
    /// A case of its own, because it is the only one that deserves a retry: renew, then once more.
    /// A token can expire while a call is on its way — the lead from
    /// `session::REFRESH_LEAD_SECOND` covers that, but not a device clock that goes wrong.
    #[error("the session has expired: {0}")]
    SessionExpired(String),

    /// No server judgement — the line was away.
    #[error("the elasticdms server cannot be reached: {0}")]
    NoNetwork(String),

    /// Something the client must not quietly take over (03 §6.0.7).
    #[error("security abort: {0}")]
    Security(String),

    /// The platform layer did not carry out an order.
    #[error(transparent)]
    Platform(#[from] edms_core::port::PlatformError),

    /// The platform has not registered yet (`set_file_system` missing).
    #[error("the folder is not set up on this device yet")]
    NoFileSystem,

    /// A bug in this program.
    #[error("internal error in the folder client: {0}")]
    Internal(String),
}

impl EngineError {
    /// The whole sentence the user reads, in the catalogue's language.
    ///
    /// The four wrapped errors (configuration, keychain, store, cryptography) are diagnoses of
    /// their own crates; they are put into a sentence that says **what it means for the user**,
    /// and the diagnosis goes along as `{reason}`. Whoever reads it can act; whoever reports it
    /// carries the technical half with them.
    pub fn user_text(&self, catalogue: &Catalog) -> String {
        let with = |k, reason: String| catalogue.format(k, &[("reason", &reason)]);
        match self {
            Self::Configuration(e) => with(key::ERROR_ENGINE_CONFIGURATION, e.to_string()),
            Self::Vault(e) => with(key::ERROR_ENGINE_VAULT, e.to_string()),
            Self::Store(e) => with(key::ERROR_ENGINE_STORE, e.to_string()),
            Self::Crypto(e) => with(key::ERROR_ENGINE_CRYPTO, e.to_string()),
            Self::Directory { path, reason } => catalogue.format(
                key::ERROR_ENGINE_DIRECTORY,
                &[("path", &path.display().to_string()), ("reason", reason)],
            ),
            Self::Runtime(reason) => with(key::ERROR_ENGINE_RUNTIME, reason.clone()),
            Self::Stopped => catalogue.text(key::ERROR_ENGINE_STOPPED).to_owned(),
            Self::NotSignedIn => catalogue.text(key::ERROR_ENGINE_NOT_SIGNED_IN).to_owned(),
            Self::EnrollmentCodeMissing => {
                catalogue.text(key::ERROR_ENGINE_ENROLLMENT_CODE_MISSING).to_owned()
            }
            Self::Refused(reason) => with(key::ERROR_ENGINE_REFUSED, reason.clone()),
            Self::SessionExpired(reason) => with(key::ERROR_ENGINE_SESSION_EXPIRED, reason.clone()),
            Self::NoNetwork(reason) => with(key::ERROR_ENGINE_NO_NETWORK, reason.clone()),
            Self::Security(reason) => with(key::ERROR_ENGINE_SECURITY, reason.clone()),
            // The platform error has a sentence of its own — it knows better what is the matter
            // with the folder than a wrapper around it could.
            Self::Platform(e) => e.user_text(catalogue),
            Self::NoFileSystem => catalogue.text(key::ERROR_ENGINE_NO_FILE_SYSTEM).to_owned(),
            Self::Internal(reason) => with(key::ERROR_ENGINE_INTERNAL, reason.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use edms_i18n::Language;

    use super::*;

    #[test]
    fn every_engine_error_says_a_whole_sentence_in_every_language() {
        // Not "the key path stands there": that is what a forgotten catalogue entry looks like,
        // and it is exactly what this test is for.
        let all = [
            EngineError::Directory { path: PathBuf::from("/x"), reason: "denied".into() },
            EngineError::Runtime("no thread".into()),
            EngineError::Stopped,
            EngineError::NotSignedIn,
            EngineError::EnrollmentCodeMissing,
            EngineError::Refused("no".into()),
            EngineError::SessionExpired("401".into()),
            EngineError::NoNetwork("timeout".into()),
            EngineError::Security("issuer".into()),
            EngineError::NoFileSystem,
            EngineError::Internal("bug".into()),
            EngineError::Platform(edms_core::port::PlatformError::NotReadyPosed),
        ];
        for language in Language::ALL {
            let catalogue = Catalog::of(language);
            for error in &all {
                let sentence = error.user_text(catalogue);
                assert!(!sentence.is_empty(), "{language} {error:?}");
                assert!(!sentence.contains('{'), "{language} {error:?}: {sentence}");
                assert!(!sentence.starts_with("error."), "{language} {error:?}: {sentence}");
            }
        }
    }

    #[test]
    fn the_diagnostic_sentence_and_the_user_sentence_are_two_different_things() {
        let error = EngineError::NoNetwork("timeout".into());
        assert_eq!(error.to_string(), "the elasticdms server cannot be reached: timeout");
        assert_eq!(
            error.user_text(Catalog::of(Language::De)),
            "Der elasticdms-Server ist nicht erreichbar: timeout"
        );
    }
}
