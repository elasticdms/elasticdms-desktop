//! The source of a workstation that has not been told where its server is — the start path of
//! ADR-D13 §11, point 1.
//!
//! Before this module the start read the configuration, found no `EDMS_API_BASE` and ended with a
//! sentence on the error output. ADR-D13's Context calls that "a terminal message from a program
//! that has no terminal", and its Consequences say the app "must reach the tray and the web view
//! before it has a configuration". MEASURED on 2026-09-13 before this module existed:
//! `env -i HOME=<fresh> elasticdms --window` printed one English line and exited 1 — double-clicked
//! from Finder or the Start menu, nothing at all happened, on the very machine the wizard was
//! built for.
//!
//! ## What it is and what it is not
//!
//! It is a [`DisplaySource`] with no engine behind it: it knows the `setting` table and nothing
//! else. The set-up works — [`crate::setup::resolve_over`], [`crate::setup::set_value`] and
//! [`crate::setup::mark_completed`] are the same three doors `wiring::EngineView` uses — and
//! everything that needs a server says so in one sentence instead of failing quietly.
//!
//! **Only for values nobody has given.** A value that is *there* and unusable still ends the
//! start on the error output: an `EDMS_API_BASE` an administrator set to something broken is a
//! mistake in a managed roll-out, and a wizard that offered to overrule it would be the one thing
//! the order of precedence forbids ("to set it is to fix it"). [`crate::setup::Resolution::missing`]
//! is what tells the two apart.
//!
//! ## How it ends
//!
//! When the wizard's last page is reached, the event loop resolves afresh; if a configuration now
//! comes out, it builds the real source on a thread of its own and takes this one's place
//! (`event_loop::Control::take_over`). Nobody has to restart the app, and nothing here ever
//! becomes half an engine.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use edms_core::log::LogEntry;
use edms_engine::config::Value;
use edms_i18n::{Catalog, key};
use edms_store::Store;

use crate::display::{
    DisplayError, DisplaySource, DisplayState, ExtensionState, SetupValues, SetupView, Status,
    Waker,
};

/// A workstation that is waiting to be told where its server is.
pub struct AwaitingSetup {
    /// The `setting` table — the one thing this source can reach. `None` when the local state
    /// cannot be opened at all: the wizard then shows what the environment and the defaults say,
    /// refuses to store anything, and says why.
    settings: Mutex<Option<Store>>,
    catalogue: &'static Catalog,
    waker: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for AwaitingSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwaitingSetup")
            .field("settings", &self.store().is_some())
            .finish_non_exhaustive()
    }
}

impl AwaitingSetup {
    /// Opens the `setting` table, or carries on without one.
    ///
    /// Without one nothing can be stored — and that is not a reason to keep the window shut: the
    /// wizard is where the sentence about it can be read, and `set_value` says it per value.
    pub fn new(catalogue: &'static Catalog) -> Self {
        let settings = match crate::setup::open_for_settings() {
            Some(store) => Some(store),
            None => {
                tracing::warn!(
                    "the local state could not be opened; the set-up can show values but not \
                     store them."
                );
                None
            }
        };
        Self { settings: Mutex::new(settings), catalogue, waker: Mutex::new(Vec::new()) }
    }

    fn store(&self) -> MutexGuard<'_, Option<Store>> {
        self.settings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The one sentence this source has for every action that needs a server.
    fn not_yet(&self) -> DisplayError {
        DisplayError::NotPossible(self.catalogue.text(key::NOTICE_SETUP_NEEDED).to_owned())
    }
}

impl DisplaySource for AwaitingSetup {
    /// Not signed in, no folder, and the reason standing in the status line.
    ///
    /// The status is the truth and not a placeholder: nobody is signed in, and nobody can be
    /// until the wizard has been walked.
    fn state(&self) -> DisplayState {
        DisplayState {
            account: None,
            status: Status::NotSignedIn,
            folder: None,
            baskets: None,
            login_code: None,
            hint: Some(self.catalogue.text(key::NOTICE_SETUP_NEEDED).to_owned()),
        }
    }

    /// Empty, and honestly so.
    ///
    /// Elsewhere an empty list would be the plausible untruth this house forbids — here it is the
    /// fact: this workstation has never been signed in, and nothing has been opened on it. There
    /// is no account to scope a log to either; the store is the same file, but its rows belong to
    /// accounts (ADR-D07, requirement 4) and this source knows none.
    fn log(
        &self,
        _before_id: Option<i64>,
        _count: usize,
    ) -> Result<Vec<(i64, LogEntry)>, DisplayError> {
        Ok(Vec::new())
    }

    fn sign_in(&self) -> Result<(), DisplayError> {
        Err(self.not_yet())
    }

    fn sign_out(&self) -> Result<(), DisplayError> {
        Err(self.not_yet())
    }

    fn open_folder(&self) -> Result<(), DisplayError> {
        Err(self.not_yet())
    }

    fn open_baskets(&self) -> Result<(), DisplayError> {
        Err(self.not_yet())
    }

    fn setup(&self) -> Option<SetupView> {
        let store = self.store();
        let resolution = match store.as_ref() {
            Some(open) => crate::setup::resolve_over(open),
            None => crate::setup::resolve(),
        };
        // The extension is a question for a device that has a folder. This one has not been told
        // where its server is, so the step says what it says for any device that has not switched
        // it on — and `wiring::EngineView` asks macOS for real once it exists.
        Some(crate::wiring::view_of(&resolution, ExtensionState::Off))
    }

    fn apply_setup(&self, values: &SetupValues) -> Result<(), DisplayError> {
        let mut store = self.store();
        let Some(open) = store.as_mut() else {
            return Err(DisplayError::NotPossible(
                self.catalogue.text(key::SETUP_WRONG_NOT_STORED).to_owned(),
            ));
        };
        crate::wiring::store_values(open, values, self.catalogue)
    }

    fn complete_setup(&self) -> Result<(), DisplayError> {
        let mut store = self.store();
        let Some(open) = store.as_mut() else {
            return Err(DisplayError::NotPossible(
                self.catalogue.text(key::SETUP_WRONG_NOT_STORED).to_owned(),
            ));
        };
        crate::setup::mark_completed(open).map_err(|error| {
            tracing::warn!(%error, "the set-up's completed mark was not written.");
            DisplayError::NotPossible(self.catalogue.text(key::SETUP_WRONG_NOT_STORED).to_owned())
        })
    }

    fn extension_state(&self) -> ExtensionState {
        ExtensionState::Off
    }

    fn observe(&self, waker: Waker) {
        self.waker.lock().unwrap_or_else(PoisonError::into_inner).push(Arc::from(waker));
    }

    /// The store goes before the engine's own opens it.
    ///
    /// `tao` exits the process without running a single `Drop`, and the real source opens the
    /// same file a moment later (`event_loop::Control::take_over`). SQLite in WAL mode takes a
    /// second connection — but a connection nobody closes is a lock nobody releases at a
    /// sign-out.
    fn stop(&self) {
        drop(self.store().take());
    }
}

/// Whether this workstation can be started, or has to be asked first.
///
/// `Ok`: go the way the start always went — build the engine, or end on the error output with the
/// configuration's own sentence. `Err(values)`: exactly these values nobody has given, and a
/// window with the set-up in it is the only place they can be asked for.
pub fn what_is_missing(resolution: &crate::setup::Resolution) -> Result<(), Vec<Value>> {
    let missing = resolution.missing();
    // **"To set it is to fix it."** A variable an administrator set is their decision, and one
    // they set to nothing is a mistake in a managed roll-out — `EDMS_API_BASE=` out of an Intune
    // value that did not substitute. Both end the start on the error output, where an
    // administrator reads it. A set-up that offered to fill such a value in would be a user
    // overruling an administrator, which is the one thing the order of precedence exists to
    // prevent (ADR-D13, "The question that decides the shape").
    if missing.is_empty() || missing.iter().any(|which| resolution.is_fixed(*which)) {
        return Ok(());
    }
    Err(missing)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use edms_engine::config::{VAR_API_BASE, VAR_APP_BASE, VAR_AUTH_BASE};
    use edms_i18n::Language;

    use super::*;

    fn resolution(environment: &HashMap<String, String>) -> crate::setup::Resolution {
        crate::setup::read(&|name| environment.get(name).cloned(), &|_| None, Language::De)
    }

    fn with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn a_workstation_nobody_has_told_where_its_server_is_names_the_three_addresses() {
        // The whole reason this module exists: these three are what the wizard has to ask for,
        // and asking is only possible in a window.
        let missing = what_is_missing(&resolution(&HashMap::new()))
            .expect_err("a fresh machine has no address at all");
        assert_eq!(missing, vec![Value::ApiBase, Value::AuthBase, Value::AppBase]);
    }

    #[test]
    fn a_workstation_that_has_all_three_is_not_waiting_for_anything() {
        let found = resolution(&with(&[
            (VAR_API_BASE, "https://api.example"),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
        ]));
        assert_eq!(what_is_missing(&found), Ok(()));
    }

    #[test]
    fn a_value_that_is_set_to_nothing_is_not_a_value_nobody_gave() {
        // "To set it is to fix it": an administrator who set the variable made a decision, and a
        // broken one is a mistake in a roll-out, not a question for the user. The start therefore
        // still ends on the error output, and `Resolution::configuration` is what says so.
        let found = resolution(&with(&[
            (VAR_API_BASE, "   "),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
        ]));
        assert_eq!(what_is_missing(&found), Ok(()), "the variable is set; nobody may overrule it");
        assert!(found.configuration().is_err(), "and the start says so");
    }

    #[test]
    fn every_action_that_needs_a_server_says_so_in_one_sentence() {
        let source = AwaitingSetup::new(Catalog::of(Language::De));
        for answer in
            [source.sign_in(), source.sign_out(), source.open_folder(), source.open_baskets()]
        {
            let error = answer.expect_err("there is no server to ask");
            let sentence = error.user_text(Catalog::of(Language::De));
            assert!(!sentence.is_empty(), "a refusal without a sentence is a dead end");
        }
        // And the set-up is exactly what does work.
        assert!(source.setup().is_some(), "the wizard is the whole point of this source");
        assert!(source.log(None, 10).unwrap().is_empty());
    }
}
