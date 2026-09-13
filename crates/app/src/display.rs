//! The seam between the user interface and the engine: what icon and window show, and where a
//! click goes.
//!
//! The user-interface shell does not know the engine (README, crate layout: the app is the only
//! place where the crates know each other — and even there only in one place). It knows only
//! [`DisplaySource`]. The wiring implements the trait over the engine; until then there is
//! [`crate::demo::DemoSource`], so that the user interface runs and can be tested already.
//!
//! **Everything here runs on the user-interface thread.** Every method has to return immediately:
//! a call that waits on the network freezes menu and window, and on macOS the system then marks
//! the app as "not responding". Long work (device flow, signing out at the server) is started by
//! the source in the background, and the result is reported through the waker from
//! [`DisplaySource::observe`].

use std::path::PathBuf;

use edms_core::log::LogEntry;
use edms_i18n::{Catalog, key};
use serde::{Deserialize, Serialize};

/// Who delivers the state to the user interface and carries out its clicks.
///
/// Implemented by the wiring (over the engine) and by [`crate::demo::DemoSource`].
pub trait DisplaySource: Send + Sync {
    /// The state for status line, icon and window header. Cheap: read on every wake.
    fn state(&self) -> DisplayState;

    /// Rows of the usage log, **newest first**, only with an identifier smaller than `before_id`
    /// (`None`: from the newest on), at most `count` of them.
    ///
    /// The identifier is strictly increasing in the order of writing; it is the cursor for "load
    /// older". Two guarantees are the source's, not the user interface's:
    ///
    /// * **Rows belong to the account** (ADR-D07, requirement 4): another user on the same machine
    ///   does not see them.
    /// * **Redacted rows arrive redacted** ([`LogEntry::redacted`]); the user interface never gets
    ///   to see an erased name, not even briefly.
    ///
    /// A read error is an error and not an empty list — the window would otherwise show "nothing
    /// has happened yet", and that would be exactly the plausible untruth this house forbids.
    fn log(
        &self,
        before_id: Option<i64>,
        count: usize,
    ) -> Result<Vec<(i64, LogEntry)>, DisplayError>;

    /// Starts the sign-in (device flow, ADR-D03). Returns immediately; the code appears
    /// afterwards in [`DisplayState::login_code`].
    fn sign_in(&self) -> Result<(), DisplayError>;

    /// Signs out and clears the mirror (ADR-D03, point 5). Returns immediately.
    fn sign_out(&self) -> Result<(), DisplayError>;

    /// Opens the root of the mirror in Explorer or Finder.
    fn open_folder(&self) -> Result<(), DisplayError>;

    /// Opens the mail baskets inside the mirror — the drop target for new documents
    /// (namespace v2 §3, ADR-D08 amended).
    fn open_baskets(&self) -> Result<(), DisplayError>;

    /// Registers a waker that the source calls after every change to state or log — from any
    /// thread at all. The user interface then reads [`Self::state`] and the loaded rows afresh;
    /// that way a name that has just been redacted disappears from an already open window too.
    fn observe(&self, waker: Waker);

    /// The last act before the process ends: stop work in flight and clear the traces.
    ///
    /// `tao`'s event loop never returns from `run` — it exits the process (`ControlFlow::Exit`),
    /// and **no** `Drop` runs while it does. Without this call the rendezvous file with the port
    /// and secret of a channel that no longer exists would stay behind on macOS, and the extension
    /// would run into a timeout instead of into "the app is not running".
    ///
    /// The default does nothing: a source without background work (the demo) has nothing to
    /// clear.
    fn stop(&self) {}
}

/// A callback "something has changed", callable from any thread.
pub type Waker = Box<dyn Fn() + Send + Sync>;

/// What icon, menu and window header show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayState {
    /// Display name of the signed-in (or last signed-in) account.
    pub account: Option<String>,
    /// The state of the session.
    pub status: Status,
    /// The root of the mirror, if it is set up.
    pub folder: Option<PathBuf>,
    /// The mail basket folder inside the mirror, if the mirror stands.
    pub baskets: Option<PathBuf>,
    /// The device flow in progress, for as long as it waits on the user.
    pub login_code: Option<LoginCode>,
    /// The last sentence the source has to say to the user — a hint from the engine
    /// ([`edms_engine::EngineEvent::Hint`]) or the reason why there is no folder on this machine.
    ///
    /// It stands in the status line **next to** the state and never replaces it: "signed in as
    /// Erika Mustermann" stays true even when something just went wrong. It arrives ready to
    /// read, in the user's language — the engine takes it from the same catalogue. It stays until
    /// a new hint arrives or the user does something themselves — "disappearing must not be
    /// silent" (requirement 6) would not be met by a sentence that is gone after two seconds.
    pub hint: Option<String>,
}

/// The state of the session — one status line in the menu, one dot on the icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    /// Nobody is signed in; the mirror is empty.
    NotSignedIn,
    /// The device is registered but not approved yet (geraete-auth: `SOFTWARE` usually means
    /// `pending_admin_approval`; ADR-D03 point 1). Signing in only works after that.
    AwaitingApproval,
    /// Signed in and connected.
    SignedIn,
    /// The session has expired (Q-4, ADR-D03 consequences): the tree stays visible, opening
    /// fails, the icon shows it — never a silent emptying of the tree.
    LoginRequired,
    /// The server is not reachable.
    Offline,
    /// A signature or key problem (Q-8): the new key set was rejected, the client carries on
    /// reading, IT has to be told.
    SecurityWarning,
}

/// A device flow in progress (RFC 8628), as the user has to see it.
///
/// the brief said `anmeldecode: Option<(String, String)>` — here a struct with two
/// extra fields. A pair of two strings can be swapped silently (the address would then stand as
/// the code in the window), and the four-character anchor is part of the anti-phishing defence
/// (geraete-auth, Device Authorization: "der Vier-Zeichen-Anker steht auf dem Panel und im
/// Dialog" — the four-character anchor stands on the panel and in the dialog; contract extract
/// Q-3: show it in the window). Without it in the window one of the three defences would be
/// silently weakened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginCode {
    /// `user_code`, e.g. `WQPX-7TRM` — large in the window.
    pub user_code: String,
    /// `verification_uri` — the address to type on another device.
    pub address: String,
    /// `verification_uri_complete` — the address with the code already filled in; the "open
    /// sign-in page" button takes it when it exists.
    pub address_complete: Option<String>,
    /// `urn:elasticdms:anchor`, e.g. `K7-M4` — has to read exactly the same on the confirmation page.
    pub anchor: Option<String>,
}

/// Which of the two folders an action was about.
///
/// A value, not a piece of text: the sentence about it is in the catalogue, and a `&'static str`
/// here would be that sentence in one language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The mirror.
    Mirror,
    /// The mail baskets inside the mirror (namespace v2 §3).
    Baskets,
}

/// Why an action of the user interface was not carried out.
///
/// Two faces, like every error in this house (`edms_engine::error`): `Display` is the diagnostic
/// sentence for the log and stays English, [`DisplayError::user_text`] is the whole sentence the
/// window shows, in the user's language.
///
/// [`Self::NotPossible`] is the exception and carries its sentence: it comes out of the engine,
/// which has already put it into the user's language ([`edms_engine::EngineError::user_text`]).
/// Translating it a second time would mean translating a sentence, and only values can be
/// translated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisplayError {
    /// The action does not fit the state, e.g. "you are already signed in". Already a whole
    /// sentence in the user's language.
    #[error("{0}")]
    NotPossible(String),
    /// The mirror, or the mail basket folder in it, is not set up.
    #[error("{0:?} is not set up on this device")]
    NotProvisioned(Place),
    /// The operating system could not open something.
    #[error("`{target}` could not be opened: {reason}")]
    Open {
        /// What was to be opened.
        target: String,
        /// The operating system's message.
        reason: String,
    },
    /// The usage log is not readable.
    ///
    /// [`crate::demo::DemoSource`] reads from memory and cannot fail doing so. The wiring over
    /// `edms-store` (SQLite) very much can, and the user interface then has to show an error
    /// instead of "nothing has happened yet" — the plausible untruth this house forbids.
    #[error("the usage log could not be read: {0}")]
    Log(String),
    /// A sign-in address no browser gets (see `event_loop::check_login_address`).
    #[error("the sign-in address `{0}` will not be opened: only https:// is allowed")]
    LoginAddress(String),
}

impl DisplayError {
    /// The whole sentence for the window, in the catalogue's language.
    pub fn user_text(&self, catalogue: &Catalog) -> String {
        match self {
            Self::NotPossible(sentence) => sentence.clone(),
            Self::NotProvisioned(Place::Mirror) => {
                catalogue.text(key::ERROR_FOLDER_NOT_PROVISIONED).to_owned()
            }
            Self::NotProvisioned(Place::Baskets) => {
                catalogue.text(key::ERROR_BASKETS_NOT_PROVISIONED).to_owned()
            }
            Self::Open { target, reason } => {
                catalogue.format(key::ERROR_OPEN_FAILED, &[("target", target), ("reason", reason)])
            }
            Self::Log(reason) => catalogue.format(key::ERROR_LOG_UNREADABLE, &[("reason", reason)]),
            Self::LoginAddress(address) => {
                catalogue.format(key::ERROR_LOGIN_ADDRESS, &[("address", address)])
            }
        }
    }
}
