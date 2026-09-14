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

    /// What the set-up wizard shows (ADR-D13): every value with its origin, and what is already
    /// done.
    ///
    /// `None` means: this source knows nothing about a set-up. That is not a state a shipped
    /// build has — it is the marker for a wiring that does not implement this yet, and the window
    /// then says that the set-up cannot be opened here instead of showing an empty wizard.
    fn setup(&self) -> Option<SetupView> {
        None
    }

    /// Takes the values of the wizard's input pages. Returns immediately, like everything here.
    ///
    /// **The source decides, not the page.** A value for a field the source reported as
    /// [`Fixed::Operator`] is to be discarded there: the environment wins for every value
    /// (ADR-D13 §1), and a page cannot be the place where that is enforced — it is the side that
    /// could be got wrong.
    fn apply_setup(&self, _values: &SetupValues) -> Result<(), DisplayError> {
        Err(DisplayError::SetupNotAvailable)
    }

    /// The last page of the wizard was reached — `setup.completed` may be written.
    ///
    /// Reached, not succeeded (ADR-D13 §11): a device that is waiting for its approval has
    /// finished its set-up honestly, and a wizard that reopened at every login would nag the one
    /// person who can do least about it.
    fn complete_setup(&self) -> Result<(), DisplayError> {
        Err(DisplayError::SetupNotAvailable)
    }

    /// Whether the macOS extension is switched on — **the last known answer, at once**.
    ///
    /// The question itself (`DomainManagement::domain()`, `DomainDetails.enabled`) must not be
    /// asked from here: it runs off the user-interface thread under the existing deadline, and a
    /// timeout counts as "not on yet", never as an error (ADR-D13 §9). A source that has not
    /// asked yet answers [`ExtensionState::Asking`]; the page asks again every two seconds.
    fn extension_state(&self) -> ExtensionState {
        ExtensionState::Asking
    }

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

/// What the set-up wizard has to show (ADR-D13).
///
/// One value per thing the wizard can ask about, each with the reason why it may **not** be asked
/// about here ([`SetupField`]) — and three places that are only ever shown. Which pages the
/// wizard then has is worked out from this and nowhere else: a page all of whose values are fixed
/// is not a step (ADR-D13 §3), and its values stand as facts on the first page instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupView {
    /// Why the wizard is open.
    pub reason: SetupReason,
    /// Where the documents come from.
    pub api_base: SetupField,
    /// Where the sign-in happens.
    pub auth_base: SetupField,
    /// The web interface — every address the server offers is measured against it
    /// (`edms_wire::basics::is_below`).
    pub app_base: SetupField,
    /// Whether the three above are **one** question on this workstation (ADR-D13, correction of
    /// 2026-09-14).
    ///
    /// `true` when they carry the same text through the same channel — then the page shows one
    /// field, and the one answer travels back in all three of [`SetupValues`]'s address members.
    /// `false` the moment they differ, and then the page shows the three above as they are: an
    /// administrator who set only one of the variables has said something the wizard is not
    /// allowed to average away.
    ///
    /// The judgement is made in `crate::setup::Resolution::one_address` and not in the page: the
    /// page renders what it is told, and the rule has a test on the side that can have one.
    pub one_address: bool,
    /// What the one address field stands prefilled with when no channel carries an address at
    /// all — and `None` whenever one does.
    ///
    /// **Never a value that holds.** It is `crate::setup::DEVELOPMENT_BASE`, elasticdms's own
    /// development server, put there while the product is unreleased; the resolution reports no
    /// address, the configuration still refuses to be built, and this becomes a setting of this
    /// workstation only if a human being walks the address page and presses Next there. That
    /// constant's documentation carries the rest of the argument, including what it costs and
    /// when it goes.
    pub suggested_base: Option<String>,
    /// The address the page recognises under the address field: for as long as the field carries
    /// it, the sentence `setup.server.development` stands beneath it.
    ///
    /// The same constant as above, and a second member all the same, because the two say
    /// different things. [`Self::suggested_base`] is an offer and is made **once**, to a
    /// workstation nobody has told an address; this one is a fact about the build and does not go
    /// away when the offer is taken. Tying the sentence to the offer meant it was never read: the
    /// address was stored on the first Next, the next view offered nothing any more, and the
    /// page that finally showed the address showed it as an ordinary value with nothing under it
    /// (MEASURED on 2026-09-14; view.js, `showSuggestion` carries the measurement).
    ///
    /// `None` says this build knows no such address — which is what a released one will say, when
    /// `crate::setup::DEVELOPMENT_BASE` and this member go together.
    pub development_base: Option<String>,
    /// The name this workstation shows in the console.
    pub device_name: SetupField,
    /// Where the mirror lies. Windows only — on macOS the root is named by File Provider and
    /// lies under `~/Library/CloudStorage/` (ADR-D13, measurement 5).
    pub mirror_path: SetupField,
    /// The language of the user interface, as a tag (`de`, `en`).
    pub language: SetupField,
    /// The code from the console. Its `value` is always empty: it is never stored (ADR-D13 §6),
    /// and only [`SetupField::fixed`] says whether the device was given one.
    pub enrollment_code: SetupField,
    /// Where the local state lies — shown, never offered (the setting table lies at the end of
    /// this path).
    pub data_path: String,
    /// The scratch area — shown, never offered.
    pub staging_path: String,
    /// The holding directory — shown, never offered.
    pub holding_path: String,
    /// Whether this device is registered with the archive. It decides whether the wizard asks
    /// for an enrolment code at all.
    pub enrolled: bool,
    /// macOS: whether the extension is switched on.
    pub extension: ExtensionState,
}

/// One value of the set-up: what holds today, and whether the user may change it here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupField {
    /// The value that holds — the effective one, whatever its origin.
    pub value: String,
    /// Why it is not a field. [`Fixed::No`]: it is one.
    pub fixed: Fixed,
}

impl SetupField {
    /// A value the user may change.
    pub fn open(value: impl Into<String>) -> Self {
        Self { value: value.into(), fixed: Fixed::No }
    }

    /// A value somebody else has decided.
    pub fn fixed(value: impl Into<String>, fixed: Fixed) -> Self {
        Self { value: value.into(), fixed }
    }

    /// Whether the wizard offers this value.
    pub fn is_open(&self) -> bool {
        self.fixed == Fixed::No
    }
}

/// Why a value stands in the wizard as a line of text and not as a field.
///
/// Each of the four carries its own sentence in the catalogue, and none of them names the
/// variable: `EDMS_API_BASE` is an operator surface and belongs in `doctor` (ADR-D13 §3). There
/// is deliberately no "greyed-out field" — a disabled field is a field that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Fixed {
    /// Not fixed at all: an input field.
    No,
    /// The administrator set the variable. To set it is to fix it (ADR-D13 §1).
    Operator,
    /// Spent: the device is registered under this name.
    Enrolled,
    /// The root of the mirror is not this window's to move.
    ///
    /// Two ways to get here, one sentence: on Windows because the mirror already stands in this
    /// place and a root left behind is worse than a path that stays; off Windows because the File
    /// Provider names the root and puts it under `~/Library/CloudStorage/` (ADR-D13,
    /// measurement 5) — there the value decides nothing, and the field is not even in the page
    /// (`window::MIRROR`). Saying it here is what makes the source discard a value for it, which
    /// is where §1 has to be enforced.
    Mirror,
    /// Only the installation decides this — the data path, the scratch area, the holding
    /// directory (ADR-D13 §6).
    Variable,
}

/// Why the wizard is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetupReason {
    /// This device has never been walked through to the end.
    First,
    /// The counterpart changed (ADR-D13 §4): the mirror and the session were given up, and the
    /// first page says so. Never a quiet re-point.
    Counterpart,
    /// The user opened it from the window. Then nothing is wrong and nothing is said about it.
    ByHand,
}

/// Whether the macOS File Provider extension is switched on.
///
/// Three states and no error state: a timeout on the question is read as "not on yet"
/// (ADR-D13 §9), because the page says the same thing either way and a dialog about
/// `NSFileProviderErrorDomain` would be a sentence nobody can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExtensionState {
    /// `userEnabled` is true: the folder works.
    On,
    /// Not switched on yet — and what a timeout counts as.
    Off,
    /// Not asked yet. The question runs off the user-interface thread; until the answer is there
    /// the page says that it is asking.
    Asking,
}

/// What the user typed into the wizard.
///
/// Every value is optional, because the page sends only what it offered. A value for a field the
/// source reported as fixed is to be discarded by the source — see
/// [`DisplaySource::apply_setup`]. The enrolment code travels in here and goes no further than
/// the engine: it is not stored (ADR-D13 §6).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupValues {
    /// Where the documents come from.
    pub api_base: Option<String>,
    /// Where the sign-in happens.
    pub auth_base: Option<String>,
    /// The web interface.
    pub app_base: Option<String>,
    /// The name in the console.
    pub device_name: Option<String>,
    /// Where the mirror lies (Windows).
    pub mirror_path: Option<String>,
    /// The language tag of the user interface.
    pub language: Option<String>,
    /// The code from the console, for this one registration.
    pub enrollment_code: Option<String>,
}

/// Written out by hand, for the one field.
///
/// This module took deliberate care that the enrolment code is not a [`Value`] and has no setting
/// key, "so no loop over the values can print it" — and then a derived `Debug` would have been
/// the one way left: a `tracing::debug!(?values)` somebody adds later, or a panic message, would
/// put a one-time secret from the console into the diagnostic log. No call site does that today;
/// the type is what has to make it impossible.
///
/// [`Value`]: edms_engine::config::Value
impl std::fmt::Debug for SetupValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupValues")
            .field("api_base", &self.api_base)
            .field("auth_base", &self.auth_base)
            .field("app_base", &self.app_base)
            .field("device_name", &self.device_name)
            .field("mirror_path", &self.mirror_path)
            .field("language", &self.language)
            .field("enrollment_code", &self.enrollment_code.as_ref().map(|_| "<given>"))
            .finish()
    }
}

impl SetupValues {
    /// The length of the first value longer than `limit` characters, or `None`.
    ///
    /// Characters, not bytes: the page counts what the user typed, and a name with umlauts in it
    /// would otherwise be refused at a length the field itself accepted.
    pub fn longest_over(&self, limit: usize) -> Option<usize> {
        [
            &self.api_base,
            &self.auth_base,
            &self.app_base,
            &self.device_name,
            &self.mirror_path,
            &self.language,
            &self.enrollment_code,
        ]
        .into_iter()
        .flatten()
        .map(|value| value.chars().count())
        .find(|length| *length > limit)
    }
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
    /// This source knows no set-up ([`DisplaySource::setup`] answered `None`).
    ///
    /// A gap marker, not a state of the world: in a build whose wiring implements the set-up this
    /// cannot occur. Until it does, a click on "Set-up" says so in one sentence instead of
    /// opening an empty wizard.
    #[error("this display source knows no set-up; the wizard cannot be opened")]
    SetupNotAvailable,
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
            Self::SetupNotAvailable => catalogue.text(key::SETUP_NOT_AVAILABLE).to_owned(),
        }
    }
}
