//! The wiring: [`DisplaySource`] over the engine.
//!
//! Here the user-interface shell meets the finished work. The shell knows only [`DisplaySource`];
//! this module is the only place where `edms-engine`, `edms-store`, `edms-net`, `edms-crypto` and
//! the platform layer come together.
//!
//! ## The order of construction is not free
//!
//! It stands this way in the module header of `edms_engine::engine` and is kept here:
//!
//! ```text
//! configuration → store → keychain (the vault!) → connection → server access
//!               → Engine::start → platform::connect(engine.source()) → set_file_system
//!               → sign in
//! ```
//!
//! `edms_net::Connection` requires the device identifier and `ServerAccess` the key source —
//! neither exists before the keychain. The platform requires the
//! [`edms_core::port::NamespaceSource`] before it registers with the operating system; the engine
//! requires the [`edms_core::port::FileSystem`] only once it has changes to report.
//!
//! ## Everything here returns immediately
//!
//! Every method of [`DisplaySource`] runs on the user-interface thread. `Engine::sign_out` blocks
//! deliberately until everything has been cleared — which is why it runs on a thread of its own
//! here, and the result comes back through the waker. A menu that freezes during sign-out is
//! reported by macOS as "not responding".
//!
//! ## What the engine calls and what the app makes of it
//!
//! | Event | App |
//! |---|---|
//! | [`EngineEvent::OpenBrowser`] | `open::that_detached` after the same check as in the window (`event_loop::check_login_address`) |
//! | [`EngineEvent::Hint`] | the status line **and**, where a kind of the core labels it honestly, one row in the usage log |
//! | [`EngineEvent::StateChanged`] | read icon, menu and window afresh |
//! | [`EngineEvent::LogGrown`] | reload the list |
//! | [`EngineEvent::InboxProgress`] | the status line ("… files from the mail baskets") |
//! | [`EngineEvent::CommandApplied`] | the status line; the engine writes the log row itself |
//!
//! **Never with a subject.** Every row that comes into being here is a [`LogEntry::plain`] — a
//! row without a name, without a document, without a location. An erasure hint ("erased by
//! order") therefore carries no subject, not even by accident: there is no parameter through
//! which one could get in.
//!
//! **Every sentence comes ready to read.** The engine puts its hints into the user's language
//! itself (`EngineConfiguration::language`); what this module adds comes out of the same
//! catalogue. Nothing here is translated twice.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use edms_core::log::{LogEntry, LogKind};
use edms_engine::config::ConfigurationError;
use edms_engine::{
    Engine, EngineConfiguration, EngineError, EngineEvent, EngineState, KeyBundle, ServerObject,
    StoreVault, Vault,
};
use edms_i18n::{Catalog, key};
use edms_net::{Connection, ServerAccess};
use edms_store::Store;

use crate::display::{DisplayError, DisplaySource, DisplayState, LoginCode, Status, Waker};
use crate::platform::Platform;
use crate::time::now;
use crate::vault::SystemVault;

/// Environment variable for choosing the vault.
pub const VAR_VAULT: &str = "EDMS_VAULT";

/// Value of [`VAR_VAULT`] for the operating system's keychain (the default).
pub const VAULT_KEYCHAIN: &str = "keychain";

/// Value of [`VAR_VAULT`] for a vault in memory.
pub const VAULT_MEMORY: &str = "memory";

/// The numbers of the hint rows start here.
///
/// The store's numbers are SQLite row ids: they start at 1 and grow by one per row, trimmed per
/// account to `LOG_PER_ACCOUNT` — they never reach this order of magnitude. Because the list pages
/// **by descending number**, the app's rows have to lie above every row of the store; otherwise
/// they would appear between the old ones instead of at the top.
const HINT_BASE: i64 = 1 << 62;

/// This many hints the app keeps; older ones fall away.
///
/// They live in memory only: the database belongs to the engine, and a second writer would be a
/// second owner. After a restart they are gone — what has to stay the engine writes itself.
const HINT_MAX: usize = 20;

/// Why the app could not start. Every sentence names what to do.
///
/// Read on the error output by whoever set the workstation up, before there is a window at all —
/// an operator surface, and therefore English like every other diagnostic in this house.
#[derive(Debug, thiserror::Error)]
pub enum StartupAbort {
    /// A mandatory variable is missing, or two paths point at the same place.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// The value of [`VAR_VAULT`] is none of the permitted ones.
    #[error(
        "`{0}` is not a known vault. {VAR_VAULT} takes `{VAULT_KEYCHAIN}` (the operating \
         system's keychain) or `{VAULT_MEMORY}` (development runs only; device and session are \
         gone once the program ends)"
    )]
    VaultChoice(String),
    /// A directory could not be created.
    #[error("`{path}` could not be set up: {reason}")]
    Directory {
        /// Which directory.
        path: PathBuf,
        /// What the operating system reports.
        reason: String,
    },
    /// The local state could not be opened.
    #[error(transparent)]
    Store(#[from] edms_store::StoreError),
    /// The server addresses are not usable.
    #[error("the server addresses are not usable: {0}")]
    Connection(#[from] edms_net::ConnectionError),
    /// The engine itself.
    #[error(transparent)]
    Engine(#[from] EngineError),
}

/// The engine behind the user interface.
pub struct EngineView {
    engine: Arc<Engine>,
    inner: Arc<Inner>,
    mirror_path: PathBuf,
    /// The mail basket folder **inside** the mirror — the drop target since namespace v2 §5.
    /// Computed, not configured: the platform layer creates it from the same catalogue name.
    baskets_path: PathBuf,
    /// The reason why there is no folder on this machine; `None` when there is one.
    without_folder: Option<String>,
    /// Held until [`DisplaySource::stop`] clears it.
    platform: Mutex<Option<Platform>>,
}

impl std::fmt::Debug for EngineView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineView")
            .field("state", &self.engine.state_now().label())
            .field("without_folder", &self.without_folder)
            .finish_non_exhaustive()
    }
}

/// What the user interface and the listener thread share.
///
/// No `Debug`: a waker is a callback into the event loop and has no representation.
#[derive(Default)]
struct View {
    waker: Vec<Arc<dyn Fn() + Send + Sync>>,
    hint: Option<String>,
    rows: VecDeque<(i64, LogEntry)>,
    next: i64,
}

struct Inner {
    view: Mutex<View>,
    /// Every sentence of this run, in the language of this workstation.
    catalogue: &'static Catalog,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let view = self.lock();
        f.debug_struct("Inner")
            .field("waker", &view.waker.len())
            .field("notice", &view.hint)
            .field("rows", &view.rows.len())
            .finish()
    }
}

impl Inner {
    fn new(catalogue: &'static Catalog) -> Self {
        Self { view: Mutex::new(View { next: HINT_BASE, ..View::default() }), catalogue }
    }

    /// A poisoned mutex here only means: a thread crashed in the middle of an insert. The data is
    /// still the last valid state; carrying on is the right thing.
    fn lock(&self) -> MutexGuard<'_, View> {
        self.view.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Calls every waker — **outside** the lock, so that a waker reading the state does not wait
    /// on itself.
    fn wake(&self) {
        let waker = self.lock().waker.clone();
        for w in waker {
            w();
        }
    }

    fn hint(&self) -> Option<String> {
        self.lock().hint.clone()
    }

    fn set_hint(&self, text: Option<String>) {
        self.lock().hint = text;
    }

    /// Appends a row that exists only in this session.
    fn insert(&self, kind: LogKind, text: &str) {
        let mut view = self.lock();
        let number = view.next;
        view.next = view.next.saturating_add(1);
        // `plain` never carries a subject: a hint names no document, not even an erased one
        // (edms_core::log).
        let entry = LogEntry::plain(now(), kind, Some(text.to_owned()));
        view.rows.push_back((number, entry));
        while view.rows.len() > HINT_MAX {
            view.rows.pop_front();
        }
    }

    /// The hint rows, newest first, only with a number smaller than `before`.
    fn row_before(&self, before: Option<i64>, count: usize) -> Vec<(i64, LogEntry)> {
        self.lock()
            .rows
            .iter()
            .rev()
            .filter(|(number, _)| before.is_none_or(|v| *number < v))
            .take(count)
            .cloned()
            .collect()
    }
}

impl EngineView {
    /// Builds everything and signs in.
    ///
    /// A machine without a platform layer (a Windows that is too old, a macOS without an app
    /// bundle) is **no** reason not to start: the reason then stands in the status line, and
    /// signing in, the usage log and the diagnostics carry on.
    ///
    /// # Errors
    ///
    /// [`StartupAbort`] when configuration, store, keychain or engine are not up.
    pub fn start(configuration: EngineConfiguration) -> Result<Self, StartupAbort> {
        let catalogue = Catalog::of(configuration.language);
        let mirror_path = configuration.mirror_path.clone();
        let baskets_path =
            mirror_path.join(edms_core::namespace::name_baskets(configuration.language));
        let engine = Arc::new(build_engine(configuration)?);

        let (platform, without_folder) =
            match crate::platform::connect(engine.source(), engine.intake(), &mirror_path) {
                Ok(platform) => {
                    engine.set_file_system(platform.file_system());
                    (Some(platform), None)
                }
                Err(abort) => {
                    tracing::warn!(%abort, "no folder on this device");
                    (None, Some(abort.user_text(catalogue)))
                }
            };

        let view = Self {
            engine: Arc::clone(&engine),
            inner: Arc::new(Inner::new(catalogue)),
            mirror_path,
            baskets_path,
            without_folder,
            platform: Mutex::new(platform),
        };
        start_listener(Arc::clone(&engine), Arc::clone(&view.inner));
        if let Err(error) = engine.sign_in() {
            tracing::warn!(%error, "the sign-in was not started");
            view.inner.set_hint(Some(error.user_text(catalogue)));
        }
        Ok(view)
    }
}

/// Builds store, keychain, connection, server access and engine — in that order.
///
/// `doctor` takes this route too: a report from an engine built differently would be a report about
/// a different program.
///
/// # Errors
///
/// [`StartupAbort`] naming the step that did not work.
pub fn build_engine(configuration: EngineConfiguration) -> Result<Engine, StartupAbort> {
    // The engine creates its directories itself — but only in `start`, and the store is opened
    // before that. Without this call `Store::open` would fail on the very first start.
    configuration.create_directories().map_err(|reason| StartupAbort::Directory {
        path: configuration.data_path.clone(),
        reason: reason.to_string(),
    })?;
    let mut store = Store::open(&configuration.data_path)?;
    let hardware = crate::device_key::of_this_platform();
    let bundle = KeyBundle::set_up(choose_vault()?, &mut store, hardware.as_deref())?;
    let connection = Connection::new(
        &configuration.api_base,
        &configuration.auth_base,
        bundle.device(),
        env!("CARGO_PKG_VERSION"),
    )?;
    let server: Arc<dyn ServerObject> =
        Arc::new(ServerAccess::new(connection, bundle.as_source())?);
    Ok(Engine::start(configuration, server, store, bundle)?)
}

/// Which vault holds the secrets.
///
/// The default is the operating system's keychain (ADR-D03, point 4). `memory` is there for
/// development runs — and says so out loud: whoever chooses it has no device and no session left
/// after quitting. There is no **silent** fallback; a vault that secretly wrote into a file when
/// the keychain was locked would be exactly the mistake ADR-D03 forbids.
fn choose_vault() -> Result<Box<dyn Vault>, StartupAbort> {
    let choice = std::env::var(VAR_VAULT).unwrap_or_default();
    match choice.trim() {
        "" => Ok(Box::new(SystemVault::new())),
        value if value == VAULT_KEYCHAIN => Ok(Box::new(SystemVault::new())),
        value if value == VAULT_MEMORY => {
            tracing::warn!(
                "{VAR_VAULT}={VAULT_MEMORY}: the device key and the refresh token live in memory \
                 only and are gone once the program ends."
            );
            Ok(Box::new(StoreVault::new()))
        }
        value => Err(StartupAbort::VaultChoice(value.to_owned())),
    }
}

/// Listens for the engine's events and carries them into the user interface.
///
/// A thread of its own, not a `tokio` task: the runtime belongs to the engine, and this thread sees
/// only the broadcast channel. `blocking_recv` is permitted here because the thread stands in no
/// runtime.
fn start_listener(engine: Arc<Engine>, inner: Arc<Inner>) {
    let started = std::thread::Builder::new()
        .name("edms-events".to_owned())
        .spawn(move || listen(&engine, &inner));
    if let Err(error) = started {
        // Without a listener thread the user interface would stay at the state of the start — it
        // would show "Loading …" while the engine has long since signed in.
        tracing::error!(%error, "the thread for the engine events could not be started.");
    }
}

fn listen(engine: &Arc<Engine>, inner: &Arc<Inner>) {
    let mut channel = engine.events();
    loop {
        match channel.blocking_recv() {
            Ok(event) => {
                handle(engine, inner, event);
                inner.wake();
            }
            // The buffer overflowed (the channel depth). What was lost stands in the state;
            // waking once catches everything up.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                tracing::debug!(count, "events skipped; the state is read afresh.");
                inner.wake();
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                tracing::debug!("the engine has closed the event channel.");
                return;
            }
        }
    }
}

fn handle(engine: &Arc<Engine>, inner: &Arc<Inner>, event: EngineEvent) {
    match event {
        EngineEvent::OpenBrowser(address) => open_browser(inner, &address),
        EngineEvent::Hint { text } => {
            tracing::info!(%text, "a hint from the engine");
            if let Some(kind) = hint_kind(&engine.state_now()) {
                inner.insert(kind, &text);
            }
            inner.set_hint(Some(text));
        }
        // The state carries itself; the wake in `listen` suffices. It belongs in the diagnostic
        // log all the same: whoever investigates a sign-in would otherwise see only what did
        // **not** happen, and would have to read the state off the menu.
        EngineEvent::StateChanged => {
            tracing::info!(state = engine.state_now().label(), "new state");
        }
        EngineEvent::LogGrown => {}
        EngineEvent::InboxProgress { open } => inner.set_hint(match open {
            0 => None,
            1 => Some(inner.catalogue.text(key::NOTICE_BASKET_PROGRESS_ONE).to_owned()),
            many => Some(
                inner
                    .catalogue
                    .format(key::NOTICE_BASKET_PROGRESS_MANY, &[("count", &many.to_string())]),
            ),
        }),
        // The engine writes the log row itself — and without a subject, because an erasure leaves
        // no name behind.
        EngineEvent::CommandApplied { kind } => {
            inner.set_hint(Some(kind.label(inner.catalogue).to_owned()));
        }
    }
}

/// Opens the sign-in page in the system browser — after the same check as in the window.
///
/// The engine has already checked the address against `EDMS_APP_BASE`; the second, independent
/// check (scheme and host) comes on top here, because `open::that_detached` passes the address on
/// to the operating system unchecked.
fn open_browser(inner: &Arc<Inner>, address: &str) {
    let result = crate::event_loop::check_login_address(address).and_then(|()| {
        open::that_detached(address).map_err(|error| DisplayError::Open {
            target: address.to_owned(),
            reason: error.to_string(),
        })
    });
    if let Err(error) = result {
        tracing::warn!(%error, "the sign-in page could not be opened.");
        inner.set_hint(Some(error.user_text(inner.catalogue)));
    }
}

/// Under which kind a hint stands in the list — `None` when no kind of the core labels it
/// **honestly**.
///
/// The hint itself carries only a sentence; its meaning stands in the state the engine holds
/// alongside it. A row comes into being only where the core's label is then true as well: a row
/// "connection lost" over a folder that could not be set up would be the plausible untruth this
/// house forbids.
///
/// `[GAP → PROPOSAL]` `edms_core::log::LogKind` knows no neutral kind "hint" (severity `Hint`,
/// label `log.hint`). With it **every** sentence of the engine would get its row; until then the
/// rest stands only in the status line and in the diagnostic log — visible, but not in the list.
fn hint_kind(state: &EngineState) -> Option<LogKind> {
    match state {
        // Nobody is signed in, and a hint in this state says why the sign-in did not come about.
        // "Sign-in required" is then true.
        EngineState::SignedOut
        | EngineState::EnrollmentCodeRequired
        | EngineState::LoginRequired { .. } => Some(LogKind::LoginRequired),
        // Signed in, but without a connection: that is exactly what the row says.
        EngineState::SignedIn { connected: false, .. } => Some(LogKind::ConnectionLost),
        EngineState::Starting
        | EngineState::AwaitingApproval { .. }
        | EngineState::LoginRuns { .. }
        | EngineState::SignedIn { connected: true, .. }
        | EngineState::Stopped => None,
    }
}

/// The engine's state, translated into what the user interface shows.
///
/// The fingerprint on "waiting for approval" is not decoration: without a human comparing it,
/// anyone who installs the software could enrol a device against the tenant (03 §6.2.4, residual
/// risk 17). It therefore stands in the sentence menu and window show — next to the procedural
/// documentation it is compared against. The client can only **show** it, not compare it.
fn interpret(
    state: &EngineState,
    catalogue: &Catalog,
) -> (Option<String>, Status, Option<LoginCode>, Option<String>) {
    match state {
        EngineState::Starting => (None, Status::NotSignedIn, None, None),
        EngineState::EnrollmentCodeRequired => (
            None,
            Status::NotSignedIn,
            None,
            Some(catalogue.text(key::NOTICE_ENROLLMENT_CODE_MISSING).to_owned()),
        ),
        EngineState::AwaitingApproval { fingerprint } => (
            None,
            Status::AwaitingApproval,
            None,
            Some(catalogue.format(key::NOTICE_AWAITING_APPROVAL, &[("fingerprint", fingerprint)])),
        ),
        EngineState::SignedOut => (None, Status::NotSignedIn, None, None),
        EngineState::LoginRuns { user_code, address, anchor } => (
            None,
            Status::NotSignedIn,
            Some(LoginCode {
                user_code: user_code.clone(),
                address: address.clone(),
                // The engine names exactly one address; it has already been checked against
                // `EDMS_APP_BASE`. Inventing a second, "complete" one would mean hanging the code
                // into an address the server never named that way.
                address_complete: None,
                anchor: anchor.clone(),
            }),
            None,
        ),
        EngineState::SignedIn { display_name, connected, .. } => (
            Some(display_name.clone()),
            if *connected { Status::SignedIn } else { Status::Offline },
            None,
            None,
        ),
        EngineState::LoginRequired { reason } => {
            (None, Status::LoginRequired, None, Some(reason.clone()))
        }
        EngineState::Stopped => {
            (None, Status::NotSignedIn, None, Some(catalogue.text(key::NOTICE_STOPPING).to_owned()))
        }
    }
}

/// An engine error as the user interface shows it: the engine's own sentence for the user, not its
/// diagnostic one.
fn as_display_error(error: &EngineError, catalogue: &Catalog) -> DisplayError {
    DisplayError::NotPossible(error.user_text(catalogue))
}

impl DisplaySource for EngineView {
    fn state(&self) -> DisplayState {
        let state = self.engine.state_now();
        let (account, status, login_code, state_hint) = interpret(&state, self.inner.catalogue);
        DisplayState {
            account,
            status,
            // No folder, no path: a button that opened a directory that does not exist would be
            // worse than a greyed-out one.
            folder: self.without_folder.is_none().then(|| self.mirror_path.clone()),
            // The baskets stand in the mirror; without a mirror there is no folder to open.
            baskets: self.without_folder.is_none().then(|| self.baskets_path.clone()),
            login_code,
            // The state takes precedence: it is always current, an event can be old. Last of all
            // the reason why there is no folder — that one holds for the whole run.
            hint: state_hint.or_else(|| self.inner.hint()).or_else(|| self.without_folder.clone()),
        }
    }

    fn log(
        &self,
        before_id: Option<i64>,
        count: usize,
    ) -> Result<Vec<(i64, LogEntry)>, DisplayError> {
        let mut rows = self.inner.row_before(before_id, count);
        let rest = count.saturating_sub(rows.len());
        if rest == 0 {
            return Ok(rows);
        }
        // While paging within the hint rows the store starts from the beginning again; its
        // numbers all lie below `HINT_BASE`.
        let before = match before_id {
            None => None,
            Some(v) if v >= HINT_BASE => None,
            // Before number 1 there is nothing left — and there is no negative number.
            Some(v) => match u64::try_from(v) {
                Ok(v) => Some(v),
                Err(_) => return Ok(rows),
            },
        };
        let page =
            self.engine.log(before, rest).map_err(|error| DisplayError::Log(error.to_string()))?;
        for row in page.rows {
            let number = i64::try_from(row.number).map_err(|_| {
                DisplayError::NotPossible(
                    self.inner
                        .catalogue
                        .format(key::ERROR_ROW_NUMBER, &[("number", &row.number.to_string())]),
                )
            })?;
            rows.push((number, row.entry));
        }
        Ok(rows)
    }

    fn sign_in(&self) -> Result<(), DisplayError> {
        let catalogue = self.inner.catalogue;
        match self.engine.state_now() {
            EngineState::SignedIn { .. } => Err(DisplayError::NotPossible(
                catalogue.text(key::ERROR_ALREADY_SIGNED_IN).to_owned(),
            )),
            EngineState::LoginRuns { .. } => Err(DisplayError::NotPossible(
                catalogue.text(key::ERROR_SIGN_IN_RUNNING).to_owned(),
            )),
            // Without approval the server refuses every sign-in (`403 device-pending-approval`);
            // an attempt would be a button that only fails.
            EngineState::AwaitingApproval { fingerprint } => Err(DisplayError::NotPossible(
                catalogue
                    .format(key::ERROR_AWAITING_APPROVAL_SIGN_IN, &[("fingerprint", &fingerprint)]),
            )),
            EngineState::Stopped => {
                Err(DisplayError::NotPossible(catalogue.text(key::NOTICE_STOPPING).to_owned()))
            }
            _ => {
                self.inner.set_hint(None);
                self.engine.sign_in().map_err(|error| as_display_error(&error, catalogue))
            }
        }
    }

    fn sign_out(&self) -> Result<(), DisplayError> {
        let catalogue = self.inner.catalogue;
        if !self.engine.state_now().is_signed_in() {
            return Err(DisplayError::NotPossible(
                catalogue.text(key::ERROR_NOBODY_SIGNED_IN).to_owned(),
            ));
        }
        self.inner.set_hint(Some(catalogue.text(key::NOTICE_SIGNING_OUT).to_owned()));
        let engine = Arc::clone(&self.engine);
        let inner = Arc::clone(&self.inner);
        // `Engine::sign_out` blocks deliberately until everything has been cleared
        // (requirement 4). On the user-interface thread that would be a frozen menu.
        let started =
            std::thread::Builder::new().name("edms-sign-out".to_owned()).spawn(move || {
                let hint = match engine.sign_out() {
                    Ok(()) => None,
                    Err(error) => {
                        tracing::warn!(%error, "the sign-out was not completed");
                        Some(error.user_text(catalogue))
                    }
                };
                inner.set_hint(hint);
                inner.wake();
            });
        match started {
            Ok(_) => Ok(()),
            Err(error) => {
                self.inner.set_hint(None);
                Err(DisplayError::NotPossible(
                    catalogue
                        .format(key::ERROR_SIGN_OUT_NOT_STARTED, &[("reason", &error.to_string())]),
                ))
            }
        }
    }

    fn open_folder(&self) -> Result<(), DisplayError> {
        if let Some(reason) = &self.without_folder {
            return Err(DisplayError::NotPossible(reason.clone()));
        }
        if !self.mirror_path.exists() {
            return Err(DisplayError::NotProvisioned(crate::display::Place::Mirror));
        }
        open(&self.mirror_path)
    }

    fn open_baskets(&self) -> Result<(), DisplayError> {
        // Not created here: the basket folder belongs to the platform layer, which places it from
        // the server's listing (namespace v2 §1). A directory of our own next to it would be a
        // second, empty folder that never takes a file in.
        if let Some(reason) = &self.without_folder {
            return Err(DisplayError::NotPossible(reason.clone()));
        }
        if !self.baskets_path.is_dir() {
            return Err(DisplayError::NotProvisioned(crate::display::Place::Baskets));
        }
        open(&self.baskets_path)
    }

    fn observe(&self, waker: Waker) {
        self.inner.lock().waker.push(Arc::from(waker));
    }

    fn stop(&self) {
        self.engine.stop();
        if let Some(mut platform) =
            self.platform.lock().unwrap_or_else(PoisonError::into_inner).take()
        {
            platform.stop();
        }
    }
}

/// Hands a path to Explorer or Finder.
fn open(path: &Path) -> Result<(), DisplayError> {
    open::that_detached(path).map_err(|error| DisplayError::Open {
        target: path.display().to_string(),
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The German catalogue — the sentences read here the way the user sees them.
    fn german() -> &'static Catalog {
        Catalog::of(edms_i18n::Language::De)
    }

    fn entries(inner: &Inner) -> Vec<(i64, LogEntry)> {
        inner.row_before(None, usize::MAX)
    }

    #[test]
    fn hint_rows_lie_above_every_row_number_of_the_store() {
        // The list pages by descending number. If the app's rows lay below, they would not appear
        // at the top but somewhere in the past.
        let inner = Inner::new(Catalog::of(edms_i18n::Language::De));
        inner.insert(LogKind::LoginRequired, "first");
        inner.insert(LogKind::LoginRequired, "second");
        let rows = entries(&inner);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].0 > rows[1].0, "newest first");
        assert!(rows.iter().all(|(number, _)| *number >= HINT_BASE));
    }

    #[test]
    fn a_hint_row_never_carries_a_subject() {
        // An erasure hint names no document either (edms_core::log): `plain` has no parameter
        // through which one could get in.
        let inner = Inner::new(Catalog::of(edms_i18n::Language::De));
        inner.insert(LogKind::LoginRequired, "Auf Anordnung entfernt");
        let mut rows = entries(&inner);
        let (_, entry) = rows.remove(0);
        assert!(entry.subject().is_none());
        assert_eq!(entry.detail(), Some("Auf Anordnung entfernt"));
    }

    #[test]
    fn the_list_of_hints_is_bounded_and_keeps_the_newest() {
        let inner = Inner::new(Catalog::of(edms_i18n::Language::De));
        for number in 0..HINT_MAX + 5 {
            inner.insert(LogKind::LoginRequired, &format!("number {number}"));
        }
        let rows = entries(&inner);
        assert_eq!(rows.len(), HINT_MAX);
        let newest = format!("number {}", HINT_MAX + 4);
        assert_eq!(rows[0].1.detail(), Some(newest.as_str()));
    }

    #[test]
    fn paging_keeps_to_the_number() {
        let inner = Inner::new(Catalog::of(edms_i18n::Language::De));
        inner.insert(LogKind::LoginRequired, "old");
        inner.insert(LogKind::LoginRequired, "new");
        let rows = entries(&inner);
        let before = rows[0].0;
        let next = inner.row_before(Some(before), 10);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].1.detail(), Some("old"));
        assert!(inner.row_before(Some(rows[1].0), 10).is_empty());
    }

    #[test]
    fn a_hint_gets_a_row_only_where_the_label_is_true() {
        assert_eq!(hint_kind(&EngineState::SignedOut), Some(LogKind::LoginRequired));
        assert_eq!(
            hint_kind(&EngineState::SignedIn {
                display_name: "E. M.".into(),
                tenant: "t_acme".into(),
                since: now(),
                connected: false,
            }),
            Some(LogKind::ConnectionLost)
        );
        // While a device flow is running, "Sign-in required" (`status.login_required`) would be
        // a statement against the visible state — better no row than a wrong one.
        assert_eq!(
            hint_kind(&EngineState::LoginRuns {
                user_code: "WQPX-7TRM".into(),
                address: "https://app.example/geraet".into(),
                anchor: None,
            }),
            None
        );
        assert_eq!(hint_kind(&EngineState::AwaitingApproval { fingerprint: "AB-CD".into() }), None);
    }

    #[test]
    fn the_fingerprint_stands_in_the_sentence_for_menu_and_window() {
        // 03 §6.2.4, residual risk 17: a human compares it with the procedural documentation.
        let (account, status, code, hint) =
            interpret(&EngineState::AwaitingApproval { fingerprint: "K7M4-2TQX".into() }, german());
        assert_eq!(account, None);
        assert_eq!(status, Status::AwaitingApproval);
        assert_eq!(code, None);
        let hint = hint.expect("without a fingerprint the approval would be blind");
        assert!(hint.contains("K7M4-2TQX"), "{hint}");
        assert!(hint.contains("Verfahrensdokumentation"), "{hint}");
    }

    #[test]
    fn a_running_device_flow_carries_code_address_and_anchor_into_the_display() {
        let (_, status, code, _) = interpret(
            &EngineState::LoginRuns {
                user_code: "WQPX-7TRM".into(),
                address: "https://app.example/geraet".into(),
                anchor: Some("K7-M4".into()),
            },
            german(),
        );
        assert_eq!(status, Status::NotSignedIn);
        let code = code.expect("a running flow has a code");
        assert_eq!(code.user_code, "WQPX-7TRM");
        assert_eq!(code.address, "https://app.example/geraet");
        assert_eq!(code.anchor.as_deref(), Some("K7-M4"));
    }

    #[test]
    fn without_a_connection_the_account_stays_and_the_status_becomes_offline() {
        // ADR-D03, consequences: "offline" is not "signed out" — the tree stays visible.
        let (account, status, _, _) = interpret(
            &EngineState::SignedIn {
                display_name: "Erika Mustermann".into(),
                tenant: "t_acme".into(),
                since: now(),
                connected: false,
            },
            german(),
        );
        assert_eq!(account.as_deref(), Some("Erika Mustermann"));
        assert_eq!(status, Status::Offline);
    }

    #[test]
    fn an_unknown_vault_name_is_refused_and_names_the_permitted_ones() {
        let error = StartupAbort::VaultChoice("file".to_owned()).to_string();
        assert!(error.contains(VAULT_KEYCHAIN), "{error}");
        assert!(error.contains(VAULT_MEMORY), "{error}");
        assert!(error.contains(VAR_VAULT), "{error}");
    }
}
