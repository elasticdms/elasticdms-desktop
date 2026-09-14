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
use edms_engine::config::{ConfigurationError, Value};
use edms_engine::session::{SETTING_ENROLLED, SETTING_KEY_SET};
use edms_engine::{
    Engine, EngineConfiguration, EngineError, EngineEvent, EngineState, KeyBundle, ServerObject,
    StoreVault, Vault,
};
use edms_i18n::{Catalog, key};
use edms_net::{Connection, ServerAccess};
use edms_store::Store;

use crate::display::{
    DisplayError, DisplaySource, DisplayState, ExtensionState, Fixed, LoginCode, SetupField,
    SetupReason, SetupValues, SetupView, Status, Waker,
};
use crate::platform::Platform;
use crate::setup::{Addresses, Counterpart, Resolution, SettingRefused};
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
    /// This device is enrolled against another server, and the sign-out from it did not start.
    ///
    /// The start aborts here rather than carrying on: carrying on would mean a mirror of the old
    /// tenant's documents lying open on a machine that now speaks to a different server, which is
    /// exactly the quiet re-point ADR-D13 §4 exists to prevent.
    #[error(
        "this device is enrolled against `{stored}` and is configured for `{now}` now; the \
         sign-out from the old server did not start, and the folder is not cleared until it does: \
         {reason}"
    )]
    Counterpart {
        /// The API this device enrolled against.
        stored: String,
        /// The API it is pointed at now.
        now: String,
        /// What went wrong on the way there.
        reason: String,
    },
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
    /// The `setting` table for the set-up — a second connection to the same file.
    ///
    /// The store is in WAL mode exactly so that a second reader can stand beside the writer
    /// (`edms_store`, module header), and `setup::resolve` already opens one at every start. It
    /// is held rather than opened per click because every method of [`DisplaySource`] runs on the
    /// user-interface thread and has to answer at once; opening a database file per render of the
    /// wizard would be a file operation in that path.
    settings: Mutex<Store>,
    /// What macOS last said about the extension, and whether a question is on its way.
    extension: Arc<ExtensionWatch>,
}

/// The last answer to "is the folder switched on?", and one question at a time.
///
/// ADR-D13 §9: the question runs off the user-interface thread and a timeout counts as "not on
/// yet". The page asks every two seconds while its step is open; without the flag every one of
/// those would start a thread of its own against a call that may sit for the whole deadline.
///
/// Empty off macOS, and behind a `cfg` rather than behind an unread field: there is no extension
/// to switch on there, the page that would ask is not in the binary (`window::EXTENSION`), and a
/// mutex nobody reads is a mutex the next reader has to work out the meaning of.
#[derive(Debug, Default)]
struct ExtensionWatch {
    #[cfg(target_os = "macos")]
    answered: Mutex<Option<bool>>,
    #[cfg(target_os = "macos")]
    asking: std::sync::atomic::AtomicBool,
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
        // Before the engine is built, and only here: `doctor` goes through `build_engine` and must
        // change nothing (ADR-D13 §4).
        let mut store = open_state(&configuration)?;
        if let Counterpart::Changed(old) = crate::setup::counterpart_of(&store, &configuration)? {
            drop(store);
            start_afresh(&configuration, &old)?;
            store = open_state(&configuration)?;
            crate::setup::note_counterpart_changed(&mut store, &old)?;
        }
        crate::setup::remember_counterpart(&mut store, &configuration)?;
        // Before the engine takes the first connection: the set-up's own, to the same file. See
        // the field's comment for why it is held and not opened per click.
        let settings = open_state(&configuration)?;
        let engine = Arc::new(build_with(configuration, store)?);

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
            settings: Mutex::new(settings),
            extension: Arc::new(ExtensionWatch::default()),
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
/// a different program. What `doctor` does **not** take is the counterpart seal: a diagnosis reads
/// and changes nothing, and signing a workstation out is not a reading.
///
/// # Errors
///
/// [`StartupAbort`] naming the step that did not work.
pub fn build_engine(configuration: EngineConfiguration) -> Result<Engine, StartupAbort> {
    let store = open_state(&configuration)?;
    build_with(configuration, store)
}

/// The local state, with the directories that have to exist before it can be opened.
///
/// The engine creates its directories itself — but only in `start`, and the store is opened before
/// that. Without this call `Store::open` would fail on the very first start.
///
/// `[GAP → PROPOSAL]` The store is opened three times on a real start: once by `setup::resolve`,
/// which has to read the settings before it knows the three addresses, once here for the engine,
/// and once more for the set-up's own reading and writing (`EngineView::settings`). It is one
/// SQLite file in WAL mode, which is what makes that possible at all (`edms_store`, module
/// header), and the third is deliberate — it outlives this call, where the engine's does not.
/// ADR-D13 §7 wants `build_engine` to take an already open store instead of opening its own; that
/// means a changed signature at `EngineView::start`'s caller, which belongs to whoever owns the
/// event loop.
fn open_state(configuration: &EngineConfiguration) -> Result<Store, StartupAbort> {
    configuration.create_directories().map_err(|reason| StartupAbort::Directory {
        path: configuration.data_path.clone(),
        reason: reason.to_string(),
    })?;
    Ok(Store::open(&configuration.data_path)?)
}

/// The rest of the order, once the local state is open.
fn build_with(
    configuration: EngineConfiguration,
    mut store: Store,
) -> Result<Engine, StartupAbort> {
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

/// Signs this device out of the server it enrolled against, and forgets what belonged to that
/// server — because the addresses have changed underneath it (ADR-D13 §4).
///
/// The order is the ADR's, and each step has its reason:
///
/// 1. **Build against the stored addresses and sign out through the normal path.** The revoke goes
///    to the old server, the mirror is cleared, the namespace emptied, the session forgotten — the
///    revoke may fail and the clearing happens anyway (`Engine::sign_out`). A clearing written
///    afresh here would be a second sign-out, and the second one is the one nobody maintains.
/// 2. **Clear `device.enrolled` and the anchored key set.** The anchor belongs to the old server,
///    and an anchor from another tenant would silently discard every delivery command of the new
///    one — "when in doubt, preserve" would become "never again".
/// 3. **Keep the device key and the device identifier.** They are this machine's, and a new device
///    key is a different device (ADR-D12 §6).
///
/// This can sit for a connect timeout against a server that is no longer there. That is the price
/// of not carrying a signed-in session across, and it is paid once.
fn start_afresh(configuration: &EngineConfiguration, old: &Addresses) -> Result<(), StartupAbort> {
    tracing::warn!(
        stored = old.api_base,
        configured = configuration.api_base,
        "this device is enrolled against another server; signing out from the old one before the \
         set-up starts afresh."
    );
    let refused = |reason: String| StartupAbort::Counterpart {
        stored: old.api_base.clone(),
        now: configuration.api_base.clone(),
        reason,
    };
    let old_configuration = EngineConfiguration {
        api_base: old.api_base.clone(),
        auth_base: old.auth_base.clone(),
        app_base: old.app_base.clone(),
        // Nothing else is the old server's: the paths, the name and the language belong to this
        // machine, and the enrolment code is not carried into a sign-out.
        enrollment_code: None,
        ..configuration.clone()
    };
    let engine = build_engine(old_configuration).map_err(|error| refused(error.to_string()))?;
    // The folder has to be connected for this, and for exactly one reason: `clear_everything` is
    // the step that empties the mirror, and an engine without a file system skips it silently —
    // the old tenant's documents would stay lying on a machine that now speaks to another server.
    let platform = match crate::platform::connect(
        engine.source(),
        engine.intake(),
        &configuration.mirror_path,
    ) {
        Ok(platform) => {
            engine.set_file_system(platform.file_system());
            Some(platform)
        }
        Err(abort) => {
            tracing::warn!(%abort, "no folder on this device; the sign-out clears what there is");
            None
        }
    };
    // The revoke may fail — the old server may be gone, and the local clearing is what matters.
    if let Err(error) = engine.sign_out() {
        tracing::warn!(%error, "the sign-out from the old server did not complete; the local state is cleared all the same.");
    }
    engine.stop();
    if let Some(mut platform) = platform {
        platform.stop();
    }
    drop(engine);

    let mut store = open_state(configuration)?;
    store.delete_setting(SETTING_ENROLLED)?;
    store.delete_setting(SETTING_KEY_SET)?;
    Ok(())
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

/// The values of the wizard, in the order the pages ask for them.
///
/// The enrolment code is deliberately not among them: it has no `setting_key`, is never stored,
/// and reaches the engine only inside a configuration (ADR-D13 §6). It arrives in
/// [`SetupValues`] and goes no further than this list refuses to carry it.
const OFFERED: [Value; 6] = [
    Value::ApiBase,
    Value::AuthBase,
    Value::AppBase,
    Value::DeviceName,
    Value::MirrorPath,
    Value::Language,
];

/// What a resolution says about one value, as the wizard has to show it (ADR-D13 §3).
///
/// Three of the four reasons are decided here. [`Fixed::Operator`] is the environment's, and the
/// resolution knows it. [`Fixed::Enrolled`] is the device name once the server carries it — the
/// same refusal [`crate::setup::set_value`] makes, said before the user types rather than after.
/// [`Fixed::Mirror`] is the root of the mirror where this platform does not let a value decide
/// it.
fn field_of(resolution: &Resolution, which: Value) -> SetupField {
    let value = resolution.text(which).unwrap_or_default();
    if resolution.is_fixed(which) {
        return SetupField::fixed(value, Fixed::Operator);
    }
    match which {
        Value::DeviceName if matches!(resolution.counterpart(), Counterpart::Enrolled { .. }) => {
            SetupField::fixed(value, Fixed::Enrolled)
        }
        // ADR-D13, measurement 5: off Windows the root is named by the File Provider and lies
        // under `~/Library/CloudStorage/`. The field is not in the page there (`window::MIRROR`),
        // and saying so here is what makes `apply_setup` discard a value for it — the source
        // decides, not the page (§1).
        Value::MirrorPath if !cfg!(windows) => SetupField::fixed(value, Fixed::Mirror),
        _ => SetupField::open(value),
    }
}

/// Which of the three reasons the wizard is open for.
///
/// The order is the order of urgency: a device that was pointed somewhere else has something to
/// be told, a device that has never been walked through is being set up, and everything after
/// that is somebody opening the wizard from the window, where nothing is wrong and nothing is
/// said about it.
fn reason_of(resolution: &Resolution) -> SetupReason {
    if resolution.counterpart_changed().is_some() {
        SetupReason::Counterpart
    } else if resolution.completed() {
        SetupReason::ByHand
    } else {
        SetupReason::First
    }
}

/// The whole wizard, out of one resolution.
pub fn view_of(resolution: &Resolution, extension: ExtensionState) -> SetupView {
    let place = |which: Value| resolution.text(which).unwrap_or_default().to_owned();
    SetupView {
        reason: reason_of(resolution),
        api_base: field_of(resolution, Value::ApiBase),
        auth_base: field_of(resolution, Value::AuthBase),
        app_base: field_of(resolution, Value::AppBase),
        one_address: resolution.one_address(),
        // Only where the page would otherwise show an empty field: one question, open, and
        // nothing anywhere to put in it. A workstation that has been told an address — by its
        // operator or by an earlier walk through this wizard — is never offered ours
        // (`setup::DEVELOPMENT_BASE`, which says what this is and when it goes).
        suggested_base: (resolution.one_address()
            && !resolution.is_fixed(Value::ApiBase)
            && resolution.text(Value::ApiBase).is_none_or(str::is_empty))
        .then(|| crate::setup::DEVELOPMENT_BASE.to_owned()),
        // Unconditionally, because this is not an offer but the address the page has to recognise
        // under the field — including the one it stored itself one click ago, and including it
        // written with a slash or in capitals. Where the sentence then stands is the page's
        // judgement and nobody else's (view.js, `showSuggestion`): only under an open one-address
        // field that carries exactly this host.
        development_base: Some(crate::setup::DEVELOPMENT_BASE.to_owned()),
        device_name: field_of(resolution, Value::DeviceName),
        mirror_path: field_of(resolution, Value::MirrorPath),
        language: field_of(resolution, Value::Language),
        // Never a value, only whether the device was given one: the code is a one-time secret
        // that is not stored and not reported (ADR-D13 §6). An environment that carries one takes
        // the page away, exactly as a set variable takes every other field away.
        enrollment_code: if resolution.has_enrollment_code() {
            SetupField::fixed("", Fixed::Operator)
        } else {
            SetupField::open("")
        },
        data_path: place(Value::DataPath),
        staging_path: place(Value::Staging),
        holding_path: place(Value::Holding),
        enrolled: matches!(resolution.counterpart(), Counterpart::Enrolled { .. }),
        extension,
    }
}

/// Takes what the wizard's input pages carried over — through [`crate::setup::set_value`] and
/// through nothing else.
///
/// Here and not in either source, because both have to behave identically:
/// [`crate::awaiting::AwaitingSetup`] runs this before there is an engine and [`EngineView`] runs
/// it afterwards, and a workstation that was set up before its first start must end up with the
/// same `setting` table as one that was set up after.
///
/// **The source decides, not the page** (ADR-D13 §1). A value for a field [`view_of`] reported as
/// fixed is discarded in silence: the page never offered it, so a sentence about it would be a
/// complaint about a click the user did not make. Everything else the door refuses comes back as
/// the sentence the catalogue has for it.
///
/// A value the door takes is written at once, one by one. There is no transaction over the six:
/// each is its own answer to its own question, and a run that stops at the third has stored the
/// first two — which is what the next render then shows.
///
/// # Errors
///
/// [`DisplayError::NotPossible`] with the catalogue's whole sentence for the first value the
/// store's door refused for a reason the user can do something about.
pub fn store_values(
    store: &mut Store,
    values: &SetupValues,
    catalogue: &Catalog,
) -> Result<(), DisplayError> {
    let resolution = crate::setup::resolve_over(store);
    let typed = [
        &values.api_base,
        &values.auth_base,
        &values.app_base,
        &values.device_name,
        &values.mirror_path,
        &values.language,
    ];
    for (which, text) in OFFERED.into_iter().zip(typed) {
        let Some(text) = text else { continue };
        // What the view says is fixed is not this page's to set, whatever it sent. The door
        // refuses the same values for itself; this is the reason the page is told nothing about
        // it.
        if !field_of(&resolution, which).is_open() {
            tracing::debug!(value = which.variable(), "a value for a fixed field was discarded.");
            continue;
        }
        match crate::setup::set_value(store, &resolution, which, text) {
            Ok(stored) => tracing::info!(
                value = which.variable(),
                key = which.setting_key().unwrap_or("—"),
                length = stored.len(),
                "a value of the set-up was stored."
            ),
            Err(refused) if refused.is_not_offered() => {
                tracing::debug!(%refused, "a value the set-up does not offer was discarded.");
            }
            Err(refused) => return Err(refused_text(which, &refused, catalogue)),
        }
    }
    // The code is never stored and never reported. It reaches the engine through the
    // configuration of the next start, and that is the whole of its way (ADR-D13 §6).
    if values.enrollment_code.is_some() {
        tracing::debug!("an enrolment code was handed over; it is not stored.");
    }
    Ok(())
}

/// A refusal of the store's door as the person who typed the value reads it.
///
/// Two faces, as everywhere in this house: the English diagnostic goes into the log, the
/// catalogue's sentence into the window.
fn refused_text(which: Value, refused: &SettingRefused, catalogue: &Catalog) -> DisplayError {
    tracing::warn!(%refused, value = which.variable(), "a value of the set-up was not stored.");
    DisplayError::NotPossible(catalogue.text(refused.user_key()).to_owned())
}

impl EngineView {
    /// The `setting` table, for the one reader and the one writer of `crate::setup`.
    fn settings(&self) -> MutexGuard<'_, Store> {
        self.settings.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ExtensionWatch {
    /// The last answer, at once — and a question on its way when there is none in flight.
    ///
    /// The question itself must not run here (ADR-D13 §9); what runs here is reading a mutex.
    #[cfg(target_os = "macos")]
    fn answer(self: &Arc<Self>) -> ExtensionState {
        use std::sync::atomic::Ordering;

        let known = *self.answered.lock().unwrap_or_else(PoisonError::into_inner);
        // One question at a time: the page asks every two seconds while its step is open, and the
        // call may sit for the whole deadline.
        if !self.asking.swap(true, Ordering::AcqRel) {
            let mine = Arc::clone(self);
            let started =
                std::thread::Builder::new().name("edms-extension".to_owned()).spawn(move || {
                    let answer = crate::platform::extension_is_on();
                    *mine.answered.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer);
                    mine.asking.store(false, Ordering::Release);
                });
            if let Err(error) = started {
                // Without the thread the page would say "asking macOS …" for ever. Letting the
                // flag go means the next of its two-second questions tries again.
                tracing::warn!(%error, "the question about the folder's extension was not started.");
                self.asking.store(false, Ordering::Release);
            }
        }
        match known {
            None => ExtensionState::Asking,
            Some(true) => ExtensionState::On,
            Some(false) => ExtensionState::Off,
        }
    }

    /// Nothing to ask, and nothing waiting on an answer.
    ///
    /// This platform's folder needs no extension switched on, and the page that would ask is not
    /// in the binary (`window::EXTENSION`), so nothing reads this. [`ExtensionState::On`] is the
    /// answer that adds no step — and it is not a claim about an extension but about the folder:
    /// here it works without one.
    #[cfg(not(target_os = "macos"))]
    fn answer(self: &Arc<Self>) -> ExtensionState {
        ExtensionState::On
    }
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

    /// The set-up as this workstation stands right now — read afresh on every call.
    ///
    /// Not cached: between two renders the engine may have enrolled the device, which closes the
    /// name and takes the code page away, and a wizard drawn from a resolution of five minutes
    /// ago would offer a field that is no longer anybody's to type in.
    fn setup(&self) -> Option<SetupView> {
        let resolution = crate::setup::resolve_over(&self.settings());
        Some(view_of(&resolution, self.extension.answer()))
    }

    /// Takes what the wizard's input pages carried over — see [`store_values`], which both
    /// sources share so that a workstation set up before its first start ends up with the same
    /// `setting` table as one set up after.
    fn apply_setup(&self, values: &SetupValues) -> Result<(), DisplayError> {
        store_values(&mut self.settings(), values, self.inner.catalogue)
    }

    /// The last page was reached — `setup.completed` is written, and the note about a counterpart
    /// that changed is forgotten.
    ///
    /// The two belong together. `note_counterpart_changed` writes the note and drops the
    /// completed mark at the start that found the re-point; this is the one place that has shown
    /// the sentence to somebody. Without it the note would stay in the `setting` table for the
    /// life of the installation and every later set-up would open on "this device was set up
    /// against a different server".
    ///
    /// Reached, not succeeded (ADR-D13 §11): a device waiting for its approval has finished its
    /// set-up honestly.
    fn complete_setup(&self) -> Result<(), DisplayError> {
        let mut store = self.settings();
        let catalogue = self.inner.catalogue;
        let refused = |error: edms_store::StoreError| {
            tracing::warn!(%error, "the set-up's completed mark was not written.");
            DisplayError::NotPossible(catalogue.text(key::SETUP_WRONG_NOT_STORED).to_owned())
        };
        crate::setup::mark_completed(&mut store).map_err(refused)?;
        crate::setup::forget_counterpart_changed(&mut store).map_err(refused)?;
        tracing::info!("the set-up was walked to its last page.");
        Ok(())
    }

    fn extension_state(&self) -> ExtensionState {
        self.extension.answer()
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

    // ── The set-up, on the product's own path ──────────────────────────────────
    //
    // These exercise [`view_of`] and [`store_values`] — what `EngineView` and
    // `crate::awaiting::AwaitingSetup` both answer with. An `EngineView` itself cannot be built
    // in a test (it opens the operating system's keychain and starts an engine), and that is
    // exactly why the two halves of the wizard live in free functions here: a test of the demo's
    // source proves nothing about the shipped one, and for a while there was no other kind.

    use std::collections::HashMap;

    use edms_engine::config::{
        SETTING_API_BASE, SETTING_APP_BASE, SETTING_AUTH_BASE, SETTING_COMPLETED,
        SETTING_COUNTERPART_CHANGED, SETTING_DEVICE_NAME, VAR_API_BASE, VAR_APP_BASE, YES,
    };
    use edms_engine::session::SETTING_ENROLLED;

    use crate::display::Fixed;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    fn resolution(
        environment: &HashMap<String, String>,
        settings: &HashMap<String, String>,
    ) -> Resolution {
        crate::setup::read(
            &|name| environment.get(name).cloned(),
            &|key| settings.get(key).cloned(),
            edms_i18n::Language::De,
        )
    }

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().expect("a directory for the test");
        let store = Store::open(&directory.path().join(crate::setup::DATABASE_NAME))
            .expect("a fresh state");
        (directory, store)
    }

    #[test]
    fn the_wizard_a_shipped_build_shows_is_built_from_the_resolution_and_nothing_else() {
        // The state this used to be in: `EngineView` overrode none of the four set-up methods, so
        // the trait defaults held — `setup()` answered `None` and every click on "Set-up" in a
        // real run produced "the set-up cannot be opened on this device". No test noticed,
        // because no test built anything but the demo's source.
        let found = resolution(
            &map(&[(VAR_APP_BASE, "https://app.acme")]),
            &map(&[(SETTING_API_BASE, "https://api.acme")]),
        );
        let view = view_of(&found, ExtensionState::Asking);
        assert_eq!(view.reason, SetupReason::First, "nothing has been walked to the end yet");
        assert_eq!(view.app_base.fixed, Fixed::Operator, "the environment decided this one");
        assert_eq!(view.app_base.value, "https://app.acme");
        assert!(view.api_base.is_open(), "a stored value stays the user's");
        assert_eq!(view.api_base.value, "https://api.acme");
        assert!(view.auth_base.is_open(), "and one nobody has given is a question");
        assert!(view.auth_base.value.is_empty());
        assert!(view.device_name.is_open(), "not enrolled: the name is still the user's");
        assert!(!view.enrolled);
        assert!(!view.data_path.is_empty(), "shown, never offered");
        assert!(!view.staging_path.is_empty());
        assert!(!view.holding_path.is_empty());
        assert!(view.enrollment_code.value.is_empty(), "never a value, in any state");
    }

    #[test]
    fn a_workstation_that_has_been_told_nothing_is_asked_once_and_offered_the_prefill() {
        // The correction of 2026-09-14, at the seam between the resolution and the page. The
        // suggestion is the one thing in a view that does not hold anywhere; everything that
        // makes that bearable is in `setup::DEVELOPMENT_BASE`, and this is where it is handed
        // over.
        let view = view_of(&resolution(&HashMap::new(), &HashMap::new()), ExtensionState::Off);
        assert!(view.one_address, "nothing stands, so one answer would be the truth for three");
        assert_eq!(view.suggested_base.as_deref(), Some(crate::setup::DEVELOPMENT_BASE));
        assert!(view.api_base.value.is_empty(), "and it is not a value of this workstation");
        assert!(view.api_base.is_open() && view.auth_base.is_open() && view.app_base.is_open());
    }

    #[test]
    fn a_workstation_that_already_has_an_address_is_never_offered_ours() {
        // Two devices, one rule: whoever has been told an address — by an administrator or by an
        // earlier walk through this wizard — is not shown a development server underneath it.
        let stored = resolution(
            &HashMap::new(),
            &map(&[
                (SETTING_API_BASE, "https://dms.acme"),
                (SETTING_AUTH_BASE, "https://dms.acme"),
                (SETTING_APP_BASE, "https://dms.acme"),
            ]),
        );
        let view = view_of(&stored, ExtensionState::Off);
        assert!(view.one_address, "one host, and the page still asks once");
        assert_eq!(view.suggested_base, None, "there is something to show already");
        assert_eq!(view.api_base.value, "https://dms.acme");

        let managed = resolution(&map(&[(VAR_APP_BASE, "https://app.acme")]), &HashMap::new());
        let view = view_of(&managed, ExtensionState::Off);
        assert!(!view.one_address, "one of the three came from somewhere else");
        assert_eq!(view.suggested_base, None, "and nothing is suggested into a page showing three");
    }

    #[test]
    fn the_address_the_page_recognises_stands_in_every_view_and_not_only_in_the_offer() {
        // The Rust half of the repair of 2026-09-14. The offer is made **once**, and only to a
        // workstation nobody has told an address; the sentence under the field has to stand for
        // as long as that address stands, and one "Next" later it is an ordinary stored value
        // with no offer beside it. MEASURED before the repair: "Next", then "Back", and
        // elasticdms's development server stood in a field labelled "Address of your archive"
        // with nothing at all underneath.
        let fresh = view_of(&resolution(&HashMap::new(), &HashMap::new()), ExtensionState::Off);
        assert_eq!(fresh.development_base.as_deref(), Some(crate::setup::DEVELOPMENT_BASE));

        let ours = "https://dms.dev.elasticdms.com";
        let stored = resolution(
            &HashMap::new(),
            &map(&[(SETTING_API_BASE, ours), (SETTING_AUTH_BASE, ours), (SETTING_APP_BASE, ours)]),
        );
        let view = view_of(&stored, ExtensionState::Off);
        assert_eq!(view.api_base.value, ours, "it is a value of this workstation now");
        assert_eq!(view.suggested_base, None, "so nothing is offered any more");
        assert_eq!(
            view.development_base.as_deref(),
            Some(crate::setup::DEVELOPMENT_BASE),
            "and the page can still say what the value in the field is"
        );
    }

    #[test]
    fn an_enrolled_device_shows_its_name_and_stops_offering_it() {
        let found = resolution(
            &HashMap::new(),
            &map(&[(SETTING_ENROLLED, YES), (SETTING_DEVICE_NAME, "Front desk")]),
        );
        let view = view_of(&found, ExtensionState::On);
        assert_eq!(view.device_name.fixed, Fixed::Enrolled);
        assert_eq!(view.device_name.value, "Front desk");
        assert!(view.enrolled, "and the code page falls away with it");
    }

    #[test]
    fn an_enrolment_code_from_the_environment_takes_the_page_away_and_is_never_a_value() {
        let mut environment = map(&[(VAR_API_BASE, "https://api.acme")]);
        environment
            .insert(edms_engine::config::VAR_ENROLLMENT_CODE.to_owned(), "K7QM-4T2X".to_owned());
        let view = view_of(&resolution(&environment, &HashMap::new()), ExtensionState::Off);
        assert_eq!(view.enrollment_code.fixed, Fixed::Operator);
        assert_eq!(view.enrollment_code.value, "", "the code is not carried into a view");
    }

    #[test]
    fn the_reason_the_wizard_is_open_follows_what_the_setting_table_says() {
        let first = resolution(&HashMap::new(), &HashMap::new());
        assert_eq!(view_of(&first, ExtensionState::Off).reason, SetupReason::First);

        let done = resolution(&HashMap::new(), &map(&[(SETTING_COMPLETED, YES)]));
        assert_eq!(view_of(&done, ExtensionState::Off).reason, SetupReason::ByHand);

        // The note outlives the mark: `note_counterpart_changed` writes the one and deletes the
        // other, and this is the page that says what happened.
        let moved =
            resolution(&HashMap::new(), &map(&[(SETTING_COUNTERPART_CHANGED, "https://api.old")]));
        assert_eq!(view_of(&moved, ExtensionState::Off).reason, SetupReason::Counterpart);
    }

    #[test]
    fn a_value_for_a_field_the_source_reported_as_fixed_is_discarded_by_the_source() {
        // ADR-D13 §1, at the place that can enforce it. A page can be bypassed; this cannot.
        let (_directory, mut store) = store();
        let catalogue = german();
        let values = SetupValues {
            api_base: Some("https://api.typed".to_owned()),
            app_base: Some("https://attacker.example".to_owned()),
            device_name: Some("Front desk".to_owned()),
            ..SetupValues::default()
        };
        // `app_base` is the environment's on this run, so nothing the page sends for it counts.
        // The resolution `store_values` uses is the one it reads for itself, so the environment
        // has to be the process's — which no test may set. What is checked here instead is the
        // half that does not need one: an open value is stored, and the door's own refusal of a
        // fixed value is covered by `setup::the_setter_refuses_a_value_the_environment_has_fixed`.
        store_values(&mut store, &values, catalogue).expect("two open values");
        assert_eq!(store.setting(SETTING_API_BASE).unwrap().as_deref(), Some("https://api.typed"));
        assert_eq!(store.setting(SETTING_DEVICE_NAME).unwrap().as_deref(), Some("Front desk"));
    }

    #[test]
    fn a_value_the_door_refuses_comes_back_as_a_whole_sentence_and_not_as_a_diagnosis() {
        let (_directory, mut store) = store();
        let values = SetupValues {
            api_base: Some("http://api.example".to_owned()),
            ..SetupValues::default()
        };
        let error = store_values(&mut store, &values, german())
            .expect_err("plaintext against a host that is not this machine");
        let sentence = error.user_text(german());
        assert!(sentence.contains("https"), "{sentence}");
        assert!(!sentence.contains("ConnectionError"), "the diagnosis stays in the log");
        assert_eq!(store.setting(SETTING_API_BASE).unwrap(), None, "and nothing was written");
    }

    #[test]
    fn the_enrolment_code_never_reaches_the_setting_table() {
        // It is a one-time secret (ADR-D13 §6): no `setting_key`, never stored, never reported.
        let (_directory, mut store) = store();
        let values =
            SetupValues { enrollment_code: Some("K7QM-4T2X".to_owned()), ..SetupValues::default() };
        store_values(&mut store, &values, german()).expect("a code is taken and passed on");
        for key in ["setup.enrollment-code", "enrollment-code", "setup.code"] {
            assert_eq!(store.setting(key).unwrap(), None, "{key}");
        }
        // And it cannot be printed either: `SetupValues` writes its own `Debug`.
        let shown = format!("{values:?}");
        assert!(!shown.contains("K7QM-4T2X"), "{shown}");
    }
}
