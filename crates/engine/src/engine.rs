//! The handle: [`Engine`] — and the works all modules share.
//!
//! ## The order at the start is not free
//!
//! The platform layer needs the [`NamespaceSource`] **before** it registers with the operating
//! system: on Windows `CfConnectSyncRoot` calls callbacks at once, on macOS the Finder enumerates
//! as soon as the domain stands. The other way round the engine needs the [`FileSystem`] only when
//! it has changes to report. Hence:
//!
//! ```ignore
//! let engine = Engine::start(configuration, server, store, bundle)?;
//! let mirror = Mirror::connect(engine.source(), …)?;   // the platform gets the source
//! engine.set_file_system(Arc::new(mirror)); // and the engine afterwards the file system
//! ```
//!
//! Without a file system the engine runs on completely — it then reports changes to nobody, and
//! that is exactly the state between these two lines. An engine that aborted beforehand would not
//! be startable.
//!
//! ## The runtime belongs to the engine
//!
//! The engine holds its own `tokio` runtime. The platform layers call from threads of the operating
//! system (cfAPI callback, Foundation thread), the app from its event loop; none of them is a tokio
//! worker, and none is to need one. The bridge into the runtime stands in [`crate::source`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use edms_core::log::LogEntry;
use edms_core::namespace::Container;
use edms_core::port::{FileSystem, NamespaceSource};
use edms_core::time::Timestamp;
use edms_store::{Account, LogPage, Store};
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use crate::config::EngineConfiguration;
use crate::error::EngineError;
use crate::event::{CHANNEL_DEPTH, EngineEvent};
use crate::report::Report;
use crate::server_object::ServerObject;
use crate::session::{EngineState, KeyBundle};

/// Spacing between two complete reconciles of the namespace.
///
/// Two minutes are the middle way between "the folder lags behind" and "200 workstations ask in
/// unison". Whoever has to be faster gets the delivery command `RECONCILE` (ADR-D04) — the server
/// knows when something has changed, and the client does not have to guess it.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(120);

/// Measures the free space of a directory; `None` when that is not possible.
///
/// The app sets it with [`Engine::set_space_probe`] — `std` knows no way to ask for free space, and
/// platform API does not belong in the engine (ADR-D02).
pub type SpaceProbe = Arc<dyn Fn(&Path) -> Option<u64> + Send + Sync>;

/// How many contents are loaded at the same time.
///
/// More than four gain nothing on an office line and make every single fetch slower — and slow here
/// is the file a human being is waiting for right now.
pub const CONCURRENT_DOWNLOADS: usize = 4;

/// Everything the engine's modules share.
///
/// `store` stands behind a `std::sync::Mutex`: `rusqlite` is blocking, and the lock is therefore
/// **never held across an `await`** (clippy `await_holding_lock` watches that). Every piece of
/// database work is a short, synchronous stretch between two network calls.
pub(crate) struct Shared {
    pub(crate) configuration: EngineConfiguration,
    pub(crate) server: Arc<dyn ServerObject>,
    pub(crate) bundle: Arc<KeyBundle>,
    /// Serialises sign-in, renewal and sign-out — two device flows side by side would be two codes
    /// on the screen, and one of them is wrong.
    pub(crate) login_lock: tokio::sync::Mutex<()>,
    /// Bounds the concurrent content fetches (see [`CONCURRENT_DOWNLOADS`]).
    pub(crate) load_gate: Arc<tokio::sync::Semaphore>,
    /// The files the platform announced in mail baskets and the ingest has not finished
    /// ([`crate::ingest::Intake`]).
    pub(crate) announced: crate::ingest::Announced,
    store: Mutex<Store>,
    file_system: RwLock<Option<Arc<dyn FileSystem>>>,
    space_probe: RwLock<Option<SpaceProbe>>,
    state: watch::Sender<EngineState>,
    events: broadcast::Sender<EngineEvent>,
    enrollment_code: Mutex<Option<String>>,
    token_expiry: Mutex<Option<Timestamp>>,
    stopped: AtomicBool,
}

impl Shared {
    /// The text catalogue in the language of this workstation — every sentence the engine says
    /// to the user comes from here, and none from a string literal.
    pub(crate) fn catalogue(&self) -> &'static edms_i18n::Catalog {
        edms_i18n::Catalog::of(self.configuration.language)
    }

    /// The local state. The guard is never held across an `await`.
    pub(crate) fn store(&self) -> MutexGuard<'_, Store> {
        // A poisoned mutex means: a thread died holding the lock. The database itself is
        // untouched by that (every change runs in a transaction); a panic here would take the whole
        // folder away from the user instead of showing an error.
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current state.
    pub(crate) fn state(&self) -> EngineState {
        self.state.borrow().clone()
    }

    /// Sets the state and calls it out.
    pub(crate) fn set_state(&self, new: EngineState) {
        if *self.state.borrow() == new {
            return;
        }
        // `send_replace` and not `send`: `send` fails **without setting the value** when nobody
        // happens to be listening — and then a window opened later would show the state of an hour
        // ago. The engine runs on without a window, and so does its state.
        self.state.send_replace(new);
        self.record(EngineEvent::StateChanged);
    }

    /// Sets `connected` in the state `SignedIn`, without changing anything else.
    pub(crate) fn set_connected(&self, connected: bool) {
        if let EngineState::SignedIn { display_name, tenant, since, .. } = self.state() {
            self.set_state(EngineState::SignedIn { display_name, tenant, since, connected });
        }
    }

    /// Calls an event out.
    pub(crate) fn record(&self, event: EngineEvent) {
        let _ = self.events.send(event);
    }

    /// The account of the running session; `None` for as long as nobody is signed in.
    pub(crate) fn account(&self) -> Option<Account> {
        self.store().session().ok().flatten().and_then(|row| row.account().cloned())
    }

    /// Writes a row into the usage log and calls [`EngineEvent::LogGrown`] out.
    ///
    /// If the writing fails, it is logged and work goes on: the usage log is display, not evidence
    /// (ADR-D07) — the authoritative access log is kept by the server.
    pub(crate) fn append_log(&self, entry: &LogEntry) {
        let account = self.account();
        let result = self.store().append_log(account.as_ref(), entry);
        match result {
            Ok(_) => self.record(EngineEvent::LogGrown),
            Err(error) => {
                tracing::error!(%error, kind = ?entry.kind(), "usage-log row not written");
            }
        }
    }

    /// The platform layer, as soon as it has registered.
    pub(crate) fn file_system(&self) -> Option<Arc<dyn FileSystem>> {
        self.file_system.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub(crate) fn set_file_system(&self, file_system: Arc<dyn FileSystem>) {
        *self.file_system.write().unwrap_or_else(PoisonError::into_inner) = Some(file_system);
    }

    /// The enrolment code, if there is one.
    pub(crate) fn enrollment_code(&self) -> Option<String> {
        self.enrollment_code.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub(crate) fn set_enrollment_code(&self, code: Option<String>) {
        *self.enrollment_code.lock().unwrap_or_else(PoisonError::into_inner) = code;
    }

    /// When the access token expires.
    pub(crate) fn token_expiry(&self) -> Option<Timestamp> {
        *self.token_expiry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn set_token_expiry(&self, expiry: Option<Timestamp>) {
        *self.token_expiry.lock().unwrap_or_else(PoisonError::into_inner) = expiry;
    }

    /// The free disk space at the place of the database, in so far as the app can measure it.
    pub(crate) fn free_store(&self) -> crate::report::StoreSpace {
        let probe = self.space_probe.read().unwrap_or_else(PoisonError::into_inner).clone();
        let folder = self
            .configuration
            .data_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        match probe.and_then(|probe| probe(folder)) {
            Some(bytes) => crate::report::StoreSpace::Bytes(bytes),
            None => crate::report::StoreSpace::NotDetermined(
                "the app has set no space measurer (see Engine::set_space_probe)",
            ),
        }
    }

    pub(crate) fn set_space_probe(&self, probe: SpaceProbe) {
        *self.space_probe.write().unwrap_or_else(PoisonError::into_inner) = Some(probe);
    }

    /// Whether [`Engine::stop`] has already run.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// The folder client's engine.
///
/// All methods are **synchronous**: the app calls them from its event loop, the platform layer from
/// threads of the operating system. What takes longer than a key press (a sign-in with the device
/// flow) runs in the background and reports back over [`Engine::state`] and [`Engine::events`].
///
/// **The waiting methods** ([`Engine::sign_out`], [`Engine::reconcile_now`]) block the calling
/// thread, and it must therefore stand in **no** tokio runtime — the same holds for
/// [`crate::source::EngineSource`]. Called from an `async fn`, that would bring one's own runtime
/// to a halt. For the app and for cfAPI/File Provider the condition is met; neither of the two
/// knows tokio.
pub struct Engine {
    shared: Arc<Shared>,
    handle: Handle,
    runtime: Mutex<Option<Runtime>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("device", &self.shared.bundle.device())
            .field("state", &self.shared.state())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Starts the engine: runtime, state from the session row, reconcile beat.
    ///
    /// **No network call.** The start succeeds without a server; signing in happens only with
    /// [`Engine::sign_in`]. An engine that went onto the network at the start would have made a
    /// workstation without a connection unstartable — and the tree is to stand still precisely then
    /// (ADR-D01, point 8).
    ///
    /// # Errors
    ///
    /// When its own directories cannot be created or the runtime does not start.
    pub fn start(
        configuration: EngineConfiguration,
        server: Arc<dyn ServerObject>,
        store: Store,
        bundle: Arc<KeyBundle>,
    ) -> Result<Self, EngineError> {
        configuration.create_directories().map_err(|error| EngineError::Directory {
            path: configuration.staging.clone(),
            reason: error.to_string(),
        })?;
        // Half-finished loads of an earlier run: they carry no checked content and would otherwise
        // lie there forever.
        crate::hydration::clear_staging(&configuration.staging);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            // Two workers are enough: the engine almost only waits — for the network, for the
            // disk, for a human being. One worker per core would be, on a workstation with eight
            // cores, a tray program with eight sleeping threads.
            .worker_threads(2)
            .thread_name("edms-engine")
            .build()
            .map_err(|error| EngineError::Runtime(error.to_string()))?;
        let handle = runtime.handle().clone();

        let (state, _) = watch::channel(EngineState::Starting);
        let (events, _) = broadcast::channel(CHANNEL_DEPTH);
        let enrollment_code = configuration.enrollment_code.clone();
        let shared = Arc::new(Shared {
            configuration,
            server,
            bundle,
            login_lock: tokio::sync::Mutex::new(()),
            load_gate: Arc::new(tokio::sync::Semaphore::new(CONCURRENT_DOWNLOADS)),
            announced: crate::ingest::Announced::default(),
            store: Mutex::new(store),
            file_system: RwLock::new(None),
            space_probe: RwLock::new(None),
            state,
            events,
            enrollment_code: Mutex::new(enrollment_code),
            token_expiry: Mutex::new(None),
            stopped: AtomicBool::new(false),
        });

        let fingerprint = crate::session::read_key_set(&shared)
            .map(|key_set| key_set.fingerprint().display())
            .unwrap_or_default();
        let start = {
            let store = shared.store();
            crate::session::state_on_start(&store, &fingerprint, shared.catalogue())
        };
        shared.set_state(start);

        // Three background runs, and each keeps to a clock of its own: the reconcile to the beat,
        // the delivery channel to the long poll, the ingest to what the platform announces in the
        // mail baskets. All three run even while nobody is signed in — an erasure has to reach a
        // device then too (ADR-D04), and a handed-in file must not be lost.
        let interval = handle.spawn(crate::reconcile::interval(Arc::clone(&shared)));
        let channel = handle.spawn(crate::delivery::channel(Arc::clone(&shared)));
        let inbox = handle.spawn(crate::ingest::watch(Arc::clone(&shared)));
        Ok(Self {
            shared,
            handle,
            runtime: Mutex::new(Some(runtime)),
            tasks: Mutex::new(vec![interval, channel, inbox]),
        })
    }

    /// The source for the platform layer.
    ///
    /// It is due **before** the file system; see the module head.
    pub fn source(&self) -> Arc<dyn NamespaceSource> {
        Arc::new(crate::source::EngineSource::new(Arc::clone(&self.shared), self.handle.clone()))
    }

    /// The mouth for files the platform finds in a mail basket.
    ///
    /// The counterpart to [`Self::source`]: there the platform asks, here it tells. It may be
    /// fetched before the file system stands — an announcement for a file the ingest cannot get
    /// to yet simply waits in the queue.
    pub fn intake(&self) -> crate::ingest::Intake {
        crate::ingest::Intake::new(Arc::clone(&self.shared))
    }

    /// Registers the platform layer; from now on it gets changes reported.
    pub fn set_file_system(&self, file_system: Arc<dyn FileSystem>) {
        self.shared.set_file_system(file_system);
    }

    /// Sets the measurer for the free disk space.
    ///
    /// `std` knows no way to ask for free space; it needs `statvfs` or `GetDiskFreeSpaceEx`, and
    /// platform API does not belong in the engine (ADR-D02). The app measures, the engine asks —
    /// without a measurer [`crate::report::StoreSpace::NotDetermined`] stands in the [`Report`]
    /// instead of an invented number.
    pub fn set_space_probe(&self, probe: SpaceProbe) {
        self.shared.set_space_probe(probe);
    }

    /// The state, written forward continuously.
    ///
    /// A new receiver sees the **current** state at once, not the prehistory.
    pub fn state(&self) -> watch::Receiver<EngineState> {
        self.shared.state.subscribe()
    }

    /// The current state as a value — for callers without a runtime.
    pub fn state_now(&self) -> EngineState {
        self.shared.state()
    }

    /// The one-off events.
    ///
    /// Whoever listens too late misses some; precisely for that reason everything lasting stands in
    /// the state.
    pub fn events(&self) -> broadcast::Receiver<EngineEvent> {
        self.shared.events.subscribe()
    }

    /// The identifier of this workstation.
    pub fn device(&self) -> edms_core::identifier::DeviceIdentifier {
        self.shared.bundle.device()
    }

    /// Passes on the enrolment code a human being has typed in.
    pub fn set_enrollment_code(&self, code: &str) {
        let code = code.trim();
        self.shared.set_enrollment_code((!code.is_empty()).then(|| code.to_owned()));
    }

    /// Signs in — in the background. The progress stands in the state.
    ///
    /// Returns at once: a device flow waits for a human being, and a menu bar that freezes while it
    /// does is broken.
    ///
    /// # Errors
    ///
    /// Only when the engine has stopped. Everything else stands in the state.
    pub fn sign_in(&self) -> Result<(), EngineError> {
        if self.shared.is_stopped() {
            return Err(EngineError::Stopped);
        }
        let shared = Arc::clone(&self.shared);
        let task = self.handle.spawn(async move {
            if let Err(error) = crate::session::sign_in(&shared).await {
                tracing::warn!(%error, "sign-in not completed");
                shared.record(EngineEvent::Hint { text: error.to_string() });
            } else if let Err(error) = crate::reconcile::reconcile_everything(&shared).await {
                tracing::warn!(%error, "first reconcile after the sign-in failed");
            }
        });
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner).push(task);
        Ok(())
    }

    /// Signs out and waits until everything is cleared up.
    ///
    /// Blocks on purpose: "sign out" is a promise (requirement 4), and the user is to see it
    /// completed before the app goes on.
    ///
    /// # Errors
    ///
    /// The first error, after **all** steps have been attempted.
    pub fn sign_out(&self) -> Result<(), EngineError> {
        let shared = Arc::clone(&self.shared);
        self.in_background(async move { crate::session::sign_out(&shared).await })
    }

    /// Reconciles now; `None` means: everything.
    ///
    /// # Errors
    ///
    /// When the reconcile did not go through — because the server stays silent, for instance.
    pub fn reconcile_now(&self, container: Option<Container>) -> Result<(), EngineError> {
        let shared = Arc::clone(&self.shared);
        self.in_background(async move {
            match container {
                Some(container) => crate::reconcile::reconcile_container(&shared, container).await,
                None => crate::reconcile::reconcile_everything(&shared).await,
            }
        })
    }

    /// One page of the usage log, newest row first.
    ///
    /// `before_id` pages onwards ([`LogPage::more_before`]); without a sign-in these are the device
    /// rows.
    ///
    /// # Errors
    ///
    /// When the store does not read or `count` is zero.
    pub fn log(&self, before_id: Option<u64>, count: usize) -> Result<LogPage, EngineError> {
        let account = self.shared.account();
        Ok(self.shared.store().log_page(account.as_ref(), before_id, count)?)
    }

    /// The report for `doctor` — without the network.
    ///
    /// # Errors
    ///
    /// When the store does not read.
    pub fn report(&self) -> Result<Report, EngineError> {
        crate::report::gather(&self.shared)
    }

    /// Stops the engine: abort tasks, close the runtime.
    ///
    /// Afterwards the [`NamespaceSource`] answers with
    /// [`edms_core::port::SourceError::NotSignedIn`] instead of reaching into a closed runtime.
    /// Called twice it is harmless.
    pub fn stop(&self) {
        if self.shared.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        for task in self.tasks.lock().unwrap_or_else(PoisonError::into_inner).drain(..) {
            task.abort();
        }
        self.shared.set_state(EngineState::Stopped);
        if let Some(runtime) = self.runtime.lock().unwrap_or_else(PoisonError::into_inner).take() {
            // With a deadline instead of at once: a running content fetch is to be able to close
            // its scratch file. Whoever takes longer is cut off — at the next start `clear_staging`
            // clears up.
            runtime.shutdown_timeout(Duration::from_secs(5));
        }
    }

    /// Runs a future on the engine's runtime and waits for it.
    fn in_background<T: Send + 'static>(
        &self,
        future: impl std::future::Future<Output = Result<T, EngineError>> + Send + 'static,
    ) -> Result<T, EngineError> {
        if self.shared.is_stopped() {
            return Err(EngineError::Stopped);
        }
        let task = self.handle.spawn(future);
        // `block_on` belongs here and not in the caller: the caller is a thread of the app or of
        // the operating system and is to know nothing about the runtime.
        self.handle.block_on(task).unwrap_or_else(|error| {
            Err(EngineError::Internal(format!("the task ended unexpectedly: {error}")))
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
impl Shared {
    /// A works without a runtime, without a file system and with a database in memory.
    ///
    /// For single samples of the flows in [`crate::session`]: they need the shared state, but
    /// neither a runtime nor a platform.
    pub(crate) fn for_sample(
        server: Arc<dyn ServerObject>,
        bundle: Arc<KeyBundle>,
        store: Store,
        staging: std::path::PathBuf,
    ) -> Arc<Self> {
        let (state, _) = watch::channel(EngineState::Starting);
        let (events, _) = broadcast::channel(CHANNEL_DEPTH);
        Arc::new(Self {
            configuration: EngineConfiguration::builder(&staging).finished(),
            server,
            bundle,
            login_lock: tokio::sync::Mutex::new(()),
            load_gate: Arc::new(tokio::sync::Semaphore::new(CONCURRENT_DOWNLOADS)),
            announced: crate::ingest::Announced::default(),
            store: Mutex::new(store),
            file_system: RwLock::new(None),
            space_probe: RwLock::new(None),
            state,
            events,
            enrollment_code: Mutex::new(None),
            token_expiry: Mutex::new(None),
            stopped: AtomicBool::new(false),
        })
    }
}

/// The path of the scratch area — for modules that need only it.
pub(crate) fn staging(shared: &Shared) -> &Path {
    &shared.configuration.staging
}
