//! The Windows part: everything that touches `cldapi.dll`.
//!
//! Here stands [`Mirror`] — the implementation of [`edms_core::port::FileSystem`] — and the shared
//! state [`Inner`] that the callbacks and the engine share. The modules below it are cut by kind of
//! call, not by flow:
//!
//! | Module | What for |
//! |---|---|
//! | [`win`] | Win32 outside cfAPI: handles, directories, attributes, volumes |
//! | [`registration`] | `CfRegisterSyncRoot` / `CfUnregisterSyncRoot` (Win32, not WinRT) |
//! | [`registry`] | The keys of the entry in Explorer's navigation pane, under HKLM |
//! | [`connection`] | `CfConnectSyncRoot` / `CfDisconnectSyncRoot` together with the callback table |
//! | [`callback`] | The `extern "system"` callbacks and how they are handled |
//! | [`command`] | `CfExecute` — every answer to cldflt |
//! | [`placeholder`] | Creating, updating, dehydrating and reading placeholders |
//! | [`sink`] | The 4 KB sink for `FETCH_DATA` |
//! | [`watch`] | The beat that finds files dropped into a mail basket |
//!
//! ## Two directions, one state
//!
//! The engine gives orders (`FileSystem`), Windows asks (`NamespaceSource`). Both directions work
//! on the same [`PathMap`] and the same [`Exemptions`] list, on different threads. That is why the
//! state lives in an `Arc<Inner>`: the `Mirror` holds one share, the connection a second one (as a
//! raw pointer in the callback context). The second one goes back on disconnect, and only then can
//! the state disappear.
//!
//! ## What is **not** here
//!
//! No decision that can be made without Windows. Which steps follow from a change list
//! [`crate::plan`] computes; whether a name is permitted [`crate::checks`]; which status belongs to
//! which reason [`crate::status`]. Those modules are tested on macOS — this one is not and cannot
//! be.
//!
//! **Not executed on Windows here.** Checked with `cargo xwin check` and clippy for
//! `x86_64-pc-windows-msvc`.

mod callback;
mod command;
mod connection;
mod placeholder;
mod registration;
mod registry;
mod sink;
mod watch;
mod win;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use edms_core::change::Change;
use edms_core::namespace::EntryIdentifier;
use edms_core::port::{FileSystem, LocalState, NamespaceSource, PlatformError, Provisioning};

use crate::cancel::Cancellations;
use crate::checks::{
    BUILD_WITH_IS_SUPPORTED, check_account, check_display_name, check_name, check_root_path,
};
use crate::error::MirrorError;
use crate::exemptions::{Exemptions, Scope};
use crate::intake::{Beat, Intake};
use crate::navigation_pane;
use crate::path::{connect, parent_and_name, unify};
use crate::path_map::PathMap;
use crate::plan::{Step, plan, staging_name};
use crate::raw::{is_in_use, is_not_found};
use crate::sync_root::SyncRootIdentifier;
use crate::worker_pool::WorkGroup;

use connection::Connection;
use placeholder::PlaceholderBuilder;

/// What `CfGetPlatformInfo` says about this Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformDetails {
    /// The build number (Windows 10 1709 is 16299).
    pub build: u32,
    /// The revision within the build.
    pub revision: u32,
    /// The integration number; it unlocks newer cfAPI fields.
    pub integration: u32,
}

impl PlatformDetails {
    /// Whether this Windows knows `StorageProviderSyncRootManager.IsSupported` (from 10 2004 on).
    ///
    /// For information only: registration goes through Win32 ([`registration`]), which has existed
    /// since 1709.
    pub const fn knows_is_supported(self) -> bool {
        self.build >= BUILD_WITH_IS_SUPPORTED
    }
}

/// Whether this Windows can carry the folder client — and with which version of cfAPI.
///
/// The question is asked **before** setting up, so that the user reads "Windows is too old" and not
/// an HRESULT from a registration that should never have been attempted.
pub fn platform_available() -> Result<PlatformDetails, MirrorError> {
    let info = registration::platform_info()?;
    crate::checks::check_build(info.BuildNumber)?;
    Ok(PlatformDetails {
        build: info.BuildNumber,
        revision: info.RevisionNumber,
        integration: info.IntegrationNumber,
    })
}

/// The state shared by the engine and the callbacks.
///
/// Every field is used by both sides; none belongs to one alone:
///
/// * `root` — the full path against which every callback path is computed.
/// * `source` — the seam to the engine; the callbacks ask it, nobody else does.
/// * `intake` — the other seam to the engine, and the only one that leads out of the folder: a
///   file that appeared in a mail basket. The watch calls it, and so does the close callback.
/// * `map` — where which entry lies. The callback enters what it handed over; the engine reads it
///   to turn an identifier into a path.
/// * `exemption` — our own deletions and renames, which the veto has to let through.
/// * `cancellations` — the switches of the hydrations in flight.
/// * `work` — the thread pool on which callbacks are carried to completion.
pub(crate) struct Inner {
    pub(crate) root: String,
    pub(crate) source: Arc<dyn NamespaceSource>,
    pub(crate) intake: Arc<dyn Intake>,
    pub(crate) map: Mutex<PathMap>,
    pub(crate) exemption: Exemptions,
    pub(crate) cancellations: Cancellations,
    pub(crate) work: WorkGroup,
    /// Counts the staging names of a rename through (`plan::staging_name`).
    interim_counter: AtomicU64,
}

// `NamespaceSource` does not require `Debug` (it should not bind the engine), hence by hand.
// Into a log belongs only what says something anyway: the folder and the number of entries.
impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `try_lock`, not `lock`: a log line must not wait and certainly must not deadlock.
        // Whoever writes `{:?}` in the middle of a change to the map would otherwise lie on a lock
        // they hold themselves — `std::sync::Mutex` is not reentrant.
        let entries = self.map.try_lock().ok().map(|k| k.count());
        f.debug_struct("Inner")
            .field("root", &self.root)
            .field("entries", &entries)
            .finish_non_exhaustive()
    }
}

impl Inner {
    /// The path map, secured against poisoning.
    ///
    /// A panic in a callback must not make the map unusable: otherwise the engine would find a path
    /// for no identifier afterwards, and no document could be removed any more — precisely what has
    /// to happen after an erasure command (ADR-D04).
    pub(crate) fn map(&self) -> MutexGuard<'_, PathMap> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The full path of an entry, or [`MirrorError::NotFound`].
    pub(crate) fn path(&self, identifier: EntryIdentifier) -> Result<String, MirrorError> {
        let relative = self.map().path(identifier).ok_or(MirrorError::NotFound(identifier))?;
        Ok(connect(&self.root, &relative))
    }

    /// Announces an intervention of our own, so that the veto lets it through.
    fn expect(&self, relative: &str, folder: bool) -> crate::exemptions::Expectation<'_> {
        self.exemption.expect(relative, if folder { Scope::Subtree } else { Scope::Exactly })
    }

    /// The next staging name of a two-stage rename.
    fn next_staging_name(&self) -> String {
        staging_name(std::process::id(), self.interim_counter.fetch_add(1, Ordering::Relaxed))
    }
}

/// The read-only mirror of the archive in Explorer.
///
/// A `Mirror` belongs to exactly one folder and exactly one account. It is created before anyone is
/// signed in ([`Mirror::new`]) and provisioned with the account ([`Mirror::connect`] or
/// [`FileSystem::place_ready`]).
///
/// When it is dropped it disconnects and waits for its worker threads; the registration stays — the
/// folder should be there again after a restart of the program. It goes only after
/// [`FileSystem::clear_everything`].
#[derive(Debug)]
pub struct Mirror {
    inner: Arc<Inner>,
    connection: Mutex<Option<Connection>>,
    account: Mutex<Option<String>>,
    /// Runs for as long as a connection is up; it is what finds a file dropped into a basket.
    watch: Mutex<Option<Beat>>,
}

impl Mirror {
    /// Creates the mirror for a folder, without touching Windows.
    ///
    /// The path is checked straight away: a network path or a drive root should show up while
    /// setting up, not on the first callback.
    pub fn new(
        root_path: &str,
        source: Arc<dyn NamespaceSource>,
        intake: Arc<dyn Intake>,
    ) -> Result<Self, MirrorError> {
        check_root_path(root_path)?;
        Ok(Self {
            inner: Arc::new(Inner {
                root: unify(root_path),
                source,
                intake,
                map: Mutex::new(PathMap::default()),
                exemption: Exemptions::default(),
                cancellations: Cancellations::default(),
                work: WorkGroup::default(),
                interim_counter: AtomicU64::new(0),
            }),
            connection: Mutex::new(None),
            account: Mutex::new(None),
            watch: Mutex::new(None),
        })
    }

    /// Creates the mirror **and** provisions it straight away — the app's route after sign-in.
    pub fn connect(
        root_path: &str,
        provisioning: &Provisioning,
        source: Arc<dyn NamespaceSource>,
        intake: Arc<dyn Intake>,
    ) -> Result<Self, MirrorError> {
        let mirror = Self::new(root_path, source, intake)?;
        mirror.set_up(provisioning)?;
        Ok(mirror)
    }

    /// The root folder.
    pub fn root(&self) -> &str {
        &self.inner.root
    }

    /// Whether a connection to cldflt is currently up.
    pub fn is_connected(&self) -> bool {
        lock(&self.connection).is_some()
    }

    /// Register and connect. A second call with the same account does nothing.
    fn set_up(&self, provisioning: &Provisioning) -> Result<(), MirrorError> {
        check_display_name(&provisioning.display_name)?;
        check_account(&provisioning.account)?;
        platform_available()?;

        {
            let account = lock(&self.account);
            if let Some(already) = account.as_deref() {
                if already != provisioning.account {
                    return Err(MirrorError::OtherAccount);
                }
                if self.is_connected() {
                    return Ok(());
                }
            }
        }

        // After a sign-out the worker pool has ended; without this call it would accept no
        // callback in the second session, and the folder would be there but empty.
        self.inner.work.accept_again();

        let root = &self.inner.root;
        win::create_folder(root)?;
        let file_system = win::file_system_name(root)?;
        if !file_system.eq_ignore_ascii_case("NTFS") {
            return Err(MirrorError::NoNtfs { path: root.clone(), file_system });
        }
        check_foreign_root(root, &provisioning.account)?;

        // The display name does not come along on the Win32 registration: `CF_SYNC_REGISTRATION`
        // has no field for it. It goes into the registry keys under HKLM that the next call
        // writes — that is where the entry in Explorer's navigation pane hangs.
        registration::register(root, &provisioning.account)?;
        // Not fatal, and deliberately so: the folder is fully usable through its path without the
        // row in the sidebar, and whether a process without elevated rights may write under
        // `SyncRootManager` is unmeasured (ADR-D06 §7, "Open"). Nextcloud writes these keys at
        // runtime too and treats a failure as non-fatal; a sign-in that failed because a
        // decoration is missing would be the worse trade. The reasons stand in full in
        // `platform::registry`.
        if let Err(error) = write_navigation_pane_entry(root, provisioning) {
            tracing::warn!(
                %error,
                "the entry in File Explorer's navigation pane was not written; the folder stands \
                 under its path all the same"
            );
        }
        let connection = Connection::open(root, &self.inner)?;
        *lock(&self.connection) = Some(connection);
        *lock(&self.account) = Some(provisioning.account.clone());
        // Only now: the watch reads directories under the root, and before `CfConnectSyncRoot`
        // every one of them is a folder full of placeholders that nobody serves.
        *lock(&self.watch) = Some(watch::start(&self.inner));
        tracing::info!(
            root = %root,
            display_name = %provisioning.display_name,
            "sync root registered and connected"
        );
        Ok(())
    }

    /// Disconnects and lets the worker threads run out; the registration stays.
    fn disconnect(&self) {
        // The watch first, and it is waited for: its round reads a directory under the root, and
        // what comes after this either disconnects that root or deletes it. It still needs the
        // worker pool while it waits — a directory that has never been listed answers only through
        // a callback — so the pool is stopped after it, not before.
        drop(lock(&self.watch).take());
        self.inner.cancellations.all_abort();
        // The connection first, then the threads: after `CfDisconnectSyncRoot` no callback arrives
        // any more, and therefore no new job either.
        drop(lock(&self.connection).take());
        self.inner.work.stop();
    }

    /// Carries out one step from [`crate::plan::plan`].
    fn run_step(&self, step: &Step) -> Result<(), MirrorError> {
        match step {
            Step::Remove { identifier } => self.remove_entry(*identifier),
            Step::StagingName { identifier, between } => self.rename_entry(*identifier, between),
            Step::FinalName { identifier, name } => self.rename_entry(*identifier, name),
            Step::Update { entry, stale } => {
                let path = self.inner.path(entry.identifier)?;
                placeholder::update(&path, entry, *stale)
                    .map_err(|f| with_identifier(entry.identifier, f))
            }
            Step::Create { entry } => {
                check_name(&entry.name)?;
                let parent = entry.identifier.parent().ok_or_else(|| {
                    MirrorError::Internal(
                        "an entry without a parent container cannot be created".into(),
                    )
                })?;
                let parent_path = self.inner.path(EntryIdentifier::Container(parent))?;
                let builder = PlaceholderBuilder::new(entry)?;
                placeholder::create(&parent_path, std::slice::from_ref(&builder))?;
                self.inner.map().set(entry.identifier, &entry.name, entry.is_folder());
                Ok(())
            }
        }
    }

    /// Renames a known entry — with an exemption for our own veto.
    fn rename_entry(&self, identifier: EntryIdentifier, name: &str) -> Result<(), MirrorError> {
        check_name(name)?;
        let old = self.inner.path(identifier)?;
        let folder = identifier.container().is_some();
        let (parent, _) = parent_and_name(&old);
        let new = connect(parent, name);
        callback::rename_with_exemption(&self.inner, &old, &new, folder)
            .map_err(|f| with_identifier(identifier, f))?;
        self.inner.map().rename(identifier, name);
        Ok(())
    }

    /// Deletes an entry together with everything below it and takes it out of the map.
    fn remove_entry(&self, identifier: EntryIdentifier) -> Result<(), MirrorError> {
        let path = self.inner.path(identifier)?;
        let folder = identifier.container().is_some();
        let relative = self.inner.map().path(identifier).unwrap_or_default();
        {
            let _expectation = self.inner.expect(&relative, folder);
            win::delete(&path, folder).map_err(|f| with_identifier(identifier, f))?;
        }
        self.inner.map().remove(identifier);
        Ok(())
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Writes the entry in Explorer's navigation pane; everything it needs is gathered here.
///
/// The display name is end-user text and is **not** built here: it comes from the app through
/// [`Provisioning`] and is checked at the head of [`Mirror::set_up`].
fn write_navigation_pane_entry(root: &str, provisioning: &Provisioning) -> Result<(), MirrorError> {
    let sid = win::current_user_sid()?;
    let program = registry::program_path()?;
    registry::write(&navigation_pane::Entry {
        sid: &sid,
        account: &provisioning.account,
        display_name: &provisioning.display_name,
        root_path: root,
        program: &program,
        // NAMED GAP: the number behind `Flags` is undocumented and nothing on the machine this
        // was written on has it to copy from (`crate::navigation_pane`, NAMED GAP 2).
        flags: None,
    })
}

/// Removes that entry again — the counterpart of the call above, at sign-out.
fn remove_navigation_pane_entry(account: &str) -> Result<(), MirrorError> {
    let sid = win::current_user_sid()?;
    registry::remove(&SyncRootIdentifier::new(&sid, account)?)
}

/// Rejects a root that belongs to another provider or to another account.
///
/// `CF_REGISTER_FLAG_UPDATE` would overwrite a foreign root without complaint — and thereby hijack
/// another provider's folder. And carrying on with the previous user's root would mean showing
/// them their placeholders (requirement 4).
fn check_foreign_root(root: &str, account: &str) -> Result<(), MirrorError> {
    let Some(existing) = registration::existing_root(root)? else {
        return Ok(());
    };
    if existing.provider != crate::checks::PROVIDER {
        return Err(MirrorError::ForeignRoot {
            path: root.to_owned(),
            identifier: existing.provider,
        });
    }
    if existing.account != account {
        return Err(MirrorError::OtherAccount);
    }
    Ok(())
}

/// How an entry stands locally ([`edms_core::port::FileSystem::state`]).
///
/// Three cases that have to be kept apart: it does not exist (the engine creates it), it exists as
/// an ordinary file (the user put it there themselves — it stays, and there is no content that
/// could be released), or it is a placeholder.
fn local_state(path: &str, folder: bool) -> Result<LocalState, MirrorError> {
    if !win::present(path) {
        return Ok(LocalState::default());
    }
    let Some(details) = placeholder::details(path, folder)? else {
        return Ok(LocalState { present: true, hydrated: false, pinned: false });
    };
    Ok(LocalState { present: true, hydrated: details.hydrated(), pinned: details.pinned })
}

/// Attaches an entry identifier to an operating system error, where it makes a difference.
///
/// The engine distinguishes "is not here" and "currently open" from everything else: the first is
/// done with, the second is retried, the third is reported. Without this mapping every file that
/// happened to be open would arrive as an unrecoverable system error, and the deletion after a
/// delivered command would not happen (ADR-D04).
fn with_identifier(identifier: EntryIdentifier, error: MirrorError) -> MirrorError {
    match &error {
        MirrorError::OperatingSystem { code, .. } if is_in_use(*code) => {
            MirrorError::InUse(identifier)
        }
        MirrorError::OperatingSystem { code, .. } if is_not_found(*code) => {
            MirrorError::NotFound(identifier)
        }
        _ => error,
    }
}

impl FileSystem for Mirror {
    fn place_ready(&self, provisioning: &Provisioning) -> Result<(), PlatformError> {
        self.set_up(provisioning).map_err(Into::into)
    }

    fn report_change(&self, changes: &[Change]) -> Result<(), PlatformError> {
        if !self.is_connected() {
            return Err(PlatformError::NotReadyPosed);
        }
        // The plan is built under a single lock; it is carried out without one, because every
        // step calls Windows and a callback will want to read the same map meanwhile.
        let steps = {
            let map = self.inner.map();
            let mut names = || self.inner.next_staging_name();
            plan(changes, &map, &mut names)
        };
        // A failed step does not hold up the others: they belong to other entries, and a
        // half-applied change list is better than one not applied at all. The first error is
        // reported, so that the engine retries.
        let mut first: Option<MirrorError> = None;
        for step in &steps {
            if let Err(error) = self.run_step(step) {
                tracing::warn!(?step, %error, "a step of the change list failed");
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), |f| Err(f.into()))
    }

    fn state(&self, identifier: EntryIdentifier) -> Result<LocalState, PlatformError> {
        let path = self.inner.path(identifier)?;
        let folder = identifier.container().is_some();
        local_state(&path, folder).map_err(|f| with_identifier(identifier, f).into())
    }

    fn dehydrate(&self, identifier: EntryIdentifier, unpin: bool) -> Result<(), PlatformError> {
        if identifier.container().is_some() {
            return Err(MirrorError::FolderNotDehydratable(identifier).into());
        }
        let path = self.inner.path(identifier)?;
        match placeholder::dehydrate(&path, unpin).map_err(|f| with_identifier(identifier, f)) {
            Ok(()) => Ok(()),
            Err(MirrorError::InUse(k)) => {
                // A program holds the file open. The engine retries — but perhaps only after a
                // restart, and until then a revoked copy must not stand there as "at the server's
                // state". The "not in sync" mark survives the end of the process; the next
                // `NOTIFY_FILE_CLOSE_COMPLETION` sees it and dehydrates then (ADR-D04, "when in
                // doubt, remove").
                if let Err(error) = placeholder::mark_outdated(&path) {
                    tracing::warn!(%error, "the `outdated` mark could not be set");
                }
                Err(PlatformError::InUse(k))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn remove(&self, identifier: EntryIdentifier) -> Result<(), PlatformError> {
        self.remove_entry(identifier).map_err(Into::into)
    }

    fn clear_everything(&self) -> Result<(), PlatformError> {
        // Order: disconnect first (after that no callback arrives and nobody is still hydrating),
        // then delete the tree (the root has to be registered still for that, otherwise the
        // placeholders are ordinary files with foreign reparse points), then unregister.
        self.disconnect();
        let root = self.inner.root.clone();
        // Read before the registration goes: the key name of the navigation pane entry carries the
        // account. Signing out has it in hand; the uninstallation does not — it builds a `Mirror`
        // and calls this method straight away (`crates/app/src/uninstall.rs`), and then the
        // account comes off the root itself, which at this point is still registered.
        let account = lock(&self.account).clone().or_else(|| {
            registration::existing_root(&root)
                .ok()
                .flatten()
                .filter(|details| details.provider == crate::checks::PROVIDER)
                .map(|details| details.account)
        });
        let _expectation = self.inner.expect("", true);
        let mut first: Option<MirrorError> = None;
        for child in win::read_directory(&root).map_err(PlatformError::from)? {
            if let Err(error) = win::delete(&connect(&root, &child.name), child.folder) {
                tracing::warn!(name = %child.name, %error, "an entry could not be deleted");
                first.get_or_insert(error);
            }
        }
        // The root folder itself stays: it carries no name of the user's, it may well sit in
        // Explorer's quick access, and an empty folder is not a piece of personal data.
        if let Err(error) = registration::unregister(&root) {
            first.get_or_insert(error);
        }
        // The keys of the navigation pane entry go with the registration: a row pointing at a
        // folder nobody serves any more would stay behind otherwise, per profile. Not fatal, for
        // the same reasons as when writing them (`platform::registry`) — and a sign-out has to go
        // through in any case.
        if let Some(account) = account
            && let Err(error) = remove_navigation_pane_entry(&account)
        {
            tracing::warn!(%error, "the entry in File Explorer's navigation pane stays behind");
        }
        self.inner.map().empty();
        *lock(&self.account) = None;
        first.map_or(Ok(()), |f| Err(f.into()))
    }
}
