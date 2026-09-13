//! Choosing and connecting the platform layer — the only place with `cfg` branches.
//!
//! The engine knows only [`edms_core::port::FileSystem`] (ADR-D02, rules R4/R5). Which
//! implementation stands behind it is decided here:
//!
//! | Target | Implementation | Particularity |
//! |---|---|---|
//! | Windows | `edms_cfapi::Mirror` | in the same process; cldflt calls the source directly |
//! | macOS | `edms_fileprovider::MacFileSystem` | the extension runs in a sandboxed process of its own and reaches the source through `edms-bridge` (ADR-D05) |
//! | everything else | none | the folder does not appear; everything else carries on |
//!
//! ## "Not available" is not a crash
//!
//! A Windows that is too old, a macOS without an installed app bundle, a compilation target
//! without a platform layer: every one of these cases ends in a [`PlatformAbort`] with a whole
//! sentence that the status line shows — and the rest of the app carries on. Signing in, the log
//! and `doctor` do not hang off the folder; whoever does not learn **why** the folder is missing
//! picks up the phone.
//!
//! ## The order
//!
//! The platform needs the [`NamespaceSource`] **before** it registers with the operating system
//! (`CfConnectSyncRoot` calls back immediately, Finder enumerates immediately). The engine only
//! needs the file system once it has changes to report. Hence: `Engine::start` first, then
//! `platform::connect(engine.source(), engine.intake(), …)`, then `Engine::set_file_system`.
//!
//! ## The other direction: what was dropped into a mail basket
//!
//! The source carries the server's truth downwards; [`edms_engine::Intake`] carries upwards the
//! one thing the platform sees and the engine cannot — a file the user dropped into a basket
//! (namespace v2 §3). Neither platform crate may name `edms-engine`
//! (`crates/architecture-rules/tests/rules.rs`), so each declares the seam for itself and this
//! module puts the two sides together: on Windows through [`EngineIntake`] for
//! `edms_cfapi::Intake`, on macOS through the beat that asks
//! `edms_fileprovider::MacFileSystem::arrivals`.
//!
//! **Provisioning** (registering the root, the display name, creating the domain) does **not**
//! happen here: that requires the account, and the account only exists after the sign-in. The
//! engine calls `FileSystem::place_ready` itself as soon as the session is up.
//!
//! the brief said "`Mirror::connect(mirror_path, provisioning, engine.source())`" —
//! here `Mirror::new`. `connect` is `new` **plus** `place_ready`, and `place_ready` needs the
//! account identifier (`edms_core::port::Provisioning`), which nobody has at startup. An invented
//! account in the root identifier would be a folder that after the sign-in belonged to the wrong
//! person (requirement 4).

use std::path::Path;
use std::sync::Arc;

use edms_core::port::{FileSystem, NamespaceSource};
use edms_i18n::{Catalog, key};

/// Why there is no folder on this machine.
///
/// Every variant becomes a whole sentence for the status line ([`Self::user_text`]); none of them
/// is a reason not to start the app. The variants are **values**, not sentences: a sentence in a
/// variant would be a sentence in one language.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformAbort {
    /// Neither Windows nor macOS — there is no folder at all here.
    ///
    /// `cfg` like the variants below and for the same reason: on Windows and on macOS there is a
    /// platform layer, and a variant nothing can build would be dead code there.
    #[cfg(not(any(windows, target_os = "macos")))]
    #[error("the folder client's mirror exists for Windows and macOS only")]
    NotOnThisPlatform,
    /// The platform layer refused; `{0}` is its own diagnosis.
    ///
    /// Windows only: on macOS the three cases below say what the matter is, and each of them says
    /// it more precisely than a wrapped diagnosis could.
    #[cfg(windows)]
    #[error("the platform layer is not available: {0}")]
    NotAvailable(String),
    /// The mirror path is not Unicode text (Windows: the Cloud Filter API takes no other).
    ///
    /// Windows only — on macOS the path never reaches a `PCWSTR`, and a variant that no code
    /// builds would be dead there.
    #[cfg(windows)]
    #[error("the mirror path `{0}` is not valid Unicode text")]
    PathNotUnicode(std::path::PathBuf),
    /// macOS: elasticdms was not started from an app bundle, so there is no extension.
    #[cfg(target_os = "macos")]
    #[error(
        "elasticdms is not running from an app bundle; the file provider extension is inside one"
    )]
    NotInBundle,
    /// The channel to the file provider extension could not be set up (macOS).
    ///
    /// macOS only: the channel exists there alone (ADR-D05); on Windows cldflt calls the source in
    /// the same process. Without `cfg` the variant would be dead on Windows, and `dead_code` would
    /// rightly report it — as with the fields of [`Platform`], the `cfg` branch here is the truth
    /// about the platform and not a way of silencing a lint.
    #[cfg(target_os = "macos")]
    #[error("the channel to the folder extension could not be set up: {0}")]
    Bridge(String),
    /// The operating system's randomness stays silent — without it there is no secret for the
    /// channel.
    ///
    /// macOS only, for the same reason as [`PlatformAbort::Bridge`]: the secret belongs to the
    /// channel, and the channel exists only there.
    #[cfg(target_os = "macos")]
    #[error("the secret for the folder channel could not be created: {0}")]
    Random(String),
}

impl PlatformAbort {
    /// The whole sentence for the status line, in the user's language.
    pub fn user_text(&self, catalogue: &Catalog) -> String {
        match self {
            #[cfg(not(any(windows, target_os = "macos")))]
            Self::NotOnThisPlatform => {
                catalogue.text(key::NOTICE_NO_FOLDER_ON_THIS_PLATFORM).to_owned()
            }
            #[cfg(windows)]
            Self::NotAvailable(reason) => {
                catalogue.format(key::ERROR_FOLDER_NOT_AVAILABLE, &[("reason", reason)])
            }
            #[cfg(windows)]
            Self::PathNotUnicode(path) => catalogue.format(
                key::NOTICE_MIRROR_PATH_NOT_UNICODE,
                &[("path", &path.display().to_string())],
            ),
            #[cfg(target_os = "macos")]
            Self::NotInBundle => catalogue.text(key::NOTICE_NO_FOLDER_WITHOUT_BUNDLE).to_owned(),
            #[cfg(target_os = "macos")]
            Self::Bridge(reason) => {
                catalogue.format(key::ERROR_FOLDER_CHANNEL, &[("reason", reason)])
            }
            #[cfg(target_os = "macos")]
            Self::Random(reason) => {
                catalogue.format(key::ERROR_FOLDER_SECRET, &[("reason", reason)])
            }
        }
    }
}

/// The connected platform layer.
///
/// It holds everything that has to live for as long as the folder stands: on macOS the bridge
/// server (its `Drop` closes the channel) and the path of the rendezvous file, which disappears
/// again on shutdown.
pub struct Platform {
    file_system: Arc<dyn FileSystem>,
    #[cfg(target_os = "macos")]
    bridge: Option<edms_bridge::BridgeServer>,
    #[cfg(target_os = "macos")]
    rendezvous: Option<std::path::PathBuf>,
    /// The beat that announces what lies in the mail baskets; its `Drop` stops the thread.
    #[cfg(target_os = "macos")]
    arrivals: Option<ArrivalBeat>,
}

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform").finish_non_exhaustive()
    }
}

impl Platform {
    /// The file system for [`edms_engine::Engine::set_file_system`].
    pub fn file_system(&self) -> Arc<dyn FileSystem> {
        Arc::clone(&self.file_system)
    }

    /// Clears the traces of this run: the rendezvous file and the channel.
    ///
    /// Calling it twice is harmless. If the file stays behind after a crash, it points at a dead
    /// process id; `Rendezvous::remove_own` clears it at the next start.
    pub fn stop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            // First the beat: a round that has just started would otherwise ask a file system
            // whose domain is about to go.
            drop(self.arrivals.take());
            if let Some(path) = self.rendezvous.take() {
                match edms_bridge::Rendezvous::remove_own(&path) {
                    Ok(removed) => tracing::debug!(removed, "rendezvous file cleared"),
                    Err(error) => tracing::warn!(%error, "rendezvous file stayed behind"),
                }
            }
            drop(self.bridge.take());
        }
    }
}

/// Connects the platform layer to the engine's source.
///
/// # Errors
///
/// [`PlatformAbort`] when this machine cannot carry a folder. The caller shows the sentence and
/// carries on.
pub fn connect(
    source: Arc<dyn NamespaceSource>,
    intake: edms_engine::Intake,
    mirror_path: &Path,
) -> Result<Platform, PlatformAbort> {
    // Every target needs a different part of the details; what it does not need is dropped
    // explicitly here, so that `-D warnings` stays green on every target.
    #[cfg(not(windows))]
    let _ = mirror_path;
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = (source, intake);

    #[cfg(windows)]
    {
        windows_mirror(source, intake, mirror_path)
    }
    #[cfg(target_os = "macos")]
    {
        macos_provider(source, intake)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(PlatformAbort::NotOnThisPlatform)
    }
}

/// The engine's [`edms_engine::Intake`] as `edms-cfapi` asks for it.
///
/// The crate may name `edms-core` and `edms-i18n` and nothing else, so it declares a trait of its
/// own; the app is the only crate that may know both sides
/// (`crates/architecture-rules/tests/rules.rs`). The adapter is the whole of the seam: no path in
/// the mirror is built here, and nothing is decided — `edms_cfapi::intake` has already asked
/// [`edms_core::namespace::Container::accepts_new_files`] before it calls.
#[cfg(windows)]
struct EngineIntake(edms_engine::Intake);

#[cfg(windows)]
impl edms_cfapi::Intake for EngineIntake {
    fn file_appeared(&self, basket: edms_core::identifier::BasketIdentifier, path: &str) {
        self.0.file_appeared(edms_engine::Arrival { basket, path: std::path::PathBuf::from(path) });
    }
}

/// Windows: the mirror over the Cloud Filter API, in the same process.
#[cfg(windows)]
fn windows_mirror(
    source: Arc<dyn NamespaceSource>,
    intake: edms_engine::Intake,
    mirror_path: &Path,
) -> Result<Platform, PlatformAbort> {
    // The question "can this Windows do it?" first — so that the user reads "Windows is too old"
    // and not an HRESULT from a registration that should never have been attempted.
    edms_cfapi::platform_available()
        .map_err(|error| PlatformAbort::NotAvailable(error.to_string()))?;
    let path = mirror_path
        .to_str()
        .ok_or_else(|| PlatformAbort::PathNotUnicode(mirror_path.to_path_buf()))?;
    let mirror = edms_cfapi::Mirror::new(path, source, Arc::new(EngineIntake(intake)))
        .map_err(|error| PlatformAbort::NotAvailable(error.to_string()))?;
    Ok(Platform { file_system: Arc::new(mirror) })
}

/// macOS: the channel to the extension, the domain management, and the beat over the baskets.
#[cfg(target_os = "macos")]
fn macos_provider(
    source: Arc<dyn NamespaceSource>,
    intake: edms_engine::Intake,
) -> Result<Platform, PlatformAbort> {
    // The bundle question first: without a bundle there is no extension, and without an extension
    // macOS accepts no domain (ADR-D05: PlugInKit loads only what lies in `Contents/PlugIns` of a
    // bundle). The channel would then be a door nobody ever knocks on — and the rendezvous file of
    // a run that has no folder is nothing but confusion.
    if !runs_in_bundle() {
        return Err(PlatformAbort::NotInBundle);
    }
    // 32 random bytes from `edms-crypto` — that crate has the only tested randomness in the
    // house, and `edms-bridge` deliberately has none of its own.
    let mut bytes = [0u8; edms_bridge::SECRET_BYTES];
    edms_crypto::random::fill(&mut bytes)
        .map_err(|error| PlatformAbort::Random(error.to_string()))?;
    let secret = edms_bridge::secret_from_bytes(&bytes);
    let server = edms_bridge::BridgeServer::start(Arc::clone(&source), &secret)
        .map_err(|error| PlatformAbort::Bridge(error.to_string()))?;
    let path = edms_bridge::Rendezvous::default_path()
        .map_err(|error| PlatformAbort::Bridge(error.to_string()))?;
    server.rendezvous().write(&path).map_err(|error| PlatformAbort::Bridge(error.to_string()))?;
    tracing::info!(port = server.port(), path = %path.display(), "the folder channel is up");
    let file_system = Arc::new(edms_fileprovider::filesystem::MacFileSystem::new());
    let arrivals = ArrivalBeat::start(Arc::clone(&file_system), source, intake);
    Ok(Platform {
        file_system,
        bridge: Some(server),
        rendezvous: Some(path),
        arrivals: Some(arrivals),
    })
}

/// How often the mail baskets are looked at.
///
/// Two seconds, the same window the engine already waits out: a file counts as finished when its
/// size and modification time have stood still for two seconds (ADR-D08 point 3). Looking more
/// often would only find files that are not ready yet. `edms_cfapi::intake::LOOK_AGAIN` says the
/// same number for Windows, and for the same reason.
#[cfg(target_os = "macos")]
const LOOK_AGAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// The beat that tells the engine what lies in the mail baskets.
///
/// macOS announces nothing of its own accord. A file created in the folder makes the system ask
/// the extension for an item it can hand back, and namespace v2 §2 defines no entry identifier
/// for a file lying in a basket — so `createItemBasedOnTemplate:` refuses
/// (`edms_fileprovider::extension`, module header). What is left is looking: at the start, after
/// the provider has come back (the next round asks the domain afresh), and on this beat.
/// Announcing the same path twice costs nothing — the engine drops the second one; announcing one
/// too seldom loses a receipt.
#[cfg(target_os = "macos")]
struct ArrivalBeat {
    /// `true` once the beat is to end. The condition variable wakes the sleeping thread, so that
    /// quitting does not wait out the interval.
    stop: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    /// `None` when the thread could not be started; the reason then stands in the log.
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl ArrivalBeat {
    fn start(
        file_system: Arc<edms_fileprovider::filesystem::MacFileSystem>,
        source: Arc<dyn NamespaceSource>,
        intake: edms_engine::Intake,
    ) -> Self {
        let stop = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let mine = Arc::clone(&stop);
        let thread =
            std::thread::Builder::new().name("edms-arrivals".to_owned()).spawn(move || {
                let (ended, wake) = (&mine.0, &mine.1);
                loop {
                    // A round that crashes must not end the beat: from then on nothing dropped
                    // into a basket would ever be taken in again, and nothing would say so. The
                    // one place that can panic here is `EngineSource::children` against a runtime
                    // that is shutting down (`edms_engine::source`, `runnable`).
                    let round = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        look(&file_system, source.as_ref(), &intake);
                    }));
                    if round.is_err() {
                        tracing::warn!("a look at the mail baskets crashed; the beat carries on");
                    }
                    let waiting = ended.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if *waiting {
                        return;
                    }
                    let (waiting, _) = wake
                        .wait_timeout(waiting, LOOK_AGAIN)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if *waiting {
                        return;
                    }
                }
            });
        match thread {
            Ok(thread) => Self { stop, thread: Some(thread) },
            Err(error) => {
                // Without this thread nothing dropped into a basket is ever taken in, and the user
                // waits for a receipt nobody is looking for.
                tracing::error!(%error, "the beat over the mail baskets could not be started");
                Self { stop, thread: None }
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for ArrivalBeat {
    fn drop(&mut self) {
        {
            let (ended, wake) = (&self.stop.0, &self.stop.1);
            *ended.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            wake.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            // The join waits out the round in flight, never the interval — that is what the
            // condition variable is for. A round can wait: `EngineSource::children` fetches the
            // basket listing over the network the first time it is asked. `EngineView::stop`
            // stops the engine before it stops the platform, and a stopped engine answers at
            // once.
            let _ = thread.join();
        }
    }
}

/// One round: which baskets there are, what lies in them, and the engine is told.
#[cfg(target_os = "macos")]
fn look(
    file_system: &edms_fileprovider::filesystem::MacFileSystem,
    source: &dyn NamespaceSource,
    intake: &edms_engine::Intake,
) {
    let baskets = baskets_of(source);
    if baskets.is_empty() {
        return;
    }
    match file_system.arrivals(&baskets) {
        Ok(arrivals) => {
            for arrival in arrivals {
                // The conversion is the app's: `edms-fileprovider` may not name `edms-engine`
                // (architecture rule), and the two types carry the same two values.
                intake.file_appeared(edms_engine::Arrival {
                    basket: arrival.basket,
                    path: arrival.path,
                });
            }
        }
        // Before the sign-in there is no domain and hence no basket on disk. That is the normal
        // state at the start, not something to report every two seconds.
        Err(edms_core::port::PlatformError::NotReadyPosed) => {}
        Err(error) => tracing::debug!(%error, "the mail baskets could not be looked at"),
    }
}

/// The mail baskets the engine knows.
///
/// The match stands here because [`edms_core::namespace::Container`] has no accessor for the
/// identifier inside a variant. Before the sign-in the source answers with an error; there is
/// then nothing to announce, and that is not a fault worth a log line on every beat.
#[cfg(target_os = "macos")]
fn baskets_of(source: &dyn NamespaceSource) -> Vec<edms_core::identifier::BasketIdentifier> {
    use edms_core::namespace::Container;

    let Ok(entries) = source.children(Container::Baskets) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| match entry.identifier.container() {
            Some(Container::Basket(basket)) => Some(basket),
            _ => None,
        })
        .collect()
}

/// Whether this program is running out of a `.app` bundle.
///
/// The measurement is the path — `…/elasticdms.app/Contents/MacOS/elasticdms` (see
/// `scripts/macos-bundle.sh`). Asking `NSBundle` would be more precise, but it would need
/// Objective-C in the app, and the platform API belongs in `edms-fileprovider`.
#[cfg(target_os = "macos")]
fn runs_in_bundle() -> bool {
    std::env::current_exe().is_ok_and(|exe| is_bundle_path(&exe))
}

/// The testable core of [`runs_in_bundle`].
#[cfg(target_os = "macos")]
fn is_bundle_path(exe: &Path) -> bool {
    let Some(macos) = exe.parent() else { return false };
    if macos.file_name().is_none_or(|n| n != "MacOS") {
        return false;
    }
    let Some(contents) = macos.parent() else { return false };
    if contents.file_name().is_none_or(|n| n != "Contents") {
        return false;
    }
    contents
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".app"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_program_in_contents_macos_a_app_bundle_applies_as_bundled() {
        assert!(is_bundle_path(&PathBuf::from(
            "/Applications/elasticdms.app/Contents/MacOS/elasticdms"
        )));
    }

    #[test]
    fn a_program_from_target_debug_applies_not_as_bundled() {
        // Exactly this case happens on `cargo run`: the extension does not exist then, and the
        // status line has to say so instead of attempting a domain macOS refuses.
        assert!(!is_bundle_path(&PathBuf::from("/w/target/debug/elasticdms")));
        assert!(!is_bundle_path(&PathBuf::from("/w/elasticdms.app/MacOS/elasticdms")));
        assert!(!is_bundle_path(&PathBuf::from("/w/elasticdms/Contents/MacOS/elasticdms")));
        assert!(!is_bundle_path(&PathBuf::from("elasticdms")));
    }

    /// A source that answers the basket listing and nothing else.
    struct Listing(Result<Vec<edms_core::namespace::Entry>, edms_core::port::SourceError>);

    impl NamespaceSource for Listing {
        fn children(
            &self,
            container: edms_core::namespace::Container,
        ) -> Result<Vec<edms_core::namespace::Entry>, edms_core::port::SourceError> {
            assert_eq!(container, edms_core::namespace::Container::Baskets, "only this one");
            self.0.clone()
        }

        fn entry(
            &self,
            identifier: edms_core::namespace::EntryIdentifier,
        ) -> Result<edms_core::namespace::Entry, edms_core::port::SourceError> {
            Err(edms_core::port::SourceError::NotFound(identifier))
        }

        fn current_sequence(&self) -> Result<u64, edms_core::port::SourceError> {
            Err(edms_core::port::SourceError::NotSignedIn)
        }

        fn changes_since(
            &self,
            _sequence: u64,
            _max: usize,
        ) -> Result<edms_core::change::ChangeState, edms_core::port::SourceError> {
            Err(edms_core::port::SourceError::NotSignedIn)
        }

        fn content(
            &self,
            _identifier: edms_core::namespace::EntryIdentifier,
            _request: &edms_core::port::ContentRequest,
            _sink: &mut dyn edms_core::port::ContentSink,
        ) -> Result<edms_core::port::ContentReceipt, edms_core::port::SourceError> {
            Err(edms_core::port::SourceError::NotSignedIn)
        }
    }

    #[test]
    fn the_baskets_of_the_listing_come_back_in_its_order() {
        use edms_core::identifier::{BasketIdentifier, Identifier};
        use edms_core::namespace::{ContainerItem, baskets_entries};

        let first: BasketIdentifier = Identifier::from_value(1);
        let second: BasketIdentifier = Identifier::from_value(2);
        let entries = baskets_entries(&[
            ContainerItem { identifier: first, title: "Buchhaltung".into() },
            ContainerItem { identifier: second, title: "Post".into() },
        ]);
        assert_eq!(entries.len(), 2, "the listing really carries both");
        assert_eq!(baskets_of(&Listing(Ok(entries))), vec![first, second]);
    }

    #[test]
    fn an_entry_that_is_no_basket_is_passed_over_instead_of_becoming_one() {
        // The root listing is the counter-example that really occurs: three folders, none of them
        // a basket, and a hint file that is no container at all. Both are silently passed over —
        // a file dropped anywhere but in a basket is nothing the engine may be told about
        // (namespace v2 §3).
        let entries = edms_core::namespace::root_entries(edms_i18n::Language::De);
        assert_eq!(entries.len(), 4, "root: baskets, archives, searches, README");
        assert!(baskets_of(&Listing(Ok(entries))).is_empty());
    }

    #[test]
    fn before_the_sign_in_there_is_nothing_to_announce_and_no_crash() {
        // The source answers with an error until the session stands; the beat runs from the very
        // first second and must simply find nothing then.
        let refused = Listing(Err(edms_core::port::SourceError::NotSignedIn));
        assert!(baskets_of(&refused).is_empty());
    }
}
