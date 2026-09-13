//! The engine against the contract-faithful server mock — in the same process, over real HTTP.
//!
//! Here the whole program runs but for two places: the operating system is replaced by a
//! [`RecordingFilesystem`] that writes down every order, and the keychain by a [`MirrorVault`] the
//! test can look into. Everything else is real — DPoP proofs the mock really recomputes, nonce
//! retries, ETags, `304`, tombstones, real PDF bytes with real checksums.
//!
//! **Why two runtimes.** The mock needs one (it serves two listeners), the engine brings its own.
//! The test thread itself stands in **neither** — exactly like a cfAPI callback on Windows and a
//! Foundation thread on macOS. Only that way is the `Handle::block_on` in `edms_engine::source`
//! permitted at all, and only that way does this test check the path the platform really takes
//! later.

// Test code may `unwrap`/`expect` (clippy.toml); the helpers stand outside `#[test]`, and there
// clippy does not recognise them as test code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use edms_core::change::Change;
use edms_core::identifier::{BasketIdentifier, CommandIdentifier, DocumentIdentifier, Identifier};
use edms_core::log::LogKind;
use edms_core::namespace::{Container, Entry, EntryIdentifier};
use edms_core::port::{
    ContentRequest, ContentSink, FileSystem, LocalState, NamespaceSource, PlatformError,
    Provisioning, SinkError, SourceError,
};
use edms_engine::vault::{SLOT_DEVICE_KEY, SLOT_REFRESH_TOKEN, SLOT_SESSION_KEY, Vault};
use edms_mock::{CommandQuality, Configuration, Control, Fault, Mangling, Mock};

use edms_engine::{
    Arrival, Engine, EngineConfiguration, EngineEvent, EngineState, KeyBundle, ServerObject,
};
use edms_net::{Connection, ServerAccess};
use edms_store::Store;
use serde_json::{Value, json};
use tempfile::TempDir;

// ── Doubles for platform and keychain ───────────────────────────────────────────────────────

/// A file system that does nothing and writes everything down.
///
/// It additionally keeps a **local state** per entry: without it the decision
/// `edms_core::delivery::actions(reason, pinned)` could not be tested — and it is exactly what
/// decides whether a pinned file stays put on `SPACE_RECLAIM`.
#[derive(Debug, Default)]
struct RecordingFilesystem {
    changes: Mutex<Vec<Change>>,
    cleared: AtomicUsize,
    provisioned: AtomicUsize,
    states: Mutex<BTreeMap<EntryIdentifier, LocalState>>,
    dehydrated: Mutex<Vec<(EntryIdentifier, bool)>>,
    removed: Mutex<Vec<EntryIdentifier>>,
}

impl RecordingFilesystem {
    fn changes(&self) -> Vec<Change> {
        self.changes.lock().unwrap().clone()
    }

    fn cleared(&self) -> usize {
        self.cleared.load(Ordering::Acquire)
    }

    fn provisioned(&self) -> usize {
        self.provisioned.load(Ordering::Acquire)
    }

    /// Settles how an entry stands on this disk.
    fn store(&self, identifier: EntryIdentifier, state: LocalState) {
        self.states.lock().unwrap().insert(identifier, state);
    }

    /// The calls of `dehydrate`, together with the question whether it should unpin.
    fn dehydrated(&self) -> Vec<(EntryIdentifier, bool)> {
        self.dehydrated.lock().unwrap().clone()
    }

    /// The calls of `remove`.
    fn removed(&self) -> Vec<EntryIdentifier> {
        self.removed.lock().unwrap().clone()
    }
}

impl FileSystem for RecordingFilesystem {
    fn place_ready(&self, _provisioning: &Provisioning) -> Result<(), PlatformError> {
        self.provisioned.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn report_change(&self, changes: &[Change]) -> Result<(), PlatformError> {
        self.changes.lock().unwrap().extend_from_slice(changes);
        Ok(())
    }

    fn state(&self, identifier: EntryIdentifier) -> Result<LocalState, PlatformError> {
        Ok(self.states.lock().unwrap().get(&identifier).copied().unwrap_or_default())
    }

    fn dehydrate(&self, identifier: EntryIdentifier, unpin: bool) -> Result<(), PlatformError> {
        self.dehydrated.lock().unwrap().push((identifier, unpin));
        if let Some(state) = self.states.lock().unwrap().get_mut(&identifier) {
            state.hydrated = false;
            if unpin {
                state.pinned = false;
            }
        }
        Ok(())
    }

    fn remove(&self, identifier: EntryIdentifier) -> Result<(), PlatformError> {
        self.removed.lock().unwrap().push(identifier);
        self.states.lock().unwrap().remove(&identifier);
        Ok(())
    }

    fn clear_everything(&self) -> Result<(), PlatformError> {
        self.cleared.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

/// A vault the test may look into — otherwise "the secrets are gone" could not be asserted.
#[derive(Clone, Debug, Default)]
struct MirrorVault {
    slots: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MirrorVault {
    fn read_slot(&self, slot: &str) -> Option<Vec<u8>> {
        self.slots.lock().unwrap().get(slot).cloned()
    }

    fn set_slot(&self, slot: &str, value: &[u8]) {
        self.slots.lock().unwrap().insert(slot.to_owned(), value.to_vec());
    }

    fn slots(&self) -> Vec<String> {
        self.slots.lock().unwrap().keys().cloned().collect()
    }
}

impl Vault for MirrorVault {
    fn read(&self, slot: &str) -> Result<Option<Vec<u8>>, edms_engine::VaultError> {
        Ok(self.read_slot(slot))
    }

    fn write(&mut self, slot: &str, value: &[u8]) -> Result<(), edms_engine::VaultError> {
        self.set_slot(slot, value);
        Ok(())
    }

    fn delete(&mut self, slot: &str) -> Result<(), edms_engine::VaultError> {
        self.slots.lock().unwrap().remove(slot);
        Ok(())
    }
}

/// A content sink that writes along — and reports gaps instead of closing them.
#[derive(Debug, Default)]
struct RecordingSink {
    bytes: Vec<u8>,
    progress_reports: usize,
    writes: usize,
}

impl ContentSink for RecordingSink {
    fn progress(&mut self, _loaded: u64, _total: u64) {
        self.progress_reports += 1;
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), SinkError> {
        let offset = usize::try_from(offset).map_err(|error| SinkError(error.to_string()))?;
        if offset != self.bytes.len() {
            return Err(SinkError(format!(
                "chunks come ascending and without gaps; expected {}, came {offset}",
                self.bytes.len()
            )));
        }
        self.bytes.extend_from_slice(data);
        self.writes += 1;
        Ok(())
    }
}

// ── The test rig ────────────────────────────────────────────────────────────────────────────

struct Harness {
    engine: Engine,
    source: Arc<dyn NamespaceSource>,
    file_system: Arc<RecordingFilesystem>,
    vault: MirrorVault,
    control: Control,
    mock: Option<Mock>,
    runtime: tokio::runtime::Runtime,
    data_path: PathBuf,
    staging: PathBuf,
    /// Where the test plays the platform: the directory a mail basket has on disk.
    mirror_path: PathBuf,
    /// Where an ingested file waits for the server's confirmation.
    holding: PathBuf,
    app_base: String,
    _directory: TempDir,
}

impl Harness {
    fn new(configuration: Configuration) -> Self {
        let directory = tempfile::tempdir().expect("a working directory");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("a runtime for the mock");
        let mock = runtime.block_on(Mock::start(configuration)).expect("the mock");
        let control = mock.control();
        let app_base = mock.app_base().to_owned();

        let engine_config = EngineConfiguration::builder(directory.path())
            .with_address(mock.api_base(), mock.auth_base(), mock.app_base())
            .with_device_name("Arbeitsplatz Buchhaltung EG")
            .finished();
        let data_path = engine_config.data_path.clone();
        let staging = engine_config.staging.clone();
        let mirror_path = engine_config.mirror_path.clone();
        let holding = engine_config.holding.clone();

        let mut store = Store::open(&data_path).expect("the local state");
        let vault = MirrorVault::default();
        let bundle =
            KeyBundle::set_up(Box::new(vault.clone()), &mut store, None).expect("device and keys");
        let connection = Connection::new(
            &engine_config.api_base,
            &engine_config.auth_base,
            bundle.device(),
            "1.0.0",
        )
        .expect("the connection");
        let server: Arc<dyn ServerObject> =
            Arc::new(ServerAccess::new(connection, bundle.as_source()).expect("the server access"));

        let engine = Engine::start(engine_config, server, store, bundle).expect("the engine");
        let file_system = Arc::new(RecordingFilesystem::default());
        engine.set_file_system(Arc::clone(&file_system) as Arc<dyn FileSystem>);
        let source = engine.source();

        Self {
            engine,
            source,
            file_system,
            vault,
            control,
            mock: Some(mock),
            runtime,
            data_path,
            staging,
            mirror_path,
            holding,
            app_base,
            _directory: directory,
        }
    }

    /// A test rig whose delivery channel waits briefly.
    ///
    /// The server names its waiting time in `policy.deliveryWaitSeconds` (03 §7.0.5), and the
    /// engine keeps to it. One second instead of twenty-five turns a test that waits minutes on
    /// long polls into one that runs in seconds — and what is checked is exactly the path of
    /// operation.
    fn with_delivery_channel() -> Self {
        Self::new(Configuration {
            wait_time_max: 1,
            ..Configuration::default().awaiting_confirmation()
        })
    }

    /// A test rig whose device flow waits for a human being — that way the [`Control`] is really
    /// needed and not merely carried along.
    fn with_confirmation() -> Self {
        Self::new(Configuration::default().awaiting_confirmation())
    }

    /// Signs in and confirms the device flow like a human being in the browser.
    fn sign_in(&self) {
        self.engine.sign_in().expect("the sign-in starts");
        let state = wait(
            &self.engine,
            |state| {
                matches!(
                    state,
                    EngineState::LoginRuns { .. }
                        | EngineState::SignedIn { .. }
                        | EngineState::LoginRequired { .. }
                )
            },
            Duration::from_secs(30),
        );
        if let EngineState::LoginRuns { user_code, address, .. } = &state {
            assert!(
                address.starts_with(&self.app_base),
                "the confirmation page lies below the web interface: {address}"
            );
            assert!(self.control.confirm(user_code), "the mock knows the code");
        }
        wait(&self.engine, EngineState::is_signed_in, Duration::from_secs(60));
    }

    /// Stops both listeners; afterwards the server is no longer reachable.
    fn cut_the_network(&mut self) {
        if let Some(mock) = self.mock.take() {
            // With a deadline: `stop` waits for every running request, and the delivery channel
            // holds a long poll open for 25 seconds. New connections the mock stops accepting with
            // the shutdown signal already — which is exactly what this test needs.
            let _ = self.runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), mock.stop()).await
            });
        }
    }

    /// A second writer on the same database.
    ///
    /// Only in the test, and only for what would otherwise need a restart — forgetting the delivery
    /// cursor, say. In operation exactly one process writes (`edms_store`, module head).
    fn second_store(&self) -> Store {
        Store::open(&self.data_path).expect("a second writer")
    }

    /// Queues a delivery command for **this** device.
    fn queue_command(
        &self,
        kind: &str,
        payload: Value,
        quality: CommandQuality,
    ) -> CommandIdentifier {
        self.control
            .queue_command(self.engine.device(), kind, payload, quality)
            .expect("the mock signs the command")
    }

    /// Waits until the server has the acknowledgement for a command, and returns it.
    fn wait_on_acknowledgement(&self, command: CommandIdentifier) -> Value {
        wait_until(
            || self.control.acknowledgement(command).is_some(),
            Duration::from_secs(60),
            "the command was not acknowledged",
        );
        self.control.acknowledgement(command).expect("just checked")
    }

    /// All names that stand in the usage log.
    fn log_names(&self) -> Vec<String> {
        self.engine
            .log(None, 500)
            .expect("the usage log")
            .rows
            .iter()
            .filter_map(|row| row.entry.subject().map(|subject| subject.name.clone()))
            .collect()
    }

    /// How often a log kind occurs.
    fn log_kinds(&self, wanted: LogKind) -> usize {
        self.engine
            .log(None, 500)
            .expect("the usage log")
            .rows
            .iter()
            .filter(|row| row.entry.kind() == wanted)
            .count()
    }

    /// Hands a file in: writes it into the basket's directory and says what the platform says.
    ///
    /// This is the whole seam. In operation the mirror lies here and the platform layer resolves
    /// the directory to its basket; the test does both by hand, because the recording file system
    /// above holds no directories of its own.
    fn drop_in_basket(&self, basket: BasketIdentifier, name: &str, bytes: &[u8]) -> PathBuf {
        let folder = self.mirror_path.join(basket.to_string());
        std::fs::create_dir_all(&folder).expect("the basket's directory");
        let path = folder.join(name);
        std::fs::write(&path, bytes).expect("the handed-in file");
        self.engine.intake().file_appeared(Arrival { basket, path: path.clone() });
        path
    }

    /// The subdirectories of the holding directory, one per ingest.
    fn held(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.holding)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
    }

    fn leftovers_in_staging(&self) -> usize {
        std::fs::read_dir(&self.staging)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| entry.path().extension().is_some_and(|end| end == "part"))
                    .count()
            })
            .unwrap_or_default()
    }
}

fn wait(engine: &Engine, check: impl Fn(&EngineState) -> bool, deadline: Duration) -> EngineState {
    let end = Instant::now() + deadline;
    loop {
        let state = engine.state_now();
        if check(&state) {
            return state;
        }
        assert!(Instant::now() < end, "state not reached; last: {state:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Waits until a condition holds; if the deadline passes, the test fails with `what`.
fn wait_until(mut check: impl FnMut() -> bool, deadline: Duration, what: &str) {
    let end = Instant::now() + deadline;
    loop {
        if check() {
            return;
        }
        assert!(Instant::now() < end, "{what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Collects what has been called out since the subscription.
fn events(receiver: &mut tokio::sync::broadcast::Receiver<EngineEvent>) -> Vec<EngineEvent> {
    let mut seen = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        seen.push(event);
    }
    seen
}

/// The addresses of all browser prompts.
fn browser_target(events: &[EngineEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            EngineEvent::OpenBrowser(address) => Some(address.clone()),
            _ => None,
        })
        .collect()
}

fn request(program: &str) -> ContentRequest {
    ContentRequest { requesting_application: Some(program.to_owned()) }
}

/// The archives of the example tenant, as the mirror shows them.
fn archives(harness: &Harness) -> Vec<Container> {
    harness
        .source
        .children(Container::Archives)
        .expect("the archive listing")
        .iter()
        .filter_map(|entry| entry.identifier.container())
        .collect()
}

/// Every case file of the example tenant — one per archive, and each one under its own.
fn cases(harness: &Harness) -> Vec<Entry> {
    archives(harness)
        .into_iter()
        .flat_map(|archive| {
            harness.source.children(archive).expect("the case listing of an archive")
        })
        .collect()
}

/// The first case file (Akte) of the example tenant, as the mirror shows it.
fn first_case(harness: &Harness) -> Container {
    let all = cases(harness);
    let sulzer = all
        .iter()
        .find(|entry| entry.name.contains("Sulzer"))
        .unwrap_or_else(|| panic!("the case file \"Sulzer …\" is missing: {:?}", names(&all)));
    sulzer.identifier.container().expect("a case file is a container")
}

/// A mail basket of the example tenant — the drop target of the ingest.
///
/// Out of the mock's control and not out of the mirror: which basket it is does not matter here,
/// and the listing is the reconcile's business, not the ingest's.
fn a_basket(harness: &Harness) -> BasketIdentifier {
    harness.control.baskets().first().expect("the example tenant has mail baskets").0
}

fn names(entries: &[Entry]) -> Vec<String> {
    entries.iter().map(|entry| entry.name.clone()).collect()
}

/// A document from a container, together with its entry identifier.
fn a_document(harness: &Harness, container: Container) -> (EntryIdentifier, Entry) {
    let children = harness.source.children(container).expect("the document listing");
    let entry = children
        .iter()
        .find(|entry| entry.identifier.document().is_some())
        .unwrap_or_else(|| panic!("no document in {container}: {:?}", names(&children)));
    (entry.identifier, entry.clone())
}

fn document_identifier(identifier: EntryIdentifier) -> DocumentIdentifier {
    identifier.document().expect("a document")
}

// ── The samples ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_whole_way_from_the_sign_in_to_the_checked_content() {
    let harness = Harness::with_confirmation();
    let mut events = harness.engine.events();
    harness.sign_in();

    // The engine opens no browser — it tells the app which address (architecture rule R7).
    let mut browser_target = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let EngineEvent::OpenBrowser(address) = event {
            browser_target.push(address);
        }
    }
    assert_eq!(browser_target.len(), 1, "exactly one prompt: {browser_target:?}");
    assert!(browser_target[0].starts_with(&harness.app_base), "{}", browser_target[0]);

    harness.engine.reconcile_now(None).expect("the first reconcile");

    // The tree: mail baskets, archives and saved searches, nothing else (requirement 3,
    // namespace v2 §1).
    let root = harness.source.children(Container::Root).expect("the root");
    let root_names = names(&root);
    assert!(root_names.contains(&"Briefkörbe".to_owned()), "{root_names:?}");
    assert!(root_names.contains(&"Archive".to_owned()), "{root_names:?}");
    assert!(root_names.contains(&"Gespeicherte Suchen".to_owned()), "{root_names:?}");
    assert!(root_names.iter().any(|name| name == "LIESMICH.txt"), "{root_names:?}");

    let baskets = harness.source.children(Container::Baskets).expect("the basket listing");
    assert_eq!(baskets.len(), 2, "two mail baskets: {:?}", names(&baskets));
    let basket = baskets[0].identifier.container().expect("a basket is a container");
    assert!(basket.accepts_new_files(), "a basket is the only place that takes a file");
    assert!(
        harness.source.children(basket).expect("the basket listing").is_empty(),
        "a basket holds nothing of the server's (namespace v2 §4)"
    );

    // A case file hangs under exactly one archive, and each archive lists only its own.
    let archives = archives(&harness);
    assert_eq!(archives.len(), 2, "the example tenant has two archives: {archives:?}");
    for archive in &archives {
        let rows = harness.source.children(*archive).expect("the case listing of an archive");
        assert_eq!(rows.len(), 1, "one case file per archive: {:?}", names(&rows));
    }

    let case = first_case(&harness);
    let children = harness.source.children(case).expect("the document listing");
    assert_eq!(children.len(), 5, "five documents: {:?}", names(&children));

    assert_eq!(
        harness.file_system.provisioned(),
        1,
        "the mirror is named as soon as it is known whom it belongs to"
    );

    // The platform got the changes — the mirror does not come into being by itself.
    assert!(
        !harness.file_system.changes().is_empty(),
        "the engine reports to the file system what has changed"
    );

    // The content: loaded, checked, handed over.
    let (identifier, entry) = a_document(&harness, case);
    let details = entry.file().expect("a file").clone();
    let mut sink = RecordingSink::default();
    let receipt = harness
        .source
        .content(identifier, &request("Preview"), &mut sink)
        .expect("the content arrives");

    assert_eq!(receipt.size, details.size);
    assert_eq!(receipt.sha256, details.sha256, "the receipt names the checked, matching checksum");
    assert_eq!(sink.bytes.len() as u64, details.size);
    assert_eq!(
        edms_crypto::checksum::sha256(&sink.bytes),
        details.sha256.expect("a document carries a checksum"),
        "what stands in the sink is exactly what the listing promised"
    );
    assert!(sink.progress_reports > 0, "during the load the sink reports progress");
    assert_eq!(harness.leftovers_in_staging(), 0, "the scratch file is cleared away");

    // Every hydration is an access — on the server side …
    let access = harness.control.access_log();
    assert_eq!(access.len(), 1, "exactly one access: {access:?}");
    assert_eq!(access[0].document, document_identifier(identifier));
    assert_eq!(access[0].device, harness.engine.device());
    assert_eq!(
        access[0].application.as_deref(),
        Some("Preview"),
        "the program name is an observation, and it arrives"
    );

    // … and locally in the usage log (ADR-D07).
    let log = harness.engine.log(None, 50).expect("the usage log");
    let opened = log
        .rows
        .iter()
        .find(|row| row.entry.kind() == LogKind::Opened)
        .expect("a row \"Opened\" (`log.opened`)");
    assert_eq!(opened.entry.subject().map(|s| s.name.as_str()), Some(entry.name.as_str()));
    assert!(
        log.rows.iter().any(|row| row.entry.kind() == LogKind::SignedIn),
        "and a row \"Signed in\" (`log.signed_in`)"
    );
}

#[test]
fn a_mutilated_content_does_not_reach_the_platform() {
    // Contract test T13: the server notices the hash error only at the last Read, after `200` and
    // all headers have been sent. A client that passes bytes through puts a broken file into the
    // folder and takes it for complete.
    let harness = Harness::with_confirmation();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, entry) = a_document(&harness, case);

    assert!(harness.control.mangle(document_identifier(identifier), Mangling::Tampered));

    let mut sink = RecordingSink::default();
    let error = harness
        .source
        .content(identifier, &request("Preview"), &mut sink)
        .expect_err("a falsified content is not taken over");

    match error {
        SourceError::Integrity { expected, actual } => {
            assert_eq!(Some(expected), entry.file().and_then(|file| file.sha256));
            assert_ne!(expected, actual);
        }
        other => panic!("expected an integrity error, came: {other}"),
    }
    assert!(sink.bytes.is_empty(), "no byte reaches the platform");
    assert_eq!(sink.writes, 0, "the sink was not written to a single time");
    assert_eq!(harness.leftovers_in_staging(), 0, "the scratch file is gone");

    let log = harness.engine.log(None, 50).expect("the usage log");
    assert!(
        log.rows.iter().any(|row| row.entry.kind() == LogKind::OpenFailed),
        "a quiet failure would be an access nobody sees"
    );
}

#[test]
fn without_a_network_the_remembered_state_comes_and_otherwise_a_reason() {
    let mut harness = Harness::with_confirmation();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let before = harness.source.children(case).expect("the document listing");
    assert!(!before.is_empty());

    // A case file nobody has ever opened — it has no remembered state.
    let all = cases(&harness);
    let unopened = all
        .iter()
        .filter_map(|entry| entry.identifier.container())
        .find(|container| *container != case)
        .expect("the second case file");

    harness.cut_the_network();

    // The tree stays put (ADR-D01, point 8).
    let after = harness.source.children(case).expect("the remembered state still holds");
    assert_eq!(names(&after), names(&before));
    assert_eq!(
        harness.source.children(Container::Archives).map(|rows| rows.len()).ok(),
        Some(2),
        "the archive listing stands too"
    );

    // Without a remembered state the user learns the reason instead of seeing an empty folder.
    let error = harness
        .source
        .children(unopened)
        .expect_err("for a folder never fetched there is nothing to show offline");
    assert_eq!(error, SourceError::NoNetwork, "{error}");
}

#[test]
fn the_renewal_rotates_the_refresh_token_and_stores_it_before_use() {
    // Short-lived access tokens: with them the lead from `session::REFRESH_LEAD_SECOND` takes hold
    // on every call, and the rotation is testable without waiting.
    let harness = Harness::new(Configuration {
        access_token_second: 60,
        ..Configuration::default().awaiting_confirmation()
    });
    harness.sign_in();
    let first = harness.vault.read_slot(SLOT_REFRESH_TOKEN).expect("a refresh token in the vault");

    harness.engine.reconcile_now(None).expect("the reconcile renews on the way");
    let second = harness.vault.read_slot(SLOT_REFRESH_TOKEN).expect("and one afterwards");

    assert_ne!(first, second, "every renewal rotates (03 §6.3.3)");
    assert!(harness.engine.state_now().is_signed_in(), "the session runs on");
    assert!(
        harness.vault.slots().contains(&SLOT_SESSION_KEY.to_owned()),
        "the refresh token is bound to the session key; it has to survive the restart"
    );
}

#[test]
fn a_reused_refresh_token_leads_to_login_required() {
    // Contract test T14: reusing a rotated refresh token revokes the whole token family across
    // devices. The client must never "just try again".
    let harness = Harness::new(Configuration {
        access_token_second: 60,
        ..Configuration::default().awaiting_confirmation()
    });
    harness.sign_in();
    let old = harness.vault.read_slot(SLOT_REFRESH_TOKEN).expect("the first refresh token");
    harness.engine.reconcile_now(None).expect("renew once");
    let new = harness.vault.read_slot(SLOT_REFRESH_TOKEN).expect("the rotated one");
    assert_ne!(old, new);

    // Now the used-up token back into the vault — that is what it looks like when an image of the
    // disk is restored or somebody has captured the old token.
    harness.vault.set_slot(SLOT_REFRESH_TOKEN, &old);
    let _ = harness.engine.reconcile_now(None);

    let state = wait(
        &harness.engine,
        |state| matches!(state, EngineState::LoginRequired { .. }),
        Duration::from_secs(20),
    );
    assert!(matches!(state, EngineState::LoginRequired { .. }), "{state:?}");
    assert!(
        harness.vault.read_slot(SLOT_REFRESH_TOKEN).is_none(),
        "a token the server no longer accepts does not stay put"
    );

    let log = harness.engine.log(None, 50).expect("the usage log");
    assert!(
        log.rows.iter().any(|row| row.entry.kind() == LogKind::SecurityWarning),
        "the user's only opportunity to notice it: {:?}",
        log.rows.iter().map(|row| row.entry.kind()).collect::<Vec<_>>()
    );
}

#[test]
fn signing_out_clears_mirror_namespace_and_secrets() {
    let harness = Harness::with_confirmation();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    assert!(!harness.source.children(case).expect("the document listing").is_empty());
    assert!(harness.vault.read_slot(SLOT_REFRESH_TOKEN).is_some());

    harness.engine.sign_out().expect("the sign-out runs through");

    assert_eq!(harness.file_system.cleared(), 1, "the mirror was cleared (requirement 4)");
    let report = harness.engine.report().expect("the report");
    assert_eq!(report.cases, 0, "the namespace is empty");
    assert_eq!(report.searches, 0);
    assert!(!report.session.token_in_store, "no token in memory any more");
    assert_eq!(report.session.state, Some(edms_store::SessionState::SignedOut));

    assert!(harness.vault.read_slot(SLOT_REFRESH_TOKEN).is_none(), "the refresh token is gone");
    assert!(harness.vault.read_slot(SLOT_SESSION_KEY).is_none(), "the session key is gone");
    assert!(
        harness.vault.read_slot(SLOT_DEVICE_KEY).is_some(),
        "the device key belongs to the machine and stays"
    );
    assert!(matches!(harness.engine.state_now(), EngineState::SignedOut));
}

#[test]
fn changes_since_delivers_the_journal_and_an_old_anchor_expires() {
    let harness = Harness::with_confirmation();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let _ = harness.source.children(case).expect("the document listing");

    let sequence = harness.source.current_sequence().expect("the current sequence number");
    assert!(sequence > 0, "the reconcile has handed out sequence numbers");

    let state_from_zero =
        harness.source.changes_since(0, 10_000).expect("everything since the start");
    assert!(!state_from_zero.changes.is_empty());
    assert_eq!(state_from_zero.until_sequence, sequence);
    assert!(!state_from_zero.more);

    let empty = harness.source.changes_since(sequence, 10_000).expect("since now there is nothing");
    assert!(empty.changes.is_empty());
    assert_eq!(empty.until_sequence, sequence);

    // The sign-out empties the namespace; every anchor from the time before is expired afterwards,
    // and the platform enumerates afresh instead of guessing gaps.
    harness.engine.sign_out().expect("the sign-out");
    let error = harness
        .source
        .changes_since(0, 10_000)
        .expect_err("an anchor from before the sign-out no longer holds");
    assert_eq!(error, SourceError::AnchorExpired, "{error}");
}

#[test]
fn an_erased_document_comes_back_through_no_listing() {
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let before = harness.source.children(case).expect("the document listing");
    let erased = document_identifier(before[0].identifier);
    let other = document_identifier(before[1].identifier);

    // The real way: a signed erasure command out of the delivery channel (ADR-D04, reason ERASURE).
    let command = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [erased.to_string()], "reason": "ERASURE"}),
        CommandQuality::Valid,
    );
    assert_eq!(harness.wait_on_acknowledgement(command)["outcome"], "APPLIED");

    // The server goes on delivering the document; only a new version turns the ETag, so that the
    // listing is fetched anew at all.
    assert!(harness.control.new_version(other).is_some());
    harness.engine.reconcile_now(Some(case)).expect("the reconcile after the erasure");

    let after = harness.source.children(case).expect("the document listing");
    assert!(
        !after.iter().any(|entry| entry.identifier.document() == Some(erased)),
        "a stale listing does not undo a DSGVO (GDPR) erasure: {:?}",
        names(&after)
    );
    assert_eq!(after.len(), before.len() - 1);
}

#[test]
fn a_device_without_approval_shows_the_self_computed_fingerprint() {
    // `pending_admin_approval` is the rule, not the exception (03 §7.0.5): without the comparison
    // by a human being, anybody who installs the software could enrol a device against the
    // tenant.
    let harness =
        Harness::new(Configuration::default().awaiting_approval().awaiting_confirmation());
    harness.engine.sign_in().expect("the sign-in starts");
    let state = wait(
        &harness.engine,
        |state| matches!(state, EngineState::AwaitingApproval { .. }),
        Duration::from_secs(20),
    );
    let EngineState::AwaitingApproval { fingerprint } = state else { unreachable!("just checked") };
    assert!(!fingerprint.is_empty(), "the fingerprint belongs on the screen");
    assert!(fingerprint.contains('-'), "readable in groups: {fingerprint}");

    let report = harness.engine.report().expect("the report");
    assert!(report.key.anchored, "the anchor stands before the approval comes");
    assert_eq!(report.key.fingerprint, fingerprint, "the same, self-computed value");
    assert!(!report.key.carries, "before the confirmation the set carries no signature");

    // After the approval the sign-in goes through, and the anchor counts as confirmed.
    assert!(harness.control.approve_device(harness.engine.device()));
    harness.sign_in();
    let report = harness.engine.report().expect("the report after the approval");
    assert!(report.key.carries, "now the set withstands signatures");
}

// ── The delivery channel (ADR-D04, 03 §7.3) ─────────────────────────────────────────────────

/// A document this device does not know — for commands that are to find nothing.
fn foreign_document(value: u128) -> DocumentIdentifier {
    Identifier::from_value(value)
}

/// Stores an entry as locally present, hydrated and pinned.
fn pinned() -> LocalState {
    LocalState { present: true, hydrated: true, pinned: true }
}

#[test]
fn a_signed_erasure_command_removes_the_entry_redacts_the_log_and_acknowledges() {
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, entry) = a_document(&harness, case);
    let document = document_identifier(identifier);

    // An earlier row that carries the name — it is the reason for the redaction.
    let mut sink = RecordingSink::default();
    harness.source.content(identifier, &request("Preview"), &mut sink).expect("the content");
    assert!(harness.log_names().contains(&entry.name), "the row stands there with a name");

    harness.file_system.store(identifier, pinned());
    let mut heard = harness.engine.events();

    let command = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [document.to_string()], "reason": "ERASURE"}),
        CommandQuality::Valid,
    );
    let acknowledgement = harness.wait_on_acknowledgement(command);
    assert_eq!(acknowledgement["outcome"], "APPLIED", "{acknowledgement}");

    // The entry is gone, and no listing brings it back (tombstone).
    let children = harness.source.children(case).expect("the document listing");
    assert!(
        !children.iter().any(|entry| entry.identifier.document() == Some(document)),
        "the erased document still stands there: {:?}",
        names(&children)
    );

    // The platform was unpinned and cleared — without unpinning the release would fail.
    assert!(
        harness.file_system.dehydrated().contains(&(identifier, true)),
        "the pinning has to fall before the release: {:?}",
        harness.file_system.dehydrated()
    );
    assert!(harness.file_system.removed().contains(&identifier), "the placeholder belongs gone");

    // The usage log: one nameless row, and the old name is gone.
    assert_eq!(harness.log_kinds(LogKind::ErasedByOrder), 1);
    let page = harness.engine.log(None, 500).expect("the usage log");
    let erasure_row = page
        .rows
        .iter()
        .find(|row| row.entry.kind() == LogKind::ErasedByOrder)
        .expect("a row \"Erased by order\" (`log.erased_by_order`)");
    assert!(erasure_row.entry.subject().is_none(), "an erasure leaves no name behind");
    assert!(
        !harness.log_names().contains(&entry.name),
        "the title must not of all things stay standing in the window meant for transparency: {:?}",
        harness.log_names()
    );

    // The user learns of it — without the title ("disappearing must not be silent").
    let seen = events(&mut heard);
    let hints: Vec<&String> = seen
        .iter()
        .filter_map(|event| match event {
            EngineEvent::Hint { text } => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(hints.len(), 1, "exactly one hint: {hints:?}");
    assert!(
        !hints[0].contains(&entry.name),
        "the hint on an erasure names no document title (ADR-011): {}",
        hints[0]
    );
    assert!(
        seen.contains(&EngineEvent::CommandApplied { kind: edms_engine::CommandKind::Dehydrate }),
        "the app learns the kind, never the subject: {seen:?}"
    );
}

#[test]
fn an_access_revocation_lifts_the_pinning_and_releases_the_copy() {
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, _) = a_document(&harness, case);
    let document = document_identifier(identifier);
    harness.file_system.store(identifier, pinned());

    let command = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [document.to_string()], "reason": "ACCESS_REVOKED"}),
        CommandQuality::Valid,
    );
    assert_eq!(harness.wait_on_acknowledgement(command)["outcome"], "APPLIED");

    assert!(
        harness.file_system.dehydrated().contains(&(identifier, true)),
        "an access revocation lifts the pinning: {:?}",
        harness.file_system.dehydrated()
    );
    assert!(
        harness.file_system.removed().is_empty(),
        "the entry stays standing; the next listing takes it out"
    );
    let children = harness.source.children(case).expect("the document listing");
    assert!(
        children.iter().any(|entry| entry.identifier.document() == Some(document)),
        "an access revocation is not an erasure: {:?}",
        names(&children)
    );
}

#[test]
fn space_reclaim_leaves_a_pinned_file_untouched() {
    // "Routine is no occasion to overrule a deliberate decision of the user; space is made
    // elsewhere." (03 §7.3.3)
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, _) = a_document(&harness, case);
    let document = document_identifier(identifier);
    harness.file_system.store(identifier, pinned());

    let command = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [document.to_string()], "reason": "SPACE_RECLAIM"}),
        CommandQuality::Valid,
    );
    assert_eq!(harness.wait_on_acknowledgement(command)["outcome"], "APPLIED");

    assert!(
        !harness.file_system.dehydrated().iter().any(|(entry, _)| *entry == identifier),
        "the pinned copy stays: {:?}",
        harness.file_system.dehydrated()
    );
    assert!(harness.file_system.removed().is_empty());
    assert!(
        harness
            .source
            .children(case)
            .expect("the document listing")
            .iter()
            .any(|entry| entry.identifier == identifier)
    );
}

#[test]
fn a_command_with_a_foreign_signature_executes_nothing_and_warns() {
    // The threat model expressly names the compromised server (geraete-auth §5.4); a test rig that
    // only produces valid commands would show nothing of it.
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, _) = a_document(&harness, case);
    let document = document_identifier(identifier);
    harness.file_system.store(identifier, pinned());
    let before = harness.log_kinds(LogKind::SecurityWarning);

    let command = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [document.to_string()], "reason": "ERASURE"}),
        CommandQuality::ForeignSignature,
    );
    let acknowledgement = harness.wait_on_acknowledgement(command);
    assert_eq!(acknowledgement["outcome"], "REJECTED", "{acknowledgement}");

    assert!(harness.file_system.dehydrated().is_empty(), "nothing was released");
    assert!(harness.file_system.removed().is_empty(), "nothing was removed");
    assert!(
        harness
            .source
            .children(case)
            .expect("the document listing")
            .iter()
            .any(|entry| entry.identifier == identifier),
        "an erasure carried out unchecked would be a remote erasure tool"
    );
    assert_eq!(
        harness.log_kinds(LogKind::SecurityWarning),
        before + 1,
        "the user's only opportunity to notice it"
    );
    assert_eq!(harness.log_kinds(LogKind::ErasedByOrder), 0);
}

#[test]
fn an_unknown_kind_and_an_unknown_payload_field_are_rejected() {
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, _) = a_document(&harness, case);
    let document = document_identifier(identifier);

    let unknown = harness.queue_command("DELETE_EVERYTHING", json!({}), CommandQuality::Valid);
    let acknowledgement = harness.wait_on_acknowledgement(unknown);
    assert_eq!(acknowledgement["outcome"], "REJECTED", "{acknowledgement}");
    assert!(
        acknowledgement["detail"].as_str().unwrap_or_default().contains("DELETE_EVERYTHING"),
        "the reason names the kind, never a title: {acknowledgement}"
    );

    // A field the client does not know can narrow the meaning; half carried out would mean doing
    // more than was ordered (03 §7.3.2).
    let half = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [document.to_string()], "reason": "ERASURE", "includePinned": false}),
        CommandQuality::Valid,
    );
    assert_eq!(harness.wait_on_acknowledgement(half)["outcome"], "REJECTED");
    assert!(
        harness
            .source
            .children(case)
            .expect("the document listing")
            .iter()
            .any(|entry| entry.identifier == identifier),
        "rejected means: nothing happens"
    );
}

#[test]
fn the_same_command_delivered_twice_is_executed_only_once() {
    // Delivered at least once, effective once (03 §7.3.6). So that the server really sends the same
    // command a second time, the first two acknowledgement attempts fail here — and the cursor is
    // reset, as if the client had restarted.
    let harness = Harness::with_delivery_channel();
    harness.sign_in();
    harness.engine.reconcile_now(None).expect("the first reconcile");
    let case = first_case(&harness);
    let (identifier, _) = a_document(&harness, case);
    let document = document_identifier(identifier);

    harness.control.inject_fault(Fault {
        path: "/v1/delivery/commands/cmd_".to_owned(),
        status: Some(503),
        delay_millis: 1_500,
        times: 2,
    });

    let command = harness.queue_command(
        "DEHYDRATE",
        json!({"documentIds": [document.to_string()], "reason": "ERASURE"}),
        CommandQuality::Valid,
    );

    wait_until(
        || {
            harness
                .source
                .children(case)
                .map(|children| !children.iter().any(|entry| entry.identifier == identifier))
                .unwrap_or_default()
        },
        Duration::from_secs(60),
        "the erasure command was not carried out",
    );
    assert!(
        harness.control.acknowledgement(command).is_none(),
        "the acknowledgement is still stuck"
    );

    // As after a crash: the cursor is gone, the server delivers everything open again.
    {
        let mut second = harness.second_store();
        second
            .delete_setting(edms_engine::delivery::SETTING_CURSOR)
            .expect("the cursor falls away");
    }

    let acknowledgement = harness.wait_on_acknowledgement(command);
    assert_eq!(acknowledgement["outcome"], "APPLIED", "{acknowledgement}");
    assert_eq!(
        harness.log_kinds(LogKind::ErasedByOrder),
        1,
        "a second run would be a second log entry about a document that no longer exists"
    );
}

#[test]
fn the_rate_limit_holds_back_the_thirty_first_command_of_a_minute() {
    // The limit prevents no erasure — the server splits large erasures up — but it prevents a
    // single misused key from emptying the whole mirror in one go (ADR-013).
    let harness = Harness::with_delivery_channel();
    harness.sign_in();

    let limit = usize::try_from(edms_core::delivery::MAX_COMMANDS_PER_MINUTE).expect("it fits");
    let commands: Vec<CommandIdentifier> = (0..=limit)
        .map(|number| {
            harness.queue_command(
                "DEHYDRATE",
                json!({
                    "documentIds": [foreign_document(number as u128 + 1).to_string()],
                    "reason": "SPACE_RECLAIM"
                }),
                CommandQuality::Valid,
            )
        })
        .collect();

    let acknowledgement: Vec<Value> =
        commands.iter().map(|command| harness.wait_on_acknowledgement(*command)).collect();
    let outcomes: Vec<&str> =
        acknowledgement.iter().map(|row| row["outcome"].as_str().unwrap_or_default()).collect();

    assert_eq!(
        outcomes.iter().filter(|outcome| **outcome == "NOT_APPLICABLE").count(),
        limit,
        "exactly {limit} commands per minute: {outcomes:?}"
    );
    let held_back: Vec<&Value> =
        acknowledgement.iter().filter(|row| row["outcome"] == "FAILED").collect();
    assert_eq!(held_back.len(), 1, "the thirty-first is held back: {outcomes:?}");
    assert!(
        held_back[0]["detail"].as_str().unwrap_or_default().contains("rate limit"),
        "and it says why: {}",
        held_back[0]
    );
    // `FAILED` is the only outcome that is not final: the command comes again.
    assert_ne!(held_back[0]["outcome"], "REJECTED", "a command held back is not discarded");
}

// ── The mail baskets (ADR-D08, 03 §7.4, namespace v2 §5) ────────────────────────────────────

/// A small, valid PDF — real bytes, real checksum.
fn receipt(number: usize) -> Vec<u8> {
    format!("%PDF-1.4\n% receipt {number}\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\n")
        .into_bytes()
}

#[test]
fn a_filed_document_is_uploaded_put_aside_and_opens_exactly_one_tab() {
    let harness = Harness::with_confirmation();
    harness.sign_in();
    let mut heard = harness.engine.events();

    let name = "Rechnung 2026-0412.pdf";
    let basket = a_basket(&harness);
    let path = harness.drop_in_basket(basket, name, &receipt(1));

    wait_until(|| !harness.held().is_empty(), Duration::from_secs(60), "the file was not ingested");

    // A basket is a trigger, not a filing destination — and nothing is **ever** deleted.
    assert!(!path.exists(), "the file no longer lies in the basket");
    let filed = harness.held();
    assert_eq!(filed.len(), 1, "one directory per ingest: {filed:?}");
    assert!(
        filed[0].file_name().and_then(|name| name.to_str()).unwrap_or_default().starts_with("upl_"),
        "named after the upload identifier: {filed:?}"
    );
    assert!(filed[0].join(name).exists(), "until the server confirms, it is the only copy");

    // Upload first, then the browser: the address comes after the completion.
    wait_until(
        || !harness.control.recordings_for("/v1/ingest-uploads").is_empty(),
        Duration::from_secs(10),
        "the upload did not arrive at the server",
    );
    // The upload arriving at the server and the prompt being called out are two steps: the
    // engine reports `OpenBrowser` only after `:complete` and after the whole batch has joined.
    // A single drain here read the empty channel in between — green on macOS, red on a Windows
    // runner after eleven minutes, and the difference was speed, not behaviour.
    let mut targets: Vec<String> = Vec::new();
    wait_until(
        || {
            targets.extend(browser_target(&events(&mut heard)));
            !targets.is_empty()
        },
        Duration::from_secs(10),
        "no browser prompt",
    );
    // One more follow-up: had the engine reported a second tab, it would come now.
    std::thread::sleep(Duration::from_millis(500));
    targets.extend(browser_target(&events(&mut heard)));
    assert_eq!(targets.len(), 1, "exactly one prompt: {targets:?}");
    assert!(
        targets[0].starts_with(&harness.app_base),
        "only below the web interface: {}",
        targets[0]
    );

    let page = harness.engine.log(None, 500).expect("the usage log");
    let row = page
        .rows
        .iter()
        .find(|row| row.entry.kind() == LogKind::IngestAccepted)
        .expect("a row \"Taken into the inbox\" (`log.ingest_accepted`)");
    assert_eq!(row.entry.subject().map(|s| s.name.as_str()), Some(name));

    // That the submission named a basket the server knows is what the mock checked before it
    // promised anything: an unknown one is a `404` and no grant (03 §7.4.1, namespace v2 §7).
    assert!(
        harness.control.baskets().iter().any(|(known, _)| *known == basket),
        "the ingest went into a basket that exists"
    );
}

#[test]
fn a_file_out_of_a_basket_that_is_gone_is_filed_nowhere_else() {
    // "A basket that no longer exists is a `404` … not a silent filing somewhere else"
    // (namespace v2 §7). The receipt then stays where it is — losing it would be worse than
    // failing.
    let harness = Harness::with_confirmation();
    harness.sign_in();
    let basket = harness.control.create_basket("Briefkorb Ablage");
    assert!(harness.control.remove_basket(basket), "the basket is gone before the file comes");

    let path = harness.drop_in_basket(basket, "Rechnung ohne Korb.pdf", &receipt(4));
    wait_until(
        || harness.log_kinds(LogKind::IngestFailed) > 0,
        Duration::from_secs(60),
        "the refusal did not reach the usage log",
    );

    assert!(path.exists(), "nothing is ever deleted, a refusal least of all");
    assert!(harness.held().is_empty(), "and nothing was put aside");
    assert_eq!(harness.log_kinds(LogKind::IngestAccepted), 0);
    let refused = harness.control.recordings_for("/v1/ingest-uploads");
    assert_eq!(refused.len(), 1, "one attempt, and it is not repeated at once: {refused:?}");
    assert_eq!(refused[0].status, 404);
}

#[test]
fn five_files_at_once_open_a_single_inbox_page() {
    // "200 tabs would no longer be a workstation" (ADR-D08 point 4).
    let harness = Harness::with_confirmation();
    harness.sign_in();
    let mut heard = harness.engine.events();

    let basket = a_basket(&harness);
    for number in 0..5 {
        harness.drop_in_basket(basket, &format!("Beleg {number}.pdf"), &receipt(number));
    }

    wait_until(
        || harness.held().len() == 5,
        Duration::from_secs(90),
        "not all five files were ingested",
    );
    let mut targets: Vec<String> = Vec::new();
    wait_until(
        || {
            targets.extend(browser_target(&events(&mut heard)));
            !targets.is_empty()
        },
        Duration::from_secs(10),
        "no browser prompt",
    );
    // One more follow-up: had the engine reported a tab per file, they would come now.
    std::thread::sleep(Duration::from_millis(500));
    targets.extend(browser_target(&events(&mut heard)));

    assert_eq!(targets.len(), 1, "exactly one prompt, not five: {targets:?}");
    assert_eq!(
        targets[0],
        format!(
            "{}{}",
            harness.app_base.trim_end_matches('/'),
            edms_engine::ingest::PATH_INBOX_PAGE
        ),
        "with more than three files the inbox page"
    );
}

#[test]
fn a_file_that_is_still_growing_is_not_ingested() {
    use std::io::Write as _;

    let harness = Harness::with_confirmation();
    harness.sign_in();

    let name = "Scan.pdf";
    let path = harness.drop_in_basket(a_basket(&harness), name, &receipt(7));
    // Longer than the stability deadline, but never two seconds unchanged in one stretch.
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(300));
        let mut file =
            std::fs::OpenOptions::new().append(true).open(&path).expect("the growing file");
        file.write_all(b"% more bytes\n").expect("append");
    }

    assert!(path.exists(), "a growing file stays lying (ADR-D08 point 3)");
    assert!(
        harness.held().is_empty(),
        "whoever uploads at the first byte puts half a PDF into the archive"
    );
    assert!(
        harness.control.recordings_for("/v1/ingest-uploads").is_empty(),
        "and it has not even been announced"
    );

    // As soon as it stands still, it is ingested — the watch forgets nothing, and it needs no
    // second announcement for that.
    wait_until(
        || !harness.held().is_empty(),
        Duration::from_secs(60),
        "the finished file was not ingested",
    );
    assert!(!path.exists());
}

#[test]
fn without_a_network_a_filed_document_stays_lying_and_the_progress_says_so() {
    // "Offline files stay lying, the icon shows 'N files waiting', and the ingest begins by itself
    // at the next contact." (ADR-D08 point 6)
    let mut harness = Harness::with_confirmation();
    harness.sign_in();
    let basket = a_basket(&harness);
    harness.cut_the_network();
    let mut heard = harness.engine.events();

    let name = "Beleg ohne Netz.pdf";
    let path = harness.drop_in_basket(basket, name, &receipt(3));

    let mut open = Vec::new();
    wait_until(
        || {
            open.extend(events(&mut heard).into_iter().filter_map(|event| match event {
                EngineEvent::InboxProgress { open } => Some(open),
                _ => None,
            }));
            open.contains(&1)
        },
        Duration::from_secs(30),
        "the progress does not name the waiting file",
    );

    assert!(path.exists(), "the file stays lying, it is the copy");
    assert!(harness.held().is_empty(), "moving happens only after the completion");
    assert_eq!(
        harness.log_kinds(LogKind::IngestFailed),
        0,
        "a failure of the line is not a failure the log enumerates per attempt"
    );
    assert_eq!(harness.log_kinds(LogKind::IngestAccepted), 0);
}
