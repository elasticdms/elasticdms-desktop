//! The mail baskets — a trigger, not a filing destination (requirement 2, ADR-D08, 03 §7.4).
//!
//! A basket lies **inside** the mirror, where the user is already looking (namespace v2 §1, §5);
//! the inbox folder next to it is gone. Whoever drags a file into a basket hands it in; the
//! capture happens afterwards in the browser. The engine does exactly three things for that —
//! upload, put the file aside, name an address to the app.
//!
//! ```text
//! mirror/Briefkörbe/Briefkorb Buchhaltung/    the platform watches, the engine is told
//!   Rechnung.pdf              size and modification time unchanged for 2 s → finished
//!   Scan.pdf.crdownload       passed over (still growing)
//!
//! <app data>/holding/upl_01JK…/Rechnung.pdf   ← moved after the ingest, never deleted
//! ```
//!
//! ## The seam: the platform knows paths, the engine knows baskets
//!
//! [`Intake::file_appeared`] is the whole of it. The platform layer (`edms-cfapi`,
//! `edms-fileprovider`) sees a file creation in a directory, resolves that directory to the
//! [`BasketIdentifier`] it stands for — [`edms_core::namespace::Container::accepts_new_files`]
//! says which directories may take one at all — and hands both over as an [`Arrival`]. From then
//! on the engine reads that path and nothing else: it never builds a path in the mirror itself,
//! because the folder names are the server's titles and the platform is the layer that already
//! has them on disk.
//!
//! The engine holds what it was told **only in memory**. After a restart the platform announces
//! afresh what still lies in the baskets; a queue in the database would be a second truth about a
//! directory the engine cannot see.
//!
//! ## The order is the rule
//!
//! **Upload first, then open the browser.** `POST /v1/ingest-uploads` · `PUT <uploadUrl>` ·
//! `POST …:complete`, and **after that** [`crate::EngineEvent::OpenBrowser`]. The
//! clarification-case invariant demands that "an event never ends without a persisted result"
//! (`scope-cut` A6): if the document already lies in the inbox, a closed browser is harmless. In
//! the reverse order every abort would lose the document — and the user would believe he had
//! handed it in.
//!
//! **Never delete.** After the ingest the file moves into the holding directory of the app's own
//! data directory, `<holding>/<uploadId>/`. Until the server has confirmed the ingest, the local
//! file is the only copy (GoBD completeness, ADR-D08 point 5). It does **not** stay in the
//! mirror: the mirror shows the server's truth, not our spool (namespace v2 §5).
//!
//! **An error applies to one file, never to the batch.** Whoever drags in twenty receipts and fails
//! on one has handed in nineteen — and still has the twentieth lying in the basket, together with a
//! row in the usage log that says why.
//!
//! **Offline everything stays lying.** The files are ingested by themselves at the next contact;
//! [`crate::EngineEvent::InboxProgress`] tells the user interface how many are waiting (ADR-D08
//! point 6).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{BasketIdentifier, UploadIdentifier};
use edms_core::log::{LogEntry, LogKind, Subject};
use edms_core::time::Timestamp;
use edms_crypto::checksum::Sha256Machine;
use edms_net::IdempotencyKey;
use edms_store::InboxPending;
use edms_wire::ingest::{UploadGrant, UploadRequest};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::engine::Shared;
use crate::error::EngineError;
use crate::event::EngineEvent;
use crate::time::now;

/// The page that is opened instead of many capture tabs.
pub const PATH_INBOX_PAGE: &str = "/postkorb";

/// How long size and modification time have to stand for a file to count as finished.
///
/// Two seconds (ADR-D08 point 3). A browser, a scanner or a copy operation writes in morsels;
/// whoever uploads at the first byte puts half a PDF into the archive.
pub const STABLE: Duration = Duration::from_secs(2);

/// The fallback beat when nothing wakes the watch.
///
/// The platform reports a creation, but not every platform reports every one: network drives,
/// mounted images and some virus scanners swallow the operating system's events. A file that
/// stays lying because nobody said it was there would be a receipt nobody misses — hence the
/// announced files are looked at again in this beat even without a wake-up call.
pub const ROUND: Duration = Duration::from_secs(10);

/// The short beat for as long as a file is still growing.
pub const FOLLOW_UP: Duration = Duration::from_millis(500);

/// How many files are ingested at the same time (ADR-D08 point 4).
pub const CONCURRENT_INGESTS: usize = 3;

/// Up to how many files each get a capture tab; above that one with the inbox page.
///
/// "200 tabs would no longer be a workstation" (ADR-D08 point 4).
pub const TABS_MAX: usize = 3;

/// Extensions of half-finished files that are passed over (ADR-D08 point 3).
pub const EXTENSION_SKIP: [&str; 3] = ["crdownload", "part", "tmp"];

/// The prefix of Microsoft Office's backup copies.
pub const PREFIX_SKIP: &str = "~$";

/// Chunk size when reading for the checksum.
const READ_CHUNK: usize = 256 * 1024;

/// How long a file is left alone after a failed attempt.
///
/// Offline every attempt fails, and without a retry delay that would be one network call per file
/// and second — on thirty receipts left lying, sustained fire that gains nothing.
pub const RETRY_AFTER: Duration = Duration::from_secs(60);

/// A file the platform saw appear in a mail basket.
///
/// Serializable, because on macOS it travels from the file-provider extension through
/// `edms-bridge` into the app's process and has to arrive there as the same statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arrival {
    /// The basket it was dropped into — the target of the ingest (03 §7.4.1).
    pub basket: BasketIdentifier,
    /// Where the file lies **now**. The platform resolved it; the engine only reads it.
    pub path: PathBuf,
}

/// The engine's mouth: the platform announces, the engine ingests.
///
/// Cheap to clone and callable from any thread — the platform layers call on threads of the
/// operating system, and none of them is a worker of the engine's runtime. The call returns at
/// once; the file is looked at in the engine's own beat until it stands still.
#[derive(Clone)]
pub struct Intake {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Intake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intake").finish_non_exhaustive()
    }
}

impl Intake {
    pub(crate) const fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// "A file appeared in basket `bsk_…`."
    ///
    /// Announcing the same path twice is harmless: the second call is dropped, so that a platform
    /// reporting both `create` and `close-write` does not ingest anything twice.
    ///
    /// A half-finished file — `.crdownload`, `.part`, `.tmp`, `~$…` or a name with a leading dot
    /// — never enters the queue; it is announced again under its final name when the program that
    /// is writing it renames it.
    pub fn file_appeared(&self, arrival: Arrival) {
        let Some(name) = file_name(&arrival.path) else {
            // A name that is not valid UTF-8 does not go out as `fileName` (03 §7.4.1); it would
            // otherwise wait in the queue for ever, so it stands at least in the application log.
            tracing::warn!(
                path = %arrival.path.display(),
                "a file with an unreadable name is passed over"
            );
            return;
        };
        if skip(name) {
            return;
        }
        if self.shared.announced.add(arrival) {
            self.shared.announced.wake();
        }
    }
}

/// What was announced and is not yet ingested — the queue the watch works through.
#[derive(Debug, Default)]
pub(crate) struct Announced {
    files: Mutex<BTreeMap<PathBuf, BasketIdentifier>>,
    awake: Notify,
}

impl Announced {
    /// Takes a file in; `false` when the same path was already waiting.
    fn add(&self, arrival: Arrival) -> bool {
        self.files().insert(arrival.path, arrival.basket).is_none()
    }

    /// Forgets a file — ingested, or gone from the basket again.
    fn forget(&self, path: &Path) {
        self.files().remove(path);
    }

    /// The queue as it stands now.
    fn all(&self) -> BTreeMap<PathBuf, BasketIdentifier> {
        self.files().clone()
    }

    /// Wakes the watch.
    fn wake(&self) {
        self.awake.notify_one();
    }

    /// Waits for the next announcement.
    async fn woken(&self) {
        self.awake.notified().await;
    }

    /// A poisoned lock means a thread died holding it; the queue itself is whole. A panic here
    /// would take the ingest away from the user instead of showing an error.
    fn files(&self) -> MutexGuard<'_, BTreeMap<PathBuf, BasketIdentifier>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The watch: look at what was announced, wait, ingest — for as long as the engine runs.
pub(crate) async fn watch(shared: Arc<Shared>) {
    let mut watch = Watch::default();
    loop {
        if shared.is_stopped() {
            return;
        }
        pass(&shared, &mut watch).await;
        // A short follow-up happens only while a file is still growing; otherwise the fallback
        // beat is enough, because an announcement wakes us anyway. A queue in which a file waits
        // for its retry is no reason to look every half second.
        let wait_time = if watch.grows_something() { FOLLOW_UP } else { ROUND };
        let _ = tokio::time::timeout(wait_time, shared.announced.woken()).await;
    }
}

/// What the watch keeps between two passes.
#[derive(Debug, Default)]
struct Watch {
    /// What was to be seen at the last look — the basis of the stability deadline.
    observes: HashMap<PathBuf, Sample>,
    /// When a failed file is attempted again at the earliest.
    retry_after: HashMap<PathBuf, Instant>,
    /// The progress last called out; `None` for as long as none has been called out.
    reported: Option<usize>,
}

impl Watch {
    /// Whether an announced file has not yet met its stability deadline.
    fn grows_something(&self) -> bool {
        self.observes.values().any(|sample| sample.since.elapsed() < STABLE)
    }

    /// Calls the progress out when it has changed.
    fn report_progress(&mut self, shared: &Shared, open: usize) {
        if self.reported == Some(open) {
            return;
        }
        shared.record(EngineEvent::InboxProgress { open });
        self.reported = Some(open);
    }
}

/// One pass: see what is finished, and ingest it.
async fn pass(shared: &Arc<Shared>, watch: &mut Watch) {
    let mut alive: BTreeMap<PathBuf, (BasketIdentifier, u64, Timestamp)> = BTreeMap::new();
    for (path, &basket) in &shared.announced.all() {
        match look(path) {
            Some((size, changed)) => {
                alive.insert(path.clone(), (basket, size, changed));
            }
            // The file is gone: the user pulled it back out of the basket, or another program
            // took it. That is no error and no reason to keep asking about it.
            None => shared.announced.forget(path),
        }
    }
    // What is gone is no longer observed.
    watch.observes.retain(|path, _| alive.contains_key(path));
    watch.retry_after.retain(|path, _| alive.contains_key(path));

    let now = Instant::now();
    let mut finished = Vec::new();
    for (path, &(basket, size, changed)) in &alive {
        match watch.observes.get(path) {
            Some(sample) if sample.unchanged(size, changed) => {
                let waits = watch.retry_after.get(path).is_some_and(|earliest| *earliest > now);
                if sample.since.elapsed() >= STABLE && !waits {
                    finished.push(Arrival { basket, path: path.clone() });
                }
            }
            // New or grown: the deadline starts over, and an earlier failed attempt no longer
            // counts — it is a different file.
            _ => {
                watch.retry_after.remove(path);
                watch.observes.insert(path.clone(), Sample { size, changed, since: now });
            }
        }
    }
    // **Before** the batch: the progress is to show the queue, not its result.
    watch.report_progress(shared, alive.len());

    // Without a sign-in there is no inbox for anything to go into. The files stay lying, and the
    // ingest begins by itself at the next contact (ADR-D08 point 6).
    if finished.is_empty() || !shared.state().is_signed_in() {
        return;
    }
    // The samples stay put: an ingested file is gone from the queue at the next look anyway, and
    // a failed one keeps its retry delay that way — whoever forgot it here would see it as "new"
    // straight afterwards and try again at once.
    let failed = adopt_batch(shared, finished).await;
    for path in failed {
        watch.retry_after.insert(path, Instant::now() + RETRY_AFTER);
    }
    // What is left over is the new queue.
    watch.report_progress(shared, shared.announced.all().len());
}

/// What was to be seen at the last look at a file.
#[derive(Debug, Clone, Copy)]
struct Sample {
    size: u64,
    changed: Timestamp,
    since: Instant,
}

impl Sample {
    const fn unchanged(&self, size: u64, changed: Timestamp) -> bool {
        self.size == size && self.changed.unix_millis() == changed.unix_millis()
    }
}

/// Size and modification time of an announced file; `None` when it is not a readable file any
/// more.
fn look(path: &Path) -> Option<(u64, Timestamp)> {
    let details = std::fs::metadata(path).ok()?;
    details.is_file().then(|| (details.len(), changed_at(&details)))
}

/// The file name, if it can go out as `fileName` (03 §7.4.1).
fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(std::ffi::OsStr::to_str)
}

/// Whether a file is passed over.
///
/// ADR-D08 point 3 names `.crdownload`, `.part`, `.tmp` and `~$`. Passed over in
/// addition are **all** names with a leading dot. They keep `.DS_Store` (macOS) and `desktop.ini`
/// out of the archive — a file the operating system created itself has been handed in by nobody.
fn skip(name: &str) -> bool {
    if name.starts_with('.') || name.starts_with(PREFIX_SKIP) || name.is_empty() {
        return true;
    }
    name.rsplit_once('.').is_some_and(|(_, extension)| {
        EXTENSION_SKIP.contains(&extension.to_ascii_lowercase().as_str())
    })
}

/// The modification time; without a readable time [`Timestamp::NULL`].
///
/// No crash and no invented time: a file without a readable modification time then counts as stable
/// over its size — slower to recognise, never wrong.
fn changed_at(details: &std::fs::Metadata) -> Timestamp {
    let millis = details
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |span| i64::try_from(span.as_millis()).unwrap_or(i64::MAX));
    Timestamp::from_unix_millis(millis)
}

/// Ingests a batch: at most [`CONCURRENT_INGESTS`] at the same time, one outcome of its own per
/// file. Returns the paths that failed.
async fn adopt_batch(shared: &Arc<Shared>, files: Vec<Arrival>) -> Vec<PathBuf> {
    let gate = Arc::new(Semaphore::new(CONCURRENT_INGESTS));
    let mut tasks: JoinSet<Result<String, PathBuf>> = JoinSet::new();
    for arrival in files {
        let shared = Arc::clone(shared);
        let gate = Arc::clone(&gate);
        tasks.spawn(async move {
            let Ok(_permit) = gate.acquire_owned().await else {
                return Err(arrival.path);
            };
            let name = file_name(&arrival.path).unwrap_or_default().to_owned();
            match adopt_file(&shared, &arrival).await {
                Ok(capture) => {
                    shared.announced.forget(&arrival.path);
                    shared.append_log(&adopted(&shared, &name));
                    Ok(capture)
                }
                Err(error) => {
                    // The file stays lying and is attempted again later — a receipt the client
                    // throws away because it cannot get rid of it is the most expensive mistake of
                    // this program.
                    tracing::warn!(name, %error, "ingest out of a mail basket failed");
                    if !only_the_link(&error) {
                        shared.append_log(&failed(&shared, &name, &error.to_string()));
                    }
                    Err(arrival.path)
                }
            }
        });
    }
    let mut captures = Vec::new();
    let mut failed = Vec::new();
    while let Some(finished) = tasks.join_next().await {
        match finished {
            Ok(Ok(capture)) => captures.push(capture),
            Ok(Err(path)) => failed.push(path),
            Err(error) => tracing::error!(%error, "an ingest ended unexpectedly"),
        }
    }
    for target in browser_target(&shared.configuration.app_base, captures) {
        shared.record(EngineEvent::OpenBrowser(target));
    }
    failed
}

/// Whether a failure was only down to the line — then it stays out of the usage log.
///
/// "Offline files stay lying" (ADR-D08 point 6) is no error but the intended state. One row per
/// file and attempt would, after a day without a network, crowd every real row out of the log
/// (`edms_store::LOG_PER_ACCOUNT`) — in exactly the window that is to show what happened to the
/// user's files.
fn only_the_link(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::NoNetwork(_) | EngineError::NotSignedIn | EngineError::SessionExpired(_)
    )
}

/// Which addresses the app is to open.
///
/// Up to [`TABS_MAX`] captures one each; above that **one** with the inbox page. What is counted
/// are the **successful** ingests: a tab for a file that did not arrive would show a capture page
/// without a document.
fn browser_target(app_base: &str, captures: Vec<String>) -> Vec<String> {
    if captures.len() <= TABS_MAX {
        return captures;
    }
    vec![format!("{}{PATH_INBOX_PAGE}", app_base.trim_end_matches('/'))]
}

/// One file: check, create, upload, complete, put aside.
///
/// # Errors
///
/// Every step that does not go through — with the reason in a whole sentence. The file stays lying
/// in any case.
async fn adopt_file(shared: &Arc<Shared>, arrival: &Arrival) -> Result<String, EngineError> {
    let path = arrival.path.as_path();
    let name = file_name(path)
        .ok_or_else(|| EngineError::Internal(format!("`{}` has no usable name", path.display())))?;
    let (sha256, size, changed) = check_file(path).await?;
    let note = note_key(arrival.basket, name);
    let pending = pending(shared, &note, size, changed)?;
    let key = IdempotencyKey::read(&pending.key)
        .map_err(|error| EngineError::Internal(error.to_string()))?;

    // The basket is the target: a submission without one would leave the server to decide where
    // the document goes, and a basket that is gone is answered `404` instead of a filing
    // somewhere else (03 §7.4, namespace v2 §7).
    let request = UploadRequest::new(arrival.basket, name, media_type(name), size, sha256)
        .map_err(|error| EngineError::Refused(error.to_string()))?;
    let grant = crate::value_from(
        shared.server.inbox_create(&request, &key).await,
        "the ingest into the inbox",
        shared.catalogue(),
    )?
    .value;
    // **Before** the bytes: after a crash the next run knows where the file belongs.
    shared.store().set_inbox_upload(&note, grant.upload_id)?;

    load_high(shared, path, &grant, size, sha256).await?;

    // A key of its own per attempt: `:complete` carries the upload identifier in the path and for
    // that reason alone cannot create a second document (03 §6.0.10 demands a stable key only for
    // the same payload, and that one is empty here).
    let completion_key = IdempotencyKey::generate(now())?;
    let completion = crate::value_from(
        shared.server.inbox_complete(grant.upload_id, &completion_key).await,
        "the completion of the ingest",
        shared.catalogue(),
    )?
    .value;

    // Now the document lies in the inbox; only now may the file leave the basket.
    hold(shared, path, name, grant.upload_id)?;
    shared.store().forget_inbox(&note)?;

    // The address is checked: a foreign capture page in the user's browser is a sign-in form that
    // looks genuine because the client opened it (03 §7.4.3).
    completion
        .browser_target(&shared.configuration.app_base)
        .map(ToOwned::to_owned)
        .map_err(|error| EngineError::Security(error.to_string()))
}

/// Under which name the note for a file stands in the store.
///
/// Basket **and** file name: the same `Rechnung.pdf` can lie in two baskets at the same time, and
/// the note carries the idempotency key. One key for two payloads would be
/// `422 idempotency-key-reuse` (03 §6.0.10), and the second receipt would be lost.
fn note_key(basket: BasketIdentifier, name: &str) -> String {
    format!("{basket}/{name}")
}

/// The note for a file — the existing one when it still fits, otherwise a new one.
///
/// The key stays the same across every retry; only that way is the repetition not a second upload
/// (03 §6.0.10). If the file grows in between, it is a different payload and a new key.
fn pending(
    shared: &Arc<Shared>,
    note: &str,
    size: u64,
    changed: Timestamp,
) -> Result<InboxPending, EngineError> {
    if let Some(present) = shared.store().inbox(note)?
        && present.matches(size, changed)
    {
        return Ok(present);
    }
    let new = InboxPending {
        file: note.to_owned(),
        key: edms_crypto::random::ulid(now())?,
        size,
        changed,
        upload: None,
        created: now(),
    };
    shared.store().remember_inbox(&new)?;
    Ok(new)
}

/// Checksum, size and modification time — over exactly the bytes that are about to go out.
async fn check_file(path: &Path) -> Result<(Sha256Value, u64, Timestamp), EngineError> {
    let directory_error = |error: std::io::Error| EngineError::Directory {
        path: path.to_owned(),
        reason: error.to_string(),
    };
    let details = tokio::fs::metadata(path).await.map_err(directory_error)?;
    let changed = changed_at(&details);
    let mut file = tokio::fs::File::open(path).await.map_err(directory_error)?;
    let mut machine = Sha256Machine::new();
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = file.read(&mut buffer).await.map_err(directory_error)?;
        if read == 0 {
            break;
        }
        machine.add_added(&buffer[..read]);
    }
    let size = machine.read();
    Ok((machine.finished(), size, changed))
}

/// The bytes, with `Content-Digest` over exactly them.
async fn load_high(
    shared: &Arc<Shared>,
    path: &Path,
    grant: &UploadGrant,
    size: u64,
    sha256: Sha256Value,
) -> Result<(), EngineError> {
    let file = tokio::fs::File::open(path).await.map_err(|error| EngineError::Directory {
        path: path.to_owned(),
        reason: error.to_string(),
    })?;
    crate::value_from(
        shared.server.inbox_high_load(grant, file, size, sha256).await,
        "the upload",
        shared.catalogue(),
    )?;
    Ok(())
}

/// Puts the file into `<holding>/<uploadId>/` — **never** delete (ADR-D08 point 5).
///
/// The holding directory lies in the app's own data directory and not in the mirror (namespace v2
/// §5): what stands in the mirror is what the server says, and a spool of ours would be a second
/// answer to the same question. In the basket the file is gone afterwards, which is exactly what
/// §4 asks for — until the confirmation it was visible there because until then it was the only
/// copy.
fn hold(
    shared: &Shared,
    path: &Path,
    name: &str,
    upload: UploadIdentifier,
) -> Result<(), EngineError> {
    let target = shared.configuration.holding.join(upload.to_string());
    std::fs::create_dir_all(&target).map_err(|error| EngineError::Directory {
        path: target.clone(),
        reason: error.to_string(),
    })?;
    let after = target.join(name);
    // A rename across two file systems fails (`EXDEV`), and mirror and data directory do not lie
    // on the same volume on every machine. Then the copy comes first and the basket's copy goes
    // only once the one in the holding directory stands — in that order nothing is ever the only
    // copy for a moment.
    if std::fs::rename(path, &after).is_ok() {
        return Ok(());
    }
    let directory_error = |error: std::io::Error| EngineError::Directory {
        path: after.clone(),
        reason: error.to_string(),
    };
    std::fs::copy(path, &after).map_err(directory_error)?;
    std::fs::remove_file(path).map_err(|error| EngineError::Directory {
        path: path.to_owned(),
        reason: error.to_string(),
    })
}

/// The media type from the extension — the operating system's statement.
///
/// The server recognises the type **anew itself** (03 §7.4.1): the extension on a workstation is a
/// claim by the user, not a property of the bytes. Hence the short list of what really arrives in
/// an archive is enough here; everything else is honestly `application/octet-stream` and not a
/// guessed type.
fn media_type(name: &str) -> &'static str {
    let extension =
        name.rsplit_once('.').map(|(_, end)| end.to_ascii_lowercase()).unwrap_or_default();
    match extension.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "tif" | "tiff" => "image/tiff",
        "txt" | "csv" => "text/plain",
        "xml" => "application/xml",
        "eml" => "message/rfc822",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

/// The row "taken into the inbox".
///
/// With a subject only when somebody is signed in: a device row never carries a name, otherwise the
/// file name would stand in front of everyone who opens the machine without signing in (ADR-D07).
fn adopted(shared: &Shared, name: &str) -> LogEntry {
    row(shared, LogKind::IngestAccepted, name, None)
}

/// The row "ingest failed" together with the reason.
fn failed(shared: &Shared, name: &str, reason: &str) -> LogEntry {
    row(shared, LogKind::IngestFailed, name, Some(reason.to_owned()))
}

fn row(shared: &Shared, kind: LogKind, name: &str, detail: Option<String>) -> LogEntry {
    if shared.account().is_none() {
        return LogEntry::plain(now(), kind, detail.clone());
    }
    let subject = Subject { name: name.to_owned(), document: None, location: None };
    LogEntry::new(now(), kind, Some(subject), detail.clone())
        .unwrap_or_else(|_| LogEntry::plain(now(), kind, detail))
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;

    use super::*;

    /// The basket of the tests; which one it is does not matter, only that it is one.
    fn basket() -> BasketIdentifier {
        Identifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_0101)
    }

    #[test]
    fn half_finished_and_hidden_files_are_passed_over() {
        for name in [
            "Rechnung.pdf.crdownload",
            "Scan.part",
            "irgendwas.TMP",
            "~$Angebot.docx",
            ".DS_Store",
            "",
        ] {
            assert!(skip(name), "\"{name}\" does not belong in a mail basket");
        }
    }

    #[test]
    fn a_finished_file_is_not_passed_over() {
        for name in ["Rechnung 2026-0412.pdf", "Scan.PDF", "Notiz.txt", "without-extension"] {
            assert!(!skip(name), "\"{name}\" is a handed-in file");
        }
    }

    #[test]
    fn up_to_three_captures_get_a_tab_each_and_more_get_the_inbox_page() {
        let base = "https://app.example/";
        let three: Vec<String> =
            (0..3).map(|n| format!("https://app.example/erfassung?u={n}")).collect();
        assert_eq!(browser_target(base, three.clone()), three, "three tabs are a workstation");

        let four: Vec<String> =
            (0..4).map(|n| format!("https://app.example/erfassung?u={n}")).collect();
        assert_eq!(
            browser_target(base, four),
            vec!["https://app.example/postkorb".to_owned()],
            "from four files exactly one tab"
        );
        assert!(browser_target(base, Vec::new()).is_empty(), "without an ingest no browser");
    }

    #[test]
    fn an_unknown_type_is_not_guessed() {
        assert_eq!(media_type("Rechnung.pdf"), "application/pdf");
        assert_eq!(media_type("Scan.JPEG"), "image/jpeg");
        assert_eq!(media_type("Beleg.xyz"), "application/octet-stream");
        assert_eq!(media_type("ohne-endung"), "application/octet-stream");
    }

    #[test]
    fn follow_up_happens_only_while_something_is_growing() {
        let mut watch = Watch::default();
        assert!(!watch.grows_something(), "an empty queue needs no short beat");

        // A file whose deadline has passed waits for its retry, not for bytes.
        watch.observes.insert(
            PathBuf::from("stands.pdf"),
            Sample {
                size: 1,
                changed: Timestamp::NULL,
                since: Instant::now() - STABLE - Duration::from_millis(1),
            },
        );
        assert!(!watch.grows_something());

        watch.observes.insert(
            PathBuf::from("grows.pdf"),
            Sample { size: 1, changed: Timestamp::NULL, since: Instant::now() },
        );
        assert!(watch.grows_something(), "here the short beat is worth it");
    }

    #[test]
    fn a_failure_of_the_line_is_no_row_in_the_usage_log() {
        assert!(only_the_link(&EngineError::NoNetwork("not reachable".into())));
        assert!(only_the_link(&EngineError::NotSignedIn));
        assert!(only_the_link(&EngineError::SessionExpired("expired".into())));
        // Everything the user can fix or has to know does stand in the log.
        assert!(!only_the_link(&EngineError::Refused("too large".into())));
        assert!(!only_the_link(&EngineError::Security("foreign address".into())));
        assert!(!only_the_link(&EngineError::Directory {
            path: PathBuf::from("/x"),
            reason: "no access".into(),
        }));
    }

    #[test]
    fn a_sample_holds_only_for_the_same_size_and_time() {
        let sample =
            Sample { size: 10, changed: Timestamp::from_unix_millis(5), since: Instant::now() };
        assert!(sample.unchanged(10, Timestamp::from_unix_millis(5)));
        assert!(!sample.unchanged(11, Timestamp::from_unix_millis(5)), "grown");
        assert!(!sample.unchanged(10, Timestamp::from_unix_millis(6)), "written anew");
    }

    #[test]
    fn the_same_path_announced_twice_stands_in_the_queue_once() {
        let queue = Announced::default();
        let arrival = Arrival { basket: basket(), path: PathBuf::from("/mirror/b/Rechnung.pdf") };
        assert!(queue.add(arrival.clone()), "the first announcement is new");
        assert!(!queue.add(arrival.clone()), "`create` and `close-write` are one file");
        assert_eq!(queue.all().len(), 1);

        queue.forget(&arrival.path);
        assert!(queue.all().is_empty(), "what is ingested leaves the queue");
    }

    #[test]
    fn the_note_names_the_basket_as_well_as_the_file() {
        let other: BasketIdentifier =
            Identifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_0102);
        let name = "Rechnung.pdf";
        assert_ne!(
            note_key(basket(), name),
            note_key(other, name),
            "the same name in two baskets is two ingests, and each one its own key"
        );
        assert!(note_key(basket(), name).ends_with("/Rechnung.pdf"));
    }

    #[test]
    fn a_look_at_something_that_is_no_file_yields_nothing() {
        let directory = tempfile::tempdir().expect("a directory");
        assert!(look(&directory.path().join("does-not-exist")).is_none());
        assert!(look(directory.path()).is_none(), "a directory is not a handed-in file");

        let file = directory.path().join("Rechnung.pdf");
        std::fs::write(&file, b"%PDF-1.4").expect("a file");
        assert_eq!(look(&file).expect("the file is readable").0, 8);
        assert_eq!(file_name(&file), Some("Rechnung.pdf"));
    }
}
