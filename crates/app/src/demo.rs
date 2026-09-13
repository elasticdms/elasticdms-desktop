//! Sample data for `--demo`: a [`DisplaySource`] without a server, so that icon and window run
//! now — before the wiring to the engine.
//!
//! The data is chosen so that every peculiarity of the view occurs: at least one row per log kind,
//! one **redacted** row (the name erased, because the document was erased on order later), the
//! "erased by order" row without a name, warnings, and more than one page, so that the "load
//! older" button appears.
//!
//! The demo keeps requirement 4 too: every row belongs to an account, and [`DemoSource`] delivers
//! only the rows of the account being shown (and account-less ones such as "device registered").
//! After signing out no document name stands in the window any more — exactly what the wiring
//! achieves as well.
//!
//! **The sample data is user text.** Its explanations, locations and the account name come out of
//! the text catalogue like everything else: a window shown in English with a half-German log
//! would be a worse demonstration than none. Only the document names stay as they are — they are
//! archive content and belong to the document, not to the user interface.
//!
//! The demo opens no browser and talks to no server. The sign-in address is under `.example`
//! (RFC 2606, never assigned); the folder and the mail baskets in it lie in the temp directory and
//! only come into being when somebody wants to open them.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use edms_core::identifier::Identifier;
use edms_core::log::{LogEntry, LogError, LogKind, Subject};
use edms_core::time::Timestamp;
use edms_i18n::{Catalog, Key, key};

use crate::display::{DisplayError, DisplaySource, DisplayState, LoginCode, Status, Waker};

/// The sample account — a name, therefore the same in every catalogue.
pub fn account(catalogue: &Catalog) -> &str {
    catalogue.text(key::DEMO_ACCOUNT)
}

/// This is how long the approval in the browser "takes" until the demo reports itself signed in.
const LOGIN_DURATION: Duration = Duration::from_secs(6);

const MINUTE: i64 = 60_000;

/// What the demo starts with (`--demo=<name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoState {
    /// Signed in and connected (the default).
    SignedIn,
    /// A sign-in is in progress: the window shows the code.
    Login,
    /// Nobody signed in.
    SignedOut,
    /// The session has expired.
    Expired,
    /// The device is waiting for approval.
    Approval,
    /// Server not reachable.
    Offline,
    /// Security warning.
    Warning,
}

impl DemoState {
    const ALL: [Self; 7] = [
        Self::SignedIn,
        Self::Login,
        Self::SignedOut,
        Self::Expired,
        Self::Approval,
        Self::Offline,
        Self::Warning,
    ];

    /// The names for the command line, in the order of [`Self::ALL`].
    pub const NAMES: [&'static str; 7] =
        ["signed-in", "login", "signed-out", "expired", "approval", "offline", "warning"];

    /// The name for the command line.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignedIn => "signed-in",
            Self::Login => "login",
            Self::SignedOut => "signed-out",
            Self::Expired => "expired",
            Self::Approval => "approval",
            Self::Offline => "offline",
            Self::Warning => "warning",
        }
    }

    /// The state for a name.
    pub fn from_text(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == text)
    }
}

/// The app's clock — a single one in the whole program (see [`crate::time`]).
pub use crate::time::now;

/// One row together with the account it belongs to (`None`: device-scoped, without a name).
struct DemoRow {
    id: i64,
    account: Option<String>,
    entry: LogEntry,
}

struct Inner {
    state: DisplayState,
    rows: Vec<DemoRow>,
    waker: Vec<Arc<dyn Fn() + Send + Sync>>,
    /// Counts sign-in attempts; a stale approval after "Sign out" (`menu.sign_out`) no longer
    /// takes effect.
    login: u64,
}

impl Inner {
    fn insert(&mut self, account: Option<String>, entry: LogEntry) {
        let id = self.rows.last().map_or(1, |z| z.id + 1);
        self.rows.push(DemoRow { id, account, entry });
    }
}

/// The sample source.
pub struct DemoSource {
    inner: Arc<Mutex<Inner>>,
    folder: PathBuf,
    baskets: PathBuf,
    login_duration: Duration,
    /// Every sentence of the sample data, in the language of this run.
    catalogue: &'static Catalog,
}

impl DemoSource {
    /// Sample data relative to `now`; the folder with its mail baskets under `root`.
    pub fn new(
        now: Timestamp,
        state: DemoState,
        root: &Path,
        catalogue: &'static Catalog,
    ) -> Result<Self, LogError> {
        let folder = root.join("elasticdms – Demo");
        // Inside the folder, not next to it: the baskets are the drop target, and they stand in
        // the mirror where the user is already looking (namespace v2 §5).
        let baskets = folder.join(catalogue.text(key::MIRROR_BASKETS));
        let inner = Inner {
            state: start_state(state, &folder, &baskets, catalogue),
            rows: sample_row(now, catalogue)?,
            waker: Vec::new(),
            login: 0,
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            folder,
            baskets,
            login_duration: LOGIN_DURATION,
            catalogue,
        })
    }

    #[cfg(test)]
    fn with_login_duration(mut self, duration: Duration) -> Self {
        self.login_duration = duration;
        self
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    /// A refusal as a whole sentence out of the catalogue.
    fn refuse(&self, which: Key) -> DisplayError {
        DisplayError::NotPossible(self.catalogue.text(which).to_owned())
    }
}

/// A poisoned mutex here only means: a thread crashed in the middle of an insert. The data is
/// still the last valid state; carrying on is the right thing.
fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Calls every waker — outside the lock, so that a waker reading the state does not hang.
fn wake(inner: &Mutex<Inner>) {
    let waker = lock(inner).waker.clone();
    for w in waker {
        w();
    }
}

fn demo_code() -> LoginCode {
    LoginCode {
        user_code: "WQPX-7TRM".to_owned(),
        address: "https://anmeldung.example/geraet".to_owned(),
        address_complete: Some(
            "https://anmeldung.example/geraet?user_code=WQPX-7TRM&anchor=K7M4".to_owned(),
        ),
        anchor: Some("K7-M4".to_owned()),
    }
}

fn signed_in(folder: &Path, baskets: &Path, status: Status, catalogue: &Catalog) -> DisplayState {
    DisplayState {
        account: Some(account(catalogue).to_owned()),
        status,
        folder: Some(folder.to_path_buf()),
        baskets: Some(baskets.to_path_buf()),
        login_code: None,
        // The demo has no engine that would publish hints — and it invents none.
        hint: None,
    }
}

fn without_account(status: Status, login_code: Option<LoginCode>) -> DisplayState {
    DisplayState { account: None, status, folder: None, baskets: None, login_code, hint: None }
}

fn start_state(
    state: DemoState,
    folder: &Path,
    baskets: &Path,
    catalogue: &Catalog,
) -> DisplayState {
    match state {
        DemoState::SignedIn => signed_in(folder, baskets, Status::SignedIn, catalogue),
        DemoState::Expired => signed_in(folder, baskets, Status::LoginRequired, catalogue),
        DemoState::Offline => signed_in(folder, baskets, Status::Offline, catalogue),
        DemoState::Warning => signed_in(folder, baskets, Status::SecurityWarning, catalogue),
        DemoState::Login => without_account(Status::NotSignedIn, Some(demo_code())),
        DemoState::SignedOut => without_account(Status::NotSignedIn, None),
        DemoState::Approval => without_account(Status::AwaitingApproval, None),
    }
}

impl DisplaySource for DemoSource {
    fn state(&self) -> DisplayState {
        self.inner().state.clone()
    }

    fn log(
        &self,
        before_id: Option<i64>,
        count: usize,
    ) -> Result<Vec<(i64, LogEntry)>, DisplayError> {
        let inner = self.inner();
        let account = inner.state.account.clone();
        Ok(inner
            .rows
            .iter()
            .rev()
            .filter(|z| z.account.is_none() || z.account == account)
            .filter(|z| before_id.is_none_or(|v| z.id < v))
            .take(count)
            .map(|z| (z.id, z.entry.clone()))
            .collect())
    }

    fn sign_in(&self) -> Result<(), DisplayError> {
        let number = {
            let mut inner = self.inner();
            if inner.state.login_code.is_some() {
                return Err(self.refuse(key::ERROR_SIGN_IN_RUNNING));
            }
            match inner.state.status {
                Status::SignedIn => return Err(self.refuse(key::ERROR_ALREADY_SIGNED_IN)),
                Status::AwaitingApproval => {
                    // Without the fingerprint: the demo has no device and therefore none to name.
                    return Err(DisplayError::NotPossible(
                        self.catalogue
                            .format(key::ERROR_AWAITING_APPROVAL_SIGN_IN, &[("fingerprint", "—")]),
                    ));
                }
                Status::Offline => return Err(self.refuse(key::ERROR_OFFLINE_SIGN_IN)),
                Status::NotSignedIn | Status::LoginRequired | Status::SecurityWarning => {}
            }
            inner.state.login_code = Some(demo_code());
            inner.login += 1;
            inner.login
        };
        wake(&self.inner);
        let inner = Arc::clone(&self.inner);
        let (folder, baskets, duration) =
            (self.folder.clone(), self.baskets.clone(), self.login_duration);
        let catalogue = self.catalogue;
        let started = thread::Builder::new().name("demo-sign-in".into()).spawn(move || {
            thread::sleep(duration);
            {
                let mut i = lock(&inner);
                if i.login != number || i.state.login_code.is_none() {
                    return;
                }
                i.state = signed_in(&folder, &baskets, Status::SignedIn, catalogue);
                let name = account(catalogue);
                i.insert(
                    Some(name.to_owned()),
                    LogEntry::plain(
                        now(),
                        LogKind::SignedIn,
                        Some(catalogue.format(key::NOTICE_SIGNED_IN_AS, &[("account", name)])),
                    ),
                );
            }
            wake(&inner);
        });
        if let Err(e) = started {
            self.inner().state.login_code = None;
            wake(&self.inner);
            return Err(DisplayError::NotPossible(
                self.catalogue.format(key::DEMO_SIGN_IN_NOT_STARTED, &[("reason", &e.to_string())]),
            ));
        }
        Ok(())
    }

    fn sign_out(&self) -> Result<(), DisplayError> {
        {
            let mut inner = self.inner();
            if inner.state.account.is_none() {
                return Err(self.refuse(key::ERROR_NOBODY_SIGNED_IN));
            }
            inner.state = without_account(Status::NotSignedIn, None);
            inner.login += 1;
            inner.insert(
                None,
                LogEntry::plain(
                    now(),
                    LogKind::SignedOut,
                    Some(self.catalogue.text(key::DEMO_MIRROR_CLEARED).to_owned()),
                ),
            );
        }
        wake(&self.inner);
        Ok(())
    }

    fn open_folder(&self) -> Result<(), DisplayError> {
        let path = self
            .state()
            .folder
            .ok_or(DisplayError::NotProvisioned(crate::display::Place::Mirror))?;
        open_directory(&path)
    }

    fn open_baskets(&self) -> Result<(), DisplayError> {
        let path = self
            .state()
            .baskets
            .ok_or(DisplayError::NotProvisioned(crate::display::Place::Baskets))?;
        open_directory(&path)
    }

    fn observe(&self, waker: Waker) {
        self.inner().waker.push(Arc::from(waker));
    }
}

/// Creates the (empty) demo directory and opens it in the file manager.
fn open_directory(path: &Path) -> Result<(), DisplayError> {
    let error = |e: std::io::Error| DisplayError::Open {
        target: path.display().to_string(),
        reason: e.to_string(),
    };
    std::fs::create_dir_all(path).map_err(error)?;
    open::that_detached(path).map_err(error)
}

// ── Sample rows ─────────────────────────────────────────────────────────────────────────────
//
// The table names **keys**, not sentences: locations and explanations come out of the catalogue,
// so that `--demo` shows a whole user interface in whichever language this workstation speaks.
// The document names are the exception — they are archive content, and an archive is not
// translated.

/// One sample row: how many minutes ago, what, on what.
struct Pattern {
    before_minute: i64,
    kind: LogKind,
    /// File name (archive content) and the catalogue key of its location.
    file: Option<(&'static str, Key)>,
    /// The catalogue key of the explanation.
    detail: Option<Key>,
    /// Redacted afterwards (the document was erased on order later).
    redacted: bool,
    /// Belongs to no account (device-scoped).
    account_loose: bool,
}

const fn file(
    before_minute: i64,
    kind: LogKind,
    name: &'static str,
    location: Key,
    detail: Option<Key>,
) -> Pattern {
    Pattern {
        before_minute,
        kind,
        file: Some((name, location)),
        detail,
        redacted: false,
        account_loose: false,
    }
}

const fn plain(before_minute: i64, kind: LogKind, detail: Key) -> Pattern {
    Pattern {
        before_minute,
        kind,
        file: None,
        detail: Some(detail),
        redacted: false,
        account_loose: false,
    }
}

const LOADED: Option<Key> = Some(key::DEMO_LOADED);

const PATTERN: &[Pattern] = &[
    file(
        2,
        LogKind::Opened,
        "Prüfbericht Pumpe 7.pdf",
        key::DEMO_CASE_SULZER,
        Some(key::DEMO_LOADED_2_4),
    ),
    file(
        11,
        LogKind::IngestAccepted,
        "Lieferschein 2026-0912.pdf",
        key::DEMO_BASKET,
        Some(key::DEMO_INGEST_WITH_BROWSER),
    ),
    file(
        26,
        LogKind::NewVersion,
        "Angebot Kühlwasserpumpe KW-40.pdf",
        key::DEMO_SEARCH_OFFERS,
        Some(key::DEMO_NEW_VERSION),
    ),
    Pattern {
        before_minute: 48,
        kind: LogKind::ErasedByOrder,
        file: None,
        detail: None,
        redacted: false,
        account_loose: false,
    },
    plain(95, LogKind::ConnectionRestored, key::DEMO_CONNECTION_RESTORED),
    plain(131, LogKind::ConnectionLost, key::DEMO_CONNECTION_LOST),
    file(
        190,
        LogKind::Opened,
        "Wartungsprotokoll Q2 2026.pdf",
        key::DEMO_CASE_SULZER,
        Some(key::DEMO_LOADED_1_1),
    ),
    file(
        245,
        LogKind::SpaceReclaimed,
        "Montageanleitung Baureihe 400.pdf",
        key::DEMO_CASE_ENGINEERING,
        Some(key::DEMO_SPACE_RECLAIMED_STALE),
    ),
    file(
        1_500,
        LogKind::OpenFailed,
        "Rechnung 2026-0815.pdf",
        key::DEMO_SEARCH_INVOICES,
        Some(key::DEMO_NO_ACCESS),
    ),
    file(
        1_560,
        LogKind::AccessRevoked,
        "Kalkulation Projekt Nordhafen.xlsx",
        key::DEMO_CASE_NORTHPORT,
        Some(key::DEMO_ACCESS_REVOKED),
    ),
    plain(1_620, LogKind::SecurityWarning, key::DEMO_SECURITY_WARNING),
    file(
        1_700,
        LogKind::IngestFailed,
        "Scan_0042.tiff",
        key::DEMO_BASKET,
        Some(key::DEMO_INGEST_FAILED),
    ),
    file(1_745, LogKind::Opened, "Prüfbericht Pumpe 5.pdf", key::DEMO_CASE_SULZER, LOADED),
    plain(2_880, LogKind::SignedIn, key::NOTICE_SIGNED_IN_AS),
    plain(2_884, LogKind::LoginRequired, key::DEMO_SESSION_EXPIRED),
    file(3_020, LogKind::Opened, "Rechnung 2026-0733.pdf", key::DEMO_SEARCH_INVOICES, LOADED),
    file(
        3_400,
        LogKind::Opened,
        "Wartungsvertrag 2026 – unterschrieben.pdf",
        key::DEMO_CASE_SULZER,
        LOADED,
    ),
    file(
        4_150,
        LogKind::Opened,
        "Lieferantenbewertung 2025.docx",
        key::DEMO_CASE_PURCHASING,
        LOADED,
    ),
    Pattern {
        before_minute: 4_310,
        kind: LogKind::Opened,
        file: Some(("Arbeitsvertrag M. Schneider.pdf", key::DEMO_CASE_PERSONNEL)),
        detail: Some(key::DEMO_LOADED_480),
        redacted: true,
        account_loose: false,
    },
    file(
        5_700,
        LogKind::Opened,
        "Protokoll Betriebsbegehung Halle 3.pdf",
        key::DEMO_CASE_SAFETY,
        LOADED,
    ),
    file(
        5_760,
        LogKind::Opened,
        "Gefährdungsbeurteilung Schweißplatz.pdf",
        key::DEMO_CASE_SAFETY,
        LOADED,
    ),
    file(
        7_200,
        LogKind::NewVersion,
        "Angebot Dichtungssätze DS-12.pdf",
        key::DEMO_SEARCH_OFFERS,
        None,
    ),
    file(
        7_260,
        LogKind::Opened,
        "Angebot Dichtungssätze DS-12.pdf",
        key::DEMO_SEARCH_OFFERS,
        LOADED,
    ),
    file(8_600, LogKind::Opened, "Zertifikat ISO 9001 – 2026.pdf", key::DEMO_CASE_QUALITY, LOADED),
    file(8_700, LogKind::Opened, "Prüfbericht Pumpe 3.pdf", key::DEMO_CASE_SULZER, LOADED),
    file(
        10_100,
        LogKind::SpaceReclaimed,
        "Kaufvertrag Gabelstapler.pdf",
        key::DEMO_CASE_FLEET,
        Some(key::DEMO_SPACE_RECLAIMED_ASKED),
    ),
    file(
        10_200,
        LogKind::Opened,
        "TÜV-Bericht Druckbehälter 2026.pdf",
        key::DEMO_CASE_ENGINEERING,
        LOADED,
    ),
    file(
        11_500,
        LogKind::Opened,
        "Reisekostenabrechnung August.pdf",
        key::DEMO_SEARCH_RECEIPTS,
        LOADED,
    ),
    file(
        11_560,
        LogKind::IngestAccepted,
        "Quittung Tankstelle.jpg",
        key::DEMO_BASKET,
        Some(key::DEMO_INGEST_PLAIN),
    ),
    file(12_900, LogKind::Opened, "Rechnung 2026-0691.pdf", key::DEMO_SEARCH_INVOICES, LOADED),
    file(13_000, LogKind::Opened, "Mahnung 2026-0691.pdf", key::DEMO_SEARCH_INVOICES, LOADED),
    file(
        14_400,
        LogKind::Opened,
        "Schulungsnachweis Staplerfahrer.pdf",
        key::DEMO_CASE_SAFETY,
        LOADED,
    ),
    file(
        15_800,
        LogKind::Opened,
        "Ersatzteilliste Baureihe 400.pdf",
        key::DEMO_CASE_ENGINEERING,
        LOADED,
    ),
    file(
        17_300,
        LogKind::Opened,
        "Rahmenvertrag Wartung 2024–2026.pdf",
        key::DEMO_CASE_SULZER,
        LOADED,
    ),
    plain(18_700, LogKind::SignedIn, key::NOTICE_SIGNED_IN_AS),
    Pattern {
        before_minute: 18_720,
        kind: LogKind::DeviceRegistered,
        file: None,
        detail: Some(key::DEMO_DEVICE_APPROVED),
        redacted: false,
        account_loose: true,
    },
];

/// The sample rows as a log, oldest first (the identifier grows with time).
fn sample_row(now: Timestamp, catalogue: &Catalog) -> Result<Vec<DemoRow>, LogError> {
    let mut pattern: Vec<(usize, &Pattern)> = PATTERN.iter().enumerate().collect();
    pattern.sort_by_key(|(_, m)| std::cmp::Reverse(m.before_minute));
    let name = account(catalogue);
    // The only sentence of the sample data with a placeholder; everything else is plain text.
    let detail = |which: Key| catalogue.format(which, &[("account", name)]);
    let mut inner = Inner {
        state: without_account(Status::NotSignedIn, None),
        rows: Vec::new(),
        waker: Vec::new(),
        login: 0,
    };
    for (nr, m) in pattern {
        let time = now.plus_millis(-m.before_minute * MINUTE);
        let entry = match (m.kind, m.file) {
            (LogKind::ErasedByOrder, _) => LogEntry::erased_by_order(time),
            (kind, Some((file_name, location))) => {
                let subject = Subject {
                    name: file_name.to_owned(),
                    // A UUIDv7-like identifier per sample row, so that a document identifier
                    // stands in the detail.
                    document: Some(Identifier::from_value(
                        0x0190_F1C2_3A4B_7C5D_8E6F_0000_0000_0000 + nr as u128,
                    )),
                    location: Some(catalogue.text(location).to_owned()),
                };
                let e = LogEntry::new(time, kind, Some(subject), m.detail.map(detail))?;
                if m.redacted { e.redacted() } else { e }
            }
            (kind, None) => LogEntry::plain(time, kind, m.detail.map(detail)),
        };
        inner.insert((!m.account_loose).then(|| name.to_owned()), entry);
    }
    Ok(inner.rows)
}
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    use edms_core::log::REDACTED;
    use edms_i18n::Language;

    use super::*;

    /// The German catalogue — the sample data reads in it the way the user sees it.
    fn german() -> &'static Catalog {
        Catalog::of(Language::De)
    }

    const NOW: Timestamp = Timestamp::from_unix_millis(1_788_334_692_118);

    fn source(state: DemoState) -> DemoSource {
        DemoSource::new(NOW, state, Path::new("/does/not/exist"), german()).unwrap()
    }

    fn all_rows(q: &DemoSource) -> Vec<(i64, LogEntry)> {
        q.log(None, usize::MAX).unwrap()
    }

    #[test]
    fn the_sample_data_shows_one_redacted_row_and_one_erasure_row() {
        let rows = all_rows(&source(DemoState::SignedIn));
        let redacted = rows.iter().filter(|(_, e)| e.subject().is_some_and(|g| g.name == REDACTED));
        assert_eq!(redacted.count(), 1);
        assert!(rows.iter().any(|(_, e)| e.kind() == LogKind::ErasedByOrder));
    }

    #[test]
    fn no_erasure_row_carries_a_name() {
        for (_, e) in all_rows(&source(DemoState::SignedIn)) {
            if e.kind() == LogKind::ErasedByOrder {
                assert!(e.subject().is_none() && e.detail().is_none());
            }
        }
    }

    #[test]
    fn paging_delivers_every_row_exactly_once_newest_first() {
        let q = source(DemoState::SignedIn);
        let all = all_rows(&q);
        let mut paged = Vec::new();
        let mut before = None;
        loop {
            let page = q.log(before, 7).unwrap();
            let Some((last, _)) = page.last() else { break };
            before = Some(*last);
            paged.extend(page);
        }
        assert_eq!(paged, all);
        assert!(all.windows(2).all(|p| p[0].0 > p[1].0 && p[0].1.time() >= p[1].1.time()));
    }

    #[test]
    fn there_is_more_than_one_page() {
        assert!(all_rows(&source(DemoState::SignedIn)).len() > crate::event_loop::PAGE);
    }

    #[test]
    fn signing_out_clears_account_folders_and_names_and_wakes_the_user_interface() {
        let q = source(DemoState::SignedIn);
        let woken = Arc::new(AtomicUsize::new(0));
        let g = Arc::clone(&woken);
        q.observe(Box::new(move || {
            g.fetch_add(1, Ordering::SeqCst);
        }));
        q.sign_out().unwrap();
        let s = q.state();
        assert_eq!(
            (s.account, s.status, s.folder, s.baskets),
            (None, Status::NotSignedIn, None, None)
        );
        assert_eq!(woken.load(Ordering::SeqCst), 1);
        let rows = all_rows(&q);
        assert!(
            rows.iter().all(|(_, e)| e.subject().is_none()),
            "after the sign-out no name stands there any more"
        );
        assert_eq!(rows.first().map(|(_, e)| e.kind()), Some(LogKind::SignedOut));
    }

    #[test]
    fn signing_in_shows_the_code_and_reports_signed_in_after_the_approval() {
        let q = source(DemoState::SignedOut).with_login_duration(Duration::from_millis(20));
        let (tx, rx) = mpsc::channel();
        q.observe(Box::new(move || {
            let _ = tx.send(());
        }));
        q.sign_in().unwrap();
        assert_eq!(q.state().login_code.map(|c| c.user_code), Some("WQPX-7TRM".into()));
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let s = q.state();
        assert_eq!(
            (s.status, s.account.as_deref(), s.login_code),
            (Status::SignedIn, Some(account(german())), None)
        );
        assert_eq!(all_rows(&q).first().map(|(_, e)| e.kind()), Some(LogKind::SignedIn));
    }

    #[test]
    fn a_second_sign_in_during_a_sign_in_is_an_error() {
        let q = source(DemoState::Login);
        assert!(matches!(q.sign_in(), Err(DisplayError::NotPossible(_))));
    }

    #[test]
    fn without_approval_signing_in_is_an_error_and_so_is_signing_out_without_an_account() {
        assert!(matches!(source(DemoState::Approval).sign_in(), Err(DisplayError::NotPossible(_))));
        assert!(matches!(
            source(DemoState::SignedOut).sign_out(),
            Err(DisplayError::NotPossible(_))
        ));
    }

    #[test]
    fn a_folder_that_is_not_set_up_is_an_error_and_not_an_empty_window() {
        let q = source(DemoState::SignedOut);
        assert_eq!(
            q.open_folder(),
            Err(DisplayError::NotProvisioned(crate::display::Place::Mirror))
        );
        assert_eq!(
            q.open_baskets(),
            Err(DisplayError::NotProvisioned(crate::display::Place::Baskets))
        );
    }

    #[test]
    fn every_demo_state_has_its_name() {
        for (state, name) in DemoState::ALL.into_iter().zip(DemoState::NAMES) {
            assert_eq!(state.name(), name);
            assert_eq!(DemoState::from_text(name), Some(state));
        }
        assert_eq!(DemoState::from_text("Signed-In"), None);
    }
}
