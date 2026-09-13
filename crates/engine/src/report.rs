//! The report — what `doctor` shows, **without the network**.
//!
//! A diagnostic tool that first has to ask the server is useless at exactly the moment one needs
//! it: the call comes because nothing works. Everything here stands locally — the anchored key set
//! together with the self-computed fingerprint, the key facts of the session, open
//! acknowledgements, leftovers in the scratch area, readability of the database, free space.
//!
//! Two values do **not** come from here, and both for the same reason — a house rule that is more
//! important than a convenient report:
//!
//! * **`PRAGMA integrity_check`** needs SQL, and SQL stands only in `edms-store` (architecture rule
//!   R3). The engine instead checks whether every view of the database can be read
//!   ([`DatabaseReport`]) — that catches a truncated file and a broken schema, but not a damaged
//!   page deep in the B-tree.
//!   `[GAP → PROPOSAL]` `edms-store` should offer `PRAGMA integrity_check` as a method of its own;
//!   then the report carries it through.
//! * **Free disk space** needs a system call (`statvfs`, `GetDiskFreeSpaceEx`) that `std` does not
//!   have. The platform API does not belong in the engine (ADR-D02, rules R4/R5), hence the hook
//!   [`crate::Engine::set_space_probe`]: the app measures, the engine asks. Without a measurer
//!   [`StoreSpace::NotDetermined`] stands — honest, instead of an invented number.

use std::path::Path;

use edms_core::identifier::DeviceIdentifier;
use edms_core::namespace::Container;
use edms_core::time::Timestamp;
use edms_crypto::key_set::AnchorState;
use edms_store::SessionState;

use crate::device_key::DeviceKeyOrigin;
use crate::engine::Shared;
use crate::error::EngineError;
use crate::session::SETTING_IDENTITY_GUESSED;

/// What is settled about the anchored server key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReport {
    /// Whether an anchor is stored at all. Without an anchor **nothing** is ever removed by order
    /// (03 §6.2.4, "when in doubt, preserve").
    pub anchored: bool,
    /// Whether the set carries: confirmed and at least one valid anchor.
    pub carries: bool,
    /// The state of the anchor set.
    pub anchor_state: AnchorState,
    /// The **self-computed** fingerprint — the value for the comparison by a human being.
    pub fingerprint: String,
    /// `keySetVersion`.
    pub state: u64,
    /// Number of anchors.
    pub anchor: usize,
    /// Number of proof keys.
    pub evidence_key: usize,
}

/// The key facts of the session — nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    /// The stored state; `None` for as long as there is no session row.
    pub state: Option<SessionState>,
    /// The account (`sub`) that the usage log and the tree stand under.
    pub account: Option<String>,
    /// The tenant.
    pub tenant: Option<String>,
    /// "Signed in as …".
    pub display_name: Option<String>,
    /// Since when.
    pub since: Option<Timestamp>,
    /// Whether the account had to be guessed ([`crate::Identity`]).
    pub identity_guessed: bool,
    /// Whether an access token lies in memory.
    pub token_in_store: bool,
    /// When it expires.
    pub token_expires: Option<Timestamp>,
}

/// Leftovers in the scratch area — half-finished loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeftoversReport {
    /// How many files.
    pub count: usize,
    /// How many bytes together.
    pub bytes: u64,
}

/// Whether the local state can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseReport {
    /// Every view could be read.
    Readable,
    /// A view could not be read; the sentence names which one.
    NotReadable(String),
}

/// The name of the session view in the reason of [`DatabaseReport::NotReadable`].
///
/// These three are public so that `doctor`'s test can build its fixture from the same words
/// production uses. They were `Sitzung`, `Zustellung` and `Journal` until 2026-09-13: `doctor`
/// then printed `Database  NOT readable: Sitzung: …` — a German word in an English frame, which
/// ADR-D10's "operator surfaces stay English" forbids, and which every test in the suite missed
/// because the app's fixture had been written in English. What follows the colon is the store's
/// own `Display` text and still German in most crates; that is the separate pass ADR-D10 names.
pub const VIEW_SESSION: &str = "session";
/// The name of the delivery view; see [`VIEW_SESSION`].
pub const VIEW_DELIVERY: &str = "delivery";
/// The name of the change journal; see [`VIEW_SESSION`].
pub const VIEW_JOURNAL: &str = "journal";

/// Free space on the storage device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreSpace {
    /// This many bytes are free.
    Bytes(u64),
    /// Not measured; the sentence says why.
    NotDetermined(&'static str),
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The identifier of this workstation.
    pub device: DeviceIdentifier,
    /// Where the private device key lies — and, when it is not in hardware, why not.
    pub device_key: DeviceKeyOrigin,
    /// The key set.
    pub key: KeyReport,
    /// The session.
    pub session: SessionReport,
    /// Commands with an outcome whose acknowledgement is not yet at the server.
    pub unacknowledged_command: usize,
    /// The oldest of them — the answer to "since when has it been stuck?".
    pub oldest_unacknowledged: Option<Timestamp>,
    /// Leftovers in the scratch area.
    pub leftovers: LeftoversReport,
    /// Readability of the database.
    pub database: DatabaseReport,
    /// Free disk space at the place of the database.
    pub free_store: StoreSpace,
    /// The current sequence number of the change journal (macOS `currentSyncAnchor`).
    pub current_sequence: u64,
    /// The oldest sequence number still deliverable.
    pub oldest_sequence: u64,
    /// Number of known mail baskets.
    pub baskets: usize,
    /// Number of known archives.
    pub archives: usize,
    /// Number of known case files (Akten), across all archives whose listing has been fetched.
    pub cases: usize,
    /// Number of known saved searches.
    pub searches: usize,
}

impl Report {
    /// The report as rows "feature: value".
    ///
    /// `doctor` is an operator surface, not the user interface: it is read in a terminal, pasted
    /// into a ticket and searched for. It is therefore English and does **not** go through the
    /// text catalogue — a report translated into a language the person reading the ticket does
    /// not speak helps nobody.
    pub fn rows(&self) -> Vec<(String, String)> {
        let time = |point: Option<Timestamp>| {
            point.map_or_else(|| "—".to_owned(), edms_core::time::Timestamp::rfc3339)
        };
        vec![
            ("Device".to_owned(), self.device.to_string()),
            // The second of the two places that keep the fallback from being silent (ADR-D12 §3).
            // A row and not an objection: on macOS today no permanent Secure Enclave key can be
            // made at all, so an objection would turn `doctor` red on every Mac and say nothing
            // anybody could act on.
            ("Device key".to_owned(), self.device_key.row()),
            (
                "Key set".to_owned(),
                format!(
                    "{} ({}), fingerprint {}, state {}, {} anchors / {} evidence keys",
                    if self.key.anchored { "anchored" } else { "not anchored" },
                    self.key.anchor_state,
                    if self.key.fingerprint.is_empty() { "—" } else { &self.key.fingerprint },
                    self.key.state,
                    self.key.anchor,
                    self.key.evidence_key,
                ),
            ),
            (
                "Session".to_owned(),
                format!(
                    "{:?}, account {}, tenant {}, since {}{}",
                    self.session.state,
                    self.session.account.as_deref().unwrap_or("—"),
                    self.session.tenant.as_deref().unwrap_or("—"),
                    time(self.session.since),
                    if self.session.identity_guessed { " (account guessed)" } else { "" },
                ),
            ),
            (
                "Access token".to_owned(),
                format!(
                    "{}, expires {}",
                    if self.session.token_in_store { "held" } else { "none" },
                    time(self.session.token_expires)
                ),
            ),
            (
                "Open acknowledgements".to_owned(),
                format!(
                    "{} (oldest arrival {})",
                    self.unacknowledged_command,
                    time(self.oldest_unacknowledged)
                ),
            ),
            (
                "Staging area".to_owned(),
                format!("{} leftovers, {} bytes", self.leftovers.count, self.leftovers.bytes),
            ),
            (
                "Database".to_owned(),
                match &self.database {
                    DatabaseReport::Readable => "readable".to_owned(),
                    DatabaseReport::NotReadable(reason) => format!("NOT readable: {reason}"),
                },
            ),
            (
                "Free space".to_owned(),
                match &self.free_store {
                    StoreSpace::Bytes(bytes) => format!("{bytes} bytes"),
                    StoreSpace::NotDetermined(reason) => format!("not determined ({reason})"),
                },
            ),
            (
                "Namespace".to_owned(),
                format!(
                    "{} mail baskets, {} archives with {} case files, {} saved searches, \
                     sequence {}-{}",
                    self.baskets,
                    self.archives,
                    self.cases,
                    self.searches,
                    self.oldest_sequence,
                    self.current_sequence
                ),
            ),
        ]
    }
}

/// Gathers the report — without a single network call.
///
/// # Errors
///
/// Only when the key set cannot be read; everything else is reported as a finding and not as an
/// error. A `doctor` that aborts itself says the least.
pub(crate) fn gather(shared: &Shared) -> Result<Report, EngineError> {
    let key_set = crate::session::read_key_set(shared)?;
    let key = KeyReport {
        anchored: !key_set.anchors().is_empty(),
        carries: key_set.carries(),
        anchor_state: key_set.anchor_state(),
        fingerprint: key_set.fingerprint().display(),
        state: key_set.key_set_version(),
        anchor: key_set.anchors().len(),
        evidence_key: key_set.signature_signing_key().len(),
    };

    let mut not_readable: Option<String> = None;
    let mut remember = |what: &str, error: &dyn std::fmt::Display| {
        if not_readable.is_none() {
            not_readable = Some(format!("{what}: {error}"));
        }
    };

    let store = shared.store();
    let session_row = match store.session() {
        Ok(row) => row,
        Err(error) => {
            remember(VIEW_SESSION, &error);
            None
        }
    };
    let login = session_row.as_ref().and_then(|row| row.login());
    let session = SessionReport {
        state: session_row.as_ref().map(edms_store::Session::state),
        account: login.map(|login| login.account.as_str().to_owned()),
        tenant: login.map(|login| login.tenant.clone()),
        display_name: login.map(|login| login.display_name.clone()),
        since: login.map(|login| login.signed_in_since),
        identity_guessed: store.setting(SETTING_IDENTITY_GUESSED).ok().flatten().as_deref()
            == Some("yes"),
        token_in_store: shared.bundle.has_user_token(),
        token_expires: shared.token_expiry(),
    };

    let open = match store.open_acknowledgement() {
        Ok(open) => open,
        Err(error) => {
            remember(VIEW_DELIVERY, &error);
            Vec::new()
        }
    };
    let current_sequence = store.current_sequence().unwrap_or_else(|error| {
        remember(VIEW_JOURNAL, &error);
        0
    });
    let oldest_sequence = store.oldest_sequence().unwrap_or_else(|error| {
        remember(VIEW_JOURNAL, &error);
        0
    });
    let count = |container| store.children(container).map(|rows| rows.len()).unwrap_or_default();
    let baskets = count(Container::Baskets);
    let searches = count(Container::Searches);
    // Since namespace v2 a case file stands under its archive, so there is no one listing that
    // holds them all. Counted are the archives whose listing this machine has fetched — an
    // archive nobody has opened yet has none, and a guessed number would say less than an honest
    // one about what really lies here.
    let archive_rows = store.children(Container::Archives).unwrap_or_default();
    let archives = archive_rows.len();
    let cases = archive_rows
        .iter()
        .filter_map(|entry| entry.identifier.container())
        .map(count)
        .sum::<usize>();
    drop(store);

    Ok(Report {
        device: shared.bundle.device(),
        device_key: shared.bundle.device_key_origin().clone(),
        key,
        session,
        unacknowledged_command: open.len(),
        oldest_unacknowledged: open.first().map(|state| state.received),
        leftovers: count_leftovers(&shared.configuration.staging),
        database: match not_readable {
            None => DatabaseReport::Readable,
            Some(reason) => DatabaseReport::NotReadable(reason),
        },
        free_store: shared.free_store(),
        current_sequence,
        oldest_sequence,
        baskets,
        archives,
        cases,
        searches,
    })
}

/// Counts the half-finished loads in the scratch area.
fn count_leftovers(directory: &Path) -> LeftoversReport {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return LeftoversReport::default();
    };
    let mut report = LeftoversReport::default();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|end| end == crate::hydration::EXTENSION_PART) {
            continue;
        }
        report.count += 1;
        if let Ok(details) = entry.metadata() {
            report.bytes = report.bytes.saturating_add(details.len());
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leftovers_are_counted_and_weighed() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("a.part"), b"1234").unwrap();
        std::fs::write(directory.path().join("b.part"), b"12").unwrap();
        std::fs::write(directory.path().join("c.txt"), b"not mine").unwrap();
        let report = count_leftovers(directory.path());
        assert_eq!(report.count, 2);
        assert_eq!(report.bytes, 6);
    }

    #[test]
    fn without_a_directory_there_are_no_leftovers() {
        assert_eq!(count_leftovers(Path::new("/does/not/exist")), LeftoversReport::default());
    }
}
