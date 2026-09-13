//! The folder client's local state — SQLite in WAL mode, and SQL only here (rule R3).
//!
//! What lies here is what the client needs when the server stays silent:
//!
//! * the last seen **namespace**, so that the tree stands still offline (ADR-D01, point 8) and
//!   the Explorer gets its listing without every expand being a search at the server;
//! * the **change journal** — the answer to `enumerateChanges(from:)` on macOS, the only way a
//!   server-side change reaches the Finder (ADR-D05);
//! * the **tombstones** of erased documents, so that a stale listing does not undo a DSGVO (GDPR)
//!   erasure;
//! * the local **usage log** per account (ADR-D07);
//! * the **delivery commands** with outcome and acknowledgement (ADR-D04, point 4: delivered at
//!   least once, deduplicated over the command identifier, acknowledgements survive a crash);
//! * the **key facts of the session** and **settings**.
//!
//! **What never lies here: tokens and private keys.** They belong in the operating system's
//! keychain (ADR-D03, point 4). A SQLite file is gone with one copy command; a refresh token
//! inside it would be a session that lives on at any other machine.
//!
//! ## Why configured this way
//!
//! * **WAL**, because one process writes and a second must be able to read at the same time (head
//!   of `Cargo.toml`). If a file cannot be put into WAL (network drive), opening aborts instead of
//!   quietly running in rollback mode, in which the reader locks the writer.
//! * **`synchronous = FULL`** (escan 01 §1.4): with the WAL default `NORMAL`, a hard power loss
//!   loses precisely the last transactions — here that would be the outcome of an erasure command
//!   and the tombstone. Afterwards the erased document would stand in the folder again, and the
//!   server would never get an acknowledgement.
//! * **`secure_delete = ON`**: deleted rows are overwritten with zeros. Otherwise the title of a
//!   document erased by order would still stand in free pages of the file — "on an erasure the
//!   name must not stay behind either" (`ordnerclient-vorgaben.md`). After an erasure, redaction
//!   and sign-out the store also folds the log into the file ([`Store::condense`]), so that the
//!   old pages do not stay behind there either.
//! * **Exactly one writer**, the engine. Every writing method demands `&mut self` and runs in an
//!   `IMMEDIATE` transaction that reads the sequence number only under the lock; even two writing
//!   processes would therefore not count twice.
//!
//! ## The tables (schema 3)
//!
//! | Table             | Content                                                                |
//! |-------------------|------------------------------------------------------------------------|
//! | `entry`           | namespace, one row per entry; `document` finds every place              |
//! | `container_state` | per container ETag, fetch time, truncation                              |
//! | `journal`         | changes, sequence number strictly rising and without gaps               |
//! | `journal_state`   | highest sequence number handed out and lower bound of the journal       |
//! | `erased`          | tombstones of erased documents, in effect for 30 days                   |
//! | `log`             | usage log, each row carries the account                                 |
//! | `delivery`        | accepted commands, outcome, acknowledged                                |
//! | `session`         | one row: device, state, account, tenant, display name                   |
//! | `setting`         | key and value                                                           |
//!
//! **escan 01 §1.4** — there, no free text stands in the database ("No plaintext
//! paths", "No free text"). The folder client has to hold file names, case-file (Akte) titles and
//! the rows of the usage log: the tree is to stand still offline, and the log is the app's first
//! view. Taken over is the column discipline (identifiers as TEXT, checksums as lowercase hex,
//! enumerations by name, times as milliseconds). The names are protected by the operating
//! system's user profile, by `secure_delete` and by the redaction on an erasure; an encryption of
//! the file (contract extract §4.5, Q-10) is not built.

#![forbid(unsafe_code)]

mod account;
mod column;
mod delivery;
mod error;
mod ingest;
mod log;
mod namespace;
mod schema;
mod session;
mod setting;

#[cfg(test)]
mod test_support;

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

pub use crate::account::{Account, AccountError};
pub use crate::delivery::{Acceptance, CommandState};
pub use crate::error::StoreError;
pub use crate::ingest::InboxPending;
pub use crate::log::{LogPage, LogRow};
pub use crate::namespace::{ContainerState, TruncationState};
pub use crate::schema::SCHEMA_VERSION;
pub use crate::session::{Login, Session, SessionError, SessionState};

/// Maximum number of entries in the change journal; the oldest fall out.
///
/// Ten thousand changes are enough for a long time without the Finder having to ask again. Whoever
/// is away longer gets [`StoreError::AnchorExpired`] and enumerates afresh — slower, never wrong.
pub const JOURNAL_MAX: u64 = 10_000;

/// Maximum number of log rows per account (and for the device rows without an account).
///
/// The log is display, not evidence — the authoritative access log is kept by the server
/// (ADR-D07). The limit keeps file and view small.
pub const LOG_PER_ACCOUNT: u64 = 5_000;

/// How long a tombstone is in effect, in milliseconds: 30 days.
///
/// For that long no listing brings an erased document back — neither one that was fetched before
/// the erasure and applied only afterwards, nor one from a search index that lags behind the
/// erasure (ADR-011: every projection reads the erasure register, but not every one immediately).
pub const ERASURE_TAKES_EFFECT_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// How long a call waits when another process is holding the database locked.
pub const WAIT_TIME_AT_LOCK: Duration = Duration::from_secs(5);

/// The local state, one connection to a SQLite file.
///
/// Reading methods take `&self`, writing ones `&mut self`: the engine is the only writer, and the
/// type says so. For several threads the engine puts it behind a lock.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    limit: Limit,
}

/// The size limits; smaller in tests, so that trimming is testable without ten thousand rows.
#[derive(Debug, Clone, Copy)]
struct Limit {
    journal: u64,
    log_per_account: u64,
}

impl Limit {
    const DEFAULT: Self = Self { journal: JOURNAL_MAX, log_per_account: LOG_PER_ACCOUNT };
}

impl Store {
    /// Opens the database at `path` for writing, creates it if it does not exist, and runs the
    /// missing migrations.
    ///
    /// The directory has to exist; which one it is, the app decides, not the store. Without
    /// `SQLITE_OPEN_URI`: a path that begins with `file:` stays a path.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection = Connection::open_with_flags(path, flags)
            .map_err(|source| StoreError::Open { path: path.to_owned(), source })?;
        schema::set_up(&mut connection, schema::Location::File)
            .map_err(|error| error.with_path(path))?;
        Ok(Self { connection, limit: Limit::DEFAULT })
    }

    /// Opens an already set-up database for reading only — for a second process next to the
    /// engine (a diagnosis, say) that must not change anything.
    ///
    /// Does not migrate and creates nothing: a database at another schema level is an error,
    /// because a reader that migrated would be a second writer.
    pub fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|source| StoreError::Open { path: path.to_owned(), source })?;
        schema::check_read_only(&connection).map_err(|error| error.with_path(path))?;
        Ok(Self { connection, limit: Limit::DEFAULT })
    }

    /// A database in memory, for tests and the demo without a server. Same schema, same pragmas,
    /// only without WAL (there is none in memory).
    pub fn in_memory() -> Result<Self, StoreError> {
        let mut connection = Connection::open_in_memory()?;
        schema::set_up(&mut connection, schema::Location::Memory)?;
        Ok(Self { connection, limit: Limit::DEFAULT })
    }

    /// Folds the write-ahead log into the file and truncates it to zero bytes.
    ///
    /// `true` if that fully succeeded; `false` if a reader still holds an older state — then the
    /// next automatic checkpoint catches up. After [`Self::remove_document_everywhere`],
    /// [`Self::redact`] and [`Self::empty_namespace`] the store calls this itself: only then do
    /// the old pages with the erased names no longer stand in the log either.
    pub fn condense(&self) -> Result<bool, StoreError> {
        let occupied: i64 =
            self.connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        Ok(occupied == 0)
    }

    /// Condense as best as possible after an erasure.
    fn condense_after_erasure(&self) {
        // The result is discarded on purpose. The erasure is committed; what is open is at most
        // old pages in file and log, and those the next automatic checkpoint overwrites. Reporting
        // an error here as an error of the erasure would make the engine repeat an erasure that
        // has succeeded.
        let _ = self.condense();
    }
}

#[cfg(test)]
mod tests {
    use edms_core::delivery::CommandOutcome;
    use edms_core::identifier::{CommandIdentifier, DeviceIdentifier, Identifier};
    use edms_core::log::{LogEntry, LogKind};

    use super::*;
    use crate::test_support::{case_container, doc, in_case, item, scaffold, state, time};

    #[test]
    fn everything_is_still_there_after_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let command: CommandIdentifier = Identifier::from_value(5);
        let device: DeviceIdentifier = Identifier::from_value(6);
        let account = Account::new("usr_01JK4R7ZQ8M3N5P6T9V0WXYZAB").unwrap();
        let session = Session::signed_in(
            device,
            Login {
                account: account.clone(),
                tenant: "ten_lm".into(),
                display_name: "N. Lotzer".into(),
                signed_in_since: time(4),
            },
        );
        let list = in_case(1, &[item(1, "Rechnung", "1")]);
        let (sequence, log) = {
            let mut s = Store::open(&path).unwrap();
            scaffold(&mut s, &[(1, "Sulzer")], &[]);
            s.replace_container(case_container(1), &list, &state(3)).unwrap();
            let row = LogEntry::plain(time(4), LogKind::SignedIn, None);
            s.append_log(Some(&account), &row).unwrap();
            s.accept_command(command, time(5)).unwrap();
            s.set_outcome(command, CommandOutcome::Applied).unwrap();
            s.set_session(&session).unwrap();
            s.set_setting("window", "open").unwrap();
            s.remove_document_everywhere(doc(9), time(6)).unwrap();
            (s.current_sequence().unwrap(), s.log_page(Some(&account), None, 10).unwrap())
        };

        let s = Store::open(&path).unwrap();
        assert_eq!(s.current_sequence().unwrap(), sequence);
        assert_eq!(s.children(case_container(1)).unwrap(), list);
        assert_eq!(s.log_page(Some(&account), None, 10).unwrap(), log);
        assert_eq!(s.open_acknowledgement().unwrap().len(), 1);
        assert_eq!(s.session().unwrap(), Some(session));
        assert_eq!(s.setting("window").unwrap().as_deref(), Some("open"));
        assert!(s.is_erased(doc(9), time(7)).unwrap());
    }

    #[test]
    fn condensing_empties_the_log_when_nobody_is_reading() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let mut s = Store::open(&path).unwrap();
        s.set_setting("a", "b").unwrap();
        assert!(s.condense().unwrap());
        let log = std::fs::metadata(path.with_extension("sqlite-wal")).unwrap();
        assert_eq!(log.len(), 0);
    }
}
