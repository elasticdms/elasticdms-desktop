//! The local usage log, per account (ADR-D07, requirement 4).
//!
//! The rows are built by the core ([`LogEntry`]); here they are stored, read page by page, limited
//! and redacted.
//!
//! * **Rows belong to the account** that was signed in. The view shows only those of the signed-in
//!   account; another user of the same machine does not see them. Rows without an account (such as
//!   "device registered" before the first sign-in) are **device rows**: visible only for as long as
//!   nobody is signed in, and never with a subject — otherwise a document name would stand in front
//!   of everyone who opens the machine without signing in.
//! * **Page by page over the row number, not over the time.** Two rows can carry the same
//!   millisecond; the number is unique and rising, and `AUTOINCREMENT` never hands out a number a
//!   second time after trimming.
//! * **Limited** to [`LOG_PER_ACCOUNT`](crate::LOG_PER_ACCOUNT) rows per account; the newest stay.
//!   It is display, not evidence — the authoritative access log is kept by the server.
//! * **Redacting** is [`LogEntry::redacted`] in SQL, across all accounts: after an erasure the
//!   title must not stay behind in another user's row either.

use edms_core::identifier::DocumentIdentifier;
use edms_core::log::{LogEntry, LogKind, REDACTED, Subject};
use edms_core::time::Timestamp;
use rusqlite::{Row, TransactionBehavior, params};
use serde::Serialize;

use crate::Store;
use crate::account::Account;
use crate::column::{from_name, from_u64, name_of, read_identifier, to_u64};
use crate::error::StoreError;

const T_LOG: &str = "log";

/// A stored row with its number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogRow {
    /// Unique and rising; the paging cursor of the view.
    pub number: u64,
    /// The row.
    pub entry: LogEntry,
}

/// One page of the log, newest row first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogPage {
    /// The rows, descending by number.
    pub rows: Vec<LogRow>,
    /// The number before which the next page begins; `None` when this is the last one.
    pub more_before: Option<u64>,
}

impl Store {
    /// Appends a row and returns its number; trims the account to the newest
    /// [`LOG_PER_ACCOUNT`](crate::LOG_PER_ACCOUNT) rows.
    ///
    /// `account` is the signed-in account; `None` creates a device row, which must not carry a
    /// subject ([`StoreError::DeviceRowWithSubject`]).
    pub fn append_log(
        &mut self,
        account: Option<&Account>,
        entry: &LogEntry,
    ) -> Result<u64, StoreError> {
        if account.is_none() && entry.subject().is_some() {
            return Err(StoreError::DeviceRowWithSubject);
        }
        let limit = from_u64(self.limit.log_per_account, "log_per_account")?;
        let account = account.map(Account::as_str);
        let kind = name_of(&entry.kind(), "log kind")?;
        let subject = entry.subject();
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.prepare_cached(
            "INSERT INTO log (account, time, kind, name, document, location, detail) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?
        .execute(params![
            account,
            entry.time().unix_millis(),
            kind,
            subject.map(|g| g.name.as_str()),
            subject.and_then(|g| g.document).map(|d| d.to_string()),
            subject.and_then(|g| g.location.as_deref()),
            entry.detail(),
        ])?;
        let number = tx.last_insert_rowid();
        tx.prepare_cached(
            "DELETE FROM log WHERE account IS ?1 AND id <= \
             (SELECT id FROM log WHERE account IS ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)",
        )?
        .execute(params![account, limit])?;
        tx.commit()?;
        to_u64(number, T_LOG, "id")
    }

    /// One page of an account's rows, newest first; with `before`, the page before that number.
    ///
    /// `account = None` reads the device rows — what the view shows for as long as nobody is
    /// signed in.
    pub fn log_page(
        &self,
        account: Option<&Account>,
        before: Option<u64>,
        max: usize,
    ) -> Result<LogPage, StoreError> {
        if max == 0 {
            return Err(StoreError::EmptyPage);
        }
        let before = before.map(|number| from_u64(number, "before")).transpose()?;
        // Read one row more, to know whether it goes on.
        let limit = i64::try_from(max).unwrap_or(i64::MAX - 1).saturating_add(1);
        let raw: Vec<RawRow> = {
            let mut query = self.connection.prepare_cached(
                "SELECT id, time, kind, name, document, location, detail FROM log \
                 WHERE account IS ?1 AND (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?3",
            )?;
            query
                .query_map(params![account.map(Account::as_str), before, limit], RawRow::read)?
                .collect::<Result<_, _>>()?
        };
        let mut rows = raw.into_iter().map(RawRow::row).collect::<Result<Vec<_>, _>>()?;
        let more_before = if rows.len() > max {
            rows.truncate(max);
            rows.last().map(|row| row.number)
        } else {
            None
        };
        Ok(LogPage { rows, more_before })
    }

    /// Takes the name off every row belonging to a document — in all accounts — and returns their
    /// number.
    ///
    /// Exactly the semantics of [`LogEntry::redacted`]: the name becomes [`REDACTED`], document,
    /// location and detail are erased, time and kind stay.
    pub fn redact(&mut self, document: DocumentIdentifier) -> Result<usize, StoreError> {
        let redacted = self
            .connection
            .prepare_cached(
                "UPDATE log SET name = ?1, document = NULL, location = NULL, detail = NULL \
                 WHERE document = ?2",
            )?
            .execute(params![REDACTED, document.to_string()])?;
        self.condense_after_erasure();
        Ok(redacted)
    }
}

/// One row from `log`, not yet checked.
struct RawRow {
    id: i64,
    time: i64,
    kind: String,
    name: Option<String>,
    document: Option<String>,
    location: Option<String>,
    detail: Option<String>,
}

impl RawRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            time: row.get(1)?,
            kind: row.get(2)?,
            name: row.get(3)?,
            document: row.get(4)?,
            location: row.get(5)?,
            detail: row.get(6)?,
        })
    }

    fn row(self) -> Result<LogRow, StoreError> {
        let Self { id, time, kind, name, document, location, detail } = self;
        let kind: LogKind = from_name(&kind, T_LOG, "kind")?;
        let document: Option<DocumentIdentifier> =
            document.as_deref().map(|text| read_identifier(text, T_LOG, "document")).transpose()?;
        let subject = match name {
            Some(name) => Some(Subject { name, document, location }),
            None if document.is_none() && location.is_none() => None,
            None => {
                return Err(StoreError::corrupt(T_LOG, "document or location without a name"));
            }
        };
        // The rules of the type hold when reading too: an erasure row with a name is corruption.
        let entry = LogEntry::new(Timestamp::from_unix_millis(time), kind, subject, detail)
            .map_err(|error| StoreError::corrupt(T_LOG, error.to_string()))?;
        Ok(LogRow { number: to_u64(id, T_LOG, "id")?, entry })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{doc, store, time};

    fn account(sub: &str) -> Account {
        Account::new(sub).unwrap()
    }

    fn opened(millis: i64, document: u128, name: &str) -> LogEntry {
        let subject = Subject {
            name: name.into(),
            document: Some(doc(document)),
            location: Some("Akte Sulzer".into()),
        };
        LogEntry::new(time(millis), LogKind::Opened, Some(subject), Some(format!("{name}, 1 KB")))
            .unwrap()
    }

    fn detail(page: &LogPage) -> Vec<String> {
        page.rows.iter().map(|z| z.entry.detail().unwrap_or_default().to_owned()).collect()
    }

    #[test]
    fn a_row_survives_the_round_trip() {
        let mut s = store();
        let a = account("usr_A");
        let row = opened(5, 7, "Rechnung.pdf");
        let number = s.append_log(Some(&a), &row).unwrap();
        let page = s.log_page(Some(&a), None, 10).unwrap();
        assert_eq!(page.rows, [LogRow { number, entry: row }]);
        assert_eq!(page.more_before, None);
    }

    #[test]
    fn the_page_shows_the_newest_row_first_and_pages_over_the_number() {
        let mut s = store();
        let a = account("usr_A");
        for i in 0..5 {
            let row = LogEntry::plain(time(1), LogKind::SignedIn, Some(format!("z{i}")));
            s.append_log(Some(&a), &row).unwrap();
        }
        let first = s.log_page(Some(&a), None, 2).unwrap();
        assert_eq!(detail(&first), ["z4", "z3"]);
        let second = s.log_page(Some(&a), first.more_before, 2).unwrap();
        assert_eq!(detail(&second), ["z2", "z1"]);
        let third = s.log_page(Some(&a), second.more_before, 2).unwrap();
        assert_eq!(detail(&third), ["z0"]);
        assert_eq!(third.more_before, None);
    }

    #[test]
    fn an_account_sees_only_its_rows_and_without_a_sign_in_only_the_device_ones() {
        let mut s = store();
        let (a, b) = (account("usr_A"), account("usr_B"));
        s.append_log(Some(&a), &opened(1, 7, "A.pdf")).unwrap();
        s.append_log(Some(&b), &opened(2, 8, "B.pdf")).unwrap();
        let device = LogEntry::plain(time(3), LogKind::DeviceRegistered, None);
        s.append_log(None, &device).unwrap();

        assert_eq!(detail(&s.log_page(Some(&a), None, 10).unwrap()), ["A.pdf, 1 KB"]);
        assert_eq!(detail(&s.log_page(Some(&b), None, 10).unwrap()), ["B.pdf, 1 KB"]);
        let without = s.log_page(None, None, 10).unwrap();
        assert_eq!(without.rows.len(), 1);
        assert_eq!(without.rows[0].entry, device);
    }

    #[test]
    fn redacting_takes_the_name_in_all_accounts_exactly_as_the_core_does() {
        let mut s = store();
        let (a, b) = (account("usr_A"), account("usr_B"));
        let row_a = opened(1, 7, "Abmahnung.pdf");
        let row_b = opened(2, 7, "Abmahnung.pdf");
        let other = opened(3, 8, "Urlaub.pdf");
        s.append_log(Some(&a), &row_a).unwrap();
        s.append_log(Some(&b), &row_b).unwrap();
        s.append_log(Some(&a), &other).unwrap();

        assert_eq!(s.redact(doc(7)).unwrap(), 2);

        let at_a: Vec<LogEntry> =
            s.log_page(Some(&a), None, 10).unwrap().rows.into_iter().map(|z| z.entry).collect();
        assert_eq!(at_a, [other, row_a.redacted()]);
        let at_b: Vec<LogEntry> =
            s.log_page(Some(&b), None, 10).unwrap().rows.into_iter().map(|z| z.entry).collect();
        assert_eq!(at_b, [row_b.redacted()]);
        assert_eq!(s.redact(doc(7)).unwrap(), 0, "nothing left to redact");
    }

    #[test]
    fn the_log_keeps_only_the_newest_rows_per_account() {
        let mut s = store();
        s.limit.log_per_account = 3;
        let (a, b) = (account("usr_A"), account("usr_B"));
        for i in 0..5 {
            let row = LogEntry::plain(time(i), LogKind::SignedIn, Some(format!("a{i}")));
            s.append_log(Some(&a), &row).unwrap();
        }
        for i in 0..2 {
            let row = LogEntry::plain(time(i), LogKind::SignedIn, Some(format!("b{i}")));
            s.append_log(Some(&b), &row).unwrap();
        }
        assert_eq!(detail(&s.log_page(Some(&a), None, 10).unwrap()), ["a4", "a3", "a2"]);
        assert_eq!(detail(&s.log_page(Some(&b), None, 10).unwrap()), ["b1", "b0"]);
    }

    #[test]
    fn a_device_row_with_a_subject_and_an_empty_page_are_rejected() {
        let mut s = store();
        assert!(matches!(
            s.append_log(None, &opened(1, 7, "x.pdf")),
            Err(StoreError::DeviceRowWithSubject)
        ));
        assert!(s.log_page(None, None, 10).unwrap().rows.is_empty());
        assert!(matches!(s.log_page(None, None, 0), Err(StoreError::EmptyPage)));
    }

    #[test]
    fn every_log_kind_is_stored_by_its_name() {
        use LogKind::*;
        let kinds = [
            Opened,
            OpenFailed,
            NewVersion,
            SpaceReclaimed,
            AccessRevoked,
            ErasedByOrder,
            IngestAccepted,
            IngestFailed,
            DeviceRegistered,
            SignedIn,
            SignedOut,
            LoginRequired,
            ConnectionLost,
            ConnectionRestored,
            SecurityWarning,
        ];
        let mut s = store();
        let a = account("usr_A");
        for (i, kind) in kinds.iter().enumerate() {
            let row = LogEntry::plain(time(i64::try_from(i).unwrap()), *kind, None);
            s.append_log(Some(&a), &row).unwrap();
        }
        let read: Vec<LogKind> = s
            .log_page(Some(&a), None, 100)
            .unwrap()
            .rows
            .iter()
            .rev()
            .map(|z| z.entry.kind())
            .collect();
        assert_eq!(read, kinds);

        let names: Vec<String> = s
            .connection
            .prepare("SELECT kind FROM log ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(names[1], "OPEN_FAILED");
        assert_eq!(names[5], "ERASED_BY_ORDER");
    }
}
