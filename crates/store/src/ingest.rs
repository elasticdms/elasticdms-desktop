//! What an ingest out of a mail basket needs across a crash (ADR-D08, amended by ADR-D11).
//!
//! An ingest has three steps — `POST /v1/ingest-uploads`, `PUT <uploadUrl>`, `POST …:complete`
//! (contract §7.4) —, and between any two of them the machine can go out. Hence one row per file
//! handed in stands here:
//!
//! * **The idempotency key is stable per file.** A retry after an abort carries the same key and is
//!   therefore **not a second upload** (03 §6.0.10, obligation AND-2: unchanged on every technical
//!   retry of the same payload). One key per attempt would be wrong here — the payload is the same
//!   file.
//! * **Not keyed over the content.** Two identical invoices can be two matters (§7.4.2: a duplicate
//!   is **marked, not suppressed**); a key over the checksum would quietly swallow the second one.
//!   The key hangs off [`InboxPending::file`], and changes as soon as size or modification time
//!   change: then it is a different file.
//! * **The upload identifier stays put** until the file has moved into the app's own holding
//!   directory, `<holding>/<uploadId>/` (ADR-D11 §5). If the machine crashes between `:complete`
//!   and the move, the engine finds the identifier again and puts the file there instead of
//!   uploading it a second time.
//!
//! The row is deleted only once the file has been moved — never before: "until the server has
//! confirmed the ingest, the local file is the only copy" (ADR-D08, point 5).

use edms_core::identifier::UploadIdentifier;
use edms_core::time::Timestamp;
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};

use crate::Store;
use crate::column::{from_u64, read_identifier, to_u64};
use crate::error::StoreError;

const T_INGEST: &str = "ingest";

/// Length of a ULID — the same check as in `edms_net::IdempotencyKey`.
const LENGTH_KEY: usize = 26;

/// What is settled about an ingest that has begun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPending {
    /// Which basket, and which file in it: `bsk_…/Rechnung.pdf`, never a path of the machine.
    ///
    /// The basket belongs in the key because the same `Rechnung.pdf` can lie in two baskets at
    /// once, and they are two ingests with two targets (`edms_engine::ingest`).
    pub file: String,
    /// The idempotency key of this ingest, a ULID — one per file, the same one across all
    /// attempts.
    pub key: String,
    /// Size in bytes at the time the file was noted.
    pub size: u64,
    /// Modification time at the time the file was noted.
    pub changed: Timestamp,
    /// The upload identifier, as soon as the server has promised it.
    pub upload: Option<UploadIdentifier>,
    /// When the note came into being.
    pub created: Timestamp,
}

impl InboxPending {
    /// Whether the note still belongs to the file that lies on the disk now.
    ///
    /// If a file grows or is overwritten, it is a **different** payload; the same idempotency key
    /// would then run into `422 idempotency-key-reuse` (03 §6.0.10).
    pub const fn matches(&self, size: u64, changed: Timestamp) -> bool {
        self.size == size && self.changed.unix_millis() == changed.unix_millis()
    }
}

impl Store {
    /// Creates a note or replaces it; returns it as it is now stored.
    ///
    /// The key has to be a ULID — a command or document identifier is not one (03 §6.0.10).
    ///
    /// # Errors
    ///
    /// [`StoreError::IngestKeyInvalid`] when the key does not have 26 characters; otherwise when
    /// the database does not write.
    pub fn remember_inbox(&mut self, pending: &InboxPending) -> Result<(), StoreError> {
        if pending.key.chars().count() != LENGTH_KEY {
            return Err(StoreError::IngestKeyInvalid(pending.key.clone()));
        }
        self.connection
            .prepare_cached(
                "INSERT INTO ingest (file, key, size, changed, upload, created) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT (file) DO UPDATE SET key = excluded.key, \
                 size = excluded.size, changed = excluded.changed, \
                 upload = excluded.upload, created = excluded.created",
            )?
            .execute(params![
                pending.file,
                pending.key,
                from_u64(pending.size, "size")?,
                pending.changed.unix_millis(),
                pending.upload.map(|u| u.to_string()),
                pending.created.unix_millis(),
            ])?;
        Ok(())
    }

    /// The note for a file; `None` when there is none.
    ///
    /// # Errors
    ///
    /// When the database does not read or the row is corrupt.
    pub fn inbox(&self, file: &str) -> Result<Option<InboxPending>, StoreError> {
        let raw = self
            .connection
            .prepare_cached(
                "SELECT file, key, size, changed, upload, created \
                 FROM ingest WHERE file = ?1",
            )?
            .query_row(params![file], RawInbox::read)
            .optional()?;
        raw.map(RawInbox::pending).transpose()
    }

    /// Records the promised upload identifier — **before** the bytes go out.
    ///
    /// After that the engine knows, following a crash, where the file belongs, and does not upload
    /// it a second time.
    ///
    /// # Errors
    ///
    /// [`StoreError::InboxUnknown`] when there is no note.
    pub fn set_inbox_upload(
        &mut self,
        file: &str,
        upload: UploadIdentifier,
    ) -> Result<(), StoreError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let affected = tx
            .prepare_cached("UPDATE ingest SET upload = ?1 WHERE file = ?2")?
            .execute(params![upload.to_string(), file])?;
        if affected == 0 {
            return Err(StoreError::InboxUnknown(file.to_owned()));
        }
        tx.commit()?;
        Ok(())
    }

    /// Removes the note; `true` when there was one.
    ///
    /// To be called only **after** the move into `<holding>/<uploadId>/`: before that, the note is
    /// the only thing that finds an ingest that has begun.
    ///
    /// # Errors
    ///
    /// When the database does not write.
    pub fn forget_inbox(&mut self, file: &str) -> Result<bool, StoreError> {
        let deleted = self
            .connection
            .prepare_cached("DELETE FROM ingest WHERE file = ?1")?
            .execute(params![file])?;
        Ok(deleted > 0)
    }

    /// All notes, oldest first — the work stock after a restart.
    ///
    /// # Errors
    ///
    /// When the database does not read or a row is corrupt.
    pub fn open_inbound(&self) -> Result<Vec<InboxPending>, StoreError> {
        let raw: Vec<RawInbox> = {
            let mut query = self.connection.prepare_cached(
                "SELECT file, key, size, changed, upload, created \
                 FROM ingest ORDER BY created, file",
            )?;
            query.query_map([], RawInbox::read)?.collect::<Result<_, _>>()?
        };
        raw.into_iter().map(RawInbox::pending).collect()
    }
}

/// One row from `ingest`, not yet checked.
struct RawInbox {
    file: String,
    key: String,
    size: i64,
    changed: i64,
    upload: Option<String>,
    created: i64,
}

impl RawInbox {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            file: row.get(0)?,
            key: row.get(1)?,
            size: row.get(2)?,
            changed: row.get(3)?,
            upload: row.get(4)?,
            created: row.get(5)?,
        })
    }

    fn pending(self) -> Result<InboxPending, StoreError> {
        Ok(InboxPending {
            file: self.file,
            key: self.key,
            size: to_u64(self.size, T_INGEST, "size")?,
            changed: Timestamp::from_unix_millis(self.changed),
            upload: self
                .upload
                .as_deref()
                .map(|text| read_identifier(text, T_INGEST, "upload"))
                .transpose()?,
            created: Timestamp::from_unix_millis(self.created),
        })
    }
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;

    use super::*;
    use crate::test_support::{store, time};

    fn pending(file: &str, key: &str) -> InboxPending {
        InboxPending {
            file: file.to_owned(),
            key: key.to_owned(),
            size: 1_024,
            changed: time(2_000),
            upload: None,
            created: time(3_000),
        }
    }

    #[test]
    fn a_note_holds_the_same_key_across_every_attempt() {
        let mut s = store();
        let first = pending("Rechnung.pdf", "01JKC6F8G0H2J4K6M8N0P2Q4R6");
        s.remember_inbox(&first).unwrap();
        let read = s.inbox("Rechnung.pdf").unwrap().unwrap();
        assert_eq!(read, first);
        assert!(read.matches(1_024, time(2_000)));
        // A second run at the same file finds the same key in place — otherwise the repetition
        // would be a second upload (03 §6.0.10).
        assert_eq!(s.inbox("Rechnung.pdf").unwrap().unwrap().key, first.key);
    }

    #[test]
    fn a_file_that_has_grown_is_a_different_payload() {
        let noted = pending("Scan.pdf", "01JKC6F8G0H2J4K6M8N0P2Q4R6");
        assert!(!noted.matches(2_048, time(2_000)), "different size");
        assert!(!noted.matches(1_024, time(9_000)), "different modification time");
    }

    #[test]
    fn a_key_that_is_not_a_ulid_is_not_stored() {
        let mut s = store();
        let error = s
            .remember_inbox(&pending("x.pdf", "upl_01JKD8H0J2K4M6N8P0Q2R4S6T8"))
            .expect_err("an identifier with a prefix is not an idempotency key");
        assert!(matches!(error, StoreError::IngestKeyInvalid(_)), "{error}");
        assert_eq!(s.inbox("x.pdf").unwrap(), None);
    }

    #[test]
    fn the_upload_identifier_survives_closing_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let upload: UploadIdentifier = Identifier::from_value(7);
        {
            let mut s = Store::open(&path).unwrap();
            s.remember_inbox(&pending("Beleg.pdf", "01JKC6F8G0H2J4K6M8N0P2Q4R6")).unwrap();
            s.set_inbox_upload("Beleg.pdf", upload).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let open = s.open_inbound().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].upload, Some(upload), "otherwise the upload would run a second time");
    }

    #[test]
    fn an_unknown_file_does_not_get_an_upload_identifier_slipped_to_it() {
        let mut s = store();
        let error = s
            .set_inbox_upload("never_seen.pdf", Identifier::from_value(1))
            .expect_err("without a note there is nothing to record");
        assert!(matches!(error, StoreError::InboxUnknown(_)), "{error}");
    }

    #[test]
    fn forgetting_clears_the_row_and_is_harmless_twice() {
        let mut s = store();
        s.remember_inbox(&pending("a.pdf", "01JKC6F8G0H2J4K6M8N0P2Q4R6")).unwrap();
        s.remember_inbox(&pending("b.pdf", "01JKC6F8G0H2J4K6M8N0P2Q4R7")).unwrap();
        assert_eq!(s.open_inbound().unwrap().len(), 2);
        assert!(s.forget_inbox("a.pdf").unwrap());
        assert!(!s.forget_inbox("a.pdf").unwrap());
        assert_eq!(s.open_inbound().unwrap().len(), 1);
    }
}
