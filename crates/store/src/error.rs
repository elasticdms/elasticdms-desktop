//! The store's errors: values carrying whole sentences.
//!
//! "No function that quietly does the wrong thing" (README, house rules): where the store cannot
//! or must not do something, a reason stands here — never an empty vector that looks like
//! "nothing there", and never a fallback value that looks like a result.

use std::path::{Path, PathBuf};

use edms_core::identifier::CommandIdentifier;
use edms_core::namespace::{Container, EntryIdentifier};
use edms_core::port::SourceError;

/// Why the store does not fulfil a request.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The file cannot be opened or created, or it is not a SQLite database.
    #[error(
        "the local database `{location}` cannot be opened: {source}",
        location = .path.display()
    )]
    Open {
        /// Where it lies.
        path: PathBuf,
        /// What SQLite reports.
        #[source]
        source: rusqlite::Error,
    },

    /// SQLite reports an error.
    #[error("the local database reports an error: {0}")]
    Database(#[from] rusqlite::Error),

    /// The database comes from a newer version of the folder client.
    ///
    /// It is not touched: an older version that reads a newer schema reads columns wrongly or
    /// not at all, and one that "migrates them back" destroys data.
    #[error(
        "the local database is at schema {found}, this program knows only up to {known}; it \
         comes from a newer version of the folder client and is not touched"
    )]
    SchemaTooNew {
        /// The file's `user_version`.
        found: i64,
        /// The highest version this crate knows.
        known: i64,
    },

    /// Opened for reading, but the database is not yet at this program's level.
    #[error(
        "the local database is at schema {found} instead of {expected}; reading does not \
         migrate, the engine has to open it for writing first"
    )]
    SchemaStale {
        /// The file's `user_version`.
        found: i64,
        /// This crate's version.
        expected: i64,
    },

    /// The file cannot be run in WAL mode.
    #[error(
        "the local database runs in mode `{mode}` instead of WAL; without WAL a reading \
         process locks the writing one. Does it lie on a network drive?"
    )]
    NoWal {
        /// The mode SQLite reports.
        mode: String,
    },

    /// A pragma does not hold the demanded value after being set.
    #[error(
        "Pragma {name} stands at {found} instead of {expected}; without this setting the \
         database is not used"
    )]
    Pragma {
        /// The pragma.
        name: &'static str,
        /// Demanded.
        expected: i64,
        /// Read back.
        found: i64,
    },

    /// The anchor lies before the oldest entry the journal can still deliver.
    #[error(
        "the change journal begins only at sequence {oldest_sequence}; the anchor {anchor} has \
         expired, the namespace has to be enumerated afresh"
    )]
    AnchorExpired {
        /// The caller's anchor.
        anchor: u64,
        /// The smallest sequence number still delivered; anchors from `oldest_sequence - 1`
        /// on are valid.
        oldest_sequence: u64,
    },

    /// The anchor lies beyond the current sequence number — it is not from this database.
    #[error(
        "the anchor {anchor} lies beyond the current sequence {current_sequence}; it does not \
         come from this database, the namespace has to be enumerated afresh"
    )]
    AnchorUnknown {
        /// The caller's anchor.
        anchor: u64,
        /// The highest sequence number handed out.
        current_sequence: u64,
    },

    /// A page of size zero.
    #[error(
        "a page has to hold at least one entry; with zero the caller would never reach the end"
    )]
    EmptyPage,

    /// The container stands in no stored listing of its parent container.
    #[error(
        "the container `{0}` stands in no stored listing of its parent container; reconcile \
         the listing above it first"
    )]
    ContainerUnknown(Container),

    /// An entry of the listing belongs in a different container.
    ///
    /// The identifier lies in a box, and only here: since namespace v2 an entry identifier carries
    /// archive, case file and document and measures 80 bytes (`size_of`, measured 2026-09-12), a
    /// container 48 — together the only variant that pushes this error to 128 bytes, the width at
    /// which clippy reports every `Result` of the store (`result_large_err`). The allocation falls
    /// on a path that no correct listing takes.
    #[error("the entry `{identifier}` does not belong in the container `{container}`")]
    ForeignEntry {
        /// The container whose listing was to be replaced.
        container: Container,
        /// The entry that does not belong in it.
        identifier: Box<EntryIdentifier>,
    },

    /// An identifier stands twice in the same listing.
    #[error(
        "the identifier `{0}` stands twice in the same listing; a place holds every entry only \
         once"
    )]
    DuplicateIdentifier(EntryIdentifier),

    /// Two siblings carry the same name in the form in which the file systems compare.
    #[error(
        "in the container `{container}` the name `{name}` stands twice (upper and lower case \
         and Unicode form do not count); Explorer and Finder take only one"
    )]
    DuplicateName {
        /// The container.
        container: Container,
        /// The second name, as it stood in the listing.
        name: String,
    },

    /// A container is not a folder, or a document/hint is not a file.
    #[error(
        "the entry `{0}` has the wrong kind: a container is always a folder, a document or a \
         hint always a file"
    )]
    WrongKind(EntryIdentifier),

    /// A document without a checksum.
    #[error(
        "the document `{0}` comes without a checksum; without it the loaded content cannot be \
         checked, and unchecked no byte reaches the disk (edms_core::port)"
    )]
    WithoutChecksum(EntryIdentifier),

    /// A usage-log row without an account that carries a subject.
    #[error(
        "a usage-log row without an account must not carry a subject; it would be visible to \
         anybody who opens the machine without signing in (requirement 4)"
    )]
    DeviceRowWithSubject,

    /// This device never accepted the command.
    #[error("this device never accepted the command `{0}`")]
    CommandUnknown(CommandIdentifier),

    /// The command has no outcome yet.
    #[error("the command `{0}` has no outcome yet; only what has been carried out is acknowledged")]
    CommandWithoutOutcome(CommandIdentifier),

    /// The command is already acknowledged.
    #[error(
        "the command `{0}` is already acknowledged; its outcome stands at the server and cannot \
         be changed here any more"
    )]
    CommandAcknowledged(CommandIdentifier),

    /// There is no note for this file of a mail basket.
    #[error("there is no note for the file `{0}` in the mail basket")]
    InboxUnknown(String),

    /// The idempotency key of an ingest is not a ULID.
    #[error(
        "`{0}` is not an idempotency key: that is a ULID of 26 characters, not the identifier \
         of an upload (03 §6.0.10)"
    )]
    IngestKeyInvalid(String),

    /// An empty setting key.
    #[error("a setting key must not be empty")]
    EmptyKey,

    /// A number does not fit into a SQLite integer.
    #[error("the value {value} for {field} does not fit into a SQLite number (at most 2^63 - 1)")]
    NumberTooLarge {
        /// The field.
        field: &'static str,
        /// The value.
        value: u64,
    },

    /// A value cannot be stored as JSON.
    #[error("{what} cannot be stored as JSON: {source}")]
    Encoding {
        /// What was to be stored.
        what: &'static str,
        /// What serde reports.
        #[source]
        source: serde_json::Error,
    },

    /// Data read back violates the rules of its type.
    #[error("the local database is corrupt (table {table}): {reason}")]
    Corrupt {
        /// The table.
        table: &'static str,
        /// What is wrong.
        reason: String,
    },
}

impl StoreError {
    /// Whether the caller must enumerate the namespace afresh instead of catching up changes.
    pub const fn requires_new_enumeration(&self) -> bool {
        matches!(self, Self::AnchorExpired { .. } | Self::AnchorUnknown { .. })
    }

    /// A SQLite error during set-up belongs to the path that was opened.
    pub(crate) fn with_path(self, path: &Path) -> Self {
        match self {
            Self::Database(source) => Self::Open { path: path.to_owned(), source },
            other => other,
        }
    }

    pub(crate) fn corrupt(table: &'static str, reason: impl Into<String>) -> Self {
        Self::Corrupt { table, reason: reason.into() }
    }
}

/// The seam to the platform (`edms_core::port::NamespaceSource`) knows reasons of its own.
///
/// An expired and a foreign anchor both become `AnchorExpired`, because both demand the same
/// thing: enumerate afresh. An unknown container becomes `NotFound`. Everything else is, to the
/// platform, an error of this program (`Internal`), with the whole sentence as its text.
impl From<StoreError> for SourceError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::AnchorExpired { .. } | StoreError::AnchorUnknown { .. } => {
                Self::AnchorExpired
            }
            StoreError::ContainerUnknown(container) => {
                Self::NotFound(EntryIdentifier::Container(container))
            }
            other => Self::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;

    use super::*;

    #[test]
    fn store_errors_become_the_source_errors_of_the_seam() {
        let expired = StoreError::AnchorExpired { anchor: 1, oldest_sequence: 3 };
        assert!(expired.requires_new_enumeration());
        assert_eq!(SourceError::from(expired), SourceError::AnchorExpired);
        let foreign = StoreError::AnchorUnknown { anchor: 9, current_sequence: 3 };
        assert!(foreign.requires_new_enumeration());
        assert_eq!(SourceError::from(foreign), SourceError::AnchorExpired);

        let case =
            Container::Case { archive: Identifier::from_value(2), case: Identifier::from_value(1) };
        assert_eq!(
            SourceError::from(StoreError::ContainerUnknown(case)),
            SourceError::NotFound(EntryIdentifier::Container(case))
        );
        assert!(!StoreError::EmptyPage.requires_new_enumeration());
        assert!(matches!(
            SourceError::from(StoreError::EmptyPage),
            SourceError::Internal(text) if text.contains("at least one entry")
        ));
    }

    #[test]
    fn a_sqlite_error_during_set_up_names_the_path() {
        let error = StoreError::Database(rusqlite::Error::InvalidQuery)
            .with_path(Path::new("/tmp/state.sqlite"));
        assert!(matches!(&error, StoreError::Open { path, .. } if path.ends_with("state.sqlite")));
        assert!(error.to_string().contains("/tmp/state.sqlite"), "{error}");
    }
}
