//! The local usage log — the app's first view.
//!
//! Like OneDrive's activity list: what happened on **this device** to **your** files, newest
//! first. Two things set it apart from a gimmick:
//!
//! 1. **It is not the access log.** The authoritative log is kept by the server: every hydration
//!    runs through it, and there it is recorded as an access (requirement: „Jede Hydrierung ist
//!    ein Zugriff und gehoert ins Protokoll" — every hydration is an access and belongs in the
//!    log). The local list is display, and it says so in the user interface too.
//! 2. **An erasure leaves no name behind.** A row „Auf Anordnung entfernt" (erased by order)
//!    never carries a subject — the type enforces that, not the user interface. And earlier rows
//!    about the same document have the name taken from them ([`LogEntry::redacted`]); otherwise
//!    the title that the erasure was meant to wipe out would stand in, of all places, the window
//!    built for transparency.
//! 3. **The row is a value, the sentence is not.** What a row *says* stands in the text catalogue
//!    ([`LogKind::text_key`]); what is *stored* is the variant name in SCREAMING_SNAKE_CASE. A
//!    database that held sentences would hold them in the language of the day they were written.

use edms_i18n::{Catalog, Key, key};
use serde::{Deserialize, Serialize};

use crate::identifier::DocumentIdentifier;
use crate::time::Timestamp;

/// What takes the place of a redacted name **in the store and on the wire**.
///
/// A marker, not a sentence: it is written into the database, and a database written in German
/// would show German rows to an English user for ever. The sentence the user reads stands under
/// [`key::LOG_REDACTED`] and is picked at display time ([`Subject::display_name`]).
///
/// Store migration 4 rewrites the sentence of the earlier versions to this marker.
pub const REDACTED: &str = "REDACTED";

/// The kinds of row. The wire value (for database and user interface) is the variant name in
/// SCREAMING_SNAKE_CASE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogKind {
    /// Content loaded from the server (hydration).
    Opened,
    /// Opening failed.
    OpenFailed,
    /// A new version on the server; the local copy was discarded.
    NewVersion,
    /// Local content released (space reclamation or by the user).
    SpaceReclaimed,
    /// Access revoked; the local copy is gone.
    AccessRevoked,
    /// DSGVO (GDPR) erasure carried out. Never carries a subject.
    ErasedByOrder,
    /// File taken from a mail basket into the inbox.
    IngestAccepted,
    /// Ingest from a mail basket failed.
    IngestFailed,
    /// Device registered or waiting for approval.
    DeviceRegistered,
    /// Signed in.
    SignedIn,
    /// Signed out; the mirror is cleared.
    SignedOut,
    /// Session expired; a sign-in is needed.
    LoginRequired,
    /// Server unreachable.
    ConnectionLost,
    /// Server reachable again.
    ConnectionRestored,
    /// Signature or key problem; a command was not executed.
    SecurityWarning,
}

/// How prominently a row is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// A normal operation.
    Info,
    /// Worth a look.
    Notice,
    /// Something went wrong or is suspicious.
    Warning,
}

impl LogKind {
    /// The catalogue key of the label. Exhaustive, so that a new kind turns this file red instead
    /// of arriving in the window without a label.
    pub const fn text_key(self) -> Key {
        match self {
            Self::Opened => key::LOG_OPENED,
            Self::OpenFailed => key::LOG_OPEN_FAILED,
            Self::NewVersion => key::LOG_NEW_VERSION,
            Self::SpaceReclaimed => key::LOG_SPACE_RECLAIMED,
            Self::AccessRevoked => key::LOG_ACCESS_REVOKED,
            Self::ErasedByOrder => key::LOG_ERASED_BY_ORDER,
            Self::IngestAccepted => key::LOG_INGEST_ACCEPTED,
            Self::IngestFailed => key::LOG_INGEST_FAILED,
            Self::DeviceRegistered => key::LOG_DEVICE_REGISTERED,
            Self::SignedIn => key::LOG_SIGNED_IN,
            Self::SignedOut => key::LOG_SIGNED_OUT,
            Self::LoginRequired => key::LOG_LOGIN_REQUIRED,
            Self::ConnectionLost => key::LOG_CONNECTION_LOST,
            Self::ConnectionRestored => key::LOG_CONNECTION_RESTORED,
            Self::SecurityWarning => key::LOG_SECURITY_WARNING,
        }
    }

    /// The label in the user interface, in the catalogue's language.
    pub fn label(self, catalogue: &Catalog) -> &str {
        catalogue.text(self.text_key())
    }

    /// How prominent.
    pub const fn severity(self) -> Severity {
        match self {
            Self::OpenFailed | Self::IngestFailed | Self::SecurityWarning => Severity::Warning,
            Self::ErasedByOrder
            | Self::AccessRevoked
            | Self::LoginRequired
            | Self::ConnectionLost => Severity::Notice,
            _ => Severity::Info,
        }
    }

    /// Whether a row of this kind may carry a subject.
    pub const fn may_carry_subject(self) -> bool {
        !matches!(self, Self::ErasedByOrder)
    }
}

/// What a row refers to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// The file name as it stood in the mirror, or [`REDACTED`] when the name has been taken off.
    pub name: String,
    /// The document, if there is one (inbound files do not have one yet).
    pub document: Option<DocumentIdentifier>,
    /// Display name of the location, e.g. the case file (Akte).
    pub location: Option<String>,
}

impl Subject {
    /// Whether the name has been taken off this subject ([`LogEntry::redacted`]).
    ///
    /// All three conditions together, not the marker alone: a file really called `REDACTED` would
    /// otherwise look like an erased one, and its location and document would contradict the
    /// claim.
    pub fn is_redacted(&self) -> bool {
        self.name == REDACTED && self.document.is_none() && self.location.is_none()
    }

    /// The name as a user reads it: the file name, or the sentence about the erasure.
    pub fn display_name<'a>(&'a self, catalogue: &'a Catalog) -> &'a str {
        if self.is_redacted() { catalogue.text(key::LOG_REDACTED) } else { &self.name }
    }
}

/// One row of the usage log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawLogEntry")]
pub struct LogEntry {
    time: Timestamp,
    kind: LogKind,
    subject: Option<Subject>,
    detail: Option<String>,
}

/// A row violates the rules of its type. A programming fault, never a sentence for a user.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a row of kind {0:?} must not carry a subject — an erasure leaves no name behind")]
pub struct LogError(pub LogKind);

#[derive(Deserialize)]
struct RawLogEntry {
    time: Timestamp,
    kind: LogKind,
    subject: Option<Subject>,
    detail: Option<String>,
}

impl TryFrom<RawLogEntry> for LogEntry {
    type Error = LogError;

    fn try_from(raw: RawLogEntry) -> Result<Self, Self::Error> {
        Self::new(raw.time, raw.kind, raw.subject, raw.detail)
    }
}

impl LogEntry {
    /// One row; fails when the kind may carry no subject and one is handed in anyway.
    pub fn new(
        time: Timestamp,
        kind: LogKind,
        subject: Option<Subject>,
        detail: Option<String>,
    ) -> Result<Self, LogError> {
        if subject.is_some() && !kind.may_carry_subject() {
            return Err(LogError(kind));
        }
        Ok(Self { time, kind, subject, detail })
    }

    /// A row without a subject (sign-in, connection).
    pub fn plain(time: Timestamp, kind: LogKind, detail: Option<String>) -> Self {
        Self { time, kind, subject: None, detail }
    }

    /// The row for a carried-out erasure. No name, no document, no location — there is no
    /// parameter through which one could get in.
    pub fn erased_by_order(time: Timestamp) -> Self {
        Self { time, kind: LogKind::ErasedByOrder, subject: None, detail: None }
    }

    /// The same row without the name: name replaced, document, location and detail removed.
    pub fn redacted(self) -> Self {
        let subject = self.subject.map(|_| Subject {
            name: REDACTED.to_owned(),
            document: None,
            location: None,
        });
        Self { subject, detail: None, ..self }
    }

    /// When.
    pub const fn time(&self) -> Timestamp {
        self.time
    }
    /// What.
    pub const fn kind(&self) -> LogKind {
        self.kind
    }
    /// About what.
    pub const fn subject(&self) -> Option<&Subject> {
        self.subject.as_ref()
    }
    /// Explanation, such as the reason for a failure.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Identifier;

    fn subject() -> Subject {
        Subject {
            name: "Rechnung.pdf".into(),
            document: Some(Identifier::from_value(1)),
            location: Some("Akte 7".into()),
        }
    }

    #[test]
    fn an_erasure_row_with_a_name_cannot_be_built() {
        let e = LogEntry::new(Timestamp::NULL, LogKind::ErasedByOrder, Some(subject()), None);
        assert_eq!(e, Err(LogError(LogKind::ErasedByOrder)));
    }

    #[test]
    fn an_erasure_row_with_a_name_cannot_be_read_in_either() {
        let json = serde_json::json!({
            "time": 0, "kind": "ERASED_BY_ORDER",
            "subject": { "name": "Rechnung.pdf", "document": null, "location": null },
            "detail": null
        });
        assert!(serde_json::from_value::<LogEntry>(json).is_err());
    }

    #[test]
    fn redacting_takes_name_document_location_and_detail() {
        let e = LogEntry::new(
            Timestamp::NULL,
            LogKind::Opened,
            Some(subject()),
            Some("Rechnung.pdf, 3 MB".into()),
        )
        .unwrap()
        .redacted();
        let s = e.subject().unwrap();
        assert_eq!(s.name, REDACTED);
        assert!(s.document.is_none() && s.location.is_none());
        assert!(e.detail().is_none());
        assert_eq!(e.kind(), LogKind::Opened);
    }

    #[test]
    fn a_redacted_name_is_a_marker_in_the_store_and_a_sentence_in_the_window() {
        // What is stored has to survive a change of language; what is shown has to follow it.
        let entry = LogEntry::new(Timestamp::NULL, LogKind::Opened, Some(subject()), None).unwrap();
        let taken = entry.redacted();
        let subject = taken.subject().unwrap();
        assert!(subject.is_redacted());
        assert_eq!(subject.name, "REDACTED", "the marker is what goes into the database");
        assert_eq!(
            subject.display_name(Catalog::of(edms_i18n::Language::De)),
            "Dokument auf Anordnung entfernt"
        );
        assert_eq!(
            subject.display_name(Catalog::of(edms_i18n::Language::En)),
            "Document erased by order"
        );
    }

    #[test]
    fn a_file_that_is_really_called_redacted_is_not_taken_for_an_erased_one() {
        let plain = Subject {
            name: REDACTED.to_owned(),
            document: Some(Identifier::from_value(1)),
            location: None,
        };
        assert!(!plain.is_redacted());
        assert_eq!(plain.display_name(Catalog::of(edms_i18n::Language::De)), REDACTED);
    }

    #[test]
    fn every_log_kind_has_a_label_in_every_language() {
        const ALL: [LogKind; 15] = [
            LogKind::Opened,
            LogKind::OpenFailed,
            LogKind::NewVersion,
            LogKind::SpaceReclaimed,
            LogKind::AccessRevoked,
            LogKind::ErasedByOrder,
            LogKind::IngestAccepted,
            LogKind::IngestFailed,
            LogKind::DeviceRegistered,
            LogKind::SignedIn,
            LogKind::SignedOut,
            LogKind::LoginRequired,
            LogKind::ConnectionLost,
            LogKind::ConnectionRestored,
            LogKind::SecurityWarning,
        ];
        for language in edms_i18n::Language::ALL {
            let catalogue = Catalog::of(language);
            for kind in ALL {
                let label = kind.label(catalogue);
                assert!(!label.is_empty(), "{language} {kind:?}");
                assert_ne!(label, kind.text_key().path(), "{language} {kind:?}: no sentence");
            }
        }
    }

    #[test]
    fn a_row_survives_the_round_trip() {
        let e =
            LogEntry::new(Timestamp::from_unix_millis(5), LogKind::Opened, Some(subject()), None)
                .unwrap();
        let back: LogEntry = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
    }
}
