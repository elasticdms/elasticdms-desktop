//! The messages between web view and app — a small, typed protocol.
//!
//! * **Page → app:** `window.ipc.postMessage(JSON)`; read here as a [`Request`].
//! * **App → page:** `evaluate_script("window.receive(<JSON>)")`; written here as a [`Notice`].
//!
//! Both directions are closed catalogues with a tag field `kind`. A request that does not stand
//! here the app does not carry out, and one field too many is an error, not an addition: the page
//! is embedded and cannot send anything this code does not know — if something else does arrive,
//! something is wrong, and that should stand in the diagnostic log instead of passing silently.
//!
//! Wire names: kinds and fields in camelCase (JavaScript), enum values of the core in
//! SCREAMING_SNAKE_CASE, the way `edms_core` serialises them (`OPENED`, `WARNING`).

use edms_core::log::{LogEntry, LogKind, Severity};
use edms_i18n::Catalog;
use serde::{Deserialize, Serialize};

use crate::display::{DisplayState, LoginCode, Status};
use crate::icon::IconState;
use crate::menu::{AccountAction, MenuState};

/// Maximum length of a request in bytes. The largest real one is under 200.
pub const MAX_LENGTH: usize = 4_096;

/// What the page wants from the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Request {
    /// The page has loaded and can receive messages.
    Ready {
        /// `navigator.language` — for the diagnostic log only.
        language: Option<String>,
        /// The time zone the page computes in — for the diagnostic log only.
        time_zone: Option<String>,
    },
    /// "Load older": rows with an identifier smaller than `before_id`.
    LoadOlder {
        /// The identifier of the oldest row shown.
        before_id: i64,
    },
    /// The "sign in" button.
    SignIn,
    /// The "open folder" button.
    OpenFolder,
    /// The "mailbaskets" button.
    OpenBaskets,
    /// The "open the sign-in page" button in the sign-in panel.
    OpenLoginPage,
}

impl Request {
    /// Reads a request from the page.
    pub fn read(text: &str) -> Result<Self, MessageError> {
        if text.len() > MAX_LENGTH {
            return Err(MessageError::TooLong(text.len()));
        }
        serde_json::from_str(text).map_err(|e| MessageError::Unreadable(e.to_string()))
    }
}

/// What the app tells the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Notice {
    /// The header: account, status, buttons, sign-in in progress.
    State {
        /// The state. Behind a `Box`, because it is ten times the size of any other message and
        /// `Notice` would otherwise drag that size along for every row of the list.
        state: Box<StateView>,
    },
    /// Rows of the usage log, newest first.
    Rows {
        /// The rows.
        rows: Vec<Row>,
        /// Whether they replace the list or are appended at the bottom.
        mode: Mode,
        /// Whether there are older rows (show the "load older" button).
        more: bool,
    },
    /// An action failed; the text is a whole sentence for the user.
    Error {
        /// The sentence.
        text: String,
    },
}

/// How delivered rows enter the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// Fill the list afresh (first load, every wake). Replace instead of append, so that a name
    /// redacted in the meantime disappears from rows already shown too.
    Replace,
    /// Append at the bottom (after "load older").
    Append,
}

/// The window header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    /// Display name of the account.
    pub account: Option<String>,
    /// The session state.
    pub status: Status,
    /// The same status line as in the menu — it names the account as well.
    pub status_line: String,
    /// The same state without the account name. The window header shows the name as a heading and
    /// does not need it a second time in the line below (`menu::status_short`).
    pub short_status: String,
    /// The colour of the status dot — the same state as on the icon.
    pub tone: IconState,
    /// Path of the root, when it is set up (for the tooltip on the button).
    pub folder: Option<String>,
    /// Path of the mail basket folder in the mirror, when the mirror stands.
    pub baskets: Option<String>,
    /// The sign-in in progress — the window then shows the code large.
    pub login: Option<LoginCode>,
    /// Whether the "sign in" button appears.
    pub sign_in_possible: bool,
    /// The sentence from [`DisplayState::hint`] — the window shows it in the message panel.
    ///
    /// It stands in `status_line` **as well**; but in the window that one is replaced by
    /// `short_status` when an account is signed in (the name already stands as a heading above
    /// it). Without this field a signed-in user would see the hint only in the menu.
    pub hint: Option<String>,
}

impl StateView {
    /// From the source's state and the menu state computed from it.
    pub fn from(state: &DisplayState, menu: &MenuState, catalogue: &Catalog) -> Self {
        Self {
            account: state.account.clone(),
            status: state.status,
            status_line: menu.status_line.clone(),
            short_status: crate::menu::status_short(state, catalogue),
            tone: menu.icon,
            folder: state.folder.as_ref().map(|p| p.display().to_string()),
            baskets: state.baskets.as_ref().map(|p| p.display().to_string()),
            login: state.login_code.clone(),
            sign_in_possible: menu.account_action == AccountAction::SignIn,
            hint: state.hint.clone(),
        }
    }
}

/// A row as the page needs it: label and severity already resolved, so that the texts stand in
/// one place only (`edms_core::log`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    /// Identifier in the source; the cursor for "load older".
    pub id: i64,
    /// Milliseconds since 1970 (UTC). The page computes the local time (`time.rs`: no time zone
    /// rule in the core).
    pub time: i64,
    /// The kind — it picks the row's glyph.
    pub kind: LogKind,
    /// The label in the user's language: "Opened", "Erased by order" …
    pub label: String,
    /// How conspicuous.
    pub severity: Severity,
    /// File name, if the row has a subject.
    pub name: Option<String>,
    /// Display name of the location.
    pub location: Option<String>,
    /// Document identifier in wire form (`doc_…`), for questions to support.
    pub document: Option<String>,
    /// An explanation.
    pub detail: Option<String>,
    /// Whether the name has been erased (the page sets it in italics and explains it).
    pub redacted: bool,
}

impl Row {
    /// From a row of the core, in the catalogue's language.
    ///
    /// The redaction marker never leaves this function: what goes to the page is the sentence
    /// about the erasure, and `redacted` says that it is one. The page never sees
    /// `edms_core::log::REDACTED`, and the store never sees the sentence.
    pub fn from_entry(id: i64, entry: &LogEntry, catalogue: &Catalog) -> Self {
        let g = entry.subject();
        let kind = entry.kind();
        Self {
            id,
            time: entry.time().unix_millis(),
            kind,
            label: kind.label(catalogue).to_owned(),
            severity: kind.severity(),
            name: g.map(|g| g.display_name(catalogue).to_owned()),
            location: g.and_then(|g| g.location.clone()),
            document: g.and_then(|g| g.document).map(|d| d.to_string()),
            detail: entry.detail().map(str::to_owned),
            redacted: g.is_some_and(edms_core::log::Subject::is_redacted),
        }
    }
}

impl Notice {
    /// The script that delivers the message into the page.
    pub fn as_script(&self) -> Result<String, MessageError> {
        let json =
            serde_json::to_string(self).map_err(|e| MessageError::Unwritable(e.to_string()))?;
        // U+2028 and U+2029 are permitted in JSON, but in JavaScript source before ES2019 they are
        // line terminators: a document title containing one of them would break the script off in
        // the middle of the string, and the whole message would be lost.
        let json = json.replace('\u{2028}', "\\u2028").replace('\u{2029}', "\\u2029");
        Ok(format!("window.receive({json});"))
    }
}

/// A message does not fit the protocol.
///
/// Diagnostic only: these sentences never reach a user. The page is embedded and knows this
/// catalogue; whatever else arrives is a bug in this program, and a bug belongs in the log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// Longer than [`MAX_LENGTH`].
    #[error(
        "the message from the user interface is {0} bytes long; the app takes at most {MAX_LENGTH}"
    )]
    TooLong(usize),
    /// Not JSON, an unknown kind, a missing or a surplus field.
    #[error("the message from the user interface is unreadable: {0}")]
    Unreadable(String),
    /// Serialising failed (should never happen; if it does, it is a bug).
    #[error("the message to the user interface could not be written: {0}")]
    Unwritable(String),
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;
    use edms_core::log::{REDACTED, Subject};
    use edms_core::time::Timestamp;
    use edms_i18n::Language;

    use super::*;

    /// The German catalogue — the assertions below read like the window the user sees.
    fn german() -> &'static Catalog {
        Catalog::of(Language::De)
    }

    fn all_requests() -> Vec<Request> {
        vec![
            Request::Ready {
                language: Some("de-DE".into()),
                time_zone: Some("Europe/Berlin".into()),
            },
            Request::Ready { language: None, time_zone: None },
            Request::LoadOlder { before_id: 17 },
            Request::SignIn,
            Request::OpenFolder,
            Request::OpenBaskets,
            Request::OpenLoginPage,
        ]
    }

    fn subject() -> Subject {
        Subject {
            name: "Prüfbericht Pumpe 7.pdf".into(),
            document: Some(Identifier::from_value(7)),
            location: Some("Archive › Kunden › Sulzer Pumpen".into()),
        }
    }

    #[test]
    fn the_requests_of_the_script_are_read_word_for_word() {
        // This is exactly how view.js sends them.
        let cases = [
            (
                r#"{"kind":"ready","language":"de-DE","timeZone":"Europe/Berlin"}"#,
                Request::Ready {
                    language: Some("de-DE".into()),
                    time_zone: Some("Europe/Berlin".into()),
                },
            ),
            (
                r#"{"kind":"ready","language":null,"timeZone":null}"#,
                Request::Ready { language: None, time_zone: None },
            ),
            (r#"{"kind":"loadOlder","beforeId":17}"#, Request::LoadOlder { before_id: 17 }),
            (r#"{"kind":"signIn"}"#, Request::SignIn),
            (r#"{"kind":"openFolder"}"#, Request::OpenFolder),
            (r#"{"kind":"openBaskets"}"#, Request::OpenBaskets),
            (r#"{"kind":"openLoginPage"}"#, Request::OpenLoginPage),
        ];
        for (text, expected) in cases {
            assert_eq!(Request::read(text).unwrap(), expected, "{text}");
        }
    }

    #[test]
    fn every_request_survives_the_round_trip() {
        for a in all_requests() {
            let text = serde_json::to_string(&a).unwrap();
            assert_eq!(Request::read(&text).unwrap(), a, "{text}");
        }
    }

    #[test]
    fn a_foreign_or_overloaded_request_is_refused() {
        let wrong = [
            r#"{"kind":"delete"}"#,
            r#"{"kind":"loadOlder","beforeId":"17"}"#,
            r#"{"kind":"loadOlder","beforeId":17,"count":10000}"#,
            r#"{"kind":"loadOlder"}"#,
            r#"{"beforeId":1}"#,
            "not JSON",
            "",
        ];
        for text in wrong {
            assert!(
                matches!(Request::read(text), Err(MessageError::Unreadable(_))),
                "\"{text}\" should have been refused"
            );
        }
        let long = format!(r#"{{"kind":"ready","language":"{}"}}"#, "x".repeat(MAX_LENGTH));
        assert!(matches!(Request::read(&long), Err(MessageError::TooLong(_))));
    }

    #[test]
    fn every_notice_survives_the_round_trip() {
        let entry = LogEntry::new(
            Timestamp::from_unix_millis(1_788_334_692_118),
            LogKind::Opened,
            Some(subject()),
            Some("Geladen und geprüft".into()),
        )
        .unwrap();
        let notices = [
            Notice::State {
                state: Box::new(StateView {
                    account: Some("Erika Mustermann".into()),
                    status: Status::NotSignedIn,
                    status_line: "Anmeldung läuft – Code WQPX-7TRM".into(),
                    short_status: "Anmeldung läuft – Code WQPX-7TRM".into(),
                    tone: IconState::Notice,
                    folder: None,
                    baskets: Some("/tmp/elasticdms/Briefkörbe".into()),
                    login: Some(LoginCode {
                        user_code: "WQPX-7TRM".into(),
                        address: "https://anmeldung.example/geraet".into(),
                        address_complete: None,
                        anchor: Some("K7-M4".into()),
                    }),
                    sign_in_possible: false,
                    hint: Some("Das Gerät wartet auf die Freigabe durch die IT.".into()),
                }),
            },
            Notice::Rows {
                rows: vec![Row::from_entry(3, &entry, german())],
                mode: Mode::Append,
                more: true,
            },
            Notice::Error { text: "Der Ordner ist auf diesem Gerät nicht eingerichtet.".into() },
        ];
        for m in notices {
            let text = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<Notice>(&text).unwrap(), m, "{text}");
        }
    }

    #[test]
    fn the_wire_form_of_a_row_is_the_script_s() {
        let entry = LogEntry::new(
            Timestamp::from_unix_millis(5),
            LogKind::OpenFailed,
            Some(subject()),
            None,
        )
        .unwrap();
        let m = Notice::Rows {
            rows: vec![Row::from_entry(9, &entry, german())],
            mode: Mode::Replace,
            more: false,
        };
        let value = serde_json::to_value(&m).unwrap();
        assert_eq!(value["kind"], "rows");
        assert_eq!(value["mode"], "replace");
        let z = &value["rows"][0];
        assert_eq!(z["kind"], "OPEN_FAILED");
        assert_eq!(z["severity"], "WARNING");
        assert_eq!(z["label"], "Öffnen fehlgeschlagen");
        assert_eq!(z["time"], 5);
        assert_eq!(z["document"], "doc_00000000000000000000000007");
    }

    #[test]
    fn the_script_calls_receive_and_escapes_line_separators() {
        let m = Notice::Error { text: "before\u{2028}after\u{2029}".into() };
        let script = m.as_script().unwrap();
        assert!(script.starts_with("window.receive({") && script.ends_with("});"), "{script}");
        assert!(!script.contains('\u{2028}') && !script.contains('\u{2029}'));
        assert!(script.contains("\\u2028") && script.contains("\\u2029"));
    }

    #[test]
    fn a_redacted_row_is_marked_as_such_and_carries_neither_location_nor_document() {
        let e =
            LogEntry::new(Timestamp::NULL, LogKind::Opened, Some(subject()), Some("3 MB".into()))
                .unwrap()
                .redacted();
        let z = Row::from_entry(1, &e, german());
        assert!(z.redacted);
        // The sentence, not the marker: the page never sees what stands in the database.
        assert_eq!(z.name.as_deref(), Some("Dokument auf Anordnung entfernt"));
        assert_ne!(z.name.as_deref(), Some(REDACTED));
        assert!(z.location.is_none() && z.document.is_none() && z.detail.is_none());
        let not_redacted =
            LogEntry::new(Timestamp::NULL, LogKind::Opened, Some(subject()), None).unwrap();
        assert!(!Row::from_entry(2, &not_redacted, german()).redacted);
    }

    #[test]
    fn an_erasure_row_arrives_without_a_name_but_with_a_label() {
        let z = Row::from_entry(4, &LogEntry::erased_by_order(Timestamp::NULL), german());
        assert!(z.name.is_none() && z.location.is_none() && z.document.is_none());
        assert_eq!(z.label, "Auf Anordnung entfernt");
        assert_eq!(z.severity, Severity::Notice);
    }
}
