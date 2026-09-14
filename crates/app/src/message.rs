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

use crate::display::{DisplayState, ExtensionState, LoginCode, SetupValues, SetupView, Status};
use crate::icon::IconState;
use crate::menu::{AccountAction, MenuState};

/// Maximum length of a request in **bytes**.
///
/// It has to cover the largest request a page holding to [`MAX_VALUE`] can build, and that is the
/// set-up's seven values. The two budgets are counted in different units, and they have to be
/// made to meet in one: [`MAX_VALUE`] is characters, this is bytes, and one character is up to
/// [`WORST_BYTES`] of them once JSON has escaped it. `the_page_knows_the_same_length_limit`
/// (window.rs) compares the two in bytes and holds this number honest.
///
/// It stood at 4 096 while the guard multiplied characters against a byte budget, and that only
/// ever held for ASCII: seven fields of 256 CJK characters are 5 376 bytes, and the message was
/// discarded with nothing but a line in the diagnostic log — the user clicked "Next" and nothing
/// at all happened, which is the one failure [`MAX_VALUE`] exists to prevent.
pub const MAX_LENGTH: usize = 12_288;

/// Maximum length of one value of the set-up wizard, in characters.
///
/// The page holds to it as well and says so per field (`setup.wrong.too_long`) — otherwise a
/// pasted-in value would make the whole request too long, and [`Request::read`] would discard it
/// with nothing but a line in the diagnostic log: the user would have clicked "Next" and nothing
/// at all would have happened. `the_page_knows_the_same_length_limit` holds the two numbers
/// together.
///
/// Characters and not bytes, deliberately: the page's own `maxLength` counts what the user typed,
/// and a name full of umlauts would otherwise be refused at a length the field itself accepted.
pub const MAX_VALUE: usize = 256;

/// How many bytes one character of a value can take up in the JSON that carries it.
///
/// Six, and the worst case is not a foreign alphabet but a control character: `serde_json` writes
/// one of those as a six-character escape, while it passes a three-byte character through as its
/// own bytes. A character outside the basic plane is four bytes, and two UTF-16 units in the
/// page's own count — so it costs the page twice and this budget less.
pub const WORST_BYTES: usize = 6;

/// How many values the set-up's message carries ([`SetupValues`]).
const SETUP_FIELDS: usize = 7;

/// Braces, the kind, the seven names, their quotes and the commas between them.
const SETUP_FRAME: usize = 512;

/// The two budgets, made to meet — **bytes against bytes**, and at compile time.
///
/// A page that holds to [`MAX_VALUE`] per field can then never build a message
/// [`Request::read`] refuses as too long. The guard that stood for this before lived in a test in
/// `window.rs` and read `MAX_VALUE * 7 < MAX_LENGTH / 2`: it multiplied characters and compared
/// them against a byte budget, so it held for ASCII and for nothing else.
const _: () = assert!(MAX_VALUE * WORST_BYTES * SETUP_FIELDS + SETUP_FRAME <= MAX_LENGTH);

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
    /// The "Set-up" button: show the wizard (ADR-D13 §11 — it stays reachable by hand at any
    /// time, and on a device where nothing is open it shows the facts).
    OpenSetup,
    /// The values of the wizard's input pages, on the way to the page after them.
    ///
    /// They travel **before** the sign-in and not at the end: the registration is the first thing
    /// `sign_in` does, and a device flow that stopped at a missing address would show a failure
    /// for a value nobody had been asked about yet (ADR-D13 §5).
    ApplySetup {
        /// What the user typed. Behind a `Box` for the same reason as [`StateView`].
        values: Box<SetupValues>,
    },
    /// The last page of the wizard was reached.
    CompleteSetup,
    /// "Check again" on the extension page — and the page's own poll, every two seconds.
    CheckExtension,
    /// The button to System Settings on the extension page (macOS).
    OpenExtensionSettings,
}

impl Request {
    /// Reads a request from the page.
    pub fn read(text: &str) -> Result<Self, MessageError> {
        if text.len() > MAX_LENGTH {
            return Err(MessageError::TooLong(text.len()));
        }
        let request: Self =
            serde_json::from_str(text).map_err(|e| MessageError::Unreadable(e.to_string()))?;
        if let Self::ApplySetup { values } = &request {
            // The page holds to [`MAX_VALUE`] and says so per field. A longer value is therefore
            // not this page speaking, and the app does not pass on what it never offered to take.
            if let Some(length) = values.longest_over(MAX_VALUE) {
                return Err(MessageError::ValueTooLong(length));
            }
        }
        Ok(request)
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
    /// Open the set-up wizard, or fill it afresh (ADR-D13).
    Setup {
        /// Every value with its origin. Behind a `Box`, like [`Self::State`].
        setup: Box<SetupView>,
    },
    /// The answer to a [`Request::CheckExtension`] — and nothing else.
    ///
    /// A message of its own rather than another [`Self::Setup`]: the poll runs every two seconds
    /// while the extension page is open, and a whole set-up arriving that often would overwrite
    /// what the user is typing on the page they walk back to.
    SetupExtension {
        /// What macOS last answered.
        state: ExtensionState,
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
    /// One value of the set-up is longer than the page says it takes.
    #[error(
        "a value of the set-up is {0} characters long; the app takes at most {MAX_VALUE} per value"
    )]
    ValueTooLong(usize),
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
    use crate::display::{Fixed, SetupField, SetupReason};

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
            Request::OpenSetup,
            Request::ApplySetup { values: Box::new(values()) },
            Request::ApplySetup { values: Box::default() },
            Request::CompleteSetup,
            Request::CheckExtension,
            Request::OpenExtensionSettings,
        ]
    }

    /// What an unmanaged workstation sends after its two input pages: everything it was offered,
    /// and `None` for the value its operator had already decided.
    fn values() -> SetupValues {
        SetupValues {
            api_base: Some("https://api.example".into()),
            auth_base: Some("https://anmeldung.example".into()),
            app_base: None,
            device_name: Some("Werkstatt 4".into()),
            mirror_path: None,
            language: Some("de".into()),
            enrollment_code: Some("7QK3-88MT".into()),
        }
    }

    fn view() -> SetupView {
        SetupView {
            reason: SetupReason::Counterpart,
            api_base: SetupField::open("https://api.example"),
            auth_base: SetupField::open("https://anmeldung.example"),
            app_base: SetupField::fixed("https://archiv.example", Fixed::Operator),
            one_address: false,
            suggested_base: None,
            development_base: None,
            device_name: SetupField::fixed("Werkstatt 4", Fixed::Enrolled),
            mirror_path: SetupField::fixed("C:\\Users\\erika\\elasticdms", Fixed::Mirror),
            language: SetupField::open("de"),
            enrollment_code: SetupField::open(""),
            data_path: "C:\\ProgramData\\elasticdms\\state.sqlite".into(),
            staging_path: "C:\\ProgramData\\elasticdms\\staging".into(),
            holding_path: "C:\\ProgramData\\elasticdms\\holding".into(),
            enrolled: true,
            extension: ExtensionState::Off,
        }
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
            (r#"{"kind":"openSetup"}"#, Request::OpenSetup),
            (r#"{"kind":"completeSetup"}"#, Request::CompleteSetup),
            (r#"{"kind":"checkExtension"}"#, Request::CheckExtension),
            (r#"{"kind":"openExtensionSettings"}"#, Request::OpenExtensionSettings),
            // Exactly as view.js builds it: every value it was offered, `null` for every value it
            // was not. A field the operator decided is not the page's to send.
            (
                r#"{"kind":"applySetup","values":{"apiBase":"https://api.example","authBase":null,
                    "appBase":null,"deviceName":null,"mirrorPath":null,"language":null,
                    "enrollmentCode":null}}"#,
                Request::ApplySetup {
                    values: Box::new(SetupValues {
                        api_base: Some("https://api.example".into()),
                        ..SetupValues::default()
                    }),
                },
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(Request::read(text).unwrap(), expected, "{text}");
        }
    }

    #[test]
    fn a_set_up_a_page_could_ever_send_fits_in_one_request() {
        // Seven values at the page's limit. If this were over `MAX_LENGTH`, a user who pasted
        // long addresses would click "Next" and nothing at all would happen — the message would
        // be discarded on this side, with a line in the log the user never sees.
        //
        // Three alphabets and not one: the limit is counted in characters and the message in
        // bytes, and `"x".repeat(…)` is the one case where the two are the same number. The CJK
        // line is the one that used to go over: seven fields of it are 5 376 bytes, against a
        // `MAX_LENGTH` that stood at 4 096. The control characters are the true worst case —
        // JSON writes each of them as six.
        for filler in ['x', 'ü', '文', '\u{1}'] {
            let long: String = std::iter::repeat_n(filler, MAX_VALUE).collect();
            assert_eq!(long.chars().count(), MAX_VALUE, "the page would let this through");
            let full = SetupValues {
                api_base: Some(long.clone()),
                auth_base: Some(long.clone()),
                app_base: Some(long.clone()),
                device_name: Some(long.clone()),
                mirror_path: Some(long.clone()),
                language: Some(long.clone()),
                enrollment_code: Some(long),
            };
            let text =
                serde_json::to_string(&Request::ApplySetup { values: Box::new(full) }).unwrap();
            assert!(text.len() <= MAX_LENGTH, "{filler:?}: {} bytes", text.len());
            assert!(Request::read(&text).is_ok(), "{filler:?}");
        }
    }

    #[test]
    fn a_value_longer_than_the_page_offers_to_take_is_refused() {
        // Not our page speaking: it holds to the same limit and says so per field. Counted in
        // characters, so that a name full of umlauts is not refused at a length the field itself
        // accepted.
        let long = "ü".repeat(MAX_VALUE + 1);
        let text = serde_json::to_string(&Request::ApplySetup {
            values: Box::new(SetupValues { device_name: Some(long), ..SetupValues::default() }),
        })
        .unwrap();
        assert!(text.len() < MAX_LENGTH, "this is about one value, not about the whole message");
        assert!(matches!(Request::read(&text), Err(MessageError::ValueTooLong(_))));
        // Exactly at the limit it goes through.
        let edge = serde_json::to_string(&Request::ApplySetup {
            values: Box::new(SetupValues {
                device_name: Some("ü".repeat(MAX_VALUE)),
                ..SetupValues::default()
            }),
        })
        .unwrap();
        assert!(Request::read(&edge).is_ok());
    }

    #[test]
    fn a_fixed_value_arrives_with_the_reason_it_is_fixed() {
        // The page needs no second table of its own: which sentence stands under a value follows
        // from `fixed`, and `NO` is the only value for which a field appears at all.
        let value = serde_json::to_value(Notice::Setup { setup: Box::new(view()) }).unwrap();
        let setup = &value["setup"];
        assert_eq!(setup["kind"], serde_json::Value::Null, "the notice's tag, not the view's");
        assert_eq!(value["kind"], "setup");
        assert_eq!(setup["reason"], "COUNTERPART");
        assert_eq!(setup["apiBase"]["fixed"], "NO");
        assert_eq!(setup["appBase"]["fixed"], "OPERATOR");
        assert_eq!(setup["deviceName"]["fixed"], "ENROLLED");
        assert_eq!(setup["mirrorPath"]["fixed"], "MIRROR");
        assert_eq!(setup["extension"], "OFF");
        // Never stored, and therefore never sent back either (ADR-D13 §6).
        assert_eq!(setup["enrollmentCode"]["value"], "");
    }

    #[test]
    fn the_extension_has_an_answer_of_its_own_and_it_is_never_an_error() {
        // A timeout is read as "not on yet" (ADR-D13 §9); there is no third face for it to
        // arrive in, because a sentence about `NSFileProviderErrorDomain` is one nobody can act
        // on.
        for state in [ExtensionState::On, ExtensionState::Off, ExtensionState::Asking] {
            let text = serde_json::to_string(&Notice::SetupExtension { state }).unwrap();
            assert_eq!(
                serde_json::from_str::<Notice>(&text).unwrap(),
                Notice::SetupExtension { state }
            );
        }
        let value =
            serde_json::to_value(Notice::SetupExtension { state: ExtensionState::On }).unwrap();
        assert_eq!(value["kind"], "setupExtension");
        assert_eq!(value["state"], "ON");
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
            Notice::Setup { setup: Box::new(view()) },
            Notice::SetupExtension { state: ExtensionState::Asking },
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
