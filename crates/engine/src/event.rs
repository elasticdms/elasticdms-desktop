//! What the engine calls up to the app — the broadcast channel.
//!
//! Two ways upwards, and they part at one question: **state or occurrence?**
//!
//! * The state ([`crate::EngineState`]) goes over `tokio::sync::watch`. Whoever listens late gets
//!   the **current** state — a window opened after ten minutes shows "Signed in as …" and not the
//!   prehistory.
//! * An occurrence goes over `tokio::sync::broadcast` and is **one-off**: "open this address in the
//!   browser" must not be repeated when a second listener joins.
//!
//! **The engine opens no browser and shows no message.** It says what is to be done; the app does
//! it. Otherwise the engine would have a platform API (`open`, notifications), and architecture
//! rule R7 ("user interface only in the app") would be a request instead of a rule.
//!
//! The catalogue is **complete**, for the parts not yet built as well (delivery channel, ingest
//! folder): whoever programs against it is to see all the cases today and not have to write a
//! `_ =>` later that quietly does the wrong thing.

use edms_core::delivery::Command;
use edms_i18n::{Catalog, Key, key};

/// How many events the channel buffers before a slow listener loses some.
///
/// A lost event is reported by `tokio` as `RecvError::Lagged`; the app then reads the state anew.
/// Hence the buffer may be small: it is not a store but a shock absorber.
pub const CHANNEL_DEPTH: usize = 64;

/// The kind of a delivery command that has been carried out — the closed catalogue from
/// [`edms_core::delivery::Command`] without its payload.
///
/// Without the payload, because the event lands in the user interface: "removed by order" never
/// names a subject (`edms_core::log`), and an event with the document list would carry the name out
/// after all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandKind {
    /// Release local copies.
    Dehydrate,
    /// Fetch a listing anew at once.
    Reconcile,
    /// The session has been ended on the server side.
    SignOut,
    /// Fetch the key set anew.
    RefreshKeys,
}

impl CommandKind {
    /// The kind of a command.
    pub const fn of(command: &Command) -> Self {
        match command {
            Command::Dehydrate { .. } => Self::Dehydrate,
            Command::Reconcile { .. } => Self::Reconcile,
            Command::SignOut => Self::SignOut,
            Command::RefreshKeys => Self::RefreshKeys,
        }
    }

    /// The catalogue key of the label.
    pub const fn text_key(self) -> Key {
        match self {
            Self::Dehydrate => key::COMMAND_DEHYDRATE,
            Self::Reconcile => key::COMMAND_RECONCILE,
            Self::SignOut => key::COMMAND_SIGN_OUT,
            Self::RefreshKeys => key::COMMAND_REFRESH_KEYS,
        }
    }

    /// The label in the user interface, in the catalogue's language.
    pub fn label(self, catalogue: &Catalog) -> &str {
        catalogue.text(self.text_key())
    }
}

/// A one-off occurrence out of the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// The app is to open this address in the system browser.
    ///
    /// The engine has checked it beforehand against [`crate::EngineConfiguration::app_base`]
    /// (`DeviceAuthorization::browser_target`): an address on a foreign host would be the template
    /// for a phishing page that decks itself out with a real code and anchor.
    OpenBrowser(String),

    /// A sentence for the user — "disappearing must not be silent" (requirement 6).
    ///
    /// Already in the user's language: the engine takes it from the text catalogue of
    /// `EngineConfiguration::language`. The app shows it word for word and does not translate it
    /// a second time.
    Hint {
        /// The whole sentence, ready to read.
        text: String,
    },

    /// The state has changed; whoever holds no `watch` receiver reads it now.
    StateChanged,

    /// The usage log has new rows — the view may reload.
    LogGrown,

    /// How many files the platform has announced in mail baskets that are not ingested yet.
    ///
    /// ADR-D08 point 6: offline the files stay lying, and the user is to see how many are
    /// waiting. `0` means "nothing open" and is the app's opportunity to hide a progress display
    /// again.
    InboxProgress {
        /// Number of open files.
        open: usize,
    },

    /// A delivery command has been carried out.
    ///
    /// For the second part of the engine (delivery channel, ADR-D04).
    CommandApplied {
        /// Which kind — never the documents concerned.
        kind: CommandKind,
    },
}

#[cfg(test)]
mod tests {
    use edms_core::delivery::Reason;
    use edms_core::identifier::Identifier;

    use super::*;

    #[test]
    fn every_command_of_the_catalogue_has_a_kind_and_a_label() {
        let all = [
            Command::Dehydrate {
                documents: vec![Identifier::from_value(1)],
                reason: Reason::Erasure,
            },
            Command::Reconcile { container: None },
            Command::SignOut,
            Command::RefreshKeys,
        ];
        let kinds: Vec<CommandKind> = all.iter().map(CommandKind::of).collect();
        assert_eq!(
            kinds,
            [
                CommandKind::Dehydrate,
                CommandKind::Reconcile,
                CommandKind::SignOut,
                CommandKind::RefreshKeys
            ]
        );
        for language in edms_i18n::Language::ALL {
            let catalogue = Catalog::of(language);
            for kind in &kinds {
                let label = kind.label(catalogue);
                assert!(!label.is_empty(), "{language} {kind:?}");
                assert_ne!(label, kind.text_key().path(), "{language} {kind:?}: no sentence");
            }
        }
    }

    #[test]
    fn a_command_that_was_carried_out_takes_no_document_into_the_user_interface() {
        // An erasure leaves no name behind (edms_core::log). The event therefore carries only the
        // kind — there is no parameter through which a document could come in.
        let event = EngineEvent::CommandApplied { kind: CommandKind::Dehydrate };
        let output = format!("{event:?}");
        assert!(!output.contains("doc_"), "{output}");
    }
}
