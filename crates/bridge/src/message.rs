//! The messages of the line, as JSON in `J` frames.
//!
//! Every message carries its kind in the field `kind` (SCREAMING_SNAKE_CASE like the core's wire
//! values), so that a recording stays readable without the source code. The payloads are the core's
//! types, unchanged: a [`SourceError`] arrives as the same variant the engine delivered — otherwise
//! the user would see a reason in the Finder other than the real one.

use serde::{Deserialize, Serialize};

use edms_core::change::ChangeState;
use edms_core::namespace::{Container, Entry, EntryIdentifier};
use edms_core::port::{ContentReceipt, ContentRequest, SourceError};

/// The first message of every connection, from the extension.
///
/// An enum with a single variant, not a struct with `tag`: the struct with `tag` and
/// `deny_unknown_fields` accepted not a single handshake (the round-trip test below holds that
/// fast). In the enum form serde checks the kind and rejects foreign fields.
///
/// Deliberately without `Debug`: the secret must not be able to land in any log line.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub(crate) enum Handshake {
    /// Credential and version of the extension.
    Hello {
        /// The extension's [`crate::VERSION`].
        version: u32,
        /// The secret from the rendezvous file.
        secret: String,
    },
}

/// A question of the extension — one per method of the [`NamespaceSource`].
///
/// [`NamespaceSource`]: edms_core::port::NamespaceSource
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Request {
    /// `children(container)`.
    Children {
        /// Which container.
        container: Container,
    },
    /// `entry(identifier)`.
    Entry {
        /// Which entry.
        identifier: EntryIdentifier,
    },
    /// `current_sequence()`.
    CurrentSequence,
    /// `changes_since(sequence, max)`.
    ChangesSince {
        /// From which sequence number on.
        sequence: u64,
        /// At most this many; u64 on the wire, so that the width does not depend on the machine.
        max: u64,
    },
    /// `content(identifier, request, sink)`.
    Content {
        /// Which file.
        identifier: EntryIdentifier,
        /// Who wants it.
        request: ContentRequest,
    },
}

/// A message of the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Notice {
    /// The handshake succeeded.
    Welcome {
        /// The app's [`crate::VERSION`].
        version: u32,
    },
    /// Answer to [`Request::Children`].
    Children {
        /// The engine's result.
        result: Result<Vec<Entry>, SourceError>,
    },
    /// Answer to [`Request::Entry`].
    Entry {
        /// The engine's result.
        result: Result<Entry, SourceError>,
    },
    /// Answer to [`Request::CurrentSequence`].
    CurrentSequence {
        /// The engine's result.
        result: Result<u64, SourceError>,
    },
    /// Answer to [`Request::ChangesSince`].
    ChangesSince {
        /// The engine's result.
        result: Result<ChangeState, SourceError>,
    },
    /// Load progress during [`Request::Content`].
    Progress {
        /// Loaded.
        loaded: u64,
        /// In total.
        total: u64,
    },
    /// The content has been handed over completely.
    End {
        /// What the engine confirms.
        receipt: ContentReceipt,
    },
    /// The request failed before or while content was flowing — or the answer did not fit over
    /// the line.
    Error {
        /// The reason.
        error: SourceError,
    },
}

impl Notice {
    /// The kind as it stands on the wire — for error messages.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Welcome { .. } => "WELCOME",
            Self::Children { .. } => "CHILDREN",
            Self::Entry { .. } => "ENTRY",
            Self::CurrentSequence { .. } => "CURRENT_SEQUENCE",
            Self::ChangesSince { .. } => "CHANGES_SINCE",
            Self::Progress { .. } => "PROGRESS",
            Self::End { .. } => "END",
            Self::Error { .. } => "ERROR",
        }
    }
}

impl Request {
    /// The kind as it stands on the wire — for error messages.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Children { .. } => "CHILDREN",
            Self::Entry { .. } => "ENTRY",
            Self::CurrentSequence => "CURRENT_SEQUENCE",
            Self::ChangesSince { .. } => "CHANGES_SINCE",
            Self::Content { .. } => "CONTENT",
        }
    }
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;
    use edms_core::namespace::Location;
    use serde_json::json;

    use super::*;

    #[test]
    fn the_wire_form_of_the_requests_is_settled() {
        let request = Request::Children { container: Container::Root };
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"kind": "CHILDREN", "container": "root"})
        );
        let request = Request::ChangesSince { sequence: 7, max: 100 };
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"kind": "CHANGES_SINCE", "sequence": 7, "max": 100})
        );
        assert_eq!(
            serde_json::to_value(Request::CurrentSequence).unwrap(),
            json!({"kind": "CURRENT_SEQUENCE"})
        );
    }

    #[test]
    fn a_source_error_keeps_its_variant_in_the_result() {
        let identifier = EntryIdentifier::Document {
            location: Location::Case {
                archive: Identifier::from_value(1),
                case: Identifier::from_value(2),
            },
            document: Identifier::from_value(3),
        };
        let notice = Notice::Entry { result: Err(SourceError::NotFound(identifier)) };
        let text = serde_json::to_string(&notice).unwrap();
        assert!(text.contains(r#""Err":{"reason":"NOT_FOUND""#), "{text}");
        assert_eq!(serde_json::from_str::<Notice>(&text).unwrap(), notice);
    }

    #[test]
    fn hello_survives_the_round_trip_and_accepts_nothing_else() {
        let hello = Handshake::Hello { version: 1, secret: "s".into() };
        let value = serde_json::to_value(&hello).unwrap();
        assert_eq!(value, json!({"kind": "HELLO", "version": 1, "secret": "s"}));
        // The round trip the first version (struct with `tag`) failed at.
        let Handshake::Hello { version, secret } = serde_json::from_value(value).unwrap();
        assert_eq!((version, secret.as_str()), (1, "s"));
        // A request in place of the hello is no hello, not even with matching fields.
        let other = json!({"kind": "CHILDREN", "version": 1, "secret": "s"});
        assert!(serde_json::from_value::<Handshake>(other).is_err());
        let more = json!({"kind": "HELLO", "version": 1, "secret": "s", "container": "root"});
        assert!(serde_json::from_value::<Handshake>(more).is_err());
        let without_kind = json!({"version": 1, "secret": "s"});
        assert!(serde_json::from_value::<Handshake>(without_kind).is_err());
    }
}
