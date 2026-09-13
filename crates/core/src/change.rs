//! Changes to the namespace — the expensive part of the requirements, as a pure function.
//!
//! „Akten und gespeicherte Suchen sind dynamische Ordner. Ihr Inhalt aendert sich ohne Zutun im
//! Ordner. Der Client muss dem Explorer laufend Aenderungen der Namensstruktur melden, nicht
//! einmalig einen Baum aufbauen." (`ordnerclient-vorgaben.md`) — case files and saved searches
//! are dynamic folders; their content changes without anyone touching the folder, so the client
//! has to report namespace changes to Explorer continuously instead of building a tree once.
//!
//! The engine fetches a listing anew, puts it next to the remembered one and reports only the
//! difference to the platform. That difference is computed here, without network and without a
//! file system — which is why it is testable, and why Windows and macOS compute the same thing.
//!
//! **Order of the output:** removed first, then changed, then new. A new document can carry the
//! name of one just removed; if the platform applies “new” before “removed”, it runs into a file
//! that is about to disappear. A rename cycle (A is now called what B was and B what A was) is
//! not resolved by this order; the platform has to do that via an intermediate name, and
//! `edms-cfapi` does.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::namespace::{Entry, EntryIdentifier};

/// A change to one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
#[expect(
    clippy::large_enum_variant,
    reason = "changes are short-lived and live in a Vec; a Box per rename would cost an allocation for no gain"
)]
pub enum Change {
    /// The entry is new.
    New {
        /// The new entry.
        entry: Entry,
    },
    /// Name or details have changed; the identifier is the same.
    Changed {
        /// How it was.
        before: Entry,
        /// How it is.
        after: Entry,
    },
    /// The entry is gone.
    Removed {
        /// How it last was.
        entry: Entry,
    },
}

impl Change {
    /// The identifier of the affected entry.
    pub fn identifier(&self) -> EntryIdentifier {
        match self {
            Self::New { entry } | Self::Removed { entry } => entry.identifier,
            Self::Changed { after, .. } => after.identifier,
        }
    }

    /// The entry after the change; `None` for removed.
    pub fn after(&self) -> Option<&Entry> {
        match self {
            Self::New { entry } => Some(entry),
            Self::Changed { after, .. } => Some(after),
            Self::Removed { .. } => None,
        }
    }

    /// Whether locally loaded content is stale because of this change.
    ///
    /// Yes, as soon as version, checksum or size differ. A mere rename leaves the content valid —
    /// a file reloaded after every title correction would be an access nobody triggered, and it
    /// would stand in the log.
    pub fn content_stale(&self) -> bool {
        match self {
            Self::Changed { before, after } => match (before.file(), after.file()) {
                (Some(a), Some(b)) => {
                    a.version != b.version || a.sha256 != b.sha256 || a.size != b.size
                }
                (None, None) => false,
                // Folder became file or the other way round: the server can mean neither.
                _ => true,
            },
            Self::New { .. } | Self::Removed { .. } => false,
        }
    }

    /// Whether the name has changed.
    pub fn renamed(&self) -> bool {
        matches!(self, Self::Changed { before, after } if before.name != after.name)
    }
}

/// Compares the remembered listing of a container with the fresh one.
pub fn compare(old: &[Entry], new: &[Entry]) -> Vec<Change> {
    let old: BTreeMap<EntryIdentifier, &Entry> = old.iter().map(|e| (e.identifier, e)).collect();
    let new: BTreeMap<EntryIdentifier, &Entry> = new.iter().map(|e| (e.identifier, e)).collect();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut added = Vec::new();
    for (identifier, before) in &old {
        match new.get(identifier) {
            None => removed.push(Change::Removed { entry: (*before).clone() }),
            Some(after) if after != before => {
                changed.push(Change::Changed { before: (*before).clone(), after: (*after).clone() })
            }
            Some(_) => {}
        }
    }
    for (identifier, entry) in &new {
        if !old.contains_key(identifier) {
            added.push(Change::New { entry: (*entry).clone() });
        }
    }
    removed.into_iter().chain(changed).chain(added).collect()
}

/// One change with its sequence number in the engine's change journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Strictly increasing, without gaps, per session.
    pub sequence: u64,
    /// The change.
    pub change: Change,
}

/// What has happened since a sequence number — the answer to “what has changed?”.
///
/// On macOS this is the answer to the working set's `enumerateChanges(from: anchor)`: the only
/// way a server-side change reaches the Finder (`signalEnumerator` accepts only the working set
/// for replicated providers, NSFileProviderManager.h).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeState {
    /// The changes, in sequence order.
    pub changes: Vec<JournalEntry>,
    /// The sequence number to ask from next time.
    pub until_sequence: u64,
    /// Whether more is pending (page limit reached).
    pub more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Identifier;
    use crate::namespace::{EntryContent, FileDetails, Location};
    use crate::time::Timestamp;

    fn file(value: u128, name: &str, version: &str) -> Entry {
        Entry {
            identifier: EntryIdentifier::Document {
                location: Location::Case {
                    archive: Identifier::from_value(1),
                    case: Identifier::from_value(2),
                },
                document: Identifier::from_value(value),
            },
            name: name.to_owned(),
            content: EntryContent::File(FileDetails {
                size: 10,
                sha256: None,
                version: version.to_owned(),
                created: Timestamp::NULL,
                changed: Timestamp::NULL,
                media_type: "application/pdf".to_owned(),
            }),
        }
    }

    #[test]
    fn equal_listings_produce_no_change() {
        let l = [file(1, "a.pdf", "1"), file(2, "b.pdf", "1")];
        assert!(compare(&l, &l).is_empty());
    }

    #[test]
    fn removed_comes_before_changed_and_changed_before_new() {
        let old = [file(1, "a.pdf", "1"), file(2, "b.pdf", "1")];
        let new = [file(2, "b2.pdf", "1"), file(3, "a.pdf", "1")];
        let kinds: Vec<&str> = compare(&old, &new)
            .iter()
            .map(|a| match a {
                Change::Removed { .. } => "removed",
                Change::Changed { .. } => "changed",
                Change::New { .. } => "new",
            })
            .collect();
        assert_eq!(kinds, ["removed", "changed", "new"]);
    }

    #[test]
    fn a_rename_does_not_make_the_content_stale() {
        let a = compare(&[file(1, "a.pdf", "1")], &[file(1, "b.pdf", "1")]);
        assert_eq!(a.len(), 1);
        assert!(a[0].renamed());
        assert!(!a[0].content_stale());
    }

    #[test]
    fn a_new_version_makes_the_content_stale() {
        let a = compare(&[file(1, "a.pdf", "1")], &[file(1, "a.pdf", "2")]);
        assert!(a[0].content_stale());
        assert!(!a[0].renamed());
    }
}
