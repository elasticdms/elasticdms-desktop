//! Namespace, change journal and tombstones.
//!
//! "Akten und gespeicherte Suchen sind dynamische Ordner. … Der Client muss dem Explorer laufend
//! Aenderungen der Namensstruktur melden" (`ordnerclient-vorgaben.md`) — case files (Akten) and
//! saved searches are dynamic folders, and the client has to report changes of the name structure
//! to the Explorer continuously. The difference itself comes into being in the core
//! (`edms_core::change::compare`); here it is written together with the new listing in **one**
//! transaction and put into the journal. Otherwise there would be, after a crash, a listing
//! without a journal entry — and the Finder would never learn of the change — or a journal entry
//! without a listing, and it would report a file that does not exist.
//!
//! ## The journal
//!
//! The sequence number rises strictly and without gaps. The journal holds exactly the entries with
//! a sequence number in `(lower_limit, last]`; older ones are trimmed as soon as there are more
//! than [`JOURNAL_MAX`](crate::JOURNAL_MAX) of them. An anchor `f` can be answered as long as
//! `lower_limit <= f <= last` — put differently, `f >= oldest_sequence() - 1`. Older:
//! [`StoreError::AnchorExpired`], and the platform enumerates afresh instead of guessing gaps.
//!
//! **The counting never starts over.** [`Store::empty_namespace`] deletes entries and journal, but
//! keeps counting and consumes a number doing so: an anchor of the old session lies below the lower
//! bound afterwards and is expired. If the counting started anew, anchor 57 of the old session
//! would at some point stand for a state of the new one — and the Finder would take names of the
//! old user for current ones (requirement 4).
//!
//! ## Erasure
//!
//! [`Store::remove_document_everywhere`] removes every place of a document, sets a tombstone and
//! redacts the journal: every earlier entry belonging to the document becomes a `Removed` without a
//! name. That way the numbering stays without gaps, and whoever catches up from an old anchor lands
//! at the right state — the document is gone — without ever seeing the name.

use std::collections::{HashMap, HashSet};

use edms_core::change::{Change, ChangeState, JournalEntry, compare};
use edms_core::checksum::Sha256Value;
use edms_core::filename::comparison_form;
use edms_core::identifier::DocumentIdentifier;
use edms_core::log::REDACTED;
use edms_core::namespace::{
    Container, Entry, EntryContent, EntryIdentifier, FileDetails, Truncation,
};
use edms_core::time::Timestamp;
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use crate::column::{bool_from, decode, encode, from_u64, from_usize, read_identifier, to_u64};
use crate::error::StoreError;
use crate::{ERASURE_TAKES_EFFECT_MILLIS, Store};

/// Name of the kind "folder" in `entry.kind` — the core's serde tag (`EntryContent`).
pub(crate) const KIND_FOLDER: &str = "FOLDER";
/// Name of the kind "file" in `entry.kind`.
pub(crate) const KIND_FILE: &str = "FILE";

/// Media type in the redacted journal entry; it betrays nothing about the document.
const MEDIA_TYPE_REDACTED: &str = "application/octet-stream";

const T_ENTRY: &str = "entry";
const T_STATE: &str = "container_state";
const T_JOURNAL: &str = "journal";
const T_JOURNAL_STATE: &str = "journal_state";
const T_ERASED: &str = "erased";

const CHILDREN: &str = "SELECT identifier, name, kind, size, sha256, version, created, changed, \
                      media_type, rank FROM entry WHERE parent = ?1 ORDER BY rank, identifier";
const A: &str = "SELECT identifier, name, kind, size, sha256, version, created, changed, \
                     media_type, rank FROM entry WHERE identifier = ?1";
const PLACED: &str = "SELECT identifier, name, kind, size, sha256, version, created, changed, \
                         media_type, rank FROM entry WHERE document = ?1 ORDER BY identifier";

/// What the engine knows about the last fetch of a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    /// `ETag` of the last listing, for `If-None-Match` on the next fetch. An ETag per folder is
    /// something the server still has to deliver (contract extract §4.4, server requirement).
    pub etag: Option<String>,
    /// When the listing was fetched. At the same time the clock against which a tombstone is
    /// measured: a listing from before an erasure must not undo it.
    pub fetched: Timestamp,
    /// Whether and how the listing is truncated; `None` means complete.
    pub truncation: Option<TruncationState>,
}

/// A truncated hit list (contract extract Q-12: never cut off quietly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncationState {
    /// How many hits the folder shows.
    pub display_upper_limit: u64,
    /// Where the search can be refined in the browser.
    pub refine_url: Option<String>,
}

impl TruncationState {
    /// The form `edms_core::namespace::document_entries` expects for the hint.
    pub fn as_truncation(&self) -> Truncation<'_> {
        Truncation { displayed: self.display_upper_limit, address: self.refine_url.as_deref() }
    }
}

/// How a journal entry is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalForm {
    /// Just as it is returned.
    Complete,
    /// As a `Removed` without a name — for everything that concerns an erased document.
    Redacted,
}

impl Store {
    /// Replaces the child listing of a container and returns the difference as journal entries —
    /// all in **one** transaction.
    ///
    /// The steps, in this order:
    ///
    /// 1. **Check**, before anything is written: every entry belongs in `container`; a container is
    ///    a folder, a document or hint a file; a document carries a checksum (otherwise the engine
    ///    could not keep the promise in `edms_core::port`); no identifier stands twice; no two
    ///    names are equal in the form in which both file systems compare
    ///    (`edms_core::filename::comparison_form`).
    /// 2. **The container has to be known**: the root always, every other one only if it stands in
    ///    the stored listing of its parent container. Otherwise entries without a parent folder
    ///    would come into being — a case file (Akte) whose content arrives later than the news that
    ///    it no longer exists would come back as an orphan. The engine therefore reconciles from
    ///    top to bottom: root, then the baskets, archives and searches folders, then the single
    ///    archives, and only after them the case files that hang in them and the searches.
    /// 3. **Tombstones** filter erased documents out before the comparison, measured against
    ///    `state.fetched` ([`ERASURE_TAKES_EFFECT_MILLIS`](crate::ERASURE_TAKES_EFFECT_MILLIS)).
    /// 4. **Compare** with the stored listing (`edms_core::change::compare`).
    /// 5. **If a container disappears** from the listing (a case file is gone), its descendants go
    ///    with it, and each one gets its own `Removed` — before the container's, so that the
    ///    platform never has to touch a child of an already removed folder.
    /// 6. **Write**: entries, order, state, journal, trimming of the journal.
    ///
    /// The return value is exactly what went into the journal, with sequence numbers; the engine
    /// passes it on to `FileSystem::report_change`. An unchanged listing yields an empty return
    /// value and consumes no sequence number; order and state are renewed all the same.
    pub fn replace_container(
        &mut self,
        container: Container,
        new: &[Entry],
        state: &ContainerState,
    ) -> Result<Vec<JournalEntry>, StoreError> {
        check_list(container, new)?;
        let limit = self.limit.journal;
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !container_known(&tx, container)? {
            return Err(StoreError::ContainerUnknown(container));
        }
        let erased = effective_erasure(&tx, state.fetched)?;
        let fresh: Vec<Entry> = new
            .iter()
            .filter(|entry| entry.identifier.document().is_none_or(|d| !erased.contains(&d)))
            .cloned()
            .collect();
        let read = read_children(&tx, container)?;
        let old_ranks: HashMap<EntryIdentifier, i64> =
            read.iter().map(|(entry, rank)| (entry.identifier, *rank)).collect();
        let old: Vec<Entry> = read.into_iter().map(|(entry, _)| entry).collect();

        let mut changes = Vec::new();
        for change in compare(&old, &fresh) {
            if let Change::Removed { entry } = &change {
                if let Some(gone) = entry.identifier.container() {
                    changes.extend(remove_descendant(&tx, gone)?);
                }
                delete_entry(&tx, entry.identifier)?;
            }
            changes.push(change);
        }

        let to_write: HashSet<EntryIdentifier> =
            changes.iter().filter_map(|a| a.after().map(|e| e.identifier)).collect();
        for (place, entry) in fresh.iter().enumerate() {
            let rank = from_usize(place, "rank")?;
            if to_write.contains(&entry.identifier) {
                write_entry(&tx, container, rank, entry)?;
            } else if old_ranks.get(&entry.identifier) != Some(&rank) {
                set_rank(&tx, entry.identifier, rank)?;
            }
        }
        write_state(&tx, container, state)?;
        let entries = journal(&tx, changes, state.fetched, limit, JournalForm::Complete)?;
        tx.commit()?;
        Ok(entries)
    }

    /// Renews only the state of a container — for `304 Not Modified`: the listing is the same, but
    /// it has now been confirmed.
    pub fn update_container_state(
        &mut self,
        container: Container,
        state: &ContainerState,
    ) -> Result<(), StoreError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !container_known(&tx, container)? {
            return Err(StoreError::ContainerUnknown(container));
        }
        write_state(&tx, container, state)?;
        tx.commit()?;
        Ok(())
    }

    /// The state of the last fetch; `None` when the container was never fetched.
    pub fn container_state(
        &self,
        container: Container,
    ) -> Result<Option<ContainerState>, StoreError> {
        let raw = self
            .connection
            .prepare_cached(
                "SELECT etag, fetched, truncated, display_limit, refine_url \
                 FROM container_state WHERE container = ?1",
            )?
            .query_row(params![container.to_string()], RawState::read)
            .optional()?;
        raw.map(RawState::state).transpose()
    }

    /// The stored children of a container, in the order of the listing last stored.
    ///
    /// A container that stands in no listing of its parent container is an error
    /// ([`StoreError::ContainerUnknown`]) and not an empty listing: a case file (Akte) that has
    /// disappeared is something different from an empty one. Whether a known container has already
    /// been fetched is said by [`Self::container_state`].
    pub fn children(&self, container: Container) -> Result<Vec<Entry>, StoreError> {
        let tx = self.connection.unchecked_transaction()?;
        if !container_known(&tx, container)? {
            return Err(StoreError::ContainerUnknown(container));
        }
        let children = read_children(&tx, container)?;
        tx.commit()?;
        Ok(children.into_iter().map(|(entry, _)| entry).collect())
    }

    /// A single entry; `None` when it does not exist.
    ///
    /// The root itself never stands in the table — it has no parent container and no details that
    /// change; how it is presented is the platform's business.
    pub fn entry(&self, identifier: EntryIdentifier) -> Result<Option<Entry>, StoreError> {
        let raw = self
            .connection
            .prepare_cached(A)?
            .query_row(params![identifier.to_string()], RawEntry::read)
            .optional()?;
        raw.map(|raw| raw.entry().map(|(entry, _)| entry)).transpose()
    }

    /// Every place at which a document stands — in a case file (Akte) and in every saved search.
    ///
    /// Whoever has to dehydrate a document dehydrates every one of these places
    /// (`edms_core::namespace`).
    pub fn placements(
        &self,
        document: DocumentIdentifier,
    ) -> Result<Vec<EntryIdentifier>, StoreError> {
        let texts: Vec<String> = {
            let mut query = self.connection.prepare_cached(
                "SELECT identifier FROM entry WHERE document = ?1 ORDER BY identifier",
            )?;
            query
                .query_map(params![document.to_string()], |row| row.get(0))?
                .collect::<Result<_, _>>()?
        };
        texts.iter().map(|text| read_identifier(text, T_ENTRY, "identifier")).collect()
    }

    /// Erases a document from the namespace — the DSGVO (GDPR) erasure (ADR-D04, reason
    /// `ERASURE`).
    ///
    /// In **one** transaction: every place of the document is removed and journalled as `Removed`,
    /// a tombstone is set, and every earlier journal entry belonging to the document is redacted.
    /// Called twice it is harmless: the second time there is nothing to remove.
    ///
    /// **Return value and journal differ on purpose.** The return value carries the last complete
    /// entry, because the platform on Windows finds a placeholder over its name in the parent
    /// folder, and a placeholder that is not found would stay on the disk, name and all. In the
    /// journal the same sequence number stands redacted; macOS needs only the identifier for a
    /// `Removed`.
    ///
    /// The local usage log is redacted by [`Self::redact`], a step of its own in the actions
    /// (`edms_core::delivery::Actions::redact_log`).
    pub fn remove_document_everywhere(
        &mut self,
        document: DocumentIdentifier,
        now: Timestamp,
    ) -> Result<Vec<JournalEntry>, StoreError> {
        let limit = self.limit.journal;
        let text = document.to_string();
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let locations = read_placed(&tx, &text)?;
        tx.prepare_cached("DELETE FROM entry WHERE document = ?1")?.execute(params![text])?;
        tx.prepare_cached(
            "INSERT INTO erased (document, time) VALUES (?1, ?2) \
             ON CONFLICT (document) DO UPDATE SET time = max(time, excluded.time)",
        )?
        .execute(params![text, now.unix_millis()])?;
        redact_journal(&tx, &text)?;
        let changes = locations.into_iter().map(|entry| Change::Removed { entry }).collect();
        let entries = journal(&tx, changes, now, limit, JournalForm::Redacted)?;
        tx.commit()?;
        self.condense_after_erasure();
        Ok(entries)
    }

    /// Empties the namespace on sign-out: entries, container states and journal.
    ///
    /// The counting runs on and consumes a number; the return value is the new current sequence
    /// number. Every anchor from the time before is expired afterwards (module head). The usage log
    /// stays — it belongs to the account and shows itself only to it (ADR-D07) —, and so do the
    /// tombstones: they carry no name and protect the next session too.
    pub fn empty_namespace(&mut self) -> Result<u64, StoreError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("DELETE FROM entry; DELETE FROM container_state; DELETE FROM journal;")?;
        let state = read_journal_state(&tx)?;
        let new = next(state.last)?;
        write_journal_state(&tx, JournalState { last: new, lower_limit: new })?;
        tx.commit()?;
        self.condense_after_erasure();
        Ok(new)
    }

    /// The highest sequence number handed out (macOS `currentSyncAnchor`); 0 while nothing has
    /// happened.
    pub fn current_sequence(&self) -> Result<u64, StoreError> {
        Ok(read_journal_state(&self.connection)?.last)
    }

    /// The smallest sequence number the journal can still deliver; with an empty journal the next
    /// one to be handed out. An anchor `f` is valid as long as `f >= oldest_sequence() - 1`.
    pub fn oldest_sequence(&self) -> Result<u64, StoreError> {
        Ok(read_journal_state(&self.connection)?.oldest_sequence())
    }

    /// The changes after `sequence`, at most `max` of them (macOS `enumerateChanges`).
    ///
    /// `until_sequence` is the anchor for the next call, `more` says whether more is already
    /// there. Errors instead of guessing:
    ///
    /// * `sequence` before the lower bound: [`StoreError::AnchorExpired`];
    /// * `sequence` beyond the current sequence number: [`StoreError::AnchorUnknown`] — the anchor
    ///   comes from a different database;
    /// * `max == 0`: [`StoreError::EmptyPage`] — with `more = true` and an empty page the caller
    ///   would never reach the end;
    /// * a gap in the journal: [`StoreError::Corrupt`], never a quiet end of page.
    pub fn changes_since(&self, sequence: u64, max: usize) -> Result<ChangeState, StoreError> {
        if max == 0 {
            return Err(StoreError::EmptyPage);
        }
        let tx = self.connection.unchecked_transaction()?;
        let state = read_journal_state(&tx)?;
        if sequence < state.lower_limit {
            return Err(StoreError::AnchorExpired {
                anchor: sequence,
                oldest_sequence: state.oldest_sequence(),
            });
        }
        if sequence > state.last {
            return Err(StoreError::AnchorUnknown {
                anchor: sequence,
                current_sequence: state.last,
            });
        }
        // There are never more than i64::MAX rows; capping the page limit changes no result.
        let page = i64::try_from(max).unwrap_or(i64::MAX);
        let rows: Vec<(i64, String)> = {
            let mut query = tx.prepare_cached(
                "SELECT sequence, change FROM journal WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            )?;
            query
                .query_map(params![from_u64(sequence, "sequence")?, page], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<Result<_, _>>()?
        };
        tx.commit()?;

        let mut changes = Vec::with_capacity(rows.len());
        let mut expected = sequence;
        for (read, text) in rows {
            // sequence <= last <= i64::MAX: the + 1 never overflows.
            expected += 1;
            let read = to_u64(read, T_JOURNAL, "sequence")?;
            if read != expected {
                return Err(StoreError::corrupt(
                    T_JOURNAL,
                    format!("gap in the journal: sequence {expected} expected, {read} read"),
                ));
            }
            changes.push(JournalEntry { sequence: read, change: decode(&text, T_JOURNAL)? });
        }
        let until_sequence = changes.last().map_or(sequence, |entry| entry.sequence);
        let more = until_sequence < state.last;
        if more && changes.len() < max {
            return Err(StoreError::corrupt(
                T_JOURNAL,
                format!(
                    "entries after sequence {until_sequence} are missing, although up to {} \
                     was handed out",
                    state.last
                ),
            ));
        }
        Ok(ChangeState { changes, until_sequence, more })
    }

    /// Whether a tombstone is in effect for the document at the point in time `now`.
    ///
    /// For the engine, which wants to take a document out before the naming — otherwise a sibling
    /// might carry a short form that it only got because of the erased name.
    pub fn is_erased(
        &self,
        document: DocumentIdentifier,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        let takes_effect: bool = self
            .connection
            .prepare_cached(
                "SELECT EXISTS (SELECT 1 FROM erased WHERE document = ?1 AND time > ?2)",
            )?
            .query_row(params![document.to_string(), erasure_limit(now)], |row| row.get(0))?;
        Ok(takes_effect)
    }

    /// Removes tombstones that are no longer in effect at the point in time `now`; returns their
    /// number.
    pub fn clear_erasure(&mut self, now: Timestamp) -> Result<usize, StoreError> {
        Ok(self
            .connection
            .prepare_cached("DELETE FROM erased WHERE time <= ?1")?
            .execute(params![erasure_limit(now)])?)
    }
}

// ── Checking ──────────────────────────────────────────────────────────────────────────────────

fn check_list(container: Container, new: &[Entry]) -> Result<(), StoreError> {
    let mut identifiers = HashSet::with_capacity(new.len());
    let mut names = HashSet::with_capacity(new.len());
    for entry in new {
        let identifier = entry.identifier;
        if identifier.parent() != Some(container) {
            return Err(StoreError::ForeignEntry { container, identifier: Box::new(identifier) });
        }
        if identifier.container().is_some() != entry.is_folder() {
            return Err(StoreError::WrongKind(identifier));
        }
        if identifier.document().is_some() && entry.file().is_some_and(|d| d.sha256.is_none()) {
            return Err(StoreError::WithoutChecksum(identifier));
        }
        if !identifiers.insert(identifier) {
            return Err(StoreError::DuplicateIdentifier(identifier));
        }
        if !names.insert(comparison_form(&entry.name)) {
            return Err(StoreError::DuplicateName { container, name: entry.name.clone() });
        }
    }
    Ok(())
}

fn container_known(connection: &Connection, container: Container) -> Result<bool, StoreError> {
    if container == Container::Root {
        return Ok(true);
    }
    let known: bool = connection
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM entry WHERE identifier = ?1)")?
        .query_row(params![EntryIdentifier::Container(container).to_string()], |row| row.get(0))?;
    Ok(known)
}

// ── Tombstones ────────────────────────────────────────────────────────────────────────────────

/// A tombstone is in effect as long as `time > now - 30 days`.
fn erasure_limit(now: Timestamp) -> i64 {
    now.plus_millis(-ERASURE_TAKES_EFFECT_MILLIS).unix_millis()
}

fn effective_erasure(
    connection: &Connection,
    now: Timestamp,
) -> Result<HashSet<DocumentIdentifier>, StoreError> {
    let texts: Vec<String> = {
        let mut query = connection.prepare_cached("SELECT document FROM erased WHERE time > ?1")?;
        query.query_map(params![erasure_limit(now)], |row| row.get(0))?.collect::<Result<_, _>>()?
    };
    texts.iter().map(|text| read_identifier(text, T_ERASED, "document")).collect()
}

// ── Entries ───────────────────────────────────────────────────────────────────────────────────

fn read_children(
    connection: &Connection,
    container: Container,
) -> Result<Vec<(Entry, i64)>, StoreError> {
    let raw: Vec<RawEntry> = {
        let mut query = connection.prepare_cached(CHILDREN)?;
        query
            .query_map(params![container.to_string()], RawEntry::read)?
            .collect::<Result<_, _>>()?
    };
    raw.into_iter().map(RawEntry::entry).collect()
}

fn read_placed(connection: &Connection, document: &str) -> Result<Vec<Entry>, StoreError> {
    let raw: Vec<RawEntry> = {
        let mut query = connection.prepare_cached(PLACED)?;
        query.query_map(params![document], RawEntry::read)?.collect::<Result<_, _>>()?
    };
    raw.into_iter().map(|raw| raw.entry().map(|(entry, _)| entry)).collect()
}

/// Removes all descendants of a container, deepest first, together with their states; returns
/// their `Removed` in that order. The depth is bounded by the fixed tree
/// (root → archives folder → archive → case file → document).
fn remove_descendant(
    connection: &Connection,
    container: Container,
) -> Result<Vec<Change>, StoreError> {
    let mut from = Vec::new();
    for (kind, _) in read_children(connection, container)? {
        if let Some(below) = kind.identifier.container() {
            from.extend(remove_descendant(connection, below)?);
        }
        delete_entry(connection, kind.identifier)?;
        from.push(Change::Removed { entry: kind });
    }
    connection
        .prepare_cached("DELETE FROM container_state WHERE container = ?1")?
        .execute(params![container.to_string()])?;
    Ok(from)
}

fn write_entry(
    connection: &Connection,
    container: Container,
    rank: i64,
    entry: &Entry,
) -> Result<(), StoreError> {
    let (kind, d) = column(&entry.content)?;
    connection
        .prepare_cached(
            "INSERT INTO entry (identifier, parent, rank, name, kind, size, sha256, version, \
             created, changed, media_type, document) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
             ON CONFLICT (identifier) DO UPDATE SET parent = excluded.parent, rank = excluded.rank, \
             name = excluded.name, kind = excluded.kind, size = excluded.size, \
             sha256 = excluded.sha256, version = excluded.version, created = excluded.created, \
             changed = excluded.changed, media_type = excluded.media_type, \
             document = excluded.document",
        )?
        .execute(params![
            entry.identifier.to_string(),
            container.to_string(),
            rank,
            entry.name,
            kind,
            d.size,
            d.sha256,
            d.version,
            d.created,
            d.changed,
            d.media_type,
            entry.identifier.document().map(|k| k.to_string()),
        ])?;
    Ok(())
}

fn set_rank(
    connection: &Connection,
    identifier: EntryIdentifier,
    rank: i64,
) -> Result<(), StoreError> {
    connection
        .prepare_cached("UPDATE entry SET rank = ?1 WHERE identifier = ?2")?
        .execute(params![rank, identifier.to_string()])?;
    Ok(())
}

fn delete_entry(connection: &Connection, identifier: EntryIdentifier) -> Result<(), StoreError> {
    connection
        .prepare_cached("DELETE FROM entry WHERE identifier = ?1")?
        .execute(params![identifier.to_string()])?;
    Ok(())
}

/// The file columns of an entry; a folder has none.
#[derive(Default)]
struct FileColumn<'a> {
    size: Option<i64>,
    sha256: Option<String>,
    version: Option<&'a str>,
    created: Option<i64>,
    changed: Option<i64>,
    media_type: Option<&'a str>,
}

fn column(content: &EntryContent) -> Result<(&'static str, FileColumn<'_>), StoreError> {
    match content {
        EntryContent::Folder => Ok((KIND_FOLDER, FileColumn::default())),
        EntryContent::File(d) => Ok((
            KIND_FILE,
            FileColumn {
                size: Some(from_u64(d.size, "size")?),
                sha256: d.sha256.map(|sum| sum.hex()),
                version: Some(&d.version),
                created: Some(d.created.unix_millis()),
                changed: Some(d.changed.unix_millis()),
                media_type: Some(&d.media_type),
            },
        )),
    }
}

/// One row from `entry`, not yet checked.
struct RawEntry {
    identifier: String,
    name: String,
    kind: String,
    size: Option<i64>,
    sha256: Option<String>,
    version: Option<String>,
    created: Option<i64>,
    changed: Option<i64>,
    media_type: Option<String>,
    rank: i64,
}

impl RawEntry {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            identifier: row.get(0)?,
            name: row.get(1)?,
            kind: row.get(2)?,
            size: row.get(3)?,
            sha256: row.get(4)?,
            version: row.get(5)?,
            created: row.get(6)?,
            changed: row.get(7)?,
            media_type: row.get(8)?,
            rank: row.get(9)?,
        })
    }

    fn entry(self) -> Result<(Entry, i64), StoreError> {
        let Self {
            identifier: text,
            name,
            kind,
            size,
            sha256,
            version,
            created,
            changed,
            media_type,
            rank,
        } = self;
        let identifier: EntryIdentifier = read_identifier(&text, T_ENTRY, "identifier")?;
        let missing = |field: &str| {
            StoreError::corrupt(T_ENTRY, format!("file “{text}” without column {field}"))
        };
        let content = match kind.as_str() {
            KIND_FOLDER => EntryContent::Folder,
            KIND_FILE => EntryContent::File(FileDetails {
                size: to_u64(size.ok_or_else(|| missing("size"))?, T_ENTRY, "size")?,
                sha256: sha256
                    .map(|hex| {
                        Sha256Value::from_hex(&hex)
                            .map_err(|error| StoreError::corrupt(T_ENTRY, error.to_string()))
                    })
                    .transpose()?,
                version: version.ok_or_else(|| missing("version"))?,
                created: Timestamp::from_unix_millis(created.ok_or_else(|| missing("created"))?),
                changed: Timestamp::from_unix_millis(changed.ok_or_else(|| missing("changed"))?),
                media_type: media_type.ok_or_else(|| missing("media_type"))?,
            }),
            other => {
                return Err(StoreError::corrupt(T_ENTRY, format!("unknown kind “{other}”")));
            }
        };
        Ok((Entry { identifier, name, content }, rank))
    }
}

// ── Container state ───────────────────────────────────────────────────────────────────────────

fn write_state(
    connection: &Connection,
    container: Container,
    state: &ContainerState,
) -> Result<(), StoreError> {
    let (truncated, upper_limit, address) = match &state.truncation {
        Some(truncation) => (
            true,
            Some(from_u64(truncation.display_upper_limit, "display_limit")?),
            truncation.refine_url.as_deref(),
        ),
        None => (false, None, None),
    };
    connection
        .prepare_cached(
            "INSERT INTO container_state (container, etag, fetched, truncated, display_limit, \
             refine_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (container) DO UPDATE SET etag = excluded.etag, \
             fetched = excluded.fetched, truncated = excluded.truncated, \
             display_limit = excluded.display_limit, refine_url = excluded.refine_url",
        )?
        .execute(params![
            container.to_string(),
            state.etag,
            state.fetched.unix_millis(),
            truncated,
            upper_limit,
            address
        ])?;
    Ok(())
}

/// One row from `container_state`, not yet checked.
struct RawState {
    etag: Option<String>,
    fetched: i64,
    truncated: i64,
    upper_limit: Option<i64>,
    address: Option<String>,
}

impl RawState {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            etag: row.get(0)?,
            fetched: row.get(1)?,
            truncated: row.get(2)?,
            upper_limit: row.get(3)?,
            address: row.get(4)?,
        })
    }

    fn state(self) -> Result<ContainerState, StoreError> {
        let truncation = if bool_from(self.truncated, T_STATE, "truncated")? {
            let upper_limit = self
                .upper_limit
                .ok_or_else(|| StoreError::corrupt(T_STATE, "truncated without display_limit"))?;
            Some(TruncationState {
                display_upper_limit: to_u64(upper_limit, T_STATE, "display_limit")?,
                refine_url: self.address,
            })
        } else {
            None
        };
        Ok(ContainerState {
            etag: self.etag,
            fetched: Timestamp::from_unix_millis(self.fetched),
            truncation,
        })
    }
}

// ── Journal ───────────────────────────────────────────────────────────────────────────────────

/// The only row from `journal_state`.
#[derive(Debug, Clone, Copy)]
struct JournalState {
    last: u64,
    lower_limit: u64,
}

impl JournalState {
    /// `lower_limit` fits into a SQLite number; the + 1 never overflows.
    const fn oldest_sequence(self) -> u64 {
        self.lower_limit + 1
    }
}

fn next(sequence: u64) -> Result<u64, StoreError> {
    sequence.checked_add(1).ok_or(StoreError::NumberTooLarge { field: "sequence", value: sequence })
}

fn read_journal_state(connection: &Connection) -> Result<JournalState, StoreError> {
    let raw: Option<(i64, i64)> = connection
        .prepare_cached("SELECT last_sequence, lower_bound FROM journal_state WHERE only_one = 1")?
        .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let (last, lower_limit) =
        raw.ok_or_else(|| StoreError::corrupt(T_JOURNAL_STATE, "the only row is missing"))?;
    Ok(JournalState {
        last: to_u64(last, T_JOURNAL_STATE, "last_sequence")?,
        lower_limit: to_u64(lower_limit, T_JOURNAL_STATE, "lower_bound")?,
    })
}

fn write_journal_state(connection: &Connection, state: JournalState) -> Result<(), StoreError> {
    connection
        .prepare_cached(
            "UPDATE journal_state SET last_sequence = ?1, lower_bound = ?2 WHERE only_one = 1",
        )?
        .execute(params![
            from_u64(state.last, "sequence")?,
            from_u64(state.lower_limit, "sequence")?
        ])?;
    Ok(())
}

/// Puts changes into the journal with consecutive sequence numbers and trims it.
fn journal(
    connection: &Connection,
    changes: Vec<Change>,
    time: Timestamp,
    limit: u64,
    form: JournalForm,
) -> Result<Vec<JournalEntry>, StoreError> {
    if changes.is_empty() {
        return Ok(Vec::new());
    }
    let mut state = read_journal_state(connection)?;
    let mut from = Vec::with_capacity(changes.len());
    {
        let mut insert = connection.prepare_cached(
            "INSERT INTO journal (sequence, change, time, document) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for change in changes {
            state.last = next(state.last)?;
            let stored = match form {
                JournalForm::Complete => encode(&change, "journal entry")?,
                JournalForm::Redacted => {
                    encode(&redacted_removal(change.identifier()), "journal entry")?
                }
            };
            let document = change.identifier().document().map(|d| d.to_string());
            insert.execute(params![
                from_u64(state.last, "sequence")?,
                stored,
                time.unix_millis(),
                document
            ])?;
            from.push(JournalEntry { sequence: state.last, change });
        }
    }
    state.lower_limit = truncate_journal(connection, state, limit)?;
    write_journal_state(connection, state)?;
    Ok(from)
}

/// Trims to the newest `limit` entries and returns the new lower bound.
fn truncate_journal(
    connection: &Connection,
    state: JournalState,
    limit: u64,
) -> Result<u64, StoreError> {
    // The journal holds exactly (lower_limit, last]; so there are last - lower_limit entries.
    if state.last.saturating_sub(state.lower_limit) <= limit {
        return Ok(state.lower_limit);
    }
    let new_lower_bound = state.last - limit;
    connection
        .prepare_cached("DELETE FROM journal WHERE sequence <= ?1")?
        .execute(params![from_u64(new_lower_bound, "sequence")?])?;
    Ok(new_lower_bound)
}

/// Rewrites every journal entry belonging to a document as a `Removed` without a name.
fn redact_journal(connection: &Connection, document: &str) -> Result<(), StoreError> {
    let rows: Vec<(i64, String)> = {
        let mut query = connection
            .prepare_cached("SELECT sequence, change FROM journal WHERE document = ?1")?;
        query
            .query_map(params![document], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    let mut update =
        connection.prepare_cached("UPDATE journal SET change = ?1 WHERE sequence = ?2")?;
    for (sequence, text) in rows {
        let change: Change = decode(&text, T_JOURNAL)?;
        let redacted = encode(&redacted_removal(change.identifier()), "journal entry")?;
        update.execute(params![redacted, sequence])?;
    }
    Ok(())
}

/// A `Removed` that betrays only the identifier: name, size, checksum and times are gone. Whoever
/// catches up on it removes an entry that he knows, or passes over one that he never knew — both
/// end at the right state.
fn redacted_removal(identifier: EntryIdentifier) -> Change {
    Change::Removed {
        entry: Entry {
            identifier,
            name: REDACTED.to_owned(),
            content: EntryContent::File(FileDetails {
                size: 0,
                sha256: None,
                version: String::new(),
                created: Timestamp::NULL,
                changed: Timestamp::NULL,
                media_type: MEDIA_TYPE_REDACTED.to_owned(),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use edms_core::log::{LogEntry, LogKind, Subject};
    use edms_core::namespace::{
        HintKind, Location, name_archives, name_baskets, name_read_me, root_entries,
    };
    use edms_core::port::SourceError;

    use super::*;
    use crate::account::Account;
    use crate::test_support::{
        ARCHIVE_TITLE, LANGUAGE, archive, basket, baskets_list, case, case_container, cases_list,
        changes, contains, doc, in_case, in_search, item, scaffold, search, sequences, state,
        store, time,
    };

    fn search_container(value: u128) -> Container {
        Container::Search(search(value))
    }

    /// The location of the case file `value` in the fixtures' archive.
    fn in_the_archive(value: u128) -> Location {
        Location::Case { archive: archive(), case: case(value) }
    }

    /// Reads database and log as bytes, as far as they exist.
    fn file_content(path: &std::path::Path) -> Vec<u8> {
        let mut bytes = std::fs::read(path).unwrap();
        if let Ok(log) = std::fs::read(path.with_extension("sqlite-wal")) {
            bytes.extend(log);
        }
        bytes
    }

    #[test]
    fn an_empty_store_has_sequence_zero_and_an_empty_root() {
        let s = store();
        assert_eq!(s.current_sequence().unwrap(), 0);
        assert_eq!(s.oldest_sequence().unwrap(), 1);
        assert!(s.children(Container::Root).unwrap().is_empty());
        let empty = s.changes_since(0, 10).unwrap();
        assert!(empty.changes.is_empty());
        assert_eq!((empty.until_sequence, empty.more), (0, false));
    }

    #[test]
    fn replacing_a_container_journals_exactly_the_difference() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer")], &[]);
        let before = in_case(1, &[item(1, "Rechnung", "1"), item(2, "Lieferschein", "1")]);
        s.replace_container(case_container(1), &before, &state(10)).unwrap();
        let anchor = s.current_sequence().unwrap();

        let after = in_case(1, &[item(2, "Lieferschein neu", "1"), item(3, "Mahnung", "1")]);
        let j = s.replace_container(case_container(1), &after, &state(20)).unwrap();

        assert_eq!(changes(&j), compare(&before, &after));
        assert_eq!(sequences(&j), [anchor + 1, anchor + 2, anchor + 3]);
        let caught_up = s.changes_since(anchor, 100).unwrap();
        assert_eq!(caught_up.changes, j);
        assert_eq!(s.children(case_container(1)).unwrap(), after);
    }

    #[test]
    fn an_unchanged_listing_makes_no_journal_entry_and_consumes_no_sequence() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer")], &[]);
        let list = in_case(1, &[item(1, "Rechnung", "1")]);
        s.replace_container(case_container(1), &list, &state(10)).unwrap();
        let sequence = s.current_sequence().unwrap();

        let with_etag = ContainerState { etag: Some("\"7\"".into()), ..state(11) };
        assert!(s.replace_container(case_container(1), &list, &with_etag).unwrap().is_empty());
        assert_eq!(s.current_sequence().unwrap(), sequence);
        assert_eq!(s.container_state(case_container(1)).unwrap(), Some(with_etag));
    }

    #[test]
    fn the_children_come_back_in_the_stored_order_even_after_reordering() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer")], &[]);
        let list = in_case(1, &[item(1, "A", "1"), item(2, "B", "1"), item(3, "C", "1")]);
        s.replace_container(case_container(1), &list, &state(10)).unwrap();
        assert_eq!(s.children(case_container(1)).unwrap(), list);

        let reversed: Vec<Entry> = list.iter().rev().cloned().collect();
        assert!(s.replace_container(case_container(1), &reversed, &state(11)).unwrap().is_empty());
        assert_eq!(s.children(case_container(1)).unwrap(), reversed);
        assert_eq!(s.container_state(case_container(1)).unwrap().unwrap().fetched, time(11));
    }

    #[test]
    fn a_case_file_outside_the_listing_of_its_archive_is_unknown_and_nothing_is_written() {
        let mut s = store();
        let list = in_case(1, &[item(1, "A", "1")]);
        assert!(matches!(
            s.replace_container(case_container(1), &list, &state(1)),
            Err(StoreError::ContainerUnknown(b)) if b == case_container(1)
        ));
        assert!(matches!(s.children(case_container(1)), Err(StoreError::ContainerUnknown(_))));
        assert!(matches!(
            s.children(Container::Archive(archive())),
            Err(StoreError::ContainerUnknown(_))
        ));
        assert!(matches!(s.children(Container::Archives), Err(StoreError::ContainerUnknown(_))));
        assert_eq!(s.current_sequence().unwrap(), 0);
        assert!(s.placements(doc(1)).unwrap().is_empty());
        assert!(s.container_state(case_container(1)).unwrap().is_none());
    }

    #[test]
    fn a_listing_with_foreign_duplicate_or_wrongly_kinded_entries_is_rejected_whole() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer"), (2, "KSB")], &[]);

        let foreign = in_case(2, &[item(1, "A", "1")]);
        assert!(matches!(
            s.replace_container(case_container(1), &foreign, &state(2)),
            Err(StoreError::ForeignEntry { .. })
        ));

        let mut duplicate = in_case(1, &[item(1, "A", "1")]);
        duplicate.push(duplicate[0].clone());
        assert!(matches!(
            s.replace_container(case_container(1), &duplicate, &state(2)),
            Err(StoreError::DuplicateIdentifier(_))
        ));

        // "A.pdf" and "A.PDF" are the same name for NTFS and APFS.
        let mut same_name = in_case(1, &[item(1, "A", "1"), item(2, "B", "1")]);
        same_name[1].name = same_name[0].name.to_uppercase();
        assert!(matches!(
            s.replace_container(case_container(1), &same_name, &state(2)),
            Err(StoreError::DuplicateName { .. })
        ));

        let mut as_folder = in_case(1, &[item(1, "A", "1")]);
        as_folder[0].content = EntryContent::Folder;
        assert!(matches!(
            s.replace_container(case_container(1), &as_folder, &state(2)),
            Err(StoreError::WrongKind(_))
        ));

        let mut without_sum = in_case(1, &[item(1, "A", "1")]);
        if let EntryContent::File(d) = &mut without_sum[0].content {
            d.sha256 = None;
        }
        assert!(matches!(
            s.replace_container(case_container(1), &without_sum, &state(2)),
            Err(StoreError::WithoutChecksum(_))
        ));

        assert!(s.children(case_container(1)).unwrap().is_empty());
        assert!(s.container_state(case_container(1)).unwrap().is_none());
    }

    #[test]
    fn a_case_file_that_disappears_takes_its_documents_into_the_journal_with_it() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer"), (2, "KSB")], &[]);
        let documents = in_case(1, &[item(1, "A", "1"), item(2, "B", "1")]);
        s.replace_container(case_container(1), &documents, &state(10)).unwrap();

        let j = s
            .replace_container(
                Container::Archive(archive()),
                &cases_list(&[(2, "KSB")]),
                &state(20),
            )
            .unwrap();

        let removed: Vec<EntryIdentifier> = j
            .iter()
            .map(|e| match &e.change {
                Change::Removed { entry } => entry.identifier,
                other => panic!("expected only Removed, was {other:?}"),
            })
            .collect();
        assert_eq!(
            removed,
            [
                documents[0].identifier,
                documents[1].identifier,
                EntryIdentifier::Container(case_container(1))
            ]
        );
        assert!(matches!(s.children(case_container(1)), Err(StoreError::ContainerUnknown(_))));
        assert!(s.container_state(case_container(1)).unwrap().is_none());
        assert!(s.placements(doc(1)).unwrap().is_empty());
        assert_eq!(s.changes_since(j[0].sequence - 1, 10).unwrap().changes, j);
    }

    #[test]
    fn the_journal_rises_strictly_and_without_gaps_across_every_kind_of_write() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer")], &[(2, "Offen")]);
        s.replace_container(
            case_container(1),
            &in_case(1, &[item(1, "A", "1"), item(2, "B", "1")]),
            &state(2),
        )
        .unwrap();
        s.replace_container(search_container(2), &in_search(2, &[item(1, "A", "1")]), &state(3))
            .unwrap();
        s.remove_document_everywhere(doc(1), time(4)).unwrap();
        s.replace_container(case_container(1), &in_case(1, &[item(2, "B2", "2")]), &state(5))
            .unwrap();

        let everything = s.changes_since(0, usize::MAX).unwrap();
        let last = s.current_sequence().unwrap();
        assert_eq!(sequences(&everything.changes), (1..=last).collect::<Vec<_>>());
        assert_eq!((everything.until_sequence, everything.more), (last, false));
    }

    #[test]
    fn changes_since_pages_through_to_the_end() {
        let mut s = store();
        // Root: four New (baskets, archives, searches, README); the archive container: one.
        scaffold(&mut s, &[], &[]);
        assert_eq!(s.current_sequence().unwrap(), 5);

        let first = s.changes_since(0, 4).unwrap();
        assert_eq!(
            (sequences(&first.changes), first.until_sequence, first.more),
            (vec![1, 2, 3, 4], 4, true)
        );
        let second = s.changes_since(first.until_sequence, 4).unwrap();
        assert_eq!(
            (sequences(&second.changes), second.until_sequence, second.more),
            (vec![5], 5, false)
        );
        let third = s.changes_since(second.until_sequence, 4).unwrap();
        assert_eq!((third.changes.len(), third.until_sequence, third.more), (0, 5, false));
    }

    #[test]
    fn a_page_of_size_zero_and_an_anchor_from_the_future_are_errors() {
        let mut s = store();
        scaffold(&mut s, &[], &[]);
        assert!(matches!(s.changes_since(0, 0), Err(StoreError::EmptyPage)));
        match s.changes_since(6, 10) {
            Err(error @ StoreError::AnchorUnknown { anchor: 6, current_sequence: 5 }) => {
                assert!(error.requires_new_enumeration());
            }
            other => panic!("expected AnchorUnknown, was {other:?}"),
        }
    }

    #[test]
    fn after_trimming_an_anchor_that_is_too_old_is_expired_and_the_next_one_is_not() {
        let mut s = store();
        s.limit.journal = 4;
        // Root: 4 New; archive container: 1 New; the archive: 3 New — 8 entries, the newest 4 stay.
        scaffold(&mut s, &[(1, "A"), (2, "B"), (3, "C")], &[]);
        assert_eq!(s.current_sequence().unwrap(), 8);
        assert_eq!(s.oldest_sequence().unwrap(), 5);

        assert_eq!(sequences(&s.changes_since(4, 100).unwrap().changes), [5, 6, 7, 8]);
        match s.changes_since(3, 100) {
            Err(StoreError::AnchorExpired { anchor: 3, oldest_sequence: 5 }) => {}
            other => panic!("expected AnchorExpired, was {other:?}"),
        }
        let at_the_seam: SourceError = s.changes_since(3, 100).unwrap_err().into();
        assert_eq!(at_the_seam, SourceError::AnchorExpired);
    }

    #[test]
    fn a_gap_in_the_journal_is_corruption_and_not_a_quiet_end() {
        let mut s = store();
        scaffold(&mut s, &[], &[]);
        s.connection.execute("DELETE FROM journal WHERE sequence = 2", []).unwrap();
        assert!(matches!(
            s.changes_since(0, 10),
            Err(StoreError::Corrupt { table: "journal", .. })
        ));
        s.connection.execute("DELETE FROM journal WHERE sequence = 3", []).unwrap();
        assert!(matches!(
            s.changes_since(1, 10),
            Err(StoreError::Corrupt { table: "journal", .. })
        ));
    }

    #[test]
    fn the_counting_survives_emptying_the_namespace_and_an_old_anchor_expires() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Sulzer")], &[]);
        let account = Account::new("usr_A").unwrap();
        let row = LogEntry::plain(time(1), LogKind::SignedIn, None);
        s.append_log(Some(&account), &row).unwrap();
        let old = s.current_sequence().unwrap();

        let new = s.empty_namespace().unwrap();
        assert_eq!(new, old + 1);
        assert_eq!(s.current_sequence().unwrap(), new);
        assert!(s.children(Container::Root).unwrap().is_empty());
        assert!(matches!(s.children(Container::Archives), Err(StoreError::ContainerUnknown(_))));
        assert!(s.container_state(Container::Root).unwrap().is_none());
        // Even the anchor that knew the old session completely denotes no new state.
        assert!(matches!(s.changes_since(old, 10), Err(StoreError::AnchorExpired { .. })));

        let j = s.replace_container(Container::Root, &root_entries(LANGUAGE), &state(2)).unwrap();
        assert_eq!(j[0].sequence, new + 1);
        assert_eq!(s.changes_since(new, 10).unwrap().changes, j);
        assert_eq!(s.log_page(Some(&account), None, 10).unwrap().rows.len(), 1);
    }

    #[test]
    fn placements_find_a_document_at_every_place() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Personal")], &[(2, "Offen")]);
        s.replace_container(
            case_container(1),
            &in_case(1, &[item(7, "Abmahnung", "1")]),
            &state(2),
        )
        .unwrap();
        let hits = in_search(2, &[item(7, "Abmahnung", "1"), item(8, "Urlaub", "1")]);
        s.replace_container(search_container(2), &hits, &state(2)).unwrap();

        let locations = s.placements(doc(7)).unwrap();
        assert_eq!(locations.len(), 2);
        assert!(locations.contains(&EntryIdentifier::Document {
            location: in_the_archive(1),
            document: doc(7)
        }));
        assert!(locations.contains(&EntryIdentifier::Document {
            location: Location::Search(search(2)),
            document: doc(7)
        }));
        assert_eq!(s.placements(doc(8)).unwrap().len(), 1);
        assert!(s.placements(doc(9)).unwrap().is_empty());
    }

    #[test]
    fn removing_a_document_everywhere_clears_every_place_redacts_the_journal_and_sets_a_tombstone()
    {
        let mut s = store();
        scaffold(&mut s, &[(1, "Personal")], &[(2, "Offen")]);
        let anchor = s.current_sequence().unwrap();
        let title = "Abmahnung Mustermann";
        s.replace_container(
            case_container(1),
            &in_case(1, &[item(7, title, "1"), item(8, "Urlaub", "1")]),
            &state(10),
        )
        .unwrap();
        s.replace_container(search_container(2), &in_search(2, &[item(7, title, "1")]), &state(10))
            .unwrap();
        // A rename, so that a Changed with before and after stands in the journal too.
        let renamed = in_case(1, &[item(7, "Abmahnung Mustermann 2", "2"), item(8, "Urlaub", "1")]);
        s.replace_container(case_container(1), &renamed, &state(11)).unwrap();

        let j = s.remove_document_everywhere(doc(7), time(20)).unwrap();

        // The return value: both places, with the full name — by it the platform finds the
        // placeholder.
        assert_eq!(j.len(), 2);
        assert!(j.iter().all(|e| matches!(
            &e.change,
            Change::Removed { entry } if entry.name.starts_with(title)
        )));
        assert!(s.placements(doc(7)).unwrap().is_empty());
        assert!(s.is_erased(doc(7), time(21)).unwrap());

        // The journal: the same sequence numbers, but no name any more, not in earlier entries
        // either.
        let caught_up = s.changes_since(anchor, 100).unwrap();
        assert_eq!(
            &sequences(&caught_up.changes)[caught_up.changes.len() - 2..],
            &sequences(&j)[..]
        );
        let text = serde_json::to_string(&caught_up.changes).unwrap();
        assert!(!text.contains("Mustermann"), "{text}");
        assert!(text.contains("Urlaub"), "the check has to be able to find something too");
        for e in &caught_up.changes {
            if e.change.identifier().document() == Some(doc(7)) {
                assert!(
                    matches!(&e.change, Change::Removed { entry } if entry.name == REDACTED),
                    "{e:?}"
                );
            }
        }

        // Erasing twice is harmless.
        assert!(s.remove_document_everywhere(doc(7), time(30)).unwrap().is_empty());
        assert_eq!(s.children(case_container(1)).unwrap().len(), 1);
    }

    #[test]
    fn a_tombstone_prevents_the_resurrection_by_a_stale_listing() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Personal")], &[]);
        let list = in_case(1, &[item(7, "Abmahnung", "1"), item(8, "Urlaub", "1")]);
        s.replace_container(case_container(1), &list, &state(10)).unwrap();
        s.remove_document_everywhere(doc(7), time(20)).unwrap();

        // Fetched before the erasure, applied afterwards:
        assert!(s.replace_container(case_container(1), &list, &state(15)).unwrap().is_empty());
        // Fetched after the erasure, from a search index that lags behind:
        assert!(s.replace_container(case_container(1), &list, &state(25)).unwrap().is_empty());

        let documents: Vec<_> = s
            .children(case_container(1))
            .unwrap()
            .iter()
            .map(|e| e.identifier.document())
            .collect();
        assert_eq!(documents, [Some(doc(8))]);
        assert!(s.placements(doc(7)).unwrap().is_empty());
    }

    #[test]
    fn after_thirty_days_the_tombstone_is_no_longer_in_effect() {
        let mut s = store();
        scaffold(&mut s, &[(1, "Personal")], &[]);
        let list = in_case(1, &[item(7, "Abmahnung", "1")]);
        s.replace_container(case_container(1), &list, &state(10)).unwrap();
        s.remove_document_everywhere(doc(7), time(20)).unwrap();
        let end = 20 + ERASURE_TAKES_EFFECT_MILLIS;

        assert!(s.is_erased(doc(7), time(end - 1)).unwrap());
        assert!(!s.is_erased(doc(7), time(end)).unwrap());
        assert!(s.replace_container(case_container(1), &list, &state(end - 1)).unwrap().is_empty());
        let j = s.replace_container(case_container(1), &list, &state(end)).unwrap();
        assert!(matches!(
            &j[..],
            [JournalEntry { change: Change::New { entry }, .. }]
                if entry.identifier.document() == Some(doc(7))
        ));

        assert_eq!(s.clear_erasure(time(end - 1)).unwrap(), 0);
        assert_eq!(s.clear_erasure(time(end)).unwrap(), 1);
    }

    #[test]
    fn the_container_state_survives_the_round_trip_truncation_included() {
        let mut s = store();
        scaffold(&mut s, &[], &[(2, "Offen")]);
        let truncated = ContainerState {
            etag: Some("\"v7\"".into()),
            fetched: time(5),
            truncation: Some(TruncationState {
                display_upper_limit: 5_000,
                refine_url: Some("https://app.example/suche/2".into()),
            }),
        };
        s.replace_container(search_container(2), &[], &truncated).unwrap();
        assert_eq!(s.container_state(search_container(2)).unwrap().as_ref(), Some(&truncated));
        let truncation = truncated.truncation.as_ref().unwrap().as_truncation();
        assert_eq!(
            (truncation.displayed, truncation.address),
            (5_000, Some("https://app.example/suche/2"))
        );

        let confirmed = ContainerState { etag: None, fetched: time(6), truncation: None };
        s.update_container_state(search_container(2), &confirmed).unwrap();
        assert_eq!(s.container_state(search_container(2)).unwrap(), Some(confirmed));
        assert!(matches!(
            s.update_container_state(search_container(9), &truncated),
            Err(StoreError::ContainerUnknown(_))
        ));
    }

    #[test]
    fn a_single_entry_can_be_read_and_the_root_itself_never_stands_in_the_table() {
        let mut s = store();
        scaffold(&mut s, &[], &[]);
        let readme = EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe };
        assert_eq!(s.entry(readme).unwrap().unwrap().name, name_read_me(LANGUAGE));
        let baskets = s.entry(EntryIdentifier::Container(Container::Baskets)).unwrap().unwrap();
        assert_eq!((baskets.name.as_str(), baskets.is_folder()), (name_baskets(LANGUAGE), true));
        let archives = s.entry(EntryIdentifier::Container(Container::Archives)).unwrap().unwrap();
        assert_eq!((archives.name.as_str(), archives.is_folder()), (name_archives(LANGUAGE), true));
        let missing = EntryIdentifier::Document { location: in_the_archive(1), document: doc(1) };
        assert!(s.entry(missing).unwrap().is_none());
        assert!(s.entry(EntryIdentifier::ROOT).unwrap().is_none());
    }

    #[test]
    fn a_basket_becomes_known_through_the_basket_listing_and_holds_nothing_of_the_server() {
        // The baskets came with namespace v2, and for the store they are a container like every
        // other: known only through the listing above them. What may be put into one the core
        // decides (`Container::accepts_new_files`) — the store keeps entries, not permissions.
        let mut s = store();
        scaffold(&mut s, &[], &[]);
        let one = Container::Basket(basket(3));
        assert!(matches!(s.children(one), Err(StoreError::ContainerUnknown(_))));

        let title = "Rechnungseingang";
        let j = s
            .replace_container(Container::Baskets, &baskets_list(&[(3, title)]), &state(2))
            .unwrap();
        assert_eq!(j.len(), 1);
        assert_eq!(s.entry(EntryIdentifier::Container(one)).unwrap().unwrap().name, title);
        // Known, and empty: nothing of the server stands in a basket (namespace v2 §4).
        assert!(s.children(one).unwrap().is_empty());
        assert!(s.container_state(one).unwrap().is_none());
    }

    #[test]
    fn the_kind_names_are_the_serde_tags_of_the_core() {
        let folder = serde_json::to_value(EntryContent::Folder).unwrap();
        assert_eq!(folder["kind"], KIND_FOLDER);
        let file = root_entries(LANGUAGE).into_iter().find(|e| !e.is_folder()).unwrap();
        assert_eq!(serde_json::to_value(&file.content).unwrap()["kind"], KIND_FILE);
    }

    #[test]
    fn after_an_erasure_the_name_stands_nowhere_in_the_file_any_more() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let secret = "Abmahnung Erika Mustermann";
        {
            let mut s = Store::open(&path).unwrap();
            scaffold(&mut s, &[(1, "Personal")], &[(2, "Offen")]);
            let list = in_case(1, &[item(7, secret, "1"), item(8, "Urlaubsantrag", "1")]);
            s.replace_container(case_container(1), &list, &state(10)).unwrap();
            s.replace_container(
                search_container(2),
                &in_search(2, &[item(7, secret, "1")]),
                &state(10),
            )
            .unwrap();
            let renamed = in_case(
                1,
                &[item(7, &format!("{secret} Kopie"), "2"), item(8, "Urlaubsantrag", "1")],
            );
            s.replace_container(case_container(1), &renamed, &state(11)).unwrap();
            let account = Account::new("usr_A").unwrap();
            let subject = Subject {
                name: format!("{secret}.pdf"),
                document: Some(doc(7)),
                location: Some("Personal".into()),
            };
            let row = LogEntry::new(
                time(12),
                LogKind::Opened,
                Some(subject),
                Some(format!("{secret}.pdf, 1 KB")),
            )
            .unwrap();
            s.append_log(Some(&account), &row).unwrap();

            s.remove_document_everywhere(doc(7), time(20)).unwrap();
            s.redact(doc(7)).unwrap();
        }
        let bytes = file_content(&path);
        assert!(!contains(&bytes, b"Mustermann"), "the erased name still stands in the file");
        assert!(
            contains(&bytes, b"Urlaubsantrag"),
            "the check has to be able to find something too"
        );
    }

    #[test]
    fn after_signing_out_no_name_of_the_tree_stands_in_the_file_any_more() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        {
            let mut s = Store::open(&path).unwrap();
            scaffold(
                &mut s,
                &[(1, "Sulzer Pumpen Wartungsvertrag")],
                &[(2, "Offene Grossauftraege")],
            );
            s.replace_container(
                case_container(1),
                &in_case(1, &[item(7, "Pruefbericht Pumpe", "1")]),
                &state(2),
            )
            .unwrap();
            let account = Account::new("usr_A").unwrap();
            let row = LogEntry::plain(time(3), LogKind::SignedOut, Some("control row".into()));
            s.append_log(Some(&account), &row).unwrap();
            s.empty_namespace().unwrap();
        }
        let bytes = file_content(&path);
        for name in ["Sulzer Pumpen", "Grossauftraege", "Pruefbericht", "LIESMICH", ARCHIVE_TITLE] {
            assert!(
                !contains(&bytes, name.as_bytes()),
                "\"{name}\" still stands in the file after signing out"
            );
        }
        assert!(
            contains(&bytes, b"control row"),
            "the usage log stays; the check really does read"
        );
    }
}
