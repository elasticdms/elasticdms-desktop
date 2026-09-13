//! The schema: pragmas, numbered migrations and the check performed when opening.
//!
//! **Migrations are never destructive.** Each runs in an `IMMEDIATE` transaction of its own and
//! sets `PRAGMA user_version` at the end; if it aborts, the database stays at the old version. A
//! shipped migration is never changed again — on some machine it has already run, and the changed
//! one would never run there. A new version appends one. The counterpart to
//! `fallbackToDestructiveMigration()`, which escan 01 §1.4 forbids via Detekt, does not exist here
//! at all: a database from a newer version is rejected and not touched.
//!
//! **Pragmas are set and read back.** SQLite silently ignores a pragma it cannot change inside a
//! transaction (`foreign_keys`, `journal_mode`), and `synchronous` applies per connection, not per
//! file. Hence: set again after the migrations and then read; what does not match is an error, not
//! an assumption.

use rusqlite::{Connection, TransactionBehavior};

use crate::WAIT_TIME_AT_LOCK;
use crate::column::from_usize;
use crate::error::StoreError;

/// The schema version this crate writes and reads (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 5;

/// `PRAGMA synchronous` as a number: 2 is `FULL`.
const SYNCHRONOUS_FULL: i64 = 2;

/// The migrations in order; entry `i` lifts the version from `i` to `i + 1`.
const MIGRATIONS: &[&str] = &[MIGRATION_1, MIGRATION_2, MIGRATION_3, MIGRATION_4, MIGRATION_5];

/// Where the database lies. In memory there is no WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    File,
    Memory,
}

/// Sets up a writing connection: lock timeout, version check, WAL, pragmas, migrations, pragmas
/// again, read back.
pub(crate) fn set_up(connection: &mut Connection, location: Location) -> Result<(), StoreError> {
    connection.busy_timeout(WAIT_TIME_AT_LOCK)?;
    // The version first: a database from a newer version does not even get WAL.
    let found = version(connection)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew { found, known: SCHEMA_VERSION });
    }
    if location == Location::File {
        let mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::NoWal { mode });
        }
    }
    set_pragmas(connection)?;
    migrate(connection, found)?;
    set_pragmas(connection)?;
    check_pragmas(connection)
}

/// Checks a reading connection: same version, WAL, and `query_only` as a second bolt.
pub(crate) fn check_read_only(connection: &Connection) -> Result<(), StoreError> {
    connection.busy_timeout(WAIT_TIME_AT_LOCK)?;
    let found = version(connection)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew { found, known: SCHEMA_VERSION });
    }
    if found < SCHEMA_VERSION {
        return Err(StoreError::SchemaStale { found, expected: SCHEMA_VERSION });
    }
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::NoWal { mode });
    }
    connection.pragma_update(None, "query_only", true)?;
    Ok(())
}

fn version(connection: &Connection) -> Result<i64, StoreError> {
    Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

fn set_pragmas(connection: &Connection) -> Result<(), StoreError> {
    connection.pragma_update(None, "synchronous", SYNCHRONOUS_FULL)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "secure_delete", true)?;
    Ok(())
}

fn check_pragmas(connection: &Connection) -> Result<(), StoreError> {
    for (name, expected) in
        [("synchronous", SYNCHRONOUS_FULL), ("foreign_keys", 1), ("secure_delete", 1)]
    {
        let found: i64 = connection.pragma_query_value(None, name, |row| row.get(0))?;
        if found != expected {
            return Err(StoreError::Pragma { name, expected, found });
        }
    }
    Ok(())
}

fn migrate(connection: &mut Connection, of: i64) -> Result<(), StoreError> {
    for (place, step) in MIGRATIONS.iter().enumerate() {
        let target = from_usize(place + 1, "user_version")?;
        if target <= of {
            continue;
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A second process may have migrated between the read above and this lock.
        let now = version(&tx)?;
        if now > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew { found: now, known: SCHEMA_VERSION });
        }
        if now >= target {
            continue;
        }
        tx.execute_batch(step)?;
        tx.pragma_update(None, "user_version", target)?;
        tx.commit()?;
    }
    Ok(())
}

// ── Schema 1 ─────────────────────────────────────────────────────────────────────────────────
//
// escan 01 §1.4 — there, string columns are only admissible as an opaque identifier, a
// hex checksum or an enumeration name. `entry.name`, `log.name/location/detail` and
// `session.display_name` are free text, because the tree has to stand offline and the usage log
// has to be readable; the reasoning is in the module head of `lib.rs`.
//
// Column discipline (`column`): identifiers TEXT in wire form, checksums 64 lowercase hex digits
// without a prefix, enumerations by name, times INTEGER in milliseconds since 1970. STRICT, so
// that SQLite rejects a string in an INTEGER column instead of quietly storing it.
const MIGRATION_1: &str = r#"
-- Namespace: one row per entry. `kennung` and `eltern` are the text forms from
-- edms_core::namespace (`cas_.../doc_...`, `wurzel`, `akten`); `rang` is the position in the
-- listing last stored; `dokument` is the document identifier of a document entry, so that every
-- place of a document can be found with one query.
CREATE TABLE eintrag (
    kennung   TEXT    NOT NULL PRIMARY KEY,
    eltern    TEXT    NOT NULL,
    rang      INTEGER NOT NULL CHECK (rang >= 0),
    name      TEXT    NOT NULL CHECK (name <> ''),
    art       TEXT    NOT NULL CHECK (art IN ('ORDNER', 'DATEI')),
    groesse   INTEGER CHECK (groesse >= 0),
    sha256    TEXT    CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    fassung   TEXT,
    erstellt  INTEGER,
    geaendert INTEGER,
    medientyp TEXT,
    dokument  TEXT,
    CHECK (
        (art = 'ORDNER' AND groesse IS NULL AND sha256 IS NULL AND fassung IS NULL
            AND erstellt IS NULL AND geaendert IS NULL AND medientyp IS NULL AND dokument IS NULL)
        OR
        (art = 'DATEI' AND groesse IS NOT NULL AND fassung IS NOT NULL AND erstellt IS NOT NULL
            AND geaendert IS NOT NULL AND medientyp IS NOT NULL)
    )
) STRICT;
CREATE INDEX eintrag_nach_eltern ON eintrag (eltern, rang);
CREATE INDEX eintrag_nach_dokument ON eintrag (dokument) WHERE dokument IS NOT NULL;

-- Per container the last fetch. A truncation always has an upper limit; without truncation there
-- is neither an upper limit nor a refinement address.
CREATE TABLE behaelter_stand (
    behaelter          TEXT    NOT NULL PRIMARY KEY,
    etag               TEXT,
    abgerufen          INTEGER NOT NULL,
    gekappt            INTEGER NOT NULL CHECK (gekappt IN (0, 1)),
    anzeige_obergrenze INTEGER CHECK (anzeige_obergrenze >= 0),
    verfeinern_url     TEXT,
    CHECK (gekappt = 1 OR (anzeige_obergrenze IS NULL AND verfeinern_url IS NULL)),
    CHECK (gekappt = 0 OR anzeige_obergrenze IS NOT NULL)
) STRICT;

-- The change journal. `aenderung` is the JSON of edms_core::change::Change; `dokument` finds, on
-- an erasure, every earlier entry belonging to a document.
CREATE TABLE journal (
    folge     INTEGER NOT NULL PRIMARY KEY CHECK (folge > 0),
    aenderung TEXT    NOT NULL,
    zeit      INTEGER NOT NULL,
    dokument  TEXT
) STRICT;
CREATE INDEX journal_nach_dokument ON journal (dokument) WHERE dokument IS NOT NULL;

-- One row: the highest sequence number ever handed out and the lower bound. The journal holds
-- exactly the sequences in (untergrenze, letzte_folge]. Kept apart from the journal, because the
-- counting must survive the emptying of the journal.
CREATE TABLE journal_stand (
    nur_eine     INTEGER NOT NULL PRIMARY KEY CHECK (nur_eine = 1),
    letzte_folge INTEGER NOT NULL CHECK (letzte_folge >= 0),
    untergrenze  INTEGER NOT NULL CHECK (untergrenze >= 0 AND untergrenze <= letzte_folge)
) STRICT;
INSERT INTO journal_stand (nur_eine, letzte_folge, untergrenze) VALUES (1, 0, 0);

-- Tombstones of erased documents. Only the identifier and when, never a name.
CREATE TABLE getilgt (
    dokument TEXT    NOT NULL PRIMARY KEY,
    zeit     INTEGER NOT NULL
) STRICT;

-- The usage log. `konto` NULL is a device row, which never carries a subject.
-- AUTOINCREMENT, so that no number returns after trimming: an open page of the view would
-- otherwise suddenly show a foreign row at the old place.
CREATE TABLE protokoll (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    konto    TEXT    CHECK (konto <> ''),
    zeit     INTEGER NOT NULL,
    art      TEXT    NOT NULL,
    name     TEXT,
    dokument TEXT,
    ort      TEXT,
    detail   TEXT,
    CHECK (name IS NOT NULL OR (dokument IS NULL AND ort IS NULL)),
    CHECK (konto IS NOT NULL OR name IS NULL)
) STRICT;
CREATE INDEX protokoll_nach_konto ON protokoll (konto, id);
CREATE INDEX protokoll_nach_dokument ON protokoll (dokument) WHERE dokument IS NOT NULL;

-- Accepted delivery commands. `ausgang` NULL means: accepted, execution not finished.
CREATE TABLE zustellung (
    befehl      TEXT    NOT NULL PRIMARY KEY,
    eingegangen INTEGER NOT NULL,
    ausgang     TEXT    CHECK (ausgang IN ('AUSGEFUEHRT', 'NICHT_ANWENDBAR', 'ABGELEHNT', 'FEHLGESCHLAGEN')),
    quittiert   INTEGER NOT NULL DEFAULT 0 CHECK (quittiert IN (0, 1)),
    CHECK (quittiert = 0 OR ausgang IS NOT NULL)
) STRICT;
CREATE INDEX zustellung_offen ON zustellung (eingegangen) WHERE quittiert = 0;

-- One row of session, nothing secret. The sign-in stands whole or not at all, and exactly in the
-- signed-in states.
CREATE TABLE sitzung (
    nur_eine        INTEGER NOT NULL PRIMARY KEY CHECK (nur_eine = 1),
    geraet          TEXT    NOT NULL,
    zustand         TEXT    NOT NULL CHECK (zustand IN
                        ('ABGEMELDET', 'WARTET_AUF_FREIGABE', 'ANGEMELDET', 'ANMELDUNG_ERFORDERLICH')),
    konto           TEXT    CHECK (konto <> ''),
    mandant         TEXT,
    anzeigename     TEXT,
    angemeldet_seit INTEGER,
    CHECK ((zustand IN ('ANGEMELDET', 'ANMELDUNG_ERFORDERLICH')) = (konto IS NOT NULL)),
    CHECK ((konto IS NULL) = (mandant IS NULL)
        AND (konto IS NULL) = (anzeigename IS NULL)
        AND (konto IS NULL) = (angemeldet_seit IS NULL))
) STRICT;

CREATE TABLE einstellung (
    schluessel TEXT NOT NULL PRIMARY KEY CHECK (schluessel <> ''),
    wert       TEXT NOT NULL
) STRICT;
"#;

// ── Schema 2 ─────────────────────────────────────────────────────────────────────────────────
//
// Purely additive: one new table, no existing one touched. A database from version 1 gets it on
// the next open and keeps everything that stands in it.
const MIGRATION_2: &str = r#"
-- Ingests begun from the inbox folder (ADR-D08, contract §7.4). One row per file, for as long as
-- it has not yet moved to `.uebertragen/<uploadId>/`. `schluessel` is the idempotency key of this
-- ingest — a ULID, **one** per file, so that a retry after an abort does not become a second
-- upload (03 §6.0.10).
CREATE TABLE eingang (
    datei      TEXT    NOT NULL PRIMARY KEY CHECK (datei <> ''),
    schluessel TEXT    NOT NULL CHECK (length(schluessel) = 26),
    groesse    INTEGER NOT NULL CHECK (groesse >= 0),
    geaendert  INTEGER NOT NULL,
    upload     TEXT,
    angelegt   INTEGER NOT NULL
) STRICT;
"#;

// ── Schema 3 ─────────────────────────────────────────────────────────────────────────────────
//
// Everything developers touch is English — the stored values included (owner's decision,
// 2026-09-12). Tables, columns, indexes and the stored enumeration values move along with the
// code. Migrations 1 and 2 stay untouched: a shipped migration is never changed.
//
// Three tables name the old values in a CHECK (`eintrag.art`, `zustellung.ausgang`,
// `sitzung.zustand`). A CHECK cannot be altered, so these three are rebuilt the SQLite way: new
// table, `INSERT … SELECT` with the mapping, old one away. The rest is renamed in place — that
// keeps the AUTOINCREMENT counter of `protokoll`, and a returning row number would otherwise
// suddenly show a foreign row on an open page.
const MIGRATION_3: &str = r#"
-- Namespace. The text forms of the entry identifier move along
-- (`wurzel|akten|suchen` -> `root|cases|searches`, `hinweis-*` -> `hint-*`).
CREATE TABLE entry (
    identifier TEXT    NOT NULL PRIMARY KEY,
    parent     TEXT    NOT NULL,
    rank       INTEGER NOT NULL CHECK (rank >= 0),
    name       TEXT    NOT NULL CHECK (name <> ''),
    kind       TEXT    NOT NULL CHECK (kind IN ('FOLDER', 'FILE')),
    size       INTEGER CHECK (size >= 0),
    sha256     TEXT    CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    version    TEXT,
    created    INTEGER,
    changed    INTEGER,
    media_type TEXT,
    document   TEXT,
    CHECK (
        (kind = 'FOLDER' AND size IS NULL AND sha256 IS NULL AND version IS NULL
            AND created IS NULL AND changed IS NULL AND media_type IS NULL AND document IS NULL)
        OR
        (kind = 'FILE' AND size IS NOT NULL AND version IS NOT NULL AND created IS NOT NULL
            AND changed IS NOT NULL AND media_type IS NOT NULL)
    )
) STRICT;
INSERT INTO entry (identifier, parent, rank, name, kind, size, sha256, version, created,
                   changed, media_type, document)
SELECT kennung, eltern, rang, name,
       CASE art WHEN 'ORDNER' THEN 'FOLDER' WHEN 'DATEI' THEN 'FILE' ELSE art END,
       groesse, sha256, fassung, erstellt, geaendert, medientyp, dokument
FROM eintrag;
DROP TABLE eintrag;
UPDATE entry SET
       identifier = REPLACE(identifier, 'hinweis-liesmich', 'hint-readme'),
       parent = REPLACE(parent, 'hinweis-liesmich', 'hint-readme');
UPDATE entry SET
       identifier = REPLACE(identifier, 'hinweis-gekappt', 'hint-truncated'),
       parent = REPLACE(parent, 'hinweis-gekappt', 'hint-truncated');
UPDATE entry SET
       identifier = REPLACE(identifier, 'wurzel', 'root'),
       parent = REPLACE(parent, 'wurzel', 'root');
UPDATE entry SET
       identifier = REPLACE(identifier, 'akten', 'cases'),
       parent = REPLACE(parent, 'akten', 'cases');
UPDATE entry SET
       identifier = REPLACE(identifier, 'suchen', 'searches'),
       parent = REPLACE(parent, 'suchen', 'searches');
CREATE INDEX entry_by_parent ON entry (parent, rank);
CREATE INDEX entry_by_document ON entry (document) WHERE document IS NOT NULL;

-- Per container the last fetch.
ALTER TABLE behaelter_stand RENAME TO container_state;
ALTER TABLE container_state RENAME COLUMN behaelter TO container;
ALTER TABLE container_state RENAME COLUMN abgerufen TO fetched;
ALTER TABLE container_state RENAME COLUMN gekappt TO truncated;
ALTER TABLE container_state RENAME COLUMN anzeige_obergrenze TO display_limit;
ALTER TABLE container_state RENAME COLUMN verfeinern_url TO refine_url;
UPDATE container_state SET
       container = REPLACE(container, 'hinweis-liesmich', 'hint-readme');
UPDATE container_state SET
       container = REPLACE(container, 'hinweis-gekappt', 'hint-truncated');
UPDATE container_state SET
       container = REPLACE(container, 'wurzel', 'root');
UPDATE container_state SET
       container = REPLACE(container, 'akten', 'cases');
UPDATE container_state SET
       container = REPLACE(container, 'suchen', 'searches');

-- The change journal. `change` is the JSON of edms_core::change::Change; its fields, its tag, its
-- values and the identifier text form inside it all move along.
ALTER TABLE journal RENAME COLUMN folge TO sequence;
ALTER TABLE journal RENAME COLUMN aenderung TO change;
ALTER TABLE journal RENAME COLUMN zeit TO time;
ALTER TABLE journal RENAME COLUMN dokument TO document;
DROP INDEX journal_nach_dokument;
CREATE INDEX journal_by_document ON journal (document) WHERE document IS NOT NULL;
UPDATE journal SET
       change = REPLACE(change, '"art":', '"kind":');
UPDATE journal SET
       change = REPLACE(change, '"eintrag":', '"entry":');
UPDATE journal SET
       change = REPLACE(change, '"vorher":', '"before":');
UPDATE journal SET
       change = REPLACE(change, '"nachher":', '"after":');
UPDATE journal SET
       change = REPLACE(change, '"kennung":', '"identifier":');
UPDATE journal SET
       change = REPLACE(change, '"inhalt":', '"content":');
UPDATE journal SET
       change = REPLACE(change, '"groesse":', '"size":');
UPDATE journal SET
       change = REPLACE(change, '"fassung":', '"version":');
UPDATE journal SET
       change = REPLACE(change, '"erstellt":', '"created":');
UPDATE journal SET
       change = REPLACE(change, '"geaendert":', '"changed":');
UPDATE journal SET
       change = REPLACE(change, '"medientyp":', '"media_type":');
UPDATE journal SET
       change = REPLACE(change, ':"NEU"', ':"NEW"');
UPDATE journal SET
       change = REPLACE(change, ':"GEAENDERT"', ':"CHANGED"');
UPDATE journal SET
       change = REPLACE(change, ':"ENTFERNT"', ':"REMOVED"');
UPDATE journal SET
       change = REPLACE(change, ':"ORDNER"', ':"FOLDER"');
UPDATE journal SET
       change = REPLACE(change, ':"DATEI"', ':"FILE"');
UPDATE journal SET
       change = REPLACE(change, '"identifier":"wurzel"', '"identifier":"root"');
UPDATE journal SET
       change = REPLACE(change, '"identifier":"akten"', '"identifier":"cases"');
UPDATE journal SET
       change = REPLACE(change, '"identifier":"suchen"', '"identifier":"searches"');
UPDATE journal SET
       change = REPLACE(change, '"identifier":"wurzel/', '"identifier":"root/');
UPDATE journal SET
       change = REPLACE(change, '"identifier":"akten/', '"identifier":"cases/');
UPDATE journal SET
       change = REPLACE(change, '"identifier":"suchen/', '"identifier":"searches/');
UPDATE journal SET
       change = REPLACE(change, '/hinweis-liesmich"', '/hint-readme"');
UPDATE journal SET
       change = REPLACE(change, '/hinweis-gekappt"', '/hint-truncated"');

ALTER TABLE journal_stand RENAME TO journal_state;
ALTER TABLE journal_state RENAME COLUMN nur_eine TO only_one;
ALTER TABLE journal_state RENAME COLUMN letzte_folge TO last_sequence;
ALTER TABLE journal_state RENAME COLUMN untergrenze TO lower_bound;

-- Tombstones of erased documents.
ALTER TABLE getilgt RENAME TO erased;
ALTER TABLE erased RENAME COLUMN dokument TO document;
ALTER TABLE erased RENAME COLUMN zeit TO time;

-- The usage log. Renamed instead of rebuilt, so that AUTOINCREMENT keeps counting.
ALTER TABLE protokoll RENAME TO log;
ALTER TABLE log RENAME COLUMN konto TO account;
ALTER TABLE log RENAME COLUMN zeit TO time;
ALTER TABLE log RENAME COLUMN art TO kind;
ALTER TABLE log RENAME COLUMN dokument TO document;
ALTER TABLE log RENAME COLUMN ort TO location;
DROP INDEX protokoll_nach_konto;
DROP INDEX protokoll_nach_dokument;
CREATE INDEX log_by_account ON log (account, id);
CREATE INDEX log_by_document ON log (document) WHERE document IS NOT NULL;
UPDATE log SET kind = CASE kind
        WHEN 'GEOEFFNET' THEN 'OPENED'
        WHEN 'OEFFNEN_FEHLGESCHLAGEN' THEN 'OPEN_FAILED'
        WHEN 'NEUE_FASSUNG' THEN 'NEW_VERSION'
        WHEN 'SPEICHER_FREIGEGEBEN' THEN 'SPACE_RECLAIMED'
        WHEN 'ZUGRIFF_ENTZOGEN' THEN 'ACCESS_REVOKED'
        WHEN 'AUF_ANORDNUNG_ENTFERNT' THEN 'ERASED_BY_ORDER'
        WHEN 'EINGANG_UEBERNOMMEN' THEN 'INGEST_ACCEPTED'
        WHEN 'EINGANG_FEHLGESCHLAGEN' THEN 'INGEST_FAILED'
        WHEN 'GERAET_REGISTRIERT' THEN 'DEVICE_REGISTERED'
        WHEN 'ANGEMELDET' THEN 'SIGNED_IN'
        WHEN 'ABGEMELDET' THEN 'SIGNED_OUT'
        WHEN 'ANMELDUNG_ERFORDERLICH' THEN 'LOGIN_REQUIRED'
        WHEN 'VERBINDUNG_UNTERBROCHEN' THEN 'CONNECTION_LOST'
        WHEN 'VERBINDUNG_WIEDERHERGESTELLT' THEN 'CONNECTION_RESTORED'
        WHEN 'SICHERHEITSWARNUNG' THEN 'SECURITY_WARNING'
        ELSE kind
    END;

-- Accepted delivery commands.
CREATE TABLE delivery (
    command      TEXT    NOT NULL PRIMARY KEY,
    received     INTEGER NOT NULL,
    outcome      TEXT    CHECK (outcome IN ('APPLIED', 'NOT_APPLICABLE', 'REJECTED', 'FAILED')),
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    CHECK (acknowledged = 0 OR outcome IS NOT NULL)
) STRICT;
INSERT INTO delivery (command, received, outcome, acknowledged)
SELECT befehl, eingegangen, CASE ausgang
       WHEN 'AUSGEFUEHRT' THEN 'APPLIED'
       WHEN 'NICHT_ANWENDBAR' THEN 'NOT_APPLICABLE'
       WHEN 'ABGELEHNT' THEN 'REJECTED'
       WHEN 'FEHLGESCHLAGEN' THEN 'FAILED'
       ELSE ausgang
    END, quittiert
FROM zustellung;
DROP TABLE zustellung;
CREATE INDEX delivery_open ON delivery (received) WHERE acknowledged = 0;

-- One row of session, nothing secret.
CREATE TABLE session (
    only_one        INTEGER NOT NULL PRIMARY KEY CHECK (only_one = 1),
    device          TEXT    NOT NULL,
    state           TEXT    NOT NULL CHECK (state IN
                        ('SIGNED_OUT', 'AWAITING_APPROVAL', 'SIGNED_IN', 'LOGIN_REQUIRED')),
    account         TEXT    CHECK (account <> ''),
    tenant          TEXT,
    display_name    TEXT,
    signed_in_since INTEGER,
    CHECK ((state IN ('SIGNED_IN', 'LOGIN_REQUIRED')) = (account IS NOT NULL)),
    CHECK ((account IS NULL) = (tenant IS NULL)
        AND (account IS NULL) = (display_name IS NULL)
        AND (account IS NULL) = (signed_in_since IS NULL))
) STRICT;
INSERT INTO session (only_one, device, state, account, tenant, display_name, signed_in_since)
SELECT nur_eine, geraet, CASE zustand
       WHEN 'ABGEMELDET' THEN 'SIGNED_OUT'
       WHEN 'WARTET_AUF_FREIGABE' THEN 'AWAITING_APPROVAL'
       WHEN 'ANGEMELDET' THEN 'SIGNED_IN'
       WHEN 'ANMELDUNG_ERFORDERLICH' THEN 'LOGIN_REQUIRED'
       ELSE zustand
    END, konto, mandant, anzeigename, angemeldet_seit
FROM sitzung;
DROP TABLE sitzung;

ALTER TABLE einstellung RENAME TO setting;
ALTER TABLE setting RENAME COLUMN schluessel TO key;
ALTER TABLE setting RENAME COLUMN wert TO value;

ALTER TABLE eingang RENAME TO ingest;
ALTER TABLE ingest RENAME COLUMN datei TO file;
ALTER TABLE ingest RENAME COLUMN schluessel TO key;
ALTER TABLE ingest RENAME COLUMN groesse TO size;
ALTER TABLE ingest RENAME COLUMN geaendert TO changed;
ALTER TABLE ingest RENAME COLUMN angelegt TO created;
"#;

// ── Schema 4 ─────────────────────────────────────────────────────────────────────────────────
//
// The user interface became multilingual (`edms-i18n`), and with it the last stored sentence had
// to go: a redacted row used to carry the **German sentence** „Dokument auf Anordnung entfernt" in
// `log.name`. A database written in German would have shown German rows to an English user for
// ever, and the check for "is this row redacted?" would have failed on every row written in the
// other language.
//
// What is stored now is the marker `edms_core::log::REDACTED`; the sentence is picked at display
// time. The `WHERE` clause is exactly the condition of `Subject::is_redacted` — a file that was
// really called that way (with a document and a location) is not touched.
//
// The entries of the namespace are **not** rewritten: their names are the names of the mirror, and
// the next reconcile after the start writes them afresh in the current language (a rename in
// Explorer and Finder, which is what a language change is).
const MIGRATION_4: &str = r#"
UPDATE log SET name = 'REDACTED'
 WHERE name = 'Dokument auf Anordnung entfernt'
   AND document IS NULL AND location IS NULL AND detail IS NULL;
"#;

// ── Schema 5 ─────────────────────────────────────────────────────────────────────────────────
//
// Namespace v2 (owner's decision of 2026-09-12): a case file (Akte) hangs in an archive now, the
// top-level `cases` container is gone, and the mail baskets have arrived. `entry`,
// `container_state` and the journal hold nothing but a cache of the server's tree — and that tree
// has a different shape. So the cache is emptied and the next contact fetches the whole tree
// afresh.
//
// **Nothing is rewritten.** A stored `cases` has no place in the new tree, and a stored `cas_…`
// names a case file whose archive nobody here knows — `EntryIdentifier` reads both as
// `EntryIdentifierError::Shape` since namespace v2. Hanging them under some archive would be
// inventing exactly the one fact that is missing, and the invented tree would stand in Explorer
// and Finder until the next fetch.
//
// **The counting runs on** and consumes one number, exactly as on a sign-out
// (`Store::empty_namespace`): the platform keeps its anchor across an update, and an anchor of the
// old tree has to be expired afterwards instead of being answered with changes of the new one. If
// the counting began at 0 again, anchor 57 of the old tree would at some point stand for a state
// of the new one, and the Finder would take names from before the update for current ones.
// `last_sequence = 0` means no number was ever handed out, hence no anchor exists that could be
// wrong; there this changes nothing, and a store created by this very migration run still starts
// at sequence 0.
//
// Everything that is not this cache stays: the session, the settings (the vault's slots stand
// among them), the usage log, the tombstones of erased documents, the accepted delivery commands
// and the begun ingests.
const MIGRATION_5: &str = r#"
DELETE FROM entry;
DELETE FROM container_state;
DELETE FROM journal;
UPDATE journal_state
   SET last_sequence = last_sequence + 1,
       lower_bound = last_sequence + 1
 WHERE only_one = 1 AND last_sequence > 0;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    fn tables(connection: &Connection) -> Vec<String> {
        let mut query = connection
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
                 ORDER BY name",
            )
            .unwrap();
        query.query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
    }

    fn pragma(connection: &Connection, name: &str) -> String {
        connection
            .pragma_query_value(None, name, |row| {
                row.get::<_, rusqlite::types::Value>(0).map(|value| match value {
                    rusqlite::types::Value::Integer(number) => number.to_string(),
                    rusqlite::types::Value::Text(text) => text,
                    other => format!("{other:?}"),
                })
            })
            .unwrap()
    }

    #[test]
    fn the_schema_version_is_the_number_of_migrations() {
        assert_eq!(usize::try_from(SCHEMA_VERSION).unwrap(), MIGRATIONS.len());
    }

    /// The words that really stood in schema 1 and 2 and that migration 3 renamed away.
    ///
    /// The architecture rule in `crates/architecture-rules` strips string literals before it looks
    /// for German, so the whole SQL of this file is invisible to it. Schema 1 may keep its German
    /// names — it is history and is replayed on every old file — but what a freshly migrated
    /// database really carries is checked here, against the database and not against the source.
    const GERMAN_IN_SCHEMA_1: &[&str] = &[
        "aenderung",
        "akten",
        "angelegt",
        "anzeigename",
        "art",
        "ausgang",
        "befehl",
        "behaelter",
        "datei",
        "dokument",
        "eingang",
        "eingegangen",
        "einstellung",
        "eintrag",
        "eltern",
        "erstellt",
        "fassung",
        "folge",
        "geaendert",
        "gekappt",
        "geraet",
        "getilgt",
        "groesse",
        "hinweis",
        "inhalt",
        "kennung",
        "konto",
        "mandant",
        "medientyp",
        "protokoll",
        "quittiert",
        "rang",
        "schluessel",
        "sitzung",
        "sprache",
        "untergrenze",
        "wert",
        "wurzel",
        "zeit",
        "zustand",
        "zustellung",
    ];

    #[test]
    fn a_migrated_database_carries_no_german_name_any_more() {
        let s = Store::in_memory().unwrap();
        let tables = tables(&s.connection);
        assert!(
            tables.len() >= 8,
            "only {} tables read — the check reads into the void",
            tables.len()
        );
        let mut names: Vec<String> = tables.clone();
        {
            let mut query = s
                .connection
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE type = 'index' AND name NOT LIKE                      'sqlite_%' ORDER BY name",
                )
                .unwrap();
            let indexes: Vec<String> =
                query.query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
            assert!(!indexes.is_empty(), "no index read — the check reads into the void");
            names.extend(indexes);
        }
        let mut columns = 0usize;
        for table in &tables {
            let mut query = s.connection.prepare(&format!("PRAGMA table_info({table})")).unwrap();
            let of_table: Vec<String> = query
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!of_table.is_empty(), "{table} has no column — the check reads into the void");
            columns += of_table.len();
            names.extend(of_table);
        }
        assert!(columns >= 40, "only {columns} columns read — the check reads into the void");
        let mut german = Vec::new();
        for name in &names {
            for word in name.split('_') {
                if GERMAN_IN_SCHEMA_1.contains(&word) {
                    german.push(format!("`{name}` carries `{word}`"));
                }
            }
        }
        assert!(
            german.is_empty(),
            "a German name came back into the schema ({}); everything developers touch is English \
             (owner's decision 2026-09-12), and migration 3 renamed exactly these away:\n{}",
            german.len(),
            german.join("\n")
        );
        // A rule that can never fire is decoration: these three names really stood in schema 1.
        for gone in ["eintrag_nach_eltern", "behaelter_stand", "zustellung"] {
            assert!(
                gone.split('_').any(|word| GERMAN_IN_SCHEMA_1.contains(&word)),
                "`{gone}` should have been recognized"
            );
        }
    }

    #[test]
    fn the_migration_sets_an_empty_store_up_completely() {
        let s = Store::in_memory().unwrap();
        assert_eq!(version(&s.connection).unwrap(), SCHEMA_VERSION);
        assert_eq!(
            tables(&s.connection),
            [
                "container_state",
                "delivery",
                "entry",
                "erased",
                "ingest",
                "journal",
                "journal_state",
                "log",
                "session",
                "setting"
            ]
        );
        assert_eq!(pragma(&s.connection, "synchronous"), "2");
        assert_eq!(pragma(&s.connection, "foreign_keys"), "1");
        assert_eq!(pragma(&s.connection, "secure_delete"), "1");
    }

    #[test]
    fn a_file_runs_in_wal_mode_with_synchronous_full_and_secure_delete() {
        let directory = tempfile::tempdir().unwrap();
        let s = Store::open(&directory.path().join("state.sqlite")).unwrap();
        assert_eq!(pragma(&s.connection, "journal_mode"), "wal");
        assert_eq!(pragma(&s.connection, "synchronous"), "2");
        assert_eq!(pragma(&s.connection, "foreign_keys"), "1");
        assert_eq!(pragma(&s.connection, "secure_delete"), "1");
        assert_eq!(pragma(&s.connection, "busy_timeout"), "5000");
    }

    #[test]
    fn a_second_open_does_not_migrate_again() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        {
            let mut s = Store::open(&path).unwrap();
            s.set_setting("stays", "yes").unwrap();
        }
        // If migration 1 ran again, CREATE TABLE would fail on the table already there.
        let s = Store::open(&path).unwrap();
        assert_eq!(version(&s.connection).unwrap(), SCHEMA_VERSION);
        assert_eq!(s.setting("stays").unwrap().as_deref(), Some("yes"));
    }

    #[test]
    fn a_database_from_a_newer_version_is_not_touched() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        {
            let foreign = Connection::open(&path).unwrap();
            foreign
                .execute_batch("CREATE TABLE future (x INTEGER); PRAGMA user_version = 99;")
                .unwrap();
        }
        match Store::open(&path) {
            Err(StoreError::SchemaTooNew { found: 99, known: SCHEMA_VERSION }) => {}
            other => panic!("expected SchemaTooNew, was {other:?}"),
        }
        let after = Connection::open(&path).unwrap();
        assert_eq!(version(&after).unwrap(), 99);
        // Not even the journal mode was switched over.
        assert_eq!(pragma(&after, "journal_mode"), "delete");
        assert_eq!(tables(&after), ["future"]);
    }

    #[test]
    fn a_foreign_file_is_not_a_database_and_the_error_names_the_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        std::fs::write(
            &path,
            "Dies ist keine SQLite-Datei, sondern ein Einkaufszettel.".repeat(40),
        )
        .unwrap();
        match Store::open(&path) {
            Err(error @ StoreError::Open { .. }) => {
                assert!(error.to_string().contains("state.sqlite"), "{error}");
            }
            other => panic!("expected Open, was {other:?}"),
        }
        let missing = directory.path().join("does-not-exist").join("state.sqlite");
        assert!(matches!(Store::open(&missing), Err(StoreError::Open { .. })));
    }

    #[test]
    fn opened_for_reading_it_reads_and_does_not_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let mut writer = Store::open(&path).unwrap();
        writer.set_setting("language", "de").unwrap();

        let mut reader = Store::open_read_only(&path).unwrap();
        assert_eq!(reader.setting("language").unwrap().as_deref(), Some("de"));
        assert!(reader.set_setting("language", "en").is_err());
        // The writer goes on writing, the reader sees it.
        writer.set_setting("language", "fr").unwrap();
        assert_eq!(reader.setting("language").unwrap().as_deref(), Some("fr"));
    }

    #[test]
    fn opening_for_reading_neither_creates_nor_migrates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        assert!(matches!(Store::open_read_only(&path), Err(StoreError::Open { .. })));
        assert!(!path.exists());
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE x (a INTEGER);").unwrap();
        }
        assert!(matches!(
            Store::open_read_only(&path),
            Err(StoreError::SchemaStale { found: 0, expected: SCHEMA_VERSION })
        ));
    }

    /// A database as version 2 left it: German tables, columns and values.
    fn write_schema_2(path: &std::path::Path) {
        let c = Connection::open(path).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        c.execute_batch(MIGRATION_1).unwrap();
        c.execute_batch(MIGRATION_2).unwrap();
        c.execute_batch(
            r#"
            INSERT INTO eintrag (kennung, eltern, rang, name, art)
                VALUES ('akten', 'wurzel', 0, 'Akten', 'ORDNER');
            INSERT INTO eintrag (kennung, eltern, rang, name, art, groesse, sha256, fassung,
                                 erstellt, geaendert, medientyp, dokument)
                VALUES ('cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB/doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB',
                        'cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 1, 'Rechnung.pdf', 'DATEI', 12,
                        '0000000000000000000000000000000000000000000000000000000000000000',
                        'v1', 0, 0, 'application/pdf', 'doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB');
            INSERT INTO eintrag (kennung, eltern, rang, name, art)
                VALUES ('wurzel/hinweis-liesmich', 'wurzel', 2, 'LIESMICH.txt', 'ORDNER');
            INSERT INTO behaelter_stand (behaelter, abgerufen, gekappt)
                VALUES ('akten', 7, 0);
            INSERT INTO journal (folge, aenderung, zeit, dokument)
                VALUES (1, '{"art":"NEU","eintrag":{"kennung":"akten/doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB","name":"Rechnung.pdf","inhalt":{"art":"DATEI","groesse":12,"sha256":null,"fassung":"v1","erstellt":0,"geaendert":0,"medientyp":"application/pdf"}}}',
                        7, 'doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB');
            INSERT INTO getilgt (dokument, zeit) VALUES ('doc_01JK4R7ZQ8M3N5P6T9V0WXYZAC', 9);
            INSERT INTO protokoll (konto, zeit, art, name)
                VALUES ('a@b.de', 1, 'GEOEFFNET', 'Rechnung.pdf');
            INSERT INTO protokoll (konto, zeit, art)
                VALUES ('a@b.de', 2, 'AUF_ANORDNUNG_ENTFERNT');
            INSERT INTO protokoll (konto, zeit, art, name)
                VALUES ('a@b.de', 3, 'SPEICHER_FREIGEGEBEN', 'Rechnung.pdf');
            INSERT INTO zustellung (befehl, eingegangen, ausgang, quittiert)
                VALUES ('cmd_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 4, 'AUSGEFUEHRT', 1);
            INSERT INTO sitzung (nur_eine, geraet, zustand, konto, mandant, anzeigename,
                                 angemeldet_seit)
                VALUES (1, 'dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 'ANGEMELDET', 'a@b.de', 'm', 'A', 5);
            INSERT INTO einstellung (schluessel, wert) VALUES ('sprache', 'de');
            INSERT INTO eingang (datei, schluessel, groesse, geaendert, upload, angelegt)
                VALUES ('a.pdf', '01JK4R7ZQ8M3N5P6T9V0WXYZAB', 3, 6, NULL, 6);
            PRAGMA user_version = 2;
            "#,
        )
        .unwrap();
    }

    #[test]
    fn migration_3_rewrites_the_old_german_rows_onto_the_new_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        write_schema_2(&path);

        // Only up to 3, and not through `Store::open`: migration 5 empties the namespace cache
        // afterwards (the tree changed its shape), and what is asserted here is precisely how 3
        // carries the old rows over. That the whole chain runs when a store is opened is shown by
        // `migration_4_…` and `migration_5_…`.
        let c = Connection::open(&path).unwrap();
        c.execute_batch(MIGRATION_3).unwrap();
        c.pragma_update(None, "user_version", 3).unwrap();
        assert_eq!(version(&c).unwrap(), 3);
        assert_eq!(
            tables(&c),
            [
                "container_state",
                "delivery",
                "entry",
                "erased",
                "ingest",
                "journal",
                "journal_state",
                "log",
                "session",
                "setting"
            ]
        );

        let one =
            |sql: &str| -> String { c.query_row(sql, [], |row| row.get::<_, String>(0)).unwrap() };
        // The text forms of the entry identifier.
        assert_eq!(one("SELECT identifier FROM entry ORDER BY rank LIMIT 1"), "cases");
        assert_eq!(one("SELECT parent FROM entry ORDER BY rank LIMIT 1"), "root");
        assert_eq!(one("SELECT kind FROM entry ORDER BY rank LIMIT 1"), "FOLDER");
        assert_eq!(one("SELECT kind FROM entry WHERE rank = 1"), "FILE");
        assert_eq!(one("SELECT identifier FROM entry WHERE rank = 2"), "root/hint-readme");
        assert_eq!(one("SELECT container FROM container_state"), "cases");

        // The journal JSON: tag, fields, values and the identifier inside it.
        let change = one("SELECT change FROM journal");
        assert!(change.contains(r#""kind":"NEW""#), "{change}");
        assert!(change.contains(r#""entry":{"identifier":"cases/doc_"#), "{change}");
        assert!(change.contains(r#""content":{"kind":"FILE","size":12"#), "{change}");
        assert!(change.contains(r#""version":"v1""#), "{change}");
        assert!(change.contains(r#""media_type":"application/pdf""#), "{change}");
        assert!(!change.contains("art"), "no German remainder: {change}");

        // The fifteen log kinds, the four outcomes, the four session states.
        let kinds: Vec<String> = c
            .prepare("SELECT kind FROM log ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(kinds, ["OPENED", "ERASED_BY_ORDER", "SPACE_RECLAIMED"]);
        assert_eq!(one("SELECT outcome FROM delivery"), "APPLIED");
        assert_eq!(one("SELECT state FROM session"), "SIGNED_IN");
        assert_eq!(one("SELECT key FROM setting"), "sprache");
        assert_eq!(one("SELECT file FROM ingest"), "a.pdf");
        assert_eq!(one("SELECT document FROM erased"), "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAC");

        // The AUTOINCREMENT counter of the usage log survived the rename.
        assert_eq!(
            c.query_row("SELECT seq FROM sqlite_sequence WHERE name = 'log'", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn migration_4_turns_the_stored_german_redaction_sentence_into_the_marker() {
        // Before the user interface became multilingual, a redacted row carried the German
        // sentence in `name`. A row like that would have stayed German for ever, and
        // `Subject::is_redacted` would no longer have recognised it — the window would then have
        // shown an erased document as an ordinary one, with a file name that reads like a name.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        write_schema_2(&path);
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                r#"
                INSERT INTO protokoll (konto, zeit, art, name)
                    VALUES ('a@b.de', 4, 'GEOEFFNET', 'Dokument auf Anordnung entfernt');
                INSERT INTO protokoll (konto, zeit, art, name, dokument)
                    VALUES ('a@b.de', 5, 'GEOEFFNET', 'Dokument auf Anordnung entfernt',
                            'doc_01JK4R7ZQ8M3N5P6T9V0WXYZAD');
                "#,
            )
            .unwrap();
        }

        let s = Store::open(&path).unwrap();
        assert_eq!(version(&s.connection).unwrap(), SCHEMA_VERSION);
        let names: Vec<Option<String>> = s
            .connection
            .prepare("SELECT name FROM log WHERE time IN (4, 5) ORDER BY time")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        // The redacted row becomes the marker …
        assert_eq!(names[0].as_deref(), Some(edms_core::log::REDACTED));
        // … and a row that only happens to carry the same text, but has a document, is left
        // alone: it is not a redaction, and rewriting it would be inventing one.
        assert_eq!(names[1].as_deref(), Some("Dokument auf Anordnung entfernt"));
    }

    /// A database as version 4 left it: English tables and values, and a namespace of the shape
    /// before namespace v2 — a top-level `cases` container and case files (Akten) without the
    /// archive they hang in.
    fn write_schema_4(path: &std::path::Path) {
        let c = Connection::open(path).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        for step in [MIGRATION_1, MIGRATION_2, MIGRATION_3, MIGRATION_4] {
            c.execute_batch(step).unwrap();
        }
        c.execute_batch(
            r#"
            INSERT INTO entry (identifier, parent, rank, name, kind)
                VALUES ('cases', 'root', 0, 'Akten', 'FOLDER');
            INSERT INTO entry (identifier, parent, rank, name, kind)
                VALUES ('cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 'cases', 0, 'Sulzer', 'FOLDER');
            INSERT INTO entry (identifier, parent, rank, name, kind, size, sha256, version,
                               created, changed, media_type, document)
                VALUES ('cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB/doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB',
                        'cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 0, 'Rechnung.pdf', 'FILE', 12,
                        '0000000000000000000000000000000000000000000000000000000000000000',
                        'v1', 0, 0, 'application/pdf', 'doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB');
            INSERT INTO container_state (container, etag, fetched, truncated)
                VALUES ('cases', '"7"', 7, 0);
            INSERT INTO journal (sequence, change, time, document)
                VALUES (7, '{"kind":"NEW","entry":{"identifier":"cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB/doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB","name":"Rechnung.pdf","content":{"kind":"FILE","size":12,"sha256":null,"version":"v1","created":0,"changed":0,"media_type":"application/pdf"}}}',
                        7, 'doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB');
            UPDATE journal_state SET last_sequence = 7, lower_bound = 6 WHERE only_one = 1;
            INSERT INTO erased (document, time) VALUES ('doc_01JK4R7ZQ8M3N5P6T9V0WXYZAC', 9);
            INSERT INTO log (account, time, kind, name)
                VALUES ('usr_A', 1, 'OPENED', 'Rechnung.pdf');
            INSERT INTO delivery (command, received, outcome, acknowledged)
                VALUES ('cmd_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 4, 'APPLIED', 1);
            INSERT INTO session (only_one, device, state, account, tenant, display_name,
                                 signed_in_since)
                VALUES (1, 'dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB', 'SIGNED_IN', 'usr_A', 'ten_lm',
                        'N. Lotzer', 5);
            INSERT INTO setting (key, value) VALUES ('key-set', 'the vault''s slot');
            INSERT INTO ingest (file, key, size, changed, upload, created)
                VALUES ('a.pdf', '01JK4R7ZQ8M3N5P6T9V0WXYZAB', 3, 6, NULL, 6);
            PRAGMA user_version = 4;
            "#,
        )
        .unwrap();
    }

    #[test]
    fn migration_5_empties_the_namespace_cache_and_leaves_everything_else_standing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        write_schema_4(&path);
        let before = Connection::open(&path).unwrap();
        let count = |c: &Connection, sql: &str| c.query_row(sql, [], |row| row.get::<_, i64>(0));
        // What the migration has to find, so that the emptiness below says something.
        assert_eq!(count(&before, "SELECT count(*) FROM entry").unwrap(), 3);
        assert_eq!(count(&before, "SELECT count(*) FROM container_state").unwrap(), 1);
        assert_eq!(count(&before, "SELECT count(*) FROM journal").unwrap(), 1);
        drop(before);

        let s = Store::open(&path).unwrap();
        assert_eq!(version(&s.connection).unwrap(), SCHEMA_VERSION);

        // The cache of the server's tree is gone: `cases` has no place in the new tree, and the
        // archive of `cas_…` stands nowhere in this file.
        assert_eq!(count(&s.connection, "SELECT count(*) FROM entry").unwrap(), 0);
        assert_eq!(count(&s.connection, "SELECT count(*) FROM container_state").unwrap(), 0);
        assert_eq!(count(&s.connection, "SELECT count(*) FROM journal").unwrap(), 0);

        // The counting ran on, so the anchor of the old tree is expired instead of being answered
        // with changes of the new one.
        assert_eq!(s.current_sequence().unwrap(), 8);
        assert_eq!(s.oldest_sequence().unwrap(), 9);
        assert!(matches!(s.changes_since(7, 10), Err(StoreError::AnchorExpired { .. })));

        // Everything that is not this cache is untouched.
        let one = |sql: &str| -> String {
            s.connection.query_row(sql, [], |row| row.get::<_, String>(0)).unwrap()
        };
        assert_eq!(one("SELECT state FROM session"), "SIGNED_IN");
        assert_eq!(one("SELECT account FROM session"), "usr_A");
        assert_eq!(s.setting("key-set").unwrap().as_deref(), Some("the vault's slot"));
        assert_eq!(one("SELECT name FROM log"), "Rechnung.pdf");
        assert_eq!(one("SELECT document FROM erased"), "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAC");
        assert_eq!(one("SELECT outcome FROM delivery"), "APPLIED");
        assert_eq!(one("SELECT file FROM ingest"), "a.pdf");
    }

    #[test]
    fn a_store_created_now_still_begins_at_sequence_zero() {
        // Migration 5 consumes a sequence number where one was ever handed out. On a database
        // that this very run has created, none was — and a first anchor of 0 has to keep meaning
        // "I have seen nothing" instead of already being expired.
        let s = Store::in_memory().unwrap();
        assert_eq!(s.current_sequence().unwrap(), 0);
        assert_eq!(s.oldest_sequence().unwrap(), 1);
        assert!(s.changes_since(0, 10).unwrap().changes.is_empty());
    }
}
