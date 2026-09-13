//! The namespace: what stands beneath the root in Explorer and in Finder.
//!
//! Requirement 3 (`ordnerclient-vorgaben.md`): **the tree shows case files (Akten) and saved
//! searches** — nothing else. Not the folder structure of the archive (`fld_…`), not the inbox.
//! Namespace v2 (owner's decision of 2026-09-12) adds the two things that were missing: the
//! archive a case file hangs in, and the mail baskets, which take over from the inbound folder
//! next to the root (ADR-D04, ADR-D08 §1 amended). From this follows the fixed shape:
//!
//! ```text
//! <root>                                  read-only
//! ├── README.txt                          hint, generated locally (de: LIESMICH.txt)
//! ├── Mailbaskets/                        baskets                (de: Briefkörbe/)
//! │   └── <basket>/                       bsk_…                  files may be put here
//! ├── Archives/                           archives               (de: Archive/)
//! │   └── <archive>/                      arc_…
//! │       └── <case file>/                arc_…/cas_…
//! │           └── <document>.pdf          arc_…/cas_…/doc_…
//! └── Saved searches/                     (de: Gespeicherte Suchen/)
//!     └── <search>/                       srch_…
//!         ├── <document>.pdf              srch_…/doc_…
//!         └── Result list truncated – README.txt   only when truncated
//! ```
//!
//! **A case file carries its archive.** [`Container::Case`] holds both identifiers, not the case
//! alone. Without the archive [`Container::parent`] could not be computed, and every layer above
//! would need a lookup table for something the identifier can say itself.
//!
//! **A basket is a trigger, not a heap.** [`Container::accepts_new_files`] is true for a basket
//! and for nothing else, and it is the only place that decides it — the platform layers ask this
//! function instead of matching on variants of their own. What is dropped there is filed by the
//! ingest rule into an archive; the basket keeps nothing.
//!
//! **One document can stand in several places** — in one case file and in two saved searches. On
//! macOS an entry has exactly one parent, so the entry identifier is the pair of location and
//! document. Whoever has to dehydrate a document dehydrates every location where it stands; that
//! is the engine's business, which knows the locations, not the platform's.
//!
//! ## The names are user text, the identifiers are not
//!
//! What stands in Explorer and in Finder is a sentence in the user's language — the three
//! container names, the two hint files, and the hint files' names as well: `README.txt` in
//! English, `LIESMICH.txt` in German. What travels over the wire and into the database is not:
//! the entry identifier stays `root`, `baskets`, `archives`, `searches`, `hint-readme`,
//! `hint-truncated` in every language, because it is a key and not a sentence. The names of
//! baskets, archives, case files and searches are server titles and are not translated either.
//!
//! The language is **handed in** ([`Language`]), never fetched here: this crate has no operating
//! system, and a core that asked for the locale would have one.

use std::fmt;
use std::str::FromStr;

use edms_i18n::{Catalog, Language, key};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::checksum::Sha256Value;
use crate::filename;
use crate::identifier::{
    ArchiveIdKind, ArchiveIdentifier, BasketIdKind, BasketIdentifier, CaseIdKind, CaseIdentifier,
    DocumentIdKind, DocumentIdentifier, Identifier, IdentifierError, Kind, SearchIdKind,
    SearchIdentifier,
};
use crate::time::Timestamp;

/// Display name of the container for the mail baskets.
pub fn name_baskets(language: Language) -> &'static str {
    Catalog::of(language).text(key::MIRROR_BASKETS)
}

/// Display name of the container for the archives, in each of which case files (Akten) stand.
pub fn name_archives(language: Language) -> &'static str {
    Catalog::of(language).text(key::MIRROR_ARCHIVES)
}

/// Display name of the container for saved searches.
pub fn name_searches(language: Language) -> &'static str {
    Catalog::of(language).text(key::MIRROR_SEARCHES)
}

/// File name of the hint in the root — `README.txt`, in German `LIESMICH.txt`.
pub fn name_read_me(language: Language) -> &'static str {
    Catalog::of(language).text(key::MIRROR_README_NAME)
}

/// File name of the hint in a truncated search.
pub fn name_truncated(language: Language) -> &'static str {
    Catalog::of(language).text(key::MIRROR_TRUNCATED_NAME)
}

/// Version of the hint texts. If the text changes, this number changes — otherwise the platform
/// would hold the old, already hydrated version for current.
///
/// `hint-2`, because the texts moved into the catalogue and the language became part of them; a
/// mirror from the previous version has to fetch them afresh. The language stands in the version
/// as well ([`hint`]): otherwise a client switched from German to English would keep the German
/// file, because two texts of the same length look the same to the platform.
pub const HINT_VERSION: &str = "hint-2";

/// A place that holds entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Container {
    /// The root of the mirror.
    Root,
    /// The mail baskets.
    Baskets,
    /// One mail basket — the only container new files may be put into.
    Basket(BasketIdentifier),
    /// The archives.
    Archives,
    /// One archive.
    Archive(ArchiveIdentifier),
    /// One case file (Akte) in the archive it stands in.
    Case {
        /// The archive that holds it.
        archive: ArchiveIdentifier,
        /// Which case file.
        case: CaseIdentifier,
    },
    /// The saved searches.
    Searches,
    /// One saved search.
    Search(SearchIdentifier),
}

/// A place where documents can stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Location {
    /// In a case file (Akte) of an archive.
    Case {
        /// The archive that holds the case file.
        archive: ArchiveIdentifier,
        /// Which case file.
        case: CaseIdentifier,
    },
    /// In the result list of a saved search.
    Search(SearchIdentifier),
}

/// The locally generated hint files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HintKind {
    /// Explains the mirror; the only place that carries „Anheften ist keine Zusicherung" —
    /// pinning is no guarantee — when the platform reports no pin moment (requirement, section
    /// "Angeheftete Dateien" — pinned files).
    ReadMe,
    /// Explains that a result list was cut short.
    Truncated,
}

/// The identifier of an entry in the mirror. Stable across renames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntryIdentifier {
    /// A container.
    Container(Container),
    /// A document at a location.
    Document {
        /// Where it stands.
        location: Location,
        /// Which document.
        document: DocumentIdentifier,
    },
    /// A locally generated hint file.
    Hint {
        /// Where it stands.
        location: Container,
        /// Which hint.
        kind: HintKind,
    },
}

impl Container {
    /// The parent container; the root has none.
    pub const fn parent(self) -> Option<Container> {
        match self {
            Self::Root => None,
            Self::Baskets | Self::Archives | Self::Searches => Some(Self::Root),
            Self::Basket(_) => Some(Self::Baskets),
            Self::Archive(_) => Some(Self::Archives),
            Self::Case { archive, .. } => Some(Self::Archive(archive)),
            Self::Search(_) => Some(Self::Searches),
        }
    }

    /// Whether this container's content comes from the server and changes without anyone acting.
    ///
    /// Root and the three fixed containers have a shape of their own apart from their child
    /// listing; baskets, archives, case files and searches are the requirements' “dynamic
    /// folders”, whose content the client has to report to the operating system continuously.
    pub const fn is_dynamic(self) -> bool {
        !matches!(self, Self::Root)
    }

    /// Whether a new file may be created in this container.
    ///
    /// A basket and nothing else. **This is the only place that decides it**: the platform layers
    /// ask here instead of matching on variants, so that a container added later cannot become
    /// writable in one layer and read-only in the other. Inside a basket the platform takes a
    /// file creation and nothing further — no rename, no deletion, no folder, no write to an
    /// entry that is already there (namespace v2 §3).
    pub const fn accepts_new_files(self) -> bool {
        matches!(self, Self::Basket(_))
    }

    /// The location, if documents can stand in this container.
    const fn location(self) -> Option<Location> {
        match self {
            Self::Case { archive, case } => Some(Location::Case { archive, case }),
            Self::Search(k) => Some(Location::Search(k)),
            _ => None,
        }
    }
}

impl From<Location> for Container {
    fn from(location: Location) -> Self {
        match location {
            Location::Case { archive, case } => Self::Case { archive, case },
            Location::Search(k) => Self::Search(k),
        }
    }
}

impl EntryIdentifier {
    /// The root.
    pub const ROOT: Self = Self::Container(Container::Root);

    /// The parent container; only the root has none.
    pub const fn parent(self) -> Option<Container> {
        match self {
            Self::Container(b) => b.parent(),
            Self::Document { location: Location::Case { archive, case }, .. } => {
                Some(Container::Case { archive, case })
            }
            Self::Document { location: Location::Search(k), .. } => Some(Container::Search(k)),
            Self::Hint { location, .. } => Some(location),
        }
    }

    /// The document behind this entry, if it is one.
    pub const fn document(self) -> Option<DocumentIdentifier> {
        match self {
            Self::Document { document, .. } => Some(document),
            _ => None,
        }
    }

    /// The container, if this entry is one.
    pub const fn container(self) -> Option<Container> {
        match self {
            Self::Container(b) => Some(b),
            _ => None,
        }
    }
}

/// Why a string is not an entry identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryIdentifierError {
    /// The shape matches no kind of entry. A technical value, never a sentence for a user: it
    /// names a malformed identifier, and an identifier is not user text.
    #[error("`{0}` is not an entry identifier of the folder client")]
    Shape(String),
    /// One part is not a valid identifier.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
}

const TEXT_ROOT: &str = "root";
const TEXT_BASKETS: &str = "baskets";
const TEXT_ARCHIVES: &str = "archives";
const TEXT_SEARCHES: &str = "searches";
const TEXT_HINT_READ_ME: &str = "hint-readme";
const TEXT_HINT_TRUNCATED: &str = "hint-truncated";

/// Whether the text begins with the wire prefix of kind `A` and its underscore.
///
/// The underscore is what separates a prefix from a word: `archives` begins with `arc` and is the
/// container, `arc_…` is one archive.
fn carries_prefix<A: Kind>(text: &str) -> bool {
    text.strip_prefix(A::PREFIX).is_some_and(|rest| rest.starts_with('_'))
}

impl fmt::Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str(TEXT_ROOT),
            Self::Baskets => f.write_str(TEXT_BASKETS),
            Self::Archives => f.write_str(TEXT_ARCHIVES),
            Self::Searches => f.write_str(TEXT_SEARCHES),
            Self::Basket(k) => write!(f, "{k}"),
            Self::Archive(k) => write!(f, "{k}"),
            Self::Case { archive, case } => write!(f, "{archive}/{case}"),
            Self::Search(k) => write!(f, "{k}"),
        }
    }
}

impl FromStr for Container {
    type Err = EntryIdentifierError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // A case file is the only container of two segments, and both of them are spoken for: a
        // bare `cas_…` from the tree before namespace v2 falls through to the shape error below
        // instead of being read as a case file whose archive nobody knows.
        if let Some((archive, case)) = text.split_once('/') {
            if carries_prefix::<ArchiveIdKind>(archive)
                && carries_prefix::<CaseIdKind>(case)
                && !case.contains('/')
            {
                return Ok(Self::Case { archive: archive.parse()?, case: case.parse()? });
            }
            return Err(EntryIdentifierError::Shape(text.to_owned()));
        }
        Ok(match text {
            TEXT_ROOT => Self::Root,
            TEXT_BASKETS => Self::Baskets,
            TEXT_ARCHIVES => Self::Archives,
            TEXT_SEARCHES => Self::Searches,
            _ if carries_prefix::<BasketIdKind>(text) => Self::Basket(text.parse()?),
            _ if carries_prefix::<ArchiveIdKind>(text) => Self::Archive(text.parse()?),
            _ if carries_prefix::<SearchIdKind>(text) => Self::Search(text.parse()?),
            _ => return Err(EntryIdentifierError::Shape(text.to_owned())),
        })
    }
}

impl fmt::Display for EntryIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Container(b) => write!(f, "{b}"),
            Self::Document { location, document } => {
                write!(f, "{}/{document}", Container::from(*location))
            }
            Self::Hint { location, kind: HintKind::ReadMe } => {
                write!(f, "{location}/{TEXT_HINT_READ_ME}")
            }
            Self::Hint { location, kind: HintKind::Truncated } => {
                write!(f, "{location}/{TEXT_HINT_TRUNCATED}")
            }
        }
    }
}

impl FromStr for EntryIdentifier {
    type Err = EntryIdentifierError;

    /// One to three segments. The last one decides: a hint marker, a document, or nothing of the
    /// two — then the whole text is a container, which since namespace v2 may itself be two
    /// segments long.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((front, back)) = text.rsplit_once('/') else {
            return Ok(Self::Container(text.parse()?));
        };
        match back {
            TEXT_HINT_READ_ME => {
                Ok(Self::Hint { location: front.parse()?, kind: HintKind::ReadMe })
            }
            TEXT_HINT_TRUNCATED => {
                Ok(Self::Hint { location: front.parse()?, kind: HintKind::Truncated })
            }
            _ if carries_prefix::<DocumentIdKind>(back) => {
                let location = front
                    .parse::<Container>()?
                    .location()
                    .ok_or_else(|| EntryIdentifierError::Shape(text.to_owned()))?;
                Ok(Self::Document { location, document: back.parse()? })
            }
            _ => Ok(Self::Container(text.parse()?)),
        }
    }
}

macro_rules! serde_as_text {
    ($typ:ty) => {
        impl Serialize for $typ {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $typ {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}
serde_as_text!(Container);
serde_as_text!(EntryIdentifier);

/// An entry in the mirror, fully named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Stable identifier.
    pub identifier: EntryIdentifier,
    /// The file name as it stands in Explorer/Finder — sanitized and free of collisions.
    pub name: String,
    /// Folder or file.
    pub content: EntryContent,
}

/// Whether an entry is a folder or a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryContent {
    /// A folder.
    Folder,
    /// A file.
    File(FileDetails),
}

/// What the platform has to know about a file before it is opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDetails {
    /// Size in bytes; the placeholder carries it before a single byte is loaded.
    pub size: u64,
    /// Expected checksum of the content. `None` only for locally generated hints.
    pub sha256: Option<Sha256Value>,
    /// The server's version marker. If it changes, the local content is stale.
    pub version: String,
    /// Created.
    pub created: Timestamp,
    /// Last changed.
    pub changed: Timestamp,
    /// Media type, e.g. `application/pdf`.
    pub media_type: String,
}

impl Entry {
    /// Whether it is a folder.
    pub const fn is_folder(&self) -> bool {
        matches!(self.content, EntryContent::Folder)
    }

    /// The file details, if it is a file.
    pub const fn file(&self) -> Option<&FileDetails> {
        match &self.content {
            EntryContent::File(d) => Some(d),
            EntryContent::Folder => None,
        }
    }
}

/// A document as the server lists it for a location — still without a file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentItem {
    /// Which document.
    pub document: DocumentIdentifier,
    /// Title, free text from the server.
    pub title: String,
    /// Media type of the rendition the client gets (never the original record, Q-13).
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Checksum of the rendition.
    pub sha256: Sha256Value,
    /// Version marker.
    pub version: String,
    /// Created.
    pub created: Timestamp,
    /// Last changed.
    pub changed: Timestamp,
}

/// A basket, an archive, a case file (Akte) or a saved search as the server lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerItem<K> {
    /// Identifier.
    pub identifier: K,
    /// Title, free text from the server.
    pub title: String,
}

/// The fixed children of the root, named in `language`.
pub fn root_entries(language: Language) -> Vec<Entry> {
    vec![
        folder(EntryIdentifier::Container(Container::Baskets), name_baskets(language)),
        folder(EntryIdentifier::Container(Container::Archives), name_archives(language)),
        folder(EntryIdentifier::Container(Container::Searches), name_searches(language)),
        hint(Container::Root, HintKind::ReadMe, &hint_text_read_me(language), language),
    ]
}

/// The children of the basket container: one folder per mail basket, named free of collisions.
/// The titles come from the server and are not translated.
pub fn baskets_entries(baskets: &[ContainerItem<BasketIdentifier>]) -> Vec<Entry> {
    container_entries(baskets, Container::Basket)
}

/// The children of the archive container: one folder per archive.
pub fn archives_entries(archives: &[ContainerItem<ArchiveIdentifier>]) -> Vec<Entry> {
    container_entries(archives, Container::Archive)
}

/// The children of **one** archive: its case files (Akten). The archive is handed in because a
/// case file is only ever named together with it — see [`Container::Case`].
pub fn cases_entries(
    archive: ArchiveIdentifier,
    cases: &[ContainerItem<CaseIdentifier>],
) -> Vec<Entry> {
    container_entries(cases, |case| Container::Case { archive, case })
}

/// The children of the search container: one folder per saved search.
pub fn searches_entries(searches: &[ContainerItem<SearchIdentifier>]) -> Vec<Entry> {
    container_entries(searches, Container::Search)
}

/// One folder per item, named free of collisions in the order the server delivered them.
fn container_entries<A: Kind>(
    item: &[ContainerItem<Identifier<A>>],
    container: impl Fn(Identifier<A>) -> Container,
) -> Vec<Entry> {
    let names = filename::name(
        item.iter().map(|x| filename::RawName::folder(&x.title, x.identifier.short_form())),
        &[],
    );
    item.iter()
        .zip(names)
        .map(|(x, name)| folder(EntryIdentifier::Container(container(x.identifier)), &name))
        .collect()
}

/// The children of a case file or a search.
///
/// Duplicate documents (the same server item twice in one answer) collapse into one: a location
/// can hold a document only once, and two entries with the same identifier would be a program
/// fault for both platforms. If the listing is `truncated`, the hint comes along; its name is
/// reserved, and a document of the same name gives way.
pub fn document_entries(
    location: Location,
    item: &[DocumentItem],
    truncated: Option<Truncation<'_>>,
    language: Language,
) -> Vec<Entry> {
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<&DocumentItem> = item.iter().filter(|p| seen.insert(p.document)).collect();
    let reserved: &[&str] = if truncated.is_some() { &[name_truncated(language)] } else { &[] };
    let names = filename::name(
        unique
            .iter()
            .map(|p| filename::RawName::file(&p.title, &p.media_type, p.document.short_form())),
        reserved,
    );
    let mut entries: Vec<Entry> = unique
        .iter()
        .zip(names)
        .map(|(p, name)| Entry {
            identifier: EntryIdentifier::Document { location, document: p.document },
            name,
            content: EntryContent::File(FileDetails {
                size: p.size,
                sha256: Some(p.sha256),
                version: p.version.clone(),
                created: p.created,
                changed: p.changed,
                media_type: p.media_type.clone(),
            }),
        })
        .collect();
    if let Some(truncation) = truncated {
        entries.push(hint(
            location.into(),
            HintKind::Truncated,
            &hint_text_truncated(truncation, language),
            language,
        ));
    }
    entries
}

/// Why and where a result list was cut short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncation<'a> {
    /// How many hits the folder shows.
    pub displayed: u64,
    /// Where the search can be refined in the browser.
    pub address: Option<&'a str>,
}

/// The text of the hint in the root, in `language`.
///
/// Line endings are CRLF: the editor on Windows shows LF correctly by now, older viewers do not,
/// and TextEdit reads CRLF without complaint. One line of effort, no phone call. The catalogue
/// keeps the text with plain line breaks — where the lines are joined is a decision about
/// Windows, not about German.
pub fn hint_text_read_me(language: Language) -> String {
    crlf(Catalog::of(language).text(key::MIRROR_README_BODY))
}

/// The text of the hint in a truncated search, in `language`.
pub fn hint_text_truncated(truncation: Truncation<'_>, language: Language) -> String {
    let count = truncation.displayed.to_string();
    let mut text =
        crlf(&Catalog::of(language).format(key::MIRROR_TRUNCATED_BODY, &[("count", &count)]));
    // The address is not a sentence and stands on a line of its own; the catalogue would only be
    // able to wrap it in one language.
    if let Some(address) = truncation.address {
        text.push_str(address);
        text.push_str("\r\n");
    }
    text
}

/// Line endings for a text file that has to open on Windows too.
fn crlf(text: &str) -> String {
    text.replace('\n', "\r\n")
}

fn folder(identifier: EntryIdentifier, name: &str) -> Entry {
    Entry { identifier, name: name.to_owned(), content: EntryContent::Folder }
}

fn hint(location: Container, kind: HintKind, text: &str, language: Language) -> Entry {
    let name = match kind {
        HintKind::ReadMe => name_read_me(language),
        HintKind::Truncated => name_truncated(language),
    };
    Entry {
        identifier: EntryIdentifier::Hint { location, kind },
        name: name.to_owned(),
        content: EntryContent::File(FileDetails {
            size: text.len() as u64,
            sha256: None,
            // The language belongs in the version: two texts of the same length in two languages
            // would otherwise look identical to the platform, and the mirror would keep the old
            // one after a language change.
            version: format!("{HINT_VERSION}-{}-{}", language.tag(), text.len()),
            created: Timestamp::NULL,
            changed: Timestamp::NULL,
            media_type: "text/plain; charset=utf-8".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Identifier;

    const ARCHIVE: ArchiveIdentifier = Identifier::from_value(41);
    const CASE: CaseIdentifier = Identifier::from_value(42);
    const SEARCH: SearchIdentifier = Identifier::from_value(43);
    const BASKET: BasketIdentifier = Identifier::from_value(44);

    fn doc(value: u128) -> DocumentIdentifier {
        Identifier::from_value(value)
    }

    /// Every container the tree knows, each exactly once — the list the checks below walk.
    ///
    /// The match without a wildcard is what keeps the list complete: a variant added later makes
    /// this function red until it stands here too, and with it in every check that walks it.
    fn every_container() -> [Container; 8] {
        let all = [
            Container::Root,
            Container::Baskets,
            Container::Basket(BASKET),
            Container::Archives,
            Container::Archive(ARCHIVE),
            Container::Case { archive: ARCHIVE, case: CASE },
            Container::Searches,
            Container::Search(SEARCH),
        ];
        for container in all {
            match container {
                Container::Root
                | Container::Baskets
                | Container::Basket(_)
                | Container::Archives
                | Container::Archive(_)
                | Container::Case { .. }
                | Container::Searches
                | Container::Search(_) => {}
            }
        }
        all
    }

    fn item(value: u128, title: &str) -> DocumentItem {
        DocumentItem {
            document: doc(value),
            title: title.to_owned(),
            media_type: "application/pdf".to_owned(),
            size: 1_024,
            sha256: Sha256Value::from_bytes([7; 32]),
            version: "1-abc".to_owned(),
            created: Timestamp::NULL,
            changed: Timestamp::NULL,
        }
    }

    #[test]
    fn every_entry_identifier_survives_the_round_trip_as_text() {
        let mut all: Vec<EntryIdentifier> =
            every_container().into_iter().map(EntryIdentifier::Container).collect();
        all.extend([
            EntryIdentifier::Document {
                location: Location::Case { archive: ARCHIVE, case: CASE },
                document: doc(1),
            },
            EntryIdentifier::Document { location: Location::Search(SEARCH), document: doc(1) },
            EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe },
            EntryIdentifier::Hint {
                location: Container::Search(SEARCH),
                kind: HintKind::Truncated,
            },
        ]);
        assert_eq!(all.len(), 12);
        for k in all {
            let text = k.to_string();
            assert_eq!(text.parse::<EntryIdentifier>().unwrap(), k, "{text}");
        }
    }

    #[test]
    fn the_text_forms_are_the_ones_the_wire_and_the_store_carry() {
        // The table of namespace v2 §2, literally. These strings stand in the change journal and
        // in the store; a silent change of shape here would be a migration nobody wrote.
        let archive = ARCHIVE.to_string();
        let case = CASE.to_string();
        let of = |k: Container| EntryIdentifier::Container(k).to_string();
        assert_eq!(of(Container::Root), "root");
        assert_eq!(of(Container::Baskets), "baskets");
        assert_eq!(of(Container::Basket(BASKET)), BASKET.to_string());
        assert_eq!(of(Container::Archives), "archives");
        assert_eq!(of(Container::Archive(ARCHIVE)), archive);
        assert_eq!(
            of(Container::Case { archive: ARCHIVE, case: CASE }),
            format!("{archive}/{case}")
        );
        assert_eq!(of(Container::Searches), "searches");
        assert_eq!(of(Container::Search(SEARCH)), SEARCH.to_string());
        assert_eq!(
            EntryIdentifier::Document {
                location: Location::Case { archive: ARCHIVE, case: CASE },
                document: doc(1),
            }
            .to_string(),
            format!("{archive}/{case}/{}", doc(1))
        );
        assert_eq!(
            EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe }.to_string(),
            "root/hint-readme"
        );
    }

    #[test]
    fn the_tree_before_namespace_v2_is_rejected_and_not_reinterpreted() {
        // A stored identifier of the old shape is an error, not a guess: `cases` has no place in
        // the new tree, and a bare case file would be one whose archive nobody knows.
        for old in [
            "cases".to_owned(),
            CASE.to_string(),
            format!("cases/{CASE}"),
            format!("{CASE}/{}", doc(1)),
        ] {
            let error = old.parse::<EntryIdentifier>().unwrap_err();
            let EntryIdentifierError::Shape(ref named) = error else {
                panic!("`{old}` should have been a shape error, was {error:?}");
            };
            // The error names the segment it stumbled over, and that segment comes from the
            // input — a message that invents a text is one nobody can trace back.
            assert!(old.contains(named.as_str()), "`{named}` does not stand in `{old}`");
        }
    }

    #[test]
    fn a_document_directly_under_a_fixed_container_is_not_a_valid_identifier() {
        for container in [Container::Root, Container::Baskets, Container::Archives] {
            let text = format!("{container}/{}", doc(1));
            assert!(text.parse::<EntryIdentifier>().is_err(), "{text}");
        }
    }

    #[test]
    fn only_a_basket_accepts_new_files() {
        // Requirement 2: a basket is the trigger for an ingest. Everywhere else the mirror is a
        // view, and the platform layers read that decision here instead of making their own.
        let accepting: Vec<Container> =
            every_container().into_iter().filter(|b| b.accepts_new_files()).collect();
        assert_eq!(accepting, [Container::Basket(BASKET)]);
        assert_eq!(every_container().len() - accepting.len(), 7);
    }

    #[test]
    fn the_parents_yield_the_fixed_tree() {
        let case = Container::Case { archive: ARCHIVE, case: CASE };
        let d = EntryIdentifier::Document {
            location: Location::Case { archive: ARCHIVE, case: CASE },
            document: doc(1),
        };
        assert_eq!(d.parent(), Some(case));
        assert_eq!(case.parent(), Some(Container::Archive(ARCHIVE)));
        assert_eq!(Container::Archive(ARCHIVE).parent(), Some(Container::Archives));
        assert_eq!(Container::Basket(BASKET).parent(), Some(Container::Baskets));
        assert_eq!(Container::Search(SEARCH).parent(), Some(Container::Searches));
        for top in [Container::Baskets, Container::Archives, Container::Searches] {
            assert_eq!(top.parent(), Some(Container::Root), "{top}");
        }
        assert_eq!(EntryIdentifier::ROOT.parent(), None);
    }

    #[test]
    fn every_container_of_the_tree_is_reachable_from_the_root() {
        // Walking up has to arrive, not circle: each container's chain of parents ends at the
        // root, and the root is the only one without a parent.
        for container in every_container() {
            let mut walk = container;
            let mut steps = 0;
            while let Some(parent) = walk.parent() {
                walk = parent;
                steps += 1;
                assert!(steps <= 3, "{container} does not arrive at the root");
            }
            assert_eq!(walk, Container::Root, "{container}");
        }
    }

    #[test]
    fn one_archive_names_the_case_files_that_stand_in_it() {
        let cases = [
            ContainerItem { identifier: CASE, title: "Mustermann".to_owned() },
            ContainerItem {
                identifier: Identifier::from_value(99),
                title: "Mustermann".to_owned(),
            },
        ];
        let entries = cases_entries(ARCHIVE, &cases);
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            assert_eq!(entry.identifier.parent(), Some(Container::Archive(ARCHIVE)));
            assert!(entry.is_folder());
        }
        // Two case files of the same title keep two folders apart (`filename::name`).
        assert_ne!(entries[0].name, entries[1].name);
    }

    #[test]
    fn an_item_delivered_twice_stands_only_once_in_the_folder() {
        let case = Location::Case { archive: ARCHIVE, case: CASE };
        let e =
            document_entries(case, &[item(1, "Rechnung"), item(1, "Rechnung")], None, Language::De);
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn a_truncated_search_gets_the_hint_and_a_document_of_the_same_name_gives_way() {
        for language in Language::ALL {
            let search = Location::Search(SEARCH);
            let reserved = name_truncated(language);
            let title = reserved.trim_end_matches(".txt");
            let mut p = item(1, title);
            p.media_type = "text/plain".to_owned();
            let e = document_entries(
                search,
                &[p],
                Some(Truncation { displayed: 5_000, address: None }),
                language,
            );
            assert_eq!(e.len(), 2, "{language}");
            let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
            assert!(names.contains(&reserved), "{language}: {names:?}");
            assert!(names.iter().filter(|n| **n == reserved).count() == 1, "{language}: {names:?}");
        }
    }

    #[test]
    fn the_size_of_the_hint_is_the_size_of_its_text() {
        for language in Language::ALL {
            let readme = root_entries(language)
                .into_iter()
                .find(|e| e.name == name_read_me(language))
                .unwrap();
            assert_eq!(
                readme.file().unwrap().size,
                hint_text_read_me(language).len() as u64,
                "{language}"
            );
        }
    }

    #[test]
    fn the_mirror_is_named_in_the_language_that_is_handed_in() {
        // The whole point of the parameter: the same tree, two languages, and not a word of the
        // one in the other.
        let german: Vec<String> = root_entries(Language::De).into_iter().map(|e| e.name).collect();
        let english: Vec<String> = root_entries(Language::En).into_iter().map(|e| e.name).collect();
        assert_eq!(german, ["Briefkörbe", "Archive", "Gespeicherte Suchen", "LIESMICH.txt"]);
        assert_eq!(english, ["Mailbaskets", "Archives", "Saved searches", "README.txt"]);
    }

    #[test]
    fn the_hint_text_ends_every_line_with_crlf_and_names_the_count() {
        for language in Language::ALL {
            let readme = hint_text_read_me(language);
            assert!(readme.contains("\r\n"), "{language}");
            assert!(!readme.contains("\n\n"), "{language}: a lone LF stayed behind");
            let truncated = hint_text_truncated(
                Truncation { displayed: 5_000, address: Some("https://app.example/s/7") },
                language,
            );
            assert!(truncated.contains("5000"), "{language}: {truncated}");
            assert!(truncated.contains("https://app.example/s/7"), "{language}");
            assert!(truncated.ends_with("\r\n"), "{language}");
        }
    }

    #[test]
    fn the_version_of_a_hint_changes_with_the_language() {
        // Without the language in the version the platform would hold a German hint of the same
        // length for the current English one — and nobody would see why the file stays German.
        let of = |language| {
            root_entries(language)
                .into_iter()
                .find(|e| !e.is_folder())
                .and_then(|e| e.file().map(|f| f.version.clone()))
                .unwrap()
        };
        assert_ne!(of(Language::De), of(Language::En));
        assert!(of(Language::De).starts_with("hint-2-de-"), "{}", of(Language::De));
    }
}
