//! Building blocks for the tests: real entries from the core's builders instead of hand-built
//! ones, so that the tests see the same names, short forms and hints as the engine.

use edms_core::change::{Change, JournalEntry};
use edms_core::checksum::Sha256Value;
use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, DocumentIdentifier, Identifier,
    SearchIdentifier,
};
use edms_core::namespace::{
    Container, ContainerItem, DocumentItem, Entry, Location, archives_entries, baskets_entries,
    cases_entries, document_entries, root_entries, searches_entries,
};
use edms_core::time::Timestamp;
use edms_i18n::Language;

use crate::{ContainerState, Store};

/// The language of the test fixtures. German, because that is what the tests' expected names were
/// written against — which language it is does not matter here, only that it is one and the same.
pub(crate) const LANGUAGE: Language = Language::De;

/// Value of the archive every case file (Akte) of the fixtures hangs in. Since namespace v2 a case
/// file is named only together with its archive; one archive is enough here, because what the
/// tests are about is the listing of a container and not which archive holds it. A number far away
/// from the small ones of cases, searches and documents, so that a failed assertion says at once
/// which identifier it is looking at.
const ARCHIVE: u128 = 100;

/// Title of the fixtures' archive — distinctive, so that a check for "is this name gone?" can look
/// for it.
pub(crate) const ARCHIVE_TITLE: &str = "Vertragsarchiv";

pub(crate) fn store() -> Store {
    Store::in_memory().unwrap()
}

pub(crate) fn time(millis: i64) -> Timestamp {
    Timestamp::from_unix_millis(millis)
}

pub(crate) fn state(millis: i64) -> ContainerState {
    ContainerState { etag: None, fetched: time(millis), truncation: None }
}

/// The one archive of the fixtures, the one [`scaffold`] puts up.
pub(crate) fn archive() -> ArchiveIdentifier {
    Identifier::from_value(ARCHIVE)
}

pub(crate) fn basket(value: u128) -> BasketIdentifier {
    Identifier::from_value(value)
}

pub(crate) fn case(value: u128) -> CaseIdentifier {
    Identifier::from_value(value)
}

pub(crate) fn search(value: u128) -> SearchIdentifier {
    Identifier::from_value(value)
}

pub(crate) fn doc(value: u128) -> DocumentIdentifier {
    Identifier::from_value(value)
}

/// The case file `value` in the fixtures' archive.
pub(crate) fn case_container(value: u128) -> Container {
    Container::Case { archive: archive(), case: case(value) }
}

pub(crate) fn item(value: u128, title: &str, version: &str) -> DocumentItem {
    DocumentItem {
        document: doc(value),
        title: title.to_owned(),
        media_type: "application/pdf".to_owned(),
        size: 1_024,
        sha256: Sha256Value::from_bytes([u8::try_from(value % 256).unwrap(); 32]),
        version: version.to_owned(),
        created: time(1_000),
        changed: time(2_000),
    }
}

pub(crate) fn in_case(value: u128, item: &[DocumentItem]) -> Vec<Entry> {
    let location = Location::Case { archive: archive(), case: case(value) };
    document_entries(location, item, None, LANGUAGE)
}

pub(crate) fn in_search(value: u128, item: &[DocumentItem]) -> Vec<Entry> {
    document_entries(Location::Search(search(value)), item, None, LANGUAGE)
}

pub(crate) fn baskets_list(baskets: &[(u128, &str)]) -> Vec<Entry> {
    let item: Vec<ContainerItem<BasketIdentifier>> = baskets
        .iter()
        .map(|&(value, title)| ContainerItem { identifier: basket(value), title: title.to_owned() })
        .collect();
    baskets_entries(&item)
}

fn archives_list(archives: &[(ArchiveIdentifier, &str)]) -> Vec<Entry> {
    let item: Vec<ContainerItem<ArchiveIdentifier>> = archives
        .iter()
        .map(|&(identifier, title)| ContainerItem { identifier, title: title.to_owned() })
        .collect();
    archives_entries(&item)
}

/// The case files of the fixtures' archive; they carry it, and nothing else could name them.
pub(crate) fn cases_list(cases: &[(u128, &str)]) -> Vec<Entry> {
    let item: Vec<ContainerItem<CaseIdentifier>> = cases
        .iter()
        .map(|&(value, title)| ContainerItem { identifier: case(value), title: title.to_owned() })
        .collect();
    cases_entries(archive(), &item)
}

pub(crate) fn searches_list(searches: &[(u128, &str)]) -> Vec<Entry> {
    let item: Vec<ContainerItem<SearchIdentifier>> = searches
        .iter()
        .map(|&(value, title)| ContainerItem { identifier: search(value), title: title.to_owned() })
        .collect();
    searches_entries(&item)
}

/// Root, the archive container with the one archive of the fixtures, that archive's case files and
/// the saved searches — the substructure without which a case file (Akte) is unknown.
///
/// The basket container stays unfetched: nothing of the server stands in a basket (namespace v2
/// §4), and the tests that are about baskets list them themselves.
pub(crate) fn scaffold(s: &mut Store, cases: &[(u128, &str)], searches: &[(u128, &str)]) {
    s.replace_container(Container::Root, &root_entries(LANGUAGE), &state(1)).unwrap();
    s.replace_container(
        Container::Archives,
        &archives_list(&[(archive(), ARCHIVE_TITLE)]),
        &state(1),
    )
    .unwrap();
    s.replace_container(Container::Archive(archive()), &cases_list(cases), &state(1)).unwrap();
    s.replace_container(Container::Searches, &searches_list(searches), &state(1)).unwrap();
}

pub(crate) fn changes(entries: &[JournalEntry]) -> Vec<Change> {
    entries.iter().map(|e| e.change.clone()).collect()
}

pub(crate) fn sequences(entries: &[JournalEntry]) -> Vec<u64> {
    entries.iter().map(|e| e.sequence).collect()
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|chunk| chunk == needle)
}
