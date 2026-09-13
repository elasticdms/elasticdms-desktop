//! Test harness: a mock of the namespace source, and observers that write everything down.
//!
//! The extension is tested in the same process, through the same Objective-C calls the system
//! makes — only that the source is a mock and the observers are Rust classes that record every
//! message. No call here registers a domain: that would be an intervention into the machine the
//! tests run on.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use edms_core::change::{Change, ChangeState, JournalEntry};
use edms_core::checksum::Sha256Value;
use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, DocumentIdentifier, Identifier,
    SearchIdentifier,
};
use edms_core::namespace::{
    Container, ContainerItem, DocumentItem, Entry, EntryIdentifier, Location, Truncation,
    archives_entries, baskets_entries, cases_entries, document_entries, root_entries,
    searches_entries,
};
use edms_core::port::{ContentReceipt, ContentRequest, ContentSink, NamespaceSource, SourceError};
use edms_core::time::Timestamp;
use edms_i18n::Language;
/// The language of the fixtures: which one it is does not matter, only that it is one and the
/// same everywhere in this harness.
const LANGUAGE: Language = Language::De;

use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, DefinedClass, define_class, msg_send};
use objc2_file_provider::{
    NSFileProviderChangeObserver, NSFileProviderEnumerationObserver, NSFileProviderItemProtocol,
};
use objc2_foundation::{NSArray, NSData, NSError, NSInteger, NSString};

/// Content of document 10 (21 bytes, as announced in the listing).
pub(crate) const CONTENT_10: &[u8] = b"%PDF-1.7 Pruefbericht";

pub(crate) fn case_1() -> CaseIdentifier {
    Identifier::from_value(1)
}
pub(crate) fn case_2() -> CaseIdentifier {
    Identifier::from_value(2)
}
pub(crate) fn search_3() -> SearchIdentifier {
    Identifier::from_value(3)
}
pub(crate) fn basket_4() -> BasketIdentifier {
    Identifier::from_value(4)
}
pub(crate) fn archive_5() -> ArchiveIdentifier {
    Identifier::from_value(5)
}
/// The case file both documents stand in — a case file is only ever named with its archive
/// (namespace v2 §1).
pub(crate) fn case_file_1() -> Container {
    Container::Case { archive: archive_5(), case: case_1() }
}
/// The empty case file in the same archive.
pub(crate) fn case_file_2() -> Container {
    Container::Case { archive: archive_5(), case: case_2() }
}
fn doc(value: u128) -> DocumentIdentifier {
    Identifier::from_value(value)
}
fn in_case_file_1(value: u128) -> EntryIdentifier {
    EntryIdentifier::Document {
        location: Location::Case { archive: archive_5(), case: case_1() },
        document: doc(value),
    }
}
pub(crate) fn document_10() -> EntryIdentifier {
    in_case_file_1(10)
}
pub(crate) fn document_11() -> EntryIdentifier {
    in_case_file_1(11)
}
pub(crate) fn document_12() -> EntryIdentifier {
    in_case_file_1(12)
}

fn item(value: u128, title: &str, size: u64) -> DocumentItem {
    DocumentItem {
        document: doc(value),
        title: title.to_owned(),
        media_type: "application/pdf".to_owned(),
        size,
        sha256: Sha256Value::from_bytes([7; 32]),
        version: "1-abc".to_owned(),
        created: Timestamp::from_unix_millis(1_788_334_692_118),
        changed: Timestamp::from_unix_millis(1_788_334_700_000),
    }
}

/// A namespace source built from fixed listings and a fixed journal.
pub(crate) struct MockSource {
    children: Mutex<BTreeMap<Container, Result<Vec<Entry>, SourceError>>>,
    pub(crate) journal: Vec<JournalEntry>,
    /// Oldest sequence number from which the journal still gives an answer.
    pub(crate) journal_beginning: u64,
    /// Reports `more` without delivering anything (a broken engine).
    pub(crate) promises_more_without_delivering: bool,
    pub(crate) contents: HashMap<EntryIdentifier, Vec<u8>>,
    pub(crate) content_error: Option<SourceError>,
    /// Every call fails with this (not signed in, no network …).
    pub(crate) every_call_fails: Option<SourceError>,
    pub(crate) requests: Mutex<Vec<ContentRequest>>,
    pub(crate) calls: AtomicUsize,
}

/// The sample tree: one mail basket, one archive with two case files (Akten, one empty), one
/// truncated search, a journal with four sequences.
pub(crate) fn sample_source() -> MockSource {
    let mut children = BTreeMap::new();
    children.insert(Container::Root, Ok(root_entries(LANGUAGE)));
    children.insert(
        Container::Baskets,
        Ok(baskets_entries(&[ContainerItem {
            identifier: basket_4(),
            title: "Briefkorb Buchhaltung".into(),
        }])),
    );
    // A basket holds no documents: what is filed lands in an archive (namespace v2 §4).
    children.insert(Container::Basket(basket_4()), Ok(Vec::new()));
    children.insert(
        Container::Archives,
        Ok(archives_entries(&[ContainerItem {
            identifier: archive_5(),
            title: "Zentralarchiv".into(),
        }])),
    );
    children.insert(
        Container::Archive(archive_5()),
        Ok(cases_entries(
            archive_5(),
            &[
                ContainerItem {
                    identifier: case_1(),
                    title: "Sulzer Pumpen – Wartungsvertrag 2026".into(),
                },
                ContainerItem { identifier: case_2(), title: "Personal".into() },
            ],
        )),
    );
    children.insert(
        Container::Searches,
        Ok(searches_entries(&[ContainerItem {
            identifier: search_3(),
            title: "Offene Rechnungen über 10.000 €".into(),
        }])),
    );
    let case_1_list = document_entries(
        Location::Case { archive: archive_5(), case: case_1() },
        &[
            item(10, "Prüfbericht Pumpe 7", 21),
            item(11, "Rechnung 2026/0412", 5),
            item(12, "Lieferschein", 7),
        ],
        None,
        LANGUAGE,
    );
    children.insert(case_file_1(), Ok(case_1_list.clone()));
    children.insert(case_file_2(), Ok(Vec::new()));
    children.insert(
        Container::Search(search_3()),
        Ok(document_entries(
            Location::Search(search_3()),
            &[item(10, "Prüfbericht Pumpe 7", 21)],
            Some(Truncation { displayed: 1, address: None }),
            LANGUAGE,
        )),
    );

    let find = |identifier: EntryIdentifier| -> Entry {
        case_1_list
            .iter()
            .find(|e| e.identifier == identifier)
            .cloned()
            .unwrap_or_else(|| panic!("{identifier}"))
    };
    let eleven = find(document_11());
    let mut eleven_renamed = eleven.clone();
    eleven_renamed.name = "Rechnung (Entwurf).pdf".to_owned();
    let mut twelve_moved = find(document_12());
    twelve_moved.identifier = EntryIdentifier::Document {
        location: Location::Case { archive: archive_5(), case: case_2() },
        document: doc(12),
    };
    let journal = vec![
        JournalEntry {
            sequence: 1,
            change: Change::Changed { before: eleven.clone(), after: eleven_renamed.clone() },
        },
        JournalEntry {
            sequence: 2,
            change: Change::Changed { before: eleven_renamed, after: eleven },
        },
        JournalEntry { sequence: 3, change: Change::New { entry: twelve_moved } },
        JournalEntry { sequence: 4, change: Change::Removed { entry: find(document_12()) } },
    ];

    let mut contents = HashMap::new();
    contents.insert(document_10(), CONTENT_10.to_vec());
    MockSource {
        children: Mutex::new(children),
        journal,
        journal_beginning: 0,
        promises_more_without_delivering: false,
        contents,
        content_error: None,
        every_call_fails: None,
        requests: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl MockSource {
    /// The entry for an identifier, the way `entry` delivers it.
    pub(crate) fn entry_to(&self, identifier: EntryIdentifier) -> Entry {
        self.search(identifier).unwrap_or_else(|| panic!("{identifier} is in no listing"))
    }

    /// Every identifier in every listing.
    pub(crate) fn all_identifiers(&self) -> Vec<EntryIdentifier> {
        lock(&self.children)
            .values()
            .filter_map(|l| l.as_ref().ok())
            .flat_map(|l| l.iter().map(|e| e.identifier))
            .collect()
    }

    /// Takes a child out of a listing (the engine has refreshed the listing).
    pub(crate) fn remove_child(&self, container: Container, identifier: EntryIdentifier) {
        if let Some(Ok(list)) = lock(&self.children).get_mut(&container) {
            list.retain(|e| e.identifier != identifier);
        }
    }

    /// Makes `children(container)` fail.
    pub(crate) fn set_children_error(&self, container: Container, error: SourceError) {
        lock(&self.children).insert(container, Err(error));
    }

    fn search(&self, identifier: EntryIdentifier) -> Option<Entry> {
        lock(&self.children)
            .values()
            .filter_map(|l| l.as_ref().ok())
            .flat_map(|l| l.iter())
            .find(|e| e.identifier == identifier)
            .cloned()
    }

    fn check(&self) -> Result<(), SourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.every_call_fails {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

impl NamespaceSource for MockSource {
    fn children(&self, container: Container) -> Result<Vec<Entry>, SourceError> {
        self.check()?;
        lock(&self.children)
            .get(&container)
            .cloned()
            .unwrap_or(Err(SourceError::NotFound(EntryIdentifier::Container(container))))
    }

    fn entry(&self, identifier: EntryIdentifier) -> Result<Entry, SourceError> {
        self.check()?;
        self.search(identifier).ok_or(SourceError::NotFound(identifier))
    }

    fn current_sequence(&self) -> Result<u64, SourceError> {
        self.check()?;
        Ok(self.journal.last().map_or(self.journal_beginning, |j| j.sequence))
    }

    fn changes_since(&self, sequence: u64, max: usize) -> Result<ChangeState, SourceError> {
        self.check()?;
        if sequence < self.journal_beginning {
            return Err(SourceError::AnchorExpired);
        }
        if self.promises_more_without_delivering {
            return Ok(ChangeState { changes: Vec::new(), until_sequence: sequence, more: true });
        }
        let open: Vec<JournalEntry> =
            self.journal.iter().filter(|j| j.sequence > sequence).cloned().collect();
        let more = open.len() > max;
        let changes: Vec<JournalEntry> = open.into_iter().take(max).collect();
        let until_sequence = changes.last().map_or(sequence, |j| j.sequence);
        Ok(ChangeState { changes, until_sequence, more })
    }

    fn content(
        &self,
        identifier: EntryIdentifier,
        request: &ContentRequest,
        sink: &mut dyn ContentSink,
    ) -> Result<ContentReceipt, SourceError> {
        self.check()?;
        lock(&self.requests).push(request.clone());
        if let Some(error) = &self.content_error {
            return Err(error.clone());
        }
        let data = self.contents.get(&identifier).ok_or(SourceError::NotFound(identifier))?;
        let total = data.len() as u64;
        sink.progress(total, total);
        let middle = data.len() / 2;
        sink.write(0, &data[..middle])?;
        sink.write(middle as u64, &data[middle..])?;
        Ok(ContentReceipt { size: total, sha256: None })
    }
}

/// What an observer has seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) identifier: String,
    pub(crate) parent: String,
    pub(crate) name: String,
}

/// One message to an observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    Entries(Vec<Seen>),
    PageFinished(Option<Vec<u8>>),
    Updated(Vec<Seen>),
    Removed(Vec<String>),
    ChangesFinished { anchor: Vec<u8>, more: bool },
    Error { domain: String, code: isize },
}

impl Event {
    fn completes(&self) -> bool {
        matches!(self, Self::PageFinished(_) | Self::ChangesFinished { .. } | Self::Error { .. })
    }

    fn error(error: &NSError) -> Self {
        Self::Error { domain: error.domain().to_string(), code: error.code() }
    }
}

/// The transcript of an observer.
pub(crate) struct Transcript {
    events: Mutex<Vec<Event>>,
    signal: Condvar,
    size: NSInteger,
}

impl Transcript {
    fn insert(&self, event: Event) {
        lock(&self.events).push(event);
        self.signal.notify_all();
    }

    /// Every message so far, without waiting.
    pub(crate) fn so_far(&self) -> Vec<Event> {
        lock(&self.events).clone()
    }

    /// Waits until the observer has been finished, and returns every message.
    pub(crate) fn wait_on_completion(&self) -> Vec<Event> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut events = lock(&self.events);
        loop {
            if events.last().is_some_and(Event::completes) {
                return events.clone();
            }
            let rest = deadline.saturating_duration_since(Instant::now());
            assert!(!rest.is_zero(), "the observer was never finished: {:?}", *events);
            events =
                self.signal.wait_timeout(events, rest).unwrap_or_else(PoisonError::into_inner).0;
        }
    }
}

fn seen(list: &NSArray<ProtocolObject<dyn NSFileProviderItemProtocol>>) -> Vec<Seen> {
    list.iter()
        .map(|item| {
            // SAFETY: properties of an id<NSFileProviderItem>, read the way the system reads them.
            unsafe {
                Seen {
                    identifier: item.itemIdentifier().to_string(),
                    parent: item.parentItemIdentifier().to_string(),
                    name: item.filename().to_string(),
                }
            }
        })
        .collect()
}

define_class!(
    /// An observer for pages that writes everything down.
    #[unsafe(super(NSObject))]
    #[name = "EdmsTestPageObserver"]
    #[ivars = Transcript]
    pub(crate) struct PageObserver;

    unsafe impl NSObjectProtocol for PageObserver {}

    unsafe impl NSFileProviderEnumerationObserver for PageObserver {
        #[unsafe(method(didEnumerateItems:))]
        fn entries(&self, entries: &NSArray<ProtocolObject<dyn NSFileProviderItemProtocol>>) {
            self.ivars().insert(Event::Entries(seen(entries)));
        }

        #[unsafe(method(finishEnumeratingUpToPage:))]
        fn page_finished(&self, next: Option<&NSData>) {
            self.ivars().insert(Event::PageFinished(next.map(NSData::to_vec)));
        }

        #[unsafe(method(finishEnumeratingWithError:))]
        fn page_failed(&self, error: &NSError) {
            self.ivars().insert(Event::error(error));
        }

        #[unsafe(method(suggestedPageSize))]
        fn proposed_page_size(&self) -> NSInteger {
            self.ivars().size
        }
    }
);

define_class!(
    /// An observer for changes that writes everything down.
    #[unsafe(super(NSObject))]
    #[name = "EdmsTestChangeObserver"]
    #[ivars = Transcript]
    pub(crate) struct ChangeObserver;

    unsafe impl NSObjectProtocol for ChangeObserver {}

    unsafe impl NSFileProviderChangeObserver for ChangeObserver {
        #[unsafe(method(didUpdateItems:))]
        fn updated(&self, entries: &NSArray<ProtocolObject<dyn NSFileProviderItemProtocol>>) {
            self.ivars().insert(Event::Updated(seen(entries)));
        }

        #[unsafe(method(didDeleteItemsWithIdentifiers:))]
        fn removed(&self, identifiers: &NSArray<NSString>) {
            self.ivars()
                .insert(Event::Removed(identifiers.iter().map(|k| k.to_string()).collect()));
        }

        #[unsafe(method(finishEnumeratingChangesUpToSyncAnchor:moreComing:))]
        fn changes_finished(&self, anchor: &NSData, more: bool) {
            self.ivars().insert(Event::ChangesFinished { anchor: anchor.to_vec(), more });
        }

        #[unsafe(method(finishEnumeratingWithError:))]
        fn changes_failed(&self, error: &NSError) {
            self.ivars().insert(Event::error(error));
        }

        #[unsafe(method(suggestedBatchSize))]
        fn proposed_batch_size(&self) -> NSInteger {
            self.ivars().size
        }
    }
);

fn transcript(size: NSInteger) -> Transcript {
    Transcript { events: Mutex::new(Vec::new()), signal: Condvar::new(), size }
}

impl PageObserver {
    /// An observer that proposes `size` as the page size.
    pub(crate) fn new(size: NSInteger) -> Retained<Self> {
        let this = Self::alloc().set_ivars(transcript(size));
        // SAFETY: -[NSObject init] on the freshly allocated instance whose ivars are set.
        unsafe { msg_send![super(this), init] }
    }

    /// The transcript.
    pub(crate) fn transcript(&self) -> &Transcript {
        self.ivars()
    }
}

impl ChangeObserver {
    /// An observer that proposes `size` as the batch size.
    pub(crate) fn new(size: NSInteger) -> Retained<Self> {
        let this = Self::alloc().set_ivars(transcript(size));
        // SAFETY: -[NSObject init] on the freshly allocated instance whose ivars are set.
        unsafe { msg_send![super(this), init] }
    }

    /// The transcript.
    pub(crate) fn transcript(&self) -> &Transcript {
        self.ivars()
    }
}
