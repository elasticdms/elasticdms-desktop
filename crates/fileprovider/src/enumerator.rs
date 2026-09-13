//! Enumerating: `EdmsEnumerator` implements `NSFileProviderEnumerator`.
//!
//! The system asks two things:
//!
//! 1. **What is here?** (`enumerateItemsForObserver:startingAtPage:`) — page by page, with a marker
//!    of at most 500 bytes. The source delivers a listing of children in one piece
//!    (`NamespaceSource::children`, cfAPI demands it that way); the paging happens here, through a
//!    [`PageMarker`] with fingerprints, so that a listing refreshed between two pages shows up as
//!    `PageExpired` instead of as a silent gap.
//! 2. **What has changed since the anchor?** (`enumerateChangesForObserver:fromSyncAnchor:`) —
//!    answered out of the engine's change journal (`changes_since`).
//!
//! **The working set is the change channel.** A replicated provider may signal only the working
//! set (NSFileProviderManager.h); every change to every item arrives there, and the enumeration of
//! the working set has to contain **every item** if the extension does not track what is
//! materialised (NSFileProviderReplicatedExtension.h, `materializedItemsDidChange`). Otherwise,
//! after an expired anchor, the system would take every item not enumerated again for deleted. The
//! enumeration of the working set therefore runs over the core's whole tree: root, the three fixed
//! folders (baskets, archives, saved searches), every basket, every archive, every case file
//! (Akte) in it and every search (`namespace.rs`). The archives are the one branch two levels
//! deep — a case file hangs under its archive (namespace v2 §1).
//!
//! **Folders report their own changes just the same.** The methods for changes are only "optional
//! for historical reasons, but really mandatory" (NSFileProviderEnumerating.h); a folder reports
//! the same journal entries, filtered down to its children. Reporting twice is harmless, keeping
//! quiet would not be.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use block2::DynBlock;
use edms_core::change::Change;
use edms_core::namespace::{Container, Entry, EntryIdentifier};
use edms_core::port::{NamespaceSource, SourceError};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, DefinedClass, Message, define_class, msg_send, sel};
use objc2_file_provider::{
    NSFileProviderChangeObserver, NSFileProviderEnumerationObserver, NSFileProviderEnumerator,
    NSFileProviderInitialPageSortedByDate, NSFileProviderInitialPageSortedByName,
    NSFileProviderItem,
};
use objc2_foundation::{NSArray, NSData, NSInteger, NSString};

use crate::anchor::{Anchor, PageMarker, fingerprint};
use crate::connection::Context;
use crate::entry::EdmsEntry;
use crate::error::ProviderError;
use crate::identifier::{SystemIdentifiers, Target};
use crate::thread::{ThreadFixed, in_background};

/// Page size when the observer proposes none.
pub(crate) const DEFAULT_PAGE_SIZE: usize = 200;
/// A page never hands out more than this, even if the observer proposes more.
pub(crate) const MAX_PAGE_SIZE: usize = 1_000;

/// What an enumerator enumerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnumerateTarget {
    /// A folder of the fixed tree.
    Container(Container),
    /// A file: it has no children, the enumeration is empty.
    File(EntryIdentifier),
    /// The working set: the whole tree.
    WorkingSet,
}

impl EnumerateTarget {
    /// The target for an identifier of the system.
    pub(crate) fn for_target(target: Target) -> Result<Self, ProviderError> {
        match target {
            Target::Root => Ok(Self::Container(Container::Root)),
            Target::WorkingSet => Ok(Self::WorkingSet),
            Target::Trash => Err(ProviderError::NoTrash),
            Target::Entry(EntryIdentifier::Container(container)) => Ok(Self::Container(container)),
            Target::Entry(identifier) => Ok(Self::File(identifier)),
        }
    }

    /// Whether a change to `identifier` belongs in this enumeration.
    fn affects(self, identifier: EntryIdentifier) -> bool {
        match self {
            Self::WorkingSet => true,
            Self::Container(container) => identifier.parent() == Some(container),
            Self::File(_) => false,
        }
    }
}

/// One page, still without Objective-C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page {
    /// The entries of this page.
    pub(crate) entries: Vec<Entry>,
    /// The marker of the next page; `None` at the end.
    pub(crate) next: Option<PageMarker>,
}

/// The changes since an anchor, collapsed per identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangePage {
    /// New or changed entries, in their latest shape.
    pub(crate) updated: Vec<Entry>,
    /// Removed entries.
    pub(crate) removed: Vec<EntryIdentifier>,
    /// The anchor from which to ask the next time.
    pub(crate) until: Anchor,
    /// Whether the journal holds more.
    pub(crate) more: bool,
}

/// The page size derived from the observer's proposal.
pub(crate) fn page_size(proposal: Option<NSInteger>) -> usize {
    match proposal.and_then(|n| usize::try_from(n).ok()) {
        Some(n) if n > 0 => n.min(MAX_PAGE_SIZE),
        _ => DEFAULT_PAGE_SIZE,
    }
}

/// The containers an enumeration runs through (module header).
fn plan(
    source: &dyn NamespaceSource,
    target: EnumerateTarget,
) -> Result<Vec<Container>, ProviderError> {
    match target {
        EnumerateTarget::Container(container) => Ok(vec![container]),
        EnumerateTarget::File(_) => Ok(Vec::new()),
        EnumerateTarget::WorkingSet => {
            // The tree from namespace.rs. Baskets and searches hold one level of folders; the
            // archives hold two, because a case file stands in an archive. Below a case file, a
            // search and a basket there are only documents and hints, so the walk ends there.
            let mut plan =
                vec![Container::Root, Container::Baskets, Container::Archives, Container::Searches];
            for top in [Container::Baskets, Container::Archives, Container::Searches] {
                for container in folders_in(source, top)? {
                    plan.push(container);
                    if top == Container::Archives {
                        plan.extend(folders_in(source, container)?);
                    }
                }
            }
            Ok(plan)
        }
    }
}

/// The folders directly inside `container`, in the order the source lists them.
fn folders_in(
    source: &dyn NamespaceSource,
    container: Container,
) -> Result<Vec<Container>, ProviderError> {
    Ok(source.children(container)?.into_iter().filter_map(|e| e.identifier.container()).collect())
}

/// Reads one page from `marker` on (`None` = the beginning).
pub(crate) fn read_page(
    source: &dyn NamespaceSource,
    target: EnumerateTarget,
    marker: Option<PageMarker>,
    size: usize,
) -> Result<Page, ProviderError> {
    let plan = plan(source, target)?;
    let plan_fingerprint = fingerprint(plan.iter().map(|b| EntryIdentifier::Container(*b)));
    let (index, offset, children_fingerprint) = match marker {
        None if plan.is_empty() => return Ok(Page { entries: Vec::new(), next: None }),
        None => (0, 0, None),
        Some(m) if m.plan != plan_fingerprint => return Err(ProviderError::PageExpired),
        Some(m) => (
            usize::try_from(m.container_index).map_err(|_| ProviderError::PageExpired)?,
            usize::try_from(m.offset).map_err(|_| ProviderError::PageExpired)?,
            Some(m.children),
        ),
    };
    // A marker beyond the plan can only be a foreign one; a changed plan is caught by the
    // fingerprint.
    let container = *plan.get(index).ok_or(ProviderError::PageExpired)?;
    let children = match source.children(container) {
        Ok(children) => children,
        // In the working set a folder that has disappeared means "listing changed", not "the
        // working set does not exist" — the system would otherwise delete the working set.
        Err(SourceError::NotFound(_)) if target == EnumerateTarget::WorkingSet => {
            return Err(ProviderError::PageExpired);
        }
        Err(error) => return Err(error.into()),
    };
    let children_now = fingerprint(children.iter().map(|e| e.identifier));
    if offset > 0 && children_fingerprint != Some(children_now) {
        return Err(ProviderError::PageExpired);
    }
    if offset > children.len() {
        return Err(ProviderError::PageExpired);
    }
    let end = offset.saturating_add(size).min(children.len());
    let marker_for =
        |index: usize, offset: usize, children: u64| -> Result<PageMarker, ProviderError> {
            Ok(PageMarker {
                container_index: u32::try_from(index).map_err(|_| ProviderError::PageExpired)?,
                offset: u32::try_from(offset).map_err(|_| ProviderError::PageExpired)?,
                plan: plan_fingerprint,
                children,
            })
        };
    let next = if end < children.len() {
        Some(marker_for(index, end, children_now)?)
    } else if index + 1 < plan.len() {
        Some(marker_for(index + 1, 0, 0)?)
    } else {
        None
    };
    Ok(Page { entries: children[offset..end].to_vec(), next })
}

/// Reads the changes since `anchor`, collapses them per identifier, removed before updated.
///
/// The order follows `change.rs`: a new document can carry the name of one just removed, and the
/// system should get rid of the removed one first.
pub(crate) fn read_change(
    source: &dyn NamespaceSource,
    target: EnumerateTarget,
    anchor: Anchor,
    size: usize,
) -> Result<ChangePage, ProviderError> {
    // An anchor beyond the journal: the journal has started over (a new session). Asking from it
    // would deliver an empty answer and keep quiet about everything up to then.
    let current = source.current_sequence()?;
    if anchor.sequence() > current {
        return Err(SourceError::AnchorExpired.into());
    }
    let state = source.changes_since(anchor.sequence(), size)?;
    if state.until_sequence < anchor.sequence() {
        return Err(SourceError::Internal(format!(
            "the change journal answers sequence {} with the older sequence {}",
            anchor.sequence(),
            state.until_sequence
        ))
        .into());
    }
    if state.more && state.until_sequence == anchor.sequence() {
        return Err(SourceError::Internal(format!(
            "the change journal reports more changes after sequence {} but delivers none",
            anchor.sequence()
        ))
        .into());
    }
    let mut last: BTreeMap<EntryIdentifier, Option<Entry>> = BTreeMap::new();
    for journal_entry in state.changes {
        let identifier = journal_entry.change.identifier();
        if !target.affects(identifier) {
            continue;
        }
        let after = match journal_entry.change {
            Change::New { entry } | Change::Changed { after: entry, .. } => Some(entry),
            Change::Removed { .. } => None,
        };
        last.insert(identifier, after);
    }
    let mut updated = Vec::new();
    let mut removed = Vec::new();
    for (identifier, after) in last {
        match after {
            Some(entry) => updated.push(entry),
            None => removed.push(identifier),
        }
    }
    Ok(ChangePage { updated, removed, until: Anchor::new(state.until_sequence), more: state.more })
}

/// The details behind an `EdmsEnumerator`.
///
/// They live in a box, not directly in the object's storage: objc2 registers ivars with at most
/// 8-byte alignment into the class (`defined_ivars.rs`, otherwise it aborts at registration time),
/// and an [`EnumerateTarget`] contains an [`EntryIdentifier`] with its 128-bit value — that is
/// 16-byte alignment.
pub(crate) struct EnumeratorData {
    target: EnumerateTarget,
    context: Arc<Context>,
    valid: Arc<AtomicBool>,
}

define_class!(
    /// An enumerator for a folder, a file or the working set.
    #[unsafe(super(NSObject))]
    #[name = "EdmsEnumerator"]
    #[ivars = Box<EnumeratorData>]
    pub(crate) struct EdmsEnumerator;

    unsafe impl NSObjectProtocol for EdmsEnumerator {}

    unsafe impl NSFileProviderEnumerator for EdmsEnumerator {
        #[unsafe(method(invalidate))]
        fn mark_invalid(&self) {
            self.ivars().valid.store(false, Ordering::Release);
        }

        #[unsafe(method(enumerateItemsForObserver:startingAtPage:))]
        fn count_on(
            &self,
            observer: &ProtocolObject<dyn NSFileProviderEnumerationObserver>,
            page: &NSData,
        ) {
            self.start_page(observer, page);
        }

        #[unsafe(method(enumerateChangesForObserver:fromSyncAnchor:))]
        fn count_change(
            &self,
            observer: &ProtocolObject<dyn NSFileProviderChangeObserver>,
            anchor: &NSData,
        ) {
            self.start_change(observer, anchor);
        }

        #[unsafe(method(currentSyncAnchorWithCompletionHandler:))]
        fn current_anchor(&self, finished: &DynBlock<dyn Fn(*mut NSData)>) {
            self.start_anchor(finished);
        }
    }
);

impl EdmsEnumerator {
    /// An enumerator; the work only starts once the system enumerates.
    pub(crate) fn new(target: EnumerateTarget, context: Arc<Context>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Box::new(EnumeratorData {
            target,
            context,
            valid: Arc::new(AtomicBool::new(true)),
        }));
        // SAFETY: -[NSObject init] on the freshly allocated instance whose ivars are set.
        unsafe { msg_send![super(this), init] }
    }

    fn start_page(
        &self,
        observer: &ProtocolObject<dyn NSFileProviderEnumerationObserver>,
        page: &NSData,
    ) {
        let proposal = observer.respondsToSelector(sel!(suggestedPageSize)).then(|| {
            // SAFETY: the observer responds to the optional selector (just checked).
            unsafe { observer.suggestedPageSize() }
        });
        let size = page_size(proposal);
        let marker = read_page_detail(page);
        // SAFETY: File Provider observers may be called from any thread; the system itself calls
        // the extension from arbitrary queues (module header of thread.rs).
        let observer = unsafe { ThreadFixed::new(observer.retain()) };
        let data = self.ivars();
        let (target, context, valid) =
            (data.target, Arc::clone(&data.context), Arc::clone(&data.valid));
        in_background("edms-enumerate", move || {
            let result =
                marker.and_then(|marker| context.ask(|q| read_page(q, target, marker, size)));
            if valid.load(Ordering::Acquire) {
                report_page(observer.value(), context.identifiers(), result);
            }
        });
    }

    fn start_change(
        &self,
        observer: &ProtocolObject<dyn NSFileProviderChangeObserver>,
        anchor: &NSData,
    ) {
        let proposal = observer.respondsToSelector(sel!(suggestedBatchSize)).then(|| {
            // SAFETY: the observer responds to the optional selector (just checked).
            unsafe { observer.suggestedBatchSize() }
        });
        let size = page_size(proposal);
        // An unreadable anchor has expired: the system enumerates afresh instead of guessing gaps.
        let anchor = Anchor::read(&anchor.to_vec())
            .map_err(|_| ProviderError::from(SourceError::AnchorExpired));
        // SAFETY: as in start_page.
        let observer = unsafe { ThreadFixed::new(observer.retain()) };
        let data = self.ivars();
        let (target, context, valid) =
            (data.target, Arc::clone(&data.context), Arc::clone(&data.valid));
        in_background("edms-changes", move || {
            let result =
                anchor.and_then(|anchor| context.ask(|q| read_change(q, target, anchor, size)));
            if valid.load(Ordering::Acquire) {
                report_change(observer.value(), context.identifiers(), result);
            }
        });
    }

    fn start_anchor(&self, finished: &DynBlock<dyn Fn(*mut NSData)>) {
        let context = Arc::clone(&self.ivars().context);
        // SAFETY: File Provider completion blocks may be called from any thread; `copy` keeps the
        // block alive beyond this call.
        let finished = unsafe { ThreadFixed::new(finished.copy()) };
        in_background("edms-anchor", move || match context.ask(|q| Ok(q.current_sequence()?)) {
            Ok(sequence) => {
                let anchor = NSData::with_bytes(&Anchor::new(sequence).bytes());
                finished.value().call((Retained::as_ptr(&anchor).cast_mut(),));
            }
            Err(error) => {
                // The block has no error path; nil means "no anchor", and the system asks again
                // after the next signal.
                tracing::warn!(%error, "the current anchor could not be determined");
                finished.value().call((std::ptr::null_mut(),));
            }
        });
    }
}

/// The system's initial pages become `None`, markers of our own are read, everything else has
/// expired.
fn read_page_detail(page: &NSData) -> Result<Option<PageMarker>, ProviderError> {
    let bytes = page.to_vec();
    // SAFETY: both initial pages are exported, immutable NSData constants
    // (NSFileProviderEnumerating.h).
    let (by_name, by_date) = unsafe {
        (
            NSFileProviderInitialPageSortedByName.to_vec(),
            NSFileProviderInitialPageSortedByDate.to_vec(),
        )
    };
    if bytes == by_name || bytes == by_date {
        return Ok(None);
    }
    PageMarker::read(&bytes).map(Some).map_err(|_| ProviderError::PageExpired)
}

fn report_page(
    observer: &ProtocolObject<dyn NSFileProviderEnumerationObserver>,
    identifiers: &SystemIdentifiers,
    result: Result<Page, ProviderError>,
) {
    match result {
        Ok(page) => {
            if !page.entries.is_empty() {
                let entries: Vec<Retained<EdmsEntry>> = page
                    .entries
                    .into_iter()
                    .map(|e| EdmsEntry::from_entry(e, identifiers))
                    .collect();
                let for_system: Vec<&NSFileProviderItem> =
                    entries.iter().map(|e| e.for_system()).collect();
                // SAFETY: didEnumerateItems: takes an NSArray<id<NSFileProviderItem>>.
                unsafe { observer.didEnumerateItems(&NSArray::from_slice(&for_system)) };
            }
            let next = page.next.map(|m| NSData::with_bytes(&m.bytes()));
            // SAFETY: nil ends the enumeration, otherwise a marker of at most 500 bytes.
            unsafe { observer.finishEnumeratingUpToPage(next.as_deref()) };
        }
        // SAFETY: finishEnumeratingWithError: takes an NSError from one of the two domains.
        Err(error) => unsafe { observer.finishEnumeratingWithError(&error.as_nserror()) },
    }
}

fn report_change(
    observer: &ProtocolObject<dyn NSFileProviderChangeObserver>,
    identifiers: &SystemIdentifiers,
    result: Result<ChangePage, ProviderError>,
) {
    match result {
        Ok(page) => {
            if !page.removed.is_empty() {
                let removed: Vec<Retained<NSString>> = page
                    .removed
                    .iter()
                    .map(|k| NSString::from_str(&identifiers.text(*k)))
                    .collect();
                // SAFETY: didDeleteItemsWithIdentifiers: takes an
                // NSArray<NSFileProviderItemIdentifier>.
                unsafe {
                    observer.didDeleteItemsWithIdentifiers(&NSArray::from_retained_slice(&removed))
                };
            }
            if !page.updated.is_empty() {
                let entries: Vec<Retained<EdmsEntry>> = page
                    .updated
                    .into_iter()
                    .map(|e| EdmsEntry::from_entry(e, identifiers))
                    .collect();
                let for_system: Vec<&NSFileProviderItem> =
                    entries.iter().map(|e| e.for_system()).collect();
                // SAFETY: didUpdateItems: takes an NSArray<id<NSFileProviderItem>>.
                unsafe { observer.didUpdateItems(&NSArray::from_slice(&for_system)) };
            }
            let until = NSData::with_bytes(&page.until.bytes());
            // SAFETY: anchor at most 500 bytes; `more` as reported by the journal.
            unsafe {
                observer.finishEnumeratingChangesUpToSyncAnchor_moreComing(&until, page.more)
            };
        }
        // SAFETY: as in report_page.
        Err(error) => unsafe { observer.finishEnumeratingWithError(&error.as_nserror()) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::SourceHolder;
    use crate::harness::{
        ChangeObserver, Event, MockSource, PageObserver, archive_5, basket_4, case_file_1,
        case_file_2, document_10, document_11, document_12, sample_source, search_3,
    };

    fn all_pages(source: &dyn NamespaceSource, target: EnumerateTarget, size: usize) -> Vec<Page> {
        let mut pages = Vec::new();
        let mut marker = None;
        loop {
            let page = read_page(source, target, marker, size).unwrap();
            marker = page.next;
            pages.push(page);
            if marker.is_none() {
                return pages;
            }
            assert!(pages.len() < 100, "the enumeration does not end");
        }
    }

    #[test]
    fn a_folder_is_enumerated_page_by_page_completely_and_without_duplicates() {
        let source = sample_source();
        let target = EnumerateTarget::Container(case_file_1());
        let pages = all_pages(&source, target, 2);
        assert_eq!(pages.iter().map(|s| s.entries.len()).collect::<Vec<_>>(), [2, 1]);
        let identifiers: Vec<_> =
            pages.iter().flat_map(|s| s.entries.iter().map(|e| e.identifier)).collect();
        assert_eq!(identifiers, [document_10(), document_11(), document_12()]);
    }

    #[test]
    fn a_listing_changed_between_two_pages_lets_the_page_expire() {
        let source = sample_source();
        let target = EnumerateTarget::Container(case_file_1());
        let first = read_page(&source, target, None, 2).unwrap();
        source.remove_child(case_file_1(), document_10());
        assert_eq!(read_page(&source, target, first.next, 2), Err(ProviderError::PageExpired));
    }

    #[test]
    fn a_marker_from_another_folder_expires() {
        let source = sample_source();
        let first = read_page(&source, EnumerateTarget::Container(case_file_1()), None, 1).unwrap();
        let foreign = read_page(
            &source,
            EnumerateTarget::Container(Container::Search(search_3())),
            first.next,
            1,
        );
        assert_eq!(foreign, Err(ProviderError::PageExpired));
    }

    #[test]
    fn the_working_set_walks_into_every_archive_down_to_its_case_files() {
        // The one branch of the tree that is two folders deep. If the walk stopped at the
        // archives, every case file and every document in them would be missing from the working
        // set — and after an expired anchor the system would take them all for deleted.
        let source = sample_source();
        assert_eq!(
            plan(&source, EnumerateTarget::WorkingSet).unwrap(),
            [
                Container::Root,
                Container::Baskets,
                Container::Archives,
                Container::Searches,
                Container::Basket(basket_4()),
                Container::Archive(archive_5()),
                case_file_1(),
                case_file_2(),
                Container::Search(search_3()),
            ]
        );
    }

    #[test]
    fn the_working_set_contains_every_entry_of_the_tree() {
        let source = sample_source();
        let all: Vec<_> = all_pages(&source, EnumerateTarget::WorkingSet, 2)
            .into_iter()
            .flat_map(|s| s.entries)
            .map(|e| e.identifier)
            .collect();
        let expected = source.all_identifiers();
        assert_eq!(all.len(), expected.len(), "{all:?}");
        for identifier in expected {
            assert!(all.contains(&identifier), "{identifier} is missing");
        }
    }

    #[test]
    fn in_the_working_set_a_vanished_folder_means_enumerate_afresh_not_no_such_item() {
        let source = sample_source();
        source.set_children_error(
            case_file_2(),
            SourceError::NotFound(EntryIdentifier::Container(case_file_2())),
        );
        let mut marker = None;
        let error = loop {
            match read_page(&source, EnumerateTarget::WorkingSet, marker, 50) {
                Ok(page) => marker = page.next,
                Err(error) => break error,
            }
        };
        assert_eq!(error, ProviderError::PageExpired);
        // The same folder enumerated directly: that one does not exist, the system may delete it.
        let direct = read_page(&source, EnumerateTarget::Container(case_file_2()), None, 50);
        assert_eq!(direct.unwrap_err().error_image().code, -1005);
    }

    #[test]
    fn a_file_has_an_empty_enumeration() {
        let page =
            read_page(&sample_source(), EnumerateTarget::File(document_10()), None, 10).unwrap();
        assert!(page.entries.is_empty() && page.next.is_none());
    }

    #[test]
    fn the_page_size_follows_the_proposal_within_limits() {
        assert_eq!(page_size(None), DEFAULT_PAGE_SIZE);
        assert_eq!(page_size(Some(0)), DEFAULT_PAGE_SIZE);
        assert_eq!(page_size(Some(-3)), DEFAULT_PAGE_SIZE);
        assert_eq!(page_size(Some(7)), 7);
        assert_eq!(page_size(Some(1_000_000)), MAX_PAGE_SIZE);
    }

    #[test]
    fn changes_arrive_collapsed_removed_before_updated_with_a_new_anchor() {
        let source = sample_source();
        let page = read_change(&source, EnumerateTarget::WorkingSet, Anchor::new(0), 10).unwrap();
        assert_eq!(page.removed, [document_12()]);
        let updated: Vec<_> =
            page.updated.iter().map(|e| (e.identifier, e.name.as_str())).collect();
        assert!(updated.contains(&(document_11(), "Rechnung 2026-0412.pdf")), "{updated:?}");
        assert_eq!(page.until, Anchor::new(4));
        assert!(!page.more);
    }

    #[test]
    fn an_entry_that_came_and_went_in_the_same_batch_is_only_removed() {
        let source = sample_source();
        // Sequence 3 creates document 12 in case file 2 and sequence 4 removes document 12 from
        // case file 1: two identifiers. Sequence 1 changes document 11, sequence 2 renames it
        // again: one identifier.
        let page = read_change(&source, EnumerateTarget::WorkingSet, Anchor::new(0), 10).unwrap();
        let eleven: Vec<_> =
            page.updated.iter().filter(|e| e.identifier == document_11()).collect();
        assert_eq!(eleven.len(), 1);
    }

    #[test]
    fn a_batch_ends_at_its_limit_and_reports_more() {
        let source = sample_source();
        let first = read_change(&source, EnumerateTarget::WorkingSet, Anchor::new(0), 3).unwrap();
        assert_eq!(first.until, Anchor::new(3));
        assert!(first.more);
        let second = read_change(&source, EnumerateTarget::WorkingSet, first.until, 3).unwrap();
        assert_eq!(second.until, Anchor::new(4));
        assert!(!second.more);
        assert_eq!(second.removed, [document_12()]);
    }

    #[test]
    fn a_folder_reports_only_changes_to_its_children() {
        let source = sample_source();
        let case_2_changes =
            read_change(&source, EnumerateTarget::Container(case_file_2()), Anchor::new(0), 10)
                .unwrap();
        assert!(case_2_changes.removed.is_empty());
        assert_eq!(case_2_changes.updated.len(), 1);
        assert_eq!(case_2_changes.updated[0].identifier.parent(), Some(case_file_2()));
        let root =
            read_change(&source, EnumerateTarget::Container(Container::Root), Anchor::new(0), 10)
                .unwrap();
        assert!(root.updated.is_empty() && root.removed.is_empty());
        assert_eq!(root.until, Anchor::new(4), "the anchor moves along all the same");
    }

    #[test]
    fn an_anchor_that_is_too_old_or_in_the_future_has_expired() {
        let mut source = sample_source();
        let future = read_change(&source, EnumerateTarget::WorkingSet, Anchor::new(99), 10);
        assert_eq!(future, Err(SourceError::AnchorExpired.into()));
        source.journal_beginning = 2;
        let old = read_change(&source, EnumerateTarget::WorkingSet, Anchor::new(1), 10);
        assert_eq!(old, Err(SourceError::AnchorExpired.into()));
        assert_eq!(old.unwrap_err().error_image().code, -1002);
    }

    #[test]
    fn a_journal_that_promises_more_but_delivers_nothing_is_an_error_not_a_loop() {
        let mut source = sample_source();
        source.promises_more_without_delivering = true;
        let error =
            read_change(&source, EnumerateTarget::WorkingSet, Anchor::new(4), 10).unwrap_err();
        assert!(matches!(error, ProviderError::Source(SourceError::Internal(_))), "{error:?}");
    }

    fn enumerator_for(
        source: MockSource,
        target: EnumerateTarget,
    ) -> (Retained<EdmsEnumerator>, Arc<Context>) {
        let context = Arc::new(Context::new(
            SourceHolder::fixed(Arc::new(source)),
            "elasticdms – test harness".to_owned(),
        ));
        (EdmsEnumerator::new(target, Arc::clone(&context)), context)
    }

    fn count_on(enumerator: &EdmsEnumerator, size: NSInteger, page: &NSData) -> Vec<Event> {
        let observer = PageObserver::new(size);
        let for_system: &ProtocolObject<dyn NSFileProviderEnumerationObserver> =
            ProtocolObject::from_ref(&*observer);
        // SAFETY: a call through the protocol's method, exactly as the system makes it.
        unsafe { enumerator.enumerateItemsForObserver_startingAtPage(for_system, page) };
        observer.transcript().wait_on_completion()
    }

    fn count_change(enumerator: &EdmsEnumerator, anchor: &NSData) -> Vec<Event> {
        let observer = ChangeObserver::new(10);
        let for_system: &ProtocolObject<dyn NSFileProviderChangeObserver> =
            ProtocolObject::from_ref(&*observer);
        // SAFETY: as above.
        unsafe { enumerator.enumerateChangesForObserver_fromSyncAnchor(for_system, anchor) };
        observer.transcript().wait_on_completion()
    }

    fn first_page() -> &'static NSData {
        // SAFETY: an exported, immutable NSData constant (NSFileProviderEnumerating.h).
        unsafe { NSFileProviderInitialPageSortedByName }
    }

    #[test]
    fn the_system_gets_a_page_and_may_page_on_with_its_marker() {
        let (enumerator, _context) =
            enumerator_for(sample_source(), EnumerateTarget::Container(case_file_1()));
        let first = count_on(&enumerator, 2, first_page());
        let Some(Event::Entries(seen)) = first.first() else { panic!("{first:?}") };
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].identifier, document_10().to_string());
        assert_eq!(seen[0].parent, case_file_1().to_string());
        let Some(Event::PageFinished(Some(marker))) = first.last() else { panic!("{first:?}") };
        assert!(marker.len() <= crate::anchor::MAX_MARKER_BYTES);
        let second = count_on(&enumerator, 2, &NSData::with_bytes(marker));
        let Some(Event::Entries(rest)) = second.first() else { panic!("{second:?}") };
        assert_eq!(rest.len(), 1);
        assert_eq!(second.last(), Some(&Event::PageFinished(None)));
    }

    #[test]
    fn a_foreign_page_marker_makes_the_system_start_over() {
        let (enumerator, _context) = enumerator_for(sample_source(), EnumerateTarget::WorkingSet);
        let events = count_on(&enumerator, 10, &NSData::with_bytes(b"not a marker of ours"));
        assert_eq!(
            events.last(),
            Some(&Event::Error { domain: "NSFileProviderErrorDomain".to_owned(), code: -1002 })
        );
    }

    #[test]
    fn the_changes_reach_the_system_removed_before_updated_with_a_new_anchor() {
        let (enumerator, _context) = enumerator_for(sample_source(), EnumerateTarget::WorkingSet);
        let events = count_change(&enumerator, &NSData::with_bytes(&Anchor::new(0).bytes()));
        let Some(Event::Removed(removed)) = events.first() else { panic!("{events:?}") };
        assert_eq!(removed, &[document_12().to_string()]);
        assert!(
            matches!(events.get(1), Some(Event::Updated(_))),
            "removed has to come before updated: {events:?}"
        );
        assert_eq!(
            events.last(),
            Some(&Event::ChangesFinished { anchor: Anchor::new(4).bytes().to_vec(), more: false })
        );
    }

    #[test]
    fn an_unreadable_anchor_makes_the_system_enumerate_afresh_instead_of_guessing_gaps() {
        let (enumerator, _context) = enumerator_for(sample_source(), EnumerateTarget::WorkingSet);
        let events = count_change(&enumerator, &NSData::with_bytes(b"an old version"));
        assert_eq!(
            events.last(),
            Some(&Event::Error { domain: "NSFileProviderErrorDomain".to_owned(), code: -1002 })
        );
    }

    #[test]
    fn the_current_anchor_arrives_as_bytes_and_without_a_channel_as_nil() {
        let (enumerator, context) = enumerator_for(sample_source(), EnumerateTarget::WorkingSet);
        let fetch = || -> Option<Vec<u8>> {
            let (tx, rx) = std::sync::mpsc::channel();
            let block = block2::RcBlock::new(move |anchor: *mut NSData| {
                // SAFETY: nil or a valid NSData for the duration of the call.
                let _ = tx.send(unsafe { anchor.as_ref() }.map(NSData::to_vec));
            });
            // SAFETY: as above.
            unsafe { enumerator.currentSyncAnchorWithCompletionHandler(&block) };
            rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the completion block")
        };
        assert_eq!(fetch(), Some(Anchor::new(4).bytes().to_vec()));
        context.release();
        assert_eq!(fetch(), None, "without a channel there is no anchor, but no hang either");
    }

    #[test]
    fn an_enumerator_that_has_been_invalidated_reports_nothing_more() {
        let (enumerator, _context) = enumerator_for(sample_source(), EnumerateTarget::WorkingSet);
        // SAFETY: invalidate is a mandatory method of the protocol.
        unsafe { enumerator.invalidate() };
        let observer = PageObserver::new(10);
        let for_system: &ProtocolObject<dyn NSFileProviderEnumerationObserver> =
            ProtocolObject::from_ref(&*observer);
        // SAFETY: as above.
        unsafe { enumerator.enumerateItemsForObserver_startingAtPage(for_system, first_page()) };
        // No completion: the system has thrown the enumerator away and waits for nothing.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(observer.transcript().so_far().is_empty());
    }

    #[test]
    fn the_targets_of_the_system_identifiers() {
        assert_eq!(
            EnumerateTarget::for_target(Target::Root),
            Ok(EnumerateTarget::Container(Container::Root))
        );
        assert_eq!(
            EnumerateTarget::for_target(Target::WorkingSet),
            Ok(EnumerateTarget::WorkingSet)
        );
        assert_eq!(EnumerateTarget::for_target(Target::Trash), Err(ProviderError::NoTrash));
        assert_eq!(
            EnumerateTarget::for_target(Target::Entry(document_10())),
            Ok(EnumerateTarget::File(document_10()))
        );
        let basket = Container::Basket(basket_4());
        assert_eq!(
            EnumerateTarget::for_target(Target::Entry(EntryIdentifier::Container(basket))),
            Ok(EnumerateTarget::Container(basket))
        );
    }
}
