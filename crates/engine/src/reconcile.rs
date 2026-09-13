//! The namespace reconcile — the expensive part of the requirement.
//!
//! "Akten und gespeicherte Suchen sind dynamische Ordner. Ihr Inhalt ändert sich ohne Zutun im
//! Ordner. Der Client muss dem Explorer laufend Änderungen der Namensstruktur melden, nicht
//! einmalig einen Baum aufbauen." (`ordnerclient-vorgaben.md`, requirement 12) — case files (Akten)
//! and saved searches are dynamic folders whose content changes without anything being done in the
//! folder; the client has to report changes of the name structure to the Explorer continuously
//! instead of building a tree once.
//!
//! The way of a change, and every step belongs to a different crate:
//!
//! ```text
//! edms-net           list_baskets / list_archives / list_cases / list_searches / list_document
//!        ↓ rows                                                              (ETag, 304)
//! edms-core          baskets_entries / archives_entries / cases_entries / searches_entries /
//!                    document_entries                                        (names, hints)
//!        ↓ entries
//! edms-store         replace_container  (difference + journal in ONE transaction, tombstones)
//!        ↓ journal entries
//! edms_core::port    FileSystem::report_change  (Windows: placeholder, macOS: working set)
//! ```
//!
//! **From top to bottom.** Root, then the three fixed folders, then the individual archives,
//! case files and searches: `replace_container` rejects a container that stands in no listing of
//! its parent container — otherwise entries without a parent folder would come into being. Since
//! namespace v2 the way to a case file goes over its archive, and it is one level longer for it.
//!
//! **A basket lists nothing.** From the server it holds no documents at all (namespace v2 §4);
//! what lies in it locally is the file a user has just dropped in, and that one belongs to the
//! platform until the ingest has confirmed it. The reconcile therefore writes an empty listing
//! for a basket and asks the server nothing.
//!
//! **Only fetched containers in the beat.** A case file nobody has ever opened has no
//! [`edms_store::ContainerState`] and is not asked for either: a workstation with 200 case files
//! would otherwise ask for 200 complete listings every two minutes, for folders nobody looks at. It
//! is opened over [`crate::source`], and from then on it runs along.
//!
//! **Staggered and bounded.** Between two fetches lies [`OFFSET`], and never more than
//! [`crate::engine::CONCURRENT_DOWNLOADS`] run side by side — otherwise an office network would
//! fall upon the server all at once at the first beat after lunch.

use std::sync::Arc;
use std::time::Duration;

use edms_core::change::{Change, JournalEntry};
use edms_core::namespace::{
    Container, Entry, Location, archives_entries, baskets_entries, cases_entries, document_entries,
    root_entries, searches_entries,
};
use edms_net::ApiResult;
use edms_store::{ContainerState, TruncationState};
use edms_wire::namespace::ListQuery;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::engine::{CONCURRENT_DOWNLOADS, RECONCILE_INTERVAL, Shared};
use crate::error::EngineError;
use crate::time::now;

/// The spacing with which the beat staggers the fetches of individual containers.
pub const OFFSET: Duration = Duration::from_millis(80);

/// The beat: everything once every [`RECONCILE_INTERVAL`], for as long as the engine runs.
pub(crate) async fn interval(shared: Arc<Shared>) {
    let mut clock = tokio::time::interval(RECONCILE_INTERVAL);
    clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick comes at once; consuming it means the start stays without a network call
    // (see `Engine::start`).
    clock.tick().await;
    loop {
        clock.tick().await;
        if shared.is_stopped() {
            return;
        }
        if let Err(error) = reconcile_everything(&shared).await {
            // No cause for alarm: the next beat tries again. It becomes visible over
            // `connected: false` in the state.
            tracing::debug!(%error, "reconcile in the beat did not run through");
        }
    }
}

/// Reconciles the whole namespace: root, both container listings, every case file and search
/// already fetched.
///
/// # Errors
///
/// When the store does not write or the server does not answer. A single container that fails does
/// **not** end the run — it stands in the application log and is attempted again at the next
/// beat.
pub(crate) async fn reconcile_everything(shared: &Arc<Shared>) -> Result<(), EngineError> {
    if !crate::session::ensure_for_token(shared).await? {
        return Ok(());
    }
    // The root is fixed and manages without the network; without it the three folders beneath it
    // are unknown.
    adopt(shared, Container::Root, root_entries(shared.configuration.language), state(None, None))?;

    let mut result = Ok(());
    for container in [Container::Baskets, Container::Archives, Container::Searches] {
        if let Err(error) = reconcile_container(shared, container).await {
            result = remember(result, container, error);
        }
    }

    let open = already_fetched(shared)?;
    let gate = Arc::new(Semaphore::new(CONCURRENT_DOWNLOADS));
    let mut tasks: JoinSet<(Container, Result<(), EngineError>)> = JoinSet::new();
    for (place, container) in open.into_iter().enumerate() {
        let shared = Arc::clone(shared);
        let gate = Arc::clone(&gate);
        let offset = OFFSET.saturating_mul(u32::try_from(place).unwrap_or(u32::MAX));
        tasks.spawn(async move {
            tokio::time::sleep(offset).await;
            let Ok(_permit) = gate.acquire_owned().await else {
                return (container, Ok(()));
            };
            let outcome = reconcile_container(&shared, container).await;
            (container, outcome)
        });
    }
    while let Some(finished) = tasks.join_next().await {
        match finished {
            Ok((container, Err(error))) => result = remember(result, container, error),
            Ok((_, Ok(()))) => {}
            Err(error) => {
                tracing::error!(%error, "a reconcile task ended unexpectedly");
            }
        }
    }
    shared.set_connected(result.is_ok());
    result
}

/// Remembers the first error and writes every one into the application log.
fn remember(
    so_far: Result<(), EngineError>,
    container: Container,
    error: EngineError,
) -> Result<(), EngineError> {
    tracing::warn!(%container, %error, "container not reconciled");
    if so_far.is_err() { so_far } else { Err(error) }
}

/// Fetches the listing of a single container and writes the difference onwards.
///
/// # Errors
///
/// When the server does not answer or the store does not write.
pub(crate) async fn reconcile_container(
    shared: &Arc<Shared>,
    container: Container,
) -> Result<(), EngineError> {
    if !crate::session::ensure_for_token(shared).await? {
        return Ok(());
    }
    match fetch_and_adopt(shared, container).await {
        // Exactly **one** second attempt after `401`: renew, then once more. A loop would be
        // sustained fire at the token endpoint for a token the server rejects.
        Err(EngineError::SessionExpired(_)) => {
            if crate::session::force_refresh(shared).await? {
                fetch_and_adopt(shared, container).await
            } else {
                Ok(())
            }
        }
        other => other,
    }
}

/// The one fetch without a retry.
async fn fetch_and_adopt(shared: &Arc<Shared>, container: Container) -> Result<(), EngineError> {
    let known_etag = shared.store().container_state(container)?.and_then(|state| state.etag);
    let query =
        ListQuery::new(None, None).map_err(|error| EngineError::Internal(error.to_string()))?;
    let language = shared.configuration.language;
    match container {
        Container::Root => adopt(shared, container, root_entries(language), state(None, None)),
        Container::Baskets => {
            let result = shared.server.list_baskets(&query, known_etag.as_deref()).await;
            let list = match unchanged(shared, container, result, "the basket listing")? {
                Some(list) => list,
                None => return Ok(()),
            };
            let item: Vec<_> = list.value.entries.iter().map(|row| row.in_core()).collect();
            adopt(shared, container, baskets_entries(&item), state(list.etag, None))
        }
        // A basket holds nothing of the server's (namespace v2 §4). The empty listing is written
        // all the same: without a container state the source would fetch it on every open, and
        // every fetch would be a request for a listing that is empty by design.
        Container::Basket(_) => adopt(shared, container, Vec::new(), state(None, None)),
        Container::Archives => {
            let result = shared.server.list_archives(&query, known_etag.as_deref()).await;
            let list = match unchanged(shared, container, result, "the archive listing")? {
                Some(list) => list,
                None => return Ok(()),
            };
            let item: Vec<_> = list.value.entries.iter().map(|row| row.in_core()).collect();
            adopt(shared, container, archives_entries(&item), state(list.etag, None))
        }
        Container::Archive(archive) => {
            let result = shared.server.list_cases(archive, &query, known_etag.as_deref()).await;
            let list = match unchanged(shared, container, result, "the case-file listing")? {
                Some(list) => list,
                None => return Ok(()),
            };
            let item: Vec<_> = list.value.entries.iter().map(|row| row.in_core()).collect();
            adopt(shared, container, cases_entries(archive, &item), state(list.etag, None))
        }
        Container::Searches => {
            let result = shared.server.list_searches(&query, known_etag.as_deref()).await;
            let list = match unchanged(shared, container, result, "the search listing")? {
                Some(list) => list,
                None => return Ok(()),
            };
            let item: Vec<_> = list.value.entries.iter().map(|row| row.in_core()).collect();
            adopt(shared, container, searches_entries(&item), state(list.etag, None))
        }
        Container::Case { archive, case } => {
            reconcile_documents(shared, Location::Case { archive, case }, &query, known_etag).await
        }
        Container::Search(identifier) => {
            reconcile_documents(shared, Location::Search(identifier), &query, known_etag).await
        }
    }
}

/// The document listing of a location — together with the visible truncation.
async fn reconcile_documents(
    shared: &Arc<Shared>,
    location: Location,
    query: &ListQuery,
    known_etag: Option<String>,
) -> Result<(), EngineError> {
    let container = Container::from(location);
    let result = shared.server.list_document(location, query, known_etag.as_deref()).await;
    let list = match unchanged(shared, container, result, "the document listing")? {
        Some(list) => list,
        None => return Ok(()),
    };
    // A truncation is reported, never passed over in silence (finding Q-12): a folder that shows
    // 5 000 out of 40 000 documents and says nothing leads, in front of an auditor, to "the
    // document does not exist" — the most expensive way to be wrong.
    let truncation = list.value.truncation().map(|cut| TruncationState {
        display_upper_limit: cut.displayed,
        refine_url: cut.address.map(ToOwned::to_owned),
    });
    let item = list.value.in_core();
    let entries = document_entries(
        location,
        &item,
        truncation.as_ref().map(TruncationState::as_truncation),
        shared.configuration.language,
    );
    adopt(shared, container, entries, state(list.etag, truncation))
}

/// A container state with the now as its fetch time.
fn state(etag: Option<String>, truncation: Option<TruncationState>) -> ContainerState {
    ContainerState { etag, fetched: now(), truncation }
}

/// Separates `304` from success: on `304` only the state is confirmed, and the caller is done.
fn unchanged<T>(
    shared: &Shared,
    container: Container,
    result: ApiResult<T>,
    what: &'static str,
) -> Result<Option<edms_net::Success<T>>, EngineError> {
    if let ApiResult::Unchanged { etag } = result {
        // The listing is the same, but it has now been confirmed: the fetch time is at the same
        // time the clock against which a tombstone is measured.
        let before = shared.store().container_state(container)?.and_then(|state| state.truncation);
        let etag = etag.or_else(|| {
            shared.store().container_state(container).ok().flatten().and_then(|state| state.etag)
        });
        shared.store().update_container_state(container, &state(etag, before))?;
        return Ok(None);
    }
    Ok(Some(crate::value_from(result, what, shared.catalogue())?))
}

/// Writes a listing onwards and reports the difference to the platform.
fn adopt(
    shared: &Shared,
    container: Container,
    entries: Vec<Entry>,
    state: ContainerState,
) -> Result<(), EngineError> {
    let journal = shared.store().replace_container(container, &entries, &state)?;
    if journal.is_empty() {
        return Ok(());
    }
    register_with_platform(shared, &journal);
    Ok(())
}

/// Passes the journal entries on to the file system, if one is registered.
///
/// An error of the platform does **not** end the reconcile: the store is the truth about the
/// namespace, and macOS fetches the changes over
/// [`edms_core::port::NamespaceSource::changes_since`] anyway. Windows enumerates afresh at the
/// next open.
pub(crate) fn register_with_platform(shared: &Shared, journal: &[JournalEntry]) {
    let Some(file_system) = shared.file_system() else {
        return;
    };
    let changes: Vec<Change> = journal.iter().map(|entry| entry.change.clone()).collect();
    if let Err(error) = file_system.report_change(&changes) {
        tracing::warn!(%error, count = changes.len(), "the platform did not accept changes");
    }
}

/// Every archive, case file and search that has been fetched once — and only those.
///
/// The walk goes down as far as the tree does: an archive that has been fetched can hold case
/// files that have been fetched, and those are the folders a workstation really has open. The
/// baskets are not walked — a basket's listing is empty by design (namespace v2 §4), and fetching
/// it anew every two minutes would be a beat for nothing.
fn already_fetched(shared: &Shared) -> Result<Vec<Container>, EngineError> {
    let store = shared.store();
    let mut open = Vec::new();
    let mut ahead = vec![Container::Archives, Container::Searches];
    while let Some(parent) = ahead.pop() {
        let children = match store.children(parent) {
            Ok(children) => children,
            // The parent is still unknown: then there are no fetched children either.
            Err(_) => continue,
        };
        for child in children {
            if let Some(container) = child.identifier.container()
                && store.container_state(container)?.is_some()
            {
                open.push(container);
                ahead.push(container);
            }
        }
    }
    Ok(open)
}

/// Makes sure a container is known and fetched — the way from [`crate::source`] when somebody
/// opens a folder for the first time.
///
/// # Errors
///
/// As [`reconcile_container`].
pub(crate) async fn fetch_if_needed(
    shared: &Arc<Shared>,
    container: Container,
) -> Result<(), EngineError> {
    let known = shared.store().container_state(container)?.is_some();
    if known {
        return Ok(());
    }
    // From top to bottom: a case file is known only once its archive has enumerated it, and the
    // archive only once the archive folder has.
    if let Some(parent) = container.parent()
        && shared.store().container_state(parent)?.is_none()
    {
        Box::pin(fetch_if_needed(shared, parent)).await?;
    }
    reconcile_container(shared, container).await
}
