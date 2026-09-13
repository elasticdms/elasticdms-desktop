//! The bridge from the platform into the engine: [`EngineSource`].
//!
//! ## Who calls here
//!
//! [`edms_core::port::NamespaceSource`] is **synchronous**, and that is no oversight: on Windows
//! the cfAPI callback calls on a thread of the operating system, on macOS the extension calls on a
//! thread of Foundation (or over `edms-bridge` out of a foreign process). **None of them is a tokio
//! worker**, and none of them is to have to know anything about the engine's runtime.
//!
//! Hence a `Handle::block_on` stands here. The condition tokio sets for it applies, and it is met
//! here: **the calling thread must not stand in any runtime context.** Whoever called these methods
//! from an `async fn` of the engine would bring the runtime to a halt — for that there are the
//! internal functions in [`crate::reconcile`] and [`crate::hydration`], which do the same work and
//! use `await`.
//!
//! ## What happens without a network
//!
//! The tree stays put (ADR-D01, point 8). `children` **always** answers from the remembered state
//! as soon as there is one; if it is older than [`FRESHNESS`], it is pulled up in the background
//! and the change follows over `report_change` or the change journal. Only when there is **no**
//! remembered state at all is there any waiting — and if the fetch then fails, the user learns the
//! reason ([`SourceError::NoNetwork`]). A folder that appears empty offline is a lie about the
//! archive; a folder with yesterday's state is a statement about this machine.

use std::sync::Arc;
use std::time::Duration;

use edms_core::change::ChangeState;
use edms_core::namespace::{Container, Entry, EntryIdentifier, root_entries};
use edms_core::port::{ContentReceipt, ContentRequest, ContentSink, NamespaceSource, SourceError};
use edms_store::StoreError;
use tokio::runtime::Handle;

use crate::engine::Shared;
use crate::time::now;

/// How long a remembered listing counts as fresh before it is asked for anew when opened.
///
/// One minute: whoever expands a folder twice in a row is not to set off two network requests;
/// whoever comes back after the lunch break is to see the current state. Between the two lies the
/// beat from [`crate::reconcile`] anyway.
pub const FRESHNESS: Duration = Duration::from_secs(60);

/// The display name of the root for as long as the session knows no tenant name.
pub const NAME_ROOT: &str = "elasticdms";

/// The implementation of [`NamespaceSource`] on top of the engine.
pub struct EngineSource {
    shared: Arc<Shared>,
    handle: Handle,
}

impl std::fmt::Debug for EngineSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineSource").finish_non_exhaustive()
    }
}

impl EngineSource {
    pub(crate) fn new(shared: Arc<Shared>, handle: Handle) -> Self {
        Self { shared, handle }
    }

    /// Runs a future on the engine's runtime.
    ///
    /// See the module head: the calling thread belongs to the operating system, not to the runtime.
    fn in_engine<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        self.handle.block_on(future)
    }

    /// Pulls the listing of a container up in the background — without holding up the callback.
    fn trigger_reconcile(&self, container: Container) {
        let shared = Arc::clone(&self.shared);
        self.handle.spawn(async move {
            if let Err(error) = crate::reconcile::reconcile_container(&shared, container).await {
                tracing::debug!(%container, %error, "background pull-up failed");
            }
        });
    }

    /// The engine is still running.
    fn runnable(&self) -> Result<(), SourceError> {
        if self.shared.is_stopped() {
            // After `Engine::stop` there is no runtime any more; a `block_on` would run into a
            // closed one. The Explorer gets the reason it can display.
            return Err(SourceError::NotSignedIn);
        }
        Ok(())
    }
}

impl NamespaceSource for EngineSource {
    fn children(&self, container: Container) -> Result<Vec<Entry>, SourceError> {
        self.runnable()?;
        let state = self.shared.store().container_state(container).map_err(internal)?;
        match &state {
            // Never fetched: here there **must** be waiting. A folder that appears empty on the
            // first expand is a statement about the archive, and it would be false.
            None => {
                let shared = Arc::clone(&self.shared);
                let result = self.in_engine(async move {
                    crate::reconcile::fetch_if_needed(&shared, container).await
                });
                if let Err(error) = result {
                    return Err(as_source_error(&error, container));
                }
            }
            // Remembered but old: the remembered state goes out **at once**, the fresh one comes
            // in the background and reports itself over `report_change` or the change journal. On
            // Windows every callback has 60 seconds — a network fetch in the callback path is
            // exactly what makes the Explorer hang; and offline it would be an empty folder instead
            // of yesterday's state (ADR-D01, point 8).
            Some(state) if stale(state.fetched) => self.trigger_reconcile(container),
            Some(_) => {}
        }
        match self.shared.store().children(container) {
            Ok(children) => Ok(children),
            // The root stands even without any fetch: it is fixed (edms_core::namespace).
            Err(StoreError::ContainerUnknown(_)) if container == Container::Root => {
                Ok(root_entries(self.shared.configuration.language))
            }
            Err(StoreError::ContainerUnknown(_)) => {
                Err(SourceError::NotFound(EntryIdentifier::Container(container)))
            }
            Err(error) => Err(internal(error)),
        }
    }

    fn entry(&self, identifier: EntryIdentifier) -> Result<Entry, SourceError> {
        self.runnable()?;
        if identifier == EntryIdentifier::ROOT {
            return Ok(Entry {
                identifier,
                name: NAME_ROOT.to_owned(),
                content: edms_core::namespace::EntryContent::Folder,
            });
        }
        if let Some(entry) = self.shared.store().entry(identifier).map_err(internal)? {
            return Ok(entry);
        }
        // The fixed children of the root exist before anything has ever been reconciled.
        root_entries(self.shared.configuration.language)
            .into_iter()
            .find(|entry| entry.identifier == identifier)
            .ok_or(SourceError::NotFound(identifier))
    }

    fn current_sequence(&self) -> Result<u64, SourceError> {
        self.runnable()?;
        self.shared.store().current_sequence().map_err(internal)
    }

    fn changes_since(&self, sequence: u64, max: usize) -> Result<ChangeState, SourceError> {
        self.runnable()?;
        match self.shared.store().changes_since(sequence, max) {
            Ok(state) => Ok(state),
            // The anchor is older than the journal, or it comes from a different database (after a
            // sign-out, say): the platform then enumerates everything afresh instead of guessing
            // gaps.
            Err(StoreError::AnchorExpired { .. } | StoreError::AnchorUnknown { .. }) => {
                Err(SourceError::AnchorExpired)
            }
            Err(error) => Err(internal(error)),
        }
    }

    fn content(
        &self,
        identifier: EntryIdentifier,
        request: &ContentRequest,
        sink: &mut dyn ContentSink,
    ) -> Result<ContentReceipt, SourceError> {
        self.runnable()?;
        let shared = Arc::clone(&self.shared);
        self.in_engine(async move {
            crate::hydration::hydrate(&shared, identifier, request, sink).await
        })
    }
}

/// Whether a remembered listing is old enough to be pulled up in the background.
fn stale(fetched: edms_core::time::Timestamp) -> bool {
    let age = now().unix_millis().saturating_sub(fetched.unix_millis());
    age < 0 || age >= i64::try_from(FRESHNESS.as_millis()).unwrap_or(i64::MAX)
}

/// A store error is an error of this program, not a judgement of the server.
fn internal(error: StoreError) -> SourceError {
    SourceError::Internal(error.to_string())
}

/// Translates a failed reconcile into the reason the Explorer shows.
fn as_source_error(error: &crate::EngineError, container: Container) -> SourceError {
    match error {
        crate::EngineError::NoNetwork(_) => SourceError::NoNetwork,
        crate::EngineError::NotSignedIn
        | crate::EngineError::EnrollmentCodeMissing
        | crate::EngineError::SessionExpired(_) => SourceError::NotSignedIn,
        crate::EngineError::Security(notice) => SourceError::Server(notice.clone()),
        crate::EngineError::Refused(notice) => SourceError::Server(notice.clone()),
        crate::EngineError::Store(StoreError::ContainerUnknown(_)) => {
            SourceError::NotFound(EntryIdentifier::Container(container))
        }
        other => SourceError::Internal(other.to_string()),
    }
}
