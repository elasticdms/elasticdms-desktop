//! The channel to the app: where the engine serves the namespace source.
//!
//! The extension is a sandboxed process of its own; the engine lives in the app. It reaches the
//! source through `edms-bridge`: TCP on 127.0.0.1, port and secret in the rendezvous file
//! (ADR-D05, [`crate::home`]).
//!
//! **The app is not always running.** After a restart the user opens Finder before elasticdms has
//! started; the system then starts the extension, and there is nobody to ask. `initWithDomain:`
//! must not fail over that — it has no error path. That is why the holder tries to connect when it
//! is created but only remembers success; every request without a channel tries again, and
//! otherwise fails with "app not reachable" (`ServerUnreachable`): the system then waits until the
//! app signals the working set at startup.
//!
//! **A broken channel is discarded.** If the source reports `Internal`, the channel may be dead
//! (app restarted, new port); the holder discards it, and the next request reads the rendezvous
//! file afresh. A server error or `NoNetwork` concerns the engine, not the channel, and leaves it
//! standing.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use edms_core::port::{NamespaceSource, SourceError};

use crate::error::ProviderError;
use crate::identifier::SystemIdentifiers;

/// Where the source comes from.
pub(crate) enum ConnectionRoute {
    /// Through `edms-bridge`; the path names the rendezvous file.
    Rendezvous(PathBuf),
    /// The rendezvous file cannot even be named; every request fails with that reason.
    Undeterminable(String),
    /// A source put in place for good (test harness); it is never reconnected.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "only the test harness puts a source in place for good")
    )]
    Fixed,
}

/// Holds the source, connects when needed and discards a broken channel.
pub(crate) struct SourceHolder {
    route: ConnectionRoute,
    source: Mutex<Option<Arc<dyn NamespaceSource>>>,
}

impl SourceHolder {
    /// A holder that tries to connect immediately and otherwise tries again on every request.
    pub(crate) fn over_bridge(route: ConnectionRoute) -> Self {
        let holder = Self { route, source: Mutex::new(None) };
        if let Err(error) = holder.source() {
            tracing::info!(
                %error,
                "the channel to the app is not up yet; the first request will try again"
            );
        }
        holder
    }

    /// A holder with a source put in place for good.
    #[cfg(test)]
    pub(crate) fn fixed(source: Arc<dyn NamespaceSource>) -> Self {
        Self { route: ConnectionRoute::Fixed, source: Mutex::new(Some(source)) }
    }

    /// The source; connects if necessary.
    pub(crate) fn source(&self) -> Result<Arc<dyn NamespaceSource>, ProviderError> {
        let mut source = self.lock();
        if let Some(existing) = source.as_ref() {
            return Ok(Arc::clone(existing));
        }
        let new = match &self.route {
            ConnectionRoute::Rendezvous(path) => connect(path)?,
            ConnectionRoute::Undeterminable(reason) => {
                return Err(ProviderError::AppNotReachable(reason.clone()));
            }
            ConnectionRoute::Fixed => {
                return Err(ProviderError::AppNotReachable("the connection was released".into()));
            }
        };
        *source = Some(Arc::clone(&new));
        Ok(new)
    }

    /// Releases the source (`invalidate`: after it nothing may hang off the instance any more).
    pub(crate) fn release(&self) {
        *self.lock() = None;
    }

    /// Discards the channel if the error can mean a broken channel (module header).
    pub(crate) fn after_error(&self, error: &ProviderError) {
        let link_error = matches!(error, ProviderError::Source(SourceError::Internal(_)));
        if link_error && !matches!(self.route, ConnectionRoute::Fixed) {
            self.release();
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Arc<dyn NamespaceSource>>> {
        self.source.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn connect(path: &Path) -> Result<Arc<dyn NamespaceSource>, ProviderError> {
    match edms_bridge::BridgeClient::from_rendezvous(path) {
        Ok(client) => Ok(Arc::new(client)),
        Err(error) => Err(ProviderError::AppNotReachable(error.to_string())),
    }
}

/// What every request to an extension instance needs: source, name of the root, system identifiers.
pub(crate) struct Context {
    source: SourceHolder,
    display_name: String,
    identifiers: &'static SystemIdentifiers,
}

impl Context {
    /// A context for one domain.
    pub(crate) fn new(source: SourceHolder, display_name: String) -> Self {
        Self { source, display_name, identifiers: SystemIdentifiers::of_the_system() }
    }

    /// Display name of the domain, and at the same time the name of the root.
    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The identifiers of the system.
    pub(crate) fn identifiers(&self) -> &'static SystemIdentifiers {
        self.identifiers
    }

    /// Asks the source; discards a broken channel afterwards.
    pub(crate) fn ask<T>(
        &self,
        request: impl FnOnce(&dyn NamespaceSource) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let source = self.source.source()?;
        let result = request(&*source);
        if let Err(error) = &result {
            self.source.after_error(error);
        }
        result
    }

    /// Releases the source.
    pub(crate) fn release(&self) {
        self.source.release();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::harness::sample_source;

    #[test]
    fn without_a_determinable_route_the_app_is_not_reachable_with_a_reason() {
        let holder =
            SourceHolder::over_bridge(ConnectionRoute::Undeterminable("no home directory".into()));
        let Err(error) = holder.source() else { panic!("without a route no source may arrive") };
        assert_eq!(error, ProviderError::AppNotReachable("no home directory".into()));
        assert_eq!(error.error_image().code, -1004);
    }

    #[test]
    fn a_missing_rendezvous_file_is_app_not_reachable_and_not_a_crash() {
        let path = std::env::temp_dir().join(format!("edms-no-bridge-{}.json", std::process::id()));
        let holder = SourceHolder::over_bridge(ConnectionRoute::Rendezvous(path));
        assert!(matches!(holder.source(), Err(ProviderError::AppNotReachable(_))));
    }

    #[test]
    fn after_a_release_a_fixed_source_delivers_nothing_more() {
        let holder = SourceHolder::fixed(Arc::new(sample_source()));
        assert!(holder.source().is_ok());
        holder.release();
        assert!(matches!(holder.source(), Err(ProviderError::AppNotReachable(_))));
    }

    #[test]
    fn ask_passes_the_error_of_the_source_through() {
        let source = Arc::new(sample_source());
        let context = Context::new(SourceHolder::fixed(source.clone()), "elasticdms".into());
        let error = context
            .ask(|q| Ok(q.entry(edms_core::namespace::EntryIdentifier::ROOT)?))
            .expect_err("an error");
        assert!(matches!(error, ProviderError::Source(SourceError::NotFound(_))));
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        // A fixed source stays in place even after an error.
        assert!(context.ask(|q| Ok(q.current_sequence()?)).is_ok());
    }
}
