//! Thread hand-off: File Provider asks on one thread, the answer comes from another.
//!
//! Every method of the extension should return quickly and call its completion block later
//! (NSFileProviderReplicatedExtension.h). The source, though, answers synchronously and over a
//! channel to the app — loading large files takes time. Whoever waits on the system's thread stops
//! its XPC queue: while one file was loading, Finder would show no other folder at all. That is why
//! every request runs on a thread of its own.

use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

/// A value that may cross threads, because Foundation guarantees it on its behalf.
///
/// Completion blocks and observers of File Provider are not `Send` in Rust: a block can capture
/// arbitrary state, a protocol object can be implemented arbitrarily. But the system explicitly
/// accepts them from any thread. This wrapper makes the guarantee visible — at every place where
/// it is given, with a reason.
pub(crate) struct ThreadFixed<T>(T);

impl<T> ThreadFixed<T> {
    /// Wraps a value.
    ///
    /// # Safety
    ///
    /// The caller guarantees that `value` may be used and released from any thread — for blocks
    /// and observers of File Provider, because the system documents it that way and itself calls
    /// from arbitrary queues.
    pub(crate) unsafe fn new(value: T) -> Self {
        Self(value)
    }

    /// The wrapped value.
    pub(crate) fn value(&self) -> &T {
        &self.0
    }

    /// Takes the value back out.
    ///
    /// The counterpart to [`ThreadFixed::new`]: the wrapper has carried the value across the
    /// thread boundary, after which it is an ordinary value again. Separate from
    /// [`ThreadFixed::value`], because only this way can a `Retained` be passed on without holding
    /// it a second time.
    pub(crate) fn into_value(self) -> T {
        self.0
    }
}

// SAFETY: the guarantee is given by the caller of `ThreadFixed::new` (see there).
unsafe impl<T> Send for ThreadFixed<T> {}

/// Runs `work` on a thread of its own.
///
/// If no thread can be started (resources exhausted), the work runs on the calling thread: slower,
/// but the completion block does get called. A block that is never called would leave the system
/// waiting for an answer that never comes.
pub(crate) fn in_background<F>(name: &str, work: F)
where
    F: FnOnce() + Send + 'static,
{
    let slot = Arc::new(Mutex::new(Some(work)));
    let slot_in_thread = Arc::clone(&slot);
    let started = thread::Builder::new().name(name.to_owned()).spawn(move || {
        if let Some(work) = take(&slot_in_thread) {
            work();
        }
    });
    if let Err(error) = started {
        tracing::warn!(
            thread = name,
            %error,
            "thread not started; the request runs on the system's thread"
        );
        if let Some(work) = take(&slot) {
            work();
        }
    }
}

fn take<F>(slot: &Mutex<Option<F>>) -> Option<F> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn the_work_runs_on_a_named_thread_of_its_own() {
        let (tx, rx) = mpsc::channel();
        let caller = thread::current().id();
        in_background("edms-test", move || {
            let now = thread::current();
            tx.send((now.id(), now.name().map(str::to_owned))).unwrap();
        });
        let (id, name) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(id, caller);
        assert_eq!(name.as_deref(), Some("edms-test"));
    }
}
