//! The hydrations in flight and their cancellation switches.
//!
//! `CANCEL_FETCH_DATA` arrives on a callback thread while the hydration is hanging on the network
//! on a worker thread. The callback must not wait — it only flips a switch. The engine reads it
//! through [`edms_core::port::ContentSink::cancelled`] and drops the download.
//!
//! Without this list every cancelled hydration would run on until the server had answered: the
//! user closes the preview window and the folder client downloads 200 MB to the end all the same
//! — at the cost of their data allowance and with an access in the server log that nobody wanted.
//!
//! The key is the transfer key (`CF_CALLBACK_INFO::TransferKey`): the same value appears in the
//! cancellation callback as in the request it cancels.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The switches of all transfers in flight.
#[derive(Debug, Default)]
pub struct Cancellations(Mutex<HashMap<i64, Arc<AtomicBool>>>);

impl Cancellations {
    fn lock(&self) -> MutexGuard<'_, HashMap<i64, Arc<AtomicBool>>> {
        // A panic elsewhere must not make the list unusable: otherwise no hydration could be
        // cancelled any more, and every cancellation by the user would run into the void.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers a transfer and returns its switch.
    pub fn sign_in(&self, transfer: i64) -> Arc<AtomicBool> {
        let switch = Arc::new(AtomicBool::new(false));
        self.lock().insert(transfer, Arc::clone(&switch));
        switch
    }

    /// Flips the switch of a transfer.
    ///
    /// An unknown key is not an error: the cancellation can arrive after the hydration has already
    /// finished — cldflt and the worker thread run alongside each other.
    pub fn abort(&self, transfer: i64) {
        if let Some(switch) = self.lock().get(&transfer) {
            switch.store(true, Ordering::Relaxed);
        }
    }

    /// Takes a finished transfer out of the list.
    pub fn sign_out(&self, transfer: i64) {
        self.lock().remove(&transfer);
    }

    /// Cancels everything and empties the list — on disconnect and on sign-out.
    pub fn all_abort(&self) {
        let mut list = self.lock();
        for switch in list.values() {
            switch.store(true, Ordering::Relaxed);
        }
        list.clear();
    }

    /// How many transfers are in flight right now.
    pub fn count(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancellation_reaches_exactly_its_own_transfer() {
        let list = Cancellations::default();
        let one = list.sign_in(7);
        let other = list.sign_in(8);
        list.abort(7);
        assert!(one.load(Ordering::Relaxed));
        assert!(!other.load(Ordering::Relaxed), "the neighbour keeps downloading");
    }

    #[test]
    fn a_cancellation_for_a_finished_transfer_is_not_an_error() {
        let list = Cancellations::default();
        let _ = list.sign_in(7);
        list.sign_out(7);
        list.abort(7);
        list.abort(999);
        assert_eq!(list.count(), 0);
    }

    #[test]
    fn on_disconnect_every_hydration_in_flight_is_cancelled() {
        let list = Cancellations::default();
        let a = list.sign_in(1);
        let b = list.sign_in(2);
        list.all_abort();
        assert!(a.load(Ordering::Relaxed) && b.load(Ordering::Relaxed));
        assert_eq!(list.count(), 0, "after the disconnect the list holds on to nothing");
    }
}
