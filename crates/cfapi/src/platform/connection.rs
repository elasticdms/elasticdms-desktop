//! The connection to the root: `CfConnectSyncRoot` and `CfDisconnectSyncRoot`.
//!
//! Registering and connecting are two different things. **Registration**
//! ([`super::registration`]) survives a restart and makes the folder a sync root; the
//! **connection** holds only for as long as this process runs and is the promise to answer
//! callbacks. A root has exactly one connection: the second `CfConnectSyncRoot` gets
//! `ERROR_CLOUD_FILE_ALREADY_CONNECTED` — the reliable single-instance signal on Windows
//! (02-platform-decision §1.2).
//!
//! ## The three connection flags
//!
//! | Flag | Why |
//! |---|---|
//! | `REQUIRE_PROCESS_INFO` | Without it `CF_CALLBACK_INFO::ProcessInfo` is empty, and the server would never learn **which program** opened a document (ADR-D01 §4). |
//! | `REQUIRE_FULL_FILE_PATH` | Without it only a partial path arrives, and the exemption list against our own veto would not bite ([`crate::exemptions`]). |
//! | `BLOCK_SELF_IMPLICIT_HYDRATION` | If this process reads a placeholder itself, it deadlocks with itself: the callback waits for the read, which waits for the callback (ADR-D06 §6). |
//!
//! ## The context pointer
//!
//! `CfConnectSyncRoot` takes an opaque pointer and gives it back in every callback. Here it is an
//! `Arc<Inner>`, turned into a pointer with `Arc::into_raw`: the connection thereby holds a share
//! of the shared state, and the state cannot disappear for as long as callbacks can still arrive.
//! The share is given back only **after** `CfDisconnectSyncRoot`, because that waits for callbacks
//! in flight.
//!
//! cloud-filter 0.0.6 uses `Weak::into_raw` in the same place and never gives the pointer back — a
//! leak per connection and a `Weak` that can point into the void during a callback.

use std::sync::Arc;

use windows::Win32::Storage::CloudFilters::{
    CF_CALLBACK_REGISTRATION, CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
    CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
    CF_CONNECTION_KEY, CfConnectSyncRoot, CfDisconnectSyncRoot,
};
use windows::core::PCWSTR;

use crate::error::MirrorError;
use crate::path::for_win32;
use crate::raw::is_already_connected;

use super::Inner;
use super::callback::table;
use super::win::{error, wide};

/// An open connection. It disconnects when it is dropped.
#[derive(Debug)]
pub(crate) struct Connection {
    key: i64,
    /// The pointer from `Arc::into_raw`, as a number — so that this value may travel between
    /// threads without any further guarantee.
    context: usize,
    /// The callback table, kept in case cldflt does not copy it after all.
    _table: Box<[CF_CALLBACK_REGISTRATION; 10]>,
}

impl Connection {
    /// Connects to the root at `path`.
    pub(crate) fn open(path: &str, inner: &Arc<Inner>) -> Result<Self, MirrorError> {
        let wide_path = wide(&for_win32(path))?;
        let table = Box::new(table());
        let context = Arc::into_raw(Arc::clone(inner));
        // SAFETY: `wide_path` and `table` live beyond the call (the table until the disconnect);
        // `context` is a valid pointer from `Arc::into_raw` whose share this connection holds
        // until it gives it back in `Drop`.
        let result = unsafe {
            CfConnectSyncRoot(
                PCWSTR(wide_path.as_ptr()),
                table.as_ptr(),
                Some(context.cast()),
                CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO
                    | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH
                    | CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
            )
        };
        match result {
            Ok(key) => Ok(Self { key: key.0, context: context as usize, _table: table }),
            Err(e) => {
                // SAFETY: `context` came out of `Arc::into_raw` just now and was taken over
                // nowhere else — cldflt did not keep it on an error.
                drop(unsafe { Arc::from_raw(context) });
                Err(if is_already_connected(e.code().0) {
                    MirrorError::ForeignRoot {
                        path: path.to_owned(),
                        identifier: "a session that is already connected (elasticdms is \
                             already running)"
                            .to_owned(),
                    }
                } else {
                    error("CfConnectSyncRoot", &e)
                })
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: `self.key` comes from a successful `CfConnectSyncRoot` and is disconnected
        // exactly once — `Connection` is neither `Copy` nor `Clone`.
        if let Err(error) = unsafe { CfDisconnectSyncRoot(CF_CONNECTION_KEY(self.key)) } {
            // An error on disconnect cannot be recovered from and must not hold up the sign-out.
            // cloud-filter 0.0.6 calls `.unwrap()` here — a panic in `Drop`, that is an abort in
            // the middle of the sign-out, at exactly the moment the user's data is meant to go.
            tracing::error!(%error, "CfDisconnectSyncRoot failed");
        }
        // SAFETY: only now, after the disconnect, can no callback still be running; the share of
        // the shared state goes back. `context` is the pointer from `Arc::into_raw` and is taken
        // back exactly once.
        drop(unsafe { Arc::from_raw(self.context as *const Inner) });
    }
}
