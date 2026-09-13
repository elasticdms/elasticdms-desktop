//! The sink for `FETCH_DATA`: bytes loaded and verified by the engine, on to cldflt.
//!
//! [`edms_core::port::NamespaceSource::content`] writes however it likes — a 200 MB chunk in one
//! go, or a thousand bytes at a time. cldflt accepts only 4 KB-aligned chunks. Between the two
//! sits [`BlockBuffer`]; this sink is the thin layer around it that reports progress and passes
//! cancellation through.
//!
//! ## The 60-second deadline
//!
//! Every request from cldflt expires after 60 seconds if nothing happens. The deadline is pushed
//! back by every successful `CfExecute` **and** by `CfReportProviderProgress`. When large files
//! are being loaded, not a single byte reaches the sink for a long time (the engine first loads
//! completely and checks the checksum, `edms_core::port` — no byte reaches the platform before the
//! hash matches). During that time the progress report alone keeps the request alive. Without it
//! Explorer aborts every file over 60 MB at 1 MB/s — and the user would see "the cloud operation
//! was unsuccessful" on a document that was loading perfectly well.
//!
//! A report goes out at most every [`PROGRESS_SPACING`], not on every call: the engine happily
//! reports once per network chunk, and every report is a transition into the kernel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use edms_core::port::{ContentSink, SinkError};

use crate::blocks::{BlockBuffer, BlockError};

use super::command::{RequestKey, report_progress, transfer_data};

/// Maximum spacing between two progress reports. One sixth of the deadline — plenty of room, even
/// if a report is dropped once.
pub(crate) const PROGRESS_SPACING: Duration = Duration::from_secs(10);

/// Takes verified content and passes it on to cldflt, 4 KB-aligned.
#[derive(Debug)]
pub(crate) struct TransferSink {
    key: RequestKey,
    buffer: BlockBuffer,
    abort: Arc<AtomicBool>,
    to_last_reported: Instant,
}

impl TransferSink {
    /// For a file of `size` bytes.
    pub(crate) fn new(key: RequestKey, size: u64, abort: Arc<AtomicBool>) -> Self {
        Self {
            key,
            buffer: BlockBuffer::new(size),
            abort,
            // Set so that the first progress report goes out immediately: Explorer should see
            // the bar as soon as the user has double-clicked.
            to_last_reported: Instant::now()
                .checked_sub(PROGRESS_SPACING)
                .unwrap_or_else(Instant::now),
        }
    }

    /// How many bytes are already at cldflt — the start of the range that is still open in the
    /// error case ([`crate::blocks::error_domain`]).
    pub(crate) const fn sent(&self) -> u64 {
        self.buffer.sent()
    }

    /// Passes the remainder on and establishes that everything arrived.
    ///
    /// A call that has to exist: the last, ragged chunk may only go out once it is certain that it
    /// ends at the end of the file. Without it the tail of every file would stay in the buffer, and
    /// cldflt would wait for bytes that are already there.
    pub(crate) fn complete(&mut self) -> Result<u64, BlockError> {
        let key = self.key;
        self.buffer.complete(|offset, data| send(key, offset, data))
    }
}

fn send(key: RequestKey, offset: u64, data: &[u8]) -> Result<(), SinkError> {
    transfer_data(key, offset, data).map_err(|e| SinkError(e.to_string()))
}

impl ContentSink for TransferSink {
    fn progress(&mut self, loaded: u64, total: u64) {
        if self.to_last_reported.elapsed() < PROGRESS_SPACING {
            return;
        }
        self.to_last_reported = Instant::now();
        if let Err(error) = report_progress(self.key, total, loaded) {
            // No reason to abort: the report is only display and deadline extension. If the
            // deadline really does run out, the next transfer fails with a reason of its own.
            tracing::debug!(%error, "progress could not be reported");
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), SinkError> {
        let key = self.key;
        self.buffer.take(offset, data, |v, d| send(key, v, d)).map_err(SinkError::from)
    }

    fn cancelled(&self) -> bool {
        self.abort.load(Ordering::Relaxed)
    }
}
