//! The hydration — and the one promise it carries.
//!
//! **No byte reaches the platform before the checksum matches** (`edms_core::port`, "The promise
//! about the content"). The server notices a hash error only at the last `Read`, long after `200`
//! and all headers have been sent (contract test T13); a client that passes bytes through as they
//! come puts a mutilated file into the user's folder and takes it for complete. Hence the detour:
//!
//! ```text
//! server ──stream──▶ scratch area (<ulid>.part)      SHA-256 alongside, progress to the sink
//!                        │
//!                        ├── size and checksum against the row of the listing
//!                        │      ✗ → file gone, SourceError::Integrity, sink stays empty
//!                        ▼ ✓
//!                   content sink (platform)          in chunks, ascending and without gaps
//! ```
//!
//! The **progress** goes to the sink during the load already: on Windows that resets the 60-second
//! deadline of every callback (`CfReportProviderProgress`), otherwise the Explorer aborts large
//! files. The progress is **no** handover of content — writing happens only after the check.
//!
//! **Every hydration is an access and belongs in the log** (requirement 9). The authoritative log
//! is kept by the server (every hydration runs over it); locally stands the row
//! [`edms_core::log::LogKind::Opened`] — and on a failure `OpenFailed`, because a quiet failure
//! would be an access nobody sees.
//!
//! **Hint files come without the network.** `LIESMICH.txt` and "hit list truncated" are produced by
//! `edms_core::namespace`; they have no checksum, because there is none that would come from
//! anywhere.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use edms_core::checksum::Sha256Value;
use edms_core::identifier::DocumentIdentifier;
use edms_core::log::{LogEntry, LogKind, Subject};
use edms_core::namespace::{
    Container, Entry, EntryIdentifier, FileDetails, HintKind, Location, Truncation,
    hint_text_read_me, hint_text_truncated,
};
use edms_core::port::{ContentReceipt, ContentRequest, ContentSink, SourceError};
use edms_crypto::checksum::Sha256Machine;
use edms_net::ApiResult;
use edms_wire::basics::{ErrorKind, WireTimestamp};
use edms_wire::namespace::DocumentRow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::engine::Shared;
use crate::time::now;

/// File extension of the half-finished loads in the scratch area.
///
/// `teil` until 2026-09-13, on the same argument that kept the scratch area itself called
/// `zwischenablage` — and void for the same reason (ADR-D10, correction of 2026-09-13). Only
/// [`clear_staging`] and the leftovers row of `doctor` read it, both inside the scratch area, and
/// that directory was renamed in the same pass: a `.teil` left over from an older run lies in the
/// old directory, which no build reaches any more.
pub const EXTENSION_PART: &str = "part";

/// Chunk size in which checked content goes to the platform.
///
/// 256 KiB: large enough that a 200 MB receipt does not end up in 200 000 callbacks, small enough
/// that an abort by the user is noticed between two chunks.
pub const CHUNK: usize = 256 * 1024;

/// Deletes half-finished loads of an earlier run.
///
/// They carry no checked content — a crash in the middle of a load leaves exactly such a file
/// behind. Whoever left them lying would fill the user's disk with receipts nobody ever looks at
/// again.
pub(crate) fn clear_staging(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut cleared = 0_usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|end| end == EXTENSION_PART)
            && std::fs::remove_file(&path).is_ok()
        {
            cleared += 1;
        }
    }
    if cleared > 0 {
        tracing::info!(cleared, "half-finished loads removed from the scratch area");
    }
}

/// Delivers the content of an entry into the sink.
///
/// # Errors
///
/// [`SourceError`] — every variant has a counterpart of its own on Windows and macOS, so that the
/// user sees the right reason in the Explorer or the Finder.
pub(crate) async fn hydrate(
    shared: &Arc<Shared>,
    identifier: EntryIdentifier,
    request: &ContentRequest,
    sink: &mut dyn ContentSink,
) -> Result<ContentReceipt, SourceError> {
    match identifier {
        EntryIdentifier::Hint { location, kind } => hint(shared, location, kind, sink),
        EntryIdentifier::Container(_) => Err(SourceError::NotFound(identifier)),
        EntryIdentifier::Document { location, document } => {
            load_document(shared, identifier, location, document, request, sink).await
        }
    }
}

/// A locally produced hint file — without the network, without a checksum, without a log row.
///
/// Without a log row on purpose: the log shows accesses to **documents of the archive**; an
/// explanatory text this client wrote itself is not one.
fn hint(
    shared: &Shared,
    location: Container,
    kind: HintKind,
    sink: &mut dyn ContentSink,
) -> Result<ContentReceipt, SourceError> {
    let language = shared.configuration.language;
    let text = match kind {
        HintKind::ReadMe => hint_text_read_me(language),
        HintKind::Truncated => {
            let state = shared
                .store()
                .container_state(location)
                .map_err(|error| SourceError::Internal(error.to_string()))?
                .and_then(|state| state.truncation);
            match &state {
                Some(truncation) => hint_text_truncated(truncation.as_truncation(), language),
                // The hint stands only in truncated listings; if the truncation has gone in the
                // meantime, the entry is removed at the next reconcile. Until then an honest, empty
                // state instead of an invented number.
                None => hint_text_truncated(Truncation { displayed: 0, address: None }, language),
            }
        }
    };
    let bytes = text.as_bytes();
    sink.progress(0, bytes.len() as u64);
    sink.write(0, bytes)?;
    Ok(ContentReceipt { size: bytes.len() as u64, sha256: None })
}

/// The content of a document: load, check, and only then hand over.
async fn load_document(
    shared: &Arc<Shared>,
    identifier: EntryIdentifier,
    location: Location,
    document: DocumentIdentifier,
    request: &ContentRequest,
    sink: &mut dyn ContentSink,
) -> Result<ContentReceipt, SourceError> {
    let entry = shared
        .store()
        .entry(identifier)
        .map_err(|error| SourceError::Internal(error.to_string()))?
        .ok_or(SourceError::NotFound(identifier))?;
    let details = entry
        .file()
        .ok_or_else(|| SourceError::Internal(format!("`{identifier}` is a folder")))?
        .clone();
    let expected = details
        .sha256
        .ok_or_else(|| SourceError::Internal(format!("`{identifier}` carries no checksum")))?;

    let result = load_and_check(shared, &entry, &details, document, expected, request, sink).await;
    match &result {
        Ok(_) => append_log(shared, LogKind::Opened, &entry, location, document, None),
        Err(error) => append_log(
            shared,
            LogKind::OpenFailed,
            &entry,
            location,
            document,
            Some(error.to_string()),
        ),
    }
    result
}

async fn load_and_check(
    shared: &Arc<Shared>,
    entry: &Entry,
    details: &FileDetails,
    document: DocumentIdentifier,
    expected: Sha256Value,
    request: &ContentRequest,
    sink: &mut dyn ContentSink,
) -> Result<ContentReceipt, SourceError> {
    // Before the first byte: without a valid token there is no access, and a `401` in the middle
    // of the stream would cost the user the file he is opening.
    let signed_in = crate::session::ensure_for_token(shared)
        .await
        .map_err(|error| SourceError::Server(error.to_string()))?;
    if !signed_in {
        return Err(SourceError::NotSignedIn);
    }
    let _permit = shared
        .load_gate
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| SourceError::Internal(error.to_string()))?;
    if sink.cancelled() {
        return Err(SourceError::Cancelled);
    }

    let row = row_from(entry, details, document)?;
    let path = staging_file(shared)?;
    let mut result = stream_in_file(shared, entry, &row, request, sink, &path).await;
    // Exactly **one** second attempt when the server rejects the token: renew, load anew. The
    // stream cannot be resumed — the checksum holds only for the whole file.
    if matches!(result, Err(SourceError::NotSignedIn))
        && crate::session::force_refresh(shared).await.unwrap_or(false)
    {
        let _ = tokio::fs::remove_file(&path).await;
        result = stream_in_file(shared, entry, &row, request, sink, &path).await;
    }
    match result {
        Ok(()) => {}
        Err(error) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(error);
        }
    }
    let handover = hand_over(&path, sink).await;
    let _ = tokio::fs::remove_file(&path).await;
    handover?;
    Ok(ContentReceipt { size: details.size, sha256: Some(expected) })
}

/// Loads into the scratch file and checks size and checksum against the row of the listing.
///
/// The two expected values are not handed in separately: they stand in `row`, and that one is
/// what the server checks its answer against — two sources for the same number could disagree,
/// and then the check would say nothing.
async fn stream_in_file(
    shared: &Arc<Shared>,
    entry: &Entry,
    row: &DocumentRow,
    request: &ContentRequest,
    sink: &mut dyn ContentSink,
    path: &Path,
) -> Result<(), SourceError> {
    let expected_size = row.size;
    let expected_checksum = row.sha256;
    let file = tokio::fs::File::create(path)
        .await
        .map_err(|error| SourceError::Internal(format!("Zwischendatei: {error}")))?;
    let mut writer = CountingSink {
        file,
        machine: Sha256Machine::new(),
        written: 0,
        total: expected_size,
        sink,
    };
    let result = shared
        .server
        .load_content(row, request.requesting_application.as_deref(), &mut writer)
        .await;
    let report = match result {
        ApiResult::Success(success) => success.value,
        other => return Err(source_error_from(&other, entry.identifier)),
    };
    writer
        .file
        .flush()
        .await
        .map_err(|error| SourceError::Internal(format!("Zwischendatei: {error}")))?;
    let computed = writer.machine.finished();
    let written = writer.written;

    if report.bytes != expected_size || written != expected_size {
        return Err(SourceError::Incomplete { expected: expected_size, actual: written });
    }
    if computed != expected_checksum {
        // Exactly here the promise holds: loaded, checked, **not** taken over. The sink has so far
        // seen only progress, not a single byte.
        return Err(SourceError::Integrity { expected: expected_checksum, actual: computed });
    }
    Ok(())
}

/// Pushes the checked bytes into the sink chunk by chunk.
async fn hand_over(path: &Path, sink: &mut dyn ContentSink) -> Result<(), SourceError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| SourceError::Internal(format!("Zwischendatei: {error}")))?;
    let mut buffer = vec![0_u8; CHUNK];
    let mut offset = 0_u64;
    loop {
        if sink.cancelled() {
            return Err(SourceError::Cancelled);
        }
        let read = read_chunk(&mut file, &mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        sink.write(offset, &buffer[..read])?;
        offset = offset.saturating_add(read as u64);
    }
}

async fn read_chunk(
    file: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
) -> Result<usize, SourceError> {
    file.read(buffer)
        .await
        .map_err(|error| SourceError::Internal(format!("Zwischendatei: {error}")))
}

/// The path of a new scratch file.
fn staging_file(shared: &Shared) -> Result<PathBuf, SourceError> {
    let name = edms_crypto::random::ulid(now())
        .map_err(|error| SourceError::Internal(error.to_string()))?;
    Ok(crate::engine::staging(shared).join(format!("{name}.{EXTENSION_PART}")))
}

/// The row of the listing as `edms-net` needs it for checking the headers.
///
/// It comes out of the stored entry: version, size, checksum and media type are exactly the four
/// values `load_content` checks against **before** a single byte is read. Title and times go into
/// no check; the file name stands here so that an error text names the name the user sees in the
/// folder.
fn row_from(
    entry: &Entry,
    details: &FileDetails,
    document: DocumentIdentifier,
) -> Result<DocumentRow, SourceError> {
    let sha256 = details
        .sha256
        .ok_or_else(|| SourceError::Internal("entry without a checksum".to_owned()))?;
    Ok(DocumentRow {
        document_id: document,
        title: entry.name.clone(),
        media_type: details.media_type.clone(),
        size: details.size,
        sha256,
        version: details.version.clone(),
        created_at: WireTimestamp::from_timestamp(details.created),
        updated_at: WireTimestamp::from_timestamp(details.changed),
    })
}

/// Writes the row of the access into the local usage log.
fn append_log(
    shared: &Shared,
    kind: LogKind,
    entry: &Entry,
    location: Location,
    document: DocumentIdentifier,
    detail: Option<String>,
) {
    let location_name = shared
        .store()
        .entry(EntryIdentifier::Container(Container::from(location)))
        .ok()
        .flatten()
        .map(|entry| entry.name);
    let subject =
        Subject { name: entry.name.clone(), document: Some(document), location: location_name };
    match LogEntry::new(now(), kind, Some(subject), detail) {
        Ok(row) => shared.append_log(&row),
        Err(error) => tracing::error!(%error, "usage-log row rejected"),
    }
}

/// Translates a failed server call into the reason the Explorer shows.
pub(crate) fn source_error_from<T>(
    result: &ApiResult<T>,
    identifier: EntryIdentifier,
) -> SourceError {
    match result {
        ApiResult::NetworkError(edms_net::NetworkError::Incomplete { expected, actual }) => {
            SourceError::Incomplete { expected: *expected, actual: *actual }
        }
        ApiResult::NetworkError(error) => {
            tracing::warn!(%error, %identifier, "content not loaded");
            SourceError::NoNetwork
        }
        ApiResult::SecurityAbort { notice, .. } => SourceError::Server(notice.clone()),
        ApiResult::StepUpNeeded { .. } => SourceError::NotSignedIn,
        ApiResult::Unchanged { .. } => {
            SourceError::Internal("the server answered 304 to a content request".to_owned())
        }
        ApiResult::Success(_) => SourceError::Internal("success read as an error".to_owned()),
        ApiResult::SlotError { problem, .. } => match problem.error_kind() {
            ErrorKind::NotFound | ErrorKind::RenditionNotAvailable => {
                SourceError::NotFound(identifier)
            }
            ErrorKind::ScopeMissing
            | ErrorKind::FolderClientNotUnlocked
            | ErrorKind::DeviceLocked => SourceError::NoAccess,
            ErrorKind::SessionExpired | ErrorKind::AuthenticationTooWeak => {
                SourceError::NotSignedIn
            }
            _ if problem.status == Some(401) => SourceError::NotSignedIn,
            _ if problem.status == Some(403) => SourceError::NoAccess,
            _ => SourceError::Server(
                problem
                    .detail
                    .clone()
                    .or_else(|| problem.title.clone())
                    .unwrap_or_else(|| "Der Server hat den Abruf abgelehnt.".to_owned()),
            ),
        },
    }
}

/// The sink into which `edms-net` streams: file, checksum and progress in one.
///
/// It **never** writes into the platform's [`ContentSink`] — it only reports the progress to it.
/// That is the place the promise from `edms_core::port` hangs off, and hence there is no path here
/// that passes bytes through.
struct CountingSink<'a> {
    file: tokio::fs::File,
    machine: Sha256Machine,
    written: u64,
    total: u64,
    sink: &'a mut dyn ContentSink,
}

impl AsyncWrite for CountingSink<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.sink.cancelled() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the platform cancelled the request",
            )));
        }
        let written = ready!(Pin::new(&mut this.file).poll_write(context, buffer))?;
        this.machine.add_added(&buffer[..written]);
        this.written = this.written.saturating_add(written as u64);
        // Progress, not content: on Windows that resets the 60-second deadline of the callback
        // (`CfReportProviderProgress`).
        this.sink.progress(this.written, this.total);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_takes_only_half_finished_loads() {
        let directory = tempfile::tempdir().unwrap();
        let half = directory.path().join("01ABC.part");
        let foreign = directory.path().join("important.txt");
        std::fs::write(&half, b"half").unwrap();
        std::fs::write(&foreign, b"not mine").unwrap();

        clear_staging(directory.path());
        assert!(!half.exists(), "the half-finished load is gone");
        assert!(foreign.exists(), "foreign files stay");
    }

    #[test]
    fn clearing_a_missing_directory_is_harmless() {
        clear_staging(Path::new("/does/not/exist/hopefully"));
    }
}
