//! The callbacks from cldflt: the operating system's questions and their answers.
//!
//! ## What is registered — and what is not
//!
//! | Callback | What for |
//! |---|---|
//! | `FETCH_PLACEHOLDERS` | "What is in this folder?" → [`NamespaceSource::children`] |
//! | `CANCEL_FETCH_PLACEHOLDERS` | The user has closed the window |
//! | `FETCH_DATA` | "Give me the content" → [`NamespaceSource::content`] |
//! | `CANCEL_FETCH_DATA` | Cancellation during the download |
//! | `NOTIFY_DELETE` | **Veto** (requirement 1), except for deletions of our own and in a basket |
//! | `NOTIFY_RENAME` | **Veto**, except for renames of our own and in a basket |
//! | `NOTIFY_DEHYDRATE` | Consent: reclaiming space is allowed |
//! | `NOTIFY_DEHYDRATE_COMPLETION` | Log only |
//! | `NOTIFY_FILE_CLOSE_COMPLETION` | Taking back a local change — and handing in a dropped file |
//!
//! **Not registered:** `VALIDATE_DATA` (the `VALIDATION_REQUIRED` path is not set; the engine
//! checks the checksum itself before a byte arrives here) and `NOTIFY_FILE_OPEN_COMPLETION` (it
//! carries no access mask and is therefore no good for detecting writes —
//! 02-platform-decision §1.3).
//!
//! ## Why every callback returns immediately
//!
//! cldflt calls from a thread pool that all the cloud providers on the system share. Whoever waits
//! on the network in it leaves Explorer hanging for OneDrive as well. So: copy the request into a
//! value of our own that is `Send` (keys are numbers, paths become `String`), return from the
//! callback, and send the answer from the [`WorkGroup`].
//!
//! Only the two vetoes and the cancellations are answered inside the callback itself: they are
//! local decisions without the network, and a veto that arrived only after a round of scheduling
//! would be no veto at all.
//!
//! ## Why `catch_unwind` around every callback
//!
//! A panic that runs through an `extern "system"` boundary is an immediate process abort. The
//! process is the provider of this folder; it falls in the middle of a directory listing, and the
//! user sees a folder that hangs. A single callback may fail — the program may not.
//!
//! [`NamespaceSource::children`]: edms_core::port::NamespaceSource::children
//! [`NamespaceSource::content`]: edms_core::port::NamespaceSource::content
//! [`WorkGroup`]: crate::worker_pool::WorkGroup

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use edms_core::identifier::BasketIdentifier;
use edms_core::namespace::{Container, Entry, EntryIdentifier};
use edms_core::port::ContentRequest;
use windows::Win32::Storage::CloudFilters::{
    CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS, CF_CALLBACK_REGISTRATION,
    CF_CALLBACK_TYPE_CANCEL_FETCH_DATA, CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
    CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_NONE,
    CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE, CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,
    CF_CALLBACK_TYPE_NOTIFY_DELETE, CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
    CF_CALLBACK_TYPE_NOTIFY_RENAME,
};

use crate::blocks::error_domain;
use crate::checks::{application_name, identifier_from_blob};
use crate::error::MirrorError;
use crate::exemptions::Scope;
use crate::intake::basket_of;
use crate::path::{connect, from_callback, relative_to_root};
use crate::plan::{FollowUp, check_list, reconcile};
use crate::status::CloudStatus;

use super::Inner;
use super::command::{
    RequestKey, answer_dehydrate, answer_erasure, answer_rename, report_data_error,
    report_placeholder_error, transfer_placeholder,
};
use super::placeholder::{self, PlaceholderBuilder};
use super::sink::TransferSink;
use super::win;

/// Nine registered callbacks plus the terminator; cldflt reads the table up to
/// `CF_CALLBACK_TYPE_NONE`.
pub(crate) const COUNT_CALLBACK: usize = 10;

/// The callback table for `CfConnectSyncRoot`.
pub(crate) const fn table() -> [CF_CALLBACK_REGISTRATION; COUNT_CALLBACK] {
    [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
            Callback: Some(on_list),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
            Callback: Some(on_list_abort),
        },
        CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_FETCH_DATA, Callback: Some(on_content) },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
            Callback: Some(on_content_abort),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DELETE,
            Callback: Some(on_erasure),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_RENAME,
            Callback: Some(on_rename),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE,
            Callback: Some(on_dehydrate),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,
            Callback: Some(on_dehydrate_finished),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
            Callback: Some(on_close),
        },
        CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None },
    ]
}

/// A request from cldflt, pulled out of the raw fields into values of our own.
///
/// Everything in it is `Send` and belongs to this struct: numbers and `String`. That is exactly
/// why the callback can return immediately and a worker thread can send the answer.
#[derive(Debug, Clone)]
struct Request {
    key: RequestKey,
    /// What the placeholder carries as its file identity; `None` at the root (it has none).
    identifier: Option<EntryIdentifier>,
    /// Full path, the way Windows sees it.
    full: String,
    /// Path relative to the root; `None` if it does not lie below it.
    relative: Option<String>,
    /// Size of the placeholder according to cldflt.
    size: i64,
    /// The file name of the asking program (`WINWORD.EXE`), without a path.
    application: Option<String>,
}

impl Request {
    /// The container whose listing is being asked for.
    ///
    /// The root carries no file identity — it came into being through `CfRegisterSyncRoot`, not as
    /// a placeholder. It is recognised by the empty path relative to the root; everything else has
    /// to carry an identifier, otherwise it is none of our folders.
    fn container(&self) -> Option<Container> {
        if self.relative.as_deref() == Some("") {
            return Some(Container::Root);
        }
        self.identifier?.container()
    }
}

/// Reads the fields of a callback.
///
/// # Safety
///
/// `info` must point at a valid `CF_CALLBACK_INFO`, the way cldflt passes it.
unsafe fn read(info: *const CF_CALLBACK_INFO, root: &str) -> Option<Request> {
    // SAFETY: the caller's guarantee.
    let info = unsafe { info.as_ref() }?;
    // SAFETY: both pointers are null-terminated UTF-16 sequences from cldflt, or null.
    let drive = unsafe { win::text_from(info.VolumeDosName) };
    let normalized = unsafe { win::text_from(info.NormalizedPath) };
    let full = from_callback(&drive, &normalized);
    let relative = relative_to_root(root, &full);
    // SAFETY: `FileIdentity` points at `FileIdentityLength` bytes for as long as the callback
    // runs.
    let identifier = (!info.FileIdentity.is_null() && info.FileIdentityLength > 0)
        .then(|| unsafe {
            std::slice::from_raw_parts(
                info.FileIdentity.cast::<u8>(),
                info.FileIdentityLength as usize,
            )
        })
        .and_then(|blob| identifier_from_blob(blob).ok());
    // SAFETY: `ProcessInfo` is set, because the connection carries `REQUIRE_PROCESS_INFO`; it is
    // checked all the same — a null pointer would otherwise be a crash inside the callback.
    let application = unsafe { info.ProcessInfo.as_ref() }
        .map(|p| unsafe { win::text_from(p.ImagePath) })
        .as_deref()
        .and_then(application_name);
    Some(Request {
        key: RequestKey { connection: info.ConnectionKey.0, transfer: info.TransferKey },
        identifier,
        full,
        relative,
        size: info.FileSize,
        application,
    })
}

/// Gets the inner state out of the callback context and increments the count by one.
///
/// # Safety
///
/// `info.CallbackContext` must be the pointer that [`super::connection`] obtained from
/// `Arc::into_raw` and has not taken back yet. cldflt returns from `CfDisconnectSyncRoot` only once
/// no callback is still running; after that there is no valid pointer any more, but no callback
/// either.
unsafe fn internals(info: *const CF_CALLBACK_INFO) -> Option<Arc<Inner>> {
    // SAFETY: the caller's guarantee.
    let info = unsafe { info.as_ref() }?;
    let pointer: *const Inner = info.CallbackContext.cast_const().cast();
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the pointer comes from `Arc::into_raw` and lives for as long as the connection is up.
    unsafe {
        Arc::increment_strong_count(pointer);
        Some(Arc::from_raw(pointer))
    }
}

/// The common frame of every callback: panic guard, context, parsed request.
///
/// # Safety
///
/// `info` must be valid; see [`read`] and [`internals`].
unsafe fn frame<F>(name: &'static str, info: *const CF_CALLBACK_INFO, act: F)
where
    F: FnOnce(Arc<Inner>, Request),
{
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller's guarantee.
        let Some(inner) = (unsafe { internals(info) }) else {
            return;
        };
        // SAFETY: the same.
        let Some(request) = (unsafe { read(info, &inner.root) }) else {
            return;
        };
        act(inner, request);
    }));
    if result.is_err() {
        tracing::error!(callback = name, "a callback of the Cloud Filter API crashed");
    }
}

// ─── FETCH_PLACEHOLDERS ──────────────────────────────────────────────────────────────────────

unsafe extern "system" fn on_list(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("FETCH_PLACEHOLDERS", info, |inner, request| {
            let Some(container) = request.container() else {
                answer_not_responsible(&request, Refusal::List);
                return;
            };
            let key = request.key;
            let for_thread = Arc::clone(&inner);
            if !inner.work.give(move || fetch_list(&for_thread, &request, container)) {
                // The pool accepts nothing more (a sign-out is under way): better a clean error
                // than a request that waits out its 60 seconds.
                report_silently(report_placeholder_error(key, CloudStatus::Unsuccessful));
            }
        });
    }
}

/// Obtains and hands over the listing; registers the request for cancellation and deregisters it.
///
/// The cancellation takes effect **between** the steps, not in the middle of one:
/// [`edms_core::port::NamespaceSource::children`] is a single blocking call without a cancellation
/// hook. What it saves is the expensive part all the same — building the placeholders and the
/// `CfExecute` into a directory the user has already closed again.
fn fetch_list(inner: &Inner, request: &Request, container: Container) {
    let abort = inner.cancellations.sign_in(request.key.transfer);
    obtain_list(inner, request, container, &abort);
    inner.cancellations.sign_out(request.key.transfer);
}

fn obtain_list(inner: &Inner, request: &Request, container: Container, abort: &AtomicBool) {
    let should = match inner.source.children(container) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%container, %error, "the listing could not be fetched");
            report_silently(report_placeholder_error(
                request.key,
                CloudStatus::from_source_error(&error),
            ));
            return;
        }
    };
    if let Err(error) = check_list(container, &should) {
        // A bug in the source. It shows up here instead of leaving behind a half-populated
        // directory in which an entry is missing without anyone knowing why.
        tracing::error!(%container, %error, "the source delivered an unusable listing");
        report_silently(report_placeholder_error(request.key, CloudStatus::InvalidRequest));
        return;
    }
    if abort.load(Ordering::Relaxed) {
        // cldflt has withdrawn the request (`CANCEL_FETCH_PLACEHOLDERS`). It needs no answer any
        // more — one would be a `CfExecute` on a key that no longer exists.
        tracing::debug!(%container, "directory listing cancelled");
        return;
    }
    if let Err(error) = hand_over_list(inner, request, container, &should) {
        tracing::warn!(%container, %error, "the listing could not be handed over");
        report_silently(report_placeholder_error(request.key, CloudStatus::Unsuccessful));
    }
}

fn hand_over_list(
    inner: &Inner,
    request: &Request,
    container: Container,
    should: &[Entry],
) -> Result<(), MirrorError> {
    let found_on_disk = win::read_directory(&request.full)?;
    let reconcile = reconcile(&found_on_disk, should);
    let builders =
        reconcile.transfer.iter().map(PlaceholderBuilder::new).collect::<Result<Vec<_>, _>>()?;
    let mut array: Vec<_> = builders.iter().map(PlaceholderBuilder::info).collect();
    // The last (and only) chunk switches on `DISABLE_ON_DEMAND_POPULATION`: only with it does
    // cldflt stop asking for the directory again on every view. That is ADR-D06 §3 — fetch once
    // afresh, after which the engine reports changes itself. A saved search whose result list
    // changes without anyone's doing comes through this way too: the engine compares and sends
    // `Change::New`/`Removed`, and `report_change` works them off here, because the container now
    // counts as populated ([`crate::path_map::PathMap::is_populated`]).
    // The emergency exit — `CF_UPDATE_FLAG_ENABLE_ON_DEMAND_POPULATION`, so that cldflt asks for
    // the whole listing again — is **not** wired up; it will only be needed once a real machine
    // shows that the route through the engine leaves a listing standing.
    //
    // 02-platform-decision §1.3 — it says dynamic folders (baskets, archives, case
    // files (Akten), saved searches) should **never** get `DISABLE_ON_DEMAND_POPULATION`, so that
    // every view fetches the listing anew. Here they do get it, because ADR-D06 §3 chooses the
    // other route: after the first listing **the engine** reports changes
    // (`FileSystem::report_change`), and Explorer asks no more. The reason is the access path:
    // every enumeration of a dynamic folder is a search on the server (ADR-D01 §3). Without this
    // flag a new search would run on every window that is opened, every thumbnail and every virus
    // scan — and Explorer happily enumerates a directory several times in a row.
    //
    // The price is stated: a case file (Akte) the engine does not know as "populated" gets no
    // changes ([`crate::plan::plan`]), and its listing would stay as it is. That is why the map is
    // set and marked as populated below, in the **same** call.
    transfer_placeholder(request.key, &mut array, should.len(), true)?;
    // The call as a whole can succeed while individual entries still fail; without this loop a
    // document would be missing from the folder without a reason standing anywhere.
    for (entry, info) in reconcile.transfer.iter().zip(&array) {
        if let Err(error) = PlaceholderBuilder::result(info) {
            tracing::warn!(name = %entry.name, %error, "cldflt did not accept a placeholder");
        }
    }

    // The map now carries the state Explorer sees — including the entries that were already on
    // disk and are only being worked on afterwards.
    {
        let mut map = inner.map();
        for entry in should {
            map.set(entry.identifier, &entry.name, entry.is_folder());
        }
        map.mark_populated(container);
    }

    for step in &reconcile.follow_up {
        if let Err(error) = work_after(inner, &request.full, step) {
            tracing::warn!(%error, "follow-up work on a directory listing failed");
        }
    }
    Ok(())
}

/// What is left to do after `FETCH_PLACEHOLDERS` has been answered.
///
/// The answer has already gone out; nothing here runs into a deadline any more. That is why what
/// cannot be done inside the callback may stand here: opening and changing files in the directory
/// that has just been populated.
///
/// **Content is not discarded here.** Whether a hydrated file still matches the server's state is
/// decided by the version mark — and only the engine knows it, reporting it through
/// [`edms_core::port::FileSystem::report_change`] as `Change::Changed`
/// (`plan::Step::Update { stale: true }`). A directory listing has no history; whoever dehydrated
/// here as a precaution would throw away every loaded document on every view of a saved search.
fn work_after(inner: &Inner, directory: &str, step: &FollowUp) -> Result<(), MirrorError> {
    match step {
        FollowUp::Delete { name, folder } => {
            let path = connect(directory, name);
            // Only placeholders of our own. A file the user put there themselves is not one — it
            // stays, it belongs to them (ADR-D06, residual risk).
            if !win::present(&path) || placeholder::details(&path, *folder)?.is_none() {
                tracing::debug!(%name, "not a placeholder; stays where it is");
                return Ok(());
            }
            let relative = relative_to_root(&inner.root, &path).unwrap_or_default();
            let _expectation = inner
                .exemption
                .expect(&relative, if *folder { Scope::Subtree } else { Scope::Exactly });
            win::delete(&path, *folder)
        }
        FollowUp::Check { present, entry } => {
            let path = connect(directory, present);
            if present != &entry.name {
                // Same name, different case: NTFS considers both the same, the user does not.
                // Renaming is an operation of its own and needs its own exemption.
                let target = connect(directory, &entry.name);
                rename_with_exemption(inner, &path, &target, entry.is_folder())?;
                return placeholder::update(&target, entry, false);
            }
            placeholder::update(&path, entry, false)
        }
        FollowUp::Create { entry } => {
            let builder = PlaceholderBuilder::new(entry)?;
            placeholder::create(directory, std::slice::from_ref(&builder))
        }
    }
}

/// Renames, and lets our own veto pass the operation through.
pub(super) fn rename_with_exemption(
    inner: &Inner,
    old: &str,
    new: &str,
    folder: bool,
) -> Result<(), MirrorError> {
    let old_relative = relative_to_root(&inner.root, old).unwrap_or_default();
    let new_relative = relative_to_root(&inner.root, new).unwrap_or_default();
    let scope = if folder { Scope::Subtree } else { Scope::Exactly };
    let _old = inner.exemption.expect(&old_relative, scope);
    let _new = inner.exemption.expect(&new_relative, scope);
    // The write protection has to go, otherwise `MoveFileExW` rejects it; afterwards
    // `CfUpdatePlaceholder` sets it again along with the fresh details.
    win::set_write_protection(old, false)?;
    win::rename(old, new)
}

unsafe extern "system" fn on_list_abort(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("CANCEL_FETCH_PLACEHOLDERS", info, |inner, request| {
            // The same list as for content: the cancellation carries the same transfer key.
            inner.cancellations.abort(request.key.transfer);
        });
    }
}

// ─── FETCH_DATA ──────────────────────────────────────────────────────────────────────────────

unsafe extern "system" fn on_content(
    info: *const CF_CALLBACK_INFO,
    params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers; on FETCH_DATA the union carries `FetchData`.
    let (required_offset, length) = unsafe {
        params.as_ref().map_or((0, -1), |p| {
            (p.Anonymous.FetchData.RequiredFileOffset, p.Anonymous.FetchData.RequiredLength)
        })
    };
    // SAFETY: the same.
    unsafe {
        frame("FETCH_DATA", info, |inner, request| {
            let Some(identifier) = request.identifier else {
                // Nothing has been sent yet, so the whole requested range is open. If arithmetic
                // leaves none, an empty but valid range is the answer.
                let (offset, length) = error_domain(required_offset, length, request.size, 0)
                    .unwrap_or((required_offset.max(0), 0));
                answer_not_responsible(&request, Refusal::Content { offset, length });
                return;
            };
            let key = request.key;
            let for_thread = Arc::clone(&inner);
            if !inner.work.give(move || {
                fetch_content(&for_thread, &request, identifier, required_offset, length)
            }) {
                report_silently(report_data_error(
                    key,
                    CloudStatus::Unsuccessful,
                    required_offset.max(0),
                    length.max(0),
                ));
            }
        });
    }
}

fn fetch_content(
    inner: &Inner,
    request: &Request,
    identifier: EntryIdentifier,
    required_offset: i64,
    length: i64,
) {
    let size = u64::try_from(request.size).unwrap_or(0);
    let abort = inner.cancellations.sign_in(request.key.transfer);
    let mut sink = TransferSink::new(request.key, size, abort);
    let job = ContentRequest { requesting_application: request.application.clone() };

    // What is always loaded is the whole file from offset 0, not only the requested range: the
    // hydration policy is FULL (ADR-D06 §3), the contract knows no partial fetch, and the engine
    // checks the checksum over the whole thing. `required_offset`/`length` go into the failure
    // report only.
    let result = inner
        .source
        .content(identifier, &job, &mut sink)
        .map_err(|error| CloudStatus::from_source_error(&error))
        .and_then(|_| {
            sink.complete().map_err(|error| {
                tracing::warn!(%identifier, %error, "the content arrived incomplete");
                CloudStatus::Unsuccessful
            })
        });

    // Only what is still open is reported: what is already at cldflt has arrived and must not be
    // handed in afterwards as failed.
    if let Err(status) = result
        && let Some((offset, open)) =
            error_domain(required_offset, length, request.size, sink.sent())
    {
        report_silently(report_data_error(request.key, status, offset, open));
    }
    inner.cancellations.sign_out(request.key.transfer);
}

unsafe extern "system" fn on_content_abort(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("CANCEL_FETCH_DATA", info, |inner, request| {
            inner.cancellations.abort(request.key.transfer);
        });
    }
}

// ─── The vetoes ──────────────────────────────────────────────────────────────────────────────

unsafe extern "system" fn on_erasure(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("NOTIFY_DELETE", info, |inner, request| {
            let allowed = inner.exemption.may_delete(request.relative.as_deref())
                || dropped_into_a_basket(&inner, &request).is_some();
            if !allowed {
                tracing::info!(path = %request.full, "deletion in the mirror refused (requirement 1)");
            }
            report_silently(answer_erasure(
                request.key,
                (!allowed).then_some(CloudStatus::AccessDenied),
            ));
        });
    }
}

unsafe extern "system" fn on_rename(
    info: *const CF_CALLBACK_INFO,
    params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers; on NOTIFY_RENAME the union carries `Rename`.
    let target = unsafe {
        params.as_ref().map(|p| win::text_from(p.Anonymous.Rename.TargetPath)).unwrap_or_default()
    };
    // SAFETY: dieselbe.
    unsafe {
        frame("NOTIFY_RENAME", info, |inner, request| {
            // The rule — both ends have to have been announced — lives in `exemption` and is
            // tested there; here only the target's path is brought into the same form.
            let target_relative = relative_to_root(&inner.root, &target);
            // The target is not asked about: what is being moved is not the server's truth, and
            // where it goes is then no statement about the mirror. The engine's own move out of
            // the basket goes exactly this way — out of the root, into the app's data directory.
            let allowed =
                inner.exemption.may_move(request.relative.as_deref(), target_relative.as_deref())
                    || dropped_into_a_basket(&inner, &request).is_some();
            if !allowed {
                tracing::info!(
                    of = %request.full,
                    after = %target,
                    "rename or move in the mirror refused (requirement 1)"
                );
            }
            report_silently(answer_rename(
                request.key,
                (!allowed).then_some(CloudStatus::AccessDenied),
            ));
        });
    }
}

// ─── Dehydrating and closing ─────────────────────────────────────────────────────────────────

unsafe extern "system" fn on_dehydrate(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("NOTIFY_DEHYDRATE", info, |_inner, request| {
            report_silently(answer_dehydrate(request.key));
        });
    }
}

unsafe extern "system" fn on_dehydrate_finished(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("NOTIFY_DEHYDRATE_COMPLETION", info, |_inner, request| {
            // Completion callbacks expect no answer; one would be an error.
            tracing::debug!(path = %request.full, "content released");
        });
    }
}

unsafe extern "system" fn on_close(
    info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: cldflt passes valid pointers.
    unsafe {
        frame("NOTIFY_FILE_CLOSE_COMPLETION", info, |inner, request| {
            // A completion callback; nothing to answer. The check needs a handle on the file and
            // must not hold on to the callback thread.
            let for_thread = Arc::clone(&inner);
            inner.work.give(move || {
                announce_if_dropped(&for_thread, &request);
                take_change_back(&request);
            });
        });
    }
}

/// The basket a file was dropped into; `None` if this path is not a dropped file.
///
/// The read-only regime protects what comes from the server (requirement 1, ADR-D06 §4). A file
/// somebody dropped into a basket never came from there: it carries no file identity of ours,
/// because nothing in this crate ever made it a placeholder, and it lies in the one container that
/// takes files — which [`edms_core::namespace::Container::accepts_new_files`] decides and nobody
/// here (namespace v2 §3).
///
/// Three things hang on the veto letting such a file through:
///
/// * **the engine's own move.** After the ingest it moves the file out of the basket into the
///   app's data directory. It knows nothing of this crate and can announce nothing here; a veto
///   would leave the document lying in the basket and hand it in again on every round.
/// * **a program that writes into a temporary file** and renames it at the end — which is how
///   Word saves, and how a browser finishes a download.
/// * **the user's change of mind.** What has not been handed in yet is still theirs.
fn dropped_into_a_basket(inner: &Inner, request: &Request) -> Option<BasketIdentifier> {
    if request.identifier.is_some() {
        return None;
    }
    basket_of(&inner.map(), request.relative.as_deref()?)
}

/// Hands a file that has just been closed in a basket to the engine.
///
/// Whether `NOTIFY_FILE_CLOSE_COMPLETION` arrives for a file that is no placeholder of ours is not
/// known here, and cannot be found out without a Windows machine — the documentation of the
/// callback speaks of placeholders. Nothing hangs on it: the beat of [`super::watch`] finds the
/// file in any case, at the latest one [`crate::intake::LOOK_AGAIN`] later. This way only saves
/// that wait.
fn announce_if_dropped(inner: &Inner, request: &Request) {
    let Some(basket) = dropped_into_a_basket(inner, request) else {
        return;
    };
    tracing::debug!(path = %request.full, %basket, "a file appeared in a mail basket");
    inner.intake.file_appeared(basket, &request.full);
}

/// The last line against a local change (ADR-D06 §4, layer four).
///
/// Write protection and vetoes can be got around; this step cannot. Whatever stands there as
/// changed when the file is closed is dehydrated — the next time it is opened the server version
/// arrives. The change never leaves the device, there is no way back to the server.
fn take_change_back(request: &Request) {
    if !win::present(&request.full) {
        return;
    }
    let details = match placeholder::details(&request.full, false) {
        Ok(Some(details)) => details,
        // Not a placeholder: a file the user put there themselves. It belongs to them.
        Ok(None) => return,
        Err(error) => {
            tracing::debug!(path = %request.full, %error, "state after closing unreadable");
            return;
        }
    };
    if !details.hydrated() || !details.local_modified() {
        return;
    }
    tracing::warn!(
        path = %request.full,
        changed = details.changed,
        "the file was changed locally; the local content is being discarded"
    );
    // The pin is lifted if there is one: `CF_UPDATE_FLAG_DEHYDRATE` rejects a pinned file, and then
    // of all versions the changed one would stay. "Always keep on this device" is not a guarantee
    // (LIESMICH.txt in the root), and here requirement 1 takes precedence: what is in the mirror is
    // what is on the server.
    if let Err(error) = placeholder::dehydrate(&request.full, details.pinned) {
        // If another program still holds the file open, the next completion callback comes anyway;
        // until then the change stays (ADR-D06, residual risk).
        tracing::info!(path = %request.full, %error, "taking the change back postponed");
    }
}

// ─── Odds and ends ───────────────────────────────────────────────────────────────────────────

/// Which answer cldflt expects — every kind of request has its own, and a wrong one does not count.
///
/// This stands here as a type of its own, because an `Option<(i64, i64)>` in this place would mean
/// two things at once: "no range" and "not a content request". But a content request **without** an
/// open range does exist ([`crate::blocks::error_domain`] then returns `None`), and answering it
/// with a listing answer would silently be the wrong thing.
#[derive(Debug, Clone, Copy)]
enum Refusal {
    /// A directory listing (`FETCH_PLACEHOLDERS`).
    List,
    /// A content request (`FETCH_DATA`), with the range that stays open.
    Content {
        /// Start of the range.
        offset: i64,
        /// Its length; `0` too is a valid answer, `None` would not be one.
        length: i64,
    },
}

/// Answers a request that does not belong to this provider.
///
/// The case means: a placeholder in our root carries a file identity that is not an entry
/// identifier of this program — a leftover from an earlier version or from another provider.
/// Nothing is guessed; the request is refused with a reason.
fn answer_not_responsible(request: &Request, kind: Refusal) {
    tracing::warn!(path = %request.full, "a placeholder carries no readable file identity");
    report_silently(match kind {
        Refusal::List => report_placeholder_error(request.key, CloudStatus::InvalidRequest),
        // What is reported is the requested range, not (0, 0): the error case too needs a valid
        // range, otherwise cldflt can reject even the failure report and the request would stay
        // open until the 60-second deadline.
        Refusal::Content { offset, length } => {
            report_data_error(request.key, CloudStatus::InvalidRequest, offset, length)
        }
    });
}

/// Logs a failed `CfExecute` instead of passing it on.
///
/// At the last stage there is nobody left who could do anything: the request has been cancelled or
/// has expired, and a `?` in this place would be either a panic inside the callback or a result
/// nobody reads.
fn report_silently(result: Result<(), MirrorError>) {
    if let Err(error) = result {
        tracing::debug!(%error, "the answer to cldflt no longer went out");
    }
}
