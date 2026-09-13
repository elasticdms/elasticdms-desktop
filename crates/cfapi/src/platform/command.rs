//! `CfExecute` — the only way to answer a request from cldflt.
//!
//! Every callback is a question with a deadline (60 seconds, reset by every successful
//! `CfExecute`). Whoever does not answer leaves Explorer hanging until cldflt discards the request;
//! whoever answers with a status other than `STATUS_CLOUD_FILE_*` gets "the cloud operation was
//! unsuccessful" shown, no matter what they meant ([`crate::status`]).
//!
//! ## The `ParamSize` arithmetic
//!
//! `CF_OPERATION_PARAMETERS` is a union with a length field in front of it. cldflt reads exactly as
//! many bytes as `ParamSize` says; too few means truncated fields, too many means garbage read. The
//! right value is: size of the union member in use plus the offset of the union within the struct —
//! **not** `size_of::<CF_OPERATION_PARAMETERS>()`, because the union is as large as its largest
//! member. The same arithmetic is in cloud-filter 0.0.6 (`command/executor.rs`), where it is
//! proven, and in Microsoft's CloudMirror sample.
//!
//! ## Why every answer is a value, not a panic
//!
//! These functions are called from callback threads and from worker threads. If `CfExecute` fails —
//! because the request was cancelled or has expired — that is an ordinary outcome and not a bug:
//! the caller logs it and drops the request. cloud-filter 0.0.6 calls `.unwrap()` in the same
//! place, inside an `extern "system"` function; that terminates the process and with it the user's
//! folder.

use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};
use windows::Win32::Storage::CloudFilters::{
    CF_CONNECTION_KEY, CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE, CF_OPERATION_ACK_DELETE_FLAG_NONE,
    CF_OPERATION_ACK_RENAME_FLAG_NONE, CF_OPERATION_INFO, CF_OPERATION_PARAMETERS,
    CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_1, CF_OPERATION_PARAMETERS_0_2,
    CF_OPERATION_PARAMETERS_0_3, CF_OPERATION_PARAMETERS_0_6, CF_OPERATION_PARAMETERS_0_7,
    CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
    CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION,
    CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE, CF_OPERATION_TYPE,
    CF_OPERATION_TYPE_ACK_DEHYDRATE, CF_OPERATION_TYPE_ACK_DELETE, CF_OPERATION_TYPE_ACK_RENAME,
    CF_OPERATION_TYPE_TRANSFER_DATA, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
    CF_PLACEHOLDER_CREATE_INFO, CF_REQUEST_KEY_DEFAULT, CfExecute, CfReportProviderProgress,
};

use crate::error::MirrorError;
use crate::status::CloudStatus;

use super::win::error;

/// The keys that make a request from cldflt unique.
///
/// Both are plain numbers and therefore `Send`: that is exactly why a callback can copy them,
/// return immediately and leave the answer to a worker thread (02-platform-decision §1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestKey {
    /// The connection (`CfConnectSyncRoot`).
    pub(crate) connection: i64,
    /// The individual request.
    pub(crate) transfer: i64,
}

/// `ParamSize` for the union member `T`; see the module header.
const fn parameter_size<T>() -> u32 {
    (size_of::<T>() + std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)) as u32
}

/// Executes a fully built command.
///
/// `parameter` stays readable afterwards, because cldflt writes return values into it
/// (`EntriesProcessed`).
fn run(
    flow: &'static str,
    kind: CF_OPERATION_TYPE,
    key: RequestKey,
    parameter: &mut CF_OPERATION_PARAMETERS,
) -> Result<(), MirrorError> {
    let info = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: kind,
        ConnectionKey: CF_CONNECTION_KEY(key.connection),
        TransferKey: key.transfer,
        CorrelationVector: std::ptr::null(),
        SyncStatus: std::ptr::null(),
        RequestKey: i64::from(CF_REQUEST_KEY_DEFAULT),
    };
    // SAFETY: `info` lives until the end of this function, `parameter` longer (it belongs to the
    // caller); the pointers in it — data buffer, placeholder array — the caller holds just as long.
    unsafe { CfExecute(&raw const info, &raw mut *parameter) }.map_err(|e| error(flow, &e))
}

/// Hands over a chunk of file content (`TRANSFER_DATA`).
///
/// Offset and length have to be aligned to 4 KB; only the last chunk may be ragged, and only if it
/// ends at the end of the file. [`crate::blocks::BlockBuffer`] sees to that, not this function.
pub(crate) fn transfer_data(key: RequestKey, offset: u64, data: &[u8]) -> Result<(), MirrorError> {
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_6>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_6 {
                Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                CompletionStatus: STATUS_SUCCESS,
                Buffer: data.as_ptr().cast(),
                Offset: i64::try_from(offset).unwrap_or(i64::MAX),
                Length: i64::try_from(data.len()).unwrap_or(i64::MAX),
            },
        },
    };
    run("CfExecute(TRANSFER_DATA)", CF_OPERATION_TYPE_TRANSFER_DATA, key, &mut parameter)
}

/// Reports that a hydration failed — with the range that stays open.
///
/// The error case too needs a valid range; which one it is [`crate::blocks::error_domain`]
/// computes. cloud-filter 0.0.6 sends `Length = 0` here and risks cldflt rejecting even the failure
/// report — the request would then stay open until the deadline, and Explorer hangs for a minute on
/// a file that failed in a second.
pub(crate) fn report_data_error(
    key: RequestKey,
    status: CloudStatus,
    offset: i64,
    length: i64,
) -> Result<(), MirrorError> {
    // One byte of buffer with a valid address: on an error status cldflt reads no bytes, but it
    // does reject a null pointer.
    let empty = [0u8; 1];
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_6>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_6 {
                Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                CompletionStatus: NTSTATUS(status.ntstatus()),
                Buffer: empty.as_ptr().cast(),
                Offset: offset,
                Length: length,
            },
        },
    };
    run("CfExecute(TRANSFER_DATA, error)", CF_OPERATION_TYPE_TRANSFER_DATA, key, &mut parameter)
}

/// Hands over placeholders in answer to `FETCH_PLACEHOLDERS`; returns the number accepted.
///
/// `last_chunk` sets `DISABLE_ON_DEMAND_POPULATION`: only with it does cldflt stop asking for the
/// directory again. The flag takes effect only if **every** entry of the hand-over succeeds — which
/// is why only what meets no occupied name goes out ([`crate::plan::reconcile`]).
pub(crate) fn transfer_placeholder(
    key: RequestKey,
    entries: &mut [CF_PLACEHOLDER_CREATE_INFO],
    total: usize,
    last_chunk: bool,
) -> Result<usize, MirrorError> {
    let count = entries.len();
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_7>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferPlaceholders: CF_OPERATION_PARAMETERS_0_7 {
                Flags: if last_chunk {
                    CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION
                } else {
                    CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE
                },
                CompletionStatus: STATUS_SUCCESS,
                PlaceholderTotalCount: i64::try_from(total).unwrap_or(i64::MAX),
                // An empty array has to be a null pointer; a pointer to nothing leads, inside
                // cldflt, to an access to unallocated memory.
                PlaceholderArray: if count == 0 {
                    std::ptr::null_mut()
                } else {
                    entries.as_mut_ptr()
                },
                PlaceholderCount: count as u32,
                EntriesProcessed: 0,
            },
        },
    };
    run(
        "CfExecute(TRANSFER_PLACEHOLDERS)",
        CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
        key,
        &mut parameter,
    )?;
    // SAFETY: the union carries the same member that was written into it above.
    Ok(unsafe { parameter.Anonymous.TransferPlaceholders.EntriesProcessed } as usize)
}

/// Reports that a directory listing could not be obtained.
pub(crate) fn report_placeholder_error(
    key: RequestKey,
    status: CloudStatus,
) -> Result<(), MirrorError> {
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_7>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferPlaceholders: CF_OPERATION_PARAMETERS_0_7 {
                Flags: CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE,
                CompletionStatus: NTSTATUS(status.ntstatus()),
                PlaceholderTotalCount: 0,
                PlaceholderArray: std::ptr::null_mut(),
                PlaceholderCount: 0,
                EntriesProcessed: 0,
            },
        },
    };
    run(
        "CfExecute(TRANSFER_PLACEHOLDERS, error)",
        CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
        key,
        &mut parameter,
    )
}

/// Answers `NOTIFY_DELETE`. `Some(status)` is the veto, `None` is consent.
pub(crate) fn answer_erasure(
    key: RequestKey,
    veto: Option<CloudStatus>,
) -> Result<(), MirrorError> {
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_2>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            AckDelete: CF_OPERATION_PARAMETERS_0_2 {
                Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
                CompletionStatus: status_or_success(veto),
            },
        },
    };
    run("CfExecute(ACK_DELETE)", CF_OPERATION_TYPE_ACK_DELETE, key, &mut parameter)
}

/// Answers `NOTIFY_RENAME`. `Some(status)` is the veto, `None` is consent.
pub(crate) fn answer_rename(key: RequestKey, veto: Option<CloudStatus>) -> Result<(), MirrorError> {
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_3>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            AckRename: CF_OPERATION_PARAMETERS_0_3 {
                Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE,
                CompletionStatus: status_or_success(veto),
            },
        },
    };
    run("CfExecute(ACK_RENAME)", CF_OPERATION_TYPE_ACK_RENAME, key, &mut parameter)
}

/// Answers `NOTIFY_DEHYDRATE` — always with consent.
///
/// Reclaiming space is allowed and even wanted: the content is on the server and comes back the
/// next time the file is opened. A veto would only mean that Windows could do nothing when space
/// runs short — and that the user would keep a drive full of documents they never wanted to keep.
pub(crate) fn answer_dehydrate(key: RequestKey) -> Result<(), MirrorError> {
    let mut parameter = CF_OPERATION_PARAMETERS {
        ParamSize: parameter_size::<CF_OPERATION_PARAMETERS_0_1>(),
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            AckDehydrate: CF_OPERATION_PARAMETERS_0_1 {
                Flags: CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE,
                CompletionStatus: STATUS_SUCCESS,
                // The file identity stays as it is: after dehydration the placeholder still
                // points at the same document.
                FileIdentity: std::ptr::null(),
                FileIdentityLength: 0,
            },
        },
    };
    run("CfExecute(ACK_DEHYDRATE)", CF_OPERATION_TYPE_ACK_DEHYDRATE, key, &mut parameter)
}

fn status_or_success(veto: Option<CloudStatus>) -> NTSTATUS {
    veto.map_or(STATUS_SUCCESS, |s| NTSTATUS(s.ntstatus()))
}

/// Reports download progress and thereby resets the 60-second deadline.
///
/// Without it Explorer aborts every file whose transfer takes longer than a minute — at 1 MB/s
/// that is everything over 60 MB. A failed progress report is no reason to abort the hydration; it
/// is logged and the transfer carries on.
pub(crate) fn report_progress(
    key: RequestKey,
    total: u64,
    finished: u64,
) -> Result<(), MirrorError> {
    // SAFETY: the call takes only numbers — no pointer, no buffer. It can fail (an expired
    // request), but it cannot read anything that is no longer there.
    unsafe {
        CfReportProviderProgress(
            CF_CONNECTION_KEY(key.connection),
            key.transfer,
            i64::try_from(total).unwrap_or(i64::MAX),
            i64::try_from(finished).unwrap_or(i64::MAX),
        )
    }
    .map_err(|e| error("CfReportProviderProgress", &e))
}
