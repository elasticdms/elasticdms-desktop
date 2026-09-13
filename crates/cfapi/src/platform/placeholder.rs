//! Placeholders: create, update, read, dehydrate.
//!
//! A placeholder is a directory entry with size, times and a **file identity** (`FileIdentity`) —
//! here the text of the [`EntryIdentifier`] ([`crate::checks::identity_blob`]). The content is at
//! the server; Windows only asks for it when somebody opens the file.
//!
//! ## Why every placeholder carries `FILE_ATTRIBUTE_READONLY`
//!
//! Requirement 1: the mirror is read-only. cfAPI has no read-only mode and no callback before a
//! write (ADR-D06). The write protection is the only layer that acts **before** the write: Word,
//! Excel and Explorer respect it. Whoever strips it off can write — and then the fourth layer takes
//! over (`NOTIFY_FILE_CLOSE_COMPLETION` detects it, the content is discarded).
//!
//! ## Two flags that are never set here
//!
//! * `CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL` promises "always complete" and makes **every
//!   dehydration fail** (02-platform-decision §1.5). ADR-D04 demands the opposite: a copy has to
//!   disappear on order.
//! * `CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION` on a folder means "fully
//!   populated". A folder created that way never gets a `FETCH_PLACEHOLDERS` and would stay empty
//!   forever. The asking is switched off only once a whole listing has been handed over
//!   ([`super::command::transfer_placeholder`]).

use edms_core::namespace::{Entry, EntryIdentifier};

use windows::Win32::Storage::CloudFilters::{
    CF_CREATE_FLAG_NONE, CF_FS_METADATA, CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE,
    CF_PIN_STATE_PINNED, CF_PIN_STATE_UNSPECIFIED, CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
    CF_PLACEHOLDER_CREATE_INFO, CF_PLACEHOLDER_INFO_STANDARD, CF_PLACEHOLDER_STANDARD_INFO,
    CF_SET_IN_SYNC_FLAG_NONE, CF_SET_PIN_FLAG_NONE, CF_UPDATE_FLAG_CLEAR_IN_SYNC,
    CF_UPDATE_FLAG_DEHYDRATE, CF_UPDATE_FLAG_MARK_IN_SYNC, CfCreatePlaceholders,
    CfGetPlaceholderInfo, CfSetInSyncState, CfSetPinState, CfUpdatePlaceholder,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO,
};
use windows::core::{HRESULT, PCWSTR};

use crate::checks::{MAX_IDENTITY_BLOB, check_name, filetime, identifier_from_blob, identity_blob};
use crate::error::MirrorError;
use crate::path::for_win32;

use super::win::{Handle, error, open_for_read, open_for_write, wide};

/// A finished placeholder together with the buffers it points at.
///
/// `CF_PLACEHOLDER_CREATE_INFO` carries raw pointers to the name and the file identity. Both live
/// here in `Vec`s: their contents are on the heap and do not travel along when this value is moved.
/// Only because of that may a [`PlaceholderBuilder`] sit in a `Vec` and still go to Windows.
/// Whoever separates the buffers from the fields hands over pointers to freed memory — and Windows
/// would write a file name out of foreign memory into a directory of the user's.
#[derive(Debug)]
pub(crate) struct PlaceholderBuilder {
    name: Vec<u16>,
    identifier: Vec<u8>,
    info: CF_PLACEHOLDER_CREATE_INFO,
}

impl PlaceholderBuilder {
    /// Builds the placeholder for an entry.
    ///
    /// Name and file identity are checked here, **before** Windows sees them: otherwise a name that
    /// is too long fails only in `CfCreatePlaceholders`, with one HRESULT per entry and without a
    /// reason.
    pub(crate) fn new(entry: &Entry) -> Result<Self, MirrorError> {
        check_name(&entry.name)?;
        let name = wide(&entry.name)?;
        let identifier = identity_blob(entry.identifier)?;
        let (size, created, changed) = match entry.file() {
            Some(d) => (d.size, filetime(d.created), filetime(d.changed)),
            // Folders have neither size nor server times. `1` is the smallest value that
            // `CfUpdatePlaceholder` does not read as "do not change"
            // ([`crate::checks::filetime`]).
            None => (0, 1, 1),
        };
        let mut attributes = FILE_ATTRIBUTE_READONLY.0;
        if entry.is_folder() {
            attributes |= FILE_ATTRIBUTE_DIRECTORY.0;
        }
        let mut builder = Self {
            name,
            identifier,
            info: CF_PLACEHOLDER_CREATE_INFO {
                RelativeFileName: PCWSTR::null(),
                FsMetadata: CF_FS_METADATA {
                    BasicInfo: FILE_BASIC_INFO {
                        CreationTime: created,
                        LastAccessTime: changed,
                        LastWriteTime: changed,
                        ChangeTime: changed,
                        FileAttributes: attributes,
                    },
                    FileSize: i64::try_from(size).unwrap_or(i64::MAX),
                },
                FileIdentity: std::ptr::null(),
                FileIdentityLength: 0,
                // MARK_IN_SYNC: a fresh placeholder is by definition at the server's state.
                // Without the flag it counts as changed immediately, and the write detection
                // (InSync `TRACK_ALL`) would report a write on every file that never happened.
                Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
                Result: HRESULT(0),
                CreateUsn: 0,
            },
        };
        builder.info.RelativeFileName = PCWSTR(builder.name.as_ptr());
        builder.info.FileIdentity = builder.identifier.as_ptr().cast();
        builder.info.FileIdentityLength = builder.identifier.len() as u32;
        Ok(builder)
    }

    /// The struct for Windows. The pointers in it hold for as long as this value lives.
    pub(crate) const fn info(&self) -> CF_PLACEHOLDER_CREATE_INFO {
        self.info
    }

    /// The result Windows writes back for each entry.
    ///
    /// The call as a whole can succeed while individual entries still fail. Without this check a
    /// document would be missing from the folder without an error standing anywhere.
    pub(crate) fn result(info: &CF_PLACEHOLDER_CREATE_INFO) -> Result<(), MirrorError> {
        if info.Result.0 == 0 {
            return Ok(());
        }
        Err(MirrorError::OperatingSystem {
            flow: "CfCreatePlaceholders (entry)",
            code: info.Result.0,
            text: "Windows did not accept this placeholder".to_owned(),
        })
    }
}

/// Creates placeholders in an existing directory — **outside** a callback.
///
/// Inside `FETCH_PLACEHOLDERS` the way is [`super::command::transfer_placeholder`];
/// `CfCreatePlaceholders` would be a second writer there, into a directory cldflt is populating
/// right then.
pub(crate) fn create(directory: &str, builders: &[PlaceholderBuilder]) -> Result<(), MirrorError> {
    if builders.is_empty() {
        return Ok(());
    }
    let wide_path = wide(&for_win32(directory))?;
    let mut array: Vec<CF_PLACEHOLDER_CREATE_INFO> =
        builders.iter().map(PlaceholderBuilder::info).collect();
    // SAFETY: `wide_path` and the buffers behind the pointers in `array` (they belong to
    // `builders`, which lives longer than this call) are valid; `array` is exactly as long as it
    // says.
    unsafe {
        CfCreatePlaceholders(PCWSTR(wide_path.as_ptr()), &mut array, CF_CREATE_FLAG_NONE, None)
    }
    .map_err(|e| error("CfCreatePlaceholders", &e))?;
    for entry in &array {
        PlaceholderBuilder::result(entry)?;
    }
    Ok(())
}

/// What a placeholder on disk says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlaceholderDetails {
    /// Whether the user has pinned it ("always keep on this device").
    pub(crate) pinned: bool,
    /// Whether it is at the server's state.
    pub(crate) in_sync: bool,
    /// How many bytes of the content are on disk locally.
    pub(crate) on_disk: i64,
    /// How many bytes have been changed locally.
    pub(crate) changed: i64,
    /// The file identity, provided it comes from this program.
    pub(crate) identifier: Option<EntryIdentifier>,
}

impl PlaceholderDetails {
    /// Whether content has been loaded.
    pub(crate) const fn hydrated(&self) -> bool {
        self.on_disk > 0
    }

    /// Whether somebody has written into it locally.
    ///
    /// Two signals, because neither suffices on its own: `ModifiedDataSize` counts changed bytes,
    /// and the in-sync state already falls when an attribute is changed (policy `TRACK_ALL`,
    /// [`super::registration`]). The two together are the detection from ADR-D06 §4.
    pub(crate) const fn local_modified(&self) -> bool {
        self.changed > 0 || !self.in_sync
    }
}

/// Reads the details; `None` if the path is not a placeholder.
///
/// Not being a placeholder is **not an error**: files the user put there themselves can lie in the
/// mirror — cfAPI cannot prevent their creation (ADR-D06, residual risk). They stay where they
/// are; they belong to the user.
pub(crate) fn details(path: &str, folder: bool) -> Result<Option<PlaceholderDetails>, MirrorError> {
    let handle = open_for_read(path, folder)?;
    read_details(&handle)
}

fn read_details(handle: &Handle) -> Result<Option<PlaceholderDetails>, MirrorError> {
    // The struct plus the file identity appended to it; `MAX_IDENTITY_BLOB` is its documented
    // maximum length (`CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH`).
    let mut buffer = vec![0u8; size_of::<CF_PLACEHOLDER_STANDARD_INFO>() + MAX_IDENTITY_BLOB];
    let mut filled = 0u32;
    // SAFETY: `buffer` is as large as stated and lives beyond the call; `filled` points at a valid
    // local number.
    let result = unsafe {
        CfGetPlaceholderInfo(
            handle.raw(),
            CF_PLACEHOLDER_INFO_STANDARD,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            Some(&raw mut filled),
        )
    };
    if result.is_err() || (filled as usize) < size_of::<CF_PLACEHOLDER_STANDARD_INFO>() {
        return Ok(None);
    }
    // SAFETY: Windows has written at least the whole struct. It is read unaligned, because a
    // `Vec<u8>` need not be aligned for the `i64`s it contains.
    let info = unsafe { buffer.as_ptr().cast::<CF_PLACEHOLDER_STANDARD_INFO>().read_unaligned() };
    let offset = std::mem::offset_of!(CF_PLACEHOLDER_STANDARD_INFO, FileIdentity);
    let length = (info.FileIdentityLength as usize).min(buffer.len().saturating_sub(offset));
    let identifier =
        buffer.get(offset..offset + length).and_then(|bytes| identifier_from_blob(bytes).ok());
    Ok(Some(PlaceholderDetails {
        pinned: info.PinState == CF_PIN_STATE_PINNED,
        in_sync: info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC,
        on_disk: info.OnDiskDataSize,
        changed: info.ModifiedDataSize,
        identifier,
    }))
}

/// Sets size, times and file identity anew; discards the local content on request.
///
/// `content_discard` is not an extra but the rule for a new version: a hydrated file with a new
/// size and old content would be a mangled file. The next time it is opened the right version
/// arrives (ADR-D01 §6, "removing means dehydrating").
pub(crate) fn update(path: &str, entry: &Entry, content_discard: bool) -> Result<(), MirrorError> {
    let builder = PlaceholderBuilder::new(entry)?;
    let details = builder.info();
    let handle = open_for_write(path, entry.is_folder())?;
    let mut flags = CF_UPDATE_FLAG_MARK_IN_SYNC;
    if content_discard {
        flags |= CF_UPDATE_FLAG_DEHYDRATE;
    }
    // SAFETY: `builder` lives until the end of this function, and so do the buffers behind
    // `FsMetadata` and `FileIdentity`; `handle` is a valid, open handle on exactly this path.
    let result = unsafe {
        CfUpdatePlaceholder(
            handle.raw(),
            Some(&raw const details.FsMetadata),
            Some(details.FileIdentity),
            details.FileIdentityLength,
            None,
            flags,
            None,
            None,
        )
    };
    drop(builder);
    result.map_err(|e| error("CfUpdatePlaceholder", &e))
}

/// Releases the local content — the order from 02-platform-decision §1.5.
///
/// 1. **Unpin**, when ordered: a pinned file cannot be dehydrated, and Windows hydrates it again
///    immediately. For space reclamation the pin stays — it is the user's wish, and ADR-D04 lets it
///    stand there.
/// 2. **Set in-sync**: cfAPI refuses to dehydrate a file that counts as changed. That is exactly
///    the case when a local change is to be taken back — which is why this step comes before and
///    not after.
/// 3. **Dehydrate and mark as in sync.**
pub(crate) fn dehydrate(path: &str, unpin: bool) -> Result<(), MirrorError> {
    let handle = open_for_write(path, false)?;
    if unpin {
        set_pinning(&handle, CF_PIN_STATE_UNSPECIFIED)?;
    }
    // SAFETY: `handle` is open and belongs to this call; the USN output pointer is omitted.
    unsafe {
        CfSetInSyncState(handle.raw(), CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, None)
    }
    .map_err(|e| error("CfSetInSyncState", &e))?;
    // SAFETY: as above; without metadata and without a dehydration range means "the whole file".
    unsafe {
        CfUpdatePlaceholder(
            handle.raw(),
            None,
            None,
            0,
            None,
            CF_UPDATE_FLAG_DEHYDRATE | CF_UPDATE_FLAG_MARK_IN_SYNC,
            None,
            None,
        )
    }
    .map_err(|e| error("CfUpdatePlaceholder(DEHYDRATE)", &e))
}

fn set_pinning(handle: &Handle, state: CF_PIN_STATE) -> Result<(), MirrorError> {
    // SAFETY: `handle` is open; `CfSetPinState` without OVERLAPPED is synchronous.
    unsafe { CfSetPinState(handle.raw(), state, CF_SET_PIN_FLAG_NONE, None) }
        .map_err(|e| error("CfSetPinState", &e))
}

/// Marks a placeholder as **not** in sync.
///
/// Needed in exactly one place: a file that is open right then and therefore could not be
/// dehydrated. The mark survives a restart; without it a revoked copy would stay behind if the
/// process ended at the wrong moment (ADR-D04).
pub(crate) fn mark_outdated(path: &str) -> Result<(), MirrorError> {
    let handle = open_for_write(path, false)?;
    // SAFETY: `handle` is open and belongs to this call.
    unsafe {
        CfUpdatePlaceholder(
            handle.raw(),
            None,
            None,
            0,
            None,
            CF_UPDATE_FLAG_CLEAR_IN_SYNC,
            None,
            None,
        )
    }
    .map_err(|e| error("CfUpdatePlaceholder(CLEAR_IN_SYNC)", &e))
}
