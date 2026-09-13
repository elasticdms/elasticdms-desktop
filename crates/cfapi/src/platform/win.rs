//! The Win32 calls outside cfAPI: handles, directories, attributes, volumes.
//!
//! Everything here is tamed towards the outside: every function takes and returns ordinary Rust
//! values and reports errors as [`MirrorError`] with the name of the call. The reason is not
//! convenience — it is that an `unwrap` in one of these places terminates the process, and this
//! process serves Explorer. A program that crashes while deleting a file leaves behind the copy
//! that has to disappear under ADR-D04.
//!
//! Paths always go through [`crate::path::for_win32`] before they arrive here: a case file (Akte)
//! title plus a document title easily blows past `MAX_PATH`, and without `\\?\` it is then of all
//! things `DeleteFileW` that fails.

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FindClose,
    FindFirstFileW, FindNextFileW, GetFileAttributesW, GetVolumeInformationW, GetVolumePathNameW,
    INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MoveFileExW, OPEN_EXISTING,
    RemoveDirectoryW, SetFileAttributesW, WIN32_FIND_DATAW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

use crate::error::MirrorError;
use crate::navigation_pane::{sid_length, sid_text};
use crate::path::{connect, for_win32};
use crate::plan::FoundOnDisk;
use crate::raw::{WIN32_FILE_NOT_FOUND, hresult_from_win32, is_not_found};
use crate::text::text_until_null;

/// `WRITE_DAC` from `winnt.h`.
///
/// The provider opens every file it changes with `WRITE_DAC` instead of with write access: the
/// deny ACL on the root (02-platform-decision §1.5) would otherwise hit the provider itself,
/// because it runs under the same account. cfAPI requires "WRITE_DATA or WRITE_DAC"; the owner of
/// the folder always has WRITE_DAC, even against their own deny entry.
pub(crate) const WRITE_DAC: u32 = 0x0004_0000;

/// `SYNCHRONIZE` from `winnt.h` — without it the handle cannot be waited on.
pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;

/// A Windows handle that is closed when it goes out of scope.
///
/// A forgotten handle on a file in the mirror is not a leak that only shows up later: it holds the
/// file open, and every following dehydration fails with a sharing violation.
#[derive(Debug)]
pub(crate) struct Handle(HANDLE);

impl Handle {
    /// The raw handle, only for passing on to cfAPI.
    pub(crate) const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `CreateFileW` and is closed exactly once —
        // `Handle` is neither `Copy` nor `Clone`. The result is discarded deliberately:
        // `CloseHandle` only fails on a handle this type never holds, and a panic in `Drop` would
        // be an abort in the middle of a callback.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

// A handle is created and ends on different threads (a worker thread hydrates, a callback thread
// dehydrates). A Windows handle is only a number and is not bound to a thread.
unsafe impl Send for Handle {}

/// A text as a null-terminated UTF-16 sequence.
///
/// An embedded null character would cut the path off at that point —
/// `C:\elasticdms\Archive\0whatever` would become `C:\elasticdms\Archive`, and a `DeleteFileW`
/// would hit the wrong folder. That is why it is an error, not a truncation.
pub(crate) fn wide(text: &str) -> Result<Vec<u16>, MirrorError> {
    if text.contains('\0') {
        return Err(MirrorError::InvalidName {
            name: text.to_owned(),
            reason: "it contains a null character",
        });
    }
    Ok(text.encode_utf16().chain(std::iter::once(0)).collect())
}

/// Reads a null-terminated UTF-16 sequence, the way cfAPI passes it in callbacks.
///
/// # Safety
///
/// `pointer` must be null or point at a null-terminated UTF-16 sequence that stays valid for the
/// duration of the call.
pub(crate) unsafe fn text_from(pointer: PCWSTR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: the caller's guarantee.
    unsafe { pointer.to_string() }.unwrap_or_default()
}

/// A Windows error as a [`MirrorError`], with the name of the call.
pub(crate) fn error(flow: &'static str, e: &windows::core::Error) -> MirrorError {
    MirrorError::OperatingSystem { flow, code: e.code().0, text: e.message() }
}

/// Opens a file or a folder the way cfAPI requires for placeholder changes.
///
/// `WRITE_DAC | FILE_READ_ATTRIBUTES | SYNCHRONIZE`, without sharing: cfAPI requires an exclusive
/// handle for dehydration, and a shared one would let a second program write into the middle of
/// it. If a sharing violation occurs, that is not a bug in this program but "file currently open" —
/// the caller retries later.
pub(crate) fn open_for_write(path: &str, folder: bool) -> Result<Handle, MirrorError> {
    open(path, WRITE_DAC | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE, FILE_SHARE_MODE(0), folder)
}

/// Opens for reading and shares the file with everyone else — for pure queries
/// (`CfGetPlaceholderInfo`) that must not take anyone's access away.
pub(crate) fn open_for_read(path: &str, folder: bool) -> Result<Handle, MirrorError> {
    open(path, FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, folder)
}

fn open(
    path: &str,
    access: u32,
    share: FILE_SHARE_MODE,
    folder: bool,
) -> Result<Handle, MirrorError> {
    let wide_path = wide(&for_win32(path))?;
    // Without FILE_FLAG_BACKUP_SEMANTICS a directory cannot be opened at all; for files the flag
    // would be harmless, but it is only set where it is needed.
    let flags = if folder { FILE_FLAG_BACKUP_SEMANTICS } else { FILE_FLAGS_AND_ATTRIBUTES(0) };
    // SAFETY: `wide_path` is null-terminated and lives until the end of this function;
    // `CreateFileW` does not keep the pointer.
    let handle = unsafe {
        CreateFileW(PCWSTR(wide_path.as_ptr()), access, share, None, OPEN_EXISTING, flags, None)
    }
    .map_err(|e| error("CreateFileW", &e))?;
    if handle == INVALID_HANDLE_VALUE {
        // windows-rs already reports this result as an `Err`; the branch is here so that an
        // invalid handle can under no circumstances carry on as a valid one.
        return Err(MirrorError::OperatingSystem {
            flow: "CreateFileW",
            code: hresult_from_win32(WIN32_FILE_NOT_FOUND),
            text: format!("`{path}` could not be opened"),
        });
    }
    Ok(Handle(handle))
}

/// The file attributes of a path, or `None` if it does not exist.
pub(crate) fn attributes(path: &str) -> Option<u32> {
    let wide_path = wide(&for_win32(path)).ok()?;
    // SAFETY: `wide_path` is null-terminated and lives beyond the call.
    let value = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };
    (value != INVALID_FILE_ATTRIBUTES).then_some(value)
}

/// Whether the path exists.
pub(crate) fn present(path: &str) -> bool {
    attributes(path).is_some()
}

/// Sets or removes `FILE_ATTRIBUTE_READONLY`.
///
/// The write protection is the first of four layers (ADR-D06 §4): Word and Explorer respect it,
/// any program can strip it off. It is set all the same — and removed again before a change of our
/// own, because otherwise `MoveFileExW` and `DeleteFileW` fail on it.
pub(crate) fn set_write_protection(path: &str, on: bool) -> Result<(), MirrorError> {
    let Some(old) = attributes(path) else {
        return Ok(());
    };
    let new = if on {
        old | FILE_ATTRIBUTE_READONLY.0
    } else {
        let without = old & !FILE_ATTRIBUTE_READONLY.0;
        // `SetFileAttributesW(0)` is not a valid value; Windows requires at least NORMAL.
        if without == 0 { FILE_ATTRIBUTE_NORMAL.0 } else { without }
    };
    if new == old {
        return Ok(());
    }
    let wide_path = wide(&for_win32(path))?;
    // SAFETY: `wide_path` is null-terminated and lives beyond the call.
    unsafe { SetFileAttributesW(PCWSTR(wide_path.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(new)) }
        .map_err(|e| error("SetFileAttributesW", &e))
}

/// Creates a folder; one that already exists is not an error.
pub(crate) fn create_folder(path: &str) -> Result<(), MirrorError> {
    if present(path) {
        return Ok(());
    }
    let wide_path = wide(&for_win32(path))?;
    // SAFETY: `wide_path` is null-terminated and lives beyond the call.
    unsafe { CreateDirectoryW(PCWSTR(wide_path.as_ptr()), None) }
        .map_err(|e| error("CreateDirectoryW", &e))
}

/// Enumerates a directory (without `.` and `..`).
///
/// Needed before every answer to `FETCH_PLACEHOLDERS`: cldflt rejects the whole hand-over if even a
/// single name is already taken, and then asks again and again ([`crate::plan::reconcile`]).
pub(crate) fn read_directory(path: &str) -> Result<Vec<FoundOnDisk>, MirrorError> {
    let pattern = wide(&connect(&for_win32(path), "*"))?;
    let mut found = WIN32_FIND_DATAW::default();
    // SAFETY: `pattern` is null-terminated, `found` is a live local struct that Windows fills in
    // completely.
    let find = match unsafe { FindFirstFileW(PCWSTR(pattern.as_ptr()), &raw mut found) } {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        // An empty directory, or one not created yet, is an empty listing, not an error: the first
        // time a container is opened there is nothing there, and that is the normal case.
        _ => return Ok(Vec::new()),
    };
    let mut entries = Vec::new();
    loop {
        let name = text_until_null(&found.cFileName);
        if name != "." && name != ".." {
            entries.push(FoundOnDisk {
                name,
                folder: found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
            });
        }
        // SAFETY: `find` is a valid search handle from `FindFirstFileW`, `found` a live local
        // struct.
        if unsafe { FindNextFileW(find, &raw mut found) }.is_err() {
            break;
        }
    }
    // SAFETY: `find` is closed exactly once — the function leaves the loop before this point.
    let _ = unsafe { FindClose(find) };
    Ok(entries)
}

/// Deletes a file, or a folder together with its contents.
///
/// The write protection is removed first: `DeleteFileW` rejects a write-protected file, and those
/// are exactly what this crate creates. Without this step the copy that has to disappear would
/// stay behind after an erasure command (ADR-D04). A path that has already gone counts as deleted
/// — the goal has been reached.
pub(crate) fn delete(path: &str, folder: bool) -> Result<(), MirrorError> {
    if folder {
        for child in read_directory(path)? {
            delete(&connect(path, &child.name), child.folder)?;
        }
    }
    set_write_protection(path, false)?;
    let wide_path = wide(&for_win32(path))?;
    let result = if folder {
        // SAFETY: `wide_path` is null-terminated and lives until the end of this function.
        unsafe { RemoveDirectoryW(PCWSTR(wide_path.as_ptr())) }
    } else {
        // SAFETY: the same guarantee as in the branch above.
        unsafe { DeleteFileW(PCWSTR(wide_path.as_ptr())) }
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if is_not_found(e.code().0) => Ok(()),
        Err(e) => Err(error(if folder { "RemoveDirectoryW" } else { "DeleteFileW" }, &e)),
    }
}

/// Renames, or moves within the mirror.
pub(crate) fn rename(old: &str, new: &str) -> Result<(), MirrorError> {
    let a = wide(&for_win32(old))?;
    let n = wide(&for_win32(new))?;
    // SAFETY: `a` and `n` are null-terminated and both live until the end of this function.
    unsafe { MoveFileExW(PCWSTR(a.as_ptr()), PCWSTR(n.as_ptr()), MOVEFILE_REPLACE_EXISTING) }
        .map_err(|e| error("MoveFileExW", &e))
}

/// The name of the file system under this path (`NTFS`, `exFAT`, `FAT32`).
///
/// cldflt works only on NTFS. Without this check it is the registration that fails first, with an
/// HRESULT from which nobody reads that the folder sits on a USB stick.
pub(crate) fn file_system_name(path: &str) -> Result<String, MirrorError> {
    let wide_path = wide(&for_win32(path))?;
    let mut root = [0u16; 260];
    // SAFETY: `wide_path` is null-terminated; `root` is a live buffer whose length the call takes
    // from the slice itself.
    unsafe { GetVolumePathNameW(PCWSTR(wide_path.as_ptr()), &mut root) }
        .map_err(|e| error("GetVolumePathNameW", &e))?;
    let mut name = [0u16; 64];
    // SAFETY: `root` is null-terminated after the call above; `name` is a live buffer.
    unsafe {
        GetVolumeInformationW(PCWSTR(root.as_ptr()), None, None, None, None, Some(&mut name))
    }
    .map_err(|e| error("GetVolumeInformationW", &e))?;
    Ok(text_until_null(&name))
}

/// The SID of the user this process runs as, in the form `S-1-5-21-…`.
///
/// The key of the entry in Explorer's navigation pane carries it, and so does the value under
/// `UserSyncRoots` ([`crate::navigation_pane`]). Windows is asked only for the **token**; turning
/// the bytes into text is arithmetic and therefore lies in the pure module, where it is tested.
/// `ConvertSidToStringSidW` would be the other route and would need a `LocalFree` on top of it.
pub(crate) fn current_user_sid() -> Result<String, MirrorError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is not to be closed; `raw_token` is
    // a live local into which `OpenProcessToken` writes exactly one handle on success.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
        .map_err(|e| error("OpenProcessToken", &e))?;
    let token = Handle(raw_token);

    let mut length = 0u32;
    // The first call only asks how long the answer is; it fails with ERROR_INSUFFICIENT_BUFFER,
    // and that is the expected outcome here, not a fault.
    // SAFETY: without a buffer the call writes nothing but the required length, into a live local.
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &raw mut length) };
    if length == 0 {
        // Then it failed for another reason than the missing buffer, and that one is reported.
        return Err(error("GetTokenInformation", &windows::core::Error::from_win32()));
    }
    let mut buffer = vec![0u8; length as usize];
    // SAFETY: `buffer` is exactly `length` bytes long, lives until the end of this function, and
    // the length is passed along with the pointer.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &raw mut length,
        )
    }
    .map_err(|e| error("GetTokenInformation", &e))?;

    // SAFETY: Windows has written a `TOKEN_USER` at the start of the buffer; a `Vec<u8>` is not
    // necessarily aligned for the pointer inside that struct, which is why it is read and not
    // referenced.
    let user = unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    let sid = user.User.Sid.0.cast::<u8>();
    if sid.is_null() {
        return Err(MirrorError::Internal("the access token carries no SID".into()));
    }
    // SAFETY: the SID lies behind the struct in the same buffer, which is alive until the end of
    // this function; its second byte is the number of sub-authorities, from which the whole length
    // follows (`sid_length`, the arithmetic of `GetLengthSid`).
    let raw = unsafe { std::slice::from_raw_parts(sid, sid_length(sid.add(1).read())) };
    sid_text(raw).ok_or_else(|| {
        MirrorError::Internal("Windows delivers a SID in a shape that is not one".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_character_in_the_path_is_not_silently_truncated() {
        assert!(wide("C:\\elasticdms\0egal").is_err());
        assert_eq!(wide("ab").unwrap(), vec![u16::from(b'a'), u16::from(b'b'), 0]);
        assert_eq!(wide("").unwrap(), vec![0]);
    }
}
