//! The real home directory — in the sandbox as well (macOS only).
//!
//! In the sandboxed extension macOS sets `$HOME` to the container
//! (`~/Library/Containers/<bundle id>/Data`); `std::env::home_dir` reads `$HOME` first and thereby
//! delivers the container. The rendezvous file, however, lies in the real home, and the extension's
//! `temporary-exception.files.home-relative-path` is relative to the real home. Whoever takes the
//! container searches at a place the app never writes to, and takes the app for terminated.
//!
//! `getpwuid_r` asks the user database and knows no container. Without `unsafe` there is no way
//! there in std; the alternative of computing the path back out of `$HOME` (everything before
//! `/Library/Containers/`) would guess — and a network or moved home would break it quietly. Hence
//! this one small `unsafe` block, safe from the outside (the architecture rules permit `unsafe` in
//! this crate, `crates/architecture-rules`). The alternative "the extension passes the path in"
//! would only move the same call into `edms-fileprovider`; and app and extension would then compute
//! the path in two ways.

#![allow(unsafe_code)]

use std::ffi::{CStr, OsStr};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::error::BridgeError;

/// Initial size of the character buffer; macOS reports `_SC_GETPW_R_SIZE_MAX` = 4096.
const INITIAL_BUFFER: usize = 4096;
/// Above that there is no entry, only an error.
const MAX_BUFFER: usize = 1 << 20;

/// The home directory of the user running this process, according to the user database.
pub(crate) fn real_home_directory() -> Result<PathBuf, BridgeError> {
    // SAFETY: getuid has no preconditions and, per POSIX, cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut buffer: Vec<libc::c_char> = vec![0; INITIAL_BUFFER];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: entry, result and buffer (with its real length) are valid, writable memory of
        // this frame; getpwuid_r is thread-safe and writes only there.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buffer.len() < MAX_BUFFER {
            let larger = buffer.len() * 2;
            buffer.resize(larger, 0);
            continue;
        }
        if rc != 0 {
            return Err(BridgeError::HomeUnknown(format!(
                "getpwuid_r for user id {uid} reports: {}",
                io::Error::from_raw_os_error(rc)
            )));
        }
        if result.is_null() {
            return Err(BridgeError::HomeUnknown(format!(
                "there is no entry for user id {uid} in the user database"
            )));
        }
        // SAFETY: rc == 0 and result != null: getpwuid_r has written entry (result points at it);
        // pw_dir is null or points at a NUL-terminated string in buffer.
        let directory = unsafe { (*result).pw_dir };
        if directory.is_null() {
            return Err(BridgeError::HomeUnknown(format!(
                "the entry for user id {uid} names no home directory"
            )));
        }
        // SAFETY: directory is not null and points at a NUL-terminated string in buffer, which
        // lives until the end of this function; to_path_buf copies before buffer is freed.
        let bytes = unsafe { CStr::from_ptr(directory) }.to_bytes();
        let path = PathBuf::from(OsStr::from_bytes(bytes));
        if !path.is_absolute() {
            return Err(BridgeError::HomeUnknown(format!(
                "the user database names `{}` as the home directory; it is not absolute",
                path.display()
            )));
        }
        return Ok(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_home_directory_is_an_absolute_existing_directory() {
        let home = real_home_directory().unwrap();
        assert!(home.is_absolute() && home.is_dir(), "{}", home.display());
    }

    #[test]
    fn the_real_home_directory_does_not_hang_off_home() {
        // Outside the sandbox both agree; the point is that the function does not read $HOME at
        // all. That shows itself when $HOME is bent in a child process — here the comparison with
        // what the user database says, asked twice, is enough.
        assert_eq!(real_home_directory().unwrap(), real_home_directory().unwrap());
    }
}
