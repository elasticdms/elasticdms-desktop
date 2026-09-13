//! Where the app puts its rendezvous file — as seen from inside the sandbox too.
//!
//! The extension runs in the app sandbox; there `$HOME` is the container
//! (`~/Library/Containers/de.elasticdms.folderclient.fileprovider/Data`), not the user's home
//! directory. The app is not sandboxed and writes to
//! `~/Library/Application Support/de.elasticdms.folderclient/bridge.json` (ADR-D05). If the
//! extension read `$HOME`, it would search inside the container and never find the app. That is
//! why the home directory comes from the user database here (`getpwuid_r`), and the sandbox grants
//! read access to exactly this one folder
//! (`temporary-exception.files.home-relative-path.read-only`,
//! `packaging/macos/elasticdms-fileprovider.entitlements`).

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The app's folder under `~/Library/Application Support`.
pub const APPLICATION_FOLDER: &str = "de.elasticdms.folderclient";

/// Name of the rendezvous file (port and secret of the channel, ADR-D05).
pub const RENDEZVOUS_FILE: &str = "bridge.json";

/// The largest buffer `getpwuid_r` gets before the search gives up.
const MAX_BUFFER: usize = 1 << 20;

/// Why the home directory cannot be determined.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HomeError {
    /// The user database does not know the user id.
    #[error("the user database does not know the user id {0}")]
    NoEntry(u32),
    /// `getpwuid_r` reports an error.
    #[error("the user database cannot be read; getpwuid_r reports error {0}")]
    System(i32),
    /// The entry names no home directory, or one that is not absolute.
    #[error(
        "the user database names no usable home directory (`{0}`); it is empty or not absolute"
    )]
    Invalid(String),
}

/// The signed-in user's home directory according to the user database, not according to `$HOME`.
pub fn real_home_directory() -> Result<PathBuf, HomeError> {
    // SAFETY: getuid(2) has no preconditions and cannot fail.
    let user = unsafe { libc::getuid() };
    let mut size = 4_096;
    loop {
        let mut buffer = vec![0 as libc::c_char; size];
        // SAFETY: passwd consists of pointers and integers; the all-zero value is valid and is
        // overwritten completely by getpwuid_r before it is read.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer points at live, writable memory of the stated size; the strings
        // in `entry` afterwards point into `buffer`, which lives until the end.
        let returned = unsafe {
            libc::getpwuid_r(user, &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut result)
        };
        if returned == libc::ERANGE && size < MAX_BUFFER {
            size *= 2;
            continue;
        }
        if returned != 0 {
            return Err(HomeError::System(returned));
        }
        if result.is_null() {
            return Err(HomeError::NoEntry(user));
        }
        if entry.pw_dir.is_null() {
            return Err(HomeError::Invalid(String::new()));
        }
        // SAFETY: pw_dir is not null and points at a null-terminated string inside `buffer`,
        // which is still alive here.
        let text = unsafe { CStr::from_ptr(entry.pw_dir) };
        let path = PathBuf::from(OsStr::from_bytes(text.to_bytes()));
        if !path.is_absolute() {
            return Err(HomeError::Invalid(path.display().to_string()));
        }
        return Ok(path);
    }
}

/// `<home>/Library/Application Support/de.elasticdms.folderclient/bridge.json`.
pub fn rendezvous_path() -> Result<PathBuf, HomeError> {
    Ok(real_home_directory()?
        .join("Library")
        .join("Application Support")
        .join(APPLICATION_FOLDER)
        .join(RENDEZVOUS_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_directory_comes_from_the_user_database_and_exists() {
        let home_dir = real_home_directory().unwrap();
        assert!(home_dir.is_absolute(), "{}", home_dir.display());
        assert!(home_dir.is_dir(), "{}", home_dir.display());
        // Outside the sandbox it agrees with $HOME; inside it precisely does not.
        if let Some(home) = std::env::var_os("HOME")
            && !home.to_string_lossy().contains("/Library/Containers/")
        {
            assert_eq!(home_dir, PathBuf::from(home));
        }
    }

    #[test]
    fn the_rendezvous_path_is_the_one_from_the_adr() {
        let path = rendezvous_path().unwrap();
        let text = path.to_string_lossy();
        assert!(
            text.ends_with("/Library/Application Support/de.elasticdms.folderclient/bridge.json"),
            "{text}"
        );
        assert!(path.starts_with(real_home_directory().unwrap()));
    }
}
