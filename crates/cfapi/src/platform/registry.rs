//! The registry keys of the entry in File Explorer's navigation pane.
//!
//! What is written stands in [`crate::navigation_pane`] — key path, value names, the shape of
//! every value, all of it tested on macOS. Here only the four calls that carry it into the
//! registry: `RegCreateKeyExW`, `RegSetValueExW`, `RegCloseKey`, `RegDeleteTreeW`. **Not one of
//! them has ever run.**
//!
//! ## Why a failure is not fatal
//!
//! Three reasons, and they are not the same one three times:
//!
//! 1. **The folder works without the row.** Without these keys the mirror is missing from the
//!    sidebar and nothing else; it is opened through its path, hydrates, dehydrates, is deleted on
//!    command. A sign-in that fails because a decoration is missing would be the worse trade.
//! 2. **Whether a process without elevated rights may write under `SyncRootManager` is
//!    unmeasured** (ADR-D06 §7, "Open, to be settled only on a Windows machine"). If it may not,
//!    this path returns `E_ACCESSDENIED` on every sign-in — on every workstation. That must not be
//!    what keeps the folder from coming up.
//! 3. **Nextcloud does it the same way**: it writes its keys at runtime and treats a failure as
//!    non-fatal (ADR-D06 §7, from `02-platform-decision` §1.2). That is the only arrangement in a
//!    shipped, unpackaged product this repository has a report of.
//!
//! The caller therefore logs and carries on ([`super::Mirror`]).
//!
//! ## HKLM, and 64 bit
//!
//! Everything here hangs under `HKEY_LOCAL_MACHINE`. The client is built as a 64-bit program
//! (`packaging/windows/elasticdms.wxs`, `Bitness="always64"`), so no WOW64 view of
//! `HKLM\SOFTWARE` comes between the keys written here and the ones Explorer reads.

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
};
use windows::core::{HRESULT, PCWSTR};

use crate::error::MirrorError;
use crate::navigation_pane::{Data, Entry, Value, key_of, values};
use crate::raw::hresult_from_win32;
use crate::sync_root::SyncRootIdentifier;

use super::win::{error, wide};

/// Writes the entry in the navigation pane, value by value.
///
/// Every value is checked before the first key comes into being ([`values`]). What was written
/// before a failure stays standing: the values are set, not added to, and the next sign-in writes
/// the same ones again over the top.
pub(crate) fn write(entry: &Entry) -> Result<(), MirrorError> {
    for value in values(entry)? {
        write_value(&value)?;
    }
    Ok(())
}

/// Removes the entry of one root, together with everything under it.
///
/// Called where the registration is lifted: a row that points at a folder nobody serves any more
/// is worse than no row. A key that is not there counts as removed — the goal has been reached.
///
/// **NAMED GAP:** the key is named after the SID of the user this process runs *as*
/// ([`super::win::current_user_sid`]). An uninstallation goes over the profiles of **all** users
/// (`crates/app/src/uninstall.rs`) and, delivered per machine, runs as SYSTEM; it then names a key
/// that does not exist, removes nothing, and the entries of those profiles stay behind. Reaching
/// them would mean enumerating the subkeys of `SyncRootManager` and picking them by their third
/// part — `RegEnumKeyExW`, and a Windows machine to measure it on.
pub(crate) fn remove(identifier: &SyncRootIdentifier) -> Result<(), MirrorError> {
    let key = wide(&key_of(identifier))?;
    // SAFETY: `key` is a null-terminated UTF-16 sequence and lives until the end of this function;
    // `RegDeleteTreeW` does not keep the pointer. `HKEY_LOCAL_MACHINE` is a predefined handle that
    // is never closed.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(key.as_ptr())) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(status, "RegDeleteTreeW")
}

/// The path of the running program — the icon of the row hangs on it.
///
/// Not a Windows call, but it only ever serves this one: `IconResource` names the program whose
/// icon Explorer shows. A path that is no Unicode text is an error and not a lossily converted
/// one — the value would then name a program that is not there.
pub(crate) fn program_path() -> Result<String, MirrorError> {
    let program =
        std::env::current_exe().map_err(|e| MirrorError::ProgramPathUnknown(e.to_string()))?;
    program.to_str().map(str::to_owned).ok_or_else(|| {
        MirrorError::ProgramPathUnknown(format!("not Unicode text: {}", program.display()))
    })
}

fn write_value(value: &Value) -> Result<(), MirrorError> {
    let key = Key::create(&value.key)?;
    let name = wide(&value.name)?;
    let bytes = value.data.bytes()?;
    // SAFETY: `name` is null-terminated and lives until the end of this function; `bytes` is
    // passed as a slice with its own length, and `RegSetValueExW` copies it before it returns.
    let status = unsafe {
        RegSetValueExW(key.raw(), PCWSTR(name.as_ptr()), 0, kind(&value.data), Some(&bytes))
    };
    check(status, "RegSetValueExW")
}

/// Which registry type belongs to which value.
const fn kind(data: &Data) -> REG_VALUE_TYPE {
    match data {
        Data::Text(_) => REG_SZ,
        Data::TextWithVariables(_) => REG_EXPAND_SZ,
        Data::Number(_) => REG_DWORD,
    }
}

/// A registry return value as a [`MirrorError`], with the name of the call.
///
/// The registry functions do not return an HRESULT but a Win32 code, and `ERROR_SUCCESS` is zero.
/// It goes through the same arithmetic as every other Windows error in this crate
/// ([`hresult_from_win32`]), so that one number stands in the log and not two kinds of it.
fn check(status: WIN32_ERROR, flow: &'static str) -> Result<(), MirrorError> {
    if status == ERROR_SUCCESS {
        return Ok(());
    }
    let code = hresult_from_win32(status.0);
    Err(error(flow, &windows::core::Error::from_hresult(HRESULT(code))))
}

/// An open registry key that closes itself.
///
/// A forgotten key handle would hold the hive open for as long as the process lives — and this
/// process lives as long as the user is signed in.
struct Key(HKEY);

impl Key {
    /// Opens the key, creating it and everything above it that is missing.
    fn create(path: &str) -> Result<Self, MirrorError> {
        let wide_path = wide(path)?;
        let mut key = HKEY::default();
        // SAFETY: `wide_path` is null-terminated and lives until the end of this function; `key`
        // is a live local that the call fills in on success and leaves alone otherwise.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &raw mut key,
                None,
            )
        };
        check(status, "RegCreateKeyExW")?;
        Ok(Self(key))
    }

    const fn raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `RegCreateKeyExW` and is closed exactly once —
        // `Key` is neither `Copy` nor `Clone`. The result is discarded deliberately: a panic in
        // `Drop` would be an abort in the middle of a sign-in.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}
