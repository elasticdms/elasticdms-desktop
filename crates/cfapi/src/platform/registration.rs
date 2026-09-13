//! Registering and unregistering the sync root — through Win32, not through WinRT.
//!
//! ## ADR-D06 §7 — `CfRegisterSyncRoot` instead of `StorageProviderSyncRootManager.Register`
//!
//! ADR-D06 §7 provided for a sparse package, because experience says the WinRT registration fails
//! with `E_ACCESSDENIED` without package identity. The way out is not the package but the other
//! API: **`CfRegisterSyncRoot` is the Win32 route and requires no package identity.**
//!
//! * The WinRT `Register` from a process without package identity has been reported as
//!   `E_ACCESSDENIED` and reproduced by Microsoft (02-platform-decision §1.2).
//! * Nextcloud ships unpackaged and uses `CfRegisterSyncRoot` together with registry keys of its
//!   own — the only arrangement proven in a shipped, unpackaged product.
//! * Microsoft says: **one** registration API per root, not both. That is why not a single WinRT
//!   call remains in this crate.
//!
//! What the package would have achieved it still achieves — but only for the display: the entry in
//! Explorer's navigation pane, together with icon and name. That needs keys under
//! `HKLM\…\Explorer\SyncRootManager`: [`super::registry`] writes them right after this
//! registration and takes them away again with `CfUnregisterSyncRoot`. A failure there is not
//! fatal — the reasons stand in that module. **Without those keys the folder is fully usable**, it
//! is just not in the sidebar.
//!
//! ## The policies, and why exactly these
//!
//! | Policy | Value | Reason |
//! |---|---|---|
//! | Hydration | `FULL` + `AUTO_DEHYDRATION_ALLOWED` | `PROGRESSIVE` requires random access to the server; the contract does not offer that. `AUTO_DEHYDRATION_ALLOWED` lets Windows tidy up by itself when space runs short — welcome, since the content can be loaded again at any time. |
//! | Population | `FULL` | `PARTIAL` is documented by Microsoft as unsupported. |
//! | InSync | `TRACK_ALL` | Every local change clears the "in sync" state. That is the only signal for "somebody wrote into it" (ADR-D06, residual risk). |
//! | HardLink | `NONE` | A hard link onto a placeholder would be a second, uncontrolled copy of the same document. |
//!
//! `CF_REGISTER_FLAG_UPDATE`, so that a second start updates the same root instead of failing;
//! `CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT`, so that the root folder itself does not immediately
//! count as changed. **Not** `DISABLE_ON_DEMAND_POPULATION_ON_ROOT`: the root gets its children
//! from the server, so `FETCH_PLACEHOLDERS` has to arrive for it.

use windows::Win32::Storage::CloudFilters::{
    CF_HARDLINK_POLICY_NONE, CF_HYDRATION_POLICY, CF_HYDRATION_POLICY_FULL,
    CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED, CF_INSYNC_POLICY_TRACK_ALL,
    CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_PLATFORM_INFO, CF_POPULATION_POLICY,
    CF_POPULATION_POLICY_FULL, CF_POPULATION_POLICY_MODIFIER_NONE,
    CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT, CF_REGISTER_FLAG_UPDATE, CF_SYNC_POLICIES,
    CF_SYNC_REGISTRATION, CF_SYNC_ROOT_INFO_STANDARD, CF_SYNC_ROOT_STANDARD_INFO,
    CfGetPlatformInfo, CfGetSyncRootInfoByPath, CfRegisterSyncRoot, CfUnregisterSyncRoot,
};
use windows::core::{GUID, PCWSTR};

use crate::checks::{PROVIDER, check_provider};
use crate::error::MirrorError;
use crate::path::for_win32;
use crate::raw::{is_access_denied, is_not_found};
use crate::sync_root::{PROVIDER_GUID, PROVIDER_VERSION, identity};
use crate::text::text_until_null;

use super::win::{error, wide};

/// What is already set up as a root on a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootDetails {
    /// The provider that registered the root.
    pub(crate) provider: String,
    /// The account identifier it deposited (ours is the user's `sub`).
    pub(crate) account: String,
}

/// Registers the folder as a sync root (or updates the registration).
///
/// `SyncRootIdentity` is the bytes of the account identifier: Windows gives them back in every
/// callback, and by them the provider recognises after a restart whether the root on disk still
/// belongs to the account that is currently signed in. Without this check a second user on the same
/// machine would see the first one's placeholders (requirement 4).
pub(crate) fn register(path: &str, account: &str) -> Result<(), MirrorError> {
    check_provider(PROVIDER)?;
    let identifier = identity(account)?;
    let wide_path = wide(&for_win32(path))?;
    let name = wide(PROVIDER)?;
    let version = wide(PROVIDER_VERSION)?;

    let registration = CF_SYNC_REGISTRATION {
        StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: PCWSTR(name.as_ptr()),
        ProviderVersion: PCWSTR(version.as_ptr()),
        SyncRootIdentity: identifier.as_ptr().cast(),
        SyncRootIdentityLength: identifier.len() as u32,
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        ProviderId: GUID::from_u128(PROVIDER_GUID),
    };
    let policies = policy();

    // SAFETY: `wide_path`, `name`, `version` and `identifier` live until the end of this function;
    // CfRegisterSyncRoot copies everything it keeps before it returns.
    unsafe {
        CfRegisterSyncRoot(
            PCWSTR(wide_path.as_ptr()),
            &raw const registration,
            &raw const policies,
            CF_REGISTER_FLAG_UPDATE | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT,
        )
    }
    .map_err(|e| {
        if is_access_denied(e.code().0) {
            // On the Win32 route this is not a missing package identity but a folder that does
            // not belong to this user — the message has to name the folder, not a package.
            MirrorError::InvalidRoot {
                path: path.to_owned(),
                reason: "Windows refuses access; the folder has to belong to the signed-in user \
                        and must not lie inside another provider's root",
            }
        } else {
            error("CfRegisterSyncRoot", &e)
        }
    })
}

/// The policies of the root; see the table in the module header.
fn policy() -> CF_SYNC_POLICIES {
    CF_SYNC_POLICIES {
        StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_FULL,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_FULL,
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_TRACK_ALL,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    }
}

/// Lifts the registration. A folder that is not a root is not an error.
///
/// Called during sign-out, **after** the tree has been deleted: a lifted root with placeholders
/// still in it would leave behind files nobody can hydrate any more.
pub(crate) fn unregister(path: &str) -> Result<(), MirrorError> {
    let wide_path = wide(&for_win32(path))?;
    // SAFETY: `wide_path` is a null-terminated UTF-16 sequence and lives until the end of this
    // function; `CfUnregisterSyncRoot` does not keep the pointer.
    match unsafe { CfUnregisterSyncRoot(PCWSTR(wide_path.as_ptr())) } {
        Ok(()) => Ok(()),
        Err(e) if is_not_found(e.code().0) => Ok(()),
        Err(e) => Err(error("CfUnregisterSyncRoot", &e)),
    }
}

/// What is already registered on this folder, or `None` if it is not a root.
///
/// Asked before registering, so that the client does not overwrite another provider's root
/// (`CF_REGISTER_FLAG_UPDATE` would do that without complaint) and so that a change of account
/// shows up instead of the previous user's placeholders simply being used on.
pub(crate) fn existing_root(path: &str) -> Result<Option<RootDetails>, MirrorError> {
    let wide_path = wide(&for_win32(path))?;
    // What comes back is the struct plus the account identifier appended to it; the buffer carries
    // both.
    let mut buffer = vec![0u8; size_of::<CF_SYNC_ROOT_STANDARD_INFO>() + 4096];
    let mut filled = 0u32;
    // SAFETY: `wide_path` is null-terminated; `buffer` is exactly as large as the length passed in
    // and lives longer than the call; `filled` points at a local number.
    let result = unsafe {
        CfGetSyncRootInfoByPath(
            PCWSTR(wide_path.as_ptr()),
            CF_SYNC_ROOT_INFO_STANDARD,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            Some(&raw mut filled),
        )
    };
    match result {
        Ok(()) => {}
        // No placeholder, no root, no folder: all of them "there is nothing here yet".
        Err(_) => return Ok(None),
    }
    if (filled as usize) < size_of::<CF_SYNC_ROOT_STANDARD_INFO>() {
        return Ok(None);
    }
    // SAFETY: Windows has written `filled` bytes, at least the whole struct; the buffer would not
    // necessarily be aligned for the fields it contains (u16/u32/i64), because it is a `Vec<u8>` —
    // which is why it is read, not referenced.
    let details = unsafe { buffer.as_ptr().cast::<CF_SYNC_ROOT_STANDARD_INFO>().read_unaligned() };
    let length = details.SyncRootIdentityLength as usize;
    let offset = std::mem::offset_of!(CF_SYNC_ROOT_STANDARD_INFO, SyncRootIdentity);
    let account = buffer
        .get(offset..offset.saturating_add(length))
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default();
    Ok(Some(RootDetails { provider: text_until_null(&details.ProviderName), account }))
}

/// The platform's own details (`CfGetPlatformInfo`): build, revision, integration number.
///
/// The call is at the same time the probe for whether `cldapi.dll` exists at all: on Windows before
/// 10 1709 the process cannot even start with it, and from 1709 on the build is the number
/// [`crate::checks::check_build`] checks.
pub(crate) fn platform_info() -> Result<CF_PLATFORM_INFO, MirrorError> {
    // SAFETY: the call takes nothing and returns a struct of plain numbers.
    unsafe { CfGetPlatformInfo() }.map_err(|e| error("CfGetPlatformInfo", &e))
}
