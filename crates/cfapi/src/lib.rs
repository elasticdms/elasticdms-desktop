//! The Windows platform layer: the read-only mirror over the Cloud Filter API.
//!
//! Explorer shows the mail baskets, the archives with their case files (Akten) and the saved
//! searches under `%USERPROFILE%\elasticdms` (`edms_core::namespace`, namespace v2). Windows asks
//! for directory listings and contents through callbacks; this crate forwards the questions to an
//! `Arc<dyn NamespaceSource>` and carries out what the engine orders through
//! `edms_core::port::FileSystem`. It decides as little as possible on its own — whatever can be
//! decided without Windows lives in the pure modules below and is tested there on macOS.
//!
//! One thing goes the other way: a file dropped into a mail basket. It is the only place in the
//! mirror where something may be put in ([`edms_core::namespace::Container::accepts_new_files`] —
//! this crate never decides that itself), and the only thing this crate ever tells the engine of
//! its own accord ([`intake::Intake`]).
//!
//! ## Structure
//!
//! Pure parts, compiled and tested on every target:
//!
//! * [`check`] — validate names, file identities, provider name, account and root path **before**
//!   cfAPI sees them. Windows rejects late and wholesale: an invalid name fails only in
//!   `CfCreatePlaceholders`, with one HRESULT per entry and without a reason.
//! * [`root`] — provider GUID, provider version, root identity and the identifier
//!   `<provider>!<SID>!<account>` for the registry key.
//! * [`navigation_pane`] — the registry values behind the entry in Explorer's navigation pane:
//!   key path, value names, the shape of every value, and a SID as text.
//! * [`status`] — which `STATUS_CLOUD_FILE_*` for which `SourceError`.
//! * [`raw_value`] — the HRESULT arithmetic and the question which Windows error is an expected
//!   outcome (not found, in use, already connected).
//! * [`blocks`] — the 4 KB arithmetic for `TRANSFER_DATA`.
//! * [`text`] — UTF-16 there and back, with an upper bound and without silent truncation.
//! * [`path`], [`exemption`] — path keys and the exemption list for our own deletions.
//! * [`intake`] — the seam for a file dropped into a basket, and the beat that finds it.
//! * [`path_map`], [`plan`] — where which entry lives and what follows from a change list.
//! * [`work`], [`abort`] — the thread pool on which callbacks are carried to completion, and the
//!   switches with which they are cancelled.
//!
//! Windows part (only `cfg(windows)`): [`Mirror`] (implements `FileSystem`) and
//! [`platform_available`]. **Not executed on Windows here**; checked with
//! `cargo xwin check -p edms-cfapi --target x86_64-pc-windows-msvc` and clippy for the same target.
//!
//! ## ADR-D06 §1 — without cloud-filter
//!
//! ADR-D06 §1 chose cloud-filter 0.0.6. This crate does **not** use that crate; it is not in its
//! `Cargo.toml` any more either. Two reasons, both read off the crate's own source:
//!
//! 1. **Three `unwrap`s on paths that commonly fail.** If a `SyncFilter` callback returns `Err`,
//!    cloud-filter reports that with `command::Write::fail(..).unwrap()` — inside an
//!    `extern "system"` function (`src/filter/proxy.rs`). If that `CfExecute` fails because the
//!    request was cancelled or has expired, the process dies. The same failure report also sends
//!    `Length = 0`, although the error case too needs a valid range. And `Drop for Connection`
//!    calls `CfDisconnectSyncRoot(..).unwrap()`, while the root-watcher thread ends on every error
//!    with `expect`/`panic!` (`src/root/`). The process that falls over here serves Explorer.
//! 2. **The last use disappeared along with registration.** In the end cloud-filter remained only
//!    for the root identifier and for signing out through WinRT. Since the correction to ADR-D06
//!    §7 both run through Win32 (`CfRegisterSyncRoot`, `CfUnregisterSyncRoot`), because WinRT
//!    `Register` fails from an unpackaged process with `E_ACCESSDENIED`.
//!
//! What has been taken over from cloud-filter is the **arithmetic**, not the code: `ParamSize` as
//! field offset plus the size of the union member in use (`src/command/executor.rs`) — proven
//! there, recomputed here against the headers. Should that be replaced later, it is by ADR-D06 §2
//! a change in this crate alone.
//!
//! ## Residual risk, stated openly (ADR-D06)
//!
//! * **Writing into a hydrated file cannot be prevented.** cfAPI has no read-only mode and no
//!   callback before a write (verified against the headers and the documentation). Files carry
//!   `FILE_ATTRIBUTE_READONLY`; a program that removes the attribute can write all the same. At
//!   the next `NOTIFY_FILE_CLOSE_COMPLETION` the change is detected (`ModifiedDataSize`, or no
//!   longer "in sync") and the file is dehydrated; the next time it is opened the server version
//!   arrives. The change never leaves the device — there is no way back to the server. If the file
//!   is still open elsewhere at closing time, the change stays until the next close.
//! * **New files in the mirror cannot be prevented.** There is no callback for creation; a deny
//!   ACL would hit the provider itself, because it runs under the same account. Such files are not
//!   placeholders; reconciliation leaves them in place (they could be the user's data) and
//!   `clear_everything` removes them together with the tree. In a mail basket that is not a
//!   residual risk but the point: what appears there is handed to the engine ([`intake`]).
//!   Everywhere else the file stays lying where it is and is never announced — a creation the
//!   platform cannot refuse it can at least leave alone.
//! * **The entry in Explorer's navigation pane is written only half.** The keys under
//!   `HKLM\…\Explorer\SyncRootManager` are written at sign-in and removed again at sign-out
//!   ([`navigation_pane`], `platform::registry`); the second half under HKCU is not written, and
//!   `packaging/windows/README.md` reports that without it no row appears in the sidebar. Whether
//!   a process without elevated rights may write even the HKLM half is unmeasured, which is why a
//!   failure there is logged and nothing else. **None of those calls has ever run.** The folder is
//!   fully usable through its path either way.

pub mod blocks;
pub mod cancel;
pub mod checks;
pub mod error;
pub mod exemptions;
pub mod intake;
/// The workstation's language — read here, because the Windows API lives in this crate and
/// nowhere else.
pub mod locale;
pub mod navigation_pane;
pub mod path;
pub mod path_map;
pub mod plan;
pub mod raw;
pub mod status;
pub mod sync_root;
pub mod text;
pub mod worker_pool;

#[cfg(windows)]
mod platform;

pub use error::MirrorError;
pub use intake::Intake;
#[cfg(windows)]
pub use platform::{Mirror, platform_available};
