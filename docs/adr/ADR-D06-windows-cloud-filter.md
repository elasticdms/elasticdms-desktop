# ADR-D06: Windows — Cloud Filter API, straight over the windows bindings

**Status:** Accepted (2026-09-11).

The callback machinery is verified by compilation for `x86_64-pc-windows-msvc` and by the pure
tests of `crates/cfapi`; the operating-system calls themselves are exercised by Windows.

## Context

The Cloud Filter API (`cldapi.dll`, from Windows 10 1709) is the path OneDrive takes: placeholders
on NTFS, hydration on demand, pinning by the user. It has **no read-only mode**: no flag forbids
writing into a hydrated file, and no callback comes before the write (checked against the headers
and the Microsoft documentation).

## Decision

1. **The callback machinery stands in this repository, over windows 0.58.0** (corrected
   2026-09-11, see below). No `cloud-filter`. What was taken from that crate is the **arithmetic**,
   not the code: the `ParamSize` arithmetic of the `CF_OPERATION_PARAMETERS` union.
2. **Everything behind `edms_core::port::FileSystem`.** If the crate is replaced or absorbed, that
   is a change in `crates/cfapi`, not in the engine.
3. **Hydration FULL**, directories stay “partially populated” at first, so that
   `FETCH_PLACEHOLDERS` fetches the fresh list on first opening; after that the engine reports
   changes itself.
4. **Read-only as far as Windows allows:** a veto in `NOTIFY_DELETE`/`NOTIFY_RENAME` (except for
   our own deletions), `FILE_ATTRIBUTE_READONLY` on files, and a file that was changed all the same
   is dehydrated on close — the next opening brings back the server's version.
5. **Inputs are checked before the call**, and **no callback may abort**: every one lies in
   `catch_unwind`. A panic across the FFI boundary does not hit us but File Explorer's request.
6. **No self-hydration:** `CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION` — if our own process
   reads a placeholder, it otherwise deadlocks with itself.
7. **Registration over Win32 `CfRegisterSyncRoot`, unpackaged** (corrected 2026-09-11, see below).
   Not over WinRT `StorageProviderSyncRootManager.Register`, and **never both for the same root** —
   Microsoft explicitly demands exactly one registration API. `CF_SYNC_REGISTRATION` carries
   `ProviderName` “elasticdms”, the provider version, a fixed provider GUID and, as
   `SyncRootIdentity`, the account identifier; flags
   `CF_REGISTER_FLAG_UPDATE | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT`. Deregistration uses
   `CfUnregisterSyncRoot`, **after** the tree has been deleted.

## Correction to §7 (2026-09-11): Win32 instead of WinRT, unpackaged instead of a sparse package

The original version concluded from “`Register` fails without package identity” that a package was
needed. The conclusion was wrong: what is needed is the **other API**.

* **WinRT `Register` from an unpackaged process** is reported as `E_ACCESSDENIED` and has been
  reproduced by Microsoft. It is not clear whether that will ever be fixed.
* **`CfRegisterSyncRoot` is the Win32 path and requires no package identity.** It has been there
  since Windows 10 1709 — that is, across the whole supported range.
* **Nextcloud ships unpackaged** and uses `CfRegisterSyncRoot` together with registry keys of its
  own under `HKLM`. That is the only combination demonstrably running in a shipped, unpackaged
  product (02-platform-decision §1.2).
* A sparse package requires Windows' own tools (`MakeAppx`, `SignTool`) and a trusted certificate —
  neither present on the development machine, and for the customer an extra step with every
  delivery.

**What doing without costs:** the entry in File Explorer's navigation pane. It hangs on registry
keys under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\<provider>!<SID>!<account>`.
The client does **not write them yet**; `crates/cfapi/src/sync_root.rs` computes the identifier and
checks its limits, no more. Without those keys the folder is fully usable — it simply does not
appear in the sidebar.

**Open, to be settled only on a Windows machine:** whether a non-elevated process may write under
`SyncRootManager`. Nextcloud does it at runtime and treats a failure as non-fatal. If it does not
work, an elevated action of the installer writes the keys — or the sparse package comes after all.
For that case `packaging/windows/AppxManifest.xml` lies ready as a documented **alternative**,
expressly not as part of the product. The procedure stands in `packaging/windows/README.md`.

**What this changes about the rest:** nothing. The connection (`CfConnectSyncRoot`), the callbacks,
the placeholders and the hydration are untouched by the kind of registration.

## Residual risk, named

A program that removes the read-only attribute can write into a hydrated file. The change stays
local (there is no way back to the server) and is discarded on close. That is the limit of the
platform, not of this design.

## Rejected alternatives

- **cloud-filter 0.0.6 as a dependency** — originally chosen, then rejected; see the correction to
  §1. The reason in favour (foreign code has already run) does not outweigh the reason against (an
  `unwrap()` in the error path of a callback).
- **WinRT registration together with a sparse package.** See the correction to §7: it solves a
  problem the Win32 path does not have at all, and it costs tools and a certificate.
- **WinFsp or a driver of our own.** No placeholder model in File Explorer, and a driver needs an
  EV signature.


## Correction to §1 (2026-09-11): without cloud-filter

The original version took `cloud-filter 0.0.6` as a dependency, with the argument: others have
already run foreign callback machinery, nobody would have run ours. Two findings during the build
turned that around.

* **cloud-filter aborts in the error path of a callback.** If the provider reports an error, the
  path there runs over an `unwrap()`. A panic across the FFI boundary inside a cfAPI callback is not
  a crash of *our* program alone — it hits File Explorer's request, and precisely at the moment when
  something has already gone wrong.
* **With the Win32 registration the last use disappeared.** In the end cloud-filter only registered
  the root (over WinRT). After §7 was switched to `CfRegisterSyncRoot`, a dependency without a job
  remained.

**What that costs, spelled out:** the whole FFI layer is now our own code, and **not a byte of it
is our own code. What carries it: every decision checkable without Windows lies in pure modules
with tests (89 on macOS); every callback lies in `catch_unwind`; the `ParamSize` arithmetic is
taken from the cross-check; both Windows targets compile including clippy; and CI runs the pure
tests on `windows-2025`.
