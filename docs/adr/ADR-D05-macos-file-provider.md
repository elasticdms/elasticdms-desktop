# ADR-D05: macOS — File Provider extension in Rust

**Status:** Accepted (2026-09-11).

The decisions below rest on measurements on macOS 26.6 (build 25G72), not on documentation alone;
each says what was measured.

## Context

On macOS there is exactly one contemporary way for third parties to offer a placeholder tree: a
File Provider extension (`NSFileProviderReplicatedExtension`, from macOS 11, `contentPolicy` from
13). Kernel extensions are deprecated, FSKit requires a restricted entitlement and macOS 15.4.

## Measured, not assumed

1. **No paid developer account needed.** An ad-hoc signed app (`codesign -s -`,
   `TeamIdentifier=not set`) with an embedded extension could be registered,
   `NSFileProviderManager.add` succeeded, and the domain appeared under `~/Library/CloudStorage/`.
2. **The extension has to be sandboxed**, otherwise PlugInKit does not accept it. The app does not.
3. **No app group.** On macOS an app group needs a team ID as a prefix; ad hoc there is none.
   `NSExtensionFileProviderDocumentGroup` is therefore missing from the Info.plist — if the key is
   there and does not match, the system discards the extension without a visible error.
4. **The user has to switch the extension on** (System Settings → General → Login Items and
   Extensions). Until then the domain is `userEnabled = false`, and every access hangs.
5. **A Rust class can be the principal class**: a program with entry point `_NSExtensionMain`, the
   class via `objc2::define_class!`. But objc2 registers classes only on first access; PlugInKit
   looks them up by name before that. A constructor in `__DATA,__mod_init_func` registers them at
   load time — without it `objc_getClass` returns nothing (measured).

## Decision

- **The extension is a Rust program** (`elasticdms-fileprovider`), embedded as
  `elasticdms.app/Contents/PlugIns/elasticdms-fileprovider.appex`. It decides nothing: every
  question goes over `edms-bridge` to the engine in the app.
- **The line is TCP on 127.0.0.1**; the extension holds `com.apple.security.network.client`. Port
  and secret stand in `~/Library/Application Support/de.elasticdms.folderclient/bridge.json` (mode
  0600), readable by the extension through a `temporary-exception` for exactly that path.
- **Read-only** over the capabilities (`allowsReading`, for folders enumeration) and the refusal in
  `createItem`/`modifyItem` (`CannotSynchronize`, final) and `deleteItem` (`DeletionRejected`).
- **Server changes** arrive solely over the working set: the engine signals, the extension fetches
  `changes_since(anchor)`. With replicated providers other containers cannot be signalled at all
  (NSFileProviderManager.h).
- **No pinning in v1.** macOS offers third parties no system entry for it; an entry of our own would
  need the FileProviderUI extension. So on macOS this holds: every copy is removable at any time.

## Consequences

- **Distribution** needs a Developer ID signature and notarisation — that costs a paid account. For
  development, ad hoc is enough.
- **The Mac App Store** is ruled out by a `temporary-exception`. Should it ever be needed, an app
  group (with a team ID) replaces the rendezvous path; the line stays as it is.
- The ad-hoc identity changes with every build; approvals in System Settings then have to be given
  again.

## Rejected alternatives

- **A Swift extension with a Rust library.** Works just as well (measured), but brings a second
  language and an Xcode project into the house. It stays the fallback should the objc2 macros not
  be able to express a method.
- **FSKit.** A restricted entitlement (without a paid account `SIGKILL`, measured), macOS 15.4+.
- **macFUSE.** A kernel extension or reduced security — nothing to inflict on an office.
