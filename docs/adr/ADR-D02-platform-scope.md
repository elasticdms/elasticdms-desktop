# ADR-D02: Platform scope — Windows and macOS

**Status:** Accepted (2026-09-11).

An earlier scope covered Windows only. Both platforms are in scope, and this record supersedes
that scope.

## Context

`platform-managed.md` §2.7 had struck desktop synchronisation at 6–10 person-months for two
platforms — for a *bidirectional* sync. The requirements record that this estimate does not carry
for a reading Windows client. With macOS the second platform comes back; the reading cut stays.

## Decision

- **One shared core in Rust** that decides everything decidable without an operating system
  (`edms-core`, `edms-engine`), and **two thin platform layers**: `edms-cfapi` (Windows Cloud
  Filter API) and `edms-fileprovider` (macOS File Provider, replicated).
- The seam is two traits in `edms_core::port`: `NamespaceSource` (the platform asks, the engine
  answers) and `FileSystem` (the engine orders, the platform carries it out).
- **Windows: one process** — app, engine and cfAPI provider (one root has exactly one connection,
  `CfConnectSyncRoot`). **macOS: two processes** — the app with the engine and the sandboxed
  extension, joined by `edms-bridge`.

## Rationale

Nextcloud, the only open-source project that serves both platforms properly, runs two separate
stacks, because the ownership is the other way round: on Windows the provider owns the tree, on
macOS the operating system does. The seam here carries both, because it can turn exactly that
direction around — Windows calls `NamespaceSource` from the callback, macOS from the extension.

## Consequences

- Windows code can only be compiled on the development machine (macOS), not run
  (`cargo xwin check`). It is run only in CI (`windows-latest`) and on Windows.
- On macOS the user has to switch the extension on once in System Settings (measured from
  macOS 26; ADR-D05).
