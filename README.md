# elasticdms folder client — Windows and macOS

A **reading mirror** of the elasticdms archive in File Explorer and in Finder: archives with their
case files (Akten), and saved searches, appear as folders, documents as files that are loaded only
when opened. Inside it a branch of **mail baskets**: a file dragged into one is handed in and
capture opens in the browser. And an **icon** in the taskbar or the menu bar with the local usage
log.

Rust, one shared core, two thin platform layers: Windows over the Cloud Filter API (like OneDrive),
macOS over a File Provider extension.

The client speaks to an elasticdms server. A contract-faithful server mock ships in
`crates/mock`, so the whole client can be built, run and tested without one.

## What it does not do

No synchronisation towards the archive, no conflict resolution, no filtering in the client, and no
original record (Urschrift) on the disk — only the redacted or the view version. Lists arrive from
the server already filtered for the signed-in user, and signing out clears the mirror.

## What it looks like

```text
Icon (notification area / menu bar)          File Explorer / Finder
┌───────────────────────────────┐            elasticdms – <tenant>
│ Signed in as N. Lotzer        │            ├── README.txt
├───────────────────────────────┤            ├── Mailbaskets
│ Open elasticdms               │            │   └── Accounting                ← drag a file in here
│ Open folder in File Explorer  │            ├── Archives
│ Open mailbaskets              │            │   └── Incoming invoices
├───────────────────────────────┤            │       └── Sulzer Pumpen – maintenance contract 2026
│ Sign out                      │            │           └── Test report pump 7.pdf   (☁ loads on opening)
├───────────────────────────────┤            └── Saved searches
│ Quit                          │                └── Open invoices over 10,000 €
└───────────────────────────────┘
```

Every sentence there comes from the text catalogue: on a German workstation the hint file is called
`LIESMICH.txt` and the three folders `Briefkörbe`, `Archive` and `Gespeicherte Suchen` (see
“Languages” below). The names of baskets, archives, case files and searches are the server's
titles and are never translated.

For now the window shows exactly one thing: **the local usage log** — what happened to your files
on this device, newest first, like OneDrive's activity list. It says about itself that it is a
local view; the authoritative access log is kept by the server
([ADR-D07](docs/adr/ADR-D07-user-interface.md)).

## The crates

One responsibility per crate, dependencies strictly from the bottom up. The direction is checked by
`crates/architecture-rules` on every `cargo test` — not by this table.

| Crate | Responsibility | may depend on |
|---|---|---|
| `edms-i18n` | Every sentence the user reads, in German and English | — |
| `edms-core` | Identifiers, namespace, file names, changes, delivery rules, log, **the seam** (`port`) | i18n |
| `edms-crypto` | JCS, ES256, DPoP, client assertion, anchor fingerprint, key set | core |
| `edms-wire` | The contract's wire types, golden files | core |
| `edms-store` | Local state in SQLite (WAL); the only place with SQL | core |
| `edms-bridge` | `NamespaceSource` over loopback (macOS: extension ↔ app) | core |
| `edms-net` | Everything HTTP: DPoP with mandatory nonces, sign-in, lists, content, delivery | core, crypto, wire |
| `edms-engine` | Session, namespace reconciliation, hydration, delivery, ingest out of the mail baskets | core, crypto, wire, net, store |
| `edms-cfapi` | Windows: Cloud Filter API | core |
| `edms-fileprovider` | macOS: the File Provider extension (Rust) and domain management | core, bridge |
| `elasticdms` | Icon, window, **the wiring** — the only place where the crates know one another | all but mock |
| `edms-mock` | A contract-faithful server mock — a test rig, never a product | core, crypto, wire |

**The seam** (`edms_core::port`) is two traits, one per direction: `NamespaceSource` (the platform
asks, the engine answers) and `FileSystem` (the engine orders, the platform carries it out). On
Windows the app, the engine and the provider run in one process; on macOS the sandboxed extension
calls `NamespaceSource` over `edms-bridge` in the app's process.

## The server contract

What the client expects of a server stands in
[`docs/spec/03-api-contract-folder-client.md`](docs/spec/03-api-contract-folder-client.md).
`edms-mock` implements it, mandatory DPoP nonces included, so the client really walks the retry
path rather than a happy one. **The truth is the golden files** in `crates/wire/testdata/`, which
the client, the mock and the contract document all check against.

Because the delivery channel is our own proposal and not the counterpart's spec, its values are
English too: `DEHYDRATE`, `RECONCILE`, `SIGN_OUT`, `REFRESH_KEYS`, the reasons `ERASURE`,
`ACCESS_REVOKED`, `SPACE_RECLAIM`, the outcomes `APPLIED`, `NOT_APPLICABLE`, `REJECTED`, `FAILED`.
Field names stay as the contract has them (`documentId`), and so do error type URIs, scopes, OAuth
and HTTP header names.

## Languages

Nothing the user reads is hard-coded. `crates/i18n` (package `edms-i18n`) holds one catalogue per
language, embedded into the binary with `include_str!`:

```text
crates/i18n/catalog/de.toml     German — the text that grew with the product
crates/i18n/catalog/en.toml     English — a real translation, and the fallback
```

* **Choosing a language:** `EDMS_LANG` first (`de` or `en`), then the operating system's list of
  interface languages, then English. The choice is settled once at the start, so that the menu and
  the window never speak two languages at the same time; a fallback is written to the diagnostic
  log once per process.
* **Adding a locale:** put a `<tag>.toml` next to the two files, copy every key from `en.toml`,
  translate the values, and add the variant to `edms_i18n::Language` (`ALL`, `tag`,
  `Catalog::of`). The catalogue files are the only place where sentences stand.
* **A missing key is a build stopper, not a runtime hole.** A key is a value
  (`edms_i18n::key::MENU_OPEN`), and `crates/i18n/tests/catalogs.rs` compares every catalogue
  against the key list in both directions — a key missing from one catalogue, an extra key in
  another, or a differing set of `{placeholders}` for the same key all make the tests red, so
  `make check` does not pass. `make catalogs` reads the same files once more with a second, foreign
  TOML implementation (`scripts/check-catalogs.py`).
* **What stays English:** everything an operator reads — `--help`, `doctor`, `--uninstall` and every
  `tracing` line. They are read in a terminal, pasted into a ticket and searched for; a translated
  diagnosis cannot be found again. The reasoning stands in
  [ADR-D10](docs/adr/ADR-D10-user-interface-language.md).

## Getting started

```sh
make help        # every handle
make mock        # the server mock on 127.0.0.1:8480 (API) and :8481 (sign-in)
make demo        # the app with sample data and an open window, without a server
make bundle      # macOS: build and check elasticdms.app with the extension (installs nothing)
```

**macOS, once:** put the built app into `~/Applications` and start it once; then switch the
extension “elasticdms” on in *System Settings → General → Login Items and Extensions*. Without that
step the folder stays empty and every access hangs — macOS demands it from version 26 on, and no
program can take it off you
([ADR-D05](docs/adr/ADR-D05-macos-file-provider.md)).

**Windows:** see [`packaging/windows/README.md`](packaging/windows/README.md).

## Delivering

```sh
scripts/macos-package.sh build      # -> target/pkg/elasticdms-<version>.pkg (universal, unsigned)
pwsh scripts/windows-package.ps1    # -> target/package/elasticdms-<version>.msi (on Windows)
```

A tag `v<version>` starts [`release.yml`](.github/workflows/release.yml): the version comparison,
both packages, the signature and the notarisation **if** the secrets are deposited, then a release
draft with checksums. Every push builds the same packages unsigned over
[`ci.yml`](.github/workflows/ci.yml) — packaging that only runs at release time rots unnoticed.
Which certificates are needed and how to create them stands in
[`docs/DELIVERY.md`](docs/DELIVERY.md); the decision behind it in
[ADR-D09](docs/adr/ADR-D09-delivery-and-packaging.md).

## Configuration

Environment variables with the prefix `EDMS_`, checked at start-up; if a mandatory value is
missing, the start aborts with a message saying which value is missing and what it is needed for.
No silent defaults for things that have to be right, and no `.env` in the directory.

| Variable | Meaning |
|---|---|
| `EDMS_API_BASE` | The resource API, e.g. `https://api.elasticdms.io` (mock: `http://127.0.0.1:8480`) |
| `EDMS_AUTH_BASE` | The authorization server, e.g. `https://auth.elasticdms.io` (mock: `http://127.0.0.1:8481`) |
| `EDMS_APP_BASE` | The web interface for capture and the mailbox |
| `EDMS_LANG` | `de` or `en`; overrides the operating system's choice |
| `EDMS_LOG` | The diagnostic log level, e.g. `debug` |

Plain HTTP is allowed only against `127.0.0.1`/`localhost`.

## Checking

```sh
make check     # format, clippy (-D warnings), all tests, architecture rules, catalogues, Windows build
```

`make check` runs on macOS and on Windows, and CI runs it on both. The platform crates carry
tests for everything decidable without the platform — path shaping, the registry values, the
placeholder arithmetic — so that only the operating-system calls themselves need the operating
system.

`cargo xwin check --workspace --target x86_64-pc-windows-msvc` builds the Windows target from
macOS, which `make check` does for you.

## Licence

Apache License 2.0 — see [`LICENSE`](LICENSE).
