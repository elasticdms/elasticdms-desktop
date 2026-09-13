# Delivery: from the tag to the package

**State: 2026-09-12.** This document describes the two workflows in `.github/workflows/` and what a
human has to do around them.

> **Not run:** none of these runs has ever run — the repository has no remote on GitHub yet, so
> there are neither runners nor a place for secrets. What is checked is what could be checked on
> this machine: `actionlint` over both files (without its shellcheck rule — shellcheck is not
> installed here), the PowerShell parser over every `pwsh` block, and the bash steps individually
> against real packages (section “What is checked — and what is not”).

Why two packages and not two programs: the operator distributes to managed devices — Intune and
GPO. GPO software installation accepts `.msi` and nothing else; Jamf accepts `.pkg` and nothing
else, Intune accepts `.pkg` as the app type **“macOS app (PKG)”**. And on macOS the decisive thing
comes on top: **a bundle put into `/Applications` by the installer carries no
`com.apple.quarantine`** and is therefore never translocated — translocation would cut the ground
from under the embedded file provider extension (ADR-D05). A `.dmg` does not answer that question;
it leaves it to the user.

## The short version

```sh
# 1. Raise the version — the only truth stands in Cargo.toml, [workspace.package] version.
# 2. Set the tag and push it:
git tag v0.2.0 && git push origin v0.2.0
# 3. Wait (roughly 15–30 min macOS, 10–20 min Windows).
# 4. Under "Releases" there is a DRAFT with .pkg, .msi and SHA256SUMS.
#    Read it, check it, publish it — that is done by a human, not by the workflow.
```

A trial run without a tag: *Actions → release → Run workflow*. It builds both packages and
publishes nothing.

## What happens on a tag run

`.github/workflows/release.yml`, four jobs:

| Job | Runner | What it does |
|---|---|---|
| `version` | `ubuntu-latest` | Reads `version` from `[workspace.package]` and compares it with the tag. If they do not match, the run aborts **here** — before a macOS minute is spent. No Rust, no toolchain, about 20 seconds. |
| `macos` | `macos-15` | Toolchain from `rust-toolchain.toml`, a keychain for this one run (only with secrets), `scripts/macos-package.sh build`, the bar against the mock, signature and notarisation probes, the checksum, the artefact. |
| `windows` | `windows-2025` | Toolchain, certificate and `signtool` (only with the secret), `scripts/windows-package.ps1`, the bar against the mock, the signature probe, the checksum, the artefact. |
| `publish` | `ubuntu-latest` | Downloads both artefacts, writes a shared `SHA256SUMS`, and creates the draft with `gh release create --draft`. |

Only `publish` carries `permissions: contents: write`; at the top of the file stands
`permissions: {}`. That job runs **no foreign action code** but the preinstalled `gh` — with
`tj-actions/changed-files` (CVE-2025-30066) an attacker moved all version tags onto a malicious
commit and let secrets run into the log. The one foreign action that is needed
(`Swatinem/rust-cache`) stands on its commit hash, not on its tag.

**What comes out**

| File | Content |
|---|---|
| `elasticdms-<version>.pkg` | macOS 13+, universal (arm64 + x86\_64): `elasticdms.app` including the extension into `/Applications`, plus the login item into `/Library/LaunchAgents` |
| `elasticdms-<version>.msi` | Windows 10 1709+, x64 |
| `SHA256SUMS` | The checksums of both files, in the shape `sha256sum -c` reads |

If the signing secrets are missing, the files are called `elasticdms-<version>-unsigned.pkg` and
`…-unsigned.msi`. The name carries it along, so that nobody passes on the wrong thing outside the
web interface either.

## Packaging on every push

`.github/workflows/ci.yml` builds both packages **unsigned** on every push, on every pull request
and once a week without a reason (`schedule`). The reason: a packaging pipeline that only runs at
release time rots in silence — a runner image changes its WiX version, a path no longer matches,
and it would be noticed on release day. The artefacts are called `package-macos-unsigned` and
`package-windows-unsigned` and stay for seven days. Tags skip both jobs
(`if: github.ref_type != 'tag'`), because `release.yml` builds them then.

The test, clippy and format jobs stay as they were; the only addition is the cache
(`Swatinem/rust-cache`, filled on `main`, read everywhere).

## The seam to the packaging scripts

The workflows build **nothing themselves**. They call two scripts and check afterwards:

| | macOS | Windows |
|---|---|---|
| Call | `scripts/macos-package.sh build` | `scripts/windows-package.ps1` |
| In | `SIGNING_IDENTITY` (app; `-` means ad hoc), `INSTALLER_IDENTITY` (empty means an unsigned package), `ASC_KEY_P8` / `ASC_KEY_ID` / `ASC_ISSUER` (the notarisation lives in the script), `EDMS_API_BASE` / `EDMS_AUTH_BASE` / `EDMS_APP_BASE` (all three or none) | `VERSION`, `SIGNTOOL`, `PFX_PATH`, `PFX_PASSWORD` (empty paths mean unsigned) |
| Out | `target/pkg/elasticdms-<version>.pkg` — next to it lie the two component packages, which nobody delivers | one `elasticdms-<version>*.msi` below `target/` |

The WiX version stands **in the Windows script** (`WIX_VERSION`) and not in the workflow: up to
5.0.2 the NuGet package stands under MS-RL, from 6.0.0 it carries an “Open Source Maintenance Fee”
for companies with 10,000 US$ of annual revenue. That is a legal question, not a technical one, and
it belongs in one place (`packaging/windows/elasticdms.wxs`, section “WHICH WiX VERSION”). The
WiX 3.14 preinstalled on `windows-2025` does not compile the `.wxs`.

What is checked afterwards, instead of believed:

* The product has to **be there and carry the version in its name** — a package without a version in
  its name cannot be told apart from another one in the customer's folder.
* `edms-mock` must not stand in any bill of materials. The test rig carries a contract-faithful
  sign-in; it never belongs in a product. On macOS the bar reads every component separately
  (`pkgutil --expand`, then `lsbom -s` per `Bom`) — **`pkgutil --payload-files` shows only the first
  component of a product archive** (measured on this machine against an archive of two components).
  On Windows it reads the MSI's file table over `WindowsInstaller.Installer`; a text search in the
  raw image would not find the names inside the cabinet file.
* The macOS package has to hold the app **and** the extension — without the `.appex` the folder in
  Finder would stay empty.
* If the secrets are there, the signature really has to be on it (`pkgutil --check-signature`,
  `xcrun stapler validate`, `spctl --assess --type install`, `signtool verify /pa`). Otherwise a
  script that silently ignored a certificate handed to it would deliver an unsigned package under
  the name of a signed one.

## The secrets

The signing secrets live **not** in the repository but in the environment **`sign`**:
*Settings → Environments → New environment → `sign`*, and create **Environment secrets** there.

**Why an environment and not the repository:** this is an open repository. Repository secrets are
open to every workflow that runs in the main repo — a push to any branch included. An environment
can be bound to tags: under *Deployment protection rules → Selected branches and tags* enter the
pattern **`v*`**. That way the certificates only come past a release run, and `release.yml`
additionally checks that the tag sits on `main` (the step “Provenance”). Both together mean: what
gets signed is what went over main and carries a tag — nothing else. Whoever also wants a manual
approval enters themselves under *Required reviewers*; the run then stops before signing.

**Forks need no worry:** on a `pull_request` from a fork GitHub hands out no secrets at all, and
`ci.yml` demands none anyway (`secrets.` appears there zero times).

Certificates and keys as **base64 on one line**:

```sh
base64 -i elasticdms-app.p12 | tr -d '\n' | pbcopy
```

| Name | What | Without it |
|---|---|---|
| `APPLE_CERT_P12` | “Developer ID Application”, exported as `.p12` | The app and the extension are signed ad hoc |
| `APPLE_CERT_PASSWORD` | The password of that `.p12` | — |
| `APPLE_INSTALLER_P12` | “Developer ID Installer”, exported as `.p12` | The `.pkg` stays unsigned and therefore cannot be notarised |
| `APPLE_INSTALLER_PASSWORD` | The password of that `.p12` | — |
| `APPLE_API_KEY_P8` | App Store Connect API key (`AuthKey_*.p8`) | No notarisation, no stapled ticket |
| `APPLE_API_KEY_ID` | The key's identifier (10 characters) | — |
| `APPLE_API_ISSUER` | The team's issuer ID (a UUID) | — |
| `WINDOWS_PFX` | The Authenticode certificate as a `.pfx` | `.exe` and `.msi` stay unsigned; SmartScreen warns |
| `WINDOWS_PFX_PASSWORD` | The password of that `.pfx` | — |

All nine belong in the environment `sign`, not in the repository secrets. The jobs `macos` and
`windows` request them with `environment: sign`; no other job sees them.

On macOS signing happens only when **both** Apple certificates are there. A signed app inside an
unsigned package helps nobody: the notarisation service accepts only signed flat packages, and
Intune's app type “macOS LOB app” sees the package, not the app.

Optional as **repository variables** (not secrets — they stand in the package): `EDMS_API_BASE`,
`EDMS_AUTH_BASE`, `EDMS_APP_BASE`. If all three are set, the macOS login item carries the tenant's
addresses; otherwise the MDM supplies them afterwards. All three or none — a half-set environment
makes `macos-package.sh` abort with a sentence.

### The two Apple certificates

Both need the role *Account Holder* (or *Admin*) in the paid team; on this machine there is today
**only an “Apple Development” certificate** (team `F2N9G4DJKM`), and that is good neither for
distributing nor for signing an installer file.

1. *Keychain Access → Certificate Assistant → Request a Certificate From a Certificate Authority…*,
   “Saved to disk”, 2048-bit RSA. The result: a `.certSigningRequest`.
2. developer.apple.com → *Certificates, IDs & Profiles → Certificates → +* → **Developer ID
   Application**, upload the CSR, download the `.cer` and double-click it.
3. The same again with **Developer ID Installer**. Two certificates, not one: with an application
   identity `productsign` refuses (“An installer signing identity … is required for signing
   flat-style products”, measured).
4. In Keychain Access export **the private key together with the certificate** as a `.p12` with a
   password, in each case.
5. Put the base64 (see above) into the secrets.

Out of that the workflow creates a keychain of its own under `$RUNNER_TEMP` per run, sets
`security set-key-partition-list` (without it `codesign` in CI asks for a password nobody types, and
the step hangs until the time limit) and deletes it again in a step with `if: always()`.

### The key for `notarytool`

appstoreconnect.apple.com → *Users and Access → Integrations → App Store Connect API → Team Keys
→ +*, role *Developer*. The `.p8` file can be downloaded **exactly once**; the key identifier and
the issuer ID stand in the same view. To be preferred over the app-specific password: no personal
Apple account, no two-factor coupling, revocable on its own. The workflow writes the file into
`$RUNNER_TEMP`, hands the path on to `macos-package.sh` and deletes it afterwards.

### The Windows certificate

For our own managed devices a certificate from **our own enterprise CA** (AD CS) with the extended
key usage “Code Signing” is enough: the devices trust the root anyway, and GPO distribution runs in
the system context. A publicly trusted certificate (against SmartScreen) is a different case — since
the CA/Browser Forum's requirements of 2023 its private keys lie on hardware (a token or a cloud
HSM), and then there is **no `.pfx` file any more** that could be deposited; the workflow would need
a signing service instead. *From the documentation, not measured.* As long as that is not decided,
`WINDOWS_PFX` stays empty and the MSI is unsigned.

## What is signed and what is not — honestly

| | With all the secrets | Without secrets (today) |
|---|---|---|
| `elasticdms.app` and `.appex` | Developer ID Application, hardened runtime, timestamp | **ad hoc** (`codesign -s -`) |
| `.pkg` | Developer ID Installer | **unsigned**, the name carries `-unsigned` |
| Notarisation + stapled ticket | yes | **no** |
| `elasticdms.exe` and `.msi` | Authenticode, SHA-256, timestamp | **unsigned**, the name carries `-unsigned` |
| A double click from the network (macOS) | runs | Gatekeeper refuses (quarantine) |
| A double click (Windows) | SmartScreen, until the certificate's reputation is established | SmartScreen warns |
| Intune “macOS app (PKG)” / a Jamf policy | yes | **yes** — per Microsoft this app type explicitly accepts unsigned packages too |
| Intune “macOS LOB app” | yes | no |
| MDM pre-approval of the login item and the domain | possible (details below) | **no**: the payloads address apps as “bundle ID (team ID)”, and an ad-hoc signature has no team ID |
| GPO software distribution | yes | it does install, but every policy with a signature requirement locks it out |
| Ad-hoc side effect on macOS | — | the signature changes with every build, so the extension has to be approved again after **every** update |

The run **never fails** on missing secrets. It builds, checks, uploads — and writes a whole sentence
into the job summary, such as: *“Ad-hoc signed and not notarised — this package is a test specimen
and must not be distributed; `APPLE_CERT_P12` and `APPLE_INSTALLER_P12` are missing.”* That is
deliberate: a run from a fork gets no secret but `GITHUB_TOKEN`, and a CI that goes red over it only
teaches people to overlook red.

## After the installation: the one manual step on macOS

> *System Settings → General → Login Items and Extensions → File Providers → switch “elasticdms”
> on.*

Without it the folder stays empty and every access hangs, without an error message appearing
anywhere (measured, ADR-D05, measurement 4). **No installer can take it off the user** — not even
one that runs as `root`. The installer's conclusion text tells the user exactly that sentence.

An MDM can take it off them under two conditions (*from Apple's schema, not measured here — there is
no MDM on this machine, and neither payload can be applied by hand*):

* **Pre-allow the login item:** `com.apple.servicemanagement`, the device channel, from macOS 13.
* **Pre-approve the file provider domain:** `com.apple.fileproviderd` with
  `ManagementDomainAutoEnablementList` — **only from macOS 26.4**. Between 13.0 (this project's
  floor) and 26.3 there is no payload for it.

Both address the app as “bundle ID (team ID)” and therefore presuppose a Developer ID signature. For
a mixed fleet that means: the manual step stays in the rollout instructions.

On Windows this step does not exist: the client registers its sync root itself at the first sign-in
(`CfRegisterSyncRoot`, ADR-D06). The uninstall deregisters it again over the MSI action
`UnregisterSyncRoots` (`elasticdms.exe --uninstall`) — a root left standing jams every later
installation.

## What a run costs

If the repository is public, all minutes are free. Otherwise: Linux $0.006, Windows $0.010,
macOS $0.062 per minute. A tag run is roughly 15–30 min macOS plus 10–20 min Windows, so **about
$1–2** — estimated, not measured. The two packaging jobs in `ci.yml` cost the same again, **per
push**.

If that gets too much, the place to turn is the `if:` expression of the jobs `package-macos` and
`package-windows`. Out of

```yaml
    if: github.ref_type != 'tag'
```

becomes

```yaml
    if: >-
      github.ref_type != 'tag' &&
      (github.event_name == 'schedule' || github.ref == 'refs/heads/main')
```

— then only `main` and the weekly run package anything. Cheaper, but a fault in the packaging is
only noticed after the merge.

## What is checked — and what is not

On this machine, 2026-09-12 (macOS 26.6, arm64):

| Check | Result |
|---|---|
| `actionlint .github/workflows/ci.yml .github/workflows/release.yml` | **Exit 0** (actionlint 1.7.7). Its `shellcheck` rule stayed **disabled**: shellcheck is not installed on this machine, and actionlint says so instead of pretending. The bash steps were therefore only read, not linted |
| The PowerShell parser over every `pwsh` block of both files (10 blocks) | no syntax errors |
| `bash -n` over both shell scripts, and `-Task help` / `help` over both | no syntax errors, the help is English |
| The `version` step against `Cargo.toml` | `v0.1.0` green; `v9.9.9` aborts with a sentence; on a branch a trial run without approval |
| The mock bar against two real packages (`pkgbuild`/`productbuild`) | a clean package green, a package with `edms-mock` red |
| “Name the package” against an existing, a missing and a wrongly named package | only the correctly named one passes; component packages next to it do not get in the way |
| The release text, signed and unsigned | both versions of the table are right |

Two real faults were found only by the PowerShell parser — both would have crashed only on the
runner:

1. `if (…) { … } else { … } | Out-File` is **no valid start of a pipeline** in PowerShell (“An empty
   pipe element is not allowed”).
2. PowerShell reads **U+201C as a quotation mark**. A typographic quote inside a PowerShell string
   tears it apart in mid-sentence. In `bash` the same character is only a shellcheck warning
   (SC1111) — in PowerShell it is a syntax error.

**Not run**, because it cannot be done here: the workflows themselves. Whether `security import` and
`set-key-partition-list` pass in CI, whether `notarytool` accepts the package, whether `wix build`
compiles the `.wxs`, whether `signtool` is found — all open until the first run has gone through.

## Open

1. **None of this has run on Windows.** `scripts/windows-package.ps1` and
   `packaging/windows/elasticdms.wxs` are there and checked on this Mac as far as that goes here
   (the PowerShell parser, `xmllint`); `wix build`, `msiexec` and `signtool` have never been run. On
   the first build, rework is to be expected
   ([`packaging/windows/README.md`](../packaging/windows/README.md)).
2. **`--uninstall` clears Windows only.** The switch is built (`crates/app/src/uninstall.rs`) and
   carries the MSI action `UnregisterSyncRoots`. On macOS it does **nothing**: it says a sentence and
   ends with 0. On macOS the domain is still removed only by “Sign out” in the menu bar icon,
   because `NSFileProviderManager` demands the context of the signed-in user — see
   [`packaging/macos/README.md`](../packaging/macos/README.md), section “Uninstalling”. An
   unattended uninstall is therefore open on macOS.
3. **No repository on GitHub.** Without a remote there are no secrets, no runners, no approvals —
   and the question “public or private” (minutes free or not) is unanswered.
4. **No certificate**, neither Developer ID nor Authenticode. Until then the pipeline delivers test
   specimens.
5. **Intune recognises updates by the rising version.** It comes from `[workspace.package] version`;
   whoever delivers the same version twice delivers, for Intune, the same version.

## References

* [`docs/adr/ADR-D05-macos-file-provider.md`](adr/ADR-D05-macos-file-provider.md) — the bundle, the
  signature, the manual step in System Settings.
* [`docs/adr/ADR-D06-windows-cloud-filter.md`](adr/ADR-D06-windows-cloud-filter.md) — why unpackaged
  and `CfRegisterSyncRoot`.
* [`packaging/macos/README.md`](../packaging/macos/README.md) — what is in the package, MDM,
  uninstalling.
* [`packaging/windows/README.md`](../packaging/windows/README.md) and
  [`packaging/windows/elasticdms.wxs`](../packaging/windows/elasticdms.wxs) — the MSI and the life
  cycle of the sync root.
