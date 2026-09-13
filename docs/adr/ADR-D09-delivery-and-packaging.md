# ADR-D09: Delivery — .pkg, MSI and a pipeline that stays green without secrets

**Status:** Accepted (2026-09-11).

`docs/DELIVERY.md` describes the way from a package to a running folder, and what each artefact
carries by way of a signature.

## Context

The client was finished and undeliverable: a bundle in the build directory, no installer, no
pipeline. The operation is a Microsoft 365 house with managed devices; distribution goes over
Intune, on the Mac additionally over Jamf. Two earlier decisions bind here:

* **ADR-D05:** A program that starts out of quarantine is translocated — and translocation destroys
  the embedded extension (“designed to prevent the automatic loading of plug-ins distributed
  alongside the app”). What the installer puts into `/Applications` carries no quarantine.
* **ADR-D06:** The sync root is registered at runtime with `CfRegisterSyncRoot`, unpackaged. An
  uninstall that leaves it standing blocks the next installation.

## Decision

1. **macOS: one `.pkg`**, built by `scripts/macos-package.sh`. Two components under one product
   archive: the app into `/Applications` (`BundleIsRelocatable=false`, otherwise the installer
   writes into a developer copy it finds) and a LaunchAgent into `/Library/LaunchAgents`. A
   universal binary (`x86_64` + `arm64`), `MACOSX_DEPLOYMENT_TARGET=13.0` matching
   `LSMinimumSystemVersion`. An uninstall script lies in the package.
2. **Autostart over `/Library/LaunchAgents`, not `SMAppService`.** `SMAppService` reaches only the
   current user and demands a real signature; a plist in `/Library/LaunchAgents` holds for all
   users, future ones included — and that is the case a managed machine needs.
3. **Windows: a WiX v5 MSI**, per machine into `ProgramFiles64\elasticdms`, a fixed `UpgradeCode`,
   `MajorUpgrade`, autostart over `HKLM\…\Run`. **The uninstall calls `elasticdms --uninstall`** as
   a deferred action before `RemoveFiles` and thereby deregisters the roots. Because
   `CfUnregisterSyncRoot` is path-based, the one run as SYSTEM clears **all profiles**, not just one.
4. **The signing secrets live in the environment `sign`, not in the repository**, and in GitHub that
   environment is restricted to tags `v*`. On top of that `release.yml` checks that the tag sits on
   `main`. *Reason:* The repository is open; a repository secret would be open to every run in the
   main repo, a push to a side branch included. What gets signed is what went over main and carries
   a tag.
5. **Signing is optional, everywhere.** Without a certificate the same artefacts arise, only
   unsigned, and the pipeline stays green. `ci.yml` names `secrets.` **not once**; in `release.yml`
   they stand solely as a job environment, and every use hangs on a step that first establishes
   whether they exist.
6. **Two workflows.** `ci.yml` builds both packages unsigned on every push — a packaging step that
   only runs at release time rots unnoticed. `release.yml` hangs on the tag `v*`, first checks on an
   Ubuntu runner that the tag matches the version in `Cargo.toml` (one minute of Ubuntu instead of
   ten minutes of macOS), builds both packages, signs and notarises when the secrets are there, and
   creates a **draft** release with checksums.

## Rationale

Jamf takes `.pkg` and nothing else; Intune takes `.pkg` **unsigned** as well over the agent, while
the managed form needs “Developer ID Installer”. On Windows, MSI is the format that Intune and group
policy distribute without a detour. The draft instead of the finished release is deliberate: a
release that publishes itself publishes the failure too.

## Consequences

* **Without two Apple certificates there is no distributable macOS version.** “Developer ID
  Application” signs the app and the extension, “Developer ID Installer” signs the package; an
  application identity is hard-rejected when signing a package. Both are created by somebody with
  the role Admin or Account Holder in team F2N9G4DJKM. Notarisation uses an App Store Connect API
  key (`.p8`), not an app-specific password.
* **Without an Authenticode certificate, Windows SmartScreen shows a warning.** The MSI installs all
  the same; for a silent distribution over Intune that is bearable, for a download it is not.
* **One manual step stays with the user:** switching the extension on once in System Settings.
  **From macOS 26.4** an MDM payload takes that off their hands — `com.apple.fileproviderd`, key
  `ManagementDomainAutoEnablementList`, entry `de.elasticdms.folderclient (F2N9G4DJKM)`. Below that
  there is no payload for it; our floor is macOS 13.

## Rejected alternatives

* **A `.dmg` alone.** Right for a direct download, useless for MDM.
* **MSIX or a sparse package.** ADR-D06 chose the unpackaged path; a package would demand Windows'
  own tools and a trusted certificate with every delivery.
* **Inno Setup or NSIS.** Produces no MSI and hence no clean Intune/GPO distribution.
