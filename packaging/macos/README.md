# macOS: bundle, package, distribution

Two things come into being here: the bundle `elasticdms.app` with the file provider extension
inside it, and out of the bundle the installation package `elasticdms-<version>.pkg`.

```text
scripts/macos-bundle.sh build      → target/bundle/elasticdms.app        (development)
scripts/macos-package.sh build     → target/pkg/elasticdms-0.1.0.pkg      (delivery)
```

## Why a .pkg and not a .dmg

Because the devices are managed. Jamf accepts `.pkg` and nothing else; Intune has two ways, and the
right one for us is **“macOS app (PKG)”** (unmanaged, over the Intune agent from 2308.006) — per
Microsoft this app type explicitly accepts *unsigned* packages too and allows pre- and post-install
scripts. The second way, “macOS LOB app”, requires a package signed with **Developer ID Installer**
and is our second choice.

The real gain lies deeper: **a bundle put into `/Applications` by the installer carries no
`com.apple.quarantine`** and is therefore never translocated. Apple describes translocation as
“Gatekeeper opens apps from randomized, read-only locations … designed to prevent the automatic
loading of plug-ins distributed alongside the app” — and the embedded `.appex` is exactly such a
plug-in. A `.dmg` does not answer that question; it leaves it to the user, who has to drag the app
to the right place, or not.

## What lies here

| File | What for |
|---|---|
| `elasticdms-Info.plist` | The app: `de.elasticdms.folderclient`, a menu bar program (`LSUIElement`), macOS 13+ |
| `elasticdms-fileprovider-Info.plist` | The extension: `XPC!`, extension point `com.apple.fileprovider-nonui`, principal class `EdmsFileProvider` |
| `elasticdms-fileprovider.entitlements` | The sandbox, outbound network, read access to the one folder with `bridge.json` |
| `elasticdms-uninstall.sh` | The uninstall. Travels inside the bundle: `elasticdms.app/Contents/Resources/` |
| `de.elasticdms.folderclient.plist` | The login item for `/Library/LaunchAgents` (autostart, all users) |
| `components.plist` | The component list for `pkgbuild` — this is where `BundleIsRelocatable=false` stands |
| `distribution.dist` | The distribution description for `productbuild`: minimum version 13.0, both architectures |
| `scripts-app/preinstall` | Unloads the running version before an update |
| `scripts-loginitem/postinstall` | Loads the login item straight away instead of waiting for the next sign-in |
| `resources/conclusion.html` | The installer's conclusion text: the one manual step nobody can take off the user |
| — | The app gets **no** entitlements file: it is not sandboxed (ADR-D05, measurement 2) |

The scripts replace `@VERSION@` in the plists and in `distribution.dist` from
`[workspace.package].version`; the version has its only truth in `Cargo.toml`. The installer decides
update against downgrade on that number alone — a forgotten increase means that a successor package
counts as already installed.

The bundle identifiers (`de.elasticdms.folderclient`, `….fileprovider`, `….loginitem`) were German
until 2026-09-13 (`…ordnerclient`, `….dateianbieter`, `….anmeldeobjekt`), on the argument that they
are identities on installed machines and in MDM payloads and that changing one means a migration
rather than a rename. Measured on this machine on 2026-09-13: no `/Applications/elasticdms.app`, no
plist in either `LaunchAgents` directory, no `pkgutil` receipt, no File Provider container, no
`~/Library/CloudStorage/elasticdms-*` — and per the owner the same day no published package, no App
ID with Apple and no MDM payload anywhere else either. With nothing to migrate they became English
like the rest (ADR-D10, correction of 2026-09-13). From the first package that leaves this
repository they are identities again, and then changing one is a migration.

What that list does **not** cover is the **login keychain**, and on the development machine it is
the one place the rename costs something: ten generic-password items still stand under the old
service `de.elasticdms.ordnerclient`, among them the private device key and the refresh token of a
completed enrolment. `elasticdms-uninstall.sh` cannot reach them — `SERVICE` below names the new
identity only, and deliberately so (ADR-D10, “What the rename costs on the one machine where it
costs anything”). They are deleted by hand, once. On a customer machine the case cannot arise: no
package with the old identity was ever published.

## Building the package

```bash
scripts/macos-package.sh build
```

That is the whole way: compile both architectures (`MACOSX_DEPLOYMENT_TARGET=13.0`), join them into
universal programs with `lipo`, bundle, sign from the inside out, `pkgbuild` for both components,
`productbuild` for the product archive, notarise (as far as possible), check.

**Without any certificate that runs all the way through** and delivers an unsigned, un-notarised
`.pkg`. The script says so in a sentence and does not fail. With certificates:

```bash
SIGNING_IDENTITY="Developer ID Application: … (F2N9G4DJKM)" \
INSTALLER_IDENTITY="Developer ID Installer: … (F2N9G4DJKM)" \
ASC_KEY_P8=/path/AuthKey_XXXX.p8 ASC_KEY_ID=XXXX ASC_ISSUER=<UUID> \
scripts/macos-package.sh build
```

If the tenant's base addresses are known at build time, the package writes them into the login item;
otherwise the key stays away and the MDM supplies it afterwards (see below):

```bash
EDMS_API_BASE=https://api.customer.de \
EDMS_AUTH_BASE=https://auth.customer.de \
EDMS_APP_BASE=https://app.customer.de \
scripts/macos-package.sh build
```

Individual steps: `universal`, `bundle`, `sign`, `package`, `notarize`, `verify`, `remove`, `clean`,
`help`.

## What the package does

```text
/Applications/elasticdms.app                                  (component …folderclient.app)
└── Contents/PlugIns/elasticdms-fileprovider.appex
/Library/LaunchAgents/de.elasticdms.folderclient.plist        (component …loginitem)
```

Two components, because there are two destinations. Both are invisible choices: there is nothing to
choose — without the program the login item points at nothing, without the login item nothing starts
after signing in.

The login item lies in `/Library/LaunchAgents` and not in `~/Library/LaunchAgents`, and it is not
registered over `SMAppService`. The reason: per Apple DTS, `SMAppService.agent(plistName:)`
registers only for the current user (“The API has no way to install an agent for all users”) and
demands a real Apple signature — with an ad-hoc signature it fails. The plist in the system path
holds for every user of the device, future ones included.

It carries **no `KeepAlive`**. Without `EDMS_API_BASE`, `EDMS_AUTH_BASE` and `EDMS_APP_BASE`
elasticdms aborts the start with a sentence naming the missing variable; with `KeepAlive` that would
turn into a start loop every ten seconds that nobody sees.

## Installing by hand

```bash
sudo installer -pkg target/pkg/elasticdms-0.1.0.pkg -target /
```

A double click works just as well — **as long as the package was not downloaded from the network**.
Gatekeeper refuses an unsigned package with a quarantine attribute; that is the price of the missing
certificate and no fault of the package. Over MDM the question does not arise.

## The one manual step no installer takes off the user

After the installation — and after every sign-in to the elasticdms account — the user has to approve
the extension once:

> **System Settings → General → Login Items and Extensions → File Providers → switch “elasticdms”
> on**

Until then the domain is `userEnabled = false`, the folder stays empty, and every access hangs
without an error message appearing anywhere (ADR-D05, measurement 4). The installer's conclusion
text tells the user exactly that sentence.

On top of that, macOS 13+ reports the first time that “elasticdms added items that can run in the
background” — that is the login item, and it may stay.

With an **ad-hoc build the signature changes with every build**; the approval then has to be given
again after every update (ADR-D05). With Developer ID that falls away.

## Distribution over MDM

### Intune

* App type **“macOS app (PKG)”** (not “macOS LOB app”). Needs the Intune agent from 2308.006,
  accepts unsigned packages, package < 8 GB.
* The detection rule uses the package identifier `de.elasticdms.folderclient.app` and the version.
  “Ignore app version = No” demands that the version in `Cargo.toml` rise with every delivery.
* **There is no uninstall assignment for this app type** (“The Uninstall assignment type isn't
  available”). Removal runs over a script of our own, see below.
* If the `EDMS_*` base addresses are missing from the package, they can be added afterwards over a
  shell script of the Intune agent that extends the plist in `/Library/LaunchAgents` and reloads the
  login item.

### Jamf

Upload the package to Jamf Admin/Jamf Pro and install it over a policy; an unsigned package goes
over a policy just as well as a signed one.

### Two configuration profiles that take work off the user

In Apple's schema both payloads carry `allowmanualinstall: false` and `userapprovedmdm: true` — they
**cannot** be double-clicked as a `.mobileconfig` but only delivered over a real MDM with
user-approved enrollment. So they cannot be tried out on the development machine.

**1. Pre-allow the login item** — `com.apple.servicemanagement`, the device channel, macOS 13+:

```text
Rules = [ { RuleType        = "BundleIdentifier",
            RuleValue       = "de.elasticdms.folderclient",
            TeamIdentifier  = "F2N9G4DJKM",
            Comment         = "elasticdms folder client, ADR-D05" } ]
```

The payload “auto-enables and auto-allows matched items”: the user no longer sees the notification
and cannot switch the login item off.

**2. Pre-approve the file provider domain** — `com.apple.fileproviderd`, the device channel,
**only from macOS 26.4**:

```text
ManagementDomainAutoEnablementList = [ "de.elasticdms.folderclient (F2N9G4DJKM)" ]
```

The limits, verbatim from Apple's schema: “The device doesn't enable existing domains if enrollment
happens after they are created. The device doesn't prevent the user from disabling these File
Provider domains.”

**This project's floor is macOS 13.0** (ADR-D05). Between 13.0 and 26.3 there is **no** payload for
approving the domain — `com.apple.servicemanagement` covers login items, not appex approvals, and
`com.apple.system-extension-policy` applies only to system extensions. For a fleet with mixed
versions that means: two rollout paths, and the operating instructions still have to name the manual
step in System Settings.

**Both profiles presuppose a signature with a team ID.** They address apps in the format “bundle ID
(team ID)”, and an ad-hoc signature has no team ID. Developer ID is therefore not only a question of
what Gatekeeper says but a precondition for the unattended rollout.

## Uninstalling

The macOS installer knows no uninstall; it therefore lies inside the bundle:

```bash
/Applications/elasticdms.app/Contents/Resources/elasticdms-uninstall.sh remove
```

As the **signed-in user**, not with `sudo` — the script asks separately for `/Applications` and
`/Library/LaunchAgents`. Without a screen (MDM): `OHNE_RUECKFRAGE=ja` answers every question with
yes. `elasticdms-uninstall.sh verify` shows the state without changing anything.

The order, and why it is this one:

1. **Remove the domain** — first, because after `rm -rf` of the app there is no provider left and the
   domain would stay standing together with its sidebar entry.
2. Quit the running program.
3. Unload the login item (`launchctl bootout gui/$UID/…`) and delete the plist.
4. Delete `/Applications/elasticdms.app`, forget the package receipts (`pkgutil --forget`).
5. `~/Library/Application Support/de.elasticdms.folderclient` (with `bridge.json`) — on request.
6. The keychain entries under the service `de.elasticdms.folderclient` — on request. This is where
   the device key lies (ADR-D03); leaving it would mean leaving a sign-in secret on a device that no
   longer has the client.

**Step 1 is something the script cannot do itself today.** A domain is removed only by the provider
over `NSFileProviderManager`, in the context of the signed-in user; `fileproviderctl` knows no
“domain remove”, and from an installer script running as root the domain is out of reach. The way
today is **the menu bar icon → “Sign out”** — that calls `FileSystem::clear_everything` and removes
every elasticdms domain with `NSFileProviderDomainRemovalModeRemoveAll`. The script checks
`~/Library/CloudStorage/elasticdms-*`, says that sentence, and aborts unless one explicitly wants to
carry on.

*(On the switch `elasticdms --uninstall`: it exists by now (`crates/app/src/uninstall.rs`), but it is
**built for Windows** and does not help here. On macOS it prints a sentence, changes nothing and
ends with 0 — deliberately, because it runs where the MSI calls it, as SYSTEM without a user
profile, and a user context is exactly what `NSFileProviderManager` demands. The unattended
uninstall on macOS therefore stays open.)*

If an entry “elasticdms” still hangs in System Settings afterwards although everything has been
removed, only `sudo sfltool resetbtm` helps — that resets the login items of **all** programs and is
therefore the last resort.

## Signing and notarising

It takes **two different certificates**, both creatable in the existing paid team `F2N9G4DJKM`
(role Account Holder or Admin):

| Certificate | What for |
|---|---|
| **Developer ID Application** | `elasticdms.app` and `elasticdms-fileprovider.appex` |
| **Developer ID Installer** | the product archive `.pkg` |

With an application identity no flat package can be signed; measured on this machine:
`productsign: error: … An installer signing identity (not an application signing identity) is
required for signing flat-style products.`

The order: sign the appex (with its entitlements) → sign the app (without) → both with
`--options runtime --timestamp` → `pkgbuild` → `productbuild --sign` → `notarytool submit --wait`
→ `stapler staple`. That is exactly what `macos-package.sh` does. An **unsigned `.pkg` cannot be
notarised**: the service accepts only “disk images (UDIF format), signed flat installer packages,
and ZIP archives”.

For CI an App Store Connect API key (`.p8` + key ID + issuer UUID) is to be preferred over the
app-specific password: no personal Apple account, no two-factor coupling, revocable on its own. The
identities go into a keychain of their own:

```bash
security create-keychain -p "$KEYCHAIN_PW" build.keychain
security set-keychain-settings -lut 21600 build.keychain
security default-keychain -s build.keychain
security unlock-keychain -p "$KEYCHAIN_PW" build.keychain
security import cert.p12 -k build.keychain -P "$P12_PW" -T /usr/bin/codesign -T /usr/bin/productbuild
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" build.keychain
```

## What is checked here — and what is not

Checked on the finished package (`scripts/macos-package.sh verify`), without installing it: both
Info.plists lint, the keys are right, the signatures are valid, the extension carries its three
entitlements, the entry point is `_NSExtensionMain` **in every architecture separately**, both
programs are universal (`x86_64 arm64`, `minos 13.0`), the distribution names `min="13.0"`, the
login item lints and carries its label, program path and `RunAtLoad` — and `edms-mock` occurs
neither as a file name nor as a string in the programs.

“In every architecture separately” is the point: with a universal file `otool -l` prints both
architectures one after the other, and an `awk … exit` would read only the first (x86_64). Until
2026-09-11 `verify_entry_point` checked exactly that way — the arm64 architecture, which runs on
every Mac today, was unchecked. Now the check runs over `lipo -archs` and `otool -arch`.

**Not run**, for want of a certificate or an MDM, or because it would have changed the system:

* `sudo installer -pkg …` — the package has **never been installed** on this machine. So `preinstall`
  and `postinstall` have never run either, and the statement “the login item starts straight away” is
  reasoned, not measured.
* `productbuild --sign`, `notarytool`, `stapler` — there is neither a Developer ID Application nor a
  Developer ID Installer identity on this machine.
* The two MDM payloads — there is no MDM here, and neither can be applied by hand.
* Whether the sandbox exception
  `com.apple.security.temporary-exception.files.home-relative-path.read-only` passes together with
  the hardened runtime and notarisation. That is the first point a real Developer ID build has to
  check: if the handshake over `bridge.json` breaks, the extension reports “app not reachable”.
