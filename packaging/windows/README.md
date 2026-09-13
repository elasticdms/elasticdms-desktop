# Windows: building, distributing, getting rid of it again

> **Not run on Windows.** Everything in this directory, the whole packaging script
> `scripts/windows-package.ps1` and the entire Windows part of `crates/cfapi` is written on a Mac.
> No `wix build`, no `msiexec`, no `signtool`, no `msiexec /x` has run. What was checked is what can
> be checked here: the `.wxs` as XML (`xmllint --noout`), the PowerShell script with the parser of
> PowerShell 7 (`[Parser]::ParseFile`) and against two error paths (a missing MSI, a contradictory
> version), and the Windows build of the client with `cargo xwin check`. The ICE checks of the
> Windows Installer only run on Windows. On the first build, rework is to be expected; the most
> likely places are named below.

## What gets delivered

One **per-machine MSI**: `target\package\elasticdms-<version>.msi`, built by
[`scripts/windows-package.ps1`](../../scripts/windows-package.ps1) from
[`elasticdms.wxs`](elasticdms.wxs). It puts `elasticdms.exe` into `%ProgramFiles%\elasticdms`,
writes the autostart entry into `HKLM\…\Run`, and on uninstall deregisters the sync root of **all**
profiles.

Beside it, **one language transform per further language**:
`target\package\elasticdms-<version>.en-US.mst`. The MSI itself speaks German; the transform turns
it into the English one. It is one product either way — one ProductCode, one detection rule, one
assignment — and an administrator who ignores the `.mst` gets a working German installation. See
[Languages](#languages) for what that costs on each side and why it is not two MSIs.

Why MSI and not Inno Setup, not MSIX:

* **GPO software installation accepts `.msi` and nothing else.** An Inno Setup `.exe` could only be
  delivered there over logon scripts — without assignment, without uninstallation, without
  inventory.
* **Intune** accepts both, but for an MSI it runs the uninstall itself as
  `msiexec /x {ProductCode}` and reads ProductCode and version for detection.
* **MSIX/sparse is ruled out twice over:** ADR-D06 §7 forbids the WinRT registration path, and a
  sparse package precisely does *not* bring the automatic root deregistration with it — the system
  only cleans up roots registered over `StorageProviderSyncRootManager.Register`. One would take on
  a certificate requirement and still not get the cleanup.

**Unpackaged does not mean without an installer.** “Unpackaged” (ADR-D06 §7) means: without a
*package identity* in the MSIX sense. The client registers the root itself with Win32
`CfRegisterSyncRoot`, and that requires no identity. The MSI is untouched by this — it lays down
files, registry values and the uninstall, and nothing else.

## Building

On Windows, with the .NET SDK and the Rust toolchain from `rust-toolchain.toml`:

```powershell
# Once: WiX as a global dotnet tool. CHANGES THE MACHINE, hence a task of its own.
.\scripts\windows-package.ps1 -Task tool       # dotnet tool install --global wix --version 5.0.2
                                               # plus wix extension add -g WixToolset.Util.wixext

# The whole way: compile, (optionally) sign, pack, (optionally) sign, check.
.\scripts\windows-package.ps1
```

The script knows `-Task build|tool|msi|verify|clean|help`; without an argument it builds. It
compiles **`-p elasticdms`, never `--workspace`** — a build over the whole workspace would also put
`edms-mock.exe` into the same directory, and the test rig never belongs in a product. For the same
reason the `.wxs` lists its files **one by one** instead of harvesting them with `heat`. Both
workflows under `.github/workflows/` afterwards read the **file table** of the finished MSI and go
off if “mock” stands there or `elasticdms.exe` is missing. They install WiX with `-Task tool` and
take no version of their own — the version stands in the script and nowhere else.

The actual call, should it be needed by hand — once per language:

```powershell
wix build -arch x64 `
  -d Version=0.1.0 `
  -d BinDir=target\x86_64-pc-windows-msvc\release `
  -culture de-DE -loc packaging\windows\de-DE.wxl `
  -ext WixToolset.Util.wixext `
  packaging\windows\elasticdms.wxs `
  -o target\package\elasticdms-0.1.0.msi
```

`Version` and `BinDir` are preprocessor variable names of `elasticdms.wxs` and are spelled exactly
as that file spells them; renaming one is a change in the `.wxs` and in
`scripts/windows-package.ps1` at the same time, and a test
(`crates/architecture-rules/tests/scripts.rs`) holds the two halves against each other.

The third variable, `ProductCode`, is **missing on purpose above**: by hand `wix` rolls it itself
(the `.wxs` defaults it to `*`). The build script does pass it, because all languages of one build
have to carry the same one — see [Languages](#languages).

`-culture` and `-loc` belong together. `-culture` decides which catalogues count, so a `.wxl` that
does not match the culture is dropped **without a word** and every `!(loc.…)` in the `.wxs` then
becomes a `WIX0102`. Measured on the development Mac, see
[What can be proven without Windows](#what-can-be-proven-without-windows).

**`-sval` is not set.** On Windows `wix build` runs the ICE checks of the Windows Installer itself;
switching them off would mean throwing away the only check this package has ever seen. Warnings
about directory permissions are to be taken seriously.

### Languages

The four sentences a human reads on the package — the downgrade message, the 64-bit message, the
comment in Programs and Features and the name of the one feature — are **not** in the `.wxs`. They
are in [`de-DE.wxl`](de-DE.wxl) and [`en-US.wxl`](en-US.wxl) and are referenced by name, exactly as
the client's sentences are in `crates/i18n/catalog/`. The same rule holds: identifiers are English,
text is the language it says it is.

Which languages get built stands in **one place**, the list `Cultures` in
`scripts/windows-package.ps1`:

```powershell
$Cultures = @('de-DE', 'en-US')
```

The **first** culture becomes the MSI. Every **further** one is built a second time and the
difference between the two databases is cut out as a language transform with
`wix msi transform -t language`. A third language is this one row longer plus a `<culture>.wxl` of
its own; signing and checking walk the same list, so nothing can be forgotten in one of the two.

#### Why one MSI and a transform, and not one MSI per language

This is the only question here that costs an administrator anything, and it was decided on that:

| | Two MSIs | One MSI + `.mst` |
|---|---|---|
| Products to Windows | **two** (each build rolls its own ProductCode) | **one** |
| Intune | two apps, two uploads, two **detection rules**, two assignments | one app; a second entry for the other language shares content **and** ProductCode, so nothing reinstalls |
| GPO | two packages under *Software installation*, each with its own security filtering | one package plus one entry under *Advanced → Modifications* — the field language transforms exist for, and the same list a property transform already uses (see [GPO](#gpo)) |
| Wrong language on a device | a **major upgrade**: uninstall and reinstall for one changed sentence | a reinstallation as well — no cheaper, no dearer |
| Administrator does nothing | nothing is installed: a file has to be chosen | a working German installation |
| Release | two files to sign, two hashes, two answers to “which one is on this machine” | one file plus a small transform |
| Today's workflows | both look for **exactly one** `elasticdms-<version>*.msi` under `target\` and stop at two | unchanged, an `.mst` is not an `.msi` |

The transform is cheaper in every row, so that is what is built. The price of it is named too: the
`.mst` has to travel **with** the `.msi`. `TRANSFORMS=` points at a file, and a transform that is
not beside the package is a failed installation (`1624`), not an installation in the wrong
language.

**Why `de-DE` is first:** the operator is a German company, the German catalogue is the grown one,
and the base language is the one that needs no transform anywhere. Turning it round is reordering
the list — and then every German machine needs the transform instead.

#### What holds the two languages together

* **One ProductCode for all languages of a build.** The script rolls one GUID per run and hands it
  to every `wix build`. A transform that also moved the ProductCode would not be a language
  transform but a second product. `-Task verify` applies each transform to a copy of the MSI and
  measures both: the language has to change, the ProductCode may not.
* **The code page stays 1252** for both catalogues. A language outside Latin-1 (932 for Japanese)
  may **not** be a transform on this package — a transform that changes the code page is an error
  condition the applying side has to suppress by hand, and a suppressed error is not a
  localisation. Such a language gets a package of its own.
* **The LCID stands in the `.wxl`**, as `PackageLanguage`, not in the build script: one language is
  one file — culture, code page, identifier and text together. The `.wxs` reads it as
  `!(loc.PackageLanguage)`, the script reads the same row to check the finished transform against
  it.

### What can be proven without Windows

`wix` runs on macOS as a dotnet tool. It says so itself (`warning WIX0000: The WiX Toolset only
supports Windows`) and it cannot finish: `Directory/@Name` and `File/@Source` are rejected there on
path grounds (`WIX0389`, `WIX0027`), and writing the database needs the Windows `msi.dll`. What it
**does** do is the preprocessor, the linking and the **resolution of every `!(loc.…)`** — and that
is the half of this package that a runner minute would otherwise have to pay for.

Measured on the development Mac with wix 5.0.2, on the file as it stands:

```console
$ wix build -arch x64 -d Version=0.1.0 -d BinDir=bin \
    -culture de-DE -loc packaging/windows/de-DE.wxl \
    -ext WixToolset.Util.wixext packaging/windows/elasticdms.wxs -o out.msi
wix.exe : warning WIX0000: The WiX Toolset only supports Windows. …
elasticdms.wxs(188) : error WIX0389: The Directory/@Name attribute's value, 'elasticdms',
                      is not a relative path.
elasticdms.wxs(267) : error WIX0027: The File/@Source attribute's value, 'bin\elasticdms.exe',
                      is not a valid filename …
```

Two errors, both about paths, both only on this machine — and **no `WIX0250`** (an unknown
preprocessor variable) and no `WIX0102` (an unknown localisation variable). Those two are what the
`-d` flags and the catalogues are checked with.

The catch: those two path errors end the **compile** phase, and `!(loc.…)` is resolved later. To
get that far on a Mac the two attributes have to be taken out of the way — three `sed` replacements
into a scratch copy (`Source="elasticdms.exe"` with `-b`, and the component group straight into
`ProgramFiles64Folder`). Both catalogues then get as far as `MsiGetFileVersion`, that is into
binding, **without a single `WIX0102`**. Deliberately broken, the same run says what it is worth:

* `!(loc.FeatureTitleTypo)` → `error WIX0102: The localization variable !(loc.FeatureTitleTypo) is
  unknown.`
* `-culture en-US` with `-loc de-DE.wxl` → `WIX0102` for **every** reference, because the catalogue
  is filtered away. That is why the two switches are never written apart.

What stays unproven until a Windows runner has it: the ICE checks, `wix msi transform`, applying
the transform, and `signtool` on an `.mst`. They stand in the table below.

### Where rework is most likely on the first build

These places are written against the documentation and have never been compiled. They all fail
**loudly** (the build aborts), not silently — that is the good news:

| Place | What can happen | What to do then |
|---|---|---|
| `<?ifndef Version?>` and `$(var.Version)` | WiX v4 allows `$(Name)` and `$(var.Name)`; which form the `ifndef` directive applies to is not measured here | Take the other spelling; the error message names the variable |
| `util:CloseApplication` | The attribute set (`TerminateProcess`, `ElevatedCloseMessage`) is written against the v3 documentation | Check the schema; when in doubt drop `TerminateProcess` and leave the quitting to the user — then a root stays standing while the client runs (residual risk 2) |
| `Component/@Condition` on “Environment” together with the `Environment` rows | ICE warnings about components whose key path is a registry value | Read the message, do not suppress it |
| `Launch Condition="VersionNT64"` | The spelling of the `Launch` element in v5 | Bring it into line with the v4 documentation |
| `wix msi transform -t language` | Which validation flags the type sets is taken from the tool, not measured; the transform could refuse to apply | `-Task verify` applies it to a copy and stops right there. `-serr` flags or `-val` set the validation by hand |
| The size of the `.mst` | Both builds pack a cabinet. If the two cabinets differ bit for bit, the difference holds the whole cabinet and the transform gets as big as the MSI | The build reports the number of bytes. Should it be megabytes: `-cc` (cabinet cache) on both `wix build` calls, so that the second build reuses the first cabinet |
| `signtool sign` on an `.mst` | Not measured whether the MSI SIP takes a transform at all | It fails loudly in `-Task build`. Then decide whether the transform goes out unsigned and write it down here |

### The version of WiX is a legal question

The NuGet package `wix` stands **under MS-RL up to 5.0.2** (`requireLicenseAcceptance=false`). From
**6.0.0** it carries `OSMFEULA.txt` with `requireLicenseAcceptance=true` — an *Open Source
Maintenance Fee* for users with at least 10,000 US$ of annual revenue from revenue-generating
activity. For a GmbH that is a paid use: not a technical risk but a legal one, and in a German
company the more expensive mistake. `dotnet tool install --global wix` **without** `--version`
pulls the newest version, that is, today a fee-bearing one.

So the version stands in exactly one place: `WIX_VERSION` in `scripts/windows-package.ps1`, default
`5.0.2`. The `.wxs` itself uses the v4 schema that WiX 4, 5, 6 and 7 have in common — it builds with
any of those versions. The WiX 3.14.1.8722 **preinstalled on `windows-2025` does not compile it**
(there the root element is called `Product`, conditions stand as element text, `FileKey` instead of
`FileRef`); installing v5 is a separate, necessary step.

> **An open point, deliberately not decided from here:** v3 to v5 are out of community support,
> while v6 upwards costs money. Both are true — one version costs money, the other gets no more bug
> fixes. That is a decision for the operator, not for a script. As long as it is open, the default
> here stays at 5.0.2; the workflows can override it over the environment (`WIX_VERSION`), and today
> they do not.

## Distributing

Always **per machine**. In the device context Intune enforces `ALLUSERS=1` anyway; a real per-user
MSI would demand `MSIINSTALLPERUSER=1` and `Scope="perUserOrMachine"`, would then run again at every
sign-in, and would appear in the program list per user.

### By hand or from a script

```powershell
msiexec /i elasticdms-0.1.0.msi /qn ^
  EDMS_API_BASE=https://api.elasticdms.io ^
  EDMS_AUTH_BASE=https://auth.elasticdms.io ^
  EDMS_APP_BASE=https://app.elasticdms.io

msiexec /x {ProductCode} /qn
msiexec /i elasticdms-0.1.0.msi /qn /l*v C:\elasticdms-install.log   # with a log

REM in English — the transform has to lie beside the MSI, otherwise: 1624
msiexec /i elasticdms-0.1.0.msi TRANSFORMS=elasticdms-0.1.0.en-US.mst /qn
```

The ProductCode is read out of the finished MSI without installing it:

```powershell
$wi = New-Object -ComObject WindowsInstaller.Installer
$db = $wi.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$wi,@('elasticdms-0.1.0.msi',0))
$v  = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,
        @("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductCode'"))
$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null)
$s = $v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null)
$s.GetType().InvokeMember('StringData','GetProperty',$null,$s,@(1))
```

The ProductCode is **new with every build**; that is exactly what `MajorUpgrade` demands. Who rolls
it depends on the caller: by hand `wix` does it (`ProductCode="*"`, the default in the `.wxs`), from
the build script one GUID is rolled per run and handed to **every** language, because all languages
of one build are one product. It stays **the same** with the transform applied — that is measured in
`-Task verify`. The `UpgradeCode`, by contrast, is fixed and never changes
(`92B92D26-B56F-4151-95BC-EA80102776C4`, the table at the top of `elasticdms.wxs`).

### Intune

As a **Win32 app**, not as an LOB app: only the Win32 form allows install and uninstall commands of
your own.

```powershell
IntuneWinAppUtil.exe -c target\package -s elasticdms-0.1.0.msi -o target\package\intune
```

| Field | Value |
|---|---|
| Install command | `msiexec /i elasticdms-0.1.0.msi /qn EDMS_API_BASE=… EDMS_AUTH_BASE=… EDMS_APP_BASE=…` |
| Uninstall command | `msiexec /x {ProductCode} /qn` |
| Install behaviour | **Device** (Intune then sets `ALLUSERS=1`) |
| Detection | The MSI ProductCode **or** the file `%ProgramFiles%\elasticdms\elasticdms.exe` with its version |

**The detection rule always runs as SYSTEM**, even for a deployment in the user context. Detection
over `HKCU` or over a path in the user profile therefore fails.

`-c target\package` packs the **whole folder**, so the `.mst` is already inside the `.intunewin`.
English devices get a second app entry that differs in exactly one field:

| Field | Value |
|---|---|
| Install command | `msiexec /i elasticdms-0.1.0.msi TRANSFORMS=elasticdms-0.1.0.en-US.mst /qn EDMS_API_BASE=… EDMS_AUTH_BASE=… EDMS_APP_BASE=…` |

Same content, same uninstall command, **same detection rule** — it is the same product with the
same ProductCode. A device that already has the German one therefore does not reinstall; whoever
wants the other language on an installed machine reinstalls deliberately.

### GPO

*Computer Configuration → Policies → Software Settings → Software installation → New → Package →
Assigned.* The MSI lies on a UNC share (SYSVOL or a file server) that **domain computers** have read
access to — not the users: the installation happens at boot, in the computer context.

**GPO software installation cannot pass MSI properties.** So the three mandatory values do not come
over the command line there. Two ways:

1. *Group Policy Preferences → Computer Configuration → Preferences → Windows Settings →
   Environment*: `EDMS_API_BASE`, `EDMS_AUTH_BASE`, `EDMS_APP_BASE` as **system variables**. That is
   the simple way and the recommended one.
2. A transform (`.mst`) with the three properties, deposited as a “modification” when assigning.
   Needs Orca or a tool for it, and has to be rebuilt whenever a value changes.

**The English language is the same field.** *Advanced → tab Modifications → Add*, and there
`elasticdms-<version>.en-US.mst` from the same share — the transform has to lie beside the MSI and
be readable by **domain computers**, like the MSI itself. The tab takes a list and applies it in
order, so a language transform and a property transform are not an either-or.

### The configuration, and what the MSI explicitly does not bring

Without `EDMS_API_BASE`, `EDMS_AUTH_BASE` and `EDMS_APP_BASE` the client does not start but writes a
sentence to the error output naming the missing variable (README, section Configuration) — on a
managed device nobody would see it. If all three stand on the `msiexec` command line, the MSI
creates them as **system variables** and removes them again on uninstall. If even one is missing,
the component does not arise and the values have to come from elsewhere (GPO preferences, Intune).

System variables reach a process only when it is started after the change; an already running File
Explorer does not see them. After a first installation on a machine with a signed-in user, a sign-out
and sign-in is therefore needed. With a delivery before the first sign-in it is not noticed.

**`EDMS_ENROLLMENT_CODE` does not belong in the MSI and not in a system variable.** It is a one-time
secret out of the console; a system variable is readable by every process of every user. The code is
set at the first setup (a session variable, a script, an MDM script with secret management) and
never needed again afterwards.

## What the installation creates

| What | Where | Does the uninstall remove it? |
|---|---|---|
| `elasticdms.exe` | `%ProgramFiles%\elasticdms\` | yes |
| The autostart | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\elasticdms` | yes |
| The environment marker | `HKLM\SOFTWARE\Lotzer Digital\elasticdms\EnvironmentSet` | yes |
| `EDMS_API_BASE`, `EDMS_AUTH_BASE`, `EDMS_APP_BASE` | System variables | yes, if the MSI set them |
| The entry in the program list | `HKLM\…\Uninstall\{ProductCode}` | yes |

**Autostart over HKLM Run, not over HKCU, not over a scheduled task.** A per-machine package must not
have an HKCU value as a component's key path: at installation time there is only one user, and every
further one would trigger a self-repair at their first sign-in — visible on a terminal server as a
hang. A scheduled task would be more robust against being switched off, would demand an uninstall
action of its own and would feel paternalistic; the Run value appears in Task Manager under
“Startup” and can be switched off by the user. For a **reading** mirror there is nothing to be said
against letting them. The startup folder under `%ProgramData%` would be out anyway: no binding to the
component, and within reach of folder redirection and OneDrive profile backup.

What the **installation does not** do: register the sync root. That only comes into being when the
user signs in, because its identifier contains the account identifier
(`crates/cfapi/src/sync_root.rs`).

## The uninstall — the heart of the matter

A sync root left standing **jams every later installation**: the platform remembers all roots per
volume permanently and refuses overlapping ones, and `edms_cfapi::Mirror` deliberately aborts in
front of a foreign root it finds. The user would get a message from which nobody deduces that there
is a corpse in the folder.

The sequence in `elasticdms.wxs`:

1. `util:CloseApplication` quits a running `elasticdms.exe`. It has to:
   `CfUnregisterSyncRoot` fails with `ERROR_CLOUD_FILE_INVALID_REQUEST` as long as a provider is
   **connected** to the root.
2. The deferred action `UnregisterSyncRoots` calls `elasticdms.exe --uninstall`,
   **`Before="RemoveFiles"`** — after that the `.exe` no longer exists — and only on a real uninstall
   (`REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`). Under `msiexec /x … /l*v` the log names it by
   exactly that name.
3. Only after that does the installer remove files, registry values and environment variables.

**The context is SYSTEM in session 0** (`Execute="deferred"`, `Impersonate="no"`): no user profile,
no user `HKCU`, no credential store, no desktop. `Impersonate="yes"` would not help — it imitates
whoever started `msiexec`, and under Intune, SCCM and GPO that is SYSTEM as well. **There is no MSI
mechanism that runs in the context of the signed-in user out of a per-machine uninstall.**

Nextcloud does not solve that, it sidesteps it: an immediate action fetches the SID of the *current*
user and deletes only their keys; its own comment says “only effective for the current user (home
users)”, and its MSI does not call `CfUnregisterSyncRoot` at all. Under Intune the SID lookup returns
nothing useful.

Here it can be done better, and for a documented reason: **`CfUnregisterSyncRoot` is path-based and
requires only `WRITE_DATA` or `WRITE_DAC` on the root folder — no user identity, no elevation.**
SYSTEM has both in every profile. That is why the one action clears **all** profiles.

### What `--uninstall` does

`crates/app/src/uninstall.rs`, a pure command-line mode: no window, no credential store, no
single-instance lock, no mandatory `EDMS_` variable.

1. Determine the profile directory — from `%PUBLIC%` (its parent directory), failing that
   `%SystemDrive%\Users`. **Not** from `%USERPROFILE%`: as SYSTEM that points at
   `C:\Windows\system32\config\systemprofile`.
2. In every profile:
   * `…\elasticdms` — if the folder is empty or contains at least one entry only elasticdms
     creates (`Briefkörbe` / `Mailbaskets`, `Archive` / `Archives`, `Gespeicherte Suchen` /
     `Saved searches`, `LIESMICH.txt` / `README.txt` — the names depend on the language the mirror
     was built in, ADR-D10): disconnect, delete the tree, `CfUnregisterSyncRoot`, remove the empty
     folder. Otherwise **leave it untouched** and report it (see residual risk 5).
   * `…\AppData\Local\elasticdms\folderclient` — the local state (SQLite, the staging area), always.
3. If `EDMS_MIRROR_PATH` is set as a **system** variable, that path is handled in addition.

Exit code 0 when nothing stayed behind, otherwise 1. The MSI does **not** evaluate it
(`Return="ignore"`) — a failed cleanup must not make the product unremovable. It becomes visible in
the log: `msiexec /x {ProductCode} /qn /l*v C:\uninstall.log`.

By hand, for troubleshooting (changes the system):

```powershell
& "$env:ProgramFiles\elasticdms\elasticdms.exe" --uninstall
```

### What the uninstall does not clear away

| What stays | Why | How to get rid of it anyway |
|---|---|---|
| **The device key and the session in the credential store** | It hangs on the user profile; SYSTEM in session 0 does not reach it | “Sign out” in the program before the uninstall; or per user `cmdkey /list` and delete the entry |
| **An inbox folder with files in it** | Those are files of the user, not of the program | By hand, after checking what is in it |
| **A folder `elasticdms` holding nothing of elasticdms** | A brake against data loss: `C:\Users\…\elasticdms` could also be somebody's project folder | By hand |
| **Keys under `SyncRootManager` for the navigation pane** | The client writes them at sign-in and removes them again at sign-out — but the key name carries the SID of the process that removes them, and `--uninstall` runs as SYSTEM: it then names `…!S-1-5-18!…`, and the keys of the profiles it walks through stay behind (NAMED GAP in `crates/cfapi/src/platform/registry.rs`; closing it means `RegEnumKeyExW` and a Windows machine to measure on) | “Sign out” in the program before the uninstall; otherwise see “Clearing up by hand” — the wildcard `elasticdms!*` catches every SID |
| **The device's approval on the server** | A client cannot withdraw its own approval | Revoke it in the elasticdms console |
| **Everything, during an update** | `NOT UPGRADINGPRODUCTCODE`: the root and the mirror are meant to survive the new version | — |

### Residual risk, named

1. **A machine that was switched off during the uninstall keeps its root.** Intune removes the
   product later, or never. The countermeasure cannot lie in the installer: **the client has to be
   allowed to adopt an orphaned root *of its own* at start-up and abort only for a *foreign*
   provider.** Today it aborts in both cases (`check_foreign_root` in
   `crates/cfapi/src/platform/mod.rs`). **Is that built? No.** It is the most important open point
   of this directory, and it lies in `crates/cfapi`.
2. **Whether `util:CloseApplication` reaches processes in other sessions is not measured.** If it
   does not, `CfUnregisterSyncRoot` fails on the existing connection and the root stays standing —
   and with `Return="ignore"` the uninstall still counts as successful.
3. **Deriving the profile directory from `%PUBLIC%` is not measured on Windows.** If both variables
   are missing, `--uninstall` clears nothing and reports that with exit code 1.
4. **A deviating mirror path is only found when `EDMS_MIRROR_PATH` is a system variable.** As a user
   variable it is invisible to SYSTEM; the mirror would stay standing together with its root.
5. **A real mirror holding nothing but foreign files stays standing.** The brake from point 2 of the
   list above then bites. The price is chosen deliberately: a root left standing is annoying, a
   deleted foreign folder is data loss.

## Signing is optional

**The whole delivery path works without any certificate.** An MSI needs no signature to be built,
checked, distributed or installed: `wix build` produces it without secrets, `msiexec /i … /qn`
installs it, Intune distributes it, GPO assigns it. That is the decisive difference to MSIX, which
cannot be installed at all without a certificate the device trusts.

**The transforms go the same way.** `-Task build` signs in one loop over everything the packing
produced, and `-Task verify` checks the signature over the same list, so a language added later
cannot be forgotten by one of the two. **Not proven:** whether `signtool` takes an `.mst` at all —
nothing on a Mac can try it. If it refuses, it refuses in the build (see
[Where rework is most likely](#where-rework-is-most-likely-on-the-first-build)).

What is different when unsigned:

1. The **UAC consent prompt in an interactive installation** shows “Unknown publisher” with a yellow
   shield instead of the company name with a blue one. Under Intune and GPO the installation runs as
   SYSTEM without any UAC prompt — there the difference is nil.
2. If the MSI is **downloaded** from the internet, it carries a mark of the web, and **SmartScreen**
   shows “Windows protected your PC” with “Run anyway”. If it is delivered from Intune, SCCM, from
   SYSVOL or from an intranet share, it gets **no** mark of the web, and SmartScreen does not come
   into play. Microsoft's own table puts “no signature” and “a self-signed certificate” on the same
   level — so a self-made certificate brings nothing here, while demanding that every target device
   get it under “Trusted Publishers”. **Not recommended.**
3. **Smart App Control** (Windows 11, on by default only on freshly set-up devices) blocks unsigned
   executables without reputation, regardless of where they come from. On managed company devices it
   is usually off — that is to be checked, not assumed.
4. **WDAC and AppLocker rules by publisher** cannot be written for an unsigned package; what would
   remain is a rule by hash or path, to be brought into line with every version.

**EV is not needed.** Microsoft writes it themselves: *“EV certificates no longer bypass SmartScreen
… Paying a premium for EV solely to avoid SmartScreen warnings is no longer justified.”* OV and EV
build reputation the same way, and an internal company package never reaches the necessary download
numbers anyway. The use of a signature lies in the clean publisher name in the UAC prompt, in the
program list and in AppLocker/WDAC.

If signing does come later: the cheapest way without a hardware token is **Azure Artifact Signing**
(formerly Trusted Signing), from 9.99 US$/month, with identity verification and a connection to
GitHub Actions — that gets around the requirement in force since 2023 to keep OV keys on an HSM,
which rules out a PFX secret in CI secrets for publicly trusted certificates anyway. The PFX path
that `scripts/windows-package.ps1` supports stays right for an **internal** certificate from our own
PKI: the publisher name is correct, the managed devices already trust our own CA, and it costs
nothing.

```powershell
$env:PFX_PATH     = 'C:\path\elasticdms.pfx'
$env:PFX_PASSWORD = '…'
.\scripts\windows-package.ps1           # signs the EXE BEFORE and the MSI AFTER packing
```

The order is no matter of taste: what lies in the embedded cabinet file is out of reach of any
`signtool`. `/tr` and `/td` (the timestamp) are mandatory, otherwise the signature expires with the
certificate.

## What the client does at setup

`edms_cfapi::Mirror` (ADR-D06):

1. Create `%USERPROFILE%\elasticdms` if the folder does not exist.
2. Check that it lies on **NTFS** (`GetVolumeInformationW`). On exFAT or FAT32 `cldflt` does not
   work, and without this check only the registration fails — with an HRESULT from which nobody
   reads that the folder lies on a USB stick.
3. Check whether a root of another provider or another account already hangs there
   (`CfGetSyncRootInfoByPath`). If so: abort. `CF_REGISTER_FLAG_UPDATE` would otherwise overwrite a
   foreign root without complaint. **See residual risk 1: an orphaned root of our own does not belong
   in that abort.**
4. `CfRegisterSyncRoot` with `ProviderName` “elasticdms”, the provider version, the fixed provider
   GUID and the account identifier as `SyncRootIdentity`; flags
   `CF_REGISTER_FLAG_UPDATE | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT`.
5. `CfConnectSyncRoot` with `REQUIRE_PROCESS_INFO | REQUIRE_FULL_FILE_PATH |
   BLOCK_SELF_IMPLICIT_HYDRATION`.

Signing out in the menu runs it backwards: disconnect, delete the tree, `CfUnregisterSyncRoot`. In
that order — whoever deregisters first leaves placeholders standing that nobody can hydrate any
more. `--uninstall` uses the same order.

**A single instance.** A root has exactly one connection. The second `CfConnectSyncRoot` gets
`ERROR_CLOUD_FILE_ALREADY_CONNECTED` (0x8007017A), not `E_ACCESSDENIED`; the client reports that as
“elasticdms is already running”.

## Open: the entry in File Explorer's navigation pane

**The folder is fully usable without this step** — it simply does not appear in File Explorer's
sidebar next to OneDrive but is opened over its path.

The entry consists of **two halves**, and only one of them lies in HKLM:

* **HKLM**, under
  `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\<provider>!<SID>!<account>`:
  `DisplayNameResource` (`REG_EXPAND_SZ`), `IconResource` (`REG_EXPAND_SZ`, e.g.
  `%ProgramFiles%\elasticdms\elasticdms.exe,0`), `NamespaceCLSID` (`REG_SZ`), `Flags` (`REG_DWORD`,
  **undocumented** — copy it from Nextcloud, do not guess) and `UserSyncRoots\<SID>` (`REG_SZ`, the
  full path of the root).
* **HKCU**, roughly a dozen values: `Software\Classes\CLSID\<GUID>` with its subkeys,
  `…\Explorer\Desktop\NameSpace\<GUID>`, `HideDesktopIcons`. Without this half **no** entry appears
  in the sidebar.

Three things follow from that, to be settled before building:

1. **The MSI cannot write these keys.** The key name is `provider!SID!account`, and neither the SID
   nor the account identifier is known before somebody has signed in. They have to come into being at
   runtime, in the client, at the first sign-in.
2. **Whether a non-elevated process may create subkeys under `SyncRootManager` is open.** Nextcloud
   does it at runtime and treats a failure as non-fatal; secondary sources report registry errors
   with restricted accounts. There is no primary source on this key's ACL. If the measurement comes
   out negative, the way out would be for the MSI to loosen the parent key's ACL for
   `BUILTIN\Users` — a security-relevant change to the system that belongs named and not done in
   passing.
3. **Whoever sets the HKCU half also has to remove it again.** Otherwise a dead sidebar entry
   pointing at a folder that no longer exists stays behind per user — and `--uninstall` as SYSTEM
   reaches no foreign `HKCU`. The cleanup then belongs in the client (on signing out) **and** in a
   way that works without the client.

The identifier itself is already computed by `edms_cfapi::sync_root::SyncRootIdentifier`, which also
checks its limits (at most 255 characters, no `!` in any of the three parts, an SID of the shape
`S-1-5-21-…`). **A side finding, deliberately left as it is:** Nextcloud's root identifier has *four*
parts (`provider!SID!account!foldernumber`), the Microsoft documentation names three.
`sync_root.rs` forbids `!` in the parts and thereby settles on three. Today that is no fault (one
root per user), but a second mirror per user would not be registrable without changing the
identifier.

## What to measure first on a Windows VM

In this order, because every point presupposes the next. **Snapshot the VM before the first
registration attempt** — a snapshot beforehand saves half the troubleshooting afterwards.

1. **Build and run Microsoft's CloudMirror sample.** The touchstone for the environment: if that does
   not run, it is not this code's fault.
2. May a **non-elevated** process write under `SyncRootManager`?
   ```powershell
   (Get-Acl 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager').Access |
     Format-Table IdentityReference, RegistryRights, AccessControlType
   ```
3. Register, connect, open a folder in File Explorer: does `FETCH_PLACEHOLDERS` arrive?
4. Open a document: does `FETCH_DATA` arrive, and do the 4 KB pieces come through?
5. Try to delete and rename: does the veto bite, and does it let **our own** deletion through?
6. Write into a hydrated file after removing the read-only attribute: is the change noticed on close
   and discarded?
7. A large file over a throttled line (1 MB/s, 200 MB): does the progress report keep the 60-second
   deadline open?
8. **The whole uninstall path under SYSTEM, the way Intune drives it** — do not test interactively,
   otherwise you measure the wrong context:
   ```powershell
   psexec -s -i 0 msiexec /x {ProductCode} /qn /l*v C:\uninstall.log
   ```
   Then check: is `SyncRootManager` empty? Is the folder gone? Does `CfGetSyncRootInfoByPath` on the
   path return nothing? Can it then be installed and signed into again?
9. **Reproduce the jamming case** — it is the real danger: install, sign in, switch the machine off,
   uninstall the MSI as SYSTEM, install again, sign in again. The expectation **without** the
   countermeasure: step 3 of the setup finds an old root and aborts. That is exactly why residual
   risk 1 exists.
10. **The English language**, once, because nothing on a Mac can measure it: install with
    `TRANSFORMS=…en-US.mst`, then look into *Programs and Features* — the comment has to be the
    English sentence and the ProductCode has to be the same as without the transform. Then a
    downgrade attempt (install an older version over it) for the one message that a user really
    gets to see. `-Task verify` already does the first half on the build machine; this is the half
    that only an installed product shows.

## Clearing up by hand

A half-set-up root makes the folder unusable, and File Explorer remembers a lot.

```powershell
# 1. Quit the client.
Stop-Process -Name elasticdms -ErrorAction SilentlyContinue

# 2. Deregister the root and remove the mirror — in ALL profiles (as administrator/SYSTEM).
& "$env:ProgramFiles\elasticdms\elasticdms.exe" --uninstall

# 3. The registry keys of the navigation pane, for every profile (the wildcard catches every SID):
Remove-Item -Recurse `
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\elasticdms!*'

# 4. Restart File Explorer so that the sidebar forgets the entry.
Stop-Process -Name explorer
```

## The development path with a sparse package (an alternative, not the delivery path)

Only needed if it turns out on the VM that the navigation pane cannot be had without a package
identity. The manifest lies next door: [`AppxManifest.xml`](AppxManifest.xml), with instructions in
its header (developer mode, a self-signed certificate, `MakeAppx pack`,
`Add-AppxPackage -ExternalLocation`). It is explicitly **not part of the product**.

**If the sparse package comes, one registration path has to go** — not both. Either WinRT `Register`
(then with a package) or `CfRegisterSyncRoot` (then without). The code knows only the second way
today; a switch is a change in `crates/cfapi/src/platform/registration.rs` and nowhere else. And:
the automatic root cleanup on package uninstall applies only to roots from
`StorageProviderSyncRootManager.Register`, and even there it is reported as faulty (keys left behind
under HKLM `SyncRootManager`, HKCU `NameSpace`, HKCR `CLSID`). So the sparse package does **not**
spare us the cleanup action.

## References

* [`elasticdms.wxs`](elasticdms.wxs) — the package, with the GUID table at the top.
* [`de-DE.wxl`](de-DE.wxl), [`en-US.wxl`](en-US.wxl) — every sentence the package shows, per
  language, plus its LCID.
* [`../../scripts/windows-package.ps1`](../../scripts/windows-package.ps1) — the build, and at
  `$Cultures` the decision one MSI + transform against one MSI per language.
* `crates/app/src/uninstall.rs` — what `--uninstall` does and what it does not touch.
* `docs/adr/ADR-D06-windows-cloud-filter.md` — the decision including the correction to §7.
* `crates/cfapi/src/platform/registration.rs` — the registration, with the table of the policies and
  their reasons.
* `crates/cfapi/src/sync_root.rs` — the provider GUID, the provider version, the root identity, the
  root identifier.
