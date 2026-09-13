<#
  windows-package.ps1 — builds an installation package target\package\elasticdms-<version>.msi
  out of the compiled client.

  THE REASON this script exists, and why it builds an MSI and not an Inno Setup .exe: the operator
  rolls out to managed devices, over Intune AND over GPO. GPO software installation accepts .msi
  and nothing else; an .exe could only be delivered there over logon scripts, without assignment,
  without uninstallation, without inventory. Intune accepts both, but for an MSI it runs the
  uninstall itself as `msiexec /x {ProductCode}` and reads ProductCode and version for detection.
  But something else is decisive: the uninstall MUST deregister the sync root, otherwise it jams
  every later installation (Windows remembers roots per volume). That is exactly what
  packaging\windows\elasticdms.wxs calls a deferred action for, and exactly why the packing belongs
  in a script and not in a hand movement.

  WHAT IT PRODUCES: one MSI and, beside it, one language transform (.mst) per further language.
  Which languages, and why one MSI plus a transform rather than one MSI per language, stands at
  $Cultures below — with the price of each shape for an administrator, because that is the only
  measure that decides it.

  Calls:
    scripts\windows-package.ps1                 # the same as -Task build
    scripts\windows-package.ps1 -Task build     # compile, sign, pack, sign, check
    scripts\windows-package.ps1 -Task tool      # fetch WiX as a dotnet tool (CHANGES THE MACHINE)
    scripts\windows-package.ps1 -Task msi       # only `wix build` on an already built .exe
    scripts\windows-package.ps1 -Task verify    # measure MSI and transforms again
    scripts\windows-package.ps1 -Task clean     # empty target\package
    scripts\windows-package.ps1 -Task help

  Environment variables:
    VERSION=…            The expected version. If it is set and differs from
                         [workspace.package] version, the script aborts — two versions are never
                         both right. Not set: Cargo.toml decides.
    WIX_VERSION=…        Version of the dotnet tool `wix` (default 5.0.2). See below.
    SIGNING_ENDPOINT=…   Azure Artifact Signing. All three together switch signing to the
    SIGNING_ACCOUNT=…    service: no certificate file, no password, the private key never leaves
    SIGNING_PROFILE=…    Azure. The workflow logs in over OIDC beforehand (azure/login), the
                         client below reads that login out of the environment.
    PFX_PATH=…           PKCS#12 file — the other way, for a certificate one holds oneself.
    PFX_PASSWORD=…
    SIGNTOOL=…           Full path to signtool.exe. Not set: search the Windows SDK.
    TIMESTAMP_URL=…      Default http://timestamp.acs.microsoft.com with Artifact Signing,
                         otherwise http://timestamp.digicert.com. See `timestamp_url`, there
                         stands why the timestamp is not optional with Artifact Signing.
    SIGNING_CLIENT_VERSION=…  Version of the NuGet package Microsoft.ArtifactSigning.Client
                         (default 1.0.128).

  NOTHING OF THIS SET MEANS UNSIGNED, and that is the normal case in this repository: an MSI needs
  no signature to be built, distributed and installed.

  THE VERSION OF WiX IS A LEGAL QUESTION, NOT A TECHNICAL ONE. The NuGet package `wix` stands
  under MS-RL up to 5.0.2. From 6.0.0 it carries OSMFEULA.txt with requireLicenseAcceptance=true —
  an "Open Source Maintenance Fee" for users with 10,000 US$ of annual revenue from
  revenue-generating activity. For a German GmbH that is a paid use. Hence the default 5.0.2;
  whoever sets 6 or 7 decides that deliberately. The .wxs itself builds with 4, 5, 6 and 7 — it
  uses the shared v4 schema. The WiX 3.14 preinstalled on windows-2025 does NOT compile it
  (different syntax).

  WITHOUT ANY CERTIFICATE this script runs all the way through and delivers an unsigned MSI. That
  is no makeshift: `msiexec /i … /qn` installs it, Intune distributes it, GPO assigns it. Under
  Intune and GPO the installation runs as SYSTEM without any UAC prompt; there the difference to a
  signed MSI is nil. It shows only on a double click on a file DOWNLOADED from the internet
  (SmartScreen, "Unknown publisher") — and a self-made certificate changes nothing about that:
  Microsoft's own table puts "no signature" and "self-signed" on the same level.

  NOT RUN ON WINDOWS. This script is written on a Mac. No `wix build`, no `signtool`, no `msiexec`
  has run; on a Mac there is no Windows Installer and hence no ICE check either. On the first run
  on Windows, rework is to be expected.

  What this script explicitly does NOT do: install. `build` writes only into target\ — with one
  named exception: it registers the WiX extension `WixToolset.Util.wixext` in the tool store if it
  is missing, because `wix build` would otherwise not even begin.

  WHY THE MESSAGES USE »…« AND NOT TYPOGRAPHIC DOUBLE QUOTES: the PowerShell parser reads U+201E
  and U+201C as quotation marks and cuts a string off there — measured on this machine with
  [System.Management.Automation.Language.Parser]::ParseFile, six syntax errors. Comments (like this
  one) are not affected and keep the house style.

  The same parser, the same measurement, a second trap: a colon straight after a variable name in a
  string is a SCOPE QUALIFIER to it, so "Transform $culture: …" no longer parses. Braces around the
  name are not decoration there.
#>

[CmdletBinding()]
param(
    [ValidateSet('build', 'tool', 'msi', 'verify', 'clean', 'help')]
    [string]$Task = 'build'
)

# The PowerShell counterpart to `set -euo pipefail`: StrictMode catches mistyped variable names,
# ErrorActionPreference aborts on cmdlet errors. Neither holds for NATIVE programs — `run_tool`
# checks their exit code by hand, otherwise the script would run past a failed `cargo build` and
# pack an old .exe.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$WxsFile = Join-Path $Root 'packaging\windows\elasticdms.wxs'

# THE LANGUAGES OF THE PACKAGE. One row, and the first row is the package itself.
#
# `wix build` runs once per culture over packaging\windows\elasticdms.wxs with the catalogue
# packaging\windows\<culture>.wxl beside it. The FIRST culture becomes the MSI; every further one
# becomes a language transform (.mst) next to it, cut with `wix msi transform -t language`. A third
# language is this one row longer and a .wxl of its own — there is no second code path for it, and
# `package_artefacts` below hands everything that arises to the signing and to the check.
#
# WHY ONE MSI AND A TRANSFORM, AND NOT ONE MSI PER LANGUAGE. This product goes out over Intune AND
# over GPO (see the head of this file). The two shapes cost the administrator differently:
#
#   Two MSIs are two products. Each build rolls its own ProductCode, and the ProductCode is what
#   Intune detects by and uninstalls by. So: two apps, two uploads, two detection rules, two
#   assignments, and two packages under GPO Software installation, each with its own security
#   filtering. Who gets which has to be decided per device by somebody, and a device that moves
#   from one side to the other gets a major upgrade — a full uninstall and reinstall for a changed
#   sentence in Programs and Features. Two files also means two things to sign, two hashes in the
#   release, and two answers to "which one is on this machine". Measurable here and now: both
#   workflows in .github\workflows look for exactly ONE elasticdms-<version>*.msi under target\ and
#   stop when they find two — with two MSIs that check fails on the first run, and .github is not
#   this script's to change.
#
#   One MSI and a transform is one product. One file, one ProductCode, one detection rule, one
#   assignment. The administrator who does nothing gets a working installation in the package's own
#   language; the second language costs one addition in a dialog they are in anyway. GPO has a
#   field made for exactly this: Software installation, Advanced, tab Modifications — the same list
#   that packaging\windows\README.md already names for a property transform, so the two stack.
#   msiexec takes it as TRANSFORMS=<name>.mst, which is where it goes under Intune, in a second app
#   entry that shares content and ProductCode with the first, so no machine reinstalls for it.
#
# The second one is cheaper for the administrator in every one of those places, so that is what is
# built here. Its price, named: the language is chosen at installation time, and changing it
# afterwards is a reinstallation — but so it would be with two MSIs. And the .mst has to travel
# with the .msi; a transform that is not beside the package is a failed installation, not a package
# in the wrong language (TRANSFORMS names a file that has to be there).
#
# WHY de-DE IS FIRST: the operator is a German company (Manufacturer in elasticdms.wxs), the German
# catalogue is the grown one (crates\i18n\catalog\de.toml says so in its first lines), and the base
# language is the one that needs no transform anywhere. Turning it round is reordering this row —
# and then every German machine needs the transform instead.
$Cultures = @('de-DE', 'en-US')
$Target = 'x86_64-pc-windows-msvc'
$BinDirectory = Join-Path $Root "target\$Target\release"
$ExeFile = Join-Path $BinDirectory 'elasticdms.exe'
$PackageDir = Join-Path $Root 'target\package'
$WixVersion = if ($env:WIX_VERSION) { $env:WIX_VERSION } else { '5.0.2' }
# The timestamp URL depends on how we sign, and that is decided by `signing_mode` further down —
# a function may only be called after it is defined, hence `timestamp_url` and not a variable here.
$SigningClientVersion =
    if ($env:SIGNING_CLIENT_VERSION) { $env:SIGNING_CLIENT_VERSION } else { '1.0.128' }

# ── Helpers ─────────────────────────────────────────────────────────────────────────────────

function report([string]$text) {
    Write-Host "==> $text"
}

function hint([string]$text) {
    Write-Host "    $text"
}

# Runs a native program and aborts with a whole sentence when it reports an error. `$display` is
# there so that a password does not end up in the log.
# NEVER `start` as a function name: on Windows `start` is an alias for Start-Process, and aliases
# take precedence over functions in PowerShell. The call would then start cargo asynchronously
# without -Wait, report success immediately, and the script would look for the .exe that did not
# exist yet. On macOS it is not noticed: the alias does not exist there. Found in CI, not here.
function run_tool([string]$command, [string[]]$arguments, [string]$display = $null) {
    if (-not $display) { $display = "$command $($arguments -join ' ')" }
    hint $display
    & $command @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "»${command}« ended with exit code $LASTEXITCODE. The call was: $display"
    }
}

# The free space before and after the build. A release build of this workspace is large, and a
# build aborted because the disk is full looks like a fault in the package.
function report_space([string]$when) {
    try {
        $name = (Split-Path -Qualifier $Root).TrimEnd(':')
        $drive = Get-PSDrive -Name $name -ErrorAction SilentlyContinue
        if ($drive) {
            hint "Free space ($when): $([math]::Round($drive.Free / 1GB, 1)) GB"
        }
    }
    catch {
        # A space report must never bring a build down (network path, unusual drive).
        hint "Free space ($when): cannot be determined."
    }
}

# The version has its only truth in Cargo.toml, section [workspace.package].
#
# It is read by hand instead of with `cargo metadata`: the version should be available even when no
# toolchain is in place — and a `version = "…"` from some other section would be a wrong answer
# nobody would notice.
function version_from_cargo {
    $path = Join-Path $Root 'Cargo.toml'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Cargo.toml does not lie in $Root; this script belongs in scripts\ of the workspace."
    }
    $inside = $false
    foreach ($row in Get-Content -LiteralPath $path -Encoding utf8) {
        if ($row -match '^\[workspace\.package\]') { $inside = $true; continue }
        if ($row -match '^\[') { $inside = $false; continue }
        if ($inside -and $row -match '^\s*version\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    throw 'Cargo.toml has no line of the form version = "..." under [workspace.package].'
}

# The version for the package, held against VERSION from the environment.
function version {
    $fromCargo = version_from_cargo
    if ($env:VERSION -and $env:VERSION -ne $fromCargo) {
        throw "The environment demands version $env:VERSION, Cargo.toml names $fromCargo. Both at once is never right: either set the tag anew or raise [workspace.package] version."
    }
    return $fromCargo
}

# The version as MSI understands it: three fields, at most 255.255.65535, no suffix.
#
# MSI evaluates only three version fields and ignores a fourth; a prerelease part such as
# »0.2.0-rc.1« is no valid value at all. The cut is therefore made here, visibly — the file name
# carries the full version onwards, so that nothing gets mixed up in the folder at the customer.
function msi_version([string]$full) {
    $core = ($full -split '[-+]')[0]
    $field = $core -split '\.'
    if ($field.Count -lt 3) {
        throw "The version »$full« has fewer than three fields; MSI demands major.minor.build."
    }
    $limit = @(255, 255, 65535)
    for ($i = 0; $i -lt 3; $i++) {
        if ($field[$i] -notmatch '^\d+$' -or [int]$field[$i] -gt $limit[$i]) {
            throw "The version »$full« does not fit into an MSI version: field $($i + 1) is »$($field[$i])«, allowed is 0 to $($limit[$i])."
        }
    }
    $three = ($field[0..2] -join '.')
    if ($three -ne $full) {
        hint "MSI version $three (from the version $full; MSI knows only three fields)."
    }
    return $three
}

function wix_present {
    return [bool](Get-Command wix -ErrorAction SilentlyContinue)
}

# The version of the installed tool, e.g. »5.0.2« out of »5.0.2+aa65968c«.
function wix_version_installed {
    $raw = "$(& wix --version 2>&1)"
    if ($LASTEXITCODE -ne 0) {
        throw 'The call »wix --version« failed; the tool is there but does not answer.'
    }
    if ($raw -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    throw "No version can be read out of the answer of »wix --version« ($raw)."
}

# `wix build` aborts without the extension, and the workflows in .github/workflows fetch only `wix`
# itself. So the build does it: idempotent, and it says so.
function ensure_extension {
    $name = 'WixToolset.Util.wixext'
    $list = (& wix extension list -g) 2>&1
    if ($LASTEXITCODE -eq 0 -and ("$list" -match [regex]::Escape($name))) {
        hint "The extension $name is registered."
        return
    }
    $version = wix_version_installed
    report "Registering the extension $name/$version (the version has to match wix $version)"
    run_tool 'wix' @('extension', 'add', '-g', "$name/$version")
}

# How is signed — decided by what stands in the environment, never by a switch.
#
# `azure` is Azure Artifact Signing (formerly Trusted Signing): the key stays in Azure, the runner
# logs in over OIDC and holds nothing that could be stolen. `pfx` is a certificate file one holds
# oneself. `none` is the normal case here and stays green.
#
# All three Azure values or none: a half configuration counts as `none`, otherwise the script
# would enter azure mode and die in the middle of the build instead of quietly building unsigned.
function signing_mode {
    if ($env:SIGNING_ENDPOINT -and $env:SIGNING_ACCOUNT -and $env:SIGNING_PROFILE) { return 'azure' }
    if ($env:PFX_PATH) { return 'pfx' }
    return 'none'
}

# WHY THE TIMESTAMP IS NOT OPTIONAL WITH ARTIFACT SIGNING: the service issues a fresh certificate
# per signature and it is valid for 72 hours. Without an RFC 3161 countersignature the signature
# would therefore be dead after three days — with a PFX one would merely lose it at the end of the
# certificate's life. Microsoft's own TSA is the one that fits the chain.
function timestamp_url {
    if ($env:TIMESTAMP_URL) { return $env:TIMESTAMP_URL }
    if ((signing_mode) -eq 'azure') { return 'http://timestamp.acs.microsoft.com' }
    return 'http://timestamp.digicert.com'
}

# The signing client of the service: a NuGet package holding the dlib that signtool loads. It is
# fetched into target\ like everything else this script produces — nothing outside is touched.
function ensure_signing_client {
    $directory = Join-Path $PackageDir "artifact-signing-$SigningClientVersion"
    $dlib = Join-Path $directory 'bin\x64\Azure.CodeSigning.Dlib.dll'
    if (-not (Test-Path -LiteralPath $dlib)) {
        report "Fetching the Artifact Signing client $SigningClientVersion"
        New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null
        $archive = Join-Path $PackageDir "artifact-signing-$SigningClientVersion.zip"
        $source = "https://www.nuget.org/api/v2/package/Microsoft.ArtifactSigning.Client/$SigningClientVersion"
        Invoke-WebRequest -Uri $source -OutFile $archive -UseBasicParsing
        Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
        Remove-Item -LiteralPath $archive -Force
    }
    if (-not (Test-Path -LiteralPath $dlib)) {
        throw "The package Microsoft.ArtifactSigning.Client/$SigningClientVersion holds no bin\x64\Azure.CodeSigning.Dlib.dll. The DLL kept its old name after the service was renamed; if that has changed, it has to be changed here too."
    }
    # What signtool is to sign with. CorrelationId is only there so that a support case can be
    # found again on the Azure side; it costs nothing and is missing when nobody asks.
    $metadata = Join-Path $directory 'metadata.json'
    $description = [ordered]@{
        Endpoint               = $env:SIGNING_ENDPOINT
        CodeSigningAccountName = $env:SIGNING_ACCOUNT
        CertificateProfileName = $env:SIGNING_PROFILE
    }
    if ($env:GITHUB_RUN_ID) { $description['CorrelationId'] = "github-$env:GITHUB_RUN_ID" }
    $description | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding utf8
    return @($dlib, $metadata)
}

function find_signtool {
    if ($env:SIGNTOOL) {
        if (-not (Test-Path -LiteralPath $env:SIGNTOOL)) {
            throw "SIGNTOOL points at $env:SIGNTOOL; nothing lies there."
        }
        return $env:SIGNTOOL
    }
    # Never hard-code the path: the SDK version changes with the machine and with the runner image.
    # The newest one found wins.
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe"
    $found = Get-ChildItem -Path $kits -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $found) {
        throw 'No signtool.exe is to be found on this machine (Windows SDK). Without it nothing can be signed; without SIGNING_ACCOUNT or PFX_PATH nothing is signed anyway.'
    }
    return $found.FullName
}

# Signs a file — or says that nothing is being signed, and goes on.
#
# /tr and /td are mandatory in both modes: without a timestamp the signature holds only as long as
# the certificate does, and with Artifact Signing that is 72 hours (see `timestamp_url`).
function sign([string]$path, [string]$what) {
    $mode = signing_mode
    $stamp = timestamp_url
    if ($mode -eq 'none') {
        hint "$what stays unsigned (neither SIGNING_ACCOUNT nor PFX_PATH is set)."
        return
    }
    $signtool = find_signtool
    report "Signing $what ($mode)"
    if ($mode -eq 'azure') {
        # /dlib says WITH WHAT is signed, /dmdf WHICH profile. `/f` and `/dlib` exclude each
        # other. The login comes from azure/login in the workflow; the dlib reads it out of the
        # environment, no secret passes through this script.
        $client = ensure_signing_client
        $arguments = @(
            'sign', '/v', '/fd', 'SHA256', '/tr', $stamp, '/td', 'SHA256',
            '/dlib', $client[0], '/dmdf', $client[1], $path
        )
        run_tool $signtool $arguments
        return
    }
    if (-not (Test-Path -LiteralPath $env:PFX_PATH)) {
        throw "PFX_PATH points at $env:PFX_PATH; no certificate file lies there."
    }
    # `/p` stands there even when the password is empty: without the switch signtool asks for one
    # on a password-protected file — in a workflow the run then hangs instead of failing with a
    # sentence. The password stands briefly in the process list; that is the price of this path,
    # and the reason the Azure one exists.
    $arguments = @(
        'sign', '/fd', 'sha256', '/tr', $stamp, '/td', 'sha256',
        '/f', $env:PFX_PATH, '/p', [string]$env:PFX_PASSWORD, $path
    )
    run_tool $signtool $arguments "$signtool sign /fd sha256 /tr $stamp /td sha256 /f *** /p *** $path"
}

# The MSI file table — the only reliable list of what gets installed. A text search in the raw
# image would not find the names inside the embedded cabinet file.
function files_in_msi([string]$msi) {
    $wi = $null
    $db = $null
    $view = $null
    $names = @()
    try {
        $wi = New-Object -ComObject WindowsInstaller.Installer
        # Inline, not through a helper: a COM object handed to a typed parameter is no longer the
        # same call, and a helper that looked harmless emptied this very table (measured — the file
        # table went from two entries to none). The null checks say which call failed instead.
        $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($msi, 0))
        if ($null -eq $db) { throw "Opening $msi for reading handed back nothing." }
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `FileName` FROM `File`'))
        if ($null -eq $view) { throw "The file table of $msi could not be opened for reading." }
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        while ($true) {
            $set = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($null -eq $set) { break }
            $names += $set.GetType().InvokeMember('StringData', 'GetProperty', $null, $set, @(1))
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($set)
        }
    }
    finally {
        # An open MSI database holds a handle on the file, and PowerShell frees a COM object only
        # when the garbage collector gets round to it. Whoever renames, signs or deletes the MSI
        # afterwards in the same process runs into "used by another process" — against a handle of
        # their own. This is why the release happens here and not at the end of the script.
        foreach ($com in @($view, $db, $wi)) {
            if ($null -ne $com) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($com) }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
    return $names
}

# The Property table of an MSI — optionally with a transform applied to it first. That second case
# is the only way to measure what a .mst really does: a transform is a difference, and a difference
# can only be read against the thing it is a difference of.
#
# The release discipline of the COM objects is repeated here instead of shared with `files_in_msi`
# above: whoever reads one of the two functions has to see the try/finally, because forgetting it
# is what broke a release build once (crates\architecture-rules\tests\scripts.rs says when).
function properties_of_msi([string]$msi, [string]$transform) {
    $wi = $null
    $db = $null
    $view = $null
    $copy = $null
    $properties = @{}
    try {
        $source = $msi
        if ($transform) {
            # Applied to a COPY: no check ever touches the file that goes to the customer.
            $copy = "$transform.applied.msi"
            Copy-Item -LiteralPath $msi -Destination $copy -Force
            $source = $copy
        }
        $wi = New-Object -ComObject WindowsInstaller.Installer
        # Mode 1 is transact, because a read-only database takes no transform. Nothing is
        # committed; the copy goes away in the finally.
        $mode = if ($transform) { 1 } else { 0 }
        $what = if ($transform) { "opening a copy of $(Split-Path -Leaf $msi) so that $(Split-Path -Leaf $transform) could be applied to it" } else { "reading the properties of $(Split-Path -Leaf $msi)" }
        $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($source, $mode))
        if ($null -eq $db) { throw "$what handed back nothing." }
        if ($transform) {
            # The second argument suppresses error conditions, and 0 suppresses none: a transform
            # that does not fit this MSI has to fail here, in the build, and not at the customer as
            # »1624 Error applying transforms«.
            $db.GetType().InvokeMember('ApplyTransform', 'InvokeMethod', $null, $db, @($transform, 0))
        }
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `Property`, `Value` FROM `Property`'))
        if ($null -eq $view) { throw "$what did not work: the property table could not be opened." }
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        while ($true) {
            $set = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($null -eq $set) { break }
            $name = $set.GetType().InvokeMember('StringData', 'GetProperty', $null, $set, @(1))
            $properties[$name] = $set.GetType().InvokeMember('StringData', 'GetProperty', $null, $set, @(2))
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($set)
        }
    }
    finally {
        foreach ($com in @($view, $db, $wi)) {
            if ($null -ne $com) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($com) }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        # Only after the handle is gone: on Windows the copy cannot be deleted before that.
        if ($copy -and (Test-Path -LiteralPath $copy)) { Remove-Item -LiteralPath $copy -Force }
    }
    return $properties
}

function msi_path([string]$version) {
    return (Join-Path $PackageDir "elasticdms-$version.msi")
}

function wxl_path([string]$culture) {
    return (Join-Path $Root "packaging\windows\$culture.wxl")
}

# The transform carries the culture in its name and not the LCID: the two places that take it — the
# Modifications tab under GPO and TRANSFORMS= under Intune — are read by a person who knows en-US
# and has to look 1033 up.
function mst_path([string]$version, [string]$culture) {
    return (Join-Path $PackageDir "elasticdms-$version.$culture.mst")
}

# Everything the packing produces: the MSI and one transform per further language. Signing and
# checking both walk this list, so an added language cannot be forgotten by one of them.
function package_artefacts([string]$version) {
    $out = @(msi_path $version)
    foreach ($culture in $Cultures | Select-Object -Skip 1) {
        $out += mst_path $version $culture
    }
    return $out
}

# The LCID a catalogue is built with. It stands in the .wxl and not here so that one language is
# one file — culture, code page, identifier and text together. The .wxs reads the same row as
# !(loc.PackageLanguage); this function reads it to check afterwards that the transform really
# arrived at that language.
function package_language([string]$culture) {
    $path = wxl_path $culture
    if (-not (Test-Path -LiteralPath $path)) {
        throw "The catalogue $path is missing. A culture without a catalogue is not a language; either write the file or take the culture out of the list »Cultures« in this script."
    }
    $document = [xml](Get-Content -LiteralPath $path -Raw -Encoding utf8)
    if ($document.DocumentElement.LocalName -ne 'WixLocalization') {
        throw "$path does not begin with WixLocalization; that is not a WiX catalogue."
    }
    $row = @($document.DocumentElement.ChildNodes |
        Where-Object { $_.LocalName -eq 'String' -and $_.Id -eq 'PackageLanguage' })
    if ($row.Count -ne 1) {
        throw "$path holds $($row.Count) rows with Id=PackageLanguage; exactly one is needed — it is the LCID that elasticdms.wxs builds the package with."
    }
    return [string]$row[0].Value
}

# ── Tasks ───────────────────────────────────────────────────────────────────────────────────

function task_help {
    Write-Host @'
windows-package.ps1 — builds target\package\elasticdms-<version>.msi and one language
transform beside it per further language.

  -Task build     Compile, sign the EXE, build, sign everything, check (the default).
  -Task tool      Fetch WiX as a dotnet tool. CHANGES THE MACHINE.
  -Task msi       Only wix build on an already compiled elasticdms.exe.
  -Task verify    Measure the finished package again (file table, transforms, signature).
  -Task clean     Empty target\package.
  -Task help      This overview.

Environment: VERSION, WIX_VERSION (default 5.0.2), SIGNING_ENDPOINT, SIGNING_ACCOUNT,
SIGNING_PROFILE (Azure Artifact Signing), PFX_PATH, PFX_PASSWORD (a certificate of one's own),
SIGNTOOL, TIMESTAMP_URL. Without any of them the same MSI arises, only unsigned — that is the
normal case.

Languages: the list Cultures in this script, the catalogues packaging\windows\<culture>.wxl.
The first culture is the language of the MSI itself; every further one becomes an .mst.

Distributing: msiexec /i elasticdms-<version>.msi /qn                          (the base language)
              msiexec /i elasticdms-<version>.msi TRANSFORMS=elasticdms-<version>.en-US.mst /qn
(per machine, see packaging\windows\README.md)
'@
}

function task_tool {
    report "WiX $WixVersion as a global dotnet tool"
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw 'The .NET SDK is missing; without `dotnet` WiX cannot be installed (on windows-2025 it is preinstalled).'
    }
    if (wix_present) {
        $present = wix_version_installed
        if ($present -eq $WixVersion) {
            hint "wix $present is already here."
        }
        else {
            hint "wix $present is here, $WixVersion is demanded; it will be updated."
            run_tool 'dotnet' @('tool', 'update', '--global', 'wix', '--version', $WixVersion)
        }
    }
    else {
        run_tool 'dotnet' @('tool', 'install', '--global', 'wix', '--version', $WixVersion)
    }
    ensure_extension
    hint 'Done. `wix --version` says what is here now.'
}

function task_msi {
    if (-not (Test-Path -LiteralPath $WxsFile)) {
        throw "The package description $WxsFile is missing."
    }
    if (-not (Test-Path -LiteralPath $ExeFile)) {
        throw "No elasticdms.exe lies in $BinDirectory. Compile first (-Task build), then pack."
    }
    if (-not (wix_present)) {
        throw "The tool »wix« is missing. Fetch it with: dotnet tool install --global wix --version $WixVersion (or scripts\windows-package.ps1 -Task tool)."
    }
    ensure_extension

    $full = version
    $three = msi_version $full
    $msi = msi_path $full

    # Every catalogue is read before the first build runs. A language whose .wxl is missing, or
    # whose catalogue names no LCID, shall not surface after ten minutes of packing but in the
    # first second.
    $language = @{}
    foreach ($culture in $Cultures) { $language[$culture] = package_language $culture }

    # Exactly one MSI per folder: the workflows look for it with a pattern and abort when two are
    # there. An old version from an earlier run is exactly that case — and so is a transform of an
    # older version, which would travel beside the new MSI and fit nothing.
    New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null
    Get-ChildItem -Path (Join-Path $PackageDir '*') -Include '*.msi*', '*.mst' -ErrorAction SilentlyContinue |
        ForEach-Object {
            hint "Removing an old file: $($_.Name)"
            Remove-Item -LiteralPath $_.FullName -Force
        }

    # ONE ProductCode for ALL languages of this build, rolled here and handed to every `wix build`.
    # By hand the .wxs lets `wix` roll it (the star in its guard); here it may not, because a
    # language transform is the difference between two of these builds and a difference that also
    # moved the ProductCode would make the two languages two products. A new one per build stays —
    # that is what MajorUpgrade with AllowSameVersionUpgrades demands, and task_verify measures
    # afterwards that the transform really left it alone.
    $productCode = [guid]::NewGuid().ToString().ToUpperInvariant()

    # NO -sval: `wix build` runs the ICE checks of the Windows Installer itself, and those are
    # exactly what cannot be had on the development machine. Switching them off would mean throwing
    # away the only check this package has ever seen.
    #
    # `Version`, `BinDir` and `ProductCode` are the preprocessor variable names of
    # packaging\windows\elasticdms.wxs and are spelled as that file spells them; renaming them is a
    # change in both files at once. That this holds is proven by a test
    # (crates/architecture-rules/tests/scripts.rs) — the rename to English had already left the
    # guards in the .wxs behind, and `wix` reported it after a ten-minute build as WIX0250.
    #
    # `-culture` and `-loc` belong together: `-culture` filters which catalogues count, so a .wxl
    # that does not match the culture is silently dropped and every !(loc.…) in the .wxs becomes a
    # WIX0102. MEASURED on the development Mac (packaging\windows\README.md names the call).
    $base = $Cultures[0]
    foreach ($culture in $Cultures) {
        $output =
            if ($culture -eq $base) { $msi } else { Join-Path $PackageDir "transform-source-$culture.msi" }
        report "Building $culture (LCID $($language[$culture])): $(Split-Path -Leaf $output)"
        run_tool 'wix' @(
            'build',
            '-arch', 'x64',
            '-d', "Version=$three",
            '-d', "BinDir=$BinDirectory",
            '-d', "ProductCode=$productCode",
            '-culture', $culture,
            '-loc', (wxl_path $culture),
            '-ext', 'WixToolset.Util.wixext',
            $WxsFile,
            '-o', $output
        )
        if (-not (Test-Path -LiteralPath $output)) {
            throw "wix reported success, but $output does not exist."
        }
        if ($culture -eq $base) {
            hint "Built: $msi"
            continue
        }

        # The difference between the two builds, and nothing else, is the language. `-t language`
        # sets the validation flags of a language transform; without a type the transform would
        # carry none and would apply to any MSI at all.
        $mst = mst_path $full $culture
        run_tool 'wix' @('msi', 'transform', '-t', 'language', $msi, $output, '-out', $mst)
        if (-not (Test-Path -LiteralPath $mst)) {
            throw "wix reported success, but $mst does not exist."
        }

        # The second MSI was only the other side of the difference; what ships is the transform.
        # It goes before the measurement so that nothing matching elasticdms-<version>*.msi can
        # outlive this loop — both workflows count those files and stop at two.
        Remove-Item -LiteralPath $output -Force
        $leftover = [System.IO.Path]::ChangeExtension($output, '.wixpdb')
        if (Test-Path -LiteralPath $leftover) { Remove-Item -LiteralPath $leftover -Force }

        # The size is reported because it is the one number that shows whether this really became a
        # language difference: four sentences and a language identifier are a few kilobytes. NOT
        # MEASURED on Windows — if the two builds produce cabinets that differ bit for bit, the
        # difference holds the whole cabinet, and then the number here is as large as the MSI.
        $size = (Get-Item -LiteralPath $mst).Length
        if ($size -eq 0) {
            throw "$mst is empty. An empty transform applies and changes nothing; the package would stay in its base language without a single error message."
        }
        hint "Built: $mst ($size bytes)"
    }
}

function task_verify {
    $full = version
    $msi = msi_path $full
    if (-not (Test-Path -LiteralPath $msi)) {
        throw "There is no $msi to check. Build first."
    }
    report 'Measuring the package again'

    $found = @(Get-ChildItem -Path $PackageDir -Filter '*.msi' -ErrorAction SilentlyContinue)
    if ($found.Count -ne 1) {
        throw "In $PackageDir there is not exactly one MSI but $($found.Count). In the folder at the customer it would not be recognisable which one holds."
    }
    $transforms = @(Get-ChildItem -Path $PackageDir -Filter '*.mst' -ErrorAction SilentlyContinue)
    if ($transforms.Count -ne $Cultures.Count - 1) {
        throw "In $PackageDir there are $($transforms.Count) transforms, but $($Cultures.Count) languages are set ($($Cultures -join ', ')), which makes $($Cultures.Count - 1). A transform too many belongs to another version and fits nothing; one too few is a language that silently does not go out."
    }

    # `@(...)` and not the bare call: a PowerShell function that returns an array of nought or one
    # hands back something that is not an array, and `.Count` on it throws "The property 'Count'
    # cannot be found" instead of the sentence below (measured under StrictMode here, for both the
    # empty and the single case). A one-file MSI would have failed that way, and unreadably.
    $names = @(files_in_msi $msi)
    if ($names.Count -eq 0) {
        throw "The file table of $msi is empty; this check would have read nothing and would have been green and worthless."
    }
    $mock = $names | Where-Object { $_ -match 'mock' }
    if ($mock) {
        throw "The MSI holds the test rig edms-mock ($($mock -join ', ')); it never belongs in a product."
    }
    if (-not ($names | Where-Object { $_ -match 'elasticdms\.exe' })) {
        throw 'The MSI holds no elasticdms.exe; something other than the client was packed.'
    }
    hint "File table: $($names.Count) file(s), among them elasticdms.exe and no mock."

    # Every transform against the MSI it belongs to. A transform is a promise about a file it does
    # not contain; the only honest check applies it and looks at what came out.
    # What came back is checked before it is used. `properties_of_msi` ends in `return
    # $properties` and cannot hand back anything else here — measured under StrictMode, an empty
    # hashtable survives a function return as an empty hashtable — and yet on a runner `$before`
    # arrived as nothing, and `.ContainsKey` then said only "You cannot call a method on a
    # null-valued expression". Whatever it is, it is named here instead of crashing.
    $before = properties_of_msi $msi ''
    if ($before -isnot [hashtable]) {
        throw "Reading the properties of $(Split-Path -Leaf $msi) gave back $(if ($null -eq $before) { 'nothing at all' } else { "a $($before.GetType().FullName)" }) instead of a table of properties. That is a fault in this script, not in the package."
    }
    foreach ($name in @('ProductCode', 'ProductLanguage')) {
        if (-not $before.ContainsKey($name)) {
            throw "The MSI has no property $name. Without it nothing can be said about a transform, and Intune detects by exactly that value."
        }
    }
    foreach ($culture in $Cultures | Select-Object -Skip 1) {
        $mst = mst_path $full $culture
        if (-not (Test-Path -LiteralPath $mst)) {
            throw "The transform $mst is missing although $culture stands in the language list. The MSI would go out alone, and an installation that names the transform fails with »1624 Error applying transforms«."
        }
        $after = properties_of_msi $msi $mst
        if ($after -isnot [hashtable]) {
            throw "Applying $(Split-Path -Leaf $mst) gave back $(if ($null -eq $after) { 'nothing at all' } else { "a $($after.GetType().FullName)" }) instead of a table of properties. That is a fault in this script, not in the transform."
        }
        $expected = package_language $culture
        $reached = if ($after.ContainsKey('ProductLanguage')) { $after['ProductLanguage'] } else { '' }
        if ($reached -ne $expected) {
            throw "The transform $(Split-Path -Leaf $mst) applies, but the package is then in language »$reached« and not »$expected«. Then the four sentences would be in one language and the package would declare another."
        }
        # The transform must move the language and NOTHING about the identity: a moved ProductCode
        # would make the transformed installation a second product — a second row in Programs and
        # Features and a detection rule in Intune that no longer finds what it installed.
        if ($after['ProductCode'] -ne $before['ProductCode']) {
            throw "The transform $(Split-Path -Leaf $mst) changes the ProductCode from $($before['ProductCode']) to $($after['ProductCode']). Then it is not a language transform but a second product; both wix build calls have to receive the same ProductCode."
        }
        hint "Transform ${culture}: applies, sets language $expected, leaves the ProductCode alone."
    }

    if ((signing_mode) -ne 'none') {
        $signtool = find_signtool
        # /pa = the Authenticode policy instead of the driver policy.
        #
        # Every artefact, the transforms included — whoever may hand an administrator a .mst may
        # decide what the package says. NOT PROVEN that signtool accepts a .mst: nothing on a Mac
        # can try it. If it refuses, it refuses loudly here and not at the customer, and the
        # decision to send the transform out unsigned is then one a person takes (README.md,
        # section "Where rework is most likely").
        foreach ($artefact in @(package_artefacts $full)) {
            run_tool $signtool @('verify', '/pa', '/v', $artefact)
        }
        run_tool $signtool @('verify', '/pa', '/v', $ExeFile)
        hint 'Signature checked (MSI, every transform and the EXE).'
    }
    else {
        hint 'Unsigned — that is intended as long as no certificate is deposited.'
    }
}

function task_clean {
    if (Test-Path -LiteralPath $PackageDir) {
        report "Clearing: $PackageDir"
        Remove-Item -LiteralPath $PackageDir -Recurse -Force
    }
    else {
        hint "$PackageDir does not exist; nothing to clear."
    }
}

function task_build {
    report_space 'before'
    $full = version
    report "Building elasticdms $full for Windows x64"

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo is missing; without a Rust toolchain there is no elasticdms.exe (rustup show reads rust-toolchain.toml).'
    }
    # `-p elasticdms`, NEVER `--workspace`: a build over the whole workspace would also put
    # edms-mock.exe into the same directory, and the test rig never belongs in a product.
    run_tool 'cargo' @('build', '--release', '-p', 'elasticdms', '--target', $Target)
    if (-not (Test-Path -LiteralPath $ExeFile)) {
        throw "cargo reported success, but $ExeFile does not exist."
    }

    # Sign the EXE BEFORE packing: afterwards it sits inside the cabinet file, and no signtool
    # reaches what lies there. A signed MSI with an unsigned EXE inside would be the half of the
    # work that nobody notices.
    sign $ExeFile 'the elasticdms.exe'

    task_msi
    # One loop over everything the packing produced, not one call per language: whoever adds a
    # language to $Cultures may not have to remember the signing as a second place.
    foreach ($artefact in @(package_artefacts $full)) {
        sign $artefact (Split-Path -Leaf $artefact)
    }
    task_verify

    report_space 'after'
    report "Done: $(msi_path $full)"
    if ((signing_mode) -eq 'none') {
        hint 'Unsigned. Delivered over Intune, SCCM, SYSVOL or an intranet share, the file carries no mark of the web, and SmartScreen does not come into play.'
    }
}

# ── Flow ────────────────────────────────────────────────────────────────────────────────────

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning 'This script is written for PowerShell 7 (pwsh); under Windows PowerShell 5.1 the non-ASCII characters of the messages appear wrong. The work itself stays right.'
}

try {
    switch ($Task) {
        'build' { task_build }
        'tool' { task_tool }
        'msi' { task_msi }
        'verify' { task_verify }
        'clean' { task_clean }
        'help' { task_help }
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    # The message alone is not always enough to act on — "You cannot call a method on a null-valued
    # expression" says nothing about where. The position and the call stack say it, and they cost
    # three lines in a log that nobody reads until something has gone wrong.
    if ($_.InvocationInfo) {
        Write-Host "  at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
        Write-Host "  $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    }
    if ($_.ScriptStackTrace) {
        Write-Host ($_.ScriptStackTrace -split "`n" | ForEach-Object { "  $_" }) -ForegroundColor Red
    }
    # Without this `exit` PowerShell would return the success of the last successful line, and the
    # workflows (which check $LASTEXITCODE) would take a failure for a success.
    exit 1
}
exit 0
