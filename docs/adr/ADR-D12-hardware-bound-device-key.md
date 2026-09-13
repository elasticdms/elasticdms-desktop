# ADR-D12: The hardware-bound device key — one trait, two platforms, and a fallback that says so

**Status:** Accepted (2026-09-13).

The signing seam and the two conversions behind it are built; the platform calls that would reach a
Secure Enclave or a TPM are not, for the reasons measured below. The measurements were taken on
macOS 26.6 (build 25G72, Apple M2 Max) and, for Windows, by compiling the full CNG sequence for
`x86_64-pc-windows-msvc` against `windows =0.58.0`.
*On the number:* `D10` and `D11` were both taken on 2026-09-12; `D12` is the next free one.

## Context

ADR-D03 §4 put the private device key into the operating system's keychain and named Secure
Enclave (macOS) and TPM (Windows) as the hardware-backed alternatives.

The device key is the one a human approves. Its RFC 7638 thumbprint is `device.key_thumbprint` in
the counterpart's schema, and until an administrator has compared it out of band, every token
request is answered `403 device-pending-approval` — geraete-auth §3.1.1:
*„`pending_admin_approval` ist bei `SOFTWARE` der Regelfall, nicht die Ausnahme"* (with `SOFTWARE`
it is the rule, not the exception). The key lies in the keychain as PKCS#8 DER: it can be read and
therefore copied. That is the whole reason the counterpart calls it `SOFTWARE`.

**That `TODO` named the wrong obstacle, in both halves.** It said both paths needed “a signing
source of their own in `edms-crypto`”, and it named the levels `HARDWARE`/`STRONGBOX` as the
prize. Neither holds:

* `crates/crypto/src/lib.rs:32` is `#![forbid(unsafe_code)]`, and point 2 of that crate's own
  header says where the key is kept is the app's decision. Neither implementation can live there —
  every call of both platform APIs is `unsafe`.
* `edms-wire` knows three attestation levels, and geraete-auth §3.1.1 defines all three over one
  root: *„Kette verifiziert bis zur Google-Attestationswurzel"*. There is no `HARDWARE` to reach,
  and no Apple or Microsoft root the counterpart would recognise. The same document says twice, in
  the table and in the DDL comment on `device`, that *„`tier` ist das Ergebnis, nicht die
  Eingabe"* — the result, not the input.

So the question this ADR settles is not “how do we reach a higher tier”. It is: the private key
would no longer be copyable off the machine, and nothing else changes. That is worth something,
and it is worth less than the `TODO` suggests.

## Measured, not assumed

1. **macOS, the key itself works.** An ephemeral Secure Enclave P-256 key
   (`kSecAttrTokenIDSecureEnclave`, access control `kSecAccessControlPrivateKeyUsage` alone)
   creates in 6.60 ms, signs 2000 times without a single prompt, and hands out its public part as
   65 bytes `04||X||Y` — exactly what `edms_crypto::key::Jwk` needs. The private part refuses to
   leave: `SecKeyCopyExternalRepresentation` fails with OSStatus `-4`, attributes report
   `extr=0`.
2. **macOS, the permanent key is out of reach from this build pipeline.**
   `kSecAttrIsPermanent = true` returned `-34018` (`errSecMissingEntitlement`) in six
   configurations, ad-hoc and Developer-signed, sandboxed and not, data-protection keychain and
   legacy. The cause was isolated: a plain generic password fails the same way, so the process has
   no keychain access group at all. The entitlement that would give it one,
   `keychain-access-groups`, gets the process **SIGKILLed at exec** (exit 137) without an embedded
   provisioning profile. **Not proven:** that a Developer ID profile lifts this. No profile exists
   on the machine, both profile directories are empty, and none could be fetched without the
   developer portal.
3. **macOS, a key blob cannot be kept and put back.** The undocumented 324-byte `toid` attribute
   fed to `SecKeyCreateWithData` returns OK and silently produces a **different** key — one saved
   blob, five loads, five different public points. Apple says so in SecItem.h:1091–1094. A design
   that stored the blob in the existing vault would look as if it worked and would hand the server
   a thumbprint nobody enrolled.
4. **macOS, the signature needs converting and the naive converter is wrong.**
   `…ECDSASignatureMessageX962SHA256` returns DER; over 2000 signatures the lengths were 69 (×3),
   70 (×497), 71 (×997) and 72 (×503). The 69-byte case is an integer shorter than 32 bytes, so
   the conversion has to strip a leading `0x00` **and** left-pad — a converter that only handles
   “33 → 32” is wrong about three times in two thousand. The 64-byte `…RFC4754SHA256` would need no
   converter but is `API_AVAILABLE(macos(14.0))` and strongly linked, while both Info.plists
   declare `LSMinimumSystemVersion 13.0`.
5. **macOS costs 4.660 ms a signature** against 0.042 ms for `SoftwareKey` — about 110×. And the
   enclave does **not** sign deterministically: 2000 signatures over one message were all
   different, where `SoftwareKey::sign` uses RFC 6979 and says so.
6. **Windows compiles and nothing more.** The full CNG sequence — `NCryptOpenStorageProvider`
   with `MS_PLATFORM_CRYPTO_PROVIDER`, `NCryptIsAlgSupported`, `NCryptCreatePersistedKey`,
   `NCryptSetProperty`, `NCryptFinalizeKey`, `NCryptOpenKey`, `NCryptExportKey`,
   `NCryptSignHash`, plus `Tbsi_GetDeviceInfo` — compiles clean under `-D warnings`. The two
   features needed are `Win32_Security_Cryptography` (its only parent is `Win32_Security`, which
   `edms-cfapi` already enables) and `Win32_System_TpmBaseServices`. **Not proven: every single
   runtime claim.** No Windows machine ran any of it.
7. **Windows' signature format is not documented by Microsoft.** Both reference pages were read in
   full and neither states the ECDSA layout. The evidence that `NCryptSignHash` returns the 64
   bytes `r || s` this repository already wants is indirect (the .NET default over `ECDsaCng`) and
   third-party (`pcpcrypto`, written against this KSP). It has to be settled by a test, not by an
   assertion.
8. **Neither key changes anything on the wire.** Contract §7.0.5 fixes `attestation` at
   `{"type": "none", "available": false}` with the rule that the client never claims a chain, and
   the counterpart answers `tier: "SOFTWARE"`, `reason: "attestation_type_none"`,
   `adminConfirmationRequired: true`. The counterpart's enrolment body has **no** request-side
   field for the class of key storage at all: `strongBoxRequested`, `strongBoxAvailable` and
   `keystoreSelfTest` occur in geraete-auth in exactly one line each, inside the kiosk request
   example, and in none of the nine server steps, the tier table or the DDL. They are received and
   discarded.

## Decision

1. **One seam, and it is the one that is already there.** `edms_crypto::key::SigningKey` — “the
   private part may sit in memory, in the keychain or in a Secure Enclave — all that counts here is
   that it signs bytes”. `KeyBundle.device_key` (`crates/engine/src/session.rs:195`) becomes
   `Arc<dyn SigningKey>`, and the device slot gets a loader of its own beside `load_or_generate`
   (:388), which today serves both slots and has to go on handing the session slot a
   `SoftwareKey` (point 8). `KeySource::key` (:362) already hands out `Arc<dyn SigningKey>`, so
   the trait boundary is right and nothing above the engine changes at all.
   **No new trait in `edms_core::port`.** Those two are the mirror's seam — platform asks, engine
   orders — and a key is neither asked for by the platform nor ordered by the engine.
2. **Two implementations, in the two platform crates that already exist.** The FFI stands in
   `edms_cfapi::device_key` and `edms_fileprovider::device_key`, next to `locale` and `domain` —
   the halves of those crates the **app** uses, not the extension. They speak no crypto: they take
   the message bytes and hand back 64 bytes `r || s` and the two coordinates. The `SigningKey`
   implementation stands in `crates/app` next to the vault, because the app is the only crate that
   knows both a platform layer and `edms-crypto`, and it is already the only process with a user
   identity that a key store hangs off (R7, and the header of `vault.rs`).
   *What that costs in rules:* nothing, except one gap that has to be closed anyway — R5's pattern
   list does not contain `objc2_security::`, and because the patterns are substrings,
   `objc2_security::` does not match `objc2::`. It would slip through today. R4 already catches
   `windows::Win32`, and `cfapi` is already allowed it; both crates are already in
   `UNSAFE_ALLOWED`.
3. **Absent or refusing hardware falls back to the software key, and says so.** Four checks before
   anything is created — on Windows `Tbsi_GetDeviceInfo` → `TPM_VERSION_20`, then the provider,
   then `NCryptIsAlgSupported(ECDSA_P256)`; on macOS the one probe that exists, an **ephemeral**
   key that is created and dropped (6.60 ms, writes nothing to the keychain — Security.framework
   has no availability predicate for the enclave, grepped). Any failure is a fallback to
   `SoftwareKey`, never an abort: a workstation whose TPM is switched off in firmware must still
   reach the archive, and refusing to run would turn a hardening into an outage. The fallback is
   **named in two places**: a row in `doctor` saying which of the checks failed, and one line in
   the diagnostic log per process saying which key source is in use — the same shape ADR-D10 §4
   uses for the language fallback.
   **A silent downgrade is the worst of the three options**, worse than refusing to run, because
   the property that was bought would be gone and nobody would know which machines still had it.
   It is not chosen; the two places named above are what keep it from happening by accident.
4. **The user sees nothing, and that is correct.** No dialog, no tray state, no catalogue key. The
   fallback changes nothing the person at the machine does or decides, and a warning they cannot
   act on is noise. The operator surface carries it instead: `doctor` is read in a terminal and
   pasted into a ticket, and per the rule in `crates/engine/src/report.rs` it is English and does
   not go through the text catalogue.
   **What the counterpart learns: nothing.** It has no field for this, and its verdict would not
   move if it had one (measurement 8). Either way the device is `SOFTWARE` and waits for a human.
5. **An installed client keeps its software key. Never both, never silently.** A hardware key
   cannot be an import of the existing one — the enclave refuses imports outright (measurement 3),
   and a TPM key has no PKCS#8 to import. So the move is a **new key pair**: a new thumbprint, a
   new `device_key` row, and a second out-of-band confirmation by an administrator, because
   `device.key_thumbprint` is precisely what `confirmed_by` attests. The counterpart has no
   endpoint for it: geraete-auth §3 defines nine and none of them rotates a device key, although
   `device.key_rotated` exists as an audit event. Therefore: **hardware key on new enrolments
   only**, and the move of an enrolled device is a re-enrolment the user asks for, never an upgrade
   that happens at start-up.
   Carrying both at once is refused for the same reason: two keys are two thumbprints, and the
   administrator would not know which one they approved.
6. **`SLOT_DEVICE_KEY` holds either the key or a marker, and the two are distinguishable without
   guessing.** A hardware key leaves no private bytes for the vault; what belongs there is the
   handle — the CNG key name on Windows, the application tag on macOS — behind a header of its
   own, in the spirit of the existing `edms-vault/1`. Whatever a future build reads there, an
   unreadable slot stays what it is today: `VaultError::Corrupt`, never a quiet fresh start, for
   the reason already written at `load_or_generate` — a new device key is a different device and
   ends in `409 device-id-conflict`.
7. **The enrolment body does not change, and the field that would carry this is our proposal, not
   the counterpart's demand.** `attestation: {"type": "none", "available": false}` stays, with the
   rule and the reason that already stand in contract §7.0.5. A self-report — `keyStorage` with
   values like `software`, `os-keychain`, `secure-enclave`, `tpm` — is **an invention of this
   repository**, in neither specification, and it is not built. If it is ever proposed it must
   carry the counterpart's own precedent for an unproven hardening claim, the comment on
   `device_owner`: *„Die Selbstauskunft des Geraets ueber seine Haertung. Als Selbstauskunft
   gefuehrt (Restrisiko 15), nicht als Nachweis"* — carried as self-report, not as proof. It goes
   to whoever owns the server contract before either side builds it.
8. **The device key only. The session key stays software.** The device key signs the client
   assertion, `GET /v1/devices/me`, the server key set and the delivery long poll — roughly one
   signature every 25 seconds. The session key signs a DPoP proof on **every** call, with one
   nonce retry (ADR-D03 §3). 4.660 ms measured in the enclave — and 33 ms to 200 ms p95 reported
   for TPMs by others, measured here by nobody — is invisible in the first place and would be felt
   in every listing and every hydration in the second.

## Rationale

Two of the eight points were ours to settle; the rest follow from them or from the measurements.

**Why the app and not a crate per platform.** A crate `edms-enclave` and a crate `edms-winkeys`
would each need four edits in `crates/architecture-rules/tests/rules.rs` — its rule's allow list,
`UNSAFE_ALLOWED`, its own entry in `allowed_dependencies()` and the `elasticdms` list there — eight
in all, to arrive where the app already stands. ADR-D10 §4 decided this shape once already for a
smaller question: the platform call lives in the platform crate, the app joins the two and hands
the answer down. The device key is the same question with a bigger answer. What it costs is named:
on macOS the `.appex` links Security.framework for code it never calls, because the library half
and the extension half sit in one crate. That is a linker entry, against eight edits and two
crates.

**Why a fallback and not a refusal.** The hardware is not reliably there inside the range this
product declares supported. ADR-D06 puts the Windows floor at Windows 10 1709; TPM 1.2 machines
are inside it and have no P-256 at all, and a version-tabulated third-party report has the PCP
provider failing on elliptic curves with `0x80090029` on Windows 10 1909 and 21H1, Server 2016 and
Server 2019 RTM — fixed in 21H2 and later. On macOS, until a provisioning profile exists, the
fallback is not the exception but the only path. A feature whose failure mode is “the archive is
unreachable” cannot be the one that hardens a key nobody asked to harden.

## Consequences

- **Windows can be built first; macOS cannot get past the first permanent key.** The CNG path
  needs no entitlement, no manifest, no package identity and no certificate — the cheapest
  hardware-key story either platform offers, and the import libraries are already in the xwin
  cache. The enclave path stops at packaging: the app is signed with no entitlements file at all
  today, and `verify_entitlements()` in `scripts/macos-bundle.sh` errors out if the app carries
  any. It needs `keychain-access-groups`, an `App ID` registered under the team, and an embedded
  `Contents/embedded.provisionprofile` — a change of shape for the bundle script, and the first
  thing in this product to need more than ADR-D05's measured “No paid developer account needed”.
  That measurement was about registering the domain and it stays true; this is beside it, not
  against it.
- **The two platforms will differ for a while**, and it costs nothing on the wire, because the
  counterpart sees no difference between them anyway (measurement 8). It costs something in
  support: two answers to the same question about the same product.
- **On macOS signatures stop being deterministic.** Not a correctness problem — every verifier
  takes either — but `SoftwareKey::sign` says “RFC 6979: deterministic, no per-signature randomness
  that could fail”, and that sentence would no longer describe the device key on a Mac.
- **The architecture rule grows one pattern** (`objc2_security::` in R5), and it should grow it
  whether or not this is ever built: the gap exists today.
- **`edms-cfapi` gains a SHA-256 dependency.** `NCryptSignHash` takes a digest, the trait takes a
  message, and the PCP provider is reported to fail outright on a SHA-384/512 digest with a P-256
  key — so the platform side hashes, and refuses anything that is not 32 bytes.

## Residual risk, named

**A hardware-bound key dies with the hardware, and there is no copy anywhere.** A TPM clear, a
mainboard exchange, a reimage, a new machine — on Windows the wrapped key file is useless without
that TPM, and roams to no other. On macOS it is unknown whether such a key survives a reboot, a
macOS upgrade or a FileVault change, because no permanent key could be made to test it. A device
that loses its key is a new device: new thumbprint, new enrolment, and a second trip to an
administrator before the archive comes back.

This failure mode does not exist today, and it does not exist for the same reason the software key
is called `SOFTWARE`: a key that can be read can also be restored. The decision above buys
non-extractability by paying exactly that, and there is no escrow to soften it — an escrowed
hardware key is a software key with extra steps.

## Open point: the thumbprint nobody can compare

The whole value of this decision rests on a gesture the client does not currently support. The
counterpart's confirmation is a human comparing `device.key_thumbprint` in the console against the
thumbprint shown on the device, and it separates that comparison expressly from the anchor
fingerprint, which is compared against the Verfahrensdokumentation. In this client
`EngineState::AwaitingApproval { fingerprint }` is filled from `read_key_set(shared)?.fingerprint()`
— the **anchor set** fingerprint — and that is what reaches the window; `doctor` prints the device
identifier and the same anchor fingerprint. The device key's own thumbprint is computed nowhere
outside tests, although `PublicKey::thumbprint` has been there all along.

So today an administrator cannot perform the confirmation that lifts `403 device-pending-approval`,
and a key moved into hardware would make an uncomparable thumbprint harder to copy. Repairing that
is cheaper than everything above and is worth more; it is not part of this ADR only because it is
a defect in what is already built, not a decision about what is not.

## Rejected alternatives

- **An attestation certificate chain from either platform.** Windows offers `NCryptCreateClaim`
  with `NCRYPT_CLAIM_PLATFORM`, Apple offers App Attest and DeviceCheck. Both root in their own
  vendor's root; the counterpart's verifier knows exactly one, Google's, and would answer
  `attestation_root_untrusted`. A chain the server cannot verify buys nothing and costs an
  entitlement, a hardware dependency and a verifier nobody has scoped. This is a contract change
  first and a client change second.
- **Claiming `HARDWARE` or `TEE` on the wire.** There is no `HARDWARE` in the vocabulary, and
  `TEE` means “the chain verifies to the Google root”. Sending it would be claiming a chain that
  does not exist — and it would take away the counterpart's reason for having a person approve the
  device. The sentence already in `vault.rs` is right and is kept: an invented `HARDWARE` claim
  would be worse than the honest statement.
- **A signing source in `edms-crypto`, as the `TODO` proposes.** `#![forbid(unsafe_code)]`, and
  both platform APIs are `unsafe` throughout.
- **A crate per platform (`edms-enclave`, `edms-winkeys`).** Eight edits to the architecture rules
  to reach where the app already stands; see Rationale.
- **Putting the key in `edms-fileprovider`'s extension half, or sharing one key between app and
  extension.** `crates/fileprovider` depends on neither `edms-crypto` nor `edms-net`; the extension
  never signs anything and reaches the app over TCP on 127.0.0.1. Sharing would need both binaries
  in one keychain access group under one profile, to serve a need that does not exist.
- **Storing the enclave key blob in the vault and loading it back.** Measured: it returns a
  different key, without an error (measurement 3). This is the one alternative that would have
  looked as though it worked.
- **Key escrow, or any backup of the private part.** The property being bought is that the private
  part cannot be copied. A backup is a copy. The recovery path is re-enrolment, and it is named in
  the residual risk instead of being engineered away.
- **Refusing to start without hardware.** See Rationale; and on macOS today that would refuse every
  machine.
- **`kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256`**, which would return the 64 bytes
  directly and save the converter. macOS 14+, strongly linked, and Rust has no equivalent of
  clang's weak import from an availability attribute — the binary would fail to load on macOS 13,
  which both Info.plists declare as the floor.
- **A software key that merely claims to be hardware-bound, or a fallback that does not report
  itself.** Named here so that the option is on the record as considered and refused: it is the
  worst of the three, because the claim would outlive the property.
