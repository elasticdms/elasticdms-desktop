//! The operating system's keychain as the engine's [`Vault`].
//!
//! ADR-D03, point 4 says where the private device key and the refresh token belong: **not** into
//! the SQLite file but into the keychain — macOS Keychain, Windows Credential Manager. A database
//! file is gone with one copy command; a refresh token inside it would be a session that lives on
//! on every other machine, under the name of a person who knows nothing about it.
//!
//! The engine knows only the trait ([`edms_engine::Vault`]); the one implementation that really
//! talks to the operating system stands here — the app is the only process with a user identity
//! that a keychain hangs off (architecture rule R7).
//!
//! ## The limit of the Windows Credential Manager
//!
//! `CRED_MAX_CREDENTIAL_BLOB_SIZE` is **2560 bytes** (wincred.h: 512 × 5). A value above it is not
//! truncated — `CredWriteW` rejects it, and a vault that kept quiet about that and stored the
//! first 2560 bytes would hand back half a key on the next start. That is why this vault stores
//! **every** value in chunks: a header entry names the number of chunks and the total length, the
//! chunks stand next to it. If a chunk is missing when reading, or the length does not match, that
//! is a [`VaultError::Corrupt`] — never a shorter value.
//!
//! The chunking works the same on **both** platforms. Two ways would be two formats, and the
//! second would stay untested until somebody needed it on Windows.
//!
//! ## Measured: the keychain asks after every rebuild (development runs only)
//!
//! On macOS the access list of an entry hangs off the **program** that created it. A `cargo build`
//! produces a different, only ad-hoc signed program every time; the keychain does not recognise it
//! again and asks the person — a dialog the process waits on. Measured on 2026-09-11 (macOS 26.6):
//! the first run after the build creates the entries without asking, the first run after the
//! **next** build hangs on the dialog. The shipped bundle is signed with a stable identifier
//! (`scripts/macos-bundle.sh`) and does not have the problem. Whoever wants to work without the
//! dialog during development sets `EDMS_VAULT=memory` (see `crate::wiring`) — and then knows that
//! device and session do not survive the process.
//!
//! ## Hardware-bound keys (Secure Enclave / TPM): what is missing, measured
//!
//! The device key lies here as PKCS#8 DER, that is as a **software** key: it can be read and
//! therefore copied. geraete-auth §5 knows the level `SOFTWARE` for that, and precisely for that
//! reason it demands that a person approve the device (03 §6.2.4). A key that never leaves the
//! hardware — Secure Enclave (`kSecAttrTokenIDSecureEnclave`) or TPM through CNG
//! (`Microsoft Platform Crypto Provider`) — takes that copying away and nothing else.
//!
//! The seam for it stands in [`crate::device_key`] and the decision in ADR-D12. Two claims that
//! used to stand here were **wrong**, and both were corrected by measurement:
//!
//! * Neither key can have "a signing source of its own in `edms-crypto`": that crate is
//!   `#![forbid(unsafe_code)]`, and every call of both platform APIs is `unsafe`. The
//!   implementation stands in the app, the calls in the platform crates.
//! * `HARDWARE`/`STRONGBOX` is **not** the prize, because it cannot be reached. `edms-wire` knows
//!   three levels and geraete-auth §3.1.1 defines all three over the Google attestation root;
//!   there is no `HARDWARE`, and no Apple or Microsoft root the counterpart would recognise. The
//!   device stays `SOFTWARE` and still waits for a person.
//!
//! An invented `HARDWARE` claim would be worse than the honest statement, because it would take
//! away the server's reason for having a person approve the device. What is still missing is the
//! platform half of each side; ADR-D12 holds the measurements behind both.

use edms_engine::{Vault, VaultError};

/// The service name under which every slot stands in the keychain.
///
/// The same identifier as the application directory (`edms_bridge::APPLICATION_DIRECTORY`):
/// whoever searches the keychain should recognise the folder client's entries by one name.
pub const SERVICE: &str = "de.elasticdms.folderclient";

/// Maximum size of an entry in the Windows Credential Manager (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
pub const LIMIT_WINDOWS: usize = 2560;

/// This many bytes go into one chunk.
///
/// Well below [`LIMIT_WINDOWS`]: some keychains wrap the bytes in frames of their own (encryption,
/// encoding), and a value that only fails at byte 2559 shows up in production and not in a test.
pub const CHUNK_BYTES: usize = 2048;

/// This vault accepts no more chunks than these (128 KiB).
///
/// A device key is around 140 bytes, a refresh token a few hundred. Anything beyond that is no
/// longer a secret but a bug — and it should fail loudly instead of filling the keychain with
/// thousands of entries.
pub const CHUNK_MAX: usize = 64;

/// The marker of the header entry. The version stands with it, so that a later format recognises
/// the old entry instead of reading it as garbage.
///
/// Until 2026-09-13 the value read `edms-tresor/1` (*Tresor*, German for vault), kept on the
/// argument that a stored value cannot be renamed without a read-compatibility path. That argument
/// is void — nothing is installed anywhere (ADR-D10, correction of 2026-09-13) — and it was
/// self-defeating besides: [`SERVICE`] changed in the same pass, so an older installation's entries
/// are out of reach under the new service name whatever this marker says. From the first published
/// package on, the argument is real again and a change here needs the read-compatibility path.
const HEADER_MARKER: &str = "edms-vault/1";

/// The operating system's keychain.
///
/// `keyring` picks the implementation per platform (feature `v1`): macOS Keychain Services,
/// Windows Credential Manager. That choice is the crate's, not this module's — a second, separate
/// use of `SecItemAdd` or `CredWriteW` would be a second place nobody tests.
#[derive(Debug)]
pub struct SystemVault {
    service: String,
}

impl Default for SystemVault {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemVault {
    /// The vault under the service name [`SERVICE`].
    pub fn new() -> Self {
        Self { service: SERVICE.to_owned() }
    }

    /// A vault under a service name of its own — for tests only, so that they do not touch the
    /// entries of the running workstation.
    #[cfg(test)]
    pub fn with_service(service: &str) -> Self {
        Self { service: service.to_owned() }
    }

    /// Checks once whether this machine's keychain is reachable at all.
    ///
    /// For `doctor` and for the start: a workstation without a keychain cannot keep a device key,
    /// and it should learn that before it signs in.
    ///
    /// # Errors
    ///
    /// When the keychain is not reachable or refuses access.
    pub fn check(&self) -> Result<(), VaultError> {
        self.entry("probe").map(|_| ())
    }

    /// One entry of the keychain.
    fn entry(&self, name: &str) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service, name).map_err(|error| translate(&error, name))
    }

    /// The name of the header entry of a slot.
    fn header_name(slot: &str) -> String {
        slot.to_owned()
    }

    /// The name of the `number`-th chunk (from 1).
    fn chunk_name(slot: &str, number: usize) -> String {
        format!("{slot}#{number}")
    }

    /// Reads an entry; `Ok(None)` if it does not exist.
    fn read_entry(&self, name: &str) -> Result<Option<Vec<u8>>, VaultError> {
        match self.entry(name)?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(translate(&error, name)),
        }
    }

    /// Deletes an entry; `Ok(false)` if it never existed.
    fn delete_entry(&self, name: &str) -> Result<bool, VaultError> {
        match self.entry(name)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(translate(&error, name)),
        }
    }
}

impl Vault for SystemVault {
    fn read(&self, slot: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let Some(header) = self.read_entry(&Self::header_name(slot))? else {
            return Ok(None);
        };
        let (chunks, length) = read_header(slot, &header)?;
        let mut value = Vec::with_capacity(length);
        for number in 1..=chunks {
            let name = Self::chunk_name(slot, number);
            // A missing chunk is **not** a shorter value: half a device key would yield, on the
            // next call, a signature the server does not know, and nobody would know why.
            let Some(part) = self.read_entry(&name)? else {
                return Err(VaultError::Corrupt {
                    slot: slot.to_owned(),
                    reason: format!(
                        "chunk {number} of {chunks} is missing from the keychain; the value is \
                         incomplete"
                    ),
                });
            };
            value.extend_from_slice(&part);
        }
        if value.len() != length {
            return Err(VaultError::Corrupt {
                slot: slot.to_owned(),
                reason: format!(
                    "the header names {length} bytes, the chunks add up to {}",
                    value.len()
                ),
            });
        }
        Ok(Some(value))
    }

    fn write(&mut self, slot: &str, value: &[u8]) -> Result<(), VaultError> {
        let chunks = value.len().div_ceil(CHUNK_BYTES).max(1);
        if chunks > CHUNK_MAX {
            return Err(VaultError::Denied(format!(
                "the value for `{slot}` is {} bytes long; the folder client stores at most {} \
                 bytes (Windows Credential Manager: {LIMIT_WINDOWS} bytes per entry)",
                value.len(),
                CHUNK_MAX.saturating_mul(CHUNK_BYTES),
            )));
        }
        // The chunks first, then the header: if the operation breaks off in the middle, an old
        // header stands in front of new chunks — and that shows up on reading, through the length.
        // The other way round a new header in front of old chunks would look exactly like an
        // intact value.
        for (number, part) in value.chunks(CHUNK_BYTES).enumerate() {
            let name = Self::chunk_name(slot, number.saturating_add(1));
            self.entry(&name)?.set_secret(part).map_err(|f| translate(&f, &name))?;
        }
        if value.is_empty() {
            let name = Self::chunk_name(slot, 1);
            self.entry(&name)?.set_secret(&[]).map_err(|f| translate(&f, &name))?;
        }
        // Clear the leftovers of a longer predecessor before the header excludes them: otherwise
        // a chunk of an old token would stay behind in the keychain.
        self.clear_chunks(slot, chunks.saturating_add(1))?;
        let header = Self::header_name(slot);
        let content = format!("{HEADER_MARKER} {chunks} {}", value.len());
        self.entry(&header)?.set_secret(content.as_bytes()).map_err(|f| translate(&f, &header))
    }

    fn delete(&mut self, slot: &str) -> Result<(), VaultError> {
        // The header first: after it the slot counts as empty, even if clearing the chunks fails.
        // A chunk without a header is not a readable value.
        self.delete_entry(&Self::header_name(slot))?;
        self.clear_chunks(slot, 1)
    }
}

impl SystemVault {
    /// Deletes the chunks from `of` on, up to the first one that no longer exists.
    fn clear_chunks(&self, slot: &str, of: usize) -> Result<(), VaultError> {
        for number in of..=CHUNK_MAX {
            if !self.delete_entry(&Self::chunk_name(slot, number))? {
                break;
            }
        }
        Ok(())
    }
}

/// Reads the header entry: `edms-vault/1 <chunks> <bytes>`.
fn read_header(slot: &str, header: &[u8]) -> Result<(usize, usize), VaultError> {
    let corrupt = |reason: String| VaultError::Corrupt { slot: slot.to_owned(), reason };
    let text = std::str::from_utf8(header)
        .map_err(|_| corrupt("the header entry is not UTF-8 text".to_owned()))?;
    let mut parts = text.split(' ');
    let marker = parts.next().unwrap_or_default();
    if marker != HEADER_MARKER {
        return Err(corrupt(format!(
            "the header entry carries the marker `{marker}` instead of `{HEADER_MARKER}`"
        )));
    }
    let number = |what: &str, raw: Option<&str>| -> Result<usize, VaultError> {
        raw.and_then(|r| r.parse::<usize>().ok())
            .ok_or_else(|| corrupt(format!("the header entry names no valid {what}")))
    };
    let chunks = number("chunk count", parts.next())?;
    let length = number("length", parts.next())?;
    if chunks == 0 || chunks > CHUNK_MAX {
        return Err(corrupt(format!(
            "the header entry names {chunks} chunks; 1 to {CHUNK_MAX} are allowed"
        )));
    }
    Ok((chunks, length))
}

/// Translates an error from the keychain into the engine's language.
///
/// The English sentences from `keyring` stand behind it as the reason: they name the system error,
/// and without it a locked keychain could not be told apart from a missing service.
fn translate(error: &keyring::Error, name: &str) -> VaultError {
    match error {
        keyring::Error::NoStorageAccess(_) => VaultError::Denied(error.to_string()),
        keyring::Error::NoEntry => VaultError::Corrupt {
            slot: name.to_owned(),
            reason: "the entry disappeared while it was being read".to_owned(),
        },
        keyring::Error::BadEncoding(_)
        | keyring::Error::BadDataFormat(..)
        | keyring::Error::BadStoreFormat(_)
        | keyring::Error::Ambiguous(_) => {
            VaultError::Corrupt { slot: name.to_owned(), reason: error.to_string() }
        }
        keyring::Error::TooLong(..) => VaultError::Denied(format!(
            "{error} — the folder client chunks from {CHUNK_BYTES} bytes on, and this entry was \
             still too long"
        )),
        keyring::Error::NoDefaultStore
        | keyring::Error::PlatformFailure(_)
        | keyring::Error::Invalid(..)
        | keyring::Error::NotSupportedByStore(_) => VaultError::NotReachable(error.to_string()),
        // `keyring::Error` is an open catalogue: a new version may add a cause. "Not reachable"
        // is then the statement that claims the least.
        _ => VaultError::NotReachable(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_names_the_chunk_count_and_the_length() {
        assert_eq!(read_header("f", b"edms-vault/1 3 4100").unwrap(), (3, 4100));
    }

    #[test]
    fn a_header_with_a_foreign_marker_is_corrupt_and_not_a_value() {
        let error = read_header("device-key", b"something else 1 2").unwrap_err();
        match &error {
            VaultError::Corrupt { slot, reason } => {
                assert_eq!(slot, "device-key");
                assert!(reason.contains("marker"), "{reason}");
            }
            other => panic!("expected `corrupt`, got: {other}"),
        }
    }

    #[test]
    fn a_header_without_numbers_is_corrupt() {
        assert!(read_header("f", b"edms-vault/1").is_err());
        assert!(read_header("f", b"edms-vault/1 two 3").is_err());
        assert!(read_header("f", b"edms-vault/1 2").is_err());
    }

    #[test]
    fn zero_chunks_and_too_many_chunks_are_corrupt() {
        assert!(read_header("f", b"edms-vault/1 0 0").is_err());
        let too_many = format!("{HEADER_MARKER} {} 1", CHUNK_MAX + 1);
        assert!(read_header("f", too_many.as_bytes()).is_err());
    }

    #[test]
    fn a_value_above_the_windows_limit_is_chunked_instead_of_truncated() {
        // The arithmetic the chunking rests on: no chunk is larger than the limit of the Windows
        // Credential Manager, and the sum is the whole value.
        let value = vec![7u8; LIMIT_WINDOWS * 3 + 11];
        let chunks: Vec<&[u8]> = value.chunks(CHUNK_BYTES).collect();
        assert!(chunks.len() > 1, "a value of this length does not fit into one entry");
        assert!(chunks.iter().all(|s| s.len() <= LIMIT_WINDOWS));
        assert_eq!(chunks.iter().map(|s| s.len()).sum::<usize>(), value.len());
        assert_eq!(value.len().div_ceil(CHUNK_BYTES), chunks.len());
    }

    #[test]
    fn a_missing_entry_is_not_an_error_but_none() {
        // Without a keychain (a build without a user profile, CI) the answer is "not reachable" —
        // and that must not be a `None` either, because that would mean "the slot is empty".
        let vault = SystemVault::with_service("de.elasticdms.folderclient.probe.empty");
        match vault.read("does-not-exist") {
            Ok(value) => assert_eq!(value, None),
            Err(VaultError::NotReachable(_) | VaultError::Denied(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
