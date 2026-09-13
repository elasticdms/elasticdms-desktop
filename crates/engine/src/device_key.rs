//! Where the private device key lies — and the fallback that says which of the two it is.
//!
//! The device key is the one a human being approves: its RFC 7638 thumbprint is
//! `device.key_thumbprint` in the counterpart's schema, and until an administrator has compared it
//! out of band every token request is answered `403 device-pending-approval`. It lies in the
//! operating system's keychain as PKCS#8 DER — it can be read, and therefore copied. That is the
//! whole reason the counterpart calls the tier `SOFTWARE`.
//!
//! ADR-D12 settles what a key store outside this process changes about that, and what it does
//! not:
//!
//! 1. **One seam, the one that is already there.** [`edms_crypto::key::SigningKey`]. A key in a
//!    Secure Enclave or in a TPM is a second implementation of it, and everything above
//!    ([`edms_net`]'s DPoP proof, the client assertion) does not learn where the key lies.
//! 2. **Nothing changes on the wire.** The enrolment body keeps `attestation` at
//!    `{"type": "none", "available": false}`; the counterpart's three tiers are all defined over
//!    the Google attestation root (geraete-auth §3.1.1), so neither an Apple nor a Microsoft key
//!    reaches one of them. The device stays `SOFTWARE` and still waits for a person. What is
//!    bought is one property and no more: the private part cannot be copied off the machine.
//! 3. **The fallback is never silent.** Absent or refusing hardware falls back to
//!    [`edms_crypto::key::SoftwareKey`] — a workstation whose TPM is switched off in firmware
//!    must still reach the archive — but [`DeviceKeyOrigin`] says in `doctor` and in the
//!    diagnostic log which of the four cases holds. A silent downgrade would be worse than
//!    refusing to run, because the property that was bought would be gone and nobody would know
//!    which machines still had it.
//! 4. **An installed workstation keeps its key.** A hardware key cannot be an import of the
//!    existing one (macOS refuses imports outright; a TPM key has no PKCS#8 at all), so the move
//!    would be a new key pair, a new thumbprint and a second trip to an administrator — and the
//!    counterpart has no endpoint that rotates a device key. Hardware therefore on new enrolments
//!    only, never as an upgrade at start-up.
//!
//! The platform half is **not** here and not in the engine at all: `edms_cfapi` and
//! `edms_fileprovider` speak to CNG and to Security.framework (architecture rules R4 and R5), the
//! app joins the two sides and hands an implementation of [`HardwareKeyStore`] down. The engine
//! only ever asks.

use std::sync::Arc;

use edms_crypto::key::{SigningKey, SoftwareKey};

use crate::error::EngineError;
use crate::vault::{SLOT_DEVICE_KEY, Vault, VaultError};

/// The marker of a device key slot that holds no key but the handle of one.
///
/// Version in the marker, in the spirit of the vault's own `edms-vault/1`: a later format
/// recognises the old entry instead of reading it as garbage. The value is written into the
/// operating system's keychain, so it is a stored value and renaming it would make an installed
/// workstation's slot unreadable.
const HARDWARE_MARKER: &str = "edms-hardware-key/1";

/// Where the private part of the device key lies — and, when it is not in hardware, why not.
///
/// Four cases, and each of them a whole statement. `doctor` prints one row from this and the
/// diagnostic log one line; there is deliberately no sentence for the person at the machine
/// (ADR-D12 §4): a warning nobody can act on is noise, and the operator surface carries it
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceKeyOrigin {
    /// PKCS#8 in the operating system's keychain. No key store outside this process was asked —
    /// this build has none for this platform.
    Keychain,

    /// PKCS#8 in the keychain, because the key store refused. The sentence names which check.
    KeychainAfterRefusal(String),

    /// PKCS#8 in the keychain, because that is what this device enrolled with; this build carries
    /// a store for this platform and deliberately did not ask it (ADR-D12 §5). A hardware key
    /// would be a second thumbprint, and the administrator would not know which one they
    /// approved.
    KeychainFromEnrollment(&'static str),

    /// The private part was created in the named store and never left it.
    Hardware(&'static str),
}

impl DeviceKeyOrigin {
    /// The row for `doctor`, English and not out of the text catalogue (`crate::report`).
    pub fn row(&self) -> String {
        match self {
            Self::Keychain => {
                "software (keychain, PKCS#8 — readable and therefore copyable)".to_owned()
            }
            Self::KeychainAfterRefusal(reason) => {
                format!("software (keychain); the hardware key store refused: {reason}")
            }
            // Not "`{store}` is available": nothing on this path asked the store anything. The
            // only probe there is sits inside `create`, and ADR-D12 §5 forbids calling that for a
            // device that already holds a key. What is known is that this build carries a store
            // for this platform — and on both platforms today it is one that refuses.
            Self::KeychainFromEnrollment(store) => format!(
                "software (keychain); this device enrolled with the software key and a change of \
                 key is a re-enrolment — `{store}` is in this build and was not asked"
            ),
            Self::Hardware(store) => {
                format!("`{store}` (the private part was never outside it)")
            }
        }
    }

    /// Whether the private part of the device key can be read off this machine.
    pub const fn copyable(&self) -> bool {
        !matches!(self, Self::Hardware(_))
    }
}

/// A device key the platform holds, together with what finds it again.
pub struct HeldKey {
    /// Signs; the private part stays in the store.
    pub key: Arc<dyn SigningKey>,
    /// What names the key in the store on the next start — the CNG key name on Windows, the
    /// application tag on macOS. It goes into the vault slot as it stands, so it carries no line
    /// break and no leading space.
    pub handle: String,
}

/// A key store outside this process — the Secure Enclave on macOS, the TPM through CNG on
/// Windows.
///
/// The engine asks it in exactly two places and never anywhere else: once when the device key slot
/// is empty ([`HardwareKeyStore::create`]), and once per start when the slot names a handle
/// ([`HardwareKeyStore::open`]).
///
/// **Failure is a sentence, not a variant.** Both methods refuse with a whole English sentence
/// that names *which* pre-flight check said no, because that sentence is the payload: it is what
/// `doctor` prints and what somebody pastes into a ticket. An error catalogue here would mean an
/// engine that knows the names of Windows error codes.
pub trait HardwareKeyStore: Send + Sync {
    /// Which store this is: `secure-enclave`, `tpm`.
    ///
    /// A stable token without spaces — it is written into the vault slot and read back there, so
    /// it is a stored value like the slot's own marker and not a label anybody may reword.
    fn name(&self) -> &'static str;

    /// Creates the device key of this workstation in the store.
    ///
    /// # Errors
    ///
    /// The sentence naming which check refused. The engine then falls back to a software key —
    /// this is never an abort, because a workstation whose hardware says no still has to reach the
    /// archive.
    fn create(&self) -> Result<HeldKey, String>;

    /// Opens the key the handle names.
    ///
    /// # Errors
    ///
    /// The sentence naming why the key is not there. The engine turns that into
    /// [`VaultError::Corrupt`] and **not** into a fresh key: a hardware key dies with its
    /// hardware, and a device that quietly made itself a new one would enrol a thumbprint nobody
    /// approved.
    fn open(&self, handle: &str) -> Result<Arc<dyn SigningKey>, String>;
}

/// What stands in the device key slot.
#[derive(Debug, PartialEq, Eq)]
enum Slot<'a> {
    /// The private key itself, PKCS#8 DER — the form of every installation up to now.
    Pkcs8,
    /// The handle of a key in the named store.
    Hardware {
        /// [`HardwareKeyStore::name`], as it was written.
        store: &'a str,
        /// [`HeldKey::handle`], as it was written.
        handle: &'a str,
    },
    /// Something that begins like a marker and is none; the sentence says what is missing.
    Unreadable(String),
}

/// Reads the device key slot without guessing.
///
/// The two forms cannot be confused: PKCS#8 DER is an ASN.1 `SEQUENCE` and therefore begins with
/// `0x30`, the marker with the letter `e` (`0x65`). So an installed workstation's slot reads as it
/// always did, and no version check is needed to get that far.
fn read_slot(raw: &[u8]) -> Slot<'_> {
    let Ok(text) = std::str::from_utf8(raw) else { return Slot::Pkcs8 };
    let Some(rest) = text.strip_prefix(HARDWARE_MARKER) else { return Slot::Pkcs8 };
    let mut parts = rest.strip_prefix(' ').unwrap_or(rest).splitn(2, ' ');
    match (parts.next(), parts.next()) {
        (Some(store), Some(handle)) if !store.is_empty() && !handle.is_empty() => {
            Slot::Hardware { store, handle }
        }
        _ => Slot::Unreadable(format!(
            "the slot carries the marker `{HARDWARE_MARKER}` but no store and handle behind it"
        )),
    }
}

/// The content of the slot for a key the store holds.
fn marker_for(store: &str, handle: &str) -> Result<String, EngineError> {
    if store.is_empty() || store.contains(' ') {
        return Err(EngineError::Internal(format!(
            "the key store calls itself `{store}`; the name is written into the vault slot and \
             must be one word"
        )));
    }
    if handle.is_empty() || handle.contains('\n') || handle.starts_with(' ') {
        return Err(EngineError::Internal(format!(
            "the key store returned the handle `{handle}`; it is written into the vault slot and \
             must be one line without a leading space"
        )));
    }
    Ok(format!("{HARDWARE_MARKER} {store} {handle}"))
}

/// Settles the device key of this workstation — once in its life, and then on every start again
/// the same one.
///
/// The order is the one ADR-D12 §5 asks for and the reason is in every branch: what stands in the
/// slot wins, and hardware is asked only for a device that has none yet.
///
/// # Errors
///
/// When the vault is not reachable, when the slot holds something unreadable (then **nothing** is
/// generated anew — a new device key is a different device and ends in `409 device-id-conflict`),
/// or when no key can be produced.
pub(crate) fn settle(
    vault: &mut dyn Vault,
    hardware: Option<&dyn HardwareKeyStore>,
) -> Result<(Arc<dyn SigningKey>, DeviceKeyOrigin), EngineError> {
    let corrupt = |reason: String| {
        EngineError::Vault(VaultError::Corrupt { slot: SLOT_DEVICE_KEY.to_owned(), reason })
    };
    if let Some(raw) = vault.read(SLOT_DEVICE_KEY)? {
        return match read_slot(&raw) {
            Slot::Pkcs8 => {
                let key = SoftwareKey::from_pkcs8_der(&raw).map_err(|error| {
                    // No quiet fresh start: a new device key would be a different device, and the
                    // server would answer the enrolment with `409 device-id-conflict` (T5) — with
                    // a message nobody traces back to a broken slot in the keychain.
                    corrupt(error.to_string())
                })?;
                let origin = match hardware {
                    Some(store) => DeviceKeyOrigin::KeychainFromEnrollment(store.name()),
                    None => DeviceKeyOrigin::Keychain,
                };
                Ok((Arc::new(key) as Arc<dyn SigningKey>, origin))
            }
            Slot::Hardware { store, handle } => {
                let held = hardware.ok_or_else(|| {
                    corrupt(format!(
                        "the key of this device lies in `{store}`, and this program has no such \
                         store on this platform"
                    ))
                })?;
                if held.name() != store {
                    return Err(corrupt(format!(
                        "the key of this device lies in `{store}`, and this program has `{}`",
                        held.name()
                    )));
                }
                let key = held.open(handle).map_err(corrupt)?;
                Ok((key, DeviceKeyOrigin::Hardware(held.name())))
            }
            Slot::Unreadable(reason) => Err(corrupt(reason)),
        };
    }

    // From here on the device has no key at all — the only moment at which hardware may be taken,
    // because this is the only moment at which no thumbprint has been approved yet.
    if let Some(store) = hardware {
        match store.create() {
            Ok(held) => {
                // If the vault does not take the marker, the key stays behind in the store with
                // nothing pointing at it, and the start fails. That is the right way round: a
                // keychain that cannot write means this workstation cannot keep a device at all,
                // and an orphan in the TPM costs one key slot — a device whose handle nobody wrote
                // down would cost a re-enrolment.
                let marker = marker_for(store.name(), &held.handle)?;
                vault.write(SLOT_DEVICE_KEY, marker.as_bytes())?;
                return Ok((held.key, DeviceKeyOrigin::Hardware(store.name())));
            }
            Err(reason) => {
                let key = software_key(vault)?;
                return Ok((key, DeviceKeyOrigin::KeychainAfterRefusal(reason)));
            }
        }
    }
    Ok((software_key(vault)?, DeviceKeyOrigin::Keychain))
}

/// A fresh software key in the slot.
fn software_key(vault: &mut dyn Vault) -> Result<Arc<dyn SigningKey>, EngineError> {
    let key = SoftwareKey::generate()?;
    vault.write(SLOT_DEVICE_KEY, key.as_pkcs8_der()?.as_ref())?;
    Ok(Arc::new(key) as Arc<dyn SigningKey>)
}

#[cfg(test)]
mod tests {
    use edms_crypto::CryptoError;
    use edms_crypto::key::PublicKey;

    use super::*;
    use crate::vault::StoreVault;

    /// A store that hands out a software key and calls it hardware — enough to drive every branch
    /// here, because the engine only ever asks for something that signs.
    struct Enclave {
        name: &'static str,
        refusal: Option<String>,
        handle: String,
    }

    impl Enclave {
        fn ready() -> Self {
            Self { name: "secure-enclave", refusal: None, handle: "de.elasticdms.device/1".into() }
        }

        fn refusing(reason: &str) -> Self {
            Self { refusal: Some(reason.to_owned()), ..Self::ready() }
        }
    }

    impl HardwareKeyStore for Enclave {
        fn name(&self) -> &'static str {
            self.name
        }

        fn create(&self) -> Result<HeldKey, String> {
            match &self.refusal {
                Some(reason) => Err(reason.clone()),
                None => Ok(HeldKey {
                    key: Arc::new(SoftwareKey::generate().map_err(|e| e.to_string())?),
                    handle: self.handle.clone(),
                }),
            }
        }

        fn open(&self, handle: &str) -> Result<Arc<dyn SigningKey>, String> {
            if handle != self.handle {
                return Err(format!("`{handle}` names no key in this store"));
            }
            match &self.refusal {
                Some(reason) => Err(reason.clone()),
                None => Ok(Arc::new(SoftwareKey::generate().map_err(|e| e.to_string())?)),
            }
        }
    }

    #[test]
    fn without_a_store_the_device_gets_a_software_key_as_it_always_did() {
        let mut vault = StoreVault::new();
        let (key, origin) = settle(&mut vault, None).unwrap();
        assert_eq!(origin, DeviceKeyOrigin::Keychain);
        assert!(origin.copyable());
        // The slot really holds the key and not a marker, so an older version reads it too.
        let raw = vault.read(SLOT_DEVICE_KEY).unwrap().unwrap();
        assert_eq!(read_slot(&raw), Slot::Pkcs8);
        assert_eq!(SoftwareKey::from_pkcs8_der(&raw).unwrap().public(), key.public());
    }

    #[test]
    fn a_store_that_answers_puts_the_handle_into_the_slot_and_no_private_bytes() {
        let store = Enclave::ready();
        let mut vault = StoreVault::new();
        let (key, origin) = settle(&mut vault, Some(&store)).unwrap();
        assert_eq!(origin, DeviceKeyOrigin::Hardware("secure-enclave"));
        assert!(!origin.copyable(), "that is the whole point of the exercise");
        let raw = vault.read(SLOT_DEVICE_KEY).unwrap().unwrap();
        assert_eq!(
            read_slot(&raw),
            Slot::Hardware { store: "secure-enclave", handle: "de.elasticdms.device/1" }
        );
        // The key signs, and the signature holds against the public part it hands out.
        let signature = key.sign(b"proof").unwrap();
        key.public().check(b"proof", &signature).unwrap();
    }

    #[test]
    fn a_store_that_refuses_hands_the_reason_on_instead_of_stopping_the_start() {
        let store = Enclave::refusing("Tbsi_GetDeviceInfo: TBS_E_TPM_NOT_FOUND");
        let mut vault = StoreVault::new();
        let (_, origin) = settle(&mut vault, Some(&store)).unwrap();
        match &origin {
            DeviceKeyOrigin::KeychainAfterRefusal(reason) => {
                assert!(reason.contains("TBS_E_TPM_NOT_FOUND"), "{reason}");
            }
            other => panic!("expected the refusal, got {other:?}"),
        }
        // Loud, not silent: the row names the store's own sentence.
        assert!(origin.row().contains("TBS_E_TPM_NOT_FOUND"), "{}", origin.row());
        assert_eq!(read_slot(&vault.read(SLOT_DEVICE_KEY).unwrap().unwrap()), Slot::Pkcs8);
    }

    #[test]
    fn an_enrolled_device_keeps_its_software_key_even_where_a_store_stands_ready() {
        // ADR-D12 §5: two keys are two thumbprints, and the administrator would not know which
        // one they approved. The row names the store and says it was not asked.
        let store = Enclave::ready();
        let mut vault = StoreVault::new();
        let (first, _) = settle(&mut vault, None).unwrap();
        let (second, origin) = settle(&mut vault, Some(&store)).unwrap();
        assert_eq!(second.public(), first.public(), "the same device, the same thumbprint");
        assert_eq!(origin, DeviceKeyOrigin::KeychainFromEnrollment("secure-enclave"));
        assert!(origin.row().contains("re-enrolment"), "{}", origin.row());
        // And it may not say the store is available: `settle` took this branch off
        // `hardware.is_some()` and asked the store nothing. On this Mac the sentence would be
        // false — `of_this_platform` hands over an enclave that refuses every call.
        assert!(!origin.row().contains("is available"), "{}", origin.row());
    }

    #[test]
    fn a_handle_whose_key_is_gone_is_corrupt_and_never_a_new_device() {
        // The residual risk of ADR-D12 named as a test: a TPM clear, a reimage, a new mainboard.
        // What follows is a re-enrolment by a person, not a key this program made up for itself.
        let mut vault = StoreVault::new();
        vault
            .write(SLOT_DEVICE_KEY, b"edms-hardware-key/1 secure-enclave de.elasticdms.device/1")
            .unwrap();
        let gone = Enclave { handle: "another".into(), ..Enclave::ready() };
        let error =
            settle(&mut vault, Some(&gone)).map(|_| ()).expect_err("a lost key is no fresh start");
        assert!(matches!(error, EngineError::Vault(VaultError::Corrupt { .. })), "{error}");
    }

    #[test]
    fn a_handle_without_a_store_on_this_platform_is_corrupt_and_not_a_software_key() {
        let mut vault = StoreVault::new();
        vault.write(SLOT_DEVICE_KEY, b"edms-hardware-key/1 tpm edms/device-key/1").unwrap();
        for store in [None, Some(&Enclave::ready() as &dyn HardwareKeyStore)] {
            let error = settle(&mut vault, store).map(|_| ()).expect_err("no store, no key");
            assert!(matches!(error, EngineError::Vault(VaultError::Corrupt { .. })), "{error}");
        }
    }

    #[test]
    fn an_unreadable_slot_stays_unreadable_in_both_forms() {
        for content in [
            &b"not PKCS#8"[..],
            b"edms-hardware-key/1",
            b"edms-hardware-key/1 tpm",
            b"edms-hardware-key/1  handle-without-a-store",
        ] {
            let mut vault = StoreVault::new();
            vault.write(SLOT_DEVICE_KEY, content).unwrap();
            let error = settle(&mut vault, Some(&Enclave::ready()))
                .map(|_| ())
                .expect_err("something unreadable is no occasion for a new device");
            assert!(matches!(error, EngineError::Vault(VaultError::Corrupt { .. })), "{error}");
        }
    }

    #[test]
    fn the_two_forms_of_the_slot_cannot_be_confused_with_one_another() {
        // PKCS#8 DER is an ASN.1 SEQUENCE: 0x30 first, never the letter `e`. That is why reading
        // the slot needs no version and no guess.
        let der = SoftwareKey::generate().unwrap().as_pkcs8_der().unwrap();
        assert_eq!(der.first(), Some(&0x30));
        assert_eq!(read_slot(&der), Slot::Pkcs8);
        assert_eq!(HARDWARE_MARKER.as_bytes().first(), Some(&b'e'));
    }

    #[test]
    fn a_store_name_or_handle_that_would_not_survive_the_slot_is_a_bug_and_says_so() {
        assert!(marker_for("secure-enclave", "de.elasticdms.device/1").is_ok());
        for (store, handle) in [
            ("secure enclave", "tag"),
            ("", "tag"),
            ("tpm", ""),
            ("tpm", " tag"),
            ("tpm", "two\nlines"),
        ] {
            assert!(
                matches!(marker_for(store, handle), Err(EngineError::Internal(_))),
                "`{store}` / `{handle}` got through"
            );
        }
    }

    #[test]
    fn the_engine_takes_whatever_signs_and_asks_no_further() {
        // The seam, stated as a test: `settle` hands back `Arc<dyn SigningKey>`, and what the
        // proof above it needs is the public part and 64 bytes. A key that signs wrongly is
        // caught by the verifier of edms-crypto, not by a type.
        struct Broken;
        impl SigningKey for Broken {
            fn public(&self) -> PublicKey {
                SoftwareKey::generate().expect("randomness").public()
            }

            fn sign(&self, _: &[u8]) -> Result<[u8; 64], CryptoError> {
                Ok([7u8; 64])
            }
        }
        let key: Arc<dyn SigningKey> = Arc::new(Broken);
        let signature = key.sign(b"x").unwrap();
        assert!(key.public().check(b"x", &signature).is_err());
    }

    #[test]
    fn the_key_bundle_takes_the_hardware_key_for_the_device_and_a_software_key_for_the_session() {
        // ADR-D12 §8: the device key signs about once every 25 seconds (the delivery long poll),
        // the session key signs a DPoP proof on every single call. 4.660 ms per signature,
        // measured in the Secure Enclave, is invisible in the first place and would stand in
        // front of every listing and every hydration in the second.
        use edms_net::{KeyBinding, KeySource};

        let mut state = edms_store::Store::in_memory().unwrap();
        let enclave = Enclave::ready();
        let bundle = crate::session::KeyBundle::set_up(
            Box::new(StoreVault::new()),
            &mut state,
            Some(&enclave),
        )
        .unwrap();
        assert_eq!(*bundle.device_key_origin(), DeviceKeyOrigin::Hardware("secure-enclave"));
        let device = bundle.key(KeyBinding::Device).unwrap().public().thumbprint();
        let session = bundle.key(KeyBinding::Session).unwrap().public().thumbprint();
        assert_ne!(device, session, "two keys, two jobs (03 §6.0.9)");
        // The public part of a key in hardware travels as an ordinary JWK: the enrolment body
        // does not change, and the counterpart has no field that could carry the difference
        // (ADR-D12 §7).
        assert_eq!(
            bundle.public_jwk().x,
            bundle.key(KeyBinding::Device).unwrap().public().jwk().x()
        );
    }
}
