//! The device key when a key store outside this process holds it — Secure Enclave, TPM.
//!
//! ADR-D12 puts this module here and not in `edms-crypto` and not in a crate of its own:
//!
//! * **Not in `edms-crypto`.** `crates/crypto/src/lib.rs` is `#![forbid(unsafe_code)]`, and every
//!   call of both platform APIs is `unsafe`.
//! * **Not in a crate of its own.** `edms-enclave` and `edms-winkeys` would cost eight edits in
//!   `crates/architecture-rules/tests/rules.rs` to arrive where the app already stands: it is the
//!   only crate that knows both a platform layer and `edms-crypto`, and the only process with a
//!   user identity that a key store hangs off (rule R7, and the header of `crate::vault`).
//! * **Not in the platform crates either, beyond the calls themselves.** Neither `edms-cfapi` nor
//!   `edms-fileprovider` may name `edms-crypto`, so neither can produce a
//!   [`edms_crypto::key::PublicKey`] or a [`edms_crypto::key::SigningKey`]. They hand over the
//!   platform's own bytes — a point and a signature — and this module makes a key out of them.
//!
//! ## The two conversions, and why they are not obvious
//!
//! 1. **The point.** Both stores hand out the public part as the coordinates, not as a JWK;
//!    [`edms_crypto::key::PublicKey::from_sec1`] takes the 65 bytes `04 || X || Y` and checks that
//!    they lie on P-256 — **at creation**, not at the first signature, so that a store that
//!    answers nonsense never becomes a device.
//! 2. **The signature.** macOS returns ASN.1 DER, Windows is reported to return the 64 bytes
//!    `r || s` that RFC 7518 §3.4 wants. Which of the two it is, the platform **says**
//!    ([`SignatureConversion`]) — a converter that decided by length would be wrong in exactly the
//!    case that is hardest to find, because a DER signature can be 69 bytes and a shorter one is
//!    possible in principle.
//!
//! ## What is here and what is not
//!
//! The seam is built and tested; the two platform calls behind it are **not built**
//! ([`of_this_platform`]). The parts of this feature that can be decided without hardware are the
//! two conversions and the fallback, and those are what stands here.

use std::sync::Arc;

use edms_crypto::CryptoError;
use edms_crypto::key::{PublicKey, SigningKey};
use edms_engine::{HardwareKeyStore, HeldKey};

/// How the bytes a key store hands back become the JOSE form, `r || s`.
///
/// There are exactly two of these and both stand in `edms-crypto`, which owns signature forms
/// (architecture rule R6): [`edms_crypto::key::signature_from_der`] for macOS'
/// `SecKeyCreateSignature`, and [`edms_crypto::key::signature_from_jose`] for Windows'
/// `NCryptSignHash`, which is reported to deliver the 64 bytes already. The platform crate names
/// its own; nothing here decides it by looking at the bytes.
pub type SignatureConversion = fn(&[u8]) -> Result<[u8; 64], CryptoError>;

/// A key that a platform key store holds, in the platform's own bytes.
///
/// The two implementations of this trait are the `unsafe` halves in `edms-cfapi` and
/// `edms-fileprovider`, adapted here. They know no JOSE, no JWK and no thumbprint — they know a
/// point and a signature.
pub trait PlatformKey: Send + Sync {
    /// The public part in SEC1 form: 65 bytes `04 || X || Y`.
    fn point(&self) -> &[u8];

    /// Signs the message. SHA-256 and the curve arithmetic happen inside the store.
    ///
    /// # Errors
    ///
    /// The store's own sentence. It reaches the caller as [`CryptoError::Sign`] and ends up in the
    /// diagnostic log of the call that wanted the signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// A key a platform key store has just made, and the handle that finds it again.
pub struct MadeKey {
    /// The key, in the platform's bytes.
    pub key: Box<dyn PlatformKey>,
    /// What names it in the store from now on — it goes into the vault slot as it stands.
    pub handle: String,
}

/// A key store of a platform, as the engine asks for it.
///
/// Two function pointers and a name: the platform crate supplies the two calls, this struct adds
/// the cryptography, and the engine sees only [`HardwareKeyStore`].
pub struct PlatformKeyStore {
    /// Goes into the vault slot as a stored value — see [`edms_engine::HardwareKeyStore::name`].
    name: &'static str,
    /// How this store's signature bytes become the JOSE form.
    convert: SignatureConversion,
    /// Creates the key in the store and hands back the handle that finds it again.
    create: fn() -> Result<MadeKey, String>,
    /// Opens the key a handle names.
    open: fn(&str) -> Result<Box<dyn PlatformKey>, String>,
}

impl PlatformKeyStore {
    /// The store under `name`, served by the two calls of a platform crate.
    const fn new(
        name: &'static str,
        convert: SignatureConversion,
        create: fn() -> Result<MadeKey, String>,
        open: fn(&str) -> Result<Box<dyn PlatformKey>, String>,
    ) -> Self {
        Self { name, convert, create, open }
    }
}

impl HardwareKeyStore for PlatformKeyStore {
    fn name(&self) -> &'static str {
        self.name
    }

    fn create(&self) -> Result<HeldKey, String> {
        let made = (self.create)()?;
        Ok(HeldKey { key: signing_key(made.key, self.convert)?, handle: made.handle })
    }

    fn open(&self, handle: &str) -> Result<Arc<dyn SigningKey>, String> {
        signing_key((self.open)(handle)?, self.convert)
    }
}

/// Makes a [`SigningKey`] out of a key the platform holds.
///
/// The point is read here and not at the first signature: a store that hands out something that is
/// no point on P-256 would otherwise enrol a device whose every proof the server rejects, and the
/// error would surface a day later and somewhere else.
fn signing_key(
    key: Box<dyn PlatformKey>,
    convert: SignatureConversion,
) -> Result<Arc<dyn SigningKey>, String> {
    let public = PublicKey::from_sec1(key.point()).map_err(|error| error.to_string())?;
    Ok(Arc::new(StoredKey { key, public, convert }))
}

/// A key in a store outside this process, as the rest of the house sees it.
struct StoredKey {
    key: Box<dyn PlatformKey>,
    /// Read once at creation, so that [`SigningKey::public`] can promise instead of asking.
    public: PublicKey,
    convert: SignatureConversion,
}

impl SigningKey for StoredKey {
    fn public(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign(&self, data: &[u8]) -> Result<[u8; 64], CryptoError> {
        let raw = self.key.sign(data).map_err(CryptoError::Sign)?;
        (self.convert)(&raw)
    }
}

/// The key store of this platform, when this build reaches one.
///
/// **Not built, and the two reasons are different.** On both platforms the machine has a store and
/// this build does not reach it, so what comes back here is a store that refuses with the sentence
/// naming why — which is exactly the loud fallback of ADR-D12 §3, and on this machine today it is
/// also the truth. On a target that is neither Windows nor macOS there is nothing to ask, and
/// `None` says that instead of inventing a refusal.
pub fn of_this_platform() -> Option<Box<dyn HardwareKeyStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(PlatformKeyStore::new(
            secure_enclave::NAME,
            edms_crypto::key::signature_from_der,
            secure_enclave::create,
            secure_enclave::open,
        )))
    }
    #[cfg(windows)]
    {
        Some(Box::new(PlatformKeyStore::new(
            platform_crypto_provider::NAME,
            edms_crypto::key::signature_from_jose,
            platform_crypto_provider::create,
            platform_crypto_provider::open,
        )))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        None
    }
}

/// macOS: the Secure Enclave through `Security.framework`.
#[cfg(target_os = "macos")]
mod secure_enclave {
    use super::{MadeKey, PlatformKey};

    /// The name of the store, as it stands in the vault slot.
    ///
    /// A **stored** value: it is written into the operating system's keychain and read back from
    /// there, so a rename would make an installed workstation's device key slot unreadable.
    pub const NAME: &str = "secure-enclave";

    /// Why this build reaches no enclave key.
    ///
    /// Both halves were measured (ADR-D12, measurements 1 and 2): an **ephemeral** enclave key
    /// creates, signs 2000 times without a prompt and refuses to be exported — but
    /// `kSecAttrIsPermanent = true` answered `-34018` in six configurations, because the process
    /// has no keychain access group at all, and the entitlement that would give it one gets the
    /// process SIGKILLed at exec without an embedded provisioning profile. Whether a Developer ID
    /// profile lifts that is open: none was available to test with.
    const NOT_REACHED: &str = "the Secure Enclave is not reached by this build: the platform half \
                              (`edms_fileprovider::device_key`) is not implemented, and a \
                              permanent enclave key additionally needs the entitlement \
                              `keychain-access-groups` and an embedded provisioning profile \
                              (ADR-D12)";

    /// Would create the key in the enclave.
    pub fn create() -> Result<MadeKey, String> {
        Err(NOT_REACHED.to_owned())
    }

    /// Would open the key an application tag names.
    pub fn open(_handle: &str) -> Result<Box<dyn PlatformKey>, String> {
        Err(NOT_REACHED.to_owned())
    }
}

/// Windows: the TPM through CNG's `Microsoft Platform Crypto Provider`.
#[cfg(windows)]
mod platform_crypto_provider {
    use super::{MadeKey, PlatformKey};

    /// The name of the store, as it stands in the vault slot.
    ///
    /// A **stored** value, like its counterpart on macOS: it is written into the Windows
    /// Credential Manager and read back from there, so a rename would make an installed
    /// workstation's device key slot unreadable.
    pub const NAME: &str = "tpm";

    /// Why this build reaches no TPM key.
    ///
    /// The full CNG sequence compiles clean for `x86_64-pc-windows-msvc` against
    /// `windows =0.58.0`, and needs no entitlement, no manifest and no package identity — it is
    /// the cheaper of the two platforms. What is missing is the platform half itself, and every
    /// runtime claim about it is **unproven**: no Windows machine has run any of it (ADR-D12,
    /// measurement 6).
    const NOT_REACHED: &str = "the TPM is not reached by this build: the platform half \
                              (`edms_cfapi::device_key`) is not implemented (ADR-D12)";

    /// Would create the key in the TPM.
    pub fn create() -> Result<MadeKey, String> {
        Err(NOT_REACHED.to_owned())
    }

    /// Would open the key a CNG key name names.
    pub fn open(_handle: &str) -> Result<Box<dyn PlatformKey>, String> {
        Err(NOT_REACHED.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use edms_crypto::key::{signature_from_der, signature_from_jose};

    use super::*;

    /// The public part of the key from RFC 7515 appendix A.3 in SEC1 form, as a key store hands it
    /// out: `04 || X || Y`.
    const A3_POINT: &str = "047fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445\
                            c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad";

    /// A signature of that key over [`MESSAGE`], in DER — 69 bytes, the case in which DER writes
    /// `r` in 31 bytes. It is the same vector `edms-crypto` holds, and it stands here a second
    /// time because that is the point: this crate must get the whole way through it without
    /// knowing the curve.
    const A3_DER: &str = "3043021f67f11c8b19e9a79e681706d9fded6e0835640d84d1bd8c27003a2843c21522\
                          0220403ee997186f1c2b2cb955f590933ac51c9912ebd64622465fd68f5ebbd67668";

    /// The same signature in the form a Windows store is reported to hand back.
    const A3_JOSE: &str = "0067f11c8b19e9a79e681706d9fded6e0835640d84d1bd8c27003a2843c21522\
                           403ee997186f1c2b2cb955f590933ac51c9912ebd64622465fd68f5ebbd67668";

    /// The message those two signatures were made over.
    const MESSAGE: &[u8] = b"edms-d12 vector 1010";

    fn from_hex(text: &str) -> Vec<u8> {
        let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(digits.len() % 2, 0, "an odd number of hex digits");
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).unwrap())
            .collect()
    }

    /// A key store that answers with bytes handed to it — the platform half, without a platform.
    struct Double {
        point: Vec<u8>,
        signature: Vec<u8>,
    }

    impl PlatformKey for Double {
        fn point(&self) -> &[u8] {
            &self.point
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
            assert_eq!(message, MESSAGE, "the store signs the message, not a digest of ours");
            Ok(self.signature.clone())
        }
    }

    fn key_with(convert: SignatureConversion, signature: &str) -> Arc<dyn SigningKey> {
        let double = Double { point: from_hex(A3_POINT), signature: from_hex(signature) };
        signing_key(Box::new(double), convert).expect("the point of A.3 lies on P-256")
    }

    #[test]
    fn a_der_signature_from_the_store_is_one_the_verifier_of_edms_crypto_takes() {
        // The whole way in one test: 65 bytes point and 69 bytes DER go in, a public key and 64
        // bytes `r || s` come out, and the signature holds against them.
        let key = key_with(signature_from_der, A3_DER);
        let signature = key.sign(MESSAGE).unwrap();
        key.public().check(MESSAGE, &signature).unwrap();
        assert_eq!(signature.to_vec(), from_hex(A3_JOSE));
    }

    #[test]
    fn the_64_byte_form_is_passed_on_unchanged() {
        let key = key_with(signature_from_jose, A3_JOSE);
        let signature = key.sign(MESSAGE).unwrap();
        key.public().check(MESSAGE, &signature).unwrap();
    }

    #[test]
    fn the_two_forms_of_the_same_signature_say_the_same_thing() {
        assert_eq!(
            key_with(signature_from_der, A3_DER).sign(MESSAGE).unwrap(),
            key_with(signature_from_jose, A3_JOSE).sign(MESSAGE).unwrap()
        );
    }

    #[test]
    fn the_form_is_said_and_never_guessed_from_the_length() {
        // The DER bytes read as the JOSE form would be a proof the server refuses with
        // `invalid_dpop_proof`, and nothing would point at the conversion. Both the wrong way
        // round are refused instead of being padded or cut.
        let der_as_jose = key_with(signature_from_jose, A3_DER).sign(MESSAGE);
        assert!(matches!(der_as_jose, Err(CryptoError::Sign(_))), "{der_as_jose:?}");
        let jose_as_der = key_with(signature_from_der, A3_JOSE).sign(MESSAGE);
        assert!(matches!(jose_as_der, Err(CryptoError::Sign(_))), "{jose_as_der:?}");
    }

    #[test]
    fn a_point_that_is_no_point_is_refused_at_creation_and_not_at_the_first_signature() {
        // A device whose public part nobody can verify against would enrol, wait for an
        // administrator and then fail at every call. This has to be caught where the key is made.
        let mut bent = from_hex(A3_POINT);
        bent[64] ^= 0x01;
        for point in [Vec::new(), vec![0x04], bent] {
            let double = Double { point, signature: from_hex(A3_DER) };
            let refused = signing_key(Box::new(double), signature_from_der);
            assert!(refused.is_err(), "a point that is none got through");
        }
    }

    #[test]
    fn a_store_that_refuses_says_why_and_the_sentence_reaches_the_report() {
        // The loud fallback of ADR-D12 §3, as far as this crate can prove it: whatever
        // `of_this_platform` hands back, the answer is either "there is nothing to ask on this
        // platform" or a whole sentence naming what is missing.
        #[cfg(not(any(target_os = "macos", windows)))]
        assert!(of_this_platform().is_none(), "there is nothing to ask on this platform");
        #[cfg(any(target_os = "macos", windows))]
        {
            let store = of_this_platform().expect("both platforms have a store");
            assert!(!store.name().is_empty() && !store.name().contains(' '));
            let reason = store.create().err().expect("not built, so it has to refuse");
            assert!(reason.contains("ADR-D12"), "{reason}");
            assert!(reason.contains("not reached by this build"), "{reason}");
            let reason = store.open("any").err().expect("not built, so it has to refuse");
            assert!(reason.contains("ADR-D12"), "{reason}");
        }
    }

    #[test]
    fn the_name_of_a_store_is_a_stored_value_and_stays_what_it_is() {
        // It is written into the keychain and read back there; a rename would make an installed
        // workstation's device key slot unreadable.
        #[cfg(target_os = "macos")]
        assert_eq!(secure_enclave::NAME, "secure-enclave");
        #[cfg(windows)]
        assert_eq!(platform_crypto_provider::NAME, "tpm");
    }
}
