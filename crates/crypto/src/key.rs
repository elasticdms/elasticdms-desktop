//! Keys: the device key, its public part as a JWK, the RFC 7638 thumbprint.
//!
//! **One curve, one procedure.** [`Jwk`] knows only `kty: "EC"` and `crv: "P-256"`; a type that
//! admitted other curves would turn “is this really ES256?” into a runtime question at every
//! call site instead of a promise made by the type (escan `Jwk`).
//!
//! **Signatures in JOSE form.** [`SigningKey::sign`] delivers `r || s` with 32 bytes each, not
//! DER. That difference is the most frequent cause of an `invalid_dpop_proof` that looks like a
//! key problem (geraete-auth §5.5, pitfall 1). A key store outside this process does not
//! necessarily hand back that form, so the two conversions it needs stand here and nowhere else:
//! [`signature_from_der`] and [`PublicKey::from_sec1`] (ADR-D12).
//!
//! **The private part leaves this crate only as PKCS#8** — for the operating system's keychain
//! (ADR-D03: secrets never in SQLite). A key that never leaves its hardware has no PKCS#8 at all;
//! it is an implementation of [`SigningKey`] and not of [`SoftwareKey`]. `Debug` shows the
//! thumbprint and nothing else.

use std::fmt;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey as P256SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::{FieldBytes, Sec1Point};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

pub use p256::elliptic_curve::zeroize::Zeroizing;

use crate::CryptoError;
use crate::encoding::{b64u, from_b64u, sha256};

/// Length of a coordinate and of a scalar on P-256, in bytes.
const COORDINATE: usize = 32;

/// This many times a random scalar is drawn before giving up. One failed attempt has a
/// probability of about 2^-32; eight in a row mean that the randomness is broken.
const GENERATION_ATTEMPT: usize = 8;

/// A key that signs ES256. The private part may sit in memory, in the keychain or in a Secure
/// Enclave — all that counts here is that it signs bytes.
pub trait SigningKey: Send + Sync {
    /// The public part. Goes as `jwk` into every DPoP proof.
    fn public(&self) -> PublicKey;

    /// ES256 over `data`: SHA-256, then ECDSA on P-256, result `r || s` (64 bytes).
    fn sign(&self, data: &[u8]) -> Result<[u8; 64], CryptoError>;
}

/// Reads an ECDSA signature in ASN.1 DER form and hands it back in JOSE form, `r || s`.
///
/// For implementations of [`SigningKey`] whose key store returns the other form. macOS'
/// `SecKeyCreateSignature` does: it hands back `SEQUENCE { INTEGER r, INTEGER s }` (Windows'
/// `NCryptSignHash` is reported to return the 64 bytes directly, so that side needs this
/// function).
///
/// **Why this is not a matter of dropping a leading byte.** Measured on macOS 26.6 over 2000
/// signatures of one message with one Secure Enclave key, the DER was 69 bytes 3 times, 70 bytes
/// 497 times, 71 bytes 997 times and 72 bytes 503 times (ADR-D12, measurement 4). DER writes an
/// INTEGER in as few bytes as it can and prefixes `0x00` when the top bit would make it negative,
/// so `r` and `s` each arrive somewhere between 1 and 33 bytes. A converter that only turns 33
/// into 32 is wrong for the short integer — about three times in two thousand, which under the
/// delivery long poll is once a week.
///
/// Nothing is parsed by hand here: `p256` reads the form and rejects an `r` or an `s` outside the
/// group while it does so. What this function adds is the name and the place — curve and
/// signature form are this crate's business (architecture rule R6), and the two key stores that
/// need the conversion may not depend on this crate.
///
/// # Errors
///
/// [`CryptoError::Sign`] when the bytes are not a readable DER signature over P-256. That is the
/// same error the calling `sign` returns, because from the caller's side no usable signature came
/// about — regardless of whether the key store or the conversion is to blame.
pub fn signature_from_der(der: &[u8]) -> Result<[u8; 64], CryptoError> {
    let signature = Signature::from_der(der).map_err(|error| {
        CryptoError::Sign(format!(
            "the key store's signature is not a readable DER signature over P-256 \
             ({} bytes): {error}",
            der.len()
        ))
    })?;
    Ok(signature.to_bytes().into())
}

/// Takes the 64 bytes a key store hands back that already uses the JOSE form, and checks the
/// length.
///
/// The counterpart of [`signature_from_der`], and it exists for the length check alone: Windows'
/// `NCryptSignHash` is *reported* to deliver `r || s` for P-256 — third-party evidence and the
/// .NET default, and Microsoft's own reference pages state the layout nowhere (ADR-D12,
/// measurement 7). Anything other than 64 bytes would otherwise be cut or padded further up, and
/// the server would answer `invalid_dpop_proof` about a key that is sound.
///
/// # Errors
///
/// [`CryptoError::Sign`] for any other number of bytes.
pub fn signature_from_jose(raw: &[u8]) -> Result<[u8; 64], CryptoError> {
    <[u8; 64]>::try_from(raw).map_err(|_| {
        CryptoError::Sign(format!(
            "the key store delivered {} bytes; the JOSE form has 64",
            raw.len()
        ))
    })
}

/// A public P-256 key in JWK form (RFC 7517), without checking the curve.
///
/// The thumbprint (RFC 7638) is computed over the strings `x` and `y`, not over a point: the
/// anchor fingerprint has to match for entries whose point this client never uses either.
/// Whether the point lies on the curve is checked only by [`PublicKey::from_jwk`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Jwk {
    x: String,
    y: String,
}

impl Jwk {
    /// The only key type of the procedure.
    pub const KTY: &'static str = "EC";
    /// The only curve of the procedure.
    pub const CRV: &'static str = "P-256";

    /// From the two coordinates, base64url without padding, 32 bytes each.
    pub fn new(x: &str, y: &str) -> Result<Self, CryptoError> {
        for (name, value) in [("x", x), ("y", y)] {
            let bytes = from_b64u(value, if name == "x" { "x" } else { "y" })?;
            if bytes.len() != COORDINATE {
                return Err(CryptoError::Jwk(format!(
                    "the coordinate {name} has {} bytes instead of {COORDINATE}",
                    bytes.len()
                )));
            }
        }
        Ok(Self { x: x.to_owned(), y: y.to_owned() })
    }

    /// Reads `kty`, `crv`, `x`, `y` from a JSON object; further fields are ignored.
    ///
    /// An object with a private part `d` is rejected: a JWK that travels over the wire and
    /// carries the private key is an accident that nobody should pass on.
    pub fn from_json(value: &Value) -> Result<Self, CryptoError> {
        let object = value
            .as_object()
            .ok_or_else(|| CryptoError::Jwk("the JWK is not a JSON object".into()))?;
        let text = |name: &str| object.get(name).and_then(Value::as_str);
        if object.contains_key("d") {
            return Err(CryptoError::Jwk("the JWK carries a private part \"d\"".into()));
        }
        if text("kty") != Some(Self::KTY) {
            return Err(CryptoError::Jwk(format!("kty is {:?}, only EC is allowed", text("kty"))));
        }
        if text("crv") != Some(Self::CRV) {
            return Err(CryptoError::Jwk(format!(
                "crv is {:?}, only P-256 is allowed",
                text("crv")
            )));
        }
        match (text("x"), text("y")) {
            (Some(x), Some(y)) => Self::new(x, y),
            _ => Err(CryptoError::Jwk("x or y is missing".into())),
        }
    }

    /// The four mandatory members as a JSON object — the form used in the DPoP header.
    pub fn as_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("crv".into(), Value::from(Self::CRV));
        object.insert("kty".into(), Value::from(Self::KTY));
        object.insert("x".into(), Value::from(self.x.as_str()));
        object.insert("y".into(), Value::from(self.y.as_str()));
        Value::Object(object)
    }

    /// The RFC 7638 thumbprint: base64url(SHA-256(JCS({crv, kty, x, y}))).
    ///
    /// Only these four members: the thumbprint names the **key**, not its label — otherwise a
    /// renamed `kid` would change the identity. It is `dpop_jkt`, `cnf.jkt` in the token, and the
    /// value the administrator reads back.
    pub fn thumbprint(&self) -> String {
        // x and y are checked base64url: no character that JCS would have to escape. The form
        // is therefore literally the JCS form; a test holds the two against each other.
        let canonical =
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, self.x, self.y);
        b64u(&sha256(canonical.as_bytes()))
    }

    /// The x coordinate, base64url.
    pub fn x(&self) -> &str {
        &self.x
    }

    /// The y coordinate, base64url.
    pub fn y(&self) -> &str {
        &self.y
    }
}

impl Serialize for Jwk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_json().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_json(&value).map_err(serde::de::Error::custom)
    }
}

/// A public key whose point lies on P-256 — the only kind anything is verified with.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
    jwk: Jwk,
}

impl PublicKey {
    /// From a JWK; fails when the point does not lie on the curve.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, CryptoError> {
        let coordinate = |text: &str, field: &'static str| -> Result<FieldBytes, CryptoError> {
            let bytes: [u8; COORDINATE] = from_b64u(text, field)?.try_into().map_err(|_| {
                CryptoError::Jwk(format!("the coordinate {field} does not have 32 bytes"))
            })?;
            Ok(FieldBytes::from(bytes))
        };
        let point = Sec1Point::from_affine_coordinates(
            &coordinate(&jwk.x, "x")?,
            &coordinate(&jwk.y, "y")?,
            false,
        );
        let key = VerifyingKey::from_sec1_point(&point)
            .map_err(|_| CryptoError::Jwk("the point does not lie on P-256".into()))?;
        Ok(Self { key, jwk: jwk.clone() })
    }

    /// From a point in SEC1 form, as a key store outside this process hands it out.
    ///
    /// Measured (ADR-D12, measurement 1): `SecKeyCopyExternalRepresentation` on the public part of
    /// a Secure Enclave key delivers 65 bytes beginning with `0x04` — uncompressed, `04 || X || Y`.
    /// Windows' `BCRYPT_ECCPUBLIC_BLOB` carries the same two coordinates behind an 8-byte header,
    /// so that side builds the same 65 bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyMaterial`] when the bytes are no point on P-256. A key store that hands
    /// out a point nobody can verify against would produce a device the server never accepts, and
    /// the error would surface at the first signature instead of here.
    pub fn from_sec1(point: &[u8]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_sec1_bytes(point).map_err(|error| {
            CryptoError::KeyMaterial(format!(
                "the key store's {} bytes are no point on P-256: {error}",
                point.len()
            ))
        })?;
        Self::from_verifying_key(key)
    }

    fn from_verifying_key(key: VerifyingKey) -> Result<Self, CryptoError> {
        let point = key.to_sec1_point(false);
        match (point.x(), point.y()) {
            (Some(x), Some(y)) => Ok(Self { key, jwk: Jwk { x: b64u(x), y: b64u(y) } }),
            _ => Err(CryptoError::KeyMaterial("the point at infinity is no key".into())),
        }
    }

    /// The JWK.
    pub fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// The RFC 7638 thumbprint.
    pub fn thumbprint(&self) -> String {
        self.jwk.thumbprint()
    }

    /// Verifies an ES256 signature `r || s` over `data`.
    pub fn check(&self, data: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let signature = Signature::from_slice(signature)
            .map_err(|_| CryptoError::SignatureHoldsNot("r or s lies outside the group".into()))?;
        self.key.verify(data, &signature).map_err(|_| {
            CryptoError::SignatureHoldsNot("the signature does not match key and data".into())
        })
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.thumbprint())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.jwk.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let jwk = Jwk::deserialize(deserializer)?;
        Self::from_jwk(&jwk).map_err(serde::de::Error::custom)
    }
}

/// An ES256 key in this process's memory; stored as PKCS#8 in the keychain.
///
/// v1 of the folder client uses it as the device key (ADR-D03); Secure Enclave and TPM are
/// further implementations of [`SigningKey`], not of this type.
pub struct SoftwareKey {
    key: P256SigningKey,
    public: PublicKey,
}

impl SoftwareKey {
    /// A new key from the operating system's randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        for _ in 0..GENERATION_ATTEMPT {
            let mut scalar = Zeroizing::new([0u8; COORDINATE]);
            crate::random::fill(scalar.as_mut())?;
            // from_slice rejects zero and values at or above the group order; drawing again keeps
            // the distribution uniform (rejection sampling).
            if let Ok(key) = P256SigningKey::from_slice(scalar.as_ref()) {
                return Self::from_signing_key(key);
            }
        }
        Err(CryptoError::Random(format!(
            "{GENERATION_ATTEMPT} random values in a row lay outside the group"
        )))
    }

    /// Reads the key from PKCS#8 DER, as it lies in the keychain.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let key = P256SigningKey::from_pkcs8_der(der)
            .map_err(|error| CryptoError::KeyMaterial(format!("PKCS#8 unreadable: {error}")))?;
        Self::from_signing_key(key)
    }

    /// The key as PKCS#8 DER; the buffer is overwritten when it is released.
    pub fn as_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.key
            .to_pkcs8_der()
            .map(|document| document.to_bytes())
            .map_err(|error| CryptoError::KeyMaterial(format!("PKCS#8 not writable: {error}")))
    }

    fn from_signing_key(key: P256SigningKey) -> Result<Self, CryptoError> {
        let public = PublicKey::from_verifying_key(*key.verifying_key())?;
        Ok(Self { key, public })
    }
}

impl SigningKey for SoftwareKey {
    fn public(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign(&self, data: &[u8]) -> Result<[u8; 64], CryptoError> {
        // RFC 6979: deterministic, no per-signature randomness that could fail.
        let signature: Signature =
            self.key.try_sign(data).map_err(|error| CryptoError::Sign(error.to_string()))?;
        Ok(signature.to_bytes().into())
    }
}

impl fmt::Debug for SoftwareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SoftwareKey({})", self.public.thumbprint())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The key from RFC 7515 appendix A.3 — with a known private part.
    pub(crate) const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    pub(crate) const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    pub(crate) const A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

    pub(crate) fn a3_key() -> SoftwareKey {
        let d = from_b64u(A3_D, "d").unwrap();
        SoftwareKey::from_signing_key(P256SigningKey::from_slice(&d).unwrap()).unwrap()
    }

    #[test]
    fn the_thumbprint_follows_rfc_7638() {
        let jwk = Jwk::new(A3_X, A3_Y).unwrap();
        assert_eq!(jwk.thumbprint(), "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
        // The literal short form is the JCS form of the four mandatory members.
        let jcs = crate::jcs::canonicalize(&jwk.as_json()).unwrap();
        assert_eq!(b64u(&sha256(jcs.as_bytes())), jwk.thumbprint());
    }

    #[test]
    fn the_thumbprints_from_03_6_2_4_are_recomputed() {
        // The coordinates of the contract example do not lie on the curve; the thumbprint is
        // computed all the same, because it goes over the strings.
        for (x, y, expected) in [
            (
                "KR8R1P0MYXQSkmTLEUy76S4-mcDVbNBGSblM0nVghbQ",
                "bWqbl_fHbboDqf1kHx1VLMi9lXR5Iqu-nWefmpONuTY",
                "LAsBA719DG2FA0dsYL6V-xZPqUvH2HX8f1Zu55HYrYc",
            ),
            (
                "gbSRUaCT8FRHbSq1oR2QP2Y4OKDSuiC3_aigrNgEzfw",
                "1lis6j8wpAYp0ZQeYB3srLGomXGVhf-ExpmyZPfzP30",
                "8ji41YR5dcmyQ9yXVvI2DegpkzJlf8EK1EnNjMlv-eA",
            ),
        ] {
            let jwk = Jwk::new(x, y).unwrap();
            assert_eq!(jwk.thumbprint(), expected);
            assert!(PublicKey::from_jwk(&jwk).is_err(), "no point on P-256");
        }
    }

    #[test]
    fn the_private_part_from_rfc_7515_yields_the_public_one_named_there() {
        let key = a3_key();
        assert_eq!(key.public().jwk().x(), A3_X);
        assert_eq!(key.public().jwk().y(), A3_Y);
    }

    #[test]
    fn es256_signs_and_verifies_in_a_round_trip() {
        let key = SoftwareKey::generate().unwrap();
        let signature = key.sign(b"the bytes to be signed").unwrap();
        let public = key.public();
        assert!(public.check(b"the bytes to be signed", &signature).is_ok());
        assert!(public.check(b"other bytes", &signature).is_err());
        let foreign = SoftwareKey::generate().unwrap().public();
        assert!(foreign.check(b"the bytes to be signed", &signature).is_err());
        // Restored through the JWK, the same key verifies.
        let again = PublicKey::from_jwk(public.jwk()).unwrap();
        assert!(again.check(b"the bytes to be signed", &signature).is_ok());
    }

    #[test]
    fn a_signature_of_zeroes_does_not_hold_and_does_not_panic() {
        let public = a3_key().public();
        assert!(matches!(public.check(b"x", &[0u8; 64]), Err(CryptoError::SignatureHoldsNot(_))));
    }

    #[test]
    fn pkcs8_survives_the_round_trip_and_garbage_is_rejected() {
        let key = SoftwareKey::generate().unwrap();
        let der = key.as_pkcs8_der().unwrap();
        let again = SoftwareKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(again.public(), key.public());
        assert!(matches!(
            SoftwareKey::from_pkcs8_der(b"not pkcs8"),
            Err(CryptoError::KeyMaterial(_))
        ));
    }

    #[test]
    fn debug_shows_the_thumbprint_and_never_the_private_part() {
        let key = a3_key();
        let text = format!("{key:?}");
        assert_eq!(text, "SoftwareKey(oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U)");
        assert!(!text.contains(A3_D));
    }

    #[test]
    fn only_public_p256_jwks_are_read() {
        let good =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": A3_X, "y": A3_Y, "kid": "any"});
        assert!(Jwk::from_json(&good).is_ok());
        for bad in [
            serde_json::json!({"kty": "EC", "crv": "P-384", "x": A3_X, "y": A3_Y}),
            serde_json::json!({"kty": "RSA", "crv": "P-256", "x": A3_X, "y": A3_Y}),
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": A3_X, "y": A3_Y, "d": A3_D}),
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AQID", "y": A3_Y}),
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": A3_X}),
            serde_json::json!([A3_X, A3_Y]),
        ] {
            assert!(Jwk::from_json(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_public_key_travels_as_a_jwk_through_serde() {
        let public = a3_key().public();
        let json = serde_json::to_value(&public).unwrap();
        assert_eq!(json, serde_json::json!({"crv": "P-256", "kty": "EC", "x": A3_X, "y": A3_Y}));
        let back: PublicKey = serde_json::from_value(json).unwrap();
        assert_eq!(back, public);
    }

    /// The four DER lengths the Secure Enclave really produced (ADR-D12, measurement 4), here
    /// with the key of RFC 7515 A.3 so that they can be checked without an enclave: message, the
    /// signature as DER, the same signature as `r || s`.
    ///
    /// They are not invented. Each was searched for by signing `edms-d12 vector <n>` with
    /// [`a3_key`] until all four lengths had turned up — `SoftwareKey::sign` is deterministic
    /// (RFC 6979), so the same message always yields these bytes again.
    const DER_VECTOR: &[(usize, &str, &str, &str)] = &[
        (
            69,
            "edms-d12 vector 1010",
            "3043021f67f11c8b19e9a79e681706d9fded6e0835640d84d1bd8c27003a2843c21522\
             0220403ee997186f1c2b2cb955f590933ac51c9912ebd64622465fd68f5ebbd67668",
            "0067f11c8b19e9a79e681706d9fded6e0835640d84d1bd8c27003a2843c21522\
             403ee997186f1c2b2cb955f590933ac51c9912ebd64622465fd68f5ebbd67668",
        ),
        (
            70,
            "edms-d12 vector 8",
            "3044022046550d42039fac1308b0c4a69d4b031ad1c0ecd2be67cd74683c18d326c28f30\
             022011e108efeca3ceb9fe0c2ba9a9fe53d5c9e9dcd3dddba32bac2fb846804539bf",
            "46550d42039fac1308b0c4a69d4b031ad1c0ecd2be67cd74683c18d326c28f30\
             11e108efeca3ceb9fe0c2ba9a9fe53d5c9e9dcd3dddba32bac2fb846804539bf",
        ),
        (
            71,
            "edms-d12 vector 0",
            "304502204239a994f8be18fe1b75c3e8d40fc3deac40adaa97418929df79c4b8b8f647f7\
             0221009eadc40a61b7ab9cacde037de9cd9e469fd080368aa674b8e9fc28196d102ce0",
            "4239a994f8be18fe1b75c3e8d40fc3deac40adaa97418929df79c4b8b8f647f7\
             9eadc40a61b7ab9cacde037de9cd9e469fd080368aa674b8e9fc28196d102ce0",
        ),
        (
            72,
            "edms-d12 vector 3",
            "304602210081ca0afc81de92adbc7cfdc392d8a56015120262263c989a1637cec69fe910c8\
             022100d34cb944b082af64b658a3f470d91d4ed4934cfc6bfa9b1640123b347fe2afa4",
            "81ca0afc81de92adbc7cfdc392d8a56015120262263c989a1637cec69fe910c8\
             d34cb944b082af64b658a3f470d91d4ed4934cfc6bfa9b1640123b347fe2afa4",
        ),
    ];

    /// Hexadecimal into bytes; whitespace from the line wrapping above is passed over.
    fn from_hex(text: &str) -> Vec<u8> {
        let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(digits.len() % 2, 0, "an odd number of hex digits");
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).unwrap())
            .collect()
    }

    #[test]
    fn the_four_der_lengths_measured_in_the_enclave_all_become_the_same_64_bytes() {
        let public = a3_key().public();
        for (length, message, der, raw) in DER_VECTOR {
            let der = from_hex(der);
            assert_eq!(der.len(), *length, "{message}");
            let converted = signature_from_der(&der).unwrap();
            assert_eq!(converted.to_vec(), from_hex(raw), "{message}");
            // The point of the whole conversion: the verifier of this crate takes the result.
            public.check(message.as_bytes(), &converted).unwrap();
        }
    }

    #[test]
    fn a_der_integer_shorter_than_32_bytes_is_left_padded_and_not_merely_stripped() {
        // The 69-byte case, about three times in two thousand: DER writes `r` in 31 bytes because
        // its leading byte is zero. A converter that only turns 33 into 32 would hand out 63
        // bytes here, and the server would answer `invalid_dpop_proof` — for a signature that is
        // correct.
        let (_, message, der, raw) = DER_VECTOR[0];
        let der = from_hex(der);
        assert_eq!(der[2], 0x02, "the first element is an INTEGER");
        assert_eq!(der[3], 31, "and it is written in 31 bytes");
        let converted = signature_from_der(&der).unwrap();
        assert_eq!(converted[0], 0, "r was left-padded to 32 bytes");
        assert_eq!(converted.to_vec(), from_hex(raw));
        a3_key().public().check(message.as_bytes(), &converted).unwrap();
    }

    #[test]
    fn every_signature_of_the_software_key_survives_the_way_through_der() {
        // The four vectors above are the lengths that were measured; this is the general case —
        // whatever comes out, the DER form and the JOSE form say the same thing.
        let key = a3_key();
        for round in 0..500u32 {
            let message = format!("edms-d12 round trip {round}");
            let expected = key.sign(message.as_bytes()).unwrap();
            let signature: Signature = key.key.try_sign(message.as_bytes()).unwrap();
            let der = signature.to_der();
            assert_eq!(signature_from_der(der.as_bytes()).unwrap(), expected);
        }
    }

    #[test]
    fn bytes_that_are_no_der_signature_are_refused_instead_of_producing_64_bytes() {
        let good = from_hex(DER_VECTOR[1].2);
        let mut trailing = good.clone();
        trailing.push(0x00);
        let mut zero_r = good.clone();
        // r set to zero: a readable shape whose content is no signature. Everything that gets
        // through here would be a proof the server rejects without saying why.
        zero_r[4..36].fill(0);
        for bad in
            [Vec::new(), b"not der".to_vec(), good[..good.len() - 1].to_vec(), trailing, zero_r]
        {
            assert!(
                matches!(signature_from_der(&bad), Err(CryptoError::Sign(_))),
                "{} bytes got through",
                bad.len()
            );
        }
    }

    #[test]
    fn a_point_in_sec1_form_becomes_the_same_key_as_its_jwk() {
        // What a key store outside this process hands out: 65 bytes, first byte 0x04.
        let key = a3_key();
        let point = key.key.verifying_key().to_sec1_point(false);
        let point = point.as_bytes();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        let from_point = PublicKey::from_sec1(point).unwrap();
        assert_eq!(from_point, key.public());
        assert_eq!(from_point.thumbprint(), key.public().thumbprint());
    }

    #[test]
    fn a_point_that_does_not_lie_on_p256_is_refused_instead_of_becoming_a_device() {
        let key = a3_key();
        let point = key.key.verifying_key().to_sec1_point(false);
        let mut bent = point.as_bytes().to_vec();
        bent[64] ^= 0x01;
        for bad in [Vec::new(), vec![0x04], bent, vec![0x04; 65]] {
            assert!(
                matches!(PublicKey::from_sec1(&bad), Err(CryptoError::KeyMaterial(_))),
                "{} bytes got through",
                bad.len()
            );
        }
    }

    #[test]
    fn the_64_byte_form_is_taken_as_it_stands_and_every_other_length_is_refused() {
        let raw = from_hex(DER_VECTOR[1].3);
        assert_eq!(signature_from_jose(&raw).unwrap().to_vec(), raw);
        for bad in [Vec::new(), raw[..63].to_vec(), [raw.clone(), vec![0]].concat()] {
            assert!(
                matches!(signature_from_jose(&bad), Err(CryptoError::Sign(_))),
                "{}",
                bad.len()
            );
        }
    }
}
