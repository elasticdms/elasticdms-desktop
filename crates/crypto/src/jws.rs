//! JWS with ES256: compact for proofs, detached for server signatures (geraete-auth §5.2).
//!
//! **Compact** (RFC 7515 §3.1) — DPoP proof and client assertion, where the recipient does not
//! already have the payload. Header and payload are JCS-canonicalized before the encoding, as in
//! the sibling client (`JwsBau`): JOSE does not demand that, but it makes proofs reproducible
//! byte for byte, and only then does a test against an expected value become writable at all.
//!
//! **Detached** (RFC 7515 appendix F) — the signature of a carrier that stands beside it:
//!
//! ```text
//! signed bytes     = JCS( carrier without the field "serverSignature" )   [RFC 8785]
//! serverSignature  = "<b64u(header)>..<b64u(signature)>"
//! protected header = { "alg": "ES256", "typ": <media type>, "kid": <kid of the signer> }
//! signature input  = ASCII( b64u(header) || "." || b64u(signed bytes) )
//! ```
//!
//! In the serialization the payload is **left out, but contained in the input**. Whoever signs
//! only `b64u(header) || "."` creates a signature that nobody can check (geraete-auth §5.5,
//! pitfall 2) — a test pins exactly that.
//!
//! The verifier takes the **expected** media type and rejects every other one (P11): without
//! that binding, a signature from one context would be reusable in another as soon as two
//! canonicalized bodies coincided even once. `alg` has to be exactly `ES256` (P1), and the `kid`
//! has to name a key of the given set (P3) — never “just try one of them”.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::encoding::{b64u, from_b64u};
use crate::key::{PublicKey, SigningKey};
use crate::{ALG, CryptoError, jcs};

/// The name of the signature field in every signed carrier.
pub const FIELD_SIGNATURE: &str = "serverSignature";

/// The members a protected header may carry — exactly those from geraete-auth §5.2.
///
/// A further member is rejected, not passed over: `crit` or `b64: false` change the meaning of
/// the signature input (RFC 7797), `jwk` or `jku` would bring in a key past the anchored set. A
/// header whose meaning this verifier does not evaluate does not count.
const HEADER_MEMBERS: [&str; 3] = ["alg", "typ", "kid"];

/// Signs a compact JWS; header and payload are JCS-canonicalized.
///
/// The header has to carry `"alg": "ES256"` — otherwise a JWS would arise whose header claims
/// something other than what was signed.
pub fn sign_jwt(
    header: &Value,
    payload: &Value,
    key: &dyn SigningKey,
) -> Result<String, CryptoError> {
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default();
    if alg != ALG {
        return Err(CryptoError::WrongAlgorithm { read: alg.to_owned() });
    }
    if !payload.is_object() {
        return Err(CryptoError::JwsUnreadable("the payload of a JWT is a JSON object".into()));
    }
    let input = format!(
        "{}.{}",
        b64u(&jcs::canonicalize_bytes(header)?),
        b64u(&jcs::canonicalize_bytes(payload)?)
    );
    let signature = key.sign(input.as_bytes())?;
    Ok(format!("{input}.{}", b64u(&signature)))
}

/// A compact JWS that has been read, with its payload (DPoP proof, client assertion).
#[derive(Debug, Clone, PartialEq)]
pub struct CompactJws {
    header: Map<String, Value>,
    payload: Map<String, Value>,
    input: String,
    signature: [u8; 64],
}

impl CompactJws {
    /// Reads `<header>.<payload>.<signature>`; `alg` has to be `ES256`.
    pub fn read(text: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = text.split('.').collect();
        let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
            return Err(CryptoError::JwsUnreadable(format!(
                "{} parts instead of three",
                parts.len()
            )));
        };
        let header = object_from_b64u(header_b64, "header")?;
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default();
        if alg != ALG {
            return Err(CryptoError::WrongAlgorithm { read: alg.to_owned() });
        }
        let payload = object_from_b64u(payload_b64, "payload")?;
        Ok(Self {
            header,
            payload,
            input: format!("{header_b64}.{payload_b64}"),
            signature: signature_from_b64u(signature_b64)?,
        })
    }

    /// The header.
    pub fn header(&self) -> &Map<String, Value> {
        &self.header
    }

    /// The payload (claims).
    pub fn payload(&self) -> &Map<String, Value> {
        &self.payload
    }

    /// Verifies the signature against a public key.
    pub fn check(&self, key: &PublicKey) -> Result<(), CryptoError> {
        key.check(self.input.as_bytes(), &self.signature)
    }
}

/// The protected header of a detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedHeader {
    /// Always `ES256`; anything else is rejected while reading.
    pub alg: String,
    /// The media type of the carrier, such as `edms-server-key+jwt`.
    pub typ: String,
    /// The `kid` of the signer.
    pub kid: String,
}

/// A detached compact signature `<b64u(header)>..<b64u(signature)>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    header_b64: String,
    header: ProtectedHeader,
    signature: [u8; 64],
}

impl DetachedSignature {
    /// Reads the form strictly: three parts, the middle one empty, header exactly
    /// `{alg, typ, kid}`.
    pub fn read(compact: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = compact.split('.').collect();
        let [header_b64, middle, signature_b64] = parts.as_slice() else {
            return Err(CryptoError::JwsUnreadable(format!(
                "a detached signature has the form <header>..<signature>, here {} parts",
                parts.len()
            )));
        };
        if !middle.is_empty() {
            return Err(CryptoError::JwsUnreadable(
                "the payload of a detached signature is empty; here one stood".into(),
            ));
        }
        let header = object_from_b64u(header_b64, "header")?;
        if let Some(foreign) = header.keys().find(|name| !HEADER_MEMBERS.contains(&name.as_str())) {
            return Err(CryptoError::JwsUnreadable(format!(
                "the protected header carries the member \"{foreign}\"; only alg, typ and kid are allowed"
            )));
        }
        let text = |name: &str| header.get(name).and_then(Value::as_str);
        let alg = text("alg").unwrap_or_default();
        if alg != ALG {
            return Err(CryptoError::WrongAlgorithm { read: alg.to_owned() });
        }
        let (Some(typ), Some(kid)) = (text("typ"), text("kid")) else {
            return Err(CryptoError::JwsUnreadable(
                "the protected header names no typ or no kid".into(),
            ));
        };
        Ok(Self {
            header_b64: (*header_b64).to_owned(),
            header: ProtectedHeader {
                alg: alg.to_owned(),
                typ: typ.to_owned(),
                kid: kid.to_owned(),
            },
            signature: signature_from_b64u(signature_b64)?,
        })
    }

    /// The protected header.
    pub fn header(&self) -> &ProtectedHeader {
        &self.header
    }

    /// Checks media type (P11) and signature over `signed_bytes` against a key.
    pub fn check(
        &self,
        expected_type: &str,
        signed_bytes: &[u8],
        key: &PublicKey,
    ) -> Result<(), CryptoError> {
        if self.header.typ != expected_type {
            return Err(CryptoError::WrongTyp {
                expected: expected_type.to_owned(),
                read: self.header.typ.clone(),
            });
        }
        let input = format!("{}.{}", self.header_b64, b64u(signed_bytes));
        key.check(input.as_bytes(), &self.signature)
    }
}

/// `JCS(carrier without serverSignature)` — the bytes that were signed over.
///
/// There is no field selection (P2): a field this client does not know is part of the signature.
/// A verifier that picks its fields together checks a different statement from the signed one.
pub fn signed_bytes(carrier: &Value) -> Result<Vec<u8>, CryptoError> {
    let object = carrier.as_object().ok_or_else(|| CryptoError::Unreadable {
        what: "The signed carrier",
        reason: "it is not a JSON object".into(),
    })?;
    let mut without = object.clone();
    without.remove(FIELD_SIGNATURE);
    jcs::canonicalize_bytes(&Value::Object(without))
}

/// The `serverSignature` of a carrier, read.
pub fn signature_of_the_carrier(carrier: &Value) -> Result<DetachedSignature, CryptoError> {
    match carrier.get(FIELD_SIGNATURE) {
        Some(Value::String(compact)) => DetachedSignature::read(compact),
        _ => Err(CryptoError::SignatureMissing),
    }
}

/// Checks a carrier with a detached signature against a set of public keys.
///
/// Order: shape and `alg` (P1), media type (P11), `kid` in the set (P3), signature over
/// `JCS(carrier without serverSignature)` (P2). Role, validity window and revocation are the
/// caller's business ([`crate::key_set`]); this verifier knows only keys.
pub fn check_detached(
    carrier: &Value,
    expected_type: &str,
    key: &BTreeMap<String, PublicKey>,
) -> Result<ProtectedHeader, CryptoError> {
    let signature = signature_of_the_carrier(carrier)?;
    if signature.header.typ != expected_type {
        return Err(CryptoError::WrongTyp {
            expected: expected_type.to_owned(),
            read: signature.header.typ.clone(),
        });
    }
    let public = key
        .get(&signature.header.kid)
        .ok_or_else(|| CryptoError::UnknownKid { kid: signature.header.kid.clone() })?;
    signature.check(expected_type, &signed_bytes(carrier)?, public)?;
    Ok(signature.header)
}

/// Signs bytes detached: `<b64u(header)>..<b64u(signature)>`.
///
/// The header stands in the order `alg`, `typ`, `kid` as in the contract example (03 §6.2.4) and
/// in the sibling client's forge; for the check only the transmitted form counts anyway.
pub fn sign_detached(
    signed_bytes: &[u8],
    typ: &str,
    kid: &str,
    key: &dyn SigningKey,
) -> Result<String, CryptoError> {
    let header =
        format!(r#"{{"alg":"{ALG}","typ":{},"kid":{}}}"#, jcs::quoted(typ), jcs::quoted(kid));
    let header_b64 = b64u(header.as_bytes());
    let input = format!("{header_b64}.{}", b64u(signed_bytes));
    let signature = key.sign(input.as_bytes())?;
    Ok(format!("{header_b64}..{}", b64u(&signature)))
}

fn object_from_b64u(text: &str, field: &'static str) -> Result<Map<String, Value>, CryptoError> {
    let bytes = from_b64u(text, field)?;
    let json = String::from_utf8(bytes)
        .map_err(|_| CryptoError::JwsUnreadable(format!("the {field} is not UTF-8")))?;
    match jcs::read(&json)? {
        Value::Object(object) => Ok(object),
        _ => Err(CryptoError::JwsUnreadable(format!("the {field} is not a JSON object"))),
    }
}

fn signature_from_b64u(text: &str) -> Result<[u8; 64], CryptoError> {
    from_b64u(text, "signature")?.try_into().map_err(|raw: Vec<u8>| {
        CryptoError::JwsUnreadable(format!(
            "the signature has {} bytes instead of 64; expected is r || s, not DER",
            raw.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Jwk;
    use crate::key::SoftwareKey;
    use crate::key::tests::{A3_X, A3_Y, a3_key};
    use serde_json::json;

    const TYP: &str = "edms-qc-clearance+jwt";

    fn set(kid: &str, key: &SoftwareKey) -> BTreeMap<String, PublicKey> {
        BTreeMap::from([(kid.to_owned(), key.public())])
    }

    fn signed_carrier(key: &SoftwareKey, kid: &str) -> Value {
        let mut carrier =
            json!({"batchId": "bat_01", "clearedAt": "2026-06-01T00:00:00Z", "new": [1, 2]});
        let signature = sign_detached(&signed_bytes(&carrier).unwrap(), TYP, kid, key).unwrap();
        carrier[FIELD_SIGNATURE] = Value::from(signature);
        carrier
    }

    #[test]
    fn the_example_from_rfc_7515_appendix_a3_verifies() {
        let jws = "eyJhbGciOiJFUzI1NiJ9.\
                   eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
                   DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        let read = CompactJws::read(jws).unwrap();
        let public = PublicKey::from_jwk(&Jwk::new(A3_X, A3_Y).unwrap()).unwrap();
        assert!(read.check(&public).is_ok());
        assert_eq!(read.payload()["iss"], "joe");
        let foreign = SoftwareKey::generate().unwrap().public();
        assert!(read.check(&foreign).is_err());
    }

    #[test]
    fn a_jwt_is_canonicalized_and_verifies_in_a_round_trip() {
        let key = a3_key();
        let jwt = sign_jwt(
            &json!({"typ": "JWT", "alg": "ES256", "kid": "k1"}),
            &json!({"z": 1, "a": "ä"}),
            &key,
        )
        .unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(from_b64u(parts[0], "k").unwrap(), br#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#);
        assert_eq!(from_b64u(parts[1], "n").unwrap(), r#"{"a":"ä","z":1}"#.as_bytes());
        assert!(CompactJws::read(&jwt).unwrap().check(&key.public()).is_ok());
    }

    #[test]
    fn a_jwt_with_another_alg_is_not_even_signed() {
        let error = sign_jwt(&json!({"alg": "HS256"}), &json!({}), &a3_key()).unwrap_err();
        assert_eq!(error, CryptoError::WrongAlgorithm { read: "HS256".into() });
    }

    #[test]
    fn a_detached_signature_verifies_and_carries_no_payload() {
        let key = SoftwareKey::generate().unwrap();
        let carrier = signed_carrier(&key, "edms-kms-2026-09");
        let compact = carrier[FIELD_SIGNATURE].as_str().unwrap();
        assert_eq!(compact.split('.').nth(1), Some(""));
        let header = check_detached(&carrier, TYP, &set("edms-kms-2026-09", &key)).unwrap();
        assert_eq!(header.kid, "edms-kms-2026-09");
        assert_eq!(header.typ, TYP);
        // The header stands in the order of the contract example.
        let header_b64 = compact.split('.').next().unwrap();
        assert_eq!(
            from_b64u(header_b64, "k").unwrap(),
            br#"{"alg":"ES256","typ":"edms-qc-clearance+jwt","kid":"edms-kms-2026-09"}"#
        );
    }

    #[test]
    fn a_changed_field_breaks_the_signature() {
        let key = SoftwareKey::generate().unwrap();
        let mut carrier = signed_carrier(&key, "k");
        carrier["batchId"] = Value::from("bat_02");
        assert!(matches!(
            check_detached(&carrier, TYP, &set("k", &key)),
            Err(CryptoError::SignatureHoldsNot(_))
        ));
        // An added field is part of the signature too (P2): no field selection.
        let mut carrier = signed_carrier(&key, "k");
        carrier["unknown"] = Value::from(true);
        assert!(check_detached(&carrier, TYP, &set("k", &key)).is_err());
    }

    #[test]
    fn another_media_type_is_rejected() {
        let key = SoftwareKey::generate().unwrap();
        let carrier = signed_carrier(&key, "k");
        let error =
            check_detached(&carrier, "edms-release-grant+jwt", &set("k", &key)).unwrap_err();
        assert_eq!(
            error,
            CryptoError::WrongTyp { expected: "edms-release-grant+jwt".into(), read: TYP.into() }
        );
    }

    #[test]
    fn an_unknown_kid_is_rejected_instead_of_trying_some_key() {
        let key = SoftwareKey::generate().unwrap();
        let carrier = signed_carrier(&key, "k");
        let error = check_detached(&carrier, TYP, &set("other", &key)).unwrap_err();
        assert_eq!(error, CryptoError::UnknownKid { kid: "k".into() });
    }

    fn with_header(header: &str, key: &SoftwareKey, carrier: &Value) -> Value {
        let header_b64 = b64u(header.as_bytes());
        let input = format!("{header_b64}.{}", b64u(&signed_bytes(carrier).unwrap()));
        let signature = key.sign(input.as_bytes()).unwrap();
        let mut from = carrier.clone();
        from[FIELD_SIGNATURE] = Value::from(format!("{header_b64}..{}", b64u(&signature)));
        from
    }

    #[test]
    fn another_algorithm_in_the_header_is_rejected_even_with_a_real_signature() {
        let key = SoftwareKey::generate().unwrap();
        let carrier = json!({"a": 1});
        for (header, read) in [
            (r#"{"alg":"HS256","typ":"edms-qc-clearance+jwt","kid":"k"}"#, "HS256"),
            (r#"{"alg":"none","typ":"edms-qc-clearance+jwt","kid":"k"}"#, "none"),
            (r#"{"typ":"edms-qc-clearance+jwt","kid":"k"}"#, ""),
        ] {
            let error = check_detached(&with_header(header, &key, &carrier), TYP, &set("k", &key))
                .unwrap_err();
            assert_eq!(error, CryptoError::WrongAlgorithm { read: read.into() }, "{header}");
        }
    }

    #[test]
    fn a_header_with_further_members_does_not_count() {
        let key = SoftwareKey::generate().unwrap();
        let carrier = json!({"a": 1});
        let header =
            r#"{"alg":"ES256","typ":"edms-qc-clearance+jwt","kid":"k","crit":["b64"],"b64":false}"#;
        let error =
            check_detached(&with_header(header, &key, &carrier), TYP, &set("k", &key)).unwrap_err();
        assert!(matches!(error, CryptoError::JwsUnreadable(_)), "{error:?}");
    }

    #[test]
    fn a_signature_over_the_header_alone_does_not_verify() {
        // geraete-auth §5.5, pitfall 2: the payload belongs in the input, detached as well.
        let key = SoftwareKey::generate().unwrap();
        let carrier = json!({"a": 1});
        let header_b64 = b64u(br#"{"alg":"ES256","typ":"edms-qc-clearance+jwt","kid":"k"}"#);
        let signature = key.sign(format!("{header_b64}.").as_bytes()).unwrap();
        let mut wrong = carrier.clone();
        wrong[FIELD_SIGNATURE] = Value::from(format!("{header_b64}..{}", b64u(&signature)));
        assert!(matches!(
            check_detached(&wrong, TYP, &set("k", &key)),
            Err(CryptoError::SignatureHoldsNot(_))
        ));
    }

    #[test]
    fn wrong_shapes_are_rejected_by_name() {
        let key = SoftwareKey::generate().unwrap();
        let real = signed_carrier(&key, "k");
        let compact = real[FIELD_SIGNATURE].as_str().unwrap().to_owned();
        let (header, signature) = compact.split_once("..").unwrap();
        for wrong in [
            format!("{header}.eyJhIjoxfQ.{signature}"),
            format!("{header}.{signature}"),
            format!("{header}..{signature}.x"),
            format!("{header}..AQID"),
            String::new(),
        ] {
            assert!(DetachedSignature::read(&wrong).is_err(), "{wrong}");
        }
        let mut without = real.clone();
        without.as_object_mut().unwrap().remove(FIELD_SIGNATURE);
        assert_eq!(
            check_detached(&without, TYP, &set("k", &key)),
            Err(CryptoError::SignatureMissing)
        );
        let mut null = real;
        null[FIELD_SIGNATURE] = Value::Null;
        assert_eq!(check_detached(&null, TYP, &set("k", &key)), Err(CryptoError::SignatureMissing));
    }

    #[test]
    fn the_signed_bytes_leave_out_only_the_signature() {
        let carrier = json!({"b": 1, "serverSignature": "x..y", "a": {"z": null}});
        assert_eq!(signed_bytes(&carrier).unwrap(), br#"{"a":{"z":null},"b":1}"#);
        assert!(signed_bytes(&json!([1])).is_err());
    }
}
