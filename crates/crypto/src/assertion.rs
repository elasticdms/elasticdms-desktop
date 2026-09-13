//! The device's client assertion per RFC 7523 §2.2 (`private_key_jwt`, 03 §6.2.2).
//!
//! ```text
//! header  { "alg": "ES256", "kid": <kid of the device key>, "typ": "JWT" }
//! claims  { iss = sub = deviceId, aud = base of the authorization server, jti, iat, exp = iat + 60 }
//! ```
//!
//! It is the defence against reverse phishing of the device flow: only an enrolled device gets a
//! `user_code`, and the token carries a `device_id` claim that the API holds against the device
//! proven by DPoP (geraete-auth §2.4). `aud` is mandatory — an assertion without a recipient
//! binding could be replayed at another server. The `jti` sits in the server-side replay cache
//! for ten minutes; 60 s of validity are enough for exactly one call.

use edms_core::identifier::DeviceIdentifier;
use edms_core::time::Timestamp;
use serde_json::json;

use crate::key::SigningKey;
use crate::{ALG, CryptoError, dpop, jws, random};

/// The value of the `client_assertion_type` form field.
pub const ASSERTION_TYP: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Validity of an assertion in seconds (03 §6.2.2).
pub const VALIDITY_SECOND: i64 = 60;

/// An assertion with a fresh `jti`.
pub fn client_assertion(
    key: &dyn SigningKey,
    kid: &str,
    device: DeviceIdentifier,
    audience: &str,
    time: Timestamp,
) -> Result<String, CryptoError> {
    client_assertion_with_jti(key, kid, device, audience, time, &random::jti()?)
}

/// An assertion with a given `jti` — reproducible, for tests and for the mock.
pub fn client_assertion_with_jti(
    key: &dyn SigningKey,
    kid: &str,
    device: DeviceIdentifier,
    audience: &str,
    time: Timestamp,
    jti: &str,
) -> Result<String, CryptoError> {
    if kid.is_empty() {
        return Err(CryptoError::JwsUnreadable(
            "a client assertion without a kid names no key".into(),
        ));
    }
    if jti.is_empty() {
        return Err(CryptoError::JwsUnreadable("an empty jti protects against no replay".into()));
    }
    // The base has to be an http(s) URL with a host; the same check as for htu.
    dpop::htu(audience)?;
    let iat = dpop::iat(time);
    let device = device.to_string();
    let header = json!({ "alg": ALG, "kid": kid, "typ": "JWT" });
    let claims = json!({
        "iss": device,
        "sub": device,
        "aud": audience,
        "jti": jti,
        "iat": iat,
        "exp": iat + VALIDITY_SECOND,
    });
    jws::sign_jwt(&header, &claims, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::CompactJws;
    use crate::key::tests::a3_key;
    use serde_json::Value;

    // geraete-auth §3.1 — the example identifier printed there,
    // `dev_01JB8Z5K3M4N6P7Q8R9S0T1U2V`, carries a `U` at position 24. The Crockford alphabet
    // from §2.2 (`edms_core::identifier::ALPHABET`) knows neither `I`, `L`, `O` nor `U` —
    // precisely so that `1/I/l` and `0/O` cannot be confused. The example is therefore not a
    // valid identifier; the test uses the same sequence ending in `V2W`. Reported as an open
    // point.
    const DEVICE: &str = "dev_01JB8Z5K3M4N6P7Q8R9S0T1V2W";
    const NOW: Timestamp = Timestamp::from_unix_millis(1_775_383_872_000);

    #[test]
    fn the_assertion_names_the_device_as_iss_and_sub_and_expires_after_60_s() {
        let device: DeviceIdentifier = DEVICE.parse().unwrap();
        let jwt = client_assertion_with_jti(
            &a3_key(),
            "dev_01JB8Z#1",
            device,
            "https://auth.elasticdms.io",
            NOW,
            "01JB8QX7YV5R3T0N2K4M6P8S9C",
        )
        .unwrap();
        let jws = CompactJws::read(&jwt).unwrap();
        assert_eq!(
            Value::Object(jws.header().clone()),
            json!({"alg": "ES256", "kid": "dev_01JB8Z#1", "typ": "JWT"})
        );
        assert_eq!(
            Value::Object(jws.payload().clone()),
            json!({
                "iss": DEVICE, "sub": DEVICE, "aud": "https://auth.elasticdms.io",
                "jti": "01JB8QX7YV5R3T0N2K4M6P8S9C", "iat": 1_775_383_872, "exp": 1_775_383_932,
            })
        );
        assert!(jws.check(&a3_key().public()).is_ok());
    }

    #[test]
    fn every_assertion_has_its_own_jti() {
        let device: DeviceIdentifier = DEVICE.parse().unwrap();
        let a =
            client_assertion(&a3_key(), "k", device, "https://auth.elasticdms.io", NOW).unwrap();
        let b =
            client_assertion(&a3_key(), "k", device, "https://auth.elasticdms.io", NOW).unwrap();
        let jti = |t: &str| CompactJws::read(t).unwrap().payload()["jti"].clone();
        assert_ne!(jti(&a), jti(&b));
    }

    #[test]
    fn without_kid_jti_or_recipient_no_assertion_is_created() {
        let device: DeviceIdentifier = DEVICE.parse().unwrap();
        let s = a3_key();
        assert!(
            client_assertion_with_jti(&s, "", device, "https://auth.elasticdms.io", NOW, "j")
                .is_err()
        );
        assert!(
            client_assertion_with_jti(&s, "k", device, "https://auth.elasticdms.io", NOW, "")
                .is_err()
        );
        assert!(
            client_assertion_with_jti(&s, "k", device, "auth.elasticdms.io", NOW, "j").is_err()
        );
    }
}
