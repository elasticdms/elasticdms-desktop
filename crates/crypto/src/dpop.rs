//! DPoP proofs per RFC 9449 and the nonce store per origin (03 §6.0.5, geraete-auth §2.4).
//!
//! A proof binds method, URL and — as soon as an access token is in play — its hash (`ath`) to
//! the device key:
//!
//! ```text
//! header  { "typ": "dpop+jwt", "alg": "ES256", "jwk": { crv, kty, x, y } }
//! claims  { jti, htm, htu, iat, nonce?, ath? }        -- exactly these, no further ones
//! ```
//!
//! **Freshness comes from the nonce, not from `iat`.** The server does not check `iat` against
//! its clock (geraete-auth §2.4 point 7): after a power cut in the segmented network the clock is
//! wrong, and an `iat` check would refuse every call. `iat` is in there all the same, because
//! RFC 9449 demands it — computed from the timestamp handed in, not from a clock.
//!
//! **Nonces are kept apart per origin** (`scheme://host:port`). A nonce from `auth.` does not
//! hold at `api.` and the other way round; whoever mixes them reaps an endless alternation of
//! `use_dpop_nonce` (RFC 9449 §8 and §9, escan `NonceStore`).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use edms_core::time::Timestamp;
use serde_json::{Map, Value, json};

use crate::encoding::{b64u, sha256};
use crate::key::SigningKey;
use crate::{ALG, CryptoError, jws, random};

/// The media type of a DPoP proof (RFC 9449 §4.2).
pub const TYP: &str = "dpop+jwt";

/// What a proof is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpopProofRequest<'a> {
    /// HTTP method; goes out in upper case as `htm`.
    pub method: &'a str,
    /// The full target URL; query and fragment are cut off for `htu`.
    pub url: &'a str,
    /// The server nonce of this origin, if one is at hand.
    pub nonce: Option<&'a str>,
    /// The access token without the `DPoP ` prefix; its hash goes out as `ath`. At the token
    /// fetch itself there is none.
    pub access_token: Option<&'a str>,
}

/// A proof with a fresh `jti` from the operating system's randomness.
pub fn proof(
    key: &dyn SigningKey,
    request: &DpopProofRequest<'_>,
    time: Timestamp,
) -> Result<String, CryptoError> {
    proof_with_jti(key, request, time, &random::jti()?)
}

/// A proof with a given `jti` — reproducible, for tests and for the mock.
pub fn proof_with_jti(
    key: &dyn SigningKey,
    request: &DpopProofRequest<'_>,
    time: Timestamp,
    jti: &str,
) -> Result<String, CryptoError> {
    if jti.is_empty() {
        return Err(CryptoError::DpopInvalid("an empty jti protects against no replay".into()));
    }
    let header = json!({ "typ": TYP, "alg": ALG, "jwk": key.public().jwk().as_json() });
    let mut claims = Map::new();
    claims.insert("jti".into(), Value::from(jti));
    claims.insert("htm".into(), Value::from(htm(request.method)?));
    claims.insert("htu".into(), Value::from(htu(request.url)?));
    claims.insert("iat".into(), Value::from(iat(time)));
    if let Some(nonce) = request.nonce {
        if nonce.is_empty() {
            return Err(CryptoError::DpopInvalid(
                "an empty nonce is none; without a nonce the field stays away".into(),
            ));
        }
        claims.insert("nonce".into(), Value::from(nonce));
    }
    if let Some(token) = request.access_token {
        claims.insert("ath".into(), Value::from(ath(token)?));
    }
    jws::sign_jwt(&header, &Value::Object(claims), key)
}

/// `htm`: the method in upper case; only letters are a method.
pub fn htm(method: &str) -> Result<String, CryptoError> {
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(CryptoError::Method { method: method.to_owned() });
    }
    Ok(method.to_ascii_uppercase())
}

/// `htu`: the target URL without query and fragment (RFC 9449 §4.2).
///
/// Without this shortening a proof would be bound to an order of parameters. Nothing more is
/// rewritten: the server compares against the externally visible URL (geraete-auth §2.4 point 4),
/// and every rewrite here would be a second opinion about what it reads.
pub fn htu(url: &str) -> Result<String, CryptoError> {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    let without = &url[..end];
    let error = |reason| CryptoError::Url { url: url.to_owned(), reason };
    let (scheme, rest) =
        without.split_once("://").ok_or_else(|| error("scheme and host are missing"))?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return Err(error("only http and https carry a proof"));
    }
    if rest.is_empty() || rest.starts_with('/') {
        return Err(error("the host is missing"));
    }
    Ok(without.to_owned())
}

/// `ath` = base64url(SHA-256(US-ASCII(access token))) (RFC 9449 §4.2).
pub fn ath(access_token: &str) -> Result<String, CryptoError> {
    if !access_token.is_ascii() {
        return Err(CryptoError::TokenNotAscii);
    }
    Ok(b64u(&sha256(access_token.as_bytes())))
}

/// `iat` in whole seconds; fractions are truncated, not rounded.
pub fn iat(time: Timestamp) -> i64 {
    time.unix_millis().div_euclid(1_000)
}

/// The origin of a URL: `scheme://host:port`, lower case, default port written out.
///
/// `https://API.elasticdms.io/v1/x` and `https://api.elasticdms.io:443/y` are the same origin;
/// otherwise the store would hold the same nonce twice and one of the two would be stale.
pub fn origin(url: &str) -> Result<String, CryptoError> {
    let error = |reason| CryptoError::Url { url: url.to_owned(), reason };
    let (scheme, rest) =
        url.split_once("://").ok_or_else(|| error("scheme and host are missing"))?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port: u16 = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return Err(error("only http and https have an origin for nonces")),
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@') {
        return Err(error("credentials do not belong in a URL"));
    }
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (address, tail) =
            after.split_once(']').ok_or_else(|| error("the IPv6 address is not closed"))?;
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':').ok_or_else(|| error("no port follows the IPv6 address"))?)
        };
        (format!("[{}]", address.to_ascii_lowercase()), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_ascii_lowercase(), Some(port)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    if host.is_empty() || host == "[]" {
        return Err(error("the host is missing"));
    }
    let port = match port {
        None | Some("") => default_port,
        Some(text) => {
            text.parse::<u16>().map_err(|_| error("the port is not a number up to 65535"))?
        }
    };
    Ok(format!("{scheme}://{host}:{port}"))
}

/// The server nonces last seen, per origin, for all threads of the process.
///
/// Volatile on purpose: a nonce lives 300 s (geraete-auth §2.4); a stored one would, after the
/// first restart, be nothing but the reliable source of one extra failed attempt.
#[derive(Debug, Default)]
pub struct NonceStore {
    nonces: Mutex<HashMap<String, String>>,
}

impl NonceStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The nonce for the origin of `url`, if one is at hand.
    pub fn nonce(&self, url: &str) -> Result<Option<String>, CryptoError> {
        let key = origin(url)?;
        Ok(self.lock().get(&key).cloned())
    }

    /// Remembers the nonce from `DPoP-Nonce` for the origin of `url`; an empty one deletes.
    pub fn remember(&self, url: &str, nonce: &str) -> Result<(), CryptoError> {
        let key = origin(url)?;
        let nonce = nonce.trim();
        let mut nonces = self.lock();
        if nonce.is_empty() {
            nonces.remove(&key);
        } else {
            nonces.insert(key, nonce.to_owned());
        }
        Ok(())
    }

    /// Forgets the nonce of one origin.
    pub fn forget(&self, url: &str) -> Result<(), CryptoError> {
        let key = origin(url)?;
        self.lock().remove(&key);
        Ok(())
    }

    /// Forgets everything — on sign-out and on a network change.
    #[doc(alias = "clear")]
    pub fn empty(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, String>> {
        // A thread that crashed while holding the lock leaves behind at most one stale nonce;
        // that costs one retry and no error.
        self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::from_b64u;
    use crate::jws::CompactJws;
    use crate::key::tests::{A3_X, A3_Y, a3_key};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    const NOW: Timestamp = Timestamp::from_unix_millis(1_788_334_692_118);

    fn names(object: &Map<String, Value>) -> BTreeSet<&str> {
        object.keys().map(String::as_str).collect()
    }

    #[test]
    fn the_claim_set_is_exactly_the_one_from_rfc_9449_without_nonce_and_token() {
        let request = DpopProofRequest {
            method: "post",
            url: "https://auth.elasticdms.io/v1/oauth/token?x=1#top",
            nonce: None,
            access_token: None,
        };
        let proof = proof_with_jti(&a3_key(), &request, NOW, "01JB8Z5K3M4N6P7Q8R9S0T1V2W").unwrap();
        let jws = CompactJws::read(&proof).unwrap();
        assert_eq!(names(jws.header()), BTreeSet::from(["alg", "jwk", "typ"]));
        assert_eq!(jws.header()["typ"], TYP);
        assert_eq!(jws.header()["alg"], "ES256");
        assert_eq!(jws.header()["jwk"], json!({"crv": "P-256", "kty": "EC", "x": A3_X, "y": A3_Y}));
        assert_eq!(names(jws.payload()), BTreeSet::from(["htm", "htu", "iat", "jti"]));
        assert_eq!(jws.payload()["jti"], "01JB8Z5K3M4N6P7Q8R9S0T1V2W");
        assert_eq!(jws.payload()["htm"], "POST");
        assert_eq!(jws.payload()["htu"], "https://auth.elasticdms.io/v1/oauth/token");
        assert_eq!(jws.payload()["iat"], 1_788_334_692);
        assert!(jws.check(&a3_key().public()).is_ok());
    }

    #[test]
    fn with_nonce_and_token_exactly_nonce_and_ath_are_added() {
        let request = DpopProofRequest {
            method: "GET",
            url: "https://api.elasticdms.io/v1/folders",
            nonce: Some("eyJ0IjoxNzcyNDQ4MjkyfQ"),
            access_token: Some("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
        };
        let proof = proof(&a3_key(), &request, NOW).unwrap();
        let jws = CompactJws::read(&proof).unwrap();
        assert_eq!(
            names(jws.payload()),
            BTreeSet::from(["ath", "htm", "htu", "iat", "jti", "nonce"])
        );
        assert_eq!(jws.payload()["nonce"], "eyJ0IjoxNzcyNDQ4MjkyfQ");
        assert_eq!(jws.payload()["ath"], "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
        assert_eq!(jws.payload()["jti"].as_str().unwrap().len(), 26);
    }

    #[test]
    fn header_and_claims_stand_canonicalized_in_the_proof() {
        let request = DpopProofRequest {
            method: "GET",
            url: "https://api.elasticdms.io/v1/x",
            nonce: None,
            access_token: None,
        };
        let proof = proof_with_jti(&a3_key(), &request, NOW, "J").unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        let header = format!(
            r#"{{"alg":"ES256","jwk":{{"crv":"P-256","kty":"EC","x":"{A3_X}","y":"{A3_Y}"}},"typ":"dpop+jwt"}}"#
        );
        assert_eq!(from_b64u(parts[0], "k").unwrap(), header.as_bytes());
        assert_eq!(
            from_b64u(parts[1], "n").unwrap(),
            br#"{"htm":"GET","htu":"https://api.elasticdms.io/v1/x","iat":1788334692,"jti":"J"}"#
        );
        // RFC 6979: the same key over the same bytes gives the same proof.
        assert_eq!(proof, proof_with_jti(&a3_key(), &request, NOW, "J").unwrap());
    }

    #[test]
    fn ath_follows_the_example_from_rfc_9449() {
        assert_eq!(
            ath("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU").unwrap(),
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        );
        assert_eq!(ath("tökén"), Err(CryptoError::TokenNotAscii));
    }

    #[test]
    fn htu_cuts_off_only_query_and_fragment() {
        assert_eq!(htu("https://a.example/v1/x?y=1").unwrap(), "https://a.example/v1/x");
        assert_eq!(htu("https://a.example:8443/v1/x#f").unwrap(), "https://a.example:8443/v1/x");
        assert_eq!(htu("http://127.0.0.1:8480/v1/x").unwrap(), "http://127.0.0.1:8480/v1/x");
        for wrong in ["/v1/x", "ftp://a.example/x", "https:///x", "https://?x"] {
            assert!(htu(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn a_method_is_a_word_made_of_letters() {
        assert_eq!(htm("delete").unwrap(), "DELETE");
        assert!(htm("").is_err());
        assert!(htm("GE T").is_err());
    }

    #[test]
    fn an_empty_jti_and_an_empty_nonce_are_rejected() {
        let mut request = DpopProofRequest {
            method: "GET",
            url: "https://api.elasticdms.io/",
            nonce: None,
            access_token: None,
        };
        assert!(proof_with_jti(&a3_key(), &request, NOW, "").is_err());
        request.nonce = Some("");
        assert!(proof_with_jti(&a3_key(), &request, NOW, "J").is_err());
    }

    #[test]
    fn the_origin_writes_out_the_default_port_and_lower_cases() {
        assert_eq!(
            origin("https://API.elasticdms.io/v1/x?y").unwrap(),
            "https://api.elasticdms.io:443"
        );
        assert_eq!(
            origin("https://api.elasticdms.io:443").unwrap(),
            "https://api.elasticdms.io:443"
        );
        assert_eq!(origin("HTTP://localhost/x").unwrap(), "http://localhost:80");
        assert_eq!(origin("http://[::1]:8480/x").unwrap(), "http://[::1]:8480");
        for wrong in [
            "api.elasticdms.io",
            "ftp://x/",
            "https://",
            "https://u:p@x/",
            "https://x:99999/",
            "http://[::1/",
        ] {
            assert!(origin(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn the_store_keeps_auth_and_api_apart() {
        let store = NonceStore::new();
        store.remember("https://auth.elasticdms.io/v1/oauth/token", "nonce-auth").unwrap();
        store.remember("https://api.elasticdms.io/v1/folders", "nonce-api").unwrap();
        assert_eq!(
            store.nonce("https://auth.elasticdms.io/v1/oauth/revoke").unwrap().as_deref(),
            Some("nonce-auth")
        );
        assert_eq!(
            store.nonce("https://api.elasticdms.io:443/v1/x").unwrap().as_deref(),
            Some("nonce-api")
        );
        // Same host, different port: a different origin (the mock on 8480 and 8481).
        store.remember("http://127.0.0.1:8480/", "a").unwrap();
        assert_eq!(store.nonce("http://127.0.0.1:8481/").unwrap(), None);
        // A new nonce replaces the old one, an empty one deletes.
        store.remember("https://api.elasticdms.io/", "nonce-api-2").unwrap();
        assert_eq!(
            store.nonce("https://api.elasticdms.io/").unwrap().as_deref(),
            Some("nonce-api-2")
        );
        store.remember("https://api.elasticdms.io/", " ").unwrap();
        assert_eq!(store.nonce("https://api.elasticdms.io/").unwrap(), None);
        store.forget("https://auth.elasticdms.io/").unwrap();
        assert_eq!(store.nonce("https://auth.elasticdms.io/").unwrap(), None);
        store.empty();
        assert_eq!(store.nonce("http://127.0.0.1:8480/").unwrap(), None);
    }

    #[test]
    fn the_store_is_usable_from_several_threads() {
        let store = Arc::new(NonceStore::new());
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let url = format!("http://127.0.0.1:{}/", 9000 + i);
                    for n in 0..100 {
                        s.remember(&url, &format!("n{n}")).unwrap();
                    }
                    s.nonce(&url).unwrap()
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap().as_deref(), Some("n99"));
        }
    }
}
