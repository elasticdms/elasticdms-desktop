//! Discovery — the two `.well-known` documents and the start conditions that hang on them
//! (03 §6.1, geraete-auth §3.0).
//!
//! On first start the client loads only the base addresses from the configuration and works out
//! the rest here. Three checks are **start conditions, not features**:
//!
//! 1. `issuer` is exactly the expected issuer (RFC 8414 §3.3) — otherwise the client would fetch
//!    the endpoints of another authorization server (mix-up).
//! 2. `code_challenge_methods_supported` contains `S256` — the client does not use the code flow,
//!    but 03 §6.1 makes it an abort condition, and a server without it is not the one this
//!    contract was written for.
//! 3. Every endpoint lies below the issuer. A discovery document that puts the token endpoint on
//!    a foreign host would send every client assertion there.
//!
//! An `authorization_endpoint` is neither expected nor used (AND-4: no PAR, no code flow, no
//! WebView); if one is there anyway, it stays unused in
//! [`AuthorizationServerMetadata::further`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::basics::is_below;
use crate::login::{GRANT_CLIENT_CREDENTIALS, GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN};

/// Path of the AS metadata on the sign-in host (RFC 8414).
pub const PATH_AS_METADATA: &str = "/.well-known/oauth-authorization-server";

/// Path of the resource metadata on the API host (RFC 9728).
pub const PATH_RESOURCE_METADATA: &str = "/.well-known/oauth-protected-resource";

/// The only method of client authentication (geraete-auth §3.2).
pub const AUTH_METHOD_PRIVATE_KEY_JWT: &str = "private_key_jwt";

/// The only algorithm in the procedure (geraete-auth §5.1).
pub const ALGORITHM_ES256: &str = "ES256";

/// The PKCE method whose absence aborts the start (03 §6.1).
pub const PKCE_S256: &str = "S256";

/// `GET /.well-known/oauth-authorization-server` (RFC 8414), as far as the client reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// The issuer, `https://auth.elasticdms.io`.
    pub issuer: String,
    /// `POST` for all three grants.
    pub token_endpoint: String,
    /// RFC 8628.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// RFC 7009.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// Only the token signing key — **never** the source of the evidence keys (03 §6.2.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// The grants on offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// Has to contain `private_key_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Algorithms of the client assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Has to contain `ES256` (RFC 9449 §5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Has to contain `S256` (03 §6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// The known scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// RFC 9207.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    /// Everything else, unchanged.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

/// The endpoints that are settled once the check has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginEndpoint {
    /// Token endpoint.
    pub token: String,
    /// Device authorization endpoint.
    pub device_authorization: String,
    /// Revocation endpoint.
    pub revocation: String,
}

/// Why a discovery document does not carry the start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// RFC 8414 §3.3: the issuer in the document is not the one that was asked.
    #[error(
        "the authorization server calls itself `{actual}`, expected was `{expected}`; its \
         endpoints are not adopted (RFC 8414 §3.3)"
    )]
    ForeignIssuer {
        /// Configured.
        expected: String,
        /// Delivered.
        actual: String,
    },
    /// A mandatory entry is missing or does not carry the mandatory value.
    #[error(
        "the discovery document does not name `{value}` in `{field}`; without it the folder \
         client does not start (03 §6.1)"
    )]
    RequiredValueMissing {
        /// The field.
        field: &'static str,
        /// The demanded value.
        value: &'static str,
    },
    /// An endpoint is missing.
    #[error("the discovery document names no `{0}`")]
    EndpointMissing(&'static str),
    /// An endpoint does not lie below the issuer.
    #[error(
        "`{field}` points at `{address}`, outside `{issuer}`; client assertions go to no \
         foreign host"
    )]
    ForeignEndpoint {
        /// The field.
        field: &'static str,
        /// The address.
        address: String,
        /// The issuer.
        issuer: String,
    },
    /// RFC 9728: the resource is not the configured API.
    #[error("the resource calls itself `{actual}`, expected was `{expected}` (RFC 9728 §3.3)")]
    ForeignResource {
        /// Configured.
        expected: String,
        /// Delivered.
        actual: String,
    },
    /// RFC 9728: the configured authorization server is not in the resource's list.
    #[error("the resource does not name `{0}` as an authorization server (RFC 9728)")]
    IssuerNotListed(String),
}

fn contains(list: Option<&Vec<String>>, value: &str) -> bool {
    list.is_some_and(|l| l.iter().any(|x| x == value))
}

fn under_issuer(
    field: &'static str,
    address: &str,
    issuer: &str,
) -> Result<String, DiscoveryError> {
    if is_below(address, issuer) {
        Ok(address.to_owned())
    } else {
        Err(DiscoveryError::ForeignEndpoint {
            field,
            address: address.to_owned(),
            issuer: issuer.to_owned(),
        })
    }
}

impl AuthorizationServerMetadata {
    /// Checks the start conditions and yields the endpoints the client may use.
    pub fn check(&self, expected_issuer: &str) -> Result<LoginEndpoint, DiscoveryError> {
        if self.issuer != expected_issuer {
            return Err(DiscoveryError::ForeignIssuer {
                expected: expected_issuer.to_owned(),
                actual: self.issuer.clone(),
            });
        }
        let required: [(&'static str, Option<&Vec<String>>, &'static str); 6] = [
            (
                "code_challenge_methods_supported",
                self.code_challenge_methods_supported.as_ref(),
                PKCE_S256,
            ),
            (
                "dpop_signing_alg_values_supported",
                self.dpop_signing_alg_values_supported.as_ref(),
                ALGORITHM_ES256,
            ),
            (
                "token_endpoint_auth_methods_supported",
                self.token_endpoint_auth_methods_supported.as_ref(),
                AUTH_METHOD_PRIVATE_KEY_JWT,
            ),
            (
                "grant_types_supported",
                self.grant_types_supported.as_ref(),
                GRANT_CLIENT_CREDENTIALS,
            ),
            ("grant_types_supported", self.grant_types_supported.as_ref(), GRANT_DEVICE_CODE),
            ("grant_types_supported", self.grant_types_supported.as_ref(), GRANT_REFRESH_TOKEN),
        ];
        for (field, list, value) in required {
            if !contains(list, value) {
                return Err(DiscoveryError::RequiredValueMissing { field, value });
            }
        }
        let device = self
            .device_authorization_endpoint
            .as_deref()
            .ok_or(DiscoveryError::EndpointMissing("device_authorization_endpoint"))?;
        let revocation = self
            .revocation_endpoint
            .as_deref()
            .ok_or(DiscoveryError::EndpointMissing("revocation_endpoint"))?;
        Ok(LoginEndpoint {
            token: under_issuer("token_endpoint", &self.token_endpoint, &self.issuer)?,
            device_authorization: under_issuer(
                "device_authorization_endpoint",
                device,
                &self.issuer,
            )?,
            revocation: under_issuer("revocation_endpoint", revocation, &self.issuer)?,
        })
    }
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMetadata {
    /// The API, `https://api.elasticdms.io`.
    pub resource: String,
    /// The authorization servers in charge.
    pub authorization_servers: Vec<String>,
    /// How tokens are presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,
    /// The scopes of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// Everything else, unchanged.
    #[serde(flatten)]
    pub further: Map<String, Value>,
}

impl ResourceMetadata {
    /// Checks that API and authorization server name each other.
    pub fn check(&self, api_base: &str, auth_base: &str) -> Result<(), DiscoveryError> {
        if self.resource != api_base {
            return Err(DiscoveryError::ForeignResource {
                expected: api_base.to_owned(),
                actual: self.resource.clone(),
            });
        }
        if !self.authorization_servers.iter().any(|a| a == auth_base) {
            return Err(DiscoveryError::IssuerNotListed(auth_base.to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden;

    const AUTH: &str = "https://auth.elasticdms.io";

    fn metadata() -> AuthorizationServerMetadata {
        serde_json::from_str(golden("authorization_server_metadata.json")).unwrap()
    }

    #[test]
    fn the_document_from_the_blueprint_passes_the_start_check() {
        let e = metadata().check(AUTH).unwrap();
        assert_eq!(e.token, "https://auth.elasticdms.io/v1/oauth/token");
        assert_eq!(
            e.device_authorization,
            "https://auth.elasticdms.io/v1/oauth/device_authorization"
        );
    }

    #[test]
    fn without_s256_the_start_aborts() {
        let mut m = metadata();
        m.code_challenge_methods_supported = Some(vec!["plain".into()]);
        assert_eq!(
            m.check(AUTH),
            Err(DiscoveryError::RequiredValueMissing {
                field: "code_challenge_methods_supported",
                value: "S256"
            })
        );
        m.code_challenge_methods_supported = None;
        assert!(m.check(AUTH).is_err());
    }

    #[test]
    fn a_foreign_issuer_is_not_adopted() {
        assert!(matches!(
            metadata().check("https://auth.example.org"),
            Err(DiscoveryError::ForeignIssuer { .. })
        ));
    }

    #[test]
    fn a_token_endpoint_on_a_foreign_host_is_rejected() {
        let mut m = metadata();
        m.token_endpoint = "https://auth.elasticdms.io.example.org/v1/oauth/token".into();
        assert!(matches!(
            m.check(AUTH),
            Err(DiscoveryError::ForeignEndpoint { field: "token_endpoint", .. })
        ));
    }

    #[test]
    fn without_the_device_code_grant_there_is_no_sign_in() {
        let mut m = metadata();
        m.grant_types_supported =
            Some(vec![GRANT_CLIENT_CREDENTIALS.into(), GRANT_REFRESH_TOKEN.into()]);
        assert!(
            matches!(m.check(AUTH), Err(DiscoveryError::RequiredValueMissing { value, .. }) if value == GRANT_DEVICE_CODE)
        );
        let mut m = metadata();
        m.device_authorization_endpoint = None;
        assert_eq!(
            m.check(AUTH),
            Err(DiscoveryError::EndpointMissing("device_authorization_endpoint"))
        );
    }

    #[test]
    fn the_resource_has_to_name_the_issuer() {
        let r: ResourceMetadata = serde_json::from_str(golden("resource_metadata.json")).unwrap();
        assert_eq!(r.check("https://api.elasticdms.io", AUTH), Ok(()));
        assert!(matches!(
            r.check("https://api.example.org", AUTH),
            Err(DiscoveryError::ForeignResource { .. })
        ));
        assert!(matches!(
            r.check("https://api.elasticdms.io", "https://auth.example.org"),
            Err(DiscoveryError::IssuerNotListed(_))
        ));
    }
}
