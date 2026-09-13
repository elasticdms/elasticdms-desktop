//! Two origins, fixed headers, two time limits — everything every call needs.
//!
//! The two base addresses are **never** mixed: `api.elasticdms.io` carries the resources,
//! `auth.elasticdms.io` the sign-in. Separated with them are the DPoP nonces (03 §6.0.5) — a nonce
//! of the one host presented at the other is invalid, and the client would run into an endless
//! alternation of two prompts taking turns.
//!
//! Checking happens **when building**: a plaintext address against a real host aborts the start,
//! not the first call. An error at the start names the variable and the reason; an error at the
//! first call looks like a fault of the server.

use std::time::Duration;

use edms_core::identifier::DeviceIdentifier;
use edms_wire::basics::API_VERSION;

use crate::error::ConnectionError;

/// Time limit for establishing the connection.
///
/// Short, because a hanging connect is frequent in a corporate network and the user would otherwise
/// be sitting in front of a folder that says "in a moment" and does nothing.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time limit for the **silence** between two pieces read.
///
/// What is limited is the silence, not the duration: a 200 MB receipt over a saturated line runs
/// longer than any overall limit one could defend here. A connection that keeps moving bytes is
/// never cut off.
pub const READ_LIMIT: Duration = Duration::from_secs(30);

/// Supplement to the waiting time of the long poll (contract §7.3.1).
///
/// The server holds for up to 25 seconds; the read limit has to lie above that, otherwise the
/// client cuts off every quiet wait itself and would count every silent day as a fault.
pub const LONG_POLL_INCREMENT: Duration = Duration::from_secs(10);

/// The language of the `title` and `detail` texts. The `type` URI is never translated (03 §6.17).
pub const LANGUAGE: &str = "de-DE";

const LOOP: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

/// Everything the network contract has to know about its counterpart.
///
/// The base addresses are `String` and not `reqwest::Url`: reqwest appears in no public signature
/// of this crate, so that engine and app build against the contract and not against the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    api_base: String,
    auth_base: String,
    device: DeviceIdentifier,
    api_version: String,
    user_identifier: String,
    connect_timeout: Duration,
    read_limit: Duration,
}

impl Connection {
    /// A connection, checked.
    ///
    /// `application_version` is the version of this program (`1.0.0`); it stands in the
    /// `User-Agent` together with the operating system — `elasticdms-folder-client/1.0.0
    /// (windows)`. By it the server recognises which version in the field violates a rule, without
    /// anybody having to ask.
    ///
    /// # Errors
    ///
    /// An address without a scheme or host, or plaintext against a host other than the loopback
    /// (see [`ConnectionError::Plaintext`]).
    pub fn new(
        api_base: &str,
        auth_base: &str,
        device: DeviceIdentifier,
        application_version: &str,
    ) -> Result<Self, ConnectionError> {
        let api_base = check("API base", api_base)?;
        let auth_base = check("sign-in base", auth_base)?;
        Ok(Self {
            api_base,
            auth_base,
            device,
            api_version: API_VERSION.to_owned(),
            user_identifier: format!(
                "elasticdms-folder-client/{application_version} ({})",
                std::env::consts::OS
            ),
            connect_timeout: CONNECT_TIMEOUT,
            read_limit: READ_LIMIT,
        })
    }

    /// Sets the `User-Agent` outright (tests, special builds).
    #[must_use]
    pub fn with_user_identifier(mut self, identifier: &str) -> Self {
        self.user_identifier = identifier.to_owned();
        self
    }

    /// Sets the dated minor version that goes out as `Elasticdms-Version`.
    ///
    /// It goes to **both** hosts, to `/v1/oauth/*` as well: a header that goes along only
    /// sometimes is forgotten at exactly the moment the server starts to evaluate it
    /// (contract §7.0.1, finding Q-6).
    #[must_use]
    pub fn with_api_version(mut self, version: &str) -> Self {
        self.api_version = version.to_owned();
        self
    }

    /// Sets the time limits.
    #[must_use]
    pub fn with_time_limit(mut self, connection: Duration, read: Duration) -> Self {
        self.connect_timeout = connection;
        self.read_limit = read;
        self
    }

    /// The resource API, without a trailing slash.
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// The authorization server, without a trailing slash.
    pub fn auth_base(&self) -> &str {
        &self.auth_base
    }

    /// The identifier of this workstation.
    pub const fn device(&self) -> DeviceIdentifier {
        self.device
    }

    /// The value of the `Elasticdms-Version` header.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// The value of the `User-Agent` header.
    pub fn user_identifier(&self) -> &str {
        &self.user_identifier
    }

    /// The time limit for establishing the connection.
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The time limit of the silence while reading.
    pub const fn read_limit(&self) -> Duration {
        self.read_limit
    }

    /// `<api_base><path>` — `path` begins with a slash (that is how the path functions in
    /// `edms-wire` deliver it).
    pub(crate) fn api(&self, path: &str) -> String {
        format!("{}{path}", self.api_base)
    }

    /// `<auth_base><path>`.
    pub(crate) fn auth(&self, path: &str) -> String {
        format!("{}{path}", self.auth_base)
    }
}

/// Checks a base address and cuts off the trailing slash.
///
/// The slash falls here and only here: `edms_wire::basics::is_below` compares later against
/// `<base>/`, and a base with two meanings would yield two comparisons.
fn check(field: &'static str, address: &str) -> Result<String, ConnectionError> {
    let trimmed = address.trim_end_matches('/');
    let error = |reason| ConnectionError::Address { field, address: address.to_owned(), reason };
    let (scheme, rest) =
        trimmed.split_once("://").ok_or_else(|| error("scheme and host are missing"))?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err(error("the host is missing"));
    }
    if rest.contains('?') || rest.contains('#') {
        return Err(error("a base carries neither query nor fragment"));
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(trimmed.to_owned()),
        "http" if shows_on_loop(rest) => Ok(trimmed.to_owned()),
        "http" => Err(ConnectionError::Plaintext { field, address: address.to_owned() }),
        _ => Err(error("only http and https")),
    }
}

/// Whether the host behind `://` is the local loopback.
///
/// Compared is the host up to the colon of the port and up to the first slash;
/// `127.0.0.1.example.org` is therefore **not** the loopback — otherwise the exception for the mock
/// would be a way to permit plaintext against a foreign host.
fn shows_on_loop(rest: &str) -> bool {
    let without_path = rest.split('/').next().unwrap_or(rest);
    // IPv6 stands in square brackets; the colon of the port stands behind the closing one, the
    // colons of the address before it. Without brackets the first colon separates off the port.
    let host = match without_path.find(']') {
        Some(end) => without_path.get(..=end).unwrap_or(without_path),
        None => without_path.split(':').next().unwrap_or(without_path),
    };
    LOOP.contains(&host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceIdentifier {
        "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB".parse().expect("the contract's example identifier")
    }

    #[test]
    fn https_bases_are_remembered_without_a_trailing_slash() {
        let c = Connection::new(
            "https://api.elasticdms.io/",
            "https://auth.elasticdms.io",
            device(),
            "1.0.0",
        )
        .expect("both bases are https");
        assert_eq!(c.api_base(), "https://api.elasticdms.io");
        assert_eq!(c.auth_base(), "https://auth.elasticdms.io");
        assert_eq!(c.api("/v1/cases"), "https://api.elasticdms.io/v1/cases");
        assert_eq!(c.auth("/v1/oauth/token"), "https://auth.elasticdms.io/v1/oauth/token");
    }

    #[test]
    fn plaintext_against_a_real_host_aborts_the_start() {
        let error = Connection::new(
            "http://api.elasticdms.io",
            "https://auth.elasticdms.io",
            device(),
            "1.0.0",
        )
        .expect_err("plaintext against a tenant host is ruled out");
        assert!(matches!(error, ConnectionError::Plaintext { field: "API base", .. }));
    }

    #[test]
    fn plaintext_against_the_loopback_is_allowed_because_the_mock_runs_there() {
        for base in ["http://127.0.0.1:8480", "http://localhost:8480", "http://[::1]:8480"] {
            Connection::new(base, base, device(), "1.0.0")
                .unwrap_or_else(|_| panic!("{base} is the loopback"));
        }
    }

    #[test]
    fn a_prefix_of_the_loopback_is_not_yet_the_loopback() {
        let error =
            Connection::new("http://127.0.0.1.example.org", "https://auth.example", device(), "1")
                .expect_err("only the host itself is the loopback, no prefix of it");
        assert!(matches!(error, ConnectionError::Plaintext { .. }));
    }

    #[test]
    fn a_base_without_a_scheme_or_host_is_rejected() {
        for (address, _) in [("api.elasticdms.io", ()), ("https:///v1", ()), ("ftp://x", ())] {
            let error = Connection::new(address, "https://auth.example", device(), "1")
                .expect_err("no usable base");
            assert!(matches!(error, ConnectionError::Address { field: "API base", .. }));
        }
    }

    #[test]
    fn a_base_with_a_query_is_not_a_base() {
        let error =
            Connection::new("https://api.example?x=1", "https://auth.example", device(), "1")
                .expect_err("a base carries no query");
        assert!(matches!(error, ConnectionError::Address { .. }));
    }

    #[test]
    fn the_user_agent_names_version_and_operating_system() {
        let c = Connection::new("https://a.example", "https://b.example", device(), "1.2.3")
            .expect("https");
        assert!(c.user_identifier().starts_with("elasticdms-folder-client/1.2.3 ("));
        assert!(c.user_identifier().ends_with(')'));
        assert_eq!(c.api_version(), API_VERSION);
    }
}
