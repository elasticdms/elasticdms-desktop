//! A secret that does not give its own `Debug` output away.
//!
//! Access token, refresh token, `device_code` and client assertion are strings like any other — and
//! precisely for that reason they land in the field in a log as soon as a `{request:?}` stands
//! somewhere. A type of its own takes that opportunity away: the value comes out only over
//! [`Secret::open`], and one sees that place when reading the code (contract test T25, 03 §6.0.6).

use std::fmt;

/// A string that must stand in no output.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Takes a string as a secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext — for the one header it belongs in.
    ///
    /// The name says what happens here: from here on the secret is open, and whoever passes it on
    /// has done so himself.
    pub fn open(&self) -> &str {
        &self.0
    }

    /// Whether there is anything in it at all. An empty token is none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Neither content nor length: the length of a token betrays its kind, and an output that says
/// "24 characters" is the first step towards one that says the value.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("‹secret›")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_stands_in_no_debug_output() {
        let secret = Secret::new("eyJhbGciOiJFUzI1NiJ9.access-token");
        assert_eq!(format!("{secret:?}"), "‹secret›");
        assert!(!format!("{secret:?}").contains("access-token"));
        assert!(!format!("{:?}", Some(secret.clone())).contains("access-token"));
        assert_eq!(secret.open(), "eyJhbGciOiJFUzI1NiJ9.access-token");
    }

    #[test]
    fn an_empty_secret_reports_itself_as_empty() {
        assert!(Secret::new("").is_empty());
        assert!(!Secret::from("x").is_empty());
    }
}
