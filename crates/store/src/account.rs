//! The account: the opaque `sub` of the signed-in user.
//!
//! Log rows and the session hang off it. Requirement 4 binds the view to the user, and the store
//! separates the rows at exactly this string — that is why it is a type of its own and not a
//! `String` that could be mistaken for the tenant or the display name.
//!
//! The content stays opaque, the way the client treats the `sub`
//! (`edms_core::identifier::UserKind`). Checked is only what would otherwise undercut the
//! separation: empty — then the rows of all users without a `sub` would land in one common pot —,
//! whitespace at the edges or control characters — then `usr_1` and `usr_1 ` would be two accounts
//! of the same person, and his rows would disappear.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The account identifier (`sub`) that log rows and the session stand under.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Account(String);

/// Why a string is not an account identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{text}` is not usable as an account identifier: {reason}")]
pub struct AccountError {
    text: String,
    reason: &'static str,
}

impl Account {
    /// An account identifier; fails on empty, whitespace at the edges and control characters.
    pub fn new(sub: impl Into<String>) -> Result<Self, AccountError> {
        let text = sub.into();
        let reason = if text.is_empty() {
            Some("it is empty")
        } else if text.trim() != text {
            Some("it has whitespace at the edges")
        } else if text.chars().any(char::is_control) {
            Some("it contains control characters")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(AccountError { text, reason }),
            None => Ok(Self(text)),
        }
    }

    /// The string as it stood in the token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Account {
    type Err = AccountError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl TryFrom<String> for Account {
    type Error = AccountError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<Account> for String {
    fn from(account: Account) -> Self {
        account.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_account_or_one_with_whitespace_or_control_characters_is_rejected() {
        assert!(Account::new("").is_err());
        assert!(Account::new("usr_1 ").is_err());
        assert!(Account::new(" usr_1").is_err());
        assert!(Account::new("usr\n1").is_err());
        let error = Account::new("").unwrap_err();
        assert!(error.to_string().contains("empty"), "{error}");
    }

    #[test]
    fn an_account_stays_opaque_and_survives_the_round_trip_as_json() {
        // No check for `usr_`: the sub belongs to the server, not to this crate.
        let k = Account::new("00000000-entra-oid").unwrap();
        assert_eq!(k.as_str(), "00000000-entra-oid");
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, "\"00000000-entra-oid\"");
        assert_eq!(serde_json::from_str::<Account>(&json).unwrap(), k);
        assert!(serde_json::from_str::<Account>("\"\"").is_err());
        assert_eq!("usr_A".parse::<Account>().unwrap().to_string(), "usr_A");
    }
}
