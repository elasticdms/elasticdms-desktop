//! The network's errors: values carrying whole sentences.
//!
//! Two families, and they part at one question: did the **server** pass judgement or not?
//!
//! * [`ConnectionError`] comes into being when building — a plaintext address, a host without a
//!   scheme. It aborts the start before a single byte goes out.
//! * [`NetworkError`] comes into being afterwards and always means: **no server judgement**. The
//!   line was away, the answer was not readable, the counterpart did not keep the contract. A
//!   server error on the merits, by contrast, is a judgement and stands as
//!   [`crate::ApiResult::SlotError`].
//!
//! The separation is no formality: on a network error the client waits and tries again, on a server
//! judgement never blindly (contract test T14).

use edms_crypto::CryptoError;
use edms_wire::content::ContentHeaderError;

use crate::binding::KeyBinding;

/// Why a [`crate::Connection`] does not even come into being.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    /// The address is not an absolute http(s) address with a host.
    #[error("`{address}` is not usable as the {field}: {reason}")]
    Address {
        /// `API base` or `sign-in base`.
        field: &'static str,
        /// What was configured.
        address: String,
        /// What it is down to.
        reason: &'static str,
    },

    /// Plaintext against a host other than the loopback.
    ///
    /// Against `127.0.0.1`, `localhost` and `[::1]`, `http` is allowed and also necessary — the
    /// mock runs there. Against any other host it would be an archive going in plaintext over the
    /// customer's network, and the deviation strikes nobody, because everything works.
    #[error(
        "`{address}` is configured as the {field} in plaintext; http counts only against \
         127.0.0.1, localhost and [::1] (the mock), everywhere else https and nothing but"
    )]
    Plaintext {
        /// `API base` or `sign-in base`.
        field: &'static str,
        /// What was configured.
        address: String,
    },

    /// The HTTP client could not be built (TLS backing of the operating system, missing roots).
    #[error("the HTTP client could not be set up: {0}")]
    Client(String),
}

/// Why a call ended without a judgement of the server.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// The connection did not come about or broke off.
    #[error("`{target}` cannot be reached: {reason}")]
    Connection {
        /// Method and path, without query parameters.
        target: String,
        /// What the library reports.
        reason: String,
    },

    /// The counterpart did not answer within the time limit.
    #[error("`{target}` did not answer within the time limit")]
    Timeout {
        /// Method and path.
        target: String,
    },

    /// A redirect. It is evaluated, never followed.
    ///
    /// Every resource of this contract has exactly one place. A redirect is therefore either an
    /// error of the counterpart or an attack — and a client that followed it would send token and
    /// proof along to the new place.
    #[error("`{target}` answered with a redirect{location}; the client follows none", location = .location.as_ref().map(|o| format!(" to `{o}`")).unwrap_or_default())]
    Redirect {
        /// Method and path.
        target: String,
        /// The content of `Location`, if one came.
        location: Option<String>,
    },

    /// The answer could not be read into its type.
    #[error("the answer to `{what}` was not readable: {reason}")]
    UnreadableResponse {
        /// Which call — named as a noun phrase, not as a path.
        what: &'static str,
        /// What it failed at.
        reason: String,
    },

    /// The request body of our own could not be written.
    ///
    /// Can only be a bug in this program — a wire type that does not serialise. It stands as a
    /// value all the same and not as an `expect`: a crash in the tray process takes the whole
    /// folder away from the user, and this message at least says which call it was.
    #[error("the body for {what} could not be written: {reason}")]
    RequestBody {
        /// Which call.
        what: &'static str,
        /// What serde reports.
        reason: String,
    },

    /// The answer was readable but contradicts the contract.
    ///
    /// The model case is `hasMore: true` without `nextCursor`: whoever resolved it in favour of
    /// "then that is the end" would quietly show a truncated case file (Akte) — and a missing
    /// document in the folder is exactly the lie this client must not tell (03 §6.0.8).
    #[error("the counterpart does not keep the contract: {reason}")]
    ContractBreach {
        /// Which promise was broken.
        reason: String,
    },

    /// The headers of the content are missing or do not match the row of the listing.
    #[error(transparent)]
    ContentHeader(#[from] ContentHeaderError),

    /// The server delivered fewer or more bytes than announced in `Content-Length`.
    ///
    /// It notices a hash error only at the last `Read`, long after `200` and the headers have been
    /// sent (contract test T13). Without this comparison the client would see a short body without
    /// an error status — and would put a mutilated file into the folder.
    #[error(
        "the server delivered {actual} instead of {expected} bytes; the file was not taken over"
    )]
    Incomplete {
        /// According to `Content-Length`.
        expected: u64,
        /// Actually received.
        actual: u64,
    },

    /// The sink did not accept the bytes (disk full, platform has aborted).
    #[error("the loaded content could not be written: {reason}")]
    Sink {
        /// What the operating system reports.
        reason: String,
    },

    /// The server demanded a new nonce twice for the same request.
    ///
    /// Exactly one retry (03 §6.0.5, contract test T9). A loop would be a self-DoS here against a
    /// server that does not accept its own nonce.
    #[error(
        "`{target}` demanded a new DPoP nonce even after the retry; the client repeats exactly \
         once and then breaks off"
    )]
    NonceLoop {
        /// Method and path.
        target: String,
    },

    /// In the middle of a stream the prompt for a new nonce came.
    ///
    /// A body that streams out of a file cannot be sent a second time without reopening the file —
    /// and that is a decision of the engine, not of this crate. The nonce stands in the store
    /// afterwards; the next attempt goes through.
    #[error(
        "`{target}` demanded a new DPoP nonce while the body was already streaming; the call is \
         to be repeated with the nonce now known"
    )]
    NonceInStream {
        /// Method and path.
        target: String,
    },

    /// For this binding there is no proof key.
    #[error(
        "without the {0} key no call goes out; the device is not set up or nobody is signed in"
    )]
    NoKey(KeyBinding),

    /// For this binding there is no token.
    #[error("without the {0} token this call does not go out; it demands a valid sign-in")]
    NoToken(KeyBinding),

    /// A proof, an assertion or an identifier could not be produced.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// The renewal broke off before an answer arrived.
    ///
    /// A refresh attempt is **never** repeated blindly: reusing a rotated refresh token revokes the
    /// whole token family across devices (03 §6.3.3, contract test T14). Whether the server has
    /// rotated, nobody here knows — so the user signs in anew instead of the client guessing.
    #[error(
        "the renewal of the session broke off before an answer arrived ({reason}); whether the \
         server has already rotated the refresh token is unknown. A second attempt with the same \
         token would revoke the whole token family — please sign in anew"
    )]
    RefreshUncertain {
        /// What the line reported.
        reason: String,
    },
}

impl NetworkError {
    /// Whether a retry comes into question at all.
    ///
    /// "The line was away" may be repeated; "the server broke the contract" and "the renewal is
    /// uncertain" may not — the second attempt would find the same error, the third one too, and
    /// with the renewal it would cost the whole token family.
    pub fn may_repeated_become(&self) -> bool {
        matches!(self, Self::Connection { .. } | Self::Timeout { .. } | Self::NonceInStream { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redirect_names_its_destination_in_plain_text() {
        let error = NetworkError::Redirect {
            target: "GET /v1/cases".into(),
            location: Some("https://evil.example/v1/cases".into()),
        };
        let text = error.to_string();
        assert!(text.contains("https://evil.example/v1/cases"), "{text}");
        assert!(text.contains("follows none"), "{text}");
    }

    #[test]
    fn a_redirect_without_a_location_stays_a_whole_sentence() {
        let error = NetworkError::Redirect { target: "GET /v1/cases".into(), location: None };
        assert_eq!(
            error.to_string(),
            "`GET /v1/cases` answered with a redirect; the client follows none"
        );
    }

    #[test]
    fn an_uncertain_renewal_must_not_be_repeated() {
        let error = NetworkError::RefreshUncertain { reason: "connection broken off".into() };
        assert!(!error.may_repeated_become());
        assert!(NetworkError::Timeout { target: "GET /v1/cases".into() }.may_repeated_become());
        assert!(
            !NetworkError::ContractBreach { reason: "hasMore without nextCursor".into() }
                .may_repeated_become()
        );
    }

    #[test]
    fn a_plaintext_target_names_the_permitted_exception() {
        let error = ConnectionError::Plaintext {
            field: "API base",
            address: "http://api.example.org".into(),
        };
        assert!(error.to_string().contains("127.0.0.1"));
    }
}
