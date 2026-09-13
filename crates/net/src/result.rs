//! The result of a server call — six outcomes, not two.
//!
//! The difference between "the server said no on the merits", "you already have it", "somebody has
//! to sign in more strongly", "something is wrong here that we must not quietly take over" and "the
//! network was away" is no nicety at a workstation: the first case shows a message in the Explorer,
//! the second nothing at all (the listing is already there), the third opens the browser, the
//! fourth a security warning in the usage log, the fifth nothing — because work goes on as soon as
//! the network comes back.
//!
//! Whoever collapses them into `Result<T, Error>` makes the distinction later at every call site
//! anew — and wrongly at the third.

use edms_wire::basics::{ErrorKind, Problem};

use crate::challenge::StepUpRequest;
use crate::error::NetworkError;

/// The successful call together with what the headers say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Success<T> {
    /// The value that was read.
    pub value: T,
    /// The strong ETag of the resource, if the server delivered one.
    pub etag: Option<String>,
    /// `Idempotency-Replayed: true` — the server has repeated a stored answer (03 §6.0.10). Not
    /// an error: that is exactly what the key is there for.
    pub idempotency_repeat: bool,
    /// The HTTP status; `201` and `200` mean different things at the enrolment.
    pub status: u16,
}

impl<T> Success<T> {
    /// A success without header details — for mocks and tests.
    pub fn plain(value: T) -> Self {
        Self { value, etag: None, idempotency_repeat: false, status: 200 }
    }
}

/// What a call yielded.
#[derive(Debug)]
pub enum ApiResult<T> {
    /// The call went through.
    Success(Success<T>),

    /// `304 Not Modified`: the ETag sent along is still current.
    ///
    /// Not an error and not an empty success, but the statement "you already have it". A
    /// workstation with 200 case files (Akten) would otherwise ask for 200 complete listings on
    /// every beat, and the archive would bear the load of a display that has not changed
    /// (contract §7.1.3).
    Unchanged {
        /// The ETag the server confirmed along the way, if it sent one.
        etag: Option<String>,
    },

    /// The server rejected the call on the merits (RFC 9457 or RFC 6749 §5.2).
    SlotError {
        /// The problem that was read; an unknown `type` becomes [`ErrorKind::Unknown`] and is
        /// **never** reinterpreted into a crash or into a known type (contract §7.5.1).
        problem: Problem,
        /// `Retry-After` in seconds. It beats every local backoff (03 §6.0.11): a client with a
        /// schedule of its own turns a throttling into an overload.
        repeat_after: Option<u64>,
    },

    /// RFC 9470: the action demands a fresher or stronger sign-in.
    ///
    /// Not an error in the narrow sense — the client starts a second device flow with exactly the
    /// values from the challenge and repeats the call unchanged afterwards. It never guesses the
    /// level itself; otherwise the policy would live in the client instead of in the server.
    StepUpNeeded {
        /// `acr_values` and `max_age`, as the server names them.
        request: StepUpRequest,
        /// The problem that belongs to it.
        problem: Problem,
    },

    /// Something the client **must not quietly take over**.
    ///
    /// The server carries the case as a `securityEvent` (03 §6.0.7), or the answer itself is the
    /// finding: a foreign issuer in the discovery document, an `uploadUrl` on a foreign host, a
    /// reused refresh token. The engine writes a security warning into the usage log — the user's
    /// only opportunity to notice it.
    SecurityAbort {
        /// A whole sentence for the usage log and the display.
        notice: String,
        /// The problem, if the server delivered one.
        problem: Option<Problem>,
    },

    /// No server judgement: the line was away, the answer not readable, the contract broken.
    NetworkError(NetworkError),
}

impl<T> ApiResult<T> {
    /// A plain success — above all for mocks of the engine.
    pub fn success(value: T) -> Self {
        Self::Success(Success::plain(value))
    }

    /// Whether the call went through. `304` does **not** count as a success here: there is no
    /// value.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// The value on success, otherwise `None`.
    pub fn value(self) -> Option<T> {
        match self {
            Self::Success(success) => Some(success.value),
            _ => None,
        }
    }

    /// The problem, if the server delivered one.
    pub const fn problem(&self) -> Option<&Problem> {
        match self {
            Self::SlotError { problem, .. } | Self::StepUpNeeded { problem, .. } => Some(problem),
            Self::SecurityAbort { problem, .. } => problem.as_ref(),
            _ => None,
        }
    }

    /// The error kind behind the `type` URI, if the server rejected the call.
    pub fn error_kind(&self) -> Option<ErrorKind> {
        self.problem().map(Problem::error_kind)
    }

    /// Whether the case counts as a security event — marked by the server or by the catalogue.
    pub fn is_security_event(&self) -> bool {
        matches!(self, Self::SecurityAbort { .. })
            || self.problem().is_some_and(Problem::is_security_event)
    }

    /// Separates the success from every other outcome — and carries the other outcome over into a
    /// **different** value type.
    ///
    /// With it a call whose value is only an intermediate stage can be passed on with `?`-like
    /// brevity, without a "cannot happen" standing anywhere: the translation is complete, and a
    /// success comes out as `Ok`.
    // The error branch is deliberately large: it carries the whole problem with `detail`,
    // `errors[]` and `traceId`. Boxing it saves a few bytes on the stack and costs an indirection
    // at every call site — with one call per network request that is the wrong trade.
    #[allow(clippy::result_large_err)]
    pub fn success_or<R>(self) -> Result<Success<T>, ApiResult<R>> {
        match self {
            Self::Success(success) => Ok(success),
            Self::Unchanged { etag } => Err(ApiResult::Unchanged { etag }),
            Self::SlotError { problem, repeat_after } => {
                Err(ApiResult::SlotError { problem, repeat_after })
            }
            Self::StepUpNeeded { request, problem } => {
                Err(ApiResult::StepUpNeeded { request, problem })
            }
            Self::SecurityAbort { notice, problem } => {
                Err(ApiResult::SecurityAbort { notice, problem })
            }
            Self::NetworkError(error) => Err(ApiResult::NetworkError(error)),
        }
    }

    /// Maps the success value and leaves every other outcome standing unchanged.
    pub fn map<R>(self, mapping: impl FnOnce(T) -> R) -> ApiResult<R> {
        match self {
            Self::Success(success) => ApiResult::Success(Success {
                value: mapping(success.value),
                etag: success.etag,
                idempotency_repeat: success.idempotency_repeat,
                status: success.status,
            }),
            Self::Unchanged { etag } => ApiResult::Unchanged { etag },
            Self::SlotError { problem, repeat_after } => {
                ApiResult::SlotError { problem, repeat_after }
            }
            Self::StepUpNeeded { request, problem } => ApiResult::StepUpNeeded { request, problem },
            Self::SecurityAbort { notice, problem } => ApiResult::SecurityAbort { notice, problem },
            Self::NetworkError(error) => ApiResult::NetworkError(error),
        }
    }
}

impl<T> From<NetworkError> for ApiResult<T> {
    fn from(error: NetworkError) -> Self {
        Self::NetworkError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(kind: &str, status: u16) -> Problem {
        Problem::read(
            status,
            format!(r#"{{"type":"{kind}","title":"x","status":{status}}}"#).as_bytes(),
        )
    }

    #[test]
    fn an_unchanged_is_no_success_and_carries_no_value() {
        let result: ApiResult<u8> = ApiResult::Unchanged { etag: Some("\"7\"".into()) };
        assert!(!result.is_success());
        assert_eq!(result.value(), None);
    }

    #[test]
    fn an_unknown_type_stays_a_value_and_is_not_reinterpreted() {
        let result: ApiResult<u8> = ApiResult::SlotError {
            problem: problem("https://errors.elasticdms.io/does-not-exist-yet", 418),
            repeat_after: None,
        };
        assert_eq!(result.error_kind(), Some(ErrorKind::Unknown));
        assert!(!result.is_security_event());
    }

    #[test]
    fn a_security_event_of_the_catalogue_stands_out_even_without_a_marking() {
        let result: ApiResult<u8> = ApiResult::SlotError {
            problem: problem("https://errors.elasticdms.io/device-signature-mismatch", 403),
            repeat_after: None,
        };
        assert!(result.is_security_event());
    }

    #[test]
    fn map_leaves_every_error_outcome_standing() {
        let network: ApiResult<u8> =
            ApiResult::NetworkError(NetworkError::Timeout { target: "GET /x".into() });
        assert!(matches!(network.map(u32::from), ApiResult::NetworkError(_)));

        let success: ApiResult<u8> = ApiResult::success(3);
        assert_eq!(success.map(|value| u32::from(value) * 2).value(), Some(6));
    }
}
