//! The `WWW-Authenticate` header — two prompts that have nothing to do with each other.
//!
//! * `error="use_dpop_nonce"` — a **technical** repetition with the new nonce, without a human
//!   doing anything (RFC 9449 §8). Exactly one.
//! * `error="insufficient_user_authentication"` — a human has to sign in **again and more
//!   strongly** (RFC 9470). The client never guesses the level itself: `acr_values` and `max_age`
//!   come unchanged out of the challenge, so that the policy lives in the server and not in the
//!   program.
//!
//! The authorization server says the same thing differently: `400` with
//! `{"error":"use_dpop_nonce"}` in the body instead of `401` with a header (RFC 9449 §8 as against
//! §9). Both forms mean the same and are treated alike — otherwise the sign-in hangs at exactly the
//! point where it begins.
//!
//! Reading is **lenient**. The header is an `auth-param` construct after RFC 9110 with optional
//! quotation marks, several schemes and arbitrary whitespace. A strict parser that delivers nothing
//! on a deviation would lead to a sign-in failure here; the tolerance costs nothing, because the
//! values only steer *which* question the client asks next.

use edms_wire::basics::{ErrorKind, Problem, WWW_ERROR_NONCE, WWW_ERROR_STEP_UP};

/// A step-up prompt after RFC 9470.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StepUpRequest {
    /// The demanded `acr` values, in the server's order.
    pub acr_values: Vec<String>,
    /// Maximum age of the sign-in in seconds.
    pub max_age_second: Option<u64>,
    /// Plain text of the server for display, the folder name for instance.
    pub rationale: Option<String>,
}

impl StepUpRequest {
    /// The first demanded `acr` value — the one the new flow starts with.
    pub fn first_acr(&self) -> Option<&str> {
        self.acr_values.first().map(String::as_str)
    }

    /// The `acr_values` as one form value, separated by spaces.
    pub fn acr_value(&self) -> Option<String> {
        if self.acr_values.is_empty() { None } else { Some(self.acr_values.join(" ")) }
    }
}

/// Whether the header demands a new nonce.
pub(crate) fn requires_nonce(header: Option<&str>) -> bool {
    parameter(header).into_iter().any(|(name, value)| name == "error" && value == WWW_ERROR_NONCE)
}

/// Whether the body of the authorization server demands a new nonce (RFC 9449 §8).
///
/// Read is the field `error`, not the whole body: an error description that happens to contain the
/// word would otherwise set off a repetition that changes nothing.
pub(crate) fn body_requires_nonce(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
        .is_some_and(|error| error == WWW_ERROR_NONCE)
}

/// The step-up challenge, if header or problem carries one.
///
/// The body is the fallback: if the header does not pass the values along, `requiredAcr` and
/// `maxAgeSeconds` stand as extension fields in the problem (03 §6.3.5).
pub(crate) fn step_up(header: Option<&str>, problem: &Problem) -> Option<StepUpRequest> {
    let field = parameter(header);
    let value = |wanted: &str| {
        field.iter().find(|(name, _)| name == wanted).map(|(_, value)| value.clone())
    };
    let from_header = value("error").is_some_and(|f| f == WWW_ERROR_STEP_UP);
    let from_body = problem.error_kind() == ErrorKind::AuthenticationTooWeak;
    if !from_header && !from_body {
        return None;
    }

    let mut acr_values: Vec<String> = value("acr_values")
        .map(|text| text.split(' ').filter(|part| !part.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default();
    if let Some(from_problem) = problem.extension("requiredAcr").and_then(|value| value.as_str())
        && !acr_values.iter().any(|v| v == from_problem)
    {
        acr_values.push(from_problem.to_owned());
    }
    let max_age_second = value("max_age")
        .and_then(|text| text.parse().ok())
        .or_else(|| problem.extension("maxAgeSeconds").and_then(serde_json::Value::as_u64));

    Some(StepUpRequest {
        acr_values,
        max_age_second,
        rationale: value("error_description").or_else(|| problem.detail.clone()),
    })
}

/// Breaks `DPoP error="…", acr_values="…", max_age=120` into its parameters.
///
/// Deliberately by hand instead of with a regular expression: one more crate in the workspace would
/// be one more dependency, and the language is small enough — name, `=`, value in quotation marks
/// or up to the next comma or space.
fn parameter(header: Option<&str>) -> Vec<(String, String)> {
    let Some(header) = header else { return Vec::new() };
    let character: Vec<char> = header.chars().collect();
    let mut from: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < character.len() {
        // A name begins with a letter or an underscore.
        if !(character[i].is_ascii_alphabetic() || character[i] == '_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < character.len()
            && (character[i].is_ascii_alphanumeric() || character[i] == '_' || character[i] == '-')
        {
            i += 1;
        }
        let name: String = character[start..i].iter().collect::<String>().to_ascii_lowercase();
        let by_name = i;
        while i < character.len() && character[i] == ' ' {
            i += 1;
        }
        if i >= character.len() || character[i] != '=' {
            // Not a parameter but the name of the scheme (`DPoP`). On to the next word.
            i = by_name;
            continue;
        }
        i += 1;
        while i < character.len() && character[i] == ' ' {
            i += 1;
        }
        let value: String = if i < character.len() && character[i] == '"' {
            i += 1;
            let start = i;
            while i < character.len() && character[i] != '"' {
                i += 1;
            }
            let value = character[start..i].iter().collect();
            if i < character.len() {
                i += 1;
            }
            value
        } else {
            let start = i;
            while i < character.len() && character[i] != ',' && character[i] != ' ' {
                i += 1;
            }
            character[start..i].iter().collect()
        };
        // The first value counts: a second `error=` in a second scheme does not change the prompt
        // of the first.
        if !from.iter().any(|(present, _)| present == &name) {
            from.push((name, value));
        }
    }
    from
}

// The `error_description` and `detail` texts below are German on purpose: they stand for what
// the **server** writes, and this client asks for exactly that with `Accept-Language: de-DE`
// (see `connection::LANGUAGE`). They are carried through word for word into `rationale`, so a
// fixture in English would prove the wrong thing.
#[cfg(test)]
mod tests {
    use super::*;

    fn problem(body: &str) -> Problem {
        Problem::read(401, body.as_bytes())
    }

    #[test]
    fn use_dpop_nonce_is_recognised_in_the_header() {
        assert!(requires_nonce(Some(r#"DPoP error="use_dpop_nonce", algs="ES256""#)));
        assert!(requires_nonce(Some("DPoP error=use_dpop_nonce")));
        assert!(!requires_nonce(Some(r#"DPoP error="invalid_token""#)));
        assert!(!requires_nonce(None));
    }

    #[test]
    fn use_dpop_nonce_is_recognised_in_the_body_of_the_sign_in_server() {
        assert!(body_requires_nonce(br#"{"error":"use_dpop_nonce"}"#));
        assert!(!body_requires_nonce(br#"{"error":"invalid_grant"}"#));
        assert!(!body_requires_nonce(b"no json"));
    }

    #[test]
    fn an_error_description_containing_the_word_sets_off_no_repetition() {
        assert!(!body_requires_nonce(
            br#"{"error":"invalid_request","error_description":"use_dpop_nonce fehlte"}"#
        ));
    }

    #[test]
    fn a_step_up_challenge_is_read_from_the_header() {
        let request = step_up(
            Some(
                r#"DPoP error="insufficient_user_authentication", acr_values="urn:a urn:b", max_age=120, error_description="Ordner verlangt mehr""#,
            ),
            &problem("{}"),
        )
        .expect("the header carries a challenge");
        assert_eq!(request.acr_values, vec!["urn:a".to_owned(), "urn:b".to_owned()]);
        assert_eq!(request.max_age_second, Some(120));
        assert_eq!(request.first_acr(), Some("urn:a"));
        assert_eq!(request.rationale.as_deref(), Some("Ordner verlangt mehr"));
    }

    #[test]
    fn a_step_up_challenge_without_a_header_comes_from_the_problem() {
        let body = r#"{"type":"https://errors.elasticdms.io/insufficient-authentication",
            "status":401,"detail":"Bitte erneut anmelden","requiredAcr":"urn:c","maxAgeSeconds":60}"#;
        let request = step_up(None, &problem(body)).expect("the problem carries the challenge");
        assert_eq!(request.acr_values, vec!["urn:c".to_owned()]);
        assert_eq!(request.max_age_second, Some(60));
        assert_eq!(request.acr_value().as_deref(), Some("urn:c"));
    }

    #[test]
    fn a_nonce_prompt_is_not_a_step_up() {
        assert!(step_up(Some(r#"DPoP error="use_dpop_nonce""#), &problem("{}")).is_none());
    }

    #[test]
    fn the_scheme_name_is_not_taken_for_a_parameter() {
        let field = parameter(Some(r#"Bearer realm="x", DPoP error="use_dpop_nonce""#));
        assert!(field.iter().any(|(name, value)| name == "realm" && value == "x"));
        assert!(field.iter().any(|(name, value)| name == "error" && value == "use_dpop_nonce"));
    }
}
