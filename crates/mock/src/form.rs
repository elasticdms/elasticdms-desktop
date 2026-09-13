//! `application/x-www-form-urlencoded` — reading and writing, without a foreign crate.
//!
//! The token endpoint (RFC 6749 §4), the device authorization (RFC 8628 §3.1) and the revocation
//! (RFC 7009 §2.1) carry their fields as a form; query parameters (`cursor`, `limit`, `wait`,
//! `user_code`) use the same encoding. The mock passes the pairs on to [`edms_wire::login`] as a
//! `Vec<(String, String)>` — exactly the shape its `from_form` expects.
//!
//! **Why by hand and not `serde_urlencoded`:** the wire needs the pairs in their **order** and
//! with repetitions, because by RFC 6749 §3.1 a duplicated field is an error and has to arrive as
//! one; a reader that folds into a map swallows the second value, and the mock would silently
//! accept what the server refused.

/// Reads the pairs of a form body or a query string, in their order.
///
/// A field without `=` gets the empty value; an empty chunk (`a=1&&b=2`) falls away. Both follow
/// the reading of WHATWG URL §5.1 that browsers and servers keep to.
pub fn read(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| match chunk.split_once('=') {
            Some((name, value)) => (decode(name), decode(value)),
            None => (decode(chunk), String::new()),
        })
        .collect()
}

/// Finds the first value of a field.
pub fn field<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(n, _)| n == name).map(|(_, w)| w.as_str())
}

/// Decodes `%XX` and `+`. An incomplete or invalid sequence stays as it arrived — a form that is
/// mangled on its way to the mock should show up as a wrong value and not as an empty one.
pub fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let high = (bytes[i + 1] as char).to_digit(16);
                let low = (bytes[i + 2] as char).to_digit(16);
                match (high, low) {
                    (Some(h), Some(t)) => {
                        out.push(((h << 4) | t) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encodes a value for a query string (`application/x-www-form-urlencoded`).
///
/// Only the characters RFC 3986 §2.3 lists as "unreserved" stay unescaped. Everything else is
/// percent-encoded — the space too, and as `%20` rather than `+`: in a path a `+` would be a plus
/// sign, and the address the client opens is a path.
pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(*b));
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duplicated_field_stays_duplicated_and_the_order_stays() {
        let pairs = read("grant_type=refresh_token&scope=a&scope=b");
        assert_eq!(
            pairs,
            vec![
                ("grant_type".to_owned(), "refresh_token".to_owned()),
                ("scope".to_owned(), "a".to_owned()),
                ("scope".to_owned(), "b".to_owned()),
            ]
        );
    }

    #[test]
    fn plus_and_percent_become_a_space_and_an_umlaut() {
        assert_eq!(
            decode("Offene+Rechnungen+%C3%BCber+10.000+%E2%82%AC"),
            "Offene Rechnungen über 10.000 €"
        );
    }

    #[test]
    fn an_incomplete_percent_sequence_stays_instead_of_disappearing() {
        assert_eq!(decode("a%"), "a%");
        assert_eq!(decode("a%zz"), "a%zz");
    }

    #[test]
    fn a_field_without_an_equals_sign_has_the_empty_value() {
        assert_eq!(read("wait"), vec![("wait".to_owned(), String::new())]);
        assert_eq!(read(""), Vec::new());
        assert_eq!(read("a=1&&b=2").len(), 2);
    }

    #[test]
    fn encoding_and_decoding_are_the_same_value() {
        for value in ["Prüfbericht Pumpe 7.pdf", "cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7", "a&b=c%20d"] {
            assert_eq!(decode(&encode(value)), value);
        }
        assert!(!encode("a b").contains('+'), "a space belongs in a path as %20");
    }

    #[test]
    fn field_finds_the_first_value() {
        let pairs = read("a=1&a=2");
        assert_eq!(field(&pairs, "a"), Some("1"));
        assert_eq!(field(&pairs, "b"), None);
    }
}
