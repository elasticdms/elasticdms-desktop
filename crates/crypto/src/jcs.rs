//! JSON canonicalization per RFC 8785 (JCS) — the bytes that are signed over.
//!
//! **RFC 8785 is not `serde_json`** (geraete-auth §5.2). `serde_json::to_string` writes `1.0`
//! instead of `1`, does not sort at all (with `preserve_order`) and knows no ECMAScript number
//! form; Go's `json.Marshal` escapes `<`, `>` and `&` — either would be a different byte
//! sequence from the one the server signed, and then no signature of an honest server would hold.
//!
//! The three rules:
//!
//! 1. **Names** ascending by UTF-16 code units (RFC 8785 §3.2.3). Not by bytes: for surrogate
//!    pairs against `U+E000..U+FFFF` that would give a different order.
//! 2. **Numbers** per ECMAScript `Number::toString` ([`number`]): `1` instead of `1.0`, fixed
//!    point below 10^21, above that `1e+21`.
//! 3. **Strings** minimally escaped: only `"`, `\` and `U+0000..U+001F` (with the short forms
//!    `\b \t \n \f \r`, otherwise `\u00xx` in lower case). Never `<`, `>`, `&`, never non-ASCII.
//!
//! No whitespace, no `NaN`, no infinity. A whole number beyond 2^53 is rejected instead of
//! silently rounded — as an IEEE 754 double it is no longer unambiguous, and a canonicalization
//! that rounds would sign a different value from the one it read (so too escan `Ecma262Zahl`).
//!
//! **A silent change here is the only way the chain can lie** (E5 on the counterpart's side).
//! That is why a golden corpus runs alongside (`testdata/jcs/`): the vectors from RFC 8785, the
//! corpus of the sibling client elasticdms-escan taken over byte for byte, and the cases from
//! geraete-auth §5.2.

use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::CryptoError;

/// The version of the canonicalization — the value that stands in fields like
/// `canonicalization`.
///
/// The same value as `Jcs.NAME` in the sibling client; the corpus' reference transcript carries
/// it.
pub const JCS_VERSION: &str = "RFC8785";

/// 2^53 — the largest whole number whose neighbours are still distinguishable as a double.
pub const MAX_EXACT_INTEGER: u64 = 1 << 53;

/// Upper bound of the fixed-point notation per ECMA-262: `n <= 21`.
const FIXED_POINT_TOP: i64 = 21;

/// Lower bound of the fixed-point notation per ECMA-262: `-6 < n`.
const FIXED_POINT_BOTTOM: i64 = -6;

/// Canonicalizes a JSON value into text.
pub fn canonicalize(value: &Value) -> Result<String, CryptoError> {
    let mut from = String::new();
    write(value, &mut from)?;
    Ok(from)
}

/// Canonicalizes a JSON value into the UTF-8 bytes that are signed and hashed over.
pub fn canonicalize_bytes(value: &Value) -> Result<Vec<u8>, CryptoError> {
    canonicalize(value).map(String::into_bytes)
}

/// Reads JSON text strictly per I-JSON (RFC 7493), as RFC 8785 §3.1 presupposes.
///
/// Unlike `serde_json::from_str`, a name that appears twice in the same object is **rejected**
/// instead of being silently overwritten by the last occurrence: two readers, one taking the
/// first and one the last occurrence, would check two different statements against the same
/// signature. Signed carriers should be read through this function.
pub fn read(text: &str) -> Result<Value, CryptoError> {
    let mut reader = serde_json::Deserializer::from_str(text);
    let value = StrictValue
        .deserialize(&mut reader)
        .map_err(|error| CryptoError::JsonUnreadable(error.to_string()))?;
    reader.end().map_err(|error| CryptoError::JsonUnreadable(error.to_string()))?;
    Ok(value)
}

/// Reads JSON text strictly ([`read`]) and canonicalizes it.
pub fn canonicalize_text(text: &str) -> Result<String, CryptoError> {
    canonicalize(&read(text)?)
}

/// A double in the form of ECMAScript `Number::toString` (ECMA-262 §6.1.6.1.20).
///
/// The specification demands two things, and the standard library delivers one of them each:
///
/// 1. **`k` as small as possible** — the shortest digit sequence that yields the same bit
///    pattern when read back. That is `{:e}` without a precision.
/// 2. **Among several `s` the one nearest the value, on a tie the even one.** That is `{:.*e}`
///    with `k-1` decimal places: exact rounding to the nearest even digit.
///
/// Taking only step 1 is the mistake that RFC 8785 appendix B records as *“Round to even”*:
/// `1424953923781206.25` has two shortest forms, `…6.2` and `…6.3`, and the standard library
/// picks `…6.3` — the counterpart writes `…6.2`, and the signature no longer holds. That is why
/// an exact rounding follows step 1.
///
/// `NaN` and the infinities are an error: JSON does not know them, and a substitute value would
/// be a lie in the hash.
pub fn number(value: f64) -> Result<String, CryptoError> {
    if value.is_nan() {
        return Err(CryptoError::JcsNumber {
            text: "NaN".into(),
            reason: "JSON does not know NaN",
        });
    }
    if value.is_infinite() {
        return Err(CryptoError::JcsNumber {
            text: format!("{value}"),
            reason: "JSON does not know infinity",
        });
    }
    // ECMAScript prints negative zero like the positive one.
    if value == 0.0 {
        return Ok("0".into());
    }
    if value < 0.0 {
        return Ok(format!("-{}", number(-value)?));
    }
    // Step 1: the shortest digit sequence that reads back as the same bit pattern.
    let (shortest, _) = exponential_form(&format!("{value:e}"))?;
    // Step 2: the same number of places again, this time rounded exactly (tie: to even).
    let positions = shortest.len().saturating_sub(1);
    let (digits, exponent) = exponential_form(&format!("{value:.positions$e}"))?;
    let digits = digits.trim_end_matches('0');
    let unreadable = || CryptoError::JcsNumber {
        text: format!("{value:e}"),
        reason: "the standard library delivered no exponential form",
    };
    if digits.is_empty() {
        return Err(unreadable());
    }
    // value = 0.digits * 10^n
    let k = i64::try_from(digits.len()).map_err(|_| unreadable())?;
    let n = exponent + 1;
    let zeroes = |count: i64| "0".repeat(usize::try_from(count).unwrap_or_default());
    let text = if k <= n && n <= FIXED_POINT_TOP {
        // Step 6: whole number with zeroes appended.
        format!("{digits}{}", zeroes(n - k))
    } else if 0 < n && n <= FIXED_POINT_TOP {
        // Step 7: the point inside the digits.
        let (front, back) = digits.split_at(usize::try_from(n).map_err(|_| unreadable())?);
        format!("{front}.{back}")
    } else if FIXED_POINT_BOTTOM < n && n <= 0 {
        // Step 8: leading zero and zeroes behind the point.
        format!("0.{}{digits}", zeroes(-n))
    } else {
        // Steps 9 and 10: exponential form, the plus sign is mandatory.
        let e = n - 1;
        let sign = if e >= 0 { '+' } else { '-' };
        let (first, rest) = digits.split_at(1);
        if rest.is_empty() {
            format!("{first}e{sign}{}", e.abs())
        } else {
            format!("{first}.{rest}e{sign}{}", e.abs())
        }
    };
    Ok(text)
}

/// Splits `<digits>[.<digits>]e<exponent>` into the digit sequence without the point and the
/// exponent.
fn exponential_form(text: &str) -> Result<(String, i64), CryptoError> {
    let unreadable = || CryptoError::JcsNumber {
        text: text.to_owned(),
        reason: "the standard library delivered no exponential form",
    };
    let (mantissa, exponent) = text.split_once('e').ok_or_else(unreadable)?;
    let exponent: i64 = exponent.parse().map_err(|_| unreadable())?;
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Err(unreadable());
    }
    Ok((digits, exponent))
}

fn write(value: &Value, from: &mut String) -> Result<(), CryptoError> {
    match value {
        Value::Null => from.push_str("null"),
        Value::Bool(true) => from.push_str("true"),
        Value::Bool(false) => from.push_str("false"),
        Value::Number(n) => from.push_str(&number_from_json(n)?),
        Value::String(text) => write_quoted(text, from),
        Value::Array(list) => {
            from.push('[');
            for (i, element) in list.iter().enumerate() {
                if i > 0 {
                    from.push(',');
                }
                write(element, from)?;
            }
            from.push(']');
        }
        Value::Object(object) => {
            let mut names: Vec<&String> = object.keys().collect();
            // RFC 8785 §3.2.3: ascending by UTF-16 code units, not by bytes.
            names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            from.push('{');
            for (i, name) in names.into_iter().enumerate() {
                if i > 0 {
                    from.push(',');
                }
                write_quoted(name, from);
                from.push(':');
                if let Some(element) = object.get(name) {
                    write(element, from)?;
                }
            }
            from.push('}');
        }
    }
    Ok(())
}

fn number_from_json(n: &Number) -> Result<String, CryptoError> {
    let beyond = || CryptoError::JcsNumber {
        text: n.to_string(),
        reason: "a whole number beyond 2^53 is no longer unambiguous as an IEEE 754 double",
    };
    if let Some(value) = n.as_u64() {
        return if value <= MAX_EXACT_INTEGER { Ok(value.to_string()) } else { Err(beyond()) };
    }
    if let Some(whole) = n.as_i64() {
        return if whole.unsigned_abs() <= MAX_EXACT_INTEGER {
            Ok(whole.to_string())
        } else {
            Err(beyond())
        };
    }
    match n.as_f64() {
        Some(value) => number(value),
        None => Err(CryptoError::JcsNumber { text: n.to_string(), reason: "not a finite number" }),
    }
}

/// A string in its JCS form including the quotation marks — for headers that are built
/// literally (detached signature).
pub(crate) fn quoted(text: &str) -> String {
    let mut from = String::with_capacity(text.len() + 2);
    write_quoted(text, &mut from);
    from
}

fn write_quoted(text: &str, from: &mut String) {
    from.push('"');
    for character in text.chars() {
        match character {
            '"' => from.push_str("\\\""),
            '\\' => from.push_str("\\\\"),
            '\u{8}' => from.push_str("\\b"),
            '\u{c}' => from.push_str("\\f"),
            '\n' => from.push_str("\\n"),
            '\r' => from.push_str("\\r"),
            '\t' => from.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                from.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            otherwise => from.push(otherwise),
        }
    }
    from.push('"');
}

/// Builds a [`Value`] and rejects duplicate names (I-JSON, RFC 7493 §2.3).
struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, reader: D) -> Result<Value, D::Error> {
        reader.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("the number is not finite"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut list = Vec::new();
        while let Some(element) = sequence.next_element_seed(StrictValue)? {
            list.push(element);
        }
        Ok(Value::Array(list))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if object.contains_key(&name) {
                return Err(de::Error::custom(format!(
                    "the name \"{name}\" stands twice in the same object"
                )));
            }
            let value = map.next_value_seed(StrictValue)?;
            object.insert(name, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The input/expectation pairs of the corpus. Expected byte for byte, without a line end.
    const PAIRS: &[(&str, &str, &str)] = &[
        (
            "escan: sorting",
            include_str!("../testdata/jcs/sorting-input.json"),
            include_str!("../testdata/jcs/sorting-expected.txt"),
        ),
        (
            "escan: escaping",
            include_str!("../testdata/jcs/escaping-input.json"),
            include_str!("../testdata/jcs/escaping-expected.txt"),
        ),
        (
            "escan: structure",
            include_str!("../testdata/jcs/structure-input.json"),
            include_str!("../testdata/jcs/structure-expected.txt"),
        ),
        (
            "RFC 8785 §3.2.2",
            include_str!("../testdata/jcs/rfc8785-primitives-input.json"),
            include_str!("../testdata/jcs/rfc8785-primitives-expected.txt"),
        ),
        (
            "RFC 8785 appendix (subtypes)",
            include_str!("../testdata/jcs/rfc8785-subtypes-input.json"),
            include_str!("../testdata/jcs/rfc8785-subtypes-expected.txt"),
        ),
        (
            "umlauts and non-ASCII names",
            include_str!("../testdata/jcs/umlauts-input.json"),
            include_str!("../testdata/jcs/umlauts-expected.txt"),
        ),
        (
            "HTML characters",
            include_str!("../testdata/jcs/html-characters-input.json"),
            include_str!("../testdata/jcs/html-characters-expected.txt"),
        ),
        (
            "whole and fractional numbers",
            include_str!("../testdata/jcs/numbers-input.json"),
            include_str!("../testdata/jcs/numbers-expected.txt"),
        ),
        (
            "deeply nested, empty, null",
            include_str!("../testdata/jcs/structure-deep-input.json"),
            include_str!("../testdata/jcs/structure-deep-expected.txt"),
        ),
        (
            "key statement from 03 §6.2.4",
            include_str!("../testdata/jcs/key-statement-input.json"),
            include_str!("../testdata/jcs/key-statement-expected.txt"),
        ),
    ];

    const REFERENCE_TRANSCRIPT: &str = include_str!("../testdata/jcs/reference-log.jcs.json");

    fn without_trailing_newline(text: &str) -> &str {
        text.strip_suffix('\n').unwrap_or(text)
    }

    #[test]
    fn every_pair_of_the_corpus_canonicalizes_byte_for_byte_to_the_expectation() {
        for (name, input, expected) in PAIRS {
            assert_eq!(
                canonicalize_text(input).unwrap(),
                without_trailing_newline(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn the_canonicalization_is_idempotent_over_the_whole_corpus() {
        for (name, input, _) in PAIRS {
            let once = canonicalize_text(input).unwrap();
            assert_eq!(canonicalize_text(&once).unwrap(), once, "{name}");
        }
    }

    #[test]
    fn the_rfc_example_matches_as_a_byte_sequence_too() {
        let hex = include_str!("../testdata/jcs/rfc8785-primitives-expected.hex");
        let expected: Vec<u8> =
            hex.split_whitespace().map(|pair| u8::from_str_radix(pair, 16).unwrap()).collect();
        let input = include_str!("../testdata/jcs/rfc8785-primitives-input.json");
        assert_eq!(canonicalize_bytes(&read(input).unwrap()).unwrap(), expected);
    }

    #[test]
    fn the_reference_transcript_of_the_sibling_client_is_a_fixed_point() {
        let golden = without_trailing_newline(REFERENCE_TRANSCRIPT);
        assert_eq!(canonicalize_text(golden).unwrap(), golden);
        let value = read(golden).unwrap();
        assert_eq!(value["canonicalization"], JCS_VERSION);
    }

    fn check_number_table(table: &str) -> usize {
        let mut checked = 0;
        for row in table.lines().filter(|r| !r.trim().is_empty() && !r.starts_with('#')) {
            let column: Vec<&str> = row.split('\t').collect();
            let bits = u64::from_str_radix(column[0], 16).unwrap();
            let value = f64::from_bits(bits);
            if column[1] == "ERROR" {
                assert!(number(value).is_err(), "{} has to be rejected", column[0]);
            } else {
                assert_eq!(number(value).unwrap(), column[1], "bit pattern {}", column[0]);
                // Counter-check: the representation leads back losslessly (-0 and 0 are equal).
                assert_eq!(column[1].parse::<f64>().unwrap(), value, "round trip {}", column[0]);
            }
            checked += 1;
        }
        checked
    }

    #[test]
    fn the_number_appendix_of_rfc_8785_holds_completely() {
        let checked = check_number_table(include_str!("../testdata/jcs/rfc8785-numbers.tsv"));
        assert!(checked >= 26, "only {checked} rows read");
    }

    #[test]
    fn the_number_vectors_of_the_sibling_client_hold_unchanged() {
        let checked = check_number_table(include_str!("../testdata/jcs/numbers.tsv"));
        assert!(checked >= 15, "only {checked} rows read");
    }

    #[test]
    fn nan_and_infinity_are_not_json_numbers() {
        assert!(number(f64::NAN).is_err());
        assert!(number(f64::INFINITY).is_err());
        assert!(number(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn a_whole_number_beyond_2_to_the_53_is_rejected_instead_of_rounded() {
        assert_eq!(canonicalize_text("9007199254740992").unwrap(), "9007199254740992");
        assert_eq!(canonicalize_text("-9007199254740992").unwrap(), "-9007199254740992");
        let error = canonicalize_text("9007199254740993").unwrap_err();
        assert!(matches!(error, CryptoError::JcsNumber { .. }), "{error:?}");
        assert!(canonicalize_text("-9007199254740993").is_err());
    }

    #[test]
    fn a_duplicate_name_is_rejected_instead_of_overwritten() {
        let error = read(r#"{"kid":"real","kid":"slipped-in"}"#).unwrap_err();
        assert!(
            // The offending name has to stand in the message: a reader who only learns
            // "not readable" goes hunting for a syntax error that is not there.
            matches!(error, CryptoError::JsonUnreadable(ref t) if t.contains(r#""kid" stands twice"#)),
            "{error:?}"
        );
        // Deep in the tree as well.
        assert!(read(r#"{"a":[{"b":1,"b":2}]}"#).is_err());
        // Equal names in different objects are allowed.
        assert!(read(r#"{"a":{"b":1},"c":{"b":2}}"#).is_ok());
    }

    #[test]
    fn trailing_text_makes_the_json_invalid() {
        assert!(read(r#"{"a":1} {"b":2}"#).is_err());
        assert!(read("").is_err());
    }

    #[test]
    fn the_order_of_the_input_does_not_change_the_bytes() {
        let a = serde_json::json!({"b": 2, "a": 1, "c": "three"});
        let b = serde_json::json!({"c": "three", "a": 1, "b": 2});
        assert_eq!(canonicalize(&a).unwrap(), r#"{"a":1,"b":2,"c":"three"}"#);
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    #[test]
    fn a_surrogate_pair_sorts_by_code_units_before_the_bmp_upper_bound() {
        // By bytes U+1F600 (F0..) would come after U+FB33 (EF..); by UTF-16 (D83D..) before it.
        let text = canonicalize_text(include_str!("../testdata/jcs/sorting-input.json")).unwrap();
        assert!(text.find("Emoji").unwrap() < text.find("Hebrew").unwrap());
    }

    #[test]
    fn angle_brackets_and_ampersand_stay_literal() {
        let text = canonicalize(&serde_json::json!({"t": "<a> & </a>"})).unwrap();
        assert_eq!(text, r#"{"t":"<a> & </a>"}"#);
    }
}
