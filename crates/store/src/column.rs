//! Column discipline (escan 01 §1.4) and the conversions that go with it — in one place.
//!
//! * **Opaque identifiers as TEXT** in their wire form (`cas_…/doc_…`), never as a number: the
//!   same string stands in the log, in the usage log and on the wire, and can be compared by eye.
//! * **Checksums as 64 lowercase hex digits, without a prefix**
//!   (`edms_core::checksum::Sha256Value::hex`); a `CHECK` constraint keeps uppercase out, because
//!   `ABC` and `abc` would otherwise be two values for the same checksum.
//! * **Enumerations by NAME, never by ordinal.** The name is the core's serde form (`OPENED`,
//!   `APPLIED`). An ordinal would shift with the next variant added in the middle, and every old
//!   row would quietly mean something else.
//! * **Times as INTEGER in milliseconds since 1970** (`Timestamp::unix_millis`).
//! * **Unsigned numbers** are converted explicitly: SQLite only knows i64, and a size above
//!   `i64::MAX` is rejected instead of being quietly stored as a negative number.

use std::fmt::Display;
use std::str::FromStr;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::ser::Error as _;

use crate::error::StoreError;

/// u64 into a SQLite number; too large is an error.
pub(crate) fn from_u64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::NumberTooLarge { field, value })
}

/// usize into a SQLite number; too large is an error.
pub(crate) fn from_usize(value: usize, field: &'static str) -> Result<i64, StoreError> {
    let wide =
        u64::try_from(value).map_err(|_| StoreError::NumberTooLarge { field, value: u64::MAX })?;
    from_u64(wide, field)
}

/// A SQLite number read back as u64; negative means corrupt.
pub(crate) fn to_u64(
    value: i64,
    table: &'static str,
    field: &'static str,
) -> Result<u64, StoreError> {
    u64::try_from(value)
        .map_err(|_| StoreError::corrupt(table, format!("column {field} is negative ({value})")))
}

/// 0 or 1 as a boolean; anything else means corrupt.
pub(crate) fn bool_from(
    value: i64,
    table: &'static str,
    field: &'static str,
) -> Result<bool, StoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => {
            Err(StoreError::corrupt(table, format!("column {field} is neither 0 nor 1 ({other})")))
        }
    }
}

/// The name of an enumeration as the core serialises it (`OPENED`).
pub(crate) fn name_of<T: Serialize>(value: &T, what: &'static str) -> Result<String, StoreError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => Ok(name),
        Ok(other) => Err(StoreError::Encoding {
            what,
            source: serde_json::Error::custom(format!("not a name, but {other}")),
        }),
        Err(source) => Err(StoreError::Encoding { what, source }),
    }
}

/// An enumeration from its stored name; an unknown name means corrupt.
pub(crate) fn from_name<T: DeserializeOwned>(
    name: &str,
    table: &'static str,
    field: &'static str,
) -> Result<T, StoreError> {
    serde_json::from_value(serde_json::Value::String(name.to_owned())).map_err(|_| {
        StoreError::corrupt(table, format!("“{name}” in column {field} is not a known name"))
    })
}

/// An identifier from its text form; as strict as when reading from the wire.
pub(crate) fn read_identifier<T>(
    text: &str,
    table: &'static str,
    field: &'static str,
) -> Result<T, StoreError>
where
    T: FromStr,
    T::Err: Display,
{
    text.parse().map_err(|error| StoreError::corrupt(table, format!("column {field}: {error}")))
}

/// A value as JSON text.
pub(crate) fn encode<T: Serialize>(value: &T, what: &'static str) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|source| StoreError::Encoding { what, source })
}

/// A value from JSON text; unreadable means corrupt.
pub(crate) fn decode<T: DeserializeOwned>(
    text: &str,
    table: &'static str,
) -> Result<T, StoreError> {
    serde_json::from_str(text)
        .map_err(|error| StoreError::corrupt(table, format!("unreadable JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use edms_core::delivery::CommandOutcome;
    use edms_core::log::LogKind;

    use super::*;

    #[test]
    fn enumerations_are_stored_by_the_name_the_core_gives_them() {
        assert_eq!(name_of(&CommandOutcome::NotApplicable, "outcome").unwrap(), "NOT_APPLICABLE");
        assert_eq!(from_name::<LogKind>("OPEN_FAILED", "t", "kind").unwrap(), LogKind::OpenFailed);
    }

    #[test]
    fn an_unknown_name_is_corruption_and_not_a_fallback_value() {
        let error = from_name::<CommandOutcome>("VIELLEICHT", "delivery", "outcome").unwrap_err();
        assert!(matches!(error, StoreError::Corrupt { table: "delivery", .. }));
        assert!(error.to_string().contains("VIELLEICHT"), "{error}");
    }

    #[test]
    fn numbers_above_i64_max_and_negative_ones_are_rejected() {
        assert_eq!(from_u64(7, "size").unwrap(), 7);
        assert!(matches!(
            from_u64(u64::MAX, "size"),
            Err(StoreError::NumberTooLarge { field: "size", value: u64::MAX })
        ));
        assert!(matches!(to_u64(-1, "entry", "size"), Err(StoreError::Corrupt { .. })));
        assert!(matches!(bool_from(2, "t", "truncated"), Err(StoreError::Corrupt { .. })));
        assert!(bool_from(1, "t", "truncated").unwrap());
    }
}
