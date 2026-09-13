//! Randomness from the operating system — the crate's only source.
//!
//! The core creates no identifiers, it only shapes them (`edms_core::identifier`); the 128 bits
//! come from here. Likewise `jti` for DPoP proofs and the client assertion, and the ULID of the
//! `Idempotency-Key` (geraete-auth §2.5: one ULID per *attempt*).
//!
//! **No substitute when randomness is missing.** If the operating system delivers nothing, there
//! is an error and no identifier made from the clock or a counter: a predictable `jti` is a
//! replay that the server takes for fresh.

use edms_core::identifier::{self, Identifier, Kind};
use edms_core::time::Timestamp;

use crate::CryptoError;

/// 48 bits of milliseconds — the time span of a ULID.
const ULID_TIME_LIMIT: i64 = 1 << 48;

/// Fills a buffer with randomness from the operating system.
pub fn fill(buffer: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buffer).map_err(|error| CryptoError::Random(error.to_string()))
}

/// 128 bits of randomness.
pub fn random_128() -> Result<u128, CryptoError> {
    let mut bytes = [0u8; 16];
    fill(&mut bytes)?;
    Ok(u128::from_be_bytes(bytes))
}

/// A new domain identifier of kind `A`, such as the device identifier before enrollment.
pub fn new_identifier<A: Kind>() -> Result<Identifier<A>, CryptoError> {
    random_128().map(Identifier::from_value)
}

/// A `jti`: 128 bits of randomness, 26 characters of Crockford base32, **without a timestamp**.
///
/// Like `Kennungen.new()` in the sibling client: a ULID would carry 48 bits of device clock, and
/// a clock in an identifier looks, later on, like evidence. For the replay cache only uniqueness
/// counts.
pub fn jti() -> Result<String, CryptoError> {
    Ok(as_text(identifier::encode(random_128()?)))
}

/// A ULID for `Idempotency-Key`: 48 bits of milliseconds, then 80 bits of randomness, 26
/// characters.
///
/// Here the time is wanted: it sorts the attempts. A timestamp before 1970 or beyond the year
/// 10889 does not fit into 48 bits and is an error, not a truncated number.
pub fn ulid(time: Timestamp) -> Result<String, CryptoError> {
    let mut random = [0u8; 10];
    fill(&mut random)?;
    ulid_from(time, random)
}

fn ulid_from(time: Timestamp, random: [u8; 10]) -> Result<String, CryptoError> {
    let millis = time.unix_millis();
    if !(0..ULID_TIME_LIMIT).contains(&millis) {
        return Err(CryptoError::UlidTime { millis });
    }
    let time_part = u128::try_from(millis).map_err(|_| CryptoError::UlidTime { millis })?;
    let random_part = random.iter().fold(0u128, |acc, &b| (acc << 8) | u128::from(b));
    Ok(as_text(identifier::encode((time_part << 80) | random_part)))
}

fn as_text(character: [u8; identifier::LENGTH]) -> String {
    character.iter().map(|&b| char::from(b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::DeviceIdentifier;

    #[test]
    fn a_jti_has_26_characters_of_the_strict_alphabet_and_never_repeats() {
        let all: Vec<String> = (0..200).map(|_| jti().unwrap()).collect();
        let distinct: std::collections::BTreeSet<&String> = all.iter().collect();
        assert_eq!(distinct.len(), 200);
        for j in &all {
            assert_eq!(j.len(), 26);
            assert!(j.bytes().all(|b| identifier::ALPHABET.contains(&b)), "{j}");
        }
        // No timestamp: the beginnings are randomly spread, not ascending.
        let mut sorted = all.clone();
        sorted.sort();
        assert_ne!(sorted, all);
    }

    #[test]
    fn a_new_identifier_is_a_valid_wire_identifier() {
        let k: DeviceIdentifier = new_identifier().unwrap();
        let text = k.to_string();
        assert!(text.starts_with("dev_"));
        assert_eq!(text.parse::<DeviceIdentifier>().unwrap(), k);
    }

    #[test]
    fn the_ulid_carries_the_time_up_front_like_the_ulid_specification() {
        // Example from the ULID specification: 01ARYZ6S41… is 1469918176385 ms.
        let u = ulid_from(Timestamp::from_unix_millis(1_469_918_176_385), [0; 10]).unwrap();
        assert_eq!(&u[..10], "01ARYZ6S41");
        assert_eq!(&u[10..], "0000000000000000");
        let u = ulid(Timestamp::from_unix_millis(1_469_918_176_385)).unwrap();
        assert_eq!(u.len(), 26);
        assert!(u.starts_with("01ARYZ6S41"));
    }

    #[test]
    fn later_ulids_sort_behind_earlier_ones() {
        let early = ulid(Timestamp::from_unix_millis(1_788_334_692_118)).unwrap();
        let late = ulid(Timestamp::from_unix_millis(1_788_334_692_119)).unwrap();
        assert!(early < late);
    }

    #[test]
    fn a_ulid_before_1970_or_beyond_48_bits_is_an_error() {
        assert_eq!(
            ulid(Timestamp::from_unix_millis(-1)),
            Err(CryptoError::UlidTime { millis: -1 })
        );
        assert!(ulid(Timestamp::from_unix_millis(1 << 48)).is_err());
        assert!(ulid(Timestamp::from_unix_millis((1 << 48) - 1)).is_ok());
    }
}
