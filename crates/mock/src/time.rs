//! The mock's clock — the only place in this crate that reads one.
//!
//! The core reads no clock (`edms_core::lib`, boundary 1); timestamps are handed in. A server has
//! to have one: the `issuedAt` of a delivery command, the `expiresAt` of an upload grant, the
//! `acknowledgedAt` of an acknowledgement receipt and the `serverTime` of the heartbeat are
//! statements about the present moment. It stands here alone, so that a test finds it in one
//! place.

use edms_core::time::Timestamp;

/// The present moment in milliseconds since 1970.
///
/// There is no sensible case before 1970; a clock pointing there yields [`Timestamp::NULL`]
/// instead of a negative value that every display would later round wrongly.
pub fn now() -> Timestamp {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => {
            Timestamp::from_unix_millis(i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
        }
        Err(_) => Timestamp::NULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_lies_after_2020_and_before_2100() {
        let t = now().unix_millis();
        assert!(t > 1_577_836_800_000, "before 2020: {t}");
        assert!(t < 4_102_444_800_000, "after 2100: {t}");
    }
}
