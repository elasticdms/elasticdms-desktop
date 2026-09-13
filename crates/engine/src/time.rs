//! The engine's one clock.
//!
//! The core deliberately has none (`edms_core`, boundary 1), and `edms-crypto` has none either:
//! points in time are passed in. Somewhere the system clock has to be read all the same, and that
//! is here — one function, in one place, so that a test clock later has exactly one place to go.

use std::time::{SystemTime, UNIX_EPOCH};

use edms_core::time::Timestamp;

/// Now, in milliseconds since the Unix epoch.
///
/// If the system clock goes back before the epoch (a dead coin cell does that), the result is
/// [`Timestamp::NULL`] and not a crash: a wrong clock makes log rows useless, a crash in the tray
/// process takes the whole folder away from the user.
pub(crate) fn now() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |span| i64::try_from(span.as_millis()).unwrap_or(i64::MAX));
    Timestamp::from_unix_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_lies_after_the_year_2020_and_before_the_year_2200() {
        // 2020-01-01 and 2200-01-01 in milliseconds — a clock outside that is broken, and this
        // test catches a swapped seconds/milliseconds pair.
        let now = now().unix_millis();
        assert!(now > 1_577_836_800_000, "before 2020: {now}");
        assert!(now < 7_258_118_400_000, "after 2200: {now}");
    }
}
