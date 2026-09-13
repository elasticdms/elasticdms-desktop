//! The client's only clock — and it is an observation, not a proof.
//!
//! `edms-core` deliberately has no clock: the core is to stay decidable without an operating
//! system. This crate needs one all the same, because RFC 9449 demands `iat` in the DPoP proof and
//! RFC 7523 `iat`/`exp` in the client assertion. It therefore stands behind a trait: in tests a
//! fixed time runs, in operation the machine's.
//!
//! **The freshness comes from the nonce, not from this clock** (geraete-auth §2.4, point 7). If the
//! workstation's clock goes wrong — after a power cut, in a sealed-off network without NTP —, the
//! client stays usable. A server that checked `iat` against its own clock would lock out exactly
//! those devices that already have a problem.

use std::time::{SystemTime, UNIX_EPOCH};

use edms_core::time::Timestamp;

/// Where `iat` comes from.
pub trait Clock: Send + Sync {
    /// The present point in time, as this device sees it.
    fn now(&self) -> Timestamp;
}

/// The operating system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// Milliseconds since the epoch.
    ///
    /// If the clock stands before 1970 — a reset BIOS —, the value falls back to the epoch instead
    /// of the call failing: a proof with a wrong `iat` is accepted (the nonce carries the
    /// freshness), a proof that never comes into being is not.
    fn now(&self) -> Timestamp {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Timestamp::from_unix_millis(i64::try_from(since_epoch.as_millis()).unwrap_or(i64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_lies_after_the_year_2020() {
        // 2020-01-01T00:00:00Z. A smaller value would mean that the conversion goes wrong —
        // not that the machine stands wrong.
        assert!(SystemClock.now().unix_millis() > 1_577_836_800_000);
    }

    #[test]
    fn a_fixed_clock_fulfils_the_same_contract() {
        struct Fixed(i64);
        impl Clock for Fixed {
            fn now(&self) -> Timestamp {
                Timestamp::from_unix_millis(self.0)
            }
        }
        let clock: &dyn Clock = &Fixed(7);
        assert_eq!(clock.now(), Timestamp::from_unix_millis(7));
    }
}
