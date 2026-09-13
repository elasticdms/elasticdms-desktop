//! The app's clock.
//!
//! The core reads no clock (`edms_core::time`): a type that fetches the system time itself cannot
//! be tested, and a device clock that runs wrong would then be spread everywhere. Whoever needs a
//! time gets it from here — in exactly one place.

use std::time::{SystemTime, UNIX_EPOCH};

use edms_core::time::Timestamp;

/// Now, in milliseconds since 1970 (UTC).
///
/// There is no clock before 1970: in that case the origin stands here. A negative timestamp would
/// be a line from the future of the past in the listing, and nobody could explain that.
pub fn now() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    Timestamp::from_unix_millis(millis)
}
