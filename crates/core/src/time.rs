//! Timestamps — without a clock.
//!
//! The core reads no clock (boundary 1 in `lib.rs`); a timestamp is handed in. Only the value
//! and its RFC 3339 form live here, because server timestamps arrive over the wire as RFC 3339
//! text (03 §6.0: UTC with `Z`, sometimes with milliseconds) and a timestamp with an offset
//! (`+02:00`) has to be the same instant as its UTC form.
//!
//! **No local time here.** The usage log displays local time, but the user interface computes
//! that (the web view knows the machine's time zone). A time-zone rule in the core would be a
//! second one, and the second one is always the one that is wrong at the daylight-saving edge.

use std::fmt;

use serde::{Deserialize, Serialize};

/// An instant, in milliseconds since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

/// Why a string is not an RFC 3339 timestamp.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{text}` is not a timestamp per RFC 3339 ({reason})")]
pub struct TimeError {
    text: String,
    reason: &'static str,
}

const MILLIS_PER_SECOND: i64 = 1_000;
const SECOND_PER_DAY: i64 = 86_400;

impl Timestamp {
    /// The start of Unix time. Serves as “never” in comparisons, not as something to display.
    pub const NULL: Self = Self(0);

    /// From milliseconds since 1970-01-01T00:00:00Z.
    pub const fn from_unix_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since 1970-01-01T00:00:00Z.
    pub const fn unix_millis(self) -> i64 {
        self.0
    }

    /// Shifts by milliseconds; never overflows, it saturates.
    pub const fn plus_millis(self, millis: i64) -> Self {
        Self(self.0.saturating_add(millis))
    }

    /// The RFC 3339 form in UTC with milliseconds: `2026-09-02T07:38:12.118Z`.
    pub fn rfc3339(self) -> String {
        let millis = self.0.rem_euclid(MILLIS_PER_SECOND);
        let second = self.0.div_euclid(MILLIS_PER_SECOND);
        let days = second.div_euclid(SECOND_PER_DAY);
        let in_day = second.rem_euclid(SECOND_PER_DAY);
        let (year, month, day) = civil_from_day(days);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
            in_day / 3_600,
            (in_day % 3_600) / 60,
            in_day % 60
        )
    }

    /// Reads RFC 3339: `YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)`.
    ///
    /// Fractions below a millisecond are truncated, not rounded — the same direction the
    /// database takes when storing, so that a timestamp is not later after the round trip than
    /// it was before.
    pub fn from_rfc3339(text: &str) -> Result<Self, TimeError> {
        let error = |reason| TimeError { text: text.to_owned(), reason };
        let b = text.as_bytes();
        if b.len() < 20 {
            return Err(error("too short"));
        }
        let number = |of: usize, until: usize| -> Result<i64, TimeError> {
            let part = text.get(of..until).ok_or_else(|| error("digits missing"))?;
            if !part.bytes().all(|z| z.is_ascii_digit()) {
                return Err(error("digits expected"));
            }
            part.parse::<i64>().map_err(|_| error("digits expected"))
        };
        if b[4] != b'-'
            || b[7] != b'-'
            || !matches!(b[10], b'T' | b't')
            || b[13] != b':'
            || b[16] != b':'
        {
            return Err(error("separators do not match"));
        }
        let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
        let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
        if !(1..=12).contains(&month) || day < 1 || day > day_in_month(year, month) {
            return Err(error("no such date"));
        }
        // Per RFC 3339, 60 is a leap second; it folds onto the 59th second.
        if hour > 23 || minute > 59 || second > 60 {
            return Err(error("no such time of day"));
        }
        let mut pos = 19;
        let mut millis = 0_i64;
        if b.get(pos) == Some(&b'.') {
            pos += 1;
            let start = pos;
            while b.get(pos).is_some_and(u8::is_ascii_digit) {
                pos += 1;
            }
            if pos == start {
                return Err(error("fraction without digits"));
            }
            let digits = &text[start..pos.min(start + 3)];
            millis = digits.parse::<i64>().map_err(|_| error("fraction"))?
                * 10_i64.pow(3 - u32::try_from(digits.len()).map_err(|_| error("fraction"))?);
        }
        let offset_minutes = match b.get(pos) {
            Some(b'Z' | b'z') if pos + 1 == b.len() => 0,
            Some(&sign @ (b'+' | b'-')) if pos + 6 == b.len() && b[pos + 3] == b':' => {
                let (h, m) = (number(pos + 1, pos + 3)?, number(pos + 4, pos + 6)?);
                if h > 23 || m > 59 {
                    return Err(error("no such offset"));
                }
                if sign == b'+' { h * 60 + m } else { -(h * 60 + m) }
            }
            _ => return Err(error("time zone missing or unreadable")),
        };
        let second = day_from_civil(year, month, day) * SECOND_PER_DAY
            + hour * 3_600
            + minute * 60
            + second.min(59)
            - offset_minutes * 60;
        Ok(Self(second * MILLIS_PER_SECOND + millis))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rfc3339())
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn day_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// The two functions below are Howard Hinnant's well-known algorithm (“chrono-Compatible
// Low-Level Date Algorithms”): proleptic Gregorian calendar, the year starting in March so that
// the leap day falls at the end.
fn day_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_day(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 { month_from_march + 3 } else { month_from_march - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_of_unix_time_is_zero() {
        assert_eq!(Timestamp::from_rfc3339("1970-01-01T00:00:00Z").unwrap(), Timestamp::NULL);
        assert_eq!(Timestamp::NULL.rfc3339(), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn a_server_timestamp_survives_the_round_trip() {
        let text = "2026-09-02T07:38:12.118Z";
        let z = Timestamp::from_rfc3339(text).unwrap();
        assert_eq!(z.rfc3339(), text);
        assert_eq!(z.unix_millis(), 1_788_334_692_118);
    }

    #[test]
    fn an_offset_is_the_same_instant_as_utc() {
        // 03 §6.5: startedAtDevice with a local offset next to startedAtTrusted in UTC.
        let local = Timestamp::from_rfc3339("2026-09-02T09:38:11+02:00").unwrap();
        let utc = Timestamp::from_rfc3339("2026-09-02T07:38:11Z").unwrap();
        assert_eq!(local, utc);
    }

    #[test]
    fn the_leap_day_exists_only_in_a_leap_year() {
        assert!(Timestamp::from_rfc3339("2024-02-29T12:00:00Z").is_ok());
        assert!(Timestamp::from_rfc3339("2026-02-29T12:00:00Z").is_err());
        assert!(Timestamp::from_rfc3339("2000-02-29T12:00:00Z").is_ok());
        assert!(Timestamp::from_rfc3339("1900-02-29T12:00:00Z").is_err());
    }

    #[test]
    fn fractions_are_truncated_not_rounded() {
        let z = Timestamp::from_rfc3339("2026-09-02T07:38:12.999999Z").unwrap();
        assert_eq!(z.unix_millis() % 1_000, 999);
        let z = Timestamp::from_rfc3339("2026-09-02T07:38:12.5Z").unwrap();
        assert_eq!(z.unix_millis() % 1_000, 500);
    }

    #[test]
    fn before_1970_the_arithmetic_is_the_same() {
        let z = Timestamp::from_rfc3339("1969-12-31T23:59:59.500Z").unwrap();
        assert_eq!(z.unix_millis(), -500);
        assert_eq!(z.rfc3339(), "1969-12-31T23:59:59.500Z");
    }

    #[test]
    fn without_a_time_zone_it_is_not_a_timestamp() {
        // A timestamp without a zone is a wall-clock time somewhere — exactly what a server must
        // never deliver and a client must never silently read as UTC.
        assert!(Timestamp::from_rfc3339("2026-09-02T07:38:12").is_err());
        assert!(Timestamp::from_rfc3339("2026-09-02T07:38:12.118").is_err());
        assert!(Timestamp::from_rfc3339("2026-13-02T07:38:12Z").is_err());
        assert!(Timestamp::from_rfc3339("2026-09-02 07:38:12Z").is_err());
    }

    #[test]
    fn every_day_of_a_century_survives_the_round_trip() {
        for days in -36_525..36_525 {
            let (y, m, d) = civil_from_day(days);
            assert_eq!(day_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
    }
}
