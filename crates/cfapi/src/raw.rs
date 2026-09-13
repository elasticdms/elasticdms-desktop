//! The numbers from Windows: Win32 error codes, HRESULT arithmetic, expected outcomes.
//!
//! Why this is a module of its own, free of the platform: the decision "is this an error or an
//! expected outcome?" is made here — and precisely that decision has to be testable. On this
//! machine no `DeleteFileW` can be executed, but it can be pinned down that
//! `ERROR_FILE_NOT_FOUND` on deletion is **not** an error (the goal has been reached) and that
//! `ERROR_SHARING_VIOLATION` on dehydration is **not** an error either but a "try again later"
//! ([`edms_core::port::PlatformError::InUse`]).
//!
//! The HRESULT arithmetic is `HRESULT_FROM_WIN32` from `winerror.h`: `0x8007_0000 | code`, as long
//! as the code fits into 16 bits. It is recomputed here because windows-rs does not offer it as a
//! function and a miscomputed comparison silently misses — the error "file not found" would then
//! be reported as an unknown system error, and a sign-out would need a restart afterwards.

/// `ERROR_FILE_NOT_FOUND`.
pub const WIN32_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
pub const WIN32_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_ACCESS_DENIED`.
pub const WIN32_ACCESS_DENIED: u32 = 5;
/// `ERROR_SHARING_VIOLATION` — another program holds the file open.
pub const WIN32_SHARING_VIOLATION: u32 = 32;
/// `ERROR_ALREADY_EXISTS`.
pub const WIN32_ALREADY_PRESENT: u32 = 183;
/// `ERROR_DIR_NOT_EMPTY`.
pub const WIN32_FOLDER_NOT_EMPTY: u32 = 145;
/// `ERROR_CLOUD_FILE_ALREADY_CONNECTED` (0x17A) — a second instance holds the root.
///
/// This is the reliable single-instance signal on Windows: a root has exactly one connection, and
/// the second `CfConnectSyncRoot` gets this code, not `E_ACCESSDENIED`
/// (02-platform-decision §1.2).
pub const WIN32_ALREADY_CONNECTED: u32 = 0x17A;

/// `HRESULT_FROM_WIN32` from `winerror.h`.
///
/// Codes above 16 bits are already HRESULTs and stay unchanged — exactly the rule of the macro;
/// without it an HRESULT would be "converted" a second time and would no longer match anything.
pub const fn hresult_from_win32(code: u32) -> i32 {
    if code & 0x8000_0000 != 0 { code as i32 } else { (0x8007_0000 | (code & 0xFFFF)) as i32 }
}

/// Whether an HRESULT means "does not exist (any more)".
pub const fn is_not_found(hresult: i32) -> bool {
    hresult == hresult_from_win32(WIN32_FILE_NOT_FOUND)
        || hresult == hresult_from_win32(WIN32_PATH_NOT_FOUND)
}

/// Whether an HRESULT means "a program holds the file open".
pub const fn is_in_use(hresult: i32) -> bool {
    hresult == hresult_from_win32(WIN32_SHARING_VIOLATION)
}

/// Whether an HRESULT is `E_ACCESSDENIED` or `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)` — both are
/// the same value.
pub const fn is_access_denied(hresult: i32) -> bool {
    hresult == hresult_from_win32(WIN32_ACCESS_DENIED)
}

/// Whether an HRESULT means "this root already has a connection".
pub const fn is_already_connected(hresult: i32) -> bool {
    hresult == hresult_from_win32(WIN32_ALREADY_CONNECTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{HRESULT_ACCESS_DENIED, HRESULT_ALREADY_PRESENT, as_u32};

    #[test]
    fn the_hresult_arithmetic_matches_the_values_from_winerror_h() {
        assert_eq!(as_u32(hresult_from_win32(WIN32_FILE_NOT_FOUND)), 0x8007_0002);
        assert_eq!(as_u32(hresult_from_win32(WIN32_ACCESS_DENIED)), HRESULT_ACCESS_DENIED);
        assert_eq!(as_u32(hresult_from_win32(WIN32_ALREADY_PRESENT)), HRESULT_ALREADY_PRESENT);
        assert_eq!(as_u32(hresult_from_win32(WIN32_SHARING_VIOLATION)), 0x8007_0020);
        assert_eq!(as_u32(hresult_from_win32(WIN32_ALREADY_CONNECTED)), 0x8007_017A);
    }

    #[test]
    fn a_finished_hresult_is_not_converted_a_second_time() {
        // E_UNEXPECTED is already an HRESULT; sent through the arithmetic once more it would be
        // 0x8007FFFF and would no longer match any comparison.
        let e_unexpected = 0x8000_FFFF_u32 as i32;
        assert_eq!(hresult_from_win32(as_u32(e_unexpected)), e_unexpected);
    }

    #[test]
    fn the_expected_outcomes_are_recognisable_as_such() {
        assert!(is_not_found(hresult_from_win32(WIN32_FILE_NOT_FOUND)));
        assert!(is_not_found(hresult_from_win32(WIN32_PATH_NOT_FOUND)));
        assert!(is_in_use(hresult_from_win32(WIN32_SHARING_VIOLATION)));
        assert!(is_access_denied(hresult_from_win32(WIN32_ACCESS_DENIED)));
        assert!(is_already_connected(hresult_from_win32(WIN32_ALREADY_CONNECTED)));
    }

    #[test]
    fn no_expected_outcome_is_confused_with_another() {
        let all: [fn(i32) -> bool; 4] =
            [is_not_found, is_in_use, is_access_denied, is_already_connected];
        for code in [
            WIN32_FILE_NOT_FOUND,
            WIN32_ACCESS_DENIED,
            WIN32_SHARING_VIOLATION,
            WIN32_ALREADY_CONNECTED,
        ] {
            let hresult = hresult_from_win32(code);
            let hits = all.iter().filter(|p| p(hresult)).count();
            assert_eq!(hits, 1, "{code} matches {hits} predicates");
        }
        // A code that is none of the expected outcomes stays an ordinary error.
        let otherwise = hresult_from_win32(WIN32_FOLDER_NOT_EMPTY);
        assert!(all.iter().all(|p| !p(otherwise)));
    }
}
