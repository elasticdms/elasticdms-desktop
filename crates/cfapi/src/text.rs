//! Text between Rust and Win32: UTF-8 here, UTF-16 there.
//!
//! The pure halves live here so that they can be tested on this machine; reading a `PCWSTR` (a raw
//! pointer with a null terminator) lives in the Windows part.
//!
//! Two traps that the functions checked here stand against:
//!
//! 1. **An embedded null character truncates silently.** `PCWSTR` ends at the first `0`; a path
//!    `C:\a\0\evil` would be `C:\a` to Windows. That is the classic way to get around a check that
//!    worked on the whole text. [`nul_terminated`] rejects such texts instead of shortening them.
//! 2. **Lone surrogates.** Windows file names are UTF-16 *without* a well-formedness guarantee; an
//!    unpaired surrogate yields no valid Rust `String`. [`from_utf16`] replaces it with U+FFFD
//!    instead of dropping the name — an entry with an odd name is better than a directory in which
//!    an entry is missing without anyone knowing why.

use crate::error::MirrorError;

/// A text as a null-terminated UTF-16 sequence, the way `PCWSTR` expects it.
///
/// The caller has to keep the buffer alive for as long as Windows uses the pointer.
pub fn nul_terminated(text: &str) -> Result<Vec<u16>, MirrorError> {
    if text.contains('\0') {
        return Err(MirrorError::InvalidName {
            name: text.to_owned(),
            reason: "it contains a null character, at which Windows would cut the text off",
        });
    }
    let mut out: Vec<u16> = text.encode_utf16().collect();
    out.push(0);
    Ok(out)
}

/// A UTF-16 sequence (without a null terminator) as a `String`; lone surrogates become U+FFFD.
pub fn from_utf16(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// The length up to the first null character, at most `max` units.
///
/// The upper bound is not decoration: if the Windows part reads a pointer whose null character is
/// missing (a bug in cldflt, or a pointer that points into the void), the search otherwise runs
/// through foreign memory until the process falls over.
pub fn length_until_null(units: &[u16], max: usize) -> usize {
    units.iter().take(max).position(|z| *z == 0).unwrap_or(units.len().min(max))
}

/// A fixed UTF-16 field up to the first null character as a `String`.
///
/// Windows pads fixed fields (`WIN32_FIND_DATAW::cFileName`, `CF_SYNC_ROOT_STANDARD_INFO::
/// ProviderName`) with nulls behind the text. Whoever converts the whole field gets a name with
/// 200 invisible null characters attached — and never finds it in any listing again.
pub fn text_until_null(field: &[u16]) -> String {
    from_utf16(&field[..length_until_null(field, field.len())])
}

/// Maximum length up to which a `PCWSTR` from a callback is read.
///
/// 32,767 is the greatest path length NTFS allows with `\\?\`; nothing that cldflt passes as a
/// path, a pattern or a program path can be longer.
pub const MAX_UTF16: usize = 32_767;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_is_handed_over_null_terminated() {
        assert_eq!(nul_terminated("ab").unwrap(), vec![0x61, 0x62, 0x00]);
        assert_eq!(nul_terminated("").unwrap(), vec![0x00]);
        assert_eq!(*nul_terminated("Prüfbericht").unwrap().last().unwrap(), 0);
    }

    #[test]
    fn an_embedded_null_character_is_rejected_instead_of_truncated() {
        let f = nul_terminated("C:\\a\0\\b").unwrap_err();
        assert!(f.to_string().contains("null character"), "{f}");
    }

    #[test]
    fn a_lone_surrogate_does_not_cost_the_whole_name() {
        // 0xD83D without a partner: not valid UTF-16, but a name NTFS can carry.
        let name = from_utf16(&[0x0041, 0xD83D, 0x0042]);
        assert!(name.starts_with('A') && name.ends_with('B'), "{name}");
        assert!(name.contains('\u{FFFD}'), "{name}");
    }

    #[test]
    fn the_round_trip_preserves_every_ordinary_name() {
        for text in ["Rechnung 2026-0412.pdf", "Müller & Söhne", "😀.txt", ""] {
            let wide = nul_terminated(text).unwrap();
            let until = length_until_null(&wide, MAX_UTF16);
            assert_eq!(from_utf16(&wide[..until]), text);
        }
    }

    #[test]
    fn a_fixed_field_ends_at_the_null_character_not_at_the_end_of_the_field() {
        let mut field = [0u16; 16];
        for (target, source) in field.iter_mut().zip("NTFS".encode_utf16()) {
            *target = source;
        }
        assert_eq!(text_until_null(&field), "NTFS");
        assert_eq!(text_until_null(&[0u16; 8]), "");
        // A completely filled field without a null character stays complete.
        assert_eq!(text_until_null(&[0x41, 0x42]), "AB");
    }

    #[test]
    fn the_length_search_stops_at_the_upper_bound() {
        let without_null = vec![0x41_u16; 10];
        assert_eq!(
            length_until_null(&without_null, 4),
            4,
            "the upper bound applies even without a null character"
        );
        assert_eq!(length_until_null(&without_null, 100), 10, "never beyond the buffer");
        assert_eq!(length_until_null(&[0x41, 0x00, 0x42], MAX_UTF16), 1);
        assert_eq!(length_until_null(&[], MAX_UTF16), 0);
    }
}
