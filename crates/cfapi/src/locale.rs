//! Which language this Windows workstation is set to — the one place in the workspace that asks
//! Windows.
//!
//! `GetUserDefaultUILanguage` gives the **user interface** language (the one Explorer's menus are
//! in), not the formats language of the region settings: a workstation set to German with
//! Austrian formats gets German, which is the answer a person expects. `LCIDToLocaleName` turns
//! the language identifier into a tag (`de-DE`), so that the same resolution runs here as on
//! macOS (`edms_i18n::Language::from_tag`).
//!
//! **Why here and not in the app.** The Windows API lives in this crate and nowhere else
//! (architecture rule R4, ADR-D02). The app is the only crate that knows both this one and
//! `edms-i18n`.

use edms_i18n::Language;

/// The language of the user interface on this workstation.
///
/// [`edms_i18n::VAR_LANGUAGE`] wins over the system — a support call ("start it in English once
/// so I can read the message") must not need a change to the Windows settings. When Windows names
/// no language this client speaks, `Language::resolve` takes the fallback and says so in the log.
pub fn language() -> Language {
    match Language::from_environment() {
        Some(chosen) => chosen,
        None => Language::resolve(preferred_languages().iter().map(String::as_str)),
    }
}

/// The language tags of the system, best first; empty when Windows names none.
///
/// Windows names exactly one user-interface language here; the list has one entry or none. It is
/// a list all the same, so that the app treats both platforms the same way.
pub fn preferred_languages() -> Vec<String> {
    inner::preferred_languages()
}

#[cfg(windows)]
mod inner {
    use windows::Win32::Globalization::{GetUserDefaultUILanguage, LCIDToLocaleName};

    /// `LOCALE_NAME_MAX_LENGTH` (winnls.h): 85 UTF-16 units including the null character.
    const NAME_MAX: usize = 85;

    pub(super) fn preferred_languages() -> Vec<String> {
        // SAFETY: `GetUserDefaultUILanguage` takes no arguments and reads no memory of ours.
        let language_id = unsafe { GetUserDefaultUILanguage() };
        let mut buffer = [0_u16; NAME_MAX];
        // SAFETY: the buffer belongs to this stack frame and outlives the call; its length is
        // passed as the count of UTF-16 units, exactly as LCIDToLocaleName demands. A zero return
        // means the identifier is unknown — then nothing was written, and nothing is read.
        let written = unsafe { LCIDToLocaleName(u32::from(language_id), Some(&mut buffer), 0) };
        if written <= 1 {
            tracing::debug!(
                language_id,
                "Windows names no locale for the user interface language."
            );
            return Vec::new();
        }
        // The count includes the null character; the tag is everything before it.
        let units = usize::try_from(written).unwrap_or(0).saturating_sub(1).min(buffer.len());
        vec![String::from_utf16_lossy(&buffer[..units])]
    }
}

#[cfg(not(windows))]
mod inner {
    /// Off the platform there is no list — the caller then takes the fallback, loudly
    /// (`Language::resolve`). This build exists so that the pure parts of this crate can be
    /// checked on a machine that is not a Windows one, which is where they are checked.
    pub(super) fn preferred_languages() -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_list_is_read_and_never_panics() {
        let tags = preferred_languages();
        if cfg!(windows) {
            assert_eq!(tags.len(), 1, "Windows names exactly one interface language: {tags:?}");
            assert!(tags[0].contains('-') || !tags[0].is_empty(), "{tags:?}");
        } else {
            assert!(tags.is_empty(), "{tags:?}");
        }
    }

    #[test]
    fn the_chosen_language_is_one_the_client_really_speaks() {
        // Whatever this machine is set to: what comes out is a language with a catalogue behind
        // it. There is no third state, and no `Option` a caller could forget to handle.
        assert!(Language::ALL.contains(&language()));
    }
}
