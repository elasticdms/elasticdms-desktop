//! Which language this Mac is set to — the one place in the workspace that asks macOS.
//!
//! `NSLocale.preferredLanguages` is the list the user has dragged into order in System Settings
//! ("Language & Region"), best first: `["de-AT", "de-DE", "en-GB"]`. It is the same list every
//! Cocoa application resolves its `.lproj` bundles against, which is why elasticdms follows it
//! instead of the POSIX `LANG` — a program started from the Dock has no `LANG` at all, and one
//! started from a terminal has whatever the terminal happens to set.
//!
//! **Why here and not in the app.** Objective-C lives in this crate and nowhere else
//! (architecture rule R5, ADR-D02). The app is the only crate that knows both this one and
//! `edms-i18n`; it asks here, resolves there, and hands the answer down to the engine and the
//! core.
//!
//! The extension asks for itself: it runs in a process of its own, and the sentences Finder shows
//! come out of that process ([`crate::error`]).

use edms_i18n::Language;

/// The language of the user interface on this Mac.
///
/// [`edms_i18n::VAR_LANGUAGE`] wins over the system — a support call ("start it in English once
/// so I can read the message") must not need a change to System Settings. When macOS names no
/// language this client speaks, `Language::resolve` takes the fallback and says so in the log.
pub fn language() -> Language {
    match Language::from_environment() {
        Some(chosen) => chosen,
        None => Language::resolve(preferred_languages().iter().map(String::as_str)),
    }
}

/// The language tags of the system, best first; empty when macOS names none.
pub fn preferred_languages() -> Vec<String> {
    inner::preferred_languages()
}

#[cfg(target_os = "macos")]
mod inner {
    use objc2_foundation::NSLocale;

    pub(super) fn preferred_languages() -> Vec<String> {
        NSLocale::preferredLanguages().iter().map(|tag| tag.to_string()).collect()
    }
}

#[cfg(not(target_os = "macos"))]
mod inner {
    /// Off the platform there is no list — the caller then takes the fallback, loudly
    /// (`Language::resolve`). This build exists only so that the pure parts of this crate can be
    /// checked on a machine that is not a Mac.
    pub(super) fn preferred_languages() -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_list_is_read_and_never_panics() {
        // On a Mac the list is not empty; in a build for another target it is. Both are answers,
        // and neither may abort: a folder client that will not start because of a locale would be
        // the most expensive way to be exact.
        let tags = preferred_languages();
        if cfg!(target_os = "macos") {
            assert!(!tags.is_empty(), "macOS always names at least one language");
            assert!(tags.iter().all(|tag| !tag.trim().is_empty()), "{tags:?}");
        }
    }

    #[test]
    fn the_chosen_language_is_one_the_client_really_speaks() {
        // Whatever this machine is set to: what comes out is a language with a catalogue behind
        // it. There is no third state, and no `Option` a caller could forget to handle.
        let chosen = language();
        assert!(Language::ALL.contains(&chosen), "{chosen}");
    }
}
