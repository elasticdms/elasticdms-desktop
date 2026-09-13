//! Which language this workstation speaks — asked once at the start, then handed down.
//!
//! The app is the only crate that knows both the text catalogue (`edms-i18n`) and the platform
//! layer, and therefore the only one that can join the two. The platform call itself is **not**
//! here: `AppleLanguages` is Objective-C and lives in `edms-fileprovider`,
//! `GetUserDefaultUILanguage` is Win32 and lives in `edms-cfapi` (architecture rules R4 and R5).
//! This module asks whichever of the two exists on this build and resolves the answer.
//!
//! The order is the same on both platforms:
//!
//! 1. `EDMS_LANG` — set by an administrator or for a support call.
//! 2. The operating system's list of interface languages, best first.
//! 3. English, and the fall-back is written into the diagnostic log once.
//!
//! **Once at the start, not on every access.** A language that changed under a running program
//! would mean a menu in one language and a window in another; whoever switches the system
//! language restarts elasticdms, as with every other program on both platforms.

use std::sync::OnceLock;

use edms_i18n::{Catalog, Language};

/// The language of this run.
pub fn language() -> Language {
    static HELD: OnceLock<Language> = OnceLock::new();
    *HELD.get_or_init(|| {
        let chosen = resolve();
        tracing::info!(
            language = chosen.tag(),
            offered = system_languages().join(", "),
            "the language of the user interface has been settled."
        );
        chosen
    })
}

/// The text catalogue of this run — the one every part of the app reads from.
pub fn catalogue() -> &'static Catalog {
    Catalog::of(language())
}

/// The choice, without the log line — so that the decision can be read on its own.
fn resolve() -> Language {
    match Language::from_environment() {
        Some(chosen) => chosen,
        None => Language::resolve(system_languages().iter().map(String::as_str)),
    }
}

/// What the operating system offers, best first.
///
/// On a build for neither platform (a check run on a Linux CI machine) the list is empty and
/// English holds — loudly, through `Language::resolve`.
fn system_languages() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        edms_fileprovider::locale::preferred_languages()
    }
    #[cfg(windows)]
    {
        edms_cfapi::locale::preferred_languages()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_language_of_this_run_is_one_the_client_really_speaks() {
        // Whatever this machine is set to and whatever stands in the environment: what comes out
        // is a language with a catalogue behind it, and the catalogue answers.
        let chosen = language();
        assert!(Language::ALL.contains(&chosen), "{chosen}");
        let catalogue = catalogue();
        assert_eq!(catalogue.language(), chosen);
        assert!(!catalogue.text(edms_i18n::key::MENU_OPEN).is_empty());
    }

    #[test]
    fn the_choice_is_settled_once_and_does_not_change_under_a_running_program() {
        assert_eq!(language(), language());
    }

    #[test]
    fn the_platform_list_is_read_without_an_operating_system_call_failing() {
        // The list may be empty (a build for neither platform); what must not happen is a panic
        // in the start path, which would be a program that will not come up because of a locale.
        let offered = system_languages();
        assert!(offered.iter().all(|tag| !tag.contains('\0')), "{offered:?}");
    }
}
