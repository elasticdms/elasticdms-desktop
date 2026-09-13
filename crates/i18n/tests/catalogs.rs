//! The catalogues against each other and against the key list — the test that makes a missing
//! sentence a build failure instead of a hole in a window.
//!
//! Five properties, and each of them has cost somebody a bug report somewhere:
//!
//! 1. **Every key of [`edms_i18n::KEYS`] stands in every catalogue.** A call site cannot ask for
//!    a sentence that is not there.
//! 2. **Every catalogue key stands in `KEYS`.** A translator's leftover from a deleted feature
//!    does not sit in the binary for years pretending to be in use.
//! 3. **The same placeholders in every language.** A German sentence with `{count}` and an
//!    English one without it would show a number in one language and swallow it in the other.
//! 4. **No sentence is empty**, and none carries a stray brace: `{` always opens a placeholder.
//! 5. **The two catalogues really are two languages** — no key where the English is still the
//!    German, which is what an unfinished translation looks like.

use std::collections::{BTreeMap, BTreeSet};

use edms_i18n::{Catalog, KEYS, Language};

fn catalogue(language: Language) -> Catalog {
    Catalog::read(language).unwrap_or_else(|error| panic!("catalog/{language}.toml: {error}"))
}

/// The placeholders of a sentence, in the order in which they stand.
fn placeholders(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                out.insert(after[..end].to_owned());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

#[test]
fn every_key_of_the_program_stands_in_every_catalogue() {
    let mut missing = Vec::new();
    for language in Language::ALL {
        let catalogue = catalogue(language);
        let present: BTreeSet<&str> = catalogue.entries().map(|(k, _)| k).collect();
        for key in KEYS {
            if !present.contains(key.path()) {
                missing.push(format!("{language}: `{key}`"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these sentences are missing from a catalogue — the user interface would show the key \
         path instead:\n{}",
        missing.join("\n")
    );
}

#[test]
fn no_catalogue_carries_a_key_the_program_does_not_ask_for() {
    let known: BTreeSet<&str> = KEYS.iter().map(|key| key.path()).collect();
    let mut surplus = Vec::new();
    for language in Language::ALL {
        let catalogue = catalogue(language);
        for (key, _) in catalogue.entries() {
            if !known.contains(key) {
                surplus.push(format!("{language}: `{key}`"));
            }
        }
    }
    assert!(
        surplus.is_empty(),
        "these sentences stand in a catalogue but in no key of the program; enter them in \
         `catalogue_keys!` or delete them:\n{}",
        surplus.join("\n")
    );
}

#[test]
fn a_key_uses_the_same_placeholders_in_every_language() {
    let mut sheets: BTreeMap<Language, Catalog> = BTreeMap::new();
    for language in Language::ALL {
        sheets.insert(language, catalogue(language));
    }
    let mut wrong = Vec::new();
    for key in KEYS {
        let mut expected: Option<(Language, BTreeSet<String>)> = None;
        for language in Language::ALL {
            let found = placeholders(sheets[&language].text(*key));
            match &expected {
                None => expected = Some((language, found)),
                Some((first, wanted)) if *wanted != found => wrong
                    .push(format!("`{key}`: {first} uses {wanted:?}, {language} uses {found:?}")),
                Some(_) => {}
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "a placeholder that stands in one language only shows a value in that language and \
         swallows it in the other:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn no_sentence_is_empty_and_no_brace_stands_alone() {
    let mut wrong = Vec::new();
    for language in Language::ALL {
        let catalogue = catalogue(language);
        for (key, text) in catalogue.entries() {
            if text.trim().is_empty() {
                wrong.push(format!("{language} `{key}`: empty"));
            }
            if text.matches('{').count() != text.matches('}').count() {
                wrong.push(format!("{language} `{key}`: a brace without its partner"));
            }
            for name in placeholders(text) {
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                    wrong.push(format!("{language} `{key}`: `{{{name}}}` is not a placeholder"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_english_catalogue_is_a_translation_and_not_a_copy() {
    // An unfinished translation looks exactly like this: the key is there, the German text is
    // there, and nobody notices until a customer does. Sentences that are the same in both
    // languages on purpose (a product name, a code) are named here one by one — the list is the
    // place where that decision is visible.
    const SAME_ON_PURPOSE: &[&str] = &[
        "status.offline",
        "status.with_hint",
        "menu.tooltip",
        "window.title_with_account",
        "demo.account",
    ];
    let german = catalogue(Language::De);
    let english = catalogue(Language::En);
    let mut copies = Vec::new();
    for key in KEYS {
        if SAME_ON_PURPOSE.contains(&key.path()) {
            continue;
        }
        if german.text(*key) == english.text(*key) {
            copies.push(format!("`{key}`: {}", german.text(*key)));
        }
    }
    assert!(
        copies.is_empty(),
        "these sentences are identical in both catalogues; either translate them or enter them \
         in SAME_ON_PURPOSE:\n{}",
        copies.join("\n")
    );
}

#[test]
fn the_two_hint_files_of_the_mirror_have_different_names_per_language() {
    // README.txt in English, LIESMICH.txt in German — the file name is part of the view, not a
    // technical identifier (the identifier is `hint-readme` and stays English).
    let german = catalogue(Language::De);
    let english = catalogue(Language::En);
    assert_eq!(german.text(edms_i18n::key::MIRROR_README_NAME), "LIESMICH.txt");
    assert_eq!(english.text(edms_i18n::key::MIRROR_README_NAME), "README.txt");
    for language in [&german, &english] {
        let name = language.text(edms_i18n::key::MIRROR_TRUNCATED_NAME);
        assert!(name.ends_with(".txt"), "{name}");
    }
}

#[test]
fn the_hint_of_the_mirror_sends_the_user_to_a_mail_basket_and_not_beside_the_folder() {
    // This is the one sentence every user reads before they use the product, and until 2026-09-13
    // it named `elasticdms Eingang` — a folder namespace v2 removed (ADR-D11 §5). A stale
    // instruction here does not fail anywhere: the user follows it, creates the folder by hand and
    // waits for an ingest that never comes.
    for (language, container) in [(Language::De, "Briefkörbe"), (Language::En, "Mailbaskets")] {
        let catalogue = catalogue(language);
        let body = catalogue.text(edms_i18n::key::MIRROR_README_BODY);
        assert!(body.contains(container), "{language}: the hint names no drop target:\n{body}");
        assert_eq!(
            container,
            catalogue.text(edms_i18n::key::MIRROR_BASKETS),
            "{language}: the hint has to name the folder the mirror really shows"
        );
        assert!(
            !body.contains("Eingang"),
            "{language}: the hint still points at the folder that was removed:\n{body}"
        );
    }
}
