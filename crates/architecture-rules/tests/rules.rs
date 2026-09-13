//! The house rules of the folder client as a test — green or red, never "please note".
//!
//! The model is `build-regeln` in the sister repository elasticdms-escan: every rule has an
//! identifier, a pattern, an allow list and a sentence of rationale; comments and string literals
//! are stripped before the check (otherwise every rule would fire on its own documentation); and
//! every check has to prove that it reads anything at all — with a lower bound on the number of
//! files read and one mandatory hit per rule. "A check that reads nothing is green and worthless."
//!
//! Deliberately no Rust parser: the patterns are substrings of the stripped source. That is
//! coarse, but there is no place where a parser would give a different answer that matters here.
//! KNOWN LIMIT, stated openly: a pattern that spans a line break (`reqwest\n::Client`) slips
//! through. Nobody writes like that unless they mean to cheat.

// The helper functions of this test target (`root`, `production_files`, `collect`,
// `read_everything`) live outside `#[test]` functions. For `allow-expect-in-tests` (clippy.toml,
// already set there) clippy only inspects the enclosing function for `#[test]` and therefore does
// not see the permission here — the same calls inside `dependencies_point_only_downwards` pass.
// Aborting is the right behaviour at these places: if the check cannot read its own workspace it
// must fail loudly instead of quietly turning green.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// At least this many production files the check must read, otherwise it is red.
const MIN_FILES: usize = 40;

struct Rule {
    identifier: &'static str,
    title: &'static str,
    pattern: &'static [&'static str],
    allowed_in: &'static [&'static str],
    /// A crate in which the pattern MUST occur — the proof that the rule bites.
    required_hit: Option<&'static str>,
    rationale: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        identifier: "R1",
        title: "HTTP client only in edms-net",
        pattern: &["reqwest::"],
        allowed_in: &["net"],
        required_hit: Some("net"),
        rationale: "reqwest in a second crate would mean a second way around DPoP, nonce and the error catalogue.",
    },
    Rule {
        identifier: "R2",
        title: "HTTP server only in the mock",
        pattern: &["axum::", "hyper::server"],
        allowed_in: &["mock"],
        required_hit: Some("mock"),
        rationale: "The client listens on no port (ADR-D04); a server in production code would be one.",
    },
    Rule {
        identifier: "R3",
        title: "SQL only in edms-store",
        pattern: &["rusqlite::"],
        allowed_in: &["store"],
        required_hit: Some("store"),
        rationale: "Exactly one place writes the local state — otherwise there are two truths about the namespace.",
    },
    Rule {
        identifier: "R4",
        title: "Windows API only in edms-cfapi",
        pattern: &["cloud_filter::", "windows::Win32", "windows::Storage"],
        allowed_in: &["cfapi"],
        required_hit: Some("cfapi"),
        rationale: "The platform layer stays thin and alone (ADR-D02); the engine knows only edms_core::port.",
    },
    Rule {
        identifier: "R5",
        title: "Objective-C only in edms-fileprovider",
        pattern: &["objc2::", "objc2_foundation::", "objc2_file_provider::", "block2::"],
        allowed_in: &["fileprovider"],
        required_hit: Some("fileprovider"),
        rationale: "The platform layer stays thin and alone (ADR-D02); the engine knows only edms_core::port.",
    },
    Rule {
        identifier: "R6",
        title: "Elliptic curves only in edms-crypto",
        pattern: &["p256::"],
        allowed_in: &["crypto"],
        required_hit: Some("crypto"),
        rationale: "One algorithm in the whole procedure, computed in one place (geraete-auth §5.1).",
    },
    Rule {
        identifier: "R7",
        title: "User interface only in the app",
        pattern: &["tao::", "wry::", "tray_icon::"],
        allowed_in: &["app"],
        required_hit: Some("app"),
        rationale: "The app is the only place where the crates know each other; a window in the engine would be a second one.",
    },
];

/// Crates in which `unsafe` may appear at all.
const UNSAFE_ALLOWED: &[&str] = &["cfapi", "fileprovider", "bridge"];

/// Permitted dependencies between our own crates, direction strictly bottom-up.
fn allowed_dependencies() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    let mut m = BTreeMap::new();
    let mut set = |c: &'static str, deps: &[&'static str]| {
        m.insert(c, deps.iter().copied().collect::<BTreeSet<_>>());
    };
    // edms-i18n lies **below** edms-core: the core builds the mirror's hint file and needs its
    // text, and only a crate below it can supply that without turning the direction around.
    set("edms-i18n", &[]);
    set("edms-core", &["edms-i18n"]);
    set("edms-crypto", &["edms-core"]);
    set("edms-wire", &["edms-core"]);
    set("edms-store", &["edms-core", "edms-i18n"]);
    set("edms-bridge", &["edms-core", "edms-i18n"]);
    set("edms-cfapi", &["edms-core", "edms-i18n"]);
    set("edms-fileprovider", &["edms-core", "edms-bridge", "edms-i18n"]);
    set("edms-net", &["edms-core", "edms-crypto", "edms-wire"]);
    set("edms-mock", &["edms-core", "edms-crypto", "edms-wire"]);
    set(
        "edms-engine",
        &["edms-core", "edms-crypto", "edms-wire", "edms-net", "edms-store", "edms-i18n"],
    );
    set(
        "elasticdms",
        &[
            "edms-i18n",
            "edms-core",
            "edms-crypto",
            "edms-wire",
            "edms-net",
            "edms-store",
            "edms-engine",
            "edms-bridge",
            "edms-cfapi",
            "edms-fileprovider",
        ],
    );
    set("architecture-rules", &[]);
    m
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("workspace")
}

/// All .rs files under `crates/<name>/src`, keyed by crate directory name.
fn production_files() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let crates = root().join("crates");
    for entry in fs::read_dir(&crates).expect("crates/ readable") {
        let path = entry.expect("entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_owned();
        if name == "architecture-rules" {
            continue;
        }
        let src = path.join("src");
        if src.is_dir() {
            collect(&src, &name, &mut out);
        }
    }
    out.sort();
    out
}

fn collect(directory: &Path, crate_name: &str, out: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(directory).expect("directory readable") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            collect(&path, crate_name, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push((crate_name.to_owned(), path));
        }
    }
}

/// Strips comments, string literals and character literals; line breaks stay so that line numbers
/// remain correct. A state machine over six states.
fn only_code(source: &str) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Code,
        LineComment,
        BlockComment(u32),
        Str,
        RawStr(usize),
        Character,
    }
    let z: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut state = State::Code;
    let mut i = 0;
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < z.len() {
        let c = z[i];
        let n = z.get(i + 1).copied();
        match state {
            State::Code => {
                if c == '/' && n == Some('/') {
                    state = State::LineComment;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '/' && n == Some('*') {
                    state = State::BlockComment(1);
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                // Raw strings: r"..", r#".."#, br#".."#
                let raw_start = if c == 'r' && matches!(n, Some('"' | '#')) {
                    Some(i + 1)
                } else if c == 'b' && n == Some('r') && matches!(z.get(i + 2), Some('"' | '#')) {
                    Some(i + 2)
                } else {
                    None
                };
                let identifier_before = i > 0 && (z[i - 1].is_alphanumeric() || z[i - 1] == '_');
                if let (Some(mut j), false) = (raw_start, identifier_before) {
                    let mut hashes = 0;
                    while z.get(j) == Some(&'#') {
                        hashes += 1;
                        j += 1;
                    }
                    if z.get(j) == Some(&'"') {
                        for _ in i..=j {
                            out.push(' ');
                        }
                        state = State::RawStr(hashes);
                        i = j + 1;
                        continue;
                    }
                }
                if c == '"' {
                    state = State::Str;
                    out.push(' ');
                    i += 1;
                    continue;
                }
                if c == '\'' {
                    // Character literal or lifetime?
                    let is_character = n == Some('\\') || z.get(i + 2) == Some(&'\'');
                    if is_character {
                        state = State::Character;
                        out.push(' ');
                        i += 1;
                        continue;
                    }
                }
                out.push(c);
                i += 1;
            }
            State::LineComment => {
                if c == '\n' {
                    state = State::Code;
                }
                out.push(blank(c));
                i += 1;
            }
            State::BlockComment(depth) => {
                if c == '/' && n == Some('*') {
                    state = State::BlockComment(depth + 1);
                    out.push_str("  ");
                    i += 2;
                } else if c == '*' && n == Some('/') {
                    state = if depth == 1 { State::Code } else { State::BlockComment(depth - 1) };
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(blank(c));
                    i += 1;
                }
            }
            State::Str => {
                if c == '\\' {
                    out.push(' ');
                    if let Some(m) = n {
                        out.push(blank(m));
                    }
                    i += 2;
                } else {
                    if c == '"' {
                        state = State::Code;
                    }
                    out.push(blank(c));
                    i += 1;
                }
            }
            State::RawStr(hashes) => {
                if c == '"' && (1..=hashes).all(|k| z.get(i + k) == Some(&'#')) {
                    for _ in 0..=hashes {
                        out.push(' ');
                    }
                    state = State::Code;
                    i += hashes + 1;
                } else {
                    out.push(blank(c));
                    i += 1;
                }
            }
            State::Character => {
                if c == '\\' {
                    out.push_str("  ");
                    i += 2;
                } else {
                    if c == '\'' {
                        state = State::Code;
                    }
                    out.push(blank(c));
                    i += 1;
                }
            }
        }
    }
    out
}

struct File {
    crate_name: String,
    path: PathBuf,
    source: String,
    code: String,
}

fn read_everything() -> Vec<File> {
    production_files()
        .into_iter()
        .map(|(crate_name, path)| {
            let source = fs::read_to_string(&path).expect("source readable");
            let code = only_code(&source);
            File { crate_name, path, source, code }
        })
        .collect()
}

fn relative(p: &Path) -> String {
    p.strip_prefix(root()).unwrap_or(p).display().to_string()
}

#[test]
fn the_check_reads_enough_files() {
    let n = read_everything().len();
    assert!(
        n >= MIN_FILES,
        "Only {n} production files read, expected at least {MIN_FILES}. A check that reads nothing is green and worthless."
    );
}

#[test]
fn every_rule_holds_and_bites() {
    let files = read_everything();
    let mut violations = Vec::new();
    for rule in RULES {
        let mut hit = false;
        for d in &files {
            for (nr, row) in d.code.lines().enumerate() {
                for pattern in rule.pattern {
                    if row.contains(pattern) {
                        if rule.allowed_in.contains(&d.crate_name.as_str()) {
                            if rule.required_hit == Some(d.crate_name.as_str()) {
                                hit = true;
                            }
                        } else {
                            violations.push(format!(
                                "{} {} — {}:{}: `{}`. {}",
                                rule.identifier,
                                rule.title,
                                relative(&d.path),
                                nr + 1,
                                pattern,
                                rule.rationale
                            ));
                        }
                    }
                }
            }
        }
        if rule.required_hit.is_some() && !hit {
            violations.push(format!(
                "{} {} — mandatory hit missing in crates/{}: the rule reads into the void.",
                rule.identifier,
                rule.title,
                rule.required_hit.unwrap_or_default()
            ));
        }
    }
    assert!(violations.is_empty(), "architecture rules violated:\n{}", violations.join("\n"));
}

#[test]
fn unsafe_only_in_platform_crates_and_always_justified() {
    let mut violations = Vec::new();
    for d in read_everything() {
        let row_source: Vec<&str> = d.source.lines().collect();
        for (nr, row) in d.code.lines().enumerate() {
            let has_block = row.contains("unsafe {") || row.trim_end().ends_with("unsafe");
            let has_unsafe = has_block || row.contains("unsafe fn") || row.contains("unsafe impl");
            if !has_unsafe {
                continue;
            }
            if !UNSAFE_ALLOWED.contains(&d.crate_name.as_str()) {
                violations.push(format!(
                    "{}:{}: unsafe outside the platform crates",
                    relative(&d.path),
                    nr + 1
                ));
                continue;
            }
            if has_block {
                let of = nr.saturating_sub(4);
                let justified = row_source[of..=nr.min(row_source.len() - 1)]
                    .iter()
                    .any(|z| z.contains("SAFETY:"));
                if !justified {
                    violations.push(format!(
                        "{}:{}: unsafe block without `// SAFETY:` in the four lines above",
                        relative(&d.path),
                        nr + 1
                    ));
                }
            }
        }
    }
    assert!(violations.is_empty(), "unsafe rule violated:\n{}", violations.join("\n"));
}

#[test]
fn identifiers_are_ascii() {
    let mut violations = Vec::new();
    for d in read_everything() {
        for (nr, row) in d.code.lines().enumerate() {
            if let Some(z) = row.chars().find(|c| !c.is_ascii()) {
                violations.push(format!(
                    "{}:{}: `{}` in code outside comment and string literal",
                    relative(&d.path),
                    nr + 1,
                    z
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "identifiers must be ASCII (ae/oe/ue/ss instead of umlauts), as everywhere in this house:\n{}",
        violations.join("\n")
    );
}

#[test]
fn libraries_do_not_write_to_the_console() {
    let mut violations = Vec::new();
    for d in read_everything() {
        let is_program = d.crate_name == "app"
            || d.path.ends_with("src/main.rs")
            || d.path.to_string_lossy().contains("/src/bin/");
        if is_program {
            continue;
        }
        for (nr, row) in d.code.lines().enumerate() {
            if row.contains("println!") || row.contains("eprintln!") {
                violations.push(format!(
                    "{}:{}: console output in a library; use tracing",
                    relative(&d.path),
                    nr + 1
                ));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// Reads the dependencies of a manifest section by section, without a TOML parser: only the names
/// of our own crates matter, and those always stand at the start of a line.
fn own_dependencies(manifest: &str) -> (String, BTreeSet<String>, BTreeSet<String>, Vec<String>) {
    let mut name = String::new();
    let mut normal = BTreeSet::new();
    let mut development = BTreeSet::new();
    let mut forge_normal = Vec::new();
    let mut section = String::new();
    for row in manifest.lines() {
        let t = row.trim();
        if t.starts_with('[') {
            section = t.to_owned();
            continue;
        }
        if section == "[package]"
            && let Some(rest) = t.strip_prefix("name")
        {
            name = rest.trim_start_matches([' ', '=']).trim_matches('"').to_owned();
        }
        let key = t.split(['=', '.', ' ']).next().unwrap_or_default();
        let own = key.starts_with("edms-") || key == "elasticdms";
        let is_development = section.contains("dev-dependencies");
        let is_normal = section.ends_with("dependencies]") && !is_development;
        if own && is_normal {
            normal.insert(key.to_owned());
            if t.contains("forge") {
                forge_normal.push(key.to_owned());
            }
        } else if own && is_development {
            development.insert(key.to_owned());
        }
    }
    (name, normal, development, forge_normal)
}

#[test]
fn dependencies_point_only_downwards() {
    let allowed = allowed_dependencies();
    let mut violations = Vec::new();
    let mut read = 0;
    for entry in fs::read_dir(root().join("crates")).expect("crates/") {
        let manifest = entry.expect("entry").path().join("Cargo.toml");
        let Ok(text) = fs::read_to_string(&manifest) else { continue };
        read += 1;
        let (name, normal, development, forge) = own_dependencies(&text);
        let Some(permitted) = allowed.get(name.as_str()) else {
            violations.push(format!(
                "{name}: unknown crate — enter it in allowed_dependencies() and give a reason"
            ));
            continue;
        };
        for dep in &normal {
            if !permitted.contains(dep.as_str()) {
                violations.push(format!("{name} depends on {dep}; allowed is only {permitted:?}"));
            }
        }
        for dep in &development {
            if !permitted.contains(dep.as_str()) && dep != "edms-mock" {
                violations.push(format!(
                    "{name} (dev) depends on {dep}; allowed is {permitted:?} and edms-mock"
                ));
            }
        }
        // The mock and its workshop must never end up in a release (crate header edms-mock).
        if name != "edms-mock" {
            for w in &forge {
                violations.push(format!("{name} pulls {w} with feature `forge` as a normal dependency — mock and tests only"));
            }
        }
    }
    assert!(read >= 12, "Only {read} manifests read; the check reads into the void.");
    assert!(violations.is_empty(), "dependency direction violated:\n{}", violations.join("\n"));
}

#[test]
fn the_stripper_removes_comments_strings_and_characters() {
    let q = "let a = \"reqwest::x\"; // reqwest::y\nlet b = r#\"axum::z\"#; /* p256:: /* deep */ */ let c = 'x'; fn f<'a>(x: &'a str) {}";
    let c = only_code(q);
    assert!(!c.contains("reqwest::") && !c.contains("axum::") && !c.contains("p256::"), "{c}");
    assert!(c.contains("fn f<'a>(x: &'a str)"), "lifetimes are code: {c}");
    assert_eq!(c.lines().count(), q.lines().count());
}

/// German word stems that were identifiers in this repository before the conversion of 2026-09-12.
///
/// Compared against the **words of an identifier**, not against the identifier as a whole: an
/// identifier is split at `_` and at every lower-to-upper step, and a word counts as German when
/// it begins with one of these stems. Comparing whole substrings instead would report
/// `didUpdateItems`, because `upDATEItems` carries `datei` in the middle of two English words.
///
/// The list is the vocabulary that actually stood here, not German as such — a rule nobody can
/// read the reason for is one that gets switched off at the first false report.
const GERMAN_STEMS: &[&str] = &[
    "abgleich",
    "abhaengig",
    "abmeld",
    "aenderung",
    "akten",
    "anbieter",
    "anmeld",
    "anzeigename",
    "attrappe",
    "ausgang",
    "befehl",
    "behaelter",
    "bruecke",
    "datei",
    "dokument",
    "eingang",
    "eingegangen",
    "einstellung",
    "eintrag",
    "erstellt",
    "fassung",
    "fehler",
    "geaendert",
    "gekappt",
    "geraet",
    "getilgt",
    "groesse",
    "hinweis",
    "inhalt",
    "kennung",
    "krypto",
    "liesmich",
    "loeschung",
    "mandant",
    "medientyp",
    "nutzung",
    "ordner",
    "platzhalter",
    "protokoll",
    "pruef",
    "quittier",
    "quittung",
    "schluessel",
    "sitzung",
    "speicher",
    "spiegel",
    "stueck",
    "suchen",
    "untergrenze",
    "versatz",
    "verzeichnis",
    "vorgang",
    "werkstatt",
    "wurzel",
    "zustand",
    "zustell",
];

/// Splits an identifier into lowercase words: `SyncRootIdentifier` and `sync_root_identifier`
/// both become `["sync", "root", "identifier"]`.
fn words_of(identifier: &str) -> Vec<String> {
    let mut words = Vec::new();
    for part in identifier.split('_') {
        let mut current = String::new();
        let mut previous_lower = false;
        for c in part.chars() {
            if c.is_uppercase() && previous_lower && !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = c.is_lowercase() || c.is_ascii_digit();
            current.push(c.to_ascii_lowercase());
        }
        if !current.is_empty() {
            words.push(current);
        }
    }
    words
}

fn german_stem_of(identifier: &str) -> Option<&'static str> {
    words_of(identifier)
        .iter()
        .find_map(|word| GERMAN_STEMS.iter().copied().find(|stem| word.starts_with(stem)))
}

/// No German identifier comes back.
///
/// WHY THIS RULE EXISTS: the owner's decision of 2026-09-12 — *"Jeder programmiert in Englisch und
/// auch IDs"* (everyone programs in English, identifiers included). The conversion was a single
/// large pass; without a rule the next new module quietly writes `kennung` again, because half the
/// surrounding documents and the sister repository still speak German. A test costs nothing and
/// notices it on the first `cargo test` instead of in the next review.
///
/// Comments and string literals are stripped first, exactly as for every other rule here: a
/// **quote** from a German source spec is allowed and shall stay (README, "Style"), a stored
/// German **value** is allowed where a migration keeps it readable, and the German catalogue is a
/// catalogue. Only what the compiler sees as a name is checked.
#[test]
fn no_german_identifier_returns() {
    let mut violations = Vec::new();
    let mut identifiers = 0usize;
    let files = read_everything();
    for d in &files {
        for (nr, row) in d.code.lines().enumerate() {
            for identifier in row.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                if identifier.is_empty() || identifier.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                identifiers += 1;
                if let Some(stem) = german_stem_of(identifier) {
                    violations.push(format!(
                        "{}:{}: `{identifier}` carries the German stem `{stem}`",
                        relative(&d.path),
                        nr + 1
                    ));
                }
            }
        }
    }
    assert!(
        identifiers >= 20_000,
        "only {identifiers} identifiers read — the check reads into the void"
    );
    assert!(
        violations.is_empty(),
        "German identifiers are back ({}); everything developers touch is English (owner's decision 2026-09-12):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Proof that the rule above bites — a rule that can never fire is decoration.
#[test]
fn the_german_identifier_rule_recognizes_what_it_is_for() {
    for name in ["kennung", "Kennung", "eltern_kennung", "ServerSchluessel", "zustellBefehl"] {
        assert!(german_stem_of(name).is_some(), "`{name}` should have been recognized");
    }
    // English names that carry a German stem only across a word boundary must stay silent.
    for name in [
        "didUpdateItems",
        "candidate",
        "Identifier",
        "update_items",
        "SyncRootIdentifier",
        "sha256",
    ] {
        assert_eq!(german_stem_of(name), None, "`{name}` is not German");
    }
    assert_eq!(words_of("SyncRootIdentifier"), ["sync", "root", "identifier"]);
    assert_eq!(words_of("eltern_kennung"), ["eltern", "kennung"]);
}

// ── Error texts ──────────────────────────────────────────────────────────────────────────────
//
// Every rule above runs on `only_code`, which blanks string literals. That is right for them and
// it is the reason none of them ever saw an `#[error("…")]` text: on 2026-09-13, ten months after
// the conversion to English, 190 of the 293 error texts of the production crates still stood in
// German — and they are not internal. `crates/mock` forwards them verbatim into the `detail` of
// RFC 9457 problem documents (src/api.rs, src/http.rs), so they reached the wire; `doctor`,
// `--uninstall` and every `tracing` line render them, so they reached the operator. The rules
// below therefore read the **raw** source.

/// At least this many `#[error("…")]` texts the check must read, otherwise it is red.
///
/// Measured on 2026-09-13: 293 in `crates/*/src`. The bound sits below that so that retiring a
/// handful of variants does not turn the rule red for the wrong reason — but a broken extractor,
/// which is the failure that matters, reads nothing at all and is caught.
const MIN_ERROR_TEXTS: usize = 250;

/// One `#[error("…")]` text together with the place it stands.
struct ErrorText {
    /// `crates/…/src/….rs:<line>`, the line the attribute begins on.
    place: String,
    /// The text as a reader of a log sees it: `\`-continuations joined.
    text: String,
}

/// Reads an `#[error( … )]` from its opening parenthesis.
///
/// Returns the first string literal of the attribute — the format string; a trailing
/// `name = expression` argument is deliberately not read, it is code and the rules above cover it
/// — and the index just past the closing parenthesis.
fn first_error_literal(chars: &[char], open: usize) -> (Option<String>, usize) {
    let mut depth = 0usize;
    let mut i = open;
    let mut found: Option<String> = None;
    while i < chars.len() {
        match chars[i] {
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                i += 1;
                if depth == 0 {
                    break;
                }
            }
            '"' => {
                let mut text = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] != '\\' {
                        text.push(chars[i]);
                        i += 1;
                        continue;
                    }
                    i += 1;
                    match chars.get(i) {
                        // A line continuation: Rust eats the newline and the indentation after it,
                        // so the rendered sentence runs on. Half the German of 2026-09-13 stood on
                        // such a second line, which is why this is not a detail.
                        Some('\n') => {
                            i += 1;
                            while matches!(chars.get(i), Some(c) if c.is_whitespace() && *c != '\n')
                            {
                                i += 1;
                            }
                        }
                        Some('n') | Some('t') => {
                            text.push(' ');
                            i += 1;
                        }
                        Some(other) => {
                            text.push(*other);
                            i += 1;
                        }
                        None => break,
                    }
                }
                i += 1;
                if found.is_none() {
                    found = Some(text);
                }
            }
            _ => i += 1,
        }
    }
    (found, i)
}

/// Every `#[error("…")]` text of the production crates.
fn error_texts(files: &[File]) -> Vec<ErrorText> {
    let needle: Vec<char> = "#[error(".chars().collect();
    let mut out = Vec::new();
    for d in files {
        let chars: Vec<char> = d.source.chars().collect();
        let mut i = 0;
        while i + needle.len() <= chars.len() {
            if chars[i..i + needle.len()] != needle[..] {
                i += 1;
                continue;
            }
            let open = i + needle.len() - 1;
            let (text, end) = first_error_literal(&chars, open);
            if let Some(text) = text {
                let line = chars[..i].iter().filter(|c| **c == '\n').count() + 1;
                out.push(ErrorText { place: format!("{}:{}", relative(&d.path), line), text });
            }
            i = end.max(i + 1);
        }
    }
    out
}

/// German function words, for prose rather than for identifiers.
///
/// Complements [`GERMAN_STEMS`] instead of repeating it: that list carries the nouns this
/// repository actually used, this one the little words that give a German sentence away even when
/// every noun in it happens to be a technical term.
///
/// `der`, `die`, `man`, `hat`, `war`, `als` are deliberately **absent**. Each is also an English
/// word or an acronym that stands here on purpose — `DER` is the encoding named in
/// `crates/crypto` ("expected is `r || s`, not DER"). A rule that reports a correct line is a rule
/// somebody switches off.
const GERMAN_PROSE_WORDS: &[&str] = &[
    "aber", "alle", "auch", "auf", "aus", "bei", "beim", "bereits", "bleibt", "bzw", "dabei",
    "dadurch", "dafuer", "dagegen", "daher", "damit", "daran", "darauf", "darin", "dass", "davon",
    "dazu", "dem", "den", "denn", "des", "deshalb", "diese", "dieser", "dieses", "doch", "dort",
    "durch", "ein", "eine", "einem", "einen", "einer", "eines", "enthaelt", "entweder", "erlaubt",
    "erst", "erwartet", "euch", "fehlt", "fuer", "ganz", "gegen", "gehoert", "gemaess", "gibt",
    "gilt", "heisst", "hier", "ihm", "ihn", "ihre", "immer", "ist", "jede", "jeder", "jedes",
    "jedoch", "jetzt", "jeweils", "kann", "kein", "keine", "keinem", "keinen", "keiner", "keines",
    "laesst", "liefert", "liegt", "macht", "mehr", "meldet", "mit", "muss", "nach", "nennt",
    "nicht", "nie", "niemals", "noch", "nur", "ohne", "oder", "schon", "sehr", "seine", "selbst",
    "sich", "sind", "soll", "sollen", "sondern", "sowie", "sowohl", "stammt", "steht", "stehen",
    "traegt", "ueber", "und", "uns", "unter", "verlangt", "vom", "von", "vor", "waere", "warum",
    "weder", "weil", "welche", "wenn", "wie", "wieder", "wird", "worden", "wurde", "werden",
    "zwar", "zwischen", "zum", "zur",
];

/// Names of the counterpart's German documents that stand verbatim inside an error text.
///
/// The owner's rule is that every paragraph reference stays exactly as it is, and `geraete-auth`
/// is a file name, not prose. Without this exemption the stem `geraet` would report all 15 texts
/// that carry a `geraete-auth §…` reference (measured 2026-09-13).
const SPEC_NAMES_IN_ERROR_TEXTS: &[&str] = &["geraete-auth"];

/// Why this text is German, or `None`.
fn german_in_prose(text: &str) -> Option<String> {
    let mut rest = text.to_owned();
    for name in SPEC_NAMES_IN_ERROR_TEXTS {
        rest = rest.replace(name, " ");
    }
    if let Some(c) = rest.chars().find(|c| "äöüÄÖÜß„".contains(*c)) {
        return Some(format!("the German character `{c}`"));
    }
    for word in rest.split(|c: char| !c.is_ascii_alphabetic()) {
        // Acronyms carry no case information worth reading: DER, JWK, NTFS, WAL, ES256.
        if word.is_empty() || word.chars().all(char::is_uppercase) {
            continue;
        }
        let lower = word.to_ascii_lowercase();
        if GERMAN_PROSE_WORDS.contains(&lower.as_str()) {
            return Some(format!("the German word `{word}`"));
        }
        if let Some(stem) = GERMAN_STEMS.iter().find(|stem| lower.starts_with(**stem)) {
            return Some(format!("the German stem `{stem}` in `{word}`"));
        }
    }
    None
}

/// Error texts that may carry German, each with its reason.
///
/// Empty, and that is a measurement and not an oversight: on 2026-09-13 not one of the 293 texts
/// needs an entry. The only admissible reason would be a verbatim quotation of the counterpart's
/// German specification **inside the sentence itself** — and such a quotation belongs in the doc
/// comment above the variant, where it is allowed and where it already stands, not in a line an
/// operator pastes into a ticket and searches for (ADR-D10).
///
/// Whoever adds an entry writes the text and the reason next to it, so that the next reviewer
/// reads a decision instead of guessing at one.
const GERMAN_ERROR_TEXT_ALLOWED: &[(&str, &str)] = &[];

/// No German error text comes back.
///
/// WHY THIS RULE EXISTS: the conversion of 2026-09-12 renamed the identifiers and rewrote the
/// comments and left the error texts standing, and nothing noticed for ten months, because every
/// rule in this file strips string literals before it looks. These texts are the one surface that
/// is at once foreign-visible and unguarded: `crates/mock` puts them into the `detail` of an
/// RFC 9457 problem document at eighteen places, and ADR-D10 decides that operator surfaces stay
/// English — "they are read in a terminal, pasted into a ticket and searched for; a translated
/// diagnosis cannot be found again".
#[test]
fn no_german_error_text_returns() {
    let files = read_everything();
    let texts = error_texts(&files);
    assert!(
        texts.len() >= MIN_ERROR_TEXTS,
        "only {} error texts read, expected at least {MIN_ERROR_TEXTS}. A check that reads nothing is green and worthless.",
        texts.len()
    );
    let mut violations = Vec::new();
    for found in &texts {
        if GERMAN_ERROR_TEXT_ALLOWED.iter().any(|(allowed, _)| *allowed == found.text) {
            continue;
        }
        if let Some(why) = german_in_prose(&found.text) {
            violations.push(format!("{}: {why} — \"{}\"", found.place, found.text));
        }
    }
    assert!(
        violations.is_empty(),
        "German error texts are back ({}); they reach the wire in the `detail` of a problem document and the operator in the terminal (ADR-D10):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Words that legitimately start an error text with a capital letter.
///
/// Measured on 2026-09-13 over all 293 texts: exactly these three. A name Windows or SQLite gave
/// the thing keeps its spelling; nothing else starts upper-case.
const ERROR_TEXT_PROPER_NOUNS: &[&str] = &["Content-Length", "Pragma", "Windows"];

/// Why this text breaks the house voice, or `None`.
fn voice_fault(text: &str) -> Option<String> {
    if let Some(first) = text.chars().next()
        && first.is_uppercase()
        && !ERROR_TEXT_PROPER_NOUNS.iter().any(|noun| text.starts_with(noun))
    {
        return Some(format!("it starts upper-case (`{first}`)"));
    }
    if text.ends_with('.') {
        return Some("it ends with a full stop".to_owned());
    }
    if let Some(c) = text.chars().find(|c| "“”„".contains(*c)) {
        return Some(format!("it quotes with `{c}` instead of a backtick"));
    }
    None
}

/// Every error text is written in the one voice.
///
/// WHY THIS RULE EXISTS: an error text is a sentence an operator greps for, and three different
/// conventions in one workspace mean three different searches. The convention is not invented
/// here, it is measured: of the 89 texts that were already English before the pass of 2026-09-13
/// — `crates/app`, `bridge`, `core`, `engine`, `fileprovider` — not one started upper-case and
/// none quoted with anything but a backtick. The crates translated afterwards drifted (crypto 43
/// texts, store 25, net 10, mock 4) and were brought back onto it; without a rule they drift again
/// on the next pass, because a translator reaches for the capital letter the German sentence had.
#[test]
fn every_error_text_is_written_in_the_house_voice() {
    let files = read_everything();
    let texts = error_texts(&files);
    assert!(
        texts.len() >= MIN_ERROR_TEXTS,
        "only {} error texts read — the check reads into the void",
        texts.len()
    );
    let mut violations = Vec::new();
    for found in &texts {
        if let Some(why) = voice_fault(&found.text) {
            violations.push(format!("{}: {why} — \"{}\"", found.place, found.text));
        }
    }
    assert!(
        violations.is_empty(),
        "error texts out of the house voice ({}): lower-case start, no trailing full stop, backticks around literals:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Proof that the two rules above bite — a rule that can never fire is decoration.
#[test]
fn the_error_text_rules_recognize_what_they_are_for() {
    // Four lines taken verbatim out of `git show HEAD` of 2026-09-13, one per shape the German
    // had: transliterated (`ae`), with an umlaut, a noun that is only a stem, and a sentence whose
    // every noun is a technical term so that only the little words give it away.
    for text in [
        "Das JWK enthaelt einen privaten Anteil; ein solcher Schluessel gilt als preisgegeben (geraete-auth §3.1).",
        "Die Marke trägt Fassung {read}; diese Erweiterung schreibt Fassung {expected}.",
        "Der Befehl nennt kein Dokument.",
        "htu ist „{read}“, angefragt wurde „{expected}“",
    ] {
        assert!(german_in_prose(text).is_some(), "not recognized as German: {text}");
    }
    // English that stands in the tree today and must stay silent: the acronym `DER`, the kept
    // `geraete-auth` reference, and the English words that carry a German stem only across a word
    // boundary.
    for text in [
        "the JWK carries a private part; such a key counts as given away (geraete-auth §3.1)",
        "the signature has 3 bytes instead of 64; expected is r || s, not DER",
        "Windows does not support sync roots on this device",
        "the access token is bound to the key {bound}, the proof comes from {read} (geraete-auth §2.4 point 8)",
        "the local database is corrupt (table {table}): {reason}",
    ] {
        assert_eq!(german_in_prose(text), None, "falsely reported as German: {text}");
    }

    // The voice rule, in both directions.
    assert!(voice_fault("The key material is unusable").is_some(), "upper-case start");
    assert!(voice_fault("the key material is unusable.").is_some(), "trailing full stop");
    assert!(voice_fault("the key “{kid}” is unusable").is_some(), "curly quotes");
    for text in [
        "the key `{kid}` is unusable",
        "Windows does not support sync roots on this device",
        "`{0}` is not an entry identifier of the folder client",
        "the local database runs in mode `{mode}` instead of WAL; does it lie on a network drive?",
    ] {
        assert_eq!(voice_fault(text), None, "falsely reported: {text}");
    }

    // The extractor has to join a `\`-continuation, or it would only ever see the first line —
    // and half the German of 2026-09-13 stood on the second.
    let source = "#[error(\n    \"one half \\\n     and the other\"\n)]";
    let chars: Vec<char> = source.chars().collect();
    let (text, end) = first_error_literal(&chars, "#[error".chars().count());
    assert_eq!(text.as_deref(), Some("one half and the other"));
    assert_eq!(end, chars.len() - 1, "the walk stops just past the closing parenthesis");
}
