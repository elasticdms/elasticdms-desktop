//! The contract document and the golden files are one source, not two.
//!
//! `docs/spec/03-api-contract-folder-client.md` explains the contract; `crates/wire/testdata/`
//! delivers its bodies to the mock and to the client. Without this test those would be two
//! transcripts: somebody changes a field in the document, the mock keeps sending the old one —
//! and both sides stay green, because each checks against itself. That is exactly what
//! `geraete-auth §9.1` warns about.
//!
//! Four promises:
//!
//! 1. Every JSON block behind `<!-- golden: … -->` is **byte-identical** with its file.
//! 2. Every marker names a file that exists.
//! 3. Every body **proposed** in this repository stands in the document — a proposal nobody can
//!    read is no proposal.
//! 4. Every short code of the error catalogue from `basics` stands in the document (§7.5).

// Test code may use `unwrap` (clippy.toml); but clippy does not recognize helper functions of an
// integration test file outside `#[test]` as test code.
#![allow(clippy::unwrap_used)]

use edms_wire::basics::ErrorKind;
use edms_wire::golden::{ALL, Provenance, find};

/// The contract document, included at compile time: if it disappears or moves, the build
/// notices, not the test.
const DOCUMENT: &str = include_str!("../../../docs/spec/03-api-contract-folder-client.md");

const MARKER_START: &str = "<!-- golden: ";
const MARKER_END: &str = " -->";
const FENCE: &str = "```";

/// A find in the document: the name from the marker and the body from the fence behind it.
struct Block {
    name: String,
    body: String,
    row: usize,
}

/// Reads all marked JSON blocks of the document.
///
/// Deliberately a small line reader instead of a Markdown parser: the test should check exactly
/// what a human sees when reading — a marker, a fence below it, the body inside.
fn blocks() -> Vec<Block> {
    let rows: Vec<&str> = DOCUMENT.lines().collect();
    let mut found = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(rest) = row.trim().strip_prefix(MARKER_START) else { continue };
        let name = rest
            .strip_suffix(MARKER_END)
            .unwrap_or_else(|| panic!("line {}: marker without an end: {row}", i + 1))
            .trim()
            .to_owned();
        let start = rows.get(i + 1).copied().unwrap_or_default();
        assert!(
            start.starts_with(FENCE),
            "line {}: the marker „{name}“ is not followed by a code fence but by: {start}",
            i + 2
        );
        let mut body = String::new();
        let mut j = i + 2;
        loop {
            let z = rows.get(j).unwrap_or_else(|| {
                panic!("the block „{name}“ starting at line {} is never closed", i + 2)
            });
            if z.trim_end() == FENCE {
                break;
            }
            body.push_str(z);
            body.push('\n');
            j += 1;
        }
        found.push(Block { name, body, row: i + 1 });
    }
    found
}

#[test]
fn every_json_block_stands_byte_identical_in_its_golden_file() {
    let found = blocks();
    assert!(found.len() >= 30, "only {} marked blocks — the document is incomplete", found.len());
    for block in &found {
        let golden = find(&block.name).unwrap_or_else(|e| panic!("line {}: {e}", block.row));
        assert_eq!(
            block.body, golden.content,
            "line {}: the block „{}“ differs from crates/wire/testdata/{}",
            block.row, block.name, block.name
        );
    }
}

#[test]
fn every_proposed_body_stands_in_the_contract_document() {
    let found: Vec<String> = blocks().into_iter().map(|b| b.name).collect();
    let missing: Vec<&str> = ALL
        .iter()
        .filter(|g| matches!(g.provenance, Provenance::Proposal(_)))
        .map(|g| g.name)
        .filter(|n| !found.iter().any(|g| g == n))
        .collect();
    // A proposal that lies only in testdata/ has never been put to the counterpart.
    assert!(missing.is_empty(), "without a section in the contract: {}", missing.join(", "));
}

#[test]
fn no_block_stands_twice_with_different_content() {
    // Two transcripts of the same body in the same document are the same fault one floor down.
    let found = blocks();
    for (i, a) in found.iter().enumerate() {
        for b in &found[i + 1..] {
            assert_ne!(a.name, b.name, "„{}“ stands twice (lines {} and {})", a.name, a.row, b.row);
        }
    }
}

#[test]
fn the_error_catalogue_of_the_code_stands_completely_in_the_contract() {
    let missing: Vec<&str> = ErrorKind::all()
        .filter_map(ErrorKind::short_code)
        .filter(|short| !DOCUMENT.contains(*short))
        .collect();
    // An error type the client knows and the document does not is behaviour without a contract.
    assert!(missing.is_empty(), "not in §7.5: {}", missing.join(", "));
}

#[test]
fn the_contract_names_its_inventions_as_such() {
    // Every section that proposes something the counterpart does not have carries the marker from
    // 03: without it, in a year somebody takes an invention for a decision.
    let markers = DOCUMENT.matches("[GAP → PROPOSAL]").count();
    assert!(markers >= 10, "only {markers} gap markers — the inventions are not declared");
    for section in ["## §7.0", "## §7.1", "## §7.2", "## §7.3", "## §7.4", "## §7.5", "## §7.6"]
    {
        assert!(DOCUMENT.contains(section), "section {section} is missing");
    }
}

/// The sources in which the tests from §7.6 may stand. Included at compile time, so that a
/// renamed test makes this test fail instead of letting the document go stale in silence.
const SOURCES: &[&str] = &[
    include_str!("golden_bodies.rs"),
    include_str!("contract_document.rs"),
    include_str!("../src/login.rs"),
    include_str!("../src/ingest.rs"),
    include_str!("../src/discovery.rs"),
    include_str!("../src/device.rs"),
    include_str!("../src/golden.rs"),
    include_str!("../src/basics.rs"),
    include_str!("../src/content.rs"),
    include_str!("../src/namespace.rs"),
    include_str!("../src/delivery.rs"),
];

#[test]
fn every_test_the_table_in_7_6_names_really_exists() {
    // The “place” column of every row names either a neighbouring crate (`edms-net`,
    // `edms-crypto`, `edms_core::…`) or a test of this crate. A contract that points at a test
    // that does not exist claims a safeguard nobody has — and that is worse than naming none,
    // because nobody looks again.
    let mut checked = 0_usize;
    for row in DOCUMENT.lines() {
        let trimmed = row.trim();
        if !(trimmed.starts_with("| T") || trimmed.starts_with("| **T")) {
            continue;
        }
        let column: Vec<&str> = trimmed.trim_matches('|').split('|').collect();
        let Some(location) = column.last().map(|s| s.trim().trim_matches('`')) else { continue };
        // Neighbouring crates and module paths cannot be looked up here and are passed over.
        if location.contains('-') || location.contains("::") || location.is_empty() {
            continue;
        }
        let wanted = format!("fn {location}(");
        assert!(
            SOURCES.iter().any(|q| q.contains(&wanted)),
            "§7.6 names the test „{location}“, which does not exist in edms-wire"
        );
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} rows of the table point at a test of this crate");
}
