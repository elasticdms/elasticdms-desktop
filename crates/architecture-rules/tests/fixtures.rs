//! No carriage return gets into this repository, and no checkout may add one.
//!
//! WHY THIS TEST EXISTS: `crypto::jcs::the_reference_transcript_of_the_sibling_client_is_a_fixed_point`
//! was red on Windows and green everywhere else. The golden ends in a single newline; with
//! `core.autocrlf=true` — the default on GitHub's Windows runners — the checkout made `}\n` into
//! `}\r\n`, the test stripped the `\n`, and the remaining `\r` was compared against a
//! canonicalisation that had just removed it. Ten minutes of build for a diff in which both sides
//! looked identical.
//!
//! `.gitattributes` fixes the cause. These two tests keep it fixed: one reads the file, the other
//! reads every checked-out byte — because on a Windows runner the second one is what notices when
//! the first rule stops taking effect.

// The helpers below live outside `#[test]` functions, where clippy does not see
// `allow-expect-in-tests` from clippy.toml. Aborting is right here: a check that cannot read its
// own workspace has to fail loudly instead of quietly turning green.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// At least this many files the check must read, otherwise it is green out of blindness.
const MIN_FILES: usize = 100;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("workspace root")
}

/// Everything that is checked out, without the two directories that belong to no one: `.git` and
/// the build output.
fn checked_out_files(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if matches!(name.to_str(), Some(".git" | "target" | "node_modules" | "__pycache__")) {
            continue;
        }
        if path.is_dir() {
            checked_out_files(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

/// A file with a zero byte is binary — the images, and nothing else here. Their bytes are their
/// own business.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

#[test]
fn no_checked_out_file_carries_a_carriage_return() {
    let root = root();
    let mut files = Vec::new();
    checked_out_files(&root, &mut files);

    let mut read = 0;
    let mut guilty = Vec::new();
    for path in &files {
        let Ok(bytes) = fs::read(path) else { continue };
        if is_binary(&bytes) {
            continue;
        }
        read += 1;
        if bytes.contains(&b'\r') {
            let line = bytes.split(|b| *b == b'\n').position(|l| l.contains(&b'\r'));
            guilty.push(format!(
                "{} (line {})",
                path.strip_prefix(&root).unwrap_or(path).display(),
                line.map_or(0, |index| index + 1)
            ));
        }
    }

    assert!(read >= MIN_FILES, "only {read} files read, that proves nothing");
    assert!(
        guilty.is_empty(),
        "carriage returns in the working tree — on Windows that is the checkout, everywhere else \
         it is an editor. Both corrupt goldens that are compared byte for byte:\n  {}",
        guilty.join("\n  ")
    );
}

#[test]
fn the_line_endings_are_pinned_for_every_path() {
    let text = fs::read_to_string(root().join(".gitattributes"))
        .expect(".gitattributes — without it a Windows checkout decides the line endings itself");

    let pinned = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(char::is_whitespace))
        .any(|(pattern, attributes)| pattern == "*" && attributes.contains("eol=lf"));

    assert!(
        pinned,
        "`.gitattributes` has to pin `eol=lf` for the pattern `*`. Anything narrower leaves the \
         next fixture to `core.autocrlf`, which on Windows runners is on."
    );
}
