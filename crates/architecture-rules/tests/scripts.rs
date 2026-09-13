//! Every task a caller names must exist in the script it calls.
//!
//! WHY THIS TEST EXISTS: the German-to-English rename translated the same word differently in two
//! files — `pruefen` became `verify` in macos-bundle.sh and `check` in its caller. The call still
//! looked perfectly reasonable, the script answered "unknown task", and it surfaced only on a CI
//! runner after a full release build. The sibling failure was `starte` becoming `start`, which on
//! Windows is an alias for Start-Process and silently ran cargo asynchronously.
//!
//! Both are the same class: a name that moved on one side of a call. A test is cheaper than a
//! runner minute, so the call sites are checked here rather than discovered in CI.

// `allow-expect-in-tests` in clippy.toml applies only to functions that carry `#[test]`
// themselves — not to the free helpers below. The permission is granted, it was merely invisible.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("workspace root")
}

/// The `task_<name>` functions a shell script defines.
fn tasks_of(script: &Path) -> BTreeSet<String> {
    let text = fs::read_to_string(script).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line.strip_prefix("task_")?;
            let name: String =
                rest.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
            rest[name.len()..].starts_with("()").then_some(name)
        })
        .collect()
}

/// Files that actually carry commands.
///
/// KNOWN LIMIT, named rather than hidden: documents and plists are NOT scanned. Their prose wraps,
/// and a sentence continuing with "scripts/macos-bundle.sh aus [workspace.package].version" begins
/// a line with the path without being a call. Position alone cannot tell the two apart, so this
/// test guards the call sites that break a build, not the ones that mislead a reader.
fn candidates(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![root.join("Makefile")];
    for dir in ["scripts", ".github/workflows"] {
        let Ok(entries) = fs::read_dir(root.join(dir)) else { continue };
        out.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_file()));
    }
    out
}

/// An invocation is the script at a command position: optional indentation, optional environment
/// assignments, then the path and the task word. Prose that merely mentions a script name — in a
/// comment or inside an error message — never matches, because something precedes the path.
fn invoked_task(line: &str, script_names: &[&str]) -> Option<(String, String)> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    let mut rest = line;
    // Skip leading VAR=value assignments.
    while let Some(word_end) = rest.find(' ') {
        let word = &rest[..word_end];
        let is_assignment = word.contains('=') && !word.contains('/') && !word.starts_with('"');
        if is_assignment {
            rest = rest[word_end + 1..].trim_start();
        } else {
            break;
        }
    }
    for name in script_names {
        let hit = rest.starts_with(&format!("scripts/{name}"))
            || rest.starts_with(&format!("./scripts/{name}"))
            || (name.ends_with("bundle.sh") && rest.starts_with("\"$BUNDLE_SCRIPT\""));
        if !hit {
            continue;
        }
        let after = rest.split_whitespace().nth(1)?;
        let task: String =
            after.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
        if task.is_empty() || task != after {
            return None;
        }
        return Some(((*name).to_owned(), task));
    }
    None
}

#[test]
fn every_called_task_exists_in_the_script_it_calls() {
    let root = root();
    let scripts: BTreeMap<&str, BTreeSet<String>> = ["macos-bundle.sh", "macos-package.sh"]
        .into_iter()
        .map(|n| (n, tasks_of(&root.join("scripts").join(n))))
        .collect();
    for (name, tasks) in &scripts {
        assert!(
            !tasks.is_empty(),
            "no task_* functions found in scripts/{name} — the scan reads into the void"
        );
    }
    let names: Vec<&str> = scripts.keys().copied().collect();

    let mut violations = Vec::new();
    let mut checked = 0usize;
    for file in candidates(&root) {
        let Ok(text) = fs::read_to_string(&file) else { continue };
        for (number, line) in text.lines().enumerate() {
            let Some((script, task)) = invoked_task(line, &names) else { continue };
            checked += 1;
            if !scripts[script.as_str()].contains(&task) {
                let known: Vec<&str> =
                    scripts[script.as_str()].iter().map(String::as_str).collect();
                violations.push(format!(
                    "{}:{}: calls `{script} {task}`, but that script only knows: {}",
                    file.strip_prefix(&root).unwrap_or(&file).display(),
                    number + 1,
                    known.join(", ")
                ));
            }
        }
    }
    assert!(checked >= 3, "only {checked} invocations found — the scan reads into the void");
    assert!(
        violations.is_empty(),
        "call sites name tasks that do not exist:\n{}",
        violations.join("\n")
    );
}

/// A job that calls `gh` must say which repository it means.
///
/// WHY THIS TEST EXISTS: the job that publishes the release checks nothing out — it only needs the
/// artefacts of the two build jobs. `gh release create` then asked git which repository it was in,
/// found no `.git`, and stopped with "fatal: not a git repository" — after both packages had been
/// built, signed and notarised. Seven seconds of failure at the end of eleven minutes of work.
///
/// Either the job checks the repository out or it sets `GH_REPO`. Both are cheap; neither is the
/// default.
#[test]
fn every_job_that_calls_gh_names_its_repository() {
    let root = root();
    let mut jobs_seen = 0;
    let mut guilty = Vec::new();

    for file in ["ci.yml", "release.yml"] {
        let path = root.join(".github/workflows").join(file);
        let text = fs::read_to_string(&path).expect("a workflow");
        for (name, block) in jobs_of(&text) {
            jobs_seen += 1;
            if !calls_gh(&block) {
                continue;
            }
            let named = block.contains("GH_REPO:")
                || block.contains("actions/checkout")
                || block.contains("--repo ");
            if !named {
                guilty.push(format!("{file}:{name}"));
            }
        }
    }

    assert!(jobs_seen >= 4, "only {jobs_seen} jobs found — the scan reads into the void");
    assert!(
        guilty.is_empty(),
        "these jobs call `gh` without checking the repository out and without GH_REPO; `gh` then \
         asks git, and a job without a checkout has no git: {guilty:?}"
    );
}

/// The jobs of a workflow, as (name, text). A job begins at four spaces of indentation under
/// `jobs:` and ends where the next one begins — enough structure for this check, and no YAML
/// parser in a crate that deliberately has no dependencies.
fn jobs_of(text: &str) -> Vec<(String, String)> {
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut inside_jobs = false;
    for line in text.lines() {
        if line.starts_with("jobs:") {
            inside_jobs = true;
            continue;
        }
        if !inside_jobs {
            continue;
        }
        let is_job_head = line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim_start().starts_with('#');
        if is_job_head {
            let name = line.trim().trim_end_matches(':').to_owned();
            jobs.push((name, String::new()));
        } else if let Some(last) = jobs.last_mut() {
            last.1.push_str(line);
            last.1.push('\n');
        }
    }
    jobs
}

/// Whether a job runs the `gh` command — not whether the three letters appear somewhere.
fn calls_gh(block: &str) -> bool {
    block.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('#') {
            return false;
        }
        line.starts_with("gh ") || line.contains("| gh ") || line.contains("&& gh ")
    })
}

/// Whoever opens an MSI over COM has to let go of it again.
///
/// WHY THIS TEST EXISTS: `windows-package.ps1` built the MSI, the workflow read its file table
/// over `WindowsInstaller.Installer` — and the rename in the very next line failed with "The
/// process cannot access the file because it is being used by another process". The other process
/// was itself: PowerShell frees a COM object only when the garbage collector gets round to it, and
/// an open MSI database holds a handle on the file. Eleven minutes of build, then a rename.
#[test]
fn whoever_opens_an_msi_over_com_releases_it() {
    let root = root();
    let mut opened = Vec::new();
    let mut guilty = Vec::new();

    for path in candidates(&root) {
        let text = fs::read_to_string(&path).unwrap_or_default();
        if !text.contains("New-Object -ComObject WindowsInstaller.Installer") {
            continue;
        }
        opened.push(path.clone());
        let releases = text.contains("FinalReleaseComObject") && text.contains("[GC]::Collect()");
        if !releases {
            guilty.push(path.strip_prefix(&root).unwrap_or(&path).display().to_string());
        }
    }

    assert!(
        opened.len() >= 2,
        "only {} file(s) open an MSI over COM — the scan reads into the void; ci.yml, release.yml \
         and windows-package.ps1 all do it",
        opened.len()
    );
    assert!(
        guilty.is_empty(),
        "these open an MSI over COM without releasing the handle (FinalReleaseComObject plus \
         [GC]::Collect()); the next file operation on the MSI fails against their own handle: {guilty:?}"
    );
}

/// The WiX sources reference things that must exist somewhere else.
///
/// WHY: `wix build` found `Action="WurzelnAbmelden"` pointing at a custom action that had been
/// renamed to `UnregisterSyncRoots` — the third half-finished rename of the day, and the only one
/// that needs a Windows runner and a ten-minute release build to surface. Both halves live in this
/// repository, so both halves can be compared here.
#[test]
fn wix_references_resolve_and_every_variable_is_passed() {
    let root = root();
    let wxs_path = root.join("packaging/windows/elasticdms.wxs");
    let wxs = fs::read_to_string(&wxs_path).expect("elasticdms.wxs");
    let ps1 =
        fs::read_to_string(root.join("scripts/windows-package.ps1")).expect("windows-package.ps1");

    let value_after = |text: &str, key: &str| -> BTreeSet<String> {
        let mut found = BTreeSet::new();
        let mut rest = text;
        while let Some(at) = rest.find(key) {
            rest = &rest[at + key.len()..];
            let value: String = rest.chars().take_while(|c| *c != '"').collect();
            if !value.is_empty() {
                found.insert(value);
            }
        }
        found
    };

    // 1. Every <Custom Action="X"> needs a <CustomAction Id="X">.
    let defined = value_after(&wxs, "<CustomAction\n        Id=\"");
    let mut defined = defined;
    defined.extend(value_after(&wxs, "<CustomAction Id=\""));
    let referenced = value_after(&wxs, "<Custom\n          Action=\"");
    let mut referenced = referenced;
    referenced.extend(value_after(&wxs, "<Custom Action=\""));
    assert!(!referenced.is_empty(), "no custom action referenced — the scan reads into the void");
    let dangling: Vec<&String> = referenced.difference(&defined).collect();
    assert!(
        dangling.is_empty(),
        "elasticdms.wxs references custom actions that are not defined: {dangling:?}; defined are {defined:?}"
    );

    // 2. Every preprocessor variable the .wxs consults must be handed over with -d X=… by the
    //    build script — and the error texts have to name the same flag as the call.
    //
    //    WHY ALL FOUR PLACES: the rename to English translated `$(var.Fassung)` to
    //    `$(var.Version)` and left `<?ifndef Fassung?>` standing. The reference resolved, the
    //    guard did not, and its own error message advised `-d Fassung=` — the wrong flag in the
    //    sentence that was supposed to help. `wix` says WIX0250 to that, after the whole release
    //    build, on a runner.
    let mut used = BTreeSet::new();
    for (opening, closing) in [("$(var.", ')'), ("<?ifndef ", '?'), ("<?ifdef ", '?'), ("-d ", '=')]
    {
        let mut rest = wxs.as_str();
        while let Some(at) = rest.find(opening) {
            rest = &rest[at + opening.len()..];
            let name: String = rest.chars().take_while(|c| *c != closing).collect();
            // `-d ` also occurs in prose; only a bare identifier counts as a variable name.
            if !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && name.chars().next().is_some_and(char::is_alphabetic)
            {
                used.insert(name);
            }
        }
    }
    assert!(
        used.len() >= 2,
        "only {} preprocessor variables found — the scan reads into the void, elasticdms.wxs has at least Version and BinDir",
        used.len()
    );
    let missing: Vec<&String> =
        used.iter().filter(|name| !ps1.contains(&format!("\"{name}="))).collect();
    assert!(
        missing.is_empty(),
        "elasticdms.wxs consults preprocessor variables that windows-package.ps1 never passes \
         with -d: {missing:?}. Both files have to spell them the same way — {} and the wix call \
         in scripts/windows-package.ps1.",
        wxs_path.display()
    );
}
