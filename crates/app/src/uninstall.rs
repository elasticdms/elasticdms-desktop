//! `elasticdms --uninstall` — clear this machine's traces, **without a user interface**.
//!
//! THE REASON this switch exists: the MSI calls it during uninstallation as a deferred action
//! (`packaging/windows/elasticdms.wxs`, action `UnregisterSyncRoots`) **before** `RemoveFiles` —
//! after that the `.exe` is gone. If a sync root stayed registered, it would jam every later
//! installation: Windows remembers the roots per volume, and `edms_cfapi::Mirror` aborts in front
//! of a root it finds (`packaging/windows/README.md`, step 3). Without this switch the clean-up
//! action in the installer would be a sham: `Return="ignore"` would swallow the exit code 2 for an
//! unknown option, and nobody would notice until the next installation.
//!
//! ## The context is SYSTEM in session 0
//!
//! `Impersonate="no"` means: no user profile, no user `HKCU`, no keychain, no desktop, no window
//! station — and under Intune, SCCM and GPO that also holds for `Impersonate="yes"`, because there
//! SYSTEM starts the `msiexec`. That is why this path touches **none** of it: no mandatory `EDMS_*`
//! variables, no `keyring`, no `tray-icon`, no window, no single-instance lock. It reads
//! environment variables, enumerates folders and deletes.
//!
//! The counterpart to that is the permission: per the documentation `CfUnregisterSyncRoot` requires
//! only `WRITE_DATA` or `WRITE_DAC` on the root folder — **no** user identity and **no**
//! elevation. SYSTEM has both in every profile. That is why this switch clears **all** profiles and
//! not just one (Nextcloud in the same situation clears only the currently signed-in user and says
//! in its own source that it is "only effective for the current user").
//!
//! ## What it explicitly does NOT clear
//!
//! * **The keychain** (device key, session). The Windows credential store is bound to the user
//!   profile; SYSTEM in session 0 does not reach it. It stays and is usable again after a
//!   reinstallation; whoever wants to be rid of it signs out in the program beforehand. It says so
//!   in `packaging/windows/README.md`.
//! * **Files the server has not confirmed yet.** Since namespace v2 §5 they lie in the holding
//!   directory inside the local state and no longer in an inbox folder of their own. An empty
//!   holding directory goes with the rest; a filled one stays, and the line says where
//!   ([`clear_state`]).
//! * **A folder of the same name that does not look like the mirror.** See [`shape`].

#![allow(clippy::print_stdout, reason = "--uninstall writes a result like doctor, not a log")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use edms_core::namespace::{name_archives, name_baskets, name_read_me, name_searches};

use crate::setup::{FOLDER_NAME, HOLDING_NAME};

/// The organisation part of the local data directory.
///
/// Has to stay in step with `setup::data_directory` (`ProjectDirs::from("de", "elasticdms",
/// "folderclient")` there): as SYSTEM, `directories` cannot be asked, because it would compute
/// **this** process's profile — the machine's, not the user's.
const ORGANISATION: &str = "elasticdms";

/// The application part of the local data directory; see [`ORGANISATION`].
const APPLICATION: &str = "folderclient";

/// The level `directories` puts between the application directory and our files.
///
/// `ProjectDirs::data_local_dir` on Windows is `…\<organisation>\<application>\data` — read in
/// `directories-6.0.0`, `src/win.rs`. It only matters here for the holding directory: everything
/// else under the application directory goes anyway.
const DATA: &str = "data";

/// What is to be done in one user profile.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Task {
    /// Unregister the root, delete the tree, remove the folder.
    Mirror(PathBuf),
    /// A folder with our name in which nothing of ours lies: do not touch.
    Foreign(PathBuf, String),
    /// The local state (SQLite, staging area, holding directory) under `AppData\Local`.
    State(PathBuf),
}

/// What a folder with our name looks like from the inside.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    /// Empty, or with at least one entry that only elasticdms creates.
    Mirror,
    /// Nothing of ours in it — probably a person's folder that happens to be called that.
    Foreign(String),
}

/// Runs `elasticdms --uninstall`.
///
/// Exit code `0` when nothing stayed behind; `1` when there is something to object to — so that a
/// `psexec -s msiexec /x … ; echo $LASTEXITCODE` can evaluate the answer without reading text. The
/// MSI itself does **not** evaluate it (`Return="ignore"`): a failed clean-up must not make the
/// product impossible to remove.
pub fn run() -> ExitCode {
    println!("elasticdms {} - uninstall (tidies up, starts nothing)", env!("CARGO_PKG_VERSION"));
    // The switch clears the Windows installation. On macOS the folder belongs to a file provider
    // domain that disappears together with the bundle (ADR-D05); there is nothing to do there, and
    // a clean-up "on the off chance" would be exactly the kind of function that silently does the
    // wrong thing. Deliberately no `#[cfg]` around the whole function: that way every platform
    // compiles and checks the path along with it, and the tests below run on the development
    // machine too.
    if !cfg!(windows) {
        println!(
            "\nThis switch clears the Windows installation (synchronisation root, mirror, local \
             state). On this operating system there is none of that; nothing was changed."
        );
        return ExitCode::SUCCESS;
    }

    let lookup = |name: &str| std::env::var(name).ok();
    let mut tasks = match profile_directory(&lookup) {
        Some(directory) => {
            println!("\nProfile directory: {}", directory.display());
            collect(&directory)
        }
        None => {
            println!(
                "\nNeither %PUBLIC% nor %SystemDrive% is set; without one of them the profile \
                 directory cannot be determined. Nothing was changed."
            );
            return ExitCode::FAILURE;
        }
    };
    // A mirror path set to something else is the only place the enumeration does not find. Under
    // Intune the variable is not set; whoever uninstalls by hand can set it.
    if let Some(path) = lookup("EDMS_MIRROR_PATH").map(|w| PathBuf::from(w.trim())) {
        let already_there =
            tasks.iter().any(|a| matches!(a, Task::Mirror(p) | Task::Foreign(p, _) if *p == path));
        if !already_there && let Some(task) = task_mirror(&path) {
            tasks.push(task);
        }
    }

    if tasks.is_empty() {
        println!("\nNothing found: no mirror, no local state.");
        return ExitCode::SUCCESS;
    }
    let mut objected = 0usize;
    println!();
    for task in &tasks {
        let (row, objection) = run_task(task);
        println!("  {row}");
        if objection {
            objected += 1;
        }
    }
    if objected == 0 {
        println!("\nTidied up.");
        return ExitCode::SUCCESS;
    }
    println!(
        "\n{objected} place(s) stayed behind; they are named above. A synchronisation root left \
         standing jams the next installation — please check it by hand."
    );
    ExitCode::FAILURE
}

/// The directory the user profiles live in (usually `C:\Users`).
///
/// **Not** `%USERPROFILE%`: as SYSTEM that points at
/// `C:\Windows\system32\config\systemprofile` and would walk past every profile. `%PUBLIC%` is a
/// machine variable (`C:\Users\Public`) and points into the real profile directory even when it
/// was moved during setup; what is wanted is its parent directory. `%SystemDrive%\Users` is the
/// fallback when that is missing too.
fn profile_directory(lookup: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let value = |name: &str| lookup(name).map(|w| w.trim().to_owned()).filter(|w| !w.is_empty());
    if let Some(parent) = value("PUBLIC").and_then(|p| parent_part(&p)) {
        return Some(PathBuf::from(parent));
    }
    value("SystemDrive").map(|drive| PathBuf::from(format!("{drive}\\Users")))
}

/// The parent directory of a **Windows** path, computed as text.
///
/// Not `Path::parent`: `std` computes by the rules of the running system, and on the development
/// machine `\` is not a separator — `C:\Users\Public` would be a single component there and its
/// parent empty. The rule therefore belongs here, where it can be tested on any machine; it is
/// only computed on Windows anyway.
fn parent_part(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let parent = &trimmed[..trimmed.rfind(['\\', '/'])?];
    if parent.is_empty() {
        return None;
    }
    // "C:" on its own would be, on Windows, the current directory of that drive and not its root —
    // a difference that would only show up during the enumeration.
    if parent.ends_with(':') {
        return Some(format!("{parent}\\"));
    }
    Some(parent.to_owned())
}

/// Every task from every profile, in a stable order.
///
/// Without a deny list for `Public`, `Default` and their like: what is to be done is decided by
/// [`shape`] from the folder's contents, not by the name of its parent directory. A profile that
/// cannot be read is passed over — the uninstallation of the others should not fail over it.
fn collect(profile_directory: &Path) -> Vec<Task> {
    let mut tasks = Vec::new();
    let Ok(entries) = fs::read_dir(profile_directory) else {
        return tasks;
    };
    let mut profile: Vec<PathBuf> =
        entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    profile.sort();
    for profile in profile {
        if let Some(task) = task_mirror(&profile.join(FOLDER_NAME)) {
            tasks.push(task);
        }
        let state = profile.join("AppData").join("Local").join(ORGANISATION).join(APPLICATION);
        if state.is_dir() {
            tasks.push(Task::State(state));
        }
    }
    tasks
}

/// The task for a folder that could be the mirror — or `None` when it does not exist or cannot be
/// read.
fn task_mirror(path: &Path) -> Option<Task> {
    if !path.is_dir() {
        return None;
    }
    let names: Vec<String> = fs::read_dir(path)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    match shape(&names) {
        Shape::Mirror => Some(Task::Mirror(path.to_path_buf())),
        Shape::Foreign(name) => Some(Task::Foreign(path.to_path_buf(), name)),
    }
}

/// Whether a folder with our name is the mirror — the brake in front of data loss.
///
/// The uninstallation runs as SYSTEM through **foreign** profiles and deletes trees there. The name
/// alone is too thin for that: `C:\Users\…\elasticdms` could just as well be a person's project
/// folder. Hence the rule:
///
/// * empty → mirror (nothing to lose, and the root has to be unregistered all the same; that is
///   exactly what a folder looks like in which nobody has ever signed in),
/// * at least one entry that only elasticdms creates (the basket folder, the archive folder, the
///   saved-searches folder, `LIESMICH.txt`, `edms_core::namespace`) → mirror, together with
///   everything else that lies in it (`FileSystem::clear_everything` clears in the same way on
///   sign-out),
/// * otherwise → foreign; the folder stays and is reported.
///
/// The price of the brake is stated: a real mirror in which **only** foreign files lie (hydrated
/// placeholders are not foreign — they are named like our entries) stays, root and all. That is
/// the reason why the uninstallation must not be the only place that resolves the jammed state:
/// the client has to be allowed to take over an orphaned root **of its own** (an open point in
/// `packaging/windows/README.md`).
fn shape(names: &[String]) -> Shape {
    if names.is_empty() || names.iter().any(|n| is_own_entry(n)) {
        return Shape::Mirror;
    }
    Shape::Foreign(names.iter().min().cloned().unwrap_or_default())
}

/// Whether this name in the root directory can only come from elasticdms.
fn is_own_entry(name: &str) -> bool {
    // In **every** language: `--uninstall` runs after a language change too, and a mirror named
    // in German must be recognised by a client whose interface is English.
    edms_i18n::Language::ALL.into_iter().any(|language| {
        name == name_baskets(language)
            || name == name_archives(language)
            || name == name_searches(language)
            || name == name_read_me(language)
    })
}

/// Carries out a task and returns the line for the report, together with "is this an objection".
fn run_task(task: &Task) -> (String, bool) {
    match task {
        Task::Mirror(path) => match unregister_root(path) {
            // The root folder itself stays on `clear_everything` (signing out leaves it in quick
            // access); on uninstallation it should go. `remove_dir` takes only the empty folder —
            // if something stays behind, the line says so.
            Ok(()) => match fs::remove_dir(path) {
                Ok(()) => (format!("Mirror unregistered and removed: {}", path.display()), false),
                Err(error) => (
                    format!(
                        "Mirror unregistered: {} — the folder itself stayed behind: {error}",
                        path.display()
                    ),
                    false,
                ),
            },
            Err(reason) => (
                format!("The synchronisation root {} stayed behind: {reason}", path.display()),
                true,
            ),
        },
        Task::Foreign(path, name) => (
            format!(
                "The folder {} stays untouched: “{name}” lies in it, but nothing of elasticdms's. \
                 If it does belong to elasticdms after all, it has to be removed by hand.",
                path.display()
            ),
            true,
        ),
        Task::State(path) => clear_state(path),
    }
}

/// Removes the local state — all of it, unless files are still lying in the holding directory.
///
/// **The set-up's settings go with it, and that is why they live in the `setting` table.** The
/// three addresses, the device name, the mirror's place, the language, the completed mark and the
/// three `counterpart.*` keys all lie in `state.sqlite` and nowhere else (ADR-D13 §6): a JSON file
/// beside the binary, an `HKCU` key or a plist would each need a line here **and** one in
/// `packaging/macos/elasticdms-uninstall.sh`, and a forgotten line there is a tenant address that
/// outlives the uninstallation. Nothing was added to this function for them, and nothing had to be.
///
/// A file that was dropped into a mail basket lies there until the server has confirmed the
/// ingest; until then the local copy is the only one (ADR-D08 point 5, GoBD completeness).
/// A `remove_dir_all` over the whole state would take those with it, and whoever uninstalls would
/// never learn that they had been there.
///
/// Only the default place is protected. A holding directory moved with `EDMS_HOLDING_DIR` lies
/// somewhere this enumeration never looks — and is therefore not touched here either.
fn clear_state(path: &Path) -> (String, bool) {
    let holding = path.join(DATA).join(HOLDING_NAME);
    if !holds_something(&holding) {
        return match fs::remove_dir_all(path) {
            Ok(()) => (format!("Local state removed: {}", path.display()), false),
            Err(error) => {
                (format!("Local state stayed behind: {} — {error}", path.display()), true)
            }
        };
    }
    let mut failed = Vec::new();
    remove_around(path, DATA, &mut failed);
    remove_around(&path.join(DATA), HOLDING_NAME, &mut failed);
    if failed.is_empty() {
        return (
            format!(
                "Local state removed except for {}: files still lie in it whose ingest the \
                 server has not confirmed.",
                holding.display()
            ),
            false,
        );
    }
    (format!("Local state stayed partly behind: {}", failed.join("; ")), true)
}

/// Whether something lies in this directory.
fn holds_something(path: &Path) -> bool {
    let Ok(mut entries) = fs::read_dir(path) else {
        // A directory that is not there holds nothing. One that is there and cannot be read may
        // hold everything — and the brake belongs on the side that keeps files, not on the side
        // that deletes them.
        return path.is_dir();
    };
    entries.next().is_some()
}

/// Removes every entry of `directory` except the one called `keep`; what fails is named.
fn remove_around(directory: &Path, keep: &str, failed: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() == keep {
            continue;
        }
        let path = entry.path();
        let result = if path.is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
        if let Err(error) = result {
            failed.push(format!("{}: {error}", path.display()));
        }
    }
}

/// Unregisters the root and deletes its tree — in exactly that order.
///
/// Through [`edms_cfapi::Mirror`], not through a call of our own: by architecture rule R4 cfAPI
/// belongs in exactly one crate, and `FileSystem::clear_everything` keeps the order (disconnect,
/// delete the tree, unregister). The source is never asked while doing so — without
/// `CfConnectSyncRoot` not a single callback arrives, and nothing is connected here.
#[cfg(windows)]
fn unregister_root(path: &Path) -> Result<(), String> {
    use std::sync::Arc;

    use edms_core::port::FileSystem;

    let text = path
        .to_str()
        .ok_or_else(|| format!("the path `{}` is not valid Unicode text", path.display()))?;
    let mirror = edms_cfapi::Mirror::new(text, Arc::new(EmptySource), Arc::new(EmptyIntake))
        .map_err(|f| f.to_string())?;
    mirror.clear_everything().map_err(|f| f.to_string())
}

/// Unreachable on every other platform: [`run`] turns back before it. It is compiled all the same,
/// so that the enumeration and the brake are tested on the development machine.
#[cfg(not(windows))]
fn unregister_root(_path: &Path) -> Result<(), String> {
    Err("A synchronisation root of the Cloud Filter API exists only on Windows.".to_owned())
}

/// A namespace source that knows nothing.
///
/// `edms_cfapi::Mirror::new` demands one; it is only asked by the callbacks of a **connected**
/// root. The uninstallation does not connect — it unregisters. Every answer here would therefore
/// be an answer to a question nobody asks; hence the honest error instead of a plausible return
/// value.
#[cfg(windows)]
struct EmptySource;

#[cfg(windows)]
impl edms_core::port::NamespaceSource for EmptySource {
    fn children(
        &self,
        _container: edms_core::namespace::Container,
    ) -> Result<Vec<edms_core::namespace::Entry>, edms_core::port::SourceError> {
        Err(edms_core::port::SourceError::NotSignedIn)
    }

    fn entry(
        &self,
        _identifier: edms_core::namespace::EntryIdentifier,
    ) -> Result<edms_core::namespace::Entry, edms_core::port::SourceError> {
        Err(edms_core::port::SourceError::NotSignedIn)
    }

    fn current_sequence(&self) -> Result<u64, edms_core::port::SourceError> {
        Err(edms_core::port::SourceError::NotSignedIn)
    }

    fn changes_since(
        &self,
        _sequence: u64,
        _max: usize,
    ) -> Result<edms_core::change::ChangeState, edms_core::port::SourceError> {
        Err(edms_core::port::SourceError::NotSignedIn)
    }

    fn content(
        &self,
        _identifier: edms_core::namespace::EntryIdentifier,
        _request: &edms_core::port::ContentRequest,
        _sink: &mut dyn edms_core::port::ContentSink,
    ) -> Result<edms_core::port::ContentReceipt, edms_core::port::SourceError> {
        Err(edms_core::port::SourceError::NotSignedIn)
    }
}

/// A mouth for dropped files that is never spoken to.
///
/// `edms_cfapi::Mirror::new` demands one, for the same reason as [`EmptySource`]: it is only asked
/// by the callbacks of a **connected** root. The uninstallation does not connect — `set_up` is
/// never called here, so the beat over the baskets never starts and nothing is ever announced.
#[cfg(windows)]
struct EmptyIntake;

#[cfg(windows)]
impl edms_cfapi::Intake for EmptyIntake {
    fn file_appeared(&self, _basket: edms_core::identifier::BasketIdentifier, _path: &str) {}
}

#[cfg(test)]
mod tests {
    use crate::setup::{DATABASE_NAME, STAGING_NAME};

    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn an_empty_folder_counts_as_the_mirror_because_the_root_has_to_be_unregistered_anyway() {
        assert_eq!(shape(&[]), Shape::Mirror);
    }

    #[test]
    fn one_entry_of_our_own_suffices_and_takes_everything_else_with_it() {
        for own in [
            name_baskets(edms_i18n::Language::De),
            name_archives(edms_i18n::Language::De),
            name_searches(edms_i18n::Language::De),
            name_read_me(edms_i18n::Language::De),
        ] {
            assert_eq!(shape(&names([own].as_slice())), Shape::Mirror, "{own}");
        }
        assert_eq!(
            shape(&names(&["Urlaub.jpg", name_archives(edms_i18n::Language::De)])),
            Shape::Mirror
        );
    }

    #[test]
    fn a_folder_named_like_the_container_that_namespace_v2_dropped_is_not_ours_any_more() {
        // „Akten“ was the cases container until namespace v2 §1; a folder of that name is now an
        // ordinary folder of the user’s, and the brake has to keep its hands off it.
        assert_eq!(shape(&names(&["Akten"])), Shape::Foreign("Akten".to_owned()));
    }

    #[test]
    fn a_foreign_folder_of_the_same_name_is_not_touched() {
        assert_eq!(
            shape(&names(&["Steuer 2025.xlsx", "Angebote"])),
            Shape::Foreign("Angebote".to_owned())
        );
    }

    #[test]
    fn the_profile_directory_comes_from_the_public_profile_not_from_our_own() {
        // Exactly the MSI's case: as SYSTEM, USERPROFILE points at the system profile.
        let lookup = |name: &str| match name {
            "PUBLIC" => Some("C:\\Users\\Public".to_owned()),
            "USERPROFILE" => Some("C:\\Windows\\system32\\config\\systemprofile".to_owned()),
            _ => None,
        };
        assert_eq!(profile_directory(&lookup), Some(PathBuf::from("C:\\Users")));
    }

    #[test]
    fn without_public_the_profile_directory_comes_from_the_system_drive() {
        let lookup = |name: &str| match name {
            "SystemDrive" => Some("D:".to_owned()),
            // Empty is like not set: an empty %PUBLIC% would otherwise yield an empty parent.
            "PUBLIC" => Some("   ".to_owned()),
            _ => None,
        };
        assert_eq!(profile_directory(&lookup), Some(PathBuf::from("D:\\Users")));
    }

    #[test]
    fn without_either_variable_there_is_no_profile_directory_and_no_guess() {
        assert_eq!(profile_directory(&|_| None), None);
    }

    #[test]
    fn the_parent_is_computed_by_windows_rules_on_this_machine_too() {
        assert_eq!(parent_part("C:\\Users\\Public").as_deref(), Some("C:\\Users"));
        assert_eq!(parent_part("D:\\Profile\\Public\\").as_deref(), Some("D:\\Profile"));
        // A drive without a separator is relative on Windows; it has to be the root.
        assert_eq!(parent_part("C:\\Public").as_deref(), Some("C:\\"));
        assert_eq!(parent_part("Public"), None);
    }

    #[test]
    fn the_enumeration_finds_mirror_and_state_in_every_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path();

        // User 1: has been signed in — mirror with content and local state.
        let one = profile.join("anna");
        fs::create_dir_all(one.join(FOLDER_NAME).join(name_archives(edms_i18n::Language::De)))
            .unwrap();
        fs::create_dir_all(one.join("AppData").join("Local").join(ORGANISATION).join(APPLICATION))
            .unwrap();
        // User 2: installed, never signed in — an empty mirror, nothing else.
        let two = profile.join("bernd");
        fs::create_dir_all(two.join(FOLDER_NAME)).unwrap();
        // User 3: a foreign folder that happens to be called that.
        let three = profile.join("clara");
        fs::create_dir_all(three.join(FOLDER_NAME)).unwrap();
        fs::write(three.join(FOLDER_NAME).join("notizen.md"), b"x").unwrap();

        assert_eq!(
            collect(profile),
            vec![
                Task::Mirror(one.join(FOLDER_NAME)),
                Task::State(one.join("AppData").join("Local").join(ORGANISATION).join(APPLICATION)),
                Task::Mirror(two.join(FOLDER_NAME)),
                Task::Foreign(three.join(FOLDER_NAME), "notizen.md".to_owned()),
            ]
        );
    }

    #[test]
    fn a_profile_directory_that_does_not_exist_yields_no_task_and_no_crash() {
        assert!(collect(Path::new("/there/is/no/such/directory")).is_empty());
    }

    #[test]
    fn the_local_state_is_removed_together_with_its_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join(APPLICATION);
        fs::create_dir_all(state.join(STAGING_NAME)).unwrap();
        fs::write(state.join(DATABASE_NAME), b"x").unwrap();

        let (row, objection) = run_task(&Task::State(state.clone()));
        assert!(!objection, "{row}");
        assert!(!state.exists(), "{row}");
    }

    #[test]
    fn a_file_the_server_has_not_confirmed_survives_the_uninstallation() {
        // ADR-D08 point 5: until the confirmation the local copy is the only one. An empty
        // holding directory, on the other hand, has nothing to keep and goes with the rest.
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join(APPLICATION);
        let holding = state.join(DATA).join(HOLDING_NAME);
        fs::create_dir_all(holding.join("upl_01JK")).unwrap();
        fs::write(holding.join("upl_01JK").join("rechnung.pdf"), b"x").unwrap();
        fs::create_dir_all(state.join(STAGING_NAME)).unwrap();
        fs::write(state.join(DATABASE_NAME), b"x").unwrap();

        let (row, objection) = run_task(&Task::State(state.clone()));
        assert!(!objection, "{row}");
        assert!(holding.join("upl_01JK").join("rechnung.pdf").exists(), "{row}");
        assert!(!state.join(DATABASE_NAME).exists(), "the database goes: {row}");
        assert!(!state.join(STAGING_NAME).exists(), "the staging area goes: {row}");
        assert!(row.contains(&holding.display().to_string()), "{row}");

        fs::remove_dir_all(holding.join("upl_01JK")).unwrap();
        let (row, objection) = run_task(&Task::State(state.clone()));
        assert!(!objection, "{row}");
        assert!(!state.exists(), "an empty holding directory keeps nothing: {row}");
    }

    /// Whether this byte sequence lies anywhere under `directory` — database, write-ahead log or
    /// shared-memory file, whichever of them SQLite happens to be holding it in.
    fn lies_anywhere(directory: &Path, needle: &str) -> bool {
        let Ok(entries) = fs::read_dir(directory) else { return false };
        entries.flatten().any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                return lies_anywhere(&path, needle);
            }
            fs::read(&path).is_ok_and(|bytes| {
                bytes.windows(needle.len()).any(|part| part == needle.as_bytes())
            })
        })
    }

    #[test]
    fn the_set_up_settings_go_with_the_local_state_and_needed_no_line_of_their_own() {
        // ADR-D13 §6 rests on exactly this: the tenant's addresses live in the `setting` table
        // because the uninstall already removes the file that holds it. The test writes them the
        // way the set-up does, proves they really lie on the disk, and then reads the disk again.
        // The harder of the two branches: files still lie in the holding directory, so the tree is
        // taken apart piece by piece instead of in one `remove_dir_all`.
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join(APPLICATION);
        // Where the database really lies on Windows: `directories` puts `data` between the
        // application directory and our files (see `DATA`).
        let data = state.join(DATA);
        let holding = data.join(HOLDING_NAME);
        fs::create_dir_all(&holding).unwrap();
        fs::write(holding.join("rechnung.pdf"), b"not confirmed yet").unwrap();
        {
            let mut store = edms_store::Store::open(&data.join(DATABASE_NAME)).unwrap();
            store.set_setting(edms_engine::config::SETTING_API_BASE, "https://api.acme").unwrap();
            store
                .set_setting(edms_engine::config::SETTING_COUNTERPART_API_BASE, "https://api.acme")
                .unwrap();
            store
                .set_setting(edms_engine::config::SETTING_COMPLETED, edms_engine::config::YES)
                .unwrap();
            store.set_setting(edms_engine::config::SETTING_DEVICE_NAME, "Front desk").unwrap();
        }
        assert!(
            lies_anywhere(&state, "https://api.acme"),
            "the test would be green out of blindness"
        );

        let (row, objection) = run_task(&Task::State(state.clone()));
        assert!(!objection, "{row}");
        assert!(!data.join(DATABASE_NAME).exists(), "the database goes: {row}");
        assert!(
            !lies_anywhere(&state, "https://api.acme"),
            "a tenant address outlived the uninstall: {row}"
        );
        assert!(
            !lies_anywhere(&state, "Front desk"),
            "the device name outlived the uninstall: {row}"
        );
        assert!(
            holding.join("rechnung.pdf").exists(),
            "and what the server has not confirmed stays"
        );
    }

    #[test]
    fn a_foreign_folder_is_an_objection_and_is_not_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let foreign = tmp.path().join(FOLDER_NAME);
        fs::create_dir_all(&foreign).unwrap();
        fs::write(foreign.join("notizen.md"), b"x").unwrap();

        let (row, objection) = run_task(&Task::Foreign(foreign.clone(), "notizen.md".to_owned()));
        assert!(objection, "{row}");
        assert!(foreign.join("notizen.md").exists(), "{row}");
    }
}
