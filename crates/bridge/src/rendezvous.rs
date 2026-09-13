//! The rendezvous file: where the app listens and what the extension identifies itself with.
//!
//! The app writes it as soon as the line is listening; the extension reads it before every request.
//! It lies under `~/Library/Application Support/de.elasticdms.folderclient/bridge.json`, reachable
//! for the extension over a `temporary-exception` for exactly this path (ADR-D05) — an App Group
//! does not exist without a team ID.
//!
//! Three rules, each with its reason:
//!
//! 1. **Mode 0600, checked when reading.** Whoever can read the secret reads, over the line, every
//!    document of the user, and the server logs it as an access by this user. A file that group or
//!    world can read or write therefore counts as used up and is rejected instead of being quietly
//!    used — the way `ssh` rejects an open key. On Windows there are no Unix permissions; there,
//!    however, the line is not used either.
//! 2. **Replaced atomically.** The app writes into a neighbouring file and renames it. The
//!    extension never reads a half-written file that it would take for broken.
//! 3. **Only an ordinary file, at most 4 KiB.** A FIFO in its place would make the open hang
//!    forever in the extension; a giant file is no rendezvous.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::error::BridgeError;

/// Length of the secret in bytes (before the encoding).
pub const SECRET_BYTES: usize = 32;

/// File name of the rendezvous file.
pub const RENDEZVOUS_FILE: &str = "bridge.json";

/// The app's directory under `~/Library/Application Support/`.
pub const APPLICATION_DIRECTORY: &str = "de.elasticdms.folderclient";

/// Anything larger is no rendezvous file (it has around 120 bytes).
const MAX_FILE_BYTES: u64 = 4096;

/// Where the app listens and what one identifies oneself with.
///
/// `Debug` does not show the secret: a log line `{:?}` is not to spread it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rendezvous {
    /// The port on 127.0.0.1.
    pub port: u16,
    /// 32 random bytes as base64url without padding (43 characters); see [`secret_from_bytes`].
    pub secret: String,
    /// Process id of the app — for the diagnosis and for [`Rendezvous::remove_own`].
    pub pid: u32,
    /// The app's [`crate::VERSION`].
    pub version: u32,
}

impl fmt::Debug for Rendezvous {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rendezvous")
            .field("port", &self.port)
            .field("secret", &"<hidden>")
            .field("pid", &self.pid)
            .field("version", &self.version)
            .finish()
    }
}

/// Encodes 32 random bytes as a secret (base64url without padding, 43 characters).
///
/// The bytes come from outside (in the app from `edms-crypto`): this crate has no randomness, and a
/// second random generator in the house would be one nobody checks.
pub fn secret_from_bytes(bytes: &[u8; SECRET_BYTES]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Checks the form of the secret: canonical base64url without padding, exactly 32 bytes.
///
/// The message never names the secret.
pub(crate) fn check_secret(text: &str) -> Result<(), String> {
    match URL_SAFE_NO_PAD.decode(text) {
        Ok(bytes) if bytes.len() == SECRET_BYTES => Ok(()),
        Ok(bytes) => Err(format!(
            "it carries {} instead of {SECRET_BYTES} bytes; 32 random bytes are demanded",
            bytes.len()
        )),
        Err(error) => Err(format!("it is not canonical base64url without padding ({error})")),
    }
}

/// Compares in a time that depends only on the length, not on the position of the first
/// difference. The length is no secret (always 43 characters).
pub(crate) fn equal_in_constant_time(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let difference = a.iter().zip(b).fold(0u8, |sum, (x, y)| sum | (x ^ y));
    std::hint::black_box(difference) == 0
}

impl Rendezvous {
    /// The path of the rendezvous file in the user's **real** home directory.
    ///
    /// In the sandboxed extension `$HOME` points into its container
    /// (`~/Library/Containers/<bundle id>/Data`); whoever searches there never finds the app's
    /// file. Both sides therefore call this one function, and it asks the user database
    /// (`getpwuid_r`, see `home.rs`) instead of the environment — that way app and extension
    /// compute the same path, and the `temporary-exception` (relative to the real home) fits it.
    pub fn default_path() -> Result<PathBuf, BridgeError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self::path_under(&crate::home::real_home_directory()?))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(BridgeError::NotSupported(
                "the bridge joins extension and app only on macOS; on Windows the provider runs \
                 inside the app's own process (ADR-D02, ADR-D05)",
            ))
        }
    }

    /// The path of the rendezvous file under a given home directory.
    pub fn path_under(home: &Path) -> PathBuf {
        home.join("Library")
            .join("Application Support")
            .join(APPLICATION_DIRECTORY)
            .join(RENDEZVOUS_FILE)
    }

    /// Writes the file atomically with mode 0600; creates the directory with mode 0700.
    pub fn write(&self, path: &Path) -> Result<(), BridgeError> {
        self.check()
            .map_err(|reason| BridgeError::RendezvousInvalid { path: path.to_owned(), reason })?;
        let error =
            |reason: String| BridgeError::RendezvousNotWritten { path: path.to_owned(), reason };
        let (Some(directory), Some(name)) =
            (path.parent().filter(|parent| !parent.as_os_str().is_empty()), path.file_name())
        else {
            return Err(error("the path names neither a directory nor a file name".to_owned()));
        };
        create_directory(directory)
            .map_err(|why| error(format!("directory {}: {why}", directory.display())))?;
        let mut json = serde_json::to_vec_pretty(self)
            .map_err(|why| error(format!("it cannot be written as JSON: {why}")))?;
        json.push(b'\n');

        let mut staging_name = name.to_os_string();
        staging_name.push(format!(".{}.new", std::process::id()));
        let between = directory.join(staging_name);
        // Leftover of an aborted run of the same process; if there is none, there is nothing to do.
        let _ = fs::remove_file(&between);
        let written = (|| -> io::Result<()> {
            let mut file = open_private(&between)?;
            file.write_all(&json)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&between, path)
        })();
        if let Err(why) = written {
            let _ = fs::remove_file(&between);
            return Err(error(why.to_string()));
        }
        Ok(())
    }

    /// Reads and checks the file.
    ///
    /// If it is missing, [`BridgeError::NoRendezvousFile`] comes — "the app is not running".
    pub fn read(path: &Path) -> Result<Self, BridgeError> {
        let unreadable = |why: io::Error| BridgeError::RendezvousUnreadable {
            path: path.to_owned(),
            reason: why.to_string(),
        };
        let invalid =
            |reason: String| BridgeError::RendezvousInvalid { path: path.to_owned(), reason };
        // Check the kind first, then open: opening a FIFO blocks until somebody writes.
        match fs::metadata(path) {
            Ok(details) if details.is_file() => {}
            Ok(_) => return Err(invalid("it is not an ordinary file".to_owned())),
            Err(why) if why.kind() == io::ErrorKind::NotFound => {
                return Err(BridgeError::NoRendezvousFile { path: path.to_owned() });
            }
            Err(why) => return Err(unreadable(why)),
        }
        let file = match File::open(path) {
            Ok(file) => file,
            Err(why) if why.kind() == io::ErrorKind::NotFound => {
                return Err(BridgeError::NoRendezvousFile { path: path.to_owned() });
            }
            Err(why) => return Err(unreadable(why)),
        };
        check_permission(path, &file.metadata().map_err(unreadable)?)?;
        let mut content = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut content).map_err(unreadable)?;
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(invalid(format!("it is larger than {MAX_FILE_BYTES} bytes")));
        }
        let rendezvous: Self = serde_json::from_slice(&content)
            .map_err(|why| invalid(format!("it is not rendezvous JSON ({why})")))?;
        rendezvous.check().map_err(invalid)?;
        Ok(rendezvous)
    }

    /// Removes the file, but only if this process wrote it.
    ///
    /// For the app shutting down: a file left lying points at a port that a foreign program can
    /// occupy later. The check of the process id prevents a second app, ended straight away, from
    /// removing the file of the first one, which is still running. `Ok(true)` means removed,
    /// `Ok(false)` means: not there or not ours.
    pub fn remove_own(path: &Path) -> Result<bool, BridgeError> {
        let rendezvous = match Self::read(path) {
            Ok(rendezvous) => rendezvous,
            Err(BridgeError::NoRendezvousFile { .. }) => return Ok(false),
            Err(why) => return Err(why),
        };
        if rendezvous.pid != std::process::id() {
            return Ok(false);
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(why) if why.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(why) => Err(BridgeError::RendezvousNotWritten {
                path: path.to_owned(),
                reason: format!("it cannot be removed: {why}"),
            }),
        }
    }

    /// Checks port and secret.
    pub(crate) fn check(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("port 0 is no port the app can listen on".to_owned());
        }
        check_secret(&self.secret).map_err(|reason| format!("secret: {reason}"))
    }
}

#[cfg(unix)]
fn create_directory(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(directory)
}

#[cfg(not(unix))]
fn create_directory(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)
}

#[cfg(unix)]
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    // The process's umask can only take bits away; exactly 0600 is settled only after this call.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn check_permission(path: &Path, details: &fs::Metadata) -> Result<(), BridgeError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = details.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(BridgeError::PermissionsTooOpen { path: path.to_owned(), mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permission(_path: &Path, _details: &fs::Metadata) -> Result<(), BridgeError> {
    // ADR-D05 (mode 0600) — Windows knows no Unix permissions. The file lies there in
    // the user profile, whose access list admits only the user, SYSTEM and administrators; and the
    // line is not used on Windows (the provider runs in the app's process).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Rendezvous {
        Rendezvous {
            port: 49_152,
            secret: secret_from_bytes(&[7; SECRET_BYTES]),
            pid: std::process::id(),
            version: crate::VERSION,
        }
    }

    #[test]
    fn the_rendezvous_file_survives_the_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("deep").join("inside").join(RENDEZVOUS_FILE);
        example().write(&path).unwrap();
        assert_eq!(Rendezvous::read(&path).unwrap(), example());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_has_mode_0600_and_its_directory_0700() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("new").join(RENDEZVOUS_FILE);
        example().write(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let directory = path.parent().unwrap();
        assert_eq!(fs::metadata(directory).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_readable_by_others_is_rejected_instead_of_used() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(RENDEZVOUS_FILE);
        example().write(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = Rendezvous::read(&path).unwrap_err();
        assert!(matches!(error, BridgeError::PermissionsTooOpen { mode: 0o644, .. }), "{error}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(Rendezvous::read(&path), Err(BridgeError::PermissionsTooOpen { .. })));
    }

    #[test]
    fn writing_replaces_the_old_file_and_leaves_no_staging_file_behind() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(RENDEZVOUS_FILE);
        example().write(&path).unwrap();
        let new = Rendezvous { port: 50_000, ..example() };
        new.write(&path).unwrap();
        assert_eq!(Rendezvous::read(&path).unwrap().port, 50_000);
        let names: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [RENDEZVOUS_FILE]);
    }

    #[test]
    fn a_missing_file_means_the_app_is_not_running() {
        let directory = tempfile::tempdir().unwrap();
        let error = Rendezvous::read(&directory.path().join(RENDEZVOUS_FILE)).unwrap_err();
        assert!(matches!(error, BridgeError::NoRendezvousFile { .. }));
    }

    #[test]
    fn broken_files_are_rejected_with_a_reason() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join(RENDEZVOUS_FILE);
        let mut broken = example();
        broken.secret = "too-short".into();
        // write refuses what read would reject.
        assert!(matches!(broken.write(&path), Err(BridgeError::RendezvousInvalid { .. })));
        let zero = Rendezvous { port: 0, ..example() };
        assert!(matches!(zero.write(&path), Err(BridgeError::RendezvousInvalid { .. })));

        for content in
            ["no json".to_owned(), serde_json::to_string(&broken).unwrap(), " ".repeat(5000)]
        {
            example().write(&path).unwrap(); // the right permissions
            fs::write(&path, &content).unwrap();
            let error = Rendezvous::read(&path).unwrap_err();
            assert!(matches!(error, BridgeError::RendezvousInvalid { .. }), "{error}");
            assert!(!error.to_string().contains(&secret_from_bytes(&[7; 32])));
        }
        let folder = base.path().join("folder");
        fs::create_dir(&folder).unwrap();
        assert!(matches!(Rendezvous::read(&folder), Err(BridgeError::RendezvousInvalid { .. })));
    }

    #[test]
    fn the_secret_does_not_stand_in_the_debug_output() {
        let rendezvous = example();
        let text = format!("{rendezvous:?}");
        assert!(!text.contains(&rendezvous.secret), "{text}");
        assert!(text.contains("49152"), "{text}");
    }

    #[test]
    fn the_secret_is_canonical_base64url_of_32_bytes() {
        let secret = secret_from_bytes(&[0xFB; SECRET_BYTES]);
        assert_eq!(secret.len(), 43);
        assert!(
            secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{secret}"
        );
        assert!(check_secret(&secret).is_ok());
        assert!(check_secret(&format!("{secret}=")).is_err(), "padding");
        assert!(check_secret(&secret.replace('-', "+")).is_err(), "standard alphabet");
        assert!(check_secret(&secret_from_arbitrary_bytes(&[1; 31])).is_err(), "31 bytes");
        assert!(check_secret(&secret_from_arbitrary_bytes(&[1; 33])).is_err(), "33 bytes");
        // Last character with filler bits set: the same bytes, but not canonical.
        let mut not_canonical = secret_from_bytes(&[0; SECRET_BYTES]);
        not_canonical.pop();
        not_canonical.push('B');
        assert!(check_secret(&not_canonical).is_err(), "filler bits");
    }

    fn secret_from_arbitrary_bytes(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn the_constant_time_comparison_compares_correctly() {
        assert!(equal_in_constant_time(b"abc", b"abc"));
        assert!(!equal_in_constant_time(b"abc", b"abd"));
        assert!(!equal_in_constant_time(b"abc", b"abcd"));
        assert!(equal_in_constant_time(b"", b""));
    }

    #[test]
    fn only_our_own_file_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(RENDEZVOUS_FILE);
        assert!(!Rendezvous::remove_own(&path).unwrap(), "missing: nothing to do");
        let foreign = Rendezvous { pid: std::process::id().wrapping_add(1), ..example() };
        foreign.write(&path).unwrap();
        assert!(!Rendezvous::remove_own(&path).unwrap());
        assert!(path.exists(), "the file of another app stays put");
        example().write(&path).unwrap();
        assert!(Rendezvous::remove_own(&path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn the_path_under_a_home_follows_adr_d05() {
        let path = Rendezvous::path_under(Path::new("/Users/n"));
        assert_eq!(
            path,
            Path::new(
                "/Users/n/Library/Application Support/de.elasticdms.folderclient/bridge.json"
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_default_path_lies_in_the_real_home_directory() {
        let path = Rendezvous::default_path().unwrap();
        assert!(path.is_absolute(), "{}", path.display());
        assert!(
            path.ends_with("Library/Application Support/de.elasticdms.folderclient/bridge.json")
        );
        let home = path.ancestors().nth(4).unwrap();
        assert!(home.is_dir(), "{}", home.display());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn outside_macos_there_is_no_default_path() {
        assert!(matches!(Rendezvous::default_path(), Err(BridgeError::NotSupported(_))));
    }
}
