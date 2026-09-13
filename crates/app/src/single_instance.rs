//! One instance per user: a second start creates no second icon but asks the running instance to
//! show its window.
//!
//! Two icons would be two engines on the same mirror — two delivery channels, two writers to the
//! same database, two answers to the same cfAPI request. That is why an operating system lock
//! decides, not a "is there already a process with that name?".
//!
//! Like this, and with the standard library alone:
//!
//! 1. **Lock:** `<name>.lock` in the user's directory, held with [`File::try_lock`] for as long
//!    as the process lives. The operating system releases it when the process ends, even after a
//!    crash — a file left behind never locks out the next start.
//! 2. **Address:** the first instance listens on `127.0.0.1:<free port>` and writes the port and a
//!    random marker into `<name>.address`. Separate from the lock file, because Windows locks a
//!    locked file for reading too.
//! 3. **Request:** a second instance sends one line `ELASTICDMS WINDOW <marker>`, the first
//!    answers `OK` and opens its window. The marker keeps other users of the same machine out
//!    (they cannot read the address file in a foreign user directory); it is not a secret in the
//!    cryptographic sense, and it cannot do more than open a window.
//!
//! The file names and the request line are the compatibility surface between two versions of this
//! program running at the same time: a version that used different names would not see the lock of
//! an old instance still running and would start a second engine on the same mirror. That is why
//! they stood German (`sperre`, `adresse`, `ELASTICDMS FENSTER`) after the conversion of
//! 2026-09-12. MEASURED on this machine on 2026-09-13: no bundle in `/Applications`, no launch
//! agent, no `pkgutil` receipt — and nothing published anywhere else either, per the owner the same
//! day. There is no old instance for a new one to meet, so the names are English like the rest
//! (ADR-D10, correction of 2026-09-13). From the first package that leaves this repository the
//! question is a compatibility question again.
//!
//! ADR-D04 decision 1 ("no listening port on the workstation"; rule R2 in
//! `architecture-rules`) — this back channel does listen, but only on the loopback address, it
//! accepts exactly one line with a marker, and it can do nothing except "show the window". ADR-D04
//! means the delivery channel (outgoing only, and it stays that way); on macOS the app already
//! listens on 127.0.0.1 for `edms-bridge` anyway (ADR-D05). Without a back channel, the standard
//! library would leave a second start on Windows with no effect at all — a click that silently
//! does nothing.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::hash::{BuildHasher, Hasher, RandomState};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Name of the lock in real operation.
pub const NAME: &str = "single-instance";

/// Name of the lock in demo operation — separate from real operation, so that a demo never asks a
/// running real icon for its window (and the other way round).
pub const NAME_DEMO: &str = "single-instance-demo";

const REQUEST: &str = "ELASTICDMS WINDOW";
const RESPONSE: &str = "OK";
/// Anything longer is not a valid request; no more than this is read.
const ROW_MAX: u64 = 128;
/// The second instance asks this often, because the first writes the address only after the lock.
const ATTEMPT: u32 = 20;
const PAUSE: Duration = Duration::from_millis(100);

/// The result of the attempt to be the first instance.
#[derive(Debug)]
pub enum Claim {
    /// This instance is the first; the guard has to live for as long as it runs.
    First(Guard),
    /// Another instance holds the lock.
    RunsAlready,
}

/// Holds the lock and the back channel of the first instance.
#[derive(Debug)]
pub struct Guard {
    /// Only held, never read: for as long as the file is open, the lock holds.
    _lock: File,
    listener: TcpListener,
    marker: String,
}

/// The single instance could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    /// No user directory.
    #[error(
        "the user directory could not be determined; without it elasticdms cannot check whether \
         it is already running"
    )]
    NoDirectory,
    /// The lock file cannot be created or cannot be locked.
    #[error("the lock file `{}` could not be created or locked: {reason}", path.display())]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The operating system's message.
        reason: io::Error,
    },
    /// The loopback back channel could not be opened.
    #[error("the back channel for a second start could not be opened: {0}")]
    BackChannel(io::Error),
    /// The address file could not be written.
    #[error("the address file `{}` could not be written: {reason}", path.display())]
    Address {
        /// The address file.
        path: PathBuf,
        /// The operating system's message.
        reason: io::Error,
    },
    /// The running instance holds the lock but does not answer the request.
    #[error(
        "elasticdms is already running but does not answer. End the running instance through its \
         icon — or in the Task Manager on Windows, in Activity Monitor on macOS — and start again"
    )]
    Unresponsive,
}

/// The directory for lock and address: the folder client's local data directory (macOS
/// `~/Library/Application Support/de.elasticdms.folderclient`, as in ADR-D05).
pub fn instance_directory() -> Result<PathBuf, InstanceError> {
    directories::ProjectDirs::from("de", "elasticdms", "folderclient")
        .map(|p| p.data_local_dir().to_path_buf())
        .ok_or(InstanceError::NoDirectory)
}

/// Tries to be the first instance.
pub fn claim(directory: &Path, name: &str) -> Result<Claim, InstanceError> {
    let lock_path = directory.join(format!("{name}.lock"));
    let lock_error = |reason| InstanceError::Lock { path: lock_path.clone(), reason };
    fs::create_dir_all(directory).map_err(lock_error)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(lock_error)?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(Claim::RunsAlready),
        Err(TryLockError::Error(reason)) => return Err(lock_error(reason)),
    }
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(InstanceError::BackChannel)?;
    let port = listener.local_addr().map_err(InstanceError::BackChannel)?.port();
    let marker = new_marker();
    write_address(&directory.join(format!("{name}.address")), port, &marker)?;
    Ok(Claim::First(Guard { _lock: lock, listener, marker }))
}

impl Guard {
    /// Accepts requests from second instances, on a thread of its own. `callback` opens the
    /// window (through the event loop); if it returns `false`, the loop has ended and the thread
    /// stops.
    pub fn listen(&self, callback: Box<dyn Fn() -> bool + Send>) -> Result<(), InstanceError> {
        let listener = self.listener.try_clone().map_err(InstanceError::BackChannel)?;
        let expected = format!("{REQUEST} {}", self.marker);
        thread::Builder::new()
            .name("single-instance".into())
            .spawn(move || {
                for connection in listener.incoming() {
                    let Ok(mut stream) = connection else { continue };
                    if !serve(&mut stream, &expected, &*callback) {
                        break;
                    }
                }
            })
            .map_err(InstanceError::BackChannel)?;
        Ok(())
    }
}

/// Answers a connection; `false` means: stop listening.
fn serve(stream: &mut TcpStream, expected: &str, callback: &dyn Fn() -> bool) -> bool {
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(1))) {
        tracing::debug!(%e, "single instance: no timeout set for the back channel.");
        return true;
    }
    let mut row = String::new();
    let read = BufReader::new((&mut *stream).take(ROW_MAX)).read_line(&mut row);
    if read.is_err() || row.trim_end() != expected {
        tracing::warn!("single instance: a foreign request on the back channel was refused.");
        return true;
    }
    let carry_on = callback();
    if let Err(e) = stream.write_all(format!("{RESPONSE}\n").as_bytes()) {
        tracing::debug!(%e, "single instance: the answer to the second instance was not delivered.");
    }
    carry_on
}

/// Asks the running instance to show its window.
pub fn ask_for_window(directory: &Path, name: &str) -> Result<(), InstanceError> {
    ask_for_window_with(directory, name, ATTEMPT)
}

fn ask_for_window_with(directory: &Path, name: &str, attempt: u32) -> Result<(), InstanceError> {
    let path = directory.join(format!("{name}.address"));
    for attempt in 0..attempt {
        if attempt > 0 {
            thread::sleep(PAUSE);
        }
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let Some((port, marker)) = read_address(&text) else { continue };
        match ask(port, marker) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!(%e, attempt, "single instance: the running instance is not answering yet.")
            }
        }
    }
    Err(InstanceError::Unresponsive)
}

fn ask(port: u16, marker: &str) -> io::Result<()> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("{REQUEST} {marker}\n").as_bytes())?;
    let mut response = String::new();
    BufReader::new(stream.take(16)).read_line(&mut response)?;
    if response.trim_end() == RESPONSE {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the back channel answered something other than the expected acknowledgement; the \
             recorded port may belong to another program by now",
        ))
    }
}

/// `<port> <32 hex digits>\n` — strict, so that a half-written file does not count as an address.
fn read_address(text: &str) -> Option<(u16, &str)> {
    let (port, marker) = text.strip_suffix('\n')?.split_once(' ')?;
    let port: u16 = port.parse().ok()?;
    let marker_valid = marker.len() == 32 && marker.bytes().all(|b| b.is_ascii_hexdigit());
    (port != 0 && marker_valid).then_some((port, marker))
}

/// Writes the address through a staging file and a rename, so that a second instance never reads
/// half a line.
fn write_address(path: &Path, port: u16, marker: &str) -> Result<(), InstanceError> {
    let error = |reason| InstanceError::Address { path: path.to_path_buf(), reason };
    let between = path.with_extension("address.new");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&between).map_err(error)?;
    file.write_all(format!("{port} {marker}\n").as_bytes()).map_err(error)?;
    drop(file);
    fs::rename(&between, path).map_err(error)
}

/// 128 bits out of two freshly keyed SipHash runs from the standard library. Not cryptographic —
/// it does not have to be (see the module header); `edms-crypto` stays responsible for that.
fn new_marker() -> String {
    let time =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    (0_u8..2)
        .map(|i| {
            let mut h = RandomState::new().build_hasher();
            h.write_u8(i);
            h.write_u128(time);
            h.write_u32(std::process::id());
            format!("{:016x}", h.finish())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    fn first(directory: &Path) -> Guard {
        match claim(directory, "probe").unwrap() {
            Claim::First(w) => w,
            Claim::RunsAlready => {
                panic!("the first instance should have got the lock")
            }
        }
    }

    #[test]
    fn a_second_instance_does_not_get_the_lock() {
        let d = tempfile::tempdir().unwrap();
        let _w = first(d.path());
        assert!(matches!(claim(d.path(), "probe").unwrap(), Claim::RunsAlready));
    }

    #[test]
    fn a_second_instance_asks_the_first_for_its_window() {
        let d = tempfile::tempdir().unwrap();
        let w = first(d.path());
        let (tx, rx) = mpsc::channel();
        w.listen(Box::new(move || tx.send(()).is_ok())).unwrap();
        ask_for_window(d.path(), "probe").unwrap();
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the first instance should have opened the window");
    }

    #[test]
    fn a_wrong_marker_opens_no_window() {
        let d = tempfile::tempdir().unwrap();
        let w = first(d.path());
        let (tx, rx) = mpsc::channel();
        w.listen(Box::new(move || tx.send(()).is_ok())).unwrap();
        let text = fs::read_to_string(d.path().join("probe.address")).unwrap();
        let (port, _) = read_address(&text).unwrap();
        let wrong = "0".repeat(32);
        assert!(ask(port, &wrong).is_err(), "without a matching marker there is no OK");
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "and no window");
    }

    #[test]
    fn after_the_first_one_ends_the_next_start_is_the_first_again() {
        let d = tempfile::tempdir().unwrap();
        drop(first(d.path()));
        let _w = first(d.path());
    }

    #[test]
    fn without_a_running_instance_the_request_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let f = ask_for_window_with(d.path(), "probe", 2).unwrap_err();
        assert!(matches!(f, InstanceError::Unresponsive), "{f}");
    }

    #[test]
    fn the_address_line_is_read_strictly() {
        let marker = "0123456789abcdef0123456789ABCDEF";
        assert_eq!(read_address(&format!("8480 {marker}\n")), Some((8480, marker)));
        assert_eq!(read_address(&format!("8480 {marker}")), None, "half written");
        assert_eq!(read_address(&format!("0 {marker}\n")), None);
        assert_eq!(read_address("8480 short\n"), None);
        assert_eq!(read_address(""), None);
    }

    #[test]
    fn two_markers_are_different_and_thirty_two_hex_digits_long() {
        let (a, b) = (new_marker(), new_marker());
        assert_ne!(a, b);
        assert!(a.len() == 32 && a.bytes().all(|z| z.is_ascii_hexdigit()), "{a}");
    }
}
