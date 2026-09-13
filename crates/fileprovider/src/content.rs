//! Downloaded content: the staging file `fetchContents` hands to the system.
//!
//! The system demands an **ordinary file on the same volume** as the visible location; it clones
//! it there and then deletes it itself (NSFileProviderReplicatedExtension.h, "File ownership").
//! The folder for that is named by `-[NSFileProviderManager temporaryDirectoryURLWithError:]`.
//!
//! The core's guarantee still holds: the source only writes into the sink once the checksum
//! matches (`port.rs`). The sink here only writes, but it does check that the chunks arrive
//! without gaps and ascending — a gap would be a file with zeros in a place nobody sees.
//!
//! **Orphaned staging files.** If the process crashes between the completion block and the
//! system's deletion, the file stays behind, "and you are responsible for deleting it" (ibid.).
//! The extension therefore tidies up on its first access to the folder — but only files of
//! **another** process that are **older than one hour**: during an update the old and the new
//! extension run alongside each other briefly, and the new one must not take a file away from the
//! old one in the middle of a hand-over.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use edms_core::port::{ContentSink, SinkError};
use objc2::rc::Retained;
use objc2_foundation::NSProgress;

use crate::error::ProviderError;

/// Prefix of every staging file.
pub(crate) const PREFIX: &str = "edms-";
/// Extension of every staging file.
pub(crate) const EXTENSION: &str = ".content";
/// From this age on a staging file of a foreign process counts as orphaned.
pub(crate) const ORPHANED_AFTER: Duration = Duration::from_secs(60 * 60);

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates a new, empty staging file: `edms-<pid>-<counter>.content`.
pub(crate) fn new_staging_file(directory: &Path) -> Result<(File, PathBuf), ProviderError> {
    let pid = std::process::id();
    for _ in 0..16 {
        let number = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("{PREFIX}{pid}-{number}{EXTENSION}"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            // A file of the same name from an earlier process with the same pid.
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(ProviderError::File(format!("{}: {error}", path.display())));
            }
        }
    }
    Err(ProviderError::File(format!(
        "no free name for a staging file found in {} after 16 tries",
        directory.display()
    )))
}

/// Clears orphaned staging files (module header); returns how many were removed.
pub(crate) fn clear_orphaned(directory: &Path, own_pid: u32, now: SystemTime) -> usize {
    let Ok(entries) = fs::read_dir(directory) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid) = foreign_pid(name) else { continue };
        if pid == own_pid {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|changed| now.duration_since(changed).ok())
            .is_some_and(|age| age >= ORPHANED_AFTER);
        if old && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Clears every folder once per process.
pub(crate) fn clear_once(directory: &Path) {
    static CLEARED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    let mut cleared = CLEARED.lock().unwrap_or_else(PoisonError::into_inner);
    if cleared.iter().any(|p| p == directory) {
        return;
    }
    cleared.push(directory.to_owned());
    let n = clear_orphaned(directory, std::process::id(), SystemTime::now());
    if n > 0 {
        tracing::info!(count = n, "orphaned staging files removed");
    }
}

/// The pid in the name of a staging file, if the name is one.
fn foreign_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(PREFIX)?.strip_suffix(EXTENSION)?;
    let (pid, number) = rest.split_once('-')?;
    number.parse::<u64>().ok()?;
    pid.parse().ok()
}

/// The sink into which the source writes verified content.
pub(crate) struct FileSink {
    file: BufWriter<File>,
    written: u64,
    progress: Option<Retained<NSProgress>>,
}

impl FileSink {
    /// A sink over a fresh staging file; reports progress to `progress`.
    pub(crate) fn new(file: File, progress: Option<Retained<NSProgress>>) -> Self {
        Self { file: BufWriter::new(file), written: 0, progress }
    }

    /// How many bytes have been written without gaps.
    pub(crate) fn written(&self) -> u64 {
        self.written
    }

    /// Flushes the buffer. Only after that may the system clone the file.
    pub(crate) fn complete(&mut self) -> Result<(), ProviderError> {
        self.file.flush().map_err(|f| ProviderError::File(f.to_string()))
    }
}

impl ContentSink for FileSink {
    fn progress(&mut self, loaded: u64, total: u64) {
        if let Some(progress) = &self.progress {
            progress.setTotalUnitCount(i64::try_from(total).unwrap_or(i64::MAX));
            progress.setCompletedUnitCount(i64::try_from(loaded).unwrap_or(i64::MAX));
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), SinkError> {
        if offset != self.written {
            return Err(SinkError(format!(
                "chunk at offset {offset}, expected {}; chunks have to arrive without gaps \
                 and ascending",
                self.written
            )));
        }
        self.file.write_all(data).map_err(|f| SinkError(f.to_string()))?;
        self.written += data.len() as u64;
        if let Some(progress) = &self.progress {
            progress.setCompletedUnitCount(i64::try_from(self.written).unwrap_or(i64::MAX));
        }
        Ok(())
    }

    fn cancelled(&self) -> bool {
        self.progress.as_ref().is_some_and(|f| f.isCancelled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("edms-fileprovider-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn chunks_have_to_arrive_without_gaps() {
        let o = folder("sink");
        let (file, path) = new_staging_file(&o).unwrap();
        let mut sink = FileSink::new(file, None);
        sink.write(0, b"abc").unwrap();
        let error = sink.write(5, b"x").unwrap_err();
        assert!(error.0.contains("offset 5"), "{}", error.0);
        sink.write(3, b"de").unwrap();
        sink.complete().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abcde");
        assert_eq!(sink.written(), 5);
        fs::remove_dir_all(&o).unwrap();
    }

    #[test]
    fn every_staging_file_gets_a_name_of_its_own() {
        let o = folder("names");
        let (_, a) = new_staging_file(&o).unwrap();
        let (_, b) = new_staging_file(&o).unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap();
        assert_eq!(foreign_pid(name), Some(std::process::id()));
        fs::remove_dir_all(&o).unwrap();
    }

    #[test]
    fn only_old_staging_files_of_foreign_processes_are_cleared() {
        let o = folder("clear");
        let foreign = o.join("edms-1-0.content");
        let own = o.join(format!("edms-{}-0.content", std::process::id()));
        let other = o.join("note.txt");
        for p in [&foreign, &own, &other] {
            fs::write(p, b"x").unwrap();
        }
        // Fresh: nothing is cleared.
        assert_eq!(clear_orphaned(&o, std::process::id(), SystemTime::now()), 0);
        // Two hours later: only the foreign staging file.
        let later = SystemTime::now() + Duration::from_secs(2 * 60 * 60);
        assert_eq!(clear_orphaned(&o, std::process::id(), later), 1);
        assert!(!foreign.exists());
        assert!(own.exists() && other.exists());
        fs::remove_dir_all(&o).unwrap();
    }
}
