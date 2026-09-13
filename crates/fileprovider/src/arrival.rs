//! What the Finder dropped into a mail basket — the platform sees it, the engine ingests it.
//!
//! A basket is a trigger, not a filing destination (namespace v2 §3, ADR-D08 amended): whoever
//! drags a file in has handed it in, and the ingest rule decides where it lands. The seam between
//! the two layers is one sentence — "a file appeared in basket `bsk_…`, and it lies here" — and
//! this module is the macOS half of it.
//!
//! **It runs in the app, not in the extension.** The extension is sandboxed and may not write
//! anywhere the engine could read (`packaging/macos/elasticdms-fileprovider.entitlements` grants
//! the one folder read-only). [`MacFileSystem`] however lives in the app's process, next to the
//! engine, and may ask macOS where a basket lies for the user
//! (`getUserVisibleURLForItemIdentifier:`, `domain.rs`). From there it is an ordinary directory:
//! the app is not sandboxed and reads it like any other.
//!
//! **The core decides where a file may be taken at all.** [`Container::accepts_new_files`] — and
//! nothing here matches on container variants of its own; a container that is added later and
//! takes files is then a drop target in every layer at once, or in none.
//!
//! **Nothing is filtered out here.** A `.crdownload`, a `~$…`, a name beginning with a dot: the
//! engine drops those, and it drops them in one place for both platforms
//! (`edms_engine::ingest`). Announcing the same file twice is free, so a round that reports it
//! again costs nothing either — what must not happen is a file nobody mentions.

use std::path::{Path, PathBuf};

use edms_core::identifier::BasketIdentifier;
use edms_core::namespace::{Container, EntryIdentifier};
use edms_core::port::PlatformError;

use crate::domain::DomainError;
use crate::filesystem::{MacFileSystem, platform_error};

/// A file that lies in a mail basket and has not been ingested yet.
///
/// The pair the engine's `Intake` expects: the basket says where it was handed in, the path says
/// where it lies now. This layer builds no path inside the mirror on its own — macOS names the
/// basket's directory, and the file name comes from the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrival {
    /// The basket it was dropped into — the target of the ingest (03 §7.4.1).
    pub basket: BasketIdentifier,
    /// Where the file lies now, as an absolute path on this machine.
    pub path: PathBuf,
}

impl MacFileSystem {
    /// Every file lying in one of these mail baskets, for the engine to ingest.
    ///
    /// Asked afresh each time and never remembered: the queue lives in the engine, and a second
    /// list here would be a second truth about a directory both can see. A basket macOS does not
    /// know yet — not materialised on this device — is passed over, not reported as an error:
    /// nothing lies in a folder that is not there.
    pub fn arrivals(&self, baskets: &[BasketIdentifier]) -> Result<Vec<Arrival>, PlatformError> {
        let domain = self.active_domain().ok_or(PlatformError::NotReadyPosed)?;
        let mut arrivals = Vec::new();
        for &basket in baskets {
            let container = Container::Basket(basket);
            // The core decides, not this layer (module header).
            if !container.accepts_new_files() {
                continue;
            }
            let entry = EntryIdentifier::Container(container);
            match self.management().visible_location(&domain, entry) {
                Ok(directory) => arrivals.extend(files_in(&directory, basket)),
                Err(DomainError::System(s)) if s.is_no_entry() => {}
                Err(error) => return Err(platform_error(error, Some(entry))),
            }
        }
        Ok(arrivals)
    }
}

/// The files lying directly in `directory`, in the order of their names.
///
/// Only files, and only this one level: a basket takes files (namespace v2 §3), and a folder
/// somebody put there is not something the engine could hand in. A directory that cannot be read
/// yields nothing — it may be a basket the user has just deleted, and an error would stop the
/// other baskets from being looked at at all.
fn files_in(directory: &Path, basket: BasketIdentifier) -> Vec<Arrival> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::debug!(
                directory = %directory.display(),
                %error,
                "the mail basket cannot be read; nothing is announced from it"
            );
            return Vec::new();
        }
    };
    let mut arrivals: Vec<Arrival> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| Arrival { basket, path: entry.path() })
        .collect();
    // `read_dir` promises no order; the engine works through a queue sorted by path anyway, and a
    // fixed order makes the log and this crate's tests readable.
    arrivals.sort_by(|a, b| a.path.cmp(&b.path));
    arrivals
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use edms_core::identifier::Identifier;

    use super::*;
    use crate::domain::DomainManagement;
    use crate::harness::basket_4;

    fn folder(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("edms-arrival-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("the folder");
        path
    }

    #[test]
    fn everything_lying_in_a_basket_is_announced_including_what_the_engine_will_drop() {
        let directory = folder("lying");
        for name in ["Rechnung.pdf", "Scan.pdf.crdownload", ".DS_Store", "~$Brief.docx"] {
            fs::write(directory.join(name), b"x").expect("the file");
        }
        // A folder is not a hand-in, and a basket takes files only (namespace v2 §3).
        fs::create_dir(directory.join("Unterlagen")).expect("the folder");
        let arrivals = files_in(&directory, basket_4());
        let names: Vec<String> = arrivals
            .iter()
            .map(|a| a.path.file_name().expect("a name").to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [".DS_Store", "Rechnung.pdf", "Scan.pdf.crdownload", "~$Brief.docx"]);
        // The filtering happens in the engine, in one place for both platforms.
        assert!(arrivals.iter().all(|a| a.basket == basket_4()), "{arrivals:?}");
        assert!(arrivals.iter().all(|a| a.path.starts_with(&directory)), "{arrivals:?}");
        fs::remove_dir_all(&directory).expect("tidied up");
    }

    #[test]
    fn a_basket_that_is_not_on_this_device_yields_nothing_instead_of_an_error() {
        let missing = std::env::temp_dir().join(format!("edms-no-basket-{}", std::process::id()));
        let _ = fs::remove_dir_all(&missing);
        assert_eq!(files_in(&missing, basket_4()), Vec::new());
    }

    #[test]
    fn without_a_provisioning_no_basket_is_looked_at() {
        let file_system = MacFileSystem::with_management(DomainManagement::with_deadline(
            Duration::from_millis(1),
        ));
        assert_eq!(file_system.arrivals(&[basket_4()]), Err(PlatformError::NotReadyPosed));
    }

    #[test]
    fn only_a_basket_is_a_drop_target_and_the_core_says_so() {
        // This layer asks the core instead of deciding for itself; if that answer ever changed,
        // `arrivals` would look into the wrong folders.
        assert!(Container::Basket(basket_4()).accepts_new_files());
        for container in [
            Container::Root,
            Container::Baskets,
            Container::Archives,
            Container::Archive(Identifier::from_value(5)),
            Container::Searches,
        ] {
            assert!(!container.accepts_new_files(), "{container}");
        }
    }
}
