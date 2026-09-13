//! `MacFileSystem` — the macOS side of `edms_core::port::FileSystem`.
//!
//! The engine gives orders, this layer carries them out. On macOS that means:
//!
//! | Order               | macOS                                                             |
//! |---------------------|-------------------------------------------------------------------|
//! | `place_ready`       | clear foreign elasticdms domains, then `addDomain`                |
//! | `report_change`     | signal the working set; the extension fetches `changes_since`     |
//! | `state`             | ask for the visible location, `lstat`, check `SF_DATALESS`        |
//! | `dehydrate`         | `evictItemWithIdentifier:`                                        |
//! | `remove`            | evict and signal; the name goes as soon as the engine journals `Removed` |
//! | `clear_everything`  | remove every elasticdms domain with `RemoveAll`                   |
//!
//! **No pinning on macOS (v1).** macOS offers third parties no system entry "always keep on this
//! device"; one of our own would need the FileProviderUI extension (ADR-D05). So `pinned` is always
//! `false` here, and `unpin` has nothing to lift — every copy can be evicted at any time, for an
//! erasure too (requirement 5).
//!
//! **Foreign domains give way to the provisioning.** If the app crashed during sign-out, the
//! previous account's domain is still there; if another user signs in, they would see that name in
//! Finder. Requirement 4 binds view and placeholder listing to the user, so `place_ready` clears
//! every other elasticdms domain before it creates its own.
//!
//! **Where the state comes from.** The system names the visible location of an item
//! (`getUserVisibleURLForItemIdentifier:`); whether content lies there the file system says
//! itself: a replicated file without content is a "dataless object" with the flag `SF_DATALESS`
//! (`<sys/stat.h>`). `lstat` reads metadata only and downloads nothing.

use std::fs;
use std::io::ErrorKind;
use std::os::macos::fs::MetadataExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use edms_core::change::Change;
use edms_core::namespace::EntryIdentifier;
use edms_core::port::{FileSystem, LocalState, PlatformError, Provisioning};

use crate::domain::{self, DOMAIN_POSIX, DomainError, DomainManagement};

/// `SF_DATALESS` from `<sys/stat.h>`: "file is dataless object".
pub const SF_DATALESS: u32 = 0x4000_0000;

/// The macOS platform layer for the engine.
#[derive(Debug)]
pub struct MacFileSystem {
    management: DomainManagement,
    active: Mutex<Option<String>>,
}

impl Default for MacFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl MacFileSystem {
    /// With the default deadline for every call into macOS.
    pub fn new() -> Self {
        Self::with_management(DomainManagement::new())
    }

    /// With a management of its own (a shorter deadline, say).
    pub fn with_management(management: DomainManagement) -> Self {
        Self { management, active: Mutex::new(None) }
    }

    /// The identifier of the provisioned domain.
    pub fn active_domain(&self) -> Option<String> {
        self.lock().clone()
    }

    /// The management, for instance to query `userEnabled` for the user interface.
    pub fn management(&self) -> &DomainManagement {
        &self.management
    }

    fn active(&self) -> Result<String, PlatformError> {
        self.lock().clone().ok_or(PlatformError::NotReadyPosed)
    }

    fn lock(&self) -> MutexGuard<'_, Option<String>> {
        self.active.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FileSystem for MacFileSystem {
    fn place_ready(&self, provisioning: &Provisioning) -> Result<(), PlatformError> {
        let identifier =
            domain::check_provisioning(provisioning).map_err(|f| platform_error(f, None))?;
        let removed =
            self.management.remove_all(Some(&identifier)).map_err(|f| platform_error(f, None))?;
        if !removed.is_empty() {
            tracing::info!(
                count = removed.len(),
                "domains of other accounts cleared (requirement 4)"
            );
        }
        self.management.add(provisioning).map_err(|f| platform_error(f, None))?;
        *self.lock() = Some(identifier);
        Ok(())
    }

    fn report_change(&self, changes: &[Change]) -> Result<(), PlatformError> {
        if changes.is_empty() {
            return Ok(());
        }
        let domain = self.active()?;
        self.management.signal_working_set(&domain).map_err(|f| platform_error(f, None))
    }

    fn state(&self, identifier: EntryIdentifier) -> Result<LocalState, PlatformError> {
        let domain = self.active()?;
        match self.management.visible_location(&domain, identifier) {
            Ok(path) => local_state_of(&path),
            // The system does not know the item: it is not on this device.
            Err(DomainError::System(s)) if s.is_no_entry() => Ok(LocalState::default()),
            Err(error) => Err(platform_error(error, Some(identifier))),
        }
    }

    fn dehydrate(
        &self,
        identifier: EntryIdentifier,
        _pinning_release: bool,
    ) -> Result<(), PlatformError> {
        // On macOS in v1 there is no pin that could be lifted (module header).
        let domain = self.active()?;
        self.management.evict(&domain, identifier).map_err(|f| platform_error(f, Some(identifier)))
    }

    fn remove(&self, identifier: EntryIdentifier) -> Result<(), PlatformError> {
        let domain = self.active()?;
        // The content first, immediately; then the signal, so that the extension fetches the
        // `Removed` out of the journal and the name disappears. Both are attempted, even if the
        // first one fails.
        let eviction = self.management.evict(&domain, identifier);
        let signal = self.management.signal_working_set(&domain);
        eviction.map_err(|f| platform_error(f, Some(identifier)))?;
        signal.map_err(|f| platform_error(f, None))
    }

    fn clear_everything(&self) -> Result<(), PlatformError> {
        self.management.remove_all(None).map_err(|f| platform_error(f, None))?;
        *self.lock() = None;
        Ok(())
    }
}

/// The local state at the visible location of an item.
pub fn local_state_of(path: &Path) -> Result<LocalState, PlatformError> {
    match fs::symlink_metadata(path) {
        Ok(details) => Ok(LocalState {
            present: true,
            hydrated: details.st_flags() & SF_DATALESS == 0,
            pinned: false,
        }),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(LocalState::default()),
        Err(error) => Err(PlatformError::OperatingSystem {
            code: error.raw_os_error().map_or(-1, i64::from),
            text: format!("{}: {error}", path.display()),
        }),
    }
}

/// Translates an error from the management for the engine.
pub(crate) fn platform_error(error: DomainError, entry: Option<EntryIdentifier>) -> PlatformError {
    match error {
        DomainError::Unknown(_) | DomainError::NoManager(_) => PlatformError::NotReadyPosed,
        DomainError::System(s) => match entry {
            Some(k) if s.is_no_entry() => PlatformError::NotFound(k),
            Some(k) if s.is(DOMAIN_POSIX, libc::EBUSY as isize) => PlatformError::InUse(k),
            _ if s.is_domain_unknown() => PlatformError::NotReadyPosed,
            _ => PlatformError::OperatingSystem { code: s.code as i64, text: s.to_string() },
        },
        f @ (DomainError::Timeout { .. } | DomainError::WithoutResponse { .. }) => {
            PlatformError::OperatingSystem { code: i64::from(libc::ETIMEDOUT), text: f.to_string() }
        }
        // PlatformError knows no "invalid order" (a wish addressed to edms-core); the text says
        // what is missing, the code is EINVAL.
        f @ (DomainError::AccountEmpty | DomainError::DisplayNameEmpty) => {
            PlatformError::OperatingSystem { code: i64::from(libc::EINVAL), text: f.to_string() }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::domain::{DOMAIN_FILE_PROVIDER, SystemError};
    use crate::harness::document_10;

    fn document() -> EntryIdentifier {
        document_10()
    }

    fn without_provisioning() -> MacFileSystem {
        MacFileSystem::with_management(DomainManagement::with_deadline(Duration::from_millis(1)))
    }

    #[test]
    fn without_a_provisioning_no_order_does_anything() {
        let fs = without_provisioning();
        let change = Change::Removed {
            entry: edms_core::namespace::root_entries(edms_i18n::Language::De).remove(0),
        };
        assert_eq!(fs.report_change(&[change]), Err(PlatformError::NotReadyPosed));
        assert_eq!(fs.state(document()), Err(PlatformError::NotReadyPosed));
        assert_eq!(fs.dehydrate(document(), true), Err(PlatformError::NotReadyPosed));
        assert_eq!(fs.remove(document()), Err(PlatformError::NotReadyPosed));
        assert_eq!(fs.active_domain(), None);
    }

    #[test]
    fn no_change_means_no_signal_even_without_a_provisioning() {
        assert_eq!(without_provisioning().report_change(&[]), Ok(()));
    }

    #[test]
    fn an_empty_provisioning_fails_with_a_reason_before_macos_is_asked() {
        let fs = without_provisioning();
        let error = fs
            .place_ready(&Provisioning {
                display_name: "elasticdms".into(),
                account: String::new(),
            })
            .unwrap_err();
        let PlatformError::OperatingSystem { code, text } = error else { panic!("{error:?}") };
        assert_eq!(code, i64::from(libc::EINVAL));
        assert!(text.contains("account identifier"), "{text}");
        assert_eq!(fs.active_domain(), None);
    }

    #[test]
    fn the_errors_of_the_management_become_the_engine_s_reasons() {
        let system = |domain: &str, code: isize| {
            DomainError::System(SystemError {
                domain: domain.into(),
                code,
                text: "t".into(),
                below: None,
            })
        };
        let k = document();
        assert_eq!(
            platform_error(system(DOMAIN_FILE_PROVIDER, -1005), Some(k)),
            PlatformError::NotFound(k)
        );
        assert_eq!(platform_error(system(DOMAIN_POSIX, 16), Some(k)), PlatformError::InUse(k));
        assert_eq!(
            platform_error(system(DOMAIN_FILE_PROVIDER, -2013), None),
            PlatformError::NotReadyPosed
        );
        assert_eq!(
            platform_error(DomainError::Unknown("x".into()), None),
            PlatformError::NotReadyPosed
        );
        let time = platform_error(
            DomainError::Timeout { flow: "evict copy", deadline: Duration::from_secs(30) },
            Some(k),
        );
        assert!(matches!(time, PlatformError::OperatingSystem { code: 60, .. }), "{time:?}");
        let otherwise = platform_error(system(DOMAIN_FILE_PROVIDER, -2008), Some(k));
        assert!(
            matches!(otherwise, PlatformError::OperatingSystem { code: -2008, .. }),
            "{otherwise:?}"
        );
        // Without an item, -1005 is not "item missing" but an error of the system.
        assert!(matches!(
            platform_error(system(DOMAIN_FILE_PROVIDER, -1005), None),
            PlatformError::OperatingSystem { .. }
        ));
    }

    #[test]
    fn an_ordinary_file_is_present_hydrated_and_never_pinned() {
        let path = std::env::temp_dir().join(format!("edms-state-{}.txt", std::process::id()));
        fs::write(&path, b"x").unwrap();
        assert_eq!(
            local_state_of(&path).unwrap(),
            LocalState { present: true, hydrated: true, pinned: false }
        );
        fs::remove_file(&path).unwrap();
        assert_eq!(local_state_of(&path).unwrap(), LocalState::default());
    }

    #[test]
    fn the_file_system_is_good_enough_for_the_engine() {
        fn takes(_: &dyn FileSystem) {}
        takes(&without_provisioning());
    }
}
