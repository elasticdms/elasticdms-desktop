//! Domain management — the part of this layer the app uses.
//!
//! To macOS a domain is an entry in Finder's sidebar and a folder under
//! `~/Library/CloudStorage/elasticdms-<display name>`. The app creates it
//! (`+[NSFileProviderManager addDomain:]`), signals changes to it, evicts copies and clears it on
//! sign-out.
//!
//! **One domain per account, named after a short hash.** The identifier may contain neither `/`
//! nor `:` (NSFileProviderDomain.h) and appears in the system's logs; the account identifier
//! (`sub`) has no business being there. `elasticdms-` plus 16 hex digits of the SHA-256 of the
//! account identifier: stable across restarts, different per account, without naming the account.
//!
//! **Every call waits at most one deadline.** File Provider answers through completion blocks; the
//! methods here wait for them. Without a deadline the app hangs: `removeDomain` was measured
//! hanging for a domain whose extension had never started (`userEnabled = false`). Never call from
//! the main thread — a block arriving there would wait for the thread that is waiting for it.

use std::fmt;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use block2::RcBlock;
use edms_core::namespace::EntryIdentifier;
use edms_core::port::Provisioning;
use objc2::AllocAnyThread;
use objc2::rc::Retained;
use objc2_file_provider::{
    NSFileProviderDomain, NSFileProviderDomainRemovalMode, NSFileProviderManager,
    NSFileProviderWorkingSetContainerItemIdentifier,
};
use objc2_foundation::{NSArray, NSError, NSString, NSURL, NSUnderlyingErrorKey};
use sha2::{Digest, Sha256};

use crate::identifier::SystemIdentifiers;
use crate::thread::ThreadFixed;

/// Prefix of every domain of this app.
pub const DOMAIN_PREFIX: &str = "elasticdms-";

/// This many bytes of the SHA-256 go into the identifier (16 hex digits).
const SHORT_HASH_BYTES: usize = 8;

/// File Provider's error domain, the way `NSError.domain` names it.
pub const DOMAIN_FILE_PROVIDER: &str = "NSFileProviderErrorDomain";
/// POSIX error domain (`EBUSY` when evicting an open file).
pub const DOMAIN_POSIX: &str = "NSPOSIXErrorDomain";

/// `NSFileProviderErrorNoSuchItem`.
const CODE_NO_ENTRY: isize = -1005;
/// `NSFileProviderErrorProviderDomainNotFound`.
const CODE_DOMAIN_UNKNOWN: isize = -2013;

/// The identifier of the domain for an account.
pub fn domain_identifier(account: &str) -> String {
    let digest = Sha256::digest(account.as_bytes());
    let short: String = digest.iter().take(SHORT_HASH_BYTES).map(|b| format!("{b:02x}")).collect();
    format!("{DOMAIN_PREFIX}{short}")
}

/// An error macOS reported, as a Rust value (an `NSError` may not cross threads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemError {
    /// `NSError.domain`.
    pub domain: String,
    /// `NSError.code`.
    pub code: isize,
    /// `NSError.localizedDescription`.
    pub text: String,
    /// Domain and code of `NSUnderlyingErrorKey`, if present — on `-2001` the actual cause stands
    /// there (`-2014`: no launchable extension in the bundle, ADR-D05).
    pub below: Option<(String, isize)>,
}

impl SystemError {
    /// Reads an `NSError`.
    pub fn from(error: &NSError) -> Self {
        Self {
            domain: error.domain().to_string(),
            code: error.code(),
            text: error.localizedDescription().to_string(),
            below: underlying(error),
        }
    }

    /// Whether it is this error.
    pub fn is(&self, domain: &str, code: isize) -> bool {
        self.domain == domain && self.code == code
    }

    /// `NSFileProviderErrorNoSuchItem`: the system does not know the item.
    pub fn is_no_entry(&self) -> bool {
        self.is(DOMAIN_FILE_PROVIDER, CODE_NO_ENTRY)
    }

    /// `NSFileProviderErrorProviderDomainNotFound`: the domain is gone.
    ///
    /// It can disappear between two calls — the user switches the extension off in System
    /// Settings, or a second sign-in clears it. To the engine that is "not provisioned", not
    /// "operating system error": only that way does the app set up again instead of laying the
    /// error in front of the user.
    pub fn is_domain_unknown(&self) -> bool {
        self.is(DOMAIN_FILE_PROVIDER, CODE_DOMAIN_UNKNOWN)
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.domain, self.code, self.text)?;
        if let Some((domain, code)) = &self.below {
            write!(f, " (cause: {domain} {code})")?;
        }
        Ok(())
    }
}

fn underlying(error: &NSError) -> Option<(String, isize)> {
    // SAFETY: NSUnderlyingErrorKey is an exported, immutable constant (NSError.h).
    let key = unsafe { NSUnderlyingErrorKey };
    let value = error.userInfo().objectForKey(key)?;
    let below = value.downcast::<NSError>().ok()?;
    Some((below.domain().to_string(), below.code()))
}

/// Why the domain management could not carry out an order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// Empty account identifier.
    #[error("the account identifier is empty; without it no folder can be set up")]
    AccountEmpty,
    /// Empty display name.
    #[error("the display name is empty; Finder would show a root without a name")]
    DisplayNameEmpty,
    /// macOS did not answer within the deadline.
    #[error("macOS did not answer `{flow}` within {deadline:?}")]
    Timeout {
        /// What was asked for.
        flow: &'static str,
        /// The deadline.
        deadline: Duration,
    },
    /// macOS released the completion block without calling it.
    #[error("macOS ended `{flow}` without answering")]
    WithoutResponse {
        /// What was asked for.
        flow: &'static str,
    },
    /// No domain with this identifier.
    #[error("the domain `{0}` is not set up on this device")]
    Unknown(String),
    /// No `NSFileProviderManager` for the domain.
    #[error("macOS provides no manager for the domain `{0}`")]
    NoManager(String),
    /// An error from macOS.
    #[error("macOS reports {0}")]
    System(SystemError),
}

/// What the app has to know about a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDetails {
    /// Identifier (`elasticdms-…`).
    pub identifier: String,
    /// Display name, and at the same time the name of the root.
    pub display_name: String,
    /// Whether the user has switched the extension on. On macOS 26 a new domain is off until the
    /// user switches it on in *System Settings → General → Login Items & Extensions*; until then
    /// every access hangs (measured, ADR-D05). The app should say so.
    pub enabled: bool,
    /// Whether the domain is disconnected (`disconnectWithReason:`).
    pub disconnected: bool,
}

/// Sets domains up, clears them and passes orders on to File Provider.
#[derive(Debug, Clone)]
pub struct DomainManagement {
    deadline: Duration,
}

impl Default for DomainManagement {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainManagement {
    /// Deadline per call, unless something else is said.
    pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

    /// With the default deadline.
    pub fn new() -> Self {
        Self { deadline: Self::DEFAULT_DEADLINE }
    }

    /// With a deadline of its own.
    pub fn with_deadline(deadline: Duration) -> Self {
        Self { deadline }
    }

    /// Creates the domain for a provisioning; returns its identifier.
    ///
    /// If it already exists, macOS only updates the display name (NSFileProviderManager.h).
    pub fn add(&self, provisioning: &Provisioning) -> Result<String, DomainError> {
        let identifier = check_provisioning(provisioning)?;
        // SAFETY: -initWithIdentifier:displayName: on a freshly allocated instance; the identifier
        // contains neither '/' nor ':' (NSFileProviderDomain.h), the name is not empty.
        let domain = unsafe {
            NSFileProviderDomain::initWithIdentifier_displayName(
                NSFileProviderDomain::alloc(),
                &NSString::from_str(&identifier),
                &NSString::from_str(&provisioning.display_name),
            )
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let block = error_block(tx);
        // SAFETY: class method with a valid domain; the system copies the block.
        unsafe { NSFileProviderManager::addDomain_completionHandler(&domain, &block) };
        response_without_value(rx, self.deadline, "add domain")?;
        Ok(identifier)
    }

    /// Every domain of this app.
    pub fn domain(&self) -> Result<Vec<DomainDetails>, DomainError> {
        Ok(self.system_domain()?.iter().map(|d| details(d)).collect())
    }

    /// Removes a domain together with every local copy (`NSFileProviderDomainRemovalModeRemoveAll`).
    pub fn remove(&self, identifier: &str) -> Result<(), DomainError> {
        let domain = self.find(identifier)?;
        self.remove_domain(&domain)
    }

    /// Removes every domain of this app except `except`; returns the identifiers removed.
    ///
    /// It tries all of them, even if one fails, and then reports the first error: one hanging
    /// domain must not leave the names of the others on disk (requirement 4).
    pub fn remove_all(&self, except: Option<&str>) -> Result<Vec<String>, DomainError> {
        let mut removed = Vec::new();
        let mut first_error = None;
        for domain in self.system_domain()? {
            let identifier = details(&domain).identifier;
            if !identifier.starts_with(DOMAIN_PREFIX) || except == Some(identifier.as_str()) {
                continue;
            }
            match self.remove_domain(&domain) {
                Ok(()) => removed.push(identifier),
                Err(error) => {
                    tracing::warn!(domain = %identifier, %error, "the domain could not be removed");
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(removed),
        }
    }

    /// Signals the working set: the extension fetches the changes out of the journal.
    ///
    /// The working set is the only container a replicated provider may signal; the system ignores
    /// every other identifier (NSFileProviderManager.h).
    pub fn signal_working_set(&self, identifier: &str) -> Result<(), DomainError> {
        let manager = self.manager(identifier)?;
        let (tx, rx) = mpsc::sync_channel(1);
        let block = error_block(tx);
        // SAFETY: the working set is an exported constant; the manager belongs to the domain.
        unsafe {
            manager.signalEnumeratorForContainerItemIdentifier_completionHandler(
                NSFileProviderWorkingSetContainerItemIdentifier,
                &block,
            );
        }
        response_without_value(rx, self.deadline, "signal changes")
    }

    /// Evicts the local content of an item (`evictItemWithIdentifier:`).
    pub fn evict(&self, identifier: &str, entry: EntryIdentifier) -> Result<(), DomainError> {
        let manager = self.manager(identifier)?;
        let system_identifier = NSString::from_str(&SystemIdentifiers::of_the_system().text(entry));
        let (tx, rx) = mpsc::sync_channel(1);
        let block = error_block(tx);
        // SAFETY: identifier and block are valid; the manager belongs to the domain.
        unsafe { manager.evictItemWithIdentifier_completionHandler(&system_identifier, &block) };
        response_without_value(rx, self.deadline, "evict copy")
    }

    /// Where an item lies for the user (`getUserVisibleURLForItemIdentifier:`).
    pub fn visible_location(
        &self,
        identifier: &str,
        entry: EntryIdentifier,
    ) -> Result<PathBuf, DomainError> {
        let manager = self.manager(identifier)?;
        let system_identifier = NSString::from_str(&SystemIdentifiers::of_the_system().text(entry));
        let (tx, rx) = mpsc::sync_channel::<Result<Option<PathBuf>, SystemError>>(1);
        let block = RcBlock::new(move |location: *mut NSURL, error: *mut NSError| {
            // SAFETY: the system passes nil or valid objects for the duration of the call.
            let result = match unsafe { (location.as_ref(), error.as_ref()) } {
                (_, Some(error)) => Err(SystemError::from(error)),
                (Some(location), None) => Ok(location.to_file_path()),
                (None, None) => Ok(None),
            };
            let _ = tx.try_send(result);
        });
        // SAFETY: identifier and block are valid; the manager belongs to the domain.
        unsafe {
            manager.getUserVisibleURLForItemIdentifier_completionHandler(&system_identifier, &block)
        };
        match receive(rx, self.deadline, "determine location")? {
            Ok(Some(path)) => Ok(path),
            Ok(None) => Err(DomainError::WithoutResponse { flow: "determine location" }),
            Err(error) => Err(DomainError::System(error)),
        }
    }

    fn system_domain(&self) -> Result<Vec<Retained<NSFileProviderDomain>>, DomainError> {
        type Response = Result<ThreadFixed<Vec<Retained<NSFileProviderDomain>>>, SystemError>;
        let (tx, rx) = mpsc::sync_channel::<Response>(1);
        let block = RcBlock::new(
            move |domain: NonNull<NSArray<NSFileProviderDomain>>, error: *mut NSError| {
                // SAFETY: the system passes nil or a valid NSError for the duration of the call.
                let result = match unsafe { error.as_ref() } {
                    Some(error) => Err(SystemError::from(error)),
                    // SAFETY: per the header the array is nonnull and lives for the duration of the
                    // call; `to_vec` retains every domain. Domains are value objects that are only
                    // read here and handed back to File Provider — any thread may do that.
                    None => Ok(unsafe { ThreadFixed::new(domain.as_ref().to_vec()) }),
                };
                let _ = tx.try_send(result);
            },
        );
        // SAFETY: class method with a valid block.
        unsafe { NSFileProviderManager::getDomainsWithCompletionHandler(&block) };
        receive(rx, self.deadline, "list domains")?
            .map(ThreadFixed::into_value)
            .map_err(DomainError::System)
    }

    fn find(&self, identifier: &str) -> Result<Retained<NSFileProviderDomain>, DomainError> {
        self.system_domain()?
            .into_iter()
            .find(|d| details(d).identifier == identifier)
            .ok_or_else(|| DomainError::Unknown(identifier.to_owned()))
    }

    fn manager(&self, identifier: &str) -> Result<Retained<NSFileProviderManager>, DomainError> {
        let domain = self.find(identifier)?;
        // SAFETY: managerForDomain: with a domain delivered by the system.
        unsafe { NSFileProviderManager::managerForDomain(&domain) }
            .ok_or_else(|| DomainError::NoManager(identifier.to_owned()))
    }

    fn remove_domain(&self, domain: &NSFileProviderDomain) -> Result<(), DomainError> {
        let (tx, rx) = mpsc::sync_channel(1);
        let block = RcBlock::new(move |_preserved: *mut NSURL, error: *mut NSError| {
            // SAFETY: the system passes nil or a valid NSError for the duration of the call.
            let _ = tx.try_send(unsafe { error.as_ref() }.map(SystemError::from));
        });
        // SAFETY: class method with a valid domain and block; RemoveAll preserves nothing.
        unsafe {
            NSFileProviderManager::removeDomain_mode_completionHandler(
                domain,
                NSFileProviderDomainRemovalMode::RemoveAll,
                &block,
            );
        }
        response_without_value(rx, self.deadline, "remove domain")
    }
}

/// Checks a provisioning before anything goes to macOS; returns the domain identifier.
pub(crate) fn check_provisioning(provisioning: &Provisioning) -> Result<String, DomainError> {
    if provisioning.account.trim().is_empty() {
        return Err(DomainError::AccountEmpty);
    }
    if provisioning.display_name.trim().is_empty() {
        return Err(DomainError::DisplayNameEmpty);
    }
    Ok(domain_identifier(&provisioning.account))
}

fn details(domain: &NSFileProviderDomain) -> DomainDetails {
    // SAFETY: read-only properties of a domain, all from macOS 11 on (NSFileProviderDomain.h).
    unsafe {
        DomainDetails {
            identifier: domain.identifier().to_string(),
            display_name: domain.displayName().to_string(),
            enabled: domain.userEnabled(),
            disconnected: domain.isDisconnected(),
        }
    }
}

fn error_block(tx: SyncSender<Option<SystemError>>) -> RcBlock<dyn Fn(*mut NSError)> {
    RcBlock::new(move |error: *mut NSError| {
        // SAFETY: the system passes nil or a valid NSError for the duration of the call.
        let _ = tx.try_send(unsafe { error.as_ref() }.map(SystemError::from));
    })
}

fn receive<T>(rx: Receiver<T>, deadline: Duration, flow: &'static str) -> Result<T, DomainError> {
    rx.recv_timeout(deadline).map_err(|error| match error {
        RecvTimeoutError::Timeout => DomainError::Timeout { flow, deadline },
        RecvTimeoutError::Disconnected => DomainError::WithoutResponse { flow },
    })
}

fn response_without_value(
    rx: Receiver<Option<SystemError>>,
    deadline: Duration,
    flow: &'static str,
) -> Result<(), DomainError> {
    match receive(rx, deadline, flow)? {
        None => Ok(()),
        Some(error) => Err(DomainError::System(error)),
    }
}

#[cfg(test)]
mod tests {
    use objc2::runtime::AnyObject;
    use objc2_foundation::{NSDictionary, NSErrorUserInfoKey};

    use super::*;

    fn provisioning(account: &str, name: &str) -> Provisioning {
        Provisioning { display_name: name.to_owned(), account: account.to_owned() }
    }

    #[test]
    fn the_domain_identifier_is_stable_per_account_and_does_not_name_it() {
        let a = domain_identifier("usr_01JK4R7ZQ8M3N5P6T9V0WXYZAB");
        assert_eq!(a, domain_identifier("usr_01JK4R7ZQ8M3N5P6T9V0WXYZAB"));
        assert_ne!(a, domain_identifier("usr_01JK4R7ZQ8M3N5P6T9V0WXYZAC"));
        assert!(a.starts_with(DOMAIN_PREFIX));
        assert_eq!(a.len(), DOMAIN_PREFIX.len() + 16);
        assert!(!a.contains("usr_"));
        for account in ["a/b", "a:b", "ä ö ü"] {
            let k = domain_identifier(account);
            assert!(!k.contains('/') && !k.contains(':') && k.is_ascii(), "{k}");
        }
    }

    #[test]
    fn an_empty_provisioning_is_rejected_before_macos_is_asked() {
        let v = DomainManagement::with_deadline(Duration::from_millis(1));
        assert_eq!(v.add(&provisioning(" ", "elasticdms")), Err(DomainError::AccountEmpty));
        assert_eq!(v.add(&provisioning("usr_1", "")), Err(DomainError::DisplayNameEmpty));
        assert_eq!(
            check_provisioning(&provisioning("usr_1", "elasticdms – Example GmbH")),
            Ok(domain_identifier("usr_1"))
        );
    }

    #[test]
    fn an_answer_that_never_comes_is_a_timeout_not_a_hang() {
        let (_tx, rx) = mpsc::sync_channel::<Option<SystemError>>(1);
        let error = response_without_value(rx, Duration::from_millis(20), "probe").unwrap_err();
        assert_eq!(
            error,
            DomainError::Timeout { flow: "probe", deadline: Duration::from_millis(20) }
        );
        let (tx, rx) = mpsc::sync_channel::<Option<SystemError>>(1);
        drop(tx);
        assert_eq!(
            response_without_value(rx, Duration::from_secs(5), "probe"),
            Err(DomainError::WithoutResponse { flow: "probe" })
        );
    }

    #[test]
    fn a_reported_error_arrives_as_a_system_error() {
        let (tx, rx) = mpsc::sync_channel(1);
        let block = error_block(tx);
        let error = crate::error::ProviderError::ReadOnly.as_nserror();
        block.call((Retained::as_ptr(&error).cast_mut(),));
        let reported = response_without_value(rx, Duration::from_secs(5), "probe").unwrap_err();
        let DomainError::System(s) = reported else { panic!("{reported:?}") };
        assert!(s.is(DOMAIN_FILE_PROVIDER, -2005), "{s}");
        let (tx, rx) = mpsc::sync_channel(1);
        error_block(tx).call((std::ptr::null_mut(),));
        assert_eq!(response_without_value(rx, Duration::from_secs(5), "probe"), Ok(()));
    }

    #[test]
    fn the_cause_under_a_system_error_is_carried_along() {
        let cause = crate::error::ProviderError::ReadOnly.as_nserror();
        let value: &AnyObject = &cause;
        // SAFETY: NSUnderlyingErrorKey is an exported constant.
        let key: &NSErrorUserInfoKey = unsafe { NSUnderlyingErrorKey };
        let details = NSDictionary::<NSErrorUserInfoKey, AnyObject>::from_slices(&[key], &[value]);
        // SAFETY: userInfo is an NSDictionary<NSErrorUserInfoKey, id>.
        let error = unsafe {
            NSError::errorWithDomain_code_userInfo(
                &NSString::from_str(DOMAIN_FILE_PROVIDER),
                -2001,
                Some(&details),
            )
        };
        let s = SystemError::from(&error);
        assert_eq!(s.code, -2001);
        assert_eq!(s.below, Some((DOMAIN_FILE_PROVIDER.to_owned(), -2005)));
        assert!(s.to_string().contains("cause: NSFileProviderErrorDomain -2005"), "{s}");
    }
}
