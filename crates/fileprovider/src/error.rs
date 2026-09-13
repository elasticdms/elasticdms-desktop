//! Errors of the extension and their translation into `NSError`.
//!
//! What the extension reports to the system as an error decides how the system behaves
//! (NSFileProviderReplicatedExtension.h, sections "Error cases"):
//!
//! * `NotAuthenticated`, `ServerUnreachable` — the system shows a notice and **waits until it is
//!   signalled**. Exactly the right thing when nobody is signed in or the app is not running: the
//!   app signals the working set as soon as it can serve again.
//! * `NoSuchItem` — the system **deletes the item from disk**. Only for identifiers that really do
//!   not exist; never as an answer of convenience.
//! * `SyncAnchorExpired` / `PageExpired` — the system enumerates afresh.
//! * `CannotSynchronize` — final: the system does not try again (read-only, requirement 1).
//! * `DeletionRejected` — the system restores the item from the last details it has.
//! * everything else counts as temporary and is retried.
//!
//! **Only two error domains.** Errors have to come from `NSFileProviderErrorDomain` or
//! `NSCocoaErrorDomain`; an error from any other domain is retried endlessly (ibid.). That is why
//! there is no way here to report a POSIX domain or one of our own.

use edms_core::namespace::EntryIdentifier;
use edms_core::port::SourceError;
use edms_i18n::{Catalog, key};
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_file_provider::{NSFileProviderErrorCode, NSFileProviderErrorDomain};
use objc2_foundation::{
    NSCocoaErrorDomain, NSDictionary, NSError, NSErrorUserInfoKey, NSFeatureUnsupportedError,
    NSFileReadCorruptFileError, NSFileReadNoPermissionError, NSFileReadUnknownError,
    NSFileWriteUnknownError, NSInteger, NSLocalizedDescriptionKey, NSString, NSUserCancelledError,
};

/// Why the extension cannot serve a request from the system.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// The source (the engine in the app) refused.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// The channel to the app is not up.
    #[error("the elasticdms app cannot be reached ({0})")]
    AppNotReachable(String),
    /// An identifier this extension has never handed out.
    #[error("the identifier `{0}` does not come from elasticdms")]
    ForeignIdentifier(String),
    /// The trash of a read-only mirror.
    #[error("this folder is read-only and has no wastebasket")]
    NoTrash,
    /// Content requested for a folder.
    #[error("`{0}` is a folder and has no content to load")]
    NoFile(EntryIdentifier),
    /// Creating or changing inside the mirror.
    #[error("this folder is read-only; changes are not passed on to elasticdms")]
    ReadOnly,
    /// Deleting inside the mirror.
    #[error("this folder is read-only; the file will be restored")]
    DeleteRejected,
    /// The page marker no longer matches the listing.
    #[error("the list changed while it was being enumerated; it starts again")]
    PageExpired,
    /// The system provides no staging area for downloaded content.
    #[error("macOS provides no staging folder for downloaded files: {0}")]
    Staging(String),
    /// The staging file could not be written.
    #[error("the downloaded file could not be staged: {0}")]
    File(String),
    /// The system cancelled the request.
    #[error("the request was cancelled")]
    Cancelled,
}

impl ProviderError {
    /// The sentence Finder shows, in the language of this Mac.
    ///
    /// The `Display` message is the diagnostic one and stays English (`edms_core::port`,
    /// `SourceError::user_text`, says why). This one goes into `NSLocalizedDescriptionKey` — and
    /// that is read by the person whose file will not open.
    pub fn user_text(&self, catalogue: &Catalog) -> String {
        match self {
            // The source knows its own reason better than a wrapper around it could.
            Self::Source(error) => error.user_text(catalogue),
            Self::AppNotReachable(reason) => {
                catalogue.format(key::ERROR_PROVIDER_APP_NOT_REACHABLE, &[("reason", reason)])
            }
            Self::ForeignIdentifier(identifier) => catalogue
                .format(key::ERROR_PROVIDER_FOREIGN_IDENTIFIER, &[("identifier", identifier)]),
            Self::NoTrash => catalogue.text(key::ERROR_PROVIDER_NO_TRASH).to_owned(),
            Self::NoFile(entry) => {
                catalogue.format(key::ERROR_PROVIDER_NO_FILE, &[("entry", &entry.to_string())])
            }
            Self::ReadOnly => catalogue.text(key::ERROR_PROVIDER_READ_ONLY).to_owned(),
            Self::DeleteRejected => catalogue.text(key::ERROR_PROVIDER_DELETE_REJECTED).to_owned(),
            Self::PageExpired => catalogue.text(key::ERROR_PROVIDER_PAGE_EXPIRED).to_owned(),
            Self::Staging(reason) => {
                catalogue.format(key::ERROR_PROVIDER_STAGING, &[("reason", reason)])
            }
            Self::File(reason) => catalogue.format(key::ERROR_PROVIDER_FILE, &[("reason", reason)]),
            Self::Cancelled => catalogue.text(key::ERROR_PROVIDER_CANCELLED).to_owned(),
        }
    }
}

/// Which domain a reported error comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDomain {
    /// `NSFileProviderErrorDomain`.
    FileProvider,
    /// `NSCocoaErrorDomain`.
    Cocoa,
}

/// Domain, code and text of an error, before it becomes an `NSError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorImage {
    /// Domain.
    pub domain: ErrorDomain,
    /// Code within the domain.
    pub code: NSInteger,
    /// `NSLocalizedDescriptionKey`: the sentence Finder shows.
    pub text: String,
}

impl ProviderError {
    /// Domain and code, the ones that trigger the behaviour described in the module header.
    pub fn error_image(&self) -> ErrorImage {
        use ErrorDomain::{Cocoa, FileProvider};
        let (domain, code) = match self {
            Self::Source(SourceError::NotSignedIn) => {
                (FileProvider, NSFileProviderErrorCode::NotAuthenticated.0)
            }
            Self::Source(SourceError::NoNetwork) | Self::AppNotReachable(_) => {
                (FileProvider, NSFileProviderErrorCode::ServerUnreachable.0)
            }
            Self::Source(SourceError::NotFound(_)) | Self::ForeignIdentifier(_) => {
                (FileProvider, NSFileProviderErrorCode::NoSuchItem.0)
            }
            Self::Source(SourceError::AnchorExpired) => {
                (FileProvider, NSFileProviderErrorCode::SyncAnchorExpired.0)
            }
            Self::PageExpired => (FileProvider, NSFileProviderErrorCode::PageExpired.0),
            Self::ReadOnly => (FileProvider, NSFileProviderErrorCode::CannotSynchronize.0),
            Self::DeleteRejected => (FileProvider, NSFileProviderErrorCode::DeletionRejected.0),
            // "NSFileReadNoPermissionError is surfaced to the user" (fetchContents, Error cases).
            Self::Source(SourceError::NoAccess) => (Cocoa, NSFileReadNoPermissionError),
            Self::Source(SourceError::Integrity { .. } | SourceError::Incomplete { .. }) => {
                (Cocoa, NSFileReadCorruptFileError)
            }
            Self::Source(SourceError::Cancelled) | Self::Cancelled => (Cocoa, NSUserCancelledError),
            // Trash: this is what the header of enumeratorForContainerItemIdentifier demands.
            Self::NoTrash => (Cocoa, NSFeatureUnsupportedError),
            Self::Source(SourceError::Sink(_)) | Self::File(_) | Self::Staging(_) => {
                (Cocoa, NSFileWriteUnknownError)
            }
            Self::Source(SourceError::Server(_) | SourceError::Internal(_)) | Self::NoFile(_) => {
                (Cocoa, NSFileReadUnknownError)
            }
        };
        // The sentence in the user's language, not the diagnostic one: this text lands in
        // `NSLocalizedDescriptionKey` and is read in Finder. The language is the Mac's
        // (`crate::locale`) — the extension is a process of its own and asks for itself.
        ErrorImage { domain, code, text: self.user_text(Catalog::of(crate::locale::language())) }
    }

    /// The `NSError` that goes to the system.
    pub fn as_nserror(&self) -> Retained<NSError> {
        let image = self.error_image();
        // SAFETY: both domain names are immutable NSString constants exported by their
        // respective framework (NSFileProviderError.h, NSError.h).
        let domain: &NSString = unsafe {
            match image.domain {
                ErrorDomain::FileProvider => NSFileProviderErrorDomain,
                ErrorDomain::Cocoa => NSCocoaErrorDomain,
            }
        };
        let text = NSString::from_str(&image.text);
        let value: &AnyObject = &text;
        // SAFETY: NSLocalizedDescriptionKey is an exported constant (NSError.h).
        let key: &NSErrorUserInfoKey = unsafe { NSLocalizedDescriptionKey };
        let details = NSDictionary::<NSErrorUserInfoKey, AnyObject>::from_slices(&[key], &[value]);
        // SAFETY: userInfo is an NSDictionary<NSErrorUserInfoKey, id>, the way
        // +errorWithDomain:code:userInfo: demands; the value is an NSString.
        unsafe { NSError::errorWithDomain_code_userInfo(domain, image.code, Some(&details)) }
    }
}

#[cfg(test)]
mod tests {
    use edms_core::checksum::Sha256Value;
    use edms_core::identifier::Identifier;
    use edms_core::port::SinkError;

    use super::*;

    fn image(error: ProviderError) -> (ErrorDomain, NSInteger) {
        let b = error.error_image();
        (b.domain, b.code)
    }

    #[test]
    fn not_signed_in_and_no_network_make_the_system_wait_until_it_is_signalled() {
        assert_eq!(image(SourceError::NotSignedIn.into()), (ErrorDomain::FileProvider, -1000));
        assert_eq!(image(SourceError::NoNetwork.into()), (ErrorDomain::FileProvider, -1004));
        assert_eq!(
            image(ProviderError::AppNotReachable("no file".into())),
            (ErrorDomain::FileProvider, -1004)
        );
    }

    #[test]
    fn only_what_really_does_not_exist_becomes_no_such_item() {
        let k = EntryIdentifier::Container(edms_core::namespace::Container::Case {
            archive: Identifier::from_value(5),
            case: Identifier::from_value(1),
        });
        assert_eq!(image(SourceError::NotFound(k).into()), (ErrorDomain::FileProvider, -1005));
        assert_eq!(
            image(ProviderError::ForeignIdentifier("x".into())),
            (ErrorDomain::FileProvider, -1005)
        );
        // A server error is not a "does not exist": the system would otherwise delete the file.
        assert_ne!(image(SourceError::Server("500".into()).into()).1, -1005);
        assert_ne!(image(SourceError::Internal("x".into()).into()).1, -1005);
    }

    #[test]
    fn an_expired_anchor_and_an_expired_page_enumerate_afresh() {
        assert_eq!(image(SourceError::AnchorExpired.into()), (ErrorDomain::FileProvider, -1002));
        assert_eq!(image(ProviderError::PageExpired), (ErrorDomain::FileProvider, -1002));
    }

    #[test]
    fn writing_is_refused_for_good_and_deleting_is_undone() {
        assert_eq!(image(ProviderError::ReadOnly), (ErrorDomain::FileProvider, -2005));
        assert_eq!(image(ProviderError::DeleteRejected), (ErrorDomain::FileProvider, -1006));
    }

    #[test]
    fn all_the_rest_go_into_the_cocoa_domain_never_into_a_third_one() {
        let w = Sha256Value::from_bytes([0; 32]);
        let rest = [
            (ProviderError::from(SourceError::NoAccess), 257),
            (SourceError::Integrity { expected: w, actual: w }.into(), 259),
            (SourceError::Incomplete { expected: 2, actual: 1 }.into(), 259),
            (SourceError::Cancelled.into(), 3072),
            (ProviderError::Cancelled, 3072),
            (SourceError::Sink(SinkError("disk full".into())).into(), 512),
            (SourceError::Server("502".into()).into(), 256),
            (SourceError::Internal("x".into()).into(), 256),
            (ProviderError::NoTrash, 3328),
            (ProviderError::File("disk full".into()), 512),
            (ProviderError::Staging("missing".into()), 512),
        ];
        for (error, code) in rest {
            assert_eq!(image(error.clone()), (ErrorDomain::Cocoa, code), "{error:?}");
        }
    }

    #[test]
    fn the_nserror_carries_domain_code_and_the_message() {
        let e = ProviderError::from(SourceError::NotSignedIn).as_nserror();
        assert_eq!(e.domain().to_string(), "NSFileProviderErrorDomain");
        assert_eq!(e.code(), -1000);
        // The sentence Finder shows is the one for **this** Mac's language, not the diagnostic
        // one: whichever language the machine running the test is set to, what comes out is the
        // catalogue's sentence and never the English `Display` message.
        let expected = SourceError::NotSignedIn.user_text(Catalog::of(crate::locale::language()));
        assert_eq!(e.localizedDescription().to_string(), expected);
        assert_ne!(expected, SourceError::NotSignedIn.to_string(), "diagnosis and sentence differ");
        let c = ProviderError::NoTrash.as_nserror();
        assert_eq!(c.domain().to_string(), "NSCocoaErrorDomain");
        assert_eq!(c.code(), 3328);
    }

    #[test]
    fn every_provider_error_says_a_whole_sentence_in_every_language() {
        let all = [
            ProviderError::from(SourceError::NotSignedIn),
            ProviderError::from(SourceError::NoNetwork),
            ProviderError::from(SourceError::NoAccess),
            ProviderError::from(SourceError::Cancelled),
            ProviderError::from(SourceError::Server("no".into())),
            ProviderError::AppNotReachable("no socket".into()),
            ProviderError::ForeignIdentifier("x".into()),
            ProviderError::NoTrash,
            ProviderError::ReadOnly,
            ProviderError::DeleteRejected,
            ProviderError::PageExpired,
            ProviderError::Staging("missing".into()),
            ProviderError::File("disk full".into()),
            ProviderError::Cancelled,
        ];
        for language in edms_i18n::Language::ALL {
            let catalogue = Catalog::of(language);
            for error in &all {
                let sentence = error.user_text(catalogue);
                assert!(!sentence.is_empty(), "{language} {error:?}");
                assert!(!sentence.contains('{'), "{language} {error:?}: {sentence}");
                assert!(!sentence.starts_with("error."), "{language} {error:?}: {sentence}");
            }
        }
    }
}
