//! The principal class of the .appex: `EdmsFileProvider`.
//!
//! PlugInKit starts the program of the extension, reads `NSExtensionPrincipalClass` out of its
//! `Info.plist` and looks the class up **through the Objective-C runtime, by name**, before a line
//! of Rust runs — with the entry point `_NSExtensionMain` Rust's `main` never runs at all. objc2,
//! however, registers a `define_class!` class only on the first `ClassType::class()`. That is why
//! this module contains a constructor in `__DATA,__mod_init_func`: dyld calls it when the program
//! is loaded, and the class is there before anybody asks for it (measured, ADR-D05, measurement 5:
//! without it `objc_getClass` returns nothing, and the system reports only
//! `NSFileProviderErrorProviderNotFound` under a `-2001`).
//!
//! ## The extension decides nothing
//!
//! Every question from Finder goes through [`NamespaceSource`] — in production through
//! `edms-bridge` to the engine in the app's process (ADR-D05). This module only translates:
//! identifier of the system into identifier of the core, answer of the core into an
//! `NSFileProviderItem`, error of the core into the one `NSError` that makes the system do the
//! right thing (`error.rs`). It does not filter (requirement 4: the listings arrive already
//! filtered by permission), it does not guess, and it holds no state except the channel.
//!
//! ## Read-only, in three places
//!
//! Requirement 1 ("the folders are exclusively read-only") stands not only in the capabilities of
//! every item (`entry.rs`) but here as well:
//!
//! * `createItemBasedOnTemplate:` and `modifyItem:` refuse with `CannotSynchronize` — that is
//!   **final**: the system does not try again and leaves the change locally where it is.
//! * `deleteItemWithIdentifier:` refuses with `DeletionRejected` — the system **restores the
//!   item** instead of letting it disappear and making the user believe they deleted something in
//!   the archive.
//!
//! ## A file dropped into a mail basket is not synchronised either
//!
//! A mail basket takes new files (`Container::accepts_new_files`, namespace v2 §3), and its item
//! says so, otherwise the Finder would refuse the drop before this extension is asked
//! (`entry.rs`). What the extension does **not** do is take the file into the namespace: namespace
//! v2 §2 gives a file lying in a basket no entry identifier, so there is no item
//! `createItemBasedOnTemplate:` could hand back. The refusal with `CannotSynchronize` is therefore
//! the right answer here as well — it is final, and it leaves the file lying where the user put
//! it. That is exactly what the ingest needs: the app-side platform layer finds it there
//! (`arrival.rs`) and hands it to the engine, and the engine moves it out of the basket once the
//! ingest is confirmed.
//!
//! All three answer immediately on the system's thread: there is nothing to load, and a thread
//! hand-off would only make the refusal slower.
//!
//! ## Every request that has to ask hands off to another thread
//!
//! `itemForIdentifier:` and `fetchContents…:` call the source over a channel; that takes time.
//! Whoever waits on the system's thread while doing so stops its queue (`thread.rs`). Both
//! therefore return immediately with an `NSProgress` and call their completion block from a thread
//! of their own.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use block2::DynBlock;
use edms_core::namespace::EntryIdentifier;
use edms_core::port::{ContentRequest, SourceError};
#[cfg(test)]
use objc2::AllocAnyThread;
use objc2::rc::{Allocated, Retained};
use objc2::runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{ClassType, DefinedClass, Message, define_class, msg_send};
use objc2_file_provider::{
    NSFileProviderCreateItemOptions, NSFileProviderDeleteItemOptions, NSFileProviderDomain,
    NSFileProviderEnumerating, NSFileProviderEnumerator, NSFileProviderItem,
    NSFileProviderItemFields, NSFileProviderItemVersion, NSFileProviderManager,
    NSFileProviderModifyItemOptions, NSFileProviderReplicatedExtension, NSFileProviderRequest,
};
use objc2_foundation::{NSError, NSProgress, NSString, NSURL};

use crate::connection::{ConnectionRoute, Context, SourceHolder};
use crate::content::{FileSink, clear_once, new_staging_file};
use crate::entry::EdmsEntry;
use crate::enumerator::{EdmsEnumerator, EnumerateTarget};
use crate::error::ProviderError;
use crate::identifier::Target;
use crate::thread::{ThreadFixed, in_background};

/// The name under which `NSExtensionPrincipalClass` looks the class up.
///
/// It stands twice — here and in `packaging/macos/`; a test holds the two together, because a typo
/// in the bundle would otherwise only show up when the Finder folder stays empty.
pub const PRINCIPAL_CLASS: &str = "EdmsFileProvider";

/// What one instance of the extension needs for its domain.
///
/// Public only because `DefinedClass::Ivars` of the public class points at it; the fields are not,
/// and there is no way to set them from outside.
pub struct ProviderData {
    context: Arc<Context>,
    domain: Retained<NSFileProviderDomain>,
    /// Set only in the test harness: there is no registered domain there, and therefore no
    /// staging folder `NSFileProviderManager` could name.
    #[cfg(test)]
    staging: Option<PathBuf>,
}

define_class!(
    /// The principal class of the file provider extension.
    #[unsafe(super(NSObject))]
    #[name = "EdmsFileProvider"]
    #[ivars = ProviderData]
    pub struct EdmsFileProvider;

    unsafe impl NSObjectProtocol for EdmsFileProvider {}

    unsafe impl NSFileProviderEnumerating for EdmsFileProvider {
        /// Hands out an enumerator; the work only starts once the system enumerates.
        ///
        /// "The system expects this call to complete quickly" (NSFileProviderEnumerating.h) —
        /// which is why only the identifier is read here, and the source is not asked.
        #[unsafe(method_id(enumeratorForContainerItemIdentifier:request:error:))]
        fn enumerator_for(
            &self,
            identifier: &NSString,
            _request: &NSFileProviderRequest,
            error: *mut *mut NSError,
        ) -> Option<Retained<ProtocolObject<dyn NSFileProviderEnumerator>>> {
            let context = Arc::clone(&self.ivars().context);
            match context
                .identifiers()
                .target(&identifier.to_string())
                .and_then(EnumerateTarget::for_target)
            {
                Ok(target) => {
                    Some(ProtocolObject::from_retained(EdmsEnumerator::new(target, context)))
                }
                Err(reason) => {
                    report_out_error(error, &reason);
                    None
                }
            }
        }
    }

    unsafe impl NSFileProviderReplicatedExtension for EdmsFileProvider {
        /// One instance per domain. No error path — the channel must not have to be up here.
        ///
        /// After a restart the user opens Finder before elasticdms is running; the system then
        /// starts the extension, and there is nobody to ask. The holder tries the channel and only
        /// remembers success (`connection.rs`); every request without a channel fails with
        /// `ServerUnreachable`, and the system waits until the app signals.
        #[unsafe(method_id(initWithDomain:))]
        fn init_with_domain(
            this: Allocated<Self>,
            domain: &NSFileProviderDomain,
        ) -> Retained<Self> {
            // SAFETY: displayName is a read-only property (NSFileProviderDomain.h).
            let display_name = unsafe { domain.displayName() }.to_string();
            let route = match crate::home::rendezvous_path() {
                Ok(path) => ConnectionRoute::Rendezvous(path),
                Err(reason) => ConnectionRoute::Undeterminable(reason.to_string()),
            };
            let context = Arc::new(Context::new(SourceHolder::over_bridge(route), display_name));
            let this = this.set_ivars(ProviderData {
                context,
                domain: domain.retain(),
                #[cfg(test)]
                staging: None,
            });
            // SAFETY: -[NSObject init] on the freshly allocated instance whose ivars are set.
            unsafe { msg_send![super(this), init] }
        }

        /// "should make sure that all references to the instance are released"
        /// (NSFileProviderReplicatedExtension.h): the channel is closed.
        #[unsafe(method(invalidate))]
        fn mark_invalid(&self) {
            self.ivars().context.release();
        }

        #[unsafe(method_id(itemForIdentifier:request:completionHandler:))]
        fn entry_for(
            &self,
            identifier: &NSString,
            _request: &NSFileProviderRequest,
            finished: &DynBlock<dyn Fn(*mut NSFileProviderItem, *mut NSError)>,
        ) -> Retained<NSProgress> {
            // One lookup, one step — unlike a download, the amount is known.
            let progress = progress(1);
            let context = Arc::clone(&self.ivars().context);
            let text = identifier.to_string();
            // SAFETY: File Provider completion blocks may be called from any thread; `copy` keeps
            // the block alive beyond this call.
            let finished = unsafe { ThreadFixed::new(finished.copy()) };
            let reporter = Retained::clone(&progress);
            in_background("edms-item", move || {
                let result = read_entry(&context, &text);
                reporter.setCompletedUnitCount(1);
                let block = finished.into_value();
                match result {
                    Ok(entry) => {
                        let for_system = entry.for_system();
                        block.call((
                            std::ptr::from_ref(for_system).cast_mut(),
                            std::ptr::null_mut(),
                        ));
                    }
                    Err(reason) => {
                        let error = reason.as_nserror();
                        block.call((std::ptr::null_mut(), Retained::as_ptr(&error).cast_mut()));
                    }
                }
            });
            progress
        }

        #[unsafe(method_id(fetchContentsForItemWithIdentifier:version:request:completionHandler:))]
        fn content_for(
            &self,
            identifier: &NSString,
            _version: Option<&NSFileProviderItemVersion>,
            request: &NSFileProviderRequest,
            finished: &DynBlock<dyn Fn(*mut NSURL, *mut NSFileProviderItem, *mut NSError)>,
        ) -> Retained<NSProgress> {
            // Only the engine knows the total; until then the bar is indeterminate.
            let progress = progress(-1);
            let context = Arc::clone(&self.ivars().context);
            let text = identifier.to_string();
            let request = content_request(request);
            // The staging folder is asked for here, on the system's thread: it is a local call
            // without the network, and an error should take the same route as every other.
            let storage = self.staging();
            // SAFETY: as in `entry_for`.
            let finished = unsafe { ThreadFixed::new(finished.copy()) };
            let sink_progress = Retained::clone(&progress);
            in_background("edms-content", move || {
                let result = storage.and_then(|folder| {
                    load_content(&context, &folder, &text, &request, sink_progress)
                });
                let block = finished.into_value();
                match result {
                    Ok((path, entry)) => {
                        let location =
                            NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()));
                        let for_system = entry.for_system();
                        block.call((
                            Retained::as_ptr(&location).cast_mut(),
                            std::ptr::from_ref(for_system).cast_mut(),
                            std::ptr::null_mut(),
                        ));
                    }
                    Err(reason) => {
                        let error = reason.as_nserror();
                        block.call((
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            Retained::as_ptr(&error).cast_mut(),
                        ));
                    }
                }
            });
            progress
        }

        /// Creating inside the mirror: refused for good (requirement 1, and the module header
        /// for the mail basket).
        #[unsafe(method_id(createItemBasedOnTemplate:fields:contents:options:request:completionHandler:))]
        fn create(
            &self,
            _template: &NSFileProviderItem,
            _field: NSFileProviderItemFields,
            _content: Option<&NSURL>,
            _choice: NSFileProviderCreateItemOptions,
            _request: &NSFileProviderRequest,
            finished: &DynBlock<
                dyn Fn(*mut NSFileProviderItem, NSFileProviderItemFields, Bool, *mut NSError),
            >,
        ) -> Retained<NSProgress> {
            reject(finished, &ProviderError::ReadOnly)
        }

        /// Changing inside the mirror: refused for good (requirement 1).
        #[unsafe(method_id(modifyItem:baseVersion:changedFields:contents:options:request:completionHandler:))]
        fn change(
            &self,
            _entry: &NSFileProviderItem,
            _version: &NSFileProviderItemVersion,
            _field: NSFileProviderItemFields,
            _content: Option<&NSURL>,
            _choice: NSFileProviderModifyItemOptions,
            _request: &NSFileProviderRequest,
            finished: &DynBlock<
                dyn Fn(*mut NSFileProviderItem, NSFileProviderItemFields, Bool, *mut NSError),
            >,
        ) -> Retained<NSProgress> {
            reject(finished, &ProviderError::ReadOnly)
        }

        /// Deleting inside the mirror: refused, the system restores the item (requirement 1).
        #[unsafe(method_id(deleteItemWithIdentifier:baseVersion:options:request:completionHandler:))]
        fn delete(
            &self,
            _identifier: &NSString,
            _version: &NSFileProviderItemVersion,
            _choice: NSFileProviderDeleteItemOptions,
            _request: &NSFileProviderRequest,
            finished: &DynBlock<dyn Fn(*mut NSError)>,
        ) -> Retained<NSProgress> {
            let error = ProviderError::DeleteRejected.as_nserror();
            finished.call((Retained::as_ptr(&error).cast_mut(),));
            done_progress()
        }
    }
);

impl EdmsFileProvider {
    /// The folder for staging files of downloaded content.
    fn staging(&self) -> Result<PathBuf, ProviderError> {
        #[cfg(test)]
        if let Some(path) = &self.ivars().staging {
            return Ok(path.clone());
        }
        staging_of_the_domain(&self.ivars().domain)
    }

    /// An instance with a source put in place for good and a staging folder of its own (test
    /// harness).
    ///
    /// The domain is only created, not registered: a test must not change the machine it runs on
    /// (`harness.rs`).
    #[cfg(test)]
    pub(crate) fn for_test(
        source: Arc<dyn edms_core::port::NamespaceSource>,
        display_name: &str,
        staging: Option<PathBuf>,
    ) -> Retained<Self> {
        // SAFETY: -initWithIdentifier:displayName: on a freshly allocated instance; the
        // identifier contains neither '/' nor ':' (NSFileProviderDomain.h).
        let domain = unsafe {
            NSFileProviderDomain::initWithIdentifier_displayName(
                NSFileProviderDomain::alloc(),
                &NSString::from_str("elasticdms-test"),
                &NSString::from_str(display_name),
            )
        };
        let context = Context::new(SourceHolder::fixed(source), display_name.to_owned());
        let this =
            Self::alloc().set_ivars(ProviderData { context: Arc::new(context), domain, staging });
        // SAFETY: -[NSObject init] on the freshly allocated instance whose ivars are set.
        unsafe { msg_send![super(this), init] }
    }
}

/// Registers the principal class in the Objective-C runtime, if that has not happened yet.
///
/// Calling it several times is harmless: `ClassType::class()` registers exactly once.
pub fn place_registration_safe() {
    let _ = EdmsFileProvider::class();
}

/// The constructor dyld calls when the program is loaded (module header).
///
/// `#[used]` holds the pointer against being thrown away by the linker — without it the linker
/// would discard the only reference, and the class would again not be there at load time.
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static REGISTER_ON_LOAD: extern "C" fn() = register_on_load;

extern "C" fn register_on_load() {
    place_registration_safe();
}

/// A cancellable progress over `total` units; `-1` means "not known yet".
///
/// Cancellable, because the system cancels instead of waiting: "The system will call `cancel` on
/// the progress. The extension is then expected to quickly call the completion handler"
/// (NSFileProviderReplicatedExtension.h). The sink asks `isCancelled` on every chunk.
fn progress(total: i64) -> Retained<NSProgress> {
    let progress = NSProgress::discreteProgressWithTotalUnitCount(total);
    progress.setCancellable(true);
    progress
}

/// A progress for an answer already given: finished before the system looks.
fn done_progress() -> Retained<NSProgress> {
    let done = NSProgress::discreteProgressWithTotalUnitCount(1);
    done.setCompletedUnitCount(1);
    done
}

/// Answers a writing request with an error, immediately and without a thread hand-off.
///
/// The empty set of fields means "nothing is still outstanding": with the same fields that came
/// in, from macOS 12 on the system would take those fields for unsupported and never ask again —
/// which would silently be the wrong thing, because refused is not the same as unknown.
fn reject(
    finished: &DynBlock<
        dyn Fn(*mut NSFileProviderItem, NSFileProviderItemFields, Bool, *mut NSError),
    >,
    reason: &ProviderError,
) -> Retained<NSProgress> {
    let error = reason.as_nserror();
    finished.call((
        std::ptr::null_mut(),
        NSFileProviderItemFields::empty(),
        Bool::NO,
        Retained::as_ptr(&error).cast_mut(),
    ));
    done_progress()
}

/// Writes an error into the system's `NSError **` out-parameter.
///
/// Autoreleased, not `+1`: by Cocoa convention
/// `enumeratorForContainerItemIdentifier:request:error:` returns the error unretained; a `+1`
/// pointer there would be a leak per empty folder.
fn report_out_error(output: *mut *mut NSError, reason: &ProviderError) {
    if output.is_null() {
        tracing::warn!(
            %reason,
            "the system asked without an error out-parameter; the reason only goes into the log"
        );
        return;
    }
    // SAFETY: the pointer is not null and, by Cocoa convention, points at a writable `NSError *`
    // of the caller that lives for the duration of the call.
    unsafe { *output = Retained::autorelease_ptr(reason.as_nserror()) };
}

/// Who wants the content, as far as the system says.
///
/// `requestingExecutable` is "always nil unless both an MDM profile key is set"
/// (NSFileProviderRequest.h); without MDM the field stays empty, and the server sees "user X
/// downloaded" without a program. Only the file name travels along, never the path: the path
/// carries the user name (`port.rs`, `ContentRequest`).
fn content_request(request: &NSFileProviderRequest) -> ContentRequest {
    // SAFETY: a read-only property of a request delivered by the system.
    let program = unsafe { request.requestingExecutable() };
    ContentRequest {
        requesting_application: program
            .and_then(|location| location.to_file_path())
            .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned())),
    }
}

/// The staging folder of the domain, per `-[NSFileProviderManager temporaryDirectoryURLWithError:]`.
///
/// The system demands the staging file on **the same volume** as the visible location; a `/tmp`
/// path of our own choosing would make the cloning fail (NSFileProviderReplicatedExtension.h,
/// "File ownership").
fn staging_of_the_domain(domain: &NSFileProviderDomain) -> Result<PathBuf, ProviderError> {
    // SAFETY: managerForDomain: with a domain delivered by the system.
    let manager = unsafe { NSFileProviderManager::managerForDomain(domain) }.ok_or_else(|| {
        // SAFETY: a read-only property of a domain.
        let identifier = unsafe { domain.identifier() };
        ProviderError::Staging(format!("macOS provides no manager for the domain `{identifier}`"))
    })?;
    // SAFETY: a read-only call on the manager of our own domain.
    let location = unsafe { manager.temporaryDirectoryURLWithError() }
        .map_err(|error| ProviderError::Staging(error.localizedDescription().to_string()))?;
    location.to_file_path().ok_or_else(|| {
        ProviderError::Staging(format!(
            "`{}` is not a file path",
            location.absoluteString().unwrap_or_default()
        ))
    })
}

/// A single item, the way `itemForIdentifier:` answers it.
fn read_entry(context: &Context, text: &str) -> Result<Retained<EdmsEntry>, ProviderError> {
    let identifiers = context.identifiers();
    match identifiers.target(text)? {
        Target::Root => Ok(EdmsEntry::root(context.display_name(), identifiers)),
        Target::Entry(identifier) => {
            let entry = context.ask(|source| Ok(source.entry(identifier)?))?;
            Ok(EdmsEntry::from_entry(entry, identifiers))
        }
        Target::Trash => Err(ProviderError::NoTrash),
        // The working set is a change channel, not an item on disk; the extension never hands
        // out its identifier as an item, so here it is a foreign one.
        Target::WorkingSet => Err(ProviderError::ForeignIdentifier(text.to_owned())),
    }
}

/// Downloads the content into a staging file and hands it out together with the item.
///
/// The core's guarantee holds: the source only writes into the sink once the checksum matches
/// (`port.rs`). If anything fails after that, the half-written staging file is removed — the system
/// should never clone an incomplete file into the user's folder.
fn load_content(
    context: &Context,
    folder: &Path,
    text: &str,
    request: &ContentRequest,
    progress: Retained<NSProgress>,
) -> Result<(PathBuf, Retained<EdmsEntry>), ProviderError> {
    let identifiers = context.identifiers();
    let identifier = match identifiers.target(text)? {
        Target::Entry(identifier) => identifier,
        Target::Root => return Err(ProviderError::NoFile(EntryIdentifier::ROOT)),
        Target::Trash => return Err(ProviderError::NoTrash),
        Target::WorkingSet => return Err(ProviderError::ForeignIdentifier(text.to_owned())),
    };
    let entry = context.ask(|source| Ok(source.entry(identifier)?))?;
    if entry.is_folder() {
        return Err(ProviderError::NoFile(identifier));
    }
    clear_once(folder);
    let (file, path) = new_staging_file(folder)?;
    let result = write_content(context, identifier, request, file, progress);
    match result {
        Ok(()) => Ok((path, EdmsEntry::from_entry(entry, identifiers))),
        Err(reason) => {
            if let Err(error) = fs::remove_file(&path) {
                tracing::warn!(file = %path.display(), %error, "staging file not removed");
            }
            Err(reason)
        }
    }
}

/// Writes the verified content into the staging file that has already been created.
fn write_content(
    context: &Context,
    identifier: EntryIdentifier,
    request: &ContentRequest,
    file: File,
    progress: Retained<NSProgress>,
) -> Result<(), ProviderError> {
    let cancel_guard = Retained::clone(&progress);
    let mut sink = FileSink::new(file, Some(progress));
    let receipt = context.ask(|source| Ok(source.content(identifier, request, &mut sink)?))?;
    sink.complete()?;
    if cancel_guard.isCancelled() {
        return Err(ProviderError::Cancelled);
    }
    // The engine says how much it handed over; the sink counts what arrived. If the two differ,
    // the staging file would be shorter than the placeholder promises — and Finder would show a
    // file that looks different on disk from what stands in the listing.
    if receipt.size != sink.written() {
        return Err(
            SourceError::Incomplete { expected: receipt.size, actual: sink.written() }.into()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::AnyProtocol;
    use objc2_file_provider::{
        NSFileProviderEnumerationObserver, NSFileProviderInitialPageSortedByName,
        NSFileProviderItemProtocol,
    };
    use objc2_foundation::NSData;

    use super::*;
    use crate::harness::{
        CONTENT_10, Event, MockSource, PageObserver, case_file_1, document_10, sample_source,
    };
    use crate::identifier::SystemIdentifiers;

    /// What a completion block saw: the item's name, or domain and code of the error.
    type Response = Result<String, (String, isize)>;

    fn provider(source: MockSource) -> Retained<EdmsFileProvider> {
        EdmsFileProvider::for_test(Arc::new(source), "elasticdms – test harness", None)
    }

    fn provider_with_store(source: MockSource, folder: PathBuf) -> Retained<EdmsFileProvider> {
        EdmsFileProvider::for_test(Arc::new(source), "elasticdms – test harness", Some(folder))
    }

    fn as_extension(
        provider: &EdmsFileProvider,
    ) -> &ProtocolObject<dyn NSFileProviderReplicatedExtension> {
        ProtocolObject::from_ref(provider)
    }

    fn request() -> Retained<NSFileProviderRequest> {
        // SAFETY: -[NSFileProviderRequest new] creates an empty request object; the only thing
        // read from it is `requestingExecutable`, which is then nil.
        unsafe { NSFileProviderRequest::new() }
    }

    fn error_image(error: *mut NSError) -> (String, isize) {
        // SAFETY: the system passes nil or a valid NSError; here the test harness is calling.
        let error = unsafe { error.as_ref() }.expect("an NSError");
        (error.domain().to_string(), error.code())
    }

    fn name(item: *mut NSFileProviderItem) -> String {
        // SAFETY: not nil, and the extension passes an EdmsEntry.
        let item = unsafe { item.as_ref() }.expect("an item");
        // SAFETY: filename is mandatory on every NSFileProviderItem.
        unsafe { item.filename() }.to_string()
    }

    fn entry_for(provider: &EdmsFileProvider, identifier: &str) -> Response {
        let (tx, rx) = mpsc::channel();
        let block = RcBlock::new(move |item: *mut NSFileProviderItem, error: *mut NSError| {
            let response = if error.is_null() { Ok(name(item)) } else { Err(error_image(error)) };
            let _ = tx.send(response);
        });
        // SAFETY: a call through the protocol object, exactly as the system makes it.
        let _progress = unsafe {
            as_extension(provider).itemForIdentifier_request_completionHandler(
                &NSString::from_str(identifier),
                &request(),
                &block,
            )
        };
        rx.recv_timeout(Duration::from_secs(10)).expect("the completion block")
    }

    #[test]
    fn the_class_carries_both_protocols_and_is_named_the_way_the_bundle_names_it() {
        assert_eq!(PRINCIPAL_CLASS, EdmsFileProvider::class().name().to_str().expect("ASCII"));
        for log in ["NSFileProviderReplicatedExtension", "NSFileProviderEnumerating"] {
            let name = std::ffi::CString::new(log).expect("without a null byte");
            let p = AnyProtocol::get(&name).expect("protocol known");
            assert!(EdmsFileProvider::class().conforms_to(p), "{log}");
        }
    }

    #[test]
    fn the_name_of_the_principal_class_stands_in_the_bundle_exactly_as_in_the_code() {
        // The name travels through the Objective-C runtime: the system reads it out of the
        // Info.plist and looks the class up with it. A typo on either side would otherwise only
        // show up as an empty Finder folder — without an error message, because PlugInKit says
        // nothing about it.
        let plist = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/macos/elasticdms-fileprovider-Info.plist");
        let text =
            std::fs::read_to_string(&plist).unwrap_or_else(|f| panic!("{}: {f}", plist.display()));
        assert!(
            text.contains(&format!("<string>{PRINCIPAL_CLASS}</string>")),
            "{} does not name {PRINCIPAL_CLASS}",
            plist.display()
        );
    }

    #[test]
    fn the_root_is_named_after_the_domain_without_the_source_being_asked() {
        let source = sample_source();
        let provider = provider(source);
        let k = SystemIdentifiers::of_the_system();
        assert_eq!(entry_for(&provider, &k.root), Ok("elasticdms – test harness".to_owned()));
    }

    #[test]
    fn a_document_comes_from_the_source_and_carries_its_file_name() {
        let provider = provider(sample_source());
        let response = entry_for(&provider, &document_10().to_string());
        assert_eq!(response, Ok("Prüfbericht Pumpe 7.pdf".to_owned()));
    }

    #[test]
    fn a_foreign_identifier_and_the_trash_each_get_their_own_error() {
        let provider = provider(sample_source());
        let k = SystemIdentifiers::of_the_system();
        assert_eq!(
            entry_for(&provider, "root"),
            Err(("NSFileProviderErrorDomain".to_owned(), -1005))
        );
        assert_eq!(entry_for(&provider, &k.trash), Err(("NSCocoaErrorDomain".to_owned(), 3328)));
        assert_eq!(
            entry_for(&provider, &k.working_set),
            Err(("NSFileProviderErrorDomain".to_owned(), -1005))
        );
    }

    #[test]
    fn a_device_that_is_not_signed_in_makes_the_system_wait_instead_of_deleting() {
        let mut source = sample_source();
        source.every_call_fails = Some(SourceError::NotSignedIn);
        let provider = provider(source);
        assert_eq!(
            entry_for(&provider, &document_10().to_string()),
            Err(("NSFileProviderErrorDomain".to_owned(), -1000))
        );
    }

    #[test]
    fn the_enumerator_of_a_case_file_reports_its_documents_to_the_observer() {
        let provider = provider(sample_source());
        let identifier = NSString::from_str(&case_file_1().to_string());
        // SAFETY: a call through the protocol object, exactly as the system makes it.
        let enumerator = unsafe {
            as_extension(&provider)
                .enumeratorForContainerItemIdentifier_request_error(&identifier, &request())
        }
        .expect("an enumerator");
        let observer = PageObserver::new(50);
        let for_system: &ProtocolObject<dyn NSFileProviderEnumerationObserver> =
            ProtocolObject::from_ref(&*observer);
        // SAFETY: NSFileProviderInitialPageSortedByName is an exported constant.
        let first_page: &NSData = unsafe { NSFileProviderInitialPageSortedByName };
        // SAFETY: a call through the protocol object, exactly as the system makes it.
        unsafe { enumerator.enumerateItemsForObserver_startingAtPage(for_system, first_page) };
        let events = observer.transcript().wait_on_completion();
        let names: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                Event::Entries(seen) => Some(seen.iter().map(|g| g.name.clone())),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(names.len(), 3, "{events:?}");
        assert!(names.contains(&"Prüfbericht Pumpe 7.pdf".to_owned()), "{names:?}");
        assert_eq!(events.last(), Some(&Event::PageFinished(None)));
    }

    #[test]
    fn the_trash_gets_no_enumerator_but_the_error_in_the_out_parameter() {
        let provider = provider(sample_source());
        let identifier = NSString::from_str(&SystemIdentifiers::of_the_system().trash);
        // SAFETY: as above.
        let result = unsafe {
            as_extension(&provider)
                .enumeratorForContainerItemIdentifier_request_error(&identifier, &request())
        };
        let error = result.expect_err("an error");
        assert_eq!(
            (error.domain().to_string(), error.code()),
            ("NSCocoaErrorDomain".to_owned(), 3328)
        );
    }

    #[test]
    fn creating_and_changing_are_refused_for_good() {
        let provider = provider(sample_source());
        let k = SystemIdentifiers::of_the_system();
        let template = EdmsEntry::root("elasticdms", k);
        for creating in [true, false] {
            let (tx, rx) = mpsc::channel();
            let block = RcBlock::new(
                move |_item: *mut NSFileProviderItem,
                      open: NSFileProviderItemFields,
                      _again: Bool,
                      error: *mut NSError| {
                    let _ = tx.send((error_image(error), open));
                },
            );
            // SAFETY: calls through the protocol object, exactly as the system makes them.
            unsafe {
                if creating {
                    as_extension(&provider)
                        .createItemBasedOnTemplate_fields_contents_options_request_completionHandler(
                            template.for_system(),
                            NSFileProviderItemFields::empty(),
                            None,
                            NSFileProviderCreateItemOptions::empty(),
                            &request(),
                            &block,
                        );
                } else {
                    let version = template.for_system().itemVersion();
                    as_extension(&provider)
                        .modifyItem_baseVersion_changedFields_contents_options_request_completionHandler(
                            template.for_system(),
                            &version,
                            NSFileProviderItemFields::Filename,
                            None,
                            NSFileProviderModifyItemOptions::empty(),
                            &request(),
                            &block,
                        );
                }
            }
            let (image, open) = rx.recv_timeout(Duration::from_secs(5)).expect("an answer");
            assert_eq!(image, ("NSFileProviderErrorDomain".to_owned(), -2005));
            assert_eq!(open, NSFileProviderItemFields::empty(), "refused is not unknown");
        }
    }

    #[test]
    fn deleting_is_refused_and_the_system_restores_the_item() {
        let provider = provider(sample_source());
        let template = EdmsEntry::root("elasticdms", SystemIdentifiers::of_the_system());
        let (tx, rx) = mpsc::channel();
        let block = RcBlock::new(move |error: *mut NSError| {
            let _ = tx.send(error_image(error));
        });
        // SAFETY: a call through the protocol object, exactly as the system makes it.
        unsafe {
            let version = template.for_system().itemVersion();
            as_extension(&provider)
                .deleteItemWithIdentifier_baseVersion_options_request_completionHandler(
                    &NSString::from_str(&document_10().to_string()),
                    &version,
                    NSFileProviderDeleteItemOptions::empty(),
                    &request(),
                    &block,
                );
        }
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).expect("an answer"),
            ("NSFileProviderErrorDomain".to_owned(), -1006)
        );
    }

    #[test]
    fn downloaded_content_lands_complete_in_a_staging_file() {
        let folder = std::env::temp_dir().join(format!("edms-content-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).expect("the folder");
        let provider = provider_with_store(sample_source(), folder.clone());
        let (tx, rx) = mpsc::channel();
        let block = RcBlock::new(
            move |location: *mut NSURL, item: *mut NSFileProviderItem, error: *mut NSError| {
                let response = if error.is_null() {
                    // SAFETY: not nil when no error is reported.
                    let location = unsafe { location.as_ref() }.expect("a location");
                    Ok((location.to_file_path().expect("a file path"), name(item)))
                } else {
                    Err(error_image(error))
                };
                let _ = tx.send(response);
            },
        );
        // SAFETY: a call through the protocol object, exactly as the system makes it.
        let _progress = unsafe {
            as_extension(&provider)
                .fetchContentsForItemWithIdentifier_version_request_completionHandler(
                    &NSString::from_str(&document_10().to_string()),
                    None,
                    &request(),
                    &block,
                )
        };
        let (path, filename) =
            rx.recv_timeout(Duration::from_secs(10)).expect("an answer").expect("the content");
        assert_eq!(filename, "Prüfbericht Pumpe 7.pdf");
        assert_eq!(std::fs::read(&path).expect("the staging file"), CONTENT_10);
        assert!(path.starts_with(&folder), "{}", path.display());
        std::fs::remove_dir_all(&folder).expect("tidied up");
    }

    #[test]
    fn a_folder_has_no_content_and_a_failed_download_leaves_no_file_behind() {
        let folder =
            std::env::temp_dir().join(format!("edms-content-error-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).expect("the folder");
        let mut source = sample_source();
        source.content_error = Some(SourceError::NoAccess);
        let provider = provider_with_store(source, folder.clone());
        let fetch = |identifier: String| -> (String, isize) {
            let (tx, rx) = mpsc::channel();
            let block = RcBlock::new(
                move |_location: *mut NSURL,
                      _item: *mut NSFileProviderItem,
                      error: *mut NSError| {
                    let _ = tx.send(error_image(error));
                },
            );
            // SAFETY: a call through the protocol object, exactly as the system makes it.
            let _progress = unsafe {
                as_extension(&provider)
                    .fetchContentsForItemWithIdentifier_version_request_completionHandler(
                        &NSString::from_str(&identifier),
                        None,
                        &request(),
                        &block,
                    )
            };
            rx.recv_timeout(Duration::from_secs(10)).expect("an answer")
        };
        assert_eq!(fetch(case_file_1().to_string()), ("NSCocoaErrorDomain".to_owned(), 256));
        assert_eq!(fetch(document_10().to_string()), ("NSCocoaErrorDomain".to_owned(), 257));
        let left_behind: Vec<_> = std::fs::read_dir(&folder)
            .expect("readable")
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(left_behind.is_empty(), "{left_behind:?}");
        std::fs::remove_dir_all(&folder).expect("tidied up");
    }
}
