//! An item as the system sees it: `EdmsEntry` implements `NSFileProviderItem`.
//!
//! Here stands what an item says about itself to the system, and every detail has a reason:
//!
//! * **Capabilities: reading only** (for folders also enumerating — the same value, 1 << 0,
//!   NSFileProviderItem.h). No writing, renaming, moving, deleting, trashing: requirement 1, and
//!   capabilities are not inherited, so on every item.
//! * **One exception: a mail basket takes new files.** [`Container::accepts_new_files`] is the
//!   only place that decides where (namespace v2 §3); such a folder carries
//!   `AllowsAddingSubItems` and the w bit, because without them the Finder refuses the drop
//!   before the extension is asked at all. It carries nothing else: no renaming, no deleting, no
//!   writing to what is already there.
//! * **File system flags without `UserWritable`** (everywhere but in a basket) — the second line
//!   of defence: without the w bit Word opens the file read-only instead of accepting a change
//!   that would never arrive. Folders need `UserExecutable`, otherwise one cannot change into
//!   them.
//! * **`contentType` is mandatory** on macOS (NSFileProviderItem.h). It follows the extension of
//!   the file name, which the core derives from the media type anyway
//!   (`filename::extension_for`). If the system knows neither extension nor media type,
//!   `+[UTType typeWithMIMEType:]` returns not `nil` but a **dynamic** type (`dyn.ah62d4…`,
//!   measured) — an identifier that merely encodes the MIME string and stands in no type
//!   database. That one is discarded: `public.data` says the same thing without slipping the
//!   system a type identifier no other program resolves.
//! * **Content policy `DownloadLazilyAndEvictOnRemoteUpdate`** on the root, everything else
//!   inherits: on a new version on the server the local copy is discarded instead of downloaded
//!   again. A download without an open would be an access nobody triggered — and every access
//!   stands in the server's log (requirement "every hydration is an access"; `change.rs`).
//! * **Version**: `contentVersion` is the server's version mark (at most 128 bytes, otherwise its
//!   SHA-256), `metadataVersion` a SHA-256 over name and parent folder.

use edms_core::namespace::{Container, Entry, EntryContent, EntryIdentifier, FileDetails};
use edms_core::time::Timestamp;
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AllocAnyThread, DefinedClass, Message, define_class, msg_send};
use objc2_file_provider::{
    NSFileProviderContentPolicy, NSFileProviderFileSystemFlags, NSFileProviderItem,
    NSFileProviderItemCapabilities, NSFileProviderItemProtocol, NSFileProviderItemVersion,
};
use objc2_foundation::{NSData, NSDate, NSNumber, NSString};
use objc2_uniform_type_identifiers::{UTType, UTTypeData, UTTypeFolder};
use sha2::{Digest, Sha256};

use crate::identifier::SystemIdentifiers;

/// Upper bound per version component (NSFileProviderItem.h, `initWithContentVersion:…`).
pub(crate) const MAX_VERSION_BYTES: usize = 128;

/// Content version of a folder. Folders have no content; their children come through the
/// enumeration, not through the version.
const FOLDER_VERSION: &[u8] = b"folder-1";

/// Name of the root should the domain carry no display name. The name must never be empty
/// (NSFileProviderItem.h, `filename`); it can only be empty for a domain this app did not create —
/// `DomainManagement::add_added` rejects empty names.
const ROOT_FALLBACK_NAME: &str = "elasticdms";

/// The details behind an `EdmsEntry`.
pub(crate) struct EntryData {
    identifier: String,
    parent: String,
    name: String,
    root: bool,
    /// Whether a new file may be created in this folder — the core decides, not this layer.
    takes_new_files: bool,
    file: Option<FileDetails>,
}

define_class!(
    /// An item of the mirror in the shape File Provider demands.
    #[unsafe(super(NSObject))]
    #[name = "EdmsEntry"]
    #[ivars = EntryData]
    pub(crate) struct EdmsEntry;

    unsafe impl NSObjectProtocol for EdmsEntry {}

    unsafe impl NSFileProviderItemProtocol for EdmsEntry {
        #[unsafe(method_id(itemIdentifier))]
        fn system_identifier(&self) -> Retained<NSString> {
            NSString::from_str(&self.ivars().identifier)
        }

        #[unsafe(method_id(parentItemIdentifier))]
        fn parent_identifier(&self) -> Retained<NSString> {
            NSString::from_str(&self.ivars().parent)
        }

        #[unsafe(method_id(filename))]
        fn filename(&self) -> Retained<NSString> {
            NSString::from_str(&self.ivars().name)
        }

        #[unsafe(method_id(contentType))]
        fn content_type(&self) -> Retained<UTType> {
            content_type_for(self.ivars())
        }

        #[unsafe(method(capabilities))]
        fn capability_for_system(&self) -> NSFileProviderItemCapabilities {
            capability(self.ivars().file.is_none(), self.ivars().takes_new_files)
        }

        #[unsafe(method(fileSystemFlags))]
        fn feature_for_system(&self) -> NSFileProviderFileSystemFlags {
            feature(self.ivars().file.is_none(), self.ivars().takes_new_files)
        }

        #[unsafe(method_id(documentSize))]
        fn size(&self) -> Option<Retained<NSNumber>> {
            self.ivars().file.as_ref().map(|d| NSNumber::new_u64(d.size))
        }

        #[unsafe(method_id(creationDate))]
        fn created(&self) -> Option<Retained<NSDate>> {
            self.ivars().file.as_ref().and_then(|d| date(d.created))
        }

        #[unsafe(method_id(contentModificationDate))]
        fn changed(&self) -> Option<Retained<NSDate>> {
            self.ivars().file.as_ref().and_then(|d| date(d.changed))
        }

        #[unsafe(method_id(itemVersion))]
        fn version(&self) -> Retained<NSFileProviderItemVersion> {
            let data = self.ivars();
            let content = NSData::with_bytes(&content_version(data.file.as_ref()));
            let metadata = NSData::with_bytes(&metadata_version(&data.name, &data.parent));
            // SAFETY: -initWithContentVersion:metadataVersion: takes two NSData on a freshly
            // allocated instance; both are at most MAX_VERSION_BYTES long.
            unsafe {
                NSFileProviderItemVersion::initWithContentVersion_metadataVersion(
                    NSFileProviderItemVersion::alloc(),
                    &content,
                    &metadata,
                )
            }
        }

        #[unsafe(method(contentPolicy))]
        fn content_rule(&self) -> NSFileProviderContentPolicy {
            if self.ivars().root {
                NSFileProviderContentPolicy::DownloadLazilyAndEvictOnRemoteUpdate
            } else {
                NSFileProviderContentPolicy::Inherited
            }
        }
    }
);

impl EdmsEntry {
    /// An item built from a core entry.
    pub(crate) fn from_entry(entry: Entry, identifiers: &SystemIdentifiers) -> Retained<Self> {
        let file = match entry.content {
            EntryContent::File(details) => Some(details),
            EntryContent::Folder => None,
        };
        Self::new(EntryData {
            identifier: identifiers.text(entry.identifier),
            parent: identifiers.parent_text(entry.identifier),
            name: entry.name,
            root: entry.identifier == EntryIdentifier::ROOT,
            takes_new_files: entry.identifier.container().is_some_and(Container::accepts_new_files),
            file,
        })
    }

    /// The root; its name is the display name of the domain ("elasticdms – Example GmbH").
    pub(crate) fn root(display_name: &str, identifiers: &SystemIdentifiers) -> Retained<Self> {
        let name = if display_name.trim().is_empty() { ROOT_FALLBACK_NAME } else { display_name };
        Self::new(EntryData {
            identifier: identifiers.root.clone(),
            parent: identifiers.root.clone(),
            name: name.to_owned(),
            root: true,
            takes_new_files: Container::Root.accepts_new_files(),
            file: None,
        })
    }

    fn new(data: EntryData) -> Retained<Self> {
        let this = Self::alloc().set_ivars(data);
        // SAFETY: -[NSObject init] on the freshly allocated instance whose ivars are set.
        unsafe { msg_send![super(this), init] }
    }

    /// The same item as an `id<NSFileProviderItem>`, the way observers and blocks take it.
    pub(crate) fn for_system(&self) -> &NSFileProviderItem {
        ProtocolObject::from_ref(self)
    }
}

fn content_type_for(data: &EntryData) -> Retained<UTType> {
    let Some(details) = data.file.as_ref() else {
        // SAFETY: UTTypeFolder is an exported, immutable constant (UTCoreTypes.h).
        return unsafe { UTTypeFolder }.retain();
    };
    let known = |typ: Retained<UTType>| (!typ.isDynamic()).then_some(typ);
    if let Some(typ) = extension(&data.name)
        .and_then(|e| UTType::typeWithFilenameExtension(&NSString::from_str(e)))
        .and_then(known)
    {
        return typ;
    }
    let base_type = details.media_type.split(';').next().unwrap_or_default().trim();
    if let Some(typ) = UTType::typeWithMIMEType(&NSString::from_str(base_type)).and_then(known) {
        return typ;
    }
    // Not guessed: public.data is the type "data of unknown kind", and that is exactly what it is.
    // SAFETY: UTTypeData is an exported, immutable constant (UTCoreTypes.h).
    unsafe { UTTypeData }.retain()
}

/// The extension of a file name, without the dot; `None` without an extension or for ".hidden".
pub(crate) fn extension(name: &str) -> Option<&str> {
    let (stem, extension) = name.rsplit_once('.')?;
    (!stem.is_empty() && !extension.is_empty()).then_some(extension)
}

/// Reading only; for folders enumerating is the same value, for a mail basket adding as well.
///
/// `AllowsAddingSubItems` **is** `AllowsWriting` (both 1 << 1, NSFileProviderItem.h), just as
/// `AllowsContentEnumerating` is `AllowsReading`: on a folder, writing means putting something
/// into it. So a basket cannot carry the one without the other — and it needs the one.
pub(crate) fn capability(is_folder: bool, takes_new_files: bool) -> NSFileProviderItemCapabilities {
    let mut capability = NSFileProviderItemCapabilities::AllowsReading;
    if is_folder {
        capability |= NSFileProviderItemCapabilities::AllowsContentEnumerating;
    }
    if takes_new_files {
        capability |= NSFileProviderItemCapabilities::AllowsAddingSubItems;
    }
    capability
}

/// Readable, for folders enterable, writable only where a new file may be put (module header).
pub(crate) fn feature(is_folder: bool, takes_new_files: bool) -> NSFileProviderFileSystemFlags {
    let mut feature = NSFileProviderFileSystemFlags::UserReadable;
    if is_folder {
        feature |= NSFileProviderFileSystemFlags::UserExecutable;
    }
    if takes_new_files {
        feature |= NSFileProviderFileSystemFlags::UserWritable;
    }
    feature
}

/// `contentVersion`: the version mark, or its SHA-256 if it is longer than 128 bytes.
pub(crate) fn content_version(file: Option<&FileDetails>) -> Vec<u8> {
    match file {
        None => FOLDER_VERSION.to_vec(),
        Some(d) if d.version.len() <= MAX_VERSION_BYTES => d.version.as_bytes().to_vec(),
        Some(d) => {
            let mut out = b"sha256:".to_vec();
            out.extend_from_slice(&Sha256::digest(d.version.as_bytes()));
            out
        }
    }
}

/// `metadataVersion`: SHA-256 over name and parent identifier, separated by a null byte.
pub(crate) fn metadata_version(name: &str, parent: &str) -> Vec<u8> {
    Sha256::new()
        .chain_update(name.as_bytes())
        .chain_update([0u8])
        .chain_update(parent.as_bytes())
        .finalize()
        .to_vec()
}

/// A timestamp as an `NSDate`; `Timestamp::NULL` means "unknown", not 1970.
fn date(timestamp: Timestamp) -> Option<Retained<NSDate>> {
    (timestamp != Timestamp::NULL)
        .then(|| NSDate::dateWithTimeIntervalSince1970(timestamp.unix_millis() as f64 / 1_000.0))
}

#[cfg(test)]
mod tests {
    use edms_core::namespace::{name_baskets, name_read_me, root_entries};
    use edms_i18n::Language;

    /// The language of the fixtures.
    const LANGUAGE: Language = Language::De;
    use objc2::ClassType;
    use objc2::runtime::AnyProtocol;

    use super::*;
    use crate::harness::{basket_4, case_file_1, document_10, sample_source};

    fn seen(entry: &EdmsEntry) -> &NSFileProviderItem {
        entry.for_system()
    }

    #[test]
    fn to_the_system_the_item_is_an_nsfileprovideritem() {
        let log = AnyProtocol::get(c"NSFileProviderItem").expect("protocol known");
        assert!(EdmsEntry::class().conforms_to(log));
    }

    #[test]
    fn a_document_reports_identifier_parent_name_type_size_and_dates() {
        let k = SystemIdentifiers::of_the_system();
        let source = sample_source();
        let e = EdmsEntry::from_entry(source.entry_to(document_10()), k);
        let item = seen(&e);
        // SAFETY: calls through the protocol object, exactly as the system makes them.
        unsafe {
            assert_eq!(item.itemIdentifier().to_string(), document_10().to_string());
            assert_eq!(item.parentItemIdentifier().to_string(), case_file_1().to_string());
            assert_eq!(item.filename().to_string(), "Prüfbericht Pumpe 7.pdf");
            assert_eq!(item.contentType().identifier().to_string(), "com.adobe.pdf");
            assert_eq!(item.documentSize().map(|n| n.as_u64()), Some(21));
            let created = item.creationDate().expect("a date").timeIntervalSince1970();
            assert!((created - 1_788_334_692.118).abs() < 0.001, "{created}");
            assert!(item.contentModificationDate().is_some());
        }
    }

    #[test]
    fn a_document_may_only_be_read() {
        let e = EdmsEntry::from_entry(
            sample_source().entry_to(document_10()),
            SystemIdentifiers::of_the_system(),
        );
        // SAFETY: as above.
        let (capable, feature) = unsafe { (seen(&e).capabilities(), seen(&e).fileSystemFlags()) };
        assert_eq!(capable, NSFileProviderItemCapabilities::AllowsReading);
        for forbidden in [
            NSFileProviderItemCapabilities::AllowsWriting,
            NSFileProviderItemCapabilities::AllowsRenaming,
            NSFileProviderItemCapabilities::AllowsReparenting,
            NSFileProviderItemCapabilities::AllowsTrashing,
            NSFileProviderItemCapabilities::AllowsDeleting,
        ] {
            assert!(!capable.contains(forbidden), "{forbidden:?}");
        }
        assert_eq!(feature, NSFileProviderFileSystemFlags::UserReadable);
        assert!(!feature.contains(NSFileProviderFileSystemFlags::UserWritable));
    }

    #[test]
    fn a_folder_is_a_folder_enterable_and_just_as_write_protected() {
        let k = SystemIdentifiers::of_the_system();
        let baskets = root_entries(LANGUAGE)
            .into_iter()
            .find(|e| e.name == name_baskets(LANGUAGE))
            .expect("the basket folder");
        let e = EdmsEntry::from_entry(baskets, k);
        // SAFETY: as above.
        unsafe {
            assert_eq!(seen(&e).contentType().identifier().to_string(), "public.folder");
            assert_eq!(seen(&e).parentItemIdentifier().to_string(), k.root);
            assert!(seen(&e).documentSize().is_none());
            assert!(seen(&e).creationDate().is_none());
            let feature = seen(&e).fileSystemFlags();
            assert!(feature.contains(NSFileProviderFileSystemFlags::UserExecutable));
            assert!(!feature.contains(NSFileProviderFileSystemFlags::UserWritable));
            assert!(
                !seen(&e)
                    .capabilities()
                    .contains(NSFileProviderItemCapabilities::AllowsAddingSubItems)
            );
        }
    }

    #[test]
    fn the_root_is_named_after_the_domain_and_evicts_on_a_new_version() {
        let k = SystemIdentifiers::of_the_system();
        let w = EdmsEntry::root("elasticdms – Example GmbH", k);
        let empty = EdmsEntry::root("  ", k);
        // SAFETY: as above.
        unsafe {
            assert_eq!(seen(&w).itemIdentifier().to_string(), k.root);
            assert_eq!(seen(&w).filename().to_string(), "elasticdms – Example GmbH");
            assert_eq!(
                seen(&w).contentPolicy(),
                NSFileProviderContentPolicy::DownloadLazilyAndEvictOnRemoteUpdate
            );
            assert_eq!(seen(&empty).filename().to_string(), ROOT_FALLBACK_NAME);
        }
        let child = EdmsEntry::from_entry(sample_source().entry_to(document_10()), k);
        // SAFETY: as above.
        assert_eq!(unsafe { seen(&child).contentPolicy() }, NSFileProviderContentPolicy::Inherited);
    }

    #[test]
    fn the_hint_has_no_dates_instead_of_1970() {
        let readme = root_entries(LANGUAGE)
            .into_iter()
            .find(|e| e.name == name_read_me(LANGUAGE))
            .expect("the readme");
        let e = EdmsEntry::from_entry(readme, SystemIdentifiers::of_the_system());
        // SAFETY: as above.
        unsafe {
            assert!(seen(&e).creationDate().is_none());
            assert!(seen(&e).contentModificationDate().is_none());
            assert_eq!(seen(&e).contentType().identifier().to_string(), "public.plain-text");
        }
    }

    #[test]
    fn the_content_version_is_the_version_mark_and_stays_under_128_bytes() {
        let source = sample_source();
        let mut details = source.entry_to(document_10()).file().cloned().expect("a file");
        assert_eq!(content_version(Some(&details)), b"1-abc".to_vec());
        let short = content_version(Some(&details));
        details.version = "x".repeat(300);
        let long = content_version(Some(&details));
        assert!(long.len() <= MAX_VERSION_BYTES, "{}", long.len());
        assert_ne!(long, short);
        details.version = "y".repeat(300);
        assert_ne!(
            content_version(Some(&details)),
            long,
            "different long version marks stay different"
        );
        assert_eq!(content_version(None), FOLDER_VERSION.to_vec());
    }

    #[test]
    fn the_metadata_version_follows_name_and_parent_folder() {
        let a = metadata_version("Rechnung.pdf", "cas_1");
        assert!(a.len() <= MAX_VERSION_BYTES);
        assert_eq!(a, metadata_version("Rechnung.pdf", "cas_1"));
        assert_ne!(a, metadata_version("Rechnung 2.pdf", "cas_1"));
        assert_ne!(a, metadata_version("Rechnung.pdf", "cas_2"));
        // The separator keeps name and parent from running into each other.
        assert_ne!(metadata_version("ab", "c"), metadata_version("a", "bc"));
    }

    #[test]
    fn the_version_reaches_the_system_through_nsfileprovideritemversion() {
        let e = EdmsEntry::from_entry(
            sample_source().entry_to(document_10()),
            SystemIdentifiers::of_the_system(),
        );
        // SAFETY: as above.
        let version = unsafe { seen(&e).itemVersion() };
        // SAFETY: read-only properties of an NSFileProviderItemVersion.
        let (content, metadata) =
            unsafe { (version.contentVersion().to_vec(), version.metadataVersion().to_vec()) };
        assert_eq!(content, b"1-abc".to_vec());
        assert_eq!(metadata.len(), 32);
    }

    #[test]
    fn a_file_without_an_extension_gets_its_type_from_the_media_type_else_public_data() {
        assert_eq!(extension("Rechnung.pdf"), Some("pdf"));
        assert_eq!(extension(".hidden"), None);
        assert_eq!(extension("without"), None);
        assert_eq!(extension("dot."), None);
        let mut entry = sample_source().entry_to(document_10());
        entry.name = "Without extension".to_owned();
        let e = EdmsEntry::from_entry(entry.clone(), SystemIdentifiers::of_the_system());
        // SAFETY: as above.
        assert_eq!(unsafe { seen(&e).contentType() }.identifier().to_string(), "com.adobe.pdf");
        if let EntryContent::File(d) = &mut entry.content {
            d.media_type = "application/x-edms-unknown".to_owned();
        }
        let e = EdmsEntry::from_entry(entry, SystemIdentifiers::of_the_system());
        // SAFETY: as above.
        assert_eq!(unsafe { seen(&e).contentType() }.identifier().to_string(), "public.data");
        // Measured: for an unknown media type the system invents a dynamic type instead of
        // returning nil — without the check for `isDynamic` the fallback path would be dead.
        let invented = UTType::typeWithMIMEType(&NSString::from_str("application/x-edms-unknown"))
            .expect("a dynamic type");
        assert!(invented.isDynamic(), "{}", invented.identifier());
    }

    #[test]
    fn only_a_mail_basket_lets_the_finder_put_a_file_into_it() {
        let k = SystemIdentifiers::of_the_system();
        let source = sample_source();
        let basket = source.entry_to(EntryIdentifier::Container(Container::Basket(basket_4())));
        let e = EdmsEntry::from_entry(basket, k);
        // SAFETY: as above.
        let (capable, feature) = unsafe { (seen(&e).capabilities(), seen(&e).fileSystemFlags()) };
        // Without both of these the Finder refuses the drop before the extension is asked.
        assert!(capable.contains(NSFileProviderItemCapabilities::AllowsAddingSubItems));
        assert!(feature.contains(NSFileProviderFileSystemFlags::UserWritable));
        // And nothing beyond putting a file in: namespace v2 §3. `AllowsWriting` is not in the
        // list, because on a folder it is the very same bit as `AllowsAddingSubItems` (1 << 1,
        // NSFileProviderItem.h) — the system offers no way to have the one without the other.
        for forbidden in [
            NSFileProviderItemCapabilities::AllowsRenaming,
            NSFileProviderItemCapabilities::AllowsReparenting,
            NSFileProviderItemCapabilities::AllowsTrashing,
            NSFileProviderItemCapabilities::AllowsDeleting,
        ] {
            assert!(!capable.contains(forbidden), "{forbidden:?}");
        }
        assert_eq!(
            NSFileProviderItemCapabilities::AllowsAddingSubItems,
            NSFileProviderItemCapabilities::AllowsWriting,
            "measured: the two are one bit"
        );
        // The case file in the archive is a folder just like it and stays shut.
        let case = source.entry_to(EntryIdentifier::Container(case_file_1()));
        let e = EdmsEntry::from_entry(case, k);
        // SAFETY: as above.
        let (capable, feature) = unsafe { (seen(&e).capabilities(), seen(&e).fileSystemFlags()) };
        assert!(!capable.contains(NSFileProviderItemCapabilities::AllowsAddingSubItems));
        assert!(!feature.contains(NSFileProviderFileSystemFlags::UserWritable));
    }
}
