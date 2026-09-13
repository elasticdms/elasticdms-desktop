//! Identifiers between the core and File Provider.
//!
//! The core knows [`EntryIdentifier`] with its text form (`baskets`, `bsk_…`, `archives`,
//! `arc_…`, `arc_…/cas_…`, `arc_…/cas_…/doc_…`, `searches`, `srch_…`, `srch_…/doc_…`,
//! `namespace.rs`). File Provider knows `NSFileProviderItemIdentifier` — a string that the system
//! writes into its database and hands back unchanged on every request. The mapping is the core's
//! text form, with **one** exception: to the system the root is called
//! `NSFileProviderRootContainerItemIdentifier`. If the extension gave it the core text `root`,
//! there would, for the system, be a second folder called root underneath the root.
//!
//! On top of that come two identifiers that exist only on the system's side: the working set, the
//! only change channel of a replicated provider (NSFileProviderManager.h), and the trash, which a
//! read-only mirror does not have.
//!
//! **Strict when reading.** An identifier this extension has never handed out is `NoSuchItem` —
//! including the core text `root`, because it never hands that out. Were it lenient here, there
//! would be two identifiers for the same folder, and the system would take them for two.

use std::sync::OnceLock;

use edms_core::namespace::{Container, EntryIdentifier};
use objc2_file_provider::{
    NSFileProviderRootContainerItemIdentifier, NSFileProviderTrashContainerItemIdentifier,
    NSFileProviderWorkingSetContainerItemIdentifier,
};

use crate::error::ProviderError;

/// What an identifier of the system points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `NSFileProviderRootContainerItemIdentifier` — the root of the mirror.
    Root,
    /// `NSFileProviderWorkingSetContainerItemIdentifier` — the change channel.
    WorkingSet,
    /// `NSFileProviderTrashContainerItemIdentifier` — does not exist in a read-only mirror.
    Trash,
    /// An entry of the core, never the root.
    Entry(EntryIdentifier),
}

/// The three identifiers the system prescribes, as text.
///
/// Read from the framework's exported constants, not copied out: the value is Apple's business,
/// and a copied value would only hold until Apple changes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemIdentifiers {
    /// Text of `NSFileProviderRootContainerItemIdentifier`.
    pub root: String,
    /// Text of `NSFileProviderWorkingSetContainerItemIdentifier`.
    pub working_set: String,
    /// Text of `NSFileProviderTrashContainerItemIdentifier`.
    pub trash: String,
}

impl SystemIdentifiers {
    /// The identifiers of this system, read once.
    pub fn of_the_system() -> &'static SystemIdentifiers {
        static IDENTIFIER: OnceLock<SystemIdentifiers> = OnceLock::new();
        IDENTIFIER.get_or_init(|| {
            // SAFETY: the three names are `FOUNDATION_EXPORT NSFileProviderItemIdentifier const`
            // from FileProvider.framework (NSFileProviderItem.h), present from macOS 11 on;
            // reading an immutable constant initialised by the framework is safe.
            let (root, working_set, trash) = unsafe {
                (
                    NSFileProviderRootContainerItemIdentifier.to_string(),
                    NSFileProviderWorkingSetContainerItemIdentifier.to_string(),
                    NSFileProviderTrashContainerItemIdentifier.to_string(),
                )
            };
            SystemIdentifiers { root, working_set, trash }
        })
    }

    /// Reads an identifier of the system.
    pub fn target(&self, text: &str) -> Result<Target, ProviderError> {
        if text == self.root {
            return Ok(Target::Root);
        }
        if text == self.working_set {
            return Ok(Target::WorkingSet);
        }
        if text == self.trash {
            return Ok(Target::Trash);
        }
        match text.parse::<EntryIdentifier>() {
            // The extension never hands out the core text of the root (module header).
            Ok(identifier) if identifier == EntryIdentifier::ROOT => {
                Err(ProviderError::ForeignIdentifier(text.to_owned()))
            }
            Ok(identifier) => Ok(Target::Entry(identifier)),
            Err(_) => Err(ProviderError::ForeignIdentifier(text.to_owned())),
        }
    }

    /// The identifier under which the system carries an entry.
    pub fn text(&self, identifier: EntryIdentifier) -> String {
        if identifier == EntryIdentifier::ROOT { self.root.clone() } else { identifier.to_string() }
    }

    /// The identifier of the parent folder, for the system.
    ///
    /// The root is its own parent: the system ignores the value there (NSFileProviderItem.h,
    /// `parentItemIdentifier`) but demands one.
    pub fn parent_text(&self, identifier: EntryIdentifier) -> String {
        match identifier.parent() {
            None | Some(Container::Root) => self.root.clone(),
            Some(container) => container.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use edms_core::namespace::{HintKind, Location};

    use super::*;
    use crate::harness::{archive_5, basket_4, case_1, case_file_1, document_10, search_3};

    fn identifiers() -> SystemIdentifiers {
        SystemIdentifiers {
            root: "W".to_owned(),
            working_set: "A".to_owned(),
            trash: "P".to_owned(),
        }
    }

    #[test]
    fn the_system_identifiers_come_from_the_framework() {
        let k = SystemIdentifiers::of_the_system();
        assert_eq!(k.root, "NSFileProviderRootContainerItemIdentifier");
        assert_eq!(k.working_set, "NSFileProviderWorkingSetContainerItemIdentifier");
        assert_eq!(k.trash, "NSFileProviderTrashContainerItemIdentifier");
    }

    #[test]
    fn to_the_system_the_root_is_called_what_the_system_calls_it() {
        let k = identifiers();
        assert_eq!(k.text(EntryIdentifier::ROOT), "W");
        assert_eq!(k.target("W").unwrap(), Target::Root);
        assert_eq!(k.target("A").unwrap(), Target::WorkingSet);
        assert_eq!(k.target("P").unwrap(), Target::Trash);
    }

    #[test]
    fn the_core_text_of_the_root_is_a_foreign_identifier() {
        let error = identifiers().target("root").unwrap_err();
        assert_eq!(error, ProviderError::ForeignIdentifier("root".to_owned()));
    }

    #[test]
    fn an_identifier_that_was_never_handed_out_is_foreign() {
        // `cases` and a bare `cas_…` are the shapes of namespace v1: a case file now hangs under
        // its archive, and reading one of these as an entry would invent a folder (§2).
        for text in [
            "",
            "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
            "archives/nonsense",
            "cas_01jk",
            "cases",
            "cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
        ] {
            assert!(
                matches!(identifiers().target(text), Err(ProviderError::ForeignIdentifier(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn every_entry_identifier_survives_the_round_trip_through_the_system() {
        let k = identifiers();
        let all = [
            EntryIdentifier::Container(Container::Baskets),
            EntryIdentifier::Container(Container::Basket(basket_4())),
            EntryIdentifier::Container(Container::Archives),
            EntryIdentifier::Container(Container::Archive(archive_5())),
            EntryIdentifier::Container(case_file_1()),
            EntryIdentifier::Container(Container::Searches),
            EntryIdentifier::Container(Container::Search(search_3())),
            document_10(),
            EntryIdentifier::Document {
                location: Location::Search(search_3()),
                document: document_10().document().expect("a document"),
            },
            EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe },
        ];
        for identifier in all {
            assert_eq!(k.target(&k.text(identifier)).unwrap(), Target::Entry(identifier));
        }
    }

    #[test]
    fn children_of_the_root_point_at_the_system_root_all_others_at_their_folder() {
        let k = identifiers();
        for top in [Container::Baskets, Container::Archives, Container::Searches] {
            assert_eq!(k.parent_text(EntryIdentifier::Container(top)), "W", "{top}");
        }
        assert_eq!(k.parent_text(EntryIdentifier::ROOT), "W");
        assert_eq!(k.parent_text(document_10()), case_file_1().to_string());
        // A case file names its archive, not the vanished top-level cases folder.
        assert_eq!(
            k.parent_text(EntryIdentifier::Container(case_file_1())),
            Container::Archive(archive_5()).to_string()
        );
        assert_eq!(
            k.parent_text(EntryIdentifier::Container(Container::Basket(basket_4()))),
            "baskets"
        );
        assert_eq!(case_file_1().to_string(), format!("{}/{}", archive_5(), case_1()));
    }
}
