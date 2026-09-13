//! Where every entry lies: entry identifier → name and parent container.
//!
//! The engine gives orders by identifier ("dehydrate `cas_…/doc_…`"), Windows works by path. For
//! every entry the map remembers only its own name and its parent container; it assembles the path
//! from the chain when asked. That is why renaming a case file (Akte) carries all the documents in
//! it along, without a single one of their entries being touched.
//!
//! Populated means: Windows has fetched the listing of this container (`FETCH_PLACEHOLDERS`) and
//! has not asked again since. Only in populated containers does `report_change` create and delete
//! by itself; the others fetch the listing the next time they are opened (`edms_core::port`).

use std::collections::{HashMap, HashSet};

use edms_core::filename::comparison_form;
use edms_core::namespace::{Container, EntryIdentifier};

use crate::path::{SEPARATOR, connect};

/// Where an entry lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The parent container (follows from the identifier).
    pub parent: Container,
    /// The name on disk.
    pub name: String,
    /// Folder or file.
    pub folder: bool,
}

/// The map.
#[derive(Debug, Clone, Default)]
pub struct PathMap {
    locations: HashMap<EntryIdentifier, Location>,
    populated: HashSet<Container>,
}

/// The tree goes no deeper than root → archives → archive → case file (Akte) → document; the limit
/// only catches a bug that built a cycle.
const MAX_DEPTH: usize = 8;

impl PathMap {
    /// Enters an entry or overwrites it. The root has no location (`false`).
    pub fn set(&mut self, identifier: EntryIdentifier, name: &str, folder: bool) -> bool {
        let Some(parent) = identifier.parent() else {
            return false;
        };
        self.locations.insert(identifier, Location { parent, name: name.to_owned(), folder });
        true
    }

    /// The location of an entry.
    pub fn location(&self, identifier: EntryIdentifier) -> Option<&Location> {
        self.locations.get(&identifier)
    }

    /// Whether the entry is known.
    pub fn knows(&self, identifier: EntryIdentifier) -> bool {
        self.locations.contains_key(&identifier)
    }

    /// The path relative to the root (`""` for the root); `None` if a link of the chain is missing.
    pub fn path(&self, identifier: EntryIdentifier) -> Option<String> {
        let mut parts = Vec::new();
        let mut k = identifier;
        while k != EntryIdentifier::ROOT {
            if parts.len() >= MAX_DEPTH {
                return None;
            }
            let location = self.locations.get(&k)?;
            parts.push(location.name.as_str());
            k = EntryIdentifier::Container(location.parent);
        }
        Some(parts.iter().rev().fold(String::new(), |path, part| connect(&path, part)))
    }

    /// The path of a container.
    pub fn container_path(&self, container: Container) -> Option<String> {
        self.path(EntryIdentifier::Container(container))
    }

    /// The container that lies at this path relative to the root (`""` is the root itself).
    ///
    /// The other way round from [`PathMap::path`], and the way a callback needs it: cldflt names a
    /// path, and what may happen there follows from the container it lies in
    /// ([`Container::accepts_new_files`]). Descended segment by segment, the way NTFS compares
    /// names — a path whose chain breaks off anywhere is `None`, never the container above it.
    pub fn container_at(&self, relative: &str) -> Option<Container> {
        let mut container = Container::Root;
        for part in relative.split(SEPARATOR).filter(|part| !part.is_empty()) {
            container = self.search_name(container, part)?.container()?;
        }
        Some(container)
    }

    /// Sets the name of a known entry; `false` if it is unknown.
    pub fn rename(&mut self, identifier: EntryIdentifier, name: &str) -> bool {
        match self.locations.get_mut(&identifier) {
            Some(location) => {
                name.clone_into(&mut location.name);
                true
            }
            None => false,
        }
    }

    /// The known children of a container, in order.
    pub fn children(&self, container: Container) -> Vec<EntryIdentifier> {
        let mut children: Vec<EntryIdentifier> =
            self.locations.iter().filter(|(_, o)| o.parent == container).map(|(k, _)| *k).collect();
        children.sort();
        children
    }

    /// Every container the map knows, in order.
    ///
    /// The root is not among them: it has no location and came into being through
    /// `CfRegisterSyncRoot`, not as an entry of a listing.
    pub fn containers(&self) -> Vec<Container> {
        let mut containers: Vec<Container> =
            self.locations.keys().filter_map(|k| k.container()).collect();
        containers.sort();
        containers
    }

    /// The child with this name, compared the way NTFS compares (case-insensitive, NFC).
    pub fn search_name(&self, container: Container, name: &str) -> Option<EntryIdentifier> {
        let wanted = comparison_form(name);
        self.locations
            .iter()
            .find(|(_, o)| o.parent == container && comparison_form(&o.name) == wanted)
            .map(|(k, _)| *k)
    }

    /// Removes an entry together with everything below it; returns the identifiers removed.
    ///
    /// A removed container also loses its populated mark: if the server creates it again later,
    /// Windows has to fetch the listing afresh instead of trusting an old one.
    pub fn remove(&mut self, identifier: EntryIdentifier) -> Vec<EntryIdentifier> {
        let mut removed = Vec::new();
        let mut open = vec![identifier];
        while let Some(k) = open.pop() {
            if self.locations.remove(&k).is_some() {
                removed.push(k);
            }
            if let Some(b) = k.container() {
                self.populated.remove(&b);
                let children: Vec<EntryIdentifier> =
                    self.locations.iter().filter(|(_, o)| o.parent == b).map(|(k, _)| *k).collect();
                open.extend(children);
            }
        }
        removed.sort();
        removed
    }

    /// Remembers that Windows has fetched the listing of this container.
    pub fn mark_populated(&mut self, container: Container) {
        self.populated.insert(container);
    }

    /// Whether Windows has fetched the listing.
    pub fn is_populated(&self, container: Container) -> bool {
        self.populated.contains(&container)
    }

    /// Forgets the populated mark (the container fetches afresh the next time it is opened).
    pub fn forget_population(&mut self, container: Container) {
        self.populated.remove(&container);
    }

    /// How many entries are known.
    pub fn count(&self) -> usize {
        self.locations.len()
    }

    /// Forgets everything.
    pub fn empty(&mut self) {
        self.locations.clear();
        self.populated.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::Identifier;
    use edms_core::namespace::{HintKind, Location};

    /// The one archive of these tests; a case file carries it (namespace v2 §1).
    fn archive() -> Container {
        Container::Archive(Identifier::from_value(1))
    }

    fn case(w: u128) -> Container {
        Container::Case { archive: Identifier::from_value(1), case: Identifier::from_value(w) }
    }

    fn doc(case_w: u128, w: u128) -> EntryIdentifier {
        EntryIdentifier::Document {
            location: Location::Case {
                archive: Identifier::from_value(1),
                case: Identifier::from_value(case_w),
            },
            document: Identifier::from_value(w),
        }
    }

    fn example() -> PathMap {
        let mut k = PathMap::default();
        k.set(EntryIdentifier::Container(Container::Archives), "Archive", true);
        k.set(EntryIdentifier::Container(archive()), "Zentralarchiv", true);
        k.set(EntryIdentifier::Container(case(1)), "Sulzer", true);
        k.set(doc(1, 10), "Prüfbericht.pdf", false);
        k.set(
            EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe },
            "LIESMICH.txt",
            false,
        );
        k
    }

    #[test]
    fn the_path_follows_from_the_chain() {
        let k = example();
        assert_eq!(k.path(EntryIdentifier::ROOT).as_deref(), Some(""));
        assert_eq!(
            k.path(doc(1, 10)).as_deref(),
            Some(r"Archive\Zentralarchiv\Sulzer\Prüfbericht.pdf")
        );
        assert_eq!(
            k.path(EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe })
                .as_deref(),
            Some("LIESMICH.txt")
        );
    }

    #[test]
    fn without_a_parent_link_there_is_no_path() {
        let mut k = PathMap::default();
        k.set(doc(1, 10), "a.pdf", false);
        assert_eq!(
            k.path(doc(1, 10)),
            None,
            "the case file (Akte) is missing; a guessed path would be wrong"
        );
    }

    #[test]
    fn a_renamed_case_file_takes_its_documents_along() {
        let mut k = example();
        assert!(k.rename(EntryIdentifier::Container(case(1)), "Sulzer Pumpen"));
        assert_eq!(
            k.path(doc(1, 10)).as_deref(),
            Some(r"Archive\Zentralarchiv\Sulzer Pumpen\Prüfbericht.pdf")
        );
        assert!(!k.rename(doc(9, 9), "x"));
    }

    #[test]
    fn the_root_has_no_location() {
        let mut k = PathMap::default();
        assert!(!k.set(EntryIdentifier::ROOT, "x", true));
        assert_eq!(k.count(), 0);
    }

    #[test]
    fn removing_takes_everything_below_and_the_populated_mark_with_it() {
        let mut k = example();
        k.mark_populated(case(1));
        k.mark_populated(archive());
        let route = k.remove(EntryIdentifier::Container(case(1)));
        assert_eq!(route.len(), 2);
        assert!(!k.knows(doc(1, 10)));
        assert!(!k.is_populated(case(1)));
        assert!(k.is_populated(archive()), "the parent container stays populated");
        assert!(k.knows(EntryIdentifier::Container(archive())));
    }

    #[test]
    fn names_are_looked_up_the_way_ntfs_does() {
        let k = example();
        assert_eq!(k.search_name(case(1), "PRÜFBERICHT.PDF"), Some(doc(1, 10)));
        assert_eq!(
            k.search_name(case(1), "Pru\u{0308}fbericht.pdf"),
            Some(doc(1, 10)),
            "NFD is the same name"
        );
        assert_eq!(k.search_name(case(2), "Prüfbericht.pdf"), None);
        assert_eq!(k.children(case(1)), vec![doc(1, 10)]);
    }

    #[test]
    fn a_path_finds_the_container_it_stands_for() {
        let k = example();
        assert_eq!(k.container_at(""), Some(Container::Root));
        assert_eq!(k.container_at("Archive"), Some(Container::Archives));
        assert_eq!(k.container_at(r"archive\ZENTRALARCHIV"), Some(archive()));
        assert_eq!(k.container_at(r"Archive\Zentralarchiv\Sulzer"), Some(case(1)));
    }

    #[test]
    fn a_path_that_is_no_container_yields_none_not_the_one_above_it() {
        let k = example();
        // A document is no container, and neither is a name nobody knows — and answering with the
        // folder above it would let a callback decide about the wrong place.
        assert_eq!(k.container_at(r"Archive\Zentralarchiv\Sulzer\Prüfbericht.pdf"), None);
        assert_eq!(k.container_at(r"Archive\Fremd"), None);
        assert_eq!(k.container_at(r"Archive\Fremd\Sulzer"), None);
        assert_eq!(k.container_at("LIESMICH.txt"), None);
    }

    #[test]
    fn the_containers_are_the_entries_that_hold_something() {
        let k = example();
        assert_eq!(k.containers(), vec![Container::Archives, archive(), case(1)]);
        assert!(PathMap::default().containers().is_empty(), "the root has no location");
    }
}
