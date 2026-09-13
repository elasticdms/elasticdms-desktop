//! What follows on disk from a change list or from a freshly fetched directory listing.
//!
//! Two ways in which the server's state reaches Explorer:
//!
//! 1. **The engine reports changes** ([`plan`]). Only for populated containers; the order is
//!    remove, rename in two stages, update, create. The two stages resolve the cyclic swap (A is
//!    now called what B was called and B what A was called), which `edms_core::change` explicitly
//!    leaves to the platform: first everything renamed gets a staging name, then its new one.
//!    Without that `MoveFileExW` would fail because the target is still occupied.
//! 2. **Windows fetches a listing** (`FETCH_PLACEHOLDERS`, [`reconcile`]). Something may already
//!    be on disk (from an earlier session); which part of it is still correct cannot be checked
//!    inside the callback without opening files in a directory that is being populated right then.
//!    Hence: inside the callback hand over only new entries with a free name, everything else as
//!    follow-up work, as soon as the callback has been answered.

use std::collections::{HashMap, HashSet};

use edms_core::change::Change;
use edms_core::filename::comparison_form;
use edms_core::namespace::{Container, Entry, EntryIdentifier};

use crate::checks::check_name;
use crate::error::MirrorError;
use crate::path_map::PathMap;

/// One step on disk, out of a change from the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Delete an entry (a folder together with its contents), through the exemption list.
    Remove {
        /// Which one.
        identifier: EntryIdentifier,
    },
    /// First stage of a rename.
    StagingName {
        /// Which one.
        identifier: EntryIdentifier,
        /// The staging name, unique within the process.
        between: String,
    },
    /// Second stage of a rename.
    FinalName {
        /// Which one.
        identifier: EntryIdentifier,
        /// The new name.
        name: String,
    },
    /// Set size, times and file identity anew; on `stale`, discard the content.
    ///
    /// Execution discards the content also when the size changes: a hydrated file with a new size
    /// and old content would be a mangled file.
    Update {
        /// The entry as it is now.
        entry: Entry,
        /// Whether the local content is stale (`Change::content_stale`).
        stale: bool,
    },
    /// Create a placeholder.
    Create {
        /// The new entry.
        entry: Entry,
    },
}

#[derive(Default)]
struct Plan {
    remove: Vec<Step>,
    between: Vec<Step>,
    end: Vec<Step>,
    update: Vec<Step>,
    create: Vec<Step>,
}

impl Plan {
    fn should(
        &mut self,
        entry: &Entry,
        stale: bool,
        details_changed: bool,
        map: &PathMap,
        staging_name: &mut dyn FnMut() -> String,
    ) {
        let identifier = entry.identifier;
        match map.location(identifier) {
            None => self.create.push(Step::Create { entry: entry.clone() }),
            // A folder became a file or the other way round: do not reinterpret, replace.
            Some(location) if location.folder != entry.is_folder() => {
                self.remove.push(Step::Remove { identifier });
                self.create.push(Step::Create { entry: entry.clone() });
            }
            Some(location) => {
                if location.name != entry.name {
                    self.between.push(Step::StagingName { identifier, between: staging_name() });
                    self.end.push(Step::FinalName { identifier, name: entry.name.clone() });
                }
                if !entry.is_folder() && (stale || details_changed) {
                    self.update.push(Step::Update { entry: entry.clone(), stale });
                }
            }
        }
    }
}

/// The steps for a change list from the engine, measured against the map.
///
/// Changes in containers that are not populated fall away — Windows fetches their listing afresh
/// the next time they are opened anyway. A `New` for an entry that is already known (after a
/// restart of the engine, say) becomes a reconciliation, not a second placeholder.
pub fn plan(
    changes: &[Change],
    map: &PathMap,
    staging_name: &mut dyn FnMut() -> String,
) -> Vec<Step> {
    let mut p = Plan::default();
    for change in changes {
        let identifier = change.identifier();
        let Some(parent) = identifier.parent() else {
            continue;
        };
        if !map.is_populated(parent) {
            continue;
        }
        match change {
            Change::Removed { .. } => {
                if map.knows(identifier) {
                    p.remove.push(Step::Remove { identifier });
                }
            }
            Change::New { entry } => p.should(entry, false, true, map, staging_name),
            Change::Changed { before, after } => p.should(
                after,
                change.content_stale(),
                before.file() != after.file(),
                map,
                staging_name,
            ),
        }
    }
    p.remove.into_iter().chain(p.between).chain(p.end).chain(p.update).chain(p.create).collect()
}

/// A staging name for the first stage of a rename.
///
/// Process identifier and running number: a leftover from a crashed run carries a different
/// process identifier and does not collide; the next reconciliation deletes it (it is in no
/// listing).
pub fn staging_name(process: u32, number: u64) -> String {
    format!("~edms-{process}-{number}.tmp")
}

/// What is in the directory on disk (enumerated without a callback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundOnDisk {
    /// The name.
    pub name: String,
    /// Whether it is a folder.
    pub folder: bool,
}

/// What is left to do after `FETCH_PLACEHOLDERS` has been answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowUp {
    /// Is on disk but in no listing (or of the wrong kind).
    ///
    /// Only what is a placeholder with a file identity of this program is deleted; a file the user
    /// put there themselves stays where it is.
    Delete {
        /// Name on disk.
        name: String,
        /// Whether it is a folder.
        folder: bool,
    },
    /// The name is already there; check file identity, size and spelling.
    Check {
        /// The name on disk (it may differ in case).
        present: String,
        /// The entry according to the listing.
        entry: Entry,
    },
    /// Create, after an entry of another kind with the same name has been deleted.
    Create {
        /// The entry.
        entry: Entry,
    },
}

/// The answer to `FETCH_PLACEHOLDERS` and the follow-up work.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconcile {
    /// To be handed over inside the callback: new names that are free on disk.
    pub transfer: Vec<Entry>,
    /// Afterwards, in this order: delete, check, create.
    pub follow_up: Vec<FollowUp>,
}

/// Reconciles a fresh listing with what is on disk.
///
/// Only what meets no existing name is handed over: an entry that meets an occupied name would let
/// `TRANSFER_PLACEHOLDERS` fail for it, and then cldflt does not accept
/// `DISABLE_ON_DEMAND_POPULATION` and asks again and again (ne-cfapi-
/// cf_operation_transfer_placeholders_flags: only if every entry succeeds).
pub fn reconcile(found_on_disk: &[FoundOnDisk], should: &[Entry]) -> Reconcile {
    let by_name: HashMap<String, &FoundOnDisk> =
        found_on_disk.iter().map(|v| (comparison_form(&v.name), v)).collect();
    let mut matched = HashSet::new();
    let mut delete = Vec::new();
    let mut check = Vec::new();
    let mut create = Vec::new();
    let mut transfer = Vec::new();
    for entry in should {
        let form = comparison_form(&entry.name);
        match by_name.get(&form) {
            None => transfer.push(entry.clone()),
            Some(v) if v.folder == entry.is_folder() => {
                matched.insert(form);
                check.push(FollowUp::Check { present: v.name.clone(), entry: entry.clone() });
            }
            Some(v) => {
                matched.insert(form);
                delete.push(FollowUp::Delete { name: v.name.clone(), folder: v.folder });
                create.push(FollowUp::Create { entry: entry.clone() });
            }
        }
    }
    for v in found_on_disk {
        if !matched.contains(&comparison_form(&v.name)) {
            delete.push(FollowUp::Delete { name: v.name.clone(), folder: v.folder });
        }
    }
    Reconcile { transfer, follow_up: delete.into_iter().chain(check).chain(create).collect() }
}

/// Checks a listing from the source before it reaches Windows.
///
/// Every error here is a bug in the source (`edms_core::namespace` builds the listings free of
/// collisions). It should show up: as a rejected request with a reason, not as a half-populated
/// directory in which an entry is missing without anyone knowing why.
pub fn check_list(container: Container, should: &[Entry]) -> Result<(), MirrorError> {
    let mut names = HashSet::new();
    let mut identifiers = HashSet::new();
    for entry in should {
        if entry.identifier.parent() != Some(container) {
            return Err(MirrorError::WrongLocation {
                identifier: entry.identifier,
                container: Box::new(container),
            });
        }
        if entry.is_folder() != entry.identifier.container().is_some() {
            return Err(MirrorError::WrongKind(entry.identifier));
        }
        check_name(&entry.name)?;
        if !names.insert(comparison_form(&entry.name)) {
            return Err(MirrorError::DuplicateName(entry.name.clone()));
        }
        if !identifiers.insert(entry.identifier) {
            return Err(MirrorError::DuplicateIdentifier(entry.identifier));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::Identifier;
    use edms_core::namespace::{EntryContent, FileDetails, Location};
    use edms_core::time::Timestamp;

    /// The archive every case file of these tests hangs in (namespace v2 §1).
    fn archive() -> Container {
        Container::Archive(Identifier::from_value(1))
    }

    fn case() -> Container {
        Container::Case { archive: Identifier::from_value(1), case: Identifier::from_value(1) }
    }

    fn file(w: u128, name: &str, version: &str) -> Entry {
        Entry {
            identifier: EntryIdentifier::Document {
                location: Location::Case {
                    archive: Identifier::from_value(1),
                    case: Identifier::from_value(1),
                },
                document: Identifier::from_value(w),
            },
            name: name.to_owned(),
            content: EntryContent::File(FileDetails {
                size: 10,
                sha256: None,
                version: version.to_owned(),
                created: Timestamp::NULL,
                changed: Timestamp::NULL,
                media_type: "application/pdf".to_owned(),
            }),
        }
    }

    fn folder(w: u128, name: &str) -> Entry {
        Entry {
            identifier: EntryIdentifier::Container(Container::Case {
                archive: Identifier::from_value(1),
                case: Identifier::from_value(w),
            }),
            name: name.to_owned(),
            content: EntryContent::Folder,
        }
    }

    fn map_with(entries: &[&Entry], populated: bool) -> PathMap {
        let mut k = PathMap::default();
        k.set(EntryIdentifier::Container(Container::Archives), "Archive", true);
        k.set(EntryIdentifier::Container(archive()), "Zentralarchiv", true);
        k.set(EntryIdentifier::Container(case()), "A", true);
        for e in entries {
            k.set(e.identifier, &e.name, e.is_folder());
        }
        if populated {
            k.mark_populated(case());
        }
        k
    }

    fn counter() -> impl FnMut() -> String {
        let mut n = 0;
        move || {
            n += 1;
            staging_name(7, n)
        }
    }

    #[test]
    fn nothing_is_touched_in_a_container_that_is_not_populated() {
        let a = file(1, "a.pdf", "1");
        let k = map_with(&[&a], false);
        let changes =
            [Change::Removed { entry: a.clone() }, Change::New { entry: file(2, "b.pdf", "1") }];
        assert!(plan(&changes, &k, &mut counter()).is_empty());
    }

    #[test]
    fn a_cyclic_swap_goes_through_staging_names() {
        let a = file(1, "A.pdf", "1");
        let b = file(2, "B.pdf", "1");
        let k = map_with(&[&a, &b], true);
        let changes = [
            Change::Changed { before: a.clone(), after: file(1, "B.pdf", "1") },
            Change::Changed { before: b.clone(), after: file(2, "A.pdf", "1") },
        ];
        let steps = plan(&changes, &k, &mut counter());
        assert_eq!(
            steps,
            vec![
                Step::StagingName { identifier: a.identifier, between: "~edms-7-1.tmp".into() },
                Step::StagingName { identifier: b.identifier, between: "~edms-7-2.tmp".into() },
                Step::FinalName { identifier: a.identifier, name: "B.pdf".into() },
                Step::FinalName { identifier: b.identifier, name: "A.pdf".into() },
            ],
            "a mere rename leaves the content in place (no update)"
        );
    }

    #[test]
    fn the_order_is_remove_rename_update_create() {
        let old = file(1, "Rechnung.pdf", "1");
        let renamed = file(2, "x.pdf", "1");
        let k = map_with(&[&old, &renamed], true);
        let changes = [
            Change::New { entry: file(3, "Rechnung.pdf", "1") },
            Change::Changed { before: renamed.clone(), after: file(2, "y.pdf", "2") },
            Change::Removed { entry: old.clone() },
        ];
        let kinds: Vec<&str> = plan(&changes, &k, &mut counter())
            .iter()
            .map(|s| match s {
                Step::Remove { .. } => "remove",
                Step::StagingName { .. } => "staging",
                Step::FinalName { .. } => "final",
                Step::Update { stale: true, .. } => "stale",
                Step::Update { .. } => "update",
                Step::Create { .. } => "create",
            })
            .collect();
        assert_eq!(kinds, ["remove", "staging", "final", "stale", "create"]);
    }

    #[test]
    fn a_new_for_a_known_entry_does_not_create_a_second_one() {
        let a = file(1, "a.pdf", "1");
        let k = map_with(&[&a], true);
        let steps = plan(&[Change::New { entry: a.clone() }], &k, &mut counter());
        assert_eq!(steps, vec![Step::Update { entry: a, stale: false }]);
    }

    #[test]
    fn a_removed_unknown_entry_is_nothing_to_do() {
        let k = map_with(&[], true);
        assert!(
            plan(&[Change::Removed { entry: file(9, "x.pdf", "1") }], &k, &mut counter())
                .is_empty()
        );
    }

    #[test]
    fn if_a_file_becomes_a_folder_it_is_replaced_not_reinterpreted() {
        let a = file(1, "a", "1");
        let k = map_with(&[&a], true);
        let new = Entry { content: EntryContent::Folder, ..a.clone() };
        let steps =
            plan(&[Change::Changed { before: a.clone(), after: new.clone() }], &k, &mut counter());
        assert_eq!(
            steps,
            vec![Step::Remove { identifier: a.identifier }, Step::Create { entry: new }]
        );
    }

    #[test]
    fn only_new_entries_with_a_free_name_go_out_inside_the_callback() {
        let found_on_disk = [
            FoundOnDisk { name: "alt.pdf".into(), folder: false },
            FoundOnDisk { name: "rechnung.pdf".into(), folder: false },
            FoundOnDisk { name: "Scan".into(), folder: true },
        ];
        let should = [file(1, "Rechnung.pdf", "1"), file(2, "neu.pdf", "1"), file(3, "Scan", "1")];
        let a = reconcile(&found_on_disk, &should);
        assert_eq!(a.transfer, vec![should[1].clone()]);
        assert_eq!(
            a.follow_up,
            vec![
                FollowUp::Delete { name: "Scan".into(), folder: true },
                FollowUp::Delete { name: "alt.pdf".into(), folder: false },
                FollowUp::Check { present: "rechnung.pdf".into(), entry: should[0].clone() },
                FollowUp::Create { entry: should[2].clone() },
            ]
        );
    }

    #[test]
    fn an_empty_directory_gets_the_whole_listing_inside_the_callback() {
        let should = [file(1, "a.pdf", "1"), folder(2, "B")];
        let a = reconcile(&[], &should);
        assert_eq!(a.transfer, should.to_vec());
        assert!(a.follow_up.is_empty());
    }

    #[test]
    fn a_listing_with_a_foreign_child_is_rejected() {
        let foreign = Entry {
            identifier: EntryIdentifier::Document {
                location: Location::Case {
                    archive: Identifier::from_value(1),
                    case: Identifier::from_value(2),
                },
                document: Identifier::from_value(1),
            },
            ..file(1, "a.pdf", "1")
        };
        assert!(matches!(check_list(case(), &[foreign]), Err(MirrorError::WrongLocation { .. })));
    }

    #[test]
    fn a_listing_with_a_duplicate_name_is_rejected() {
        let should = [file(1, "Rechnung.pdf", "1"), file(2, "RECHNUNG.pdf", "1")];
        assert_eq!(
            check_list(case(), &should),
            Err(MirrorError::DuplicateName("RECHNUNG.pdf".into()))
        );
        let should = [file(1, "a.pdf", "1"), file(1, "b.pdf", "1")];
        assert!(matches!(check_list(case(), &should), Err(MirrorError::DuplicateIdentifier(_))));
    }

    #[test]
    fn a_listing_with_the_wrong_kind_or_an_invalid_name_is_rejected() {
        let as_folder = Entry { content: EntryContent::Folder, ..file(1, "a", "1") };
        assert!(matches!(check_list(case(), &[as_folder]), Err(MirrorError::WrongKind(_))));
        assert!(matches!(
            check_list(case(), &[file(1, "a:b.pdf", "1")]),
            Err(MirrorError::InvalidName { .. })
        ));
        assert!(check_list(case(), &[file(1, "a.pdf", "1"), file(2, "b.pdf", "1")]).is_ok());
        assert!(check_list(archive(), &[folder(1, "A"), folder(2, "B")]).is_ok());
    }
}
