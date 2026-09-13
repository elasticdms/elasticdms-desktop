//! The exemption list: our own deletions and renames, which the veto has to let through.
//!
//! Requirement 1 demands that nothing in the mirror is deleted or renamed; the veto sits in
//! `NOTIFY_DELETE` and `NOTIFY_RENAME`. Except: cfAPI knows no separate way to remove or rename a
//! placeholder — the provider deletes like anyone else with `DeleteFileW`, and so it runs into its
//! own veto (research: "your OWN deletes also raise NOTIFY_DELETE"). Without this list, after a
//! DSGVO (GDPR) erasure exactly the file that has to go would stay behind.
//!
//! The other exception does **not** go through this list: a file somebody dropped into a mail
//! basket. Nobody could announce it — it is not an intervention of this program's, and the engine,
//! which moves it out of the basket after the ingest, knows nothing of this list. The veto
//! recognises it by where it lies and by its having no file identity of ours
//! (`platform::callback::dropped_into_a_basket`, namespace v2 §3).
//!
//! The list is keyed by [`PathKey`], not by file identity: `NOTIFY_DELETE` can arrive several
//! times per user action (recycle bin, folder, replace-on-save), and only the path is reliably
//! present in every one of them. An [`Expectation`] holds for as long as it lives — it is not
//! consumed by the first callback but removed when our own call returns.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::path::PathKey;

/// How far an expectation reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Exactly this path and nothing else (a file, or a folder being renamed).
    Exactly,
    /// This path and everything below it (deleting a folder together with its contents).
    Subtree,
}

#[derive(Debug)]
struct Exemption {
    number: u64,
    key: PathKey,
    scope: Scope,
}

/// The list of expected interventions of our own.
#[derive(Debug, Default)]
pub struct Exemptions {
    entries: Mutex<Vec<Exemption>>,
    next: AtomicU64,
}

/// For as long as it lives, the veto lets the intervention through.
#[derive(Debug)]
#[must_use = "an expectation only holds for as long as it lives"]
pub struct Expectation<'a> {
    list: &'a Exemptions,
    number: u64,
}

impl Exemptions {
    fn lock(&self) -> MutexGuard<'_, Vec<Exemption>> {
        // A panic elsewhere must not make the list unusable: otherwise the veto would refuse every
        // deletion of our own from then on.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Announces an intervention of our own at `relative` (path relative to the root).
    pub fn expect(&self, relative: &str, scope: Scope) -> Expectation<'_> {
        let number = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().push(Exemption { number, key: PathKey::from_relative(relative), scope });
        Expectation { list: self, number }
    }

    /// Whether an intervention at `relative` has been announced.
    pub fn is_expected(&self, relative: &str) -> bool {
        let key = PathKey::from_relative(relative);
        self.lock().iter().any(|a| match a.scope {
            Scope::Exactly => a.key == key,
            Scope::Subtree => key.is_below(&a.key),
        })
    }

    /// How many expectations are alive right now.
    pub fn count(&self) -> usize {
        self.lock().len()
    }

    /// Whether `NOTIFY_DELETE` may be let through.
    ///
    /// `None` means: the path does not lie under the root. That cannot really happen — cldflt only
    /// reports what lies inside the root — and if it does happen anyway, it is no reason to let
    /// through a deletion whose location this program cannot place.
    pub fn may_delete(&self, relative: Option<&str>) -> bool {
        relative.is_some_and(|r| self.is_expected(r))
    }

    /// Whether `NOTIFY_RENAME` may be let through.
    ///
    /// Only if **both ends** have been announced. If the source sufficed, every announced deletion
    /// would at the same time be permission to push that same file out of the mirror: the copy
    /// that has to disappear under ADR-D04 would afterwards lie in the user profile under a
    /// different name. If the target sufficed, anyone could rename a foreign file into a place
    /// that has just been announced.
    pub fn may_move(&self, of: Option<&str>, after: Option<&str>) -> bool {
        self.may_delete(of) && self.may_delete(after)
    }
}

impl Drop for Expectation<'_> {
    fn drop(&mut self) {
        let number = self.number;
        self.list.lock().retain(|a| a.number != number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_an_expectation_nothing_is_allowed() {
        let a = Exemptions::default();
        assert!(!a.is_expected(r"Archive\Nord\Sulzer\b.pdf"));
    }

    #[test]
    fn an_exact_expectation_holds_only_for_its_own_path() {
        let a = Exemptions::default();
        let _e = a.expect(r"Archive\Nord\Sulzer\b.pdf", Scope::Exactly);
        assert!(a.is_expected(r"archive\nord\SULZER\B.PDF"), "NTFS does not distinguish case");
        assert!(!a.is_expected(r"Archive\Nord\Sulzer\c.pdf"));
        assert!(!a.is_expected(r"Archive\Nord\Sulzer"));
    }

    #[test]
    fn a_subtree_covers_the_contents_but_not_the_neighbour() {
        let a = Exemptions::default();
        let _e = a.expect(r"Archive\Nord\Sulzer", Scope::Subtree);
        assert!(a.is_expected(r"Archive\Nord\Sulzer"));
        assert!(a.is_expected(r"Archive\Nord\Sulzer\a.pdf"));
        assert!(!a.is_expected(r"Archive\Nord\Sulzer 2\a.pdf"));
        assert!(!a.is_expected(r"Archive\Nord"));
    }

    #[test]
    fn the_expectation_ends_with_our_own_call_not_with_the_first_callback() {
        let a = Exemptions::default();
        {
            let _e = a.expect("LIESMICH.txt", Scope::Exactly);
            // NOTIFY_DELETE can arrive several times; every time it has to go through.
            assert!(a.is_expected("LIESMICH.txt"));
            assert!(a.is_expected("LIESMICH.txt"));
        }
        assert!(!a.is_expected("LIESMICH.txt"));
        assert_eq!(a.count(), 0);
    }

    #[test]
    fn only_what_has_been_announced_is_deleted() {
        let a = Exemptions::default();
        assert!(
            !a.may_delete(Some(r"Archive\Nord\Sulzer\b.pdf")),
            "without an expectation, nothing"
        );
        let _e = a.expect(r"Archive\Nord\Sulzer\b.pdf", Scope::Exactly);
        assert!(a.may_delete(Some(r"Archive\Nord\Sulzer\b.pdf")));
        assert!(!a.may_delete(Some(r"Archive\Nord\Sulzer\c.pdf")), "the neighbour stays protected");
        assert!(!a.may_delete(None), "a path outside the root is no free pass");
    }

    #[test]
    fn a_move_happens_only_if_both_ends_have_been_announced() {
        // The case the rule prevents: an announced deletion would otherwise at the same time be
        // permission to push that same copy out of the mirror instead of removing it.
        let a = Exemptions::default();
        let _source = a.expect(r"Archive\Nord\Sulzer\b.pdf", Scope::Exactly);
        assert!(!a.may_move(
            Some(r"Archive\Nord\Sulzer\b.pdf"),
            Some(r"Archive\Nord\Sulzer\~edms-7-1.tmp")
        ));
        assert!(
            !a.may_move(Some(r"Archive\Nord\Sulzer\b.pdf"), None),
            "out of the root is never allowed"
        );
        let _target = a.expect(r"Archive\Nord\Sulzer\~edms-7-1.tmp", Scope::Exactly);
        assert!(a.may_move(
            Some(r"Archive\Nord\Sulzer\b.pdf"),
            Some(r"Archive\Nord\Sulzer\~edms-7-1.tmp")
        ));
        // And the other way round the target alone is just as insufficient.
        assert!(!a.may_move(
            Some(r"Archive\Nord\Sulzer\fremd.pdf"),
            Some(r"Archive\Nord\Sulzer\~edms-7-1.tmp")
        ));
    }

    #[test]
    fn two_expectations_for_the_same_path_end_one_by_one() {
        let a = Exemptions::default();
        let first = a.expect("x", Scope::Exactly);
        let second = a.expect("x", Scope::Exactly);
        drop(first);
        assert!(a.is_expected("x"));
        drop(second);
        assert!(!a.is_expected("x"));
    }
}
