//! The one direction in which something enters the mirror: a file dropped into a mail basket.
//!
//! Everything else in this folder is the server's truth and read-only (ADR-D06 §4). The basket is
//! the exception, and the only one: [`Container::accepts_new_files`] says which container that is,
//! and nothing here decides it for itself (namespace v2 §3). A basket is a trigger, not a filing
//! destination — what is announced here the engine uploads and then moves out of the mirror; where
//! the document lands is decided by the ingest rule and by nobody in this crate.
//!
//! ## Why a beat and not a directory watch
//!
//! cfAPI has **no callback for a creation**; the crate header names that as a residual risk. What
//! is left is `ReadDirectoryChangesW` or looking. This crate looks, every [`LOOK_AGAIN`]:
//!
//! * A basket holds nothing of the server's (namespace v2 §4), so its listing is short — a handful
//!   of directories with a handful of names, and normally none at all.
//! * The engine takes a file only once its size and modification time have stood still for two
//!   seconds (ADR-D08 point 3). A watch that reported the creation in the same millisecond would
//!   buy nothing against a beat of those same two seconds.
//! * Overlapped `ReadDirectoryChangesW`, with a buffer, a thread and a cancellation of its own,
//!   is a good deal of machinery for that beat. `FindFirstFileW` in a beat is the code that is
//!   already there (`win::read_directory`) and that carries every directory listing.
//!
//! Announcing the same file twice costs nothing — the engine drops the second announcement. That
//! is what makes the beat cheap to be wrong about: whoever announces too often loses nothing,
//! whoever announces too seldom loses a receipt.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use edms_core::identifier::BasketIdentifier;
use edms_core::namespace::Container;

use crate::path::parent_and_name;
use crate::path_map::PathMap;
use crate::plan::FoundOnDisk;

/// How often the basket directories are looked at.
///
/// Two seconds, because that is the engine's own window: a file counts as finished when size and
/// modification time have stood still for two seconds (ADR-D08 point 3). Looking more often would
/// only find files that are not ready yet.
pub const LOOK_AGAIN: Duration = Duration::from_secs(2);

/// Where a file that appeared in a basket is handed over.
///
/// The counterpart in the engine is `edms_engine::Intake`; the app puts the two together, because
/// it is the only place that may know both crates (architecture rule, `crates/architecture-rules`).
/// This crate depends on `edms-core` and `edms-i18n` and on nothing else, so the seam stands here
/// as a trait of its own — exactly as [`edms_core::port::NamespaceSource`] stands for the other
/// direction.
pub trait Intake: Send + Sync {
    /// A file appeared in this basket; `path` is where it lies **now**, spelled the way Windows
    /// spells it.
    ///
    /// Called on a thread of this crate — the beat or a worker of the pool — never on a callback
    /// thread of cldflt. It should return at once all the same: one beat serves every basket.
    fn file_appeared(&self, basket: BasketIdentifier, path: &str);
}

/// The basket a file at this path was dropped into; `None` if this is no place for a new file.
///
/// `relative` is the path of the **file** relative to the root; the container asked about is its
/// parent. That is why the basket folder itself yields `None` (its parent is the basket container,
/// which takes nothing) and a file in a folder inside a basket does too — a folder in a basket is
/// nothing this program made, and nothing is taken out of it (namespace v2 §3).
pub fn basket_of(map: &PathMap, relative: &str) -> Option<BasketIdentifier> {
    let (parent, _) = parent_and_name(relative);
    basket(map.container_at(parent)?)
}

/// Every basket the map knows, with its path relative to the root.
///
/// The map learns a basket when Windows fetches the listing of the baskets container — or from
/// `platform::watch`, which asks the source once per connection so that a file left lying since
/// yesterday does not wait for somebody to open the folder.
pub fn basket_directories(map: &PathMap) -> Vec<(BasketIdentifier, String)> {
    map.containers()
        .into_iter()
        .filter_map(|container| {
            let basket = basket(container)?;
            Some((basket, map.container_path(container)?))
        })
        .collect()
}

/// What of a directory listing is a dropped file: everything the server does not know.
///
/// Two things are passed over. **Folders**, because a basket takes a file creation and nothing
/// else — a folder in it is not handed in, it is only in the way. And every name the map holds as
/// a child of this container: that would be an entry of the server's, and the server's truth is
/// never handed in as a new document. A basket holds nothing of the server's (namespace v2 §4), so
/// this second rule should never bite; it stands here because the day it does bite, the file it
/// saves is one the user never dropped.
pub fn dropped_in<'a>(
    map: &PathMap,
    basket: BasketIdentifier,
    found: &'a [FoundOnDisk],
) -> Vec<&'a str> {
    let container = Container::Basket(basket);
    found
        .iter()
        .filter(|v| !v.folder && map.search_name(container, &v.name).is_none())
        .map(|v| v.name.as_str())
        .collect()
}

/// The identifier of a container that takes files.
///
/// **Whether** something may be put in is [`Container::accepts_new_files`]'s answer and not this
/// crate's (namespace v2 §3); the match below only reads the identifier out of a container that
/// has already said yes.
fn basket(container: Container) -> Option<BasketIdentifier> {
    if !container.accepts_new_files() {
        return None;
    }
    match container {
        Container::Basket(basket) => Some(basket),
        _ => None,
    }
}

/// A thread that does one job over and over until it is stopped.
///
/// Stopping does not wait out the interval: a sign-out must not hang for seconds on a thread that
/// is sleeping. That is why the wait runs over a condition variable and not over `sleep`.
#[derive(Debug)]
pub struct Beat {
    switch: Arc<Switch>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Debug, Default)]
struct Switch {
    stopped: Mutex<bool>,
    waker: Condvar,
}

impl Switch {
    fn lock(&self) -> MutexGuard<'_, bool> {
        // A panic elsewhere must not leave the beat unstoppable: it would hold up every sign-out
        // from then on.
        self.stopped.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for the interval; `false` once it has been stopped.
    ///
    /// `wait_timeout_while` and not `wait_timeout`: the condition has to be looked at **before**
    /// the wait as well. Whoever stops the beat while its first round is still running notifies a
    /// condition variable nobody is waiting on yet; with the plain wait the test below
    /// (`stopping_does_not_wait_out_the_interval`) hung for the whole interval — measured, that is
    /// how it was found. The loop over the condition also swallows a spurious wakeup, which would
    /// otherwise start a round before its time.
    fn carry_on(&self, interval: Duration) -> bool {
        let stopped = self.lock();
        let (stopped, _) = self
            .waker
            .wait_timeout_while(stopped, interval, |stopped| !*stopped)
            .unwrap_or_else(PoisonError::into_inner);
        !*stopped
    }

    fn stop(&self) {
        *self.lock() = true;
        self.waker.notify_all();
    }
}

impl Beat {
    /// Starts the beat; the job runs at once and then every `interval`.
    ///
    /// At once, because the first round is the one that matters: whatever was lying in a basket
    /// while the program was not running should not have to wait for a beat as well.
    pub fn start<F: FnMut() + Send + 'static>(interval: Duration, mut job: F) -> Self {
        let switch = Arc::new(Switch::default());
        let mine = Arc::clone(&switch);
        let thread = thread::spawn(move || {
            loop {
                // A panic in the job must not end the beat: the next round may well succeed, and a
                // beat that has silently stopped takes every later drop with it.
                if catch_unwind(AssertUnwindSafe(&mut job)).is_err() {
                    tracing::error!("a round of the basket watch crashed");
                }
                if !mine.carry_on(interval) {
                    return;
                }
            }
        });
        Self { switch, thread: Some(thread) }
    }
}

impl Drop for Beat {
    fn drop(&mut self) {
        self.switch.stop();
        if let Some(thread) = self.thread.take() {
            // Waited for, not detached: the round that is running right now reads a directory
            // under the root, and after this the root is disconnected or deleted.
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::Identifier;
    use edms_core::namespace::EntryIdentifier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn container(container: Container) -> EntryIdentifier {
        EntryIdentifier::Container(container)
    }

    fn basket_identifier(w: u128) -> BasketIdentifier {
        Identifier::from_value(w)
    }

    /// The tree of namespace v2, as far as this module looks at it.
    fn example() -> PathMap {
        let mut k = PathMap::default();
        k.set(container(Container::Baskets), "Briefkörbe", true);
        k.set(container(Container::Basket(basket_identifier(1))), "Buchhaltung", true);
        k.set(container(Container::Basket(basket_identifier(2))), "Post", true);
        k.set(container(Container::Archives), "Archive", true);
        k.set(container(Container::Archive(Identifier::from_value(1))), "Zentralarchiv", true);
        k
    }

    #[test]
    fn a_file_in_a_basket_names_the_basket_it_lies_in() {
        let k = example();
        assert_eq!(
            basket_of(&k, r"Briefkörbe\Buchhaltung\Rechnung.pdf"),
            Some(basket_identifier(1))
        );
        assert_eq!(basket_of(&k, r"briefkörbe\POST\scan.pdf"), Some(basket_identifier(2)));
    }

    #[test]
    fn everywhere_else_takes_no_file() {
        let k = example();
        let nowhere = [
            r"Briefkörbe\Buchhaltung",
            r"Briefkörbe",
            "LIESMICH.txt",
            r"Archive\Zentralarchiv\Sulzer\Prüfbericht.pdf",
            r"Archive\Zentralarchiv\fremd.pdf",
            r"Briefkörbe\Unbekannt\a.pdf",
            // A folder inside a basket is nothing this program made; nothing is taken out of it.
            r"Briefkörbe\Buchhaltung\Scans\a.pdf",
            "",
        ];
        for path in nowhere {
            assert_eq!(basket_of(&k, path), None, "{path}");
        }
    }

    #[test]
    fn every_basket_the_map_knows_has_its_directory() {
        let k = example();
        assert_eq!(
            basket_directories(&k),
            vec![
                (basket_identifier(1), r"Briefkörbe\Buchhaltung".to_owned()),
                (basket_identifier(2), r"Briefkörbe\Post".to_owned()),
            ],
            "the archives are in there too, and none of them takes a file"
        );
        assert!(basket_directories(&PathMap::default()).is_empty());
    }

    #[test]
    fn only_what_the_server_does_not_know_counts_as_dropped() {
        let mut k = example();
        let basket = basket_identifier(1);
        k.set(
            EntryIdentifier::Hint {
                location: Container::Basket(basket),
                kind: edms_core::namespace::HintKind::ReadMe,
            },
            "LIESMICH.txt",
            false,
        );
        let found = [
            FoundOnDisk { name: "Rechnung.pdf".into(), folder: false },
            FoundOnDisk { name: "Scans".into(), folder: true },
            FoundOnDisk { name: "liesmich.txt".into(), folder: false },
        ];
        assert_eq!(
            dropped_in(&k, basket, &found),
            vec!["Rechnung.pdf"],
            "the folder and the entry of the server's stay where they are"
        );
        assert!(dropped_in(&k, basket_identifier(9), &found).contains(&"liesmich.txt"));
    }

    #[test]
    fn the_beat_runs_its_job_over_and_over() {
        let count = Arc::new(AtomicUsize::new(0));
        let mine = Arc::clone(&count);
        let beat = Beat::start(Duration::from_millis(5), move || {
            mine.fetch_add(1, Ordering::Relaxed);
        });
        let until = Instant::now() + Duration::from_secs(5);
        while count.load(Ordering::Relaxed) < 3 && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            count.load(Ordering::Relaxed) >= 3,
            "the beat ran {} times",
            count.load(Ordering::Relaxed)
        );
        drop(beat);
        let after_the_end = count.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(count.load(Ordering::Relaxed), after_the_end, "a stopped beat runs no more");
    }

    #[test]
    fn stopping_does_not_wait_out_the_interval() {
        let count = Arc::new(AtomicUsize::new(0));
        let mine = Arc::clone(&count);
        let began = Instant::now();
        // An hour: whoever waits for the interval here never returns from this test.
        drop(Beat::start(Duration::from_secs(3600), move || {
            mine.fetch_add(1, Ordering::Relaxed);
        }));
        assert!(began.elapsed() < Duration::from_secs(5), "the stop waited for the interval");
        assert_eq!(count.load(Ordering::Relaxed), 1, "the first round runs at once");
    }

    #[test]
    fn a_crashed_round_does_not_end_the_beat() {
        let count = Arc::new(AtomicUsize::new(0));
        let mine = Arc::clone(&count);
        let beat = Beat::start(Duration::from_millis(5), move || {
            if mine.fetch_add(1, Ordering::Relaxed) == 0 {
                panic!("the first round crashes");
            }
        });
        let until = Instant::now() + Duration::from_secs(5);
        while count.load(Ordering::Relaxed) < 3 && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(count.load(Ordering::Relaxed) >= 3, "the beat stopped at the panic");
        drop(beat);
    }
}
