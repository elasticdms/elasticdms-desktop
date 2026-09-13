//! The worker pool: answer callbacks without holding on to cldflt's thread.
//!
//! cldflt calls from a thread pool of its own, and **every request has a 60-second deadline** that
//! only a successful `CfExecute` pushes back (02-platform-decision §1.4). Whoever waits on the
//! network inside a callback holds on to one of those threads; a handful of documents opened at
//! the same time is then enough to make Explorer hang system-wide — for OneDrive too, which uses
//! the same pool. Hence: copy the request into a value of our own, return from the callback, and
//! send the answer from here.
//!
//! Why no runtime (tokio)? This crate depends only on `edms-core` (README, "crate layout"), and
//! the work is blocking I/O across a synchronous seam (`edms_core::port::NamespaceSource`). A
//! thread pool is the right fit for that.
//!
//! **Growing, not fixed.** A fixed pool would only push the same deadlock one level down: if every
//! thread is sitting on the network, new requests wait out their 60 seconds in the queue. The pool
//! therefore adds a thread as long as the upper bound allows it, and lets threads go again after an
//! idle time.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A job: anything that runs once and returns nothing.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// How many threads run at most at the same time.
///
/// There has to be an upper bound — one thread per request would be a thread storm during a virus
/// scan across the whole mirror. 32 is plenty for the number of documents a human opens at once,
/// and small enough not to be noticed.
pub const MAX_THREADS: usize = 32;

/// After this time without a job a thread ends.
pub const EMPTY_RUN: Duration = Duration::from_secs(30);

#[derive(Default)]
struct State {
    jobs: VecDeque<Job>,
    threads: usize,
    busy: usize,
    end: bool,
}

// A job is a closure and has no `Debug`; the numbers next to it do have one, and only they ever
// appear in a log.
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("jobs", &self.jobs.len())
            .field("threads", &self.threads)
            .field("busy", &self.busy)
            .field("end", &self.end)
            .finish()
    }
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    waker: Condvar,
    max: usize,
    empty_run: Duration,
    accepted: AtomicU64,
}

/// A growing thread pool that waits for its threads when it is dropped.
#[derive(Debug)]
pub struct WorkGroup {
    inner: Arc<Inner>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Default for WorkGroup {
    fn default() -> Self {
        Self::new(MAX_THREADS, EMPTY_RUN)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic in a job must not make the pool unusable: otherwise it would accept no callback any
    // more afterwards, and Explorer would wait its 60 seconds for every file.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl WorkGroup {
    /// A pool with its own upper bound and idle time.
    pub fn new(max: usize, empty_run: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                waker: Condvar::new(),
                max: max.max(1),
                empty_run,
                accepted: AtomicU64::new(0),
            }),
            threads: Mutex::new(Vec::new()),
        }
    }

    /// Accepts a job; `false` if the pool is already being shut down.
    ///
    /// After [`WorkGroup::stop`] nothing is accepted any more — a job that were still accepted
    /// during sign-out would run against a root that no longer exists.
    pub fn give<F: FnOnce() + Send + 'static>(&self, job: F) -> bool {
        let mut z = lock(&self.inner.state);
        if z.end {
            return false;
        }
        z.jobs.push_back(Box::new(job));
        self.inner.accepted.fetch_add(1, Ordering::Relaxed);
        let free = z.threads - z.busy;
        let needs_thread = z.jobs.len() > free && z.threads < self.inner.max;
        if needs_thread {
            z.threads += 1;
            drop(z);
            self.create_thread();
        } else {
            drop(z);
            self.inner.waker.notify_one();
        }
        true
    }

    fn create_thread(&self) {
        let inner = Arc::clone(&self.inner);
        let mut threads = lock(&self.threads);
        threads.retain(|f| !f.is_finished());
        match thread::Builder::new().name("edms-cfapi".to_owned()).spawn(move || work(&inner)) {
            Ok(f) => threads.push(f),
            Err(error) => {
                // Not getting a thread is a state of the system, not a bug in the program: the
                // booking is taken back, the job stays in the queue and the next free thread picks
                // it up.
                tracing::error!(%error, "no worker thread for the cloud filter callbacks");
                lock(&self.inner.state).threads -= 1;
                self.inner.waker.notify_all();
            }
        }
    }

    /// How many jobs have been accepted so far.
    pub fn accepted(&self) -> u64 {
        self.inner.accepted.load(Ordering::Relaxed)
    }

    /// How many threads are alive right now.
    pub fn threads(&self) -> usize {
        lock(&self.inner.state).threads
    }

    /// Accepts nothing more and waits until all accepted jobs are done.
    ///
    /// Accepted jobs run to the end — a half-written placeholder would be worse than a few seconds
    /// of waiting during sign-out.
    pub fn stop(&self) {
        {
            let mut z = lock(&self.inner.state);
            z.end = true;
        }
        self.inner.waker.notify_all();
        let threads = std::mem::take(&mut *lock(&self.threads));
        for thread in threads {
            // A thread that panicked itself has already given back its share of the bookkeeping in
            // the sentry (`Sentry`); its result is of no interest here.
            let _ = thread.join();
        }
    }

    /// Accepts jobs again after a [`WorkGroup::stop`].
    ///
    /// Needed when signing out and signing in again within the same process: there the connection
    /// is dropped and the worker threads are waited for, and afterwards the same pool faces a fresh
    /// session again. Without this call it would accept nothing more — the folder would be there
    /// after the second sign-in and every callback would run into the void, until the user restarts
    /// the program.
    ///
    /// No threads are created here; the next job creates them.
    pub fn accept_again(&self) {
        lock(&self.inner.state).end = false;
    }
}

impl Drop for WorkGroup {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Gives the "busy" booking back even when the job panics.
struct Sentry<'a>(&'a Inner);

impl Drop for Sentry<'_> {
    fn drop(&mut self) {
        lock(&self.0.state).busy -= 1;
    }
}

fn work(inner: &Inner) {
    loop {
        let job = {
            let mut z = lock(&inner.state);
            loop {
                if let Some(job) = z.jobs.pop_front() {
                    z.busy += 1;
                    break Some(job);
                }
                if z.end {
                    z.threads -= 1;
                    break None;
                }
                let (new, deadline) = match inner.waker.wait_timeout(z, inner.empty_run) {
                    Ok(value) => value,
                    Err(poisoned) => poisoned.into_inner(),
                };
                z = new;
                if deadline.timed_out() && z.jobs.is_empty() && !z.end {
                    z.threads -= 1;
                    break None;
                }
            }
        };
        let Some(job) = job else {
            return;
        };
        let _sentry = Sentry(inner);
        // A panic in the job must not take the thread with it: it would otherwise arrive at the
        // user as the end of the process, while in fact only one document could not be loaded.
        if catch_unwind(AssertUnwindSafe(job)).is_err() {
            tracing::error!("a job of the cloud filter worker pool crashed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    #[test]
    fn every_job_runs_exactly_once() {
        let group = WorkGroup::default();
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..100 {
            let z = Arc::clone(&counter);
            assert!(group.give(move || {
                z.fetch_add(1, Ordering::SeqCst);
            }));
        }
        group.stop();
        assert_eq!(counter.load(Ordering::SeqCst), 100);
        assert_eq!(group.accepted(), 100);
    }

    #[test]
    fn blocking_jobs_do_not_hold_each_other_up() {
        // Exactly the situation the pool exists for: four requests wait on the network at the same
        // time. If they ran one after another, the fourth send would never arrive, and the test
        // would hang on its deadline instead of on an assertion.
        let group = WorkGroup::new(4, EMPTY_RUN);
        let (sender, receiver) = mpsc::channel::<()>();
        let (release, wait_for_release) = mpsc::channel::<()>();
        let wait_for_release = Arc::new(Mutex::new(wait_for_release));
        for _ in 0..4 {
            let sender = sender.clone();
            let wait = Arc::clone(&wait_for_release);
            group.give(move || {
                let _ = sender.send(());
                let received = lock(&wait).recv_timeout(Duration::from_secs(10));
                assert!(received.is_ok(), "the job was not released");
            });
        }
        for _ in 0..4 {
            receiver.recv_timeout(Duration::from_secs(10)).expect("all four run at the same time");
        }
        assert_eq!(group.threads(), 4);
        for _ in 0..4 {
            let _ = release.send(());
        }
        group.stop();
    }

    #[test]
    fn above_the_upper_bound_it_waits_instead_of_sowing_threads() {
        let group = WorkGroup::new(2, EMPTY_RUN);
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..20 {
            let z = Arc::clone(&counter);
            group.give(move || {
                z.fetch_add(1, Ordering::SeqCst);
            });
        }
        group.stop();
        assert_eq!(counter.load(Ordering::SeqCst), 20);
        assert!(group.threads() <= 2, "{} threads", group.threads());
    }

    #[test]
    fn a_panic_in_one_job_does_not_take_the_pool_with_it() {
        let group = WorkGroup::new(1, EMPTY_RUN);
        let (sender, receiver) = mpsc::channel();
        group.give(|| panic!("a callback went wrong"));
        group.give(move || {
            let _ = sender.send(42);
        });
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(10)),
            Ok(42),
            "the second job did run"
        );
        group.stop();
    }

    #[test]
    fn after_a_sign_out_the_same_pool_accepts_again() {
        // Signing out and signing in again within the same process: `Mirror::clear_everything`
        // ends the pool, `Mirror::place_ready` opens it again. Without that, every callback of the
        // second session would run into the void, and the folder would be there but empty.
        let group = WorkGroup::default();
        let (sender, receiver) = mpsc::channel();
        group.stop();
        group.accept_again();
        let second = sender.clone();
        assert!(group.give(move || {
            let _ = second.send(1);
        }));
        assert_eq!(receiver.recv_timeout(Duration::from_secs(10)), Ok(1));
        group.stop();
        drop(sender);
    }

    #[test]
    fn after_the_end_nothing_is_accepted_any_more() {
        let group = WorkGroup::default();
        group.stop();
        let counter = Arc::new(AtomicUsize::new(0));
        let z = Arc::clone(&counter);
        assert!(!group.give(move || {
            z.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_idle_thread_goes_after_the_idle_time() {
        let group = WorkGroup::new(2, Duration::from_millis(20));
        let (sender, receiver) = mpsc::channel();
        group.give(move || {
            let _ = sender.send(());
        });
        receiver.recv_timeout(Duration::from_secs(10)).expect("the job did run");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while group.threads() > 0 && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(group.threads(), 0, "the idling thread gives itself up");
    }
}
