//! The domain core of the elasticdms folder client.
//!
//! Here lives everything that can be decided without an operating system — and that is more than
//! one would think: which identifier is valid, what a document is called in Explorer, what an
//! erasure command does to a pinned file, which row goes into the usage log. The platform layers
//! (`edms-cfapi`, `edms-fileprovider`) are meant to stay thin; everything they do not have to
//! decide themselves is decided by this crate, and decided testably.
//!
//! The way through the crate:
//!
//! * [`identifier`] — identifiers, one 128-bit value, two encodings (03 §6.0.3).
//! * [`time`], [`checksum`] — timestamps and checksums in their wire form.
//! * [`namespace`] — the fixed tree: mail baskets, archives with their case files (Akten) and
//!   saved searches (requirement 3, namespace v2).
//! * [`filename`] — titles turned into file names that Windows and macOS both accept.
//! * [`change`] — the difference between two listings: the “dynamic folders”.
//! * [`delivery`] — the closed command catalogue and the three occasions.
//! * [`log`] — the local usage log, the app's first view.
//! * [`port`] — the seam towards the platform layers, one direction per trait.
//!
//! Boundaries this crate does not cross:
//!
//! 1. No clock and no randomness. Timestamps and new identifiers are handed in.
//! 2. No network, no file system, no platform API.
//! 3. No `unsafe`.

#![forbid(unsafe_code)]

pub mod change;
pub mod checksum;
pub mod delivery;
pub mod filename;
pub mod identifier;
pub mod log;
pub mod namespace;
pub mod port;
pub mod time;
