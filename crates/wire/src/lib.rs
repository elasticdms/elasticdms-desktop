//! Wire types of the folder client contract — the body shapes, and only those.
//!
//! The contract stands in `docs/spec/03-api-contract-folder-client.md`: the parts of the escan
//! contract (`03 §6.0`–`§6.4`) a workstation needs, and the proposals `§7.0`–`§7.6` for what only
//! the folder client needs. **The truth is the golden files** in `testdata/`: every file is read
//! here and written again, and every JSON block in the contract document marked
//! `<!-- golden: … -->` is byte-identical with its file. Document, types and mock therefore
//! cannot drift apart silently (geraete-auth §9.1).
//!
//! The way through the crate:
//!
//! * [`basics`] — what holds for every endpoint: problem details (RFC 9457) with the error
//!   catalogue, page envelope, headers, timestamps, ETag and digest (03 §6.0).
//! * [`discovery`] — the discovery documents (RFC 8414, RFC 9728) and their start conditions.
//! * [`device`] — enrollment, device object, heartbeat (03 §6.2, §6.4.1; proposal §7.0).
//! * [`login`] — device flow (RFC 8628), token requests, OAuth errors (03 §6.3).
//! * [`namespace`] — case files (Akten), saved searches, their documents (proposal §7.1).
//! * [`content`] — the content fetch, which is an access (proposal §7.2).
//! * [`delivery`] — the delivery channel and the closed command catalogue (proposal §7.3).
//! * [`ingest`] — the ingest from the inbound folder (proposal §7.4).
//! * [`golden`] — the golden files as a table, for the mock and for the neighbours' tests.
//!
//! Boundaries this crate does not cross:
//!
//! 1. **No network, no cryptography.** `edms-crypto` checks signatures, `edms-net` speaks HTTP;
//!    only the shapes and the checks that work without keys stand here.
//! 2. **No copy of the core.** Identifiers, timestamps, checksums, namespace and command
//!    catalogue come from `edms_core`; only their wire form and the strict translation into them
//!    stand here.
//! 3. **No `unsafe`.**

#![forbid(unsafe_code)]

pub mod basics;
pub mod content;
pub mod delivery;
pub mod device;
pub mod discovery;
pub mod golden;
pub mod ingest;
pub mod login;
pub mod namespace;

pub use golden::golden;
