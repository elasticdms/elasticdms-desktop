//! HTTP access of the folder client — and HTTP exists only here (rule R1).
//!
//! The crate has exactly one job: to make real requests out of the wire types in [`edms_wire`] and
//! the proofs from [`edms_crypto`], to send them over two origins and to translate the answer into
//! a value the engine can decide on. What it does **not** do: it stores nothing, it guesses
//! nothing, it checks no signature (that is `edms-crypto`'s job) and it filters no listing (the
//! namespace is filled by the engine with what arrives — contract test T11).
//!
//! ## The way through the crate
//!
//! * [`Connection`] — the two base addresses, the headers and the time limits. It checks when
//!   built, not when sending: plaintext HTTP only against the loopback.
//! * [`KeySource`] — where proof keys and tokens come from. The crate holds no secrets; it fetches
//!   them on every call from where they lie (keychain, ADR-D03).
//! * [`Server`] — the contract as a trait. The engine tests against mocks, not against the network.
//! * [`ServerAccess`] — the one implementation that really sends.
//! * [`ApiResult`] — five outcomes plus `304`, because "the server said no on the merits",
//!   "somebody has to sign in more strongly", "something is wrong here" and "the network was away"
//!   are different screens and not one common error.
//!
//! ## The three rules this crate carries
//!
//! **1. Every call carries a DPoP proof** (03 §6.0.5). Three exceptions, each with a reason: the
//! enrolment (the server does not know the key yet), the start of the device flow (RFC 9449 §5
//! binds over `dpop_jkt`, not over a proof) and the two `.well-known` documents (public, without an
//! identity).
//!
//! **2. Exactly one retry after `use_dpop_nonce`** (contract test T9), and only if a new nonce
//! really did arrive. Without the retry the system would be unusable after every restart of the
//! server; with more than one it would be a self-DoS against a server that does not accept its own
//! nonce.
//!
//! **3. Two origins, never mixed.** `api.` and `auth.` have separate nonces
//! ([`edms_crypto::dpop::NonceStore`] keys them per origin). A nonce of the one host presented at
//! the other is invalid, and the client would run into an endless alternation of two prompts
//! taking turns.
//!
//! ## What never goes into a log
//!
//! Tokens, refresh tokens, `device_code` and client assertions. They travel as [`Secret`], which
//! gives nothing of itself away in `Debug`; the wire types in `edms-wire` do the same (contract
//! test T25). Logged are method, path, status and the `X-Request-Id` — exactly the bridge between
//! a screenshot taken by the user and the line in the server log.

#![forbid(unsafe_code)]

mod access;
mod binding;
mod challenge;
mod clock;
mod error;
mod idempotency;
mod result;
mod secret;
mod transport;

// Public since ADR-D13 §8: the set-up judges a typed address with `connection::check`, the very
// function the environment path goes through.
pub mod connection;
pub mod server;

pub use access::ServerAccess;
pub use binding::{KeyBinding, KeySource};
pub use challenge::StepUpRequest;
pub use clock::{Clock, SystemClock};
pub use connection::Connection;
pub use error::{ConnectionError, NetworkError};
pub use idempotency::{IdempotencyError, IdempotencyKey};
pub use result::{ApiResult, Success};
pub use secret::Secret;
pub use server::Server;
