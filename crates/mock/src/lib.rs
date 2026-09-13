//! A contract-faithful mock server for the folder client — a **test harness**, never a product.
//!
//! The counterpart today has not a single `/v1` endpoint (README, "the counterpart"): no device
//! registration, no JSON search, no delivery channel, no upload for clients. What the folder client
//! needs stands as a contract in `docs/spec/03-api-contract-folder-client.md`. This crate speaks
//! it — including the mandatory DPoP nonce, so that the client really takes the retry path,
//! including two hosts, so that the nonce really is checked per origin, and including the ability
//! to answer wrongly on purpose.
//!
//! ```text
//!   test / development                 mock                              client
//!   ──────────────────                 ────────                          ──────
//!   control ────────────────▶ 127.0.0.1:<api>   ── /v1/mirror/*, /content, /delivery ─▶
//!   (baskets, archives,       127.0.0.1:<auth>  ── /v1/oauth/*, /geraet, /erfassung ──▶
//!    case files, commands,            │
//!    faults, nonces)                  │
//!                                     └── access log, recordings ──────────▶ assertions
//! ```
//!
//! The way through the crate:
//!
//! * [`Mock`] — starts two listeners on 127.0.0.1 and names their base addresses.
//! * [`Configuration`] — what is set before the start; the default is the strict reading of the
//!   contract.
//! * [`Control`] — the remote control: mail baskets, archives, case files (Akten) and documents,
//!   delivery commands (also deliberately wrongly signed ones), device flow decisions, nonces,
//!   faults, manglings — and the server-side access log to read back.
//! * [`api`], [`auth`] — the two routers; [`server`] — the path of every request.
//! * [`seed`] — the German sample tenant with real PDF bytes.
//!
//! ## The golden files are the truth
//!
//! The contract document, the wire types (`edms-wire`), the client (`edms-net`) and this mock are
//! four copies of the same contract. Four copies drift apart as soon as the contract changes — and
//! all four stay green, because each checks against itself. That is why the mock builds its answers
//! out of the **wire types** and, for every error that has a golden file, sends exactly that file's
//! body ([`http::golden_problem`]).
//!
//! ## Never in a release
//!
//! This crate pulls `edms-crypto` with the feature `forge` — it can **produce** anchors and signed
//! delivery commands. That is exactly what no production code may be able to do. The architecture
//! rules (`crates/architecture-rules`) record that only `edms-mock` pulls the feature and that only
//! this crate contains an HTTP server: the folder client listens on no port (ADR-D04), and a server
//! in production code would be one.

#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod config;
pub mod control;
pub mod error;
pub mod form;
pub mod http;
pub mod pdf;
pub mod seed;
pub mod server;
pub mod state;
pub mod time;

pub use config::Configuration;
pub use control::Control;
pub use error::MockError;
pub use server::Mock;
pub use state::{
    AccessEntry, CommandItem, CommandQuality, DeviceState, Fault, Mangling, Origin, Recording,
};
