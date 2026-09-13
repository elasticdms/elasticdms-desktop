//! The line between File Provider extension and app: [`NamespaceSource`] over loopback.
//!
//! On macOS the File Provider extension runs in a sandboxed process of its own (ADR-D05,
//! measurement 2: without the sandbox PlugInKit does not accept it). The engine — sign-in, network,
//! database, checksums — lives in the app. The extension decides nothing; every question of the
//! Finder goes over this line to the engine's [`NamespaceSource`], and the answer comes back as the
//! same types of the core. On Windows this line does not exist: there the cfAPI callback calls the
//! source in the same process.
//!
//! ```text
//! Finder ─▶ extension (.appex, sandbox)                      app (elasticdms, engine)
//!           BridgeClient ──── TCP 127.0.0.1:<port> ────▶ BridgeServer ─▶ Arc<dyn NamespaceSource>
//!                  │                                            │
//!                  └── reads ─ ~/Library/Application Support/ ◀─┘ writes
//!                              de.elasticdms.folderclient/bridge.json
//!                              {port, secret, pid, version}, mode 0600
//! ```
//!
//! ## Why TCP and not a Unix socket
//!
//! A Unix socket would need a directory both processes may enter: on macOS an App Group, and that
//! demands a team ID as a prefix. Ad-hoc signed builds have none (ADR-D05, measurement 3).
//! `com.apple.security.network.client`, by contrast, permits the extension every outgoing
//! connection, to 127.0.0.1 as well; the app is not sandboxed and may listen. Listening happens
//! only on 127.0.0.1, never on an address another machine can reach.
//!
//! ## Why a secret
//!
//! On 127.0.0.1 **every** process of the machine can connect, that of another user included.
//! Without a credential every program could read all documents of the signed-in user over the line
//! — and every one of those fetches would stand in the server's access log as an access by this
//! user (requirement: "every hydration is an access"). The secret (32 random bytes, base64url; the
//! app produces them, this crate only receives them) stands only in the rendezvous file, which only
//! the user can read. The first message of every connection has to carry it, otherwise the app
//! closes without an answer. The comparison runs in constant time, so that the response time does
//! not betray how many characters already match.
//!
//! ## The protocol
//!
//! Frame: `[Length: u32 BE][Kind: u8][Payload]`, the length counts the kind in. Kind `J` is a JSON
//! message (at most [`MAX_JSON_FRAME`]), `T` a JSON part with more to follow, `D` a data chunk
//! `[Offset: u64 BE][max MAX_DATA_CHUNK bytes]`.
//!
//! ```text
//! extension                                           app
//! HELLO {version, secret}                   ──▶
//!                                           ◀──       WELCOME {version}   (else: closed, no word)
//! CHILDREN | ENTRY | CURRENT_SEQUENCE
//!   | CHANGES_SINCE | CONTENT             ──▶
//!                                           ◀──       CHILDREN {result} | ENTRY {result} | …
//!                                                     result = {"Ok": …} | {"Err": SourceError}
//!                                           ◀──       on CONTENT: PROGRESS*, D frames*,
//!                                                     then END {receipt} | ERROR {error}
//! closed                                              closed
//! ```
//!
//! The decisions in it, each with its reason:
//!
//! * **One connection per request.** No multiplexing, no state that ties a broken request to the
//!   next one. Cancelling means closing the connection — the app notices that at once, in the
//!   middle of a content too, and its sink reports the cancellation to the engine.
//! * **Limits before the read.** A single length header `0xFFFF_FFFF` would otherwise make the
//!   extension ask for 4 GiB before it has seen a single byte of content. A JSON frame is at most
//!   1 MiB; longer answers travel in parts ([`MAX_MESSAGE`]), because a case file (Akte) with 5,000
//!   documents yields around 2 MB of JSON, and the listing has to arrive complete (cfAPI and Finder
//!   demand all children of a folder).
//! * **The app catches panics.** If the engine runs into a program error during a request, the
//!   extension gets [`SourceError::Internal`] instead of a line closed without a word, which would
//!   look like a terminated app; the line stays open for the next request.
//!
//! ## "The app is not running" means [`SourceError::NoNetwork`]
//!
//! If the rendezvous file is missing, the connection is refused, a foreign program answers on the
//! port, the line breaks off or the app stays silent for [`READ_DEADLINE`], then
//! [`SourceError::NoNetwork`] arrives in the extension. The extension maps it onto
//! `serverUnreachable`, and the Finder then shows "not reachable right now" and tries again by
//! itself later — instead of marking the file as finally broken. The precise reason ("the
//! elasticdms app is not running …") is carried by [`BridgeError`]; it is delivered by
//! [`BridgeClient::check_connection`], and the line writes it into the log (`tracing`), because
//! `NoNetwork` can carry no text in the core. Program and set-up errors (wrong version, a
//! rendezvous file that is too open, a breach of the protocol) become [`SourceError::Internal`]
//! with a whole sentence instead: they do not go away by themselves.
//!
//! ## Measured, not assumed
//!
//! The extension starts over `_NSExtensionMain`, not over Rust's `main`; the runtime that otherwise
//! ignores `SIGPIPE` never runs there. A write to a closed line would have terminated the whole
//! extension. Measured on 2026-09-11 (Rust 1.98.1, macOS 26.6) with a program without a Rust
//! `main`: on Apple systems std sets `SO_NOSIGPIPE` for every socket, the write fails with
//! `BrokenPipe`, the process lives on.

#![deny(unsafe_code)]

use std::time::Duration;

mod client;
mod error;
mod frame;
#[cfg(target_os = "macos")]
mod home;
mod message;
mod rendezvous;
mod server;

pub use client::BridgeClient;
pub use edms_core::port::NamespaceSource;
pub use error::BridgeError;
pub use rendezvous::{
    APPLICATION_DIRECTORY, RENDEZVOUS_FILE, Rendezvous, SECRET_BYTES, secret_from_bytes,
};
pub use server::BridgeServer;

/// Version of the line protocol. Stands in the rendezvous file and in the handshake.
///
/// App and extension lie in the same bundle, but after an update the old app can still be running
/// while macOS is already starting the new extension. Without a version they would understand each
/// other by halves; with it there is a clear message "please restart".
pub const VERSION: u32 = 1;

/// Maximum size of the payload of a JSON frame (1 MiB).
pub const MAX_JSON_FRAME: usize = 1 << 20;

/// Maximum size of a data chunk in the `D` frame (256 KiB), without the offset.
pub const MAX_DATA_CHUNK: usize = 256 << 10;

/// Maximum size of a JSON message across all parts (64 MiB).
///
/// Around 150,000 entries in one folder. No Finder displays more of them sensibly, and an answer of
/// that size arrives as [`SourceError::Internal`] with its size instead of as a crash.
pub const MAX_MESSAGE: usize = 64 << 20;

/// Maximum number of connections served at the same time in the app.
///
/// Further ones wait in the operating system's queue until a place becomes free — they do not fail.
/// Without a limit a Finder that demands content for 500 thumbnails at once would make 500 threads
/// and 500 downloads come into being in the engine.
pub const MAX_CONNECTION: usize = 16;

/// How long the client waits for the connection to be established.
///
/// On 127.0.0.1 a running app answers in microseconds; whoever does not answer within 2 s is not
/// running. Waiting longer would mean letting the Finder hang at every folder when the app has
/// ended.
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(2);

/// How long at most the client waits without a single byte from the app.
///
/// Longer than the 60 s the server allows the engine for one read operation (01-contract §2.0,
/// `ReadTimeout 60s`): a slow but living server answer is not to break off here. During a content
/// every progress frame resets the deadline.
pub const READ_DEADLINE: Duration = Duration::from_secs(90);
