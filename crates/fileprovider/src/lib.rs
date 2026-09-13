//! macOS platform layer: File Provider extension and domain management.
//!
//! On macOS there is exactly one current way for a third party to bring a placeholder tree into
//! Finder: a File Provider extension (`NSFileProviderReplicatedExtension`, ADR-D05). This crate
//! contains both sides of it:
//!
//! * **The extension** ([`extension::EdmsFileProvider`]) — the principal class of the .appex. It
//!   runs in a sandboxed process of its own, decides nothing, and for every answer asks the
//!   engine's [`NamespaceSource`], which lives in the app's process through `edms-bridge`. The
//!   program `elasticdms-fileprovider` is only its entry point.
//! * **The management** ([`domain::DomainManagement`], [`filesystem::MacFileSystem`]) — the part
//!   the app uses: set up and clear the domain, signal changes, release copies. `MacFileSystem`
//!   is the macOS side of [`FileSystem`], and it is also the side that tells the engine what the
//!   Finder dropped into a mail basket ([`arrival`]).
//!
//! ## What this layer does not do
//!
//! It never writes back (requirement 1): apart from reading, an item's only capability is the one
//! a mail basket has — a file may be put into it — and `createItem`, `modifyItem`, `deleteItem`
//! refuse all the same. What is dropped into a basket is not written back either; it is handed to
//! the engine, which files it (`arrival.rs`, namespace v2 §3). It filters nothing (requirement 4):
//! what the source delivers has already been filtered by permission. And it never calls the
//! server itself: the extension's sandbox permits only the channel to the app (ADR-D05).
//!
//! ## macOS only
//!
//! On other targets this crate consists of this description. `cargo xwin check` for the whole
//! workspace has to pass all the same; that is why every module is bound to
//! `target_os = "macos"` instead of the whole crate to a `compile_error!`.
//!
//! [`NamespaceSource`]: edms_core::port::NamespaceSource
//! [`FileSystem`]: edms_core::port::FileSystem

#[cfg(target_os = "macos")]
pub mod anchor;
#[cfg(target_os = "macos")]
pub mod arrival;
#[cfg(target_os = "macos")]
mod connection;
#[cfg(target_os = "macos")]
mod content;
#[cfg(target_os = "macos")]
pub mod domain;
#[cfg(target_os = "macos")]
mod entry;
#[cfg(target_os = "macos")]
mod enumerator;
#[cfg(target_os = "macos")]
pub mod error;
#[cfg(target_os = "macos")]
pub mod extension;
#[cfg(target_os = "macos")]
pub mod filesystem;
#[cfg(target_os = "macos")]
pub mod home;
#[cfg(target_os = "macos")]
pub mod identifier;
/// The Mac's language — read here, because Objective-C lives in this crate and nowhere else.
pub mod locale;
#[cfg(target_os = "macos")]
mod thread;

#[cfg(all(test, target_os = "macos"))]
mod harness;

#[cfg(target_os = "macos")]
pub use arrival::Arrival;
#[cfg(target_os = "macos")]
pub use domain::{DomainDetails, DomainError, DomainManagement, domain_identifier};
#[cfg(target_os = "macos")]
pub use extension::EdmsFileProvider;
#[cfg(target_os = "macos")]
pub use filesystem::MacFileSystem;
