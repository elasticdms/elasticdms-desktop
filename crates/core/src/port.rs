//! The seam between engine and platform — two traits, one per direction.
//!
//! The platform layers (`edms-cfapi` on Windows, `edms-fileprovider` on macOS) are meant to stay
//! thin. They know only these two traits and the core's types, never the engine, never the
//! network, never the database. That is exactly why the traits stand here and not in the engine:
//!
//! * [`NamespaceSource`] — **platform asks, engine answers.** “What is in this case file?”,
//!   “Give me the content”. On Windows the cfAPI callback calls them in the same process; on
//!   macOS the extension calls them through `edms-bridge` in the app's process — the same
//!   interface, once direct, once over a wire.
//! * [`FileSystem`] — **engine orders, platform carries out.** “These entries are new”, “Release
//!   this copy”, “Clear everything”.
//!
//! Both traits are **synchronous**. cfAPI calls on operating-system threads, the extension on
//! Foundation threads; none of them is a tokio worker. The engine bridges into its own runtime,
//! and the platform need know nothing about it.
//!
//! ## The promise about content
//!
//! **Not one byte reaches the platform before the checksum matches.** The engine loads the whole
//! thing into a buffer, compares against [`FileDetails::sha256`] and only then writes into the
//! [`ContentSink`]. The server notices a hash error only at the last `Read`, after `200` has
//! already been sent; a client that passes bytes on as they come puts a mutilated file into the
//! user's folder and holds it for complete. While loading, the sink reports progress — on
//! Windows that resets the 60-second deadline of every callback (`CfReportProviderProgress`),
//! otherwise Explorer aborts large files.
//!
//! [`FileDetails::sha256`]: crate::namespace::FileDetails::sha256

use edms_i18n::{Catalog, key};
use serde::{Deserialize, Serialize};

use crate::change::{Change, ChangeState};
use crate::checksum::Sha256Value;
use crate::namespace::{Container, Entry, EntryIdentifier};

/// Platform asks, engine answers.
pub trait NamespaceSource: Send + Sync {
    /// All children of a container, fully named.
    ///
    /// Complete, not page by page: on `FETCH_PLACEHOLDERS` cfAPI demands all entries of a
    /// directory before it completes the user's request.
    fn children(&self, container: Container) -> Result<Vec<Entry>, SourceError>;

    /// A single entry (macOS `itemForIdentifier`).
    fn entry(&self, identifier: EntryIdentifier) -> Result<Entry, SourceError>;

    /// The current sequence number of the change journal (macOS `currentSyncAnchor`).
    fn current_sequence(&self) -> Result<u64, SourceError>;

    /// Changes after `sequence`, at most `max` of them (macOS `enumerateChanges`).
    ///
    /// If `sequence` is older than the journal, [`SourceError::AnchorExpired`] comes back; the
    /// platform then enumerates everything anew instead of guessing at gaps.
    fn changes_since(&self, sequence: u64, max: usize) -> Result<ChangeState, SourceError>;

    /// Loads the content of a file, checks it and only then writes it into the sink.
    ///
    /// Every call is an access: logged server-side, and locally in the usage log.
    fn content(
        &self,
        identifier: EntryIdentifier,
        request: &ContentRequest,
        sink: &mut dyn ContentSink,
    ) -> Result<ContentReceipt, SourceError>;
}

/// Who wants the content — as far as the platform says so.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRequest {
    /// File name of the program that opens the file (`WINWORD.EXE`, `Preview`), without a path.
    ///
    /// Goes to the server as a header and turns “user X loaded document Y” into “… with program
    /// Z” — the difference between a document that was opened and one that a virus scan read.
    /// The file name only: a path would give away the user name.
    pub requesting_application: Option<String>,
}

/// Where checked, loaded content is written.
pub trait ContentSink: Send {
    /// Loading progress, before the first byte is written.
    fn progress(&mut self, _loaded: u64, _total: u64) {}

    /// Writes a chunk at an offset. Chunks arrive ascending and without gaps.
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), SinkError>;

    /// Whether the platform has cancelled the request meanwhile (the user closed the program).
    fn cancelled(&self) -> bool {
        false
    }
}

/// The sink could not write.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("the platform did not accept the content: {0}")]
pub struct SinkError(pub String);

/// What is settled after a successful handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReceipt {
    /// Bytes written.
    pub size: u64,
    /// The checksum that was verified to match; `None` only for locally generated hints.
    pub sha256: Option<Sha256Value>,
}

/// Why the source cannot deliver. Every variant has its own counterpart on Windows and on
/// macOS, so that the user sees the right reason in Explorer/Finder.
///
/// Serializable, because on macOS it travels through `edms-bridge` out of the app process into
/// the extension and has to arrive there as the same reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "reason", content = "details", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceError {
    /// Nobody is signed in, or the session has expired.
    #[error("sign-in required: elasticdms is not signed in on this device")]
    NotSignedIn,
    /// The server is unreachable.
    #[error("the elasticdms server cannot be reached")]
    NoNetwork,
    /// The entry does not exist (any more).
    #[error("the entry `{0}` no longer exists")]
    NotFound(EntryIdentifier),
    /// The server refuses access.
    #[error("no access to this document")]
    NoAccess,
    /// The loaded content does not match the checksum.
    #[error(
        "the loaded content does not match the checksum (expected {expected}, received {actual})"
    )]
    Integrity {
        /// According to the listing.
        expected: Sha256Value,
        /// Computed.
        actual: Sha256Value,
    },
    /// The server delivered fewer or more bytes than announced.
    #[error("the server delivered {actual} instead of {expected} bytes")]
    Incomplete {
        /// According to the listing.
        expected: u64,
        /// Actually delivered.
        actual: u64,
    },
    /// The sequence number is older than the journal.
    #[error("the change marker is stale; the folder is enumerated afresh")]
    AnchorExpired,
    /// The platform has cancelled the request.
    #[error("the request was cancelled")]
    Cancelled,
    /// The sink did not accept the content.
    #[error(transparent)]
    Sink(#[from] SinkError),
    /// The server answered with an error that is none of the above.
    #[error("the server reports: {0}")]
    Server(String),
    /// A fault in this program.
    #[error("internal error in the folder client: {0}")]
    Internal(String),
}

impl SourceError {
    /// The sentence Explorer or Finder shows, in the user's language.
    ///
    /// The `Display` message above is the **diagnostic** one and stays English: it goes into the
    /// log, into a bug report and into a support call, and a translated diagnosis cannot be found
    /// again. This one goes to the person in front of the machine.
    ///
    /// The two of them never drift apart silently: a new variant makes the match below red.
    pub fn user_text(&self, catalogue: &Catalog) -> String {
        match self {
            Self::NotSignedIn => catalogue.text(key::ERROR_SOURCE_NOT_SIGNED_IN).to_owned(),
            Self::NoNetwork => catalogue.text(key::ERROR_SOURCE_NO_NETWORK).to_owned(),
            Self::NotFound(entry) => {
                catalogue.format(key::ERROR_SOURCE_NOT_FOUND, &[("entry", &entry.to_string())])
            }
            Self::NoAccess => catalogue.text(key::ERROR_SOURCE_NO_ACCESS).to_owned(),
            Self::Integrity { expected, actual } => catalogue.format(
                key::ERROR_SOURCE_INTEGRITY,
                &[("expected", &expected.to_string()), ("actual", &actual.to_string())],
            ),
            Self::Incomplete { expected, actual } => catalogue.format(
                key::ERROR_SOURCE_INCOMPLETE,
                &[("expected", &expected.to_string()), ("actual", &actual.to_string())],
            ),
            Self::AnchorExpired => catalogue.text(key::ERROR_SOURCE_ANCHOR_EXPIRED).to_owned(),
            Self::Cancelled => catalogue.text(key::ERROR_SOURCE_CANCELLED).to_owned(),
            Self::Sink(reason) => {
                catalogue.format(key::ERROR_SOURCE_SINK, &[("reason", &reason.to_string())])
            }
            Self::Server(reason) => {
                catalogue.format(key::ERROR_SOURCE_SERVER, &[("reason", reason)])
            }
            Self::Internal(reason) => {
                catalogue.format(key::ERROR_SOURCE_INTERNAL, &[("reason", reason)])
            }
        }
    }
}

/// Engine orders, platform carries out.
pub trait FileSystem: Send + Sync {
    /// Provisions the mirror for a session: register the root, set the display name.
    fn place_ready(&self, provisioning: &Provisioning) -> Result<(), PlatformError>;

    /// Applies changes to the namespace.
    ///
    /// Windows creates, updates and deletes placeholders (only in directories that are already
    /// filled; the others fetch their listing themselves on the next open). macOS signals the
    /// working set; the extension then fetches the changes through
    /// [`NamespaceSource::changes_since`].
    fn report_change(&self, changes: &[Change]) -> Result<(), PlatformError>;

    /// How an entry stands locally.
    fn state(&self, identifier: EntryIdentifier) -> Result<LocalState, PlatformError>;

    /// Releases the local content; the entry stays.
    ///
    /// With `unpin` the pin is released first — without that, dehydrating a pinned file fails on
    /// both platforms.
    fn dehydrate(&self, identifier: EntryIdentifier, unpin: bool) -> Result<(), PlatformError>;

    /// Removes the entry entirely, together with content and pin.
    fn remove(&self, identifier: EntryIdentifier) -> Result<(), PlatformError>;

    /// Clears the whole mirror (sign-out). Afterwards no name of the previous user is left on
    /// disk (requirement 4: view and placeholder listing are bound to the user).
    fn clear_everything(&self) -> Result<(), PlatformError>;
}

/// What the platform has to know for provisioning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provisioning {
    /// Display name of the root, e.g. "elasticdms – Example GmbH".
    pub display_name: String,
    /// Stable account identifier (`sub`), part of the root identifier on Windows.
    pub account: String,
}

/// How an entry stands locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LocalState {
    /// Whether it exists on disk.
    pub present: bool,
    /// Whether content is loaded.
    pub hydrated: bool,
    /// Whether the user has pinned it („Immer auf diesem Gerät behalten" — always keep on this
    /// device).
    pub pinned: bool,
}

/// Why the platform could not carry out an order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    /// The mirror is not provisioned.
    #[error("the folder is not set up on this device")]
    NotReadyPosed,
    /// The entry does not exist locally.
    #[error("the entry `{0}` is not on this device")]
    NotFound(EntryIdentifier),
    /// A program is holding the file open.
    #[error("the file `{0}` is open at the moment; the operation will be retried")]
    InUse(EntryIdentifier),
    /// The operating system reports an error.
    #[error("the operating system reports {code:#x}: {text}")]
    OperatingSystem {
        /// HRESULT, NSError code or similar.
        code: i64,
        /// The operating system's message.
        text: String,
    },
    /// This platform cannot do that.
    #[error("not possible on this operating system: {0}")]
    NotSupported(&'static str),
}

impl PlatformError {
    /// The sentence the user reads; the `Display` message stays the diagnostic one
    /// ([`SourceError::user_text`] says why).
    pub fn user_text(&self, catalogue: &Catalog) -> String {
        match self {
            Self::NotReadyPosed => catalogue.text(key::ERROR_PLATFORM_NOT_READY).to_owned(),
            Self::NotFound(entry) => {
                catalogue.format(key::ERROR_PLATFORM_NOT_FOUND, &[("entry", &entry.to_string())])
            }
            Self::InUse(entry) => {
                catalogue.format(key::ERROR_PLATFORM_IN_USE, &[("entry", &entry.to_string())])
            }
            Self::OperatingSystem { code, text } => catalogue.format(
                key::ERROR_PLATFORM_OPERATING_SYSTEM,
                &[("code", &format!("{code:#x}")), ("text", text)],
            ),
            Self::NotSupported(what) => {
                catalogue.format(key::ERROR_PLATFORM_NOT_SUPPORTED, &[("what", what)])
            }
        }
    }
}
