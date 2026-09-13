//! Why the mock does not start — values, not panics.
//!
//! A test harness that runs into an `unwrap` at startup leaves behind a stack trace and the
//! question which port was taken. Every variant here names the place and the reason in a whole
//! sentence, so that the message in the terminal suffices without asking anybody.

use std::net::SocketAddr;

/// Why the mock does not start, or an instruction is not accepted.
#[derive(Debug, thiserror::Error)]
pub enum MockError {
    /// A listener could not be bound — usually a port that is taken.
    #[error("the {name} listener cannot bind {address}: {reason}")]
    Binding {
        /// Which of the two listeners ("API" or "auth").
        name: &'static str,
        /// The address that was tried.
        address: SocketAddr,
        /// The operating system's reason.
        reason: std::io::Error,
    },
    /// The address of a bound listener could not be queried; without it there is no base address
    /// the client could use.
    #[error("the address of the {name} listener cannot be queried: {reason}")]
    Address {
        /// Which of the two listeners.
        name: &'static str,
        /// The operating system's reason.
        reason: std::io::Error,
    },
    /// A key, an anchor or a signature of the forge could not be produced.
    #[error("the forge cannot build the mock's key set: {0}")]
    Forge(#[from] edms_crypto::CryptoError),
    /// A value of the configuration is unusable.
    #[error("the mock's configuration is unusable: {0}")]
    Configuration(String),
}
