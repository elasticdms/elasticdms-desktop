//! Delivery: what a command from the delivery channel may do on this device.
//!
//! The delivery channel is a long poll like the one of the NAV agent (ADR-013,
//! `ordnerclient-vorgaben.md`), and it takes the decisive rule from there: **no free-form
//! command, but a closed catalogue of signed orders, with volume limits inside the client
//! itself.** A delivery channel that executes arbitrary commands is a remote-erasure tool for
//! anyone who holds the server or the load balancer.
//!
//! `edms-crypto` checks the signature, the engine checks the rate. What stands here is what a
//! valid command **brings about** — and the one decision where requirement and user rub against
//! each other: the pinned file.
//!
//! ## The three occasions (`ordnerclient-vorgaben.md`, „Angeheftete Dateien" — pinned files)
//!
//! | Occasion         | Release the pin | Entry                              | Notify |
//! |------------------|-----------------|------------------------------------|--------|
//! | `ERASURE`        | yes, forced     | remove — the name goes too         | yes    |
//! | `ACCESS_REVOKED` | yes, forced     | dehydrate; the listing keeps it    | no     |
//! | `SPACE_RECLAIM`  | **no**          | dehydrate if not pinned            | no     |
//!
//! **Why this differs from the note of 2026-09-10:** what was decided on 2026-09-10 is only „der Loeschbefehl
//! hebt die Anheftung auf" — the erasure command releases the pin. The three-way split is a
//! *proposal in the requirements, not decided*. The proposal is implemented, because only it
//! separates `SPACE_RECLAIM` from the two forced occasions; for `ERASURE` and `ACCESS_REVOKED`
//! decision and proposal agree. Should space reclamation release the pin as well, that is one
//! line in [`actions`] — and the test `space_reclamation_respects_the_pin` fails, as it should.

use serde::{Deserialize, Serialize};

use crate::identifier::DocumentIdentifier;
use crate::namespace::Container;

/// Maximum number of documents per command (volume limit inside the client, per ADR-013).
///
/// A DSGVO (GDPR) erasure across all records of one person can affect thousands of documents;
/// the server then splits it up. The limit does not prevent the erasure, it prevents a single
/// forged command from emptying the whole mirror in one go.
pub const MAX_DOCUMENTS_PER_COMMAND: usize = 500;

/// Maximum number of commands executed per minute (rate limit inside the client, per ADR-013).
pub const MAX_COMMANDS_PER_MINUTE: u32 = 30;

/// Why a document is to leave this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reason {
    /// DSGVO (GDPR) erasure (ADR-011). Not even the name may stay behind.
    Erasure,
    /// The permission has been revoked.
    AccessRevoked,
    /// Routine: make room.
    SpaceReclaim,
}

/// What is to be done at a location for an occasion. A pure consequence of [`actions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Actions {
    /// Before anything else, release the pin (otherwise dehydration fails:
    /// `ERROR_CLOUD_FILE_PINNED` on Windows, `NonEvictable` on macOS).
    pub unpin: bool,
    /// Release the local content, leave the entry standing.
    pub dehydrate: bool,
    /// Remove the entry entirely.
    pub remove_entry: bool,
    /// Fetch the container's listing again immediately.
    pub trigger_reconcile: bool,
    /// Notify the user („Verschwinden darf nicht stumm sein" — disappearing must not be silent).
    pub notify_user: bool,
    /// Erase the name from earlier rows of the local usage log.
    pub redact_log: bool,
}

/// The table from the module header, as a function.
pub const fn actions(reason: Reason, pinned: bool) -> Actions {
    match reason {
        Reason::Erasure => Actions {
            unpin: pinned,
            dehydrate: true,
            remove_entry: true,
            trigger_reconcile: false,
            notify_user: true,
            redact_log: true,
        },
        Reason::AccessRevoked => Actions {
            unpin: pinned,
            dehydrate: true,
            remove_entry: false,
            trigger_reconcile: true,
            notify_user: false,
            redact_log: false,
        },
        Reason::SpaceReclaim => Actions {
            unpin: false,
            dehydrate: !pinned,
            remove_entry: false,
            trigger_reconcile: false,
            notify_user: false,
            redact_log: false,
        },
    }
}

/// The closed catalogue. What is not here, the client does not execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Release local copies (and more depending on the occasion, see [`actions`]).
    Dehydrate {
        /// Which documents, at every location where they stand.
        documents: Vec<DocumentIdentifier>,
        /// Why.
        reason: Reason,
    },
    /// Fetch a listing again at once instead of waiting for the next tick.
    Reconcile {
        /// Which container; `None` means all of them.
        container: Option<Container>,
    },
    /// The session has ended server-side: sign out and clear the mirror.
    SignOut,
    /// Fetch the key set again (rotation or revocation on the counterpart's side).
    RefreshKeys,
}

/// How a command turned out — this is what goes into the acknowledgement to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommandOutcome {
    /// Applied.
    Applied,
    /// Nothing to do (the document was not on this device).
    NotApplicable,
    /// Not executed, because the command did not pass the check.
    Rejected,
    /// Attempted and failed; the server may deliver it again.
    Failed,
}

/// Why a command is rejected before any execution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// A dehydrate command without a document is not a command but a fault on the other side.
    #[error("the command names no document; nothing is dehydrated, and the command is rejected")]
    WithoutDocument,
    /// More documents than the volume limit allows.
    #[error(
        "the command names {0} documents; more than {MAX_DOCUMENTS_PER_COMMAND} this device does \
         not carry out in one go (ADR-013, volume limit)"
    )]
    TooMany(usize),
}

/// Checks a command against the volume limits before anything happens.
pub fn check(command: &Command) -> Result<(), CommandError> {
    match command {
        Command::Dehydrate { documents, .. } if documents.is_empty() => {
            Err(CommandError::WithoutDocument)
        }
        Command::Dehydrate { documents, .. } if documents.len() > MAX_DOCUMENTS_PER_COMMAND => {
            Err(CommandError::TooMany(documents.len()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Identifier;

    #[test]
    fn an_erasure_releases_the_pin_removes_the_entry_and_notifies() {
        let m = actions(Reason::Erasure, true);
        assert!(m.unpin && m.dehydrate && m.remove_entry);
        assert!(m.notify_user && m.redact_log);
    }

    #[test]
    fn an_access_revocation_releases_the_pin_and_stays_silent() {
        let m = actions(Reason::AccessRevoked, true);
        assert!(m.unpin && m.dehydrate && m.trigger_reconcile);
        assert!(!m.remove_entry && !m.notify_user && !m.redact_log);
    }

    #[test]
    fn space_reclamation_respects_the_pin() {
        let pinned = actions(Reason::SpaceReclaim, true);
        assert!(!pinned.unpin && !pinned.dehydrate);
        let free = actions(Reason::SpaceReclaim, false);
        assert!(free.dehydrate && !free.remove_entry);
    }

    #[test]
    fn an_unpinned_file_needs_no_release() {
        for reason in [Reason::Erasure, Reason::AccessRevoked, Reason::SpaceReclaim] {
            assert!(!actions(reason, false).unpin, "{reason:?}");
        }
    }

    #[test]
    fn the_volume_limit_bites_before_execution() {
        let many = (0..=MAX_DOCUMENTS_PER_COMMAND as u128).map(Identifier::from_value).collect();
        let b = Command::Dehydrate { documents: many, reason: Reason::Erasure };
        assert_eq!(check(&b), Err(CommandError::TooMany(MAX_DOCUMENTS_PER_COMMAND + 1)));
        let empty = Command::Dehydrate { documents: vec![], reason: Reason::SpaceReclaim };
        assert_eq!(check(&empty), Err(CommandError::WithoutDocument));
    }
}
