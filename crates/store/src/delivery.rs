//! Delivery commands: delivered at least once, effective once (ADR-D04, point 4).
//!
//! The server delivers a command until it is acknowledged; the client deduplicates over the
//! command identifier. The order in the engine:
//!
//! 1. [`Store::accept_command`] — before every execution. The answer says what is to be done.
//! 2. Execute.
//! 3. [`Store::set_outcome`] — before the acknowledgement goes out.
//! 4. Acknowledge, then [`Store::mark_acknowledged`].
//!
//! If the program crashes between 3 and 4, the outcome lies unacknowledged in the table;
//! [`Store::open_acknowledgement`] is the outbox that the engine empties first after a start. If it
//! crashes between 1 and 3, the command counts as [`Acceptance::Interrupted`] on the next delivery
//! and is executed again: every command of the catalogue is repeatable (dehydrating a dehydrated
//! entry, removing a removed one — nothing to do).
//!
//! The payload of a command does not stand here: it comes anew and signed with every delivery, and
//! a stored copy would be one whose signature nobody checks any more.

use edms_core::delivery::CommandOutcome;
use edms_core::identifier::CommandIdentifier;
use edms_core::time::Timestamp;
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use crate::Store;
use crate::column::{bool_from, from_name, name_of, read_identifier};
use crate::error::StoreError;

const T_DELIVERY: &str = "delivery";

/// What the engine is to do with a command that has just arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Seen for the first time: execute.
    New,
    /// Already accepted, but without an outcome: the last attempt broke off. Execute again.
    ///
    /// The same comes out when the same command is still being executed in this process — which is
    /// why the engine executes commands one after another, never side by side.
    Interrupted,
    /// Formerly `FAILED` — the outcome that expressly permits redelivery.
    /// The old outcome is discarded; execute again.
    Repeat,
    /// Already done: do not execute again, only send the acknowledgement (again).
    Done {
        /// How it came out.
        outcome: CommandOutcome,
        /// Whether the acknowledgement is already at the server.
        acknowledged: bool,
    },
}

impl Acceptance {
    /// Whether the command is to be executed (again).
    pub const fn from_run(self) -> bool {
        matches!(self, Self::New | Self::Interrupted | Self::Repeat)
    }
}

/// What is settled about an accepted command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandState {
    /// Which command.
    pub command: CommandIdentifier,
    /// When it first came in.
    pub received: Timestamp,
    /// How it came out; `None` for as long as the execution is not finished.
    pub outcome: Option<CommandOutcome>,
    /// Whether the acknowledgement is at the server.
    pub acknowledged: bool,
}

impl Store {
    /// Accepts a delivered command and says what is to be done with it ([`Acceptance`]).
    ///
    /// `received` counts only the first time; a redelivery does not change it.
    pub fn accept_command(
        &mut self,
        command: CommandIdentifier,
        received: Timestamp,
    ) -> Result<Acceptance, StoreError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let acceptance = match read_command_state(&tx, command)? {
            None => {
                tx.prepare_cached(
                    "INSERT INTO delivery (command, received, outcome, acknowledged) \
                     VALUES (?1, ?2, NULL, 0)",
                )?
                .execute(params![command.to_string(), received.unix_millis()])?;
                Acceptance::New
            }
            Some(CommandState { outcome: None, .. }) => Acceptance::Interrupted,
            Some(CommandState { outcome: Some(CommandOutcome::Failed), .. }) => {
                tx.prepare_cached(
                    "UPDATE delivery SET outcome = NULL, acknowledged = 0 WHERE command = ?1",
                )?
                .execute(params![command.to_string()])?;
                Acceptance::Repeat
            }
            Some(CommandState { outcome: Some(outcome), acknowledged, .. }) => {
                Acceptance::Done { outcome, acknowledged }
            }
        };
        tx.commit()?;
        Ok(acceptance)
    }

    /// Records the outcome before the acknowledgement goes out.
    ///
    /// An outcome already acknowledged cannot be changed any more: it stands at the server, and a
    /// different one here would be a second truth about the same command.
    pub fn set_outcome(
        &mut self,
        command: CommandIdentifier,
        outcome: CommandOutcome,
    ) -> Result<(), StoreError> {
        let name = name_of(&outcome, "command outcome")?;
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match read_command_state(&tx, command)? {
            None => return Err(StoreError::CommandUnknown(command)),
            Some(state) if state.acknowledged => {
                return Err(StoreError::CommandAcknowledged(command));
            }
            Some(_) => {}
        }
        tx.prepare_cached("UPDATE delivery SET outcome = ?1 WHERE command = ?2")?
            .execute(params![name, command.to_string()])?;
        tx.commit()?;
        Ok(())
    }

    /// Notes that the server has accepted the acknowledgement. Twice is harmless.
    pub fn mark_acknowledged(&mut self, command: CommandIdentifier) -> Result<(), StoreError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match read_command_state(&tx, command)? {
            None => return Err(StoreError::CommandUnknown(command)),
            Some(CommandState { outcome: None, .. }) => {
                return Err(StoreError::CommandWithoutOutcome(command));
            }
            Some(_) => {}
        }
        tx.prepare_cached("UPDATE delivery SET acknowledged = 1 WHERE command = ?1")?
            .execute(params![command.to_string()])?;
        tx.commit()?;
        Ok(())
    }

    /// The outbox: commands with an outcome whose acknowledgement is not yet at the server,
    /// oldest first.
    pub fn open_acknowledgement(&self) -> Result<Vec<CommandState>, StoreError> {
        let raw: Vec<RawCommand> = {
            let mut query = self.connection.prepare_cached(
                "SELECT command, received, outcome, acknowledged FROM delivery \
                 WHERE outcome IS NOT NULL AND acknowledged = 0 ORDER BY received, command",
            )?;
            query.query_map([], RawCommand::read)?.collect::<Result<_, _>>()?
        };
        raw.into_iter().map(RawCommand::state).collect()
    }

    /// What is settled about a command; `None` when it was never accepted.
    pub fn command_state(
        &self,
        command: CommandIdentifier,
    ) -> Result<Option<CommandState>, StoreError> {
        read_command_state(&self.connection, command)
    }

    /// Removes acknowledged commands that came in before `before`; returns their number.
    ///
    /// Unacknowledged ones always stay: they are the outbox. If the server does deliver a removed
    /// command once more, it counts as new — harmless, because every command is repeatable.
    pub fn clear_delivery(&mut self, before: Timestamp) -> Result<usize, StoreError> {
        Ok(self
            .connection
            .prepare_cached("DELETE FROM delivery WHERE acknowledged = 1 AND received < ?1")?
            .execute(params![before.unix_millis()])?)
    }
}

fn read_command_state(
    connection: &Connection,
    command: CommandIdentifier,
) -> Result<Option<CommandState>, StoreError> {
    let raw = connection
        .prepare_cached(
            "SELECT command, received, outcome, acknowledged FROM delivery WHERE command = ?1",
        )?
        .query_row(params![command.to_string()], RawCommand::read)
        .optional()?;
    raw.map(RawCommand::state).transpose()
}

/// One row from `delivery`, not yet checked.
struct RawCommand {
    command: String,
    received: i64,
    outcome: Option<String>,
    acknowledged: i64,
}

impl RawCommand {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            command: row.get(0)?,
            received: row.get(1)?,
            outcome: row.get(2)?,
            acknowledged: row.get(3)?,
        })
    }

    fn state(self) -> Result<CommandState, StoreError> {
        Ok(CommandState {
            command: read_identifier(&self.command, T_DELIVERY, "command")?,
            received: Timestamp::from_unix_millis(self.received),
            outcome: self
                .outcome
                .as_deref()
                .map(|name| from_name(name, T_DELIVERY, "outcome"))
                .transpose()?,
            acknowledged: bool_from(self.acknowledged, T_DELIVERY, "acknowledged")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;

    use super::*;
    use crate::test_support::{store, time};

    fn command(value: u128) -> CommandIdentifier {
        Identifier::from_value(value)
    }

    #[test]
    fn a_new_command_is_executed_and_after_that_only_acknowledged() {
        let mut s = store();
        let new = s.accept_command(command(1), time(1)).unwrap();
        assert_eq!(new, Acceptance::New);
        assert!(new.from_run());
        s.set_outcome(command(1), CommandOutcome::Applied).unwrap();

        let again = s.accept_command(command(1), time(2)).unwrap();
        assert_eq!(
            again,
            Acceptance::Done { outcome: CommandOutcome::Applied, acknowledged: false }
        );
        assert!(!again.from_run());
        assert_eq!(s.open_acknowledgement().unwrap().len(), 1);

        s.mark_acknowledged(command(1)).unwrap();
        s.mark_acknowledged(command(1)).unwrap();
        assert_eq!(
            s.accept_command(command(1), time(3)).unwrap(),
            Acceptance::Done { outcome: CommandOutcome::Applied, acknowledged: true }
        );
        assert!(s.open_acknowledgement().unwrap().is_empty());
        assert_eq!(s.command_state(command(1)).unwrap().unwrap().received, time(1));
    }

    #[test]
    fn a_command_without_an_outcome_counts_as_interrupted_on_redelivery() {
        let mut s = store();
        s.accept_command(command(1), time(1)).unwrap();
        // Crash before set_outcome.
        let acceptance = s.accept_command(command(1), time(2)).unwrap();
        assert_eq!(acceptance, Acceptance::Interrupted);
        assert!(acceptance.from_run());
        assert!(s.open_acknowledgement().unwrap().is_empty());
    }

    #[test]
    fn a_failed_command_is_repeated_on_redelivery() {
        let mut s = store();
        s.accept_command(command(1), time(1)).unwrap();
        s.set_outcome(command(1), CommandOutcome::Failed).unwrap();
        s.mark_acknowledged(command(1)).unwrap();

        assert_eq!(s.accept_command(command(1), time(2)).unwrap(), Acceptance::Repeat);
        let state = s.command_state(command(1)).unwrap().unwrap();
        assert_eq!((state.outcome, state.acknowledged), (None, false));
        s.set_outcome(command(1), CommandOutcome::Applied).unwrap();
        assert_eq!(s.open_acknowledgement().unwrap()[0].outcome, Some(CommandOutcome::Applied));
    }

    #[test]
    fn unacknowledged_outcomes_survive_closing_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        {
            let mut s = Store::open(&path).unwrap();
            s.accept_command(command(2), time(2)).unwrap();
            s.set_outcome(command(2), CommandOutcome::NotApplicable).unwrap();
            s.accept_command(command(1), time(1)).unwrap();
            s.set_outcome(command(1), CommandOutcome::Rejected).unwrap();
            s.accept_command(command(3), time(3)).unwrap();
            s.set_outcome(command(3), CommandOutcome::Applied).unwrap();
            s.mark_acknowledged(command(3)).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let basket = s.open_acknowledgement().unwrap();
        assert_eq!(
            basket,
            [
                CommandState {
                    command: command(1),
                    received: time(1),
                    outcome: Some(CommandOutcome::Rejected),
                    acknowledged: false
                },
                CommandState {
                    command: command(2),
                    received: time(2),
                    outcome: Some(CommandOutcome::NotApplicable),
                    acknowledged: false
                },
            ]
        );
    }

    #[test]
    fn an_acknowledged_outcome_cannot_be_changed_any_more() {
        let mut s = store();
        s.accept_command(command(1), time(1)).unwrap();
        s.set_outcome(command(1), CommandOutcome::Applied).unwrap();
        // Before the acknowledgement the outcome may still change (re-execution after a crash).
        s.set_outcome(command(1), CommandOutcome::NotApplicable).unwrap();
        s.mark_acknowledged(command(1)).unwrap();
        assert!(matches!(
            s.set_outcome(command(1), CommandOutcome::Rejected),
            Err(StoreError::CommandAcknowledged(_))
        ));
        assert_eq!(
            s.command_state(command(1)).unwrap().unwrap().outcome,
            Some(CommandOutcome::NotApplicable)
        );
    }

    #[test]
    fn acknowledging_without_an_outcome_and_unknown_commands_are_errors() {
        let mut s = store();
        assert!(matches!(
            s.set_outcome(command(9), CommandOutcome::Applied),
            Err(StoreError::CommandUnknown(_))
        ));
        assert!(matches!(s.mark_acknowledged(command(9)), Err(StoreError::CommandUnknown(_))));
        s.accept_command(command(1), time(1)).unwrap();
        assert!(matches!(
            s.mark_acknowledged(command(1)),
            Err(StoreError::CommandWithoutOutcome(_))
        ));
        assert_eq!(s.command_state(command(9)).unwrap(), None);
    }

    #[test]
    fn clearing_removes_only_old_acknowledged_commands() {
        let mut s = store();
        for (value, acknowledge) in [(1, true), (2, false), (3, true)] {
            s.accept_command(command(value), time(i64::try_from(value).unwrap())).unwrap();
            s.set_outcome(command(value), CommandOutcome::Applied).unwrap();
            if acknowledge {
                s.mark_acknowledged(command(value)).unwrap();
            }
        }
        assert_eq!(s.clear_delivery(time(3)).unwrap(), 1);
        assert_eq!(s.command_state(command(1)).unwrap(), None);
        assert!(s.command_state(command(2)).unwrap().is_some(), "unacknowledged stays");
        assert!(s.command_state(command(3)).unwrap().is_some(), "too young");
    }
}
