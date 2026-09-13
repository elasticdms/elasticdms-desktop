//! The session: which device, who is signed in, in which state — and nothing secret.
//!
//! A single row. It carries what the app has to be able to show without the keychain ("Signed in as
//! N. Lotzer", "Device is waiting for approval"), and what the usage log and the mirror hang off:
//! the account. Refresh token and private key lie in the operating system's keychain (ADR-D03,
//! point 4); for them there is neither a column nor a method here.
//!
//! The device stays put beyond the sign-out: its identifier comes into being once, before the
//! enrolment (`edms_core::identifier::DeviceIdKind`), and belongs to the machine, not to the user.

use edms_core::identifier::DeviceIdentifier;
use edms_core::time::Timestamp;
use rusqlite::{OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

use crate::Store;
use crate::account::Account;
use crate::column::{from_name, name_of, read_identifier};
use crate::error::StoreError;

const T_SESSION: &str = "session";

/// Where the session stands. In the database by name (`SIGNED_IN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    /// The device is known, nobody is signed in.
    SignedOut,
    /// The device is registered; approval by the administration is pending
    /// (`403 device-pending-approval`, ADR-D03 point 1).
    AwaitingApproval,
    /// A user is signed in.
    SignedIn,
    /// The session has expired. The tree stays visible, opening fails with "sign-in required" —
    /// never a quiet emptying of the tree (ADR-D03, consequences).
    LoginRequired,
}

impl SessionState {
    /// Whether an account belongs to the session in this state.
    pub const fn carries_login(self) -> bool {
        matches!(self, Self::SignedIn | Self::LoginRequired)
    }
}

/// Who is signed in — all of it harmless without the keychain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// The `sub` from the token; the usage-log rows hang off it.
    pub account: Account,
    /// The tenant from the token (contract extract Q-25: never selectable in the client).
    pub tenant: String,
    /// The name for "Signed in as …".
    pub display_name: String,
    /// Since when.
    pub signed_in_since: Timestamp,
}

/// The session. A sign-in belongs to exactly those states that carry one — that is enforced by
/// the type, and the table checks it once more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    device: DeviceIdentifier,
    state: SessionState,
    login: Option<Login>,
}

/// State and sign-in do not fit together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// A signed-in state without a sign-in.
    #[error(
        "in state {0:?} a sign-in belongs to the session; without it there would be no saying \
         whose tree and whose usage log are shown"
    )]
    LoginMissing(SessionState),
    /// A sign-in in a state in which nobody is signed in.
    #[error(
        "in state {0:?} nobody is signed in; a sign-in passed in would be a name without a \
         session"
    )]
    LoginSurplus(SessionState),
}

impl Session {
    /// A session from its parts; fails when state and sign-in do not fit together.
    pub fn new(
        device: DeviceIdentifier,
        state: SessionState,
        login: Option<Login>,
    ) -> Result<Self, SessionError> {
        match (state.carries_login(), login.is_some()) {
            (true, false) => Err(SessionError::LoginMissing(state)),
            (false, true) => Err(SessionError::LoginSurplus(state)),
            _ => Ok(Self { device, state, login }),
        }
    }

    /// The device is known, nobody is signed in.
    pub const fn signed_out(device: DeviceIdentifier) -> Self {
        Self { device, state: SessionState::SignedOut, login: None }
    }

    /// The device is waiting for approval by the administration.
    pub const fn awaiting_approval(device: DeviceIdentifier) -> Self {
        Self { device, state: SessionState::AwaitingApproval, login: None }
    }

    /// A user is signed in.
    pub const fn signed_in(device: DeviceIdentifier, login: Login) -> Self {
        Self { device, state: SessionState::SignedIn, login: Some(login) }
    }

    /// The device.
    pub const fn device(&self) -> DeviceIdentifier {
        self.device
    }

    /// The state.
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// The sign-in, if anybody is signed in.
    pub const fn login(&self) -> Option<&Login> {
        self.login.as_ref()
    }

    /// The account whose rows and tree are shown; `None` without a sign-in.
    pub fn account(&self) -> Option<&Account> {
        self.login.as_ref().map(|login| &login.account)
    }
}

impl Store {
    /// The stored session; `None` when there is none yet.
    pub fn session(&self) -> Result<Option<Session>, StoreError> {
        let raw = self
            .connection
            .prepare_cached(
                "SELECT device, state, account, tenant, display_name, signed_in_since \
                 FROM session WHERE only_one = 1",
            )?
            .query_row([], RawSession::read)
            .optional()?;
        raw.map(RawSession::session).transpose()
    }

    /// Writes the session; the previous one is replaced entirely.
    pub fn set_session(&mut self, session: &Session) -> Result<(), StoreError> {
        let state = name_of(&session.state, "session state")?;
        let login = session.login.as_ref();
        self.connection
            .prepare_cached(
                "INSERT INTO session (only_one, device, state, account, tenant, display_name, \
                 signed_in_since) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT (only_one) DO UPDATE SET device = excluded.device, \
                 state = excluded.state, account = excluded.account, tenant = excluded.tenant, \
                 display_name = excluded.display_name, signed_in_since = excluded.signed_in_since",
            )?
            .execute(params![
                session.device.to_string(),
                state,
                login.map(|a| a.account.as_str()),
                login.map(|a| a.tenant.as_str()),
                login.map(|a| a.display_name.as_str()),
                login.map(|a| a.signed_in_since.unix_millis()),
            ])?;
        Ok(())
    }

    /// Deletes the session entirely, the device included; `true` when there was one.
    ///
    /// For resetting the device. On a sign-out the device stays: write
    /// [`Session::signed_out`].
    pub fn delete_session(&mut self) -> Result<bool, StoreError> {
        let deleted = self.connection.prepare_cached("DELETE FROM session")?.execute([])?;
        Ok(deleted > 0)
    }
}

/// The row from `session`, not yet checked.
struct RawSession {
    device: String,
    state: String,
    account: Option<String>,
    tenant: Option<String>,
    display_name: Option<String>,
    signed_in_since: Option<i64>,
}

impl RawSession {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            device: row.get(0)?,
            state: row.get(1)?,
            account: row.get(2)?,
            tenant: row.get(3)?,
            display_name: row.get(4)?,
            signed_in_since: row.get(5)?,
        })
    }

    fn session(self) -> Result<Session, StoreError> {
        let device: DeviceIdentifier = read_identifier(&self.device, T_SESSION, "device")?;
        let state: SessionState = from_name(&self.state, T_SESSION, "state")?;
        let login = match (self.account, self.tenant, self.display_name, self.signed_in_since) {
            (Some(account), Some(tenant), Some(display_name), Some(since)) => Some(Login {
                account: Account::new(account)
                    .map_err(|error| StoreError::corrupt(T_SESSION, error.to_string()))?,
                tenant,
                display_name,
                signed_in_since: Timestamp::from_unix_millis(since),
            }),
            (None, None, None, None) => None,
            _ => {
                return Err(StoreError::corrupt(T_SESSION, "the sign-in is only half there"));
            }
        };
        Session::new(device, state, login)
            .map_err(|error| StoreError::corrupt(T_SESSION, error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use edms_core::identifier::Identifier;

    use super::*;
    use crate::test_support::{store, time};

    fn device() -> DeviceIdentifier {
        Identifier::from_value(42)
    }

    fn login() -> Login {
        Login {
            account: Account::new("usr_A").unwrap(),
            tenant: "ten_lm".into(),
            display_name: "N. Lotzer".into(),
            signed_in_since: time(5),
        }
    }

    #[test]
    fn a_session_survives_the_round_trip_in_every_state() {
        let mut s = store();
        assert_eq!(s.session().unwrap(), None);
        let all = [
            Session::signed_out(device()),
            Session::awaiting_approval(device()),
            Session::signed_in(device(), login()),
            Session::new(device(), SessionState::LoginRequired, Some(login())).unwrap(),
        ];
        for session in all {
            s.set_session(&session).unwrap();
            assert_eq!(s.session().unwrap().as_ref(), Some(&session));
        }
    }

    #[test]
    fn a_sign_in_belongs_to_exactly_the_signed_in_states() {
        use SessionState::*;
        assert_eq!(
            Session::new(device(), SignedIn, None),
            Err(SessionError::LoginMissing(SignedIn))
        );
        assert_eq!(
            Session::new(device(), LoginRequired, None),
            Err(SessionError::LoginMissing(LoginRequired))
        );
        assert_eq!(
            Session::new(device(), SignedOut, Some(login())),
            Err(SessionError::LoginSurplus(SignedOut))
        );
        assert_eq!(
            Session::new(device(), AwaitingApproval, Some(login())),
            Err(SessionError::LoginSurplus(AwaitingApproval))
        );
    }

    #[test]
    fn signing_out_keeps_the_device_and_takes_the_name() {
        let mut s = store();
        s.set_session(&Session::signed_in(device(), login())).unwrap();
        assert_eq!(s.session().unwrap().unwrap().account().map(Account::as_str), Some("usr_A"));

        s.set_session(&Session::signed_out(device())).unwrap();
        let read = s.session().unwrap().unwrap();
        assert_eq!((read.device(), read.state()), (device(), SessionState::SignedOut));
        assert!(read.login().is_none());
        let raw: (Option<String>, Option<String>) = s
            .connection
            .query_row("SELECT account, display_name FROM session", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(raw, (None, None));

        assert!(s.delete_session().unwrap());
        assert_eq!(s.session().unwrap(), None);
        assert!(!s.delete_session().unwrap());
    }

    #[test]
    fn the_table_takes_no_half_sign_in_not_even_by_hand() {
        let s = store();
        let half = s.connection.execute(
            "INSERT INTO session (only_one, device, state, account) VALUES (1, ?1, 'SIGNED_IN', 'usr_A')",
            params![device().to_string()],
        );
        assert!(half.is_err());
        let without_account = s.connection.execute(
            "INSERT INTO session (only_one, device, state) VALUES (1, ?1, 'SIGNED_IN')",
            params![device().to_string()],
        );
        assert!(without_account.is_err());
    }
}
