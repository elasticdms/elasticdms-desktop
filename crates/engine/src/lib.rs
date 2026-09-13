//! The folder client's engine: session, namespace reconcile, hydration — and the seam to
//! everything else.
//!
//! The engine is the place where the four crates below come together and become a program out of
//! them. It knows `edms-net` (what the server says), `edms-store` (what this machine knows),
//! `edms-crypto` (what has been checked) and `edms-core` (what follows from it) — but **no platform
//! API**. The platform faces it as [`edms_core::port::FileSystem`], and it faces the platform as
//! [`edms_core::port::NamespaceSource`].
//!
//! ```text
//!    App (window, menu bar, operating system keychain)
//!       │ Engine::start(…)            ▲ engine state (watch) · engine event (broadcast)
//!       ▼                             │
//!    ┌──────────────────────────────────────────────────────────────────┐
//!    │  Engine   session · reconcile · hydration · report               │
//!    └──────────────────────────────────────────────────────────────────┘
//!       │ namespace source ▲ file system     │ server object  │ store · vault
//!       ▼                  │                  ▼                ▼
//!    edms-cfapi / edms-fileprovider       edms-net        edms-store / keychain
//! ```
//!
//! The platform layers have a second, much smaller way in: [`ingest::Intake`]. They know paths,
//! the engine knows baskets — whoever sees a file appear in a mail basket says so with
//! [`ingest::Intake::file_appeared`], and the rest is the engine's business.
//!
//! The way through the crate:
//!
//! * [`config`] — the `EDMS_*` variables, without a quiet fallback value.
//! * [`vault`] — where secrets lie; **never** in the database (ADR-D03).
//! * [`session`] — enrolment, approval, device flow, renewal, sign-out.
//! * [`reconcile`] — the dynamic folders: fetch the listing, form the difference, report it.
//! * [`hydration`] — load, check, **and only then** hand over.
//! * [`source`] — the synchronous bridge over which the platform asks.
//! * [`delivery`] — the long poll: signed orders from a closed catalogue.
//! * [`ingest`] — the mail baskets: a trigger, not a filing destination.
//! * [`event`] — what the engine calls up to the app.
//! * [`report`] — `doctor`, without the network.
//! * [`server_object`] — the same network contract, object-capable.
//!
//! ## What this crate does not do
//!
//! 1. **No window, no browser, no notification.** It reports [`EngineEvent::OpenBrowser`]; opening
//!    is done by the app (architecture rule R7).
//! 2. **No HTTP.** Every request goes over [`ServerObject`] (rule R1).
//! 3. **No SQL.** Every access goes over `edms_store::Store` (rule R3).
//! 4. **No `unsafe`**, no `unwrap`, no `todo!`.
//!
//! ## Set-up in the app
//!
//! The order is not free — `edms-net` demands the device identifier and the key source before
//! there is a server, and the platform demands the source before it registers:
//!
//! ```ignore
//! let c = EngineConfiguration::from_environment()?;
//! let mut store = Store::open(&c.data_path)?;
//! let bundle = KeyBundle::set_up(Box::new(system_keychain), &mut store, hardware)?;
//! let connection =
//!     Connection::new(&c.api_base, &c.auth_base, bundle.device(), "1.0.0")?;
//! let server = Arc::new(ServerAccess::new(connection, bundle.as_source())?);
//! let engine = Engine::start(c, server, store, bundle)?;
//! let mirror = Mirror::connect(engine.source(), engine.intake(), …)?;
//! engine.set_file_system(Arc::new(mirror));
//! engine.sign_in()?;
//! ```

#![forbid(unsafe_code)]

pub mod config;
pub mod delivery;
pub mod device_key;
mod engine;
mod error;
pub mod event;
pub mod hydration;
pub mod ingest;
pub mod reconcile;
pub mod report;
pub mod server_object;
pub mod session;
pub mod source;
#[cfg(test)]
mod stub_server;
mod time;
pub mod vault;

use edms_i18n::{Catalog, key};
use edms_net::{ApiResult, Success};

pub use crate::config::{ConfigurationError, EngineConfiguration};
pub use crate::device_key::{DeviceKeyOrigin, HardwareKeyStore, HeldKey};
pub use crate::engine::{CONCURRENT_DOWNLOADS, Engine, RECONCILE_INTERVAL, SpaceProbe};
pub use crate::error::EngineError;
pub use crate::event::{CommandKind, EngineEvent};
pub use crate::ingest::{Arrival, Intake};
pub use crate::report::{DatabaseReport, Report, StoreSpace};
pub use crate::server_object::ServerObject;
pub use crate::session::{EngineState, Identity, KeyBundle};
pub use crate::source::EngineSource;
pub use crate::vault::{StoreVault, Vault, VaultError};

/// Separates the success of a server call from every other outcome.
///
/// The five outcomes of [`ApiResult`] become **four** errors of the engine here — and `304` an
/// internal one: whoever gets `Unchanged` without having sent an ETag has built a call wrongly. The
/// callers for whom `304` is a valid outcome (the reconcile) handle it **beforehand** themselves.
pub(crate) fn value_from<T>(
    result: ApiResult<T>,
    what: &'static str,
    catalogue: &Catalog,
) -> Result<Success<T>, EngineError> {
    match result {
        ApiResult::Success(success) => Ok(success),
        ApiResult::Unchanged { .. } => Err(EngineError::Internal(format!(
            "the server answered {what} with 304 although no state was sent along"
        ))),
        ApiResult::NetworkError(error) => Err(EngineError::NoNetwork(error.to_string())),
        ApiResult::SecurityAbort { notice, .. } => Err(EngineError::Security(notice)),
        other if is_expired(&other) => {
            Err(EngineError::SessionExpired(reason_from(&other, catalogue)))
        }
        other => Err(EngineError::Refused(format!("{what}: {}", reason_from(&other, catalogue)))),
    }
}

/// Whether the server rejected the access token — the only outcome that deserves a retry.
pub(crate) fn is_expired<T>(result: &ApiResult<T>) -> bool {
    match result {
        ApiResult::SlotError { problem, .. } => {
            problem.status == Some(401)
                || problem.error_kind() == edms_wire::basics::ErrorKind::SessionExpired
        }
        _ => false,
    }
}

/// The reason a failed call carries onwards, as the user reads it.
///
/// Two sources, and the difference matters: what the **server** says (`detail`, `title`, a
/// security notice) is passed through word for word — the client must not put words into the
/// server's mouth, and the server writes in the tenant's language. Only where the server says
/// nothing does a sentence of ours stand in, and that one comes from the text catalogue.
pub(crate) fn reason_from<T>(result: &ApiResult<T>, catalogue: &Catalog) -> String {
    match result {
        // Neither of the two is an outcome `value_from` turns into an error; they stand here so
        // that the match is exhaustive and a new outcome turns this file red.
        ApiResult::Success(_) => "the call went through".to_owned(),
        ApiResult::Unchanged { .. } => "the state is unchanged".to_owned(),
        ApiResult::NetworkError(error) => error.to_string(),
        ApiResult::SecurityAbort { notice, .. } => notice.clone(),
        ApiResult::StepUpNeeded { .. } => catalogue.text(key::NOTICE_STEP_UP_REQUIRED).to_owned(),
        ApiResult::SlotError { problem, .. } => problem
            .detail
            .clone()
            .or_else(|| problem.title.clone())
            .unwrap_or_else(|| catalogue.text(key::NOTICE_SERVER_REFUSED).to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use edms_net::NetworkError;
    use edms_wire::basics::Problem;

    use super::*;

    /// One catalogue for the tests; which language does not matter, only that there is one.
    fn sample() -> &'static Catalog {
        Catalog::of(edms_i18n::Language::De)
    }

    #[test]
    fn a_network_error_does_not_become_a_server_judgement() {
        let result: ApiResult<u8> =
            ApiResult::NetworkError(NetworkError::Timeout { target: "GET /x".into() });
        let error = value_from(result, "the probe", sample()).expect_err("no success");
        assert!(matches!(error, EngineError::NoNetwork(_)), "{error}");
    }

    #[test]
    fn a_security_abort_stays_one() {
        let result: ApiResult<u8> = ApiResult::SecurityAbort {
            notice: "the issuer does not belong to this tenant".into(),
            problem: None,
        };
        let error = value_from(result, "the probe", sample()).expect_err("no success");
        assert!(matches!(error, EngineError::Security(_)), "{error}");
    }

    #[test]
    fn a_401_is_not_an_ordinary_no() {
        let problem = Problem::read(
            401,
            br#"{"type":"https://errors.elasticdms.io/session-expired","title":"x","status":401}"#,
        );
        let result: ApiResult<u8> = ApiResult::SlotError { problem, repeat_after: None };
        assert!(is_expired(&result));
        let error = value_from(result, "the probe", sample()).expect_err("no success");
        assert!(matches!(error, EngineError::SessionExpired(_)), "{error}");
    }

    #[test]
    fn an_error_on_the_merits_carries_the_server_s_sentence_onwards() {
        let problem = Problem::read(
            403,
            format!(
                r#"{{"type":"https://errors.elasticdms.io/device-pending-approval",
                     "title":"x","status":403,"detail":"{}"}}"#,
                "Das Gerät wartet auf die Freigabe."
            )
            .as_bytes(),
        );
        let result: ApiResult<u8> = ApiResult::SlotError { problem, repeat_after: None };
        let sentence = reason_from(&result, sample());
        assert_eq!(sentence, "Das Gerät wartet auf die Freigabe.");
        let error = value_from(result, "the device token", sample()).expect_err("no success");
        assert!(error.to_string().contains("Freigabe"), "{error}");
    }
}
