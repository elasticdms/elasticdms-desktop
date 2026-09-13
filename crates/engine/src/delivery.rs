//! The delivery channel — signed orders from a closed catalogue (ADR-D04, 03 §7.3).
//!
//! A long poll `GET /v1/delivery/commands?wait=25`, **outbound only**: the folder client listens on
//! no port. It runs with the **device** token and not with the user's — an erasure has to reach a
//! device even when nobody is signed in, and precisely then pinned copies are still lying on the
//! disk.
//!
//! The way of a single command, and **every** stage can stop it:
//!
//! ```text
//! raw value (serde_json::Value)      a broken command does not block the channel
//!    │ CommandEnvelope::from_value
//!    ▼ without commandId → only a security warning (nothing to acknowledge)
//! Store::accept_command              delivered at least once, effective once
//!    │ Acceptance::Done → only acknowledge (again)
//!    ▼
//! check_command_signature            against the ANCHORED set; without an anchor: REJECTED
//!    │                               "when in doubt, preserve" (geraete-auth §5.8)
//!    ▼
//! CommandEnvelope::command           closed catalogue, unknown field → REJECTED
//!    │                               together with the size limit (500 documents per command)
//!    ▼
//! rate limit                         at most 30 commands per minute → FAILED
//!    ▼
//! execute → Store::set_outcome → acknowledge → Store::mark_acknowledged
//! ```
//!
//! ## Why in this order
//!
//! **Raw first.** The answer carries the commands as JSON values; a model comes into being only at
//! the translation. Whoever read the whole page in one go would let a single faulty order hold up
//! every later erasure (03 §7.3.1).
//!
//! **Deduplication before the execution.** The server delivers until it is acknowledged. Without
//! [`edms_store::Store::accept_command`] a command whose acknowledgement was lost in the network
//! would run a second time — and with `ERASURE` that would be a second log entry about a document
//! that no longer exists.
//!
//! **Signature before the translation.** What is checked is the **raw value as it arrived**,
//! unknown fields included (rule P2); `edms-crypto` separates `serverSignature` off and
//! canonicalises the rest. Whoever translated into a model first and back again would lose the
//! unknown fields, and the signature of an honest server would no longer hold.
//!
//! **Outcome before the acknowledgement.** If the machine crashes between the two, the outcome lies
//! unacknowledged in the table, and [`edms_store::Store::open_acknowledgement`] is the outbox that
//! every round empties first.
//!
//! ## What the channel does not do
//!
//! It executes **nothing** that does not stand in the catalogue, and nothing without a valid
//! signature against a confirmed anchor. A delivery channel that executes arbitrary commands is a
//! remote erasure tool for anybody who has the server or the load balancer in hand — and the threat
//! model expressly names the compromised server (geraete-auth §5.4).

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use edms_core::delivery::{Actions, Command, CommandOutcome, Reason, actions};
use edms_core::identifier::{CommandIdentifier, DocumentIdentifier};
use edms_core::log::{LogEntry, LogKind};
use edms_core::namespace::{Container, EntryIdentifier};
use edms_core::port::{LocalState, PlatformError};
use edms_crypto::key_set::check_command_signature;
use edms_net::server::AcknowledgementOutcome;
use edms_net::{ApiResult, IdempotencyKey, KeyBinding, KeySource};
use edms_store::Acceptance;
use edms_wire::basics::ErrorKind;
use edms_wire::delivery::{
    Acknowledgement, CommandEnvelope, DeliveryPage, DeliveryQuery, WAIT_TIME_SECOND,
};
use serde_json::Value;

use crate::engine::Shared;
use crate::error::EngineError;
use crate::event::{CommandKind, EngineEvent};
use crate::time::now;

/// Setting key of the cursor last confirmed.
///
/// The cursor is opaque and belongs to the server; it is stored so that a restart does not get
/// every command already dealt with delivered once more.
pub const SETTING_CURSOR: &str = "delivery.cursor";

/// How long a poll stays open — the upper limit from ADR-013 (25 s).
///
/// Above that, load balancers and corporate proxies do not hold the connection, and the failure
/// shows itself as a sporadic disconnect instead of an error.
pub const WAIT_TIME: u32 = WAIT_TIME_SECOND;

/// The first pause after a network error.
pub const BACKOFF_START: Duration = Duration::from_secs(2);

/// The longest pause between two attempts (03 §7.3.1: at most five minutes).
///
/// A client that runs against a failed service every 25 seconds prolongs the failure; one that
/// stays silent for longer than five minutes gets an erasure too late.
pub const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// How long is waited for as long as there is no device token.
///
/// A device waiting for the approval by a human being is not to ask every second — the approval
/// comes only once somebody has compared the fingerprint anyway.
pub const IDLE_WITHOUT_TOKEN: Duration = Duration::from_secs(30);

/// The time window of the rate limit.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// The beat: ask, execute, acknowledge — for as long as the engine runs.
pub(crate) async fn channel(shared: Arc<Shared>) {
    let mut rate = RateLimit::new();
    let mut pause = BACKOFF_START;
    let mut disturbed = false;
    let mut wait_time = None;
    loop {
        if shared.is_stopped() {
            return;
        }
        match a_round(&shared, &mut rate, &mut wait_time).await {
            Ok(ran) => {
                if disturbed {
                    shared.append_log(&LogEntry::plain(now(), LogKind::ConnectionRestored, None));
                    shared.set_connected(true);
                    disturbed = false;
                }
                pause = BACKOFF_START;
                if !ran {
                    tokio::time::sleep(IDLE_WITHOUT_TOKEN).await;
                }
            }
            Err(error) => {
                // Only a real line failure is an "interrupted connection"; a server judgement is
                // an answer, and it does not belong in the user's log.
                if matches!(error, EngineError::NoNetwork(_)) && !disturbed {
                    shared.append_log(&LogEntry::plain(
                        now(),
                        LogKind::ConnectionLost,
                        Some(error.to_string()),
                    ));
                    shared.set_connected(false);
                    disturbed = true;
                }
                tracing::debug!(%error, "delivery channel without an answer; there is waiting");
                tokio::time::sleep(with_spread(pause)).await;
                pause = (pause * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// One round: token, outbox, poll, commands. `false` means: there is no device token.
async fn a_round(
    shared: &Arc<Shared>,
    rate: &mut RateLimit,
    wait_time: &mut Option<u32>,
) -> Result<bool, EngineError> {
    if !fetch_device_token(shared, false).await? {
        return Ok(false);
    }
    // The outbox first: an acknowledgement a crash left lying would otherwise permanently report a
    // fault that is none (`delivery.unacknowledgedCommands` in the heartbeat).
    empty_outbox(shared).await?;

    let wait = match *wait_time {
        Some(wait) => wait,
        None => {
            let wait = ask_wait_time(shared).await;
            *wait_time = Some(wait);
            wait
        }
    };
    let page = fetch_page(shared, wait).await?;
    if !page.next_cursor.is_empty() {
        shared.store().set_setting(SETTING_CURSOR, &page.next_cursor)?;
    }
    for value in page.items {
        if shared.is_stopped() {
            return Ok(true);
        }
        // One after another, never side by side: two executions of the same command would both see
        // `Acceptance::Interrupted` and both run (edms_store::delivery).
        process(shared, value, rate).await;
    }
    Ok(true)
}

/// Makes sure there is a device token. `false` means: the device is not set up or is waiting for
/// the approval — then there is nothing to collect.
///
/// `force` fetches a new one even when one lies in memory: the answer to a `401` in
/// mid-operation.
async fn fetch_device_token(shared: &Arc<Shared>, force: bool) -> Result<bool, EngineError> {
    if !force && KeySource::token(&*shared.bundle, KeyBinding::Device).is_some() {
        return Ok(true);
    }
    if shared.store().setting(crate::session::SETTING_ENROLLED)?.as_deref() != Some("yes") {
        return Ok(false);
    }
    let result = shared.server.fetch_device_token().await;
    // The rule, not an error: a human being has not compared the fingerprint yet.
    if let ApiResult::SlotError { problem, .. } = &result
        && problem.error_kind() == ErrorKind::DeviceApprovalPending
    {
        return Ok(false);
    }
    let success = crate::value_from(result, "the device token", shared.catalogue())?;
    shared.bundle.set_device_token(&success.value.access_token);
    Ok(true)
}

/// How long the server holds a line open.
///
/// The value stands in the device object (`policy.deliveryWaitSeconds`, 03 §7.0.5). Whoever
/// stubbornly sends 25 gets `400 validation-failed` from a server with a lower limit and thereby
/// keeps the channel shut forever. The upper limit from ADR-013 stays the upper limit all the same:
/// what the server offered beyond it is capped.
///
/// Asked once per run; if the server does not answer, [`WAIT_TIME`] applies.
async fn ask_wait_time(shared: &Arc<Shared>) -> u32 {
    match shared.server.device_status().await {
        ApiResult::Success(success) => success
            .value
            .policy
            .and_then(|policy| policy.delivery_wait_seconds)
            .and_then(|second| u32::try_from(second).ok())
            .map_or(WAIT_TIME, |second| second.clamp(1, WAIT_TIME)),
        other => {
            tracing::debug!(
                reason = crate::reason_from(&other, shared.catalogue()),
                "the device state names no waiting time; the upper limit applies"
            );
            WAIT_TIME
        }
    }
}

/// The next page of the long poll — with exactly **one** second attempt after `401`.
///
/// A loop would be sustained fire at the token endpoint for a token the server rejects.
async fn fetch_page(shared: &Arc<Shared>, wait: u32) -> Result<DeliveryPage, EngineError> {
    let cursor = shared.store().setting(SETTING_CURSOR)?;
    let query = DeliveryQuery::new(wait, cursor.clone())
        .map_err(|error| EngineError::Internal(error.to_string()))?;
    let result = crate::value_from(
        shared.server.delivery_collect(&query).await,
        "the delivery channel",
        shared.catalogue(),
    );
    match result {
        Ok(success) => Ok(success.value),
        Err(EngineError::SessionExpired(_)) => {
            if !fetch_device_token(shared, true).await? {
                return Ok(DeliveryPage { items: Vec::new(), next_cursor: String::new() });
            }
            Ok(crate::value_from(
                shared.server.delivery_collect(&query).await,
                "the delivery channel",
                shared.catalogue(),
            )?
            .value)
        }
        // A cursor the server no longer knows would clog the channel forever. It is discarded; the
        // next round asks without it and gets everything open — every command is deduplicated, so
        // that is at most work, never damage.
        Err(error @ EngineError::Refused(_)) if cursor.is_some() => {
            tracing::warn!(%error, "the delivery cursor is discarded");
            shared.store().delete_setting(SETTING_CURSOR)?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

/// Sends every acknowledgement an earlier run could not get rid of.
async fn empty_outbox(shared: &Arc<Shared>) -> Result<(), EngineError> {
    let open = shared.store().open_acknowledgement()?;
    for state in open {
        let Some(outcome) = state.outcome else {
            continue;
        };
        // Without a reason: the text of the first attempt is not stored, and inventing a new one
        // would mean telling the server something other than the first time.
        acknowledge(shared, state.command, &Acknowledgement::new(outcome, None)).await;
    }
    Ok(())
}

/// A single entry of the delivery page, from raw to acknowledged.
async fn process(shared: &Arc<Shared>, value: Value, rate: &mut RateLimit) {
    let envelope = match CommandEnvelope::from_value(value) {
        Ok(envelope) => envelope,
        Err(error) => {
            let Some(command) = error.command() else {
                // Without a readable `commandId` there is nothing to acknowledge. It stays visible
                // all the same: a channel that quietly delivers rubbish is a fault.
                warn(shared, &error.to_string());
                return;
            };
            complete(
                shared,
                command,
                Acknowledgement::new(CommandOutcome::Rejected, Some(error.to_string())),
            )
            .await;
            return;
        }
    };
    let identifier = envelope.command_id();

    let acceptance = match shared.store().accept_command(identifier, now()) {
        Ok(acceptance) => acceptance,
        Err(error) => {
            tracing::error!(%error, %identifier, "command not accepted");
            return;
        }
    };
    if !acceptance.from_run() {
        if let Acceptance::Done { outcome, acknowledged: false } = acceptance {
            acknowledge(shared, identifier, &Acknowledgement::new(outcome, None)).await;
        }
        return;
    }

    // The signature against the **anchored** set. Without an anchor none holds — and then nothing
    // is removed (ADR-D04, geraete-auth §5.8 "when in doubt, preserve").
    let key_set = match crate::session::read_key_set(shared) {
        Ok(key_set) => key_set,
        Err(error) => {
            warn(
                shared,
                &shared.catalogue().format(
                    edms_i18n::key::NOTICE_KEY_SET_UNREADABLE,
                    &[("reason", &error.to_string())],
                ),
            );
            complete(
                shared,
                identifier,
                Acknowledgement::new(CommandOutcome::Failed, Some(error.to_string())),
            )
            .await;
            return;
        }
    };
    // What is checked is the **raw value as it arrived** — `edms-crypto` separates
    // `serverSignature` off itself and canonicalises the rest (JCS, rule P2). Whoever left
    // something out here would hand over different bytes from the ones the server signed.
    let raw = Value::Object(envelope.raw().clone());
    if let Err(error) = check_command_signature(&raw, &key_set) {
        warn(
            shared,
            &shared.catalogue().format(
                edms_i18n::key::NOTICE_DELIVERY_SIGNATURE,
                &[("reason", &error.to_string())],
            ),
        );
        complete(
            shared,
            identifier,
            Acknowledgement::new(CommandOutcome::Rejected, Some(error.to_string())),
        )
        .await;
        return;
    }

    // The strict translation: unknown kind, foreign device, unknown payload field, size limit —
    // each of those is `REJECTED`, never a half execution (03 §7.3.2).
    let command = match envelope.command(shared.bundle.device()) {
        Ok(command) => command,
        Err(error) => {
            complete(shared, identifier, error.acknowledgement()).await;
            return;
        }
    };

    if !rate.take(now().unix_millis()) {
        // `FAILED` and not `REJECTED`: the server splits large erasures up, and only this outcome
        // makes it deliver again (03 §7.3.6).
        complete(
            shared,
            identifier,
            Acknowledgement::new(
                CommandOutcome::Failed,
                Some(format!(
                    "this device has reached its rate limit ({} commands a minute, ADR-013); \
                     the command is carried out at the next delivery",
                    edms_core::delivery::MAX_COMMANDS_PER_MINUTE
                )),
            ),
        )
        .await;
        return;
    }

    let acknowledgement = run_from(shared, &command).await;
    if acknowledgement.outcome == CommandOutcome::Applied {
        shared.record(EngineEvent::CommandApplied { kind: CommandKind::of(&command) });
    }
    complete(shared, identifier, acknowledgement).await;
}

/// Executes a checked command and says how it came out.
async fn run_from(shared: &Arc<Shared>, command: &Command) -> Acknowledgement {
    match command {
        Command::Dehydrate { documents, reason } => dehydrate(shared, documents, *reason),
        Command::Reconcile { container } => {
            let result = match container {
                Some(container) => crate::reconcile::reconcile_container(shared, *container).await,
                None => crate::reconcile::reconcile_everything(shared).await,
            };
            match result {
                Ok(()) => Acknowledgement::new(CommandOutcome::Applied, None),
                Err(error) => Acknowledgement::new(CommandOutcome::Failed, Some(error.to_string())),
            }
        }
        // The local part of the sign-out: the server has already ended the session, a revocation
        // would be a call into the void. Clearing up happens completely all the same (requirement
        // 4).
        Command::SignOut => match crate::session::clear_after_sign_out(shared) {
            Ok(()) => Acknowledgement::new(CommandOutcome::Applied, None),
            Err(error) => Acknowledgement::new(CommandOutcome::Failed, Some(error.to_string())),
        },
        Command::RefreshKeys => match reconcile_keys(shared).await {
            Ok(()) => Acknowledgement::new(CommandOutcome::Applied, None),
            Err(error) => Acknowledgement::new(CommandOutcome::Failed, Some(error.to_string())),
        },
    }
}

/// `REFRESH_KEYS`: `GET /v1/server-keys` and the writing forward of the set.
///
/// Writing forward goes over [`edms_crypto::key_set::KeySet::adopt`] and **not** over `anchor`: the
/// distribution path establishes no trust. A smaller `keySetVersion` is a rollback attempt and is
/// rejected entirely (P8, T7); a new anchor without the counter-signature of a stored one waits and
/// has no effect (P10); nothing is ever removed (P9). What is discarded individually stands as a
/// security warning in the usage log.
async fn reconcile_keys(shared: &Arc<Shared>) -> Result<(), EngineError> {
    let offer = crate::value_from(
        shared.server.fetch_server_key().await,
        "the server keys",
        shared.catalogue(),
    )?;
    let key_set = crate::session::read_key_set(shared)?;
    let adoption = key_set.adopt(&offer.value)?;
    if adoption.security_event() {
        warn(
            shared,
            &shared.catalogue().format(
                edms_i18n::key::NOTICE_SERVER_KEYS_REJECTED,
                &[("reason", &format!("{:?}", adoption.report_code()))],
            ),
        );
    }
    crate::session::write_key_set(shared, &adoption.set)
}

/// `DEHYDRATE`: ask per placement, compute [`actions`], do exactly that.
///
/// Synchronous on purpose: between `FileSystem::state` and `FileSystem::dehydrate` no `await` may
/// lie, otherwise the engine would decide on the basis of a state that no longer exists. What needs
/// the network (`trigger_reconcile`) runs afterwards in the background.
fn dehydrate(
    shared: &Arc<Shared>,
    documents: &[DocumentIdentifier],
    reason: Reason,
) -> Acknowledgement {
    let file_system = shared.file_system();
    // What does not hang off the pinning hangs only off the reason — and holds for a document this
    // device does not know at all (a tombstone comes into being all the same).
    let without_pinning = actions(reason, false);
    let mut situation = DehydrateSituation::default();

    for &document in documents {
        let locations = match shared.store().placements(document) {
            Ok(locations) => locations,
            Err(error) => {
                situation.remember(&error.to_string());
                continue;
            }
        };
        situation.effective |= !locations.is_empty();
        for &location in &locations {
            if without_pinning.trigger_reconcile
                && let EntryIdentifier::Document { location, .. } = location
            {
                situation.to_trigger.insert(Container::from(location));
            }
            if let Some(file_system) = &file_system {
                give_location_free(&mut situation, file_system.as_ref(), location, reason);
            }
        }
        if without_pinning.remove_entry {
            match shared.store().remove_document_everywhere(document, now()) {
                Ok(journal) => {
                    situation.effective = true;
                    crate::reconcile::register_with_platform(shared, &journal);
                }
                Err(error) => situation.remember(&error.to_string()),
            }
        }
        if without_pinning.redact_log
            && let Err(error) = shared.store().redact(document)
        {
            situation.remember(&error.to_string());
        }
    }

    write_row(shared, reason, &without_pinning, documents.len(), &situation);
    trigger(shared, &situation.to_trigger);
    situation.acknowledgement()
}

/// The order at **one** place: unpin, release, remove — in exactly this order.
///
/// Without lifting the pinning the release fails (`ERROR_CLOUD_FILE_PINNED` on Windows,
/// `NonEvictable` on macOS), and an ordered erasure would hang on a user setting.
fn give_location_free(
    situation: &mut DehydrateSituation,
    file_system: &dyn edms_core::port::FileSystem,
    location: EntryIdentifier,
    reason: Reason,
) {
    let state = match file_system.state(location) {
        Ok(state) => state,
        // If the entry does not lie on the disk, there is nothing to release — the entry in the
        // namespace is dealt with below all the same.
        Err(PlatformError::NotFound(_) | PlatformError::NotReadyPosed) => LocalState::default(),
        Err(error) => {
            situation.remember(&error.to_string());
            return;
        }
    };
    let action = actions(reason, state.pinned);
    if action.dehydrate || action.unpin {
        match file_system.dehydrate(location, action.unpin) {
            Ok(()) => situation.released += usize::from(state.hydrated),
            Err(error) => situation.remember(&error.to_string()),
        }
    }
    if action.remove_entry
        && let Err(error) = file_system.remove(location)
    {
        situation.remember(&error.to_string());
    }
}

/// The rows of the usage log and the hint to the user.
///
/// **One** row per command, not per document: the row of an erasure never carries a subject
/// (`edms_core::log`), and five hundred nameless rows say no more than one with the number.
fn write_row(
    shared: &Arc<Shared>,
    reason: Reason,
    action: &Actions,
    count: usize,
    situation: &DehydrateSituation,
) {
    if !situation.effective {
        return;
    }
    let time = now();
    match reason {
        Reason::Erasure => {
            shared.append_log(&LogEntry::erased_by_order(time));
        }
        Reason::AccessRevoked => shared.append_log(&LogEntry::plain(
            time,
            LogKind::AccessRevoked,
            Some(number_set(
                shared.catalogue(),
                edms_i18n::key::NOTICE_ACCESS_REVOKED_ONE,
                edms_i18n::key::NOTICE_ACCESS_REVOKED_MANY,
                count,
            )),
        )),
        Reason::SpaceReclaim => {
            if situation.released == 0 {
                return;
            }
            shared.append_log(&LogEntry::plain(
                time,
                LogKind::SpaceReclaimed,
                Some(number_set(
                    shared.catalogue(),
                    edms_i18n::key::NOTICE_SPACE_RECLAIMED_ONE,
                    edms_i18n::key::NOTICE_SPACE_RECLAIMED_MANY,
                    situation.released,
                )),
            ));
        }
    }
    // "Disappearing must not be silent" (requirement 6) — but without a title: the erasure register
    // is free of content (ADR-011).
    if action.notify_user {
        shared.record(EngineEvent::Hint {
            text: number_set(
                shared.catalogue(),
                edms_i18n::key::NOTICE_ERASED_BY_ORDER_ONE,
                edms_i18n::key::NOTICE_ERASED_BY_ORDER_MANY,
                count,
            ),
        });
    }
}

/// A sentence with a number instead of a name.
///
/// Two keys, not one with a `{count}`: "1 Dokument" and "2 Dokumente" differ in more than the
/// number in German as in English, and a sentence built out of fragments is exactly the kind of
/// text that reads like machine translation in one language and is wrong in the next.
fn number_set(
    catalogue: &edms_i18n::Catalog,
    one: edms_i18n::Key,
    many: edms_i18n::Key,
    count: usize,
) -> String {
    if count == 1 {
        catalogue.text(one).to_owned()
    } else {
        catalogue.format(many, &[("count", &count.to_string())])
    }
}

/// Pulls the listings of the containers concerned up in the background.
///
/// In the background, because every listing is a network call: the delivery channel is to run on
/// meanwhile, otherwise a slow reconcile holds up the next erasure.
fn trigger(shared: &Arc<Shared>, container: &BTreeSet<Container>) {
    for &one in container {
        let shared = Arc::clone(shared);
        tokio::spawn(async move {
            if let Err(error) = crate::reconcile::reconcile_container(&shared, one).await {
                tracing::debug!(%one, %error, "triggered reconcile failed");
            }
        });
    }
}

/// What comes together while dehydrating.
#[derive(Debug, Default)]
struct DehydrateSituation {
    /// Whether anything happened at all — otherwise the outcome is `NOT_APPLICABLE`.
    effective: bool,
    /// How many local copies were released.
    released: usize,
    /// The first failure; it makes the outcome `FAILED`.
    error: Option<String>,
    /// Containers whose listing is to be fetched anew at once.
    to_trigger: BTreeSet<Container>,
}

impl DehydrateSituation {
    fn remember(&mut self, reason: &str) {
        tracing::warn!(reason, "a delivery command could not be carried out fully");
        if self.error.is_none() {
            self.error = Some(reason.to_owned());
        }
    }

    fn acknowledgement(self) -> Acknowledgement {
        match (self.error, self.effective) {
            // Attempted and failed: the server may deliver again.
            (Some(reason), _) => Acknowledgement::new(CommandOutcome::Failed, Some(reason)),
            (None, true) => Acknowledgement::new(CommandOutcome::Applied, None),
            // Done without there being anything to do — the document did not lie on this device.
            (None, false) => Acknowledgement::new(CommandOutcome::NotApplicable, None),
        }
    }
}

/// Records the outcome and acknowledges it — in this order (edms_store::delivery).
async fn complete(
    shared: &Arc<Shared>,
    command: CommandIdentifier,
    acknowledgement: Acknowledgement,
) {
    if let Err(error) = shared.store().set_outcome(command, acknowledgement.outcome) {
        tracing::error!(%error, %command, "outcome not recorded; nothing is acknowledged");
        return;
    }
    acknowledge(shared, command, &acknowledgement).await;
}

/// Sends an acknowledgement and notes it once the server has it.
///
/// The `Idempotency-Key` is a ULID **per attempt**: the same key with a differing body would be
/// `422 idempotency-key-reuse`, and it must be possible for `FAILED` to become `APPLIED` later
/// (03 §7.3.6).
async fn acknowledge(
    shared: &Arc<Shared>,
    command: CommandIdentifier,
    acknowledgement: &Acknowledgement,
) {
    // An acknowledgement needs the device token — and `SIGN_OUT` has just erased it.
    match fetch_device_token(shared, false).await {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            tracing::info!(%command, "without a device token the acknowledgement waits");
            return;
        }
    }
    let key = match IdempotencyKey::generate(now()) {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(%error, "no idempotency key; the acknowledgement stays put");
            return;
        }
    };
    match shared.server.acknowledge(command, acknowledgement, &key).await {
        // `409 delivery-command-already-acknowledged` is success: the server has had it for ages.
        ApiResult::Success(success) => {
            if matches!(
                success.value,
                AcknowledgementOutcome::Accepted(_) | AcknowledgementOutcome::AlreadyAcknowledged
            ) && let Err(error) = shared.store().mark_acknowledged(command)
            {
                tracing::error!(%error, %command, "acknowledgement sent, but not noted");
            }
        }
        other => {
            tracing::warn!(
                %command,
                reason = crate::reason_from(&other, shared.catalogue()),
                "acknowledgement not accepted; it stays in the outbox"
            );
        }
    }
}

/// A security warning in the usage log — the user's only opportunity to notice it.
fn warn(shared: &Arc<Shared>, text: &str) {
    tracing::warn!(text, "security warning in the delivery channel");
    shared.append_log(&LogEntry::plain(now(), LogKind::SecurityWarning, Some(text.to_owned())));
}

/// Spreads a pause by up to a quarter downwards.
///
/// Without the spread all workstations of a building would come back in the same beat after a
/// failure and bring the just-recovered service down again. **Downwards**, so that the upper limit
/// of five minutes stays an upper limit.
fn with_spread(pause: Duration) -> Duration {
    let Ok(random) = edms_crypto::random::random_128() else {
        return pause;
    };
    let span = pause.as_millis() / 4;
    if span == 0 {
        return pause;
    }
    let deduction = u64::try_from(random % span).unwrap_or(0);
    pause.saturating_sub(Duration::from_millis(deduction))
}

/// The rate limit: at most [`edms_core::delivery::MAX_COMMANDS_PER_MINUTE`] commands in
/// [`RATE_WINDOW`].
///
/// It prevents no erasure — the server splits large erasures up — but it prevents a single forged
/// or misused key from emptying the whole mirror in one go (ADR-013). A command that is held back
/// is not discarded: it is acknowledged `FAILED` and comes again.
#[derive(Debug, Default)]
struct RateLimit {
    applied: VecDeque<i64>,
}

impl RateLimit {
    const fn new() -> Self {
        Self { applied: VecDeque::new() }
    }

    /// Takes a place in the window; `false` when none is free any more.
    fn take(&mut self, now_millis: i64) -> bool {
        let window = i64::try_from(RATE_WINDOW.as_millis()).unwrap_or(i64::MAX);
        // A clock set backwards must not lift the limit either: everything that does not lie in the
        // window **around** now falls out.
        self.applied.retain(|&time| (now_millis - time).abs() < window);
        let limit =
            usize::try_from(edms_core::delivery::MAX_COMMANDS_PER_MINUTE).unwrap_or(usize::MAX);
        if self.applied.len() >= limit {
            return false;
        }
        self.applied.push_back(now_millis);
        true
    }
}

#[cfg(test)]
mod tests {
    use edms_core::delivery::MAX_COMMANDS_PER_MINUTE;

    use super::*;

    #[test]
    fn the_rate_limit_lets_thirty_commands_a_minute_through_and_not_the_thirty_first() {
        let mut limit = RateLimit::new();
        for number in 0..MAX_COMMANDS_PER_MINUTE {
            assert!(limit.take(1_000 + i64::from(number)), "command {number} still belongs in");
        }
        assert!(!limit.take(1_100), "the thirty-first is held back");
        // A minute later the window is empty.
        assert!(limit.take(1_000 + 60_001), "after the window it goes on");
    }

    #[test]
    fn a_clock_set_backwards_does_not_lift_the_rate_limit() {
        let mut limit = RateLimit::new();
        for number in 0..MAX_COMMANDS_PER_MINUTE {
            assert!(limit.take(1_000_000 + i64::from(number)));
        }
        // The clock jumps back: the old entries now lie in the future and go on counting, otherwise
        // setting the clock back would be a way past the limit.
        assert!(!limit.take(1_000_000 - 10), "backwards too the window stays full");
    }

    #[test]
    fn the_spread_shortens_and_never_lengthens() {
        for pause in [BACKOFF_START, BACKOFF_MAX] {
            for _ in 0..32 {
                let spread = with_spread(pause);
                assert!(spread <= pause, "{spread:?} > {pause:?}");
                assert!(spread >= pause * 3 / 4, "at most a quarter: {spread:?}");
            }
        }
    }

    #[test]
    fn a_number_sentence_names_a_number_and_never_a_name() {
        use edms_i18n::{Catalog, Language, key};
        for language in Language::ALL {
            let catalogue = Catalog::of(language);
            let one = number_set(
                catalogue,
                key::NOTICE_ERASED_BY_ORDER_ONE,
                key::NOTICE_ERASED_BY_ORDER_MANY,
                1,
            );
            let many = number_set(
                catalogue,
                key::NOTICE_ERASED_BY_ORDER_ONE,
                key::NOTICE_ERASED_BY_ORDER_MANY,
                7,
            );
            assert!(one.contains('1'), "{language}: {one}");
            assert!(many.contains('7'), "{language}: {many}");
            // Never a document name — the erasure register is free of content (ADR-011).
            assert!(!one.contains("doc_") && !many.contains("doc_"), "{language}");
        }
        assert_eq!(
            number_set(
                Catalog::of(Language::De),
                key::NOTICE_ERASED_BY_ORDER_ONE,
                key::NOTICE_ERASED_BY_ORDER_MANY,
                7
            ),
            "Auf Anordnung wurde von diesem Gerät entfernt: 7 Dokumente."
        );
    }

    #[test]
    fn without_effect_the_outcome_is_not_applicable_and_an_error_beats_everything() {
        assert_eq!(
            DehydrateSituation::default().acknowledgement().outcome,
            CommandOutcome::NotApplicable,
            "a document that never lay here is done, not failed"
        );
        let effective = DehydrateSituation { effective: true, ..DehydrateSituation::default() };
        assert_eq!(effective.acknowledgement().outcome, CommandOutcome::Applied);

        let mut failed = DehydrateSituation { effective: true, ..DehydrateSituation::default() };
        failed.remember("the disk is full");
        assert_eq!(
            failed.acknowledgement().outcome,
            CommandOutcome::Failed,
            "attempted and failed: the server may deliver again"
        );
    }
}
