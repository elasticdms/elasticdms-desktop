//! The mock's remote control — what a test sets up, turns and reads back.
//!
//! A test harness is only as good as the situations it can produce. The interesting cases of the
//! contract are not the successful ones but those in which something is missing or wrong: a
//! command with a broken signature, an expired device code, a rotated nonce, a truncated content
//! body, a `503` in the middle of the long poll. Every one of those situations has a handle here —
//! and every handle is synchronous, so that a test can call it without a runtime.
//!
//! Reading back works the same way: [`Control::recording`] says what really arrived (method, path,
//! headers, status), and [`Control::access_log`] is the **server-side** access log — the rows
//! §7.2.3 demands: “every hydration is an access and belongs in the log”.

use std::sync::Arc;

use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, CommandIdentifier, DeviceIdentifier,
    DocumentIdentifier, SearchIdentifier,
};
use edms_core::namespace::Location;
use edms_core::time::Timestamp;
use serde_json::Value;

use crate::error::MockError;
use crate::pdf;
use crate::state::{
    AccessEntry, Archive, Basket, CommandItem, CommandQuality, Container, DeviceState, Document,
    Fault, LoginState, Mangling, Origin, Recording, State,
};
use crate::time::now;

/// The remote control. Cloneable as often as you like; every copy points at the same state.
#[derive(Clone, Debug)]
pub struct Control {
    state: Arc<State>,
}

impl Control {
    /// Builds a remote control onto a state.
    pub(crate) fn new(state: Arc<State>) -> Self {
        Self { state }
    }

    // ── Namespace ────────────────────────────────────────────────────────────────────────

    /// Creates a mail basket and returns its identifier.
    pub fn create_basket(&self, title: &str) -> BasketIdentifier {
        let mut inner = self.state.lock();
        let identifier: BasketIdentifier = inner.new_identifier();
        inner.baskets.push(Basket { identifier, title: title.to_owned() });
        identifier
    }

    /// Removes a mail basket.
    ///
    /// A test needs this for the one case §7.4 names: a file was dropped into a basket that is
    /// gone by the time the submission arrives — and then nothing is filed anywhere else.
    pub fn remove_basket(&self, basket: BasketIdentifier) -> bool {
        let mut inner = self.state.lock();
        let before = inner.baskets.len();
        inner.baskets.retain(|entry| entry.identifier != basket);
        inner.baskets.len() != before
    }

    /// Creates an archive and returns its identifier.
    pub fn create_archive(&self, title: &str) -> ArchiveIdentifier {
        let mut inner = self.state.lock();
        let identifier: ArchiveIdentifier = inner.new_identifier();
        inner.archives.push(Archive { identifier, title: title.to_owned() });
        identifier
    }

    /// Removes an archive **together with its case files**.
    ///
    /// A case file that outlived its archive would be reachable under no path at all: its address
    /// is `arc_…/cas_…` (namespace v2 §1), and there would be no `arc_…` any more.
    pub fn remove_archive(&self, archive: ArchiveIdentifier) -> bool {
        let mut inner = self.state.lock();
        let before = inner.archives.len();
        inner.archives.retain(|entry| entry.identifier != archive);
        if inner.archives.len() == before {
            return false;
        }
        inner.container.retain(|c| c.archive() != Some(archive));
        true
    }

    /// Creates a case file (Akte) in an archive and returns its identifier.
    pub fn create_case(&self, archive: ArchiveIdentifier, title: &str) -> CaseIdentifier {
        let mut inner = self.state.lock();
        let identifier: CaseIdentifier = inner.new_identifier();
        inner.container.push(empty_container(Location::Case { archive, case: identifier }, title));
        identifier
    }

    /// Creates a saved search.
    pub fn create_search(&self, title: &str) -> SearchIdentifier {
        let mut inner = self.state.lock();
        let identifier: SearchIdentifier = inner.new_identifier();
        inner.container.push(empty_container(Location::Search(identifier), title));
        identifier
    }

    /// Removes a case file (Akte) or a saved search together with its assignment.
    ///
    /// The documents themselves stay: a document can stand in several lists, and closing a case
    /// file does not mean destroying the record.
    pub fn remove_container(&self, location: Location) -> bool {
        let mut inner = self.state.lock();
        let before = inner.container.len();
        inner.container.retain(|c| c.location != location);
        inner.container.len() != before
    }

    /// Creates a document with real PDF bytes in a container.
    pub fn create_document(&self, location: Location, title: &str) -> Option<DocumentIdentifier> {
        let bytes = pdf::generate(title, &["Created by the mock's remote control.".to_owned()]);
        self.create_document_with_bytes(location, title, "application/pdf", bytes)
    }

    /// Creates a document with given bytes — for cases in which exactly those bytes are meant
    /// (another media type, a particular size).
    pub fn create_document_with_bytes(
        &self,
        location: Location,
        title: &str,
        media_type: &str,
        bytes: Vec<u8>,
    ) -> Option<DocumentIdentifier> {
        let mut inner = self.state.lock();
        inner.container(location)?;
        let identifier: DocumentIdentifier = inner.new_identifier();
        let now = now();
        inner.documents.insert(
            identifier,
            Document {
                identifier,
                title: title.to_owned(),
                media_type: media_type.to_owned(),
                sha256: State::checksum(&bytes),
                bytes,
                version: 1,
                created: now,
                changed: now,
                mangling: Mangling::No,
                without_rendition: false,
            },
        );
        if let Some(container) = inner.container_mut(location) {
            container.content.push(identifier);
        }
        inner.bump(location);
        Some(identifier)
    }

    /// Additionally takes an existing document into a list — the way a saved search shows a
    /// document that lies in a case file (Akte).
    pub fn link_document(&self, location: Location, document: DocumentIdentifier) -> bool {
        let mut inner = self.state.lock();
        if !inner.documents.contains_key(&document) {
            return false;
        }
        let Some(container) = inner.container_mut(location) else { return false };
        if !container.content.contains(&document) {
            container.content.push(document);
        }
        inner.bump(location);
        true
    }

    /// Removes a document from the archive and from every list.
    pub fn remove_document(&self, document: DocumentIdentifier) -> bool {
        let mut inner = self.state.lock();
        let route = inner.documents.remove(&document).is_some();
        let locations: Vec<Location> = inner
            .container
            .iter()
            .filter(|c| c.content.contains(&document))
            .map(|c| c.location)
            .collect();
        for location in locations {
            if let Some(container) = inner.container_mut(location) {
                container.content.retain(|d| *d != document);
            }
            inner.bump(location);
        }
        route
    }

    /// Gives the document a new version: new bytes, new checksum, new ETag.
    ///
    /// Exactly what the client has to notice — otherwise the placeholder carries the size and
    /// checksum of another version, and the file system would later report damage instead of a
    /// change (§7.2.2).
    pub fn new_version(&self, document: DocumentIdentifier) -> Option<String> {
        let mut inner = self.state.lock();
        let version = {
            let doc = inner.documents.get_mut(&document)?;
            doc.version = doc.version.saturating_add(1);
            doc.changed = now();
            doc.bytes = pdf::generate(
                &doc.title,
                &[format!("Version {} — renewed by the remote control.", doc.version)],
            );
            doc.sha256 = State::checksum(&doc.bytes);
            doc.version.to_string()
        };
        let locations: Vec<Location> = inner
            .container
            .iter()
            .filter(|c| c.content.contains(&document))
            .map(|c| c.location)
            .collect();
        for location in locations {
            inner.bump(location);
        }
        Some(version)
    }

    /// Sets the display limit of a container (`displayLimit`, §7.1.2); `None` means "the one of
    /// the configuration".
    pub fn set_display_limit(
        &self,
        location: Location,
        limit: Option<u64>,
        refinement: Option<String>,
    ) -> bool {
        let mut inner = self.state.lock();
        let Some(container) = inner.container_mut(location) else { return false };
        container.display_limit = limit;
        container.refinement = refinement;
        true
    }

    /// Makes a saved search unrunnable (§7.1.3) — an error with a reason, never an empty folder.
    pub fn make_search_unrunnable(
        &self,
        search: SearchIdentifier,
        field: &str,
        detail: &str,
    ) -> bool {
        let mut inner = self.state.lock();
        let Some(container) = inner.container_mut(Location::Search(search)) else { return false };
        container.not_runnable = Some((field.to_owned(), detail.to_owned()));
        true
    }

    /// Makes the next content fetch go wrong on purpose (contract test T13).
    pub fn mangle(&self, document: DocumentIdentifier, kind: Mangling) -> bool {
        let mut inner = self.state.lock();
        match inner.documents.get_mut(&document) {
            Some(doc) => {
                doc.mangling = kind;
                true
            }
            None => false,
        }
    }

    /// Takes every deliverable rendition away from the document (`representation-unavailable`, §7.2.1).
    pub fn revoke_rendition(&self, document: DocumentIdentifier, without: bool) -> bool {
        let mut inner = self.state.lock();
        match inner.documents.get_mut(&document) {
            Some(doc) => {
                doc.without_rendition = without;
                true
            }
            None => false,
        }
    }

    /// The mail baskets, as the listing shows them.
    pub fn baskets(&self) -> Vec<(BasketIdentifier, String)> {
        self.state
            .lock()
            .baskets
            .iter()
            .map(|entry| (entry.identifier, entry.title.clone()))
            .collect()
    }

    /// The archives, as the listing shows them.
    pub fn archives(&self) -> Vec<(ArchiveIdentifier, String)> {
        self.state
            .lock()
            .archives
            .iter()
            .map(|entry| (entry.identifier, entry.title.clone()))
            .collect()
    }

    /// The case files (Akten), each with the archive it stands in.
    ///
    /// The whole location, not the bare `cas_…`: that is what addresses a case file since
    /// namespace v2, and it is what [`Control::documents`] and `edms_wire::namespace::path_document`
    /// both take.
    pub fn cases(&self) -> Vec<(Location, String)> {
        self.state
            .lock()
            .container
            .iter()
            .filter(|c| c.is_case())
            .map(|c| (c.location, c.title.clone()))
            .collect()
    }

    /// The saved searches.
    pub fn searches(&self) -> Vec<(SearchIdentifier, String)> {
        self.state
            .lock()
            .container
            .iter()
            .filter_map(|c| match c.location {
                Location::Search(identifier) => Some((identifier, c.title.clone())),
                Location::Case { .. } => None,
            })
            .collect()
    }

    /// The documents of a container in the order of the listing.
    pub fn documents(&self, location: Location) -> Vec<DocumentIdentifier> {
        self.state.lock().container(location).map(|c| c.content.clone()).unwrap_or_default()
    }

    // ── Delivery channel ─────────────────────────────────────────────────────────────────────

    /// Queues a delivery command and wakes every waiting long poll (§7.3.1).
    ///
    /// `quality` decides whether the signature holds. A test harness that only produces valid
    /// commands cannot show that the client rejects an invalid one — and that is the assurance a
    /// remote erasure hangs on (§7.3.4).
    pub fn queue_command(
        &self,
        device: DeviceIdentifier,
        kind: &str,
        payload: Value,
        quality: CommandQuality,
    ) -> Result<CommandIdentifier, MockError> {
        let identifier: CommandIdentifier = self.state.lock().new_identifier();
        let value = self.state.sign_command(identifier, device, kind, payload, &quality)?;
        {
            let mut inner = self.state.lock();
            let sequence = inner.next_sequence;
            inner.next_sequence = sequence.saturating_add(1);
            inner.commands.push(CommandItem {
                sequence,
                identifier,
                device,
                value,
                acknowledged: false,
            });
        }
        self.state.waker.notify_waiters();
        Ok(identifier)
    }

    /// Every command of the queue, oldest first.
    pub fn commands(&self) -> Vec<CommandItem> {
        self.state.lock().commands.clone()
    }

    /// The acknowledgement for a command, as soon as it is there.
    pub fn acknowledgement(&self, command: CommandIdentifier) -> Option<Value> {
        self.state.lock().acknowledgement.get(&command).cloned()
    }

    /// Appends an **unsigned** command to the next heartbeat answer (§7.0.10).
    ///
    /// The folder client may follow only `resyncPolicy` and `resyncServerKeys` there; everything
    /// else is a remote erasure tool for whoever holds the load balancer. That is exactly why a
    /// `forceLogout` has to be settable too: a test that cannot show that the client does **not**
    /// carry it out shows nothing.
    pub fn queue_heartbeat_command(&self, command: Value) {
        self.state.lock().heartbeat_command.push(command);
    }

    // ── Sign-in ────────────────────────────────────────────────────────────────────────

    /// Confirms a device flow as though a human had clicked “Confirm” on the page.
    pub fn confirm(&self, user_code: &str) -> bool {
        let user = self.state.signed_in_user();
        let mut inner = self.state.lock();
        match inner.login_mut(user_code) {
            Some(flow) if flow.state == LoginState::Pending => {
                flow.state = LoginState::Confirmed(user);
                true
            }
            _ => false,
        }
    }

    /// Rejects a device flow — a different screen from "expired" (§7.0.7).
    pub fn reject(&self, user_code: &str) -> bool {
        let mut inner = self.state.lock();
        match inner.login_mut(user_code) {
            Some(flow) => {
                flow.state = LoginState::Rejected;
                true
            }
            None => false,
        }
    }

    /// Lets a device flow lapse.
    pub fn let_lapse(&self, user_code: &str) -> bool {
        let mut inner = self.state.lock();
        match inner.login_mut(user_code) {
            Some(flow) => {
                flow.state = LoginState::Lapsed;
                flow.expires = Timestamp::NULL;
                true
            }
            None => false,
        }
    }

    /// Makes the next poll answer `slow_down` (RFC 8628 §3.5).
    pub fn demand_slower(&self, user_code: &str) -> bool {
        let mut inner = self.state.lock();
        match inner.login_mut(user_code) {
            Some(flow) => {
                flow.slower = true;
                true
            }
            None => false,
        }
    }

    /// The open sign-in flows as `(user_code, anchor)`.
    pub fn open_logins(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .login
            .iter()
            .filter(|flow| flow.state == LoginState::Pending)
            .map(|flow| (flow.user_code.clone(), flow.anchor.clone()))
            .collect()
    }

    /// Approves a device, as though an administrator had confirmed the thumbprint (§7.0.5).
    pub fn approve_device(&self, device: DeviceIdentifier) -> bool {
        self.set_device_state(device, DeviceState::Active)
    }

    /// Revokes a device (`device-revoked`).
    pub fn revoke_device(&self, device: DeviceIdentifier) -> bool {
        self.set_device_state(device, DeviceState::Locked)
    }

    fn set_device_state(&self, device: DeviceIdentifier, state: DeviceState) -> bool {
        let mut inner = self.state.lock();
        match inner.devices.get_mut(&device) {
            Some(entry) => {
                entry.state = state;
                if state == DeviceState::Locked {
                    inner.accesses.retain(|_, token| token.device != device);
                }
                true
            }
            None => false,
        }
    }

    /// The enrolled devices.
    pub fn devices(&self) -> Vec<DeviceIdentifier> {
        self.state.lock().devices.keys().copied().collect()
    }

    /// Raises the state of the server key set (`keySetVersion`).
    pub fn rotate_key_set(&self) -> u64 {
        let mut inner = self.state.lock();
        inner.key_state = inner.key_state.saturating_add(1);
        inner.key_state
    }

    // ── Nonces, faults, reading back ─────────────────────────────────────────────────────

    /// Rotates the nonce of an origin; the next call there gets `use_dpop_nonce`.
    pub fn rotate_nonce(&self, origin: Origin) -> String {
        self.state.rotate_nonce(origin)
    }

    /// The currently valid nonce of an origin.
    pub fn nonce(&self, origin: Origin) -> String {
        self.state.nonce(origin)
    }

    /// Forgets every `jti` seen — between two independent scenarios.
    pub fn forget_proofs(&self) {
        self.state.verifier.forget_everything();
    }

    /// Sets up a fault: a status, a delay, or both.
    pub fn inject_fault(&self, fault: Fault) {
        self.state.lock().fault.push(fault);
    }

    /// Takes the access log away from the server (§7.2.3): every content fetch then answers
    /// `503 access-log-unavailable` — and the client may take over **no** byte.
    pub fn lock_access_log(&self, locked: bool) {
        self.state.lock().access_log_locked = locked;
    }

    /// Takes back every fault.
    pub fn clear_faults(&self) {
        self.state.lock().fault.clear();
    }

    /// What really arrived — method, path, headers, status.
    pub fn recording(&self) -> Vec<Recording> {
        self.state.lock().recording.clone()
    }

    /// The recordings for a path prefix.
    pub fn recordings_for(&self, path_start: &str) -> Vec<Recording> {
        self.state
            .lock()
            .recording
            .iter()
            .filter(|entry| entry.path.starts_with(path_start))
            .cloned()
            .collect()
    }

    /// Forgets every recording.
    pub fn forget_recording(&self) {
        self.state.lock().recording.clear();
    }

    /// The **server-side** access log (§7.2.3): who read which document when, and with which
    /// program.
    pub fn access_log(&self) -> Vec<AccessEntry> {
        self.state.lock().access.clone()
    }

    /// The `serverKeys` block as `GET /v1/server-keys` delivers it — for tests that want to
    /// compute the anchor thumbprint themselves.
    pub fn key_block(&self) -> Result<Value, MockError> {
        Ok(self.state.key_block()?)
    }
}

/// A container without content.
fn empty_container(location: Location, title: &str) -> Container {
    Container {
        location,
        title: title.to_owned(),
        changed: now(),
        content: Vec::new(),
        display_limit: None,
        refinement: None,
        not_runnable: None,
        version: 1,
    }
}
