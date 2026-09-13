//! The app's side: accepts connections and answers them out of the engine.
//!
//! One acceptance thread, one thread per connection, at most [`MAX_CONNECTION`] at a time. Once the
//! limit is reached, the acceptance thread accepts again only when a place becomes free; further
//! extension requests wait that way in the operating system's queue instead of being refused (a
//! refusal would look to the Finder like a terminated app).
//!
//! **Cancellation.** The extension cancels by closing the connection. The sink the engine gets here
//! ([`RemoteSink`]) notices that in two ways: a write fails, or `cancelled()` sees the end of the
//! line when it looks (without reading, `peek`). Then `write` delivers a [`SinkError`] and
//! `cancelled` `true` — the engine aborts the download instead of going on loading for nobody.
//!
//! **Shutting down.** `Drop` stops the acceptance, closes all open connections (blocked readers
//! wake up, remote sinks report cancelled) and waits at most [`FAREWELL_DEADLINE`] for the
//! connection threads. Not longer: an engine stuck in a 60-second read operation is not to hold the
//! app's shutdown up for a minute; its thread holds a reference of its own to the source and ends
//! by itself.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use edms_core::namespace::EntryIdentifier;
use edms_core::port::{ContentRequest, ContentSink, NamespaceSource, SinkError, SourceError};

use crate::error::BridgeError;
use crate::frame::{self, Deadline, Inbox, Limit, ReadError, WriteError};
use crate::message::{Handshake, Notice, Request};
use crate::rendezvous::{self, Rendezvous};
use crate::{MAX_CONNECTION, MAX_DATA_CHUNK, MAX_MESSAGE, READ_DEADLINE, VERSION};

/// How long a handshake may take from acceptance on — fixed, not extended per byte: a mute or
/// dripping connection does not hold one of the 16 places longer than that.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// How long the request after WELCOME may take; the extension sends it at once.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Read deadline of the socket; afterwards a look is taken at whether the app is shutting down.
const TIME_SLICE: Duration = Duration::from_millis(250);
/// At most this often `cancelled()` looks at the line (three system calls per look).
const CHECK_INTERVAL: Duration = Duration::from_millis(25);
/// This long `Drop` waits at most for running connections.
const FAREWELL_DEADLINE: Duration = Duration::from_secs(5);
/// This long `Drop` waits at most for the wake-up call to its own acceptance.
const WAKE_DEADLINE: Duration = Duration::from_secs(1);
/// Pause after an unexpected acceptance error ("too many open files", say), so that the acceptance
/// thread does not run in circles.
const PAUSE_AFTER_ACCEPTANCE_ERROR: Duration = Duration::from_millis(50);

const CANCELLED: &str =
    "the extension cancelled the request; the content is not transferred any further";

/// The deadlines of the app side; shorter in tests.
#[derive(Debug, Clone, Copy)]
struct Setting {
    handshake_deadline: Duration,
    request_deadline: Duration,
}

impl Default for Setting {
    fn default() -> Self {
        Self { handshake_deadline: HANDSHAKE_DEADLINE, request_deadline: REQUEST_DEADLINE }
    }
}

/// The line on the app's side. Listens on 127.0.0.1 on a free port; stops on `Drop`.
///
/// ```no_run
/// # use std::sync::Arc;
/// # fn example(engine: Arc<dyn edms_bridge::NamespaceSource>, random: [u8; 32])
/// # -> Result<(), edms_bridge::BridgeError> {
/// use edms_bridge::{BridgeServer, Rendezvous, secret_from_bytes};
/// let server = BridgeServer::start(engine, &secret_from_bytes(&random))?;
/// server.rendezvous().write(&Rendezvous::default_path()?)?;
/// # Ok(()) }
/// ```
pub struct BridgeServer {
    port: u16,
    secret: String,
    shared: Arc<Shared>,
    acceptor: Option<JoinHandle<()>>,
}

impl fmt::Debug for BridgeServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeServer").field("port", &self.port).finish_non_exhaustive()
    }
}

struct Shared {
    source: Arc<dyn NamespaceSource>,
    secret: Vec<u8>,
    setting: Setting,
    hold: AtomicBool,
    book: Mutex<ConnectionBook>,
    switch: Condvar,
}

/// The open connections, each with a second handle on the socket, so that they can be closed when
/// shutting down.
#[derive(Default)]
struct ConnectionBook {
    next: u64,
    open: HashMap<u64, TcpStream>,
}

impl BridgeServer {
    /// Starts the line for `source`; `secret` is the base64url secret of 32 random bytes
    /// ([`crate::secret_from_bytes`]).
    ///
    /// A secret of another form is rejected: a short or empty secret would be an open door that
    /// looks like a locked one.
    pub fn start(
        source: Arc<dyn NamespaceSource>,
        secret: &str,
    ) -> Result<BridgeServer, BridgeError> {
        Self::start_with(source, secret, Setting::default())
    }

    fn start_with(
        source: Arc<dyn NamespaceSource>,
        secret: &str,
        setting: Setting,
    ) -> Result<BridgeServer, BridgeError> {
        rendezvous::check_secret(secret).map_err(BridgeError::Secret)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|why| BridgeError::Listening(why.to_string()))?;
        let port =
            listener.local_addr().map_err(|why| BridgeError::Listening(why.to_string()))?.port();
        let shared = Arc::new(Shared {
            source,
            secret: secret.as_bytes().to_vec(),
            setting,
            hold: AtomicBool::new(false),
            book: Mutex::new(ConnectionBook::default()),
            switch: Condvar::new(),
        });
        let for_acceptance = Arc::clone(&shared);
        let acceptor = thread::Builder::new()
            .name("edms-bridge-accept".to_owned())
            .spawn(move || accept(&listener, &for_acceptance))
            .map_err(|why| BridgeError::Listening(format!("no acceptance thread: {why}")))?;
        tracing::info!(port, "bridge listens on 127.0.0.1");
        Ok(Self { port, secret: secret.to_owned(), shared, acceptor: Some(acceptor) })
    }

    /// The port on 127.0.0.1.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The rendezvous details of this server, ready for [`Rendezvous::write`].
    pub fn rendezvous(&self) -> Rendezvous {
        Rendezvous {
            port: self.port,
            secret: self.secret.clone(),
            pid: std::process::id(),
            version: VERSION,
        }
    }
}

impl Drop for BridgeServer {
    fn drop(&mut self) {
        self.shared.stop();
        // Wakes the acceptance if it is blocked in accept(); if it is waiting for a place, stop has
        // already woken it.
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let wake_up = TcpStream::connect_timeout(&address, WAKE_DEADLINE);
        if let Some(acceptor) = self.acceptor.take() {
            if wake_up.is_ok() || acceptor.is_finished() {
                let _ = acceptor.join();
            } else {
                tracing::warn!(
                    port = self.port,
                    "bridge: the accept loop could not be woken; its thread ends with the process"
                );
            }
        }
        drop(wake_up);
        self.shared.close_all();
        if !self.shared.wait_until_empty(FAREWELL_DEADLINE) {
            tracing::warn!(
                port = self.port,
                "bridge: not every connection ended within {} s; they run out without a line",
                FAREWELL_DEADLINE.as_secs()
            );
        }
        tracing::info!(port = self.port, "bridge stopped");
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, ConnectionBook> {
        // A panic in a connection thread must not lock the line for all the others; the book is
        // consistent in itself after every single operation.
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn halted(&self) -> bool {
        self.hold.load(Ordering::SeqCst)
    }

    fn stop(&self) {
        // Set under the lock: the acceptance thread checks `hold` under the same lock before it
        // waits — that way the wake-up call is not lost between checking and waiting.
        let book = self.lock();
        self.hold.store(true, Ordering::SeqCst);
        drop(book);
        self.switch.notify_all();
    }

    fn wait_on_space(&self) -> bool {
        let mut book = self.lock();
        while book.open.len() >= MAX_CONNECTION && !self.halted() {
            book = self.switch.wait(book).unwrap_or_else(PoisonError::into_inner);
        }
        !self.halted()
    }

    fn insert(&self, stream: &TcpStream) -> Option<u64> {
        let second_handle = match stream.try_clone() {
            Ok(handle) => handle,
            Err(why) => {
                tracing::warn!(error = %why, "bridge: the connection could not be duplicated; refused");
                return None;
            }
        };
        let mut book = self.lock();
        let identifier = book.next;
        book.next = book.next.wrapping_add(1);
        book.open.insert(identifier, second_handle);
        Some(identifier)
    }

    fn carry_from(&self, identifier: u64) {
        let mut book = self.lock();
        book.open.remove(&identifier);
        drop(book);
        self.switch.notify_all();
    }

    fn close_all(&self) {
        for stream in self.lock().open.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn wait_until_empty(&self, deadline: Duration) -> bool {
        let until = Instant::now() + deadline;
        let mut book = self.lock();
        while !book.open.is_empty() {
            let now = Instant::now();
            if now >= until {
                return false;
            }
            book = self
                .switch
                .wait_timeout(book, until - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// Carries a connection out, however its thread ends — on a panic too.
struct Checkout {
    shared: Arc<Shared>,
    identifier: u64,
}

impl Drop for Checkout {
    fn drop(&mut self) {
        self.shared.carry_from(self.identifier);
    }
}

fn accept(listener: &TcpListener, shared: &Arc<Shared>) {
    loop {
        if !shared.wait_on_space() {
            return;
        }
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(_) if shared.halted() => return,
            Err(why) => {
                let temporary = matches!(
                    why.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                );
                if !temporary {
                    tracing::warn!(error = %why, "bridge: accepting a connection failed");
                    thread::sleep(PAUSE_AFTER_ACCEPTANCE_ERROR);
                }
                continue;
            }
        };
        if shared.halted() {
            return;
        }
        if !peer.ip().is_loopback() {
            // Cannot happen on 127.0.0.1; if it does, then do not serve it quietly.
            tracing::error!(%peer, "bridge: a connection from outside was refused");
            continue;
        }
        let Some(identifier) = shared.insert(&stream) else { continue };
        let for_thread = Arc::clone(shared);
        let started =
            thread::Builder::new().name("edms-bridge-connection".to_owned()).spawn(move || {
                let checkout = Checkout { shared: Arc::clone(&for_thread), identifier };
                serve(&stream, &for_thread);
                drop(stream);
                drop(checkout);
            });
        if let Err(why) = started {
            tracing::error!(error = %why, "bridge: no thread for a connection; refused");
            shared.carry_from(identifier);
        }
    }
}

/// How a connection ended, when not regularly.
enum Completion {
    /// Handshake failed — security-relevant, hence a warning.
    Refused(String),
    /// The extension is gone or has cancelled — everyday business.
    Torn(String),
    /// The extension violates the protocol.
    Log(String),
}

fn serve(stream: &TcpStream, shared: &Shared) {
    match run(stream, shared) {
        Ok(()) => {}
        Err(Completion::Refused(reason)) => {
            tracing::warn!(%reason, "bridge: connection closed without a valid handshake");
        }
        Err(Completion::Torn(reason)) => {
            tracing::debug!(%reason, "bridge: the connection ended early")
        }
        Err(Completion::Log(reason)) => {
            tracing::warn!(%reason, "bridge: the extension broke the protocol")
        }
    }
    // Only the write direction: the last message goes out before the FIN. In the regular course
    // nothing unread is pending; closing over it would endanger the answer with an RST.
    let _ = stream.shutdown(Shutdown::Write);
}

fn set_up(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(TIME_SLICE))?;
    // If the extension stops reading without closing, a write does not hold the place forever:
    // after the counterpart's read deadline the connection counts as torn.
    stream.set_write_timeout(Some(READ_DEADLINE))
}

fn run(stream: &TcpStream, shared: &Shared) -> Result<(), Completion> {
    set_up(stream)
        .map_err(|why| Completion::Torn(format!("the socket cannot be set up: {why}")))?;
    let stopped = || shared.halted();
    let mut reader: &TcpStream = stream;

    // 1. Handshake.
    let mut deadline = Deadline::fixed(shared.setting.handshake_deadline);
    let json = match frame::read_inbox(&mut reader, Limit::HANDSHAKE, &mut deadline, &stopped) {
        Ok(Inbox::Json(json)) => json,
        Ok(Inbox::Data { .. }) => {
            return Err(Completion::Refused("the first message is a data chunk".to_owned()));
        }
        Err(why) => return Err(Completion::Refused(format!("no HELLO: {why}"))),
    };
    let Handshake::Hello { version, secret } = serde_json::from_slice(&json)
        .map_err(|why| Completion::Refused(format!("the first message is no HELLO ({why})")))?;
    if version != VERSION {
        return Err(Completion::Refused(format!(
            "the extension speaks bridge version {}, the app version {VERSION}",
            version
        )));
    }
    if !rendezvous::equal_in_constant_time(secret.as_bytes(), &shared.secret) {
        return Err(Completion::Refused("wrong secret".to_owned()));
    }
    send(stream, &Notice::Welcome { version: VERSION })?;

    // 2. One request.
    let mut deadline = Deadline::fixed(shared.setting.request_deadline);
    let json = match frame::read_inbox(&mut reader, Limit::REQUEST, &mut deadline, &stopped) {
        Ok(Inbox::Json(json)) => json,
        Ok(Inbox::Data { .. }) => {
            return Err(Completion::Log("a data chunk instead of a request".to_owned()));
        }
        // Handshake without a request: BridgeClient::check_connection.
        Err(ReadError::Closed) => return Ok(()),
        Err(ReadError::Log(text)) => return Err(Completion::Log(text)),
        Err(why) => return Err(Completion::Torn(format!("no request: {why}"))),
    };
    let request = match serde_json::from_slice::<Request>(&json) {
        Ok(request) => request,
        Err(why) => {
            let reason = format!("the app does not understand the extension's request ({why})");
            let _ = send(stream, &Notice::Error { error: SourceError::Internal(reason.clone()) });
            return Err(Completion::Log(reason));
        }
    };
    answer(stream, shared, request)
}

fn answer(stream: &TcpStream, shared: &Shared, request: Request) -> Result<(), Completion> {
    let source = &*shared.source;
    let notice = match request {
        Request::Children { container } => {
            Notice::Children { result: guards(|| source.children(container)) }
        }
        Request::Entry { identifier } => {
            Notice::Entry { result: guards(|| source.entry(identifier)) }
        }
        Request::CurrentSequence => {
            Notice::CurrentSequence { result: guards(|| source.current_sequence()) }
        }
        Request::ChangesSince { sequence, max } => {
            // No Vec holds more than usize::MAX changes; "at most u64::MAX" and "at most
            // usize::MAX" are therefore the same limit, not an invented one.
            let max = usize::try_from(max).unwrap_or(usize::MAX);
            Notice::ChangesSince { result: guards(|| source.changes_since(sequence, max)) }
        }
        Request::Content { identifier, request } => {
            return deliver_content(stream, shared, identifier, &request);
        }
    };
    send(stream, &notice)
}

fn deliver_content(
    stream: &TcpStream,
    shared: &Shared,
    identifier: EntryIdentifier,
    request: &ContentRequest,
) -> Result<(), Completion> {
    let mut sink =
        RemoteSink { stream, shared, torn: Cell::new(false), last_check: Cell::new(None) };
    let result = guards(|| shared.source.content(identifier, request, &mut sink));
    if sink.torn.get() {
        return Err(Completion::Torn(format!(
            "the extension cancelled the content of {identifier}; the engine reports {}",
            match &result {
                Ok(receipt) => format!("{} bytes handed over", receipt.size),
                Err(error) => error.to_string(),
            }
        )));
    }
    if shared.halted() {
        // No ERROR {Cancelled}: in the extension that would mean "the user cancelled". The app is
        // going; the extension sees the line break off and reports NoNetwork.
        return Err(Completion::Torn("the app is shutting down".to_owned()));
    }
    let notice = match result {
        Ok(receipt) => Notice::End { receipt },
        Err(error) => Notice::Error { error },
    };
    send(stream, &notice)
}

fn send(stream: &TcpStream, notice: &Notice) -> Result<(), Completion> {
    let mut writer: &TcpStream = stream;
    match frame::write_json(&mut writer, notice) {
        Ok(()) => Ok(()),
        Err(WriteError::TooLarge(bytes)) => {
            let error = SourceError::Internal(format!(
                "the answer {} is {bytes} bytes and therefore too large for the bridge (at most \
                 {MAX_MESSAGE} bytes)",
                notice.kind()
            ));
            tracing::error!(%error, "bridge: the answer is too large");
            frame::write_json(&mut writer, &Notice::Error { error })
                .map_err(|why| Completion::Torn(why.to_string()))
        }
        Err(why) => Err(Completion::Torn(why.to_string())),
    }
}

/// Calls the engine and catches a panic as [`SourceError::Internal`].
///
/// Without it the connection thread would end mutely, the extension would see a line that broke off
/// and would report "not reachable" to the Finder — for a program error that recurs at every
/// attempt.
fn guards<T>(call: impl FnOnce() -> Result<T, SourceError>) -> Result<T, SourceError> {
    panic::catch_unwind(AssertUnwindSafe(call)).unwrap_or_else(|payload| {
        let text = payload
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "without a text".to_owned());
        tracing::error!(%text, "bridge: the namespace source ran into a panic");
        Err(SourceError::Internal(format!(
            "the app ran into a program fault on this request ({text})"
        )))
    })
}

/// The sink the engine gets in the app: writes progress and data onto the line.
struct RemoteSink<'a> {
    stream: &'a TcpStream,
    shared: &'a Shared,
    torn: Cell<bool>,
    last_check: Cell<Option<Instant>>,
}

impl ContentSink for RemoteSink<'_> {
    fn progress(&mut self, loaded: u64, total: u64) {
        if self.cancelled() {
            return;
        }
        let mut writer: &TcpStream = self.stream;
        if frame::write_json(&mut writer, &Notice::Progress { loaded, total }).is_err() {
            self.torn.set(true);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), SinkError> {
        if self.cancelled() {
            return Err(SinkError(CANCELLED.to_owned()));
        }
        let mut writer: &TcpStream = self.stream;
        let mut place = offset;
        for chunk in data.chunks(MAX_DATA_CHUNK) {
            if let Err(why) = frame::write_data(&mut writer, place, chunk) {
                self.torn.set(true);
                return Err(SinkError(format!(
                    "the extension takes no more data ({why}); the request counts as \
                     cancelled"
                )));
            }
            place += chunk.len() as u64;
        }
        Ok(())
    }

    fn cancelled(&self) -> bool {
        if self.torn.get() || self.shared.halted() {
            return true;
        }
        let now = Instant::now();
        if self.last_check.get().is_some_and(|last| now.duration_since(last) < CHECK_INTERVAL) {
            return false;
        }
        self.last_check.set(Some(now));
        if peer_has_closed(self.stream) {
            self.torn.set(true);
        }
        self.torn.get()
    }
}

/// Looks at whether the extension has closed the connection, without reading anything.
///
/// After the request the extension sends nothing more; every event on the read side is therefore a
/// cancellation: `Ok(0)` is its FIN, an error a reset, and bytes would be a breach of the protocol.
/// Switching to non-blocking is harmless: the same sink is the only writer, and the `&self` of a
/// sink that is only `Send` lives in one thread only.
fn peer_has_closed(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return true;
    }
    let mut one_byte = [0u8; 1];
    let result = stream.peek(&mut one_byte);
    let back = stream.set_nonblocking(false);
    match result {
        Err(why) if why.kind() == io::ErrorKind::WouldBlock => back.is_err(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use edms_core::change::ChangeState;
    use edms_core::namespace::{Container, Entry};
    use edms_core::port::ContentReceipt;

    use super::*;

    struct Empty;

    impl NamespaceSource for Empty {
        fn children(&self, _: Container) -> Result<Vec<Entry>, SourceError> {
            Ok(Vec::new())
        }
        fn entry(&self, identifier: EntryIdentifier) -> Result<Entry, SourceError> {
            Err(SourceError::NotFound(identifier))
        }
        fn current_sequence(&self) -> Result<u64, SourceError> {
            Ok(1)
        }
        fn changes_since(&self, _: u64, _: usize) -> Result<ChangeState, SourceError> {
            Err(SourceError::AnchorExpired)
        }
        fn content(
            &self,
            _: EntryIdentifier,
            _: &ContentRequest,
            _: &mut dyn ContentSink,
        ) -> Result<ContentReceipt, SourceError> {
            Err(SourceError::NoAccess)
        }
    }

    fn short() -> BridgeServer {
        let setting = Setting {
            handshake_deadline: Duration::from_millis(300),
            request_deadline: Duration::from_millis(300),
        };
        BridgeServer::start_with(Arc::new(Empty), &rendezvous::secret_from_bytes(&[3; 32]), setting)
            .unwrap()
    }

    fn closed_within(stream: &mut TcpStream, deadline: Duration) -> bool {
        stream.set_read_timeout(Some(deadline)).unwrap();
        let mut buffer = [0u8; 16];
        match stream.read(&mut buffer) {
            Ok(0) => true,
            Ok(_) => false,
            Err(why) => matches!(
                why.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ),
        }
    }

    #[test]
    fn a_mute_connection_is_closed_after_the_handshake_deadline() {
        let server = short();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, server.port())).unwrap();
        let start = Instant::now();
        assert!(closed_within(&mut stream, Duration::from_secs(3)));
        assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn a_dripping_handshake_ends_at_the_fixed_deadline() {
        let server = short();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, server.port())).unwrap();
        // A header that announces 4000 bytes, and then one byte every 50 ms: every byte would
        // arrive before a silence deadline, but the fixed deadline counts from acceptance on.
        stream.write_all(&[0, 0, 0x0F, 0xA0, b'J']).unwrap();
        let start = Instant::now();
        let mut closed = false;
        while start.elapsed() < Duration::from_secs(3) {
            if stream.write_all(b" ").is_err() {
                closed = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(closed, "the app should have closed after 300 ms");
        assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn a_secret_that_is_too_short_starts_no_server() {
        let error = BridgeServer::start(Arc::new(Empty), "short").unwrap_err();
        assert!(matches!(error, BridgeError::Secret(_)), "{error}");
        assert!(BridgeServer::start(Arc::new(Empty), "").is_err());
    }

    #[test]
    fn the_rendezvous_details_name_port_process_and_version() {
        let server = short();
        let rendezvous = server.rendezvous();
        assert_eq!(
            (rendezvous.port, rendezvous.pid, rendezvous.version),
            (server.port(), std::process::id(), VERSION)
        );
        assert!(!format!("{server:?}").contains(&rendezvous.secret));
    }
}
