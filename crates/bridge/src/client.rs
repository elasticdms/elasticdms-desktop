//! The extension's side: every question of the Finder as one connection to the app.
//!
//! [`BridgeClient`] is a [`NamespaceSource`] like the engine itself; `edms-fileprovider` notices no
//! difference between "in the process" and "over the line" — except for
//! [`SourceError::NoNetwork`] when the app is not running (see the crate head).
//!
//! **The rendezvous file is read anew before every request** (except at [`BridgeClient::connect`]).
//! If the app restarts, it has a new port and a new secret; an extension that had remembered the
//! old ones would take the running app for terminated until macOS restarts the extension at some
//! point. Reading a 120-byte file costs microseconds.
//!
//! **Cancellation.** During a content the client asks `sink.cancelled()` after every frame and in
//! every 250 ms time slice of the waiting. If there was a cancellation, it closes the connection —
//! that is the cancellation signal to the app — and delivers [`SourceError::Cancelled`].

use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use edms_core::change::ChangeState;
use edms_core::namespace::{Container, Entry, EntryIdentifier};
use edms_core::port::{ContentReceipt, ContentRequest, ContentSink, NamespaceSource, SourceError};

use crate::error::BridgeError;
use crate::frame::{self, Deadline, Inbox, Limit, ReadError, WriteError};
use crate::message::{Handshake, Notice, Request};
use crate::rendezvous::Rendezvous;
use crate::{CONNECTION_DEADLINE, READ_DEADLINE, VERSION};

/// Read deadline of the socket; afterwards the client asks whether the platform cancelled.
const TIME_SLICE: Duration = Duration::from_millis(250);

/// The line on the extension's side.
///
/// Holds no connection open: every request connects, identifies itself, asks and closes. That is
/// why it is `Send + Sync` without locks and may be called by any number of Foundation threads at
/// once; the app serves up to [`crate::MAX_CONNECTION`] of them at the same time.
#[derive(Debug, Clone)]
pub struct BridgeClient {
    target: Target,
}

#[derive(Debug, Clone)]
enum Target {
    /// Fixed, as handed in.
    Fixed(Rendezvous),
    /// From the file before every request.
    File(PathBuf),
}

impl BridgeClient {
    /// A client for exactly these rendezvous details.
    ///
    /// Does not connect yet — every request connects itself. If the app restarts, this client stays
    /// at the old port; for the extension [`BridgeClient::after_path`] is the right one.
    pub fn connect(rendezvous: &Rendezvous) -> Self {
        Self { target: Target::Fixed(rendezvous.clone()) }
    }

    /// Reads the rendezvous file now (a wrong path or permissions that are too open strike at
    /// once) and afterwards anew before every request.
    ///
    /// Fails when the file is missing ([`BridgeError::NoRendezvousFile`]: the app is not running)
    /// or invalid. Whoever needs a client even without a running app takes
    /// [`BridgeClient::after_path`].
    pub fn from_rendezvous(path: &Path) -> Result<Self, BridgeError> {
        Rendezvous::read(path)?;
        Ok(Self { target: Target::File(path.to_owned()) })
    }

    /// A client that reads the rendezvous file only at every request; never fails.
    ///
    /// The way for the extension: it often starts before the app runs, and is then to deliver
    /// [`SourceError::NoNetwork`] for every question until the app is there — without being created
    /// anew. Typically: `BridgeClient::after_path(Rendezvous::default_path()?)`.
    pub fn after_path(path: impl Into<PathBuf>) -> Self {
        Self { target: Target::File(path.into()) }
    }

    /// Connects and identifies itself without asking anything.
    ///
    /// Delivers the precise reason when the line does not carry ("the elasticdms app is not
    /// running: …") — the sentence [`SourceError::NoNetwork`] cannot carry. For the diagnosis in
    /// the extension and the app's self-test.
    pub fn check_connection(&self) -> Result<(), BridgeError> {
        self.open().map(drop)
    }

    fn rendezvous(&self) -> Result<Rendezvous, BridgeError> {
        match &self.target {
            Target::Fixed(fixed) => Ok(fixed.clone()),
            Target::File(path) => Rendezvous::read(path),
        }
    }

    /// Connection plus handshake.
    fn open(&self) -> Result<Connection, BridgeError> {
        let rendezvous = self.rendezvous()?;
        if rendezvous.version != VERSION {
            return Err(BridgeError::WrongVersion { expected: VERSION, read: rendezvous.version });
        }
        let port = rendezvous.port;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpStream::connect_timeout(&address, CONNECTION_DEADLINE)
            .map_err(|why| connection_error(port, &why))?;
        let torn = |why: io::Error| BridgeError::Torn {
            reason: format!("the socket cannot be set up: {why}"),
        };
        stream.set_nodelay(true).map_err(torn)?;
        stream.set_read_timeout(Some(TIME_SLICE)).map_err(torn)?;
        stream.set_write_timeout(Some(READ_DEADLINE)).map_err(torn)?;
        let connection = Connection { stream };

        let refused = |reason: String| BridgeError::Refused { port, reason };
        let hello = Handshake::Hello { version: VERSION, secret: rendezvous.secret };
        connection.send(&hello).map_err(|why| refused(format!("HELLO cannot be sent: {why}")))?;
        let mut deadline = Deadline::silence(READ_DEADLINE);
        match connection.receive(Limit::HANDSHAKE, &mut deadline, &|| false) {
            Ok(Inbox::Json(json)) => match serde_json::from_slice::<Notice>(&json) {
                Ok(Notice::Welcome { version }) if version == VERSION => Ok(connection),
                Ok(Notice::Welcome { version }) => {
                    Err(BridgeError::WrongVersion { expected: VERSION, read: version })
                }
                Ok(other) => Err(refused(format!("{} came instead of WELCOME", other.kind()))),
                Err(why) => {
                    Err(refused(format!("the greeting is not a message of the bridge ({why})")))
                }
            },
            Ok(Inbox::Data { .. }) => {
                Err(refused("a data chunk arrived instead of WELCOME".to_owned()))
            }
            Err(ReadError::Deadline(span)) => Err(BridgeError::Timeout { second: span.as_secs() }),
            Err(ReadError::Closed) => Err(refused(
                "the counterpart closed the connection without a greeting - wrong secret?"
                    .to_owned(),
            )),
            Err(why) => Err(refused(why.to_string())),
        }
    }

    /// A request with a JSON answer.
    fn ask(&self, request: &Request) -> Result<Notice, BridgeError> {
        let connection = self.open()?;
        connection.send(request).map_err(after_handshake)?;
        let mut deadline = Deadline::silence(READ_DEADLINE);
        match connection.receive(Limit::RESPONSE, &mut deadline, &|| false) {
            Ok(Inbox::Json(json)) => read_notice(&json),
            Ok(Inbox::Data { .. }) => {
                Err(BridgeError::Log(format!("a data chunk as the answer to {}", request.kind())))
            }
            Err(why) => Err(translate(why)),
        }
    }

    fn fetch_content(
        &self,
        identifier: EntryIdentifier,
        request: &ContentRequest,
        sink: &mut dyn ContentSink,
    ) -> Result<ContentReceipt, SourceError> {
        if sink.cancelled() {
            return Err(SourceError::Cancelled);
        }
        let connection = self.open().map_err(report)?;
        connection
            .send(&Request::Content { identifier, request: request.clone() })
            .map_err(|why| report(after_handshake(why)))?;
        let mut deadline = Deadline::silence(READ_DEADLINE);
        let mut actual: u64 = 0;
        loop {
            // After every frame; `connection` closes on leaving, that is the signal to the app.
            if sink.cancelled() {
                return Err(SourceError::Cancelled);
            }
            let inbox =
                match connection.receive(Limit::CONTENT, &mut deadline, &|| sink.cancelled()) {
                    Ok(inbox) => inbox,
                    Err(ReadError::Cancelled) => return Err(SourceError::Cancelled),
                    Err(why) => return Err(report(translate(why))),
                };
            match inbox {
                Inbox::Data { offset, bytes } => {
                    // The sink relies on it (port.rs: "ascending and without gaps"); a gap would
                    // be a file with zeros in the wrong place.
                    if offset != actual {
                        return Err(report(BridgeError::Log(format!(
                            "data chunk at offset {offset}, expected was {actual}; chunks \
                             must come ascending and without gaps"
                        ))));
                    }
                    if !bytes.is_empty() {
                        sink.write(offset, &bytes)?;
                    }
                    actual += bytes.len() as u64;
                }
                Inbox::Json(json) => match read_notice(&json).map_err(report)? {
                    Notice::Progress { loaded, total } => sink.progress(loaded, total),
                    // The receipt is the engine's word; what arrived is counted by the client
                    // itself. If they differ, something was lost on the way, and the file is not
                    // the checked one.
                    Notice::End { receipt } if receipt.size == actual => return Ok(receipt),
                    Notice::End { receipt } => {
                        return Err(SourceError::Incomplete { expected: receipt.size, actual });
                    }
                    Notice::Error { error } => return Err(error),
                    other => {
                        return Err(report(BridgeError::Log(format!(
                            "{} in the middle of a content transfer",
                            other.kind()
                        ))));
                    }
                },
            }
        }
    }
}

impl NamespaceSource for BridgeClient {
    fn children(&self, container: Container) -> Result<Vec<Entry>, SourceError> {
        response(self.ask(&Request::Children { container }), "CHILDREN", |notice| match notice {
            Notice::Children { result } => Some(result),
            _ => None,
        })
    }

    fn entry(&self, identifier: EntryIdentifier) -> Result<Entry, SourceError> {
        response(self.ask(&Request::Entry { identifier }), "ENTRY", |notice| match notice {
            Notice::Entry { result } => Some(result),
            _ => None,
        })
    }

    fn current_sequence(&self) -> Result<u64, SourceError> {
        response(self.ask(&Request::CurrentSequence), "CURRENT_SEQUENCE", |notice| match notice {
            Notice::CurrentSequence { result } => Some(result),
            _ => None,
        })
    }

    fn changes_since(&self, sequence: u64, max: usize) -> Result<ChangeState, SourceError> {
        let request = Request::ChangesSince { sequence, max: max as u64 };
        response(self.ask(&request), "CHANGES_SINCE", |notice| match notice {
            Notice::ChangesSince { result } => Some(result),
            _ => None,
        })
    }

    fn content(
        &self,
        identifier: EntryIdentifier,
        request: &ContentRequest,
        sink: &mut dyn ContentSink,
    ) -> Result<ContentReceipt, SourceError> {
        self.fetch_content(identifier, request, sink)
    }
}

/// Unpacks an answer: the engine's result, an ERROR of the app or a breach of the protocol.
///
/// `take` delivers `None` for an answer of the wrong kind; its kind then stands in the message.
fn response<T>(
    asked: Result<Notice, BridgeError>,
    expected: &'static str,
    take: impl FnOnce(Notice) -> Option<Result<T, SourceError>>,
) -> Result<T, SourceError> {
    match asked.map_err(report)? {
        Notice::Error { error } => Err(error),
        notice => {
            let kind = notice.kind();
            take(notice).unwrap_or_else(|| {
                Err(report(BridgeError::Log(format!("the app answered {expected} with {kind}"))))
            })
        }
    }
}

/// Translates and writes the precise reason into the log — [`SourceError::NoNetwork`] no longer
/// carries it.
fn report(error: BridgeError) -> SourceError {
    if error.app_not_reachable() {
        tracing::warn!(%error, "bridge: the elasticdms app cannot be reached");
    } else {
        tracing::error!(%error, "bridge: the request to the app failed");
    }
    error.into()
}

fn connection_error(port: u16, why: &io::Error) -> BridgeError {
    if why.kind() == io::ErrorKind::PermissionDenied {
        BridgeError::ConnectionForbidden { port, reason: why.to_string() }
    } else {
        BridgeError::AppUnresponsive { port, reason: why.to_string() }
    }
}

fn after_handshake(why: WriteError) -> BridgeError {
    match why {
        WriteError::Link(link) => BridgeError::Torn { reason: link.to_string() },
        other => BridgeError::Log(other.to_string()),
    }
}

fn translate(why: ReadError) -> BridgeError {
    match why {
        ReadError::Closed => BridgeError::Torn {
            reason: "the app closed the connection before the end of the answer".to_owned(),
        },
        ReadError::Deadline(span) => BridgeError::Timeout { second: span.as_secs() },
        ReadError::Log(text) => BridgeError::Log(text),
        ReadError::Cancelled => BridgeError::Torn { reason: "cancelled".to_owned() },
        ReadError::Link(link) => BridgeError::Torn { reason: link.to_string() },
    }
}

fn read_notice(json: &[u8]) -> Result<Notice, BridgeError> {
    serde_json::from_slice(json).map_err(|why| {
        BridgeError::Log(format!("the answer is not a message of the bridge ({why})"))
    })
}

/// An open connection after the handshake; closes on leaving.
struct Connection {
    stream: TcpStream,
}

impl Connection {
    fn send<T: Serialize>(&self, message: &T) -> Result<(), WriteError> {
        let mut writer: &TcpStream = &self.stream;
        frame::write_json(&mut writer, message)
    }

    fn receive(
        &self,
        limit: Limit,
        deadline: &mut Deadline,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Inbox, ReadError> {
        let mut reader: &TcpStream = &self.stream;
        frame::read_inbox(&mut reader, limit, deadline, cancelled)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Both directions: on a cancellation there is unread data pending, and closing over it
        // sends the app an RST — its next write fails at once.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
