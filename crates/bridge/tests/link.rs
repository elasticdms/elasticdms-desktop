//! The line over real loopback: a `BridgeServer` with a sample source in place of the engine, a
//! `BridgeClient` as in the extension — and raw sockets for everything an honest client would never
//! send.

// Test code may `unwrap` (clippy.toml: allow-unwrap-in-tests); clippy does not, however, recognise
// helper functions of an integration test file outside #[test] as test code.
#![allow(clippy::unwrap_used)]

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use edms_bridge::{
    BridgeClient, BridgeError, BridgeServer, MAX_DATA_CHUNK, Rendezvous, VERSION, secret_from_bytes,
};
use edms_core::change::{Change, ChangeState, JournalEntry};
use edms_core::checksum::Sha256Value;
use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, Identifier, SearchIdentifier,
};
use edms_core::namespace::{
    self, Container, ContainerItem, DocumentItem, Entry, EntryContent, EntryIdentifier,
    FileDetails, HintKind, Location, Truncation,
};
use edms_core::port::{
    ContentReceipt, ContentRequest, ContentSink, NamespaceSource, SinkError, SourceError,
};
use edms_core::time::Timestamp;

const MIB: u64 = 1 << 20;
const PATIENCE: Duration = Duration::from_secs(10);

// ── Sample source: the engine as the app hands it to the line ─────────────────────────────────

/// How a content fetch came out on the app's side.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Started,
    Finished,
    CancelledAtLoad,
    CancelledAtWrite { written: u64 },
    SinkError { written: u64 },
}

#[derive(Default)]
struct Inside {
    now: usize,
    max: usize,
}

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    switch: Condvar,
}

impl Gate {
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.switch.notify_all();
    }

    fn wait(&self) {
        let open = self.open.lock().unwrap();
        let _ = self.switch.wait_timeout_while(open, PATIENCE, |open| !*open).unwrap();
    }
}

struct SampleSource {
    /// Set: every method delivers this error.
    error: Option<SourceError>,
    size: u64,
    chunk: usize,
    progress_reports: u64,
    load_pause: Duration,
    /// This long the engine "loads" quietly (without progress) before it reports progress.
    silence: Duration,
    /// children(): wait until this many requests are in the source at the same time.
    rally_point: Option<usize>,
    /// children(): wait until the gate is open.
    gate: Option<Arc<Gate>>,
    panic: bool,
    calls: AtomicUsize,
    inside: Mutex<Inside>,
    switch: Condvar,
    requests: Mutex<Vec<ContentRequest>>,
    outcomes: mpsc::Sender<Outcome>,
}

impl SampleSource {
    fn new() -> (Self, mpsc::Receiver<Outcome>) {
        let (sender, receiver) = mpsc::channel();
        let source = Self {
            error: None,
            size: 300 * 1024,
            chunk: 100_000,
            progress_reports: 3,
            load_pause: Duration::ZERO,
            silence: Duration::ZERO,
            rally_point: None,
            gate: None,
            panic: false,
            calls: AtomicUsize::new(0),
            inside: Mutex::new(Inside::default()),
            switch: Condvar::new(),
            requests: Mutex::new(Vec::new()),
            outcomes: sender,
        };
        (source, receiver)
    }

    fn count(&self) -> Result<(), SourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.error.clone().map_or(Ok(()), Err)
    }

    fn report(&self, outcome: Outcome) {
        let _ = self.outcomes.send(outcome);
    }

    fn enter(&self) {
        let mut inside = self.inside.lock().unwrap();
        inside.now += 1;
        inside.max = inside.max.max(inside.now);
        self.switch.notify_all();
    }

    fn leave(&self) {
        self.inside.lock().unwrap().now -= 1;
        self.switch.notify_all();
    }

    fn wait_until_inside(&self, count: usize) {
        let inside = self.inside.lock().unwrap();
        let _ =
            self.switch.wait_timeout_while(inside, PATIENCE, |inside| inside.now < count).unwrap();
    }

    fn now_inside(&self) -> usize {
        self.inside.lock().unwrap().now
    }

    fn max_concurrent(&self) -> usize {
        self.inside.lock().unwrap().max
    }
}

impl NamespaceSource for SampleSource {
    fn children(&self, container: Container) -> Result<Vec<Entry>, SourceError> {
        self.count()?;
        self.enter();
        if let Some(count) = self.rally_point {
            self.wait_until_inside(count);
        }
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        self.leave();
        Ok(children_of(container))
    }

    fn entry(&self, identifier: EntryIdentifier) -> Result<Entry, SourceError> {
        self.count()?;
        assert!(!self.panic, "sample source: deliberate program error");
        match identifier {
            EntryIdentifier::Hint { .. } => Err(SourceError::NotFound(identifier)),
            EntryIdentifier::Container(container) => {
                Ok(Entry { identifier, name: container.to_string(), content: EntryContent::Folder })
            }
            EntryIdentifier::Document { .. } => Ok(Entry {
                identifier,
                name: "Prüfbericht Pumpe 7.pdf".into(),
                content: EntryContent::File(FileDetails {
                    size: self.size,
                    sha256: Some(Sha256Value::from_bytes([9; 32])),
                    version: "3-f00".into(),
                    created: Timestamp::from_unix_millis(1_788_334_692_118),
                    changed: Timestamp::from_unix_millis(1_788_334_699_000),
                    media_type: "application/pdf".into(),
                }),
            }),
        }
    }

    fn current_sequence(&self) -> Result<u64, SourceError> {
        self.count()?;
        Ok(4711)
    }

    fn changes_since(&self, sequence: u64, max: usize) -> Result<ChangeState, SourceError> {
        self.count()?;
        if sequence < 100 {
            return Err(SourceError::AnchorExpired);
        }
        let entries = children_of(case_file(3));
        let all = vec![
            Change::Removed { entry: entries[0].clone() },
            Change::Changed {
                before: entries[1].clone(),
                after: Entry { name: "umbenannt.pdf".into(), ..entries[1].clone() },
            },
            Change::New { entry: entries[2].clone() },
        ];
        let count = max.min(all.len());
        let changes = all
            .into_iter()
            .take(count)
            .zip(sequence + 1..)
            .map(|(change, sequence)| JournalEntry { sequence, change })
            .collect();
        Ok(ChangeState { changes, until_sequence: sequence + count as u64, more: count < 3 })
    }

    fn content(
        &self,
        _identifier: EntryIdentifier,
        request: &ContentRequest,
        sink: &mut dyn ContentSink,
    ) -> Result<ContentReceipt, SourceError> {
        self.requests.lock().unwrap().push(request.clone());
        self.count()?;
        self.report(Outcome::Started);
        // "Loading" like the engine: everything into the scratch area first, watching for a
        // cancellation while doing so.
        let silent_until = Instant::now() + self.silence;
        while Instant::now() < silent_until {
            if sink.cancelled() {
                self.report(Outcome::CancelledAtLoad);
                return Err(SourceError::Cancelled);
            }
            thread::sleep(Duration::from_millis(5));
        }
        for i in 1..=self.progress_reports {
            if sink.cancelled() {
                self.report(Outcome::CancelledAtLoad);
                return Err(SourceError::Cancelled);
            }
            sink.progress(self.size * i / self.progress_reports, self.size);
            thread::sleep(self.load_pause);
        }
        // Handover, only now do bytes flow.
        let mut offset = 0;
        while offset < self.size {
            if sink.cancelled() {
                self.report(Outcome::CancelledAtWrite { written: offset });
                return Err(SourceError::Cancelled);
            }
            let length = (self.chunk as u64).min(self.size - offset);
            let data: Vec<u8> = (offset..offset + length).map(byte_at).collect();
            if let Err(error) = sink.write(offset, &data) {
                self.report(Outcome::SinkError { written: offset });
                return Err(error.into());
            }
            offset += length;
        }
        self.report(Outcome::Finished);
        Ok(ContentReceipt { size: self.size, sha256: Some(Sha256Value::from_bytes([9; 32])) })
    }
}

/// A pattern that changes within a chunk and from chunk to chunk: swapped or shifted chunks would
/// stand out.
fn byte_at(place: u64) -> u8 {
    ((place % 251) as u8) ^ ((place >> 12) as u8)
}

fn basket(value: u128) -> BasketIdentifier {
    Identifier::from_value(value)
}

fn archive(value: u128) -> ArchiveIdentifier {
    Identifier::from_value(value)
}

fn case(value: u128) -> CaseIdentifier {
    Identifier::from_value(value)
}

fn search(value: u128) -> SearchIdentifier {
    Identifier::from_value(value)
}

/// One case file of the sample archive.
///
/// Since namespace v2 a case file is never named on its own: without the archive there is no
/// parent for it, and no entry identifier either (§1).
fn case_file(value: u128) -> Container {
    Container::Case { archive: archive(1), case: case(value) }
}

fn doc() -> EntryIdentifier {
    EntryIdentifier::Document {
        location: Location::Case { archive: archive(1), case: case(3) },
        document: Identifier::from_value(99),
    }
}

fn item(count: usize, origin: &str) -> Vec<DocumentItem> {
    (0..count)
        .map(|i| DocumentItem {
            document: Identifier::from_value(0x0190_F1C2_3A4B_7C5D_8E6F_0000_0000_0000 | i as u128),
            title: format!("{origin} Rechnung {i:05} – Müller & Söhne GmbH, Wartung Pumpe 7"),
            media_type: "application/pdf".into(),
            size: 10_000 + i as u64,
            sha256: Sha256Value::from_bytes([(i % 256) as u8; 32]),
            version: format!("{i}-abc"),
            created: Timestamp::from_unix_millis(1_788_334_692_118),
            changed: Timestamp::from_unix_millis(1_788_334_692_118 + i as i64),
        })
        .collect()
}

/// The language of the fixtures: which one it is does not matter here, only that both sides of
/// the line use the same one.
const LANGUAGE: edms_i18n::Language = edms_i18n::Language::De;

fn children_of(container: Container) -> Vec<Entry> {
    match container {
        Container::Root => namespace::root_entries(LANGUAGE),
        Container::Baskets => namespace::baskets_entries(&[
            ContainerItem { identifier: basket(1), title: "Buchhaltung".into() },
            ContainerItem { identifier: basket(2), title: "Post".into() },
        ]),
        // A basket holds nothing of the server's (namespace v2 §4); what lies in it locally the
        // platform sees on disk and never over this line.
        Container::Basket(_) => Vec::new(),
        Container::Archives => namespace::archives_entries(&[
            ContainerItem { identifier: archive(1), title: "Technik".into() },
            ContainerItem { identifier: archive(2), title: "Kaufmännisch".into() },
        ]),
        Container::Archive(identifier) => namespace::cases_entries(
            identifier,
            &[
                ContainerItem {
                    identifier: case(1),
                    title: "Sulzer Pumpen – Wartungsvertrag 2026".into(),
                },
                ContainerItem { identifier: case(2), title: "Lieferanten 2026".into() },
            ],
        ),
        Container::Searches => namespace::searches_entries(&[ContainerItem {
            identifier: search(1),
            title: "Offene Rechnungen über 10.000 €".into(),
        }]),
        Container::Case { archive, case } => namespace::document_entries(
            Location::Case { archive, case },
            &item(case.value() as usize, "Akte"),
            None,
            LANGUAGE,
        ),
        Container::Search(identifier) => namespace::document_entries(
            Location::Search(identifier),
            &item(identifier.value() as usize, "Suche"),
            Some(Truncation {
                displayed: identifier.value() as u64,
                address: Some("https://app.elasticdms.io/s/1"),
            }),
            LANGUAGE,
        ),
    }
}

// ── Sample sink: the platform as the extension hands it to the client ─────────────────────────

#[derive(Default)]
struct SampleSink {
    data: Vec<u8>,
    chunks: Vec<(u64, usize)>,
    progress_reports: Vec<(u64, u64)>,
    progress_after_data: bool,
    abort_after_bytes: Option<u64>,
    abort_after_progress_reports: Option<usize>,
    abort_at: Option<Instant>,
    deny: bool,
}

impl ContentSink for SampleSink {
    fn progress(&mut self, loaded: u64, total: u64) {
        self.progress_after_data |= !self.data.is_empty();
        self.progress_reports.push((loaded, total));
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), SinkError> {
        if self.deny {
            return Err(SinkError("the disk is full".into()));
        }
        self.chunks.push((offset, data.len()));
        self.data.extend_from_slice(data);
        Ok(())
    }

    fn cancelled(&self) -> bool {
        self.abort_after_bytes.is_some_and(|count| self.data.len() as u64 >= count)
            || self
                .abort_after_progress_reports
                .is_some_and(|count| self.progress_reports.len() >= count)
            || self.abort_at.is_some_and(|deadline| Instant::now() >= deadline)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────────────────────

fn secret(byte: u8) -> String {
    secret_from_bytes(&[byte; 32])
}

fn start(source: SampleSource) -> (BridgeServer, BridgeClient, Arc<SampleSource>) {
    let source = Arc::new(source);
    let server = BridgeServer::start(source.clone(), &secret(7)).unwrap();
    let client = BridgeClient::connect(&server.rendezvous());
    (server, client, source)
}

/// Waits for the first outcome that is not "Started".
fn final_outcome(outcomes: &mpsc::Receiver<Outcome>) -> Outcome {
    loop {
        match outcomes.recv_timeout(PATIENCE) {
            Ok(Outcome::Started) => {}
            Ok(end) => return end,
            Err(why) => panic!("the app side reported no outcome within {PATIENCE:?}: {why}"),
        }
    }
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(payload.len() + 1).unwrap().to_be_bytes().to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(payload);
    bytes
}

fn data_frame(offset: u64, data: &[u8]) -> Vec<u8> {
    frame(b'D', &[&offset.to_be_bytes()[..], data].concat())
}

fn hello(secret: &str) -> Vec<u8> {
    let json = format!(r#"{{"kind":"HELLO","version":{VERSION},"secret":"{secret}"}}"#);
    frame(b'J', json.as_bytes())
}

fn read_raw(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).unwrap();
    let mut rest = vec![0u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut rest).unwrap();
    (rest[0], rest[1..].to_vec())
}

fn raw_connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
}

/// Whether the counterpart closes without sending a single byte.
fn closed_without_response(stream: &mut TcpStream) -> bool {
    let mut buffer = [0u8; 64];
    match stream.read(&mut buffer) {
        Ok(0) => true,
        Ok(_) => false,
        Err(why) => {
            matches!(why.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        }
    }
}

/// A server that identifies itself like the app and then does what the test demands.
fn wrong_app(behaviour: impl FnOnce(&mut TcpStream) + Send + 'static) -> Rendezvous {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read_raw(&mut stream).0, b'J', "HELLO");
        let welcome = format!(r#"{{"kind":"WELCOME","version":{VERSION}}}"#);
        stream.write_all(&frame(b'J', welcome.as_bytes())).unwrap();
        assert_eq!(read_raw(&mut stream).0, b'J', "request");
        behaviour(&mut stream);
    });
    Rendezvous { port, secret: secret(1), pid: 1, version: VERSION }
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

fn all_source_errors() -> Vec<SourceError> {
    let all = vec![
        SourceError::NotSignedIn,
        SourceError::NoNetwork,
        SourceError::NotFound(doc()),
        SourceError::NoAccess,
        SourceError::Integrity {
            expected: Sha256Value::from_bytes([1; 32]),
            actual: Sha256Value::from_bytes([2; 32]),
        },
        SourceError::Incomplete { expected: 10_000, actual: 9_999 },
        SourceError::AnchorExpired,
        SourceError::Cancelled,
        SourceError::Sink(SinkError("the disk is full".into())),
        SourceError::Server("Der Server meldet 503 service-unavailable.".into()),
        SourceError::Internal("a fault in the engine".into()),
    ];
    // If a variant is added in the core, this match no longer compiles — and the list above grows
    // with it instead of quietly leaving a variant out.
    for error in &all {
        match error {
            SourceError::NotSignedIn
            | SourceError::NoNetwork
            | SourceError::NotFound(_)
            | SourceError::NoAccess
            | SourceError::Integrity { .. }
            | SourceError::Incomplete { .. }
            | SourceError::AnchorExpired
            | SourceError::Cancelled
            | SourceError::Sink(_)
            | SourceError::Server(_)
            | SourceError::Internal(_) => {}
        }
    }
    all
}

// ── Round trip ───────────────────────────────────────────────────────────────────────────────

#[test]
fn every_kind_of_request_survives_the_round_trip() {
    let (_server, client, source) = start(SampleSource::new().0);
    for container in [
        Container::Root,
        Container::Baskets,
        Container::Basket(basket(1)),
        Container::Archives,
        Container::Archive(archive(1)),
        Container::Searches,
        case_file(3),
        Container::Search(search(4)),
    ] {
        assert_eq!(client.children(container), Ok(children_of(container)), "{container}");
    }
    let hint = EntryIdentifier::Hint { location: Container::Root, kind: HintKind::ReadMe };
    for identifier in [EntryIdentifier::ROOT, doc(), hint] {
        assert_eq!(client.entry(identifier), source.entry(identifier), "{identifier}");
    }
    assert_eq!(client.current_sequence(), Ok(4711));
    assert_eq!(client.changes_since(500, 2), source.changes_since(500, 2));
    assert_eq!(client.changes_since(500, usize::MAX), source.changes_since(500, 3));
    assert_eq!(client.changes_since(5, 2), Err(SourceError::AnchorExpired));

    let request = ContentRequest { requesting_application: Some("Preview".into()) };
    let mut sink = SampleSink::default();
    let receipt = client.content(doc(), &request, &mut sink).unwrap();
    assert_eq!(
        receipt,
        ContentReceipt { size: 300 * 1024, sha256: Some(Sha256Value::from_bytes([9; 32])) }
    );
    assert_eq!(sink.data.len() as u64, receipt.size);
    assert_eq!(source.requests.lock().unwrap().last(), Some(&request), "the request travels along");
}

#[test]
fn a_case_file_with_six_thousand_documents_arrives_complete() {
    // Around 2.5 MB of JSON: more than one frame, so in parts.
    let (_server, client, _) = start(SampleSource::new().0);
    let expected = children_of(case_file(6_000));
    assert!(serde_json::to_vec(&expected).unwrap().len() as u64 > 2 * MIB);
    assert_eq!(client.children(case_file(6_000)), Ok(expected));
}

#[test]
fn the_connection_check_identifies_itself_without_asking_the_engine() {
    let (_server, client, source) = start(SampleSource::new().0);
    client.check_connection().unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

// ── Content ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn five_mebibytes_arrive_byte_identical_in_order_and_with_progress() {
    let (mut source, outcomes) = SampleSource::new();
    source.size = 5 * MIB;
    source.chunk = MIB as usize; // larger than one data frame: the app has to split
    source.progress_reports = 10;
    let (_server, client, _) = start(source);
    let mut sink = SampleSink::default();
    let receipt = client.content(doc(), &ContentRequest::default(), &mut sink).unwrap();

    assert_eq!(receipt.size, 5 * MIB);
    assert_eq!(sink.data.len() as u64, 5 * MIB);
    let deviation =
        sink.data.iter().enumerate().position(|(place, byte)| *byte != byte_at(place as u64));
    assert_eq!(deviation, None, "first deviating byte");
    let mut expected = 0;
    for &(offset, length) in &sink.chunks {
        assert_eq!(offset, expected, "ascending and without gaps");
        assert!(length <= MAX_DATA_CHUNK);
        expected += length as u64;
    }
    assert!(sink.chunks.len() >= 20, "{} chunks", sink.chunks.len());
    assert_eq!(sink.progress_reports.len(), 10);
    assert_eq!(sink.progress_reports.last(), Some(&(5 * MIB, 5 * MIB)));
    assert!(sink.progress_reports.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    assert!(!sink.progress_after_data, "progress comes before the first byte");
    assert_eq!(final_outcome(&outcomes), Outcome::Finished);
}

#[test]
fn a_cancellation_mid_stream_stops_the_app_side() {
    let (mut source, outcomes) = SampleSource::new();
    source.size = 64 * MIB; // more than fits into the buffers of both sockets
    source.chunk = 128 * 1024;
    source.progress_reports = 1;
    let (_server, client, _) = start(source);
    let mut sink = SampleSink { abort_after_bytes: Some(MIB), ..SampleSink::default() };
    let result = client.content(doc(), &ContentRequest::default(), &mut sink);

    assert_eq!(result, Err(SourceError::Cancelled));
    assert!((MIB..64 * MIB).contains(&(sink.data.len() as u64)));
    match final_outcome(&outcomes) {
        Outcome::CancelledAtWrite { written } | Outcome::SinkError { written } => {
            assert!(written < 64 * MIB, "{written}");
        }
        other => panic!("the app should have noticed the cancellation, but reported {other:?}"),
    }
}

#[test]
fn a_cancellation_while_the_app_is_still_loading_quietly_takes_effect_without_waiting() {
    let (mut source, outcomes) = SampleSource::new();
    source.silence = Duration::from_secs(8);
    let (_server, client, _) = start(source);
    let start = Instant::now();
    let mut sink =
        SampleSink { abort_at: Some(start + Duration::from_millis(300)), ..SampleSink::default() };
    let result = client.content(doc(), &ContentRequest::default(), &mut sink);

    assert_eq!(result, Err(SourceError::Cancelled));
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    assert_eq!(final_outcome(&outcomes), Outcome::CancelledAtLoad);
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "the engine noticed it only after {:?}",
        start.elapsed()
    );
}

#[test]
fn a_cancellation_after_the_first_progress_reaches_the_engine() {
    let (mut source, outcomes) = SampleSource::new();
    source.progress_reports = 2_000;
    source.load_pause = Duration::from_millis(5);
    let (_server, client, _) = start(source);
    let mut sink = SampleSink { abort_after_progress_reports: Some(1), ..SampleSink::default() };
    let result = client.content(doc(), &ContentRequest::default(), &mut sink);

    assert_eq!(result, Err(SourceError::Cancelled));
    assert_eq!(final_outcome(&outcomes), Outcome::CancelledAtLoad);
}

#[test]
fn a_sink_that_cannot_write_aborts_the_app_side_too() {
    let (mut source, outcomes) = SampleSource::new();
    source.size = 64 * MIB;
    let (_server, client, _) = start(source);
    let mut sink = SampleSink { deny: true, ..SampleSink::default() };
    let result = client.content(doc(), &ContentRequest::default(), &mut sink);

    assert_eq!(result, Err(SourceError::Sink(SinkError("the disk is full".into()))));
    assert!(matches!(
        final_outcome(&outcomes),
        Outcome::CancelledAtWrite { .. } | Outcome::SinkError { .. }
    ));
}

#[test]
fn a_content_with_a_gap_is_not_taken_over() {
    let rendezvous = wrong_app(|stream| {
        stream.write_all(&data_frame(0, &[1; 10])).unwrap();
        stream.write_all(&data_frame(20, &[2; 10])).unwrap();
    });
    let client = BridgeClient::connect(&rendezvous);
    let mut sink = SampleSink::default();
    let result = client.content(doc(), &ContentRequest::default(), &mut sink);

    let Err(SourceError::Internal(text)) = result else { panic!("{result:?}") };
    assert!(text.contains("offset 20"), "{text}");
    assert_eq!(sink.data, [1; 10], "the chunk behind the gap never reaches the sink");
}

#[test]
fn a_receipt_over_more_bytes_than_arrived_means_incomplete() {
    let rendezvous = wrong_app(|stream| {
        stream.write_all(&data_frame(0, &[1; 10])).unwrap();
        let end = r#"{"kind":"END","receipt":{"size":20,"sha256":null}}"#;
        stream.write_all(&frame(b'J', end.as_bytes())).unwrap();
    });
    let client = BridgeClient::connect(&rendezvous);
    let result = client.content(doc(), &ContentRequest::default(), &mut SampleSink::default());
    assert_eq!(result, Err(SourceError::Incomplete { expected: 20, actual: 10 }));
}

#[test]
fn an_app_that_ends_mid_content_means_no_network() {
    let rendezvous = wrong_app(|stream| {
        let progress = r#"{"kind":"PROGRESS","loaded":5,"total":10}"#;
        stream.write_all(&frame(b'J', progress.as_bytes())).unwrap();
    });
    let client = BridgeClient::connect(&rendezvous);
    let mut sink = SampleSink::default();
    let result = client.content(doc(), &ContentRequest::default(), &mut sink);
    assert_eq!(result, Err(SourceError::NoNetwork));
    assert_eq!(sink.progress_reports, [(5, 10)]);
}

// ── Credential and limits ────────────────────────────────────────────────────────────────────

#[test]
fn a_wrong_secret_is_rejected_without_an_answer() {
    let (server, client, source) = start(SampleSource::new().0);
    let mut raw = raw_connect(server.port());
    raw.write_all(&hello(&secret(8))).unwrap();
    assert!(closed_without_response(&mut raw));

    let wrong = Rendezvous { secret: secret(8), ..server.rendezvous() };
    let foreign = BridgeClient::connect(&wrong);
    assert_eq!(foreign.children(Container::Root), Err(SourceError::NoNetwork));
    assert!(matches!(foreign.check_connection(), Err(BridgeError::Refused { .. })));
    assert_eq!(source.calls.load(Ordering::SeqCst), 0, "the engine was never asked");
    // And the app goes on serving whoever identifies themselves afterwards.
    assert_eq!(client.current_sequence(), Ok(4711));
}

#[test]
fn an_over_long_frame_is_rejected_before_and_after_the_handshake() {
    let (server, _client, source) = start(SampleSource::new().0);
    let over_long = [0x00, 0x20, 0x00, 0x02, b'J']; // 2 MiB + 1 announced

    let mut before = raw_connect(server.port());
    before.write_all(&over_long).unwrap();
    assert!(closed_without_response(&mut before));

    let mut after = raw_connect(server.port());
    after.write_all(&hello(&secret(7))).unwrap();
    let (kind, json) = read_raw(&mut after);
    assert_eq!((kind, String::from_utf8(json).unwrap().contains("WELCOME")), (b'J', true));
    after.write_all(&over_long).unwrap();
    assert!(closed_without_response(&mut after));
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn the_client_rejects_an_over_long_frame_from_the_app() {
    let rendezvous = wrong_app(|stream| {
        stream.write_all(&[0x00, 0x20, 0x00, 0x02, b'J']).unwrap();
    });
    let client = BridgeClient::connect(&rendezvous);
    let result = client.children(Container::Root);
    let Err(SourceError::Internal(text)) = result else { panic!("{result:?}") };
    assert!(text.contains("at most"), "{text}");
}

#[test]
fn every_source_error_variant_arrives_as_the_same_variant() {
    for error in all_source_errors() {
        let (mut source, _) = SampleSource::new();
        source.error = Some(error.clone());
        let (_server, client, _) = start(source);
        let expected = Err(error.clone());
        assert_eq!(
            client.children(Container::Root),
            expected.clone().map(|_: ()| Vec::new()),
            "{error:?}"
        );
        assert_eq!(client.entry(doc()).map(|_| ()), expected, "{error:?}");
        assert_eq!(client.current_sequence().map(|_| ()), expected, "{error:?}");
        assert_eq!(client.changes_since(500, 10).map(|_| ()), expected, "{error:?}");
        let mut sink = SampleSink::default();
        let result = client.content(doc(), &ContentRequest::default(), &mut sink);
        assert_eq!(result.map(|_| ()), expected, "{error:?}");
    }
}

#[test]
fn a_panic_in_the_source_arrives_as_an_internal_error_and_the_app_lives_on() {
    let (mut source, _) = SampleSource::new();
    source.panic = true;
    let (_server, client, _) = start(source);
    let result = client.entry(doc());
    let Err(SourceError::Internal(text)) = result else { panic!("{result:?}") };
    assert!(text.contains("program fault"), "{text}");
    assert_eq!(client.current_sequence(), Ok(4711));
}

// ── Concurrency ──────────────────────────────────────────────────────────────────────────────

#[test]
fn eight_concurrent_requests_really_run_concurrently_and_mix_nothing_up() {
    let (mut sample, _) = SampleSource::new();
    sample.rally_point = Some(8);
    let (_server, client, source) = start(sample);
    let threads: Vec<_> = (1..=8u128)
        .map(|number| {
            let client = client.clone();
            thread::spawn(move || (number, client.children(case_file(number))))
        })
        .collect();
    for thread in threads {
        let (number, result) = thread.join().unwrap();
        assert_eq!(result, Ok(children_of(case_file(number))), "case file {number}");
    }
    assert_eq!(source.max_concurrent(), 8);
}

#[test]
fn more_than_sixteen_concurrent_requests_wait_instead_of_failing() {
    let gate = Arc::new(Gate::default());
    let (mut sample, _) = SampleSource::new();
    sample.gate = Some(Arc::clone(&gate));
    let (_server, client, source) = start(sample);
    let threads: Vec<_> = (0..20)
        .map(|_| {
            let client = client.clone();
            thread::spawn(move || client.children(Container::Root))
        })
        .collect();
    let until = Instant::now() + PATIENCE;
    while source.now_inside() < 16 && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(300));
    assert_eq!(source.now_inside(), 16, "exactly 16 at a time, the rest wait");
    gate.open();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), Ok(children_of(Container::Root)));
    }
    assert_eq!(source.max_concurrent(), 16);
}

// ── The app's life cycle ─────────────────────────────────────────────────────────────────────

#[test]
fn the_server_stops_on_drop_and_aborts_running_contents() {
    let (mut source, outcomes) = SampleSource::new();
    source.silence = Duration::from_secs(30);
    let (server, client, _) = start(source);
    let port = server.port();
    let thread = thread::spawn(move || {
        client.content(doc(), &ContentRequest::default(), &mut SampleSink::default())
    });
    assert_eq!(outcomes.recv_timeout(PATIENCE), Ok(Outcome::Started));

    let start = Instant::now();
    drop(server);
    assert!(start.elapsed() < Duration::from_secs(3), "Drop took {:?}", start.elapsed());
    assert_eq!(final_outcome(&outcomes), Outcome::CancelledAtLoad);
    assert_eq!(thread.join().unwrap(), Err(SourceError::NoNetwork), "the app went, not the user");
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
        "port still open"
    );
}

#[test]
fn without_a_rendezvous_file_the_client_reports_no_network_with_a_clear_reason() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bridge.json");
    let error = BridgeClient::from_rendezvous(&path).unwrap_err();
    assert!(matches!(error, BridgeError::NoRendezvousFile { .. }), "{error}");

    let client = BridgeClient::after_path(&path);
    assert_eq!(client.children(Container::Root), Err(SourceError::NoNetwork));
    let mut sink = SampleSink::default();
    assert_eq!(
        client.content(doc(), &ContentRequest::default(), &mut sink),
        Err(SourceError::NoNetwork)
    );
    let reason = client.check_connection().unwrap_err().to_string();
    assert!(reason.starts_with("the elasticdms app is not running"), "{reason}");
}

#[test]
fn a_refused_connection_means_no_network() {
    let rendezvous = Rendezvous { port: free_port(), secret: secret(1), pid: 1, version: VERSION };
    let client = BridgeClient::connect(&rendezvous);
    let start = Instant::now();
    assert_eq!(client.current_sequence(), Err(SourceError::NoNetwork));
    assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
    let error = client.check_connection().unwrap_err();
    assert!(matches!(error, BridgeError::AppUnresponsive { .. }), "{error}");
    assert!(error.to_string().starts_with("the elasticdms app is not running"), "{error}");
}

#[test]
fn the_client_finds_a_restarted_app_without_restarting_the_extension() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bridge.json");
    let first = BridgeServer::start(Arc::new(SampleSource::new().0), &secret(1)).unwrap();
    first.rendezvous().write(&path).unwrap();
    let client = BridgeClient::from_rendezvous(&path).unwrap();
    assert_eq!(client.current_sequence(), Ok(4711));

    drop(first);
    assert_eq!(client.current_sequence(), Err(SourceError::NoNetwork));

    let second = BridgeServer::start(Arc::new(SampleSource::new().0), &secret(2)).unwrap();
    second.rendezvous().write(&path).unwrap();
    assert_eq!(client.current_sequence(), Ok(4711), "new port, new secret, the same client");
}

#[test]
fn a_foreign_version_is_an_internal_error_with_a_restart_hint() {
    let (server, _, source) = start(SampleSource::new().0);
    let old = Rendezvous { version: VERSION + 1, ..server.rendezvous() };
    let client = BridgeClient::connect(&old);
    let result = client.current_sequence();
    let Err(SourceError::Internal(text)) = result else { panic!("{result:?}") };
    assert!(text.contains("different builds"), "{text}");
    assert!(matches!(client.check_connection(), Err(BridgeError::WrongVersion { .. })));
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}
