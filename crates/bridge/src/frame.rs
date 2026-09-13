//! The byte layer of the line: frames with length, kind and payload.
//!
//! ```text
//! [Length: u32 BE][Kind: u8][Payload: length - 1 bytes]
//! ```
//!
//! The length counts the kind in; a frame of length 0 has no kind and is an error.
//!
//! * `J` — a JSON message, complete or as the last part.
//! * `T` — a JSON part with more to follow. Only app → extension.
//! * `D` — a data chunk: `[Offset: u64 BE][max 256 KiB]`. Only app → extension.
//!
//! **The limit is checked before anything is read.** A single header with length `0xFFFF_FFFF`
//! would otherwise make the extension ask for 4 GiB before it has seen a single byte of content —
//! whether from an error in the app or a foreign program on the port.
//!
//! **Reading happens in time slices.** The socket has a short read deadline (250 ms); when it
//! passes, the reader asks whether there was a cancellation and then reads on, **without** losing
//! the bytes already read (`read_exact` discards them on an error). That way a cancellation in the
//! Finder takes effect within fractions of a second, even while the app is loading quietly for
//! minutes.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::{MAX_DATA_CHUNK, MAX_JSON_FRAME, MAX_MESSAGE};

/// Kind `J`: JSON, complete or the last part.
pub(crate) const KIND_JSON: u8 = b'J';
/// Kind `T`: JSON part, more to follow.
pub(crate) const KIND_PART: u8 = b'T';
/// Kind `D`: data chunk with an offset.
pub(crate) const KIND_DATA: u8 = b'D';

const OFFSET_BYTES: usize = 8;

/// Maximum size of the handshake in both directions. Before the handshake the counterpart is
/// unknown; it is not to be able to order even 1 MiB of memory.
pub(crate) const MAX_HANDSHAKE: usize = 4096;

/// What may arrive at a given place of the protocol.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limit {
    /// Maximum size of a JSON frame.
    pub(crate) json: usize,
    /// Maximum size of a JSON message across all parts; 0 means: no parts.
    pub(crate) message: usize,
    /// Whether data chunks are permitted.
    pub(crate) data: bool,
}

impl Limit {
    /// HELLO and WELCOME: small, undivided, no data.
    pub(crate) const HANDSHAKE: Self = Self { json: MAX_HANDSHAKE, message: 0, data: false };
    /// The extension's request: undivided, no data.
    pub(crate) const REQUEST: Self = Self { json: MAX_JSON_FRAME, message: 0, data: false };
    /// An answer of the app to a listing question: in parts as well.
    pub(crate) const RESPONSE: Self =
        Self { json: MAX_JSON_FRAME, message: MAX_MESSAGE, data: false };
    /// The answer to CONTENT: messages and data chunks.
    pub(crate) const CONTENT: Self =
        Self { json: MAX_JSON_FRAME, message: MAX_MESSAGE, data: true };
}

/// What has arrived completely.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Inbox {
    /// A JSON message, parts already put together.
    Json(Vec<u8>),
    /// A data chunk.
    Data {
        /// Where it belongs.
        offset: u64,
        /// The bytes.
        bytes: Vec<u8>,
    },
}

/// Why nothing arrived.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The counterpart has closed.
    Closed,
    /// The deadline has passed.
    Deadline(Duration),
    /// The caller cancelled while the wait was on.
    Cancelled,
    /// A frame violates a limit or a kind.
    Log(String),
    /// The operating system reports an error of the line.
    Link(io::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the far side closed the connection"),
            Self::Deadline(span) => write!(f, "{} seconds without a byte", span.as_secs()),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Log(text) => f.write_str(text),
            Self::Link(error) => write!(f, "{error}"),
        }
    }
}

/// Why nothing went out.
#[derive(Debug)]
pub(crate) enum WriteError {
    /// The message is larger than [`MAX_MESSAGE`].
    TooLarge(usize),
    /// The message cannot be written as JSON.
    Json(serde_json::Error),
    /// The operating system reports an error of the line.
    Link(io::Error),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(size) => {
                write!(f, "the message has {size} bytes; at most {MAX_MESSAGE} are allowed")
            }
            Self::Json(error) => {
                write!(f, "the message cannot be written as JSON ({error})")
            }
            Self::Link(error) => write!(f, "{error}"),
        }
    }
}

/// How long the wait lasts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    duration: Duration,
    until: Instant,
    extending: bool,
}

impl Deadline {
    /// A fixed deadline from now. For the app: a handshake that drips byte by byte still does not
    /// hold its place longer than this deadline.
    pub(crate) fn fixed(duration: Duration) -> Self {
        Self { duration, until: Instant::now() + duration, extending: false }
    }

    /// A silence deadline: every byte read resets it. For the client: a content that flows for ten
    /// minutes is no error; ten minutes of silence is.
    pub(crate) fn silence(duration: Duration) -> Self {
        Self { duration, until: Instant::now() + duration, extending: true }
    }

    fn motion(&mut self) {
        if self.extending {
            self.until = Instant::now() + self.duration;
        }
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.until
    }
}

/// Reads a complete input: a JSON message (parts put together) or a data chunk.
pub(crate) fn read_inbox<R: Read>(
    source: &mut R,
    limit: Limit,
    deadline: &mut Deadline,
    cancelled: &dyn Fn() -> bool,
) -> Result<Inbox, ReadError> {
    let mut collected: Vec<u8> = Vec::new();
    loop {
        let kind = read_kind_and_check(source, limit, deadline, cancelled, !collected.is_empty())?;
        match kind {
            Header::Json(length) | Header::Part(length) => {
                if collected.len() + length > limit.message.max(limit.json) {
                    return Err(ReadError::Log(format!(
                        "a JSON message exceeds {} bytes",
                        limit.message.max(limit.json)
                    )));
                }
                let start = collected.len();
                collected.resize(start + length, 0);
                read_exactly(source, &mut collected[start..], deadline, cancelled)?;
                if matches!(kind, Header::Json(_)) {
                    return Ok(Inbox::Json(collected));
                }
            }
            Header::Data(length) => {
                let mut offset = [0u8; OFFSET_BYTES];
                read_exactly(source, &mut offset, deadline, cancelled)?;
                let mut bytes = vec![0u8; length];
                read_exactly(source, &mut bytes, deadline, cancelled)?;
                return Ok(Inbox::Data { offset: u64::from_be_bytes(offset), bytes });
            }
        }
    }
}

/// A checked, admissible frame header with the length of what is still to be read.
#[derive(Debug, Clone, Copy)]
enum Header {
    Json(usize),
    Part(usize),
    /// Length without the offset.
    Data(usize),
}

fn read_kind_and_check<R: Read>(
    source: &mut R,
    limit: Limit,
    deadline: &mut Deadline,
    cancelled: &dyn Fn() -> bool,
    mid_message: bool,
) -> Result<Header, ReadError> {
    let mut header = [0u8; 5];
    read_exactly(source, &mut header, deadline, cancelled)?;
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let Some(payload) = usize::try_from(length).ok().and_then(|len| len.checked_sub(1)) else {
        return Err(ReadError::Log("a frame of length 0 has no kind".to_owned()));
    };
    let log = |text: String| Err(ReadError::Log(text));
    match header[4] {
        KIND_JSON | KIND_PART if payload > limit.json => {
            log(format!("JSON frame with {payload} bytes; at most {} are allowed", limit.json))
        }
        KIND_PART if limit.message == 0 => {
            log("no split message is allowed at this point".to_owned())
        }
        KIND_JSON => Ok(Header::Json(payload)),
        KIND_PART => Ok(Header::Part(payload)),
        KIND_DATA if !limit.data => log("no data chunk is allowed at this point".to_owned()),
        KIND_DATA if mid_message => {
            log("a data chunk in the middle of a split JSON message".to_owned())
        }
        KIND_DATA => match payload.checked_sub(OFFSET_BYTES) {
            None => log(format!("a data chunk of {payload} bytes has no offset")),
            Some(data) if data > MAX_DATA_CHUNK => {
                log(format!("data chunk of {data} bytes; at most {MAX_DATA_CHUNK} are allowed"))
            }
            Some(data) => Ok(Header::Data(data)),
        },
        other => log(format!("unknown frame kind 0x{other:02x}")),
    }
}

/// Reads exactly `buffer.len()` bytes, across time slices, without losing what has been read.
fn read_exactly<R: Read>(
    source: &mut R,
    buffer: &mut [u8],
    deadline: &mut Deadline,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), ReadError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => return Err(ReadError::Closed),
            Ok(read) => {
                filled += read;
                deadline.motion();
                // A fixed deadline holds for a counterpart too that sends a byte just often enough
                // that no time slice ever passes — otherwise one byte every 50 ms would hold one of
                // the app's 16 places forever.
                if filled < buffer.len() && deadline.expired() {
                    return Err(ReadError::Deadline(deadline.duration));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // Unix reports a read deadline that has passed as WouldBlock, Windows as TimedOut.
            Err(error)
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                if cancelled() {
                    return Err(ReadError::Cancelled);
                }
                if deadline.expired() {
                    return Err(ReadError::Deadline(deadline.duration));
                }
            }
            Err(error) => return Err(ReadError::Link(error)),
        }
    }
    Ok(())
}

/// Writes a JSON message; above [`MAX_JSON_FRAME`] in parts.
pub(crate) fn write_json<W: Write, T: Serialize>(
    target: &mut W,
    message: &T,
) -> Result<(), WriteError> {
    let json = serde_json::to_vec(message).map_err(WriteError::Json)?;
    if json.len() > MAX_MESSAGE {
        return Err(WriteError::TooLarge(json.len()));
    }
    let mut rest: &[u8] = &json;
    while rest.len() > MAX_JSON_FRAME {
        let (part, after) = rest.split_at(MAX_JSON_FRAME);
        write_frame(target, KIND_PART, &[part]).map_err(WriteError::Link)?;
        rest = after;
    }
    write_frame(target, KIND_JSON, &[rest]).map_err(WriteError::Link)
}

/// Writes a data chunk of at most [`MAX_DATA_CHUNK`] bytes.
pub(crate) fn write_data<W: Write>(target: &mut W, offset: u64, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_DATA_CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("data chunk of {} bytes; at most {MAX_DATA_CHUNK} per frame", data.len()),
        ));
    }
    write_frame(target, KIND_DATA, &[&offset.to_be_bytes(), data])
}

fn write_frame<W: Write>(target: &mut W, kind: u8, share: &[&[u8]]) -> io::Result<()> {
    let payload = 1 + share.iter().map(|part| part.len()).sum::<usize>();
    let length = u32::try_from(payload).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "frames above 4 GiB cannot be represented")
    })?;
    let mut buffer = Vec::with_capacity(4 + payload);
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.push(kind);
    for part in share {
        buffer.extend_from_slice(part);
    }
    target.write_all(&buffer)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn never() -> bool {
        false
    }

    fn raw(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(payload.len() + 1).unwrap().to_be_bytes().to_vec();
        frame.push(kind);
        frame.extend_from_slice(payload);
        frame
    }

    fn read_frame(bytes: Vec<u8>, limit: Limit) -> Result<Inbox, ReadError> {
        let mut deadline = Deadline::fixed(Duration::from_secs(5));
        read_inbox(&mut Cursor::new(bytes), limit, &mut deadline, &never)
    }

    #[test]
    fn a_header_above_the_limit_is_rejected_before_the_payload_is_read() {
        // Only the header, no payload: had it been read, "Closed" would come instead of the limit.
        let mut header = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        header.push(KIND_JSON);
        let error = read_frame(header, Limit::RESPONSE).unwrap_err();
        assert!(matches!(&error, ReadError::Log(text) if text.contains("at most")), "{error}");
    }

    #[test]
    fn a_frame_without_a_kind_and_an_unknown_kind_are_errors() {
        assert!(matches!(read_frame(vec![0, 0, 0, 0, 0], Limit::RESPONSE), Err(ReadError::Log(_))));
        assert!(matches!(read_frame(raw(b'X', b"{}"), Limit::RESPONSE), Err(ReadError::Log(_))));
    }

    #[test]
    fn a_long_message_travels_in_parts_and_arrives_whole() {
        let text = "ä".repeat(MAX_JSON_FRAME); // 2 MiB UTF-8, as a JSON string
        let mut bytes = Vec::new();
        write_json(&mut bytes, &text).unwrap();
        assert_eq!(bytes[4], KIND_PART, "the first frame has to be a part");
        let Inbox::Json(json) = read_frame(bytes.clone(), Limit::RESPONSE).unwrap() else {
            panic!("expected JSON");
        };
        assert_eq!(serde_json::from_slice::<String>(&json).unwrap(), text);
        // A request must not be divided.
        assert!(matches!(read_frame(bytes, Limit::REQUEST), Err(ReadError::Log(_))));
    }

    #[test]
    fn parts_above_the_message_limit_are_rejected() {
        let limit = Limit { json: 10, message: 25, data: false };
        let mut bytes = Vec::new();
        for _ in 0..3 {
            bytes.extend(raw(KIND_PART, &[b' '; 10]));
        }
        bytes.extend(raw(KIND_JSON, b"1"));
        assert!(matches!(read_frame(bytes, limit), Err(ReadError::Log(_))));
    }

    #[test]
    fn data_chunks_without_an_offset_above_256_kib_or_mid_json_are_rejected() {
        assert!(matches!(
            read_frame(raw(KIND_DATA, &[0; 7]), Limit::CONTENT),
            Err(ReadError::Log(_))
        ));
        let too_large = vec![0u8; OFFSET_BYTES + MAX_DATA_CHUNK + 1];
        assert!(matches!(
            read_frame(raw(KIND_DATA, &too_large), Limit::CONTENT),
            Err(ReadError::Log(_))
        ));
        let mut mixed = raw(KIND_PART, b"[1,");
        mixed.extend(raw(KIND_DATA, &[0; 9]));
        assert!(matches!(read_frame(mixed, Limit::CONTENT), Err(ReadError::Log(_))));
        // And outside a content not at all.
        assert!(matches!(
            read_frame(raw(KIND_DATA, &[0; 9]), Limit::RESPONSE),
            Err(ReadError::Log(_))
        ));
    }

    #[test]
    fn a_data_chunk_survives_the_round_trip() {
        let mut bytes = Vec::new();
        write_data(&mut bytes, 7_000_000_000, &[1, 2, 3]).unwrap();
        let inbox = read_frame(bytes, Limit::CONTENT).unwrap();
        assert_eq!(inbox, Inbox::Data { offset: 7_000_000_000, bytes: vec![1, 2, 3] });
        assert!(write_data(&mut Vec::new(), 0, &vec![0; MAX_DATA_CHUNK + 1]).is_err());
    }

    /// Delivers at most one byte per call and in between again and again "deadline passed" — like a
    /// socket whose time slice passes in the middle of a frame.
    struct Drip {
        bytes: Vec<u8>,
        place: usize,
        pause: bool,
    }

    impl Read for Drip {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.pause = !self.pause;
            if self.pause {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "time slice"));
            }
            let Some(&byte) = self.bytes.get(self.place) else { return Ok(0) };
            buffer[0] = byte;
            self.place += 1;
            Ok(1)
        }
    }

    #[test]
    fn a_time_slice_that_passes_mid_frame_loses_no_byte() {
        let mut bytes = Vec::new();
        write_json(&mut bytes, &"Prüfbericht Pumpe 7").unwrap();
        let mut drip = Drip { bytes, place: 0, pause: false };
        let mut deadline = Deadline::silence(Duration::from_secs(5));
        let inbox = read_inbox(&mut drip, Limit::RESPONSE, &mut deadline, &never).unwrap();
        assert_eq!(inbox, Inbox::Json(b"\"Pr\xc3\xbcfbericht Pumpe 7\"".to_vec()));
    }

    struct Mute;

    impl Read for Mute {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(1));
            Err(io::Error::new(io::ErrorKind::TimedOut, "time slice"))
        }
    }

    #[test]
    fn while_waiting_the_cancellation_takes_effect_first_and_then_the_deadline() {
        let mut deadline = Deadline::fixed(Duration::from_secs(60));
        let error = read_inbox(&mut Mute, Limit::RESPONSE, &mut deadline, &|| true).unwrap_err();
        assert!(matches!(error, ReadError::Cancelled));
        let mut deadline = Deadline::fixed(Duration::from_millis(20));
        let error = read_inbox(&mut Mute, Limit::RESPONSE, &mut deadline, &never).unwrap_err();
        assert!(matches!(error, ReadError::Deadline(_)));
    }

    /// One byte per millisecond and never a time slice that passes: the slowest counterpart that is
    /// nevertheless never silent.
    struct Trickle {
        header: Vec<u8>,
        place: usize,
    }

    impl Read for Trickle {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(1));
            buffer[0] = self.header.get(self.place).copied().unwrap_or(b' ');
            self.place += 1;
            Ok(1)
        }
    }

    fn trickle(payload: u32) -> Trickle {
        let mut header = (payload + 1).to_be_bytes().to_vec();
        header.push(KIND_JSON);
        Trickle { header, place: 0 }
    }

    #[test]
    fn a_fixed_deadline_holds_for_a_steady_trickle_too() {
        let mut deadline = Deadline::fixed(Duration::from_millis(50));
        let error =
            read_inbox(&mut trickle(4000), Limit::HANDSHAKE, &mut deadline, &never).unwrap_err();
        assert!(matches!(error, ReadError::Deadline(_)), "{error}");
        // A silence deadline is extended by every byte: 300 bytes take longer than the deadline
        // and come through all the same.
        let mut deadline = Deadline::silence(Duration::from_millis(200));
        let inbox = read_inbox(&mut trickle(300), Limit::HANDSHAKE, &mut deadline, &never);
        assert!(matches!(inbox, Ok(Inbox::Json(json)) if json.len() == 300));
    }
}
