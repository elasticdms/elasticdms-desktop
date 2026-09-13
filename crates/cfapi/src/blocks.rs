//! The 4 KB arithmetic for `CF_OPERATION_TYPE_TRANSFER_DATA`.
//!
//! cldflt accepts data only in chunks whose offset **and** length are multiples of 4096; only the
//! last chunk may be ragged, and only if it ends exactly at the end of the file
//! (ns-cfapi-cf_operation_parameters). The source writes however it likes — a 200 MB chunk in one
//! go, or 1000 bytes at a time. [`BlockBuffer`] sits in between: it collects, passes aligned chunks
//! on and holds the remainder until the end of the file allows it to be ragged.
//!
//! A second reason to count exactly: if the delivered amount does not match the size of the
//! placeholder, the hydration must not "almost" succeed. Too little is
//! [`BlockError::Incomplete`], too much is [`BlockError::OverEnd`] — no file that is correct
//! except for its last chunk.

use edms_core::port::SinkError;

/// The alignment cldflt demands.
pub const ALIGNMENT: u64 = 4096;

/// Chunk size for `TRANSFER_DATA`: 1 MiB, a multiple of [`ALIGNMENT`].
///
/// Larger than strictly necessary, because every `CfExecute` is a transition into the kernel;
/// smaller than the file, so that the progress bar in Explorer moves.
pub const CHUNK_SIZE: usize = 1 << 20;

/// Why a chunk was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    /// Chunks must arrive ascending and without gaps (`ContentSink::write`).
    #[error(
        "a chunk arrived at offset {got} where {expected} was expected; chunks have to arrive \
         ascending and without gaps"
    )]
    Gap {
        /// The next expected offset.
        expected: u64,
        /// The one delivered.
        got: u64,
    },
    /// The source wrote past the end of the placeholder.
    #[error(
        "the source delivered data up to byte {until}, but the placeholder is only {total} bytes"
    )]
    OverEnd {
        /// End of the delivered chunk.
        until: u64,
        /// Size of the placeholder.
        total: u64,
    },
    /// The source stopped before the end.
    #[error("the source delivered only {delivered} of {total} bytes; the file was not taken over")]
    Incomplete {
        /// Bytes delivered.
        delivered: u64,
        /// Bytes expected.
        total: u64,
    },
    /// Handing the data on to cldflt failed.
    #[error(transparent)]
    HandOff(#[from] SinkError),
}

impl From<BlockError> for SinkError {
    fn from(error: BlockError) -> Self {
        match error {
            BlockError::HandOff(s) => s,
            other => SinkError(other.to_string()),
        }
    }
}

/// Collects written bytes and passes them on in permitted chunks.
#[derive(Debug)]
pub struct BlockBuffer {
    total: u64,
    received: u64,
    sent: u64,
    buffer: Vec<u8>,
    chunk: usize,
    completed: bool,
}

impl BlockBuffer {
    /// For a placeholder of `total` bytes, with [`CHUNK_SIZE`].
    pub fn new(total: u64) -> Self {
        Self::with_chunk_size(total, CHUNK_SIZE)
    }

    /// With a different chunk size; it is rounded up to a multiple of [`ALIGNMENT`].
    pub fn with_chunk_size(total: u64, chunk: usize) -> Self {
        let alignment = ALIGNMENT as usize;
        let chunk = chunk.max(1).div_ceil(alignment) * alignment;
        Self { total, received: 0, sent: 0, buffer: Vec::new(), chunk, completed: false }
    }

    /// Size of the placeholder.
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// How many bytes the source has written so far.
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// How many bytes have been passed on to cldflt — always aligned, or equal to [`Self::total`].
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Accepts a chunk from the source and passes on to `output` whatever is aligned and ready.
    ///
    /// `output(offset, data)` only ever receives chunks with an aligned offset and a length of
    /// exactly the chunk size. Large chunks from the source are passed through without copying.
    pub fn take<F>(&mut self, offset: u64, data: &[u8], mut output: F) -> Result<(), BlockError>
    where
        F: FnMut(u64, &[u8]) -> Result<(), SinkError>,
    {
        if offset != self.received {
            return Err(BlockError::Gap { expected: self.received, got: offset });
        }
        let until = offset
            .checked_add(data.len() as u64)
            .ok_or(BlockError::OverEnd { until: u64::MAX, total: self.total })?;
        if until > self.total {
            return Err(BlockError::OverEnd { until, total: self.total });
        }
        self.received = until;
        let mut rest = data;
        if !self.buffer.is_empty() {
            let missing = self.chunk - self.buffer.len();
            let (front, back) = rest.split_at(missing.min(rest.len()));
            self.buffer.extend_from_slice(front);
            rest = back;
            if self.buffer.len() == self.chunk {
                output(self.sent, &self.buffer)?;
                self.sent += self.chunk as u64;
                self.buffer.clear();
            }
        }
        // At this point the buffer is empty, or `rest` has been used up.
        while rest.len() >= self.chunk {
            let (head, tail) = rest.split_at(self.chunk);
            output(self.sent, head)?;
            self.sent += self.chunk as u64;
            rest = tail;
        }
        self.buffer.extend_from_slice(rest);
        Ok(())
    }

    /// Passes on the remainder — permitted, because it ends at the end of the file — and
    /// establishes that everything arrived. A second call passes on nothing more.
    ///
    /// An empty file gets exactly one empty chunk at offset 0: otherwise the request would stay
    /// open without an answer until cldflt discards it after 60 seconds.
    pub fn complete<F>(&mut self, mut output: F) -> Result<u64, BlockError>
    where
        F: FnMut(u64, &[u8]) -> Result<(), SinkError>,
    {
        if self.received != self.total {
            return Err(BlockError::Incomplete { delivered: self.received, total: self.total });
        }
        if !self.completed && (!self.buffer.is_empty() || self.total == 0) {
            output(self.sent, &self.buffer)?;
            self.sent += self.buffer.len() as u64;
            self.buffer.clear();
        }
        self.completed = true;
        Ok(self.total)
    }
}

/// Which range is to be reported as failed, or `None` if nothing is open any more.
///
/// Failure too needs a valid range (research note "Windows Cloud Filter API", `TRANSFER_DATA`);
/// cloud-filter sends `Length = 0` and risks cldflt rejecting even the failure report. What is
/// reported is the requested range starting at whatever has not been sent yet — what has been sent
/// is aligned, so the start is too. `requested_length < 0` is `CF_EOF`.
pub fn error_domain(
    requested_offset: i64,
    requested_length: i64,
    file_size: i64,
    sent: u64,
) -> Option<(i64, i64)> {
    if requested_length == 0 {
        return Some((requested_offset.max(0), 0));
    }
    let end = if requested_length < 0 {
        file_size
    } else {
        requested_offset.saturating_add(requested_length)
    };
    // Files larger than i64::MAX bytes do not exist on NTFS; the saturation is arithmetic
    // protection only.
    let sent = i64::try_from(sent).unwrap_or(i64::MAX);
    let start = requested_offset.max(sent).max(0);
    (end > start).then_some((start, end - start))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `data` in chunks of lengths `cuts` (cyclically) and collects the output.
    fn write_fragmented(data: &[u8], cuts: &[usize], chunk: usize) -> Vec<(u64, Vec<u8>)> {
        let mut buffer = BlockBuffer::with_chunk_size(data.len() as u64, chunk);
        let mut out = Vec::new();
        let mut pos = 0;
        let mut i = 0;
        while pos < data.len() {
            let n = cuts[i % cuts.len()].min(data.len() - pos);
            buffer
                .take(pos as u64, &data[pos..pos + n], |v, d| {
                    out.push((v, d.to_vec()));
                    Ok(())
                })
                .unwrap();
            pos += n;
            i += 1;
        }
        buffer
            .complete(|v, d| {
                out.push((v, d.to_vec()));
                Ok(())
            })
            .unwrap();
        out
    }

    fn check_rules(out: &[(u64, Vec<u8>)], data: &[u8]) {
        let total = data.len() as u64;
        let mut expected = 0;
        let mut joined = Vec::new();
        for (v, d) in out {
            assert_eq!(*v, expected, "chunks must follow without gaps");
            assert!(v.is_multiple_of(ALIGNMENT), "offset {v} not aligned");
            let end = v + d.len() as u64;
            assert!(
                (d.len() as u64).is_multiple_of(ALIGNMENT) || end == total,
                "ragged chunk [{v}, {end}) does not end at the end of the file {total}"
            );
            expected = end;
            joined.extend_from_slice(d);
        }
        assert_eq!(joined, data, "the output adds up to the file");
    }

    fn pattern(n: usize) -> Vec<u8> {
        // A simple linear congruence: equal bytes at different places would otherwise go
        // unnoticed if chunks were swapped.
        let mut x: u32 = 12_345;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect()
    }

    #[test]
    fn every_fragmentation_yields_aligned_chunks_and_the_whole_file() {
        for size in [1, 4095, 4096, 4097, 8192, 12_345, 3 * 16_384 + 7] {
            let data = pattern(size);
            for cuts in
                [&[1][..], &[1000], &[4096], &[5000, 3], &[16_384], &[100_000], &[7, 4089, 13]]
            {
                let out = write_fragmented(&data, cuts, 16_384);
                check_rules(&out, &data);
            }
        }
    }

    #[test]
    fn only_the_last_chunk_is_ragged() {
        let data = pattern(10_000);
        let out = write_fragmented(&data, &[10_000], 4096);
        let lengths: Vec<usize> = out.iter().map(|(_, d)| d.len()).collect();
        assert_eq!(lengths, [4096, 4096, 1808]);
    }

    #[test]
    fn a_chunk_with_a_gap_is_rejected() {
        let mut p = BlockBuffer::new(10_000);
        p.take(0, &[0; 100], |_, _| Ok(())).unwrap();
        let f = p.take(200, &[0; 100], |_, _| Ok(())).unwrap_err();
        assert_eq!(f, BlockError::Gap { expected: 100, got: 200 });
    }

    #[test]
    fn more_than_the_placeholder_holds_is_rejected() {
        let mut p = BlockBuffer::new(100);
        let f = p.take(0, &[0; 101], |_, _| Ok(())).unwrap_err();
        assert_eq!(f, BlockError::OverEnd { until: 101, total: 100 });
    }

    #[test]
    fn a_delivery_that_is_too_short_is_not_a_completion() {
        let mut p = BlockBuffer::with_chunk_size(5000, 4096);
        let mut sent = 0;
        p.take(0, &[0; 4999], |_, d| {
            sent += d.len();
            Ok(())
        })
        .unwrap();
        let f = p
            .complete(|_, d| {
                sent += d.len();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(f, BlockError::Incomplete { delivered: 4999, total: 5000 });
        // The ragged tail must not have been passed on: it does not end at the end of the file.
        assert_eq!(sent, 4096);
    }

    #[test]
    fn an_empty_file_gets_exactly_one_empty_chunk() {
        let mut p = BlockBuffer::new(0);
        let mut out = Vec::new();
        p.complete(|v, d| {
            out.push((v, d.len()));
            Ok(())
        })
        .unwrap();
        p.complete(|v, d| {
            out.push((v, d.len()));
            Ok(())
        })
        .unwrap();
        assert_eq!(out, [(0, 0)]);
    }

    #[test]
    fn an_error_from_the_output_is_passed_on() {
        let mut p = BlockBuffer::with_chunk_size(8192, 4096);
        let f = p.take(0, &[0; 8192], |_, _| Err(SinkError("cldflt refuses".into()))).unwrap_err();
        assert_eq!(f, BlockError::HandOff(SinkError("cldflt refuses".into())));
        assert_eq!(SinkError::from(f).0, "cldflt refuses");
    }

    #[test]
    fn the_chunk_size_is_rounded_up_to_the_alignment() {
        let data = pattern(20_000);
        let out = write_fragmented(&data, &[20_000], 5000);
        assert!(out.iter().rev().skip(1).all(|(_, d)| d.len() == 8192));
        check_rules(&out, &data);
    }

    #[test]
    fn only_what_is_still_open_is_reported() {
        assert_eq!(error_domain(0, 8192, 8192, 0), Some((0, 8192)));
        assert_eq!(error_domain(0, 10_000, 10_000, 4096), Some((4096, 5904)));
        assert_eq!(error_domain(0, 10_000, 10_000, 10_000), None);
        // CF_EOF as the length: up to the end of the file.
        assert_eq!(error_domain(4096, -1, 10_000, 0), Some((4096, 5904)));
        // More is requested than has been sent; the report starts at what was requested.
        assert_eq!(error_domain(8192, 4096, 20_000, 4096), Some((8192, 4096)));
        // An empty request still needs an answer.
        assert_eq!(error_domain(0, 0, 0, 0), Some((0, 0)));
    }
}
