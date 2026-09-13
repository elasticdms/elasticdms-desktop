//! SHA-256 in the core's wire form (`edms_core::checksum::Sha256Value`).
//!
//! The core holds and compares checksums, it does not compute them (`checksum.rs` in the core).
//! The computation stands here, because it carries the promise of hydration: **not one byte
//! reaches the platform before the checksum matches** (`edms_core::port`). The server notices a
//! truncated body only after `200`; only this comparison turns that into a failed hydration
//! instead of a mutilated file.
//!
//! [`Sha256Machine`] computes chunk by chunk, so that content of several hundred megabytes need
//! not sit in memory twice.

use edms_core::checksum::Sha256Value;
use sha2::{Digest, Sha256};

/// SHA-256 over a whole buffer.
pub fn sha256(data: &[u8]) -> Sha256Value {
    Sha256Value::from_bytes(crate::encoding::sha256(data))
}

/// SHA-256 chunk by chunk: hand chunks in order, at the end [`Sha256Machine::finished`].
#[derive(Clone, Default)]
pub struct Sha256Machine {
    inner: Sha256,
    read: u64,
}

impl Sha256Machine {
    /// A machine with no bytes read yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes in the next chunk.
    pub fn add_added(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
        self.read = self.read.saturating_add(chunk.len() as u64);
    }

    /// How many bytes have gone in so far — for the comparison with the announced size.
    pub fn read(&self) -> u64 {
        self.read
    }

    /// The checksum over everything handed in.
    pub fn finished(self) -> Sha256Value {
        Sha256Value::from_bytes(self.inner.finalize().into())
    }
}

impl std::fmt::Debug for Sha256Machine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sha256Machine({} bytes)", self.read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_input_has_the_well_known_checksum() {
        assert_eq!(
            sha256(b"").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn chunk_by_chunk_is_the_same_as_in_one_piece() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut machine = Sha256Machine::new();
        for chunk in data.chunks(333) {
            machine.add_added(chunk);
        }
        assert_eq!(machine.read(), 10_000);
        assert_eq!(machine.finished(), sha256(&data));
    }
}
