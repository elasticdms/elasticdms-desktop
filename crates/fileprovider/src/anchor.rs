//! Sync anchors and page markers — the two pointers the system keeps on the extension's behalf.
//!
//! To the system both are opaque bytes (`NSData`), at most 500 of them
//! (NSFileProviderEnumerating.h); longer ones break off the enumeration, without a clean error.
//! That is why what stands here are pointers, not states: the anchor is a sequence number in the
//! engine's change journal, the marker a position in a listing.
//!
//! **Both carry a version byte.** The system keeps them across restarts and updates of the
//! extension. If a later version changes the format, it has to recognise an old anchor as such and
//! report `SyncAnchorExpired` — otherwise it would read old bytes as a new number, and the system
//! would get changes from a position that never existed.
//!
//! **The marker carries fingerprints.** Between two pages the engine may have refreshed the
//! listing; a mere offset would then point at a different entry, and an entry would fall unnoticed
//! between two pages. If the fingerprint no longer matches, the extension reports `PageExpired`,
//! and the system starts the enumeration from the beginning.

use edms_core::namespace::EntryIdentifier;

/// Upper bound for anchors and markers in bytes (NSFileProviderEnumerating.h).
pub const MAX_MARKER_BYTES: usize = 500;

/// Version of the anchor format.
pub const ANCHOR_VERSION: u8 = 1;
/// Length of an anchor: version byte and sequence number (u64, big endian).
pub const ANCHOR_LENGTH: usize = 1 + 8;

/// Version of the marker format.
pub const MARKER_VERSION: u8 = 1;
/// Length of a marker: version, container index (u32), offset (u32), two fingerprints (u64).
pub const MARKER_LENGTH: usize = 1 + 4 + 4 + 8 + 8;

/// Why some bytes are not an anchor or a marker of this extension.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarkerError {
    /// Wrong length — not written by this version.
    #[error("the marker has {read} bytes instead of {expected} and is not from this version")]
    Length {
        /// Bytes read.
        read: usize,
        /// Bytes expected.
        expected: usize,
    },
    /// Unknown version byte.
    #[error("the marker carries version {read}; this extension writes version {expected}")]
    Version {
        /// The version byte read.
        read: u8,
        /// The version byte of this extension.
        expected: u8,
    },
}

/// A sync anchor: the sequence number in the engine's change journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    sequence: u64,
}

impl Anchor {
    /// The anchor for a sequence number.
    pub const fn new(sequence: u64) -> Self {
        Self { sequence }
    }

    /// The sequence number.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// The bytes the system keeps.
    pub fn bytes(self) -> [u8; ANCHOR_LENGTH] {
        let mut out = [0u8; ANCHOR_LENGTH];
        out[0] = ANCHOR_VERSION;
        out[1..].copy_from_slice(&self.sequence.to_be_bytes());
        out
    }

    /// Reads the bytes the system hands back.
    pub fn read(bytes: &[u8]) -> Result<Self, MarkerError> {
        let field: &[u8; ANCHOR_LENGTH] = bytes
            .try_into()
            .map_err(|_| MarkerError::Length { read: bytes.len(), expected: ANCHOR_LENGTH })?;
        if field[0] != ANCHOR_VERSION {
            return Err(MarkerError::Version { read: field[0], expected: ANCHOR_VERSION });
        }
        let mut sequence = [0u8; 8];
        sequence.copy_from_slice(&field[1..]);
        Ok(Self { sequence: u64::from_be_bytes(sequence) })
    }
}

/// A position in a paged enumeration.
///
/// An enumeration runs over a plan of containers — a single one for a folder, all of them for the
/// working set — and inside each container over its children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageMarker {
    /// Index of the container within the plan.
    pub container_index: u32,
    /// Offset into the children of that container.
    pub offset: u32,
    /// Fingerprint of the plan (which containers in which order).
    pub plan: u64,
    /// Fingerprint of the container's children; only relevant when `offset > 0`.
    pub children: u64,
}

impl PageMarker {
    /// The bytes the system keeps as the next page.
    pub fn bytes(&self) -> [u8; MARKER_LENGTH] {
        let mut out = [0u8; MARKER_LENGTH];
        out[0] = MARKER_VERSION;
        out[1..5].copy_from_slice(&self.container_index.to_be_bytes());
        out[5..9].copy_from_slice(&self.offset.to_be_bytes());
        out[9..17].copy_from_slice(&self.plan.to_be_bytes());
        out[17..25].copy_from_slice(&self.children.to_be_bytes());
        out
    }

    /// Reads a marker this extension has handed out.
    pub fn read(bytes: &[u8]) -> Result<Self, MarkerError> {
        let field: &[u8; MARKER_LENGTH] = bytes
            .try_into()
            .map_err(|_| MarkerError::Length { read: bytes.len(), expected: MARKER_LENGTH })?;
        if field[0] != MARKER_VERSION {
            return Err(MarkerError::Version { read: field[0], expected: MARKER_VERSION });
        }
        let mut u32_field = [0u8; 4];
        let mut u64_field = [0u8; 8];
        u32_field.copy_from_slice(&field[1..5]);
        let container_index = u32::from_be_bytes(u32_field);
        u32_field.copy_from_slice(&field[5..9]);
        let offset = u32::from_be_bytes(u32_field);
        u64_field.copy_from_slice(&field[9..17]);
        let plan = u64::from_be_bytes(u64_field);
        u64_field.copy_from_slice(&field[17..25]);
        let children = u64::from_be_bytes(u64_field);
        Ok(Self { container_index, offset, plan, children })
    }
}

/// Fingerprint of a sequence of identifiers: FNV-1a (64 bit) over their text form.
///
/// No cryptographic claim — the point is to notice a listing that changed between two pages, not
/// to fend off an attacker. FNV instead of `DefaultHasher`, because the latter's values are allowed
/// to change between Rust versions and a marker can outlive an update of the extension.
pub fn fingerprint<I: IntoIterator<Item = EntryIdentifier>>(identifiers: I) -> u64 {
    const START: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut value = START;
    let mut swallow = |byte: u8| {
        value ^= u64::from(byte);
        value = value.wrapping_mul(PRIME);
    };
    for identifier in identifiers {
        for byte in identifier.to_string().bytes() {
            swallow(byte);
        }
        // A separator, so that ["ab", "c"] and ["a", "bc"] stay different.
        swallow(b'\n');
    }
    value
}

#[cfg(test)]
mod tests {
    use edms_core::namespace::Container;

    use super::*;

    #[test]
    fn an_anchor_survives_the_round_trip_and_is_one_byte_plus_sequence() {
        for sequence in [0, 1, 4_711, u64::MAX] {
            let bytes = Anchor::new(sequence).bytes();
            assert_eq!(bytes.len(), 9);
            assert_eq!(bytes[0], ANCHOR_VERSION);
            assert_eq!(&bytes[1..], &sequence.to_be_bytes());
            assert_eq!(Anchor::read(&bytes).unwrap().sequence(), sequence);
        }
    }

    #[test]
    fn an_anchor_of_a_foreign_length_is_none() {
        assert_eq!(Anchor::read(&[]), Err(MarkerError::Length { read: 0, expected: 9 }));
        assert!(Anchor::read(&[1; 10]).is_err());
        // The system's initial pages are not anchors.
        assert!(Anchor::read(&[0; 8]).is_err());
    }

    #[test]
    fn an_anchor_of_a_foreign_version_is_not_read_as_a_number() {
        let mut bytes = Anchor::new(5).bytes();
        bytes[0] = 2;
        assert_eq!(Anchor::read(&bytes), Err(MarkerError::Version { read: 2, expected: 1 }));
    }

    #[test]
    fn a_marker_survives_the_round_trip_and_stays_under_500_bytes() {
        let marker = PageMarker { container_index: 3, offset: 200, plan: u64::MAX, children: 17 };
        let bytes = marker.bytes();
        assert!(bytes.len() <= MAX_MARKER_BYTES);
        const { assert!(ANCHOR_LENGTH <= MAX_MARKER_BYTES) };
        assert_eq!(PageMarker::read(&bytes).unwrap(), marker);
    }

    #[test]
    fn a_marker_of_a_foreign_version_or_length_is_rejected() {
        let mut bytes = PageMarker { container_index: 0, offset: 1, plan: 2, children: 3 }.bytes();
        assert!(PageMarker::read(&bytes[..24]).is_err());
        bytes[0] = 9;
        assert_eq!(
            PageMarker::read(&bytes),
            Err(MarkerError::Version { read: 9, expected: MARKER_VERSION })
        );
    }

    #[test]
    fn the_fingerprint_notices_order_and_additions() {
        let a = EntryIdentifier::Container(Container::Archives);
        let s = EntryIdentifier::Container(Container::Searches);
        assert_eq!(fingerprint([a, s]), fingerprint([a, s]));
        assert_ne!(fingerprint([a, s]), fingerprint([s, a]));
        assert_ne!(fingerprint([a]), fingerprint([a, s]));
        assert_ne!(fingerprint([]), fingerprint([a]));
        // The four fixed containers are four different lists, not one.
        assert_ne!(fingerprint([a]), fingerprint([EntryIdentifier::Container(Container::Baskets)]));
    }
}
