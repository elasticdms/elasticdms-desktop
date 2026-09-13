//! Identifiers: one 128-bit value, two encodings (03 §6.0.3).
//!
//! On the wire and in paths every domain identifier stands as `<prefix>_<26 characters of
//! Crockford base32>`; in the `aoid` field and in every TR-ESOR export the same value stands as
//! RFC 9562 UUID text. The conversion is a lossless change of base and lives only here.
//!
//! **Strict when reading.** Lower-case letters, `I`/`L`/`O`/`U`, hyphens and UUID text are
//! rejected, although Crockford would be allowed to read them generously: the server answers
//! exactly these forms with `400 invalid-resource-id` (03 §6.0.3, contract test T17). A client
//! that is more lenient here than the server holds identifiers valid that the server rejects —
//! a fault that surfaces only in production, and there nobody can place it any more.
//!
//! **No randomness here.** The core does not create identifiers, it only shapes them. Whoever
//! needs a new identifier takes 128 bits from `edms-crypto` and hands them to
//! [`Identifier::from_value`].

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The Crockford alphabet without `I`, `L`, `O`, `U` — in exactly this order.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of characters of the identifier part behind the prefix.
///
/// 26 characters of 5 bits each are 130 bits; the two surplus top bits are always zero, which is
/// why the first character may be at most `7` (otherwise overflow, contract test T17).
pub const LENGTH: usize = 26;

/// Length of the RFC 9562 text `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub const UUID_TEXT_LENGTH: usize = 36;

/// Number of characters of the short form appended to a file name when names collide.
pub const SHORT_FORM_LENGTH: usize = 8;

/// Why a string is not an identifier. Every variant names the position, so that a message in
/// production points at the offending character and not merely at “invalid”.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentifierError {
    /// The prefix is missing or belongs to another kind.
    #[error("identifier `{text}` does not carry the prefix `{expected}_` (03 §6.0.3)")]
    WrongPrefix {
        /// The string that was read.
        text: String,
        /// The expected prefix without the underscore.
        expected: &'static str,
    },
    /// The identifier part does not have exactly 26 characters.
    #[error("identifier `{text}` has {read} instead of {LENGTH} characters after the prefix")]
    Length {
        /// The string that was read.
        text: String,
        /// The number of characters that was read.
        read: usize,
    },
    /// A character lies outside the strict alphabet.
    #[error(
        "identifier `{text}` carries `{character}` at position {place}; only 0-9 and A-Z without \
         I, L, O, U are allowed, in upper case (03 §6.0.3)"
    )]
    Character {
        /// The string that was read.
        text: String,
        /// The rejected character.
        character: char,
        /// Position within the identifier part, starting at 1.
        place: usize,
    },
    /// The first character is greater than `7`; the value did not fit into 128 bits.
    #[error("identifier `{text}` starts with `{character}`; above `7` the 128-bit value overflows")]
    Overflow {
        /// The string that was read.
        text: String,
        /// The first character of the identifier part.
        character: char,
    },
    /// The UUID text is not in RFC 9562 form.
    #[error("`{text}` is not a UUID text per RFC 9562 (8-4-4-4-12 hex digits)")]
    UuidText {
        /// The string that was read.
        text: String,
    },
}

/// The kinds of domain identifier the folder client knows, with their wire prefix.
///
/// The first three are in 03 §6.0.3. The rest are this repository's **proposal**
/// (`docs/spec/03-api-contract-folder-client.md` §7.0): the counterpart's contract knows none of
/// documents, archives, case files (Akten), mail baskets and saved searches as a resource.
pub trait Kind: Copy + Eq + std::hash::Hash + fmt::Debug + Send + Sync + 'static {
    /// The prefix without the underscore, exactly as on the wire.
    const PREFIX: &'static str;
    /// Whether the prefix is in the counterpart's contract (`false`) or proposed here.
    const PROPOSED: bool;
}

macro_rules! identifier_kind {
    ($(#[$doc:meta])* $kind:ident, $alias:ident, $prefix:literal, $proposed:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $kind {}

        impl Kind for $kind {
            const PREFIX: &'static str = $prefix;
            const PROPOSED: bool = $proposed;
        }

        $(#[$doc])*
        pub type $alias = Identifier<$kind>;
    };
}

identifier_kind!(
    /// Device (`dev_`, 03 §6.0.3). Created by the client itself, before enrollment.
    DeviceIdKind, DeviceIdentifier, "dev", false
);
identifier_kind!(
    /// User (`usr_`, 03 §6.0.3). Arrives as `sub` in the token; the client treats it as opaque.
    UserKind, UserIdentifier, "usr", false
);
identifier_kind!(
    /// Upload (`upl_`, 03 §6.0.3). One ingest from a mail basket.
    UploadIdKind, UploadIdentifier, "upl", false
);
identifier_kind!(
    /// Document (`doc_`, proposal §7.0). Server-side the `document_id`.
    DocumentIdKind, DocumentIdentifier, "doc", true
);
identifier_kind!(
    /// Archive (`arc_`, proposal §7.0). The shelf; every case file stands in exactly one.
    ArchiveIdKind, ArchiveIdentifier, "arc", true
);
identifier_kind!(
    /// Case file (Akte) (`cas_`, proposal §7.0). Never stands alone — its archive comes with it.
    CaseIdKind, CaseIdentifier, "cas", true
);
identifier_kind!(
    /// Mail basket (`bsk_`, proposal §7.0). The one place a new file may be dropped; it holds
    /// nothing afterwards, because the ingest rule decides where the document is filed.
    BasketIdKind, BasketIdentifier, "bsk", true
);
identifier_kind!(
    /// Saved search (`srch_`, proposal §7.0).
    SearchIdKind, SearchIdentifier, "srch", true
);
identifier_kind!(
    /// Delivery command (`cmd_`, proposal §7.4). One order from the delivery channel.
    CommandIdKind, CommandIdentifier, "cmd", true
);

/// A domain identifier of kind `A`: one 128-bit value.
///
/// The kind sits in the type, not in the value: a [`DocumentIdentifier`] cannot be handed to a
/// place that expects a [`CaseIdentifier`], although both carry the same 128 bits.
pub struct Identifier<A: Kind> {
    value: u128,
    kind: PhantomData<A>,
}

impl<A: Kind> Identifier<A> {
    /// Shapes an identifier from a 128-bit value. Every value is valid.
    pub const fn from_value(value: u128) -> Self {
        Self { value, kind: PhantomData }
    }

    /// The 128-bit value.
    pub const fn value(self) -> u128 {
        self.value
    }

    /// Only the identifier part, 26 characters, without the prefix.
    pub fn identifier_part(self) -> String {
        let character = encode(self.value);
        // The alphabet is ASCII, so every position is one byte.
        character.iter().map(|&b| char::from(b)).collect()
    }

    /// The last eight characters of the identifier part.
    ///
    /// The last, not the first: server-side, document identifiers are UUIDv7, whose first 48 bits
    /// are a timestamp. Two invoices filed on the same morning would share the same first eight
    /// characters, and the short form would tell nothing apart.
    pub fn short_form(self) -> String {
        let part = self.identifier_part();
        part[LENGTH - SHORT_FORM_LENGTH..].to_owned()
    }

    /// The RFC 9562 text, lower case.
    pub fn as_uuid_text(self) -> String {
        let hex = format!("{:032x}", self.value);
        format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
    }

    /// Reads the RFC 9562 text. Upper and lower case are equivalent per RFC 9562.
    pub fn from_uuid_text(text: &str) -> Result<Self, IdentifierError> {
        let error = || IdentifierError::UuidText { text: text.to_owned() };
        let bytes = text.as_bytes();
        if bytes.len() != UUID_TEXT_LENGTH {
            return Err(error());
        }
        let mut value: u128 = 0;
        for (place, &b) in bytes.iter().enumerate() {
            if matches!(place, 8 | 13 | 18 | 23) {
                if b != b'-' {
                    return Err(error());
                }
                continue;
            }
            let digit = char::from(b).to_digit(16).ok_or_else(error)?;
            value = (value << 4) | u128::from(digit);
        }
        Ok(Self::from_value(value))
    }
}

impl<A: Kind> Clone for Identifier<A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<A: Kind> Copy for Identifier<A> {}
impl<A: Kind> PartialEq for Identifier<A> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<A: Kind> Eq for Identifier<A> {}
impl<A: Kind> std::hash::Hash for Identifier<A> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}
impl<A: Kind> PartialOrd for Identifier<A> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<A: Kind> Ord for Identifier<A> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<A: Kind> fmt::Display for Identifier<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", A::PREFIX, self.identifier_part())
    }
}

impl<A: Kind> fmt::Debug for Identifier<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<A: Kind> FromStr for Identifier<A> {
    type Err = IdentifierError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let part =
            text.strip_prefix(A::PREFIX).and_then(|rest| rest.strip_prefix('_')).ok_or_else(
                || IdentifierError::WrongPrefix { text: text.to_owned(), expected: A::PREFIX },
            )?;
        decode(text, part).map(Self::from_value)
    }
}

impl<A: Kind> Serialize for Identifier<A> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de, A: Kind> Deserialize<'de> for Identifier<A> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Encodes 128 bits as 26 characters of Crockford base32, most significant position first.
pub fn encode(value: u128) -> [u8; LENGTH] {
    let mut from = [0u8; LENGTH];
    for (i, place) in from.iter_mut().rev().enumerate() {
        // The mask keeps the index below 32; the conversion loses nothing.
        let index = ((value >> (5 * i)) & 0x1f) as usize;
        *place = ALPHABET[index];
    }
    from
}

/// Encodes an arbitrary byte sequence as Crockford base32 without padding, most significant bit
/// first. Needed for the anchor fingerprint (geraete-auth §5.3: 10 bytes → 16 characters).
pub fn encode_bytes(bytes: &[u8]) -> String {
    let mut from = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            from.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        from.push(char::from(ALPHABET[index]));
    }
    from
}

fn decode(whole: &str, part: &str) -> Result<u128, IdentifierError> {
    let read = part.chars().count();
    if read != LENGTH || part.len() != LENGTH {
        return Err(IdentifierError::Length { text: whole.to_owned(), read });
    }
    let mut value: u128 = 0;
    for (i, character) in part.chars().enumerate() {
        let index = ALPHABET.iter().position(|&b| char::from(b) == character).ok_or_else(|| {
            IdentifierError::Character { text: whole.to_owned(), character, place: i + 1 }
        })?;
        if i == 0 && index > 7 {
            return Err(IdentifierError::Overflow { text: whole.to_owned(), character });
        }
        // With a first character <= 7 this is 3 + 25*5 = 128 bits; the shift never overflows.
        value = (value << 5) | index as u128;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB";

    #[test]
    fn an_identifier_survives_the_round_trip_over_the_wire() {
        let k: DocumentIdentifier = EXAMPLE.parse().unwrap();
        assert_eq!(k.to_string(), EXAMPLE);
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, format!("\"{EXAMPLE}\""));
        let back: DocumentIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn uuid_text_and_crockford_are_the_same_value() {
        let k = DocumentIdentifier::from_uuid_text("0190f1c2-3a4b-7c5d-8e6f-0123456789ab").unwrap();
        assert_eq!(k.as_uuid_text(), "0190f1c2-3a4b-7c5d-8e6f-0123456789ab");
        let again: DocumentIdentifier = k.to_string().parse().unwrap();
        assert_eq!(again.as_uuid_text(), k.as_uuid_text());
        // RFC 9562: upper case is the same value.
        let upper =
            DocumentIdentifier::from_uuid_text("0190F1C2-3A4B-7C5D-8E6F-0123456789AB").unwrap();
        assert_eq!(upper, k);
    }

    #[test]
    fn the_boundary_values_fit_exactly_into_26_characters() {
        assert_eq!(DeviceIdentifier::from_value(0).to_string(), "dev_00000000000000000000000000");
        assert_eq!(
            DeviceIdentifier::from_value(u128::MAX).to_string(),
            "dev_7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
        let max: DeviceIdentifier = "dev_7ZZZZZZZZZZZZZZZZZZZZZZZZZ".parse().unwrap();
        assert_eq!(max.value(), u128::MAX);
    }

    // Contract test T17: the same forms the server rejects with 400 invalid-resource-id.
    #[test]
    fn lower_case_is_rejected_instead_of_silently_read() {
        let error = "doc_01jk4r7zq8m3n5p6t9v0wxyzab".parse::<DocumentIdentifier>().unwrap_err();
        assert!(matches!(error, IdentifierError::Character { place: 3, character: 'j', .. }));
    }

    #[test]
    fn i_l_o_u_are_rejected() {
        for wrong in ['I', 'L', 'O', 'U'] {
            let text = format!("doc_01JK4R7ZQ8M3N5P6T9V0WXYZA{wrong}");
            let error = text.parse::<DocumentIdentifier>().unwrap_err();
            assert!(
                matches!(error, IdentifierError::Character { character, place: 26, .. } if character == wrong),
                "{wrong} should have been rejected, was {error:?}"
            );
        }
    }

    #[test]
    fn uuid_text_in_a_path_is_not_an_identifier() {
        let error =
            "doc_0190f1c2-3a4b-7c5d-8e6f-0123456789ab".parse::<DocumentIdentifier>().unwrap_err();
        assert!(matches!(error, IdentifierError::Length { .. }));
    }

    #[test]
    fn a_first_character_above_seven_is_an_overflow() {
        let error = "doc_81JK4R7ZQ8M3N5P6T9V0WXYZAB".parse::<DocumentIdentifier>().unwrap_err();
        assert!(matches!(error, IdentifierError::Overflow { character: '8', .. }));
    }

    #[test]
    fn a_foreign_prefix_is_not_reinterpreted() {
        let error = "cas_01JK4R7ZQ8M3N5P6T9V0WXYZAB".parse::<DocumentIdentifier>().unwrap_err();
        assert!(matches!(error, IdentifierError::WrongPrefix { expected: "doc", .. }));
        // Not without the underscore either.
        assert!("doc01JK4R7ZQ8M3N5P6T9V0WXYZAB".parse::<DocumentIdentifier>().is_err());
    }

    #[test]
    fn the_two_new_kinds_carry_their_own_prefix_and_nothing_else() {
        let archive: ArchiveIdentifier = "arc_01JK4R7ZQ8M3N5P6T9V0WXYZAB".parse().unwrap();
        let basket: BasketIdentifier = "bsk_01JK4R7ZQ8M3N5P6T9V0WXYZAB".parse().unwrap();
        assert_eq!(archive.to_string(), "arc_01JK4R7ZQ8M3N5P6T9V0WXYZAB");
        assert_eq!(basket.to_string(), "bsk_01JK4R7ZQ8M3N5P6T9V0WXYZAB");
        // `arc` begins the container's text form `archives`; a prefix is not a word, and the
        // underscore is what tells the two apart.
        assert!("archives".parse::<ArchiveIdentifier>().is_err());
        // Both are this repository's own design, like `doc_`, `cas_` and `srch_`: the
        // counterpart's contract knows neither an archive nor a basket as a resource.
        assert_eq!(
            [ArchiveIdKind::PROPOSED, BasketIdKind::PROPOSED],
            [CaseIdKind::PROPOSED, SearchIdKind::PROPOSED]
        );
    }

    #[test]
    fn the_short_form_takes_the_end_not_the_timestamp() {
        let k: DocumentIdentifier = EXAMPLE.parse().unwrap();
        assert_eq!(k.short_form(), "V0WXYZAB");
    }

    #[test]
    fn bytes_are_encoded_without_padding() {
        // 10 bytes = 80 bits = exactly 16 characters (geraete-auth §5.3).
        assert_eq!(encode_bytes(&[0u8; 10]), "0000000000000000");
        assert_eq!(encode_bytes(&[0xffu8; 10]), "ZZZZZZZZZZZZZZZZ");
        // One byte: 8 bits, two characters, the second left-aligned.
        assert_eq!(encode_bytes(&[0b1000_0100]), "GG");
    }
}
