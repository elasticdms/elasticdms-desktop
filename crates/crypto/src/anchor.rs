//! The anchor fingerprint — bit-exact per geraete-auth §5.3.
//!
//! ```text
//! thumbprints  = RFC 7638 thumbprints of ALL delivered anchors
//! sorted       = ascending, byte-wise over the base64url strings
//! joined       = sorted.join("\n")              -- no separator at the end
//! digest       = SHA-256( UTF-8( joined ) )
//! text         = Crockford base32( the first 10 bytes ), 16 characters
//! display      = "XXXX-XXXX-XXXX-XXXX"
//! ```
//!
//! **The client computes it itself** and never takes it from the answer's field of the same
//! name — whoever did that would let the sender decide its own checksum. The server has to
//! produce the same value, otherwise the device shows "The fingerprint of the server keys has
//! changed" in red for a perfectly correct set. That is why contract test T6 runs for one, two
//! and three anchors and under reordering, against values produced by an independent
//! computation.
//!
//! **Zero anchors yield the empty string**, not a fixed value — otherwise two devices without an
//! anchor would take their fingerprints for a match. [`AnchorFingerprint::agrees_agree`]
//! therefore never says yes for an empty fingerprint.

use std::fmt;

use edms_core::identifier;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::CryptoError;
use crate::encoding::sha256;
use crate::key::Jwk;

/// Characters of the fingerprint, without hyphens.
pub const CHARACTER: usize = 16;

/// The first 80 bits of the digest.
const BYTES: usize = 10;

/// Characters per group in the display form.
const GROUP: usize = 4;

/// The `anchorSetFingerprint`: 16 characters of Crockford base32, or empty without anchors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AnchorFingerprint {
    text: String,
}

impl AnchorFingerprint {
    /// From the thumbprints of all anchors, in any order.
    pub fn from_thumbprint<S: AsRef<str>>(thumbprints: &[S]) -> Self {
        if thumbprints.is_empty() {
            return Self::default();
        }
        let mut sorted: Vec<&str> = thumbprints.iter().map(AsRef::as_ref).collect();
        // Byte-wise: str::cmp compares the UTF-8 bytes, and base64url is ASCII.
        sorted.sort_unstable();
        let digest = sha256(sorted.join("\n").as_bytes());
        Self { text: identifier::encode_bytes(&digest[..BYTES]) }
    }

    /// From the JWKs of all anchors.
    pub fn from_jwks<'a>(anchor: impl IntoIterator<Item = &'a Jwk>) -> Self {
        let thumbprints: Vec<String> = anchor.into_iter().map(Jwk::thumbprint).collect();
        Self::from_thumbprint(&thumbprints)
    }

    /// Reads the display form `XXXX-XXXX-XXXX-XXXX` or the empty string — for instance the
    /// `anchorSetFingerprint` field of an answer, for comparison.
    pub fn from_display(display: &str) -> Result<Self, CryptoError> {
        if display.is_empty() {
            return Ok(Self::default());
        }
        let groups: Vec<&str> = display.split('-').collect();
        let valid = groups.len() == CHARACTER / GROUP
            && groups
                .iter()
                .all(|g| g.len() == GROUP && g.bytes().all(|b| identifier::ALPHABET.contains(&b)));
        if !valid {
            return Err(CryptoError::Unreadable {
                what: "The anchor fingerprint",
                reason: format!(
                    "\"{display}\" does not have the form XXXX-XXXX-XXXX-XXXX in the strict Crockford alphabet"
                ),
            });
        }
        Ok(Self { text: groups.concat() })
    }

    /// The 16 characters without hyphens, or empty.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Four groups of four with hyphens — the form a human reads back without mistakes.
    pub fn display(&self) -> String {
        let groups: Vec<&str> = self
            .text
            .as_bytes()
            .chunks(GROUP)
            .filter_map(|g| std::str::from_utf8(g).ok())
            .collect();
        groups.join("-")
    }

    /// Whether there was no anchor.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Whether two fingerprints attest the same anchor set. Two empty ones attest nothing.
    pub fn agrees_agree(&self, other: &Self) -> bool {
        !self.is_empty() && self == other
    }
}

impl fmt::Display for AnchorFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

impl Serialize for AnchorFingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.display())
    }
}

impl<'de> Deserialize<'de> for AnchorFingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_display(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64u;

    // The thumbprints of the anchors from 03 §6.2.4 and of the signing key next to them.
    const ANCHOR_A: &str = "LAsBA719DG2FA0dsYL6V-xZPqUvH2HX8f1Zu55HYrYc";
    const ANCHOR_B: &str = "zOY49754F5BPDBEnGA6qlv1SSbW_EvyagTv_Ik_2XBc";
    const THIRD: &str = "8ji41YR5dcmyQ9yXVvI2DegpkzJlf8EK1EnNjMlv-eA";
    /// RFC 7638 thumbprint of the key from RFC 7515 appendix A.3.
    const A3: &str = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";

    /// The golden values. Source: an independent computation (Python, hashlib), and for two
    /// anchors the value printed in 03 §6.2.4.
    const GOLDEN: &[(&[&str], &str)] = &[
        (&[ANCHOR_A], "NH37-B4E6-D3DT-XNJQ"),
        (&[ANCHOR_B], "9WR1-ETJW-TZX1-Y084"),
        (&[ANCHOR_A, ANCHOR_B], "NGJQ-CWV1-AHAR-Z4FJ"),
        (&[ANCHOR_A, ANCHOR_B, THIRD], "GSAV-G6HX-P6XZ-R58J"),
        (&[ANCHOR_A, ANCHOR_B, A3], "V8YY-TA85-PQQ0-4P7F"),
    ];

    fn all_orderings(list: &[&str]) -> Vec<Vec<String>> {
        if list.len() <= 1 {
            return vec![list.iter().map(|s| (*s).to_owned()).collect()];
        }
        let mut from = Vec::new();
        for i in 0..list.len() {
            let mut rest = list.to_vec();
            let first = rest.remove(i);
            for mut sequence in all_orderings(&rest) {
                sequence.insert(0, first.to_owned());
                from.push(sequence);
            }
        }
        from
    }

    // Contract test T6 — the test one must not leave out.
    #[test]
    fn t6_the_fingerprint_holds_for_one_two_and_three_anchors_and_under_reordering() {
        for (anchor, expected) in GOLDEN {
            for sequence in all_orderings(anchor) {
                let fingerprint = AnchorFingerprint::from_thumbprint(&sequence);
                assert_eq!(fingerprint.display(), *expected, "{sequence:?}");
                assert_eq!(fingerprint.text().len(), CHARACTER);
            }
        }
    }

    #[test]
    fn the_contract_anchors_yield_the_printed_fingerprint_through_the_jwks_too() {
        let a = Jwk::new(
            "KR8R1P0MYXQSkmTLEUy76S4-mcDVbNBGSblM0nVghbQ",
            "bWqbl_fHbboDqf1kHx1VLMi9lXR5Iqu-nWefmpONuTY",
        )
        .unwrap();
        let b = Jwk::new(
            "wr6dslMI-t-ZLz27kBKpD2vRymV7IiJbrxoya1NdsfU",
            "7uOZTl1LDSvO0pVlXAu318k809hLYh_XLpVilV2BHGo",
        )
        .unwrap();
        assert_eq!(AnchorFingerprint::from_jwks([&b, &a]).display(), "NGJQ-CWV1-AHAR-Z4FJ");
    }

    #[test]
    fn sorting_is_byte_wise_not_by_upper_and_lower_case() {
        // Byte-wise: '-' (0x2D) < 'A' (0x41) < '_' (0x5F) < 'b' (0x62).
        let fingerprint = AnchorFingerprint::from_thumbprint(&["b", "_a", "A", "-z"]);
        let expected = identifier::encode_bytes(&sha256(b"-z\nA\n_a\nb")[..BYTES]);
        assert_eq!(fingerprint.text(), expected);
        // Counter-check: no separator at the end, and with LF as the separator.
        let with_end = identifier::encode_bytes(&sha256(b"-z\nA\n_a\nb\n")[..BYTES]);
        assert_ne!(fingerprint.text(), with_end);
        assert_ne!(fingerprint.text(), identifier::encode_bytes(&sha256(b"-zA_ab")[..BYTES]));
    }

    #[test]
    fn without_anchors_the_fingerprint_is_empty_and_matches_nothing() {
        let empty = AnchorFingerprint::from_thumbprint::<&str>(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.display(), "");
        assert!(!empty.agrees_agree(&AnchorFingerprint::from_thumbprint::<&str>(&[])));
        let full = AnchorFingerprint::from_thumbprint(&[ANCHOR_A]);
        assert!(full.agrees_agree(&AnchorFingerprint::from_thumbprint(&[ANCHOR_A])));
        assert!(!full.agrees_agree(&empty));
    }

    #[test]
    fn a_different_anchor_changes_the_fingerprint() {
        let two = AnchorFingerprint::from_thumbprint(&[ANCHOR_A, ANCHOR_B]);
        let swapped = AnchorFingerprint::from_thumbprint(&[ANCHOR_A, b64u(&[7u8; 32]).as_str()]);
        assert_ne!(two, swapped);
    }

    #[test]
    fn the_display_form_survives_the_round_trip_and_wrong_forms_do_not() {
        let fingerprint = AnchorFingerprint::from_display("NGJQ-CWV1-AHAR-Z4FJ").unwrap();
        assert_eq!(fingerprint.text(), "NGJQCWV1AHARZ4FJ");
        assert_eq!(fingerprint.to_string(), "NGJQ-CWV1-AHAR-Z4FJ");
        assert!(AnchorFingerprint::from_display("").unwrap().is_empty());
        for wrong in [
            "ngjq-cwv1-ahar-z4fj",
            "NGJQCWV1AHARZ4FJ",
            "NGJQ-CWV1-AHAR-Z4FI",
            "NGJQ-CWV1-AHAR",
            "NGJQ-CWV1-AHAR-Z4FJ-",
        ] {
            assert!(AnchorFingerprint::from_display(wrong).is_err(), "{wrong}");
        }
        let json = serde_json::to_string(&fingerprint).unwrap();
        assert_eq!(json, "\"NGJQ-CWV1-AHAR-Z4FJ\"");
        assert_eq!(serde_json::from_str::<AnchorFingerprint>(&json).unwrap(), fingerprint);
    }
}
