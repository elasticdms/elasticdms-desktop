//! The content: the fetch that is an access (proposal §7.2).
//!
//! `GET /v1/documents/{documentId}/content` delivers the rendition the server chooses — redacted
//! before viewing, **never the original record** (finding Q-13) — and writes the audit event
//! `document.read` while doing so (gap G-18). This is exactly where the requirement „Jede
//! Hydrierung ist ein Zugriff und gehoert ins Protokoll" — every hydration is an access and
//! belongs in the log — is fulfilled; the client only has to make sure that every hydration runs
//! through this endpoint and none through a source the server does not see.
//!
//! The client loads **whole files**: the checksum can only be computed over the whole body, and
//! the server notices a hash error only at the last `Read`, after `200` has already been sent
//! (`edms_core::checksum`). Before a single byte is loaded, [`ContentHeader`] checks the headers
//! against the listing — a new version or a missing checksum is then an error, not a mutilated
//! file.

use edms_core::checksum::Sha256Value;
use edms_core::identifier::DocumentIdentifier;

use crate::basics::{DigestError, EtagError, read_digest_header, version_from_etag};
use crate::namespace::DocumentRow;

/// Maximum length of the program name in bytes of UTF-8, before the encoding.
pub const MAX_APPLICATION_BYTES: usize = 255;

/// `GET /v1/documents/{documentId}/content`.
pub fn path_content(document: DocumentIdentifier) -> String {
    format!("/v1/documents/{document}/content")
}

/// Why a program name does not go into the header.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationError {
    /// Empty.
    #[error("an empty program name is not sent; the header then falls away")]
    Empty,
    /// A path instead of a file name — it would give away the user name (`edms_core::port`).
    #[error(
        "`{0}` is a path; only the program's file name is sent, because a path would give away \
         the user name"
    )]
    Path(String),
    /// A control character.
    #[error("the program name carries a control character")]
    ControlCharacter,
    /// Too long.
    #[error("the program name has {0} bytes; at most {MAX_APPLICATION_BYTES} are allowed")]
    Length(usize),
    /// A percent encoding that is none.
    #[error("the header `{0}` is not a valid percent encoding of UTF-8")]
    Encoding(String),
}

fn check_application(name: &str) -> Result<(), ApplicationError> {
    if name.is_empty() {
        return Err(ApplicationError::Empty);
    }
    if name.contains(['/', '\\']) {
        return Err(ApplicationError::Path(name.to_owned()));
    }
    if name.chars().any(char::is_control) {
        return Err(ApplicationError::ControlCharacter);
    }
    if name.len() > MAX_APPLICATION_BYTES {
        return Err(ApplicationError::Length(name.len()));
    }
    Ok(())
}

/// The value for `Elasticdms-Accessing-Application`: the file name of the program,
/// percent-encoded outside the visible ASCII characters (`Übersicht` → `%C3%9Cbersicht`).
///
/// Header values are ASCII; a localized program name is not. The encoding keeps the name without
/// loss instead of silently mutilating it.
pub fn encode_application(name: &str) -> Result<String, ApplicationError> {
    check_application(name)?;
    let mut from = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_graphic() && b != b'%' {
            from.push(char::from(b));
        } else {
            from.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(from)
}

/// The inverse (mock and server).
pub fn decode_application(header: &str) -> Result<String, ApplicationError> {
    let error = || ApplicationError::Encoding(header.to_owned());
    let mut bytes = Vec::with_capacity(header.len());
    let mut rest = header.as_bytes();
    while let Some((&b, further)) = rest.split_first() {
        if b == b'%' {
            let hex = further.get(..2).ok_or_else(error)?;
            let text = std::str::from_utf8(hex).map_err(|_| error())?;
            bytes.push(u8::from_str_radix(text, 16).map_err(|_| error())?);
            rest = &further[2..];
        } else if b.is_ascii_graphic() {
            bytes.push(b);
            rest = further;
        } else {
            return Err(error());
        }
    }
    let name = String::from_utf8(bytes).map_err(|_| error())?;
    check_application(&name)?;
    Ok(name)
}

/// Why the headers of a content answer do not carry a fetch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentHeaderError {
    /// A mandatory header is missing.
    #[error(
        "the content fetch answers without `{0}`; without it nothing is adopted (proposal §7.2)"
    )]
    Missing(&'static str),
    /// `Content-Length` is not a number.
    #[error("Content-Length `{0}` is not a number")]
    Length(String),
    /// The ETag is no good.
    #[error(transparent)]
    Etag(#[from] EtagError),
    /// `Repr-Digest` is no good.
    #[error(transparent)]
    Digest(#[from] DigestError),
    /// The answer does not describe what the listing announced.
    #[error(
        "the content answer names {field} `{actual}`, the listing `{expected}`; the folder is \
         reconciled afresh first"
    )]
    Deviation {
        /// Which detail.
        field: &'static str,
        /// According to the listing.
        expected: String,
        /// According to the answer.
        actual: String,
    },
}

/// The headers of a `200` on `GET …/content`, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHeader {
    /// `Content-Type`.
    pub media_type: String,
    /// `Content-Length`.
    pub length: u64,
    /// From the strong `ETag`.
    pub version: String,
    /// From `Repr-Digest: sha-256=:…:`.
    pub sha256: Sha256Value,
}

impl ContentHeader {
    /// Reads the four mandatory headers. If one is missing, that is an error — a missing
    /// checksum is not a skipped check.
    pub fn from_header(
        content_type: Option<&str>,
        content_length: Option<&str>,
        etag: Option<&str>,
        repr_digest: Option<&str>,
    ) -> Result<Self, ContentHeaderError> {
        let media_type = content_type.ok_or(ContentHeaderError::Missing("Content-Type"))?;
        let length = content_length.ok_or(ContentHeaderError::Missing("Content-Length"))?;
        let etag = etag.ok_or(ContentHeaderError::Missing("ETag"))?;
        let digest = repr_digest.ok_or(ContentHeaderError::Missing("Repr-Digest"))?;
        Ok(Self {
            media_type: media_type.to_owned(),
            length: length
                .trim()
                .parse()
                .map_err(|_| ContentHeaderError::Length(length.to_owned()))?,
            version: version_from_etag(etag)?.to_owned(),
            sha256: read_digest_header(digest)?,
        })
    }

    /// Checks against the listing's row, **before** the body is read. If something differs, the
    /// document has changed since the listing; the placeholder then carries the size and checksum
    /// of another version.
    pub fn check_against(&self, row: &DocumentRow) -> Result<(), ContentHeaderError> {
        let deviation = |field, expected: String, actual: String| {
            Err(ContentHeaderError::Deviation { field, expected, actual })
        };
        if self.version != row.version {
            return deviation("the version", row.version.clone(), self.version.clone());
        }
        if self.sha256 != row.sha256 {
            return deviation("the checksum", row.sha256.to_string(), self.sha256.to_string());
        }
        if self.length != row.size {
            return deviation("the size", row.size.to_string(), self.length.to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basics::{WireTimestamp, digest_header_value};
    use edms_core::identifier::Identifier;

    fn row() -> DocumentRow {
        DocumentRow {
            document_id: Identifier::from_value(7),
            title: "Prüfbericht".into(),
            media_type: "application/pdf".into(),
            size: 4,
            sha256: Sha256Value::from_bytes([9; 32]),
            version: "3.2".into(),
            created_at: WireTimestamp::read("2026-09-01T08:00:00Z").unwrap(),
            updated_at: WireTimestamp::read("2026-09-01T08:00:00Z").unwrap(),
        }
    }

    #[test]
    fn only_the_file_name_goes_out_and_umlauts_stay_lossless() {
        assert_eq!(encode_application("WINWORD.EXE").unwrap(), "WINWORD.EXE");
        assert_eq!(encode_application("Übersicht").unwrap(), "%C3%9Cbersicht");
        assert_eq!(encode_application("Acrobat Reader").unwrap(), "Acrobat%20Reader");
        assert_eq!(decode_application("%C3%9Cbersicht").unwrap(), "Übersicht");
        assert!(matches!(
            encode_application("C:\\Users\\nolotz\\WINWORD.EXE"),
            Err(ApplicationError::Path(_))
        ));
        assert!(matches!(
            encode_application("/Applications/Preview.app"),
            Err(ApplicationError::Path(_))
        ));
        assert_eq!(encode_application(""), Err(ApplicationError::Empty));
        assert_eq!(encode_application(&"a".repeat(256)), Err(ApplicationError::Length(256)));
    }

    #[test]
    fn a_broken_percent_encoding_is_not_guessed() {
        assert!(decode_application("%C3").is_err());
        assert!(decode_application("%ZZ").is_err());
        assert!(decode_application("a b").is_err());
        assert!(decode_application("%2Fetc%2Fpasswd").is_err());
    }

    #[test]
    fn without_repr_digest_nothing_is_loaded() {
        let f =
            ContentHeader::from_header(Some("application/pdf"), Some("4"), Some("\"3.2\""), None);
        assert_eq!(f, Err(ContentHeaderError::Missing("Repr-Digest")));
    }

    #[test]
    fn a_new_version_is_noticed_before_the_loading() {
        let r = row();
        let digest = digest_header_value(&r.sha256);
        let matches = ContentHeader::from_header(
            Some("application/pdf"),
            Some("4"),
            Some("\"3.2\""),
            Some(&digest),
        )
        .unwrap();
        assert_eq!(matches.check_against(&r), Ok(()));
        let new = ContentHeader::from_header(
            Some("application/pdf"),
            Some("4"),
            Some("\"3.3\""),
            Some(&digest),
        )
        .unwrap();
        assert!(matches!(
            new.check_against(&r),
            Err(ContentHeaderError::Deviation { field: "the version", .. })
        ));
        let foreign = digest_header_value(&Sha256Value::from_bytes([1; 32]));
        let other = ContentHeader::from_header(
            Some("application/pdf"),
            Some("4"),
            Some("\"3.2\""),
            Some(&foreign),
        )
        .unwrap();
        assert!(matches!(
            other.check_against(&r),
            Err(ContentHeaderError::Deviation { field: "the checksum", .. })
        ));
    }

    #[test]
    fn a_weak_etag_carries_no_fetch() {
        let digest = digest_header_value(&row().sha256);
        let f = ContentHeader::from_header(
            Some("application/pdf"),
            Some("4"),
            Some("W/\"3.2\""),
            Some(&digest),
        );
        assert!(matches!(f, Err(ContentHeaderError::Etag(EtagError::Weak(_)))));
        let f = ContentHeader::from_header(
            Some("application/pdf"),
            Some("four"),
            Some("\"3.2\""),
            Some(&digest),
        );
        assert!(matches!(f, Err(ContentHeaderError::Length(_))));
    }
}
