//! The ingest from a mail basket (proposal §7.4, ADR-D08 §1 amended by namespace v2).
//!
//! **Upload first, then open the browser.** The clarification-case invariant demands: „Ein
//! Ereignis endet nie ohne persistiertes Ergebnis" — an event never ends without a persisted
//! result (`scope-cut` A6). After `:complete` the document lies in the inbox; if the user closes
//! the browser before tagging it, nothing is lost.
//!
//! **The basket is a trigger, not a filing target** (requirement 2). Since namespace v2 the drop
//! target is a mail basket inside the mirror and no longer a folder next to it, so the submission
//! has to say **which** basket it came from: [`UploadRequest::basket_id`]. Without it the server
//! could not apply the basket's ingest rule, and the client would be filing — which is exactly
//! what it must not do. A basket that no longer exists is answered `404`; nothing is filed
//! somewhere else instead.
//!
//! Three steps: `POST /v1/ingest-uploads` (grant with `uploadUrl`), `PUT <uploadUrl>` with the
//! bytes and `Content-Digest`, `POST …:complete` (with `captureUrl`). Both addresses from answers
//! are used only when they lie below the configured base — an `uploadUrl` on a foreign host would
//! send a document's bytes there, a foreign `captureUrl` would open a foreign page in the user's
//! browser.

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{BasketIdentifier, DocumentIdentifier, UploadIdentifier};
use serde::{Deserialize, Serialize};

use crate::basics::{WireTimestamp, is_below, open_catalogue};

/// Creating an ingest.
pub const PATH_UPLOAD: &str = "/v1/ingest-uploads";

/// Maximum length of a file name in bytes of UTF-8 (APFS and NTFS take 255).
pub const MAX_FILE_NAME_BYTES: usize = 255;

/// `POST /v1/ingest-uploads/{uploadId}:complete`.
pub fn path_completion(upload: UploadIdentifier) -> String {
    format!("{PATH_UPLOAD}/{upload}:complete")
}

/// Why an ingest does not begin, or an answer is not used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InboxError {
    /// The file name is not a bare name.
    #[error("the file name `{name}` is not sent: {reason}")]
    FileName {
        /// The name.
        name: String,
        /// Why.
        reason: &'static str,
    },
    /// Not a media type of the form `type/subtype`.
    #[error("`{0}` is not a media type of the form `type/subtype`")]
    MediaType(String),
    /// An address from the answer does not lie below the configured base.
    #[error("`{field}` points at `{address}`, outside `{base}`; the client does not use it")]
    ForeignOrigin {
        /// The field.
        field: &'static str,
        /// The address.
        address: String,
        /// The base.
        base: String,
    },
}

/// `POST /v1/ingest-uploads` — the body, with `Idempotency-Key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadRequest {
    /// The mail basket the file was dropped into; its rule decides where the document lands.
    pub basket_id: BasketIdentifier,
    /// The file name without a path.
    pub file_name: String,
    /// The media type as the operating system reports it; the server detects it anew itself.
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
    /// `sha256:…` over the bytes that follow next.
    pub sha256: Sha256Value,
}

impl UploadRequest {
    /// A request; the name is a bare file name, the media type has the form `a/b`.
    pub fn new(
        basket_id: BasketIdentifier,
        file_name: &str,
        media_type: &str,
        size: u64,
        sha256: Sha256Value,
    ) -> Result<Self, InboxError> {
        let reason = if file_name.is_empty() {
            Some("it is empty")
        } else if file_name.contains(['/', '\\']) {
            Some("it carries a path, and a path would give away the user name")
        } else if file_name.chars().any(char::is_control) {
            Some("it carries a control character")
        } else if file_name.len() > MAX_FILE_NAME_BYTES {
            Some("it is longer than 255 bytes")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(InboxError::FileName { name: file_name.to_owned(), reason });
        }
        let form = media_type.split_once('/').is_some_and(|(a, b)| !a.is_empty() && !b.is_empty());
        if !form {
            return Err(InboxError::MediaType(media_type.to_owned()));
        }
        Ok(Self {
            basket_id,
            file_name: file_name.to_owned(),
            media_type: media_type.to_owned(),
            size,
            sha256,
        })
    }
}

/// A hint at an identical document — only when the user is allowed to read it. Otherwise `null`:
/// a hint at an invisible document would be an oracle for its existence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateHint {
    /// The document that already exists.
    pub document_id: DocumentIdentifier,
    /// Its title.
    pub title: String,
    /// When it was filed.
    pub created_at: WireTimestamp,
}

/// The `201` answer to `POST /v1/ingest-uploads`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadGrant {
    /// `upl_…`.
    pub upload_id: UploadIdentifier,
    /// Where the bytes go — below the API, with DPoP like every call.
    pub upload_url: String,
    /// Marks, does not suppress: the human in the browser makes the decision.
    pub duplicate_of: Option<DuplicateHint>,
    /// By when the upload has to be finished.
    pub expires_at: WireTimestamp,
}

impl UploadGrant {
    /// The address for the `PUT`, only below the API.
    pub fn target(&self, api_base: &str) -> Result<&str, InboxError> {
        if is_below(&self.upload_url, api_base) {
            Ok(&self.upload_url)
        } else {
            Err(InboxError::ForeignOrigin {
                field: "uploadUrl",
                address: self.upload_url.clone(),
                base: api_base.to_owned(),
            })
        }
    }
}

open_catalogue!(
    /// `state` after `:complete`. Every value means: the event is persisted.
    InboxState {
        /// Accepted, the processing is running.
        Accepted => "ACCEPTED",
        /// In the inbox, waiting for classification.
        InInbox => "IN_INBOX",
        /// A clarification case has been opened.
        InReview => "IN_REVIEW",
    }
);

/// The `200` answer to `POST …:complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadCompletion {
    /// `upl_…`.
    pub upload_id: UploadIdentifier,
    /// State.
    pub state: InboxState,
    /// The capture page in the browser.
    pub capture_url: String,
}

impl UploadCompletion {
    /// The page the client opens — only below the web interface.
    pub fn browser_target(&self, app_base: &str) -> Result<&str, InboxError> {
        if is_below(&self.capture_url, app_base) {
            Ok(&self.capture_url)
        } else {
            Err(InboxError::ForeignOrigin {
                field: "captureUrl",
                address: self.capture_url.clone(),
                base: app_base.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value() -> Sha256Value {
        Sha256Value::from_bytes([3; 32])
    }

    fn basket() -> BasketIdentifier {
        "bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5".parse().unwrap()
    }

    #[test]
    fn only_a_bare_file_name_goes_out() {
        assert!(
            UploadRequest::new(basket(), "Rechnung 2026-0412.pdf", "application/pdf", 1, value())
                .is_ok()
        );
        for wrong in ["", "C:\\Users\\x\\a.pdf", "~/a.pdf", "a\u{7}.pdf"] {
            assert!(
                matches!(
                    UploadRequest::new(basket(), wrong, "application/pdf", 1, value()),
                    Err(InboxError::FileName { .. })
                ),
                "{wrong:?}"
            );
        }
        let long = format!("{}.pdf", "ä".repeat(126));
        assert!(UploadRequest::new(basket(), &long, "application/pdf", 1, value()).is_err());
        assert!(matches!(
            UploadRequest::new(basket(), "a.pdf", "pdf", 1, value()),
            Err(InboxError::MediaType(_))
        ));
    }

    #[test]
    fn the_submission_names_the_basket_it_came_from() {
        // Without it the server cannot apply the basket's ingest rule — and a client that leaves
        // the field out would be deciding where the document lands, which is exactly the filing
        // it must not do (requirement 2).
        let request = UploadRequest::new(basket(), "a.pdf", "application/pdf", 1, value()).unwrap();
        let raw = serde_json::to_value(&request).unwrap();
        assert_eq!(raw["basketId"], serde_json::json!("bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5"));
        // A body without the field is not a submission; nothing is guessed for it.
        let without = serde_json::json!({
            "fileName": "a.pdf", "mediaType": "application/pdf", "size": 1,
            "sha256": raw["sha256"],
        });
        assert!(serde_json::from_value::<UploadRequest>(without).is_err());
    }

    #[test]
    fn an_upload_url_on_a_foreign_host_is_not_used() {
        let grant: UploadGrant = serde_json::from_str(
            r#"{"uploadId":"upl_01JKD8H0J2K4M6N8P0Q2R4S6T8",
                "uploadUrl":"https://api.elasticdms.io/v1/ingest-uploads/upl_01JKD8H0J2K4M6N8P0Q2R4S6T8/content",
                "duplicateOf":null,"expiresAt":"2026-09-11T08:00:00Z"}"#,
        )
        .unwrap();
        assert!(grant.target("https://api.elasticdms.io").is_ok());
        assert!(matches!(
            grant.target("https://api.elasticdms.io.example.org"),
            Err(InboxError::ForeignOrigin { .. })
        ));
        let mut foreign = grant.clone();
        foreign.upload_url = "https://bucket.s3.amazonaws.com/x".into();
        assert!(foreign.target("https://api.elasticdms.io").is_err());
    }

    #[test]
    fn a_foreign_capture_page_is_not_opened_and_a_new_state_is_adopted_all_the_same() {
        let a: UploadCompletion = serde_json::from_str(
            r#"{"uploadId":"upl_01JKD8H0J2K4M6N8P0Q2R4S6T8","state":"IN_TRIAGE",
                "captureUrl":"https://phish.example.org/capture"}"#,
        )
        .unwrap();
        assert_eq!(a.state, InboxState::Unknown("IN_TRIAGE".into()));
        assert!(a.browser_target("https://app.elasticdms.io").is_err());
    }
}
