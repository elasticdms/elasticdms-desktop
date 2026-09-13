//! The namespace on the wire: mail baskets, archives with their case files (Akten), saved
//! searches, their documents (proposal §7.1).
//!
//! **A case file is listed under its archive** (namespace v2, owner's decision of 2026-09-12).
//! There is no listing across archives, because there is no entry without one:
//! [`edms_core::namespace::Container::Case`] holds archive and case together, and a flat
//! `/v1/cases` would hand the client a case file whose parent it would then have to look up
//! somewhere else.
//!
//! **A basket is a trigger, not a heap** (§7.4): it is listed so that the folder exists to drop a
//! file into, and it lists nothing itself — the ingest rule files the document into an archive.
//!
//! **A listing IS a search** (`ordnerclient-vorgaben.md`, „Ein Berechtigungspfad, nicht zwei" —
//! one permission path, not two): the server computes every listing over the same ADR-008 path as
//! the search in the web client (`acl_read`, `$visible_paths`, at most 50 ltree paths). The
//! client **never filters** — there is no function in this module that leaves entries out. What
//! arrives stands in the folder; what does not arrive does not exist for this user.
//!
//! **Truncation is visible, never silent** (finding Q-12): a result list above
//! [`DocumentPage::display_limit`] is delivered by the server only up to the limit, and it sets
//! `totalCapped`; the core then puts the hint file into the folder
//! ([`edms_core::namespace::Truncation`]).

use edms_core::checksum::Sha256Value;
use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, DocumentIdentifier, SearchIdentifier,
};
use edms_core::namespace::{ContainerItem, DocumentItem, Location, Truncation};
use serde::{Deserialize, Serialize};

use crate::basics::{EtagError, PageError, WireTimestamp, check_continuation, strong_etag};

/// The mail baskets a file may be dropped into.
pub const PATH_BASKETS: &str = "/v1/mirror/baskets";

/// The archives; every case file the user is allowed to see stands below one of them.
pub const PATH_ARCHIVES: &str = "/v1/mirror/archives";

/// The user's saved searches.
pub const PATH_SEARCHES: &str = "/v1/mirror/searches";

/// `limit` when the client names none (proposal §7.1).
pub const LIMIT_DEFAULT: u32 = 200;

/// Highest `limit` (03 §6.0.8).
pub const LIMIT_MAX: u32 = 1_000;

/// The proposed display limit of a result list: `domain.FacetThreshold`. Above it a listing can
/// no longer be shown honestly as a flat folder (finding Q-12).
pub const DISPLAY_LIMIT_PROPOSAL: u64 = 5_000;

/// `GET /v1/mirror/archives/{archiveId}/cases` — the case files of **one** archive.
pub fn path_cases(archive: ArchiveIdentifier) -> String {
    format!("{PATH_ARCHIVES}/{archive}/cases")
}

/// `GET …/cases/{caseId}/documents` or `GET …/searches/{savedSearchId}/documents`.
pub fn path_document(location: Location) -> String {
    match location {
        Location::Case { archive, case } => format!("{}/{case}/documents", path_cases(archive)),
        Location::Search(search) => format!("{PATH_SEARCHES}/{search}/documents"),
    }
}

/// Why a listing is not adopted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    /// The page envelope contradicts itself.
    #[error(transparent)]
    Page(#[from] PageError),
    /// `limit` outside 1 to 1000.
    #[error("limit {0} lies outside 1 to {LIMIT_MAX} (03 §6.0.8)")]
    Limit(u32),
    /// An empty cursor is no cursor.
    #[error("an empty cursor is no cursor; the first page is fetched without `cursor`")]
    EmptyCursor,
    /// A version marker that does not become a strong ETag — then no `If-Match` on the content.
    #[error("the document {document} carries an unusable version marker: {reason}")]
    Version {
        /// The document.
        document: DocumentIdentifier,
        /// Why.
        reason: EtagError,
    },
    /// More entries on a page than the display limit allows.
    #[error("the page delivers {delivered} documents at a display limit of {limit}")]
    OverLimit {
        /// Delivered.
        delivered: usize,
        /// `displayLimit`.
        limit: u64,
    },
}

/// The query parameters of every listing: `cursor` and `limit`, nothing else — above all no filter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

impl ListQuery {
    /// A query; `limit` has to lie between 1 and 1000, a cursor must not be empty.
    pub fn new(cursor: Option<String>, limit: Option<u32>) -> Result<Self, ListError> {
        if let Some(l) = limit
            && !(1..=LIMIT_MAX).contains(&l)
        {
            return Err(ListError::Limit(l));
        }
        if cursor.as_deref() == Some("") {
            return Err(ListError::EmptyCursor);
        }
        Ok(Self { cursor, limit })
    }

    /// The parameters for the query string.
    pub fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        if let Some(c) = &self.cursor {
            q.push(("cursor", c.clone()));
        }
        if let Some(l) = self.limit {
            q.push(("limit", l.to_string()));
        }
        q
    }

    /// The effective `limit`.
    pub fn limit(&self) -> u32 {
        self.limit.unwrap_or(LIMIT_DEFAULT)
    }

    /// The cursor, if this is not the first page.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

/// One entry in `GET /v1/mirror/baskets`.
///
/// Two fields, and no `updatedAt`: a basket holds nothing whose change could be dated. That a
/// title has been renamed the client notices by the `ETag` of the listing like every other
/// change (§7.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasketRow {
    /// `bsk_…`.
    pub basket_id: BasketIdentifier,
    /// Title, free text; the core turns it into a folder name.
    pub title: String,
}

impl BasketRow {
    /// The form the core names the folder with.
    pub fn in_core(&self) -> ContainerItem<BasketIdentifier> {
        ContainerItem { identifier: self.basket_id, title: self.title.clone() }
    }
}

/// One entry in `GET /v1/mirror/archives`. Like the basket it carries no `updatedAt`: what
/// changes inside an archive is the case file, and that has its own listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveRow {
    /// `arc_…`.
    pub archive_id: ArchiveIdentifier,
    /// Title, free text; the core turns it into a folder name.
    pub title: String,
}

impl ArchiveRow {
    /// The form the core names the folder with.
    pub fn in_core(&self) -> ContainerItem<ArchiveIdentifier> {
        ContainerItem { identifier: self.archive_id, title: self.title.clone() }
    }
}

/// One entry in `GET /v1/mirror/archives/{archiveId}/cases`.
///
/// The archive stands in the path and not in the row: it is the same for every entry of the
/// page, and the caller hands it to [`edms_core::namespace::cases_entries`] anyway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRow {
    /// `cas_…`.
    pub case_id: CaseIdentifier,
    /// Title, free text; the core turns it into a folder name.
    pub title: String,
    /// Last changed — title or content.
    pub updated_at: WireTimestamp,
}

impl CaseRow {
    /// The form the core names the folder with.
    pub fn in_core(&self) -> ContainerItem<CaseIdentifier> {
        ContainerItem { identifier: self.case_id, title: self.title.clone() }
    }
}

/// One entry in `GET /v1/mirror/searches`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRow {
    /// `srch_…`.
    pub saved_search_id: SearchIdentifier,
    /// Title.
    pub title: String,
    /// Last changed — title or search expression.
    pub updated_at: WireTimestamp,
}

impl SearchRow {
    /// The form the core names the folder with.
    pub fn in_core(&self) -> ContainerItem<SearchIdentifier> {
        ContainerItem { identifier: self.saved_search_id, title: self.title.clone() }
    }
}

/// A document in a listing. Size, checksum and media type describe the rendition that
/// `GET …/content` delivers — the redacted or the viewing version, **never the original record**
/// (finding Q-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentRow {
    /// `doc_…`.
    pub document_id: DocumentIdentifier,
    /// Title.
    pub title: String,
    /// Media type of the delivered rendition; it determines the file extension.
    pub media_type: String,
    /// Size in bytes; the placeholder carries it before a single byte is loaded.
    pub size: u64,
    /// `sha256:…` of the delivered bytes.
    pub sha256: Sha256Value,
    /// Version marker, opaque; it changes with every change of the delivered bytes and is the
    /// strong ETag of the content.
    pub version: String,
    /// Created.
    pub created_at: WireTimestamp,
    /// Last changed.
    pub updated_at: WireTimestamp,
}

impl DocumentRow {
    /// The form the core makes entry and file name from.
    pub fn in_core(&self) -> DocumentItem {
        DocumentItem {
            document: self.document_id,
            title: self.title.clone(),
            media_type: self.media_type.clone(),
            size: self.size,
            sha256: self.sha256,
            version: self.version.clone(),
            created: self.created_at.timestamp(),
            changed: self.updated_at.timestamp(),
        }
    }

    /// The strong ETag of the content, for `If-Match` on the fetch (proposal §7.2).
    pub fn etag(&self) -> Result<String, ListError> {
        strong_etag(&self.version)
            .map_err(|reason| ListError::Version { document: self.document_id, reason })
    }
}

/// One page of `GET …/documents` (proposal §7.1): the page envelope plus the truncation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentPage {
    /// The documents of this page, newest first.
    pub items: Vec<DocumentRow>,
    /// Cursor of the next page; `null` on the last one.
    pub next_cursor: Option<String>,
    /// Whether another page follows.
    pub has_more: bool,
    /// Whether the listing was cut off at [`DocumentPage::display_limit`].
    pub total_capped: bool,
    /// Maximum number of documents this listing delivers across all pages.
    pub display_limit: u64,
    /// Where the search can be refined in the browser; only on truncation.
    pub refine_url: Option<String>,
}

impl DocumentPage {
    /// The cursor to read on with — after the check that the page is consistent in itself.
    pub fn continuation(&self) -> Result<Option<&str>, ListError> {
        let limit = self.display_limit;
        if u64::try_from(self.items.len()).map_or(true, |n| n > limit) {
            return Err(ListError::OverLimit { delivered: self.items.len(), limit });
        }
        for row in &self.items {
            row.etag()?;
        }
        Ok(check_continuation(self.has_more, self.next_cursor.as_deref())?)
    }

    /// The truncation for the hint file, if the listing is cut off.
    pub fn truncation(&self) -> Option<Truncation<'_>> {
        self.total_capped.then_some(Truncation {
            displayed: self.display_limit,
            address: self.refine_url.as_deref(),
        })
    }

    /// The documents in the core's form, in server order.
    pub fn in_core(&self) -> Vec<DocumentItem> {
        self.items.iter().map(DocumentRow::in_core).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edms_core::identifier::Identifier;

    fn row(version: &str) -> DocumentRow {
        DocumentRow {
            document_id: Identifier::from_value(1),
            title: "Rechnung".into(),
            media_type: "application/pdf".into(),
            size: 10,
            sha256: Sha256Value::from_bytes([1; 32]),
            version: version.into(),
            created_at: WireTimestamp::read("2026-09-01T08:00:00Z").unwrap(),
            updated_at: WireTimestamp::read("2026-09-02T08:00:00+02:00").unwrap(),
        }
    }

    fn page(items: Vec<DocumentRow>, truncated: bool) -> DocumentPage {
        DocumentPage {
            items,
            next_cursor: None,
            has_more: false,
            total_capped: truncated,
            display_limit: 2,
            refine_url: truncated
                .then(|| "https://app.elasticdms.io/suche?gespeichert=x".to_owned()),
        }
    }

    #[test]
    fn a_case_file_is_addressed_below_its_archive_and_a_search_below_none() {
        let archive: ArchiveIdentifier = "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3".parse().unwrap();
        let case: CaseIdentifier = "cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7".parse().unwrap();
        assert_eq!(path_cases(archive), "/v1/mirror/archives/arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3/cases");
        assert_eq!(
            path_document(Location::Case { archive, case }),
            "/v1/mirror/archives/arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3/cases/\
             cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7/documents"
        );
        let search: SearchIdentifier = "srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2".parse().unwrap();
        assert_eq!(
            path_document(Location::Search(search)),
            "/v1/mirror/searches/srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2/documents"
        );
    }

    #[test]
    fn a_basket_row_and_an_archive_row_become_the_core_form_without_loss() {
        let basket = BasketRow {
            basket_id: "bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5".parse().unwrap(),
            title: "Briefkorb Buchhaltung".into(),
        };
        assert_eq!(basket.in_core().identifier, basket.basket_id);
        assert_eq!(basket.in_core().title, basket.title);

        let archive = ArchiveRow {
            archive_id: "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3".parse().unwrap(),
            title: "Rechnungseingang".into(),
        };
        assert_eq!(archive.in_core().identifier, archive.archive_id);
        assert_eq!(archive.in_core().title, archive.title);
    }

    #[test]
    fn a_truncated_listing_reports_its_truncation_and_a_complete_one_does_not() {
        let s = page(vec![row("1")], true);
        let k = s.truncation().unwrap();
        assert_eq!(k.displayed, 2);
        assert!(k.address.is_some());
        assert!(page(vec![row("1")], false).truncation().is_none());
    }

    #[test]
    fn a_page_above_the_display_limit_is_not_adopted() {
        let s = page(vec![row("1"), row("2"), row("3")], true);
        assert_eq!(s.continuation(), Err(ListError::OverLimit { delivered: 3, limit: 2 }));
    }

    #[test]
    fn a_version_without_the_etag_shape_is_not_adopted() {
        let s = page(vec![row("3\"2")], false);
        assert!(matches!(s.continuation(), Err(ListError::Version { .. })));
        let s = page(vec![row("")], false);
        assert!(matches!(
            s.continuation(),
            Err(ListError::Version { reason: EtagError::Empty, .. })
        ));
    }

    #[test]
    fn more_without_a_cursor_is_an_error_here_too() {
        let mut s = page(vec![row("1")], false);
        s.has_more = true;
        assert_eq!(s.continuation(), Err(ListError::Page(PageError::MoreWithoutCursor)));
    }

    #[test]
    fn a_limit_outside_the_contract_is_not_sent() {
        assert_eq!(ListQuery::new(None, Some(0)), Err(ListError::Limit(0)));
        assert_eq!(ListQuery::new(None, Some(1_001)), Err(ListError::Limit(1_001)));
        assert_eq!(ListQuery::new(Some(String::new()), None), Err(ListError::EmptyCursor));
        let a = ListQuery::new(Some("c1".into()), Some(500)).unwrap();
        assert_eq!(a.to_query(), vec![("cursor", "c1".to_owned()), ("limit", "500".to_owned())]);
        assert_eq!(ListQuery::default().limit(), LIMIT_DEFAULT);
    }

    #[test]
    fn the_row_becomes_the_core_form_without_loss() {
        let r = row("3.2");
        let item = r.in_core();
        assert_eq!(item.version, "3.2");
        assert_eq!(item.changed, r.updated_at.timestamp());
        assert_eq!(r.etag().unwrap(), "\"3.2\"");
    }
}
