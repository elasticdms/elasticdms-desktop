//! The sample tenant: a German archive, small enough to read, large enough to go wrong in.
//!
//! Two mail baskets, two archives with one case file (Akte) each, two saved searches, twenty-one
//! documents with **real** PDF bytes (`crate::pdf`), and therefore with a real size and a real
//! checksum. One of the searches returns more hits than its display limit allows — so that
//! `totalCapped`, `displayLimit` and `refineUrl` (§7.1.2) do not merely stand in the contract but
//! occur on the wire. A truncation nobody ever sees is never handled correctly in the client.
//!
//! **The two case files stand in two different archives.** One archive with both of them would
//! let a listing that ignores its archive pass unnoticed — and that listing is the whole of
//! namespace v2 §1: a case file hangs under exactly one archive.
//!
//! Titles and identifiers are fixed: two runs of the mock show the same folder, and a bug report
//! out of development can be reproduced.
//!
//! **The titles stay German, and so does the text in the PDFs.** They are the documents of a
//! German tenant — data, not something the mock says. That is what makes them worth having: an
//! umlaut, an en dash and a euro sign travel from the listing through a file name and back, and a
//! folder of purely ASCII names would let every mistake on that way pass unnoticed. Everything
//! the **mock itself** says is English, like the rest of the wire.

use edms_core::identifier::{
    ArchiveIdentifier, BasketIdentifier, CaseIdentifier, DocumentIdentifier, SearchIdentifier,
};
use edms_core::namespace::Location;
use edms_core::time::Timestamp;

use crate::pdf;
use crate::state::{Archive, Basket, Container, Document, Mangling, State};

/// Title of the first mail basket — the one the capture page names.
pub const BASKET_ACCOUNTING: &str = "Briefkorb Buchhaltung";

/// Title of the second mail basket.
pub const BASKET_SCANNER: &str = "Scanner Empfang";

/// Title of the first archive; the creditor's case file stands in it.
pub const ARCHIVE_INVOICE: &str = "Rechnungseingang";

/// Title of the second archive; the maintenance case file stands in it.
pub const ARCHIVE_MAINTENANCE: &str = "Wartung und Instandhaltung";

/// Title of the first case file (Akte).
pub const CASE_MAINTENANCE: &str = "Sulzer Pumpen – Wartungsvertrag 2026";

/// Title of the second case file (Akte).
pub const CASE_CREDITOR: &str = "Kreditor 4711 – Eingangsrechnungen";

/// Title of the first saved search — the truncated one.
pub const SEARCH_OPEN: &str = "Offene Rechnungen über 10.000 €";

/// Title of the second saved search.
pub const SEARCH_INSPECTION_REPORT: &str = "Prüfberichte Pumpenwerk";

/// The display limit of the truncated search.
///
/// The contract proposes 5000 (`domain.FacetThreshold`). Five thousand documents in a mock would
/// be five thousand PDFs in memory without a single case being checked any better: truncated is
/// truncated. The small limit exercises the same branch in a second.
// §7.1.2 — `displayLimit` stands at 5 here instead of 5000, purely for reasons of size.
pub const LIMIT_OPEN: u64 = 5;

const CREATED: Timestamp = Timestamp::from_unix_millis(1_767_859_200_000);
const CHANGED: Timestamp = Timestamp::from_unix_millis(1_788_336_862_000);

/// Sets up the sample tenant.
pub fn sow(state: &State) {
    let basket_accounting = BasketIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_0101);
    let basket_scanner = BasketIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_0102);
    let archive_invoice = ArchiveIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_0201);
    let archive_maintenance =
        ArchiveIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_0202);
    let case_maintenance = CaseIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_1001);
    let case_creditor = CaseIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_1002);
    let search_open = SearchIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_2001);
    let search_inspection = SearchIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0000_2002);
    // The refine URL points into the tenant's web interface, and its paths are those of the German
    // product (`/suche?gespeichert=…`) — the mock imitates the server, it does not define it.
    let refinement =
        format!("{}/suche?gespeichert={search_open}", state.app_base.trim_end_matches('/'));

    let groups: [(Location, &str, Vec<&str>); 4] = [
        (
            Location::Case { archive: archive_maintenance, case: case_maintenance },
            CASE_MAINTENANCE,
            vec![
                "Wartungsvertrag 2026 (geschwärzt)",
                "Prüfbericht Pumpe 7",
                "Prüfbericht Pumpe 12",
                "Lieferschein 88213",
                "Abnahmeprotokoll Pumpenwerk",
            ],
        ),
        (
            Location::Case { archive: archive_invoice, case: case_creditor },
            CASE_CREDITOR,
            vec![
                "Rechnung 2026-0412",
                "Rechnung 2026-0413",
                "Rechnung 2026-0501",
                "Mahnung 2026-0412",
                "Gutschrift 2026-0087",
            ],
        ),
        (
            Location::Search(search_open),
            SEARCH_OPEN,
            vec![
                "Offene Rechnung 2026-0412",
                "Offene Rechnung 2026-0413",
                "Offene Rechnung 2026-0501",
                "Offene Rechnung 2026-0577",
                "Offene Rechnung 2026-0603",
                "Offene Rechnung 2026-0644",
                "Offene Rechnung 2026-0701",
                "Offene Rechnung 2026-0712",
            ],
        ),
        (
            Location::Search(search_inspection),
            SEARCH_INSPECTION_REPORT,
            vec!["Prüfbericht Pumpe 7", "Prüfbericht Pumpe 12", "Prüfbericht Pumpe 19"],
        ),
    ];

    let mut inner = state.lock();
    inner
        .baskets
        .push(Basket { identifier: basket_accounting, title: BASKET_ACCOUNTING.to_owned() });
    inner.baskets.push(Basket { identifier: basket_scanner, title: BASKET_SCANNER.to_owned() });
    inner.archives.push(Archive { identifier: archive_invoice, title: ARCHIVE_INVOICE.to_owned() });
    inner
        .archives
        .push(Archive { identifier: archive_maintenance, title: ARCHIVE_MAINTENANCE.to_owned() });
    let mut running = 0u128;
    for (location, title, documents) in groups {
        let mut content = Vec::with_capacity(documents.len());
        for name in documents {
            running += 1;
            let identifier =
                DocumentIdentifier::from_value(0x0193_4B00_7000_8000_0000_0000_0003_0000 + running);
            let bytes = pdf::generate(
                name,
                &[
                    format!("Mandant: {}", state.configuration.tenant_name),
                    format!("Ablage: {title}"),
                    // German like the titles: this is the tenant's document, not the mock
                    // talking. The last line stands in it so that nobody takes a page out of the
                    // sample folder for a record.
                    "Ausgelieferte Fassung: geschwärzt (§7.2.1)".to_owned(),
                    "Dies ist ein Prüfstand, kein Beleg.".to_owned(),
                ],
            );
            inner.documents.insert(
                identifier,
                Document {
                    identifier,
                    title: name.to_owned(),
                    media_type: "application/pdf".to_owned(),
                    sha256: State::checksum(&bytes),
                    bytes,
                    version: 1,
                    created: CREATED,
                    changed: CHANGED,
                    mangling: Mangling::No,
                    without_rendition: false,
                },
            );
            content.push(identifier);
        }
        let truncated = location == Location::Search(search_open);
        inner.container.push(Container {
            location,
            title: title.to_owned(),
            changed: CHANGED,
            content,
            display_limit: truncated.then_some(LIMIT_OPEN),
            refinement: truncated.then(|| refinement.clone()),
            not_runnable: None,
            version: 1,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;

    fn seeded() -> State {
        let state = State::new(
            Configuration::default(),
            "http://127.0.0.1:8480".to_owned(),
            "http://127.0.0.1:8481".to_owned(),
        )
        .expect("the forge");
        sow(&state);
        state
    }

    #[test]
    fn the_sample_tenant_has_two_case_files_and_two_saved_searches() {
        let state = seeded();
        let inner = state.lock();
        let cases: Vec<&str> =
            inner.container.iter().filter(|c| c.is_case()).map(|c| c.title.as_str()).collect();
        let searches: Vec<&str> =
            inner.container.iter().filter(|c| !c.is_case()).map(|c| c.title.as_str()).collect();
        assert_eq!(cases, vec![CASE_MAINTENANCE, CASE_CREDITOR]);
        assert_eq!(searches, vec![SEARCH_OPEN, SEARCH_INSPECTION_REPORT]);
    }

    #[test]
    fn the_sample_tenant_has_two_mail_baskets_and_two_archives() {
        let state = seeded();
        let inner = state.lock();
        let baskets: Vec<&str> = inner.baskets.iter().map(|b| b.title.as_str()).collect();
        let archives: Vec<&str> = inner.archives.iter().map(|a| a.title.as_str()).collect();
        assert_eq!(baskets, vec![BASKET_ACCOUNTING, BASKET_SCANNER]);
        assert_eq!(archives, vec![ARCHIVE_INVOICE, ARCHIVE_MAINTENANCE]);
    }

    #[test]
    fn each_case_file_stands_in_an_archive_of_its_own() {
        let state = seeded();
        let inner = state.lock();
        let seen: Vec<(ArchiveIdentifier, &str)> = inner
            .container
            .iter()
            .filter_map(|c| c.archive().map(|archive| (archive, c.title.as_str())))
            .collect();
        assert_eq!(seen.len(), 2, "the two case files of the sample tenant");
        assert_ne!(
            seen[0].0, seen[1].0,
            "both in one archive, and a listing that ignores its archive would pass unnoticed"
        );
        for (archive, title) in &seen {
            assert!(inner.has_archive(*archive), "{title} stands below an archive nobody has");
        }
    }

    #[test]
    fn every_document_carries_real_pdf_bytes_with_a_matching_checksum() {
        let state = seeded();
        let inner = state.lock();
        assert_eq!(inner.documents.len(), 21);
        for doc in inner.documents.values() {
            assert!(doc.bytes.starts_with(b"%PDF-1.4"), "{} is not a PDF", doc.title);
            assert_eq!(doc.sha256, State::checksum(&doc.bytes));
            assert!(doc.bytes.len() > 400);
        }
    }

    #[test]
    fn exactly_one_search_lies_above_its_display_limit() {
        let state = seeded();
        let inner = state.lock();
        let truncated: Vec<&str> = inner
            .container
            .iter()
            .filter(|c| c.display_limit.is_some_and(|limit| (c.content.len() as u64) > limit))
            .map(|c| c.title.as_str())
            .collect();
        assert_eq!(truncated, vec![SEARCH_OPEN]);
        let search = inner.container.iter().find(|c| c.title == SEARCH_OPEN).expect("the search");
        assert!(search.refinement.is_some(), "a truncation without a refineUrl is a silent one");
    }

    #[test]
    fn sowing_twice_yields_the_same_identifiers() {
        let a = seeded();
        let b = seeded();
        let identifiers = |state: &State| -> Vec<String> {
            state.lock().documents.keys().map(ToString::to_string).collect()
        };
        assert_eq!(identifiers(&a), identifiers(&b));
    }
}
