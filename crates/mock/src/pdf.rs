//! Real, small PDF files — generated in code, not carried along as a test fixture.
//!
//! The mock delivers document contents. A body of random bytes with
//! `Content-Type: application/pdf` would suffice for the checksum but not for the purpose: the
//! folder client puts the bytes down in Explorer or Finder, and there a human opens them in the
//! preview. A placeholder that cannot be opened looks like a failed hydration — and it is exactly
//! that which the test harness is meant to let one tell apart from a successful one.
//!
//! What is generated is the smallest complete shape per PDF 1.4: catalogue, page tree, one A4
//! page, Helvetica in `WinAnsiEncoding`, one content stream, a cross-reference table with real
//! byte offsets, and a trailer. No compression filter — an uncompressed stream can be read with
//! the naked eye in a failure case.
//!
//! **Umlauts.** `WinAnsiEncoding` covers the German characters; they stand as octal escape
//! sequences in the text literal. A character the encoding does not know becomes `?` — visibly
//! wrong is better than a byte a viewer reads as a control character.

/// Width of an A4 page in PDF points (72 dpi).
pub const WIDTH: u32 = 595;

/// Height of an A4 page in PDF points.
pub const HEIGHT: u32 = 842;

/// Builds a one-page PDF with a heading and lines of text.
///
/// The content is meaningless; what carries weight are the size and the checksum the document
/// listing announces (§7.1.2). The same input yields the same bytes — otherwise the checksum of a
/// document would change on every start of the mock, and a comparison across two runs could not be
/// made.
pub fn generate(heading: &str, rows: &[String]) -> Vec<u8> {
    let mut stream = String::new();
    stream.push_str("BT\n/F1 16 Tf\n72 770 Td\n");
    stream.push_str(&format!("({}) Tj\n", literal(heading)));
    stream.push_str("/F1 11 Tf\n0 -28 Td\n");
    for row in rows {
        stream.push_str(&format!("({}) Tj\n0 -16 Td\n", literal(row)));
    }
    stream.push_str("ET\n");

    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {WIDTH} {HEIGHT}] \
             /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_owned(),
        format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()),
    ];

    let mut out: Vec<u8> = Vec::with_capacity(1024);
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offset = Vec::with_capacity(objects.len());
    for (nr, content) in objects.iter().enumerate() {
        offset.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{content}\nendobj\n", nr + 1).as_bytes());
    }

    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    // Exactly 20 bytes per row — PDF 1.4 §3.4.3. A shorter row would shift every following entry,
    // and a viewer would no longer find the first object.
    out.extend_from_slice(b"0000000000 65535 f \n");
    for v in &offset {
        out.extend_from_slice(format!("{v:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A PDF text literal: parentheses and backslash escaped, non-ASCII as an octal sequence in
/// `WinAnsiEncoding`.
fn literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for character in text.chars() {
        match character {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            ' '..='~' => out.push(character),
            other => match winansi(other) {
                Some(b) => out.push_str(&format!("\\{b:03o}")),
                None => out.push('?'),
            },
        }
    }
    out
}

/// The `WinAnsiEncoding` value of a character above ASCII, as far as the mock needs it.
fn winansi(character: char) -> Option<u8> {
    let value = match character {
        '€' => 0x80,
        '‚' => 0x82,
        '„' => 0x84,
        '…' => 0x85,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        // In this range Latin-1 coincides with WinAnsi (umlauts, eszett, section sign).
        c if ('\u{A0}'..='\u{FF}').contains(&c) => u32::from(c),
        _ => return None,
    };
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Vec<u8> {
        generate("Prüfbericht Pumpe 7", &["Sulzer Pumpen GmbH".to_owned(), "10.000 €".to_owned()])
    }

    #[test]
    fn the_generated_pdf_carries_a_header_and_a_terminator() {
        let bytes = example();
        assert!(bytes.starts_with(b"%PDF-1.4\n"), "no PDF header");
        assert!(bytes.ends_with(b"%%EOF\n"), "no terminator");
        assert!(bytes.len() > 400 && bytes.len() < 4096, "unexpected size: {}", bytes.len());
    }

    /// Finds a byte pattern.
    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|f| f == needle)
    }

    #[test]
    fn every_cross_reference_points_at_the_header_of_its_object() {
        // On bytes, not on text: the header deliberately carries a binary comment line, and a
        // lossy conversion into UTF-8 would shift every offset.
        let bytes = example();
        let marker = b"xref\n0 6\n";
        let xref = find(&bytes, marker).expect("the cross-reference table");
        let table = &bytes[xref + marker.len()..];
        for nr in 0..5usize {
            let row = &table[20 * (nr + 1)..20 * (nr + 1) + 20];
            let offset: usize =
                std::str::from_utf8(&row[..10]).expect("ASCII").parse().expect("an offset");
            let header = format!("{} 0 obj", nr + 1);
            assert!(
                bytes[offset..].starts_with(header.as_bytes()),
                "entry {nr} does not point at {header}"
            );
            assert_eq!(&row[10..], b" 00000 n \n", "every row is exactly 20 bytes long");
        }
        let start = find(&bytes, b"startxref\n").expect("startxref") + b"startxref\n".len();
        let end = find(&bytes[start..], b"\n").expect("the end of the line");
        let value: usize = std::str::from_utf8(&bytes[start..start + end])
            .expect("ASCII")
            .parse()
            .expect("a number");
        assert_eq!(value, xref, "startxref does not point at the table");
    }

    #[test]
    fn the_stream_length_matches_the_stream_content() {
        let bytes = example();
        let marker = b"/Length ";
        let header = find(&bytes, marker).expect("Length") + marker.len();
        let end = find(&bytes[header..], b" ").expect("the end of the number");
        let reported: usize = std::str::from_utf8(&bytes[header..header + end])
            .expect("ASCII")
            .parse()
            .expect("a number");
        let start = find(&bytes, b"stream\n").expect("stream") + b"stream\n".len();
        let close = find(&bytes, b"endstream").expect("endstream");
        assert_eq!(reported, close - start);
    }

    #[test]
    fn umlauts_stand_as_octal_sequences_and_parentheses_are_escaped() {
        assert_eq!(literal("Prüfbericht"), "Pr\\374fbericht");
        assert_eq!(literal("10.000 €"), "10.000 \\200");
        assert_eq!(literal("a(b)c\\d"), "a\\(b\\)c\\\\d");
        assert_eq!(literal("日本"), "??", "unknown characters become visibly wrong");
    }

    #[test]
    fn the_same_input_yields_the_same_bytes() {
        assert_eq!(example(), example());
        assert_ne!(example(), generate("Something else", &[]));
    }
}
