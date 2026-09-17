//! Finds hostnames/IPs in a pane's already-rendered output and turns them
//! into clickable/keyboard-navigable links.
//!
//! Rather than teaching every individual pane to track "this value I'm
//! drawing is a hostname" (a change repeated across ~11 differently-shaped
//! panes), this scans the *rendered* [`Buffer`] for text that looks like a
//! hostname or IP, using the same [`Target::parse`] this app already
//! trusts to decide what's a valid target. Since it works on the final
//! composed screen, a clickable region can never drift from what's
//! actually drawn -- there's nothing to keep in sync.
//!
//! `Target::parse` alone is too permissive here: a bare word like "Cert"
//! or a number like "42" is technically a valid single-label hostname,
//! so scanning would turn ordinary text into false-positive links.
//! [`Target::parse_strict`] closes that gap; see its doc comment.

use std::sync::OnceLock;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use regex::Regex;

use crate::target::Target;

/// One clickable region found in the last rendered frame: an absolute
/// (whole-terminal, not pane-relative) cell range on one row, and the
/// target clicking it should open.
#[derive(Debug, Clone)]
pub struct ClickableSpan {
    pub row: u16,
    pub col_start: u16,
    pub col_end: u16,
    pub text: String,
    pub target: Target,
}

impl ClickableSpan {
    pub fn contains(&self, row: u16, col: u16) -> bool {
        self.row == row && (self.col_start..self.col_end).contains(&col)
    }
}

/// Scans every row of `area` (normally the active pane's content area,
/// not the tab bars/status line/borders around it) for hostname/IP-shaped
/// text, returning one [`ClickableSpan`] per match that survives
/// [`Target::parse_strict`].
pub fn scan(buffer: &Buffer, area: Rect) -> Vec<ClickableSpan> {
    let mut spans = Vec::new();
    for row in area.top()..area.bottom() {
        scan_row(buffer, area, row, &mut spans);
    }
    spans
}

fn scan_row(buffer: &Buffer, area: Rect, row: u16, spans: &mut Vec<ClickableSpan>) {
    // Rebuilds the row as a plain string, remembering which terminal
    // column each `char` came from -- needed because a row can contain
    // multi-byte glyphs (box-drawing characters, icons, ...) before a
    // match, which would otherwise throw off a byte-offset-based mapping
    // back to columns.
    let mut text = String::new();
    let mut columns: Vec<u16> = Vec::new();
    for col in area.left()..area.right() {
        let Some(cell) = buffer.cell((col, row)) else {
            continue;
        };
        for ch in cell.symbol().chars() {
            text.push(ch);
            columns.push(col);
        }
    }
    if columns.is_empty() {
        return;
    }

    for m in candidate_regex().find_iter(&text) {
        let Some(target) = Target::parse_strict(m.as_str()).ok() else {
            continue;
        };
        let char_start = text[..m.start()].chars().count();
        let char_end = char_start + m.as_str().chars().count();
        let (Some(&col_start), Some(&last_col)) =
            (columns.get(char_start), columns.get(char_end - 1))
        else {
            continue;
        };
        spans.push(ClickableSpan {
            row,
            col_start,
            col_end: last_col + 1,
            text: m.as_str().to_string(),
            target,
        });
    }
}

/// A broad net for "things worth asking `Target::parse_strict` about":
/// dotted-quad-shaped runs (IPv4), colon/hex runs (IPv6), and
/// multi-label alphanumeric-and-hyphen runs (hostnames). Deliberately
/// loose -- e.g. it doesn't itself validate octet ranges or reject a
/// leading hyphen -- because `Target::parse_strict` (which uses the
/// standard library's own address parsers, and this project's existing
/// hostname validator) is the real filter; this just finds candidates
/// worth asking it about.
fn candidate_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
                \d{1,3}(?:\.\d{1,3}){3}                                # IPv4-shaped
                | [0-9a-fA-F]*(?::[0-9a-fA-F]{0,4}){2,}[0-9a-fA-F]*    # IPv6-shaped
                | [A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\.?  # multi-label hostname
            ",
        )
        .expect("candidate_regex is a fixed, tested pattern")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::text::Line;
    use ratatui::widgets::{Paragraph, Widget};

    fn render(width: u16, height: u16, text: &str) -> Buffer {
        let area = Rect::new(0, 0, width, height);
        let mut buffer = Buffer::empty(area);
        Paragraph::new(Line::from(text)).render(area, &mut buffer);
        buffer
    }

    #[test]
    fn finds_a_hostname_and_reports_its_exact_columns() {
        let text = "Host       example.com";
        let buffer = render(40, 1, text);
        let spans = scan(&buffer, Rect::new(0, 0, 40, 1));
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text, "example.com");
        assert_eq!(spans[0].col_start, text.find("example.com").unwrap() as u16);
        assert_eq!(spans[0].col_end, text.len() as u16);
        assert_eq!(spans[0].target, Target::parse("example.com").unwrap());
    }

    #[test]
    fn finds_an_ipv4_and_an_ipv6_address_on_the_same_row() {
        let text = "IPs 93.184.216.34, 2606:4700:4700::1111";
        let buffer = render(60, 1, text);
        let spans = scan(&buffer, Rect::new(0, 0, 60, 1));
        let texts: Vec<&str> = spans.iter().map(|s| s.text.as_str()).collect();
        assert!(texts.contains(&"93.184.216.34"), "{texts:?}");
        assert!(texts.contains(&"2606:4700:4700::1111"), "{texts:?}");
    }

    #[test]
    fn does_not_flag_a_bare_word_or_number_as_a_link() {
        let text = "Cert 42d Accuracy city-level";
        let buffer = render(40, 1, text);
        let spans = scan(&buffer, Rect::new(0, 0, 40, 1));
        assert!(spans.is_empty(), "{spans:?}");
    }

    /// "Washington, D.C." is syntactically a valid two-label hostname
    /// (each "label" passes the same character rules a real one would),
    /// but a real city name in a Geo pane isn't meant to be clickable.
    #[test]
    fn does_not_flag_a_two_initial_abbreviation_as_a_hostname() {
        let text = "City       Washington, D.C.";
        let buffer = render(40, 1, text);
        let spans = scan(&buffer, Rect::new(0, 0, 40, 1));
        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test]
    fn does_not_flag_a_colon_hex_fingerprint_as_ipv6() {
        // A SHA-1-shaped fingerprint: 20 colon-separated hex octets --
        // structurally nothing like a valid (8-group) IPv6 address, so
        // `Ipv6Addr::from_str` (via `Target::parse_strict`) rejects it.
        let text = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD";
        let buffer = render(80, 1, text);
        let spans = scan(&buffer, Rect::new(0, 0, 80, 1));
        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test]
    fn restricts_the_scan_to_the_given_area() {
        let text = "example.com";
        let buffer = render(40, 3, text);
        // Only row 1 is scanned; the text was drawn on row 0.
        let spans = scan(&buffer, Rect::new(0, 1, 40, 1));
        assert!(spans.is_empty());
    }

    #[test]
    fn clickable_span_contains_checks_row_and_column_range() {
        let span = ClickableSpan {
            row: 5,
            col_start: 10,
            col_end: 15,
            text: "a.com".to_string(),
            target: Target::parse("a.com").unwrap(),
        };
        assert!(span.contains(5, 10));
        assert!(span.contains(5, 14));
        assert!(!span.contains(5, 15), "col_end is exclusive");
        assert!(!span.contains(4, 12), "wrong row");
    }
}
