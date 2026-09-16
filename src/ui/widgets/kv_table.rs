//! A simple two-column key/value table, used by most panes to show
//! record-style data (headers, DNS records, cert fields, ...).

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::ui::theme;

const KEY_WIDTH: u16 = 22;
const COLUMN_SPACING: u16 = 1;

/// Renders the table scrolled so row `scroll` is the first one shown —
/// for panes whose content can be taller than the terminal (a long SAN
/// list, a zone with many DNS records, ...). Clamped to the last row
/// rather than left to scroll into blank space past the end.
///
/// Values wider than the value column wrap onto additional lines within
/// their own row (SANs, long TXT/header values, ...) rather than being
/// cut off at the terminal's edge.
pub fn render(frame: &mut Frame, area: Rect, rows: &[(String, String)], scroll: u16) {
    let value_width = area.width.saturating_sub(KEY_WIDTH + COLUMN_SPACING).max(1) as usize;

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|(k, v)| {
            let wrapped = wrap(v, value_width);
            let height = wrapped.len() as u16;
            Row::new(vec![
                Cell::from(k.as_str()).style(
                    Style::default()
                        .fg(theme::LABEL)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(Text::from(
                    wrapped.into_iter().map(Line::from).collect::<Vec<_>>(),
                ))
                .style(Style::default().fg(theme::TEXT)),
            ])
            .height(height.max(1))
        })
        .collect();

    let table = Table::new(
        table_rows,
        [Constraint::Length(KEY_WIDTH), Constraint::Fill(1)],
    );

    let mut state = TableState::default();
    let max_offset = rows.len().saturating_sub(1);
    *state.offset_mut() = (scroll as usize).min(max_offset);
    frame.render_stateful_widget(table, area, &mut state);
}

/// Greedy word-wrap into lines of at most `width` characters, hard-
/// breaking any single "word" longer than that (SANs, long hex tokens,
/// and the like rarely contain spaces at all, so this is the common
/// case for the longest values).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let mut remaining = word;
        while remaining.chars().count() > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let split_at = remaining
                .char_indices()
                .nth(width)
                .map(|(i, _)| i)
                .unwrap_or(remaining.len());
            lines.push(remaining[..split_at].to_string());
            remaining = &remaining[split_at..];
        }
        let sep_len = usize::from(!current.is_empty());
        if current.chars().count() + sep_len + remaining.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(remaining);
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_on_word_boundaries_when_possible() {
        assert_eq!(
            wrap("the quick brown fox", 10),
            vec!["the quick", "brown fox"]
        );
    }

    #[test]
    fn hard_breaks_a_single_word_longer_than_the_width() {
        assert_eq!(
            wrap("aaaaaaaaaaaaaaaa", 5),
            vec!["aaaaa", "aaaaa", "aaaaa", "a"]
        );
    }

    #[test]
    fn short_text_stays_on_one_line() {
        assert_eq!(wrap("example.com", 40), vec!["example.com"]);
    }

    #[test]
    fn empty_text_yields_one_empty_line() {
        assert_eq!(wrap("", 40), vec![""]);
    }

    #[test]
    fn zero_width_still_terminates_and_makes_progress() {
        // Degenerate input (a value column squeezed to nothing); must not
        // loop forever or panic.
        let wrapped = wrap("hello world", 0);
        assert!(!wrapped.is_empty());
    }
}
