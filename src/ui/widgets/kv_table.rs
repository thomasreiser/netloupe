//! A simple two-column key/value table, used by most panes to show
//! record-style data (headers, DNS records, cert fields, ...).

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::ui::theme;

/// Builds a `Table` widget from `(key, value)` pairs. The caller renders it
/// with `frame.render_widget(kv_table::widget(&rows), area)`, or (when the
/// row count may exceed the available height) via [`render`] instead.
pub fn widget<'a>(rows: &'a [(String, String)]) -> Table<'a> {
    let rows: Vec<Row> = rows
        .iter()
        .map(|(k, v)| {
            Row::new(vec![
                Cell::from(k.as_str()).style(
                    Style::default()
                        .fg(theme::LABEL)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(v.as_str()).style(Style::default().fg(theme::TEXT)),
            ])
        })
        .collect();

    Table::new(rows, [Constraint::Length(22), Constraint::Fill(1)])
}

/// Renders the table scrolled so row `scroll` is the first one shown —
/// for panes whose content can be taller than the terminal (a long SAN
/// list, a zone with many DNS records, ...). Clamped to the last row
/// rather than left to scroll into blank space past the end.
pub fn render(frame: &mut Frame, area: Rect, rows: &[(String, String)], scroll: u16) {
    let mut state = TableState::default();
    let max_offset = rows.len().saturating_sub(1);
    *state.offset_mut() = (scroll as usize).min(max_offset);
    frame.render_stateful_widget(widget(rows), area, &mut state);
}
