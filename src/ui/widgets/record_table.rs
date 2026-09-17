//! A three-column (type, value, TTL) table with a header row, for DNS
//! records. Reuses `kv_table`'s greedy word-wrap for the value column so
//! a long TXT/CAA value spills onto additional lines within its own row
//! rather than being cut off at the pane's edge.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::ui::theme;

const TYPE_WIDTH: u16 = 8;
const TTL_WIDTH: u16 = 8;
const COLUMN_SPACING: u16 = 1;
/// The value column is `Constraint::Fill(1)`, which stretches to
/// consume the *entire* remaining width of whatever area it's given --
/// harmless for most content, but on a wide terminal it strands the TTL
/// column far to the right of the values it describes, behind a large
/// empty gap easy to miss entirely. Capping the table's own width keeps
/// TTL adjacent to the content instead.
const MAX_TABLE_WIDTH: u16 = 100;

/// One row: the record type (e.g. "A", "MX"), its rendered value, and
/// its TTL already formatted for display (e.g. "300s", or "-" when
/// unknown/not applicable).
pub struct RecordRow {
    pub record_type: String,
    pub value: String,
    pub ttl: String,
}

/// Renders the table scrolled so row `scroll` is the first one shown,
/// same as `kv_table::render`.
pub fn render(frame: &mut Frame, area: Rect, rows: &[RecordRow], scroll: u16) {
    let area = Rect {
        width: area.width.min(MAX_TABLE_WIDTH),
        ..area
    };
    let value_width = area
        .width
        .saturating_sub(TYPE_WIDTH + TTL_WIDTH + COLUMN_SPACING * 2)
        .max(1) as usize;

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|r| {
            let wrapped = super::kv_table::wrap(&r.value, value_width);
            let height = wrapped.len() as u16;
            Row::new(vec![
                Cell::from(r.record_type.as_str()).style(
                    Style::default()
                        .fg(theme::LABEL)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(Text::from(
                    wrapped.into_iter().map(Line::from).collect::<Vec<_>>(),
                ))
                .style(Style::default().fg(theme::TEXT)),
                Cell::from(r.ttl.as_str()).style(Style::default().fg(theme::MUTED)),
            ])
            .height(height.max(1))
        })
        .collect();

    let header_style = Style::default()
        .fg(theme::MUTED)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec![
        Cell::from("TYPE").style(header_style),
        Cell::from("VALUE").style(header_style),
        Cell::from("TTL").style(header_style),
    ]);

    let table = Table::new(
        table_rows,
        [
            Constraint::Length(TYPE_WIDTH),
            Constraint::Fill(1),
            Constraint::Length(TTL_WIDTH),
        ],
    )
    .header(header);

    let mut state = TableState::default();
    let max_offset = rows.len().saturating_sub(1);
    *state.offset_mut() = (scroll as usize).min(max_offset);
    frame.render_stateful_widget(table, area, &mut state);
}
