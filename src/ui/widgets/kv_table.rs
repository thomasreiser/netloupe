//! A simple two-column key/value table, used by most panes to show
//! record-style data (headers, DNS records, cert fields, ...).

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Cell, Row, Table};

/// Builds a `Table` widget from `(key, value)` pairs. The caller renders it
/// with `frame.render_widget(kv_table::widget(&rows), area)`.
pub fn widget<'a>(rows: &'a [(String, String)]) -> Table<'a> {
    let rows: Vec<Row> = rows
        .iter()
        .map(|(k, v)| {
            Row::new(vec![
                Cell::from(k.as_str()).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(v.as_str()),
            ])
        })
        .collect();

    Table::new(rows, [Constraint::Length(22), Constraint::Fill(1)])
}
