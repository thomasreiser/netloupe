//! Renders a hosting detection's evidence trail as a bulleted list, so
//! every conclusion in the Hosting pane shows what it's based on.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem};

use crate::providers::Evidence;

pub fn widget(evidence: &[Evidence]) -> List<'static> {
    let items: Vec<ListItem> = evidence
        .iter()
        .map(|e| {
            ListItem::new(Line::from(vec![
                Span::styled("  • ", Style::default().fg(Color::DarkGray)),
                Span::raw(e.description.clone()),
                Span::styled(
                    format!(" (+{})", e.weight),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();
    List::new(items)
}
