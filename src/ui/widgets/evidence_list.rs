//! Renders a hosting detection's evidence trail as a bulleted list, so
//! every conclusion in the Hosting pane shows what it's based on.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem};

use crate::providers::Evidence;
use crate::ui::theme;

pub fn widget(evidence: &[Evidence]) -> List<'static> {
    let items: Vec<ListItem> = evidence
        .iter()
        .map(|e| {
            ListItem::new(Line::from(vec![
                Span::styled("    ▸ ", Style::default().fg(theme::FAINT)),
                Span::styled(e.description.clone(), Style::default().fg(theme::TEXT)),
                Span::styled(
                    format!(" +{}", e.weight),
                    Style::default()
                        .fg(theme::MUTED)
                        .add_modifier(Modifier::ITALIC),
                ),
            ]))
        })
        .collect();
    List::new(items)
}
