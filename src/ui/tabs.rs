//! The two tab bars: host tabs across the top (`[ example.com ] [ 8.8.8.8 ]
//! [+]`) and the pane sub-tabs below them.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use crate::app::{AppState, Pane};

pub fn render_host_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let mut spans: Vec<Span> = Vec::new();
    for (i, tab) in state.tabs.iter().enumerate() {
        let label = format!(" {} ", tab.target.display());
        let style = if i == state.active_tab {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(format!("[{label}]"), style));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled("[+]", Style::default().fg(Color::DarkGray)));
    frame.render_widget(Line::from(spans), area);
}

pub fn render_pane_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let Some(tab) = state.active() else {
        frame.render_widget(Line::from(""), area);
        return;
    };
    let mut spans: Vec<Span> = Vec::new();
    for (i, pane) in Pane::ALL.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" │ "));
        }
        let style = if i == tab.active_pane {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(pane.label(), style));
    }
    frame.render_widget(Line::from(spans), area);
}
