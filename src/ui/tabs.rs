//! The two tab bars: host tabs across the top (`[ example.com ] [ 8.8.8.8 ]
//! [+]`) and the pane sub-tabs below them.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use super::theme;
use crate::app::{AppState, Pane};

pub fn render_host_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let mut spans: Vec<Span> = Vec::new();
    for (i, tab) in state.tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        if i == state.active_tab {
            spans.push(theme::pill(tab.target.display(), theme::CYAN));
        } else {
            spans.push(Span::styled(
                format!(" {} ", tab.target.display()),
                Style::default().fg(theme::MUTED),
            ));
        }
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled("+ new", Style::default().fg(theme::FAINT)));
    frame.render_widget(Line::from(spans), area);
}

pub fn render_pane_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let Some(tab) = state.active() else {
        frame.render_widget(Line::from(""), area);
        return;
    };
    let mut spans: Vec<Span> = Vec::new();
    for (i, &pane) in Pane::ALL.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ", Style::default()));
        }
        let accent = theme::pane_accent(pane);
        if i == tab.active_pane {
            spans.push(theme::pill(pane.label(), accent));
        } else {
            spans.push(Span::styled(
                format!(" {} ", pane.label()),
                Style::default().fg(accent).add_modifier(Modifier::DIM),
            ));
        }
    }
    frame.render_widget(Line::from(spans), area);
}
