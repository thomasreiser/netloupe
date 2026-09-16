//! One module per pane; `render` dispatches to the active one.
//!
//! Every pane follows the same shape: a rounded, accent-bordered panel
//! (the accent identifies the pane at a glance, via `theme::pane_accent`)
//! containing a status line (badge + check name) and whatever the check
//! returned, rendered with `widgets::*`. Panes never await or touch check
//! state directly — they only read `TabState`, which `app.rs` already
//! applied incoming events into.

mod dns;
mod geo;
mod hosting;
mod http;
mod ipasn;
mod mail;
mod overview;
mod ping_trace;
mod ports;
mod rep;
mod tls;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::theme;
use crate::app::{CheckStatus, Pane, TabState};
use crate::checks::CheckId;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let pane = Pane::ALL
        .get(tab.active_pane)
        .copied()
        .unwrap_or(Pane::Overview);
    match pane {
        Pane::Overview => overview::render(frame, area, tab),
        Pane::Dns => dns::render(frame, area, tab),
        Pane::Mail => mail::render(frame, area, tab),
        Pane::PingTrace => ping_trace::render(frame, area, tab),
        Pane::Ports => ports::render(frame, area, tab),
        Pane::Tls => tls::render(frame, area, tab),
        Pane::Http => http::render(frame, area, tab),
        Pane::IpAsn => ipasn::render(frame, area, tab),
        Pane::Hosting => hosting::render(frame, area, tab),
        Pane::Geo => geo::render(frame, area, tab),
        Pane::Rep => rep::render(frame, area, tab),
    }
}

/// Wraps the pane in a rounded panel titled with the current pane's name
/// (in its accent color) and a target subtitle, then splits the inside
/// into a one-line status header (check badges) and the body below it.
pub(super) fn header_and_body(
    frame: &mut Frame,
    area: Rect,
    tab: &TabState,
    checks: &[CheckId],
) -> Rect {
    let pane = Pane::ALL
        .get(tab.active_pane)
        .copied()
        .unwrap_or(Pane::Overview);
    let accent = theme::pane_accent(pane);
    let subtitle = tab.target.display();
    let block = theme::panel_with_hint(pane.label(), &subtitle, theme::MUTED, accent);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);
    render_status_header(frame, chunks[0], tab, checks);
    chunks[1]
}

fn render_status_header(frame: &mut Frame, area: Rect, tab: &TabState, checks: &[CheckId]) {
    let mut spans: Vec<Span> = Vec::new();
    for (i, &id) in checks.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        let slot = tab.slot(id);
        let (glyph, color) = crate::ui::widgets::status_badge::badge(&slot.status);
        spans.push(Span::styled(
            format!("{glyph} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(id.label(), Style::default().fg(theme::MUTED)));
    }
    frame.render_widget(Line::from(spans), area);
}

/// A dimmed placeholder for a pane whose check hasn't produced data yet
/// (not started, still running with nothing streamed in, or cancelled).
pub(super) fn empty_message(message: &str) -> Paragraph<'static> {
    Paragraph::new(Line::from(Span::styled(
        format!("· {message}"),
        Style::default().fg(theme::MUTED),
    )))
}

/// Renders a check's error list, when any, as red lines with a marker.
pub(super) fn errors_widget(errors: &[String]) -> Paragraph<'static> {
    let lines: Vec<Line> = errors
        .iter()
        .map(|e| {
            Line::from(Span::styled(
                format!("✗ {e}"),
                Style::default().fg(theme::RED),
            ))
        })
        .collect();
    Paragraph::new(lines)
}

/// True if a check hasn't reported anything yet (vs. having failed, or
/// having at least partial data to show).
pub(super) fn is_waiting(status: &CheckStatus) -> bool {
    matches!(status, CheckStatus::NotStarted | CheckStatus::Running)
}
