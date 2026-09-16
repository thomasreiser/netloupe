//! One module per pane; `render` dispatches to the active one.
//!
//! Every pane follows the same shape: a status line (badge + any errors)
//! followed by whatever the check returned, rendered with `widgets::*`.
//! Panes never await or touch check state directly — they only read
//! `TabState`, which `app.rs` already applied incoming events into.

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
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

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

/// Splits a pane into a one-line status header and the body below it, and
/// draws the header (status badge, plus any error messages for `checks`).
pub(super) fn header_and_body(
    frame: &mut Frame,
    area: Rect,
    tab: &TabState,
    checks: &[CheckId],
) -> Rect {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);
    render_status_header(frame, chunks[0], tab, checks);
    chunks[1]
}

fn render_status_header(frame: &mut Frame, area: Rect, tab: &TabState, checks: &[CheckId]) {
    let mut spans: Vec<Span> = Vec::new();
    for (i, &id) in checks.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let slot = tab.slot(id);
        let (glyph, color) = crate::ui::widgets::status_badge::badge(&slot.status);
        spans.push(Span::styled(
            format!("{glyph} {}", id.label()),
            Style::default().fg(color),
        ));
    }
    frame.render_widget(Line::from(spans), area);

    // Errors from every relevant check, concatenated below the badges if
    // there's room; panes with a body layout of their own show these
    // inline instead via `errors_paragraph`.
    let _ = area;
}

/// A dimmed placeholder for a pane whose check hasn't produced data yet
/// (not started, still running with nothing streamed in, or cancelled).
pub(super) fn empty_message(message: &str) -> Paragraph<'static> {
    Paragraph::new(message.to_string()).style(Style::default().fg(Color::DarkGray))
}

/// Renders a check's error list, when any, as dimmed red lines.
pub(super) fn errors_widget(errors: &[String]) -> Paragraph<'static> {
    let lines: Vec<Line> = errors
        .iter()
        .map(|e| {
            Line::from(Span::styled(
                format!("! {e}"),
                Style::default().fg(Color::Red),
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
