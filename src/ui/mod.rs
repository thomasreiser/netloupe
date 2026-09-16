//! Rendering only: reads `AppState` and draws it. Never awaits, spawns
//! tasks, or mutates state (architecture rule 1 in `CLAUDE.md`).

pub mod panes;
pub mod tabs;
pub mod widgets;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{AppState, Mode};

pub fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    tabs::render_host_tabs(frame, chunks[0], state);
    tabs::render_pane_tabs(frame, chunks[1], state);

    match state.active() {
        Some(tab) => panes::render(frame, chunks[2], tab),
        None => frame.render_widget(
            Paragraph::new("No hosts open. Press Ctrl+t to add one.")
                .style(Style::default().fg(Color::DarkGray)),
            chunks[2],
        ),
    }

    render_status_line(frame, chunks[3], state);

    match &state.mode {
        Mode::NewHostPrompt(buf) => render_prompt(frame, area, buf),
        Mode::Help => render_help(frame, area),
        Mode::ConfirmPorts => render_confirm_ports(frame, area),
        Mode::Normal => {}
    }
}

fn render_status_line(frame: &mut Frame, area: Rect, state: &AppState) {
    let hint = "Ctrl+t new · Ctrl+w close · Tab switch host · ←/→ pane · r rerun · R rerun all · e evidence · ? help · q quit";
    let mut spans = vec![Span::styled(hint, Style::default().fg(Color::DarkGray))];
    if let Some(warning) = &state.data_age_warning {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(warning, Style::default().fg(Color::Yellow)));
    }
    frame.render_widget(Line::from(spans), area);
}

/// A centered floating box, sized to a fraction of the terminal.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn render_prompt(frame: &mut Frame, area: Rect, buf: &str) {
    let popup = centered_rect(60, 15, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" New host (Enter to open, Esc to cancel) ");
    let text = Paragraph::new(format!("{buf}_")).block(block);
    frame.render_widget(text, popup);
}

fn render_confirm_ports(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(60, 25, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Port scan ")
        .style(Style::default().fg(Color::Yellow));
    let text = Paragraph::new(
        "Scanning a host's ports without authorization may be illegal (e.g. §202c StGB in Germany).\n\
         Only scan hosts you own or are authorized to test.\n\n\
         Run the configured port scan against this host? [y/N]",
    )
    .block(block)
    .wrap(ratatui::widgets::Wrap { trim: true });
    frame.render_widget(text, popup);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(60, 60, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help (? or Esc to close) ");
    let lines = [
        "Ctrl+t / Ctrl+w   New tab / close tab",
        "Tab / Shift+Tab   Next / previous host tab",
        "1-9, 0, -, ←/→    Switch pane",
        "r                 Re-run checks for the current pane",
        "R                 Re-run all checks for the current host",
        "e                 Toggle evidence details (Hosting pane)",
        "y                 Copy the current pane as text",
        "?                 Help overlay",
        "q                 Quit",
    ]
    .map(|s| Line::from(Span::raw(s)));
    let text = Paragraph::new(lines.to_vec()).block(block);
    frame.render_widget(text, popup);
}
