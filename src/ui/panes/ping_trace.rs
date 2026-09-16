//! Ping/Trace pane: live ICMP/TCP ping sparkline plus (once implemented)
//! an MTR-style hop list.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::ping::PingMethod;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::ui::theme;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Ping, CheckId::Trace]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .split(body);

    render_ping_summary(frame, chunks[0], tab);
    render_sparkline(frame, chunks[1], tab);
    render_trace(frame, chunks[2], tab);
}

fn rtt_color(d: Option<std::time::Duration>) -> ratatui::style::Color {
    d.map(|d| theme::gradient(((d.as_millis() as f64 - 15.0) / 185.0).clamp(0.0, 1.0)))
        .unwrap_or(theme::MUTED)
}

fn render_ping_summary(frame: &mut Frame, area: Rect, tab: &TabState) {
    let slot = tab.slot(CheckId::Ping);
    let Some(CheckUpdate::Ping(ping)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "pinging..."
            } else {
                "no ping data"
            }),
            area,
        );
        return;
    };

    let method = match ping.method {
        PingMethod::Icmp => "ICMP".to_string(),
        PingMethod::TcpConnect { port } => format!("TCP connect (port {port}, fallback)"),
    };
    let fmt_ms = |d: Option<std::time::Duration>| {
        d.map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string())
    };
    let loss = if ping.sent > 0 {
        100 - (ping.received * 100 / ping.sent)
    } else {
        0
    };
    let loss_color = theme::gradient(loss as f64 / 100.0);

    let label = |s: &'static str| {
        Span::styled(
            format!("{s:<15}"),
            Style::default()
                .fg(theme::LABEL)
                .add_modifier(Modifier::BOLD),
        )
    };

    let mut method_spans = vec![
        label("Method"),
        Span::styled(method, Style::default().fg(theme::TEXT)),
    ];
    if ping.paused {
        method_spans.push(Span::styled(
            "  ⏸ paused (space to resume)",
            Style::default()
                .fg(theme::YELLOW)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let lines = vec![
        Line::from(method_spans),
        Line::from(vec![
            label("Sent/received"),
            Span::styled(
                format!("{}/{} ", ping.sent, ping.received),
                Style::default().fg(theme::TEXT),
            ),
            Span::styled(
                format!("({loss}% loss)"),
                Style::default().fg(loss_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            label("min/avg/max"),
            Span::styled(fmt_ms(ping.min), Style::default().fg(rtt_color(ping.min))),
            Span::styled(" / ", Style::default().fg(theme::FAINT)),
            Span::styled(
                fmt_ms(ping.avg),
                Style::default()
                    .fg(rtt_color(ping.avg))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" / ", Style::default().fg(theme::FAINT)),
            Span::styled(fmt_ms(ping.max), Style::default().fg(rtt_color(ping.max))),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_sparkline(frame: &mut Frame, area: Rect, tab: &TabState) {
    let slot = tab.slot(CheckId::Ping);
    let Some(CheckUpdate::Ping(ping)) = &slot.update else {
        return;
    };
    if ping.samples.is_empty() {
        return;
    }
    let title = if ping.paused { "RTT (paused)" } else { "RTT" };
    let block = theme::panel(title, theme::pane_accent(crate::app::Pane::PingTrace));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        crate::ui::widgets::sparkline::widget(&ping.samples, inner.width),
        inner,
    );
}

fn render_trace(frame: &mut Frame, area: Rect, tab: &TabState) {
    let slot = tab.slot(CheckId::Trace);
    match &slot.status {
        crate::app::CheckStatus::Failed(message) => {
            frame.render_widget(super::errors_widget(std::slice::from_ref(message)), area)
        }
        _ => frame.render_widget(empty_message("traceroute: not implemented yet"), area),
    }
}
