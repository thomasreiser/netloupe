//! Ping/Trace pane: live ICMP/TCP ping sparkline plus (once implemented)
//! an MTR-style hop list.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use super::{empty_message, errors_widget, header_and_body, is_waiting};
use crate::app::{CheckStatus, TabState};
use crate::checks::ping::PingMethod;
use crate::checks::trace::{TraceMethod, TraceUpdate};
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
    if let CheckStatus::Failed(message) = &slot.status {
        frame.render_widget(errors_widget(std::slice::from_ref(message)), area);
        return;
    }

    let Some(CheckUpdate::Trace(trace)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "tracing route..."
            } else {
                "no traceroute data"
            }),
            area,
        );
        return;
    };

    let reason_height = if trace.fallback_reason.is_some() {
        3
    } else {
        0
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(reason_height),
            Constraint::Min(0),
        ])
        .split(area);

    render_trace_summary(frame, chunks[0], trace);
    if let Some(reason) = &trace.fallback_reason {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("· {reason}"),
                Style::default().fg(theme::gradient(0.5)),
            )))
            .wrap(Wrap { trim: true }),
            chunks[1],
        );
    }
    render_hop_table(frame, chunks[2], trace);
}

fn render_trace_summary(frame: &mut Frame, area: Rect, trace: &TraceUpdate) {
    let method = match trace.method {
        TraceMethod::Icmp => "ICMP".to_string(),
        TraceMethod::TcpConnect { port } => {
            format!("TCP connect (port {port}, fallback — no hop addresses)")
        }
    };
    let status = if trace.reached {
        "reached"
    } else if trace.hops.len() >= crate::checks::trace::MAX_HOPS as usize {
        "gave up (max hops)"
    } else {
        "running"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "Method  ",
                Style::default()
                    .fg(theme::LABEL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(method, Style::default().fg(theme::TEXT)),
            Span::styled("   ", Style::default()),
            Span::styled(status, Style::default().fg(theme::MUTED)),
        ])),
        area,
    );
}

fn render_hop_table(frame: &mut Frame, area: Rect, trace: &TraceUpdate) {
    if trace.hops.is_empty() {
        frame.render_widget(empty_message("tracing route..."), area);
        return;
    }

    let rows: Vec<Row> = trace
        .hops
        .iter()
        .map(|hop| {
            let addr = hop
                .addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "*".to_string());
            let rtt = hop
                .rtt
                .map(|d| format!("{}ms", d.as_millis()))
                .unwrap_or_else(|| "-".to_string());
            let provider = hop.provider.clone().unwrap_or_default();
            Row::new(vec![
                Cell::from(hop.ttl.to_string()).style(Style::default().fg(theme::LABEL)),
                Cell::from(addr).style(Style::default().fg(if hop.addr.is_some() {
                    theme::TEXT
                } else {
                    theme::MUTED
                })),
                Cell::from(rtt).style(Style::default().fg(rtt_color(hop.rtt))),
                Cell::from(provider).style(Style::default().fg(theme::MUTED)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(40),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(vec!["TTL", "Address", "RTT", "Provider"]).style(
            Style::default()
                .fg(theme::LABEL)
                .add_modifier(Modifier::BOLD),
        ),
    );

    frame.render_widget(table, area);
}
