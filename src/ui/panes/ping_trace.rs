//! Ping/Trace pane: live ICMP/TCP ping sparkline plus (once implemented)
//! an MTR-style hop list.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::Block;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::ping::PingMethod;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

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

    let mut rows = vec![
        ("Method".to_string(), method),
        (
            "Sent/received".to_string(),
            format!("{}/{} ({loss}% loss)", ping.sent, ping.received),
        ),
        (
            "min/avg/max".to_string(),
            format!(
                "{} / {} / {}",
                fmt_ms(ping.min),
                fmt_ms(ping.avg),
                fmt_ms(ping.max)
            ),
        ),
    ];
    if let Some(reason) = &ping.fallback_reason {
        rows.push(("Note".to_string(), reason.clone()));
    }
    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), area);
}

fn render_sparkline(frame: &mut Frame, area: Rect, tab: &TabState) {
    let slot = tab.slot(CheckId::Ping);
    let Some(CheckUpdate::Ping(ping)) = &slot.update else {
        return;
    };
    if ping.samples.is_empty() {
        return;
    }
    let block = Block::bordered().title(" RTT (ms) ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(crate::ui::widgets::sparkline::widget(&ping.samples), inner);
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
