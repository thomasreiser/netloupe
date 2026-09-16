//! TLS pane: chain, SANs, expiry, negotiated protocol/cipher.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::ui::theme;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Tls]);
    let slot = tab.slot(CheckId::Tls);

    let Some(CheckUpdate::Tls(tls)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "connecting..."
            } else {
                "no TLS data"
            }),
            body,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if tls.days_until_expiry.is_some() {
                1
            } else {
                0
            }),
            Constraint::Min(0),
        ])
        .split(body);

    if let Some(days) = tls.days_until_expiry {
        let color = theme::gradient(1.0 - (days as f64 / 60.0).clamp(0.0, 1.0));
        let label = if days < 0 {
            format!("EXPIRED {} day(s) ago", -days)
        } else {
            format!("{days} day(s) until expiry")
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("⬤ ", Style::default().fg(color)),
                Span::styled(
                    label,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            ])),
            chunks[0],
        );
    }

    let mut rows: Vec<(String, String)> = vec![
        (
            "Host:port".to_string(),
            format!("{}:{}", tls.host, tls.port),
        ),
        (
            "Protocol".to_string(),
            tls.protocol_version
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Cipher suite".to_string(),
            tls.cipher_suite.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "ALPN".to_string(),
            tls.alpn.clone().unwrap_or_else(|| "-".to_string()),
        ),
        ("Chain length".to_string(), tls.chain_len.to_string()),
        (
            "Subject".to_string(),
            tls.subject.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Issuer".to_string(),
            tls.issuer.clone().unwrap_or_else(|| "-".to_string()),
        ),
    ];
    for san in &tls.sans {
        rows.push(("SAN".to_string(), san.clone()));
    }

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), chunks[1]);
}
