//! TLS pane: chain, SANs, expiry, negotiated protocol/cipher.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

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

    if let Some(days) = tls.days_until_expiry {
        let label = if days < 0 {
            format!("EXPIRED {} day(s) ago", -days)
        } else {
            format!("{days} day(s)")
        };
        rows.push(("Expires in".to_string(), label));
    }
    for san in &tls.sans {
        rows.push(("SAN".to_string(), san.clone()));
    }

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), body);

    if tls.days_until_expiry.is_some_and(|d| d < 14) {
        let warn = ratatui::text::Line::from(ratatui::text::Span::styled(
            "⚠ certificate expiry is close or already past",
            Style::default().fg(Color::Red),
        ));
        let warn_area = Rect {
            y: body.y + body.height.saturating_sub(1),
            height: 1.min(body.height),
            ..body
        };
        frame.render_widget(warn, warn_area);
    }
}
