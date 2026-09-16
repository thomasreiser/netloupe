//! TLS pane: chain, SANs, expiry, negotiated protocol/cipher, and (for a
//! recognized CA) ACME DNS-01/HTTP-01 challenge analysis.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::acme::{AcmeInfo, ChallengeHint};
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
            "CA".to_string(),
            tls.acme
                .as_ref()
                .map(|a| a.authority.name())
                .or_else(|| tls.issuer.clone())
                .unwrap_or_else(|| "-".to_string()),
        ),
    ];
    for san in &tls.sans {
        rows.push(("SAN".to_string(), san.clone()));
    }

    let expiry_height = if tls.days_until_expiry.is_some() {
        1
    } else {
        0
    };
    let table_height = rows.len() as u16 + 1;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(expiry_height),
            Constraint::Length(table_height),
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

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), chunks[1]);

    if let Some(acme) = &tls.acme {
        let block = theme::panel(
            "Certificate issuance",
            theme::pane_accent(crate::app::Pane::Tls),
        );
        let inner = block.inner(chunks[2]);
        frame.render_widget(block, chunks[2]);
        frame.render_widget(
            Paragraph::new(acme_lines(acme)).wrap(Wrap { trim: false }),
            inner,
        );
    }
}

fn label(text: &'static str) -> Span<'static> {
    Span::styled(
        format!("{text:<11}"),
        Style::default()
            .fg(theme::LABEL)
            .add_modifier(Modifier::BOLD),
    )
}

fn acme_lines(acme: &AcmeInfo) -> Vec<Line<'static>> {
    let mut lines = vec![method_line(acme)];

    match acme.challenge_hint {
        ChallengeHint::NotPublicAcme => {
            if let Some(note) = acme.note {
                lines.push(Line::from(Span::styled(
                    note,
                    Style::default().fg(theme::MUTED),
                )));
            }
        }
        ChallengeHint::Dns01Certain | ChallengeHint::EitherMethodPossible => {
            lines.extend(dns01_lines(acme));
            if let Some(http01) = &acme.http01 {
                lines.extend(http01_lines(http01));
            }
        }
    }

    lines
}

fn method_line(acme: &AcmeInfo) -> Line<'static> {
    let (text, color): (String, Color) = match acme.challenge_hint {
        ChallengeHint::Dns01Certain => (
            "DNS-01 — certain: a wildcard cert can only be proven via DNS".to_string(),
            theme::GREEN,
        ),
        ChallengeHint::EitherMethodPossible => (
            "DNS-01 or HTTP-01 — not determinable from the certificate after issuance".to_string(),
            theme::MUTED,
        ),
        ChallengeHint::NotPublicAcme => ("not public ACME".to_string(), theme::BLUE),
    };
    Line::from(vec![
        label("Method"),
        Span::styled(text, Style::default().fg(color)),
    ])
}

fn dns01_lines(acme: &AcmeInfo) -> Vec<Line<'static>> {
    let Some(dns01) = &acme.dns01 else {
        return Vec::new();
    };
    if dns01.is_empty() {
        return vec![Line::from(vec![
            label("DNS-01"),
            Span::styled(
                "no _acme-challenge record right now (expected — cleaned up after validation)",
                Style::default().fg(theme::FAINT),
            ),
        ])];
    }

    let mut lines = Vec::new();
    for (i, value) in dns01.txt_values.iter().enumerate() {
        lines.push(Line::from(vec![
            label(if i == 0 { "DNS-01 TXT" } else { "" }),
            Span::styled(value.clone(), Style::default().fg(theme::GREEN)),
        ]));
    }
    if let Some(target) = &dns01.cname_target {
        lines.push(Line::from(vec![
            label("DNS-01 CNAME"),
            Span::styled(target.clone(), Style::default().fg(theme::GREEN)),
        ]));
    }
    lines
}

fn http01_lines(http01: &crate::checks::acme::Http01Evidence) -> Vec<Line<'static>> {
    if let Some(body) = &http01.body_sample {
        return vec![
            Line::from(vec![
                label("HTTP-01"),
                Span::styled(
                    format!(
                        "responder still active (status {})",
                        http01
                            .status
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "?".to_string())
                    ),
                    Style::default().fg(theme::GREEN),
                ),
            ]),
            Line::from(vec![
                label(""),
                Span::styled(body.clone(), Style::default().fg(theme::TEXT)),
            ]),
        ];
    }
    let text = match (&http01.status, &http01.error) {
        (Some(status), _) => {
            format!("{status} at /.well-known/acme-challenge/ (no active challenge — expected)")
        }
        (None, Some(err)) => format!("unreachable ({err})"),
        (None, None) => "unreachable".to_string(),
    };
    vec![Line::from(vec![
        label("HTTP-01"),
        Span::styled(text, Style::default().fg(theme::FAINT)),
    ])]
}
