//! TLS pane: full per-certificate detail for the leaf (everything a "view
//! certificate" dialog would show -- serial, fingerprints, public key,
//! extensions, ...), a compact summary of the rest of the chain, and (for
//! a recognized CA) ACME DNS-01/HTTP-01 challenge analysis.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::acme::{AcmeInfo, ChallengeHint};
use crate::checks::tls::CertificateDetail;
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
    ];

    if let Some(leaf) = tls.chain.first() {
        rows.extend(leaf_certificate_rows(leaf));
    } else {
        rows.push((
            "Subject".to_string(),
            tls.subject.clone().unwrap_or_else(|| "-".to_string()),
        ));
        rows.push((
            "CA".to_string(),
            tls.acme
                .as_ref()
                .map(|a| a.authority.name())
                .or_else(|| tls.issuer.clone())
                .unwrap_or_else(|| "-".to_string()),
        ));
        for san in &tls.sans {
            rows.push(("SAN".to_string(), san.clone()));
        }
    }

    for (i, cert) in tls.chain.iter().enumerate().skip(1) {
        rows.push((
            format!("Chain #{i}"),
            format!(
                "{} — issued by {}, expires {}, {} ({}-bit {})",
                cert.subject,
                cert.issuer,
                format_unix_date(cert.not_after_unix),
                cert.signature_algorithm,
                cert.public_key_bits,
                cert.public_key_algorithm,
            ),
        ));
    }

    let expiry_height = if tls.days_until_expiry.is_some() {
        1
    } else {
        0
    };
    // Cap the table's height rather than always requesting exactly what
    // every row (SANs included — some certs carry dozens) would need:
    // a large request here would starve the ACME panel below it of any
    // space at all. Scrolling (via `tab.scroll`) reaches whatever rows
    // don't fit rather than losing them off-screen.
    let reserved_for_acme = if tls.acme.is_some() { 6 } else { 0 };
    // + 2: the blank row `spacing(1)` puts between each of this
    // layout's 3 regions.
    let max_table_height = body
        .height
        .saturating_sub(expiry_height)
        .saturating_sub(reserved_for_acme)
        .saturating_sub(2)
        .max(3);
    let table_height = (rows.len() as u16 + 1).min(max_table_height);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(expiry_height),
            Constraint::Length(table_height),
            Constraint::Min(0),
        ])
        .spacing(1)
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

    crate::ui::widgets::kv_table::render(frame, chunks[1], &rows, tab.scroll);

    if let Some(acme) = &tls.acme {
        let block = theme::panel(
            "Certificate issuance",
            theme::pane_accent(crate::app::Pane::Tls),
        );
        let inner = block
            .inner(chunks[2])
            .inner(ratatui::layout::Margin::new(1, 0));
        frame.render_widget(block, chunks[2]);
        frame.render_widget(
            Paragraph::new(acme_lines(acme)).wrap(Wrap { trim: false }),
            inner,
        );
    }
}

fn format_unix_date(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| unix.to_string())
}

/// Everything a "view certificate" dialog would show for one certificate,
/// as kv_table rows -- used for the leaf (the only one shown in full;
/// the rest of the chain gets one summary line each, see `Chain #N`).
fn leaf_certificate_rows(cert: &CertificateDetail) -> Vec<(String, String)> {
    let mut rows = vec![
        ("Subject".to_string(), cert.subject.clone()),
        (
            "CA".to_string(),
            if cert.is_self_signed {
                format!("{} (self-signed)", cert.issuer)
            } else {
                cert.issuer.clone()
            },
        ),
        ("Serial".to_string(), cert.serial_number.clone()),
        ("X.509 version".to_string(), format!("v{}", cert.version)),
        (
            "Valid from".to_string(),
            format_unix_date(cert.not_before_unix),
        ),
        (
            "Valid until".to_string(),
            format_unix_date(cert.not_after_unix),
        ),
        (
            "Signature algo".to_string(),
            cert.signature_algorithm.clone(),
        ),
        (
            "Public key".to_string(),
            format!(
                "{} ({}-bit)",
                cert.public_key_algorithm, cert.public_key_bits
            ),
        ),
        (
            "SHA-256 fingerprint".to_string(),
            cert.sha256_fingerprint.clone(),
        ),
        (
            "SHA-1 fingerprint".to_string(),
            cert.sha1_fingerprint.clone(),
        ),
        (
            "Is CA".to_string(),
            match (cert.is_ca, cert.path_len_constraint) {
                (true, Some(n)) => format!("yes (path length constraint: {n})"),
                (true, None) => "yes".to_string(),
                (false, _) => "no".to_string(),
            },
        ),
    ];
    if !cert.key_usage.is_empty() {
        rows.push(("Key usage".to_string(), cert.key_usage.join(", ")));
    }
    if !cert.extended_key_usage.is_empty() {
        rows.push((
            "Extended key usage".to_string(),
            cert.extended_key_usage.join(", "),
        ));
    }
    if let Some(ski) = &cert.subject_key_identifier {
        rows.push(("Subject key ID".to_string(), ski.clone()));
    }
    if let Some(aki) = &cert.authority_key_identifier {
        rows.push(("Authority key ID".to_string(), aki.clone()));
    }
    for url in &cert.crl_distribution_points {
        rows.push(("CRL".to_string(), url.clone()));
    }
    for url in &cert.ocsp_urls {
        rows.push(("OCSP".to_string(), url.clone()));
    }
    for url in &cert.ca_issuers_urls {
        rows.push(("CA Issuers".to_string(), url.clone()));
    }
    if cert.sct_count > 0 {
        rows.push(("CT (embedded SCTs)".to_string(), cert.sct_count.to_string()));
    }
    for san in &cert.sans {
        rows.push(("SAN".to_string(), san.clone()));
    }
    rows
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
        ChallengeHint::UncertainAcmeUsage => {
            if let Some(note) = acme.note {
                lines.push(Line::from(Span::styled(
                    note,
                    Style::default().fg(theme::MUTED),
                )));
            }
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
        ChallengeHint::UncertainAcmeUsage => (
            if acme.is_wildcard {
                "unclear whether ACME was used at all — if it was, DNS-01 is the only possibility (wildcard), but this CA also issues outside ACME".to_string()
            } else {
                "unclear whether ACME was used at all — this CA also issues outside ACME for its own domains".to_string()
            },
            theme::BLUE,
        ),
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
    if http01.looks_valid {
        return vec![
            Line::from(vec![
                label("HTTP-01"),
                Span::styled(
                    format!(
                        "responder still active (status {}, valid key authorization)",
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
                Span::styled(
                    http01.body_sample.clone().unwrap_or_default(),
                    Style::default().fg(theme::TEXT),
                ),
            ]),
        ];
    }
    // A non-empty (even HTTP-200) response here isn't evidence of
    // anything by itself -- a 404 page, a WAF block page, or a directory
    // listing all return one too, with nothing to do with ACME. Only
    // `looks_valid` (a well-formed key authorization) earns the green
    // "still active" text above; anything else says plainly that
    // whatever came back isn't real evidence, rather than implying it
    // might be.
    let text = match (&http01.status, &http01.body_sample, &http01.error) {
        (Some(status), Some(_), _) => format!(
            "{status} at /.well-known/acme-challenge/ (a response, but not a valid key authorization — not ACME evidence)"
        ),
        (Some(status), None, _) => {
            format!("{status} at /.well-known/acme-challenge/ (no active challenge — expected)")
        }
        (None, _, Some(err)) => format!("unreachable ({err})"),
        (None, _, None) => "unreachable".to_string(),
    };
    vec![Line::from(vec![
        label("HTTP-01"),
        Span::styled(text, Style::default().fg(theme::FAINT)),
    ])]
}
