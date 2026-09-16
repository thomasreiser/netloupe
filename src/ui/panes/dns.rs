//! DNS pane: standard records, plus a "Discovery" panel covering AXFR/ANY/
//! DNSSEC zone-signing, Certificate Transparency subdomains (reused from
//! `CheckId::AltNames`), and the opt-in NSEC zone walk's results.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{empty_message, errors_widget, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::dns::ZoneSigning;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::ui::theme;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Dns]);
    let slot = tab.slot(CheckId::Dns);

    let Some(CheckUpdate::Dns(dns)) = &slot.update else {
        if is_waiting(&slot.status) {
            frame.render_widget(empty_message("resolving..."), body);
        } else {
            frame.render_widget(empty_message("no DNS data"), body);
        }
        return;
    };

    let mut rows: Vec<(String, String)> = Vec::new();
    for ip in &dns.a {
        rows.push(("A".to_string(), ip.to_string()));
    }
    for ip in &dns.aaaa {
        rows.push(("AAAA".to_string(), ip.to_string()));
    }
    for c in &dns.cnames {
        rows.push(("CNAME".to_string(), c.clone()));
    }
    for mx in &dns.mx {
        rows.push((
            "MX".to_string(),
            format!("{} {}", mx.preference, mx.exchange),
        ));
    }
    for ns in &dns.ns {
        rows.push(("NS".to_string(), ns.clone()));
    }
    if let Some(soa) = &dns.soa {
        rows.push((
            "SOA".to_string(),
            format!("{} {} serial={}", soa.mname, soa.rname, soa.serial),
        ));
    }
    for txt in &dns.txt {
        rows.push(("TXT".to_string(), txt.clone()));
    }
    for caa in &dns.caa {
        rows.push(("CAA".to_string(), caa.clone()));
    }
    for srv in &dns.srv {
        rows.push(("SRV".to_string(), srv.clone()));
    }
    for ptr in &dns.ptr {
        rows.push(("PTR".to_string(), ptr.clone()));
    }
    rows.push((
        "DNSSEC (AD bit)".to_string(),
        dns.authenticated_data.to_string(),
    ));

    // Capped, not sized to fit every row: a zone with many records (or a
    // long SAN-style list) would otherwise crowd the Discovery panel
    // below out entirely. `tab.scroll` reaches whatever rows don't fit.
    const MAX_TABLE_ROWS_SHOWN: u16 = 12;
    let table_height = (rows.len() as u16 + 1)
        .min(MAX_TABLE_ROWS_SHOWN)
        .min(area.height.saturating_sub(6));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(table_height),
            Constraint::Min(3),
            Constraint::Length(dns.errors.len().min(4) as u16),
        ])
        .split(body);

    crate::ui::widgets::kv_table::render(frame, chunks[0], &rows, tab.scroll);
    render_discovery(frame, chunks[1], tab, dns);
    if !dns.errors.is_empty() {
        frame.render_widget(errors_widget(&dns.errors), chunks[2]);
    }
}

fn label(text: &'static str) -> Span<'static> {
    Span::styled(
        format!("{text:<14}"),
        Style::default()
            .fg(theme::LABEL)
            .add_modifier(Modifier::BOLD),
    )
}

fn render_discovery(
    frame: &mut Frame,
    area: Rect,
    tab: &TabState,
    dns: &crate::checks::dns::DnsResult,
) {
    let block = theme::panel("Discovery", theme::pane_accent(crate::app::Pane::Dns));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    // DNSSEC zone signing + the opt-in walk it enables.
    let (signing_text, signing_color) = match dns.zone_signing {
        ZoneSigning::Nsec => (
            "NSEC — the zone can be walked name-by-name (press 'w')".to_string(),
            theme::YELLOW,
        ),
        ZoneSigning::Nsec3 => (
            "NSEC3 — hashed denial-of-existence, not walkable this way".to_string(),
            theme::GREEN,
        ),
        ZoneSigning::NotSignedOrUnknown => (
            "not DNSSEC-signed, or inconclusive".to_string(),
            theme::MUTED,
        ),
    };
    lines.push(Line::from(vec![
        label("Zone signing"),
        Span::styled(signing_text, Style::default().fg(signing_color)),
    ]));

    // AXFR: the interesting case (succeeded) gets shouted about; the
    // expected case (refused) stays quiet and reassuring.
    if dns.axfr.is_empty() {
        lines.push(Line::from(vec![
            label("AXFR"),
            Span::styled("not attempted", Style::default().fg(theme::MUTED)),
        ]));
    }
    for attempt in &dns.axfr {
        let (text, color) = if attempt.succeeded {
            (
                format!(
                    "⚠ {} allows zone transfer! ({} records)",
                    attempt.nameserver, attempt.record_count
                ),
                theme::RED,
            )
        } else {
            (
                format!("{} refused ({})", attempt.nameserver, attempt.detail),
                theme::MUTED,
            )
        };
        lines.push(Line::from(vec![
            label("AXFR"),
            Span::styled(
                text,
                Style::default()
                    .fg(color)
                    .add_modifier(if attempt.succeeded {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
        ]));
    }

    // ANY query.
    if !dns.any_records.is_empty() {
        for record in &dns.any_records {
            lines.push(Line::from(vec![
                label("ANY"),
                Span::styled(record.clone(), Style::default().fg(theme::TEXT)),
            ]));
        }
    } else if let Some(note) = dns.any_note {
        lines.push(Line::from(vec![
            label("ANY"),
            Span::styled(note, Style::default().fg(theme::MUTED)),
        ]));
    }

    // Certificate Transparency subdomains: reused from the AltNames check
    // (architecture rule 8 — no reason to query crt.sh twice for one tab).
    if let Some(CheckUpdate::AltNames(alt)) = &tab.slot(CheckId::AltNames).update {
        let ct_names: Vec<&str> = alt
            .names
            .iter()
            .filter(|n| {
                n.sources
                    .contains(&crate::checks::altnames::NameSource::CertificateTransparency)
            })
            .map(|n| n.name.as_str())
            .collect();
        if !ct_names.is_empty() {
            lines.push(Line::from(vec![
                label("CT log"),
                Span::styled(
                    format!("{} name(s) — see Overview / press 'a'", ct_names.len()),
                    Style::default().fg(theme::TEXT),
                ),
            ]));
        }
    }

    // The opt-in zone walk's own result: a walk against a real zone can
    // take dozens of seconds, so this distinguishes "still running" (the
    // check streams `Progress` updates as it goes) from a finished one
    // rather than looking identically "done" — or worse, silently
    // unchanged — the whole time it's working.
    let zone_walk_slot = tab.slot(CheckId::ZoneWalk);
    match &zone_walk_slot.update {
        Some(CheckUpdate::ZoneWalk(walk)) => {
            let running = matches!(zone_walk_slot.status, crate::app::CheckStatus::Running);
            let status = if running {
                "walking…"
            } else if walk.complete {
                "complete"
            } else {
                "stopped early"
            };
            lines.push(Line::from(vec![
                label("Zone walk"),
                Span::styled(
                    format!(
                        "{} name(s) found so far, {} ({} quer{})",
                        walk.names.len(),
                        status,
                        walk.queries_made,
                        if walk.queries_made == 1 { "y" } else { "ies" }
                    ),
                    Style::default().fg(if running { theme::YELLOW } else { theme::TEXT }),
                ),
            ]));
            // Not clipped to `inner`'s height here — the Paragraph's own
            // `scroll` (set below, from `tab.scroll`) reaches names past
            // what's visible at first; `zonewalk`'s own `MAX_NAMES` cap
            // already bounds this list to something reasonable.
            for name in &walk.names {
                lines.push(Line::from(Span::styled(
                    format!("  {name}"),
                    Style::default().fg(theme::MUTED),
                )));
            }
        }
        None if zone_walk_slot.status == crate::app::CheckStatus::Running => {
            lines.push(Line::from(vec![
                label("Zone walk"),
                Span::styled(
                    "walking… (no names yet)",
                    Style::default().fg(theme::YELLOW),
                ),
            ]));
        }
        _ if dns.zone_signing == ZoneSigning::Nsec => {
            lines.push(Line::from(vec![
                label("Zone walk"),
                Span::styled(
                    "not run — press 'w' to opt in",
                    Style::default().fg(theme::FAINT),
                ),
            ]));
        }
        _ => {}
    }

    frame.render_widget(Paragraph::new(lines).scroll((tab.scroll, 0)), inner);
}
