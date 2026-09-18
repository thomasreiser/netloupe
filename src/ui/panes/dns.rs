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
use crate::ui::widgets::record_table::RecordRow;

/// A record's TTL as shown in a table cell: raw seconds with an "s"
/// suffix, or "-" for a synthetic row or one with no TTL to show (see
/// `DnsRecordRow::ttl`'s doc comment for why PTR is the one real record
/// type that falls in the latter case).
fn ttl_text(ttl: Option<u32>) -> String {
    match ttl {
        Some(t) => format!("{t}s"),
        None => "-".to_string(),
    }
}

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Dns, CheckId::Whois]);
    let slot = tab.slot(CheckId::Dns);

    let Some(CheckUpdate::Dns(dns)) = &slot.update else {
        if is_waiting(&slot.status) {
            frame.render_widget(empty_message("resolving..."), body);
        } else {
            frame.render_widget(empty_message("no DNS data"), body);
        }
        return;
    };

    // The zone tree gets a fixed right-hand column on any reasonably wide
    // terminal; a narrower one just keeps the pane's full width for its
    // main content, the same as before this section existed.
    const TREE_WIDTH: u16 = 32;
    const MIN_WIDTH_FOR_TREE: u16 = 90;
    let (body, tree_area) = if body.width >= MIN_WIDTH_FOR_TREE {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(TREE_WIDTH)])
            .spacing(1)
            .split(body);
        (split[0], Some(split[1]))
    } else {
        (body, None)
    };
    if let Some(tree_area) = tree_area {
        render_zone_tree(frame, tree_area, dns);
    }

    // Nameservers get their own section below, so they're excluded here
    // rather than shown twice.
    let mut record_rows: Vec<RecordRow> = Vec::new();
    for record in dns.records.iter().filter(|r| r.record_type != "NS") {
        record_rows.push(RecordRow {
            record_type: record.record_type.to_string(),
            value: record.value.clone(),
            ttl: ttl_text(record.ttl),
        });
    }
    record_rows.push(RecordRow {
        record_type: "DNSSEC".to_string(),
        value: format!("AD bit: {}", dns.authenticated_data),
        ttl: "-".to_string(),
    });

    let ns_rows: Vec<(String, String)> = dns
        .records
        .iter()
        .filter(|r| r.record_type == "NS")
        .map(|r| (r.value.clone(), ttl_text(r.ttl)))
        .collect();

    // The queried name's own NS records above are empty exactly when it
    // isn't a zone apex -- `dns.authority` then carries the enclosing
    // zone's SOA/NS instead (see `checks::dns::AuthorityZone`), the same
    // "AUTHORITY SECTION" `dig` shows in place of an answer. The two
    // never both apply, so this slot renders whichever is present.
    let authority = dns.authority.as_ref().filter(|_| ns_rows.is_empty());

    // Both tables are capped, not sized to fit every row: a zone with
    // many records (or many nameservers) would otherwise crowd the
    // Discovery panel out entirely. `tab.scroll` reaches whatever rows
    // don't fit in the main table; the nameservers list is short enough
    // in practice (almost always well under 10) that it isn't wired to
    // scroll separately.
    const MAX_TABLE_ROWS_SHOWN: u16 = 12;
    const MAX_NS_ROWS_SHOWN: u16 = 6;
    let ns_height = if !ns_rows.is_empty() {
        (ns_rows.len() as u16 + 3).min(MAX_NS_ROWS_SHOWN + 3)
    } else if let Some(authority) = authority {
        // +3 extra rows inside the panel for the "Zone"/"SOA" lines and
        // the blank row separating them from the NS sub-table, which
        // itself adds its own header row and border (+3).
        (authority.ns.len() as u16 + 3 + 3).min(MAX_NS_ROWS_SHOWN + 6)
    } else {
        0
    };
    let errors_height = dns.errors.len().min(4) as u16;
    // Reserves room for everything else the layout below needs (the
    // resolver line, the Nameservers section, the Discovery panel's own
    // `Min(3)`, any errors, and the blank row `spacing(1)` puts between
    // each of this layout's 5 regions -- 4 gaps) before capping the main
    // table's height, against `body.height` (the pane's actual content
    // area, already excluding the panel border and the status header)
    // rather than the outer `area` -- otherwise, on a short terminal,
    // the total requested height could exceed what's actually available
    // and ratatui's layout solver would shrink the table itself to make
    // room, potentially squeezing its header (and the TTL column with
    // it) out entirely rather than just leaving fewer Discovery rows
    // visible.
    let reserved_for_others = 1 + ns_height + 3 + errors_height + 4;
    let table_height = (record_rows.len() as u16 + 1)
        .min(MAX_TABLE_ROWS_SHOWN)
        .min(body.height.saturating_sub(reserved_for_others));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(table_height),
            Constraint::Length(ns_height),
            Constraint::Min(3),
            Constraint::Length(errors_height),
        ])
        .spacing(1)
        .split(body);

    let resolver_text = if dns.resolver == "system" {
        "system default".to_string()
    } else {
        dns.resolver.clone()
    };
    frame.render_widget(
        Line::from(vec![
            label("Resolver"),
            Span::styled(resolver_text, Style::default().fg(theme::TEXT)),
        ]),
        chunks[0],
    );

    crate::ui::widgets::record_table::render(frame, chunks[1], &record_rows, tab.scroll);
    if !ns_rows.is_empty() {
        render_nameservers(frame, chunks[2], &ns_rows);
    } else if let Some(authority) = authority {
        render_authority(frame, chunks[2], authority);
    }
    render_discovery(frame, chunks[3], tab, dns);
    if !dns.errors.is_empty() {
        frame.render_widget(errors_widget(&dns.errors), chunks[4]);
    }
}

fn render_nameservers(frame: &mut Frame, area: Rect, ns_rows: &[(String, String)]) {
    let block = theme::panel("Nameservers", theme::pane_accent(crate::app::Pane::Dns));
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    crate::ui::widgets::kv_table::render_with_header(
        frame,
        inner,
        ["NAMESERVER", "TTL"],
        ns_rows,
        0,
    );
}

/// The enclosing zone's SOA/NS for a queried name that isn't itself a
/// zone apex -- shown in place of "Nameservers" (never both; see the
/// `authority` filter in `render`) since the name's own NS lookup came
/// back empty.
fn render_authority(frame: &mut Frame, area: Rect, authority: &crate::checks::dns::AuthorityZone) {
    let block = theme::panel("Authority", theme::pane_accent(crate::app::Pane::Dns));
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);

    // The blank row at index 2 is a deliberate gap before the NS
    // sub-table -- it sets the SOA (a single, dense fact) visually apart
    // from the table of nameservers below.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Line::from(vec![
            label("Zone"),
            Span::styled(authority.zone.clone(), Style::default().fg(theme::TEXT)),
        ]),
        chunks[0],
    );
    frame.render_widget(
        Line::from(vec![
            label("SOA"),
            Span::styled(
                format!(
                    "{} {} serial={}",
                    authority.soa.mname, authority.soa.rname, authority.soa.serial
                ),
                Style::default().fg(theme::TEXT),
            ),
        ]),
        chunks[1],
    );

    if !authority.ns.is_empty() {
        let ns_rows: Vec<(String, String)> = authority
            .ns
            .iter()
            .map(|(name, ttl)| (name.clone(), ttl_text(Some(*ttl))))
            .collect();
        crate::ui::widgets::kv_table::render_with_header(
            frame,
            chunks[3],
            ["NAMESERVER", "TTL"],
            &ns_rows,
            0,
        );
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
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
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
            // Otherwise a walk that fails immediately (e.g. the zone
            // doesn't actually enter the NSEC chain the way the DNSSEC
            // probe that gated `w` suggested it would) looks identical
            // to one that simply hasn't found anything yet.
            for error in &walk.errors {
                lines.push(Line::from(Span::styled(
                    format!("  ⚠ {error}"),
                    Style::default().fg(theme::RED),
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

    render_whois(&mut lines, tab);
    render_delegation_trace(&mut lines, dns);

    let scroll = super::clamp_scroll(tab.scroll, lines.len(), inner.height);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

/// The domain's registration info (registrar, dates, status codes) --
/// from `CheckId::Whois`, a separate check reused here the same way
/// `CheckId::AltNames` feeds the CT log line above, since it's not a
/// pane of its own.
/// One node of the zone tree: its name, and whether it's a known
/// delegation boundary (a zone the delegation trace actually queried a
/// nameserver for) rather than just a plain label between one.
fn build_zone_tree_nodes(dns: &crate::checks::dns::DnsResult) -> Vec<(String, bool)> {
    let full_name = dns.queried_name.trim_end_matches('.').to_ascii_lowercase();
    if full_name.is_empty() {
        return Vec::new();
    }
    let labels: Vec<&str> = full_name.split('.').collect();
    let known_zones: std::collections::HashSet<String> = dns
        .delegation_trace
        .iter()
        .map(|h| h.zone.trim_end_matches('.').to_ascii_lowercase())
        .collect();

    (1..=labels.len())
        .map(|n| {
            let node = labels[labels.len() - n..].join(".");
            let is_zone_cut = known_zones.contains(&node);
            (node, is_zone_cut)
        })
        .collect()
}

/// A compact visual chain from the TLD down to the exact hostname being
/// inspected, shown in a fixed-width column to the right of the pane's
/// main content: the delegation trace's actual zone cuts (bold) plus any
/// remaining plain labels (dim) down to the queried name (highlighted).
fn render_zone_tree(frame: &mut Frame, area: Rect, dns: &crate::checks::dns::DnsResult) {
    let block = theme::panel("Zone tree", theme::pane_accent(crate::app::Pane::Dns));
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);

    let nodes = build_zone_tree_nodes(dns);
    let Some(last_index) = nodes.len().checked_sub(1) else {
        return;
    };
    let width = inner.width as usize;

    let mut lines: Vec<Line> = Vec::new();
    for (i, (node, is_zone_cut)) in nodes.iter().enumerate() {
        let is_current = i == last_index;
        // A leading marker, not a trailing "(NS)"/"this host" suffix:
        // truncation (below) only ever cuts the *end* of a line, so a
        // suffix would silently vanish for exactly the long names this
        // most needs to flag, while a marker up front always survives.
        let marker = if is_current {
            "▸"
        } else if *is_zone_cut {
            "●"
        } else {
            " "
        };
        let indent = " ".repeat(i);
        let text = truncate_for_tree(&format!("{marker} {indent}{node}"), width);
        let style = if is_current || *is_zone_cut {
            Style::default()
                .fg(theme::YELLOW)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::YELLOW)
        };
        lines.push(Line::from(Span::styled(text, style)));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Truncates `text` to at most `width` visible characters (marking the
/// cut with an ellipsis) instead of letting `Paragraph` word-wrap it --
/// generic word-wrap would split a tree line's leading marker/indent from
/// its name onto a fresh, unindented continuation line for any name too
/// long to fit, breaking the tree's visual structure rather than just
/// trimming it.
fn truncate_for_tree(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.chars().count() <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(1);
    let mut truncated: String = text.chars().take(keep).collect();
    truncated.push('…');
    truncated
}

fn render_whois(lines: &mut Vec<Line<'static>>, tab: &TabState) {
    let slot = tab.slot(CheckId::Whois);
    let Some(CheckUpdate::Whois(whois)) = &slot.update else {
        if is_waiting(&slot.status) {
            lines.push(Line::from(vec![
                label("WHOIS"),
                Span::styled("looking up…", Style::default().fg(theme::MUTED)),
            ]));
        }
        return;
    };

    let Some(info) = &whois.info else {
        // Both RDAP and WHOIS failed outright -- rare, but worth a single
        // line rather than silently showing nothing.
        if let Some(err) = whois.errors.last() {
            lines.push(Line::from(vec![
                label("WHOIS"),
                Span::styled(err.clone(), Style::default().fg(theme::MUTED)),
            ]));
        }
        return;
    };

    let source_note = match &info.source {
        crate::checks::whois::WhoisSource::Rdap => String::new(),
        crate::checks::whois::WhoisSource::Whois(server) => format!(" (via WHOIS: {server})"),
    };

    if let Some(registrar) = &info.registrar {
        lines.push(Line::from(vec![
            label("Registrar"),
            Span::styled(
                format!("{registrar}{source_note}"),
                Style::default().fg(theme::TEXT),
            ),
        ]));
    }
    if info.created.is_some() || info.expires.is_some() || info.updated.is_some() {
        let text = [
            info.created.as_deref().map(|d| format!("created {d}")),
            info.expires.as_deref().map(|d| format!("expires {d}")),
            info.updated.as_deref().map(|d| format!("updated {d}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("  ·  ");
        lines.push(Line::from(vec![
            label("Registered"),
            Span::styled(text, Style::default().fg(theme::TEXT)),
        ]));
    }
    if !info.statuses.is_empty() {
        lines.push(Line::from(vec![
            label("Status"),
            Span::styled(info.statuses.join(", "), Style::default().fg(theme::TEXT)),
        ]));
    }
    if let Some(org) = &info.registrant_org {
        lines.push(Line::from(vec![
            label("Registrant"),
            Span::styled(org.clone(), Style::default().fg(theme::TEXT)),
        ]));
    }
}

/// A `dig +trace`-style delegation walk, appended below Discovery's other
/// content: one line per hop, root first, showing which server answered
/// and what it delegated to -- or, at the final hop, that it answered
/// authoritatively instead.
fn render_delegation_trace(lines: &mut Vec<Line<'static>>, dns: &crate::checks::dns::DnsResult) {
    if dns.delegation_trace.is_empty() {
        return;
    }
    lines.push(Line::from(Span::styled(
        "Delegation trace (dig +trace)",
        Style::default()
            .fg(theme::MUTED)
            .add_modifier(Modifier::BOLD),
    )));
    for hop in &dns.delegation_trace {
        let detail = if hop.delegates_to.is_empty() {
            format!(
                "authoritative answer from {} ({}ms)",
                hop.answered_by,
                hop.rtt.as_millis()
            )
        } else {
            const MAX_NAMES_SHOWN: usize = 3;
            let mut names = hop
                .delegates_to
                .iter()
                .take(MAX_NAMES_SHOWN)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if hop.delegates_to.len() > MAX_NAMES_SHOWN {
                names.push_str(&format!(
                    ", +{} more",
                    hop.delegates_to.len() - MAX_NAMES_SHOWN
                ));
            }
            format!(
                "→ {names}  (via {}, {}ms)",
                hop.answered_by,
                hop.rtt.as_millis()
            )
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<24}", hop.zone),
                Style::default().fg(theme::LABEL),
            ),
            Span::styled(detail, Style::default().fg(theme::TEXT)),
        ]));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::checks::dns::{DelegationHop, DnsResult};

    fn dns_result_for(queried_name: &str, delegation_trace: Vec<DelegationHop>) -> DnsResult {
        DnsResult {
            queried_name: queried_name.to_string(),
            delegation_trace,
            ..Default::default()
        }
    }

    #[test]
    fn build_zone_tree_nodes_marks_delegation_trace_zones_as_zone_cuts() {
        let dns = dns_result_for(
            "admin.ft.europe.d3vw-i.com",
            vec![
                DelegationHop {
                    zone: "com.".to_string(),
                    answered_by: "a.root-servers.net (198.41.0.4)".to_string(),
                    delegates_to: vec!["a.gtld-servers.net.".to_string()],
                    rtt: Duration::from_millis(1),
                },
                DelegationHop {
                    zone: "d3vw-i.com.".to_string(),
                    answered_by: "a.gtld-servers.net. (192.5.6.30)".to_string(),
                    delegates_to: Vec::new(),
                    rtt: Duration::from_millis(1),
                },
            ],
        );
        let nodes = build_zone_tree_nodes(&dns);
        assert_eq!(
            nodes,
            vec![
                ("com".to_string(), true),
                ("d3vw-i.com".to_string(), true),
                ("europe.d3vw-i.com".to_string(), false),
                ("ft.europe.d3vw-i.com".to_string(), false),
                ("admin.ft.europe.d3vw-i.com".to_string(), false),
            ]
        );
    }

    #[test]
    fn build_zone_tree_nodes_handles_a_bare_apex_with_no_trace_data() {
        let dns = dns_result_for("example.com", Vec::new());
        let nodes = build_zone_tree_nodes(&dns);
        assert_eq!(
            nodes,
            vec![
                ("com".to_string(), false),
                ("example.com".to_string(), false),
            ]
        );
    }

    #[test]
    fn build_zone_tree_nodes_is_empty_for_an_empty_queried_name() {
        let dns = dns_result_for("", Vec::new());
        assert!(build_zone_tree_nodes(&dns).is_empty());
    }

    #[test]
    fn truncate_for_tree_leaves_short_text_untouched() {
        assert_eq!(truncate_for_tree("▸ com", 20), "▸ com".to_string());
    }

    #[test]
    fn truncate_for_tree_marks_a_cut_with_an_ellipsis_and_keeps_the_leading_marker() {
        let text = "▸ admin.ft.europe.example.com";
        let truncated = truncate_for_tree(text, 10);
        assert_eq!(truncated.chars().count(), 10);
        assert!(truncated.starts_with('▸'));
        assert!(truncated.ends_with('…'));
    }
}
