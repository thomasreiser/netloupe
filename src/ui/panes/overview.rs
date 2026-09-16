//! Overview pane: a dashboard of small cards, each pulling the headline
//! fact from one other check — IPs, ASN, provider badges, country, ping
//! stats, cert expiry, SPF/DMARC/DNSSEC status — so a first glance answers
//! "what is this host".

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::providers::Layer;
use crate::ui::theme;

const OVERVIEW_CHECKS: &[CheckId] = &[
    CheckId::Dns,
    CheckId::IpInfo,
    CheckId::Hosting,
    CheckId::Tls,
    CheckId::Mail,
    CheckId::Ping,
];

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = super::header_and_body(frame, area, tab, OVERVIEW_CHECKS);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(rows[0]);
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(rows[1]);

    card(frame, top[0], "TARGET", theme::CYAN, target_lines(tab));
    card(frame, top[1], "NETWORK", theme::BLUE, network_lines(tab));
    card(
        frame,
        top[2],
        "HOSTING",
        theme::pane_accent(crate::app::Pane::Hosting),
        hosting_lines(tab),
    );
    card(
        frame,
        bottom[0],
        "SECURITY",
        theme::pane_accent(crate::app::Pane::Mail),
        security_lines(tab),
    );
    card(
        frame,
        bottom[1],
        "LOCATION",
        theme::pane_accent(crate::app::Pane::Geo),
        location_lines(tab),
    );
    card(
        frame,
        bottom[2],
        "LATENCY",
        theme::pane_accent(crate::app::Pane::PingTrace),
        latency_lines(tab),
    );
}

fn card(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    accent: ratatui::style::Color,
    lines: Vec<Line<'static>>,
) {
    let block = theme::panel(title, accent);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines), inner);
}

fn kv(key: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{key:<11}"),
            Style::default()
                .fg(theme::LABEL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.into(), Style::default().fg(theme::TEXT)),
    ])
}

fn dash() -> String {
    "-".to_string()
}

fn target_lines(tab: &TabState) -> Vec<Line<'static>> {
    let mut lines = vec![kv("Host", tab.target.display())];
    if let Some(CheckUpdate::Dns(dns)) = &tab.slot(CheckId::Dns).update {
        let ips: Vec<String> = dns
            .a
            .iter()
            .map(ToString::to_string)
            .chain(dns.aaaa.iter().map(ToString::to_string))
            .collect();
        for (i, ip) in ips.iter().take(3).enumerate() {
            lines.push(kv(if i == 0 { "IPs" } else { "" }, ip.clone()));
        }
        if ips.is_empty() {
            lines.push(kv("IPs", dash()));
        }
    }
    lines
}

fn network_lines(tab: &TabState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(CheckUpdate::IpInfo(info)) = &tab.slot(CheckId::IpInfo).update {
        match &info.asn {
            Some(asn) => {
                lines.push(kv("ASN", format!("AS{}", asn.asn)));
                lines.push(kv("Org", asn.as_name.clone().unwrap_or_else(dash)));
                lines.push(kv("Registry", asn.registry.clone()));
            }
            None => lines.push(kv("ASN", "unknown")),
        }
        lines.push(kv("Class", info.class.label()));
    } else {
        lines.push(kv("ASN", "..."));
    }
    lines
}

fn hosting_lines(tab: &TabState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(CheckUpdate::Hosting(detections)) = &tab.slot(CheckId::Hosting).update {
        for layer in [Layer::Edge, Layer::Origin, Layer::Dns] {
            if let Some(d) = detections.iter().find(|d| d.layer == layer) {
                let conf_color = theme::confidence_color(d.confidence);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:<11}", format!("{layer}")),
                        Style::default()
                            .fg(theme::LABEL)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(d.provider_name.clone(), Style::default().fg(theme::TEXT)),
                    Span::raw(" "),
                    theme::pill(d.confidence.to_string(), conf_color),
                ]));
            }
        }
        if lines.is_empty() {
            lines.push(kv("Provider", "none detected"));
        }
    } else {
        lines.push(kv("Provider", "..."));
    }
    lines
}

fn security_lines(tab: &TabState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(CheckUpdate::Mail(mail)) = &tab.slot(CheckId::Mail).update {
        lines.push(bool_line("SPF", mail.spf.is_some()));
        lines.push(bool_line("DMARC", mail.dmarc.is_some()));
    }
    if let Some(CheckUpdate::Dns(dns)) = &tab.slot(CheckId::Dns).update {
        lines.push(bool_line("DNSSEC", dns.authenticated_data));
    }
    if let Some(CheckUpdate::Tls(tls)) = &tab.slot(CheckId::Tls).update {
        if let Some(days) = tls.days_until_expiry {
            let color = theme::gradient(1.0 - (days as f64 / 60.0).clamp(0.0, 1.0));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:<11}", "Cert"),
                    Style::default()
                        .fg(theme::LABEL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{days}d left"), Style::default().fg(color)),
            ]));
        }
    }
    if lines.is_empty() {
        lines.push(kv("Status", "..."));
    }
    lines
}

fn bool_line(label: &str, ok: bool) -> Line<'static> {
    let (glyph, color) = if ok {
        ("✓", theme::GREEN)
    } else {
        ("✗", theme::RED)
    };
    Line::from(vec![
        Span::styled(
            format!("{label:<11}"),
            Style::default()
                .fg(theme::LABEL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            glyph,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn location_lines(tab: &TabState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(CheckUpdate::Geo(geo)) = &tab.slot(CheckId::Geo).update {
        if let Some(country) = &geo.country {
            lines.push(kv("Country", country.clone()));
        }
        if let Some(city) = &geo.city {
            lines.push(kv("City", city.clone()));
        }
        if let Some(tz) = &geo.timezone {
            lines.push(kv("Timezone", tz.clone()));
        }
        if lines.is_empty() {
            lines.push(kv("Geo", "no database configured"));
        }
    } else {
        lines.push(kv("Geo", "..."));
    }
    lines
}

fn latency_lines(tab: &TabState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(CheckUpdate::Ping(ping)) = &tab.slot(CheckId::Ping).update {
        let fmt = |d: Option<std::time::Duration>| {
            d.map(|d| format!("{}ms", d.as_millis()))
                .unwrap_or_else(dash)
        };
        let color = ping
            .avg
            .map(|d| theme::gradient(((d.as_millis() as f64 - 15.0) / 185.0).clamp(0.0, 1.0)))
            .unwrap_or(theme::MUTED);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<11}", "Avg RTT"),
                Style::default()
                    .fg(theme::LABEL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                fmt(ping.avg),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(kv(
            "Min/Max",
            format!("{} / {}", fmt(ping.min), fmt(ping.max)),
        ));
        let loss = if ping.sent > 0 {
            100 - (ping.received * 100 / ping.sent)
        } else {
            0
        };
        lines.push(kv("Loss", format!("{loss}%")));
    } else {
        lines.push(kv("Ping", "..."));
    }
    lines
}
