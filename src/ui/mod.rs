//! Rendering only: reads `AppState` and draws it. Never awaits, spawns
//! tasks, or mutates state (architecture rule 1 in `CLAUDE.md`).

pub mod panes;
pub mod tabs;
pub mod theme;
pub mod widgets;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{AppState, Mode};

pub fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    let frame_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::FAINT))
        .title(Line::from(Span::styled(
            " netloupe ",
            Style::default()
                .fg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )))
        .title(
            Line::from(Span::styled(" ? help ", Style::default().fg(theme::MUTED))).right_aligned(),
        );
    let inner = frame_block.inner(area);
    frame.render_widget(frame_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .margin(0)
        .split(inner);

    tabs::render_host_tabs(frame, chunks[0], state);
    tabs::render_pane_tabs(frame, chunks[1], state);

    match state.active() {
        Some(tab) => panes::render(frame, chunks[2], tab, &state.geoip),
        None => frame.render_widget(
            Paragraph::new("No hosts open. Press Ctrl+t to add one.")
                .style(Style::default().fg(theme::MUTED)),
            chunks[2],
        ),
    }

    render_status_line(frame, chunks[3], state);

    match &state.mode {
        Mode::NewHostPrompt(buf) => render_prompt(frame, area, buf),
        Mode::Help => render_help(frame, area),
        Mode::ConfirmPorts => render_confirm_ports(frame, area),
        Mode::ConfirmZoneWalk => render_confirm_zone_walk(frame, area, state),
        Mode::SelectAltName { names, selected } => {
            render_select_alt_name(frame, area, names, *selected)
        }
        Mode::ChooseResolver { target, input } => {
            render_choose_resolver(frame, area, target, input)
        }
        Mode::Settings {
            draft,
            selected,
            editing,
            message,
        } => render_settings(
            frame,
            area,
            draft,
            *selected,
            editing.as_deref(),
            message.as_deref(),
        ),
        Mode::Normal => {}
    }
}

fn render_status_line(frame: &mut Frame, area: Rect, state: &AppState) {
    let key = |k: &'static str| {
        Span::styled(
            k,
            Style::default()
                .fg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
    };
    let desc = |d: &'static str| Span::styled(d, Style::default().fg(theme::MUTED));
    let sep = || Span::styled("  ", Style::default().fg(theme::FAINT));

    let mut spans = vec![
        key("^T"),
        desc(" new "),
        sep(),
        key("^W"),
        desc(" close "),
        sep(),
        key("Tab"),
        desc(" host "),
        sep(),
        key("←/→"),
        desc(" pane "),
        sep(),
        key("↑/↓"),
        desc(" scroll "),
        sep(),
        key("r"),
        desc(" rerun "),
        sep(),
        key("R"),
        desc(" rerun all "),
        sep(),
    ];

    // Only the keys that actually do something on the pane you're
    // looking at, rather than a fixed list that includes bindings like
    // `w` (zone walk) that are meaningless anywhere but DNS.
    let active_pane = state
        .active()
        .and_then(|tab| crate::app::Pane::ALL.get(tab.active_pane).copied());
    match active_pane {
        Some(crate::app::Pane::Overview) => {
            spans.push(key("a"));
            spans.push(desc(" alt. hosts "));
            spans.push(sep());
        }
        Some(crate::app::Pane::Dns) => {
            spans.push(key("w"));
            spans.push(desc(" zone walk "));
            spans.push(sep());
        }
        Some(crate::app::Pane::Hosting) => {
            spans.push(key("e"));
            spans.push(desc(" evidence "));
            spans.push(sep());
        }
        Some(crate::app::Pane::PingTrace) => {
            spans.push(key("space"));
            spans.push(desc(" pause ping "));
            spans.push(sep());
        }
        _ => {}
    }

    spans.push(key("y"));
    spans.push(desc(" copy "));
    spans.push(sep());
    spans.push(key("s"));
    spans.push(desc(" settings "));
    spans.push(sep());
    spans.push(key("q"));
    spans.push(desc(" quit"));
    if let Some(warning) = &state.data_age_warning {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("⚠ {warning}"),
            Style::default().fg(theme::YELLOW),
        ));
    }

    let geoip_text = state.geoip.status_text();
    let geoip_color = if state.geoip.downloading {
        theme::CYAN
    } else if !state.geoip.configured {
        theme::FAINT
    } else if state.geoip.last_error.is_some() && state.geoip.last_success.is_none() {
        theme::RED
    } else {
        theme::MUTED
    };
    // Split off a fixed-width right column for the GeoIP hint rather than
    // appending it to `spans`, so it stays pinned to the bottom-right
    // corner regardless of how long the keybinding hints on the left are.
    let right_width = geoip_text.chars().count() as u16 + 1;
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(right_width)])
        .split(area);
    frame.render_widget(Line::from(spans), columns[0]);
    frame.render_widget(
        Line::from(Span::styled(geoip_text, Style::default().fg(geoip_color))).right_aligned(),
        columns[1],
    );
}

/// A centered floating box, sized to a fraction of the terminal.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn render_prompt(frame: &mut Frame, area: Rect, buf: &str) {
    let popup = centered_rect(60, 15, area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint(
        "New host",
        "enter to open · esc to cancel",
        theme::MUTED,
        theme::CYAN,
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let text = Paragraph::new(Line::from(vec![
        Span::styled("❯ ", Style::default().fg(theme::CYAN)),
        Span::styled(buf, Style::default().fg(theme::TEXT)),
        Span::styled("▏", Style::default().fg(theme::CYAN)),
    ]));
    frame.render_widget(text, inner);
}

fn render_choose_resolver(
    frame: &mut Frame,
    area: Rect,
    target: &crate::target::Target,
    input: &str,
) {
    let popup = centered_rect(64, 20, area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint(
        "DNS server",
        "enter to confirm · esc to cancel",
        theme::MUTED,
        theme::CYAN,
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(1)])
        .split(inner);

    let prompt = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Query ", Style::default().fg(theme::MUTED)),
            Span::styled(
                target.display(),
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " using which DNS server?",
                Style::default().fg(theme::MUTED),
            ),
        ]),
        Line::from(Span::styled(
            "blank = system default",
            Style::default().fg(theme::FAINT),
        )),
    ]);
    frame.render_widget(prompt, chunks[0]);

    let text = Paragraph::new(Line::from(vec![
        Span::styled("❯ ", Style::default().fg(theme::CYAN)),
        Span::styled(input, Style::default().fg(theme::TEXT)),
        Span::styled("▏", Style::default().fg(theme::CYAN)),
    ]));
    frame.render_widget(text, chunks[1]);
}

fn render_settings(
    frame: &mut Frame,
    area: Rect,
    draft: &crate::config::Config,
    selected: usize,
    editing: Option<&str>,
    message: Option<&str>,
) {
    let popup = centered_rect(76, 80, area);
    frame.render_widget(Clear, popup);
    let hint = if editing.is_some() {
        "enter confirm · esc cancel edit"
    } else {
        "↑/↓ select · enter edit · esc close"
    };
    let block = theme::panel_with_hint("Settings", hint, theme::MUTED, theme::CYAN);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let fields = crate::settings::fields();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(if message.is_some() { 1 } else { 0 }),
        ])
        .split(inner);

    const LABEL_WIDTH: usize = 26;
    let items: Vec<ratatui::widgets::ListItem> = fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let value = if i == selected {
                editing
                    .map(str::to_string)
                    .unwrap_or_else(|| (field.get)(draft))
            } else {
                (field.get)(draft)
            };
            let value = if value.is_empty() {
                "-".to_string()
            } else {
                value
            };
            ratatui::widgets::ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<LABEL_WIDTH$}", field.label),
                    Style::default()
                        .fg(theme::LABEL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(value, Style::default().fg(theme::TEXT)),
            ]))
        })
        .collect();
    let list = ratatui::widgets::List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::Rgb(18, 18, 24))
                .bg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("❯ ");
    let mut list_state = ratatui::widgets::ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(list, chunks[0], &mut list_state);

    let help_text = fields.get(selected).map(|f| f.help).unwrap_or_default();
    let cursor = if editing.is_some() { "▏" } else { "" };
    frame.render_widget(
        Paragraph::new(vec![Line::from(Span::styled(
            format!("{help_text}{cursor}"),
            Style::default().fg(theme::FAINT),
        ))])
        .wrap(Wrap { trim: true }),
        chunks[1],
    );

    if let Some(message) = message {
        let color = if message.starts_with("saved") {
            theme::GREEN
        } else {
            theme::RED
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                message,
                Style::default().fg(color),
            ))),
            chunks[2],
        );
    }
}

fn render_confirm_ports(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(62, 30, area);
    frame.render_widget(Clear, popup);
    let block = theme::panel("⚠ Port scan", theme::ORANGE);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            "Scanning a host's ports without authorization may be illegal",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "(e.g. §202c StGB in Germany).",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "Only scan hosts you own or are authorized to test.",
            Style::default().fg(theme::MUTED),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "Run the configured port scan against this host?  ",
                Style::default().fg(theme::TEXT),
            ),
            Span::styled(
                "[y]",
                Style::default()
                    .fg(theme::GREEN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" / "),
            Span::styled(
                "[N]",
                Style::default().fg(theme::RED).add_modifier(Modifier::BOLD),
            ),
        ]),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(text, inner);
}

fn render_confirm_zone_walk(frame: &mut Frame, area: Rect, state: &AppState) {
    let popup = centered_rect(62, 32, area);
    frame.render_widget(Clear, popup);
    let block = theme::panel("⚠ NSEC zone walk", theme::ORANGE);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let target = state
        .active()
        .map(|t| t.target.display())
        .unwrap_or_default();
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("{target}'s zone is NSEC-signed, which means its whole set of"),
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "names can be enumerated by following the DNSSEC chain.",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "This sends many (rate-limited, capped) queries to their nameservers —",
            Style::default().fg(theme::MUTED),
        )),
        Line::from(Span::styled(
            "only do this against zones you're authorized to probe.",
            Style::default().fg(theme::MUTED),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Walk the zone now?  ", Style::default().fg(theme::TEXT)),
            Span::styled(
                "[y]",
                Style::default()
                    .fg(theme::GREEN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" / "),
            Span::styled(
                "[N]",
                Style::default().fg(theme::RED).add_modifier(Modifier::BOLD),
            ),
        ]),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(text, inner);
}

fn render_select_alt_name(
    frame: &mut Frame,
    area: Rect,
    names: &[crate::checks::altnames::AltName],
    selected: usize,
) {
    let popup = centered_rect(64, 60, area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint(
        "Open alternative host",
        "↑/↓ select · enter open · esc cancel",
        theme::MUTED,
        theme::pane_accent(crate::app::Pane::Overview),
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let items: Vec<ratatui::widgets::ListItem> = names
        .iter()
        .map(|n| {
            let sources = n
                .sources
                .iter()
                .map(|s| s.label())
                .collect::<Vec<_>>()
                .join(", ");
            ratatui::widgets::ListItem::new(Line::from(vec![
                Span::styled(n.name.clone(), Style::default().fg(theme::TEXT)),
                Span::styled(format!("  ({sources})"), Style::default().fg(theme::MUTED)),
            ]))
        })
        .collect();
    let list = ratatui::widgets::List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::Rgb(18, 18, 24))
                .bg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("❯ ");
    let mut state = ratatui::widgets::ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(56, 60, area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint("Help", "? / esc to close", theme::MUTED, theme::PURPLE);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let row = |key: &'static str, desc: &'static str| {
        Line::from(vec![
            Span::styled(
                format!("  {key:<18}"),
                Style::default()
                    .fg(theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(desc, Style::default().fg(theme::TEXT)),
        ])
    };
    let lines = vec![
        row("Ctrl+t / Ctrl+w", "New tab / close tab"),
        row("Tab / Shift+Tab", "Next / previous host tab"),
        row("1-9, 0, -, ←/→", "Switch pane"),
        row("↑/↓, PgUp/PgDn", "Scroll the current pane's content"),
        row("r", "Re-run checks for the current pane"),
        row("R", "Re-run all checks for the current host"),
        row("e", "Toggle evidence details (Hosting pane)"),
        row("a", "Open the alternative-hostname picker (Overview)"),
        row("w", "Walk an NSEC-signed zone for its full name list (DNS)"),
        row("space", "Pause/resume the continuous ping (Ping/Trace)"),
        row("y", "Copy the current pane as text"),
        row("s", "Open the settings editor"),
        row("?", "Help overlay"),
        row("q", "Quit"),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::app::{CheckSlot, CheckStatus, Mode, Pane, TabState};
    use crate::checks::acme::{AcmeInfo, CertificateAuthority, ChallengeHint, Dns01Evidence};
    use crate::checks::altnames::{AltName, NameSource};
    use crate::checks::ping::{PingMethod, PingSample, PingUpdate};
    use crate::checks::{CheckId, SharedResultsHandle};
    use crate::config::Config;
    use crate::event::CheckUpdate;
    use crate::providers::{Confidence, Detection, Evidence, Layer, ProviderDb};
    use crate::target::Target;

    fn empty_tab(id: u64, target: &str) -> TabState {
        TabState {
            id,
            target: Target::parse(target).unwrap(),
            active_pane: 0,
            show_evidence: false,
            cancel: CancellationToken::new(),
            shared: SharedResultsHandle::new(),
            checks: BTreeMap::new(),
            ports_confirmed: None,
            zone_walk_confirmed: None,
            scroll: 0,
            resolver: None,
            ping_paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A tab with real data in a handful of checks, so panes render their
    /// "populated" branches (sparkline, pills, tables) rather than only
    /// the "waiting"/"no data" placeholders.
    fn populated_tab() -> TabState {
        let mut tab = empty_tab(1, "example.com");
        tab.show_evidence = true;

        let mut dns = crate::checks::dns::DnsResult {
            queried_name: "example.com".into(),
            resolver: "system".into(),
            ..Default::default()
        };
        dns.a.push(Ipv4Addr::new(93, 184, 216, 34));
        dns.ns.push("a.iana-servers.net.".into());
        dns.authenticated_data = true;
        tab.checks.insert(
            CheckId::Dns,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Dns(dns)),
            },
        );

        let ping = PingUpdate {
            target_ip: "93.184.216.34".parse().unwrap(),
            method: PingMethod::Icmp,
            samples: vec![
                PingSample {
                    seq: 0,
                    rtt: Some(Duration::from_millis(12)),
                },
                PingSample { seq: 1, rtt: None },
                PingSample {
                    seq: 2,
                    rtt: Some(Duration::from_millis(180)),
                },
            ],
            sent: 3,
            received: 2,
            min: Some(Duration::from_millis(12)),
            max: Some(Duration::from_millis(180)),
            avg: Some(Duration::from_millis(96)),
            fallback_reason: None,
            paused: false,
        };
        tab.checks.insert(
            CheckId::Ping,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Ping(ping)),
            },
        );

        let detection = Detection {
            provider_id: "example-cdn".into(),
            provider_name: "Example CDN".into(),
            layer: Layer::Edge,
            confidence: Confidence::High,
            score: 100,
            evidence: vec![Evidence {
                description: "IP in example-cdn ips-v4".into(),
                weight: 100,
            }],
        };
        tab.checks.insert(
            CheckId::Hosting,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Hosting(vec![detection])),
            },
        );

        tab.checks.insert(
            CheckId::Http,
            CheckSlot {
                status: CheckStatus::Failed("connection refused".into()),
                update: None,
            },
        );

        let tls = crate::checks::tls::TlsResult {
            host: "example.com".into(),
            port: 443,
            protocol_version: Some("TLSv1_3".into()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".into()),
            issuer: Some("C=US, O=Let's Encrypt, CN=R3".into()),
            subject: Some("CN=example.com".into()),
            sans: vec!["*.example.com".into(), "example.com".into()],
            days_until_expiry: Some(42),
            chain_len: 2,
            acme: Some(AcmeInfo {
                authority: CertificateAuthority::LetsEncrypt,
                is_wildcard: true,
                challenge_hint: ChallengeHint::Dns01Certain,
                dns01: Some(Dns01Evidence {
                    txt_values: vec!["abc123".into()],
                    cname_target: None,
                }),
                http01: None,
                note: None,
            }),
            ..Default::default()
        };
        tab.checks.insert(
            CheckId::Tls,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Tls(tls)),
            },
        );

        let alt = crate::checks::altnames::AltNamesResult {
            ips: vec!["93.184.216.34".parse().unwrap()],
            names: vec![
                AltName {
                    name: "www.example.com".into(),
                    sources: vec![NameSource::TlsSan, NameSource::CertificateTransparency],
                },
                AltName {
                    name: "example.net".into(),
                    sources: vec![NameSource::ReverseIp],
                },
            ],
            errors: Vec::new(),
        };
        tab.checks.insert(
            CheckId::AltNames,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::AltNames(alt)),
            },
        );

        let target_ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        let trace = crate::checks::trace::TraceUpdate {
            target_ip,
            method: crate::checks::trace::TraceMethod::TcpConnect { port: 443 },
            hops: vec![
                crate::checks::trace::TraceHop {
                    ttl: 1,
                    addr: Some("10.0.0.1".parse().unwrap()),
                    rtt: Some(Duration::from_millis(2)),
                    provider: None,
                },
                crate::checks::trace::TraceHop {
                    ttl: 2,
                    addr: None,
                    rtt: None,
                    provider: None,
                },
                crate::checks::trace::TraceHop {
                    ttl: 3,
                    addr: Some(target_ip),
                    rtt: Some(Duration::from_millis(28)),
                    provider: Some("Example CDN".into()),
                },
            ],
            reached: true,
            fallback_reason: Some(
                "no ICMP socket available; running a simple TCP-connect TTL sweep instead".into(),
            ),
        };
        tab.checks.insert(
            CheckId::Trace,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Trace(trace)),
            },
        );

        let geo = crate::checks::geo::GeoResult {
            ip: Some(target_ip),
            country: Some("United States".into()),
            country_code: Some("US".into()),
            region: Some("Virginia".into()),
            city: Some("Norfolk".into()),
            lat: Some(36.8508),
            lon: Some(-76.2859),
            timezone: Some("America/New_York".into()),
            asn_org: Some("Example Org".into()),
            accuracy_hint: Some("city-level"),
            errors: Vec::new(),
        };
        tab.checks.insert(
            CheckId::Geo,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Geo(geo)),
            },
        );

        tab
    }

    fn render_at(width: u16, height: u16, f: impl FnOnce(&mut ratatui::Frame)) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| f(frame)).unwrap();
    }

    #[test]
    fn draws_with_no_tabs_open_at_several_sizes() {
        let state = AppState::new(Config::default(), ProviderDb::default());
        for (w, h) in [(80, 24), (120, 40), (40, 10)] {
            render_at(w, h, |frame| draw(frame, &state));
        }
    }

    #[test]
    fn every_pane_renders_without_data_at_a_realistic_size() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(empty_tab(1, "example.com"));
        for i in 0..Pane::ALL.len() {
            state.tabs[0].active_pane = i;
            render_at(120, 40, |frame| draw(frame, &state));
        }
    }

    #[test]
    fn every_pane_renders_with_populated_data_at_a_realistic_size() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        for i in 0..Pane::ALL.len() {
            state.tabs[0].active_pane = i;
            render_at(120, 40, |frame| draw(frame, &state));
        }
    }

    #[test]
    fn overview_pane_shows_the_target_host() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let content = buffer_to_string(terminal.backend().buffer());
        assert!(
            content.contains("example.com"),
            "expected the target host to appear somewhere on screen"
        );
        assert!(
            content.contains("Example CDN"),
            "expected the hosting detection to appear in the dashboard"
        );
    }

    /// The GeoIP status must be visible both pinned to the bottom-right
    /// of the status line and at the top of the Geo pane -- the two
    /// places `render_status_line`/`geo::render` were changed to surface
    /// `AppState::geoip`.
    #[test]
    fn geoip_status_appears_on_the_status_line_and_the_geo_pane() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.geoip = crate::geoip::GeoipStatus {
            configured: true,
            downloading: false,
            last_success: Some(std::time::SystemTime::now() - Duration::from_secs(3 * 3600)),
            last_error: None,
        };
        state.tabs.push(empty_tab(1, "example.com"));
        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Geo).unwrap();

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let content = buffer_to_string(terminal.backend().buffer());
        assert_eq!(
            content.matches("GeoIP: 3h old").count(),
            2,
            "expected the status text once on the status line and once in the Geo pane: {content}"
        );
    }

    /// Once a check has a coordinate, the Geo pane must show the world
    /// map (see `worldmap::render_map`) with a pinpoint on it, not just
    /// the plain country/city table.
    #[test]
    fn geo_pane_renders_a_map_with_a_pin_when_coordinates_are_present() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Geo).unwrap();

        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let content = buffer_to_string(terminal.backend().buffer());
        assert!(
            content.contains("Map"),
            "expected the map sub-panel title: {content}"
        );
        assert!(
            content.contains('◉'),
            "expected the pinpoint glyph somewhere on screen: {content}"
        );
    }

    /// The status line's keybinding hints should only include a pane-
    /// specific action (zone walk, evidence, alt. hosts, pause ping) when
    /// that pane is actually active -- a fixed list would show `w` on
    /// every pane even though it only does anything on DNS.
    #[test]
    fn status_line_only_shows_the_active_panes_keybinding() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());

        let status_line_for = |state: &AppState| -> String {
            let backend = TestBackend::new(160, 40);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, state)).unwrap();
            buffer_to_string(terminal.backend().buffer())
                .lines()
                .find(|l| l.contains("^T"))
                .unwrap()
                .to_string()
        };

        for (pane, present, absent) in [
            (Pane::Overview, "alt. hosts", "zone walk"),
            (Pane::Dns, "zone walk", "evidence"),
            (Pane::Hosting, "evidence", "pause ping"),
            (Pane::PingTrace, "pause ping", "alt. hosts"),
            (Pane::Rep, "quit", "zone walk"),
        ] {
            state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == pane).unwrap();
            let line = status_line_for(&state);
            assert!(
                line.contains(present),
                "{pane:?} should show {present:?}: {line}"
            );
            assert!(
                !line.contains(absent),
                "{pane:?} shouldn't show {absent:?}: {line}"
            );
        }
    }

    #[test]
    fn renders_at_a_very_small_terminal_without_panicking() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        render_at(20, 6, |frame| draw(frame, &state));
    }

    #[test]
    fn overlays_render_without_panicking() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());

        for mode in [
            Mode::NewHostPrompt("exa".to_string()),
            Mode::Help,
            Mode::ConfirmPorts,
            Mode::SelectAltName {
                names: vec![
                    AltName {
                        name: "www.example.com".into(),
                        sources: vec![NameSource::TlsSan],
                    },
                    AltName {
                        name: "example.net".into(),
                        sources: vec![NameSource::ReverseIp, NameSource::Ptr],
                    },
                ],
                selected: 1,
            },
            Mode::ChooseResolver {
                target: Target::parse("example.com").unwrap(),
                input: "1.1.1.1".to_string(),
            },
            Mode::Settings {
                draft: Box::new(Config::default()),
                selected: 0,
                editing: None,
                message: None,
            },
            Mode::Settings {
                draft: Box::new(Config::default()),
                selected: 2,
                editing: Some("in progress".to_string()),
                message: Some("not a duration".to_string()),
            },
        ] {
            state.mode = mode;
            render_at(100, 30, |frame| draw(frame, &state));
            render_at(20, 6, |frame| draw(frame, &state));
        }
    }

    fn buffer_to_string(buffer: &ratatui::buffer::Buffer) -> String {
        let area = buffer.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Not a real assertion — run with `--ignored --nocapture` to eyeball
    /// a pane's layout as plain text while iterating on styling.
    #[test]
    #[ignore]
    fn dump_overview_and_hosting() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Overview).unwrap();

        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
        println!("{}", buffer_to_string(terminal.backend().buffer()));

        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Hosting).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
        println!("{}", buffer_to_string(terminal.backend().buffer()));

        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Geo).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
        println!("{}", buffer_to_string(terminal.backend().buffer()));
    }
}
