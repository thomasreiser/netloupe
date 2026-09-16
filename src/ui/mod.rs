//! Rendering only: reads `AppState` and draws it. Never awaits, spawns
//! tasks, or mutates state (architecture rule 1 in `CLAUDE.md`).

pub mod panes;
pub mod tabs;
pub mod theme;
pub mod widgets;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
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
        Some(tab) => panes::render(frame, chunks[2], tab),
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
        key("r"),
        desc(" rerun "),
        sep(),
        key("R"),
        desc(" rerun all "),
        sep(),
        key("e"),
        desc(" evidence "),
        sep(),
        key("q"),
        desc(" quit"),
    ];
    if let Some(warning) = &state.data_age_warning {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("⚠ {warning}"),
            Style::default().fg(theme::YELLOW),
        ));
    }
    frame.render_widget(Line::from(spans), area);
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
        row("r", "Re-run checks for the current pane"),
        row("R", "Re-run all checks for the current host"),
        row("e", "Toggle evidence details (Hosting pane)"),
        row("y", "Copy the current pane as text"),
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
    }
}
