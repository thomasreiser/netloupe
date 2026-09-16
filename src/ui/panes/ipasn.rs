//! IP/ASN pane: ASN, RDAP, IP classification.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{errors_widget, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::ui::theme;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::IpInfo]);
    let slot = tab.slot(CheckId::IpInfo);

    let Some(CheckUpdate::IpInfo(info)) = &slot.update else {
        frame.render_widget(
            super::empty_message(if is_waiting(&slot.status) {
                "looking up..."
            } else {
                "no IP/ASN data"
            }),
            body,
        );
        return;
    };

    let is_global = info.class.is_global();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if is_global { 0 } else { 1 }),
            Constraint::Min(0),
            Constraint::Length(info.errors.len().min(4) as u16),
        ])
        .split(body);

    if !is_global {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("◆ ", Style::default().fg(theme::BLUE)),
                Span::styled(
                    format!(
                        "{} — a {} address, not publicly routable",
                        info.ip,
                        info.class.label()
                    ),
                    Style::default()
                        .fg(theme::BLUE)
                        .add_modifier(Modifier::BOLD),
                ),
            ])),
            chunks[0],
        );
    }

    let mut rows: Vec<(String, String)> = vec![
        ("IP".to_string(), info.ip.to_string()),
        ("Class".to_string(), info.class.label().to_string()),
    ];

    if is_global {
        rows.push(("RPKI".to_string(), "not implemented yet".to_string()));

        match &info.asn {
            Some(asn) => {
                rows.push(("ASN".to_string(), asn.asn.to_string()));
                rows.push((
                    "AS name".to_string(),
                    asn.as_name.clone().unwrap_or_else(|| "-".to_string()),
                ));
                rows.push(("Announced prefix".to_string(), asn.prefix.clone()));
                rows.push((
                    "Registry".to_string(),
                    format!("{} ({})", asn.registry, asn.country),
                ));
            }
            None => rows.push(("ASN".to_string(), "unknown".to_string())),
        }

        match &info.rdap {
            Some(rdap) => {
                rows.push((
                    "RDAP handle".to_string(),
                    rdap.handle.clone().unwrap_or_else(|| "-".to_string()),
                ));
                rows.push((
                    "RDAP name".to_string(),
                    rdap.name.clone().unwrap_or_else(|| "-".to_string()),
                ));
                rows.push((
                    "RDAP country".to_string(),
                    rdap.country.clone().unwrap_or_else(|| "-".to_string()),
                ));
                rows.push((
                    "Abuse contact".to_string(),
                    rdap.abuse_email.clone().unwrap_or_else(|| "-".to_string()),
                ));
                rows.push(("RDAP source".to_string(), rdap.registry_url.clone()));
            }
            None => rows.push(("RDAP".to_string(), "unknown".to_string())),
        }
    } else {
        rows.push(("RPKI".to_string(), "n/a — local address".to_string()));
        rows.push(("ASN".to_string(), "n/a — local address".to_string()));
        rows.push(("RDAP".to_string(), "n/a — local address".to_string()));
    }

    crate::ui::widgets::kv_table::render(frame, chunks[1], &rows, tab.scroll);
    if !info.errors.is_empty() {
        frame.render_widget(errors_widget(&info.errors), chunks[2]);
    }
}
