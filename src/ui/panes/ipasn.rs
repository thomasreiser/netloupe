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

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState, show_country_flags: bool) {
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
    let errors_height = info.errors.len().min(4) as u16;
    // A separate layout per branch, not a shared one with the local-
    // address line's `Length` zeroed out for the (common) global-IP case:
    // `.spacing(1)` still budgets a gap around a zero-height region, which
    // left a stray blank line above the table for every global IP.
    let (table_area, errors_area) = if is_global {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(errors_height)])
            .spacing(1)
            .split(body);
        (chunks[0], chunks[1])
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(errors_height),
            ])
            .spacing(1)
            .split(body);
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
        (chunks[1], chunks[2])
    };

    let mut rows: Vec<(String, String)> = vec![
        ("IP".to_string(), info.ip.to_string()),
        ("Class".to_string(), info.class.label().to_string()),
    ];

    if is_global {
        match &info.rpki {
            Some(state) => rows.push(("RPKI".to_string(), state.label().to_string())),
            None => rows.push(("RPKI".to_string(), "unknown".to_string())),
        }

        match &info.asn {
            Some(asn) => {
                rows.push(("ASN".to_string(), asn.asn.to_string()));
                rows.push((
                    "AS name".to_string(),
                    asn.as_name.clone().unwrap_or_else(|| "-".to_string()),
                ));
                rows.push(("Announced prefix".to_string(), asn.prefix.clone()));
                let text = format!("{} ({})", asn.registry, asn.country);
                rows.push((
                    "Registry".to_string(),
                    theme::with_country_flag(&text, Some(&asn.country), show_country_flags),
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
                    match &rdap.country {
                        Some(country) => {
                            theme::with_country_flag(country, Some(country), show_country_flags)
                        }
                        None => "-".to_string(),
                    },
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

    crate::ui::widgets::kv_table::render(frame, table_area, &rows, tab.scroll);
    if !info.errors.is_empty() {
        frame.render_widget(errors_widget(&info.errors), errors_area);
    }
}
