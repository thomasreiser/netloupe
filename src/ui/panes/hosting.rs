//! Hosting pane: detected providers per layer, with evidence. `e` toggles
//! the evidence list (see `TabState::show_evidence`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem};
use ratatui::Frame;

use super::{empty_message, header_and_body};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::providers::{Detection, Layer};
use crate::ui::theme;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Hosting]);
    let slot = tab.slot(CheckId::Hosting);

    let Some(CheckUpdate::Hosting(detections)) = &slot.update else {
        frame.render_widget(empty_message("waiting for DNS/HTTP/TLS/IP data..."), body);
        return;
    };
    if detections.is_empty() {
        let message = match &tab.slot(CheckId::IpInfo).update {
            Some(CheckUpdate::IpInfo(info)) if !info.class.is_global() => {
                format!(
                    "{} is a {} address — no public hosting provider applies to it",
                    info.ip,
                    info.class.label()
                )
            }
            _ => "no known provider detected (edge hidden origin is expected here)".to_string(),
        };
        frame.render_widget(empty_message(&message), body);
        return;
    }

    let mut items: Vec<ListItem> = Vec::new();
    for layer in [
        Layer::Edge,
        Layer::Origin,
        Layer::Dns,
        Layer::Mail,
        Layer::Saas,
    ] {
        let group: Vec<&Detection> = detections.iter().filter(|d| d.layer == layer).collect();
        if group.is_empty() {
            continue;
        }
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                "▍",
                Style::default().fg(theme::pane_accent(crate::app::Pane::Hosting)),
            ),
            Span::styled(
                format!(" {}", layer_title(layer)),
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
        ])));
        for detection in group {
            items.push(ListItem::new(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    detection.provider_name.clone(),
                    Style::default()
                        .fg(theme::TEXT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                theme::pill(
                    detection.confidence.to_string(),
                    theme::confidence_color(detection.confidence),
                ),
                Span::styled(
                    format!("  score {}", detection.score),
                    Style::default().fg(theme::MUTED),
                ),
            ])));
            if tab.show_evidence {
                for ev in &detection.evidence {
                    items.push(ListItem::new(Line::from(vec![
                        Span::styled("      ▸ ", Style::default().fg(theme::FAINT)),
                        Span::styled(ev.description.clone(), Style::default().fg(theme::MUTED)),
                        Span::styled(
                            format!(" +{}", ev.weight),
                            Style::default().fg(theme::FAINT),
                        ),
                    ])));
                }
            }
        }
    }

    let hint = if tab.show_evidence {
        "evidence shown — press 'e' to hide"
    } else {
        "press 'e' to show evidence"
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(body);
    frame.render_widget(List::new(items), chunks[0]);
    frame.render_widget(empty_message(hint), chunks[1]);
}

fn layer_title(layer: Layer) -> &'static str {
    match layer {
        Layer::Edge => "EDGE",
        Layer::Origin => "ORIGIN",
        Layer::Dns => "DNS",
        Layer::Mail => "MAIL",
        Layer::Saas => "USES (SaaS)",
    }
}
