//! Hosting pane: detected providers per layer, with evidence. `e` toggles
//! the evidence list (see `TabState::show_evidence`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem};
use ratatui::Frame;

use super::{empty_message, header_and_body};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::providers::{Confidence, Detection, Layer};

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Hosting]);
    let slot = tab.slot(CheckId::Hosting);

    let Some(CheckUpdate::Hosting(detections)) = &slot.update else {
        frame.render_widget(empty_message("waiting for DNS/HTTP/TLS/IP data..."), body);
        return;
    };
    if detections.is_empty() {
        frame.render_widget(
            empty_message("no known provider detected (edge hidden origin is expected here)"),
            body,
        );
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
        items.push(ListItem::new(Line::from(Span::styled(
            layer_title(layer),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ))));
        for detection in group {
            items.push(ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    detection.provider_name.clone(),
                    Style::default().add_modifier(ratatui::style::Modifier::BOLD),
                ),
                Span::raw("  "),
                confidence_span(detection.confidence),
                Span::styled(
                    format!("  (score {})", detection.score),
                    Style::default().fg(Color::DarkGray),
                ),
            ])));
            if tab.show_evidence {
                for ev in &detection.evidence {
                    items.push(ListItem::new(Line::from(Span::styled(
                        format!("    • {} (+{})", ev.description, ev.weight),
                        Style::default().fg(Color::DarkGray),
                    ))));
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

fn confidence_span(confidence: Confidence) -> Span<'static> {
    let color = match confidence {
        Confidence::High => Color::Green,
        Confidence::Medium => Color::Yellow,
        Confidence::Low => Color::DarkGray,
    };
    Span::styled(confidence.to_string(), Style::default().fg(color))
}
