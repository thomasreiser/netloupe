//! Geo pane: country/region/city, timezone, org.

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Geo]);
    let slot = tab.slot(CheckId::Geo);

    let Some(CheckUpdate::Geo(geo)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "looking up..."
            } else {
                "no geo data"
            }),
            body,
        );
        return;
    };

    let mut rows: Vec<(String, String)> = Vec::new();
    if let Some(ip) = geo.ip {
        rows.push(("IP".to_string(), ip.to_string()));
    }
    if let Some(country) = &geo.country {
        rows.push((
            "Country".to_string(),
            format!(
                "{country} ({})",
                geo.country_code.clone().unwrap_or_default()
            ),
        ));
    }
    if let Some(region) = &geo.region {
        rows.push(("Region".to_string(), region.clone()));
    }
    if let Some(city) = &geo.city {
        rows.push(("City".to_string(), city.clone()));
    }
    if let Some(tz) = &geo.timezone {
        rows.push(("Timezone".to_string(), tz.clone()));
    }
    if let Some(org) = &geo.asn_org {
        rows.push(("Org (ASN db)".to_string(), org.clone()));
    }
    if let Some(hint) = geo.accuracy_hint {
        rows.push(("Accuracy".to_string(), hint.to_string()));
    }

    if rows.is_empty() {
        frame.render_widget(super::errors_widget(&geo.errors), body);
        return;
    }

    let chunks = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Min(0),
            ratatui::layout::Constraint::Length(geo.errors.len().min(4) as u16),
        ])
        .split(body);
    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), chunks[0]);
    if !geo.errors.is_empty() {
        frame.render_widget(super::errors_widget(&geo.errors), chunks[1]);
    }
}
