//! Geo pane: country/region/city, timezone, org.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::geoip::GeoipStatus;
use crate::ui::theme;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState, geoip: &GeoipStatus) {
    let body = header_and_body(frame, area, tab, &[CheckId::Geo]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(body);
    render_geoip_status(frame, chunks[0], geoip);
    let body = chunks[1];

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
    crate::ui::widgets::kv_table::render(frame, chunks[0], &rows, tab.scroll);
    if !geo.errors.is_empty() {
        frame.render_widget(super::errors_widget(&geo.errors), chunks[1]);
    }
}

/// Live status of the GeoLite2 background downloader (see `crate::geoip`),
/// shown above the check's own data/errors: it's the one thing that
/// actually explains "why is there nothing here" when the databases
/// haven't been downloaded yet, since the check itself has no visibility
/// into whether that's still in progress.
fn render_geoip_status(frame: &mut Frame, area: Rect, geoip: &GeoipStatus) {
    let color = if geoip.downloading {
        theme::CYAN
    } else if !geoip.configured {
        theme::MUTED
    } else if geoip.last_error.is_some() && geoip.last_success.is_none() {
        theme::RED
    } else {
        theme::MUTED
    };
    frame.render_widget(
        Paragraph::new(geoip.status_text()).style(Style::default().fg(color)),
        area,
    );
}
