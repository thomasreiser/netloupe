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

pub fn render(
    frame: &mut Frame,
    area: Rect,
    tab: &TabState,
    geoip: &GeoipStatus,
    show_country_flags: bool,
) {
    let body = header_and_body(frame, area, tab, &[CheckId::Geo]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .spacing(1)
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
        let text = format!(
            "{country} ({})",
            geo.country_code.clone().unwrap_or_default()
        );
        rows.push((
            "Country".to_string(),
            theme::with_country_flag(&text, geo.country_code.as_deref(), show_country_flags),
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

    // A map only means anything once there's a coordinate to zoom to --
    // otherwise this is exactly the old full-height layout. Full width,
    // bottom half of the pane, so the map gets enough room to actually
    // show a recognizable area rather than a narrow sliver.
    let table_area = match (geo.lat, geo.lon) {
        (Some(lat), Some(lon)) => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .spacing(1)
                .split(body);
            render_map(frame, rows[1], lat, lon);
            rows[0]
        }
        _ => body,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(geo.errors.len().min(4) as u16),
        ])
        .spacing(1)
        .split(table_area);
    crate::ui::widgets::kv_table::render(frame, chunks[0], &rows, tab.scroll);
    if !geo.errors.is_empty() {
        frame.render_widget(super::errors_widget(&geo.errors), chunks[1]);
    }
}

/// The world map, zoomed to `(lat, lon)` with a pinpoint and the nearest
/// major city name(s) -- see `crate::worldmap` for the actual projection/
/// zoom/labeling logic; this just draws whatever grid it produces at
/// `area`'s exact size, live, on every render (see `worldmap::render_map`'s
/// doc comment for why that's cheap enough to redo every frame).
fn render_map(frame: &mut Frame, area: Rect, lat: f64, lon: f64) {
    let block = theme::panel("Map", theme::pane_accent(crate::app::Pane::Geo));
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let grid = crate::worldmap::render_map(lat, lon, inner.width, inner.height);
    frame.render_widget(crate::ui::widgets::worldmap::widget(&grid), inner);
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
