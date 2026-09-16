//! Ports pane: opt-in TCP-connect scan, gated by a confirmation prompt
//! handled at the `app.rs`/`ui::mod` level (see `Mode::ConfirmPorts`).

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Ports]);

    if tab.ports_confirmed != Some(true) {
        frame.render_widget(
            empty_message("press 'r' to opt in and scan the configured port list"),
            body,
        );
        return;
    }

    let slot = tab.slot(CheckId::Ports);
    let Some(CheckUpdate::Ports(ports)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "scanning..."
            } else {
                "no scan data"
            }),
            body,
        );
        return;
    };

    let rows: Vec<(String, String)> = ports
        .scanned
        .iter()
        .map(|p| {
            let value = match (&p.open, &p.banner) {
                (true, Some(banner)) => format!("open — {banner}"),
                (true, None) => "open".to_string(),
                (false, _) => "closed/filtered".to_string(),
            };
            (p.port.to_string(), value)
        })
        .collect();

    crate::ui::widgets::kv_table::render(frame, body, &rows, tab.scroll);
}
