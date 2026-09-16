//! Rep pane: DNSBLs, Tor exit list, optional API providers.

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Reputation]);
    let slot = tab.slot(CheckId::Reputation);

    let Some(CheckUpdate::Reputation(rep)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "checking reputation..."
            } else {
                "no reputation data"
            }),
            body,
        );
        return;
    };

    let mut rows: Vec<(String, String)> = Vec::new();
    for hit in &rep.dnsbl {
        let value = if hit.listed {
            format!(
                "LISTED ({})",
                hit.codes
                    .iter()
                    .map(std::net::Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            "clean".to_string()
        };
        rows.push((hit.zone.clone(), value));
    }
    if let Some(is_exit) = rep.tor_exit_node {
        rows.push(("Tor exit node".to_string(), is_exit.to_string()));
    }
    if let Some(score) = rep.abuseipdb_score {
        rows.push(("AbuseIPDB score".to_string(), format!("{score}/100")));
    }

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), body);
}
