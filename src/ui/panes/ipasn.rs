//! IP/ASN pane: ASN, RDAP, IP classification.

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::IpInfo]);
    let slot = tab.slot(CheckId::IpInfo);

    let Some(CheckUpdate::IpInfo(info)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "looking up..."
            } else {
                "no IP/ASN data"
            }),
            body,
        );
        return;
    };

    let mut rows: Vec<(String, String)> = vec![
        ("IP".to_string(), info.ip.to_string()),
        ("Class".to_string(), info.class.label().to_string()),
        ("RPKI".to_string(), "not implemented yet".to_string()),
    ];

    if let Some(asn) = &info.asn {
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
    } else {
        rows.push(("ASN".to_string(), "unknown".to_string()));
    }

    if let Some(rdap) = &info.rdap {
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

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), body);
}
