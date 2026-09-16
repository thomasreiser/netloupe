//! Mail pane: SPF, DMARC, DKIM selector probe, MTA-STS/TLS-RPT/BIMI, SMTP.

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Mail]);
    let slot = tab.slot(CheckId::Mail);

    let Some(CheckUpdate::Mail(mail)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "checking mail records..."
            } else {
                "no mail data"
            }),
            body,
        );
        return;
    };

    let mut rows: Vec<(String, String)> = Vec::new();
    match &mail.spf {
        Some(spf) => {
            rows.push(("SPF".to_string(), spf.record.clone()));
            rows.push((
                "SPF lookups".to_string(),
                format!(
                    "{}/10{}",
                    spf.lookup_count,
                    if spf.exceeds_limit {
                        " (EXCEEDS RFC 7208 LIMIT)"
                    } else {
                        ""
                    }
                ),
            ));
        }
        None => rows.push(("SPF".to_string(), "none found".to_string())),
    }
    match &mail.dmarc {
        Some(dmarc) => {
            rows.push((
                "DMARC policy".to_string(),
                dmarc.policy.clone().unwrap_or_else(|| "(none)".to_string()),
            ));
            rows.push(("DMARC record".to_string(), dmarc.record.clone()));
        }
        None => rows.push(("DMARC".to_string(), "none found".to_string())),
    }
    rows.push((
        "DKIM selectors".to_string(),
        if mail.dkim_selectors_found.is_empty() {
            "none of the common selectors responded".to_string()
        } else {
            mail.dkim_selectors_found.join(", ")
        },
    ));
    rows.push((
        "MTA-STS".to_string(),
        mail.mta_sts_record
            .clone()
            .unwrap_or_else(|| "not present".to_string()),
    ));
    rows.push((
        "TLS-RPT".to_string(),
        mail.tls_rpt_record
            .clone()
            .unwrap_or_else(|| "not present".to_string()),
    ));
    rows.push((
        "BIMI".to_string(),
        mail.bimi_record
            .clone()
            .unwrap_or_else(|| "not present".to_string()),
    ));
    for probe in &mail.smtp {
        let status = if probe.connected {
            format!("connected, STARTTLS={}", probe.starttls_advertised)
        } else {
            probe
                .error
                .clone()
                .unwrap_or_else(|| "unreachable".to_string())
        };
        rows.push((format!("SMTP {}", probe.host), status));
        if let Some(banner) = &probe.banner {
            rows.push(("  banner".to_string(), banner.clone()));
        }
    }

    crate::ui::widgets::kv_table::render(frame, body, &rows, tab.scroll);
}
