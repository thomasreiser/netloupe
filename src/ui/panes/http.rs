//! HTTP pane: status, redirect chain, timing, security headers.

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{empty_message, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Http]);
    let slot = tab.slot(CheckId::Http);

    let Some(CheckUpdate::Http(http)) = &slot.update else {
        frame.render_widget(
            empty_message(if is_waiting(&slot.status) {
                "requesting..."
            } else {
                "no HTTP data"
            }),
            body,
        );
        return;
    };

    let mut rows: Vec<(String, String)> =
        vec![("Requested".to_string(), http.requested_url.clone())];
    if http.fell_back_to_http {
        rows.push(("Note".to_string(), "fell back to plain HTTP".to_string()));
    }
    for hop in &http.redirect_chain {
        rows.push((format!("→ {}", hop.status), hop.url.clone()));
    }
    if let Some(status) = http.status {
        rows.push(("Final status".to_string(), status.to_string()));
    }
    if let Some(url) = &http.final_url {
        rows.push(("Final URL".to_string(), url.clone()));
    }
    if let Some(version) = &http.http_version {
        rows.push(("Version".to_string(), version.clone()));
    }
    if let Some(timing) = http.timing {
        rows.push(("Timing".to_string(), format!("{}ms", timing.as_millis())));
    }

    let sec = &http.security_headers;
    rows.push((
        "Security headers".to_string(),
        format!(
            "HSTS={} CSP={} XFO={} XCTO={} Referrer-Policy={}",
            sec.hsts, sec.csp, sec.x_frame_options, sec.x_content_type_options, sec.referrer_policy
        ),
    ));
    for (name, value) in &http.headers {
        rows.push((name.clone(), value.clone()));
    }

    crate::ui::widgets::kv_table::render(frame, body, &rows, tab.scroll);
}
