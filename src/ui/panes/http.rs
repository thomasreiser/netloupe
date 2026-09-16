//! HTTP pane: status, redirect chain, timing, security headers, the
//! negotiated HTTP version, and dedicated plain-HTTP-on-port-80/h2c/
//! HTTP/3 reachability probes.

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
        // A real ALPN negotiation, not just "the only protocol this
        // build speaks" -- so HTTP/1.1 here means the server genuinely
        // didn't offer HTTP/2, not that we didn't ask.
        rows.push(("Negotiated".to_string(), version.clone()));
    }
    rows.push((
        "HTTP/3".to_string(),
        if http.http3_supported {
            "supported — a QUIC-only request to the same host/port succeeded".to_string()
        } else {
            "not offered (or the QUIC connection was blocked/unreachable)".to_string()
        },
    ));
    if let Some(timing) = http.timing {
        rows.push(("Timing".to_string(), format!("{}ms", timing.as_millis())));
    }
    if let Some(plain) = &http.plain_http {
        let value = if plain.reachable {
            let status = plain
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            if plain.redirects_to_https {
                format!("yes — port {}, {status}, redirects to HTTPS", plain.port)
            } else {
                format!(
                    "yes — port {}, {status}, served over plain HTTP",
                    plain.port
                )
            }
        } else {
            format!(
                "no — port {}: {}",
                plain.port,
                plain.error.as_deref().unwrap_or("unreachable")
            )
        };
        rows.push(("HTTP (port 80)".to_string(), value));
        rows.push((
            "h2c".to_string(),
            if plain.h2c_supported {
                "supported — accepted HTTP/2 over cleartext via prior knowledge".to_string()
            } else {
                "not supported (or not offered without TLS)".to_string()
            },
        ));
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
