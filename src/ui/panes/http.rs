//! HTTP pane: status, redirect chain, timing, security headers, and a
//! per-version support table (HTTP/1.1, HTTP/2 over TLS, h2c, HTTP/3),
//! each from its own dedicated, protocol-forced probe rather than
//! inferred from whichever one the main request happened to negotiate.

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
        // What a normal client's own ALPN negotiation happened to pick
        // for the request above -- NOT the same question as "which
        // versions does this server support" (the versions table below):
        // a server offering both HTTP/2 and HTTP/3 will still show
        // "HTTP/2" here, since ALPN-over-TCP has no way to advertise
        // QUIC support at all, and this is only ever one connection's
        // outcome, not a survey.
        rows.push(("This request".to_string(), version.clone()));
    }
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
    }

    // Each row here comes from its own dedicated, protocol-forced
    // connection attempt (see `checks::http::probe_forced`), so this is
    // a real per-version yes/no, not an inference from whichever one
    // "This request" above happened to land on.
    let v = &http.versions;
    let supported = |ok: bool| {
        if ok {
            "✓ supported".to_string()
        } else {
            "✗ not supported".to_string()
        }
    };
    rows.push(("HTTP/1.1 (TLS)".to_string(), supported(v.http1_tls)));
    rows.push(("HTTP/2 (TLS)".to_string(), supported(v.http2_tls)));
    rows.push(("HTTP/2 (h2c)".to_string(), supported(v.h2c)));
    rows.push(("HTTP/3 (QUIC)".to_string(), supported(v.http3)));

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
