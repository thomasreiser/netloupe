//! DNS pane.

use ratatui::layout::Rect;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use super::{empty_message, errors_widget, header_and_body, is_waiting};
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, &[CheckId::Dns]);
    let slot = tab.slot(CheckId::Dns);

    let Some(CheckUpdate::Dns(dns)) = &slot.update else {
        if is_waiting(&slot.status) {
            frame.render_widget(empty_message("resolving..."), body);
        } else {
            frame.render_widget(empty_message("no DNS data"), body);
        }
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(dns.errors.len().min(5) as u16),
        ])
        .split(body);

    let mut rows: Vec<(String, String)> = Vec::new();
    for ip in &dns.a {
        rows.push(("A".to_string(), ip.to_string()));
    }
    for ip in &dns.aaaa {
        rows.push(("AAAA".to_string(), ip.to_string()));
    }
    for c in &dns.cnames {
        rows.push(("CNAME".to_string(), c.clone()));
    }
    for mx in &dns.mx {
        rows.push((
            "MX".to_string(),
            format!("{} {}", mx.preference, mx.exchange),
        ));
    }
    for ns in &dns.ns {
        rows.push(("NS".to_string(), ns.clone()));
    }
    if let Some(soa) = &dns.soa {
        rows.push((
            "SOA".to_string(),
            format!("{} {} serial={}", soa.mname, soa.rname, soa.serial),
        ));
    }
    for txt in &dns.txt {
        rows.push(("TXT".to_string(), txt.clone()));
    }
    for caa in &dns.caa {
        rows.push(("CAA".to_string(), caa.clone()));
    }
    for srv in &dns.srv {
        rows.push(("SRV".to_string(), srv.clone()));
    }
    for ptr in &dns.ptr {
        rows.push(("PTR".to_string(), ptr.clone()));
    }
    rows.push((
        "DNSSEC (AD bit)".to_string(),
        dns.authenticated_data.to_string(),
    ));

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), chunks[0]);
    if !dns.errors.is_empty() {
        frame.render_widget(errors_widget(&dns.errors), chunks[1]);
    }
}
