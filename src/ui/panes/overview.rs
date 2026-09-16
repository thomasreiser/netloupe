//! Overview pane: a dashboard pulling the headline fact from each other
//! check — IPs, ASN, provider badges, country, ping stats, cert expiry,
//! SPF/DMARC/DNSSEC status — so a first glance answers "what is this host".

use ratatui::layout::Rect;
use ratatui::Frame;

use super::header_and_body;
use crate::app::TabState;
use crate::checks::CheckId;
use crate::event::CheckUpdate;
use crate::providers::Layer;

const OVERVIEW_CHECKS: &[CheckId] = &[
    CheckId::Dns,
    CheckId::IpInfo,
    CheckId::Hosting,
    CheckId::Tls,
    CheckId::Mail,
    CheckId::Ping,
];

pub fn render(frame: &mut Frame, area: Rect, tab: &TabState) {
    let body = header_and_body(frame, area, tab, OVERVIEW_CHECKS);

    let mut rows: Vec<(String, String)> = vec![("Target".to_string(), tab.target.display())];

    if let Some(CheckUpdate::Dns(dns)) = &tab.slot(CheckId::Dns).update {
        let ips: Vec<String> = dns
            .a
            .iter()
            .map(ToString::to_string)
            .chain(dns.aaaa.iter().map(ToString::to_string))
            .collect();
        rows.push((
            "IPs".to_string(),
            if ips.is_empty() {
                "-".to_string()
            } else {
                ips.join(", ")
            },
        ));
    }

    if let Some(CheckUpdate::IpInfo(info)) = &tab.slot(CheckId::IpInfo).update {
        if let Some(asn) = &info.asn {
            rows.push((
                "ASN".to_string(),
                format!(
                    "AS{} ({})",
                    asn.asn,
                    asn.as_name.clone().unwrap_or_default()
                ),
            ));
        }
    }

    if let Some(CheckUpdate::Hosting(detections)) = &tab.slot(CheckId::Hosting).update {
        for layer in [Layer::Edge, Layer::Origin, Layer::Dns] {
            if let Some(d) = detections.iter().find(|d| d.layer == layer) {
                rows.push((
                    format!("{layer}"),
                    format!("{} ({})", d.provider_name, d.confidence),
                ));
            }
        }
    }

    if let Some(CheckUpdate::Geo(geo)) = &tab.slot(CheckId::Geo).update {
        if let Some(country) = &geo.country {
            rows.push(("Country".to_string(), country.clone()));
        }
    }

    if let Some(CheckUpdate::Ping(ping)) = &tab.slot(CheckId::Ping).update {
        let fmt = |d: Option<std::time::Duration>| {
            d.map(|d| format!("{}ms", d.as_millis()))
                .unwrap_or_else(|| "-".to_string())
        };
        rows.push(("Ping (avg)".to_string(), fmt(ping.avg)));
    }

    if let Some(CheckUpdate::Tls(tls)) = &tab.slot(CheckId::Tls).update {
        if let Some(days) = tls.days_until_expiry {
            rows.push(("Cert expiry".to_string(), format!("{days} day(s)")));
        }
    }

    if let Some(CheckUpdate::Mail(mail)) = &tab.slot(CheckId::Mail).update {
        rows.push((
            "SPF".to_string(),
            if mail.spf.is_some() {
                "present"
            } else {
                "absent"
            }
            .to_string(),
        ));
        rows.push((
            "DMARC".to_string(),
            mail.dmarc
                .as_ref()
                .and_then(|d| d.policy.clone())
                .unwrap_or_else(|| "absent".to_string()),
        ));
    }

    if let Some(CheckUpdate::Dns(dns)) = &tab.slot(CheckId::Dns).update {
        rows.push((
            "DNSSEC (AD bit)".to_string(),
            dns.authenticated_data.to_string(),
        ));
    }

    frame.render_widget(crate::ui::widgets::kv_table::widget(&rows), body);
}
