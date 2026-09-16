//! Rep pane: public DNSBL listings, the Tor exit-node list, and (only when
//! an API key is configured) AbuseIPDB.
//!
//! DNSBL lookups need no key or paid API: each list works by DNS A-record
//! presence for the reversed IP under the list's zone, the same mechanism
//! `dig`/`nslookup` use.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};

/// Well-known public DNSBLs that don't require registration to query.
const DNSBL_ZONES: &[&str] = &[
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
];

#[derive(Debug, Clone)]
pub struct DnsblHit {
    pub zone: String,
    pub listed: bool,
    /// The A record(s) returned, when listed; DNSBLs encode a reason in
    /// the last octet (e.g. Spamhaus's `127.0.0.2` = spam source).
    pub codes: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, Default)]
pub struct ReputationResult {
    pub ip: Option<IpAddr>,
    pub dnsbl: Vec<DnsblHit>,
    pub tor_exit_node: Option<bool>,
    pub abuseipdb_score: Option<u8>,
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Reputation;
    super::run_guarded(&ctx, id, &tx, async {
        let ip = super::resolve_target_ip(&ctx).await?;
        let mut result = ReputationResult {
            ip: Some(ip),
            ..Default::default()
        };

        let IpAddr::V4(v4) = ip else {
            result
                .errors
                .push("DNSBLs only cover IPv4; skipping for this IPv6 address".to_string());
            return Ok(CheckUpdate::Reputation(result));
        };

        let timeout = ctx.config.timeouts.reputation;
        for &zone in DNSBL_ZONES {
            result.dnsbl.push(query_dnsbl(v4, zone, timeout).await);
        }

        match query_tor_exit_list(v4, timeout).await {
            Ok(is_exit) => result.tor_exit_node = Some(is_exit),
            Err(err) => result.errors.push(format!("Tor exit list: {err}")),
        }

        if let Some(key) = &ctx.config.reputation.abuseipdb_key {
            match query_abuseipdb(v4, key, timeout).await {
                Ok(score) => result.abuseipdb_score = Some(score),
                Err(err) => result.errors.push(format!("AbuseIPDB: {err}")),
            }
        }

        Ok(CheckUpdate::Reputation(result))
    })
    .await;
}

fn reversed_octets(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

async fn query_dnsbl(ip: Ipv4Addr, zone: &str, timeout: Duration) -> DnsblHit {
    let query = format!("{}.{zone}", reversed_octets(ip));
    match crate::checks::dns::resolve_addrs(&query, timeout).await {
        Ok(addrs) => {
            let codes = addrs
                .into_iter()
                .filter_map(|a| match a {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect();
            DnsblHit {
                zone: zone.to_string(),
                listed: true,
                codes,
            }
        }
        Err(_) => DnsblHit {
            zone: zone.to_string(),
            listed: false,
            codes: Vec::new(),
        },
    }
}

/// The Tor Project publishes a plain-text list of current exit-node IPs,
/// refreshed roughly hourly; no key needed.
async fn query_tor_exit_list(ip: Ipv4Addr, timeout: Duration) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let body = client
        .get("https://check.torproject.org/torbulkexitlist")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    let needle = ip.to_string();
    Ok(body.lines().any(|line| line.trim() == needle))
}

async fn query_abuseipdb(ip: Ipv4Addr, key: &str, timeout: Duration) -> Result<u8, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip.to_string())])
        .header("Key", key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("AbuseIPDB returned {}", response.status()));
    }
    let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    body.get("data")
        .and_then(|d| d.get("abuseConfidenceScore"))
        .and_then(|s| s.as_u64())
        .map(|s| s.min(100) as u8)
        .ok_or_else(|| "unexpected response shape".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_octets_for_dnsbl_query() {
        assert_eq!(reversed_octets("192.0.2.1".parse().unwrap()), "1.2.0.192");
    }
}
