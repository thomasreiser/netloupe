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
use crate::retry::{self, Failure};

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

        // DNSBLs, the Tor exit list, and AbuseIPDB all track abuse *on the
        // public Internet*; a private/loopback/link-local/etc. address was
        // never eligible to be listed anywhere, so querying them would
        // only ever say "clean" — a fact about the list, not about this
        // address. Skip the network calls and say why instead.
        let class = crate::checks::ipinfo::classify(ip);
        if !class.is_global() {
            result.errors.push(format!(
                "{ip} is a {} address — public reputation lists don't apply to it",
                class.label()
            ));
            return Ok(CheckUpdate::Reputation(result));
        }

        let IpAddr::V4(v4) = ip else {
            result
                .errors
                .push("DNSBLs only cover IPv4; skipping for this IPv6 address".to_string());
            return Ok(CheckUpdate::Reputation(result));
        };

        let timeout = ctx.config.timeouts.reputation;
        let dns_opts = crate::checks::dns::DnsOpts::new(timeout, ctx.resolver);
        for &zone in DNSBL_ZONES {
            result.dnsbl.push(query_dnsbl(v4, zone, dns_opts).await);
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

async fn query_dnsbl(ip: Ipv4Addr, zone: &str, opts: crate::checks::dns::DnsOpts) -> DnsblHit {
    let query = format!("{}.{zone}", reversed_octets(ip));
    match crate::checks::dns::resolve_addrs(&query, opts).await {
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
/// refreshed roughly hourly; no key needed. Retried (see `crate::retry`)
/// since it's netloupe's own helper request to a third party, not a
/// measurement of the target itself.
async fn query_tor_exit_list(ip: Ipv4Addr, timeout: Duration) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let needle = ip.to_string();

    retry::run(&retry::Policy::default(), || async {
        let response = client
            .get("https://check.torproject.org/torbulkexitlist")
            .send()
            .await
            .map_err(retry::classify_send_error)?;
        if !response.status().is_success() {
            return Err(retry::classify_status(response.status()));
        }
        let body = response
            .text()
            .await
            .map_err(|e| Failure::Retryable(e.to_string()))?;
        Ok(body.lines().any(|line| line.trim() == needle))
    })
    .await
}

/// Retried like `query_tor_exit_list` above -- AbuseIPDB is a third-party
/// helper, not the target itself.
async fn query_abuseipdb(ip: Ipv4Addr, key: &str, timeout: Duration) -> Result<u8, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;

    retry::run(&retry::Policy::default(), || async {
        let response = client
            .get("https://api.abuseipdb.com/api/v2/check")
            .query(&[("ipAddress", ip.to_string())])
            .header("Key", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(retry::classify_send_error)?;
        if !response.status().is_success() {
            return Err(retry::classify_status(response.status()));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Failure::Retryable(e.to_string()))?;
        body.get("data")
            .and_then(|d| d.get("abuseConfidenceScore"))
            .and_then(|s| s.as_u64())
            .map(|s| s.min(100) as u8)
            .ok_or_else(|| Failure::Fatal("unexpected response shape".to_string()))
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::checks::{CheckContext, SharedResultsHandle};
    use crate::config::Config;
    use crate::event::CheckPayload;
    use crate::providers::ProviderDb;
    use crate::target::Target;

    #[test]
    fn reverses_octets_for_dnsbl_query() {
        assert_eq!(reversed_octets("192.0.2.1".parse().unwrap()), "1.2.0.192");
    }

    /// A private-address target has never been eligible for listing on a
    /// public DNSBL/Tor-exit list, so the check must skip those queries
    /// entirely and say why, rather than reporting a meaningless "clean".
    #[tokio::test]
    async fn skips_reputation_lookups_for_a_private_address() {
        let ctx = CheckContext {
            tab_id: 0,
            target: Target::Ip("10.0.0.5".parse().unwrap()),
            port: None,
            config: Arc::new(Config::default()),
            cancel: CancellationToken::new(),
            shared: SharedResultsHandle::new(),
            providers: Arc::new(ProviderDb::default()),
            resolver: None,
            ping_paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let (tx, mut rx) = mpsc::channel(8);
        run(ctx, tx).await;

        let mut done = None;
        while let Some(event) = rx.recv().await {
            if let CheckPayload::Done(CheckUpdate::Reputation(rep)) = event.payload {
                done = Some(rep);
                break;
            }
        }
        let rep = done.expect("reputation check must report Done even when it skips the lookup");

        assert!(rep.dnsbl.is_empty());
        assert!(rep.tor_exit_node.is_none());
        assert_eq!(rep.errors.len(), 1);
        assert!(
            rep.errors[0].contains("private"),
            "expected the error to name the address class: {:?}",
            rep.errors[0]
        );
    }
}
