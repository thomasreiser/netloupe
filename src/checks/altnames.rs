//! Alternative-hostname discovery, feeding the Overview pane's summary.
//!
//! For an IP target: what DNS names point at it (PTR, the certificate it
//! presents, certificate-transparency history, reverse-IP/passive-DNS).
//! For a hostname target: what *other* names share its destination — same
//! IP, same certificate, same CT log history. Either way the result is the
//! same shape: a deduped list of names, each tagged with which source(s)
//! corroborate it, so more agreement reads as more confidence.
//!
//! Every source here is public-record/passive (reverse DNS, a certificate
//! the server handed us anyway, public CT logs, a reverse-IP index) — the
//! same category as the RDAP/DNSBL/Cymru-whois lookups other checks
//! already make automatically, not an active probe of the target beyond
//! what the DNS/TLS checks already do. Best-effort throughout: any one
//! source failing (CT log timeout, reverse-IP API rate limit, ...) just
//! means fewer corroborating tags, never a failed check.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::retry::{self, Failure};
use crate::target::Target;

/// How a name was found. A name corroborated by more than one source is
/// more trustworthy evidence of "same destination" than any one alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameSource {
    /// Reverse-DNS (PTR) on a candidate IP.
    Ptr,
    /// Listed as a SAN on the certificate the server presented.
    TlsSan,
    /// Seen in public Certificate Transparency log history (crt.sh).
    CertificateTransparency,
    /// A reverse-IP/passive-DNS index reports it resolving to the same IP.
    ReverseIp,
}

impl NameSource {
    pub fn label(self) -> &'static str {
        match self {
            NameSource::Ptr => "PTR",
            NameSource::TlsSan => "TLS cert",
            NameSource::CertificateTransparency => "CT log",
            NameSource::ReverseIp => "reverse-IP",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AltName {
    pub name: String,
    pub sources: Vec<NameSource>,
}

#[derive(Debug, Clone, Default)]
pub struct AltNamesResult {
    /// The IP(s) these names were derived from (the target itself, or its
    /// resolved A/AAAA addresses).
    pub ips: Vec<IpAddr>,
    /// Deduped, sorted by corroborating-source count then name.
    pub names: Vec<AltName>,
    pub errors: Vec<String>,
}

/// How long to wait for DNS/TLS to populate shared state before working
/// with whatever's available; those checks seed the PTR/cert-SAN sources.
/// Short on purpose: both usually land within a second or two, and this
/// check would rather run once on a mostly-complete picture than stall.
const SEED_WAIT_BUDGET: Duration = Duration::from_secs(4);

/// More reverse-IP hits than this on one address means shared hosting or a
/// CDN edge IP, not a dedicated "same destination" — see `gather`.
const REVERSE_IP_SHARED_HOSTING_THRESHOLD: usize = 15;

/// crt.sh's own timeout, kept separate from `config.timeouts.http` (that
/// one governs the HTTP *check*, a different concern): a popular domain's
/// full CT log history can be a megabyte-plus and take several seconds to
/// download and parse, well past a typical page-load budget.
const CRTSH_TIMEOUT: Duration = Duration::from_secs(12);

/// Also kept separate from `config.timeouts.http`; HackerTarget's free
/// tier can be slow under load.
const REVERSE_IP_TIMEOUT: Duration = Duration::from_secs(8);

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::AltNames;
    super::run_guarded(&ctx, id, &tx, async {
        wait_for_seed_data(&ctx).await;
        Ok(CheckUpdate::AltNames(gather(&ctx).await))
    })
    .await;
}

/// Waits (bounded) for the DNS check, and the TLS check when this target
/// even has a TLS-reachable identity, to land in shared state.
async fn wait_for_seed_data(ctx: &CheckContext) {
    let deadline = tokio::time::Instant::now() + SEED_WAIT_BUDGET;
    loop {
        let snap = ctx.shared.snapshot().await;
        if snap.dns.is_some() && snap.tls.is_some() {
            return;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        tokio::select! {
            _ = ctx.shared.wait_for_change() => {}
            _ = tokio::time::sleep(remaining) => return,
        }
    }
}

async fn gather(ctx: &CheckContext) -> AltNamesResult {
    let snap = ctx.shared.snapshot().await;
    let mut result = AltNamesResult::default();
    let mut found: HashMap<String, HashSet<NameSource>> = HashMap::new();

    let mut ips: Vec<IpAddr> = Vec::new();
    if let Target::Ip(ip) = ctx.target {
        ips.push(ip);
    }
    if let Some(dns) = &snap.dns {
        ips.extend(dns.a.iter().map(|ip| IpAddr::V4(*ip)));
        ips.extend(dns.aaaa.iter().map(|ip| IpAddr::V6(*ip)));
    }
    ips.dedup();
    result.ips = ips.clone();

    // PTR: an IP target's own DNS check already did this; a hostname
    // target's didn't (it only reverse-resolves when the target *is* an
    // IP), so do it ourselves for each resolved address.
    if let Target::Ip(_) = ctx.target {
        if let Some(dns) = &snap.dns {
            for name in &dns.ptr {
                insert(&mut found, name, NameSource::Ptr);
            }
        }
    } else {
        for &ip in &ips {
            let opts = crate::checks::dns::DnsOpts::new(ctx.config.timeouts.dns, ctx.resolver);
            match crate::checks::dns::lookup_ptr(ip, opts).await {
                Ok(names) => {
                    for name in names {
                        insert(&mut found, &name, NameSource::Ptr);
                    }
                }
                Err(err) => result.errors.push(format!("PTR for {ip}: {err}")),
            }
        }
    }

    // The certificate the server handed us is strong evidence: every name
    // on it is, by construction, served by the same TLS endpoint.
    if let Some(tls) = &snap.tls {
        for san in &tls.sans {
            if san.parse::<IpAddr>().is_err() {
                insert(&mut found, san, NameSource::TlsSan);
            }
        }
    }

    // Certificate Transparency: search using whatever hostname-shaped seed
    // we have (the target itself, or a name PTR/TLS already turned up) —
    // crt.sh indexes by name, not IP, so an IP target with nothing else
    // found yet has no seed and this source is simply skipped.
    let seed_domain = match &ctx.target {
        Target::Host { ascii, .. } => Some(ascii.clone()),
        Target::Ip(_) => found.keys().next().cloned(),
    };

    // crt.sh and the reverse-IP lookups don't depend on each other, so run
    // them concurrently rather than paying their tail latencies twice.
    let candidate_ips: Vec<IpAddr> = ips.iter().take(2).copied().collect();
    let crtsh_fut = async {
        match &seed_domain {
            Some(domain) => Some(query_crtsh(domain, CRTSH_TIMEOUT).await),
            None => None,
        }
    };
    let reverse_ip_fut = futures::future::join_all(
        candidate_ips
            .iter()
            .map(|&ip| async move { (ip, query_reverse_ip(ip, REVERSE_IP_TIMEOUT).await) }),
    );
    let (crtsh_result, reverse_ip_results) = tokio::join!(crtsh_fut, reverse_ip_fut);

    if let Some(outcome) = crtsh_result {
        match outcome {
            Ok(names) => {
                for name in names {
                    insert(&mut found, &name, NameSource::CertificateTransparency);
                }
            }
            Err(err) => result.errors.push(format!("crt.sh: {err}")),
        }
    }

    for (ip, outcome) in reverse_ip_results {
        match outcome {
            Ok(names) if names.len() > REVERSE_IP_SHARED_HOSTING_THRESHOLD => {
                // This many unrelated names on one IP means shared
                // hosting/a CDN, not "the same destination" — folding them
                // all in would bury the real signal in noise.
                result.errors.push(format!(
                    "reverse-IP for {ip}: {} other names share this address (shared hosting/CDN) — skipped as not meaningfully \"the same destination\"",
                    names.len()
                ));
            }
            Ok(names) => {
                for name in names {
                    insert(&mut found, &name, NameSource::ReverseIp);
                }
            }
            Err(err) => result.errors.push(format!("reverse-IP for {ip}: {err}")),
        }
    }

    let self_name = match &ctx.target {
        Target::Host { ascii, .. } => Some(normalize(ascii)),
        Target::Ip(_) => None,
    };

    let mut names: Vec<AltName> = found
        .into_iter()
        .filter(|(name, _)| Some(name.clone()) != self_name)
        .map(|(name, sources)| {
            let mut sources: Vec<NameSource> = sources.into_iter().collect();
            sources.sort_by_key(|s| *s as u8);
            AltName { name, sources }
        })
        .collect();
    names.sort_by(|a, b| {
        b.sources
            .len()
            .cmp(&a.sources.len())
            .then_with(|| a.name.cmp(&b.name))
    });
    names.truncate(40); // keep the summary and the picker readable

    result.names = names;
    result
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

fn insert(map: &mut HashMap<String, HashSet<NameSource>>, name: &str, source: NameSource) {
    let name = normalize(name);
    if name.is_empty() || name.starts_with("*.") {
        return; // a bare wildcard label isn't an openable hostname
    }
    map.entry(name).or_default().insert(source);
}

/// Searches crt.sh's public Certificate Transparency log index for certs
/// naming `domain`, returning every distinct SAN/CN seen across the
/// (capped) result set.
async fn query_crtsh(domain: &str, timeout: Duration) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;

    // Retried (see `crate::retry`): crt.sh is netloupe's own helper
    // request to a third party, and it's known to intermittently 502/503
    // under load, which a short backoff-and-retry usually rides out.
    retry::run(&retry::Policy::default(), || async {
        let response = client
            .get("https://crt.sh/")
            .query(&[("q", domain), ("output", "json")])
            .send()
            .await
            .map_err(retry::classify_send_error)?;
        if !response.status().is_success() {
            return Err(retry::classify_status(response.status()));
        }
        let entries: Vec<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| Failure::Retryable(e.to_string()))?;

        let mut names = std::collections::BTreeSet::new();
        for entry in entries.iter().take(200) {
            let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) else {
                continue;
            };
            for line in name_value.lines() {
                let name = normalize(line);
                if !name.is_empty() {
                    names.insert(name);
                }
            }
        }
        Ok(names.into_iter().collect())
    })
    .await
}

/// HackerTarget's free reverse-IP/passive-DNS lookup: no key needed, but
/// rate-limited, so a failure (including a rate-limit message in the
/// plain-text body) is treated as "no data from this source", not fatal.
async fn query_reverse_ip(ip: IpAddr, timeout: Duration) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;

    // Retried like `query_crtsh` above, with one exception: the free
    // tier's rate-limit message arrives as a 200 with text in the body,
    // not a 429, and retrying immediately into an active rate limit
    // would just burn the retry budget for nothing -- that one case is
    // `Fatal` rather than `Retryable`.
    retry::run(&retry::Policy::default(), || async {
        let response = client
            .get("https://api.hackertarget.com/reverseiplookup/")
            .query(&[("q", ip.to_string())])
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
        let lower = body.to_lowercase();
        if lower.contains("error") || lower.contains("api count exceeded") {
            return Err(Failure::Fatal(body.trim().to_string()));
        }
        Ok(body
            .lines()
            .map(normalize)
            .filter(|l| !l.is_empty())
            .collect())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_normalizes_case_and_trailing_dot() {
        let mut map = HashMap::new();
        insert(&mut map, "Example.COM.", NameSource::Ptr);
        assert!(map.contains_key("example.com"));
    }

    #[test]
    fn insert_merges_sources_for_the_same_name() {
        let mut map = HashMap::new();
        insert(&mut map, "example.com", NameSource::Ptr);
        insert(&mut map, "EXAMPLE.COM", NameSource::TlsSan);
        assert_eq!(map["example.com"].len(), 2);
    }

    #[test]
    fn insert_skips_bare_wildcard_labels() {
        let mut map = HashMap::new();
        insert(&mut map, "*.example.com", NameSource::TlsSan);
        assert!(map.is_empty());
    }

    #[test]
    fn insert_skips_empty_names() {
        let mut map = HashMap::new();
        insert(&mut map, "  ", NameSource::Ptr);
        assert!(map.is_empty());
    }
}
