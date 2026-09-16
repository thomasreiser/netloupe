//! DNS pane: A/AAAA/CNAME/MX/NS/SOA/TXT/CAA/SRV/PTR, plus a comparison
//! against a second resolver to surface split-horizon / inconsistent
//! answers.
//!
//! Full DNSSEC chain validation is out of scope for now (see the roadmap in
//! `CLAUDE.md`); this only reports whether the response carried the
//! Authenticated Data (AD) flag, which is a hint, not a validated chain.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::target::Target;

/// One MX record: preference plus the mail exchange hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// The SOA record for the queried zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

/// Everything the DNS check gathered for one target, from one resolver.
#[derive(Debug, Clone, Default)]
pub struct DnsResult {
    pub queried_name: String,
    pub resolver: String,
    pub a: Vec<Ipv4Addr>,
    pub aaaa: Vec<Ipv6Addr>,
    /// The CNAME chain, in resolution order (empty when the name has no
    /// CNAME and resolves directly).
    pub cnames: Vec<String>,
    pub mx: Vec<MxRecord>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub soa: Option<SoaRecord>,
    /// Rendered `tag value` pairs, e.g. `issue "letsencrypt.org"`.
    pub caa: Vec<String>,
    /// Rendered `priority weight port target`.
    pub srv: Vec<String>,
    /// Reverse-DNS names, populated when the target itself is an IP.
    pub ptr: Vec<String>,
    /// True if any answer in this run carried the DNS "Authenticated Data"
    /// flag. A hint that DNSSEC validation happened upstream, not proof: we
    /// don't walk the trust chain ourselves yet.
    pub authenticated_data: bool,
    /// One message per record type that failed to resolve (NXDOMAIN, a
    /// timeout, ...). Never fatal: a domain with no MX records still shows
    /// its A/NS/TXT records fine.
    pub errors: Vec<String>,
}

/// A hostname's IPs as seen by the system resolver vs. a comparison
/// resolver, when they disagree — a hint at split-horizon DNS.
#[derive(Debug, Clone)]
pub struct ResolverComparison {
    pub resolver: String,
    pub result: Result<Vec<IpAddr>, String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Dns;
    super::run_guarded(&ctx, id, &tx, async {
        let timeout = ctx.config.timeouts.dns;
        let mut result = match &ctx.target {
            Target::Host { ascii, .. } => resolve_host(ascii, timeout).await,
            Target::Ip(ip) => resolve_ip(*ip, timeout).await,
        };

        // Feed anything hosting-relevant into the shared store immediately,
        // even though this task keeps running comparison lookups.
        ctx.shared.set_dns(result.clone()).await;

        if let Target::Host { ascii, .. } = &ctx.target {
            compare_resolvers(ascii, &ctx, timeout, &mut result).await;
        }

        Ok(CheckUpdate::Dns(result))
    })
    .await;
}

async fn resolve_host(name: &str, timeout: Duration) -> DnsResult {
    let mut result = DnsResult {
        queried_name: name.to_string(),
        resolver: "system".to_string(),
        ..Default::default()
    };

    let resolver = match system_resolver(timeout) {
        Ok(r) => r,
        Err(err) => {
            result
                .errors
                .push(format!("could not set up the system resolver: {err}"));
            return result;
        }
    };

    fill_forward_records(&resolver, name, &mut result).await;
    result
}

async fn resolve_ip(ip: IpAddr, timeout: Duration) -> DnsResult {
    let mut result = DnsResult {
        queried_name: ip.to_string(),
        resolver: "system".to_string(),
        ..Default::default()
    };

    let resolver = match system_resolver(timeout) {
        Ok(r) => r,
        Err(err) => {
            result
                .errors
                .push(format!("could not set up the system resolver: {err}"));
            return result;
        }
    };

    match resolver.reverse_lookup(ip).await {
        Ok(lookup) => {
            result.ptr = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::PTR(ptr) => Some(ptr.0.to_string()),
                    _ => None,
                })
                .collect();
        }
        Err(err) => result.errors.push(format!("PTR: {err}")),
    }
    result
}

/// Runs the A/AAAA/MX/NS/TXT/SOA/CAA lookups a hostname target needs,
/// against `resolver`, filling in `result`.
async fn fill_forward_records(resolver: &TokioResolver, name: &str, result: &mut DnsResult) {
    match resolver.lookup_ip(name).await {
        Ok(lookup) => {
            let message = lookup.as_lookup().message();
            result.authenticated_data = message.metadata.authentic_data;
            for record in lookup.as_lookup().answers() {
                classify_forward_record(record, result);
            }
        }
        Err(err) => result.errors.push(format!("A/AAAA: {err}")),
    }

    match resolver.mx_lookup(name).await {
        Ok(lookup) => {
            result.mx = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(mx) => Some(MxRecord {
                        preference: mx.preference,
                        exchange: mx.exchange.to_string(),
                    }),
                    _ => None,
                })
                .collect();
        }
        Err(err) => result.errors.push(format!("MX: {err}")),
    }

    match resolver.ns_lookup(name).await {
        Ok(lookup) => {
            result.ns = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::NS(ns) => Some(ns.0.to_string()),
                    _ => None,
                })
                .collect();
        }
        Err(err) => result.errors.push(format!("NS: {err}")),
    }

    match resolver.txt_lookup(name).await {
        Ok(lookup) => {
            result.txt = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(txt_to_string(txt)),
                    _ => None,
                })
                .collect();
        }
        Err(err) => result.errors.push(format!("TXT: {err}")),
    }

    match resolver.soa_lookup(name).await {
        Ok(lookup) => {
            result.soa = lookup.answers().iter().find_map(|r| match &r.data {
                RData::SOA(soa) => Some(SoaRecord {
                    mname: soa.mname.to_string(),
                    rname: soa.rname.to_string(),
                    serial: soa.serial,
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire,
                    minimum: soa.minimum,
                }),
                _ => None,
            });
        }
        Err(err) => result.errors.push(format!("SOA: {err}")),
    }

    match resolver.lookup(name, RecordType::CAA).await {
        Ok(lookup) => {
            result.caa = lookup
                .answers()
                .iter()
                .map(|r| r.data.to_string())
                .collect()
        }
        Err(err) => result.errors.push(format!("CAA: {err}")),
    }

    match resolver.srv_lookup(name).await {
        Ok(lookup) => {
            result.srv = lookup
                .answers()
                .iter()
                .map(|r| r.data.to_string())
                .collect()
        }
        Err(err) => result.errors.push(format!("SRV: {err}")),
    }
}

fn classify_forward_record(record: &Record, result: &mut DnsResult) {
    match &record.data {
        RData::A(a) => result.a.push(a.0),
        RData::AAAA(aaaa) => result.aaaa.push(aaaa.0),
        RData::CNAME(cname) => {
            let name = cname.0.to_string();
            if !result.cnames.contains(&name) {
                result.cnames.push(name);
            }
        }
        _ => {}
    }
}

fn txt_to_string(txt: &hickory_proto::rr::rdata::TXT) -> String {
    txt.txt_data
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect::<Vec<_>>()
        .join("")
}

/// Builds a resolver rooted at `ip` (used for the comparison set: 1.1.1.1,
/// 8.8.8.8, 9.9.9.9, ...).
fn resolver_for(ip: IpAddr, timeout: Duration) -> Result<TokioResolver, String> {
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp_and_tcp(ip)]);
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().timeout = timeout;
    builder.build().map_err(|e| e.to_string())
}

fn system_resolver(timeout: Duration) -> Result<TokioResolver, String> {
    let mut builder = TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
    builder.options_mut().timeout = timeout;
    builder.build().map_err(|e| e.to_string())
}

/// Looks up `name`'s A/AAAA records against every configured comparison
/// resolver and records any that disagree with the system resolver's
/// answer, or that failed outright.
async fn compare_resolvers(
    name: &str,
    ctx: &CheckContext,
    timeout: Duration,
    result: &mut DnsResult,
) {
    if ctx.config.resolvers.comparison.is_empty() {
        return;
    }
    let baseline: std::collections::BTreeSet<IpAddr> = result
        .a
        .iter()
        .map(|ip| IpAddr::V4(*ip))
        .chain(result.aaaa.iter().map(|ip| IpAddr::V6(*ip)))
        .collect();

    for &server in &ctx.config.resolvers.comparison {
        let name = name.to_string();
        let comparison = match resolver_for(server, timeout) {
            Ok(resolver) => match resolver.lookup_ip(name.as_str()).await {
                Ok(lookup) => {
                    let ips: std::collections::BTreeSet<IpAddr> = lookup.iter().collect();
                    if ips != baseline {
                        Some(format!(
                            "{server} resolved {name} to {{{}}} vs. the system resolver's {{{}}}",
                            fmt_set(&ips),
                            fmt_set(&baseline),
                        ))
                    } else {
                        None
                    }
                }
                Err(err) => Some(format!("{server} failed to resolve {name}: {err}")),
            },
            Err(err) => Some(format!("could not query {server}: {err}")),
        };
        if let Some(message) = comparison {
            result.errors.push(message);
        }
    }
}

fn fmt_set(ips: &std::collections::BTreeSet<IpAddr>) -> String {
    ips.iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolves `name`'s A/AAAA records with a short-lived resolver, for use by
/// other checks (ping, tls, http) that need an address but don't want to
/// duplicate resolver setup. Not part of `DnsResult` since it's a plain
/// utility, not a pane's data.
pub async fn resolve_addrs(name: &str, timeout: Duration) -> Result<Vec<IpAddr>, String> {
    let resolver = system_resolver(timeout)?;
    resolver
        .lookup_ip(name)
        .await
        .map(|lookup| lookup.iter().collect())
        .map_err(|e| e.to_string())
}

/// Looks up MX records for an arbitrary name, for checks (mail) that need
/// a one-off MX query outside the main `DnsResult`.
pub async fn lookup_mx(name: &str, timeout: Duration) -> Result<Vec<MxRecord>, String> {
    let resolver = system_resolver(timeout)?;
    match resolver.mx_lookup(name).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::MX(mx) => Some(MxRecord {
                    preference: mx.preference,
                    exchange: mx.exchange.to_string(),
                }),
                _ => None,
            })
            .collect()),
        Err(err) if err.to_string().to_lowercase().contains("no record") => Ok(Vec::new()),
        Err(err) => Err(err.to_string()),
    }
}

/// Looks up TXT records for an arbitrary name, for checks (SPF, DMARC,
/// Cymru ASN whois, ...) that need one-off TXT lookups outside the main
/// `DnsResult`. Empty on NXDOMAIN/no-data rather than an error, since "no
/// TXT records" is a normal, common answer.
pub async fn lookup_txt(name: &str, timeout: Duration) -> Result<Vec<String>, String> {
    let resolver = system_resolver(timeout)?;
    match resolver.txt_lookup(name).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => Some(txt_to_string(txt)),
                _ => None,
            })
            .collect()),
        Err(err) if err.to_string().to_lowercase().contains("no record") => Ok(Vec::new()),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_chunks_join_without_separator() {
        let txt = hickory_proto::rr::rdata::TXT::new(vec![
            "v=spf1 ".to_string(),
            "include:_spf.google.com ~all".to_string(),
        ]);
        assert_eq!(txt_to_string(&txt), "v=spf1 include:_spf.google.com ~all");
    }

    #[test]
    fn classify_forward_record_collects_a_aaaa_and_cname() {
        use hickory_proto::rr::{rdata, Name};
        use std::str::FromStr;

        let mut result = DnsResult::default();
        let name = Name::from_str("example.com.").unwrap();

        let a = Record::from_rdata(
            name.clone(),
            300,
            RData::A(rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        classify_forward_record(&a, &mut result);

        let cname_target = Name::from_str("edge.example.net.").unwrap();
        let cname = Record::from_rdata(name.clone(), 300, RData::CNAME(rdata::CNAME(cname_target)));
        classify_forward_record(&cname, &mut result);

        assert_eq!(result.a, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        assert_eq!(result.cnames, vec!["edge.example.net.".to_string()]);
    }
}
