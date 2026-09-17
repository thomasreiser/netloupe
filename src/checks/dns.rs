//! DNS pane: A/AAAA/CNAME/MX/NS/SOA/TXT/CAA/SRV/PTR, plus a comparison
//! against a second resolver to surface split-horizon / inconsistent
//! answers.
//!
//! Full DNSSEC chain validation is out of scope for now (see the roadmap in
//! `CLAUDE.md`); this only reports whether the response carried the
//! Authenticated Data (AD) flag, which is a hint, not a validated chain.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::{Resolver, TokioResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::target::Target;

/// One DNS record as the pane's table shows it: its type, rendered
/// value, and the TTL (seconds) the server reported for it. Kept
/// alongside (not instead of) `DnsResult`'s typed per-type fields
/// (`a`, `aaaa`, `ns`, ...), which other checks and the headless JSON
/// output consume without needing TTL. `ttl` is `None` for the one
/// record type that doesn't carry one through here: PTR, since its
/// lookup is shared with `checks::altnames`' one-off reverse queries
/// via `lookup_ptr`, which returns plain names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordRow {
    pub record_type: &'static str,
    pub value: String,
    pub ttl: Option<u32>,
}

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
    /// Every A/AAAA/CNAME/MX/NS/TXT/CAA/SRV/PTR record above, alongside
    /// its TTL, in fetch order -- what the DNS pane's table renders
    /// directly, rather than re-deriving type/value/TTL from the typed
    /// fields above (which stay as-is for the other checks and the
    /// headless JSON output that consume them).
    pub records: Vec<DnsRecordRow>,
    /// True if any answer in this run carried the DNS "Authenticated Data"
    /// flag. A hint that DNSSEC validation happened upstream, not proof: we
    /// don't walk the trust chain ourselves yet.
    pub authenticated_data: bool,
    /// A `QTYPE=ANY` query's answers, rendered `TYPE value`. Usually empty
    /// or minimal even for a fully-populated zone — see `any_note`.
    pub any_records: Vec<String>,
    /// Set when `any_records` came back empty/minimal, explaining why
    /// that's normal rather than a failure.
    pub any_note: Option<&'static str>,
    /// Whether (and how) the zone uses DNSSEC denial-of-existence, learned
    /// by probing a name that shouldn't exist. `Nsec` means the zone can
    /// be walked name-by-name (see `checks::zonewalk`); `Nsec3` means it
    /// can't, without offline hash-cracking this tool doesn't attempt.
    pub zone_signing: ZoneSigning,
    /// One zone-transfer attempt per authoritative nameserver. Almost
    /// always refused (that's the secure, expected configuration) —
    /// `succeeded: true` on any of these is a real misconfiguration worth
    /// flagging prominently.
    pub axfr: Vec<AxfrAttempt>,
    /// One message per record type that failed to resolve (NXDOMAIN, a
    /// timeout, ...). Never fatal: a domain with no MX records still shows
    /// its A/NS/TXT records fine.
    pub errors: Vec<String>,
}

/// What a probe for a deliberately nonexistent name under the zone
/// revealed about its DNSSEC denial-of-existence method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZoneSigning {
    /// The probe didn't clearly show NSEC or NSEC3 (unsigned zone, or an
    /// inconclusive/failed probe).
    #[default]
    NotSignedOrUnknown,
    /// RFC 4034 NSEC: each denial-of-existence response names the next
    /// real name in the zone in canonical order, so the whole zone can be
    /// enumerated by repeatedly following that chain.
    Nsec,
    /// RFC 5155 NSEC3: denial-of-existence uses hashed owner names, so
    /// walking the zone this way isn't possible without cracking those
    /// hashes offline — out of scope for a passive diagnostic tool.
    Nsec3,
}

/// One nameserver's response to an AXFR (zone transfer) attempt.
#[derive(Debug, Clone)]
pub struct AxfrAttempt {
    pub nameserver: String,
    pub succeeded: bool,
    pub record_count: usize,
    pub detail: String,
}

/// A hostname's IPs as seen by the system resolver vs. a comparison
/// resolver, when they disagree — a hint at split-horizon DNS.
#[derive(Debug, Clone)]
pub struct ResolverComparison {
    pub resolver: String,
    pub result: Result<Vec<IpAddr>, String>,
}

/// Which resolver to query and how long to wait — bundled since nearly
/// every lookup in this module needs both together. `resolver` carries
/// the per-tab custom DNS server the user picked when opening the tab
/// (`CheckContext::resolver`), threaded down to every lookup here,
/// including the ones other checks (mail, acme, altnames, ...) make
/// through this module's public `lookup_*`/`resolve_addrs` functions —
/// `None` means the system's normally-configured resolver.
#[derive(Debug, Clone, Copy)]
pub struct DnsOpts {
    pub timeout: Duration,
    pub resolver: Option<IpAddr>,
}

impl DnsOpts {
    pub fn new(timeout: Duration, resolver: Option<IpAddr>) -> Self {
        Self { timeout, resolver }
    }
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Dns;
    super::run_guarded(&ctx, id, &tx, async {
        let timeout = ctx.config.timeouts.dns;
        let opts = DnsOpts::new(timeout, ctx.resolver);
        let mut result = match &ctx.target {
            Target::Host { ascii, .. } => resolve_host(ascii, opts).await,
            Target::Ip(ip) => resolve_ip(*ip, opts).await,
        };
        if let Some(server) = ctx.resolver {
            result.resolver = server.to_string();
        }

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

async fn resolve_host(name: &str, opts: DnsOpts) -> DnsResult {
    let mut result = DnsResult {
        queried_name: name.to_string(),
        resolver: "system".to_string(),
        ..Default::default()
    };

    let resolver = match system_resolver(opts) {
        Ok(r) => r,
        Err(err) => {
            result
                .errors
                .push(format!("could not set up the resolver: {err}"));
            return result;
        }
    };

    fill_forward_records(&resolver, name, &mut result).await;

    fill_any_query(&resolver, name, &mut result).await;
    result.zone_signing = detect_zone_signing(name, opts).await;
    result.axfr = attempt_axfr_all(name, &result.ns, opts).await;

    result
}

async fn resolve_ip(ip: IpAddr, opts: DnsOpts) -> DnsResult {
    let mut result = DnsResult {
        queried_name: ip.to_string(),
        resolver: "system".to_string(),
        ..Default::default()
    };

    match lookup_ptr(ip, opts).await {
        Ok(names) => {
            result.records = names
                .iter()
                .map(|name| DnsRecordRow {
                    record_type: "PTR",
                    value: name.clone(),
                    ttl: None,
                })
                .collect();
            result.ptr = names;
        }
        Err(err) => result.errors.push(format!("PTR: {err}")),
    }
    result
}

/// Looks up PTR (reverse-DNS) records for an arbitrary IP, for checks
/// (alternative-hostname discovery) that need a one-off PTR query outside
/// the main `DnsResult`.
pub async fn lookup_ptr(ip: IpAddr, opts: DnsOpts) -> Result<Vec<String>, String> {
    let resolver = system_resolver(opts)?;
    match resolver.reverse_lookup(ip).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.0.to_string()),
                _ => None,
            })
            .collect()),
        Err(err) if err.to_string().to_lowercase().contains("no record") => Ok(Vec::new()),
        Err(err) => Err(err.to_string()),
    }
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
            for r in lookup.answers() {
                if let RData::MX(mx) = &r.data {
                    let exchange = mx.exchange.to_string();
                    result.mx.push(MxRecord {
                        preference: mx.preference,
                        exchange: exchange.clone(),
                    });
                    result.records.push(DnsRecordRow {
                        record_type: "MX",
                        value: format!("{} {exchange}", mx.preference),
                        ttl: Some(r.ttl),
                    });
                }
            }
        }
        Err(err) => result.errors.push(format!("MX: {err}")),
    }

    match resolver.ns_lookup(name).await {
        Ok(lookup) => {
            for r in lookup.answers() {
                if let RData::NS(ns) = &r.data {
                    let name = ns.0.to_string();
                    result.ns.push(name.clone());
                    result.records.push(DnsRecordRow {
                        record_type: "NS",
                        value: name,
                        ttl: Some(r.ttl),
                    });
                }
            }
        }
        Err(err) => result.errors.push(format!("NS: {err}")),
    }

    match resolver.txt_lookup(name).await {
        Ok(lookup) => {
            for r in lookup.answers() {
                if let RData::TXT(txt) = &r.data {
                    let text = txt_to_string(txt);
                    result.txt.push(text.clone());
                    result.records.push(DnsRecordRow {
                        record_type: "TXT",
                        value: text,
                        ttl: Some(r.ttl),
                    });
                }
            }
        }
        Err(err) => result.errors.push(format!("TXT: {err}")),
    }

    match resolver.soa_lookup(name).await {
        Ok(lookup) => {
            if let Some((soa, ttl)) = lookup.answers().iter().find_map(|r| match &r.data {
                RData::SOA(soa) => Some((soa, r.ttl)),
                _ => None,
            }) {
                result.records.push(DnsRecordRow {
                    record_type: "SOA",
                    value: format!("{} {} serial={}", soa.mname, soa.rname, soa.serial),
                    ttl: Some(ttl),
                });
                result.soa = Some(SoaRecord {
                    mname: soa.mname.to_string(),
                    rname: soa.rname.to_string(),
                    serial: soa.serial,
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire,
                    minimum: soa.minimum,
                });
            }
        }
        Err(err) => result.errors.push(format!("SOA: {err}")),
    }

    match resolver.lookup(name, RecordType::CAA).await {
        Ok(lookup) => {
            for r in lookup.answers() {
                let value = r.data.to_string();
                result.caa.push(value.clone());
                result.records.push(DnsRecordRow {
                    record_type: "CAA",
                    value,
                    ttl: Some(r.ttl),
                });
            }
        }
        Err(err) => result.errors.push(format!("CAA: {err}")),
    }

    match resolver.srv_lookup(name).await {
        Ok(lookup) => {
            for r in lookup.answers() {
                let value = r.data.to_string();
                result.srv.push(value.clone());
                result.records.push(DnsRecordRow {
                    record_type: "SRV",
                    value,
                    ttl: Some(r.ttl),
                });
            }
        }
        Err(err) => result.errors.push(format!("SRV: {err}")),
    }
}

/// A `QTYPE=ANY` query. Kept separate from `fill_forward_records`'s
/// per-type lookups since this is a single extra query, not a record type
/// of its own, and its "usually near-empty" result needs its own
/// explanation (RFC 8482) rather than looking like every other row.
async fn fill_any_query(resolver: &TokioResolver, name: &str, result: &mut DnsResult) {
    match resolver.lookup(name, RecordType::ANY).await {
        Ok(lookup) => {
            result.any_records = lookup
                .answers()
                .iter()
                .map(|r| format!("{:?} {}", r.record_type(), r.data))
                .collect();
            if result.any_records.is_empty() {
                result.any_note = Some(
                    "empty — most nameservers now restrict ANY to a minimal/synthetic response (RFC 8482), to curb its use in DNS amplification attacks",
                );
            }
        }
        // A nameserver refusing ANY outright (NotImp/Refused) is at least
        // as common today as a minimal reply, per RFC 8482 — expected
        // behavior, not a failure, so it gets the same explanatory note
        // rather than cluttering `errors` with something to worry about.
        Err(NetError::Dns(DnsError::ResponseCode(
            ResponseCode::NotImp | ResponseCode::Refused,
        ))) => {
            result.any_note = Some(
                "refused — most nameservers now decline ANY entirely or restrict it to a minimal/synthetic response (RFC 8482), to curb its use in DNS amplification attacks",
            );
        }
        Err(err) => result.errors.push(format!("ANY: {err}")),
    }
}

/// Probes a name that should never exist under this zone and inspects the
/// resulting NXDOMAIN's authority section for an NSEC or NSEC3 record,
/// revealing which denial-of-existence method (if either) the zone uses.
/// Pure protocol observation — this alone doesn't enumerate anything.
async fn detect_zone_signing(name: &str, opts: DnsOpts) -> ZoneSigning {
    let Ok(resolver) = dnssec_probe_resolver(opts) else {
        return ZoneSigning::NotSignedOrUnknown;
    };
    // Trailing dot: an absolute name, so the resolver queries it as-is
    // instead of also trying it with the local search domain appended
    // (which would probe a name under the *search domain's* zone, not
    // this one, and misreport its signing status entirely).
    let probe = format!("_netloupe-nsec-probe.{}.", name.trim_end_matches('.'));
    match resolver.lookup(probe.as_str(), RecordType::A).await {
        // The probe name surprisingly exists; not informative either way.
        Ok(_) => ZoneSigning::NotSignedOrUnknown,
        Err(err) => classify_nsec_error(&err),
    }
}

fn classify_nsec_error(err: &NetError) -> ZoneSigning {
    // A validating resolver (`dnssec_probe_resolver` turns this on) that
    // confirms the negative response is DNSSEC-signed reports it through
    // this dedicated variant instead of the plain `NoRecordsFound` a
    // non-validating lookup would get — the raw NSEC/NSEC3 records are
    // still in `response`'s authority section either way.
    let authorities: &[Record] = match err {
        NetError::Dns(DnsError::Nsec { response, .. }) => &response.authorities,
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => match &no_records.authorities {
            Some(authorities) => authorities,
            None => return ZoneSigning::NotSignedOrUnknown,
        },
        _ => return ZoneSigning::NotSignedOrUnknown,
    };

    let mut saw_nsec3 = false;
    let mut saw_nsec = false;
    for record in authorities {
        match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC3(_)) => saw_nsec3 = true,
            RData::DNSSEC(DNSSECRData::NSEC(_)) => saw_nsec = true,
            _ => {}
        }
    }
    // NSEC3 takes precedence if somehow both appear: it's the stricter
    // (non-walkable) case, and misreporting the safer one would be worse.
    if saw_nsec3 {
        ZoneSigning::Nsec3
    } else if saw_nsec {
        ZoneSigning::Nsec
    } else {
        ZoneSigning::NotSignedOrUnknown
    }
}

/// How many authoritative nameservers to try AXFR against; a zone rarely
/// has more than a handful, and each attempt already fails fast (REFUSED
/// arrives in the very first response) except in the rare success case.
const AXFR_NAMESERVER_CAP: usize = 4;
/// Safety bounds on a *successful* transfer, so an unusually permissive
/// nameserver with a huge zone can't make this check run unbounded.
const AXFR_MAX_MESSAGES: usize = 200;
const AXFR_MAX_RECORDS: usize = 5_000;

async fn attempt_axfr_all(zone: &str, ns_names: &[String], opts: DnsOpts) -> Vec<AxfrAttempt> {
    let mut attempts = Vec::new();
    for ns_name in ns_names.iter().take(AXFR_NAMESERVER_CAP) {
        let ns_host = ns_name.trim_end_matches('.').to_string();
        let ip = match resolve_addrs(&ns_host, opts).await {
            Ok(ips) => ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| ips.first())
                .copied(),
            Err(_) => None,
        };
        let Some(ip) = ip else {
            attempts.push(AxfrAttempt {
                nameserver: ns_host,
                succeeded: false,
                record_count: 0,
                detail: "could not resolve this nameserver's own address".to_string(),
            });
            continue;
        };
        attempts.push(attempt_axfr_one(zone, &ns_host, ip, opts.timeout).await);
    }
    attempts
}

async fn attempt_axfr_one(
    zone: &str,
    ns_host: &str,
    ns_ip: IpAddr,
    timeout: Duration,
) -> AxfrAttempt {
    // AXFR is a bulk operation by nature; give a successful (permitted)
    // transfer more room than a single lookup's usual timeout, while still
    // bailing out of a REFUSED-but-slow-to-close connection reasonably
    // promptly.
    let axfr_timeout = timeout.max(Duration::from_secs(5));
    match tokio::time::timeout(axfr_timeout, do_axfr(zone, ns_ip)).await {
        Ok(Ok(count)) => AxfrAttempt {
            nameserver: ns_host.to_string(),
            succeeded: true,
            record_count: count,
            detail: "succeeded — this nameserver allows zone transfer to arbitrary clients, a real misconfiguration".to_string(),
        },
        Ok(Err(detail)) => AxfrAttempt { nameserver: ns_host.to_string(), succeeded: false, record_count: 0, detail },
        Err(_) => AxfrAttempt { nameserver: ns_host.to_string(), succeeded: false, record_count: 0, detail: "timed out".to_string() },
    }
}

/// Attempts an AXFR (RFC 5936) against one nameserver over raw TCP: almost
/// every server refuses this from a client that isn't a configured
/// secondary, in the very first response, so the common case is cheap.
async fn do_axfr(zone: &str, ns_ip: IpAddr) -> Result<usize, String> {
    let name: Name = zone
        .parse()
        .map_err(|e| format!("invalid zone name: {e}"))?;
    let mut query = Message::query();
    query.add_query(Query::query(name, RecordType::AXFR));
    let bytes = query.to_bytes().map_err(|e| e.to_string())?;

    let mut stream = TcpStream::connect((ns_ip, 53))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    // DNS-over-TCP messages are framed with a 2-byte big-endian length
    // prefix (RFC 1035 §4.2.2), unlike UDP where the datagram boundary
    // *is* the message boundary.
    stream
        .write_all(&(bytes.len() as u16).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(&bytes).await.map_err(|e| e.to_string())?;

    let mut total_records = 0usize;
    let mut soa_seen = 0u32;
    let mut messages_read = 0usize;

    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // connection closed — typical of a refusal
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }
        let mut msg_buf = vec![0u8; msg_len];
        stream
            .read_exact(&mut msg_buf)
            .await
            .map_err(|e| format!("connection closed mid-message: {e}"))?;
        let message = Message::from_vec(&msg_buf).map_err(|e| e.to_string())?;

        if messages_read == 0 && message.metadata.response_code != ResponseCode::NoError {
            return Err(format!("{:?}", message.metadata.response_code));
        }
        messages_read += 1;

        for record in &message.answers {
            total_records += 1;
            if record.record_type() == RecordType::SOA {
                soa_seen += 1;
            }
        }

        if soa_seen >= 2 || messages_read >= AXFR_MAX_MESSAGES || total_records >= AXFR_MAX_RECORDS
        {
            break;
        }
    }

    if soa_seen < 2 {
        return Err(
            "REFUSED (or the connection closed before completing) — the expected, secure behavior"
                .to_string(),
        );
    }
    Ok(total_records)
}

fn classify_forward_record(record: &Record, result: &mut DnsResult) {
    let ttl = record.ttl;
    match &record.data {
        RData::A(a) => {
            result.a.push(a.0);
            result.records.push(DnsRecordRow {
                record_type: "A",
                value: a.0.to_string(),
                ttl: Some(ttl),
            });
        }
        RData::AAAA(aaaa) => {
            result.aaaa.push(aaaa.0);
            result.records.push(DnsRecordRow {
                record_type: "AAAA",
                value: aaaa.0.to_string(),
                ttl: Some(ttl),
            });
        }
        RData::CNAME(cname) => {
            let name = cname.0.to_string();
            if !result.cnames.contains(&name) {
                result.cnames.push(name.clone());
            }
            result.records.push(DnsRecordRow {
                record_type: "CNAME",
                value: name,
                ttl: Some(ttl),
            });
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

/// The distinct DNS server IPs configured on this machine (e.g.
/// `/etc/resolv.conf`'s `nameserver` lines on Linux, or the active
/// network service's servers on macOS/Windows), for display purposes
/// only -- e.g. the `Mode::ChooseResolver` prompt shows these so leaving
/// the field blank isn't a leap of faith about what "system default"
/// actually resolves to. Empty when the system config can't be read;
/// callers should fall back to a generic "system default" label rather
/// than treating that as an error, since `system_resolver` above still
/// works fine in that case -- it goes through `hickory-resolver`'s own
/// system-config handling independently of this function.
pub fn system_resolver_ips() -> Vec<IpAddr> {
    let Ok((config, _)) = hickory_resolver::system_conf::read_system_conf() else {
        return Vec::new();
    };
    let mut ips: Vec<IpAddr> = Vec::new();
    for server in config.name_servers() {
        if !ips.contains(&server.ip) {
            ips.push(server.ip);
        }
    }
    ips
}

/// Builds the resolver every plain lookup in this module (and, via the
/// public `lookup_*`/`resolve_addrs` functions, every other check) goes
/// through: the per-tab custom DNS server from `opts.resolver` when the
/// user picked one, otherwise the system's normally-configured resolver.
fn system_resolver(opts: DnsOpts) -> Result<TokioResolver, String> {
    match opts.resolver {
        Some(ip) => resolver_for(ip, opts.timeout),
        None => {
            let mut builder = TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
            builder.options_mut().timeout = opts.timeout;
            builder.build().map_err(|e| e.to_string())
        }
    }
}

/// A resolver with DNSSEC validation turned on, used by
/// `detect_zone_signing` and (via `checks::zonewalk`) the opt-in NSEC zone
/// walk: both need the server to include RRSIG/NSEC/NSEC3 records (via the
/// EDNS "DO" bit), which plain lookups don't request. Kept separate from
/// `system_resolver` so a validation hiccup (a zone with a broken DNSSEC
/// chain, a slow trust anchor fetch, ...) can only ever affect these DNSSEC
/// probes, never the A/AAAA/MX/NS/... lookups every other check relies on.
/// Also honors `opts.resolver`, same as `system_resolver`.
pub(crate) fn dnssec_probe_resolver(opts: DnsOpts) -> Result<TokioResolver, String> {
    let mut builder = match opts.resolver {
        Some(ip) => {
            let config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp_and_tcp(ip)]);
            Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        }
        None => TokioResolver::builder_tokio().map_err(|e| e.to_string())?,
    };
    builder.options_mut().timeout = opts.timeout;
    builder.options_mut().validate = true;
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
pub async fn resolve_addrs(name: &str, opts: DnsOpts) -> Result<Vec<IpAddr>, String> {
    let resolver = system_resolver(opts)?;
    resolver
        .lookup_ip(name)
        .await
        .map(|lookup| lookup.iter().collect())
        .map_err(|e| e.to_string())
}

/// Looks up MX records for an arbitrary name, for checks (mail) that need
/// a one-off MX query outside the main `DnsResult`.
pub async fn lookup_mx(name: &str, opts: DnsOpts) -> Result<Vec<MxRecord>, String> {
    let resolver = system_resolver(opts)?;
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
pub async fn lookup_txt(name: &str, opts: DnsOpts) -> Result<Vec<String>, String> {
    let resolver = system_resolver(opts)?;
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

/// Looks up a CNAME record for an arbitrary name, for checks (ACME
/// challenge evidence) that need a one-off CNAME query outside the main
/// `DnsResult`. `hickory-resolver` has no `cname_lookup` shorthand, so this
/// goes through the generic `lookup`.
pub async fn lookup_cname(name: &str, opts: DnsOpts) -> Result<Option<String>, String> {
    let resolver = system_resolver(opts)?;
    match resolver.lookup(name, RecordType::CNAME).await {
        Ok(lookup) => Ok(lookup.answers().iter().find_map(|r| match &r.data {
            RData::CNAME(cname) => Some(cname.0.to_string()),
            _ => None,
        })),
        Err(err) if err.to_string().to_lowercase().contains("no record") => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::dnssec::rdata::nsec::NSEC;
    use hickory_proto::op::Query;
    use hickory_resolver::net::NoRecords;

    use super::*;

    fn nsec_no_records(next_domain_name: &str) -> NetError {
        let next = Name::from_str(next_domain_name).unwrap();
        let nsec = NSEC::new_cover_self(next, [RecordType::A, RecordType::RRSIG, RecordType::NSEC]);
        let record = Record::from_rdata(
            Name::from_str("probe.example.com.").unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)),
        );
        let mut no_records = NoRecords::new(
            Box::new(Query::query(
                Name::from_str("probe.example.com.").unwrap(),
                RecordType::A,
            )),
            ResponseCode::NXDomain,
        );
        no_records.authorities = Some(vec![record].into());
        NetError::Dns(DnsError::NoRecordsFound(no_records))
    }

    #[test]
    fn classifies_nsec_from_a_no_records_response() {
        assert_eq!(
            classify_nsec_error(&nsec_no_records("zzz.example.com.")),
            ZoneSigning::Nsec
        );
    }

    #[test]
    fn classifies_unsigned_when_no_authorities_present() {
        let query = Box::new(Query::query(
            Name::from_str("probe.example.com.").unwrap(),
            RecordType::A,
        ));
        let err = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            query,
            ResponseCode::NXDomain,
        )));
        assert_eq!(classify_nsec_error(&err), ZoneSigning::NotSignedOrUnknown);
    }

    #[test]
    fn classifies_unrelated_errors_as_unknown() {
        assert_eq!(
            classify_nsec_error(&NetError::Busy),
            ZoneSigning::NotSignedOrUnknown
        );
    }

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
        assert_eq!(
            result.records,
            vec![
                DnsRecordRow {
                    record_type: "A",
                    value: "93.184.216.34".to_string(),
                    ttl: Some(300),
                },
                DnsRecordRow {
                    record_type: "CNAME",
                    value: "edge.example.net.".to_string(),
                    ttl: Some(300),
                },
            ]
        );
    }
}
