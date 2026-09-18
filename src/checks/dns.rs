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
use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::{Resolver, TokioResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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

/// The zone actually authoritative for the queried name, learned only
/// when the name itself isn't a zone apex (e.g. `admin.ft.europe.example.com`
/// under a zone cut at `example.com`) -- its name, SOA, and NS records.
/// This is the same "AUTHORITY SECTION" `dig` shows in place of an answer
/// for a non-apex name: RFC 2308's negative-response SOA, plus its NS
/// records when the response already carried them (a delegation referral)
/// or else a direct follow-up NS lookup against the zone's own name.
/// `None` when the queried name is itself a zone apex, since `DnsResult`'s
/// own `soa`/`ns` fields already cover it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityZone {
    pub zone: String,
    pub soa: SoaRecord,
    /// Nameserver name paired with its TTL (seconds).
    pub ns: Vec<(String, u32)>,
}

/// One hop of a `dig +trace`-style delegation walk: which server was
/// asked, and what it delegated to -- or, at the final hop, that it gave
/// an authoritative answer instead of a further referral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationHop {
    /// The zone this hop's response delegates into (the owner name of
    /// its authority section's NS records), or the last zone reached at
    /// the final, authoritative hop.
    pub zone: String,
    /// Which server answered this hop: `name (ip)` when the name is
    /// known (every root server, or a delegate resolved by name), the
    /// bare IP otherwise.
    pub answered_by: String,
    /// The NS names this hop delegated to, in order; empty at the final,
    /// authoritative hop.
    pub delegates_to: Vec<String>,
    pub rtt: Duration,
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
    /// The enclosing zone's SOA/NS, when the queried name isn't itself a
    /// zone apex -- see `AuthorityZone`'s doc comment.
    pub authority: Option<AuthorityZone>,
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
    /// A `dig +trace`-style walk from the root down to whichever server
    /// is actually authoritative for the queried name, following NS
    /// referrals one zone cut at a time (see `DelegationHop`). Queries
    /// root/TLD/delegated servers directly over UDP rather than through
    /// `opts.resolver` or the system resolver -- that's the entire point
    /// of a trace, the same way `dig +trace` always bypasses your
    /// configured resolver.
    pub delegation_trace: Vec<DelegationHop>,
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

    let name = fqdn(name);
    fill_forward_records(&resolver, &name, &mut result).await;

    fill_any_query(&resolver, &name, &mut result).await;
    result.zone_signing = detect_zone_signing(&name, opts).await;
    result.axfr = attempt_axfr_all(&name, &result.ns, opts).await;

    match name.parse::<Name>() {
        Ok(query_name) => {
            let (trace, trace_error) = delegation_trace(&query_name, opts).await;
            result.delegation_trace = trace;
            if let Some(err) = trace_error {
                result.errors.push(err);
            }
        }
        Err(err) => result
            .errors
            .push(format!("delegation trace: invalid name: {err}")),
    }

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
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
            if let Some(mut authority) = authority_zone_from_no_records(&no_records) {
                if authority.ns.is_empty() {
                    if let Ok(lookup) = resolver.ns_lookup(authority.zone.as_str()).await {
                        authority.ns = lookup
                            .answers()
                            .iter()
                            .filter_map(|r| match &r.data {
                                RData::NS(ns) => Some((ns.0.to_string(), r.ttl)),
                                _ => None,
                            })
                            .collect();
                    }
                }
                result.authority = Some(authority);
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

/// The 13 IANA root server IPv4 addresses -- the "root hints" every
/// resolver ships with (see <https://www.iana.org/domains/root/servers>),
/// stable for decades. Hardcoding them here means a trace can start
/// straight away, the same way a resolver's bundled hints file lets it
/// skip a priming query.
const ROOT_SERVERS: [(&str, Ipv4Addr); 13] = [
    ("a.root-servers.net", Ipv4Addr::new(198, 41, 0, 4)),
    ("b.root-servers.net", Ipv4Addr::new(199, 9, 14, 201)),
    ("c.root-servers.net", Ipv4Addr::new(192, 33, 4, 12)),
    ("d.root-servers.net", Ipv4Addr::new(199, 7, 91, 13)),
    ("e.root-servers.net", Ipv4Addr::new(192, 203, 230, 10)),
    ("f.root-servers.net", Ipv4Addr::new(192, 5, 5, 241)),
    ("g.root-servers.net", Ipv4Addr::new(192, 112, 36, 4)),
    ("h.root-servers.net", Ipv4Addr::new(198, 97, 190, 53)),
    ("i.root-servers.net", Ipv4Addr::new(192, 36, 148, 17)),
    ("j.root-servers.net", Ipv4Addr::new(192, 58, 128, 30)),
    ("k.root-servers.net", Ipv4Addr::new(193, 0, 14, 129)),
    ("l.root-servers.net", Ipv4Addr::new(199, 7, 83, 42)),
    ("m.root-servers.net", Ipv4Addr::new(202, 12, 27, 33)),
];

/// How many referrals to follow before giving up: a real chain is root ->
/// TLD -> (occasionally one or two more delegated levels) ->
/// authoritative, so this comfortably covers any real zone while still
/// bounding a misconfigured delegation loop.
const MAX_TRACE_HOPS: usize = 12;

/// A candidate nameserver for the next query: its name, when known (every
/// root server, or a delegate resolved by name), and its IP.
type TraceCandidate = (Option<String>, IpAddr);
/// One hop's successful response: the raw message, who answered (for
/// display), and how long it took.
type TraceResponse = (Message, String, Duration);

/// Walks the delegation chain for `name` from the root down to whichever
/// server is authoritative for it, one zone cut at a time -- the same
/// thing `dig +trace` shows. Returns whatever hops were completed even if
/// it stops early (a broken delegation, an unreachable server, ...),
/// alongside a message explaining why it stopped, if it did.
async fn delegation_trace(name: &Name, opts: DnsOpts) -> (Vec<DelegationHop>, Option<String>) {
    let mut hops = Vec::new();
    let mut candidates: Vec<TraceCandidate> = ROOT_SERVERS
        .iter()
        .map(|(hostname, ip)| (Some((*hostname).to_string()), IpAddr::V4(*ip)))
        .collect();
    let mut last_zone = Name::root();

    for _ in 0..MAX_TRACE_HOPS {
        let Some((message, answered_by, rtt)) =
            query_first_responding(&candidates, name, opts.timeout).await
        else {
            return (
                hops,
                Some("delegation trace: none of the current nameservers responded".to_string()),
            );
        };

        let (zone_name, delegate_names) = match classify_trace_response(&message) {
            TraceOutcome::Final => {
                hops.push(DelegationHop {
                    zone: last_zone.to_string(),
                    answered_by,
                    delegates_to: Vec::new(),
                    rtt,
                });
                return (hops, None);
            }
            TraceOutcome::Inconclusive => {
                return (
                    hops,
                    Some(
                        "delegation trace: response had neither an answer nor a delegation"
                            .to_string(),
                    ),
                );
            }
            TraceOutcome::Delegation { zone, delegates_to } => (zone, delegates_to),
        };
        if zone_name == last_zone {
            return (
                hops,
                Some(format!(
                    "delegation trace: stopped -- {zone_name} referred back to itself"
                )),
            );
        }

        hops.push(DelegationHop {
            zone: zone_name.to_string(),
            answered_by,
            delegates_to: delegate_names.iter().map(ToString::to_string).collect(),
            rtt,
        });

        candidates = next_hop_candidates(&message, &delegate_names, opts).await;
        if candidates.is_empty() {
            return (
                hops,
                Some(format!(
                    "delegation trace: could not resolve any nameserver for {zone_name}"
                )),
            );
        }
        last_zone = zone_name;
    }

    (
        hops,
        Some("delegation trace: stopped after too many referrals".to_string()),
    )
}

/// What one trace hop's response revealed, pure so it's testable without
/// a real query -- see `classify_trace_response`.
#[derive(Debug, PartialEq, Eq)]
enum TraceOutcome {
    /// An answer (even an empty, authoritative one) rather than a
    /// further referral: this server is authoritative for the queried
    /// name, so the walk is done.
    Final,
    /// A referral to a deeper zone.
    Delegation { zone: Name, delegates_to: Vec<Name> },
    /// Neither an answer nor a usable delegation -- a malformed or
    /// unhelpful response.
    Inconclusive,
}

/// Classifies a trace hop's raw response: an authoritative answer, a
/// referral to a deeper zone (via its authority section's NS records),
/// or neither. Pure -- kept separate from `delegation_trace`'s network
/// I/O so it's unit-testable with a hand-built `Message`.
fn classify_trace_response(message: &Message) -> TraceOutcome {
    if !message.answers.is_empty() || message.metadata.authoritative {
        return TraceOutcome::Final;
    }
    let ns_records: Vec<&Record> = message
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .collect();
    let Some(zone) = ns_records.first().map(|r| r.name.clone()) else {
        return TraceOutcome::Inconclusive;
    };
    let delegates_to = ns_records
        .iter()
        .filter_map(|r| match &r.data {
            RData::NS(ns) => Some(ns.0.clone()),
            _ => None,
        })
        .collect();
    TraceOutcome::Delegation { zone, delegates_to }
}

/// Glue records (A/AAAA) in `message`'s additional section for any of
/// `delegate_names` -- pure, kept separate from `next_hop_candidates`'
/// resolver fallback so it's unit-testable without a real lookup.
fn extract_glue(message: &Message, delegate_names: &[Name]) -> Vec<TraceCandidate> {
    let mut candidates: Vec<TraceCandidate> = Vec::new();
    for delegate in delegate_names {
        for r in &message.additionals {
            if &r.name != delegate {
                continue;
            }
            let ip = match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            };
            if let Some(ip) = ip {
                candidates.push((Some(delegate.to_string()), ip));
            }
        }
    }
    candidates
}

/// The next hop's candidate servers: glue (A/AAAA already in the
/// response's additional section) when present -- some zones only work
/// via glue in the first place (in-bailiwick nameservers) -- otherwise a
/// direct lookup of the delegate names through the normal resolver.
async fn next_hop_candidates(
    message: &Message,
    delegate_names: &[Name],
    opts: DnsOpts,
) -> Vec<TraceCandidate> {
    let candidates = extract_glue(message, delegate_names);
    if !candidates.is_empty() {
        return candidates;
    }

    // No glue: trying just the first couple of delegates is enough --
    // if a name is unreachable or doesn't resolve, the next hop's
    // `query_first_responding` still fails fast rather than hanging on a
    // dead one, and a real delegation rarely needs more than this to
    // find a working nameserver.
    let mut candidates: Vec<TraceCandidate> = Vec::new();
    for delegate in delegate_names.iter().take(3) {
        if let Ok(ips) = resolve_addrs(&delegate.to_string(), opts).await {
            candidates.extend(ips.into_iter().map(|ip| (Some(delegate.to_string()), ip)));
            if !candidates.is_empty() {
                break;
            }
        }
    }
    candidates
}

/// Queries every candidate concurrently and returns whichever answers
/// first -- a root/TLD zone cut has many nameservers precisely so that
/// losing some of them doesn't matter, and querying them one at a time
/// would otherwise multiply a single hop's worst-case latency by however
/// many of them happen to be unreachable.
async fn query_first_responding(
    candidates: &[TraceCandidate],
    name: &Name,
    timeout: Duration,
) -> Option<(Message, String, Duration)> {
    type TraceAttempt =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<TraceResponse, String>> + Send>>;
    let attempts: Vec<TraceAttempt> = candidates
        .iter()
        .map(|(hostname, ip)| {
            let hostname = hostname.clone();
            let ip = *ip;
            let name = name.clone();
            let fut = async move {
                let start = std::time::Instant::now();
                let message = query_referral(ip, &name, timeout).await?;
                let rtt = start.elapsed();
                let answered_by = match hostname {
                    Some(h) => format!("{h} ({ip})"),
                    None => ip.to_string(),
                };
                Ok::<_, String>((message, answered_by, rtt))
            };
            Box::pin(fut) as TraceAttempt
        })
        .collect();
    futures::future::select_ok(attempts)
        .await
        .ok()
        .map(|(v, _remaining)| v)
}

/// Sends one non-recursive (RD=0) query directly to `server_ip:53` over
/// UDP and returns the raw response -- a root/TLD/delegated server's
/// referral (its authority and additional sections), never a recursive
/// resolver's fully-resolved answer, which is what `delegation_trace`
/// needs in order to walk the chain one zone cut at a time. Deliberately
/// bypasses `opts.resolver`/the system resolver: that's what makes this a
/// trace rather than an ordinary lookup.
async fn query_referral(
    server_ip: IpAddr,
    name: &Name,
    timeout: Duration,
) -> Result<Message, String> {
    let mut query = Message::query();
    query.metadata.recursion_desired = false;
    query.add_query(Query::query(name.clone(), RecordType::A));
    // A root/TLD referral lists every nameserver plus its glue records,
    // comfortably past the 512-byte limit a plain (non-EDNS) UDP query
    // is held to -- without this, a truncated response would look like
    // an empty, dead-end delegation.
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    query.set_edns(edns);
    let bytes = query.to_bytes().map_err(|e| e.to_string())?;

    let bind_addr = if server_ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| e.to_string())?;
    socket
        .connect((server_ip, 53))
        .await
        .map_err(|e| e.to_string())?;
    socket.send(&bytes).await.map_err(|e| e.to_string())?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    Message::from_vec(&buf[..n]).map_err(|e| e.to_string())
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

/// Extracts the enclosing zone's name, SOA, and any NS records already
/// present in a negative SOA response's authority section (RFC 2308) --
/// pure, so it's testable without a resolver. `no_records.ns` only ever
/// carries NS records when the response was a delegation referral, not a
/// plain NODATA; the common case leaves `ns` empty here, and
/// `fill_forward_records`'s caller follows up with a direct `ns_lookup`
/// against `zone` when that happens.
fn authority_zone_from_no_records(no_records: &NoRecords) -> Option<AuthorityZone> {
    let soa_record = no_records.soa.as_ref()?;
    let zone = soa_record.name.to_string();
    let soa = &soa_record.data;
    let soa = SoaRecord {
        mname: soa.mname.to_string(),
        rname: soa.rname.to_string(),
        serial: soa.serial,
        refresh: soa.refresh,
        retry: soa.retry,
        expire: soa.expire,
        minimum: soa.minimum,
    };
    let ns = no_records
        .ns
        .as_deref()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| match &entry.ns.data {
                    RData::NS(ns) => Some((ns.0.to_string(), entry.ns.ttl)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Some(AuthorityZone { zone, soa, ns })
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

/// Marks `name` as a fully-qualified domain name (a trailing dot) before
/// it reaches any hickory-resolver lookup. Without this, a name with
/// fewer labels than the system's configured `ndots` gets the local
/// network's search domain(s) tried instead of (or as well as) the name
/// itself -- silently investigating the wrong host, or a search-suffixed
/// name that doesn't exist, rather than the exact target the user typed.
/// A trailing dot skips that entirely: hickory queries the name exactly
/// as given, in one query, regardless of `ndots` or how the resolver's
/// search list is configured.
fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
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
    let query_name = fqdn(name);
    let baseline: std::collections::BTreeSet<IpAddr> = result
        .a
        .iter()
        .map(|ip| IpAddr::V4(*ip))
        .chain(result.aaaa.iter().map(|ip| IpAddr::V6(*ip)))
        .collect();

    for &server in &ctx.config.resolvers.comparison {
        let name = name.to_string();
        let comparison = match resolver_for(server, timeout) {
            Ok(resolver) => match resolver.lookup_ip(query_name.as_str()).await {
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
        .lookup_ip(fqdn(name))
        .await
        .map(|lookup| lookup.iter().collect())
        .map_err(|e| e.to_string())
}

/// Looks up MX records for an arbitrary name, for checks (mail) that need
/// a one-off MX query outside the main `DnsResult`.
pub async fn lookup_mx(name: &str, opts: DnsOpts) -> Result<Vec<MxRecord>, String> {
    let resolver = system_resolver(opts)?;
    match resolver.mx_lookup(fqdn(name)).await {
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
    match resolver.txt_lookup(fqdn(name)).await {
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
    match resolver.lookup(fqdn(name), RecordType::CNAME).await {
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
    use hickory_resolver::net::{ForwardNSData, NoRecords};

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

    fn soa_no_records(zone: &str, ns_names: &[&str]) -> NoRecords {
        use hickory_proto::rr::rdata::{self, SOA};

        let mut no_records = NoRecords::new(
            Box::new(Query::query(
                Name::from_str("admin.ft.europe.example.com.").unwrap(),
                RecordType::SOA,
            )),
            ResponseCode::NoError,
        );
        no_records.soa = Some(Box::new(Record::from_rdata(
            Name::from_str(zone).unwrap(),
            3600,
            SOA::new(
                Name::from_str(&format!("ns1.{zone}")).unwrap(),
                Name::from_str(&format!("hostmaster.{zone}")).unwrap(),
                2024010100,
                3600,
                600,
                604800,
                300,
            ),
        )));
        if !ns_names.is_empty() {
            no_records.ns = Some(
                ns_names
                    .iter()
                    .map(|ns_name| ForwardNSData {
                        ns: Record::from_rdata(
                            Name::from_str(zone).unwrap(),
                            86400,
                            RData::NS(rdata::NS(Name::from_str(ns_name).unwrap())),
                        ),
                        glue: Vec::new().into(),
                    })
                    .collect(),
            );
        }
        no_records
    }

    #[test]
    fn authority_zone_from_no_records_extracts_the_soa() {
        let no_records = soa_no_records("example.com.", &[]);
        let authority = authority_zone_from_no_records(&no_records).unwrap();
        assert_eq!(authority.zone, "example.com.");
        assert_eq!(authority.soa.mname, "ns1.example.com.");
        assert_eq!(authority.soa.serial, 2024010100);
        assert!(authority.ns.is_empty());
    }

    #[test]
    fn authority_zone_from_no_records_includes_ns_from_a_referral() {
        let no_records = soa_no_records("example.com.", &["ns1.example.com.", "ns2.example.com."]);
        let authority = authority_zone_from_no_records(&no_records).unwrap();
        assert_eq!(
            authority.ns,
            vec![
                ("ns1.example.com.".to_string(), 86400),
                ("ns2.example.com.".to_string(), 86400),
            ]
        );
    }

    #[test]
    fn authority_zone_from_no_records_is_none_without_an_soa() {
        let no_records = NoRecords::new(
            Box::new(Query::query(
                Name::from_str("admin.ft.europe.example.com.").unwrap(),
                RecordType::SOA,
            )),
            ResponseCode::NoError,
        );
        assert!(authority_zone_from_no_records(&no_records).is_none());
    }

    fn ns_record(owner: &str, target: &str) -> Record {
        use hickory_proto::rr::rdata;
        Record::from_rdata(
            Name::from_str(owner).unwrap(),
            3600,
            RData::NS(rdata::NS(Name::from_str(target).unwrap())),
        )
    }

    fn a_record(owner: &str, ip: Ipv4Addr) -> Record {
        use hickory_proto::rr::rdata;
        Record::from_rdata(Name::from_str(owner).unwrap(), 3600, RData::A(rdata::A(ip)))
    }

    #[test]
    fn classify_trace_response_is_final_when_answers_are_present() {
        let mut message = Message::query();
        message.answers = vec![a_record("example.com.", Ipv4Addr::new(93, 184, 216, 34))];
        assert_eq!(classify_trace_response(&message), TraceOutcome::Final);
    }

    #[test]
    fn classify_trace_response_is_final_for_an_authoritative_nodata_reply() {
        let mut message = Message::query();
        message.metadata.authoritative = true;
        assert_eq!(classify_trace_response(&message), TraceOutcome::Final);
    }

    #[test]
    fn classify_trace_response_is_a_delegation_when_authorities_carry_ns_records() {
        let mut message = Message::query();
        message.authorities = vec![
            ns_record("com.", "a.gtld-servers.net."),
            ns_record("com.", "b.gtld-servers.net."),
        ];
        match classify_trace_response(&message) {
            TraceOutcome::Delegation { zone, delegates_to } => {
                assert_eq!(zone, Name::from_str("com.").unwrap());
                assert_eq!(
                    delegates_to,
                    vec![
                        Name::from_str("a.gtld-servers.net.").unwrap(),
                        Name::from_str("b.gtld-servers.net.").unwrap(),
                    ]
                );
            }
            other => panic!("expected a Delegation outcome, got {other:?}"),
        }
    }

    #[test]
    fn classify_trace_response_is_inconclusive_with_neither_answers_nor_ns() {
        let message = Message::query();
        assert_eq!(
            classify_trace_response(&message),
            TraceOutcome::Inconclusive
        );
    }

    #[test]
    fn extract_glue_finds_matching_address_records() {
        let mut message = Message::query();
        message.additionals = vec![
            a_record("a.gtld-servers.net.", Ipv4Addr::new(192, 5, 6, 30)),
            a_record("other.example.", Ipv4Addr::new(203, 0, 113, 1)),
        ];
        let delegates = vec![Name::from_str("a.gtld-servers.net.").unwrap()];
        let glue = extract_glue(&message, &delegates);
        assert_eq!(
            glue,
            vec![(
                Some("a.gtld-servers.net.".to_string()),
                IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30))
            )]
        );
    }

    #[test]
    fn extract_glue_is_empty_without_a_matching_additional_record() {
        let mut message = Message::query();
        message.additionals = vec![a_record(
            "unrelated.example.",
            Ipv4Addr::new(203, 0, 113, 1),
        )];
        let delegates = vec![Name::from_str("a.gtld-servers.net.").unwrap()];
        assert!(extract_glue(&message, &delegates).is_empty());
    }

    #[test]
    fn fqdn_appends_a_trailing_dot_only_when_missing() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
        assert_eq!(fqdn(""), ".");
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
