//! Mail pane: SPF (flattened, with its RFC 7208 lookup count), DMARC, a
//! probe for common DKIM selectors, MTA-STS/TLS-RPT/BIMI presence, and an
//! SMTP banner/STARTTLS probe against the domain's lowest-preference MX.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::target::Target;

/// RFC 7208 caps the number of DNS-lookup-causing mechanisms (`include`,
/// `a`, `mx`, `ptr`, `exists`, `redirect`) an SPF evaluation may perform.
const SPF_LOOKUP_LIMIT: u32 = 10;
/// Recursion depth guard against pathological/malicious `include:` loops;
/// well beyond anything a legitimate SPF policy needs.
const SPF_MAX_DEPTH: u32 = 15;

/// Common DKIM selector names worth probing when the real selector isn't
/// known. Not a brute-force enumeration (see `CLAUDE.md`'s safety section):
/// a short, well-known list, queried once each.
const COMMON_DKIM_SELECTORS: &[&str] = &[
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
    "dkim",
    "s1",
    "s2",
];

#[derive(Debug, Clone)]
pub struct SpfResult {
    pub record: String,
    /// Every `include:`/`redirect=` target seen while flattening, in order.
    pub includes: Vec<String>,
    /// Total DNS-lookup-causing mechanisms across the whole include tree.
    pub lookup_count: u32,
    pub exceeds_limit: bool,
}

#[derive(Debug, Clone)]
pub struct DmarcResult {
    pub record: String,
    pub policy: Option<String>,
    pub subdomain_policy: Option<String>,
    pub pct: Option<u8>,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SmtpProbe {
    pub host: String,
    pub connected: bool,
    pub banner: Option<String>,
    pub starttls_advertised: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MailResult {
    pub domain: String,
    pub spf: Option<SpfResult>,
    pub dmarc: Option<DmarcResult>,
    pub dkim_selectors_found: Vec<String>,
    pub mta_sts_record: Option<String>,
    pub tls_rpt_record: Option<String>,
    pub bimi_record: Option<String>,
    pub smtp: Vec<SmtpProbe>,
    pub errors: Vec<String>,
}

impl MailResult {
    /// SPF `include:` targets, for the hosting engine's mail-layer signals.
    pub fn spf_includes(&self) -> Vec<String> {
        self.spf
            .as_ref()
            .map(|s| s.includes.clone())
            .unwrap_or_default()
    }
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Mail;
    super::run_guarded(&ctx, id, &tx, async {
        let domain = match &ctx.target {
            Target::Host { ascii, .. } => ascii.clone(),
            Target::Ip(_) => return Err("Mail checks need a hostname, not a bare IP".to_string()),
        };
        let opts = crate::checks::dns::DnsOpts::new(ctx.config.timeouts.dns, ctx.resolver);

        let mut result = MailResult {
            domain: domain.clone(),
            ..Default::default()
        };

        match spf_lookup(&domain, opts).await {
            Ok(spf) => result.spf = spf,
            Err(err) => result.errors.push(format!("SPF: {err}")),
        }

        match dmarc_lookup(&domain, opts).await {
            Ok(dmarc) => result.dmarc = dmarc,
            Err(err) => result.errors.push(format!("DMARC: {err}")),
        }

        for &selector in COMMON_DKIM_SELECTORS {
            let name = format!("{selector}._domainkey.{domain}");
            if let Ok(txt) = crate::checks::dns::lookup_txt(&name, opts).await {
                if txt.iter().any(|t| looks_like_dkim_key(t)) {
                    result.dkim_selectors_found.push(selector.to_string());
                }
            }
        }

        result.mta_sts_record = first_txt(&format!("_mta-sts.{domain}"), opts).await;
        result.tls_rpt_record = first_txt(&format!("_smtp._tls.{domain}"), opts).await;
        result.bimi_record = first_txt(&format!("default._bimi.{domain}"), opts).await;

        if let Some(mx_host) = lowest_preference_mx(&domain, opts).await {
            result
                .smtp
                .push(probe_smtp(&mx_host, ctx.config.timeouts.tls).await);
        }

        ctx.shared.set_mail(result.clone()).await;
        Ok(CheckUpdate::Mail(result))
    })
    .await;
}

/// Distinguishes a real DKIM key record from a wildcard/parking-page TXT
/// answer some zones return for *any* subdomain (`example.com`'s own zone
/// does this: `v=DKIM1; p=` with an empty key for every selector). A real
/// key's `p=` tag carries actual base64 key material.
fn looks_like_dkim_key(txt: &str) -> bool {
    parse_tag_list(txt).get("p").is_some_and(|p| p.len() > 8)
}

async fn first_txt(name: &str, opts: crate::checks::dns::DnsOpts) -> Option<String> {
    crate::checks::dns::lookup_txt(name, opts)
        .await
        .ok()
        .and_then(|v| v.into_iter().next())
}

async fn lowest_preference_mx(domain: &str, opts: crate::checks::dns::DnsOpts) -> Option<String> {
    let mut records = crate::checks::dns::lookup_mx(domain, opts).await.ok()?;
    records.sort_by_key(|mx| mx.preference);
    records
        .into_iter()
        .next()
        .map(|mx| mx.exchange.trim_end_matches('.').to_string())
}

async fn spf_lookup(
    domain: &str,
    opts: crate::checks::dns::DnsOpts,
) -> Result<Option<SpfResult>, String> {
    let Some(record) = find_spf_record(domain, opts).await? else {
        return Ok(None);
    };
    let mut includes = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let lookup_count = flatten_spf(domain, &record, opts, 0, &mut includes, &mut visited).await;
    Ok(Some(SpfResult {
        record,
        includes,
        lookup_count,
        exceeds_limit: lookup_count > SPF_LOOKUP_LIMIT,
    }))
}

async fn find_spf_record(
    domain: &str,
    opts: crate::checks::dns::DnsOpts,
) -> Result<Option<String>, String> {
    let txt = crate::checks::dns::lookup_txt(domain, opts).await?;
    Ok(txt.into_iter().find(|t| t.starts_with("v=spf1")))
}

/// Walks an SPF record's `include:`/`redirect=` mechanisms recursively,
/// counting every DNS-lookup-causing mechanism per RFC 7208 section 4.6.4.
/// Guards against loops via `visited` and against pathological nesting via
/// `SPF_MAX_DEPTH`, so a malicious record can't hang the check.
fn flatten_spf<'a>(
    domain: &'a str,
    record: &'a str,
    opts: crate::checks::dns::DnsOpts,
    depth: u32,
    includes: &'a mut Vec<String>,
    visited: &'a mut std::collections::HashSet<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = u32> + Send + 'a>> {
    Box::pin(async move {
        if depth > SPF_MAX_DEPTH || !visited.insert(domain.to_lowercase()) {
            return 0;
        }

        let mut count = 0u32;
        for mechanism in record.split_whitespace() {
            let mechanism = mechanism.trim_start_matches(['+', '-', '~', '?']);
            if let Some(target) = mechanism.strip_prefix("include:") {
                count += 1;
                includes.push(target.to_string());
                if let Ok(Some(nested)) = find_spf_record(target, opts).await {
                    count += flatten_spf(target, &nested, opts, depth + 1, includes, visited).await;
                }
            } else if let Some(target) = mechanism.strip_prefix("redirect=") {
                count += 1;
                if let Ok(Some(nested)) = find_spf_record(target, opts).await {
                    count += flatten_spf(target, &nested, opts, depth + 1, includes, visited).await;
                }
            } else if mechanism.starts_with("a:")
                || mechanism == "a"
                || mechanism.starts_with("a/")
                || mechanism.starts_with("mx:")
                || mechanism == "mx"
                || mechanism.starts_with("mx/")
                || mechanism.starts_with("ptr")
                || mechanism.starts_with("exists:")
            {
                count += 1;
            }
        }
        count
    })
}

async fn dmarc_lookup(
    domain: &str,
    opts: crate::checks::dns::DnsOpts,
) -> Result<Option<DmarcResult>, String> {
    let name = format!("_dmarc.{domain}");
    let txt = crate::checks::dns::lookup_txt(&name, opts).await?;
    let Some(record) = txt.into_iter().find(|t| t.starts_with("v=DMARC1")) else {
        return Ok(None);
    };

    let tags = parse_tag_list(&record);
    let rua = tags
        .get("rua")
        .map(|v| v.split(',').map(str::trim).map(str::to_string).collect())
        .unwrap_or_default();
    let ruf = tags
        .get("ruf")
        .map(|v| v.split(',').map(str::trim).map(str::to_string).collect())
        .unwrap_or_default();

    Ok(Some(DmarcResult {
        record: record.clone(),
        policy: tags.get("p").cloned(),
        subdomain_policy: tags.get("sp").cloned(),
        pct: tags.get("pct").and_then(|v| v.parse().ok()),
        rua,
        ruf,
    }))
}

/// Parses a `tag1=value1; tag2=value2` record body into a map.
fn parse_tag_list(record: &str) -> std::collections::HashMap<String, String> {
    record
        .split(';')
        .filter_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            Some((k.trim().to_lowercase(), v.trim().to_string()))
        })
        .collect()
}

/// Connects to `host` on port 25 and reads the SMTP greeting banner plus
/// whether `EHLO` advertises `STARTTLS`. Tolerant of the connection being
/// firewalled (common for outbound 25 on consumer/cloud networks): that's
/// reported as `connected: false`, not an error that kills the pane.
async fn probe_smtp(host: &str, timeout: Duration) -> SmtpProbe {
    let mut probe = SmtpProbe {
        host: host.to_string(),
        connected: false,
        banner: None,
        starttls_advertised: false,
        error: None,
    };

    let attempt = async {
        let mut stream = TcpStream::connect((host, 25))
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
        probe.connected = true;
        probe.banner = Some(String::from_utf8_lossy(&buf[..n]).trim().to_string());

        stream
            .write_all(b"EHLO netloupe.local\r\n")
            .await
            .map_err(|e| e.to_string())?;
        let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
        let ehlo_response = String::from_utf8_lossy(&buf[..n]);
        probe.starttls_advertised = ehlo_response.to_uppercase().contains("STARTTLS");
        Ok::<(), String>(())
    };

    if let Err(err) = tokio::time::timeout(timeout, attempt)
        .await
        .unwrap_or_else(|_| Err("timed out".to_string()))
    {
        probe.error = Some(err);
    }
    probe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dmarc_tags() {
        let tags = parse_tag_list(
            "v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@x.com",
        );
        assert_eq!(tags.get("p"), Some(&"reject".to_string()));
        assert_eq!(tags.get("pct"), Some(&"50".to_string()));
    }

    #[tokio::test]
    async fn flattens_a_simple_spf_record_without_includes() {
        let mut includes = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let count = flatten_spf(
            "example.com",
            "v=spf1 ip4:1.2.3.0/24 -all",
            crate::checks::dns::DnsOpts::new(Duration::from_secs(1), None),
            0,
            &mut includes,
            &mut visited,
        )
        .await;
        assert_eq!(count, 0);
        assert!(includes.is_empty());
    }

    #[tokio::test]
    async fn counts_a_mx_and_ptr_mechanisms() {
        let mut includes = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let count = flatten_spf(
            "example.com",
            "v=spf1 a mx ptr exists:%{i}._spf.example.com -all",
            crate::checks::dns::DnsOpts::new(Duration::from_secs(1), None),
            0,
            &mut includes,
            &mut visited,
        )
        .await;
        assert_eq!(count, 4);
    }

    #[tokio::test]
    async fn a_self_referencing_include_does_not_loop_forever() {
        // Can't perform real DNS `include:` expansion in a unit test, but
        // the `visited` guard must still stop this from being an infinite
        // recursion for a record that includes its own domain.
        let mut includes = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let count = flatten_spf(
            "example.com",
            "v=spf1 include:example.com -all",
            crate::checks::dns::DnsOpts::new(Duration::from_secs(1), None),
            0,
            &mut includes,
            &mut visited,
        )
        .await;
        assert_eq!(count, 1);
        assert_eq!(includes, vec!["example.com".to_string()]);
    }
}
