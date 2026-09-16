//! IP/ASN pane: origin ASN (via Team Cymru's DNS whois), RDAP ownership
//! info, and IP address classification.
//!
//! RPKI route-origin validation isn't implemented yet (see the roadmap in
//! `CLAUDE.md`); `rpki` is always `Unknown` for now rather than a guess.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};

/// Where an IP address falls in the address-space taxonomy. `Global` means
/// none of the special-purpose ranges apply, i.e. it's routable on the
/// public Internet as far as its own address alone tells us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    Private,
    CarrierGradeNat,
    Loopback,
    LinkLocal,
    Multicast,
    Broadcast,
    Documentation,
    Unspecified,
    Benchmarking,
    Reserved,
    Global,
}

impl IpClass {
    pub fn label(self) -> &'static str {
        match self {
            IpClass::Private => "private (RFC 1918/4193)",
            IpClass::CarrierGradeNat => "carrier-grade NAT (RFC 6598)",
            IpClass::Loopback => "loopback",
            IpClass::LinkLocal => "link-local",
            IpClass::Multicast => "multicast",
            IpClass::Broadcast => "broadcast",
            IpClass::Documentation => "documentation/example (TEST-NET)",
            IpClass::Unspecified => "unspecified",
            IpClass::Benchmarking => "benchmarking (RFC 2544)",
            IpClass::Reserved => "reserved",
            IpClass::Global => "global unicast",
        }
    }
}

/// Origin ASN info for one IP, as reported by Team Cymru's DNS-based
/// whois (`origin.asn.cymru.com` / `origin6.asn.cymru.com`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
    pub as_name: Option<String>,
}

/// A trimmed-down view of an RDAP response: enough to show who's
/// responsible for an IP block without reproducing the whole document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdapInfo {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub country: Option<String>,
    pub registry_url: String,
    pub abuse_email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IpInfoResult {
    pub ip: IpAddr,
    pub class: IpClass,
    pub asn: Option<AsnInfo>,
    pub rdap: Option<RdapInfo>,
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::IpInfo;
    super::run_guarded(&ctx, id, &tx, async {
        let ip = match super::resolve_target_ip(&ctx).await {
            Ok(ip) => ip,
            Err(err) => return Err(err),
        };

        let mut result = IpInfoResult {
            ip,
            class: classify(ip),
            asn: None,
            rdap: None,
            errors: Vec::new(),
        };

        match lookup_asn(ip, ctx.config.timeouts.dns).await {
            Ok(asn) => result.asn = asn,
            Err(err) => result.errors.push(format!("ASN lookup: {err}")),
        }

        match lookup_rdap(ip, ctx.config.timeouts.rdap).await {
            Ok(rdap) => result.rdap = Some(rdap),
            Err(err) => result.errors.push(format!("RDAP: {err}")),
        }

        ctx.shared.set_ipinfo(result.clone()).await;
        Ok(CheckUpdate::IpInfo(result))
    })
    .await;
}

/// Classifies `ip` by RFC-defined special-purpose ranges. Pure and
/// network-free so it's trivially unit-testable.
pub fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    let octets = ip.octets();
    if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.is_private() {
        IpClass::Private
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        IpClass::CarrierGradeNat // 100.64.0.0/10
    } else if ip.is_link_local() {
        IpClass::LinkLocal
    } else if ip.is_documentation() {
        IpClass::Documentation
    } else if octets[0] == 198 && (18..=19).contains(&octets[1]) {
        IpClass::Benchmarking // 198.18.0.0/15
    } else if ip.is_broadcast() {
        IpClass::Broadcast
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if octets[0] >= 240 && !ip.is_broadcast() {
        // 240.0.0.0/4 ("Class E"), reserved for future use per RFC 1112 §4.
        IpClass::Reserved
    } else {
        IpClass::Global
    }
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_unspecified() {
        IpClass::Unspecified
    } else if is_unique_local(ip) {
        IpClass::Private // ULA, fc00::/7 — IPv6's RFC 1918 equivalent
    } else if is_link_local_v6(ip) {
        IpClass::LinkLocal
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if is_documentation_v6(ip) {
        IpClass::Documentation
    } else {
        IpClass::Global
    }
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_documentation_v6(ip: Ipv6Addr) -> bool {
    // 2001:db8::/32
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}

/// Reverses an IPv4 address's octets for a Cymru-style query name, e.g.
/// `1.2.3.4` -> `4.3.2.1`.
fn reversed_v4_labels(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

/// Reverses an IPv6 address's nibbles for a Cymru-style query name.
fn reversed_v6_labels(ip: Ipv6Addr) -> String {
    let mut nibbles = Vec::with_capacity(32);
    for byte in ip.octets() {
        nibbles.push(byte & 0x0f);
        nibbles.push(byte >> 4);
    }
    nibbles
        .iter()
        .rev()
        .map(|n| format!("{n:x}"))
        .collect::<Vec<_>>()
        .join(".")
}

async fn lookup_asn(ip: IpAddr, timeout: Duration) -> Result<Option<AsnInfo>, String> {
    let (query, is_v6) = match ip {
        IpAddr::V4(v4) => (
            format!("{}.origin.asn.cymru.com", reversed_v4_labels(v4)),
            false,
        ),
        IpAddr::V6(v6) => (
            format!("{}.origin6.asn.cymru.com", reversed_v6_labels(v6)),
            true,
        ),
    };
    let _ = is_v6;

    let txt = crate::checks::dns::lookup_txt(&query, timeout).await?;
    let Some(first) = txt.into_iter().next() else {
        return Ok(None);
    };
    let Some(mut info) = parse_origin_txt(&first) else {
        return Ok(None);
    };

    if let Ok(name_txt) =
        crate::checks::dns::lookup_txt(&format!("AS{}.asn.cymru.com", info.asn), timeout).await
    {
        if let Some(name_record) = name_txt.first() {
            info.as_name = parse_as_name_txt(name_record);
        }
    }
    Ok(Some(info))
}

/// Parses a Cymru `origin.asn.cymru.com` TXT answer:
/// `"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`.
fn parse_origin_txt(txt: &str) -> Option<AsnInfo> {
    let fields: Vec<&str> = txt.split('|').map(str::trim).collect();
    if fields.len() < 5 {
        return None;
    }
    // A prefix can be announced by more than one ASN; take the first.
    let asn = fields[0].split_whitespace().next()?.parse().ok()?;
    Some(AsnInfo {
        asn,
        prefix: fields[1].to_string(),
        country: fields[2].to_string(),
        registry: fields[3].to_string(),
        allocated: fields[4].to_string(),
        as_name: None,
    })
}

/// Parses a Cymru `ASnnnn.asn.cymru.com` TXT answer:
/// `"15169 | US | arin | 2000-03-30 | GOOGLE, US"`.
fn parse_as_name_txt(txt: &str) -> Option<String> {
    txt.split('|').nth(4).map(|s| s.trim().to_string())
}

async fn lookup_rdap(ip: IpAddr, timeout: Duration) -> Result<RdapInfo, String> {
    let url = format!("https://rdap.org/ip/{ip}");
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("RDAP server returned {}", response.status()));
    }
    let registry_url = response.url().to_string();
    let body: Value = response.json().await.map_err(|e| e.to_string())?;
    Ok(parse_rdap(&body, registry_url))
}

fn parse_rdap(body: &Value, registry_url: String) -> RdapInfo {
    let handle = body
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string);
    let name = body.get("name").and_then(Value::as_str).map(str::to_string);
    let country = body
        .get("country")
        .and_then(Value::as_str)
        .map(str::to_string);

    let abuse_email = body
        .get("entities")
        .and_then(Value::as_array)
        .and_then(|entities| {
            entities.iter().find(|e| {
                e.get("roles")
                    .and_then(Value::as_array)
                    .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some("abuse")))
            })
        })
        .and_then(extract_vcard_email);

    RdapInfo {
        handle,
        name,
        country,
        registry_url,
        abuse_email,
    }
}

/// Pulls an email address out of an RDAP entity's jCard (`vcardArray`).
fn extract_vcard_email(entity: &Value) -> Option<String> {
    let vcard = entity.get("vcardArray")?.as_array()?;
    let fields = vcard.get(1)?.as_array()?;
    fields.iter().find_map(|field| {
        let parts = field.as_array()?;
        if parts.first()?.as_str()? != "email" {
            return None;
        }
        parts.get(3)?.as_str().map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_private_v4() {
        assert_eq!(classify("192.168.1.1".parse().unwrap()), IpClass::Private);
        assert_eq!(classify("10.0.0.1".parse().unwrap()), IpClass::Private);
    }

    #[test]
    fn classifies_cgnat() {
        assert_eq!(
            classify("100.64.0.1".parse().unwrap()),
            IpClass::CarrierGradeNat
        );
        assert_eq!(
            classify("100.127.255.255".parse().unwrap()),
            IpClass::CarrierGradeNat
        );
        assert_eq!(classify("100.128.0.1".parse().unwrap()), IpClass::Global);
    }

    #[test]
    fn classifies_loopback_and_link_local() {
        assert_eq!(classify("127.0.0.1".parse().unwrap()), IpClass::Loopback);
        assert_eq!(classify("169.254.1.1".parse().unwrap()), IpClass::LinkLocal);
        assert_eq!(classify("::1".parse().unwrap()), IpClass::Loopback);
        assert_eq!(classify("fe80::1".parse().unwrap()), IpClass::LinkLocal);
    }

    #[test]
    fn classifies_global_v4_and_v6() {
        assert_eq!(classify("8.8.8.8".parse().unwrap()), IpClass::Global);
        assert_eq!(
            classify("2606:4700:4700::1111".parse().unwrap()),
            IpClass::Global
        );
    }

    #[test]
    fn classifies_ula_and_documentation_v6() {
        assert_eq!(classify("fc00::1".parse().unwrap()), IpClass::Private);
        assert_eq!(
            classify("2001:db8::1".parse().unwrap()),
            IpClass::Documentation
        );
    }

    #[test]
    fn reverses_v4_octets() {
        assert_eq!(reversed_v4_labels("8.8.8.8".parse().unwrap()), "8.8.8.8");
        assert_eq!(reversed_v4_labels("1.2.3.4".parse().unwrap()), "4.3.2.1");
    }

    #[test]
    fn parses_cymru_origin_txt() {
        let info = parse_origin_txt("15169 | 8.8.8.0/24 | US | arin | 1992-12-01").unwrap();
        assert_eq!(info.asn, 15169);
        assert_eq!(info.prefix, "8.8.8.0/24");
        assert_eq!(info.country, "US");
    }

    #[test]
    fn parses_cymru_origin_txt_with_multiple_asns() {
        // Some prefixes are announced by more than one ASN; Cymru lists them
        // space-separated in the first field.
        let info = parse_origin_txt("701 703 | 4.0.0.0/9 | US | arin | 1992-12-01").unwrap();
        assert_eq!(info.asn, 701);
    }

    #[test]
    fn rejects_malformed_origin_txt() {
        assert!(parse_origin_txt("not enough fields").is_none());
    }

    #[test]
    fn parses_cymru_as_name_txt() {
        let name = parse_as_name_txt("15169 | US | arin | 2000-03-30 | GOOGLE, US");
        assert_eq!(name.as_deref(), Some("GOOGLE, US"));
    }

    #[test]
    fn parses_rdap_entity_abuse_email() {
        let body: Value = serde_json::from_str(
            r#"{
                "handle": "NET-8-8-8-0-1",
                "name": "GOGL",
                "country": "US",
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [
                            ["version", {}, "text", "4.0"],
                            ["email", {}, "text", "abuse@google.com"]
                        ]]
                    }
                ]
            }"#,
        )
        .unwrap();
        let rdap = parse_rdap(
            &body,
            "https://rdap.arin.net/registry/ip/8.8.8.8".to_string(),
        );
        assert_eq!(rdap.handle.as_deref(), Some("NET-8-8-8-0-1"));
        assert_eq!(rdap.abuse_email.as_deref(), Some("abuse@google.com"));
    }

    #[test]
    fn parses_rdap_with_no_abuse_entity() {
        let body: Value = serde_json::from_str(r#"{"handle": "X"}"#).unwrap();
        let rdap = parse_rdap(&body, "https://example.org".to_string());
        assert_eq!(rdap.handle.as_deref(), Some("X"));
        assert!(rdap.abuse_email.is_none());
    }
}
