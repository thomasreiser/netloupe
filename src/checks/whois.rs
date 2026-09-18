//! Domain registration info -- registrar, creation/expiry dates, status
//! codes, and nameservers for the domain name itself. Not to be confused
//! with the IP/ASN pane's RDAP, which covers IP address block ownership;
//! shown inside the DNS pane rather than a pane of its own.
//!
//! RDAP over HTTP first (structured JSON, and the norm for gTLDs since
//! ICANN's 2021 mandate); raw WHOIS on port 43 as the fallback for the
//! registries -- mostly ccTLDs -- that don't publish RDAP, per
//! `CLAUDE.md`'s tech stack section.

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::retry::{self, Failure};
use crate::target::Target;

/// Where a [`WhoisInfo`] came from, so the pane can label a raw WHOIS
/// response differently from clean RDAP JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhoisSource {
    Rdap,
    /// Raw WHOIS, naming the server that actually answered.
    Whois(String),
}

/// A domain's registration info: enough to answer "who registered this,
/// when, and is it about to expire" without reproducing the whole
/// RDAP/WHOIS document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoisInfo {
    pub source: WhoisSource,
    pub registrar: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub expires: Option<String>,
    pub statuses: Vec<String>,
    pub name_servers: Vec<String>,
    /// Rarely present anymore -- most registrars redact this by default
    /// under GDPR/ICANN privacy requirements -- but shown when a registry
    /// still publishes it.
    pub registrant_org: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WhoisResult {
    pub domain: String,
    pub info: Option<WhoisInfo>,
    /// Both lookups' errors when neither produced anything -- `info` is
    /// `None` in that case, not a failed check: a domain occasionally has
    /// no reachable registry WHOIS/RDAP endpoint at all, which is still a
    /// normal (if unhelpful) outcome, not a bug in this tool.
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Whois;
    super::run_guarded(&ctx, id, &tx, async {
        let Target::Host { ascii, .. } = &ctx.target else {
            return Err("WHOIS applies to domain names, not bare IP addresses".to_string());
        };
        let domain = ascii.trim_end_matches('.').to_string();
        let timeout = ctx.config.timeouts.rdap;

        let mut result = WhoisResult {
            domain: domain.clone(),
            info: None,
            errors: Vec::new(),
        };

        match lookup_rdap_domain(&domain, timeout).await {
            Ok(info) => result.info = Some(info),
            Err(rdap_err) => match lookup_whois_domain(&domain, timeout).await {
                Ok(info) => result.info = Some(info),
                Err(whois_err) => {
                    result.errors.push(format!("RDAP: {rdap_err}"));
                    result.errors.push(format!("WHOIS: {whois_err}"));
                }
            },
        }

        Ok(CheckUpdate::Whois(result))
    })
    .await;
}

/// Retried (see `crate::retry`): `rdap.org` (a bootstrap redirector to
/// whichever registry actually holds the record, the same service
/// `checks::ipinfo` uses for IP RDAP) is netloupe's own helper request,
/// not the target itself.
async fn lookup_rdap_domain(domain: &str, timeout: Duration) -> Result<WhoisInfo, String> {
    let url = format!("https://rdap.org/domain/{domain}");
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;

    retry::run(&retry::Policy::default(), || async {
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(retry::classify_send_error)?;
        if !response.status().is_success() {
            return Err(retry::classify_status(response.status()));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|e| Failure::Retryable(e.to_string()))?;
        parse_rdap_domain(&body)
            .ok_or_else(|| Failure::Fatal("unexpected RDAP response shape".to_string()))
    })
    .await
}

fn parse_rdap_domain(body: &Value) -> Option<WhoisInfo> {
    let statuses = body
        .get("status")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let name_servers = body
        .get("nameservers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|ns| ns.get("ldhName").and_then(Value::as_str))
                .map(|s| s.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();

    let events = body.get("events").and_then(Value::as_array);
    let created = rdap_event_date(events, "registration");
    let updated = rdap_event_date(events, "last changed");
    let expires = rdap_event_date(events, "expiration");

    let entities = body.get("entities").and_then(Value::as_array);
    let registrar = entities.and_then(|entities| {
        entities
            .iter()
            .find(|e| has_role(e, "registrar"))
            .and_then(extract_vcard_fn)
    });
    let registrant_org = entities.and_then(|entities| {
        entities
            .iter()
            .find(|e| has_role(e, "registrant"))
            .and_then(extract_vcard_org)
    });

    Some(WhoisInfo {
        source: WhoisSource::Rdap,
        registrar,
        created,
        updated,
        expires,
        statuses,
        name_servers,
        registrant_org,
    })
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(Value::as_array)
        .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some(role)))
}

/// Reads an RDAP `events` array for the date of a given `eventAction`
/// (e.g. `"registration"`, `"expiration"`, `"last changed"` -- RFC 9083
/// §4.5).
fn rdap_event_date(events: Option<&Vec<Value>>, action: &str) -> Option<String> {
    events?
        .iter()
        .find(|e| e.get("eventAction").and_then(Value::as_str) == Some(action))
        .and_then(|e| e.get("eventDate"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Pulls an entity's formatted name (vCard `fn`) out of its jCard
/// (`vcardArray`) -- e.g. the registrar's display name.
fn extract_vcard_fn(entity: &Value) -> Option<String> {
    extract_vcard_field(entity, "fn").and_then(|v| v.as_str().map(str::to_string))
}

/// Pulls an entity's organization (vCard `org`) out of its jCard --
/// present as a plain string or, per RFC 6350, an array (organization
/// name followed by unit names); only the first component is shown.
fn extract_vcard_org(entity: &Value) -> Option<String> {
    let field = extract_vcard_field(entity, "org")?;
    if let Some(s) = field.as_str() {
        return Some(s.to_string());
    }
    field.as_array()?.first()?.as_str().map(str::to_string)
}

fn extract_vcard_field<'a>(entity: &'a Value, name: &str) -> Option<&'a Value> {
    let vcard = entity.get("vcardArray")?.as_array()?;
    let fields = vcard.get(1)?.as_array()?;
    fields.iter().find_map(|field| {
        let parts = field.as_array()?;
        if parts.first()?.as_str()? != name {
            return None;
        }
        parts.get(3)
    })
}

/// The well-known root WHOIS server every TLD is registered with --
/// queried first to learn which server actually holds a given domain's
/// registration record.
const IANA_WHOIS_SERVER: &str = "whois.iana.org";

async fn lookup_whois_domain(domain: &str, timeout: Duration) -> Result<WhoisInfo, String> {
    let tld = domain
        .rsplit('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "domain has no TLD".to_string())?;
    let referral = query_whois(IANA_WHOIS_SERVER, tld, timeout).await?;
    let server = extract_whois_referral(&referral)
        .ok_or_else(|| format!("IANA WHOIS has no referral for .{tld}"))?;
    let body = query_whois(&server, domain, timeout).await?;
    parse_whois_text(&body, &server)
        .ok_or_else(|| format!("could not parse a response from {server}"))
}

/// Sends one plain-text WHOIS query (RFC 3912: the query, CRLF-
/// terminated, is the entire request) and returns the response -- the
/// server closes the connection once it's done, so reading to EOF is the
/// only way to know the reply is complete.
async fn query_whois(server: &str, query: &str, timeout: Duration) -> Result<String, String> {
    let connect = TcpStream::connect((server, 43));
    let mut stream = tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| format!("connecting to {server}: timed out"))?
        .map_err(|e| format!("connecting to {server}: {e}"))?;
    stream
        .write_all(format!("{query}\r\n").as_bytes())
        .await
        .map_err(|e| format!("writing to {server}: {e}"))?;

    let mut buf = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| format!("reading from {server}: timed out"))?
        .map_err(|e| format!("reading from {server}: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Pulls the "refer:"/"whois:" field IANA's root WHOIS server gives for a
/// TLD -- the actual registry's WHOIS server to query next.
fn extract_whois_referral(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let key = key.trim().to_ascii_lowercase();
        if key != "refer" && key != "whois" {
            return None;
        }
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// Loosely parses a raw WHOIS response's `key: value` lines, tolerating
/// the many field-name variants registries use -- there's no fixed
/// schema across them, unlike RDAP's JSON. Fields not recognized are
/// simply ignored rather than causing a parse failure; `None` only when
/// nothing recognizable was found at all (e.g. an empty/garbled reply).
fn parse_whois_text(text: &str, server: &str) -> Option<WhoisInfo> {
    let mut info = WhoisInfo {
        source: WhoisSource::Whois(server.to_string()),
        registrar: None,
        created: None,
        updated: None,
        expires: None,
        statuses: Vec::new(),
        name_servers: Vec::new(),
        registrant_org: None,
    };
    let mut found_anything = false;

    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "registrar" => {
                info.registrar.get_or_insert_with(|| value.to_string());
                found_anything = true;
            }
            "creation date" | "domain registration date" | "registered on" | "created" => {
                info.created.get_or_insert_with(|| value.to_string());
                found_anything = true;
            }
            "updated date" | "last modified" | "domain last updated date" => {
                info.updated.get_or_insert_with(|| value.to_string());
                found_anything = true;
            }
            "registry expiry date"
            | "expiration date"
            | "expiry date"
            | "domain expiration date"
            | "paid-till" => {
                info.expires.get_or_insert_with(|| value.to_string());
                found_anything = true;
            }
            // Bare "status" (no "domain" prefix) is what thin registries
            // with little else to report use, e.g. DENIC's WHOIS for a
            // .de domain replies with just "Domain:"/"Status:" -- Germany's
            // privacy rules keep registrar/dates/nameservers out of it
            // entirely, so this is often the only field available at all.
            "domain status" | "status" => {
                info.statuses.push(value.to_string());
                found_anything = true;
            }
            "name server" | "nserver" => {
                info.name_servers.push(value.to_ascii_lowercase());
                found_anything = true;
            }
            "registrant organization" | "registrant org" => {
                info.registrant_org.get_or_insert_with(|| value.to_string());
                found_anything = true;
            }
            _ => {}
        }
    }

    found_anything.then_some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_realistic_rdap_domain_response() {
        let body: Value = serde_json::from_str(
            r#"{
                "status": ["client transfer prohibited"],
                "nameservers": [
                    {"ldhName": "NS1.EXAMPLE.COM"},
                    {"ldhName": "NS2.EXAMPLE.COM"}
                ],
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
                    {"eventAction": "last changed", "eventDate": "2024-08-14T04:00:00Z"}
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Example Registrar, Inc."]
                        ]]
                    }
                ]
            }"#,
        )
        .unwrap();
        let info = parse_rdap_domain(&body).unwrap();
        assert_eq!(info.source, WhoisSource::Rdap);
        assert_eq!(info.registrar.as_deref(), Some("Example Registrar, Inc."));
        assert_eq!(info.created.as_deref(), Some("1995-08-14T04:00:00Z"));
        assert_eq!(info.expires.as_deref(), Some("2026-08-13T04:00:00Z"));
        assert_eq!(info.updated.as_deref(), Some("2024-08-14T04:00:00Z"));
        assert_eq!(
            info.name_servers,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
        );
        assert_eq!(info.statuses, vec!["client transfer prohibited"]);
        assert!(info.registrant_org.is_none());
    }

    #[test]
    fn parses_registrant_org_as_a_vcard_array_value() {
        let body: Value = serde_json::from_str(
            r#"{
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [
                            ["org", {}, "text", ["Example Org", "Networking Unit"]]
                        ]]
                    }
                ]
            }"#,
        )
        .unwrap();
        let info = parse_rdap_domain(&body).unwrap();
        assert_eq!(info.registrant_org.as_deref(), Some("Example Org"));
    }

    #[test]
    fn extracts_a_refer_line_from_the_iana_response() {
        let response =
            "% IANA WHOIS server\nrefer:        whois.verisign-grs.com\ndomain:       COM\n";
        assert_eq!(
            extract_whois_referral(response).as_deref(),
            Some("whois.verisign-grs.com")
        );
    }

    #[test]
    fn extracts_a_whois_line_when_theres_no_refer_line() {
        let response = "domain:  DE\nwhois:   whois.denic.de\n";
        assert_eq!(
            extract_whois_referral(response).as_deref(),
            Some("whois.denic.de")
        );
    }

    #[test]
    fn extract_whois_referral_is_none_without_either_field() {
        assert!(extract_whois_referral("domain: EXAMPLE\nstatus: ACTIVE\n").is_none());
    }

    #[test]
    fn parses_a_realistic_raw_whois_response() {
        let text = "\
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
";
        let info = parse_whois_text(text, "whois.verisign-grs.com").unwrap();
        assert_eq!(
            info.source,
            WhoisSource::Whois("whois.verisign-grs.com".to_string())
        );
        assert_eq!(info.registrar.as_deref(), Some("Example Registrar, Inc."));
        assert_eq!(info.created.as_deref(), Some("1995-08-14T04:00:00Z"));
        assert_eq!(info.expires.as_deref(), Some("2026-08-13T04:00:00Z"));
        assert_eq!(info.statuses.len(), 2);
        assert_eq!(
            info.name_servers,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
        );
    }

    #[test]
    fn parse_whois_text_is_none_for_an_unrecognizable_response() {
        assert!(parse_whois_text("nothing useful here\n", "whois.example").is_none());
    }

    /// DENIC's actual .de WHOIS reply for a registered domain: just two
    /// fields, no registrar/dates/nameservers at all (German privacy
    /// rules keep the rest out of it). Still real, usable information --
    /// not a parse failure.
    #[test]
    fn parses_denics_minimal_de_response() {
        let text = "Domain: example.de\nStatus: connect\n";
        let info = parse_whois_text(text, "whois.denic.de").unwrap();
        assert_eq!(info.statuses, vec!["connect".to_string()]);
        assert!(info.registrar.is_none());
    }
}
