//! Hosting provider detection engine.
//!
//! This module is deliberately synchronous and does no I/O: [`evaluate`]
//! takes a plain [`Inputs`] struct (built by `checks::hosting` from the
//! results of other checks) and returns [`Detection`]s. That keeps it
//! trivially unit-testable with table-driven fixtures.

pub mod formats;
pub mod ranges;
pub mod signatures;
pub mod update;

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub use ranges::{RangeLoadReport, RangeTable, SourceLoadError};
pub use signatures::{SignatureError, SignatureLoadError};

/// A layer at which a provider can be detected. One host can involve
/// several providers at once, so results are per-layer, not a single verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// CDN/WAF/reverse proxy in front of the origin.
    Edge,
    /// Where the application actually runs, when determinable.
    Origin,
    /// Authoritative DNS provider.
    Dns,
    /// Mail provider, from MX/SPF.
    Mail,
    /// Hints from TXT verification records; shown as "uses", not "hosts".
    Saas,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Layer::Edge => "edge",
            Layer::Origin => "origin",
            Layer::Dns => "dns",
            Layer::Mail => "mail",
            Layer::Saas => "saas",
        };
        f.write_str(s)
    }
}

/// Confidence in a detection, derived from the summed weight of its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Confidence::Low => "Low",
            Confidence::Medium => "Medium",
            Confidence::High => "High",
        };
        f.write_str(s)
    }
}

/// Thresholds mapping a summed evidence weight to a [`Confidence`] level.
/// An IP range or ASN match alone (weight 100) is enough for `High`. A
/// single header or CNAME match alone (weight 50-70) gives `Medium`.
const HIGH_THRESHOLD: u32 = 100;
const MEDIUM_THRESHOLD: u32 = 40;

fn confidence_for_score(score: u32) -> Confidence {
    if score >= HIGH_THRESHOLD {
        Confidence::High
    } else if score >= MEDIUM_THRESHOLD {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// The kind of signal a [`Signal`] matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// An HTTP response header, matched by name and optionally by value.
    Header,
    /// A DNS NS record, matched against a glob pattern.
    Ns,
    /// A CNAME chain entry, matched against a glob pattern.
    Cname,
    /// A reverse-DNS (PTR) record, matched against a glob pattern.
    Ptr,
    /// The TLS certificate issuer CN, matched against a glob pattern.
    TlsIssuer,
    /// A TLS certificate SAN, matched against a glob pattern.
    TlsSan,
    /// An MX record, matched against a glob pattern.
    Mx,
    /// An SPF `include:` mechanism, matched against a glob pattern.
    SpfInclude,
}

/// A single compiled signal from a provider's signature file.
#[derive(Debug, Clone)]
pub struct Signal {
    pub layer: Layer,
    pub kind: SignalKind,
    pub weight: u32,
    /// For `header` signals: the header name to look for (case-insensitive).
    pub name: Option<String>,
    /// For `header` signals: an optional regex the value must match. When
    /// absent, the header's mere presence is enough.
    pub value_regex: Option<regex::Regex>,
    /// For every other signal kind: a glob pattern the value must match.
    pub pattern: Option<globset::GlobMatcher>,
}

/// A provider's compiled signature: identity plus its signals. Range and
/// ASN data live separately in [`RangeTable`] / the ASN index, since those
/// are shared, mergeable structures across all providers.
#[derive(Debug, Clone)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub kind: Vec<String>,
    pub asns: Vec<u32>,
    pub signals: Vec<Signal>,
}

/// A loaded set of provider signatures plus their compiled range table.
#[derive(Debug, Clone, Default)]
pub struct ProviderDb {
    pub signatures: Vec<Signature>,
    pub ranges: RangeTable,
}

impl ProviderDb {
    pub fn signature(&self, id: &str) -> Option<&Signature> {
        self.signatures.iter().find(|s| s.id == id)
    }

    /// Loads every embedded (plus user-defined, from `extra_signature_dir`)
    /// signature and builds its range table in one call. Does blocking I/O;
    /// call from a background task, not the UI event loop.
    pub fn load(
        extra_signature_dir: Option<&std::path::Path>,
        range_cache_dir: Option<&std::path::Path>,
    ) -> Result<(Self, RangeLoadReport), SignatureLoadError> {
        let loaded = signatures::load_all(extra_signature_dir)?;
        let report = ranges::load(&loaded, range_cache_dir);
        let signatures = loaded.into_iter().map(|l| l.signature).collect();
        Ok((
            Self {
                signatures,
                ranges: report.table.clone(),
            },
            report,
        ))
    }
}

/// One piece of supporting evidence behind a [`Detection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub description: String,
    pub weight: u32,
}

/// A detected provider at a given layer, with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub provider_id: String,
    pub provider_name: String,
    pub layer: Layer,
    pub confidence: Confidence,
    pub score: u32,
    pub evidence: Vec<Evidence>,
}

/// A resolved CNAME chain link, kept alongside the record it came from so
/// evidence can say which hostname resolved to what.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub ips: Vec<IpAddr>,
    /// Origin AS number of the prefix each IP belongs to, if known.
    pub asns: Vec<u32>,
    pub cnames: Vec<String>,
    pub ns: Vec<String>,
    pub ptr: Vec<String>,
    /// Lower-cased header name paired with its raw value.
    pub headers: Vec<(String, String)>,
    pub tls_issuer: Option<String>,
    pub tls_sans: Vec<String>,
    pub mx: Vec<String>,
    pub spf_includes: Vec<String>,
}

/// Runs every provider's signals against `inputs` and returns all
/// detections above zero score, strongest first. No I/O, no randomness:
/// the same inputs always produce the same output.
pub fn evaluate(db: &ProviderDb, inputs: &Inputs) -> Vec<Detection> {
    let mut acc: BTreeMap<(String, Layer), (u32, Vec<Evidence>)> = BTreeMap::new();

    let mut add = |provider_id: &str, layer: Layer, weight: u32, description: String| {
        let entry = acc.entry((provider_id.to_string(), layer)).or_default();
        entry.0 += weight;
        entry.1.push(Evidence {
            description,
            weight,
        });
    };

    // IP-range matches: strongest signal, longest-prefix match per address
    // family. Service/region tags (when the source publishes them) decide
    // the layer; otherwise the provider's configured default layer applies.
    for ip in &inputs.ips {
        if let Some(m) = db.ranges.lookup(*ip) {
            let mut desc = format!("IP {ip} \u{2208} {} {}", m.provider_id, m.source_name);
            if let Some(service) = &m.service {
                desc.push_str(&format!(" (service {service})"));
            }
            add(&m.provider_id, m.layer, 100, desc);
        }
    }

    // ASN matches.
    for sig in &db.signatures {
        for asn in &inputs.asns {
            if sig.asns.contains(asn) {
                let layer = sig.default_layer();
                add(
                    &sig.id,
                    layer,
                    100,
                    format!("ASN {asn} belongs to {}", sig.name),
                );
            }
        }
    }

    // Per-signal matches (headers, NS, CNAME, PTR, TLS, MX, SPF).
    for sig in &db.signatures {
        for signal in &sig.signals {
            match signal.kind {
                SignalKind::Header => match_header(sig, signal, inputs, &mut add),
                SignalKind::Ns => match_pattern_list(sig, signal, &inputs.ns, "NS", &mut add),
                SignalKind::Cname => {
                    match_pattern_list(sig, signal, &inputs.cnames, "CNAME", &mut add)
                }
                SignalKind::Ptr => match_pattern_list(sig, signal, &inputs.ptr, "PTR", &mut add),
                SignalKind::TlsSan => {
                    match_pattern_list(sig, signal, &inputs.tls_sans, "TLS SAN", &mut add)
                }
                SignalKind::TlsIssuer => {
                    if let Some(issuer) = &inputs.tls_issuer {
                        match_pattern_one(sig, signal, issuer, "TLS issuer", &mut add);
                    }
                }
                SignalKind::Mx => match_pattern_list(sig, signal, &inputs.mx, "MX", &mut add),
                SignalKind::SpfInclude => {
                    match_pattern_list(sig, signal, &inputs.spf_includes, "SPF include", &mut add)
                }
            }
        }
    }

    let mut detections: Vec<Detection> = acc
        .into_iter()
        .map(|((provider_id, layer), (score, mut evidence))| {
            evidence.sort_by(|a, b| b.weight.cmp(&a.weight));
            let provider_name = db
                .signature(&provider_id)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| provider_id.clone());
            Detection {
                provider_id,
                provider_name,
                layer,
                confidence: confidence_for_score(score),
                score,
                evidence,
            }
        })
        .collect();

    detections.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.provider_id.cmp(&b.provider_id))
    });
    detections
}

impl Signature {
    /// The layer an ASN match should be reported under, when the provider
    /// doesn't operate distinct edge/origin infrastructure. Providers whose
    /// `kind` includes `cdn` or `waf` default to `edge`; DNS-only providers
    /// default to `dns`; everything else defaults to `origin`.
    fn default_layer(&self) -> Layer {
        if self.kind.iter().any(|k| k == "cdn" || k == "waf") {
            Layer::Edge
        } else if self.kind.iter().all(|k| k == "dns") {
            Layer::Dns
        } else {
            Layer::Origin
        }
    }
}

fn match_header(
    sig: &Signature,
    signal: &Signal,
    inputs: &Inputs,
    add: &mut impl FnMut(&str, Layer, u32, String),
) {
    let Some(name) = &signal.name else { return };
    for (hname, hvalue) in &inputs.headers {
        if !hname.eq_ignore_ascii_case(name) {
            continue;
        }
        let matched = match &signal.value_regex {
            Some(re) => re.is_match(hvalue),
            None => true,
        };
        if matched {
            add(
                &sig.id,
                signal.layer,
                signal.weight,
                format!("header {hname} present"),
            );
        }
    }
}

fn match_pattern_list(
    sig: &Signature,
    signal: &Signal,
    values: &[String],
    label: &str,
    add: &mut impl FnMut(&str, Layer, u32, String),
) {
    let Some(pattern) = &signal.pattern else {
        return;
    };
    for value in values {
        if pattern.is_match(value.trim_end_matches('.')) {
            add(
                &sig.id,
                signal.layer,
                signal.weight,
                format!("{label} {value} matches {}", pattern.glob()),
            );
        }
    }
}

fn match_pattern_one(
    sig: &Signature,
    signal: &Signal,
    value: &str,
    label: &str,
    add: &mut impl FnMut(&str, Layer, u32, String),
) {
    let Some(pattern) = &signal.pattern else {
        return;
    };
    if pattern.is_match(value) {
        add(
            &sig.id,
            signal.layer,
            signal.weight,
            format!("{label} {value} matches {}", pattern.glob()),
        );
    }
}

#[cfg(test)]
mod tests;
