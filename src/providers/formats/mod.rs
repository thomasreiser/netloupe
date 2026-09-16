//! Parsers for the range-list formats providers publish their IP ranges in.
//!
//! Each parser is lenient about individual malformed entries (skip and keep
//! going) but returns an error when the overall document doesn't look like
//! the expected format at all, so a provider whose list changed shape fails
//! on its own without taking down the others (see `providers::update`).

pub mod aws_json;
pub mod azure_servicetags;
pub mod csv;
pub mod fastly_json;
pub mod gcp_json;
pub mod github_meta;
pub mod oracle_json;
pub mod plain;

use ip_network::IpNetwork;
use serde::Deserialize;
use thiserror::Error;

/// One IP range extracted from a source document, before it's tagged with
/// a provider id and turned into a [`super::ranges::RangeEntry`].
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRange {
    pub prefix: IpNetwork,
    /// A service/product tag, when the source distinguishes them (AWS
    /// `CLOUDFRONT`/`EC2`, GCP `Google Cloud`, Azure `systemService`, ...).
    pub service: Option<String>,
    /// A region/location tag, when the source publishes one.
    pub region: Option<String>,
}

/// Errors parsing a range-list document.
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid CSV: {0}")]
    Csv(String),
    #[error("document does not look like the expected format: {0}")]
    Shape(&'static str),
}

/// The range-list formats known to netloupe, matching the `format` field of
/// a `[[ranges.sources]]` entry in a provider's TOML signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Plain,
    AwsJson,
    GcpJson,
    AzureServiceTags,
    OracleJson,
    FastlyJson,
    GithubMeta,
    Csv,
}

impl Format {
    /// The file extension snapshot/cache files for this format use, so a
    /// provider's sources can be matched to files on disk or embedded in
    /// the binary by a predictable name.
    pub fn file_extension(self) -> &'static str {
        match self {
            Format::Plain => "txt",
            Format::Csv => "csv",
            Format::AwsJson
            | Format::GcpJson
            | Format::AzureServiceTags
            | Format::OracleJson
            | Format::FastlyJson
            | Format::GithubMeta => "json",
        }
    }

    /// Parses `data` according to this format. Individual malformed
    /// entries are skipped (a `tracing::warn!` is emitted for each); only a
    /// broken top-level shape produces an `Err`.
    pub fn parse(self, data: &str) -> Result<Vec<ParsedRange>, FormatError> {
        match self {
            Format::Plain => Ok(plain::parse(data)),
            Format::AwsJson => aws_json::parse(data),
            Format::GcpJson => gcp_json::parse(data),
            Format::AzureServiceTags => azure_servicetags::parse(data),
            Format::OracleJson => oracle_json::parse(data),
            Format::FastlyJson => fastly_json::parse(data),
            Format::GithubMeta => github_meta::parse(data),
            Format::Csv => csv::parse(data),
        }
    }
}

/// Parses a CIDR string, returning `None` (and logging a warning tagged
/// with `context`) rather than propagating an error, since one bad entry
/// in an otherwise-good list shouldn't fail the whole source.
pub(crate) fn parse_cidr(s: &str, context: &str) -> Option<IpNetwork> {
    match s.trim().parse::<IpNetwork>() {
        Ok(net) => Some(net),
        Err(err) => {
            tracing::warn!(input = %s, context, %err, "skipping unparseable CIDR entry");
            None
        }
    }
}
