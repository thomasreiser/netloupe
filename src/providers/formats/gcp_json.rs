//! `gcp-json` format: `https://www.gstatic.com/ipranges/cloud.json` (and
//! the same shape at `goog.json` for all of Google).
//!
//! Top level has a `prefixes` array; each entry has `ipv4Prefix` or
//! `ipv6Prefix`, plus `service` and `scope` (region) tags.

use serde_json::Value;

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let doc: Value = serde_json::from_str(data)?;
    let obj = doc
        .as_object()
        .ok_or(FormatError::Shape("expected a JSON object"))?;
    let prefixes = obj
        .get("prefixes")
        .and_then(Value::as_array)
        .ok_or(FormatError::Shape("missing \"prefixes\" array"))?;

    let entries = prefixes
        .iter()
        .filter_map(|item| {
            let cidr = item
                .get("ipv4Prefix")
                .or_else(|| item.get("ipv6Prefix"))
                .and_then(Value::as_str)?;
            let prefix = parse_cidr(cidr, "gcp-json")?;
            let service = item
                .get("service")
                .and_then(Value::as_str)
                .map(str::to_string);
            let region = item
                .get("scope")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some(ParsedRange {
                prefix,
                service,
                region,
            })
        })
        .collect();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/gcp-cloud.json");
    const MALFORMED: &str = include_str!("../../../tests/fixtures/ranges/gcp-cloud.malformed.json");

    #[test]
    fn parses_real_gcp_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert_eq!(entries.len(), 10);
        assert!(entries
            .iter()
            .all(|e| e.service.as_deref() == Some("Google Cloud")));
    }

    #[test]
    fn skips_entries_without_a_prefix_field() {
        let entries = parse(MALFORMED).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_missing_prefixes_key() {
        assert!(parse(r#"{"foo": 1}"#).is_err());
    }
}
