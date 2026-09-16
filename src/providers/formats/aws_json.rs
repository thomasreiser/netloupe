//! `aws-json` format: `https://ip-ranges.amazonaws.com/ip-ranges.json`.
//!
//! Top level has `prefixes` (IPv4) and `ipv6_prefixes` (IPv6) arrays; each
//! entry carries a `service` tag (`AMAZON`, `CLOUDFRONT`, `EC2`, `S3`, ...)
//! and a `region` (e.g. `eu-central-1`).

use serde_json::Value;

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let doc: Value = serde_json::from_str(data)?;
    let obj = doc
        .as_object()
        .ok_or(FormatError::Shape("expected a JSON object"))?;
    if !obj.contains_key("prefixes") {
        return Err(FormatError::Shape("missing \"prefixes\" array"));
    }

    let mut entries = Vec::new();
    entries.extend(extract(obj.get("prefixes"), "ip_prefix"));
    entries.extend(extract(obj.get("ipv6_prefixes"), "ipv6_prefix"));
    Ok(entries)
}

fn extract(list: Option<&Value>, cidr_field: &str) -> Vec<ParsedRange> {
    let Some(items) = list.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let cidr = item.get(cidr_field)?.as_str()?;
            let prefix = parse_cidr(cidr, "aws-json")?;
            let service = item
                .get("service")
                .and_then(Value::as_str)
                .map(str::to_string);
            let region = item
                .get("region")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some(ParsedRange {
                prefix,
                service,
                region,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/aws-ip-ranges.json");
    const MALFORMED: &str =
        include_str!("../../../tests/fixtures/ranges/aws-ip-ranges.malformed.json");

    #[test]
    fn parses_real_aws_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert_eq!(entries.len(), 16);
        let cloudfront = entries
            .iter()
            .find(|e| e.service.as_deref() == Some("CLOUDFRONT"));
        assert!(cloudfront.is_some() || entries.iter().any(|e| e.service.is_some()));
    }

    #[test]
    fn skips_malformed_entries_without_failing() {
        let entries = parse(MALFORMED).unwrap();
        // One valid v4 entry; the bad entry and the non-array ipv6_prefixes
        // are both skipped rather than failing the whole parse.
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_non_object_document() {
        let err = parse("[]").unwrap_err();
        assert!(matches!(err, FormatError::Shape(_)));
    }

    #[test]
    fn rejects_missing_prefixes_key() {
        let err = parse(r#"{"other": 1}"#).unwrap_err();
        assert!(matches!(err, FormatError::Shape(_)));
    }
}
