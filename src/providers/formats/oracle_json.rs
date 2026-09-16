//! `oracle-json` format:
//! `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json`.
//!
//! `{"regions": [{"region": "...", "cidrs": [{"cidr": "...", "tags": [...]}]}]}`.
//! The first tag (e.g. `"OCI"`) is used as the service tag.

use serde_json::Value;

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let doc: Value = serde_json::from_str(data)?;
    let obj = doc
        .as_object()
        .ok_or(FormatError::Shape("expected a JSON object"))?;
    let regions = obj
        .get("regions")
        .and_then(Value::as_array)
        .ok_or(FormatError::Shape("missing \"regions\" array"))?;

    let mut entries = Vec::new();
    for region_obj in regions {
        let region = region_obj.get("region").and_then(Value::as_str);
        let Some(cidrs) = region_obj.get("cidrs").and_then(Value::as_array) else {
            continue;
        };
        for cidr_obj in cidrs {
            let Some(cidr) = cidr_obj.get("cidr").and_then(Value::as_str) else {
                continue;
            };
            let Some(prefix) = parse_cidr(cidr, "oracle-json") else {
                continue;
            };
            let service = cidr_obj
                .get("tags")
                .and_then(Value::as_array)
                .and_then(|tags| tags.first())
                .and_then(Value::as_str)
                .map(str::to_string);
            entries.push(ParsedRange {
                prefix,
                service,
                region: region.map(str::to_string),
            });
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/oracle.json");
    const MALFORMED: &str = include_str!("../../../tests/fixtures/ranges/oracle.malformed.json");

    #[test]
    fn parses_real_oracle_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert!(!entries.is_empty());
        // Real Oracle data mixes the core "OCI" tag with service-specific
        // ones like "OSN" (Object Storage), so only some entries match.
        assert!(entries.iter().any(|e| e.service.as_deref() == Some("OCI")));
        assert!(entries.iter().any(|e| e.service.as_deref() == Some("OSN")));
    }

    #[test]
    fn skips_bad_cidrs_and_regions_without_cidrs() {
        let entries = parse(MALFORMED).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_missing_regions_key() {
        assert!(parse(r#"{"other": 1}"#).is_err());
    }
}
