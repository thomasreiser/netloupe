//! `fastly-json` format: `https://api.fastly.com/public-ip-list`.
//!
//! `{"addresses": [...], "ipv6_addresses": [...]}`, both flat arrays of
//! CIDR strings with no service/region tags.

use serde_json::Value;

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let doc: Value = serde_json::from_str(data)?;
    let obj = doc
        .as_object()
        .ok_or(FormatError::Shape("expected a JSON object"))?;
    if !obj.contains_key("addresses") {
        return Err(FormatError::Shape("missing \"addresses\" array"));
    }

    let mut entries = Vec::new();
    entries.extend(extract(obj.get("addresses")));
    entries.extend(extract(obj.get("ipv6_addresses")));
    Ok(entries)
}

fn extract(list: Option<&Value>) -> Vec<ParsedRange> {
    let Some(items) = list.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|s| parse_cidr(s, "fastly-json"))
        .map(|prefix| ParsedRange {
            prefix,
            service: None,
            region: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/fastly.json");
    const MALFORMED: &str = include_str!("../../../tests/fixtures/ranges/fastly.malformed.json");

    #[test]
    fn parses_real_fastly_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert_eq!(entries.len(), 21);
    }

    #[test]
    fn skips_non_string_and_invalid_entries() {
        let entries = parse(MALFORMED).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_missing_addresses_key() {
        assert!(parse(r#"{"other": []}"#).is_err());
    }
}
