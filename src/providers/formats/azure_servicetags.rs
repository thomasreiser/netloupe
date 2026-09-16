//! `azure-servicetags` format: the "Azure IP Ranges and Service Tags -
//! Public Cloud" JSON published by Microsoft. The download URL rotates
//! weekly (see `providers::update`); this parses whatever JSON it resolves
//! to, which has kept the same `values[].properties` shape for years.
//!
//! `{"values": [{"name": "...", "properties": {"region": "...",
//! "systemService": "...", "addressPrefixes": [...]}}]}`. An empty
//! `systemService` means the tag is a plain region (e.g. `AzureCloud`),
//! not a specific service like `AzureFrontDoor.Frontend`.

use serde_json::Value;

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let doc: Value = serde_json::from_str(data)?;
    let obj = doc
        .as_object()
        .ok_or(FormatError::Shape("expected a JSON object"))?;
    let values = obj
        .get("values")
        .and_then(Value::as_array)
        .ok_or(FormatError::Shape("missing \"values\" array"))?;

    let mut entries = Vec::new();
    for value in values {
        let Some(props) = value.get("properties") else {
            continue;
        };
        let Some(prefixes) = props.get("addressPrefixes").and_then(Value::as_array) else {
            continue;
        };
        let region = props
            .get("region")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let service = props
            .get("systemService")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        for prefix in prefixes {
            let Some(cidr) = prefix.as_str() else {
                continue;
            };
            let Some(prefix) = parse_cidr(cidr, "azure-servicetags") else {
                continue;
            };
            entries.push(ParsedRange {
                prefix,
                service: service.map(str::to_string),
                region: region.map(str::to_string),
            });
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/azure-servicetags.json");
    const MALFORMED: &str =
        include_str!("../../../tests/fixtures/ranges/azure-servicetags.malformed.json");

    #[test]
    fn parses_real_azure_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries
            .iter()
            .any(|e| e.service.as_deref() == Some("AzureFrontDoor.Frontend")));
        assert!(entries
            .iter()
            .any(|e| e.region.as_deref() == Some("westeurope") && e.service.is_none()));
    }

    #[test]
    fn skips_bad_prefixes_and_missing_properties() {
        let entries = parse(MALFORMED).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_missing_values_key() {
        assert!(parse(r#"{"other": 1}"#).is_err());
    }
}
