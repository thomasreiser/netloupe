//! `csv` format: DigitalOcean's `https://digitalocean.com/geo/google.csv`.
//!
//! Headerless rows of `cidr,country_code,region_code,city,postal_code`.

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let mut reader = ::csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(data.as_bytes());

    let mut entries = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| FormatError::Csv(e.to_string()))?;
        let Some(cidr) = record.get(0).filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(prefix) = parse_cidr(cidr, "csv") else {
            continue;
        };
        let country = record.get(1).filter(|s| !s.is_empty());
        let region_code = record.get(2).filter(|s| !s.is_empty());
        let region = match (country, region_code) {
            (Some(c), Some(r)) => Some(format!("{c}-{r}")),
            (Some(c), None) => Some(c.to_string()),
            (None, _) => None,
        };
        entries.push(ParsedRange {
            prefix,
            service: None,
            region,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/digitalocean.csv");
    const MALFORMED: &str =
        include_str!("../../../tests/fixtures/ranges/digitalocean.malformed.csv");

    #[test]
    fn parses_real_digitalocean_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert_eq!(entries.len(), 10);
        assert_eq!(entries[0].region.as_deref(), Some("NL-NL-NH"));
    }

    #[test]
    fn skips_malformed_rows() {
        let entries = parse(MALFORMED).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
