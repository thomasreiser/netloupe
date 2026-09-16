//! `github-meta` format: `https://api.github.com/meta`.
//!
//! A grab-bag JSON object where several top-level keys (`hooks`, `web`,
//! `api`, `git`, `actions`, `pages`, `codespaces`, ...) are each a flat
//! array of CIDR strings; other keys (booleans, key fingerprints, PGP
//! blocks) are not range lists and are skipped. The key name becomes the
//! `service` tag, since that's the most useful thing GitHub publishes here.

use serde_json::Value;

use super::{parse_cidr, FormatError, ParsedRange};

pub fn parse(data: &str) -> Result<Vec<ParsedRange>, FormatError> {
    let doc: Value = serde_json::from_str(data)?;
    let obj = doc
        .as_object()
        .ok_or(FormatError::Shape("expected a JSON object"))?;

    let mut entries = Vec::new();
    for (key, value) in obj {
        let Some(items) = value.as_array() else {
            continue;
        };
        for item in items {
            let Some(s) = item.as_str() else { continue };
            if s.is_empty() {
                continue;
            }
            if let Some(prefix) = parse_cidr(s, "github-meta") {
                entries.push(ParsedRange {
                    prefix,
                    service: Some(key.clone()),
                    region: None,
                });
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../tests/fixtures/ranges/github-meta.json");
    const MALFORMED: &str =
        include_str!("../../../tests/fixtures/ranges/github-meta.malformed.json");

    #[test]
    fn parses_real_github_sample() {
        let entries = parse(SAMPLE).unwrap();
        assert!(!entries.is_empty());
        assert!(entries
            .iter()
            .any(|e| e.service.as_deref() == Some("actions")));
    }

    #[test]
    fn skips_non_cidr_and_non_array_keys() {
        let entries = parse(MALFORMED).unwrap();
        // "web" has one valid entry and one empty string; "api" isn't a list.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].service.as_deref(), Some("web"));
    }

    #[test]
    fn rejects_non_object_document() {
        assert!(parse("42").is_err());
    }
}
