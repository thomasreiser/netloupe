//! `plain` format: one CIDR per line, as published by Cloudflare
//! (`ips-v4`/`ips-v6`) and used by most manually-curated range lists.

use super::{parse_cidr, ParsedRange};

pub fn parse(data: &str) -> Vec<ParsedRange> {
    data.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| parse_cidr(l, "plain"))
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

    const CLOUDFLARE_V4: &str = include_str!("../../../tests/fixtures/ranges/cloudflare-v4.txt");
    const MALFORMED: &str =
        include_str!("../../../tests/fixtures/ranges/cloudflare-v4.malformed.txt");

    #[test]
    fn parses_real_cloudflare_sample() {
        let entries = parse(CLOUDFLARE_V4);
        assert_eq!(entries.len(), 15);
        assert!(entries
            .iter()
            .any(|e| e.prefix.to_string() == "173.245.48.0/20"));
    }

    #[test]
    fn skips_malformed_lines() {
        let entries = parse(MALFORMED);
        // 2 valid CIDRs; "not-a-cidr" and the blank line are skipped.
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let entries = parse("# comment\n\n10.0.0.0/8\n");
        assert_eq!(entries.len(), 1);
    }
}
