//! Parsing and normalizing user input into a [`Target`].
//!
//! The user can type a bare hostname, an IPv4/IPv6 address, an IDN (unicode)
//! hostname, or a full URL. Everything funnels through [`Target::parse`] so
//! the rest of the app only ever deals with one normalized shape.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// A normalized target host, either a resolvable name or a literal IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// A hostname, stored in its ASCII (Punycode) form for lookups, with the
    /// original (possibly unicode) input kept for display.
    Host { ascii: String, display: String },
    /// A literal IPv4 or IPv6 address.
    Ip(IpAddr),
}

/// Errors that can occur while parsing user input into a [`Target`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetParseError {
    #[error("empty input")]
    Empty,
    #[error("'{0}' is not a valid hostname or IP address")]
    Invalid(String),
}

impl Target {
    /// Parses a hostname, IPv4/IPv6 address, IDN, or URL into a [`Target`].
    ///
    /// URLs are reduced to their host component (scheme, path, query, and
    /// port are discarded here; a port survives separately via
    /// [`Target::parse_with_port`] when the caller needs it).
    pub fn parse(input: &str) -> Result<Self, TargetParseError> {
        Self::parse_with_port(input).map(|(target, _port)| target)
    }

    /// Like [`Target::parse`], but also returns a port if one was present
    /// (from a URL's authority, or a bare `host:port` for IPv4/hostnames).
    pub fn parse_with_port(input: &str) -> Result<(Self, Option<u16>), TargetParseError> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(TargetParseError::Empty);
        }

        // Strip a URL scheme, if present, and keep only the authority.
        let without_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
        // Drop path/query/fragment.
        let authority = without_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(without_scheme);
        // Drop userinfo (user@host).
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);

        let (host_part, port) = split_host_port(authority)?;
        if host_part.is_empty() {
            return Err(TargetParseError::Invalid(input.to_string()));
        }

        // IPv6 literal, e.g. "::1" or "[::1]".
        let bracket_stripped = host_part
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'));
        if let Some(v6) = bracket_stripped {
            let addr: Ipv6Addr = v6
                .parse()
                .map_err(|_| TargetParseError::Invalid(input.to_string()))?;
            return Ok((Target::Ip(IpAddr::V6(addr)), port));
        }
        if let Ok(addr) = host_part.parse::<Ipv6Addr>() {
            return Ok((Target::Ip(IpAddr::V6(addr)), port));
        }
        if let Ok(addr) = host_part.parse::<Ipv4Addr>() {
            return Ok((Target::Ip(IpAddr::V4(addr)), port));
        }

        // Otherwise treat it as a hostname, converting IDN labels to ASCII.
        let ascii = idna::domain_to_ascii(host_part)
            .map_err(|_| TargetParseError::Invalid(input.to_string()))?;
        if !is_valid_hostname(&ascii) {
            return Err(TargetParseError::Invalid(input.to_string()));
        }
        Ok((
            Target::Host {
                ascii,
                display: host_part.to_string(),
            },
            port,
        ))
    }

    /// The string used for display in tab labels and pane headers.
    pub fn display(&self) -> String {
        match self {
            Target::Host { display, .. } => display.clone(),
            Target::Ip(ip) => ip.to_string(),
        }
    }

    /// The string used for DNS lookups and cache keys (ASCII/punycode form).
    pub fn lookup_name(&self) -> Option<&str> {
        match self {
            Target::Host { ascii, .. } => Some(ascii),
            Target::Ip(_) => None,
        }
    }

    /// True if this target is already a literal IP address.
    pub fn is_ip(&self) -> bool {
        matches!(self, Target::Ip(_))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Splits a `host` or `host:port` string. IPv6 literals must be bracketed
/// (`[::1]:80`) to disambiguate the colon; a bare `[::1]` without a port is
/// also accepted.
fn split_host_port(s: &str) -> Result<(&str, Option<u16>), TargetParseError> {
    if s.starts_with('[') {
        // Bracketed IPv6, optionally followed by ":port". The host part
        // (brackets included) is stripped by the caller before parsing.
        return match s.find(']') {
            Some(end) => {
                let host = &s[..=end];
                let tail = &s[end + 1..];
                let port = match tail.strip_prefix(':') {
                    Some(p) if !p.is_empty() => Some(
                        p.parse::<u16>()
                            .map_err(|_| TargetParseError::Invalid(s.to_string()))?,
                    ),
                    Some(_) => return Err(TargetParseError::Invalid(s.to_string())),
                    None => None,
                };
                Ok((host, port))
            }
            None => Err(TargetParseError::Invalid(s.to_string())),
        };
    }

    // A bare IPv6 address has multiple colons; leave it alone.
    if s.matches(':').count() > 1 {
        return Ok((s, None));
    }

    match s.split_once(':') {
        Some((host, port)) if !port.is_empty() => {
            let port = port
                .parse::<u16>()
                .map_err(|_| TargetParseError::Invalid(s.to_string()))?;
            Ok((host, Some(port)))
        }
        _ => Ok((s, None)),
    }
}

/// RFC 1123-ish hostname validation: labels of letters/digits/hyphens,
/// 1-63 chars each, not starting or ending with a hyphen, at most 253 chars
/// total, with at least one label (so a bare "." or "-" is rejected).
fn is_valid_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.is_empty() {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_hostname() {
        let t = Target::parse("example.com").unwrap();
        assert_eq!(t.display(), "example.com");
        assert_eq!(t.lookup_name(), Some("example.com"));
        assert!(!t.is_ip());
    }

    #[test]
    fn parses_ipv4() {
        let t = Target::parse("8.8.8.8").unwrap();
        assert_eq!(t, Target::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(t.is_ip());
    }

    #[test]
    fn parses_ipv6() {
        let t = Target::parse("2606:4700:4700::1111").unwrap();
        assert!(t.is_ip());
        assert_eq!(t.display(), "2606:4700:4700::1111");
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let (t, port) = Target::parse_with_port("[::1]:8443").unwrap();
        assert_eq!(t, Target::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn parses_url_to_host() {
        let t = Target::parse("https://example.com:8443/path?q=1").unwrap();
        assert_eq!(t.display(), "example.com");
        let (t2, port) = Target::parse_with_port("https://example.com:8443/path").unwrap();
        assert_eq!(t2.display(), "example.com");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn parses_hostname_with_port() {
        let (t, port) = Target::parse_with_port("example.com:443").unwrap();
        assert_eq!(t.display(), "example.com");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parses_idn_hostname() {
        let t = Target::parse("münchen.de").unwrap();
        assert_eq!(t.lookup_name(), Some("xn--mnchen-3ya.de"));
        assert_eq!(t.display(), "münchen.de");
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(Target::parse(""), Err(TargetParseError::Empty));
        assert_eq!(Target::parse("   "), Err(TargetParseError::Empty));
    }

    #[test]
    fn rejects_invalid_hostname() {
        assert!(Target::parse("-bad-.com").is_err());
        assert!(Target::parse("..").is_err());
    }

    #[test]
    fn strips_userinfo_from_url() {
        let t = Target::parse("https://user:pass@example.com/").unwrap();
        assert_eq!(t.display(), "example.com");
    }
}
