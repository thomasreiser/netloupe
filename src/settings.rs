//! In-app settings editor: a curated, ordered list of `Config` fields,
//! each described by a getter (the current value as an editable string)
//! and a setter (parses that string back, or returns a human-readable
//! error for invalid input). `app.rs`/`ui` drive one generic editable-
//! list screen from this list rather than a bespoke widget per field.
//!
//! Not every `Config` field is here -- keybindings and API-key-adjacent
//! plumbing that's rarely touched interactively are left to the file
//! itself; this covers the settings someone would actually reach for
//! while using the tool (GeoLite2 paths, timeouts, the port list, ...).

use crate::config::Config;
use crate::providers::Confidence;

/// One editable setting: `get` reads the current value out of a `Config`
/// as a plain string suitable for both display and re-editing; `set`
/// parses a (possibly edited) string back into the field, or explains
/// why it couldn't.
pub struct SettingField {
    pub label: &'static str,
    /// Shown as a hint under the input while editing.
    pub help: &'static str,
    pub get: fn(&Config) -> String,
    pub set: fn(&mut Config, &str) -> Result<(), String>,
}

/// The full, ordered list of editable settings.
pub fn fields() -> Vec<SettingField> {
    vec![
        SettingField {
            label: "MaxMind account ID",
            help: "blank to disable Geo pane lookups; from your MaxMind account's license-key page",
            get: |c| {
                c.geoip
                    .account_id
                    .map(|id| id.to_string())
                    .unwrap_or_default()
            },
            set: |c, v| {
                let trimmed = v.trim();
                c.geoip.account_id = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.parse::<u32>().map_err(|_| {
                        format!("{trimmed:?} isn't a valid MaxMind account ID (a plain number)")
                    })?)
                };
                Ok(())
            },
        },
        SettingField {
            label: "MaxMind license key",
            help: "blank to disable; generated alongside the account ID on maxmind.com",
            get: |c| c.geoip.license_key.clone().unwrap_or_default(),
            set: |c, v| {
                c.geoip.license_key = string_set(v);
                Ok(())
            },
        },
        SettingField {
            label: "GeoLite2 update interval",
            help: "e.g. \"4h\", \"1day\", \"7days\" -- how often the databases are refreshed",
            get: |c| duration_get(c.geoip.update_interval),
            set: |c, v| duration_set(v).map(|d| c.geoip.update_interval = d),
        },
        SettingField {
            label: "Extra signature directory",
            help: "blank for none; a directory of user-defined *.toml provider signatures",
            get: |c| path_get(&c.hosting.extra_signature_dir),
            set: |c, v| {
                c.hosting.extra_signature_dir = path_set(v);
                Ok(())
            },
        },
        SettingField {
            label: "Hosting data max age",
            help: "e.g. \"30days\", \"12h\" -- warns in the Hosting pane past this age",
            get: |c| duration_get(c.hosting.max_data_age),
            set: |c, v| duration_set(v).map(|d| c.hosting.max_data_age = d),
        },
        SettingField {
            label: "Hosting min confidence",
            help: "low, medium, or high -- detections below this are hidden",
            get: |c| c.hosting.min_confidence.to_string(),
            set: |c, v| {
                c.hosting.min_confidence = confidence_set(v)?;
                Ok(())
            },
        },
        SettingField {
            label: "AbuseIPDB API key",
            help: "blank to disable; optional extra signal for the Rep pane",
            get: |c| c.reputation.abuseipdb_key.clone().unwrap_or_default(),
            set: |c, v| {
                c.reputation.abuseipdb_key = string_set(v);
                Ok(())
            },
        },
        SettingField {
            label: "Shodan API key",
            help: "blank to disable (not yet used by any check)",
            get: |c| c.reputation.shodan_key.clone().unwrap_or_default(),
            set: |c, v| {
                c.reputation.shodan_key = string_set(v);
                Ok(())
            },
        },
        SettingField {
            label: "DNS timeout",
            help: "e.g. \"3s\", \"800ms\"",
            get: |c| duration_get(c.timeouts.dns),
            set: |c, v| duration_set(v).map(|d| c.timeouts.dns = d),
        },
        SettingField {
            label: "Ping timeout",
            help: "e.g. \"2s\"",
            get: |c| duration_get(c.timeouts.ping),
            set: |c, v| duration_set(v).map(|d| c.timeouts.ping = d),
        },
        SettingField {
            label: "TLS timeout",
            help: "e.g. \"4s\"",
            get: |c| duration_get(c.timeouts.tls),
            set: |c, v| duration_set(v).map(|d| c.timeouts.tls = d),
        },
        SettingField {
            label: "HTTP timeout",
            help: "e.g. \"6s\"",
            get: |c| duration_get(c.timeouts.http),
            set: |c, v| duration_set(v).map(|d| c.timeouts.http = d),
        },
        SettingField {
            label: "RDAP timeout",
            help: "e.g. \"4s\"",
            get: |c| duration_get(c.timeouts.rdap),
            set: |c, v| duration_set(v).map(|d| c.timeouts.rdap = d),
        },
        SettingField {
            label: "Reputation timeout",
            help: "e.g. \"5s\"",
            get: |c| duration_get(c.timeouts.reputation),
            set: |c, v| duration_set(v).map(|d| c.timeouts.reputation = d),
        },
        SettingField {
            label: "Port scan rate limit",
            help: "minimum delay between connection attempts, e.g. \"50ms\"",
            get: |c| duration_get(c.ports.rate_limit),
            set: |c, v| duration_set(v).map(|d| c.ports.rate_limit = d),
        },
        SettingField {
            label: "Port scan list",
            help: "comma-separated port numbers, e.g. \"22, 80, 443\"",
            get: |c| {
                c.ports
                    .scan_list
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            set: |c, v| {
                c.ports.scan_list = port_list_set(v)?;
                Ok(())
            },
        },
        SettingField {
            label: "Comparison resolvers",
            help: "comma-separated IPs, e.g. \"1.1.1.1, 8.8.8.8\" -- for split-horizon detection",
            get: |c| {
                c.resolvers
                    .comparison
                    .iter()
                    .map(std::net::IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            set: |c, v| {
                c.resolvers.comparison = ip_list_set(v)?;
                Ok(())
            },
        },
        SettingField {
            label: "Theme",
            help: "a free-form name; only \"default\" has a built-in palette so far",
            get: |c| c.theme.clone(),
            set: |c, v| {
                c.theme = v.trim().to_string();
                Ok(())
            },
        },
    ]
}

fn path_get(p: &Option<std::path::PathBuf>) -> String {
    p.as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

fn path_set(v: &str) -> Option<std::path::PathBuf> {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(trimmed))
    }
}

fn string_set(v: &str) -> Option<String> {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn duration_get(d: std::time::Duration) -> String {
    humantime::format_duration(d).to_string()
}

fn duration_set(v: &str) -> Result<std::time::Duration, String> {
    humantime::parse_duration(v.trim())
        .map_err(|e| format!("not a duration (try e.g. \"3s\" or \"800ms\"): {e}"))
}

fn confidence_set(v: &str) -> Result<Confidence, String> {
    match v.trim().to_lowercase().as_str() {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        other => Err(format!("expected low, medium, or high, got {other:?}")),
    }
}

fn port_list_set(v: &str) -> Result<Vec<u16>, String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| format!("{s:?} isn't a valid port number"))
        })
        .collect()
}

fn ip_list_set(v: &str) -> Result<Vec<std::net::IpAddr>, String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<std::net::IpAddr>()
                .map_err(|_| format!("{s:?} isn't a valid IP address"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field's `get` should be accepted right back by its own
    /// `set` unchanged -- the editor pre-fills the input with `get`'s
    /// output, so this is exactly the "press Enter without changing
    /// anything" path every field must survive.
    #[test]
    fn every_fields_get_output_round_trips_through_its_own_set() {
        let base = Config::default();
        for field in fields() {
            let value = (field.get)(&base);
            let mut c = Config::default();
            (field.set)(&mut c, &value)
                .unwrap_or_else(|e| panic!("{}: round-trip of {value:?} failed: {e}", field.label));
        }
    }

    #[test]
    fn path_fields_treat_blank_as_none() {
        let mut c = Config::default();
        c.hosting.extra_signature_dir = Some("/tmp/sigs".into());
        let field = fields()
            .into_iter()
            .find(|f| f.label == "Extra signature directory")
            .unwrap();
        assert_eq!((field.get)(&c), "/tmp/sigs");
        (field.set)(&mut c, "  ").unwrap();
        assert!(c.hosting.extra_signature_dir.is_none());
    }

    #[test]
    fn maxmind_account_id_rejects_non_numeric_input_and_accepts_blank() {
        let field = fields()
            .into_iter()
            .find(|f| f.label == "MaxMind account ID")
            .unwrap();
        let mut c = Config::default();
        assert!((field.set)(&mut c, "not a number").is_err());
        assert!(c.geoip.account_id.is_none());

        (field.set)(&mut c, "12345").unwrap();
        assert_eq!(c.geoip.account_id, Some(12345));

        (field.set)(&mut c, "  ").unwrap();
        assert!(c.geoip.account_id.is_none());
    }

    #[test]
    fn duration_set_rejects_garbage() {
        assert!(duration_set("not a duration").is_err());
        assert_eq!(
            duration_set("3s").unwrap(),
            std::time::Duration::from_secs(3)
        );
    }

    #[test]
    fn confidence_set_is_case_insensitive_and_rejects_unknown_words() {
        assert_eq!(confidence_set("Medium").unwrap(), Confidence::Medium);
        assert_eq!(confidence_set("HIGH").unwrap(), Confidence::High);
        assert!(confidence_set("extreme").is_err());
    }

    #[test]
    fn port_list_set_parses_and_rejects_out_of_range() {
        assert_eq!(port_list_set("80, 443").unwrap(), vec![80, 443]);
        assert!(port_list_set("80, notaport").is_err());
        assert!(port_list_set("80, 99999").is_err());
    }

    #[test]
    fn ip_list_set_parses_and_rejects_garbage() {
        assert_eq!(
            ip_list_set("1.1.1.1, 8.8.8.8").unwrap(),
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "8.8.8.8".parse().unwrap()
            ]
        );
        assert!(ip_list_set("1.1.1.1, not-an-ip").is_err());
    }
}
