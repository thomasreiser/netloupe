//! Application configuration.
//!
//! Loaded from `$XDG_CONFIG_HOME/netloupe/config.toml`. Every field has a
//! default, so the tool runs with no config file at all.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur while loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not determine the config directory for this platform")]
    NoConfigDir,
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize configuration: {0}")]
    Serialize(#[source] toml::ser::Error),
}

/// Top-level configuration, deserialized from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub resolvers: ResolverConfig,
    pub timeouts: TimeoutConfig,
    pub ports: PortConfig,
    pub geoip: GeoIpConfig,
    pub hosting: HostingConfig,
    pub reputation: ReputationConfig,
    pub keybindings: KeybindingConfig,
    pub theme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            resolvers: ResolverConfig::default(),
            timeouts: TimeoutConfig::default(),
            ports: PortConfig::default(),
            geoip: GeoIpConfig::default(),
            hosting: HostingConfig::default(),
            reputation: ReputationConfig::default(),
            keybindings: KeybindingConfig::default(),
            theme: "default".to_string(),
        }
    }
}

/// Resolvers used for lookups: the system resolver plus a comparison set,
/// used to detect split-horizon DNS / inconsistent answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResolverConfig {
    pub use_system: bool,
    pub comparison: Vec<IpAddr>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            use_system: true,
            comparison: vec![
                "1.1.1.1".parse().expect("valid literal"),
                "8.8.8.8".parse().expect("valid literal"),
                "9.9.9.9".parse().expect("valid literal"),
            ],
        }
    }
}

/// Per-check-type timeouts. Every network operation must use one of these;
/// there are no unbounded waits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutConfig {
    #[serde(with = "humantime_serde")]
    pub dns: Duration,
    #[serde(with = "humantime_serde")]
    pub ping: Duration,
    #[serde(with = "humantime_serde")]
    pub trace: Duration,
    #[serde(with = "humantime_serde")]
    pub port_connect: Duration,
    #[serde(with = "humantime_serde")]
    pub tls: Duration,
    #[serde(with = "humantime_serde")]
    pub http: Duration,
    #[serde(with = "humantime_serde")]
    pub rdap: Duration,
    #[serde(with = "humantime_serde")]
    pub reputation: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(3),
            ping: Duration::from_secs(2),
            trace: Duration::from_secs(10),
            port_connect: Duration::from_millis(800),
            tls: Duration::from_secs(4),
            http: Duration::from_secs(6),
            rdap: Duration::from_secs(4),
            reputation: Duration::from_secs(5),
        }
    }
}

/// The port list used by the (opt-in) Ports pane scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortConfig {
    pub scan_list: Vec<u16>,
    /// Minimum delay between connection attempts, to keep scans polite.
    #[serde(with = "humantime_serde")]
    pub rate_limit: Duration,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            scan_list: vec![
                21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443,
            ],
            rate_limit: Duration::from_millis(50),
        }
    }
}

/// MaxMind GeoLite2 access. The databases themselves aren't redistributable,
/// so rather than a local path, this holds the credentials `crate::geoip`'s
/// background updater needs to download them itself into a per-user cache
/// (see `crate::geoip::cache_dir`); `checks::geo` only ever reads whatever
/// ends up there.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoIpConfig {
    /// The numeric account ID from a MaxMind account's license-key page
    /// (not the license key itself).
    pub account_id: Option<u32>,
    /// Generated alongside the account ID. Like the reputation API keys
    /// below, only ever read from config or the settings editor, never
    /// logged.
    pub license_key: Option<String>,
    /// How often to refresh the downloaded databases. Checked
    /// opportunistically on a timer while the TUI is open, not pinned to
    /// a wall-clock schedule.
    #[serde(with = "humantime_serde")]
    pub update_interval: Duration,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            account_id: None,
            license_key: None,
            update_interval: Duration::from_secs(24 * 3600),
        }
    }
}

impl GeoIpConfig {
    /// Both credentials present and non-empty, ready to use for a
    /// download. `None` means "not configured" -- the background updater
    /// and `checks::geo`'s messaging both key off this rather than
    /// checking the two fields separately everywhere.
    pub fn credentials(&self) -> Option<(u32, String)> {
        match (self.account_id, &self.license_key) {
            (Some(id), Some(key)) if !key.trim().is_empty() => Some((id, key.clone())),
            _ => None,
        }
    }
}

/// Settings for the hosting-provider detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HostingConfig {
    /// Provider ids to skip entirely, e.g. `["oracle"]`.
    pub disabled_providers: Vec<String>,
    /// Minimum confidence to surface a detection in the pane.
    pub min_confidence: crate::providers::Confidence,
    /// Warn when cached/snapshot range data is older than this.
    #[serde(with = "humantime_serde")]
    pub max_data_age: Duration,
    /// Extra directory to load user-defined `*.toml` signatures from, e.g.
    /// for an internal company IP range.
    pub extra_signature_dir: Option<PathBuf>,
}

impl Default for HostingConfig {
    fn default() -> Self {
        Self {
            disabled_providers: Vec::new(),
            min_confidence: crate::providers::Confidence::Low,
            max_data_age: Duration::from_secs(30 * 24 * 3600),
            extra_signature_dir: None,
        }
    }
}

/// API keys for optional reputation providers (AbuseIPDB, Shodan, ...).
/// Keys never come from anywhere but config or environment variables, and
/// are never logged.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ReputationConfig {
    pub abuseipdb_key: Option<String>,
    pub shodan_key: Option<String>,
}

/// Keybinding overrides. Empty means "use the built-in defaults" for that
/// action; see the table in `CLAUDE.md` for what those are.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct KeybindingConfig {
    pub overrides: std::collections::BTreeMap<String, String>,
}

impl Config {
    /// The default config file location: `$XDG_CONFIG_HOME/netloupe/config.toml`.
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let dirs =
            directories::ProjectDirs::from("", "", "netloupe").ok_or(ConfigError::NoConfigDir)?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Loads configuration from the default path, falling back to defaults
    /// (with a warning logged, not printed) when no file exists.
    pub fn load_default() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(&path)
    }

    /// Loads and parses a config file from an explicit path.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Serializes and writes this config to `path`, creating its parent
    /// directory if needed (a first-run user won't have one yet). Used by
    /// the in-app settings editor so a field edit persists across
    /// restarts, not just for the current session.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }
        let text = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;
        std::fs::write(path, text).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Minimal `humantime` (de)serialization for `Duration` fields, e.g. "3s",
/// "800ms", "30days" in the TOML file.
mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&humantime::format_duration(*d).to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert!(c.resolvers.use_system);
        assert_eq!(c.resolvers.comparison.len(), 3);
        assert!(!c.ports.scan_list.is_empty());
        assert_eq!(c.theme, "default");
        assert_eq!(c.geoip.update_interval, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn geoip_credentials_need_both_fields_present_and_a_non_blank_key() {
        let mut c = GeoIpConfig::default();
        assert!(c.credentials().is_none());
        c.account_id = Some(12345);
        assert!(c.credentials().is_none(), "license key still missing");
        c.license_key = Some("  ".to_string());
        assert!(
            c.credentials().is_none(),
            "blank license key shouldn't count"
        );
        c.license_key = Some("abc123".to_string());
        assert_eq!(c.credentials(), Some((12345, "abc123".to_string())));
    }

    #[test]
    fn parses_minimal_toml_with_overrides() {
        let toml_str = r#"
            theme = "solarized"

            [timeouts]
            dns = "5s"

            [ports]
            scan_list = [80, 443]
        "#;
        let c: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(c.theme, "solarized");
        assert_eq!(c.timeouts.dns, Duration::from_secs(5));
        assert_eq!(c.ports.scan_list, vec![80, 443]);
        // Fields not present in the snippet keep their defaults.
        assert_eq!(c.timeouts.ping, Duration::from_secs(2));
    }

    #[test]
    fn parses_empty_toml_as_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.resolvers.comparison.len(), 3);
    }

    #[test]
    fn save_then_load_round_trips_a_modified_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");

        let c = Config {
            theme: "solarized".to_string(),
            timeouts: TimeoutConfig {
                dns: Duration::from_secs(9),
                ..Default::default()
            },
            ports: PortConfig {
                scan_list: vec![80, 443],
                ..Default::default()
            },
            ..Default::default()
        };
        c.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.theme, "solarized");
        assert_eq!(loaded.timeouts.dns, Duration::from_secs(9));
        assert_eq!(loaded.ports.scan_list, vec![80, 443]);
    }
}
