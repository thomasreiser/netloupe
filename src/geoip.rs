//! Background downloader for MaxMind's GeoLite2 City/ASN databases,
//! consumed by `checks::geo`.
//!
//! GeoLite2 databases aren't redistributable, so -- unlike
//! `providers::ranges`, which ships an offline snapshot -- there's
//! nothing bundled. Once a MaxMind account ID and license key are
//! configured (`config::GeoIpConfig`), `run_background_updater` fetches
//! both editions into a per-user cache directory and keeps them fresh on
//! a configurable interval; `checks::geo` only ever reads whatever ends
//! up there, never downloads anything itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::{mpsc, watch};

use crate::config::Config;

pub const CITY_EDITION: &str = "GeoLite2-City";
pub const ASN_EDITION: &str = "GeoLite2-ASN";

/// `$XDG_CACHE_HOME/netloupe/geoip/`, where downloaded `.mmdb` files live.
/// `None` only if this platform has no determinable cache directory at
/// all (the same condition `main.rs`'s provider-range cache already
/// tolerates).
pub fn cache_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "netloupe")?;
    Some(dirs.cache_dir().join("geoip"))
}

pub fn city_db_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(format!("{CITY_EDITION}.mmdb"))
}

pub fn asn_db_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(format!("{ASN_EDITION}.mmdb"))
}

/// Live status of the background downloader. Global rather than per-tab
/// (see `app::AppState::geoip`): the underlying files are shared by
/// every tab's Geo check, so there's one status, not one per host.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GeoipStatus {
    pub configured: bool,
    pub downloading: bool,
    /// When the databases now on disk were last successfully written.
    /// `None` if nothing has ever been downloaded (by this run or a
    /// previous one -- it's read from the files' mtimes, not session
    /// state).
    pub last_success: Option<SystemTime>,
    /// Set when the most recent refresh attempt failed. Cleared on the
    /// next success. Older files from a previous success, if any, stay
    /// usable underneath -- this doesn't mean "no data", just "no newer
    /// data yet".
    pub last_error: Option<String>,
}

impl GeoipStatus {
    /// A short one-line summary for the bottom-right of the status line
    /// and the Geo pane's header.
    pub fn status_text(&self) -> String {
        if self.downloading {
            return "GeoIP: updating…".to_string();
        }
        if !self.configured {
            return "GeoIP: no credentials".to_string();
        }
        match (self.last_success, self.last_error.is_some()) {
            (Some(t), false) => format!("GeoIP: {} old", humanize_age(age_of(t))),
            (Some(t), true) => format!("GeoIP: {} old (refresh failed)", humanize_age(age_of(t))),
            (None, true) => "GeoIP: download failed".to_string(),
            (None, false) => "GeoIP: pending".to_string(),
        }
    }
}

fn age_of(t: SystemTime) -> Duration {
    t.elapsed().unwrap_or_default()
}

fn humanize_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    if hours < 48 {
        return format!("{hours}h");
    }
    format!("{}d", hours / 24)
}

/// Sent from the background updater to the event loop.
pub enum GeoipEvent {
    Status(GeoipStatus),
    /// A download just finished successfully and wrote fresh files --
    /// already-open tabs' Geo checks should be rerun so they pick the
    /// new data up, rather than sitting on a stale "not downloaded yet"
    /// until the user manually presses 'r'.
    Refreshed,
}

/// Runs for the lifetime of the TUI. On every pass it checks whether the
/// cached databases are missing or older than `config.geoip.update_interval`
/// and, if so, refreshes them; then it sleeps until the next check is due
/// -- or wakes early if `config_rx` reports a config change (e.g.
/// credentials just added via the settings editor), rather than waiting
/// out however much of the old interval happened to be left.
pub async fn run_background_updater(
    mut config_rx: watch::Receiver<Arc<Config>>,
    status_tx: mpsc::UnboundedSender<GeoipEvent>,
    cache_dir: PathBuf,
) {
    let Ok(client) = build_client() else {
        return;
    };
    let mut last_error: Option<String> = None;

    loop {
        let geoip_config = config_rx.borrow().geoip.clone();
        let Some((account_id, license_key)) = geoip_config.credentials() else {
            let _ = status_tx.send(GeoipEvent::Status(GeoipStatus {
                configured: false,
                downloading: false,
                last_success: last_success(&cache_dir),
                last_error: None,
            }));
            wait_for_change_or(&mut config_rx, Duration::from_secs(300)).await;
            continue;
        };

        if is_due(&cache_dir, geoip_config.update_interval) {
            let _ = status_tx.send(GeoipEvent::Status(GeoipStatus {
                configured: true,
                downloading: true,
                last_success: last_success(&cache_dir),
                last_error: last_error.clone(),
            }));
            match download_editions(&client, account_id, &license_key, &cache_dir).await {
                Ok(()) => {
                    last_error = None;
                    let _ = status_tx.send(GeoipEvent::Refreshed);
                }
                Err(err) => last_error = Some(err),
            }
        }

        let _ = status_tx.send(GeoipEvent::Status(GeoipStatus {
            configured: true,
            downloading: false,
            last_success: last_success(&cache_dir),
            last_error: last_error.clone(),
        }));

        let sleep_for = time_until_due(&cache_dir, geoip_config.update_interval);
        wait_for_change_or(&mut config_rx, sleep_for).await;
    }
}

async fn wait_for_change_or(config_rx: &mut watch::Receiver<Arc<Config>>, dur: Duration) {
    tokio::select! {
        _ = config_rx.changed() => {}
        _ = tokio::time::sleep(dur) => {}
    }
}

fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(120))
        .build()
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// The older of the two databases' mtimes -- both are always written
/// together by `download_editions`, so this stands in for "when did we
/// last successfully refresh".
fn last_success(cache_dir: &Path) -> Option<SystemTime> {
    match (
        mtime(&city_db_path(cache_dir)),
        mtime(&asn_db_path(cache_dir)),
    ) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

fn is_due(cache_dir: &Path, interval: Duration) -> bool {
    match last_success(cache_dir) {
        None => true,
        Some(t) => t.elapsed().unwrap_or(Duration::MAX) >= interval,
    }
}

fn time_until_due(cache_dir: &Path, interval: Duration) -> Duration {
    let remaining = match last_success(cache_dir) {
        None => Duration::from_secs(1),
        Some(t) => interval.saturating_sub(t.elapsed().unwrap_or(interval)),
    };
    remaining.max(Duration::from_secs(1))
}

/// Downloads and extracts both GeoLite2 editions into `dest_dir`. Stops
/// at the first failure -- a partial pair (City refreshed, ASN not) is
/// worse than reporting the whole refresh as failed and retrying both
/// together next time.
async fn download_editions(
    client: &reqwest::Client,
    account_id: u32,
    license_key: &str,
    dest_dir: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
    for edition in [CITY_EDITION, ASN_EDITION] {
        download_one(client, account_id, license_key, edition, dest_dir).await?;
    }
    Ok(())
}

/// MaxMind's GeoIP Update download API: HTTP Basic auth (account ID as
/// username, license key as password) against a per-edition URL,
/// returning a `.tar.gz` whose one `.mmdb` member is what's wanted.
async fn download_one(
    client: &reqwest::Client,
    account_id: u32,
    license_key: &str,
    edition_id: &str,
    dest_dir: &Path,
) -> Result<(), String> {
    let url =
        format!("https://download.maxmind.com/geoip/databases/{edition_id}/download?suffix=tar.gz");
    let response = client
        .get(&url)
        .basic_auth(account_id, Some(license_key))
        .send()
        .await
        .map_err(|e| format!("{edition_id}: {e}"))?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(format!(
            "{edition_id}: MaxMind rejected the account ID/license key (401)"
        ));
    }
    if !response.status().is_success() {
        return Err(format!("{edition_id}: HTTP {}", response.status()));
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("{edition_id}: {e}"))?;
    let dest = dest_dir.join(format!("{edition_id}.mmdb"));
    tokio::task::spawn_blocking(move || extract_mmdb(&body, &dest))
        .await
        .map_err(|e| format!("{edition_id}: {e}"))??;
    Ok(())
}

/// Extracts the single `.mmdb` member out of a `tar.gz` archive body,
/// writing it to `dest` via a temp-file-then-rename so a concurrent
/// reader (a Geo check's `maxminddb::Reader::open_readfile`) never sees a
/// half-written file.
fn extract_mmdb(body: &[u8], dest: &Path) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(body);
    let mut archive = tar::Archive::new(gz);
    let entries = archive.entries().map_err(|e| e.to_string())?;
    for entry in entries {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let is_mmdb = entry
            .path()
            .ok()
            .and_then(|p| p.extension().map(|ext| ext == "mmdb"))
            .unwrap_or(false);
        if !is_mmdb {
            continue;
        }
        let tmp = dest.with_extension("mmdb.tmp");
        let mut out = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
        drop(out);
        std::fs::rename(&tmp, dest).map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("no .mmdb file found in the downloaded archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_prioritizes_downloading_then_unconfigured() {
        let mut s = GeoipStatus {
            downloading: true,
            configured: true,
            last_success: Some(SystemTime::now()),
            last_error: None,
        };
        assert_eq!(s.status_text(), "GeoIP: updating…");

        s.downloading = false;
        s.configured = false;
        assert_eq!(s.status_text(), "GeoIP: no credentials");
    }

    #[test]
    fn status_text_reports_age_and_failed_refresh() {
        let hour_ago = SystemTime::now() - Duration::from_secs(3600);
        let fresh = GeoipStatus {
            configured: true,
            downloading: false,
            last_success: Some(hour_ago),
            last_error: None,
        };
        assert_eq!(fresh.status_text(), "GeoIP: 1h old");

        let stale = GeoipStatus {
            last_error: Some("HTTP 500".to_string()),
            ..fresh
        };
        assert_eq!(stale.status_text(), "GeoIP: 1h old (refresh failed)");

        let never_succeeded = GeoipStatus {
            configured: true,
            downloading: false,
            last_success: None,
            last_error: Some("HTTP 401".to_string()),
        };
        assert_eq!(never_succeeded.status_text(), "GeoIP: download failed");
    }

    #[test]
    fn humanize_age_picks_the_coarsest_useful_unit() {
        assert_eq!(humanize_age(Duration::from_secs(30)), "30s");
        assert_eq!(humanize_age(Duration::from_secs(90)), "1m");
        assert_eq!(humanize_age(Duration::from_secs(3 * 3600)), "3h");
        assert_eq!(humanize_age(Duration::from_secs(3 * 24 * 3600)), "3d");
    }

    #[test]
    fn is_due_when_nothing_downloaded_yet() {
        let dir = tempfile::tempdir().unwrap();
        assert!(is_due(dir.path(), Duration::from_secs(3600)));
    }

    #[test]
    fn is_due_respects_a_fresh_download() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(city_db_path(dir.path()), b"x").unwrap();
        std::fs::write(asn_db_path(dir.path()), b"x").unwrap();
        assert!(!is_due(dir.path(), Duration::from_secs(3600)));
    }

    /// Builds a minimal `tar.gz` in memory (mirroring the layout MaxMind
    /// actually ships: the `.mmdb` nested inside a timestamped directory
    /// alongside unrelated files) and confirms extraction finds the right
    /// member and ignores the rest.
    #[test]
    fn extract_mmdb_finds_the_mmdb_member_inside_a_nested_directory() {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut append = |path: &str, contents: &[u8]| {
                let mut header = tar::Header::new_gnu();
                header.set_size(contents.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, contents).unwrap();
            };
            append("GeoLite2-City_20240101/COPYRIGHT.txt", b"not the db");
            append(
                "GeoLite2-City_20240101/GeoLite2-City.mmdb",
                b"fake mmdb bytes",
            );
            builder.finish().unwrap();
        }
        let mut gz_bytes = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::fast());
            std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
            encoder.finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("GeoLite2-City.mmdb");
        extract_mmdb(&gz_bytes, &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"fake mmdb bytes");
    }

    #[test]
    fn extract_mmdb_errors_when_no_mmdb_member_is_present() {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "README.txt", &b"hi!"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz_bytes = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::fast());
            std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
            encoder.finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        assert!(extract_mmdb(&gz_bytes, &dir.path().join("out.mmdb")).is_err());
    }
}
