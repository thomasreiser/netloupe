//! Downloads fresh range lists into `$XDG_CACHE_HOME/netloupe/ranges/`,
//! using ETag/If-Modified-Since so unchanged sources cost the provider
//! only a cheap 304. [`update_all`] is the one place this happens --
//! both the `netloupe update-data` command and [`run_background_updater`]
//! call it, so there's a single download/caching implementation to keep
//! correct.
//!
//! Every source is independent: one provider's list moving or breaking
//! never stops the others from refreshing (same principle as
//! `providers::ranges::load`, which prefers whatever ends up in this
//! cache directory over the bundled snapshot).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::{mpsc, watch};

use super::ranges::source_filename;
use super::signatures::{self, SignatureLoadError};
use super::ProviderDb;
use crate::config::Config;
use crate::refresh;
use crate::retry::{self, Failure};

/// `$XDG_CACHE_HOME/netloupe/ranges/`, where downloaded range-list files
/// (plus their ETag/Last-Modified sidecars and the last-update marker)
/// live. `None` only if this platform has no determinable cache directory
/// at all.
pub fn cache_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "netloupe")?;
    Some(dirs.cache_dir().join("ranges"))
}

/// A zero-byte file touched by [`update_all`] every time it completes a
/// full refresh (i.e. `only_provider` was `None`), so [`last_update`] has
/// something to read without having to enumerate every provider's cache
/// files, whose set changes as providers are added or removed.
fn marker_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(".last-update")
}

/// When `update_all` last completed a full refresh into `cache_dir`, read
/// from the marker file's mtime. `None` if it's never run (fresh cache
/// directory, or one that's only ever seen a single-provider refresh).
pub fn last_update(cache_dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(marker_path(cache_dir))
        .ok()?
        .modified()
        .ok()
}

/// When the range data currently in use was produced, and whether that's
/// the bundled snapshot rather than a downloaded refresh: the cache's
/// last full update if one has ever happened, otherwise the bundled
/// snapshot's build time as a fallback -- either way, "how old is what
/// Hosting detection is actually using right now".
fn data_as_of(cache_dir: &Path) -> (Option<SystemTime>, bool) {
    if let Some(t) = last_update(cache_dir) {
        return (Some(t), false);
    }
    let snapshot_time = super::ranges::snapshot_generated_at().map(|dt| {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(dt.timestamp().max(0) as u64)
    });
    (snapshot_time, snapshot_time.is_some())
}

#[derive(Debug, Default)]
pub struct UpdateReport {
    pub refreshed: Vec<String>,
    pub unchanged: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Refreshes every provider's configured range sources into `cache_dir`,
/// creating it if needed. `only_provider`, when set, limits this to one
/// provider id.
pub async fn update_all(
    cache_dir: &Path,
    only_provider: Option<&str>,
) -> Result<UpdateReport, SignatureLoadError> {
    let loaded = signatures::load_all(None)?;
    std::fs::create_dir_all(cache_dir).map_err(|source| SignatureLoadError::Read {
        path: cache_dir.to_path_buf(),
        source,
    })?;

    let client = reqwest::Client::builder()
        .user_agent(concat!(
            "netloupe/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/thomasreiser/netloupe)"
        ))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("a plain reqwest client with only a user agent and timeout set always builds");

    let mut report = UpdateReport::default();

    for loaded_sig in &loaded {
        if let Some(only) = only_provider {
            if loaded_sig.signature.id != only {
                continue;
            }
        }
        let Some(ranges) = &loaded_sig.ranges else {
            continue;
        };

        for (index, source) in ranges.sources.iter().enumerate() {
            let filename = source_filename(&loaded_sig.signature.id, index, source.format);
            let url = if is_azure_download_page(&source.url) {
                match resolve_azure_download_url(&client, &source.url).await {
                    Ok(url) => url,
                    Err(err) => {
                        report.failed.push((
                            filename,
                            format!("resolving the Microsoft download link: {err}"),
                        ));
                        continue;
                    }
                }
            } else {
                source.url.clone()
            };
            refresh_one(&client, cache_dir, &filename, &url, &mut report).await;
        }
    }

    if only_provider.is_none() {
        // Best-effort: a failure to write the marker just means the next
        // background check finds the cache "never updated" and retries
        // sooner than strictly necessary, which is harmless.
        let _ = std::fs::write(marker_path(cache_dir), b"");
    }

    Ok(report)
}

/// Live status of the background updater. Global rather than per-tab
/// (see `app::AppState::ranges`): the underlying cache is shared by every
/// tab's Hosting check, so there's one status, not one per host.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RangesStatus {
    pub downloading: bool,
    /// When the range data actually in use was produced, and whether
    /// that's the bundled snapshot rather than a downloaded refresh --
    /// see [`data_as_of`].
    pub data_as_of: Option<SystemTime>,
    pub from_snapshot: bool,
    /// Set when the most recent refresh attempt failed. Cleared on the
    /// next success. Whatever's already cached (or the bundled snapshot)
    /// stays in use underneath -- this doesn't mean "no data", just "no
    /// newer data yet".
    pub last_error: Option<String>,
}

impl RangesStatus {
    /// A short one-line summary for the bottom-right of the status line.
    pub fn status_text(&self) -> String {
        if self.downloading {
            return "Ranges: updating…".to_string();
        }
        match self.data_as_of {
            Some(t) => {
                let age = refresh::humanize_age(refresh::age_of(t));
                if self.from_snapshot {
                    format!("Ranges: {age} old (bundled snapshot)")
                } else if self.last_error.is_some() {
                    format!("Ranges: {age} old (refresh failed)")
                } else {
                    format!("Ranges: {age} old")
                }
            }
            None if self.last_error.is_some() => "Ranges: download failed".to_string(),
            None => "Ranges: pending".to_string(),
        }
    }
}

/// Sent from the background updater to the event loop.
pub enum RangesEvent {
    Status(RangesStatus),
    /// A refresh just finished and the range-list cache changed, so the
    /// provider database was reloaded from it -- already-open tabs'
    /// Hosting checks should re-evaluate against `db` rather than sitting
    /// on whatever they last computed until the user presses 'r'.
    Refreshed(Arc<ProviderDb>),
}

/// Runs for the lifetime of the TUI. On every pass it checks whether the
/// range-list cache is missing or older than
/// `config.hosting.range_update_interval` and, if so, refreshes it via
/// [`update_all`] (the same download path `netloupe update-data` uses)
/// and reloads the provider database from the refreshed cache; then it
/// sleeps until the next check is due -- or wakes early if `config_rx`
/// reports a config change (e.g. the interval was just edited in the
/// settings editor), rather than waiting out however much of the old
/// interval happened to be left.
pub async fn run_background_updater(
    mut config_rx: watch::Receiver<Arc<Config>>,
    event_tx: mpsc::UnboundedSender<RangesEvent>,
    cache_dir: PathBuf,
) {
    let mut last_error: Option<String> = None;

    loop {
        let hosting_config = config_rx.borrow().hosting.clone();

        if refresh::is_due(
            last_update(&cache_dir),
            hosting_config.range_update_interval,
        ) {
            let _ = event_tx.send(RangesEvent::Status(status(
                &cache_dir,
                true,
                last_error.clone(),
            )));
            match update_all(&cache_dir, None).await {
                Ok(report) => {
                    if !report.failed.is_empty() {
                        tracing::warn!(
                            failed = report.failed.len(),
                            refreshed = report.refreshed.len(),
                            unchanged = report.unchanged.len(),
                            "provider range update: some sources failed"
                        );
                    }
                    last_error = None;
                    if let Some(db) =
                        reload_provider_db(hosting_config.extra_signature_dir.clone(), &cache_dir)
                            .await
                    {
                        let _ = event_tx.send(RangesEvent::Refreshed(Arc::new(db)));
                    }
                }
                Err(err) => {
                    tracing::warn!(%err, "provider range update failed");
                    last_error = Some(err.to_string());
                }
            }
        }

        let _ = event_tx.send(RangesEvent::Status(status(
            &cache_dir,
            false,
            last_error.clone(),
        )));

        let sleep_for = refresh::time_until_due(
            last_update(&cache_dir),
            hosting_config.range_update_interval,
        );
        refresh::wait_for_change_or(&mut config_rx, sleep_for).await;
    }
}

fn status(cache_dir: &Path, downloading: bool, last_error: Option<String>) -> RangesStatus {
    let (data_as_of, from_snapshot) = data_as_of(cache_dir);
    RangesStatus {
        downloading,
        data_as_of,
        from_snapshot,
        last_error,
    }
}

/// Rebuilds the provider database from the (just-refreshed) cache
/// directory. Runs on a blocking-task thread since `ProviderDb::load`
/// does blocking file I/O; logs and returns `None` on failure rather than
/// tearing down the updater loop over e.g. one broken user-defined
/// signature.
async fn reload_provider_db(
    extra_signature_dir: Option<PathBuf>,
    cache_dir: &Path,
) -> Option<ProviderDb> {
    let cache_dir = cache_dir.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        ProviderDb::load(extra_signature_dir.as_deref(), Some(&cache_dir))
    })
    .await;

    match result {
        Ok(Ok((db, report))) => {
            for err in &report.errors {
                tracing::warn!(
                    provider = %err.provider_id,
                    url = %err.url,
                    "range source failed to parse: {}",
                    err.message
                );
            }
            Some(db)
        }
        Ok(Err(err)) => {
            tracing::warn!(%err, "failed to reload provider signatures after a range update");
            None
        }
        Err(err) => {
            tracing::warn!(%err, "provider database reload task panicked");
            None
        }
    }
}

/// One cached range-list file, resolved back to the provider and source
/// URL it came from, for display in the data-info popup -- not used by
/// any load/download path.
#[derive(Debug, Clone)]
pub struct CachedRangeFile {
    pub provider_id: String,
    pub provider_name: String,
    pub source_url: String,
    pub file: refresh::CachedFile,
}

/// Every range-list file actually present in `cache_dir`, resolved back
/// to the provider/source it came from. Loads signatures (including
/// `extra_signature_dir`) to do that resolution, so -- like
/// `ProviderDb::load` -- this does blocking file I/O; call it from a
/// background task, not the UI event loop. An empty result (rather than
/// an error) if signatures fail to load, since this is display-only.
pub fn list_cached_files(
    extra_signature_dir: Option<&Path>,
    cache_dir: &Path,
) -> Vec<CachedRangeFile> {
    let Ok(loaded) = signatures::load_all(extra_signature_dir) else {
        return Vec::new();
    };

    let mut files = Vec::new();
    for loaded_sig in &loaded {
        let Some(ranges) = &loaded_sig.ranges else {
            continue;
        };
        for (index, source) in ranges.sources.iter().enumerate() {
            let filename = source_filename(&loaded_sig.signature.id, index, source.format);
            let Ok(metadata) = std::fs::metadata(cache_dir.join(&filename)) else {
                continue;
            };
            files.push(CachedRangeFile {
                provider_id: loaded_sig.signature.id.clone(),
                provider_name: loaded_sig.signature.name.clone(),
                source_url: source.url.clone(),
                file: refresh::CachedFile {
                    filename,
                    size_bytes: metadata.len(),
                    modified: metadata.modified().ok(),
                },
            });
        }
    }
    files.sort_by(|a, b| {
        a.provider_id
            .cmp(&b.provider_id)
            .then_with(|| a.file.filename.cmp(&b.file.filename))
    });
    files
}

/// Whether `url` is a Microsoft Download Center page rather than a
/// direct file link -- true only for Azure's "IP Ranges and Service
/// Tags" source, the one entry in `data/providers/*.toml` configured
/// this way (see its doc comment and `resolve_azure_download_url`).
fn is_azure_download_page(url: &str) -> bool {
    url.contains("microsoft.com") && url.contains("/download/details.aspx")
}

/// Resolves the Microsoft Download Center confirmation page at `page_url`
/// to today's actual `.json` download link. Azure's "IP Ranges and
/// Service Tags" list is published under a dated filename that changes
/// every week (e.g. `ServiceTags_Public_20240415.json`), so the signature
/// file can only point at the stable landing page, not the file itself --
/// fetching that page directly as JSON is what previously produced
/// "invalid JSON: expected value at line 1 column 1". This fetches the
/// page's HTML and pulls the real link out of it before `refresh_one`'s
/// normal ETag/If-Modified-Since fetch runs against that resolved URL.
async fn resolve_azure_download_url(
    client: &reqwest::Client,
    page_url: &str,
) -> Result<String, String> {
    retry::run(&retry::Policy::default(), || async {
        let response = client
            .get(page_url)
            .send()
            .await
            .map_err(retry::classify_send_error)?;
        if !response.status().is_success() {
            return Err(retry::classify_status(response.status()));
        }
        let html = response
            .text()
            .await
            .map_err(|e| Failure::Retryable(e.to_string()))?;
        extract_azure_json_link(&html).ok_or_else(|| {
            Failure::Fatal(
                "could not find a .json download link on the Microsoft download page".to_string(),
            )
        })
    })
    .await
}

/// Pulls the actual `.json` download link out of the Download Center
/// page's HTML -- kept separate from the network fetch above so it's
/// unit-testable without a live request.
fn extract_azure_json_link(html: &str) -> Option<String> {
    let pattern = r#"https://download\.microsoft\.com/download/[^"'\s]+?\.json"#;
    let re =
        regex::Regex::new(pattern).expect("a fixed, valid regex literal never fails to compile");
    re.find(html).map(|m| m.as_str().to_string())
}

/// What one fetch attempt found, short of an outright failure: either the
/// source hasn't changed (a 304, itself a successful outcome, not
/// something to retry) or a fresh body to write.
enum FetchOutcome {
    Unchanged,
    Fetched {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

async fn refresh_one(
    client: &reqwest::Client,
    cache_dir: &Path,
    filename: &str,
    url: &str,
    report: &mut UpdateReport,
) {
    let etag_path = cache_dir.join(format!("{filename}.etag"));
    let last_modified_path = cache_dir.join(format!("{filename}.last-modified"));
    let cached_etag = std::fs::read_to_string(&etag_path).ok();
    let cached_last_modified = std::fs::read_to_string(&last_modified_path).ok();

    // Retried (see `crate::retry`): these are netloupe's own requests to
    // each provider's range-list host, not a measurement of anything --
    // worth riding out a blip rather than reporting a source as failed.
    let outcome = retry::run(&retry::Policy::default(), || async {
        let mut request = client.get(url);
        if let Some(etag) = &cached_etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag.trim().to_string());
        } else if let Some(last_modified) = &cached_last_modified {
            // Falls back to Last-Modified only when there's no ETag to
            // prefer: some sources (e.g. Cloudflare's plain-text IP
            // lists) set neither, in which case every run just
            // refetches, which is fine.
            request = request.header(
                reqwest::header::IF_MODIFIED_SINCE,
                last_modified.trim().to_string(),
            );
        }

        let response = request.send().await.map_err(retry::classify_send_error)?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(FetchOutcome::Unchanged);
        }
        if !response.status().is_success() {
            return Err(retry::classify_status(response.status()));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = response
            .bytes()
            .await
            .map_err(|e| Failure::Retryable(e.to_string()))?
            .to_vec();
        Ok(FetchOutcome::Fetched {
            body,
            etag,
            last_modified,
        })
    })
    .await;

    match outcome {
        Ok(FetchOutcome::Unchanged) => report.unchanged.push(filename.to_string()),
        Ok(FetchOutcome::Fetched {
            body,
            etag,
            last_modified,
        }) => {
            if let Err(err) = std::fs::write(cache_dir.join(filename), &body) {
                report.failed.push((filename.to_string(), err.to_string()));
                return;
            }
            if let Some(etag) = etag {
                let _ = std::fs::write(&etag_path, etag);
            }
            if let Some(last_modified) = last_modified {
                let _ = std::fs::write(&last_modified_path, last_modified);
            }
            report.refreshed.push(filename.to_string());
        }
        Err(err) => report.failed.push((filename.to_string(), err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_update_is_none_when_the_marker_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(last_update(dir.path()).is_none());
    }

    #[test]
    fn last_update_reads_the_markers_mtime() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(marker_path(dir.path()), b"").unwrap();
        assert!(last_update(dir.path()).is_some());
    }

    #[test]
    fn data_as_of_falls_back_to_the_bundled_snapshot_when_never_updated() {
        let dir = tempfile::tempdir().unwrap();
        let (as_of, from_snapshot) = data_as_of(dir.path());
        assert!(as_of.is_some());
        assert!(from_snapshot);
    }

    #[test]
    fn data_as_of_prefers_the_caches_own_last_update_once_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(marker_path(dir.path()), b"").unwrap();
        let (as_of, from_snapshot) = data_as_of(dir.path());
        assert!(as_of.is_some());
        assert!(!from_snapshot);
    }

    #[test]
    fn status_text_reports_snapshot_vs_refreshed_data() {
        let refreshed = RangesStatus {
            downloading: false,
            data_as_of: Some(SystemTime::now() - std::time::Duration::from_secs(3600)),
            from_snapshot: false,
            last_error: None,
        };
        assert_eq!(refreshed.status_text(), "Ranges: 1h old");

        let snapshot = RangesStatus {
            from_snapshot: true,
            ..refreshed.clone()
        };
        assert_eq!(snapshot.status_text(), "Ranges: 1h old (bundled snapshot)");

        let never = RangesStatus {
            downloading: false,
            data_as_of: None,
            from_snapshot: false,
            last_error: None,
        };
        assert_eq!(never.status_text(), "Ranges: pending");
    }

    /// Mirrors `ranges::tests::load_prefers_cache_dir_over_snapshot`: a
    /// cached `cloudflare-0.txt` should resolve back to Cloudflare's own
    /// first range source (`ips-v4`) using the real embedded signatures,
    /// with no network access.
    #[test]
    fn list_cached_files_resolves_a_cached_file_back_to_its_provider_and_url() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cloudflare-0.txt"), "192.0.2.0/24\n").unwrap();

        let files = list_cached_files(None, dir.path());
        let cloudflare = files
            .iter()
            .find(|f| f.provider_id == "cloudflare")
            .expect("cloudflare-0.txt should resolve to the cloudflare provider");
        assert_eq!(cloudflare.source_url, "https://www.cloudflare.com/ips-v4");
        assert_eq!(cloudflare.file.filename, "cloudflare-0.txt");
        assert_eq!(cloudflare.file.size_bytes, 13);
    }

    #[test]
    fn list_cached_files_is_empty_for_an_empty_cache_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list_cached_files(None, dir.path()).is_empty());
    }

    #[test]
    fn is_azure_download_page_matches_only_the_configured_download_center_url() {
        assert!(is_azure_download_page(
            "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
        ));
        assert!(!is_azure_download_page(
            "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20240415.json"
        ));
        assert!(!is_azure_download_page("https://www.cloudflare.com/ips-v4"));
    }

    #[test]
    fn extract_azure_json_link_finds_the_real_download_url_in_the_page_html() {
        let html = r#"
            <html><body>
            <p>Some other link: <a href="https://www.microsoft.com/other">here</a></p>
            <a id="downloadLink" href="https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20240415.json" data-bi-id="downloadretry">Download</a>
            </body></html>
        "#;
        assert_eq!(
            extract_azure_json_link(html).as_deref(),
            Some("https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20240415.json")
        );
    }

    #[test]
    fn extract_azure_json_link_is_none_when_the_page_has_no_matching_link() {
        assert!(extract_azure_json_link("<html><body>no links here</body></html>").is_none());
    }
}
