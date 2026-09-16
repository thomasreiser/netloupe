//! Downloads fresh range lists into `$XDG_CACHE_HOME/netloupe/ranges/`
//! (the `netloupe update-data` command), using ETag/If-Modified-Since so
//! unchanged sources cost the provider only a cheap 304.
//!
//! Every source is independent: one provider's list moving or breaking
//! never stops the others from refreshing (same principle as
//! `providers::ranges::load`, which prefers whatever ends up in this
//! cache directory over the bundled snapshot).

use std::path::Path;

use super::ranges::source_filename;
use super::signatures::{self, SignatureLoadError};

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
            refresh_one(&client, cache_dir, &filename, &source.url, &mut report).await;
        }
    }

    Ok(report)
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
    let mut request = client.get(url);
    if let Ok(etag) = std::fs::read_to_string(&etag_path) {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag.trim().to_string());
    } else if let Ok(last_modified) = std::fs::read_to_string(&last_modified_path) {
        // Falls back to Last-Modified only when there's no ETag to prefer:
        // some sources (e.g. Cloudflare's plain-text IP lists) set neither,
        // in which case every run just refetches, which is fine.
        request = request.header(
            reqwest::header::IF_MODIFIED_SINCE,
            last_modified.trim().to_string(),
        );
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(err) => {
            report.failed.push((filename.to_string(), err.to_string()));
            return;
        }
    };

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        report.unchanged.push(filename.to_string());
        return;
    }
    if !response.status().is_success() {
        report
            .failed
            .push((filename.to_string(), format!("HTTP {}", response.status())));
        return;
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
    match response.bytes().await {
        Ok(body) => {
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
        Err(err) => report.failed.push((filename.to_string(), err.to_string())),
    }
}
