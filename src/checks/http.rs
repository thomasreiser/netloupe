//! HTTP pane: status, redirect chain, timing, security headers, and the
//! negotiated HTTP version.
//!
//! Redirects are followed manually (rather than via reqwest's built-in
//! policy) so each hop's URL and status can be shown, not just the final
//! destination.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::target::Target;

const MAX_REDIRECTS: u32 = 10;

/// Presence of the common response security headers. `true` means the
/// header was present at all; interpreting its value is left to the pane.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityHeaders {
    pub hsts: bool,
    pub csp: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub referrer_policy: bool,
}

impl SecurityHeaders {
    fn from_headers(headers: &[(String, String)]) -> Self {
        let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
        Self {
            hsts: has("strict-transport-security"),
            csp: has("content-security-policy"),
            x_frame_options: has("x-frame-options"),
            x_content_type_options: has("x-content-type-options"),
            referrer_policy: has("referrer-policy"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HttpResult {
    pub requested_url: String,
    pub final_url: Option<String>,
    pub status: Option<u16>,
    pub redirect_chain: Vec<RedirectHop>,
    /// Final response's headers, name lower-cased.
    pub headers: Vec<(String, String)>,
    pub security_headers: SecurityHeaders,
    pub http_version: Option<String>,
    pub timing: Option<Duration>,
    /// Set when an `https://` attempt failed outright and an unencrypted
    /// `http://` retry was made instead.
    pub fell_back_to_http: bool,
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Http;
    super::run_guarded(&ctx, id, &tx, async {
        let host = match &ctx.target {
            Target::Host { ascii, .. } => ascii.clone(),
            Target::Ip(ip) => ip.to_string(),
        };
        let port = ctx.port;
        let timeout = ctx.config.timeouts.http;

        let https_url = url_for(&host, port, true);
        let mut result = HttpResult {
            requested_url: https_url.clone(),
            ..Default::default()
        };

        if let Err(https_err) = run_into(&https_url, timeout, &mut result).await {
            // HTTPS didn't even connect (refused, TLS failure, ...); retry
            // once over plain HTTP so the pane still shows something for a
            // site that simply doesn't speak TLS.
            let http_url = url_for(&host, port, false);
            result
                .errors
                .push(format!("HTTPS failed ({https_err}); retrying over HTTP"));
            result.fell_back_to_http = true;
            result.requested_url = http_url.clone();
            if let Err(err) = run_into(&http_url, timeout, &mut result).await {
                result.errors.push(err);
            }
        }

        ctx.shared.set_http(result.clone()).await;
        Ok(CheckUpdate::Http(result))
    })
    .await;
}

async fn run_into(
    start_url: &str,
    timeout: Duration,
    result: &mut HttpResult,
) -> Result<(), String> {
    let client = build_client(timeout)?;
    let mut url = start_url.to_string();
    let start = Instant::now();

    for _ in 0..MAX_REDIRECTS {
        let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let http_version = format!("{:?}", response.version());
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        if response.status().is_redirection() {
            result.redirect_chain.push(RedirectHop {
                url: url.clone(),
                status,
                location: location.clone(),
            });
            match location {
                Some(loc) => {
                    url = resolve_location(&url, &loc)?;
                    continue;
                }
                None => {
                    result.status = Some(status);
                    result.final_url = Some(url);
                    result.http_version = Some(http_version);
                    result.timing = Some(start.elapsed());
                    return Ok(());
                }
            }
        }

        result.status = Some(status);
        result.final_url = Some(url);
        result.http_version = Some(http_version);
        result.timing = Some(start.elapsed());
        result.headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        result.security_headers = SecurityHeaders::from_headers(&result.headers);
        return Ok(());
    }

    Err(format!("gave up after {MAX_REDIRECTS} redirects"))
}

fn resolve_location(base: &str, location: &str) -> Result<String, String> {
    let base = reqwest::Url::parse(base).map_err(|e| e.to_string())?;
    base.join(location)
        .map(|u| u.to_string())
        .map_err(|e| e.to_string())
}

fn build_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

fn url_for(host: &str, port: Option<u16>, https: bool) -> String {
    let scheme = if https { "https" } else { "http" };
    match port {
        Some(p) => format!("{scheme}://{host}:{p}/"),
        None => format!("{scheme}://{host}/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_headers_detects_presence_case_insensitively() {
        let headers = vec![
            (
                "Strict-Transport-Security".to_string(),
                "max-age=63072000".to_string(),
            ),
            ("x-frame-options".to_string(), "DENY".to_string()),
        ];
        let sec = SecurityHeaders::from_headers(&headers);
        assert!(sec.hsts);
        assert!(sec.x_frame_options);
        assert!(!sec.csp);
    }

    #[test]
    fn resolves_relative_and_absolute_redirect_locations() {
        assert_eq!(
            resolve_location("https://example.com/a", "/b").unwrap(),
            "https://example.com/b"
        );
        assert_eq!(
            resolve_location("https://example.com/a", "https://other.example/c").unwrap(),
            "https://other.example/c"
        );
    }

    #[test]
    fn builds_urls_with_and_without_a_port() {
        assert_eq!(url_for("example.com", None, true), "https://example.com/");
        assert_eq!(
            url_for("example.com", Some(8443), true),
            "https://example.com:8443/"
        );
        assert_eq!(url_for("example.com", None, false), "http://example.com/");
    }
}
