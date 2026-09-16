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

/// A dedicated, always-attempted plain-`http://` request to port 80 (or
/// `ctx.port` when the target specifies one), independent of whatever the
/// main HTTPS-first flow above does -- so "does this host speak HTTP at
/// all on the standard port" is answered even when HTTPS also works
/// (unlike `fell_back_to_http`, which only fires when HTTPS fails
/// outright).
#[derive(Debug, Clone)]
pub struct PlainHttpProbe {
    pub port: u16,
    pub reachable: bool,
    pub status: Option<u16>,
    /// The response's `Location` header pointed at an `https://` URL --
    /// the common "upgrade to TLS" redirect pattern.
    pub redirects_to_https: bool,
    pub error: Option<String>,
    /// Whether the server accepted an HTTP/2-over-cleartext ("h2c")
    /// connection via prior knowledge (the client just speaks the HTTP/2
    /// wire format directly, no TLS/ALPN and no Upgrade-header
    /// negotiation involved) -- a separate connection attempt from the
    /// plain-HTTP/1.1 request above, so this can be `true` even when
    /// `reachable` is `false` for HTTP/1.1's own request, or vice versa.
    pub h2c_supported: bool,
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
    pub plain_http: Option<PlainHttpProbe>,
    /// Whether an HTTP/3-only request (QUIC over UDP, TLS 1.3, no
    /// fallback) to the same host/port succeeded -- a separate connection
    /// attempt from the main flow above, which never tries HTTP/3 itself.
    pub http3_supported: bool,
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

        // The plain-HTTP-on-port-80 and HTTP/3 probes are independent of
        // whichever scheme the main flow below lands on (including the
        // fallback just below it), so they run concurrently rather than
        // being folded into that logic.
        let plain_http_probe = probe_plain_http(&host, port.unwrap_or(80), timeout);
        let http3_probe = probe_http3(&https_url, timeout);

        let main_flow = async {
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
        };

        let (_, plain_http, http3_supported) =
            tokio::join!(main_flow, plain_http_probe, http3_probe);
        result.plain_http = Some(plain_http);
        result.http3_supported = http3_supported;

        ctx.shared.set_http(result.clone()).await;
        Ok(CheckUpdate::Http(result))
    })
    .await;
}

/// Always attempts a plain (unencrypted) `http://` request to `port`,
/// regardless of whether HTTPS works -- answering "does this host speak
/// HTTP on the standard port at all" as its own question, distinct from
/// `fell_back_to_http` (which only fires when HTTPS fails outright).
async fn probe_plain_http(host: &str, port: u16, timeout: Duration) -> PlainHttpProbe {
    let url = format!("http://{host}:{port}/");
    let h2c_supported = probe_h2c(&url, timeout).await;

    let client = match build_client(timeout) {
        Ok(client) => client,
        Err(err) => {
            return PlainHttpProbe {
                port,
                reachable: false,
                status: None,
                redirects_to_https: false,
                error: Some(err),
                h2c_supported,
            }
        }
    };

    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let redirects_to_https = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|loc| loc.starts_with("https://"));
            PlainHttpProbe {
                port,
                reachable: true,
                status: Some(status),
                redirects_to_https,
                error: None,
                h2c_supported,
            }
        }
        Err(err) => PlainHttpProbe {
            port,
            reachable: false,
            status: None,
            redirects_to_https: false,
            error: Some(err.to_string()),
            h2c_supported,
        },
    }
}

/// Attempts an HTTP/2-over-cleartext connection via "prior knowledge"
/// (the client speaks the HTTP/2 wire format directly, no TLS/ALPN and no
/// Upgrade-header negotiation) -- a separate connection from the plain
/// HTTP/1.1 request `probe_plain_http` also makes, since a server that
/// doesn't understand h2c will usually just fail the connection outright
/// rather than gracefully falling back.
async fn probe_h2c(url: &str, timeout: Duration) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .http2_prior_knowledge()
        .build()
    else {
        return false;
    };
    matches!(
        client.get(url).send().await,
        Ok(response) if response.version() == reqwest::Version::HTTP_2
    )
}

/// Attempts an HTTP/3-only request (QUIC over UDP, TLS 1.3 via QUIC's own
/// handshake) to `url` -- a separate connection from the main HTTPS flow,
/// which never negotiates HTTP/3 itself. There's no fallback within a
/// single request here: if the server doesn't answer on QUIC, this simply
/// fails, which is exactly the "no" this probe is asking for.
async fn probe_http3(url: &str, timeout: Duration) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")))
        .http3_prior_knowledge()
        .build()
    else {
        return false;
    };
    // `http3_prior_knowledge()` alone only prepares the client's QUIC
    // connector; a request still needs `.version(HTTP_3)` set explicitly
    // to actually dispatch through it; the client's HTTP/2 counterpart
    // doesn't have this quirk since it also negotiates HTTP/2 normally
    // over any HTTPS request.
    let request = client.get(url).version(reqwest::Version::HTTP_3);
    matches!(
        request.send().await,
        Ok(response) if response.version() == reqwest::Version::HTTP_3
    )
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
