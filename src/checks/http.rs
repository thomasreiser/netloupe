//! HTTP pane: status, redirect chain, timing, security headers, and a
//! per-version support table (HTTP/1.0, HTTP/1.1, HTTP/2 over TLS, h2c,
//! HTTP/3), each from its own dedicated, protocol-forced probe rather
//! than inferred from whichever one the main flow's ordinary negotiation
//! happened to land on.
//!
//! Redirects are followed manually (rather than via reqwest's built-in
//! policy) so each hop's URL and status can be shown, not just the final
//! destination.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
}

/// Whether each HTTP version/transport is supported, each from its own
/// dedicated, protocol-forced connection attempt (not inferred from
/// whichever one the main flow's ordinary negotiation happened to land
/// on) -- so this is a real, independent yes/no per protocol, not just
/// "here's the one the client preferred." The main flow's `http_version`
/// only ever reports one of these (whichever a normal client's ALPN
/// negotiation picks), which reads like "server doesn't support HTTP/3"
/// if that's read as the complete picture -- the two are unrelated
/// questions: QUIC/HTTP-3 support isn't discoverable via ALPN over a
/// plain TCP+TLS connection at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpVersionSupport {
    /// HTTPS, a raw `GET / HTTP/1.0` request written directly over the
    /// TLS connection (reqwest's client always writes `HTTP/1.1` on the
    /// request line, with no builder option to send an actual 1.0
    /// request, so this one is hand-rolled like `checks::tls`'s
    /// inspection connection). "Supported" here means the server
    /// answered with a valid HTTP status line at all -- a compliant
    /// server normally replies `HTTP/1.1` even to a 1.0 request (that's
    /// correct behavior per RFC 7230, not a sign of non-support), so an
    /// exact "HTTP/1.0" echo isn't what this is checking for.
    pub http1_0_tls: bool,
    /// HTTPS, client offers only `http/1.1` via ALPN.
    pub http1_tls: bool,
    /// HTTPS, client offers only `h2` via ALPN.
    pub http2_tls: bool,
    /// Plain `http://`, HTTP/2 via prior knowledge (no TLS/ALPN, no
    /// Upgrade-header negotiation) -- rare in practice.
    pub h2c: bool,
    /// QUIC (UDP) via prior knowledge, over HTTPS's host/port.
    pub http3: bool,
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
    pub versions: HttpVersionSupport,
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

        let http_url = url_for(&host, port, false);
        let https_port = port.unwrap_or(443);

        // Every version/transport probe below is independent of the main
        // flow (and of each other), so they all run concurrently rather
        // than being folded into that logic.
        let plain_http_probe = probe_plain_http(&host, port.unwrap_or(80), timeout);
        let http1_probe = probe_forced(&https_url, timeout, reqwest::Version::HTTP_11, false);
        let http2_probe = probe_forced(&https_url, timeout, reqwest::Version::HTTP_2, false);
        let h2c_probe = probe_forced(&http_url, timeout, reqwest::Version::HTTP_2, false);
        let http3_probe = probe_forced(&https_url, timeout, reqwest::Version::HTTP_3, true);
        let http1_0_probe = async {
            match super::resolve_target_ip(&ctx).await {
                Ok(ip) => probe_http1_0(ip, &host, https_port, timeout).await,
                Err(_) => false,
            }
        };

        let main_flow = async {
            if let Err(https_err) = run_into(&https_url, timeout, &mut result).await {
                // HTTPS didn't even connect (refused, TLS failure, ...); retry
                // once over plain HTTP so the pane still shows something for a
                // site that simply doesn't speak TLS.
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

        let (_, plain_http, http1_0, http1, http2, h2c, http3) = tokio::join!(
            main_flow,
            plain_http_probe,
            http1_0_probe,
            http1_probe,
            http2_probe,
            h2c_probe,
            http3_probe
        );
        result.plain_http = Some(plain_http);
        result.versions = HttpVersionSupport {
            http1_0_tls: http1_0,
            http1_tls: http1,
            http2_tls: http2,
            h2c,
            http3,
        };

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

    let client = match build_client(timeout) {
        Ok(client) => client,
        Err(err) => {
            return PlainHttpProbe {
                port,
                reachable: false,
                status: None,
                redirects_to_https: false,
                error: Some(err),
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
            }
        }
        Err(err) => PlainHttpProbe {
            port,
            reachable: false,
            status: None,
            redirects_to_https: false,
            error: Some(err.to_string()),
        },
    }
}

/// Attempts a request to `url` with the client forced onto exactly one
/// HTTP version -- no fallback to anything else, so success is a real,
/// independent "yes" for that specific version/transport rather than
/// just whichever one a normal client's negotiation happened to prefer.
/// Used for all four version probes (HTTP/1.1-only, HTTP/2-only over
/// TLS, h2c over plain `http://`, and HTTP/3 over QUIC): which one
/// depends only on `url`'s scheme and `version`.
///
/// `is_http3` exists because HTTP/3 needs an extra step past what the
/// other three versions do: `.http3_prior_knowledge()` only prepares the
/// client's QUIC connector at build time, and an individual *request*
/// still needs `.version(HTTP_3)` set explicitly or it silently falls
/// through to HTTP/1.1 with no error at all -- the other versions'
/// builder methods (`.http1_only()`, `.http2_prior_knowledge()`) don't
/// have this quirk, since they configure the connection itself rather
/// than requiring a matching per-request marker.
async fn probe_forced(
    url: &str,
    timeout: Duration,
    version: reqwest::Version,
    is_http3: bool,
) -> bool {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("netloupe/", env!("CARGO_PKG_VERSION")));
    builder = match version {
        reqwest::Version::HTTP_11 => builder.http1_only(),
        reqwest::Version::HTTP_2 => builder.http2_prior_knowledge(),
        reqwest::Version::HTTP_3 => builder.http3_prior_knowledge(),
        _ => builder,
    };
    let Ok(client) = builder.build() else {
        return false;
    };
    let mut request = client.get(url);
    if is_http3 {
        request = request.version(version);
    }
    matches!(
        request.send().await,
        Ok(response) if response.version() == version
    )
}

/// Writes a raw `GET / HTTP/1.0` request directly over a TLS connection
/// to `ip:port` and checks for a valid HTTP status line back -- see
/// `HttpVersionSupport::http1_0_tls` for why this can't go through
/// reqwest like the other probes. Reuses `checks::tls`'s "accept any
/// certificate" config: this is a protocol probe, not a trust decision,
/// exactly like that module's own inspection connection.
async fn probe_http1_0(ip: IpAddr, host: &str, port: u16, timeout: Duration) -> bool {
    let attempt = async {
        let config = crate::checks::tls::client_config();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;

        let tcp = TcpStream::connect((ip, port))
            .await
            .map_err(|e| e.to_string())?;
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| e.to_string())?;

        let request = format!(
            "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netloupe/{}\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        // Enough to see the status line ("HTTP/1.1 200 OK\r\n...") without
        // reading a whole response body we have no use for.
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
        Ok::<bool, String>(buf[..n].starts_with(b"HTTP/1."))
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .unwrap_or(Ok(false))
        .unwrap_or(false)
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
