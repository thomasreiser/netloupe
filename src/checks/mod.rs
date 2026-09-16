//! Checks: one independent async task per pane's data source.
//!
//! A check never touches UI types. It receives a [`CheckContext`] and a
//! sender, does its network work under the context's cancellation token and
//! the config's timeouts, and reports progress/results as [`CheckEvent`]s.
//! A failed check reports its own error and never panics the task; a
//! panicking check would otherwise silently stop updating its pane, so
//! every `run` body should prefer returning an error to unwrapping.

pub mod acme;
pub mod dns;
pub mod geo;
pub mod hosting;
pub mod http;
pub mod ipinfo;
pub mod mail;
pub mod ping;
pub mod ports;
pub mod reputation;
pub mod tls;
pub mod trace;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Notify, RwLock};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::event::{CheckEvent, CheckPayload};
use crate::providers::ProviderDb;
use crate::target::Target;

/// Identifies which pane/check a [`CheckEvent`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CheckId {
    Dns,
    Mail,
    Ping,
    Trace,
    Ports,
    Tls,
    Http,
    IpInfo,
    Hosting,
    Geo,
    Reputation,
}

impl CheckId {
    /// Every check, in the pane display order from `CLAUDE.md`.
    pub const ALL: [CheckId; 11] = [
        CheckId::Dns,
        CheckId::Mail,
        CheckId::Ping,
        CheckId::Trace,
        CheckId::Ports,
        CheckId::Tls,
        CheckId::Http,
        CheckId::IpInfo,
        CheckId::Hosting,
        CheckId::Geo,
        CheckId::Reputation,
    ];

    pub fn label(self) -> &'static str {
        match self {
            CheckId::Dns => "DNS",
            CheckId::Mail => "Mail",
            CheckId::Ping => "Ping/Trace",
            CheckId::Trace => "Ping/Trace",
            CheckId::Ports => "Ports",
            CheckId::Tls => "TLS",
            CheckId::Http => "HTTP",
            CheckId::IpInfo => "IP/ASN",
            CheckId::Hosting => "Hosting",
            CheckId::Geo => "Geo",
            CheckId::Reputation => "Rep",
        }
    }

    /// True for checks that are opt-in and must not run automatically when
    /// a tab is opened (see `CLAUDE.md`'s Safety and ethics section).
    pub fn requires_opt_in(self) -> bool {
        matches!(self, CheckId::Ports)
    }
}

/// Results other checks have produced for this tab, shared so `hosting`
/// (and eventually others) can reuse them instead of re-querying the
/// network. See architecture rule 8 in `CLAUDE.md`.
#[derive(Debug, Clone, Default)]
pub struct SharedResults {
    pub dns: Option<dns::DnsResult>,
    pub ipinfo: Option<ipinfo::IpInfoResult>,
    pub tls: Option<tls::TlsResult>,
    pub http: Option<http::HttpResult>,
    pub mail: Option<mail::MailResult>,
}

/// A handle to the per-tab [`SharedResults`], plus a way to wait for the
/// next update. Cheap to clone; every check gets one.
#[derive(Clone)]
pub struct SharedResultsHandle {
    inner: Arc<RwLock<SharedResults>>,
    changed: Arc<Notify>,
}

impl SharedResultsHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SharedResults::default())),
            changed: Arc::new(Notify::new()),
        }
    }

    pub async fn snapshot(&self) -> SharedResults {
        self.inner.read().await.clone()
    }

    async fn update(&self, f: impl FnOnce(&mut SharedResults)) {
        {
            let mut guard = self.inner.write().await;
            f(&mut guard);
        }
        self.changed.notify_waiters();
    }

    pub async fn set_dns(&self, r: dns::DnsResult) {
        self.update(|s| s.dns = Some(r)).await;
    }

    pub async fn set_ipinfo(&self, r: ipinfo::IpInfoResult) {
        self.update(|s| s.ipinfo = Some(r)).await;
    }

    pub async fn set_tls(&self, r: tls::TlsResult) {
        self.update(|s| s.tls = Some(r)).await;
    }

    pub async fn set_http(&self, r: http::HttpResult) {
        self.update(|s| s.http = Some(r)).await;
    }

    pub async fn set_mail(&self, r: mail::MailResult) {
        self.update(|s| s.mail = Some(r)).await;
    }

    /// Waits until any `set_*` call happens. `hosting` loops on this to
    /// re-evaluate every time a new input arrives.
    pub async fn wait_for_change(&self) {
        self.changed.notified().await;
    }
}

impl Default for SharedResultsHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything a check needs to run, independent of the UI.
#[derive(Clone)]
pub struct CheckContext {
    pub tab_id: u64,
    pub target: Target,
    pub port: Option<u16>,
    pub config: Arc<Config>,
    pub cancel: CancellationToken,
    pub shared: SharedResultsHandle,
    pub providers: Arc<ProviderDb>,
}

/// One check implementation. Kept as a trait (rather than a bare async fn)
/// so `registry()` can hand the event loop a uniform list to spawn,
/// regardless of what each check internally awaits on.
#[async_trait]
pub trait Check: Send + Sync {
    fn id(&self) -> CheckId;

    /// Runs the check to completion (or until `ctx.cancel` fires),
    /// reporting progress through `tx`. Must not panic: on any internal
    /// error, send `CheckPayload::Failed` and return.
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>);
}

/// The IP address a check should operate on: the target itself when it's
/// already an IP, or its A/AAAA-resolved address otherwise. Prefers a
/// cached DNS result already in `ctx.shared` over a fresh lookup, so
/// checks that run after `dns` don't repeat its work.
pub(crate) async fn resolve_target_ip(ctx: &CheckContext) -> Result<std::net::IpAddr, String> {
    use std::net::IpAddr;
    match &ctx.target {
        Target::Ip(ip) => Ok(*ip),
        Target::Host { ascii, .. } => {
            if let Some(dns) = &ctx.shared.snapshot().await.dns {
                if let Some(&ip) = dns.a.first() {
                    return Ok(IpAddr::V4(ip));
                }
                if let Some(&ip) = dns.aaaa.first() {
                    return Ok(IpAddr::V6(ip));
                }
            }
            let addrs = dns::resolve_addrs(ascii, ctx.config.timeouts.dns).await?;
            // Prefer IPv4, matching the shared-cache branch above, so which
            // check happens to run first doesn't change which address
            // family the rest of the tab ends up probing.
            addrs
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| addrs.first())
                .copied()
                .ok_or_else(|| format!("{ascii} has no A/AAAA records"))
        }
    }
}

/// Sends a `Started` event, then whatever `payload` `body` resolves to,
/// respecting cancellation. Every check's `run` should go through this so
/// cancellation and the started/done bookkeeping only need writing once.
pub(crate) async fn run_guarded<F>(
    ctx: &CheckContext,
    id: CheckId,
    tx: &mpsc::Sender<CheckEvent>,
    body: F,
) where
    F: std::future::Future<Output = Result<crate::event::CheckUpdate, String>>,
{
    let _ = tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload: CheckPayload::Started,
        })
        .await;

    let payload = tokio::select! {
        _ = ctx.cancel.cancelled() => CheckPayload::Cancelled,
        result = body => match result {
            Ok(update) => CheckPayload::Done(update),
            Err(message) => CheckPayload::Failed(message),
        },
    };

    let _ = tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload,
        })
        .await;
}

struct DnsCheck;
struct MailCheck;
struct PingCheck;
struct TraceCheck;
struct PortsCheck;
struct TlsCheck;
struct HttpCheck;
struct IpInfoCheck;
struct HostingCheck;
struct GeoCheck;
struct ReputationCheck;

#[async_trait]
impl Check for DnsCheck {
    fn id(&self) -> CheckId {
        CheckId::Dns
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        dns::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for MailCheck {
    fn id(&self) -> CheckId {
        CheckId::Mail
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        mail::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for PingCheck {
    fn id(&self) -> CheckId {
        CheckId::Ping
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        ping::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for TraceCheck {
    fn id(&self) -> CheckId {
        CheckId::Trace
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        trace::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for PortsCheck {
    fn id(&self) -> CheckId {
        CheckId::Ports
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        ports::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for TlsCheck {
    fn id(&self) -> CheckId {
        CheckId::Tls
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        tls::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for HttpCheck {
    fn id(&self) -> CheckId {
        CheckId::Http
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        http::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for IpInfoCheck {
    fn id(&self) -> CheckId {
        CheckId::IpInfo
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        ipinfo::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for HostingCheck {
    fn id(&self) -> CheckId {
        CheckId::Hosting
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        hosting::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for GeoCheck {
    fn id(&self) -> CheckId {
        CheckId::Geo
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        geo::run(ctx, tx).await
    }
}

#[async_trait]
impl Check for ReputationCheck {
    fn id(&self) -> CheckId {
        CheckId::Reputation
    }
    async fn run(&self, ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
        reputation::run(ctx, tx).await
    }
}

/// Every check netloupe knows about. `app.rs` spawns one from this list per
/// tab for every check that isn't [`CheckId::requires_opt_in`]; opt-in
/// checks are spawned only after the user confirms.
pub fn registry() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(DnsCheck),
        Box::new(MailCheck),
        Box::new(PingCheck),
        Box::new(TraceCheck),
        Box::new(PortsCheck),
        Box::new(TlsCheck),
        Box::new(HttpCheck),
        Box::new(IpInfoCheck),
        Box::new(HostingCheck),
        Box::new(GeoCheck),
        Box::new(ReputationCheck),
    ]
}
