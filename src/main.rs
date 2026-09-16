//! CLI entry point: `netloupe [hosts...]` opens the TUI, `check` runs
//! headlessly, `update-data` refreshes the provider range-list cache.
//! Terminal setup/teardown lives here so `app.rs` never has to know about
//! crossterm/panic-safety at all.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use netloupe::app::{self, CheckSlot, CheckStatus};
use netloupe::checks::{self, CheckContext, CheckId, SharedResultsHandle};
use netloupe::config::Config;
use netloupe::event::{CheckEvent, CheckPayload, CheckUpdate};
use netloupe::providers::ProviderDb;
use netloupe::target::Target;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "netloupe",
    version,
    about = "A terminal UI for inspecting hosts."
)]
struct Cli {
    /// Hosts to open tabs for immediately, e.g. `netloupe example.com 8.8.8.8`.
    hosts: Vec<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Runs every check against one target without the TUI.
    Check {
        target: String,
        /// Print structured JSON instead of a plain-text summary.
        #[arg(long)]
        json: bool,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Refreshes the cached provider range lists used for hosting detection.
    UpdateData {
        /// Only refresh this provider's sources (its id in `data/providers/`).
        #[arg(long)]
        provider: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Command::UpdateData { provider }) => run_update_data(provider).await,
        Some(Command::Check { target, json, port }) => run_check(target, port, json).await,
        None => run_tui(cli.hosts).await,
    }
}

fn cache_dir() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "netloupe").ok_or_else(|| {
        anyhow::anyhow!("could not determine a cache directory for this platform")
    })?;
    Ok(dirs.cache_dir().join("ranges"))
}

async fn run_update_data(provider: Option<String>) -> anyhow::Result<()> {
    let dir = cache_dir()?;
    println!("refreshing provider range lists into {}", dir.display());
    let report = netloupe::providers::update::update_all(&dir, provider.as_deref()).await?;

    for f in &report.refreshed {
        println!("  refreshed  {f}");
    }
    for f in &report.unchanged {
        println!("  unchanged  {f}");
    }
    for (f, err) in &report.failed {
        println!("  FAILED     {f}: {err}");
    }
    println!(
        "\n{} refreshed, {} unchanged, {} failed",
        report.refreshed.len(),
        report.unchanged.len(),
        report.failed.len()
    );
    if !report.failed.is_empty() {
        println!("(a failed source keeps whatever it last had cached or the bundled snapshot; the others are unaffected)");
    }
    Ok(())
}

fn load_config_and_providers() -> anyhow::Result<(Config, ProviderDb)> {
    let config = Config::load_default().unwrap_or_else(|err| {
        eprintln!("warning: using default config ({err})");
        Config::default()
    });
    let cache = cache_dir().ok();
    let (providers, report) = ProviderDb::load(
        config.hosting.extra_signature_dir.as_deref(),
        cache.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if !report.errors.is_empty() {
        for err in &report.errors {
            eprintln!(
                "warning: {} ({}): {}",
                err.provider_id, err.url, err.message
            );
        }
    }
    Ok((config, providers))
}

async fn run_check(target: String, port: Option<u16>, json: bool) -> anyhow::Result<()> {
    let (config, providers) = load_config_and_providers()?;
    let target = Target::parse(&target).map_err(|e| anyhow::anyhow!(e))?;
    let slots = run_headless(target.clone(), port, config, providers).await;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&build_json(&target, &slots))?
        );
    } else {
        print_summary(&target, &slots);
    }
    Ok(())
}

/// Runs every non-opt-in check to completion (or a deadline), returning
/// each check's final slot. Shared by both `check --json` and the plain
/// summary output.
async fn run_headless(
    target: Target,
    port: Option<u16>,
    config: Config,
    providers: ProviderDb,
) -> BTreeMap<CheckId, CheckSlot> {
    let config = Arc::new(config);
    let providers = Arc::new(providers);
    let cancel = CancellationToken::new();
    let shared = SharedResultsHandle::new();
    let (tx, mut rx) = mpsc::channel::<CheckEvent>(256);

    // Trace isn't implemented and Ports is opt-in (never runs headlessly
    // without an explicit --yes-i-am-authorized flag, which doesn't exist
    // yet); Hosting is handled separately below since it never "finishes".
    let mut pending: BTreeSet<CheckId> = checks::registry()
        .iter()
        .map(|c| c.id())
        .filter(|id| !id.requires_opt_in() && *id != CheckId::Trace && *id != CheckId::Hosting)
        .collect();

    for check in checks::registry() {
        if check.id().requires_opt_in() || check.id() == CheckId::Trace {
            continue;
        }
        let ctx = CheckContext {
            tab_id: 0,
            target: target.clone(),
            port,
            config: config.clone(),
            cancel: cancel.clone(),
            shared: shared.clone(),
            providers: providers.clone(),
        };
        let tx = tx.clone();
        tokio::spawn(async move { check.run(ctx, tx).await });
    }
    drop(tx);

    let mut slots: BTreeMap<CheckId, CheckSlot> = BTreeMap::new();
    let deadline = tokio::time::sleep(Duration::from_secs(25));
    tokio::pin!(deadline);

    loop {
        if pending.is_empty() {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            event = rx.recv() => {
                match event {
                    None => break,
                    Some(event) => apply(&mut slots, &mut pending, event),
                }
            }
        }
    }

    // Hosting re-evaluates every time another check's result lands, so its
    // most useful state is whatever it produces right after everything
    // else above just finished. Give it one short grace window rather than
    // racing it.
    if let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        let mut ignored = BTreeSet::new();
        apply(&mut slots, &mut ignored, event);
    }

    cancel.cancel();
    slots
}

fn apply(
    slots: &mut BTreeMap<CheckId, CheckSlot>,
    pending: &mut BTreeSet<CheckId>,
    event: CheckEvent,
) {
    let slot = slots.entry(event.check).or_default();
    match event.payload {
        CheckPayload::Started => slot.status = CheckStatus::Running,
        CheckPayload::Progress(update) => {
            slot.status = CheckStatus::Running;
            slot.update = Some(update);
        }
        CheckPayload::Done(update) => {
            slot.status = CheckStatus::Done;
            slot.update = Some(update);
            pending.remove(&event.check);
        }
        CheckPayload::Failed(message) => {
            slot.status = CheckStatus::Failed(message);
            pending.remove(&event.check);
        }
        CheckPayload::Cancelled => {
            slot.status = CheckStatus::Cancelled;
            pending.remove(&event.check);
        }
    }
}

fn build_json(target: &Target, slots: &BTreeMap<CheckId, CheckSlot>) -> serde_json::Value {
    use serde_json::json;

    let mut checks_json = serde_json::Map::new();
    for (id, slot) in slots {
        checks_json.insert(
            format!("{id:?}").to_lowercase(),
            check_json(&slot.status, slot.update.as_ref()),
        );
    }
    json!({ "target": target.display(), "checks": checks_json })
}

fn check_json(status: &CheckStatus, update: Option<&CheckUpdate>) -> serde_json::Value {
    use serde_json::json;

    let status_str = match status {
        CheckStatus::NotStarted => "not_started",
        CheckStatus::Running => "running",
        CheckStatus::Done => "done",
        CheckStatus::Failed(_) => "failed",
        CheckStatus::Cancelled => "cancelled",
    };
    let error = if let CheckStatus::Failed(message) = status {
        Some(message.clone())
    } else {
        None
    };

    let data = update.map(update_json);
    json!({ "status": status_str, "error": error, "data": data })
}

fn acme_json(acme: &netloupe::checks::acme::AcmeInfo) -> serde_json::Value {
    use netloupe::checks::acme::ChallengeHint;
    use serde_json::json;

    let hint = match acme.challenge_hint {
        ChallengeHint::Dns01Certain => "dns01_certain",
        ChallengeHint::EitherMethodPossible => "either_method_possible",
        ChallengeHint::NotPublicAcme => "not_public_acme",
    };
    json!({
        "authority": acme.authority.name(),
        "is_wildcard": acme.is_wildcard,
        "challenge_hint": hint,
        "note": acme.note,
        "dns01": acme.dns01.as_ref().map(|d| json!({
            "txt_values": d.txt_values,
            "cname_target": d.cname_target,
        })),
        "http01": acme.http01.as_ref().map(|h| json!({
            "status": h.status,
            "body_sample": h.body_sample,
            "error": h.error,
        })),
    })
}

fn update_json(update: &CheckUpdate) -> serde_json::Value {
    use serde_json::json;

    match update {
        CheckUpdate::Dns(d) => json!({
            "a": d.a.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "aaaa": d.aaaa.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "cnames": d.cnames,
            "mx": d.mx.iter().map(|m| format!("{} {}", m.preference, m.exchange)).collect::<Vec<_>>(),
            "ns": d.ns,
            "txt": d.txt,
            "caa": d.caa,
            "srv": d.srv,
            "ptr": d.ptr,
            "authenticated_data": d.authenticated_data,
            "errors": d.errors,
        }),
        CheckUpdate::Ping(p) => json!({
            "method": format!("{:?}", p.method),
            "sent": p.sent,
            "received": p.received,
            "min_ms": p.min.map(|d| d.as_millis() as u64),
            "avg_ms": p.avg.map(|d| d.as_millis() as u64),
            "max_ms": p.max.map(|d| d.as_millis() as u64),
            "fallback_reason": p.fallback_reason,
        }),
        CheckUpdate::IpInfo(i) => json!({
            "ip": i.ip.to_string(),
            "class": i.class.label(),
            "asn": i.asn.as_ref().map(|a| json!({
                "asn": a.asn, "prefix": a.prefix, "country": a.country, "registry": a.registry, "as_name": a.as_name,
            })),
            "rdap": i.rdap.as_ref().map(|r| json!({
                "handle": r.handle, "name": r.name, "country": r.country, "abuse_email": r.abuse_email,
            })),
            "errors": i.errors,
        }),
        CheckUpdate::Hosting(detections) => json!(detections
            .iter()
            .map(|d| json!({
                "provider_id": d.provider_id,
                "provider_name": d.provider_name,
                "layer": format!("{}", d.layer),
                "confidence": format!("{}", d.confidence),
                "score": d.score,
                "evidence": d.evidence.iter().map(|e| json!({"description": e.description, "weight": e.weight})).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>()),
        CheckUpdate::Mail(m) => json!({
            "spf": m.spf.as_ref().map(|s| json!({"record": s.record, "lookup_count": s.lookup_count, "exceeds_limit": s.exceeds_limit})),
            "dmarc": m.dmarc.as_ref().map(|d| json!({"record": d.record, "policy": d.policy, "pct": d.pct})),
            "dkim_selectors_found": m.dkim_selectors_found,
            "mta_sts": m.mta_sts_record,
            "tls_rpt": m.tls_rpt_record,
            "bimi": m.bimi_record,
            "errors": m.errors,
        }),
        CheckUpdate::Tls(t) => json!({
            "host": t.host, "port": t.port,
            "protocol_version": t.protocol_version, "cipher_suite": t.cipher_suite,
            "issuer": t.issuer, "subject": t.subject, "sans": t.sans,
            "days_until_expiry": t.days_until_expiry,
            "acme": t.acme.as_ref().map(acme_json),
            "errors": t.errors,
        }),
        CheckUpdate::Http(h) => json!({
            "requested_url": h.requested_url, "final_url": h.final_url, "status": h.status,
            "redirect_count": h.redirect_chain.len(),
            "http_version": h.http_version,
            "timing_ms": h.timing.map(|d| d.as_millis() as u64),
            "errors": h.errors,
        }),
        CheckUpdate::Geo(g) => json!({
            "country": g.country, "region": g.region, "city": g.city, "timezone": g.timezone, "errors": g.errors,
        }),
        CheckUpdate::Reputation(r) => json!({
            "dnsbl": r.dnsbl.iter().map(|h| json!({"zone": h.zone, "listed": h.listed})).collect::<Vec<_>>(),
            "tor_exit_node": r.tor_exit_node,
            "errors": r.errors,
        }),
        CheckUpdate::Ports(p) => json!({
            "scanned": p.scanned.iter().map(|s| json!({"port": s.port, "open": s.open})).collect::<Vec<_>>(),
        }),
        CheckUpdate::Trace(_) | CheckUpdate::NotImplemented => json!(null),
    }
}

fn print_summary(target: &Target, slots: &BTreeMap<CheckId, CheckSlot>) {
    println!("netloupe check: {}", target.display());
    for id in CheckId::ALL {
        if id == CheckId::Trace {
            continue;
        }
        let Some(slot) = slots.get(&id) else { continue };
        let status = match &slot.status {
            CheckStatus::Done => "done",
            CheckStatus::Failed(_) => "FAILED",
            CheckStatus::Cancelled => "cancelled",
            CheckStatus::Running => "still running",
            CheckStatus::NotStarted => "not started",
        };
        println!("[{status:>12}] {}", id.label());
        if let CheckStatus::Failed(message) = &slot.status {
            println!("             {message}");
        }
    }
}

async fn run_tui(hosts: Vec<String>) -> anyhow::Result<()> {
    let (config, providers) = load_config_and_providers()?;

    let mut targets = Vec::new();
    for host in &hosts {
        match Target::parse(host) {
            Ok(t) => targets.push(t),
            Err(err) => eprintln!("warning: skipping {host:?}: {err}"),
        }
    }

    let _log_guard = init_file_logging();

    let terminal = ratatui::try_init().map_err(|err| {
        anyhow::anyhow!(
            "could not start the terminal UI (is this running in an interactive terminal?): {err}"
        )
    })?;
    let result = app::run(terminal, config, providers, targets).await;
    ratatui::restore();
    result
}

/// Logs go to a file only (`$XDG_STATE_HOME/netloupe/netloupe.log` or
/// equivalent) since stdout/stderr belong to the TUI. Returns the guard
/// that must stay alive for the duration of the program.
fn init_file_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let dirs = directories::ProjectDirs::from("", "", "netloupe")?;
    let log_dir = dirs
        .state_dir()
        .unwrap_or_else(|| dirs.cache_dir())
        .to_path_buf();
    std::fs::create_dir_all(&log_dir).ok()?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "netloupe.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .init();
    Some(guard)
}
