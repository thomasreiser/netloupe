//! Hosting pane: runs the provider-detection engine against whatever DNS,
//! HTTP, TLS, and IP/ASN results are available so far.
//!
//! This check never queries the network itself (architecture rule 8/9 in
//! `CLAUDE.md`): it only reads `ctx.shared` and calls the pure
//! `providers::evaluate`, re-running every time another check reports a
//! new result so the pane fills in progressively.

use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckPayload, CheckUpdate};
use crate::providers::{self, Inputs};
use crate::target::Target;

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Hosting;
    if tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload: CheckPayload::Started,
        })
        .await
        .is_err()
    {
        return;
    }

    loop {
        let inputs = build_inputs(&ctx).await;
        let detections = providers::evaluate(&ctx.providers, &inputs);
        let payload = CheckPayload::Done(CheckUpdate::Hosting(detections));
        if tx
            .send(CheckEvent {
                tab_id: ctx.tab_id,
                check: id,
                payload,
            })
            .await
            .is_err()
        {
            return;
        }

        tokio::select! {
            _ = ctx.cancel.cancelled() => {
                let _ = tx
                    .send(CheckEvent { tab_id: ctx.tab_id, check: id, payload: CheckPayload::Cancelled })
                    .await;
                return;
            }
            _ = ctx.shared.wait_for_change() => {}
        }
    }
}

async fn build_inputs(ctx: &CheckContext) -> Inputs {
    let shared = ctx.shared.snapshot().await;
    let mut inputs = Inputs::default();

    match &ctx.target {
        Target::Ip(ip) => inputs.ips.push(*ip),
        Target::Host { .. } => {}
    }

    if let Some(dns) = &shared.dns {
        inputs
            .ips
            .extend(dns.a.iter().map(|ip| std::net::IpAddr::V4(*ip)));
        inputs
            .ips
            .extend(dns.aaaa.iter().map(|ip| std::net::IpAddr::V6(*ip)));
        inputs.cnames.extend(
            dns.cnames
                .iter()
                .map(|c| c.trim_end_matches('.').to_string()),
        );
        inputs
            .ns
            .extend(dns.ns.iter().map(|n| n.trim_end_matches('.').to_string()));
        inputs
            .ptr
            .extend(dns.ptr.iter().map(|p| p.trim_end_matches('.').to_string()));
        inputs.mx.extend(
            dns.mx
                .iter()
                .map(|mx| mx.exchange.trim_end_matches('.').to_string()),
        );
    }

    if let Some(ipinfo) = &shared.ipinfo {
        if let Some(asn) = &ipinfo.asn {
            inputs.asns.push(asn.asn);
        }
    }

    if let Some(tls) = &shared.tls {
        inputs.tls_issuer = tls.issuer.clone();
        inputs.tls_sans.extend(tls.sans.iter().cloned());
    }

    if let Some(http) = &shared.http {
        inputs.headers.extend(http.headers.iter().cloned());
    }

    if let Some(mail) = &shared.mail {
        inputs.spf_includes.extend(mail.spf_includes());
    }

    inputs
}
