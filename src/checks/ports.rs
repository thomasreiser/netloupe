//! Ports pane: an opt-in, rate-limited TCP-connect scan of a configurable
//! port list, with a banner grab on anything that accepts a connection.
//!
//! Opt-in and rate-limited on purpose: scanning hosts you don't own may be
//! illegal (see `CLAUDE.md`'s Safety and ethics section). `app.rs` gates
//! this check behind a confirmation prompt shown once per tab; this module
//! doesn't know about that UI, it just always respects the configured rate
//! limit so a probe burst never happens even if that gate is bypassed.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckPayload, CheckUpdate};

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PortsUpdate {
    pub target_ip: Option<IpAddr>,
    pub scanned: Vec<PortResult>,
    pub total: usize,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Ports;
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

    let ip = match super::resolve_target_ip(&ctx).await {
        Ok(ip) => ip,
        Err(err) => {
            let _ = tx
                .send(CheckEvent {
                    tab_id: ctx.tab_id,
                    check: id,
                    payload: CheckPayload::Failed(err),
                })
                .await;
            return;
        }
    };

    let ports = ctx.config.ports.scan_list.clone();
    let mut update = PortsUpdate {
        target_ip: Some(ip),
        scanned: Vec::new(),
        total: ports.len(),
    };

    for &port in &ports {
        if ctx.cancel.is_cancelled() {
            let _ = tx
                .send(CheckEvent {
                    tab_id: ctx.tab_id,
                    check: id,
                    payload: CheckPayload::Cancelled,
                })
                .await;
            return;
        }

        let result = scan_one(ip, port, ctx.config.timeouts.port_connect).await;
        update.scanned.push(result);

        let payload = CheckPayload::Progress(CheckUpdate::Ports(update.clone()));
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
            _ = tokio::time::sleep(ctx.config.ports.rate_limit) => {}
            _ = ctx.cancel.cancelled() => {
                let _ = tx.send(CheckEvent { tab_id: ctx.tab_id, check: id, payload: CheckPayload::Cancelled }).await;
                return;
            }
        }
    }

    let _ = tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload: CheckPayload::Done(CheckUpdate::Ports(update)),
        })
        .await;
}

async fn scan_one(ip: IpAddr, port: u16, timeout: Duration) -> PortResult {
    let connect = tokio::time::timeout(timeout, TcpStream::connect((ip, port))).await;
    let Ok(Ok(mut stream)) = connect else {
        return PortResult {
            port,
            open: false,
            banner: None,
        };
    };

    // A short passive read: many services (SSH, SMTP, FTP) send a banner
    // unprompted; others (HTTP) stay silent until spoken to, so a timeout
    // here just means "open but no banner", not a failure.
    let mut buf = vec![0u8; 256];
    let banner = match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await
    {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).trim().to_string()),
        _ => None,
    };

    PortResult {
        port,
        open: true,
        banner,
    }
}
