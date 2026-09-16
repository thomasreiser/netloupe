//! Ping pane (the "Ping" half of Ping/Trace): ICMP echo when the OS allows
//! an unprivileged socket, degrading to a TCP-connect ping otherwise.
//!
//! Runs continuously (like `ping` itself) rather than a fixed batch,
//! streaming one `Progress` event per sample so the UI's sparkline keeps
//! updating live for as long as the tab/pane is open; only cancellation
//! (closing the tab, `r`/`R` re-running it, or headless mode's overall
//! deadline) stops it. The sample history kept for the sparkline is
//! capped (`MAX_SAMPLES_KEPT`) so an hours-long session doesn't grow
//! `PingUpdate` unbounded -- older samples roll off the front.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use surge_ping::{Client, Config as PingConfig, PingIdentifier, PingSequence, ICMP};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckPayload, CheckUpdate};

/// How the RTT samples in a [`PingUpdate`] were measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMethod {
    Icmp,
    /// The fallback when an ICMP socket can't be opened (no root/
    /// `CAP_NET_RAW` and no unprivileged ICMP datagram support): measures
    /// TCP connect latency to `port` instead. A meaningfully different
    /// number from real ICMP RTT, so the UI must label it as such.
    TcpConnect {
        port: u16,
    },
}

/// One RTT measurement; `None` means that probe was lost/timed out.
#[derive(Debug, Clone, Copy)]
pub struct PingSample {
    pub seq: u32,
    pub rtt: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct PingUpdate {
    pub target_ip: IpAddr,
    pub method: PingMethod,
    pub samples: Vec<PingSample>,
    pub sent: u32,
    pub received: u32,
    pub min: Option<Duration>,
    pub max: Option<Duration>,
    pub avg: Option<Duration>,
    /// Set when ICMP couldn't be used at all, explaining the fallback.
    pub fallback_reason: Option<String>,
    /// Idled via `Action::TogglePingPause` (Space, on the Ping/Trace
    /// pane): no new probes are being sent, and everything above reflects
    /// the last sample taken before pausing, not "no data".
    pub paused: bool,
}

impl PingUpdate {
    fn recompute_stats(&mut self) {
        // Both derived from the (windowed) `samples` list, not tracked as
        // separate ever-growing counters: with `run` now pinging
        // continuously rather than in one bounded batch, an unwindowed
        // `sent` would keep climbing forever while `received`/`samples`
        // stay capped at `MAX_SAMPLES_KEPT`, making the loss percentage
        // drift toward "all loss" over a long session regardless of
        // actual recent connectivity.
        self.sent = self.samples.len() as u32;
        let rtts: Vec<Duration> = self.samples.iter().filter_map(|s| s.rtt).collect();
        self.received = rtts.len() as u32;
        self.min = rtts.iter().min().copied();
        self.max = rtts.iter().max().copied();
        self.avg = if rtts.is_empty() {
            None
        } else {
            Some(rtts.iter().sum::<Duration>() / rtts.len() as u32)
        };
    }
}

/// How many recent samples the sparkline/stats keep; older ones roll off
/// as new ones arrive so a long-running tab's `PingUpdate` stays bounded.
/// At `PING_INTERVAL` below, 120 samples is ~84 seconds of history.
const MAX_SAMPLES_KEPT: usize = 120;
const PING_INTERVAL: Duration = Duration::from_millis(700);

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Ping;
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

    let target_ip = match super::resolve_target_ip(&ctx).await {
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

    let icmp_client = icmp_client_for(target_ip).ok();

    let (method, fallback_reason) = match &icmp_client {
        Some(_) => (PingMethod::Icmp, None),
        None => {
            let port = ctx.port.unwrap_or(443);
            (
                PingMethod::TcpConnect { port },
                Some("no ICMP socket available (needs root, CAP_NET_RAW, or an unprivileged ICMP range); falling back to a TCP connect ping".to_string()),
            )
        }
    };

    let mut update = PingUpdate {
        target_ip,
        method,
        samples: Vec::new(),
        sent: 0,
        received: 0,
        min: None,
        max: None,
        avg: None,
        fallback_reason,
        paused: false,
    };

    let mut seq: u32 = 0;
    let mut was_paused = false;
    loop {
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

        // Idles rather than sending a probe while paused, leaving
        // `update` (and so the sparkline/stats) exactly as they were --
        // pausing is meant to freeze the view, not to lose history the
        // way cancelling and losing this task's accumulated `samples`
        // would.
        if ctx.ping_paused.load(std::sync::atomic::Ordering::Relaxed) {
            if !was_paused {
                was_paused = true;
                update.paused = true;
                let payload = CheckPayload::Progress(CheckUpdate::Ping(update.clone()));
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
            }
            tokio::select! {
                _ = tokio::time::sleep(PING_INTERVAL) => continue,
                _ = ctx.cancel.cancelled() => {
                    let _ = tx.send(CheckEvent { tab_id: ctx.tab_id, check: id, payload: CheckPayload::Cancelled }).await;
                    return;
                }
            }
        }
        if was_paused {
            was_paused = false;
            update.paused = false;
        }

        let rtt = match (&icmp_client, method) {
            (Some(client), PingMethod::Icmp) => icmp_ping(client, target_ip, seq).await,
            (_, PingMethod::TcpConnect { port }) => {
                tcp_ping(target_ip, port, ctx.config.timeouts.ping).await
            }
            _ => None,
        };

        update.samples.push(PingSample { seq, rtt });
        if update.samples.len() > MAX_SAMPLES_KEPT {
            update.samples.remove(0);
        }
        update.recompute_stats();
        seq = seq.wrapping_add(1);

        let payload = CheckPayload::Progress(CheckUpdate::Ping(update.clone()));
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
            _ = tokio::time::sleep(PING_INTERVAL) => {}
            _ = ctx.cancel.cancelled() => {
                let _ = tx.send(CheckEvent { tab_id: ctx.tab_id, check: id, payload: CheckPayload::Cancelled }).await;
                return;
            }
        }
    }
}

fn icmp_client_for(ip: IpAddr) -> std::io::Result<Client> {
    let config = match ip {
        IpAddr::V4(_) => PingConfig::default(),
        IpAddr::V6(_) => PingConfig::builder().kind(ICMP::V6).build(),
    };
    Client::new(&config)
}

async fn icmp_ping(client: &Client, ip: IpAddr, seq: u32) -> Option<Duration> {
    let mut pinger = client
        .pinger(ip, PingIdentifier(std::process::id() as u16))
        .await;
    pinger.timeout(Duration::from_secs(2));
    pinger
        .ping(PingSequence(seq as u16), &[0u8; 32])
        .await
        .ok()
        .map(|(_, rtt)| rtt)
}

async fn tcp_ping(ip: IpAddr, port: u16, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    Some(start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recompute_stats_ignores_lost_probes() {
        let mut update = PingUpdate {
            target_ip: "127.0.0.1".parse().unwrap(),
            method: PingMethod::Icmp,
            samples: vec![
                PingSample {
                    seq: 0,
                    rtt: Some(Duration::from_millis(10)),
                },
                PingSample { seq: 1, rtt: None },
                PingSample {
                    seq: 2,
                    rtt: Some(Duration::from_millis(30)),
                },
            ],
            sent: 3,
            received: 0,
            min: None,
            max: None,
            avg: None,
            fallback_reason: None,
            paused: false,
        };
        update.recompute_stats();
        assert_eq!(update.received, 2);
        assert_eq!(update.min, Some(Duration::from_millis(10)));
        assert_eq!(update.max, Some(Duration::from_millis(30)));
        assert_eq!(update.avg, Some(Duration::from_millis(20)));
    }

    #[test]
    fn recompute_stats_handles_all_lost() {
        let mut update = PingUpdate {
            target_ip: "127.0.0.1".parse().unwrap(),
            method: PingMethod::Icmp,
            samples: vec![PingSample { seq: 0, rtt: None }],
            sent: 1,
            received: 0,
            min: None,
            max: None,
            avg: None,
            fallback_reason: None,
            paused: false,
        };
        update.recompute_stats();
        assert_eq!(update.received, 0);
        assert!(update.avg.is_none());
    }

    /// `sent` must track the (windowed) sample count rather than an
    /// ever-growing counter, or a long-running continuous ping's loss
    /// percentage would drift toward "all loss" over time regardless of
    /// actual recent connectivity, once old samples start rolling off.
    #[test]
    fn recompute_stats_derives_sent_from_the_windowed_sample_count() {
        let mut update = PingUpdate {
            target_ip: "127.0.0.1".parse().unwrap(),
            method: PingMethod::Icmp,
            samples: vec![
                PingSample {
                    seq: 0,
                    rtt: Some(Duration::from_millis(5)),
                },
                PingSample { seq: 1, rtt: None },
            ],
            sent: 999, // stale, as if carried over from a much larger window
            received: 0,
            min: None,
            max: None,
            avg: None,
            fallback_reason: None,
            paused: false,
        };
        update.recompute_stats();
        assert_eq!(update.sent, 2);
        assert_eq!(update.received, 1);
    }

    #[tokio::test]
    async fn tcp_ping_against_a_closed_local_port_times_out_or_fails() {
        // Port 1 is reserved and essentially never has a listener; this
        // just exercises the failure path without needing network access.
        let result = tcp_ping("127.0.0.1".parse().unwrap(), 1, Duration::from_millis(200)).await;
        assert!(result.is_none());
    }
}
