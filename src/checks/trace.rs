//! Traceroute (the "Trace" half of Ping/Trace pane): MTR-style hop list
//! with per-hop ASN/provider badges.
//!
//! Two methods, in order of preference:
//!
//! - [`TraceMethod::Icmp`]: a real hop-by-hop trace. Reuses `surge_ping`
//!   the same way `ping` does, but opens one `Client` per TTL (the crate
//!   applies TTL per-socket, not per-packet) and sends a single echo
//!   request per hop. `surge_ping` already routes an ICMP error (Time
//!   Exceeded from an intermediate router, Destination Unreachable, ...)
//!   back to the waiter keyed by the *target* address quoted inside the
//!   error rather than by whoever actually sent it — see its
//!   `IcmpPacket::real_destination` — so a hop's reply reads exactly like
//!   an echo reply that happens to come from a different source. Needs the
//!   same root/`CAP_NET_RAW` (or Linux's unprivileged `ping_group_range`)
//!   that ping needs to open an ICMP socket at all.
//! - [`TraceMethod::TcpConnect`]: the fallback when no ICMP socket can be
//!   opened. A plain TCP socket can have its outbound TTL set without any
//!   privilege, but with no way to receive ICMP errors it can't identify
//!   which router is at which hop — only whether *some* TTL is enough to
//!   reach the destination at all (any definite answer, whether an open
//!   port or an explicit refusal, proves the probe got there; a timeout
//!   proves nothing, since it looks the same whether a hop dropped the
//!   probe or the destination just didn't answer on that TTL). That still
//!   answers "how many hops away is it", just not "who are they".
//!
//! Either way, this never fails outright over a plain privilege gap: it
//! degrades to the TCP sweep and says so in `TraceUpdate::fallback_reason`,
//! rather than reporting the whole check as failed.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use surge_ping::{Client, Config as PingConfig, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckPayload, CheckUpdate};
use crate::providers::ProviderDb;

/// Real traceroute implementations default to 30 hops; that's plenty for
/// virtually any Internet path and bounds how long a fully-lossy run can take.
pub(crate) const MAX_HOPS: u8 = 30;

/// How a [`TraceUpdate`]'s hops were probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceMethod {
    Icmp,
    /// The fallback when an ICMP socket can't be opened: a TTL-limited TCP
    /// connect to `port` per hop. Can only say how far away the target is,
    /// not which routers are in between — see the module docs.
    TcpConnect {
        port: u16,
    },
}

/// One probed hop. `addr` is `None` when that TTL got no response at all
/// within the timeout (the classic traceroute "*").
#[derive(Debug, Clone)]
pub struct TraceHop {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub rtt: Option<Duration>,
    /// Looked up from the local provider IP-range table (no network call),
    /// so this fills in even for hops that never get a DNS PTR lookup.
    pub provider: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TraceUpdate {
    pub target_ip: IpAddr,
    pub method: TraceMethod,
    pub hops: Vec<TraceHop>,
    /// Set once a hop's address matches the target: the trace is complete,
    /// successfully, rather than having just run out of `MAX_HOPS`.
    pub reached: bool,
    /// Set when ICMP couldn't be used at all, explaining the TCP fallback.
    pub fallback_reason: Option<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Trace;
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

    let (method, fallback_reason) = if icmp_client_for(target_ip, None).is_ok() {
        (TraceMethod::Icmp, None)
    } else {
        (
            TraceMethod::TcpConnect {
                port: ctx.port.unwrap_or(443),
            },
            Some(
                "no ICMP socket available (needs root, CAP_NET_RAW, or an unprivileged ICMP \
                 range); running a simple TCP-connect TTL sweep instead. That can tell how many \
                 hops away the target is, but not which routers are in between — so the \
                 Address and Provider columns stay empty for every hop but the last. Root or \
                 CAP_NET_RAW would show the full hop-by-hop path, with provider badges."
                    .to_string(),
            ),
        )
    };

    let ident = PingIdentifier(std::process::id() as u16);
    let timeout = ctx.config.timeouts.trace;

    let mut update = TraceUpdate {
        target_ip,
        method,
        hops: Vec::new(),
        reached: false,
        fallback_reason,
    };

    for ttl in 1..=MAX_HOPS {
        let probe = async {
            match method {
                TraceMethod::Icmp => icmp_hop(target_ip, ttl, ident, timeout).await,
                TraceMethod::TcpConnect { port } => tcp_hop(target_ip, port, ttl, timeout).await,
            }
        };

        let mut hop = tokio::select! {
            _ = ctx.cancel.cancelled() => {
                let _ = tx.send(CheckEvent { tab_id: ctx.tab_id, check: id, payload: CheckPayload::Cancelled }).await;
                return;
            }
            hop = probe => hop,
        };

        if let Some(addr) = hop.addr {
            hop.provider = provider_label(&ctx.providers, addr);
        }

        let reached = hop.addr == Some(target_ip);
        update.hops.push(hop);
        update.reached = reached;

        let payload = if reached {
            CheckPayload::Done(CheckUpdate::Trace(update.clone()))
        } else {
            CheckPayload::Progress(CheckUpdate::Trace(update.clone()))
        };
        let is_done = tx
            .send(CheckEvent {
                tab_id: ctx.tab_id,
                check: id,
                payload,
            })
            .await
            .is_err();
        if is_done || reached {
            return;
        }
    }

    // Ran out of hops without reaching the target: still a normal result
    // (a partial path is a real answer, not an error) per the "partial
    // results are normal" architecture rule.
    let _ = tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload: CheckPayload::Done(CheckUpdate::Trace(update)),
        })
        .await;
}

/// Opens an ICMP client, optionally pinned to `ttl`. Used both to probe
/// whether ICMP is available at all (`ttl: None`) and, once it is known to
/// be, to build the per-hop client (`ttl: Some(_)`) — `surge_ping` applies
/// TTL per-socket, so each hop needs its own client.
fn icmp_client_for(ip: IpAddr, ttl: Option<u8>) -> std::io::Result<Client> {
    let mut builder = PingConfig::builder();
    if ip.is_ipv6() {
        builder = builder.kind(ICMP::V6);
    }
    if let Some(ttl) = ttl {
        builder = builder.ttl(ttl as u32);
    }
    Client::new(&builder.build())
}

async fn icmp_hop(target: IpAddr, ttl: u8, ident: PingIdentifier, timeout: Duration) -> TraceHop {
    let empty = || TraceHop {
        ttl,
        addr: None,
        rtt: None,
        provider: None,
    };
    let Ok(client) = icmp_client_for(target, Some(ttl)) else {
        return empty();
    };
    let mut pinger = client.pinger(target, ident).await;
    pinger.timeout(timeout);
    match pinger.ping(PingSequence(ttl as u16), &[0u8; 32]).await {
        Ok((packet, rtt)) => TraceHop {
            ttl,
            addr: Some(packet_source(&packet)),
            rtt: Some(rtt),
            provider: None,
        },
        Err(_) => empty(),
    }
}

fn packet_source(packet: &IcmpPacket) -> IpAddr {
    match packet {
        IcmpPacket::V4(p) => IpAddr::V4(p.get_source()),
        IcmpPacket::V6(p) => IpAddr::V6(p.get_source()),
    }
}

async fn tcp_hop(target: IpAddr, port: u16, ttl: u8, timeout: Duration) -> TraceHop {
    let empty = || TraceHop {
        ttl,
        addr: None,
        rtt: None,
        provider: None,
    };
    let Ok(socket) = ttl_socket(target, ttl) else {
        return empty();
    };
    let start = Instant::now();
    let addr = SocketAddr::new(target, port);
    match tokio::time::timeout(timeout, socket.connect(addr)).await {
        // Any answer at all -- an open port or an explicit refusal/
        // unreachable error -- proves the probe reached the destination.
        // A plain TCP socket has no way to see which router (if any) it
        // passed through on the way, unlike an ICMP time-exceeded reply.
        Ok(_) => TraceHop {
            ttl,
            addr: Some(target),
            rtt: Some(start.elapsed()),
            provider: None,
        },
        // No answer inside the timeout: could be a probe silently dropped
        // at this hop, or just ordinary loss further along -- the two are
        // indistinguishable without ICMP.
        Err(_) => empty(),
    }
}

/// Builds a TCP socket with its outbound TTL/hop-limit set, ready to
/// `connect()`. Setting a socket's own TTL needs no privilege (only
/// *receiving* raw ICMP does), which is what makes the TCP fallback work
/// with no root at all.
fn ttl_socket(target: IpAddr, ttl: u8) -> std::io::Result<TcpSocket> {
    let socket = match target {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    let sock_ref = socket2::SockRef::from(&socket);
    match target {
        IpAddr::V4(_) => sock_ref.set_ttl_v4(ttl as u32)?,
        IpAddr::V6(_) => sock_ref.set_unicast_hops_v6(ttl as u32)?,
    }
    Ok(socket)
}

/// Looks up `addr` in the local provider IP-range table. Synchronous and
/// network-free (the table is built once at startup), so it's cheap enough
/// to call for every hop.
fn provider_label(db: &ProviderDb, addr: IpAddr) -> Option<String> {
    let m = db.ranges.lookup(addr)?;
    Some(
        db.signature(&m.provider_id)
            .map(|sig| sig.name.clone())
            .unwrap_or(m.provider_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A closed local port still answers (with a refusal) quickly, and per
    /// the module docs that must count as "reached the destination" even
    /// though the TCP method can't open the port.
    #[tokio::test]
    async fn tcp_hop_against_a_closed_local_port_counts_as_reached() {
        let hop = tcp_hop(
            "127.0.0.1".parse().unwrap(),
            1, // reserved, essentially never has a listener
            1,
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(hop.addr, Some("127.0.0.1".parse().unwrap()));
        assert!(hop.rtt.is_some());
    }

    /// An open port must also count as reached (the ordinary success path).
    #[tokio::test]
    async fn tcp_hop_against_an_open_local_port_counts_as_reached() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let hop = tcp_hop(
            "127.0.0.1".parse().unwrap(),
            port,
            1,
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(hop.addr, Some("127.0.0.1".parse().unwrap()));
        assert!(hop.rtt.is_some());
    }

    /// A probe that doesn't get any answer before the timeout must report an
    /// unanswered hop ("*"), not be confused with a reached destination.
    /// Uses a paused clock against a real (loopback) listener rather than an
    /// unreachable address, so the timeout firing is deterministic instead
    /// of depending on how the local network happens to handle a bogus
    /// destination (sandboxed environments can reject those instantly).
    #[tokio::test(start_paused = true)]
    async fn tcp_hop_times_out_reports_no_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Never accepted, so the connect has nothing to complete with
        // before virtual time immediately elapses the zero-length timeout.
        let hop = tcp_hop("127.0.0.1".parse().unwrap(), port, 1, Duration::ZERO).await;
        assert_eq!(hop.addr, None);
        assert_eq!(hop.rtt, None);
    }

    #[test]
    fn ttl_socket_accepts_a_normal_ttl_without_privilege() {
        assert!(ttl_socket("127.0.0.1".parse().unwrap(), 5).is_ok());
        assert!(ttl_socket("::1".parse().unwrap(), 5).is_ok());
    }

    #[test]
    fn provider_label_is_none_for_an_empty_db() {
        let db = ProviderDb::default();
        assert_eq!(provider_label(&db, "1.1.1.1".parse().unwrap()), None);
    }

    /// Real-network check of the TCP fallback path (the ICMP path is
    /// exercised for free every time `netloupe check` runs on a machine
    /// where ICMP works, e.g. macOS's unprivileged ICMP sockets). Confirms
    /// the TTL sweep actually reaches a real public target and stops
    /// growing the moment it does, rather than always crawling to
    /// `MAX_HOPS`. Ignored by default per the network-tests convention.
    #[tokio::test]
    #[ignore]
    async fn tcp_sweep_against_a_real_target_finds_the_destination() {
        let target: IpAddr = "1.1.1.1".parse().unwrap();
        let mut reached_at = None;
        for ttl in 1..=MAX_HOPS {
            let hop = tcp_hop(target, 443, ttl, Duration::from_secs(2)).await;
            if hop.addr == Some(target) {
                reached_at = Some(ttl);
                break;
            }
        }
        assert!(
            reached_at.is_some(),
            "a TCP-connect sweep to 1.1.1.1:443 should reach it within {MAX_HOPS} hops"
        );
    }
}
