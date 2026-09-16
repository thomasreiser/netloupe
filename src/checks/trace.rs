//! Traceroute (the "Trace" half of Ping/Trace pane): MTR-style hop list
//! with per-hop ASN/provider badges.
//!
//! **Not implemented yet.** A correct traceroute needs a raw ICMP socket
//! (to receive `Time Exceeded` replies from intermediate routers, not just
//! the final target) with the same root/`CAP_NET_RAW` privilege ping needs
//! — see `CLAUDE.md`'s platform notes — plus hand-rolled ICMP packet
//! construction/parsing that's risky to ship untested. Rather than guess
//! at that without a way to verify it against real routers, this check
//! reports the gap plainly (architecture rule: partial results are normal)
//! instead of faking hop data. Tracked on the roadmap (phase 4).

use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::CheckEvent;

/// One discovered hop. Defined now so the pane and event plumbing exist
/// even though nothing populates it yet.
#[derive(Debug, Clone)]
pub struct TraceHop {
    pub ttl: u8,
    pub addr: Option<std::net::IpAddr>,
    pub rtt: Option<std::time::Duration>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TraceUpdate {
    pub hops: Vec<TraceHop>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Trace;
    let _ = tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload: crate::event::CheckPayload::Failed(
                "traceroute isn't implemented yet (needs a raw ICMP socket; see the roadmap)"
                    .to_string(),
            ),
        })
        .await;
}
