//! Full NSEC zone walk: opt-in, unlike everything else `checks::dns`
//! already does automatically (a single probe query, an AXFR attempt per
//! nameserver, an ANY query). Once a zone uses NSEC (not NSEC3 — see
//! `checks::dns::ZoneSigning`), its whole set of names can be enumerated
//! by repeatedly following each name's NSEC record to the next one in
//! canonical order until the chain loops back to the start. That's
//! dozens to thousands of queries against someone else's authoritative
//! nameservers rather than the handful every other check makes, so this
//! needs an explicit yes (see `app.rs`'s `Mode::ConfirmZoneWalk`), the
//! same principle as the opt-in Ports scan, and stays rate-limited and
//! bounded even once running.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckPayload, CheckUpdate};
use crate::target::Target;

/// Hard ceiling regardless of what the server allows, so a walk can't run
/// away against a huge or slow-to-respond zone.
const MAX_NAMES: usize = 2_000;
const MAX_WALL_CLOCK: Duration = Duration::from_secs(90);
/// Minimum gap between queries: this check's whole reason for being
/// opt-in is that it's many requests against someone else's
/// infrastructure, so it stays a polite, slow trickle rather than a burst.
const QUERY_DELAY: Duration = Duration::from_millis(75);

#[derive(Debug, Clone, Default)]
pub struct ZoneWalkResult {
    pub zone: String,
    /// Every name discovered, in the order the walk visited them.
    pub names: Vec<String>,
    pub queries_made: usize,
    /// True if the walk followed the NSEC chain all the way back to where
    /// it started (the whole zone was enumerated); false if it stopped
    /// early because of the name/time cap or an error partway through.
    pub complete: bool,
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::ZoneWalk;
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

    let zone = match &ctx.target {
        Target::Host { ascii, .. } => ascii.trim_end_matches('.').to_string(),
        Target::Ip(_) => {
            let _ = tx
                .send(CheckEvent {
                    tab_id: ctx.tab_id,
                    check: id,
                    payload: CheckPayload::Failed(
                        "zone walking needs a hostname, not a bare IP".to_string(),
                    ),
                })
                .await;
            return;
        }
    };

    // A walk against a large or slow zone can take the better part of a
    // minute, so this streams `Progress` updates as it goes (like the
    // Ports scan) rather than leaving the pane looking idle the whole
    // time, and checks cancellation between queries so closing the tab
    // or re-running actually stops it promptly instead of running out
    // the full budget regardless.
    let result = walk(&zone, ctx.config.timeouts.dns, &ctx, id, &tx).await;
    let Some(result) = result else {
        let _ = tx
            .send(CheckEvent {
                tab_id: ctx.tab_id,
                check: id,
                payload: CheckPayload::Cancelled,
            })
            .await;
        return;
    };

    let _ = tx
        .send(CheckEvent {
            tab_id: ctx.tab_id,
            check: id,
            payload: CheckPayload::Done(CheckUpdate::ZoneWalk(result)),
        })
        .await;
}

/// Returns `None` if cancelled partway through, so `run` can report
/// `Cancelled` instead of a `Done` with a partial (and misleadingly
/// labeled) result.
async fn walk(
    zone: &str,
    timeout: Duration,
    ctx: &CheckContext,
    id: super::CheckId,
    tx: &mpsc::Sender<CheckEvent>,
) -> Option<ZoneWalkResult> {
    let mut result = ZoneWalkResult {
        zone: zone.to_string(),
        ..Default::default()
    };

    let opts = super::dns::DnsOpts::new(timeout, ctx.resolver);
    let resolver = match super::dns::dnssec_probe_resolver(opts) {
        Ok(r) => r,
        Err(err) => {
            result.errors.push(format!(
                "could not set up a DNSSEC-validating resolver: {err}"
            ));
            return Some(result);
        }
    };

    // Enter the ring at an arbitrary point: query a name that can't exist
    // and read the "next real name" off its covering NSEC record, exactly
    // like `checks::dns::detect_zone_signing`'s probe.
    let probe = format!("_netloupe-zonewalk-entry.{zone}.");
    let Some(start) = next_name_from_nxdomain(&resolver, &probe).await else {
        result.errors.push("could not enter the NSEC chain (the zone may not actually use NSEC, or the probe query failed)".to_string());
        return Some(result);
    };
    if let Ok(probe_name) = Name::from_str(&probe) {
        if is_synthesized_dead_end(&start, &probe_name) {
            result.errors.push(
                "this nameserver synthesizes a \"minimally covering\" NSEC record for every \
                 nonexistent name queried, proving only that the exact queried name doesn't \
                 exist rather than revealing a real next name — a deliberate, effective \
                 anti-zone-walking technique, so there's no chain here to follow"
                    .to_string(),
            );
            return Some(result);
        }
    }

    let mut current = start;
    let mut visited: HashSet<Name> = HashSet::new();
    let deadline = tokio::time::Instant::now() + MAX_WALL_CLOCK;

    loop {
        if ctx.cancel.is_cancelled() {
            return None;
        }
        if visited.len() >= MAX_NAMES {
            result.errors.push(format!(
                "stopped after {MAX_NAMES} names (safety cap) — the zone may be larger than this"
            ));
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            result
                .errors
                .push("stopped after the time budget for this walk ran out".to_string());
            break;
        }
        if !visited.insert(current.clone()) {
            // Followed the chain back to a name already seen: the ring is
            // closed, so (barring the zone changing mid-walk) this is
            // every name in the zone.
            result.complete = true;
            break;
        }
        result.names.push(current.to_string());

        // A walk against a real zone can take dozens of seconds; report
        // progress as names are found rather than leaving the pane
        // looking frozen until the very end.
        let progress = tx
            .send(CheckEvent {
                tab_id: ctx.tab_id,
                check: id,
                payload: CheckPayload::Progress(CheckUpdate::ZoneWalk(result.clone())),
            })
            .await;
        if progress.is_err() {
            return None;
        }

        // A single per-name query against someone else's nameserver can
        // fail transiently (one bad UDP round-trip, a momentary negative-
        // cache hiccup) without the chain itself being broken, so one
        // retry happens before treating it as the end of the walk.
        result.queries_made += 1;
        let mut outcome = next_name_from_answer(&resolver, &current).await;
        if outcome.is_err() {
            tokio::time::sleep(QUERY_DELAY).await;
            result.queries_made += 1;
            outcome = next_name_from_answer(&resolver, &current).await;
        }
        match outcome {
            Ok(Some(next)) if is_synthesized_dead_end(&next, &current) => {
                // Same synthesized "next name" pattern as the entry probe,
                // just encountered mid-chain instead: this nameserver
                // fabricates a fresh, ever-longer dead-end name for every
                // query rather than ever revealing a real one, so
                // following it further would just grow the name forever
                // without discovering anything.
                result.errors.push(format!(
                    "{current} returned a synthesized \"minimally covering\" NSEC record instead \
                     of a real next name — stopping rather than following an anti-walking dead end"
                ));
                break;
            }
            Ok(Some(next)) => current = next,
            Ok(None) => {
                result.errors.push(format!("{current} has no NSEC record of its own — stopping (unexpected for a signed zone)"));
                break;
            }
            Err(err) => {
                result.errors.push(format!(
                    "query for {current} failed twice — stopping: {err}"
                ));
                break;
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(QUERY_DELAY) => {}
            _ = ctx.cancel.cancelled() => return None,
        }
    }

    Some(result)
}

/// True if `next` is a "minimally covering" / "white lies" synthesized
/// NSEC record's next-name rather than a real one: some online DNSSEC
/// signers (Knot DNS, PowerDNS's online signer, and others), specifically
/// to defeat zone walking, respond to *any* nonexistent-name query by
/// fabricating an NSEC record claiming the next real name is the queried
/// name itself with one extra label prepended — the single byte 0x00,
/// which canonically sorts before every real label, so the record is
/// technically valid while covering (and revealing) nothing but the exact
/// name that was asked about. Following that "next name" would just
/// re-trigger the same synthesis with another 0x00 label stacked on top,
/// forever, so it needs to be recognized and treated as a dead end rather
/// than walked into.
fn is_synthesized_dead_end(next: &Name, queried: &Name) -> bool {
    next.num_labels() == queried.num_labels().saturating_add(1)
        && &next.base_name() == queried
        && next.iter().next() == Some(&[0u8][..])
}

/// Queries `name` (expected not to exist) and pulls the "next domain name"
/// out of the NSEC record proving that, from the NXDOMAIN response's
/// authority section.
async fn next_name_from_nxdomain(
    resolver: &hickory_resolver::TokioResolver,
    name: &str,
) -> Option<Name> {
    use hickory_resolver::net::{DnsError, NetError};

    match resolver.lookup(name, RecordType::A).await {
        Ok(_) => None, // the "nonexistent" probe name unexpectedly exists
        Err(err) => {
            let authorities: Vec<hickory_proto::rr::Record> = match err {
                NetError::Dns(DnsError::Nsec { response, .. }) => response.authorities.clone(),
                NetError::Dns(DnsError::NoRecordsFound(no_records)) => no_records
                    .authorities
                    .as_deref()
                    .map(<[_]>::to_vec)
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            authorities.iter().find_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some(nsec.next_domain_name().clone()),
                _ => None,
            })
        }
    }
}

/// Queries `name` (expected to exist) directly for its own NSEC record and
/// returns the "next domain name" it carries.
async fn next_name_from_answer(
    resolver: &hickory_resolver::TokioResolver,
    name: &Name,
) -> Result<Option<Name>, String> {
    let lookup = resolver
        .lookup(name.clone(), RecordType::NSEC)
        .await
        .map_err(|e| e.to_string())?;
    Ok(lookup
        .answers()
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some(nsec.next_domain_name().clone()),
            _ => None,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_a_synthesized_minimally_covering_next_name() {
        let queried = Name::from_str("_netloupe-zonewalk-entry.example.com.").unwrap();
        let synthesized = queried.prepend_label(&[0u8][..]).unwrap();
        assert!(is_synthesized_dead_end(&synthesized, &queried));

        // ...and stacking a second one on top of the first is still
        // recognized as a dead end relative to *that* name, matching what
        // the walk loop actually compares on each iteration.
        let stacked = synthesized.prepend_label(&[0u8][..]).unwrap();
        assert!(is_synthesized_dead_end(&stacked, &synthesized));
    }

    #[test]
    fn does_not_flag_a_real_next_name() {
        let queried = Name::from_str("_netloupe-zonewalk-entry.example.com.").unwrap();
        let real_next = Name::from_str("acme.example.com.").unwrap();
        assert!(!is_synthesized_dead_end(&real_next, &queried));
    }

    #[test]
    fn does_not_flag_an_unrelated_name_with_the_right_label_count() {
        // Same number of labels as a dead-end would have, but not
        // actually built from `queried` plus a 0x00 label, and the extra
        // label isn't 0x00 either — a real name should never be mistaken
        // for the synthesized pattern just by label count.
        let queried = Name::from_str("_netloupe-zonewalk-entry.example.com.").unwrap();
        let unrelated = Name::from_str("www.other.example.com.").unwrap();
        assert!(!is_synthesized_dead_end(&unrelated, &queried));
    }
}
