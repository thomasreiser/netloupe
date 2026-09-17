//! Scheduling and freshness-display helpers shared by every background
//! task that refreshes on-disk data on a configurable interval
//! (`crate::geoip`, `crate::providers::update`). Deliberately tiny and
//! data-agnostic: each caller supplies its own notion of "when did this
//! last succeed", usually a file's mtime.

use std::time::{Duration, SystemTime};

use tokio::sync::watch;

/// How long ago `t` was, for display (e.g. a status line's "3h old").
pub fn age_of(t: SystemTime) -> Duration {
    t.elapsed().unwrap_or_default()
}

/// Renders a duration as a single coarse unit, e.g. "45s", "3m", "6h",
/// "2d" -- the coarsest unit that's still useful, not a full breakdown.
pub fn humanize_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    if hours < 48 {
        return format!("{hours}h");
    }
    format!("{}d", hours / 24)
}

/// One on-disk data file kept fresh by a background updater, for display
/// (e.g. the data-info popup) -- not used by any load/download path.
#[derive(Debug, Clone)]
pub struct CachedFile {
    pub filename: String,
    pub size_bytes: u64,
    pub modified: Option<SystemTime>,
}

/// True when `last` is unset, or old enough that `interval` has elapsed.
pub fn is_due(last: Option<SystemTime>, interval: Duration) -> bool {
    match last {
        None => true,
        Some(t) => t.elapsed().unwrap_or(Duration::MAX) >= interval,
    }
}

/// How long to sleep before the next refresh is due. At least one second,
/// so a deadline that's already passed doesn't spin.
pub fn time_until_due(last: Option<SystemTime>, interval: Duration) -> Duration {
    let remaining = match last {
        None => Duration::from_secs(1),
        Some(t) => interval.saturating_sub(t.elapsed().unwrap_or(interval)),
    };
    remaining.max(Duration::from_secs(1))
}

/// Sleeps for `dur`, waking early if `config_rx` reports a config change
/// (e.g. the update interval was just edited in the settings editor)
/// rather than waiting out however much of the old interval was left.
pub async fn wait_for_change_or<T>(config_rx: &mut watch::Receiver<T>, dur: Duration) {
    tokio::select! {
        _ = config_rx.changed() => {}
        _ = tokio::time::sleep(dur) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_due_when_never_succeeded() {
        assert!(is_due(None, Duration::from_secs(3600)));
    }

    #[test]
    fn is_due_respects_a_recent_success() {
        assert!(!is_due(Some(SystemTime::now()), Duration::from_secs(3600)));
    }

    #[test]
    fn is_due_once_the_interval_has_elapsed() {
        let old = SystemTime::now() - Duration::from_secs(7200);
        assert!(is_due(Some(old), Duration::from_secs(3600)));
    }

    #[test]
    fn time_until_due_is_never_below_one_second() {
        let almost_due = SystemTime::now() - Duration::from_secs(3599);
        assert_eq!(
            time_until_due(Some(almost_due), Duration::from_secs(3600)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn humanize_age_picks_the_coarsest_useful_unit() {
        assert_eq!(humanize_age(Duration::from_secs(30)), "30s");
        assert_eq!(humanize_age(Duration::from_secs(90)), "1m");
        assert_eq!(humanize_age(Duration::from_secs(3 * 3600)), "3h");
        assert_eq!(humanize_age(Duration::from_secs(3 * 24 * 3600)), "3d");
    }
}
