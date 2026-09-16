//! Thin wrapper turning a ping run's RTT samples into ratatui's
//! `Sparkline` widget, colored green→yellow→red by how the latest RTT
//! compares to a rough "fine/sluggish" scale, with losses as zero bars.

use ratatui::style::Style;
use ratatui::widgets::Sparkline;

use crate::checks::ping::PingSample;
use crate::ui::theme;

/// RTTs at or below this are "fully green"; at or above `SLOW_MS` they're
/// "fully red". Not a precision instrument, just a quick-glance scale.
const FAST_MS: f64 = 15.0;
const SLOW_MS: f64 = 200.0;

/// `width` is the sparkline's actual rendered width (one bar per data
/// point): ratatui's `Sparkline` always draws from the *start* of the
/// data it's given, so feeding it every kept sample (`ping::MAX_SAMPLES_KEPT`,
/// which can be wider than the pane) would either leave blank space past
/// however many happened to exist yet, or -- once more samples exist than
/// fit -- freeze on the oldest ones forever instead of scrolling to show
/// the latest. Trimming to the last `width` samples here fixes both: the
/// graph fills the available width as soon as there's enough history,
/// and keeps showing the most recent samples once there's more than fits.
pub fn widget(samples: &[PingSample], width: u16) -> Sparkline<'static> {
    let samples = trim_to_tail(samples, width);
    let data: Vec<u64> = samples
        .iter()
        .map(|s| s.rtt.map(|d| d.as_millis() as u64).unwrap_or(0))
        .collect();

    let latest = samples
        .iter()
        .rev()
        .find_map(|s| s.rtt)
        .map(|d| d.as_millis() as f64);
    let color = match latest {
        Some(ms) => theme::gradient(((ms - FAST_MS) / (SLOW_MS - FAST_MS)).clamp(0.0, 1.0)),
        None => theme::RED,
    };

    Sparkline::default()
        .data(data)
        .style(Style::default().fg(color))
}

/// Keeps only the trailing `width` samples (see [`widget`]'s doc comment
/// for why): a plain slice op, pulled out so it's unit-testable without
/// needing to inspect a rendered `Sparkline`'s private internals.
fn trim_to_tail(samples: &[PingSample], width: u16) -> &[PingSample] {
    let start = samples.len().saturating_sub(width as usize);
    &samples[start..]
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn sample(seq: u32, ms: u64) -> PingSample {
        PingSample {
            seq,
            rtt: Some(Duration::from_millis(ms)),
        }
    }

    /// Fewer samples than `width` must be kept as-is (nothing to trim);
    /// this is the "graph hasn't filled up yet" case.
    #[test]
    fn keeps_every_sample_when_there_are_fewer_than_the_width() {
        let samples = vec![sample(0, 10), sample(1, 20), sample(2, 30)];
        assert_eq!(trim_to_tail(&samples, 10).len(), 3);
    }

    /// More samples than fit must trim to the trailing `width` of them, or
    /// the graph would freeze on stale oldest data instead of scrolling.
    #[test]
    fn trims_to_the_most_recent_width_samples() {
        let samples: Vec<PingSample> = (0..50).map(|i| sample(i, i as u64)).collect();
        let trimmed = trim_to_tail(&samples, 10);
        assert_eq!(trimmed.len(), 10);
        // The last kept sample must be the most recent one (seq 49), not
        // some earlier one.
        assert_eq!(trimmed.last().map(|s| s.seq), Some(49));
    }
}
