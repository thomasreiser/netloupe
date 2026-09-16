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

pub fn widget(samples: &[PingSample]) -> Sparkline<'static> {
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
