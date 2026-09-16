//! Thin wrapper turning a ping run's RTT samples into ratatui's
//! `Sparkline` widget, with losses shown as zero-height bars.

use ratatui::style::{Color, Style};
use ratatui::widgets::Sparkline;

use crate::checks::ping::PingSample;

pub fn widget(samples: &[PingSample]) -> Sparkline<'static> {
    let data: Vec<u64> = samples
        .iter()
        .map(|s| s.rtt.map(|d| d.as_millis() as u64).unwrap_or(0))
        .collect();
    Sparkline::default()
        .data(data)
        .style(Style::default().fg(Color::Green))
}
