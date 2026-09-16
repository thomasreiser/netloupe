//! A short, colored glyph summarizing a check's run status.

use ratatui::style::Color;

use crate::app::CheckStatus;

/// Returns `(glyph, color)` for a check's current status.
pub fn badge(status: &CheckStatus) -> (&'static str, Color) {
    match status {
        CheckStatus::NotStarted => ("·", Color::DarkGray),
        CheckStatus::Running => ("●", Color::Yellow),
        CheckStatus::Done => ("✓", Color::Green),
        CheckStatus::Failed(_) => ("✗", Color::Red),
        CheckStatus::Cancelled => ("–", Color::DarkGray),
    }
}
