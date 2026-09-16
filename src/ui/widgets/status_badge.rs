//! A short, colored glyph summarizing a check's run status.

use ratatui::style::Color;

use crate::app::CheckStatus;
use crate::ui::theme;

/// Returns `(glyph, color)` for a check's current status.
pub fn badge(status: &CheckStatus) -> (&'static str, Color) {
    match status {
        CheckStatus::NotStarted => ("○", theme::FAINT),
        CheckStatus::Running => ("◐", theme::YELLOW),
        CheckStatus::Done => ("●", theme::GREEN),
        CheckStatus::Failed(_) => ("●", theme::RED),
        CheckStatus::Cancelled => ("○", theme::MUTED),
    }
}
