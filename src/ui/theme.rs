//! The shared color palette and small styling helpers every pane draws
//! from, so the whole app reads as one coherent design instead of a
//! patchwork of ad hoc `Style::default()` calls.
//!
//! Each pane gets a fixed accent color (`pane_accent`) used for its panel
//! border, title, and status glyphs, so a glance at the border tells you
//! which section you're looking at even before reading the title.
//! `gradient` turns a 0..1 fraction into a green→yellow→red color for
//! values that read better as "good/warn/bad" than as bare numbers (ping
//! RTT, certificate expiry, confidence scores, ...).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders};

use crate::app::Pane;
use crate::providers::Confidence;

pub const TEXT: Color = Color::Rgb(226, 228, 240);
pub const MUTED: Color = Color::Rgb(110, 118, 150);
pub const FAINT: Color = Color::Rgb(70, 76, 100);

pub const CYAN: Color = Color::Rgb(120, 225, 245);
pub const GREEN: Color = Color::Rgb(90, 235, 150);
pub const YELLOW: Color = Color::Rgb(240, 225, 120);
pub const ORANGE: Color = Color::Rgb(250, 170, 95);
pub const RED: Color = Color::Rgb(250, 95, 110);
pub const PINK: Color = Color::Rgb(245, 120, 190);
pub const PURPLE: Color = Color::Rgb(180, 145, 250);
pub const BLUE: Color = Color::Rgb(110, 165, 250);

/// The single accent used for labels/keys inside panels, kept distinct
/// from any `pane_accent` so a panel's border color (its category) never
/// fights with its content's color (always this one).
pub const LABEL: Color = PURPLE;

/// The accent color for a pane's panel border, title, and status glyphs.
pub fn pane_accent(pane: Pane) -> Color {
    match pane {
        Pane::Overview => PURPLE,
        Pane::Dns => BLUE,
        Pane::Mail => PINK,
        Pane::PingTrace => GREEN,
        Pane::Ports => ORANGE,
        Pane::Tls => YELLOW,
        Pane::Http => CYAN,
        Pane::IpAsn => Color::Rgb(140, 180, 250),
        Pane::Hosting => Color::Rgb(120, 220, 165),
        Pane::Geo => Color::Rgb(240, 210, 120),
        Pane::Rep => RED,
    }
}

/// A rounded panel with `accent` as the border/title color, titled with
/// ` {title} `. The caller renders content into `.inner(area)`.
pub fn panel<'a>(title: &'a str, accent: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(accent))
        .title(Line::from(Span::styled(
            format!(" {title} "),
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        )))
}

/// Same as [`panel`], but with a right-aligned secondary title (used for a
/// small status/hint in the same border line as the main title).
pub fn panel_with_hint<'a>(
    title: &'a str,
    hint: &'a str,
    hint_color: Color,
    accent: Color,
) -> Block<'a> {
    panel(title, accent).title(
        Line::from(Span::styled(
            format!(" {hint} "),
            Style::default().fg(hint_color),
        ))
        .right_aligned(),
    )
}

/// Interpolates green → yellow → red as `t` runs 0..1 (clamped), for
/// "good/warn/bad" coloring of a value against some threshold. `t = 0` is
/// best, `t = 1` is worst.
pub fn gradient(t: f64) -> Color {
    let t = t.clamp(0.0, 1.0);
    let (from, to, local_t) = if t < 0.5 {
        (GREEN, YELLOW, t * 2.0)
    } else {
        (YELLOW, RED, (t - 0.5) * 2.0)
    };
    lerp(from, to, local_t)
}

fn lerp(from: Color, to: Color, t: f64) -> Color {
    let (fr, fg, fb) = rgb(from);
    let (tr, tg, tb) = rgb(to);
    let mix = |a: u8, b: u8| (a as f64 + (b as f64 - a as f64) * t).round() as u8;
    Color::Rgb(mix(fr, tr), mix(fg, tg), mix(fb, tb))
}

fn rgb(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (255, 255, 255),
    }
}

/// The color a [`Confidence`] level reads as everywhere it's shown, so
/// "High" is always the same green whether it's in the Hosting pane's list
/// or an Overview card's pill.
pub fn confidence_color(confidence: Confidence) -> Color {
    match confidence {
        Confidence::High => GREEN,
        Confidence::Medium => YELLOW,
        Confidence::Low => MUTED,
    }
}

/// A small filled badge (colored background, dark text), for statuses that
/// deserve to stand out from the surrounding text (confidence levels,
/// open/closed ports, ...).
pub fn pill(text: impl Into<String>, bg: Color) -> Span<'static> {
    Span::styled(
        format!(" {} ", text.into()),
        Style::default()
            .fg(Color::Rgb(18, 18, 24))
            .bg(bg)
            .add_modifier(Modifier::BOLD),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gradient_endpoints_match_green_and_red() {
        assert_eq!(gradient(0.0), GREEN);
        assert_eq!(gradient(1.0), RED);
    }

    #[test]
    fn gradient_midpoint_is_yellow() {
        assert_eq!(gradient(0.5), YELLOW);
    }

    #[test]
    fn gradient_clamps_out_of_range_input() {
        assert_eq!(gradient(-1.0), gradient(0.0));
        assert_eq!(gradient(5.0), gradient(1.0));
    }
}
