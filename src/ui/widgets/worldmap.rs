//! Renders a `worldmap::MapGrid` (see `crate::worldmap`, which does all
//! the actual projection/zoom/labeling logic) as styled text: coastline
//! dots muted, country-border dots fainter still, the pinpoint bright and
//! unmistakable, city labels in plain readable text.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::ui::theme;
use crate::worldmap::{Cell, MapGrid};

pub fn widget(grid: &MapGrid) -> Paragraph<'static> {
    let mut lines = Vec::with_capacity(grid.height as usize);
    for row in 0..grid.height {
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut col = 0u16;
        while col < grid.width {
            match grid.get(row, col) {
                Cell::Empty => {
                    spans.push(Span::raw(" "));
                    col += 1;
                }
                Cell::Coast => {
                    spans.push(Span::styled("·", Style::default().fg(theme::MUTED)));
                    col += 1;
                }
                Cell::Border => {
                    spans.push(Span::styled("·", Style::default().fg(theme::FAINT)));
                    col += 1;
                }
                Cell::Pin => {
                    spans.push(Span::styled(
                        "◉",
                        Style::default()
                            .fg(theme::YELLOW)
                            .add_modifier(Modifier::BOLD),
                    ));
                    col += 1;
                }
                Cell::CityDot => {
                    spans.push(Span::styled(
                        "•",
                        Style::default()
                            .fg(theme::CYAN)
                            .add_modifier(Modifier::BOLD),
                    ));
                    col += 1;
                }
                Cell::CityLabel(_) => {
                    // One span per contiguous run of label characters,
                    // rather than one span per character.
                    let mut text = String::new();
                    while col < grid.width {
                        let Cell::CityLabel(c) = grid.get(row, col) else {
                            break;
                        };
                        text.push(c);
                        col += 1;
                    }
                    spans.push(Span::styled(text, Style::default().fg(theme::TEXT)));
                }
            }
        }
        lines.push(Line::from(spans));
    }
    Paragraph::new(lines)
}
