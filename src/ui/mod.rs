//! Rendering only: reads `AppState` and draws it. Never awaits, spawns
//! tasks, or mutates state (architecture rule 1 in `CLAUDE.md`).

pub mod panes;
pub mod tabs;
pub mod theme;
pub mod widgets;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{AppState, Mode};

pub fn draw(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    let frame_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::FAINT))
        .title(Line::from(Span::styled(
            " netloupe ",
            Style::default()
                .fg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )))
        .title(
            Line::from(Span::styled(" ? help ", Style::default().fg(theme::MUTED))).right_aligned(),
        );
    let inner = frame_block.inner(area);
    frame.render_widget(frame_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .margin(0)
        .split(inner);

    tabs::render_host_tabs(frame, chunks[0], state);
    tabs::render_pane_tabs(frame, chunks[1], state);

    match state.active() {
        Some(tab) => panes::render(frame, chunks[2], tab, &state.geoip),
        None => frame.render_widget(
            Paragraph::new("No hosts open. Press Ctrl+t to add one.")
                .style(Style::default().fg(theme::MUTED)),
            chunks[2],
        ),
    }

    render_status_line(frame, chunks[3], state);

    match &state.mode {
        Mode::NewHostPrompt(buf) => render_prompt(frame, area, buf),
        Mode::Help => render_help(frame, area),
        Mode::ConfirmPorts => render_confirm_ports(frame, area),
        Mode::ConfirmZoneWalk => render_confirm_zone_walk(frame, area, state),
        Mode::SelectAltName { names, selected } => {
            render_select_alt_name(frame, area, names, *selected)
        }
        Mode::ChooseResolver { target, input } => {
            render_choose_resolver(frame, area, target, input)
        }
        Mode::Settings {
            draft,
            selected,
            editing,
            message,
        } => render_settings(
            frame,
            area,
            draft,
            *selected,
            editing.as_deref(),
            message.as_deref(),
        ),
        Mode::Normal => {}
    }
}

fn render_status_line(frame: &mut Frame, area: Rect, state: &AppState) {
    let key = |k: &'static str| {
        Span::styled(
            k,
            Style::default()
                .fg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
    };
    let desc = |d: &'static str| Span::styled(d, Style::default().fg(theme::MUTED));
    let sep = || Span::styled("  ", Style::default().fg(theme::FAINT));

    let mut spans = vec![
        key("^T"),
        desc(" new "),
        sep(),
        key("^W"),
        desc(" close "),
        sep(),
        key("Tab"),
        desc(" host "),
        sep(),
        key("←/→"),
        desc(" pane "),
        sep(),
        key("↑/↓"),
        desc(" scroll "),
        sep(),
        key("r"),
        desc(" rerun "),
        sep(),
        key("R"),
        desc(" rerun all "),
        sep(),
    ];

    // Only the keys that actually do something on the pane you're
    // looking at, rather than a fixed list that includes bindings like
    // `w` (zone walk) that are meaningless anywhere but DNS.
    let active_pane = state
        .active()
        .and_then(|tab| crate::app::Pane::ALL.get(tab.active_pane).copied());
    match active_pane {
        Some(crate::app::Pane::Overview) => {
            spans.push(key("a"));
            spans.push(desc(" alt. hosts "));
            spans.push(sep());
        }
        Some(crate::app::Pane::Dns) => {
            spans.push(key("w"));
            spans.push(desc(" zone walk "));
            spans.push(sep());
        }
        Some(crate::app::Pane::Hosting) => {
            spans.push(key("e"));
            spans.push(desc(" evidence "));
            spans.push(sep());
        }
        Some(crate::app::Pane::PingTrace) => {
            spans.push(key("space"));
            spans.push(desc(" pause ping "));
            spans.push(sep());
        }
        _ => {}
    }

    spans.push(key("y"));
    spans.push(desc(" copy "));
    spans.push(sep());
    spans.push(key("s"));
    spans.push(desc(" settings "));
    spans.push(sep());
    spans.push(key("q"));
    spans.push(desc(" quit"));
    if let Some(warning) = &state.data_age_warning {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("⚠ {warning}"),
            Style::default().fg(theme::YELLOW),
        ));
    }

    let geoip_text = state.geoip.status_text();
    let geoip_color = if state.geoip.downloading {
        theme::CYAN
    } else if !state.geoip.configured {
        theme::FAINT
    } else if state.geoip.last_error.is_some() && state.geoip.last_success.is_none() {
        theme::RED
    } else {
        theme::MUTED
    };
    // Split off a fixed-width right column for the GeoIP hint rather than
    // appending it to `spans`, so it stays pinned to the bottom-right
    // corner regardless of how long the keybinding hints on the left are.
    let right_width = geoip_text.chars().count() as u16 + 1;
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(right_width)])
        .split(area);
    frame.render_widget(Line::from(spans), columns[0]);
    frame.render_widget(
        Line::from(Span::styled(geoip_text, Style::default().fg(geoip_color))).right_aligned(),
        columns[1],
    );
}

/// A centered floating box, sized to a fraction of the terminal.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

// One function per popup's geometry, each called from exactly two
// places -- its `render_*` function and its mouse hit-testing in
// `decode_popup_mouse` below -- so the two can never drift apart.
fn new_host_prompt_popup(area: Rect) -> Rect {
    centered_rect(60, 15, area)
}
fn choose_resolver_popup(area: Rect) -> Rect {
    centered_rect(64, 20, area)
}
pub(crate) fn settings_popup(area: Rect) -> Rect {
    centered_rect(76, 80, area)
}
pub(crate) fn confirm_ports_popup(area: Rect) -> Rect {
    centered_rect(62, 30, area)
}
fn confirm_zone_walk_popup(area: Rect) -> Rect {
    centered_rect(62, 32, area)
}
fn select_alt_name_popup(area: Rect) -> Rect {
    centered_rect(64, 60, area)
}
fn help_popup(area: Rect) -> Rect {
    centered_rect(56, 75, area)
}

fn render_prompt(frame: &mut Frame, area: Rect, buf: &str) {
    let popup = new_host_prompt_popup(area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint(
        "New host",
        "enter to open · esc to cancel",
        theme::MUTED,
        theme::CYAN,
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let text = Paragraph::new(Line::from(vec![
        Span::styled("❯ ", Style::default().fg(theme::CYAN)),
        Span::styled(buf, Style::default().fg(theme::TEXT)),
        Span::styled("▏", Style::default().fg(theme::CYAN)),
    ]));
    frame.render_widget(text, inner);
}

fn render_choose_resolver(
    frame: &mut Frame,
    area: Rect,
    target: &crate::target::Target,
    input: &str,
) {
    let popup = choose_resolver_popup(area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint(
        "DNS server",
        "enter to confirm · esc to cancel",
        theme::MUTED,
        theme::CYAN,
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(1)])
        .split(inner);

    let prompt = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Query ", Style::default().fg(theme::MUTED)),
            Span::styled(
                target.display(),
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " using which DNS server?",
                Style::default().fg(theme::MUTED),
            ),
        ]),
        Line::from(Span::styled(
            "blank = system default",
            Style::default().fg(theme::FAINT),
        )),
    ]);
    frame.render_widget(prompt, chunks[0]);

    let text = Paragraph::new(Line::from(vec![
        Span::styled("❯ ", Style::default().fg(theme::CYAN)),
        Span::styled(input, Style::default().fg(theme::TEXT)),
        Span::styled("▏", Style::default().fg(theme::CYAN)),
    ]));
    frame.render_widget(text, chunks[1]);
}

fn render_settings(
    frame: &mut Frame,
    area: Rect,
    draft: &crate::config::Config,
    selected: usize,
    editing: Option<&str>,
    message: Option<&str>,
) {
    let popup = settings_popup(area);
    frame.render_widget(Clear, popup);
    let hint = if editing.is_some() {
        "enter confirm · esc cancel edit"
    } else {
        "↑/↓/click select · enter edit · esc close"
    };
    let block = theme::panel_with_hint("Settings", hint, theme::MUTED, theme::CYAN);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let fields = crate::settings::fields();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(if message.is_some() { 1 } else { 0 }),
        ])
        .split(inner);

    const LABEL_WIDTH: usize = 26;
    let items: Vec<ratatui::widgets::ListItem> = fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let value = if i == selected {
                editing
                    .map(str::to_string)
                    .unwrap_or_else(|| (field.get)(draft))
            } else {
                (field.get)(draft)
            };
            let value = if value.is_empty() {
                "-".to_string()
            } else {
                value
            };
            ratatui::widgets::ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<LABEL_WIDTH$}", field.label),
                    Style::default()
                        .fg(theme::LABEL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(value, Style::default().fg(theme::TEXT)),
            ]))
        })
        .collect();
    let list = ratatui::widgets::List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::Rgb(18, 18, 24))
                .bg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("❯ ");
    let mut list_state = ratatui::widgets::ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(list, chunks[0], &mut list_state);

    let help_text = fields.get(selected).map(|f| f.help).unwrap_or_default();
    let cursor = if editing.is_some() { "▏" } else { "" };
    frame.render_widget(
        Paragraph::new(vec![Line::from(Span::styled(
            format!("{help_text}{cursor}"),
            Style::default().fg(theme::FAINT),
        ))])
        .wrap(Wrap { trim: true }),
        chunks[1],
    );

    if let Some(message) = message {
        let color = if message.starts_with("saved") {
            theme::GREEN
        } else {
            theme::RED
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                message,
                Style::default().fg(color),
            ))),
            chunks[2],
        );
    }
}

/// The exact question text shown (and clicked) for each yes/no prompt --
/// shared between the renderer and `yes_no_hit` so the two can't drift.
pub(crate) const PORTS_QUESTION: &str = "Run the configured port scan against this host?  ";
const ZONE_WALK_QUESTION: &str = "Walk the zone now?  ";

/// The "question  [y] / [N]" spans for a yes/no prompt, used both to
/// render the line and (via `yes_no_hit`) to hit-test clicks on it.
pub(crate) fn yes_no_spans(question: &'static str) -> Vec<Span<'static>> {
    vec![
        Span::styled(question, Style::default().fg(theme::TEXT)),
        Span::styled(
            "[y]",
            Style::default()
                .fg(theme::GREEN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" / "),
        Span::styled(
            "[N]",
            Style::default().fg(theme::RED).add_modifier(Modifier::BOLD),
        ),
    ]
}

/// Which button (`Some(true)` = yes, `Some(false)` = no) `col` (relative
/// to the yes/no line's own left edge) landed on, if any.
fn yes_no_hit(question: &'static str, col: u16) -> Option<bool> {
    let mut x = 0u16;
    for (i, span) in yes_no_spans(question).iter().enumerate() {
        let width = span.width() as u16;
        if (x..x + width).contains(&col) {
            return match i {
                1 => Some(true),
                3 => Some(false),
                _ => None,
            };
        }
        x += width;
    }
    None
}

/// The screen row the yes/no line renders on: the last row of a confirm
/// popup's bordered inner area (see `render_confirm_ports`/
/// `render_confirm_zone_walk`'s `Layout` -- the button line is always
/// the fixed-height final chunk, regardless of how the description text
/// above it wraps), and the column offset (the inner area's own left
/// edge) a click's absolute column needs to subtract before calling
/// `yes_no_hit`.
pub(crate) fn confirm_button_row_and_col_offset(popup: Rect) -> (u16, u16) {
    let inner_y = popup.y + 1;
    let inner_height = popup.height.saturating_sub(2);
    let row = inner_y + inner_height.saturating_sub(1);
    let col_offset = popup.x + 1;
    (row, col_offset)
}

fn render_confirm_ports(frame: &mut Frame, area: Rect) {
    let popup = confirm_ports_popup(area);
    frame.render_widget(Clear, popup);
    let block = theme::panel("⚠ Port scan", theme::ORANGE);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            "Scanning a host's ports without authorization may be illegal",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "(e.g. §202c StGB in Germany).",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "Only scan hosts you own or are authorized to test.",
            Style::default().fg(theme::MUTED),
        )),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(text, chunks[0]);
    frame.render_widget(Line::from(yes_no_spans(PORTS_QUESTION)), chunks[1]);
}

fn render_confirm_zone_walk(frame: &mut Frame, area: Rect, state: &AppState) {
    let popup = confirm_zone_walk_popup(area);
    frame.render_widget(Clear, popup);
    let block = theme::panel("⚠ NSEC zone walk", theme::ORANGE);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);

    let target = state
        .active()
        .map(|t| t.target.display())
        .unwrap_or_default();
    let text = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("{target}'s zone is NSEC-signed, which means its whole set of"),
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "names can be enumerated by following the DNSSEC chain.",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "This sends many (rate-limited, capped) queries to their nameservers —",
            Style::default().fg(theme::MUTED),
        )),
        Line::from(Span::styled(
            "only do this against zones you're authorized to probe.",
            Style::default().fg(theme::MUTED),
        )),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(text, chunks[0]);
    frame.render_widget(Line::from(yes_no_spans(ZONE_WALK_QUESTION)), chunks[1]);
}

fn render_select_alt_name(
    frame: &mut Frame,
    area: Rect,
    names: &[crate::checks::altnames::AltName],
    selected: usize,
) {
    let popup = select_alt_name_popup(area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint(
        "Open alternative host",
        "↑/↓ select · enter/click open · esc cancel",
        theme::MUTED,
        theme::pane_accent(crate::app::Pane::Overview),
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let items: Vec<ratatui::widgets::ListItem> = names
        .iter()
        .map(|n| {
            let sources = n
                .sources
                .iter()
                .map(|s| s.label())
                .collect::<Vec<_>>()
                .join(", ");
            ratatui::widgets::ListItem::new(Line::from(vec![
                Span::styled(n.name.clone(), Style::default().fg(theme::TEXT)),
                Span::styled(format!("  ({sources})"), Style::default().fg(theme::MUTED)),
            ]))
        })
        .collect();
    let list = ratatui::widgets::List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::Rgb(18, 18, 24))
                .bg(theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("❯ ");
    let mut state = ratatui::widgets::ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_help(frame: &mut Frame, area: Rect) {
    // Tall enough that all the rows below actually fit at a standard
    // 24-row terminal (60% of 24 rows, minus the popup's own border,
    // clipped the last couple of rows even before the mouse-support row
    // was added).
    let popup = help_popup(area);
    frame.render_widget(Clear, popup);
    let block = theme::panel_with_hint("Help", "?/esc/click to close", theme::MUTED, theme::PURPLE);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let row = |key: &'static str, desc: &'static str| {
        Line::from(vec![
            Span::styled(
                format!("  {key:<18}"),
                Style::default()
                    .fg(theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(desc, Style::default().fg(theme::TEXT)),
        ])
    };
    let lines = vec![
        row("Ctrl+t / Ctrl+w", "New tab / close tab"),
        row("Tab / Shift+Tab", "Next / previous host tab"),
        row("1-9, 0, -, ←/→", "Switch pane"),
        row("↑/↓, PgUp/PgDn", "Scroll the current pane's content"),
        row("r", "Re-run checks for the current pane"),
        row("R", "Re-run all checks for the current host"),
        row("e", "Toggle evidence details (Hosting pane)"),
        row("a", "Open the alternative-hostname picker (Overview)"),
        row("w", "Walk an NSEC-signed zone for its full name list (DNS)"),
        row("space", "Pause/resume the continuous ping (Ping/Trace)"),
        row("y", "Copy the current pane as text"),
        row("s", "Open the settings editor"),
        row("?", "Help overlay"),
        row("q", "Quit"),
        row(
            "mouse",
            "Click a tab to switch, scroll to scroll (additive)",
        ),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Decodes a mouse event against whichever modal popup `mode` is
/// currently showing. `None` means "not this function's concern" --
/// `app::decode_mouse` falls back to its own Normal-mode tab-bar/scroll
/// logic, which is the right behavior for `Mode::Normal` (no popup at
/// all) and, for the two confirm prompts, mirrors `decode_key`'s
/// identical fallthrough: a click that isn't on the popup's Yes/No
/// buttons should still work as normal navigation, dismissing the
/// prompt without recording a decision (handled by `app.rs`'s existing
/// `(Mode::ConfirmPorts | Mode::ConfirmZoneWalk, action)` arm). Every
/// other mode here is truly modal and always returns `Some(_)`, even to
/// say "consumed, does nothing" -- their content must never leak clicks
/// through to the tab bars underneath.
pub(crate) fn decode_popup_mouse(
    mode: &Mode,
    area: Rect,
    mouse: crossterm::event::MouseEvent,
) -> Option<crate::event::Action> {
    use crate::event::Action;
    use crossterm::event::{MouseButton, MouseEventKind};

    match mode {
        Mode::Normal => None,
        Mode::ConfirmPorts => confirm_click(confirm_ports_popup(area), PORTS_QUESTION, mouse),
        Mode::ConfirmZoneWalk => {
            confirm_click(confirm_zone_walk_popup(area), ZONE_WALK_QUESTION, mouse)
        }
        Mode::Help => Some(match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => Action::InputCancel,
            _ => Action::None,
        }),
        Mode::NewHostPrompt(_) => Some(outside_click_cancels(new_host_prompt_popup(area), mouse)),
        Mode::ChooseResolver { .. } => {
            Some(outside_click_cancels(choose_resolver_popup(area), mouse))
        }
        Mode::SelectAltName { names, selected } => {
            Some(select_alt_name_click(area, names.len(), *selected, mouse))
        }
        Mode::Settings {
            selected,
            editing,
            message,
            ..
        } => Some(settings_click(
            area,
            *selected,
            editing.is_some(),
            message.is_some(),
            mouse,
        )),
    }
}

/// A click on a confirm prompt's Yes/No buttons submits directly;
/// anything else (including a click elsewhere in the popup) returns
/// `None` so the caller falls through to normal navigation, same as
/// pressing any key besides `y`/`n`/Esc there already does.
fn confirm_click(
    popup: Rect,
    question: &'static str,
    mouse: crossterm::event::MouseEvent,
) -> Option<crate::event::Action> {
    use crossterm::event::{MouseButton, MouseEventKind};
    if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        return None;
    }
    let (button_row, col_offset) = confirm_button_row_and_col_offset(popup);
    if mouse.row != button_row {
        return None;
    }
    let local_col = mouse.column.saturating_sub(col_offset);
    match yes_no_hit(question, local_col) {
        Some(true) => Some(crate::event::Action::InputChar('y')),
        Some(false) => Some(crate::event::Action::InputChar('n')),
        None => None,
    }
}

/// A click outside `popup` cancels; a click inside (there's nothing else
/// clickable in a plain text-entry prompt) or any non-click event does
/// nothing.
fn outside_click_cancels(popup: Rect, mouse: crossterm::event::MouseEvent) -> crate::event::Action {
    use crossterm::event::{MouseButton, MouseEventKind};
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if popup.contains((mouse.column, mouse.row).into()) {
                crate::event::Action::None
            } else {
                crate::event::Action::InputCancel
            }
        }
        _ => crate::event::Action::None,
    }
}

/// Approximates the scroll offset ratatui's stateful `List` settles on
/// when asked to keep `selected` visible in a `viewport_height`-row
/// area, starting from an always-fresh (offset 0) `ListState` -- which
/// is what `render_select_alt_name`/`render_settings` construct on every
/// frame. Used to translate a click's screen row back into a list index
/// when there are more items than fit; harmless to get slightly wrong
/// (worst case, a click selects/opens a neighboring row instead of the
/// exact one clicked) rather than something this recomputes perfectly.
fn list_scroll_offset(selected: usize, viewport_height: u16, total: usize) -> usize {
    let height = viewport_height as usize;
    if height == 0 || total <= height || selected < height {
        0
    } else {
        (selected - height + 1).min(total.saturating_sub(height))
    }
}

fn select_alt_name_click(
    area: Rect,
    names_len: usize,
    selected: usize,
    mouse: crossterm::event::MouseEvent,
) -> crate::event::Action {
    use crate::event::Action;
    use crossterm::event::{MouseButton, MouseEventKind};

    let popup = select_alt_name_popup(area);
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if !popup.contains((mouse.column, mouse.row).into()) {
                return Action::InputCancel;
            }
            let list_top = popup.y + 1;
            let list_height = popup.height.saturating_sub(2);
            if mouse.row < list_top {
                return Action::None;
            }
            let offset = list_scroll_offset(selected, list_height, names_len);
            let index = offset + (mouse.row - list_top) as usize;
            if index < names_len {
                Action::SelectIndex(index)
            } else {
                Action::None
            }
        }
        MouseEventKind::ScrollUp => Action::SelectUp,
        MouseEventKind::ScrollDown => Action::SelectDown,
        _ => Action::None,
    }
}

fn settings_click(
    area: Rect,
    selected: usize,
    editing: bool,
    has_message: bool,
    mouse: crossterm::event::MouseEvent,
) -> crate::event::Action {
    use crate::event::Action;
    use crossterm::event::{MouseButton, MouseEventKind};

    let popup = settings_popup(area);
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if !popup.contains((mouse.column, mouse.row).into()) {
                return Action::InputCancel;
            }
            if editing {
                // Don't risk discarding in-progress typed input; the
                // user needs to confirm/cancel the edit via the keyboard
                // first, same as clicking a host/pane tab wouldn't
                // abandon it either.
                return Action::None;
            }
            let list_top = popup.y + 1;
            let field_count = crate::settings::fields().len();
            if mouse.row < list_top {
                return Action::None;
            }
            // Below the list: a fixed Length(2) help-text chunk, plus a
            // Length(1) message chunk only when there's a message to show
            // (see `render_settings`'s own `Layout`).
            let reserved_below = 2 + u16::from(has_message);
            let list_height = popup
                .height
                .saturating_sub(2)
                .saturating_sub(reserved_below);
            let offset = list_scroll_offset(selected, list_height, field_count);
            let index = offset + (mouse.row - list_top) as usize;
            if index < field_count {
                Action::SelectIndex(index)
            } else {
                Action::None
            }
        }
        MouseEventKind::ScrollUp if !editing => Action::SelectUp,
        MouseEventKind::ScrollDown if !editing => Action::SelectDown,
        _ => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::app::{CheckSlot, CheckStatus, Mode, Pane, TabState};
    use crate::checks::acme::{AcmeInfo, CertificateAuthority, ChallengeHint, Dns01Evidence};
    use crate::checks::altnames::{AltName, NameSource};
    use crate::checks::ping::{PingMethod, PingSample, PingUpdate};
    use crate::checks::{CheckId, SharedResultsHandle};
    use crate::config::Config;
    use crate::event::{Action, CheckUpdate};
    use crate::providers::{Confidence, Detection, Evidence, Layer, ProviderDb};
    use crate::target::Target;

    fn empty_tab(id: u64, target: &str) -> TabState {
        TabState {
            id,
            target: Target::parse(target).unwrap(),
            active_pane: 0,
            show_evidence: false,
            cancel: CancellationToken::new(),
            shared: SharedResultsHandle::new(),
            checks: BTreeMap::new(),
            ports_confirmed: None,
            zone_walk_confirmed: None,
            scroll: 0,
            resolver: None,
            ping_paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A tab with real data in a handful of checks, so panes render their
    /// "populated" branches (sparkline, pills, tables) rather than only
    /// the "waiting"/"no data" placeholders.
    fn populated_tab() -> TabState {
        let mut tab = empty_tab(1, "example.com");
        tab.show_evidence = true;

        let mut dns = crate::checks::dns::DnsResult {
            queried_name: "example.com".into(),
            resolver: "system".into(),
            ..Default::default()
        };
        dns.a.push(Ipv4Addr::new(93, 184, 216, 34));
        dns.ns.push("a.iana-servers.net.".into());
        dns.authenticated_data = true;
        tab.checks.insert(
            CheckId::Dns,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Dns(dns)),
            },
        );

        let ping = PingUpdate {
            target_ip: "93.184.216.34".parse().unwrap(),
            method: PingMethod::Icmp,
            samples: vec![
                PingSample {
                    seq: 0,
                    rtt: Some(Duration::from_millis(12)),
                },
                PingSample { seq: 1, rtt: None },
                PingSample {
                    seq: 2,
                    rtt: Some(Duration::from_millis(180)),
                },
            ],
            sent: 3,
            received: 2,
            min: Some(Duration::from_millis(12)),
            max: Some(Duration::from_millis(180)),
            avg: Some(Duration::from_millis(96)),
            fallback_reason: None,
            paused: false,
        };
        tab.checks.insert(
            CheckId::Ping,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Ping(ping)),
            },
        );

        let detection = Detection {
            provider_id: "example-cdn".into(),
            provider_name: "Example CDN".into(),
            layer: Layer::Edge,
            confidence: Confidence::High,
            score: 100,
            evidence: vec![Evidence {
                description: "IP in example-cdn ips-v4".into(),
                weight: 100,
            }],
        };
        tab.checks.insert(
            CheckId::Hosting,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Hosting(vec![detection])),
            },
        );

        tab.checks.insert(
            CheckId::Http,
            CheckSlot {
                status: CheckStatus::Failed("connection refused".into()),
                update: None,
            },
        );

        let tls = crate::checks::tls::TlsResult {
            host: "example.com".into(),
            port: 443,
            protocol_version: Some("TLSv1_3".into()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".into()),
            issuer: Some("C=US, O=Let's Encrypt, CN=R3".into()),
            subject: Some("CN=example.com".into()),
            sans: vec!["*.example.com".into(), "example.com".into()],
            days_until_expiry: Some(42),
            chain_len: 2,
            acme: Some(AcmeInfo {
                authority: CertificateAuthority::LetsEncrypt,
                is_wildcard: true,
                challenge_hint: ChallengeHint::Dns01Certain,
                dns01: Some(Dns01Evidence {
                    txt_values: vec!["abc123".into()],
                    cname_target: None,
                }),
                http01: None,
                note: None,
            }),
            ..Default::default()
        };
        tab.checks.insert(
            CheckId::Tls,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Tls(tls)),
            },
        );

        let alt = crate::checks::altnames::AltNamesResult {
            ips: vec!["93.184.216.34".parse().unwrap()],
            names: vec![
                AltName {
                    name: "www.example.com".into(),
                    sources: vec![NameSource::TlsSan, NameSource::CertificateTransparency],
                },
                AltName {
                    name: "example.net".into(),
                    sources: vec![NameSource::ReverseIp],
                },
            ],
            errors: Vec::new(),
        };
        tab.checks.insert(
            CheckId::AltNames,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::AltNames(alt)),
            },
        );

        let target_ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        let trace = crate::checks::trace::TraceUpdate {
            target_ip,
            method: crate::checks::trace::TraceMethod::TcpConnect { port: 443 },
            hops: vec![
                crate::checks::trace::TraceHop {
                    ttl: 1,
                    addr: Some("10.0.0.1".parse().unwrap()),
                    rtt: Some(Duration::from_millis(2)),
                    provider: None,
                },
                crate::checks::trace::TraceHop {
                    ttl: 2,
                    addr: None,
                    rtt: None,
                    provider: None,
                },
                crate::checks::trace::TraceHop {
                    ttl: 3,
                    addr: Some(target_ip),
                    rtt: Some(Duration::from_millis(28)),
                    provider: Some("Example CDN".into()),
                },
            ],
            reached: true,
            fallback_reason: Some(
                "no ICMP socket available; running a simple TCP-connect TTL sweep instead".into(),
            ),
        };
        tab.checks.insert(
            CheckId::Trace,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Trace(trace)),
            },
        );

        let geo = crate::checks::geo::GeoResult {
            ip: Some(target_ip),
            country: Some("United States".into()),
            country_code: Some("US".into()),
            region: Some("Virginia".into()),
            city: Some("Norfolk".into()),
            lat: Some(36.8508),
            lon: Some(-76.2859),
            timezone: Some("America/New_York".into()),
            asn_org: Some("Example Org".into()),
            accuracy_hint: Some("city-level"),
            errors: Vec::new(),
        };
        tab.checks.insert(
            CheckId::Geo,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::Geo(geo)),
            },
        );

        tab
    }

    fn render_at(width: u16, height: u16, f: impl FnOnce(&mut ratatui::Frame)) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| f(frame)).unwrap();
    }

    #[test]
    fn draws_with_no_tabs_open_at_several_sizes() {
        let state = AppState::new(Config::default(), ProviderDb::default());
        for (w, h) in [(80, 24), (120, 40), (40, 10)] {
            render_at(w, h, |frame| draw(frame, &state));
        }
    }

    #[test]
    fn every_pane_renders_without_data_at_a_realistic_size() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(empty_tab(1, "example.com"));
        for i in 0..Pane::ALL.len() {
            state.tabs[0].active_pane = i;
            render_at(120, 40, |frame| draw(frame, &state));
        }
    }

    #[test]
    fn every_pane_renders_with_populated_data_at_a_realistic_size() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        for i in 0..Pane::ALL.len() {
            state.tabs[0].active_pane = i;
            render_at(120, 40, |frame| draw(frame, &state));
        }
    }

    #[test]
    fn overview_pane_shows_the_target_host() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let content = buffer_to_string(terminal.backend().buffer());
        assert!(
            content.contains("example.com"),
            "expected the target host to appear somewhere on screen"
        );
        assert!(
            content.contains("Example CDN"),
            "expected the hosting detection to appear in the dashboard"
        );
    }

    /// The GeoIP status must be visible both pinned to the bottom-right
    /// of the status line and at the top of the Geo pane -- the two
    /// places `render_status_line`/`geo::render` were changed to surface
    /// `AppState::geoip`.
    #[test]
    fn geoip_status_appears_on_the_status_line_and_the_geo_pane() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.geoip = crate::geoip::GeoipStatus {
            configured: true,
            downloading: false,
            last_success: Some(std::time::SystemTime::now() - Duration::from_secs(3 * 3600)),
            last_error: None,
        };
        state.tabs.push(empty_tab(1, "example.com"));
        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Geo).unwrap();

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let content = buffer_to_string(terminal.backend().buffer());
        assert_eq!(
            content.matches("GeoIP: 3h old").count(),
            2,
            "expected the status text once on the status line and once in the Geo pane: {content}"
        );
    }

    /// Once a check has a coordinate, the Geo pane must show the world
    /// map (see `worldmap::render_map`) with a pinpoint on it, not just
    /// the plain country/city table.
    #[test]
    fn geo_pane_renders_a_map_with_a_pin_when_coordinates_are_present() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Geo).unwrap();

        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let content = buffer_to_string(terminal.backend().buffer());
        assert!(
            content.contains("Map"),
            "expected the map sub-panel title: {content}"
        );
        assert!(
            content.contains('◉'),
            "expected the pinpoint glyph somewhere on screen: {content}"
        );
    }

    /// The status line's keybinding hints should only include a pane-
    /// specific action (zone walk, evidence, alt. hosts, pause ping) when
    /// that pane is actually active -- a fixed list would show `w` on
    /// every pane even though it only does anything on DNS.
    #[test]
    fn status_line_only_shows_the_active_panes_keybinding() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());

        let status_line_for = |state: &AppState| -> String {
            let backend = TestBackend::new(160, 40);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, state)).unwrap();
            buffer_to_string(terminal.backend().buffer())
                .lines()
                .find(|l| l.contains("^T"))
                .unwrap()
                .to_string()
        };

        for (pane, present, absent) in [
            (Pane::Overview, "alt. hosts", "zone walk"),
            (Pane::Dns, "zone walk", "evidence"),
            (Pane::Hosting, "evidence", "pause ping"),
            (Pane::PingTrace, "pause ping", "alt. hosts"),
            (Pane::Rep, "quit", "zone walk"),
        ] {
            state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == pane).unwrap();
            let line = status_line_for(&state);
            assert!(
                line.contains(present),
                "{pane:?} should show {present:?}: {line}"
            );
            assert!(
                !line.contains(absent),
                "{pane:?} shouldn't show {absent:?}: {line}"
            );
        }
    }

    #[test]
    fn renders_at_a_very_small_terminal_without_panicking() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        render_at(20, 6, |frame| draw(frame, &state));
    }

    #[test]
    fn overlays_render_without_panicking() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());

        for mode in [
            Mode::NewHostPrompt("exa".to_string()),
            Mode::Help,
            Mode::ConfirmPorts,
            Mode::SelectAltName {
                names: vec![
                    AltName {
                        name: "www.example.com".into(),
                        sources: vec![NameSource::TlsSan],
                    },
                    AltName {
                        name: "example.net".into(),
                        sources: vec![NameSource::ReverseIp, NameSource::Ptr],
                    },
                ],
                selected: 1,
            },
            Mode::ChooseResolver {
                target: Target::parse("example.com").unwrap(),
                input: "1.1.1.1".to_string(),
            },
            Mode::Settings {
                draft: Box::new(Config::default()),
                selected: 0,
                editing: None,
                message: None,
            },
            Mode::Settings {
                draft: Box::new(Config::default()),
                selected: 2,
                editing: Some("in progress".to_string()),
                message: Some("not a duration".to_string()),
            },
        ] {
            state.mode = mode;
            render_at(100, 30, |frame| draw(frame, &state));
            render_at(20, 6, |frame| draw(frame, &state));
        }
    }

    fn buffer_to_string(buffer: &ratatui::buffer::Buffer) -> String {
        let area = buffer.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Not a real assertion — run with `--ignored --nocapture` to eyeball
    /// a pane's layout as plain text while iterating on styling.
    #[test]
    #[ignore]
    fn dump_overview_and_hosting() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.tabs.push(populated_tab());
        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Overview).unwrap();

        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
        println!("{}", buffer_to_string(terminal.backend().buffer()));

        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Hosting).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
        println!("{}", buffer_to_string(terminal.backend().buffer()));

        state.tabs[0].active_pane = Pane::ALL.iter().position(|&p| p == Pane::Geo).unwrap();
        terminal.draw(|frame| draw(frame, &state)).unwrap();
        println!("{}", buffer_to_string(terminal.backend().buffer()));
    }

    fn left_click(row: u16, column: u16) -> crossterm::event::MouseEvent {
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column,
            row,
            modifiers: crossterm::event::KeyModifiers::NONE,
        }
    }

    #[test]
    fn yes_no_hit_finds_yes_no_and_neither() {
        let spans = yes_no_spans(PORTS_QUESTION);
        let yes_col = spans[0].width() as u16; // right after the question text
        let no_col = yes_col + spans[1].width() as u16 + spans[2].width() as u16;
        assert_eq!(yes_no_hit(PORTS_QUESTION, yes_col), Some(true));
        assert_eq!(yes_no_hit(PORTS_QUESTION, no_col), Some(false));
        assert_eq!(
            yes_no_hit(PORTS_QUESTION, 0),
            None,
            "lands on the question text itself"
        );
    }

    #[test]
    fn confirm_click_only_fires_on_the_button_row() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = confirm_ports_popup(area);
        let (button_row, col_offset) = confirm_button_row_and_col_offset(popup);
        let yes_col = col_offset + yes_no_spans(PORTS_QUESTION)[0].width() as u16;

        assert_eq!(
            confirm_click(popup, PORTS_QUESTION, left_click(button_row, yes_col)),
            Some(Action::InputChar('y'))
        );
        // One row above the button: inside the popup, but not the
        // button row -- falls through (None), same as any other click
        // that doesn't land on a button.
        assert_eq!(
            confirm_click(popup, PORTS_QUESTION, left_click(button_row - 1, yes_col)),
            None
        );
    }

    #[test]
    fn outside_click_cancels_only_when_truly_outside() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = new_host_prompt_popup(area);
        assert_eq!(
            outside_click_cancels(popup, left_click(popup.y, popup.x)),
            Action::None,
            "inside the popup"
        );
        assert_eq!(
            outside_click_cancels(popup, left_click(0, 0)),
            Action::InputCancel,
            "the far corner is outside every popup on a 100x40 terminal"
        );
    }

    #[test]
    fn list_scroll_offset_only_scrolls_once_selection_outgrows_the_viewport() {
        assert_eq!(list_scroll_offset(0, 10, 5), 0, "fewer items than fit");
        assert_eq!(
            list_scroll_offset(3, 10, 20),
            0,
            "selection still on-screen"
        );
        assert_eq!(
            list_scroll_offset(15, 10, 20),
            6,
            "selection past the viewport pulls the list up to keep it visible"
        );
    }

    #[test]
    fn select_alt_name_click_selects_and_opens_the_clicked_row() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = select_alt_name_popup(area);
        let second_row = popup.y + 1 + 1; // inner top, then the 2nd item
        assert_eq!(
            select_alt_name_click(area, 5, 0, left_click(second_row, popup.x + 2)),
            Action::SelectIndex(1)
        );
    }

    #[test]
    fn select_alt_name_click_outside_the_popup_cancels() {
        let area = Rect::new(0, 0, 100, 40);
        assert_eq!(
            select_alt_name_click(area, 5, 0, left_click(0, 0)),
            Action::InputCancel
        );
    }

    #[test]
    fn settings_click_opens_the_clicked_field_when_not_editing() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = settings_popup(area);
        let third_row = popup.y + 1 + 2; // inner top, then the 3rd field
        assert_eq!(
            settings_click(area, 0, false, false, left_click(third_row, popup.x + 2)),
            Action::SelectIndex(2)
        );
    }

    #[test]
    fn settings_click_is_a_no_op_while_editing_to_avoid_losing_input() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = settings_popup(area);
        let third_row = popup.y + 1 + 2;
        assert_eq!(
            settings_click(area, 0, true, false, left_click(third_row, popup.x + 2)),
            Action::None
        );
    }

    #[test]
    fn decode_popup_mouse_is_none_for_normal_mode() {
        let area = Rect::new(0, 0, 100, 40);
        assert_eq!(
            decode_popup_mouse(&Mode::Normal, area, left_click(5, 5)),
            None
        );
    }

    #[test]
    fn decode_popup_mouse_closes_help_on_any_click() {
        let area = Rect::new(0, 0, 100, 40);
        assert_eq!(
            decode_popup_mouse(&Mode::Help, area, left_click(0, 0)),
            Some(Action::InputCancel)
        );
    }
}
