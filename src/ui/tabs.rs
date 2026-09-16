//! The two tab bars: host tabs across the top (`[ example.com ] [ 8.8.8.8 ]
//! [+]`) and the pane sub-tabs below them.
//!
//! Label-building is factored out (`host_tab_labels`/`pane_tab_labels`) so
//! the mouse hit-testing in `app.rs` (`host_tab_at`/`pane_tab_at`/
//! `new_tab_label_at`) walks the exact same widths the renderer draws,
//! rather than a second, easily-drifting copy of the same layout math.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use super::theme;
use crate::app::{AppState, Pane};

fn host_tab_labels(state: &AppState) -> Vec<String> {
    state
        .tabs
        .iter()
        .map(|tab| format!(" {} ", tab.target.display()))
        .collect()
}

fn pane_tab_labels() -> Vec<String> {
    Pane::ALL
        .iter()
        .map(|p| format!(" {} ", p.label()))
        .collect()
}

pub fn render_host_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let labels = host_tab_labels(state);
    let mut spans: Vec<Span> = Vec::new();
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        if i == state.active_tab {
            spans.push(theme::pill(state.tabs[i].target.display(), theme::CYAN));
        } else {
            spans.push(Span::styled(
                label.clone(),
                Style::default().fg(theme::MUTED),
            ));
        }
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        NEW_TAB_LABEL,
        Style::default().fg(theme::FAINT),
    ));
    frame.render_widget(Line::from(spans), area);
}

pub fn render_pane_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let Some(tab) = state.active() else {
        frame.render_widget(Line::from(""), area);
        return;
    };
    let labels = pane_tab_labels();
    let mut spans: Vec<Span> = Vec::new();
    for (i, (&pane, label)) in Pane::ALL.iter().zip(labels.iter()).enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ", Style::default()));
        }
        let accent = theme::pane_accent(pane);
        if i == tab.active_pane {
            spans.push(theme::pill(pane.label(), accent));
        } else {
            spans.push(Span::styled(
                label.clone(),
                Style::default().fg(accent).add_modifier(Modifier::DIM),
            ));
        }
    }
    frame.render_widget(Line::from(spans), area);
}

const NEW_TAB_LABEL: &str = "+ new";

/// The host-tab index whose rendered span covers `col` (0-based, relative
/// to the tab bar's own left edge -- i.e. already offset past the outer
/// frame border), or `None` if `col` lands on a separator or past the
/// last tab.
pub fn host_tab_at(state: &AppState, col: u16) -> Option<usize> {
    let mut x: u16 = 0;
    for (i, label) in host_tab_labels(state).iter().enumerate() {
        if i > 0 {
            x += 1; // the " " separator between tabs
        }
        let width = Span::raw(label.as_str()).width() as u16;
        if (x..x + width).contains(&col) {
            return Some(i);
        }
        x += width;
    }
    None
}

/// Whether `col` landed on the "+ new" label at the end of the host-tab
/// bar.
pub fn new_tab_label_at(state: &AppState, col: u16) -> bool {
    let mut x: u16 = 0;
    for (i, label) in host_tab_labels(state).iter().enumerate() {
        if i > 0 {
            x += 1;
        }
        x += Span::raw(label.as_str()).width() as u16;
    }
    x += 2; // the "  " gap rendered before "+ new"
    let width = Span::raw(NEW_TAB_LABEL).width() as u16;
    (x..x + width).contains(&col)
}

/// The pane-tab index whose rendered span covers `col`, or `None`.
pub fn pane_tab_at(col: u16) -> Option<usize> {
    let mut x: u16 = 0;
    for (i, label) in pane_tab_labels().iter().enumerate() {
        if i > 0 {
            x += 1;
        }
        let width = Span::raw(label.as_str()).width() as u16;
        if (x..x + width).contains(&col) {
            return Some(i);
        }
        x += width;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::app::TabState;
    use crate::checks::SharedResultsHandle;
    use crate::config::Config;
    use crate::providers::ProviderDb;
    use crate::target::Target;

    /// A minimal tab with no running checks -- plain construction rather
    /// than `AppState::open_tab`, which spawns real check tasks and so
    /// needs a Tokio runtime this plain `#[test]` module doesn't have.
    fn bare_tab(id: u64, host: &str) -> TabState {
        TabState {
            id,
            target: Target::parse(host).unwrap(),
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

    fn state_with_hosts(hosts: &[&str]) -> AppState {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        for (i, host) in hosts.iter().enumerate() {
            state.tabs.push(bare_tab(i as u64, host));
        }
        state
    }

    #[test]
    fn host_tab_at_finds_each_tab_and_the_gap_between_them() {
        let state = state_with_hosts(&["a.com", "b.com"]);
        // " a.com " is 7 cells wide, then a 1-cell separator, then
        // " b.com " starts at column 8.
        assert_eq!(host_tab_at(&state, 0), Some(0));
        assert_eq!(host_tab_at(&state, 6), Some(0));
        assert_eq!(host_tab_at(&state, 7), None, "the separator column");
        assert_eq!(host_tab_at(&state, 8), Some(1));
    }

    #[test]
    fn new_tab_label_at_finds_the_label_after_every_host_tab() {
        let state = state_with_hosts(&["a.com"]);
        // " a.com " (7) + "  " (2) = 9; "+ new" starts at column 9.
        assert!(!new_tab_label_at(&state, 8));
        assert!(new_tab_label_at(&state, 9));
        assert!(new_tab_label_at(&state, 9 + NEW_TAB_LABEL.len() as u16 - 1));
        assert!(!new_tab_label_at(&state, 9 + NEW_TAB_LABEL.len() as u16));
    }

    #[test]
    fn new_tab_label_at_with_no_hosts_starts_right_after_the_gap() {
        let state = state_with_hosts(&[]);
        assert!(!new_tab_label_at(&state, 1));
        assert!(new_tab_label_at(&state, 2));
    }

    #[test]
    fn pane_tab_at_finds_the_first_and_a_later_pane() {
        assert_eq!(pane_tab_at(0), Some(0));
        let first_width = Span::raw(pane_tab_labels()[0].as_str()).width() as u16;
        assert_eq!(pane_tab_at(first_width), None, "the separator column");
        assert_eq!(pane_tab_at(first_width + 1), Some(1));
    }

    #[test]
    fn pane_tab_at_returns_none_past_the_last_tab() {
        let total_width: u16 = pane_tab_labels()
            .iter()
            .map(|l| Span::raw(l.as_str()).width() as u16 + 1)
            .sum();
        assert_eq!(pane_tab_at(total_width + 5), None);
    }
}
