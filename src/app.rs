//! `AppState`, tab management, and the event loop.
//!
//! This is the only place that mutates `AppState` (architecture rule 3):
//! it applies incoming `CheckEvent`s and turns key presses into `Action`s
//! which are applied here too. `ui::*` only ever reads this state.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ratatui::DefaultTerminal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::checks::{self, CheckContext, CheckId, SharedResultsHandle};
use crate::config::Config;
use crate::event::{Action, CheckEvent, CheckPayload, CheckUpdate};
use crate::providers::ProviderDb;
use crate::target::Target;

/// One pane, in the display/tab order from `CLAUDE.md`'s pane table.
/// Ping and Trace are separate checks (they can fail/re-run independently)
/// but share one pane, matching the mockup's "Ping/Trace" column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Overview,
    Dns,
    Mail,
    PingTrace,
    Ports,
    Tls,
    Http,
    IpAsn,
    Hosting,
    Geo,
    Rep,
}

impl Pane {
    pub const ALL: [Pane; 11] = [
        Pane::Overview,
        Pane::Dns,
        Pane::Mail,
        Pane::PingTrace,
        Pane::Ports,
        Pane::Tls,
        Pane::Http,
        Pane::IpAsn,
        Pane::Hosting,
        Pane::Geo,
        Pane::Rep,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Pane::Overview => "Overview",
            Pane::Dns => "DNS",
            Pane::Mail => "Mail",
            Pane::PingTrace => "Ping/Trace",
            Pane::Ports => "Ports",
            Pane::Tls => "TLS",
            Pane::Http => "HTTP",
            Pane::IpAsn => "IP/ASN",
            Pane::Hosting => "Hosting",
            Pane::Geo => "Geo",
            Pane::Rep => "Rep",
        }
    }

    /// The checks whose results this pane renders.
    pub fn checks(self) -> &'static [CheckId] {
        match self {
            Pane::Overview => &[
                CheckId::Dns,
                CheckId::IpInfo,
                CheckId::Hosting,
                CheckId::Tls,
                CheckId::Mail,
                CheckId::Ping,
                CheckId::AltNames,
            ],
            Pane::Dns => &[CheckId::Dns],
            Pane::Mail => &[CheckId::Mail],
            Pane::PingTrace => &[CheckId::Ping, CheckId::Trace],
            Pane::Ports => &[CheckId::Ports],
            Pane::Tls => &[CheckId::Tls],
            Pane::Http => &[CheckId::Http],
            Pane::IpAsn => &[CheckId::IpInfo],
            Pane::Hosting => &[CheckId::Hosting],
            Pane::Geo => &[CheckId::Geo],
            Pane::Rep => &[CheckId::Reputation],
        }
    }

    fn from_index(i: usize) -> Option<Pane> {
        Pane::ALL.get(i).copied()
    }
}

/// A check's run status for one tab, independent of its actual data (kept
/// in `CheckUpdate` separately so the last-known-good result stays visible
/// while a re-run is in flight).
#[derive(Debug, Clone, Default, PartialEq)]
pub enum CheckStatus {
    #[default]
    NotStarted,
    Running,
    Done,
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone, Default)]
pub struct CheckSlot {
    pub status: CheckStatus,
    pub update: Option<CheckUpdate>,
}

/// One open host tab.
pub struct TabState {
    pub id: u64,
    pub target: Target,
    pub active_pane: usize,
    pub show_evidence: bool,
    pub cancel: CancellationToken,
    pub shared: SharedResultsHandle,
    pub checks: BTreeMap<CheckId, CheckSlot>,
    /// Ports scanning needs an explicit yes before it ever runs (safety:
    /// see `CLAUDE.md`). `None` = not asked yet this tab.
    pub ports_confirmed: Option<bool>,
}

impl TabState {
    pub fn slot(&self, id: CheckId) -> &CheckSlot {
        static EMPTY: std::sync::OnceLock<CheckSlot> = std::sync::OnceLock::new();
        self.checks
            .get(&id)
            .unwrap_or_else(|| EMPTY.get_or_init(CheckSlot::default))
    }
}

/// What the UI is doing besides showing tabs/panes.
pub enum Mode {
    Normal,
    NewHostPrompt(String),
    Help,
    /// Asking whether to run the opt-in port scan for the active tab.
    ConfirmPorts,
    /// Browsing the active tab's discovered alternative hostnames
    /// (`CheckId::AltNames`); Enter opens a new tab for the selected one.
    SelectAltName {
        names: Vec<crate::checks::altnames::AltName>,
        selected: usize,
    },
}

pub struct AppState {
    pub tabs: Vec<TabState>,
    pub active_tab: usize,
    pub mode: Mode,
    pub should_quit: bool,
    pub config: Arc<Config>,
    pub providers: Arc<ProviderDb>,
    pub data_age_warning: Option<String>,
    next_tab_id: AtomicU64,
}

impl AppState {
    pub fn new(config: Config, providers: ProviderDb) -> Self {
        Self {
            tabs: Vec::new(),
            active_tab: 0,
            mode: Mode::Normal,
            should_quit: false,
            config: Arc::new(config),
            providers: Arc::new(providers),
            data_age_warning: None,
            next_tab_id: AtomicU64::new(1),
        }
    }

    pub fn active(&self) -> Option<&TabState> {
        self.tabs.get(self.active_tab)
    }

    /// Opens a new tab for `target` and spawns every non-opt-in check for
    /// it, tagged with `sender` so their events route back to this tab.
    pub fn open_tab(&mut self, target: Target, sender: &mpsc::Sender<CheckEvent>) {
        let id = self.next_tab_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        let shared = SharedResultsHandle::new();

        let tab = TabState {
            id,
            target: target.clone(),
            active_pane: 0,
            show_evidence: false,
            cancel: cancel.clone(),
            shared: shared.clone(),
            checks: BTreeMap::new(),
            ports_confirmed: None,
        };
        self.tabs.push(tab);
        self.active_tab = self.tabs.len() - 1;

        self.spawn_checks(id, target, cancel, shared, sender.clone(), false);
    }

    fn spawn_checks(
        &self,
        tab_id: u64,
        target: Target,
        cancel: CancellationToken,
        shared: SharedResultsHandle,
        sender: mpsc::Sender<CheckEvent>,
        include_opt_in: bool,
    ) {
        for check in checks::registry() {
            if check.id().requires_opt_in() && !include_opt_in {
                continue;
            }
            let ctx = CheckContext {
                tab_id,
                target: target.clone(),
                port: None,
                config: self.config.clone(),
                cancel: cancel.clone(),
                shared: shared.clone(),
                providers: self.providers.clone(),
            };
            let tx = sender.clone();
            tokio::spawn(async move { check.run(ctx, tx).await });
        }
    }

    /// Re-runs one pane's check(s) for the active tab, cancelling and
    /// replacing any still running (architecture rule 4).
    pub fn rerun_pane(&mut self, sender: &mpsc::Sender<CheckEvent>) {
        let Some(tab) = self.tabs.get(self.active_tab) else {
            return;
        };
        let pane = Pane::from_index(tab.active_pane).unwrap_or(Pane::Overview);
        let tab_id = tab.id;
        let target = tab.target.clone();
        let cancel = tab.cancel.clone();
        let shared = tab.shared.clone();

        for &check_id in pane.checks() {
            if check_id.requires_opt_in() {
                continue; // Ports re-runs only via the confirmation flow.
            }
            self.spawn_one_check(
                check_id,
                tab_id,
                target.clone(),
                cancel.clone(),
                shared.clone(),
                sender.clone(),
            );
        }
    }

    /// Re-runs every check for the active tab.
    pub fn rerun_all(&mut self, sender: &mpsc::Sender<CheckEvent>) {
        let Some(tab) = self.tabs.get(self.active_tab) else {
            return;
        };
        let tab_id = tab.id;
        let target = tab.target.clone();
        let cancel = tab.cancel.clone();
        let shared = tab.shared.clone();
        let include_ports = tab.ports_confirmed == Some(true);
        self.spawn_checks(
            tab_id,
            target,
            cancel,
            shared,
            sender.clone(),
            include_ports,
        );
    }

    fn spawn_one_check(
        &self,
        check_id: CheckId,
        tab_id: u64,
        target: Target,
        cancel: CancellationToken,
        shared: SharedResultsHandle,
        sender: mpsc::Sender<CheckEvent>,
    ) {
        if let Some(check) = checks::registry().into_iter().find(|c| c.id() == check_id) {
            let ctx = CheckContext {
                tab_id,
                target,
                port: None,
                config: self.config.clone(),
                cancel,
                shared,
                providers: self.providers.clone(),
            };
            tokio::spawn(async move { check.run(ctx, sender).await });
        }
    }

    /// Confirms (or declines) running the Ports check for the active tab.
    pub fn confirm_ports(&mut self, confirmed: bool, sender: &mpsc::Sender<CheckEvent>) {
        let Some(tab) = self.tabs.get_mut(self.active_tab) else {
            return;
        };
        tab.ports_confirmed = Some(confirmed);
        if !confirmed {
            return;
        }
        let tab_id = tab.id;
        let target = tab.target.clone();
        let cancel = tab.cancel.clone();
        let shared = tab.shared.clone();
        self.spawn_one_check(
            CheckId::Ports,
            tab_id,
            target,
            cancel,
            shared,
            sender.clone(),
        );
    }

    pub fn close_active_tab(&mut self) {
        if self.tabs.is_empty() {
            return;
        }
        let tab = self.tabs.remove(self.active_tab);
        tab.cancel.cancel();
        if self.active_tab >= self.tabs.len() && !self.tabs.is_empty() {
            self.active_tab = self.tabs.len() - 1;
        }
    }

    /// Applies one check event to whichever tab it's tagged with. Events
    /// for a since-closed tab are dropped silently.
    pub fn apply_check_event(&mut self, event: CheckEvent) {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.id == event.tab_id) else {
            return;
        };
        let slot = tab.checks.entry(event.check).or_default();
        match event.payload {
            CheckPayload::Started => slot.status = CheckStatus::Running,
            CheckPayload::Progress(update) => {
                slot.status = CheckStatus::Running;
                slot.update = Some(update);
            }
            CheckPayload::Done(update) => {
                slot.status = CheckStatus::Done;
                slot.update = Some(update);
            }
            CheckPayload::Failed(message) => slot.status = CheckStatus::Failed(message),
            CheckPayload::Cancelled => slot.status = CheckStatus::Cancelled,
        }
    }

    fn handle_action(&mut self, action: Action, sender: &mpsc::Sender<CheckEvent>) {
        match (&mut self.mode, action) {
            (Mode::NewHostPrompt(buf), Action::InputChar(c)) => buf.push(c),
            (Mode::NewHostPrompt(buf), Action::InputBackspace) => {
                buf.pop();
            }
            (Mode::NewHostPrompt(buf), Action::InputSubmit) => {
                if let Ok(target) = Target::parse(buf.trim()) {
                    self.mode = Mode::Normal;
                    self.open_tab(target, sender);
                } else {
                    buf.clear();
                }
            }
            (Mode::NewHostPrompt(_), Action::InputCancel) => self.mode = Mode::Normal,
            (Mode::Help, Action::ToggleHelp) | (Mode::Help, Action::InputCancel) => {
                self.mode = Mode::Normal
            }
            (Mode::ConfirmPorts, Action::InputChar('y')) => {
                self.mode = Mode::Normal;
                self.confirm_ports(true, sender);
            }
            (Mode::ConfirmPorts, Action::InputChar('n'))
            | (Mode::ConfirmPorts, Action::InputCancel) => {
                self.mode = Mode::Normal;
                self.confirm_ports(false, sender);
            }
            (Mode::SelectAltName { selected, .. }, Action::SelectUp) => {
                *selected = selected.saturating_sub(1);
            }
            (Mode::SelectAltName { names, selected }, Action::SelectDown) => {
                if *selected + 1 < names.len() {
                    *selected += 1;
                }
            }
            (Mode::SelectAltName { names, selected }, Action::InputSubmit) => {
                if let Some(target) = names
                    .get(*selected)
                    .and_then(|n| Target::parse(&n.name).ok())
                {
                    self.mode = Mode::Normal;
                    self.open_tab(target, sender);
                }
            }
            (Mode::SelectAltName { .. }, Action::InputCancel) => self.mode = Mode::Normal,
            (Mode::Normal, action) => self.handle_normal_action(action, sender),
            _ => {}
        }
    }

    fn handle_normal_action(&mut self, action: Action, sender: &mpsc::Sender<CheckEvent>) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::NewTab => self.mode = Mode::NewHostPrompt(String::new()),
            Action::CloseTab => self.close_active_tab(),
            Action::NextTab => {
                if !self.tabs.is_empty() {
                    self.active_tab = (self.active_tab + 1) % self.tabs.len();
                }
            }
            Action::PrevTab => {
                if !self.tabs.is_empty() {
                    self.active_tab = (self.active_tab + self.tabs.len() - 1) % self.tabs.len();
                }
            }
            Action::SelectPane(i) => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    if i < Pane::ALL.len() {
                        tab.active_pane = i;
                        self.maybe_prompt_ports();
                    }
                }
            }
            Action::NextPane => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    tab.active_pane = (tab.active_pane + 1) % Pane::ALL.len();
                }
                self.maybe_prompt_ports();
            }
            Action::PrevPane => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    tab.active_pane = (tab.active_pane + Pane::ALL.len() - 1) % Pane::ALL.len();
                }
                self.maybe_prompt_ports();
            }
            Action::RerunPane => {
                if self.current_pane() == Some(Pane::Ports) {
                    self.maybe_prompt_ports();
                } else {
                    self.rerun_pane(sender);
                }
            }
            Action::RerunAll => self.rerun_all(sender),
            Action::ToggleEvidence => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    tab.show_evidence = !tab.show_evidence;
                }
            }
            Action::ToggleHelp => self.mode = Mode::Help,
            Action::OpenAltNames => self.open_alt_names_picker(),
            Action::CopyPane => {} // clipboard support is a later addition; no-op for now.
            _ => {}
        }
    }

    /// Opens the alternative-hostname picker for the active tab, if it has
    /// found anything to pick from yet. A no-op otherwise (rather than an
    /// empty popup), since there's nothing useful to select.
    fn open_alt_names_picker(&mut self) {
        let Some(tab) = self.active() else { return };
        let Some(CheckUpdate::AltNames(alt)) = &tab.slot(CheckId::AltNames).update else {
            return;
        };
        if alt.names.is_empty() {
            return;
        }
        self.mode = Mode::SelectAltName {
            names: alt.names.clone(),
            selected: 0,
        };
    }

    fn current_pane(&self) -> Option<Pane> {
        self.active().and_then(|t| Pane::from_index(t.active_pane))
    }

    /// Switching to the Ports pane for the first time this tab asks for
    /// confirmation before ever sending a probe.
    fn maybe_prompt_ports(&mut self) {
        if self.current_pane() != Some(Pane::Ports) {
            return;
        }
        if let Some(tab) = self.active() {
            if tab.ports_confirmed.is_none() {
                self.mode = Mode::ConfirmPorts;
            }
        }
    }
}

/// Decodes a raw crossterm key event into an [`Action`], depending on the
/// current mode (typing in the new-host prompt takes over the keyboard).
fn decode_key(mode: &Mode, key: crossterm::event::KeyEvent) -> Action {
    use crossterm::event::KeyCode;
    if key.kind == crossterm::event::KeyEventKind::Release {
        return Action::None;
    }

    match mode {
        Mode::NewHostPrompt(_) => match key.code {
            KeyCode::Char(c) => Action::InputChar(c),
            KeyCode::Backspace => Action::InputBackspace,
            KeyCode::Enter => Action::InputSubmit,
            KeyCode::Esc => Action::InputCancel,
            _ => Action::None,
        },
        Mode::ConfirmPorts => match key.code {
            KeyCode::Char(c) => Action::InputChar(c),
            KeyCode::Esc => Action::InputCancel,
            _ => Action::None,
        },
        Mode::Help => match key.code {
            KeyCode::Char('?') => Action::ToggleHelp,
            KeyCode::Esc | KeyCode::Char('q') => Action::InputCancel,
            _ => Action::None,
        },
        Mode::SelectAltName { .. } => match key.code {
            KeyCode::Up | KeyCode::Char('k') => Action::SelectUp,
            KeyCode::Down | KeyCode::Char('j') => Action::SelectDown,
            KeyCode::Enter => Action::InputSubmit,
            KeyCode::Esc | KeyCode::Char('q') => Action::InputCancel,
            _ => Action::None,
        },
        Mode::Normal => decode_normal_key(key),
    }
}

fn decode_normal_key(key: crossterm::event::KeyEvent) -> Action {
    use crossterm::event::{KeyCode, KeyModifiers};

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('t') => Action::NewTab,
            KeyCode::Char('w') => Action::CloseTab,
            KeyCode::Char('c') => Action::Quit,
            _ => Action::None,
        };
    }

    match key.code {
        KeyCode::Tab => Action::NextTab,
        KeyCode::BackTab => Action::PrevTab,
        KeyCode::Left => Action::PrevPane,
        KeyCode::Right => Action::NextPane,
        KeyCode::Char('1') => Action::SelectPane(0),
        KeyCode::Char('2') => Action::SelectPane(1),
        KeyCode::Char('3') => Action::SelectPane(2),
        KeyCode::Char('4') => Action::SelectPane(3),
        KeyCode::Char('5') => Action::SelectPane(4),
        KeyCode::Char('6') => Action::SelectPane(5),
        KeyCode::Char('7') => Action::SelectPane(6),
        KeyCode::Char('8') => Action::SelectPane(7),
        KeyCode::Char('9') => Action::SelectPane(8),
        KeyCode::Char('0') => Action::SelectPane(9),
        KeyCode::Char('-') => Action::SelectPane(10),
        KeyCode::Char('r') => Action::RerunPane,
        KeyCode::Char('R') => Action::RerunAll,
        KeyCode::Char('e') => Action::ToggleEvidence,
        KeyCode::Char('a') => Action::OpenAltNames,
        KeyCode::Char('y') => Action::CopyPane,
        KeyCode::Char('?') => Action::ToggleHelp,
        KeyCode::Char('q') => Action::Quit,
        _ => Action::None,
    }
}

/// Runs the TUI to completion. Terminal setup/teardown is the caller's
/// responsibility (see `main.rs`).
pub async fn run(
    mut terminal: DefaultTerminal,
    config: Config,
    providers: ProviderDb,
    initial_targets: Vec<Target>,
) -> anyhow::Result<()> {
    let (term_tx, mut term_rx) = mpsc::unbounded_channel::<crossterm::event::Event>();
    // A plain OS thread polling crossterm and forwarding events keeps the
    // blocking terminal read off the async runtime without needing the
    // crossterm/tokio event-stream integration feature.
    std::thread::spawn(move || loop {
        match crossterm::event::poll(Duration::from_millis(100)) {
            Ok(true) => match crossterm::event::read() {
                Ok(ev) => {
                    if term_tx.send(ev).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
            Ok(false) => {}
            Err(_) => return,
        }
    });

    let (check_tx, mut check_rx) = mpsc::channel::<CheckEvent>(1024);
    let mut state = AppState::new(config, providers);
    for target in initial_targets {
        state.open_tab(target, &check_tx);
    }

    loop {
        terminal.draw(|frame| crate::ui::draw(frame, &state))?;

        tokio::select! {
            Some(term_event) = term_rx.recv() => {
                if let crossterm::event::Event::Key(key) = term_event {
                    let action = decode_key(&state.mode, key);
                    state.handle_action(action, &check_tx);
                }
            }
            Some(check_event) = check_rx.recv() => {
                state.apply_check_event(check_event);
            }
        }

        if state.should_quit {
            break;
        }
    }

    for tab in &state.tabs {
        tab.cancel.cancel();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::altnames::{AltName, AltNamesResult, NameSource};

    fn test_sender() -> mpsc::Sender<CheckEvent> {
        mpsc::channel(16).0
    }

    /// A private-IP target so `open_tab`'s spawned checks have nothing
    /// real to reach — these tests exercise selection/mode logic, not the
    /// checks themselves.
    fn local_target() -> Target {
        Target::parse("192.168.1.1").unwrap()
    }

    fn with_alt_names(state: &mut AppState, names: Vec<AltName>) {
        state.tabs[0].checks.insert(
            CheckId::AltNames,
            CheckSlot {
                status: CheckStatus::Done,
                update: Some(CheckUpdate::AltNames(AltNamesResult {
                    ips: Vec::new(),
                    names,
                    errors: Vec::new(),
                })),
            },
        );
    }

    #[tokio::test]
    async fn opening_the_picker_without_discovered_names_is_a_no_op() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), &tx);

        state.handle_action(Action::OpenAltNames, &tx);

        assert!(matches!(state.mode, Mode::Normal));
    }

    #[tokio::test]
    async fn opening_the_picker_with_discovered_names_enters_select_mode() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), &tx);
        with_alt_names(
            &mut state,
            vec![AltName {
                name: "www.example.com".into(),
                sources: vec![NameSource::TlsSan],
            }],
        );

        state.handle_action(Action::OpenAltNames, &tx);

        assert!(matches!(state.mode, Mode::SelectAltName { .. }));
    }

    #[tokio::test]
    async fn selecting_and_confirming_opens_a_new_tab_for_that_name() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), &tx);
        with_alt_names(
            &mut state,
            vec![
                AltName {
                    name: "www.example.com".into(),
                    sources: vec![NameSource::TlsSan],
                },
                AltName {
                    name: "example.net".into(),
                    sources: vec![NameSource::ReverseIp],
                },
            ],
        );

        state.handle_action(Action::OpenAltNames, &tx);
        state.handle_action(Action::SelectDown, &tx);
        state.handle_action(Action::InputSubmit, &tx);

        assert!(matches!(state.mode, Mode::Normal));
        assert_eq!(state.tabs.len(), 2);
        assert_eq!(state.tabs[1].target.display(), "example.net");
        // The new tab becomes active, matching every other "open a tab" path.
        assert_eq!(state.active_tab, 1);
    }

    #[tokio::test]
    async fn select_up_does_not_go_below_the_first_item() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), &tx);
        with_alt_names(
            &mut state,
            vec![AltName {
                name: "www.example.com".into(),
                sources: vec![NameSource::TlsSan],
            }],
        );
        state.handle_action(Action::OpenAltNames, &tx);

        state.handle_action(Action::SelectUp, &tx);
        state.handle_action(Action::SelectUp, &tx);

        let Mode::SelectAltName { selected, .. } = &state.mode else {
            panic!("expected SelectAltName mode")
        };
        assert_eq!(*selected, 0);
    }

    #[tokio::test]
    async fn select_down_does_not_go_past_the_last_item() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), &tx);
        with_alt_names(
            &mut state,
            vec![
                AltName {
                    name: "a.example.com".into(),
                    sources: vec![NameSource::TlsSan],
                },
                AltName {
                    name: "b.example.com".into(),
                    sources: vec![NameSource::TlsSan],
                },
            ],
        );
        state.handle_action(Action::OpenAltNames, &tx);

        for _ in 0..5 {
            state.handle_action(Action::SelectDown, &tx);
        }

        let Mode::SelectAltName { selected, .. } = &state.mode else {
            panic!("expected SelectAltName mode")
        };
        assert_eq!(*selected, 1);
    }

    #[tokio::test]
    async fn cancel_returns_to_normal_without_opening_a_tab() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), &tx);
        with_alt_names(
            &mut state,
            vec![AltName {
                name: "www.example.com".into(),
                sources: vec![NameSource::TlsSan],
            }],
        );
        state.handle_action(Action::OpenAltNames, &tx);

        state.handle_action(Action::InputCancel, &tx);

        assert!(matches!(state.mode, Mode::Normal));
        assert_eq!(state.tabs.len(), 1);
    }
}
