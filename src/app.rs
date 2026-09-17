//! `AppState`, tab management, and the event loop.
//!
//! This is the only place that mutates `AppState` (architecture rule 3):
//! it applies incoming `CheckEvent`s and turns key presses into `Action`s
//! which are applied here too. `ui::*` only ever reads this state.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
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
    /// Same idea for the NSEC zone walk (`checks::zonewalk`): `None` = not
    /// asked yet this tab.
    pub zone_walk_confirmed: Option<bool>,
    /// How far the active pane's content is scrolled down, in lines/rows.
    /// Per-tab rather than per-pane: resets to 0 whenever the active pane
    /// changes, since a stale scroll position from a different pane's
    /// (differently shaped) content would be meaningless.
    pub scroll: u16,
    /// Which of `AppState::clickable_spans` (the hostnames/IPs found in
    /// the last rendered frame -- see `ui::linkscan`) has keyboard focus,
    /// moved by `Action::FocusNextLink`/`FocusPrevLink` (Down/Up) and
    /// opened by `Action::ActivateFocusedLink` (Enter). Reset alongside
    /// `scroll` for the same reason: a focus index from a different
    /// pane's (differently shaped) link list would be meaningless.
    pub focused_link: Option<usize>,
    /// The DNS server every check for this tab resolves names against,
    /// chosen once via `Mode::ChooseResolver` when the tab was opened.
    /// `None` = the system's normally-configured resolver.
    pub resolver: Option<IpAddr>,
    /// Shared with the running ping check's `CheckContext` (see
    /// `checks::ping`): flipped by `Action::TogglePingPause` (Space, on
    /// the Ping/Trace pane) so the check idles in place -- keeping its
    /// accumulated sample history and sparkline exactly as they were --
    /// rather than being cancelled and losing that history to a restart.
    pub ping_paused: Arc<std::sync::atomic::AtomicBool>,
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
    /// Asking whether to run the opt-in NSEC zone walk for the active tab.
    ConfirmZoneWalk,
    /// Browsing the active tab's discovered alternative hostnames
    /// (`CheckId::AltNames`); Enter opens a new tab for the selected one.
    SelectAltName {
        names: Vec<crate::checks::altnames::AltName>,
        selected: usize,
    },
    /// Which DNS server the about-to-open tab should use, asked every
    /// time a new host is entered (never silently reused without
    /// confirmation) but pre-filled with the last one chosen, so
    /// repeating the same server is just Enter. Blank input means the
    /// system's normally-configured resolver.
    ChooseResolver {
        target: Target,
        input: String,
    },
    /// The in-app settings editor: `draft` is a working copy of the
    /// config edited field-by-field (see `crate::settings`), saved to
    /// disk and applied to `AppState::config` immediately whenever a
    /// field is successfully committed -- there's no separate unsaved
    /// "draft state" to lose track of. `editing`, when `Some`, holds the
    /// in-progress text for the field currently being retyped.
    Settings {
        draft: Box<Config>,
        selected: usize,
        editing: Option<String>,
        /// Feedback from the last field commit (an error, or a brief
        /// "saved" confirmation), shown under the list.
        message: Option<String>,
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
    /// The most recently chosen custom DNS server (across any tab this
    /// session), used to pre-fill `Mode::ChooseResolver` so picking the
    /// same one again is just Enter. `None` once no custom resolver has
    /// been chosen yet, or if the last choice was "system default".
    pub last_resolver: Option<IpAddr>,
    /// Where the settings editor saves to. `None` if this platform's
    /// config directory couldn't be determined (`Config::default_path`
    /// failed) -- settings edits still apply for the session, just can't
    /// persist. Overridable (see `#[cfg(test)]` construction below) so
    /// tests exercising the settings flow never touch the user's real
    /// config file.
    pub config_path: Option<PathBuf>,
    /// Live status of the GeoLite2 background downloader (see
    /// `crate::geoip`), read by the Geo pane and the status line's
    /// bottom-right corner. Global rather than per-tab: the underlying
    /// database files are shared by every tab.
    pub geoip: crate::geoip::GeoipStatus,
    /// Set by `app::run` once the background updater is spawned, so a
    /// settings-editor commit can push the new config to it immediately
    /// (see `handle_settings_action`) instead of it waiting out however
    /// much of its current sleep is left. `None` in tests, which don't
    /// run the background task at all.
    geoip_config_tx: Option<tokio::sync::watch::Sender<Arc<Config>>>,
    /// The hostnames/IPs found in the last rendered frame (see
    /// `ui::linkscan`), across the whole terminal in absolute
    /// coordinates. Updated by `run`'s event loop right after each draw
    /// (rule 1: rendering itself never mutates state) -- one frame
    /// behind what's about to be drawn, same as `last_area` below, which
    /// in practice self-corrects immediately since content rarely
    /// changes between one frame and the next. `ui::draw` reads this to
    /// underline every clickable span and highlight whichever one has
    /// keyboard focus; `app::decode_mouse` reads it to hit-test clicks
    /// on pane content.
    pub clickable_spans: Vec<crate::ui::linkscan::ClickableSpan>,
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
            last_resolver: None,
            config_path: Config::default_path().ok(),
            geoip: crate::geoip::GeoipStatus::default(),
            geoip_config_tx: None,
            clickable_spans: Vec::new(),
            next_tab_id: AtomicU64::new(1),
        }
    }

    /// Applies a status update or refresh signal from the GeoLite2
    /// background updater (`crate::geoip::run_background_updater`).
    fn apply_geoip_event(
        &mut self,
        event: crate::geoip::GeoipEvent,
        sender: &mpsc::Sender<CheckEvent>,
    ) {
        match event {
            crate::geoip::GeoipEvent::Status(status) => self.geoip = status,
            crate::geoip::GeoipEvent::Refreshed => {
                // Freshly downloaded databases don't apply to an
                // already-open tab's Geo pane until its check runs
                // again -- do that now instead of leaving a stale "not
                // downloaded yet" until the user presses 'r'.
                for tab in &self.tabs {
                    self.spawn_one_check(
                        CheckId::Geo,
                        tab.id,
                        tab.target.clone(),
                        tab.cancel.clone(),
                        tab.shared.clone(),
                        tab.resolver,
                        tab.ping_paused.clone(),
                        sender.clone(),
                    );
                }
            }
        }
    }

    pub fn active(&self) -> Option<&TabState> {
        self.tabs.get(self.active_tab)
    }

    /// Opens a new tab for `target` and spawns every non-opt-in check for
    /// it, tagged with `sender` so their events route back to this tab.
    /// `resolver`: `None` for the system's default resolver, `Some(ip)`
    /// to query that DNS server instead for every lookup this tab makes
    /// (see `Mode::ChooseResolver`, which every interactive new-tab flow
    /// goes through before calling this).
    pub fn open_tab(
        &mut self,
        target: Target,
        resolver: Option<IpAddr>,
        sender: &mpsc::Sender<CheckEvent>,
    ) {
        let id = self.next_tab_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        let shared = SharedResultsHandle::new();

        let ping_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tab = TabState {
            id,
            target: target.clone(),
            active_pane: 0,
            show_evidence: false,
            cancel: cancel.clone(),
            shared: shared.clone(),
            checks: BTreeMap::new(),
            ports_confirmed: None,
            zone_walk_confirmed: None,
            scroll: 0,
            focused_link: None,
            resolver,
            ping_paused: ping_paused.clone(),
        };
        self.tabs.push(tab);
        self.active_tab = self.tabs.len() - 1;
        // See `reset_scroll`'s doc comment: the new tab starts on
        // Overview, showing completely different content than whatever
        // was on screen (or none at all, on the very first tab) --
        // any spans left over from before would be stale.
        self.clickable_spans.clear();

        self.spawn_checks(
            id,
            target,
            cancel,
            shared,
            resolver,
            ping_paused,
            sender.clone(),
            &[],
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_checks(
        &self,
        tab_id: u64,
        target: Target,
        cancel: CancellationToken,
        shared: SharedResultsHandle,
        resolver: Option<IpAddr>,
        ping_paused: Arc<std::sync::atomic::AtomicBool>,
        sender: mpsc::Sender<CheckEvent>,
        confirmed_opt_ins: &[CheckId],
    ) {
        for check in checks::registry() {
            if check.id().requires_opt_in() && !confirmed_opt_ins.contains(&check.id()) {
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
                resolver,
                ping_paused: ping_paused.clone(),
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
        let resolver = tab.resolver;
        let ping_paused = tab.ping_paused.clone();

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
                resolver,
                ping_paused.clone(),
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
        let resolver = tab.resolver;
        let ping_paused = tab.ping_paused.clone();
        let mut confirmed_opt_ins = Vec::new();
        if tab.ports_confirmed == Some(true) {
            confirmed_opt_ins.push(CheckId::Ports);
        }
        if tab.zone_walk_confirmed == Some(true) {
            confirmed_opt_ins.push(CheckId::ZoneWalk);
        }
        self.spawn_checks(
            tab_id,
            target,
            cancel,
            shared,
            resolver,
            ping_paused,
            sender.clone(),
            &confirmed_opt_ins,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_one_check(
        &self,
        check_id: CheckId,
        tab_id: u64,
        target: Target,
        cancel: CancellationToken,
        shared: SharedResultsHandle,
        resolver: Option<IpAddr>,
        ping_paused: Arc<std::sync::atomic::AtomicBool>,
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
                resolver,
                ping_paused,
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
        let resolver = tab.resolver;
        let ping_paused = tab.ping_paused.clone();
        self.spawn_one_check(
            CheckId::Ports,
            tab_id,
            target,
            cancel,
            shared,
            resolver,
            ping_paused,
            sender.clone(),
        );
    }

    pub fn confirm_zone_walk(&mut self, confirmed: bool, sender: &mpsc::Sender<CheckEvent>) {
        let Some(tab) = self.tabs.get_mut(self.active_tab) else {
            return;
        };
        tab.zone_walk_confirmed = Some(confirmed);
        if !confirmed {
            return;
        }
        let tab_id = tab.id;
        let target = tab.target.clone();
        let cancel = tab.cancel.clone();
        let shared = tab.shared.clone();
        let resolver = tab.resolver;
        let ping_paused = tab.ping_paused.clone();
        self.spawn_one_check(
            CheckId::ZoneWalk,
            tab_id,
            target,
            cancel,
            shared,
            resolver,
            ping_paused,
            sender.clone(),
        );
    }

    /// Builds the "which DNS server?" prompt for `target`, pre-filled
    /// with the last one chosen this session (or blank for "system
    /// default" if none has been).
    fn choose_resolver_mode(&self, target: Target) -> Mode {
        Mode::ChooseResolver {
            target,
            input: self
                .last_resolver
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
        }
    }

    fn open_settings(&mut self) {
        self.mode = Mode::Settings {
            draft: Box::new((*self.config).clone()),
            selected: 0,
            editing: None,
            message: None,
        };
    }

    /// All key handling while `Mode::Settings` is active. Kept as its own
    /// method (see the guard in `handle_action`) since committing a field
    /// needs to update `self.config`/write `self.config_path` alongside
    /// `self.mode`, which is awkward through the big tuple match every
    /// other mode uses. Takes `self.mode` fully out via `mem::replace`
    /// (rather than borrowing into it) so the rest of `self` stays freely
    /// accessible throughout, then puts the (possibly updated) mode back
    /// at the end -- simpler than juggling partial borrows.
    fn handle_settings_action(&mut self, action: Action) {
        let Mode::Settings {
            mut draft,
            mut selected,
            mut editing,
            mut message,
        } = std::mem::replace(&mut self.mode, Mode::Normal)
        else {
            return;
        };
        let fields = crate::settings::fields();
        let mut still_open = true;

        match action {
            Action::SelectUp if editing.is_none() => {
                selected = selected.saturating_sub(1);
            }
            Action::SelectDown if editing.is_none() => {
                if selected + 1 < fields.len() {
                    selected += 1;
                }
            }
            Action::SelectIndex(i) if editing.is_none() => {
                // A click on a field row both selects it and opens it for
                // editing -- there's no separate mouse "confirm" step the
                // way Enter is from the keyboard.
                if let Some(field) = fields.get(i) {
                    selected = i;
                    editing = Some((field.get)(&draft));
                    message = None;
                }
            }
            Action::InputChar(c) => {
                if let Some(buf) = &mut editing {
                    buf.push(c);
                }
            }
            Action::InputBackspace => {
                if let Some(buf) = &mut editing {
                    buf.pop();
                }
            }
            Action::InputSubmit => {
                if let Some(input) = editing.take() {
                    if let Some(field) = fields.get(selected) {
                        match (field.set)(&mut draft, &input) {
                            Ok(()) => {
                                let write_err = self
                                    .config_path
                                    .as_ref()
                                    .and_then(|path| draft.save(path).err());
                                self.config = Arc::new((*draft).clone());
                                if let Some(tx) = &self.geoip_config_tx {
                                    let _ = tx.send(self.config.clone());
                                }
                                message = Some(match (&self.config_path, write_err) {
                                    (None, _) => "saved for this session only (no config directory for this platform)".to_string(),
                                    (Some(_), Some(err)) => format!("applied for this session, but failed to save: {err}"),
                                    (Some(_), None) => "saved".to_string(),
                                });
                            }
                            Err(err) => {
                                message = Some(err);
                                editing = Some(input);
                            }
                        }
                    }
                } else if let Some(field) = fields.get(selected) {
                    editing = Some((field.get)(&draft));
                    message = None;
                }
            }
            Action::InputCancel => {
                if editing.is_some() {
                    editing = None;
                } else {
                    still_open = false;
                }
            }
            _ => {}
        }

        self.mode = if still_open {
            Mode::Settings {
                draft,
                selected,
                editing,
                message,
            }
        } else {
            Mode::Normal
        };
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
        // See `reset_scroll`'s doc comment: whichever tab is now active
        // (or none) shows different content than the closed one did.
        self.clickable_spans.clear();
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
        // Handled separately (not folded into the big match below): a
        // commit needs to write `self.config`/`self.config_path` while
        // `self.mode` is also mutably in play, which is awkward through
        // `match (&mut self.mode, action)`'s single borrow of `self.mode`.
        if matches!(self.mode, Mode::Settings { .. }) {
            self.handle_settings_action(action);
            return;
        }

        match (&mut self.mode, action) {
            (Mode::NewHostPrompt(buf), Action::InputChar(c)) => buf.push(c),
            (Mode::NewHostPrompt(buf), Action::InputBackspace) => {
                buf.pop();
            }
            (Mode::NewHostPrompt(buf), Action::InputSubmit) => {
                if let Ok(target) = Target::parse(buf.trim()) {
                    self.mode = self.choose_resolver_mode(target);
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
            (Mode::ConfirmZoneWalk, Action::InputChar('y')) => {
                self.mode = Mode::Normal;
                self.confirm_zone_walk(true, sender);
            }
            (Mode::ConfirmZoneWalk, Action::InputChar('n'))
            | (Mode::ConfirmZoneWalk, Action::InputCancel) => {
                self.mode = Mode::Normal;
                self.confirm_zone_walk(false, sender);
            }
            // Anything else (pane/tab navigation, rerun, ...) while a
            // confirm prompt is up: dismiss it without recording a
            // decision -- it comes back next time the Ports pane (or the
            // zone-walk hint) is reached -- and let the action through
            // rather than trapping the user until they answer y/n.
            (Mode::ConfirmPorts | Mode::ConfirmZoneWalk, action) => {
                self.mode = Mode::Normal;
                self.handle_normal_action(action, sender);
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
                    // Reuses the current tab's resolver rather than asking
                    // again: picking an alternative name found *while
                    // already inspecting this host* is a quick cross-
                    // reference, not the deliberate "start fresh" that
                    // Ctrl+T's new-host flow is -- re-prompting here would
                    // just be friction for the common case of wanting the
                    // same (often custom, e.g. internal) resolver again.
                    let resolver = self.active().and_then(|t| t.resolver);
                    self.mode = Mode::Normal;
                    self.open_tab(target, resolver, sender);
                }
            }
            (Mode::SelectAltName { names, selected }, Action::SelectIndex(i)) => {
                if i < names.len() {
                    *selected = i;
                }
                // Reuses the same "open it" logic as InputSubmit: a click
                // on a list row is one deliberate choice, not a two-step
                // select-then-confirm the way keyboard navigation is.
                if let Some(target) = names
                    .get(*selected)
                    .and_then(|n| Target::parse(&n.name).ok())
                {
                    let resolver = self.active().and_then(|t| t.resolver);
                    self.mode = Mode::Normal;
                    self.open_tab(target, resolver, sender);
                }
            }
            (Mode::SelectAltName { .. }, Action::InputCancel) => self.mode = Mode::Normal,
            (Mode::ChooseResolver { input, .. }, Action::InputChar(c)) => input.push(c),
            (Mode::ChooseResolver { input, .. }, Action::InputBackspace) => {
                input.pop();
            }
            (Mode::ChooseResolver { target, input }, Action::InputSubmit) => {
                match parse_resolver_input(input) {
                    Ok(resolver) => {
                        let target = target.clone();
                        self.last_resolver = resolver;
                        self.mode = Mode::Normal;
                        self.open_tab(target, resolver, sender);
                    }
                    Err(()) => input.clear(),
                }
            }
            (Mode::ChooseResolver { .. }, Action::InputCancel) => self.mode = Mode::Normal,
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
                    self.reset_scroll();
                }
            }
            Action::PrevTab => {
                if !self.tabs.is_empty() {
                    self.active_tab = (self.active_tab + self.tabs.len() - 1) % self.tabs.len();
                    self.reset_scroll();
                }
            }
            Action::SelectHostTab(i) => {
                if i < self.tabs.len() {
                    self.active_tab = i;
                    self.reset_scroll();
                }
            }
            Action::SelectPane(i) => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    if i < Pane::ALL.len() {
                        tab.active_pane = i;
                        tab.scroll = 0;
                        tab.focused_link = None;
                        // See `reset_scroll`'s doc comment: must not
                        // leave the old pane's links to be drawn, stale,
                        // over the new pane's content.
                        self.clickable_spans.clear();
                        self.maybe_prompt_ports();
                    }
                }
            }
            Action::NextPane => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    tab.active_pane = (tab.active_pane + 1) % Pane::ALL.len();
                    tab.scroll = 0;
                    tab.focused_link = None;
                }
                self.clickable_spans.clear();
                self.maybe_prompt_ports();
            }
            Action::PrevPane => {
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    tab.active_pane = (tab.active_pane + Pane::ALL.len() - 1) % Pane::ALL.len();
                    tab.scroll = 0;
                    tab.focused_link = None;
                }
                self.clickable_spans.clear();
                self.maybe_prompt_ports();
            }
            Action::ScrollUp => self.scroll_by(-1),
            Action::ScrollDown => self.scroll_by(1),
            Action::ScrollPageUp => self.scroll_by(-10),
            Action::ScrollPageDown => self.scroll_by(10),
            Action::FocusNextLink => {
                let len = self.clickable_spans.len();
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    if len > 0 {
                        tab.focused_link = Some(match tab.focused_link {
                            None => 0,
                            Some(i) if i + 1 < len => i + 1,
                            Some(i) => i,
                        });
                    }
                }
            }
            Action::FocusPrevLink => {
                let len = self.clickable_spans.len();
                if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                    if len > 0 {
                        tab.focused_link = Some(match tab.focused_link {
                            None => len - 1,
                            Some(i) if i > 0 => i - 1,
                            Some(i) => i,
                        });
                    }
                }
            }
            Action::ActivateFocusedLink => {
                if let Some(target) = self.active().and_then(|tab| {
                    let i = tab.focused_link?;
                    self.clickable_spans.get(i).map(|s| s.target.clone())
                }) {
                    self.open_link(target, sender);
                }
            }
            Action::OpenLink(target) => self.open_link(target, sender),
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
            Action::OpenZoneWalk => self.open_zone_walk_confirm(),
            Action::OpenSettings => self.open_settings(),
            Action::TogglePingPause => {
                // Scoped to the Ping/Trace pane so Space doesn't do
                // anything surprising while browsing other panes.
                if self.current_pane() == Some(Pane::PingTrace) {
                    if let Some(tab) = self.active() {
                        let was = tab.ping_paused.load(std::sync::atomic::Ordering::Relaxed);
                        tab.ping_paused
                            .store(!was, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            Action::CopyPane => {} // clipboard support is a later addition; no-op for now.
            _ => {}
        }
    }

    /// Opens a new tab for a hostname/IP clicked (or Enter-activated)
    /// from the active pane's content -- see `Action::OpenLink`.
    fn open_link(&mut self, target: Target, sender: &mpsc::Sender<CheckEvent>) {
        let resolver = self.active().and_then(|t| t.resolver);
        self.open_tab(target, resolver, sender);
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

    /// Asks whether to run the opt-in NSEC zone walk, if the DNS check has
    /// found this zone to actually be NSEC-signed (the only case it's
    /// possible) and hasn't already been asked this tab. A no-op
    /// otherwise: nothing to walk, or already answered.
    fn open_zone_walk_confirm(&mut self) {
        let Some(tab) = self.active() else { return };
        if tab.zone_walk_confirmed.is_some() {
            return;
        }
        let is_walkable = matches!(&tab.slot(CheckId::Dns).update, Some(CheckUpdate::Dns(d)) if d.zone_signing == crate::checks::dns::ZoneSigning::Nsec);
        if !is_walkable {
            return;
        }
        self.mode = Mode::ConfirmZoneWalk;
    }

    fn current_pane(&self) -> Option<Pane> {
        self.active().and_then(|t| Pane::from_index(t.active_pane))
    }

    fn reset_scroll(&mut self) {
        if let Some(tab) = self.tabs.get_mut(self.active_tab) {
            tab.scroll = 0;
            tab.focused_link = None;
        }
        // `clickable_spans` reflects the *previous* draw's content (see
        // its doc comment) -- rendering still uses it for the very next
        // frame, drawn *before* `run`'s loop gets a chance to rescan.
        // Left in place across a tab/pane switch, that frame would
        // overlay leftover link text from whatever was on screen before
        // on top of the new pane's freshly-drawn (and differently laid
        // out) content, corrupting it. Clearing it here means that one
        // frame just renders with no link styling yet, rather than with
        // wrong styling in the wrong place.
        self.clickable_spans.clear();
    }

    /// Scrolls the active pane's content by `delta` lines/rows (negative
    /// scrolls up). Never goes negative; there's no upper clamp since the
    /// actual content height isn't known outside rendering (rule 1: pure
    /// rendering can't write back into `AppState`) — scrolling past the
    /// end of a pane's content just shows blank space, which is harmless.
    fn scroll_by(&mut self, delta: i32) {
        if let Some(tab) = self.tabs.get_mut(self.active_tab) {
            tab.scroll = (i32::from(tab.scroll) + delta).max(0) as u16;
        }
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
/// Blank input means "system default" (`Ok(None)`); anything else must
/// parse as a bare IP address, since that's the only thing
/// `hickory-resolver` can point a resolver at directly here — a
/// hostname (e.g. a resolver's own DNS name) would need its own
/// resolution step this prompt doesn't do.
fn parse_resolver_input(input: &str) -> Result<Option<IpAddr>, ()> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed.parse::<IpAddr>().map(Some).map_err(|_| ())
}

fn decode_key(mode: &Mode, key: crossterm::event::KeyEvent) -> Action {
    use crossterm::event::KeyCode;
    if key.kind == crossterm::event::KeyEventKind::Release {
        return Action::None;
    }

    match mode {
        Mode::NewHostPrompt(_) | Mode::ChooseResolver { .. } => match key.code {
            KeyCode::Char(c) => Action::InputChar(c),
            KeyCode::Backspace => Action::InputBackspace,
            KeyCode::Enter => Action::InputSubmit,
            KeyCode::Esc => Action::InputCancel,
            _ => Action::None,
        },
        // 'y'/'n' answer the prompt; Esc explicitly declines (same as
        // 'n'). Anything else -- pane/tab navigation in particular --
        // falls through to its normal-mode meaning rather than being
        // swallowed, so arriving at the Ports pane doesn't trap the user
        // until they answer: they can keep tabbing away, and the prompt
        // just comes back next time they land on Ports (or the zone-walk
        // hint fires again), since navigating away doesn't record a
        // decision either way.
        Mode::ConfirmPorts | Mode::ConfirmZoneWalk => match key.code {
            KeyCode::Char(c @ ('y' | 'n')) => Action::InputChar(c),
            KeyCode::Esc => Action::InputCancel,
            _ => decode_normal_key(key),
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
        // While actively retyping a field's value: plain text input.
        Mode::Settings {
            editing: Some(_), ..
        } => match key.code {
            KeyCode::Char(c) => Action::InputChar(c),
            KeyCode::Backspace => Action::InputBackspace,
            KeyCode::Enter => Action::InputSubmit,
            KeyCode::Esc => Action::InputCancel,
            _ => Action::None,
        },
        // Otherwise: browsing the field list.
        Mode::Settings { editing: None, .. } => match key.code {
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
        // Up/Down move between clickable hostnames/IPs rather than
        // scrolling -- see `Action::FocusNextLink`'s doc comment.
        // PgUp/PgDn are the keyboard's scroll keys.
        KeyCode::Up => Action::FocusPrevLink,
        KeyCode::Down => Action::FocusNextLink,
        KeyCode::Enter => Action::ActivateFocusedLink,
        KeyCode::PageUp => Action::ScrollPageUp,
        KeyCode::PageDown => Action::ScrollPageDown,
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
        KeyCode::Char('w') => Action::OpenZoneWalk,
        KeyCode::Char('y') => Action::CopyPane,
        KeyCode::Char('s') => Action::OpenSettings,
        KeyCode::Char(' ') => Action::TogglePingPause,
        KeyCode::Char('?') => Action::ToggleHelp,
        KeyCode::Char('q') => Action::Quit,
        _ => Action::None,
    }
}

/// Decodes a mouse event into an `Action`.
///
/// Every modal popup (a prompt, a picker, the settings editor) gets
/// first refusal via `ui::decode_popup_mouse`, which knows each popup's
/// exact on-screen geometry (the same geometry its renderer draws, so
/// the two can't drift apart) -- see its doc comment for the full
/// per-mode behavior. `None` from it means either there's no popup at
/// all (`Mode::Normal`) or -- for the two "yes/no" confirm prompts only
/// -- the click wasn't on a Yes/No button, so it should still work as
/// normal tab/pane navigation, mirroring `decode_key`'s identical
/// fallthrough for those two modes.
///
/// `terminal_area` is the whole terminal (as last drawn; see `run`'s
/// `last_area`, matching `Frame::area()`), used to translate the mouse's
/// absolute row/column into "which row of the layout is this" and
/// "which column within the tab bar's own content area" -- the outer
/// frame has a 1-cell border on every side, which both offsets need to
/// account for.
fn decode_mouse(
    mode: &Mode,
    terminal_area: ratatui::layout::Rect,
    state: &AppState,
    mouse: crossterm::event::MouseEvent,
) -> Action {
    use crossterm::event::{MouseButton, MouseEventKind};

    if let Some(action) = crate::ui::decode_popup_mouse(mode, terminal_area, mouse) {
        return action;
    }
    if !matches!(
        mode,
        Mode::Normal | Mode::ConfirmPorts | Mode::ConfirmZoneWalk
    ) {
        return Action::None;
    }

    match mouse.kind {
        MouseEventKind::ScrollUp => Action::ScrollUp,
        MouseEventKind::ScrollDown => Action::ScrollDown,
        MouseEventKind::Down(MouseButton::Left) => {
            let host_tabs_row = terminal_area.y + 1;
            let pane_tabs_row = terminal_area.y + 2;
            let col = mouse.column.saturating_sub(terminal_area.x + 1);
            if mouse.row == host_tabs_row {
                if let Some(i) = crate::ui::tabs::host_tab_at(state, col) {
                    Action::SelectHostTab(i)
                } else if crate::ui::tabs::new_tab_label_at(state, col) {
                    Action::NewTab
                } else {
                    Action::None
                }
            } else if mouse.row == pane_tabs_row {
                match crate::ui::tabs::pane_tab_at(col) {
                    Some(i) => Action::SelectPane(i),
                    None => Action::None,
                }
            } else if let Some(span) = state
                .clickable_spans
                .iter()
                .find(|s| s.contains(mouse.row, mouse.column))
            {
                Action::OpenLink(span.target.clone())
            } else {
                Action::None
            }
        }
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

    let (geoip_config_tx, geoip_config_rx) = tokio::sync::watch::channel(state.config.clone());
    state.geoip_config_tx = Some(geoip_config_tx);
    let (geoip_event_tx, mut geoip_event_rx) = mpsc::unbounded_channel();
    if let Some(geoip_cache_dir) = crate::geoip::cache_dir() {
        tokio::spawn(crate::geoip::run_background_updater(
            geoip_config_rx,
            geoip_event_tx,
            geoip_cache_dir,
        ));
    }

    for target in initial_targets {
        // CLI-provided hosts skip the interactive resolver prompt (there's
        // no prompt to show before the terminal is even drawn); the
        // system's default resolver applies. `--resolver` on `check
        // <target>` covers the same need for the headless path.
        state.open_tab(target, None, &check_tx);
    }

    // Updated by every `draw` call below so mouse handling (which needs
    // to know the layout, but doesn't run inside a `draw`) can translate
    // an absolute row/column the same way `ui::draw` laid it out.
    let mut last_area = ratatui::layout::Rect::default();

    loop {
        let completed = terminal.draw(|frame| {
            last_area = frame.area();
            crate::ui::draw(frame, &state);
        })?;
        // See `AppState::clickable_spans`'s doc comment: this is what the
        // frame just drawn actually shows, scanned once per iteration so
        // both mouse clicks and keyboard link-navigation stay in sync
        // with what's on screen right now (a one-iteration lag behind
        // whatever content change, if any, an event is about to cause).
        state.clickable_spans =
            crate::ui::linkscan::scan(completed.buffer, crate::ui::body_area(last_area));

        tokio::select! {
            Some(term_event) = term_rx.recv() => {
                match term_event {
                    crossterm::event::Event::Key(key) => {
                        let action = decode_key(&state.mode, key);
                        state.handle_action(action, &check_tx);
                    }
                    crossterm::event::Event::Mouse(mouse) => {
                        let action = decode_mouse(&state.mode, last_area, &state, mouse);
                        state.handle_action(action, &check_tx);
                    }
                    _ => {}
                }
            }
            Some(check_event) = check_rx.recv() => {
                state.apply_check_event(check_event);
            }
            Some(geoip_event) = geoip_event_rx.recv() => {
                state.apply_geoip_event(geoip_event, &check_tx);
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
        state.open_tab(local_target(), None, &tx);

        state.handle_action(Action::OpenAltNames, &tx);

        assert!(matches!(state.mode, Mode::Normal));
    }

    #[tokio::test]
    async fn opening_the_picker_with_discovered_names_enters_select_mode() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);
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
        state.open_tab(local_target(), None, &tx);
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
        state.open_tab(local_target(), None, &tx);
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
        state.open_tab(local_target(), None, &tx);
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
        state.open_tab(local_target(), None, &tx);
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

    #[test]
    fn parse_resolver_input_accepts_blank_and_valid_ips_and_rejects_garbage() {
        assert_eq!(parse_resolver_input(""), Ok(None));
        assert_eq!(parse_resolver_input("   "), Ok(None));
        assert_eq!(
            parse_resolver_input("1.1.1.1"),
            Ok(Some("1.1.1.1".parse().unwrap()))
        );
        assert_eq!(
            parse_resolver_input("2001:4860:4860::8888"),
            Ok(Some("2001:4860:4860::8888".parse().unwrap()))
        );
        assert_eq!(parse_resolver_input("not-an-ip"), Err(()));
    }

    /// The full interactive flow this feature is for: entering a new host
    /// always asks which DNS server to use (never silently reuses one
    /// without confirmation), pre-filled with the last one chosen, and the
    /// opened tab actually carries that choice through to its `TabState`
    /// (which is what every check's `CheckContext::resolver` reads).
    #[tokio::test]
    async fn new_host_flow_asks_for_a_resolver_and_carries_it_to_the_tab() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();

        state.handle_action(Action::NewTab, &tx);
        assert!(matches!(state.mode, Mode::NewHostPrompt(_)));
        for c in "192.168.1.1".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx);

        // Not open yet -- the resolver prompt comes first, pre-filled
        // blank (no prior choice this session).
        assert!(state.tabs.is_empty());
        let Mode::ChooseResolver { input, .. } = &state.mode else {
            panic!("expected ChooseResolver mode, got a different mode");
        };
        assert_eq!(input, "");

        for c in "9.9.9.9".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx);

        assert!(matches!(state.mode, Mode::Normal));
        assert_eq!(state.tabs.len(), 1);
        assert_eq!(state.tabs[0].resolver, Some("9.9.9.9".parse().unwrap()));
        assert_eq!(state.last_resolver, Some("9.9.9.9".parse().unwrap()));

        // Opening a second host pre-fills the prompt with that choice.
        state.handle_action(Action::NewTab, &tx);
        for c in "192.168.1.2".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx);
        let Mode::ChooseResolver { input, .. } = &state.mode else {
            panic!("expected ChooseResolver mode, got a different mode");
        };
        assert_eq!(input, "9.9.9.9");
    }

    #[tokio::test]
    async fn invalid_resolver_input_is_rejected_rather_than_opening_the_tab() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.handle_action(Action::NewTab, &tx);
        for c in "192.168.1.1".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx);

        for c in "not-an-ip".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx);

        // Rejected, not silently treated as "system default" -- still
        // prompting, with the bad input cleared so the user can retry.
        assert!(state.tabs.is_empty());
        let Mode::ChooseResolver { input, .. } = &state.mode else {
            panic!("expected ChooseResolver mode, got a different mode");
        };
        assert_eq!(input, "");
    }

    /// Landing on the Ports pane puts up the confirm prompt, but it must
    /// not trap navigation: switching panes away from it should still
    /// work without answering y/n first, dismissing the prompt (not
    /// recording a decision) rather than swallowing the keypress.
    #[tokio::test]
    async fn navigating_away_dismisses_the_ports_prompt_without_deciding() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);

        let ports_index = Pane::ALL.iter().position(|&p| p == Pane::Ports).unwrap();
        state.handle_action(Action::SelectPane(ports_index), &tx);
        assert!(matches!(state.mode, Mode::ConfirmPorts));
        assert_eq!(state.tabs[0].active_pane, ports_index);

        state.handle_action(Action::NextPane, &tx);

        assert!(matches!(state.mode, Mode::Normal));
        assert_eq!(state.tabs[0].active_pane, ports_index + 1);
        assert_eq!(
            state.tabs[0].ports_confirmed, None,
            "navigating away shouldn't record a yes/no decision"
        );
    }

    /// The full settings-editor flow: open, navigate to a field, edit it,
    /// commit it, and confirm both that `AppState::config` picked up the
    /// change immediately and that it was written to disk -- using a
    /// tempdir path (never the user's real config file) so this is safe
    /// to run as an automated test.
    #[tokio::test]
    async fn editing_a_setting_applies_it_and_saves_to_disk() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let dir = tempfile::tempdir().unwrap();
        state.config_path = Some(dir.path().join("config.toml"));
        let tx = test_sender();

        state.handle_action(Action::OpenSettings, &tx);
        assert!(matches!(state.mode, Mode::Settings { .. }));

        // "Theme" is the last field in `settings::fields()`; walk down to
        // it rather than hard-coding an index that'd silently go stale
        // if the field list is reordered.
        let theme_index = crate::settings::fields()
            .iter()
            .position(|f| f.label == "Theme")
            .unwrap();
        for _ in 0..theme_index {
            state.handle_action(Action::SelectDown, &tx);
        }

        state.handle_action(Action::InputSubmit, &tx); // start editing
        let Mode::Settings { editing, .. } = &state.mode else {
            panic!("expected Settings mode");
        };
        assert_eq!(
            editing.as_deref(),
            Some("default"),
            "pre-filled with the current value"
        );

        // Replace the pre-filled value: backspace it away, type the new one.
        for _ in 0.."default".len() {
            state.handle_action(Action::InputBackspace, &tx);
        }
        for c in "solarized".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx); // commit

        assert_eq!(state.config.theme, "solarized");
        let Mode::Settings {
            editing, message, ..
        } = &state.mode
        else {
            panic!("expected Settings mode");
        };
        assert!(editing.is_none(), "commit should leave edit mode");
        assert_eq!(message.as_deref(), Some("saved"));

        let saved = Config::load(state.config_path.as_ref().unwrap()).unwrap();
        assert_eq!(saved.theme, "solarized");

        state.handle_action(Action::InputCancel, &tx);
        assert!(matches!(state.mode, Mode::Normal));
    }

    #[test]
    fn invalid_setting_input_is_rejected_and_keeps_editing() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let dir = tempfile::tempdir().unwrap();
        state.config_path = Some(dir.path().join("config.toml"));
        let tx = test_sender();

        state.handle_action(Action::OpenSettings, &tx);
        let dns_timeout_index = crate::settings::fields()
            .iter()
            .position(|f| f.label == "DNS timeout")
            .unwrap();
        for _ in 0..dns_timeout_index {
            state.handle_action(Action::SelectDown, &tx);
        }
        state.handle_action(Action::InputSubmit, &tx); // start editing
        for _ in 0.."3s".len() {
            state.handle_action(Action::InputBackspace, &tx);
        }
        for c in "not a duration".chars() {
            state.handle_action(Action::InputChar(c), &tx);
        }
        state.handle_action(Action::InputSubmit, &tx); // attempt commit

        // Unchanged: the bad input was rejected, not silently applied.
        assert_eq!(state.config.timeouts.dns, Duration::from_secs(3));
        let Mode::Settings {
            editing, message, ..
        } = &state.mode
        else {
            panic!("expected Settings mode");
        };
        assert_eq!(editing.as_deref(), Some("not a duration"));
        assert!(message.is_some(), "should explain why it was rejected");
    }

    /// Space on the Ping/Trace pane flips the shared flag the running
    /// ping check idles on, without touching any other tab's flag.
    #[tokio::test]
    async fn toggle_ping_pause_flips_only_the_active_tabs_flag() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);
        state.open_tab(local_target(), None, &tx);

        let ping_index = Pane::ALL
            .iter()
            .position(|&p| p == Pane::PingTrace)
            .unwrap();
        state.handle_action(Action::SelectPane(ping_index), &tx);

        assert!(!state.tabs[1]
            .ping_paused
            .load(std::sync::atomic::Ordering::Relaxed));
        state.handle_action(Action::TogglePingPause, &tx);
        assert!(state.tabs[1]
            .ping_paused
            .load(std::sync::atomic::Ordering::Relaxed));
        assert!(
            !state.tabs[0]
                .ping_paused
                .load(std::sync::atomic::Ordering::Relaxed),
            "the other tab's flag must be untouched"
        );

        state.handle_action(Action::TogglePingPause, &tx);
        assert!(!state.tabs[1]
            .ping_paused
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    /// Space must be scoped to the Ping/Trace pane so it doesn't do
    /// anything surprising while browsing a different pane.
    #[tokio::test]
    async fn toggle_ping_pause_is_a_no_op_outside_the_ping_trace_pane() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);

        let overview_index = Pane::ALL.iter().position(|&p| p == Pane::Overview).unwrap();
        state.handle_action(Action::SelectPane(overview_index), &tx);

        state.handle_action(Action::TogglePingPause, &tx);
        assert!(!state.tabs[0]
            .ping_paused
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    fn left_click(row: u16, column: u16) -> crossterm::event::MouseEvent {
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column,
            row,
            modifiers: crossterm::event::KeyModifiers::NONE,
        }
    }

    /// End-to-end: a click landing on the second host tab's rendered span
    /// (see `ui::tabs::host_tab_at`, exercised in isolation there) must
    /// actually switch tabs when run through `decode_mouse` +
    /// `handle_action`, the same path the real event loop uses.
    #[tokio::test]
    async fn clicking_a_host_tab_switches_to_it() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(Target::parse("192.168.1.1").unwrap(), None, &tx);
        state.open_tab(Target::parse("192.168.1.2").unwrap(), None, &tx);
        assert_eq!(state.active_tab, 1, "opening a tab activates it");
        state.active_tab = 0;

        // Rather than hand-deriving the second tab's exact column, search
        // for the column `host_tab_at` itself maps to index 1 -- keeps
        // this test correct regardless of label width. `decode_mouse`
        // subtracts 1 from the absolute column for the outer frame's
        // left border before calling `host_tab_at`, so add it back here.
        let local_col = (0..40)
            .find(|&c| crate::ui::tabs::host_tab_at(&state, c) == Some(1))
            .expect("second host tab must be findable within the first 40 columns");
        let terminal_area = ratatui::layout::Rect::new(0, 0, 80, 24);
        let action = decode_mouse(
            &state.mode,
            terminal_area,
            &state,
            left_click(1, local_col + 1),
        );
        assert_eq!(action, Action::SelectHostTab(1));
        state.handle_action(action, &tx);
        assert_eq!(state.active_tab, 1);
    }

    /// Same idea for a pane-tab click: lands on the DNS tab's span and
    /// switches the active tab's pane.
    #[tokio::test]
    async fn clicking_a_pane_tab_switches_to_it() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);

        let dns_index = Pane::ALL.iter().position(|&p| p == Pane::Dns).unwrap();
        // As above: search for the column `pane_tab_at` maps to
        // `dns_index` rather than hand-deriving it, and add back the
        // 1-cell left-border offset `decode_mouse` subtracts.
        let local_col = (0..40)
            .find(|&c| crate::ui::tabs::pane_tab_at(c) == Some(dns_index))
            .expect("DNS pane tab must be findable within the first 40 columns");

        let terminal_area = ratatui::layout::Rect::new(0, 0, 80, 24);
        let action = decode_mouse(
            &state.mode,
            terminal_area,
            &state,
            left_click(2, local_col + 1),
        );
        assert_eq!(action, Action::SelectPane(dns_index));
        state.handle_action(action, &tx);
        assert_eq!(state.tabs[0].active_pane, dns_index);
    }

    /// A scroll event anywhere must translate to the same scroll action
    /// regardless of where exactly it lands, and must be ignored in a
    /// mode that isn't expecting mouse input at all (e.g. the help
    /// overlay, which -- like most non-prompt modes -- only understands
    /// keyboard input).
    #[tokio::test]
    async fn scroll_wheel_scrolls_and_is_ignored_outside_normal_ish_modes() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);

        let terminal_area = ratatui::layout::Rect::new(0, 0, 80, 24);
        let scroll_down = crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollDown,
            column: 10,
            row: 10,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        assert_eq!(
            decode_mouse(&Mode::Normal, terminal_area, &state, scroll_down),
            Action::ScrollDown
        );

        state.handle_action(Action::ToggleHelp, &tx);
        assert!(matches!(state.mode, Mode::Help));
        assert_eq!(
            decode_mouse(&state.mode, terminal_area, &state, scroll_down),
            Action::None,
            "the help overlay isn't a mouse-aware mode"
        );
    }

    /// End-to-end: clicking the confirm prompt's "[y]" button must
    /// actually confirm the port scan when run through `decode_mouse` +
    /// `handle_action`, the same path the real event loop uses (the
    /// button-hit math itself is exercised in isolation in `ui::mod`'s
    /// tests).
    #[tokio::test]
    async fn clicking_yes_on_the_ports_prompt_confirms_the_scan() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);

        let ports_index = Pane::ALL.iter().position(|&p| p == Pane::Ports).unwrap();
        state.handle_action(Action::SelectPane(ports_index), &tx);
        assert!(matches!(state.mode, Mode::ConfirmPorts));

        let terminal_area = ratatui::layout::Rect::new(0, 0, 100, 40);
        let popup = crate::ui::confirm_ports_popup(terminal_area);
        let (button_row, col_offset) = crate::ui::confirm_button_row_and_col_offset(popup);
        let yes_col =
            col_offset + crate::ui::yes_no_spans(crate::ui::PORTS_QUESTION)[0].width() as u16;

        let action = decode_mouse(
            &state.mode,
            terminal_area,
            &state,
            left_click(button_row, yes_col),
        );
        assert_eq!(action, Action::InputChar('y'));
        state.handle_action(action, &tx);

        assert!(matches!(state.mode, Mode::Normal));
        assert_eq!(state.tabs[0].ports_confirmed, Some(true));
    }

    /// End-to-end: clicking outside the "new host" prompt's popup must
    /// cancel it via the same `decode_mouse` + `handle_action` path.
    #[tokio::test]
    async fn clicking_outside_the_new_host_prompt_cancels_it() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.handle_action(Action::NewTab, &tx);
        assert!(matches!(state.mode, Mode::NewHostPrompt(_)));

        let terminal_area = ratatui::layout::Rect::new(0, 0, 100, 40);
        let action = decode_mouse(&state.mode, terminal_area, &state, left_click(0, 0));
        assert_eq!(action, Action::InputCancel);
        state.handle_action(action, &tx);
        assert!(matches!(state.mode, Mode::Normal));
    }

    /// End-to-end: clicking a settings row opens it for editing,
    /// pre-filled with its current value -- one click doing what
    /// keyboard navigation needs an arrow-to-it-then-Enter for.
    #[tokio::test]
    async fn clicking_a_settings_row_opens_it_for_editing() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.handle_action(Action::OpenSettings, &tx);
        assert!(matches!(state.mode, Mode::Settings { .. }));

        let terminal_area = ratatui::layout::Rect::new(0, 0, 100, 40);
        let popup = crate::ui::settings_popup(terminal_area);
        let third_row = popup.y + 1 + 2; // inner top, then the 3rd field

        let action = decode_mouse(
            &state.mode,
            terminal_area,
            &state,
            left_click(third_row, popup.x + 2),
        );
        assert_eq!(action, Action::SelectIndex(2));
        state.handle_action(action, &tx);

        let Mode::Settings {
            selected, editing, ..
        } = &state.mode
        else {
            panic!("expected Settings mode");
        };
        assert_eq!(*selected, 2);
        assert!(
            editing.is_some(),
            "the click should open the field for editing"
        );
    }

    fn fake_span(row: u16, col_start: u16, text: &str) -> crate::ui::linkscan::ClickableSpan {
        crate::ui::linkscan::ClickableSpan {
            row,
            col_start,
            col_end: col_start + text.len() as u16,
            text: text.to_string(),
            target: Target::parse(text).unwrap(),
        }
    }

    /// Focus starts at one end, moves one at a time, and clamps rather
    /// than wrapping -- matching how `SelectUp`/`SelectDown` already
    /// behave in this app's other list pickers (Settings, SelectAltName).
    #[tokio::test]
    async fn focus_next_and_prev_link_cycle_without_wrapping() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);
        state.clickable_spans = vec![
            fake_span(0, 0, "a.com"),
            fake_span(1, 0, "b.com"),
            fake_span(2, 0, "c.com"),
        ];

        state.handle_action(Action::FocusNextLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(0));
        state.handle_action(Action::FocusNextLink, &tx);
        state.handle_action(Action::FocusNextLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(2));
        state.handle_action(Action::FocusNextLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(2), "clamped at the end");

        state.tabs[0].focused_link = None;
        state.handle_action(Action::FocusPrevLink, &tx);
        assert_eq!(
            state.tabs[0].focused_link,
            Some(2),
            "Up starts from the end"
        );
        state.handle_action(Action::FocusPrevLink, &tx);
        state.handle_action(Action::FocusPrevLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(0));
        state.handle_action(Action::FocusPrevLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(0), "clamped at the start");
    }

    /// End-to-end: Enter opens whichever link currently has focus.
    #[tokio::test]
    async fn activate_focused_link_opens_a_new_tab() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);
        state.clickable_spans = vec![fake_span(0, 0, "9.9.9.9")];
        state.handle_action(Action::FocusNextLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(0));

        state.handle_action(Action::ActivateFocusedLink, &tx);

        assert_eq!(state.tabs.len(), 2, "should have opened a new tab");
        assert_eq!(state.tabs[1].target, Target::parse("9.9.9.9").unwrap());
    }

    /// End-to-end: clicking a hostname/IP found in the active pane's
    /// content (see `ui::linkscan`) opens it, through the same
    /// `decode_mouse` + `handle_action` path the real event loop uses.
    #[tokio::test]
    async fn clicking_a_pane_content_link_opens_it() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);
        state.clickable_spans = vec![fake_span(10, 20, "example.com")];

        let terminal_area = ratatui::layout::Rect::new(0, 0, 100, 40);
        let action = decode_mouse(&state.mode, terminal_area, &state, left_click(10, 22));
        assert_eq!(
            action,
            Action::OpenLink(Target::parse("example.com").unwrap())
        );
        state.handle_action(action, &tx);

        assert_eq!(state.tabs.len(), 2);
        assert_eq!(state.tabs[1].target, Target::parse("example.com").unwrap());
    }

    /// Switching panes must reset link focus, the same as it already
    /// resets scroll -- a stale focus index from a differently-shaped
    /// pane's link list would be meaningless (and could even point past
    /// the new pane's list entirely).
    #[tokio::test]
    async fn switching_panes_resets_focused_link() {
        let mut state = AppState::new(Config::default(), ProviderDb::default());
        let tx = test_sender();
        state.open_tab(local_target(), None, &tx);
        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::FocusNextLink, &tx);
        assert_eq!(state.tabs[0].focused_link, Some(0));

        state.handle_action(Action::NextPane, &tx);
        assert_eq!(state.tabs[0].focused_link, None);
    }

    /// `clickable_spans` reflects the *previous* draw (see its doc
    /// comment), so switching what the active pane shows must clear it:
    /// otherwise the very next frame renders using spans positioned for
    /// content that's no longer there, overlaying leftover link text on
    /// top of the new pane's differently-laid-out content. Covers every
    /// action that changes what the active pane shows.
    #[tokio::test]
    async fn switching_pane_or_tab_clears_stale_clickable_spans() {
        let tx = test_sender();

        let mut state = AppState::new(Config::default(), ProviderDb::default());
        state.open_tab(local_target(), None, &tx);
        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::NextPane, &tx);
        assert!(state.clickable_spans.is_empty(), "NextPane");

        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::PrevPane, &tx);
        assert!(state.clickable_spans.is_empty(), "PrevPane");

        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::SelectPane(2), &tx);
        assert!(state.clickable_spans.is_empty(), "SelectPane");

        state.open_tab(Target::parse("192.168.1.2").unwrap(), None, &tx);
        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::SelectHostTab(0), &tx);
        assert!(state.clickable_spans.is_empty(), "SelectHostTab");

        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::NextTab, &tx);
        assert!(state.clickable_spans.is_empty(), "NextTab");

        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::PrevTab, &tx);
        assert!(state.clickable_spans.is_empty(), "PrevTab");

        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.open_tab(Target::parse("192.168.1.3").unwrap(), None, &tx);
        assert!(state.clickable_spans.is_empty(), "open_tab");

        state.clickable_spans = vec![fake_span(0, 0, "a.com")];
        state.handle_action(Action::CloseTab, &tx);
        assert!(state.clickable_spans.is_empty(), "CloseTab");
    }
}
