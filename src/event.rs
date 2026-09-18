//! Input and inter-task message types.
//!
//! `Action` is what the UI layer produces from a key press; `CheckEvent` is
//! what a running check reports back to the event loop. Neither type knows
//! anything about `AppState` or `ratatui` — only `app.rs` interprets them.

use crate::checks::CheckId;
use crate::providers::Detection;
use crate::target::Target;

/// A user-driven action, decoded from raw key/mouse input in `app.rs`.
/// Kept separate from `KeyEvent`/`MouseEvent` so remapping either only
/// has to change one place.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    /// Jumps directly to a host tab by index, e.g. from clicking it.
    SelectHostTab(usize),
    /// A hostname/IP found in the active pane's content (see
    /// `ui::linkscan`) was clicked directly: asks which DNS server to
    /// query for it, the same `Mode::ChooseResolver` prompt every other
    /// way of opening a new tab goes through.
    OpenLink(Target),
    SelectPane(usize),
    NextPane,
    PrevPane,
    RerunPane,
    RerunAll,
    ToggleEvidence,
    CopyPane,
    ToggleHelp,
    /// Opens/closes the data-info popup (what was downloaded, when, from
    /// where, and how big it is).
    ToggleDataInfo,
    Quit,
    /// Opens the alternative-hostname picker for the active tab.
    OpenAltNames,
    /// Asks whether to run the opt-in NSEC zone walk for the active tab.
    OpenZoneWalk,
    /// Opens the in-app settings editor.
    OpenSettings,
    /// Pauses/resumes the active tab's continuous ping (Ping/Trace pane).
    TogglePingPause,
    /// Moves the picker's selection up/down (also usable by any future
    /// selectable-list mode).
    SelectUp,
    SelectDown,
    /// Jumps a list-picker mode's selection directly to an index, e.g.
    /// from clicking a row. Interpreted per-mode: in `Mode::SelectAltName`
    /// it also asks which DNS server to query for that name immediately
    /// (a click is one deliberate choice, with no separate mouse
    /// "confirm" step the way Enter is from the keyboard); in
    /// `Mode::Settings` it also starts editing that field, but only when
    /// nothing else is already being edited.
    SelectIndex(usize),
    /// Scrolls the active pane's content, for panes whose content is
    /// taller than the terminal (a long SAN list, a large DNS zone's
    /// records, ...). `ScrollUp`/`ScrollDown` (fine, one-line scrolling)
    /// are reachable only via the mouse wheel -- see `Action::FocusNextLink`
    /// below for why Up/Down don't send them from the keyboard anymore.
    /// `ScrollPageUp`/`ScrollPageDown` (Up on `PgUp`/`PgDn`) are the
    /// keyboard's only scroll action.
    ScrollUp,
    ScrollDown,
    ScrollPageUp,
    ScrollPageDown,
    /// Moves keyboard focus among `AppState::clickable_spans` (the
    /// hostnames/IPs `ui::linkscan` found in the active pane's last
    /// rendered content), one at a time, clamped at the ends -- not
    /// wrapping, matching how `SelectUp`/`SelectDown` already behave in
    /// this app's other list pickers. Bound to Up/Down instead of
    /// scrolling: with every host/IP now clickable, moving between them
    /// is the far more common thing to want from the keyboard than
    /// nudging the scroll position by one line, and `PgUp`/`PgDn` still
    /// cover scrolling.
    FocusNextLink,
    FocusPrevLink,
    /// Opens whichever span currently has focus, if any -- the
    /// keyboard's equivalent of clicking it.
    ActivateFocusedLink,
    /// Raw text typed into the "new host" prompt.
    InputChar(char),
    InputBackspace,
    InputSubmit,
    InputCancel,
    Resize(u16, u16),
    /// Anything not mapped to an action; ignored by the event loop.
    None,
}

/// One check's progress or result, tagged with which tab and check it
/// belongs to so the event loop can route it without the check knowing
/// about tab indices.
#[derive(Debug, Clone)]
pub struct CheckEvent {
    pub tab_id: u64,
    pub check: CheckId,
    pub payload: CheckPayload,
}

/// The status/data payload of a [`CheckEvent`]. Streaming checks (ping,
/// traceroute, ports) emit `Progress` repeatedly before `Done`.
#[derive(Debug, Clone)]
pub enum CheckPayload {
    Started,
    /// An incremental update a streaming check reports as it runs (e.g. one
    /// more ping RTT, one more discovered hop, one more open port).
    Progress(CheckUpdate),
    Done(CheckUpdate),
    Failed(String),
    Cancelled,
}

/// The actual data a check produces. Each variant corresponds to one
/// `checks::*` module; `ui::panes::*` matches on this to render.
#[derive(Debug, Clone)]
pub enum CheckUpdate {
    Dns(crate::checks::dns::DnsResult),
    Ping(crate::checks::ping::PingUpdate),
    IpInfo(crate::checks::ipinfo::IpInfoResult),
    Hosting(Vec<Detection>),
    Mail(crate::checks::mail::MailResult),
    Tls(crate::checks::tls::TlsResult),
    Http(crate::checks::http::HttpResult),
    Geo(crate::checks::geo::GeoResult),
    Reputation(crate::checks::reputation::ReputationResult),
    Trace(crate::checks::trace::TraceUpdate),
    Ports(crate::checks::ports::PortsUpdate),
    AltNames(crate::checks::altnames::AltNamesResult),
    ZoneWalk(crate::checks::zonewalk::ZoneWalkResult),
    Whois(crate::checks::whois::WhoisResult),
    /// A pane that hasn't been wired up to a real check yet.
    NotImplemented,
}

/// A request to open a new tab for `target`, produced by the "new host"
/// prompt once the user submits it.
#[derive(Debug, Clone)]
pub struct NewHostRequest {
    pub target: Target,
}
