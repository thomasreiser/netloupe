//! Input and inter-task message types.
//!
//! `Action` is what the UI layer produces from a key press; `CheckEvent` is
//! what a running check reports back to the event loop. Neither type knows
//! anything about `AppState` or `ratatui` — only `app.rs` interprets them.

use crate::checks::CheckId;
use crate::providers::Detection;
use crate::target::Target;

/// A user-driven action, decoded from raw key input in `app.rs`. Kept
/// separate from `KeyEvent` so key remapping only has to change one place.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    SelectPane(usize),
    NextPane,
    PrevPane,
    RerunPane,
    RerunAll,
    ToggleEvidence,
    CopyPane,
    ToggleHelp,
    Quit,
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
    /// A pane that hasn't been wired up to a real check yet.
    NotImplemented,
}

/// A request to open a new tab for `target`, produced by the "new host"
/// prompt once the user submits it.
#[derive(Debug, Clone)]
pub struct NewHostRequest {
    pub target: Target,
}
