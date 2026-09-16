//! netloupe: a terminal UI for inspecting hosts.
//!
//! Structured as a library plus a thin binary (`main.rs`) so `xtask` and
//! integration tests can reuse the same code, e.g. `providers::signatures`
//! for `cargo xtask lint-signatures`.

pub mod app;
pub mod checks;
pub mod config;
pub mod event;
pub mod geoip;
pub mod providers;
pub mod retry;
pub mod settings;
pub mod target;
pub mod ui;
pub mod worldmap;
