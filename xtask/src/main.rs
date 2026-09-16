//! Developer tasks for netloupe: `cargo xtask <command>`.
//!
//! Kept as a thin wrapper around `netloupe`'s own `providers` module (via
//! the path dependency in this crate's `Cargo.toml`) rather than
//! reimplementing signature loading or format parsing, so the lint and the
//! real engine can never silently drift apart.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use netloupe::providers::signatures;

#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Regenerates the bundled range-list snapshot in `data/snapshot/`.
    UpdateData {
        /// Only refresh this provider's sources (matches its `id` in
        /// `data/providers/<id>.toml`); refreshes every provider by default.
        #[arg(long)]
        provider: Option<String>,
    },
    /// Validates every `data/providers/*.toml` signature file: parses as
    /// TOML, compiles every glob pattern and regex, and checks that
    /// `header` signals have a `name` and every other kind has a `pattern`.
    LintSignatures,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = repo_root()?;

    match cli.command {
        Command::UpdateData { provider } => update_data(&repo_root, provider.as_deref()),
        Command::LintSignatures => lint_signatures(&repo_root),
    }
}

/// The workspace root: this crate lives at `<root>/xtask`.
fn repo_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .context("xtask must live directly under the workspace root")
}

fn lint_signatures(repo_root: &Path) -> Result<()> {
    let providers_dir = repo_root.join("data/providers");
    let mut checked = 0usize;
    let mut entries: Vec<_> = fs::read_dir(&providers_dir)
        .with_context(|| format!("reading {}", providers_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    entries.sort();

    for path in &entries {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        signatures::parse_and_validate(&text)
            .with_context(|| format!("{} failed validation", path.display()))?;
        checked += 1;
        println!("ok   {}", path.file_name().unwrap().to_string_lossy());
    }

    // Cross-file check the per-file validator can't do on its own: ids must
    // be unique across the whole embedded set (build.rs embeds every file
    // in the directory, so a duplicate id would silently shadow one at
    // startup rather than erroring at compile time).
    signatures::load_all(None).context("loading the full embedded signature set")?;

    println!("\n{checked} signature file(s) OK");
    Ok(())
}

fn update_data(repo_root: &Path, only_provider: Option<&str>) -> Result<()> {
    let providers_dir = repo_root.join("data/providers");
    let snapshot_dir = repo_root.join("data/snapshot");
    fs::create_dir_all(&snapshot_dir)?;

    let mut entries: Vec<_> = fs::read_dir(&providers_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    entries.sort();

    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!(
            "netloupe-xtask/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/thomasreiser/netloupe)"
        ))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut refreshed = 0usize;
    let mut failed = Vec::new();

    for path in &entries {
        let text = fs::read_to_string(path)?;
        let loaded = signatures::parse_and_validate(&text)
            .with_context(|| format!("{} failed validation", path.display()))?;
        let Some(ranges) = &loaded.ranges else {
            continue;
        };

        if let Some(only) = only_provider {
            if loaded.signature.id != only {
                continue;
            }
        }

        for (index, source) in ranges.sources.iter().enumerate() {
            let filename = netloupe::providers::ranges::source_filename(
                &loaded.signature.id,
                index,
                source.format,
            );
            print!("fetching {filename} <- {} ... ", source.url);
            match client
                .get(&source.url)
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.bytes())
            {
                Ok(body) => {
                    fs::write(snapshot_dir.join(&filename), &body)?;
                    println!("ok ({} bytes)", body.len());
                    refreshed += 1;
                }
                Err(err) => {
                    println!("FAILED: {err}");
                    failed.push(filename);
                }
            }
        }
    }

    fs::write(
        snapshot_dir.join("GENERATED_AT"),
        chrono::Utc::now().to_rfc3339(),
    )?;

    println!("\nrefreshed {refreshed} source(s)");
    if !failed.is_empty() {
        println!("failed: {}", failed.join(", "));
        println!(
            "(a failed source keeps its last snapshot; per-provider failures never take down the others, same as the runtime loader)"
        );
    }
    if refreshed == 0 && !failed.is_empty() {
        bail!("every source failed to refresh");
    }
    Ok(())
}
