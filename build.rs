//! Embeds `data/providers/*.toml` and `data/snapshot/*` into the binary as
//! `(filename, contents)` tables, so detection works offline with zero
//! setup. Regenerated whenever those directories change.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=data/providers");
    println!("cargo:rerun-if-changed=data/snapshot");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("set by cargo");
    let out_dir = env::var("OUT_DIR").expect("set by cargo");

    embed_dir(
        &Path::new(&manifest_dir).join("data/providers"),
        &Path::new(&out_dir).join("embedded_providers.rs"),
        |name| name.ends_with(".toml"),
    );
    embed_dir(
        &Path::new(&manifest_dir).join("data/snapshot"),
        &Path::new(&out_dir).join("embedded_snapshot.rs"),
        |name| name != "README.md",
    );
}

/// Writes a Rust source file at `out_path` defining a `&[(&str, &str)]`
/// array literal (via `include!`), one entry per file in `dir` matching
/// `filter`, sorted by filename for reproducible builds.
fn embed_dir(dir: &Path, out_path: &Path, filter: impl Fn(&str) -> bool) {
    let mut entries: Vec<(String, std::path::PathBuf)> = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        {
            let entry = entry.expect("reading directory entry");
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if filter(&name) {
                entries.push((name, path));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::from("[\n");
    for (name, path) in &entries {
        let path_str = path.display().to_string();
        out.push_str(&format!("    ({name:?}, include_str!({path_str:?})),\n"));
    }
    out.push(']');

    fs::write(out_path, out).unwrap_or_else(|e| panic!("writing {}: {e}", out_path.display()));
}
