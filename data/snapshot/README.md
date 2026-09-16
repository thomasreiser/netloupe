# Bundled range-list snapshot

These files are what ships inside the `netloupe` binary so hosting-provider
detection works offline on first run (see `providers::ranges` and
`build.rs`, which embeds every file here except this one).

Regenerate with:

```
cargo xtask update-data --snapshot
```

Naming: `<provider-id>-<source-index>.<ext>`, matching the order of that
provider's `[[ranges.sources]]` entries in `data/providers/<id>.toml`.
`GENERATED_AT` is an RFC 3339 timestamp of the last real regeneration, shown
in the Hosting pane's data-age footer as a fallback when no fresher copy
exists in the user's cache directory.

## Known-stale entries

- `azure-0.json`: Azure's "IP Ranges and Service Tags" JSON is published at
  a URL that rotates weekly and isn't discoverable by a stable link (see
  `CLAUDE.md`'s data-sources table). This file is a small hand-built sample
  in the real schema, **not** a live download, so Azure detection works out
  of the box but only covers the ranges listed here. Run `update-data` with
  a resolved URL (`--azure-url <url>`, found via the current download page)
  to refresh it with real data.
