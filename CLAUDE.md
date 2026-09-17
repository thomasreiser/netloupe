# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

**netloupe** is a terminal UI (TUI) for inspecting hosts. The user enters a hostname or IP address. The tool then runs checks in parallel (DNS, mail security, ICMP/TCP ping, traceroute, ports, TLS, HTTP, IP/ASN, **hosting provider detection**, geolocation, reputation) and shows the results in panes. Each host gets its own top-level tab, so several hosts can be inspected side by side.

```
[ example.com ] [ 8.8.8.8 ] [ mail.foo.de ] [+]
 Overview │ DNS │ Mail │ Ping/Trace │ Ports │ TLS │ HTTP │ IP/ASN │ Hosting │ Geo │ Rep
```

### Goals
- Fast, keyboard-driven, and fully responsive: the UI never blocks on network I/O.
- A single static binary that works without root where possible.
- Useful offline for everything that doesn't need the network (GeoIP, provider IP ranges, IP classification).
- Explainable results: every conclusion shows the evidence it's based on.

### Non-goals
- Not a full vulnerability scanner or an nmap replacement.
- No web UI and no daemon mode.
- No mandatory paid APIs. Third-party intel (AbuseIPDB, Shodan, ...) is optional and needs a key.

## Panes

| # | Pane | Content |
|---|---|---|
| 1 | Overview | Dashboard: IPs, ASN, provider badges, country, ping sparkline, cert expiry, SPF/DMARC/DNSSEC status |
| 2 | DNS | A/AAAA/CNAME/MX/NS/SOA/TXT/CAA/SRV/PTR, DNSSEC chain, resolver comparison, delegation trace, AXFR/ANY attempts, NSEC/NSEC3 zone-signing detection, CT-log subdomains (reused from Alt. hosts), opt-in full NSEC zone walk |
| 3 | Mail | SPF (flattened, lookup count), DMARC, DKIM (common selectors), MTA-STS, TLS-RPT, BIMI, SMTP banner/STARTTLS |
| 4 | Ping/Trace | ICMP + TCP ping with live sparkline, MTR-style traceroute with ASN/provider per hop |
| 5 | Ports | Opt-in scan of a configurable port list, banners |
| 6 | TLS | Full per-certificate detail for the whole chain (serial, fingerprints, public key, extensions, SCTs, ...), SANs, expiry, protocol/cipher, ACME issuance analysis |
| 7 | HTTP | Status, redirect chain, timing breakdown, security headers, per-version support table (HTTP/1.0, HTTP/1.1, HTTP/2 TLS, h2c, HTTP/3), plain-HTTP-on-port-80 reachability |
| 8 | IP/ASN | ASN, prefix, RPKI state, RDAP (RIR, owner, abuse contact), IP class (private/CGNAT/bogon/anycast) |
| 9 | Hosting | Detected cloud/CDN/hosting/DNS/mail providers, with layers and evidence (see below) |
| 10 | Geo | Country/region/city, timezone, org, connection type, accuracy hint, a low-resolution world map zoomed to the coordinate with a pinpoint and nearby major-city labels |
| 11 | Rep | DNSBLs, Tor exit list, optional API providers |

## Hosting provider detection

Goal: answer questions like "Is this behind Cloudflare?", "Is the origin on AWS?", "Who hosts the DNS and the mail?"

### Layers
One host can involve several providers at once, so results are reported **per layer** rather than as a single verdict:

| Layer | Example |
|---|---|
| `edge` | CDN/WAF/reverse proxy in front (Cloudflare, CloudFront, Akamai, Fastly, Azure Front Door) |
| `origin` | Where the application actually runs, when it can be determined (AWS, Azure, GCP, Hetzner, Vercel, ...) |
| `dns` | Authoritative DNS provider (Route 53, Cloudflare DNS, Azure DNS, ...) |
| `mail` | Mail provider from MX/SPF (Google Workspace, Microsoft 365, Proton, ...) |
| `saas` | Hints from TXT verification records (Atlassian, Salesforce, ...), shown as "uses", not "hosts" |

### Signals, strongest first
1. **Official IP range lists**, matched with a longest-prefix lookup. Many providers also publish region/service tags (e.g. AWS `CLOUDFRONT` vs `EC2`, `eu-central-1`), and those should be shown.
2. **ASN**: the origin AS of the prefix, matched against a known provider ASN table.
3. **CNAME chain patterns**, e.g. `*.cloudfront.net`, `*.azureedge.net`, `*.edgekey.net`.
4. **HTTP response headers**, e.g. `cf-ray`, `x-amz-cf-id`, `x-azure-ref`, `x-vercel-id`, `server: AkamaiGHost`.
5. **NS records**, e.g. `*.ns.cloudflare.com`, `ns-*.awsdns-*`, `*.azure-dns.*`.
6. **PTR records**, e.g. `*.compute.amazonaws.com`, `*.your-server.de`.
7. **TLS certificate** issuer and SANs (e.g. Cloudflare-issued edge certificates, `*.azurewebsites.net` SAN).
8. **MX/SPF includes** for the mail layer, e.g. `_spf.google.com`, `spf.protection.outlook.com`.

### Confidence
- Each signal has a weight defined in the signature file. The engine sums the weights per provider and layer and maps the total to `High` / `Medium` / `Low`.
- An IP range match or an ASN match alone is enough for `High`. A header or CNAME match alone gives `Medium`.
- **Always show the evidence list** in the pane (e.g. `IP 104.16.x ∈ cloudflare ips-v4`, `header cf-ray present`).
- Conflicting signals are expected (e.g. an edge on Cloudflare and a CNAME to AWS) and should be reported as separate layers, not as an error.
- When an edge provider is detected, state clearly that the origin is hidden unless other signals reveal it. Never guess.

### Data sources (IP ranges)

| Provider | Source |
|---|---|
| AWS | `https://ip-ranges.amazonaws.com/ip-ranges.json` |
| Cloudflare | `https://www.cloudflare.com/ips-v4`, `https://www.cloudflare.com/ips-v6` |
| Google Cloud | `https://www.gstatic.com/ipranges/cloud.json` (all Google: `goog.json`) |
| Azure | "Azure IP Ranges and Service Tags – Public Cloud" JSON (the download URL changes weekly; resolve it from the Microsoft download page) |
| Oracle Cloud | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` |
| Fastly | `https://api.fastly.com/public-ip-list` |
| DigitalOcean | `https://digitalocean.com/geo/google.csv` |
| GitHub | `https://api.github.com/meta` |
| Others | No official list, so use ASN matching (see the table below) |

Verify URLs when implementing a fetcher, because providers occasionally move these. Every fetcher must tolerate format changes and fail per provider without breaking the others.

### Known provider ASNs (seed list, extend in data files)

| Provider | ASNs |
|---|---|
| Amazon / AWS | 16509, 14618 |
| Google | 15169, 396982 |
| Microsoft / Azure | 8075 |
| Cloudflare | 13335 |
| Akamai | 20940, 16625 |
| Akamai (Linode) | 63949 |
| Fastly | 54113 |
| Hetzner | 24940 |
| OVHcloud | 16276 |
| DigitalOcean | 14061 |
| Oracle | 31898 |
| IONOS | 8560 |

ASNs are data, not code: they live in `data/providers/*.toml`, not in Rust match arms.

### Signature file format

One TOML file per provider in `data/providers/`, embedded into the binary at build time:

```toml
id = "cloudflare"
name = "Cloudflare"
kind = ["cdn", "dns", "waf"]

[ranges]
sources = [
  { url = "https://www.cloudflare.com/ips-v4", format = "plain" },
  { url = "https://www.cloudflare.com/ips-v6", format = "plain" },
]

[asn]
numbers = [13335]

[[signal]]
layer = "edge"
type = "header"
name = "cf-ray"
weight = 60

[[signal]]
layer = "edge"
type = "header"
name = "server"
value_regex = "(?i)^cloudflare$"
weight = 50

[[signal]]
layer = "dns"
type = "ns"
pattern = "*.ns.cloudflare.com"
weight = 90

[[signal]]
layer = "edge"
type = "cname"
pattern = "*.cdn.cloudflare.net"
weight = 70
```

Supported `format` values: `plain` (one CIDR per line), `aws-json`, `gcp-json`, `azure-servicetags`, `oracle-json`, `fastly-json`, `github-meta`, `csv`. Each format has its own parser in `providers/formats/`, covered by fixture tests.

### Data lifecycle
- A **snapshot** of all range lists ships with the binary (`data/snapshot/`, generated by `cargo xtask update-data`), so detection works offline on first run.
- `netloupe update-data` downloads fresh lists into `$XDG_CACHE_HOME/netloupe/ranges/`, using ETag/If-Modified-Since. The cache takes precedence over the snapshot.
- Show the data age in the Hosting pane footer, and warn when it's older than 30 days (configurable).
- Build one prefix trie per address family at startup, in a background task, from all providers. Lookups must be O(prefix length) and non-blocking.

### Geo pane world map
Natural Earth vector data, rasterized by `cargo xtask update-geo-data` into `data/geo/` (coastline/border bitmaps + a cities table) and committed -- no runtime download. `src/worldmap.rs` renders it (pure, synchronous, no I/O): see its doc comments for the zoom/dash/label logic.

## Tech stack

- **Language:** Rust (stable, edition 2021)
- **TUI:** `ratatui` + `crossterm`
- **Async runtime:** `tokio`
- **DNS:** `hickory-resolver` / `hickory-proto` (including DNSSEC and custom resolvers)
- **ICMP:** `surge-ping`, with a TCP-connect ping as the fallback
- **TLS:** `rustls`, `tokio-rustls`, `x509-parser`
- **HTTP:** `reqwest` (rustls backend, no OpenSSL)
- **IP prefixes:** `ipnet` plus a longest-prefix-match table (e.g. `ip_network_table`)
- **Pattern matching:** `globset` for hostname patterns, `regex` for header values
- **GeoIP:** `maxminddb` with GeoLite2 City/ASN databases, downloaded automatically (see Configuration) once MaxMind credentials are set, never committed
- **RDAP/WHOIS:** RDAP over HTTP first, with raw WHOIS on port 43 as the fallback
- **CLI/config:** `clap` (derive), `serde` + `toml`, `directories` for XDG paths
- **Errors:** `thiserror` in library modules, `anyhow` only in `main.rs` and `xtask`
- **Logging:** `tracing` + `tracing-appender`, written **to a file only**, because stdout/stderr belong to the TUI

Add new dependencies only when needed. Prefer pure-Rust crates and avoid anything that pulls in OpenSSL.

## Repository layout

```
src/
  main.rs              # CLI parsing (tui | update-data | check --json), terminal setup/teardown
  app.rs               # AppState, tab management, event loop
  event.rs             # Input + message types (Action, CheckEvent)
  target.rs            # Parsing/normalizing input: hostname, IPv4, IPv6, IDN, URL → host
  config.rs
  geoip.rs             # Background GeoLite2 City/ASN downloader (MaxMind GeoIP Update API)
  retry.rs             # Jittered-backoff retry for calls to third-party helper APIs
  worldmap.rs          # Pure ASCII world-map rendering (Geo pane): zoom/pin/city-label logic
  ui/                  # Rendering only; no I/O, no business logic
    mod.rs
    tabs.rs
    linkscan.rs        # Finds hostnames/IPs in rendered pane output, makes them clickable
    panes/             # one file per pane (overview.rs, dns.rs, hosting.rs, ...)
    widgets/           # reusable widgets (sparkline, kv_table, status_badge, evidence_list, worldmap)
  checks/              # One module per check; no ratatui imports here
    mod.rs             # Check trait + registry
    dns.rs
    mail.rs            # SPF/DMARC/DKIM/MTA-STS
    ping.rs
    trace.rs
    ports.rs
    tls.rs
    http.rs
    ipinfo.rs          # ASN, RDAP, RPKI, IP classification
    hosting.rs         # Collects signals from other checks + runs the provider engine
    geo.rs
    reputation.rs      # DNSBLs + optional API providers
  providers/           # Provider detection engine (sync, pure, fully unit-testable)
    mod.rs             # ProviderDb, Signal, Evidence, Layer, Confidence
    signatures.rs      # Loading/validating data/providers/*.toml
    ranges.rs          # Prefix tables, snapshot + cache loading
    update.rs          # Downloading/refreshing range lists
    formats/           # One parser per range-list format
data/
  providers/           # *.toml signature files (embedded via include_str!/build.rs)
  snapshot/            # Bundled range-list snapshot (generated, committed)
  geo/                 # World-map bitmaps + cities.csv (generated, committed; see worldmap.rs)
xtask/                 # cargo xtask update-data, update-geo-data, lint-signatures
tests/
  fixtures/            # canned DNS responses, certs, HTTP responses, range-list samples
```

## Architecture rules

1. **Rendering is pure.** `ui::*` only reads `AppState` and draws it. It never awaits, spawns tasks, or mutates state.
2. **Checks are independent async tasks.** Each check implements the `Check` trait, receives a `Target` and a `CancellationToken`, and reports progress through an `mpsc::Sender<CheckEvent>`. Checks never touch UI types.
3. **One state owner.** Only the event loop in `app.rs` mutates `AppState`, applying incoming `CheckEvent`s and key actions.
4. **Cancellation.** Closing a tab or re-running a check must cancel the running tasks via their token. Don't leak tasks.
5. **Timeouts everywhere.** Every network operation has an explicit timeout taken from config. No unbounded waits.
6. **Partial results are normal.** A failed check shows its error inside its own pane and never takes down the tab or the app.
7. **Streaming checks** (ping, traceroute, port scan) emit incremental events so the UI updates live.
8. **Reuse results, don't repeat queries.** `hosting` consumes the results of DNS, HTTP, TLS and IP/ASN checks through a shared per-tab result store instead of issuing its own lookups. It re-evaluates whenever a new input arrives, so its pane fills in progressively.
9. **The provider engine is synchronous and pure.** `providers::evaluate(&Inputs) -> Vec<Detection>` does no I/O, which keeps it trivially testable.
10. **Headless mode.** `netloupe check <target> --json` runs the same checks without the TUI and prints structured results, which serves scripting and integration tests.
11. **Retry third-party helper calls, never the target itself.** A request to some other service that merely *supports* a check -- crt.sh, RDAP, MaxMind's GeoIP Update API, a provider's IP-range list host, the Tor exit list, AbuseIPDB -- gets `crate::retry::run` (a small jittered-backoff loop; classify failures with `retry::classify_send_error`/`retry::classify_status`, or `Failure::Retryable`/`Failure::Fatal` directly when the shape doesn't fit those). A request to the target under inspection (`checks::http`, `checks::tls`, `checks::acme`'s challenge probes, `checks::ports`, ...) never gets this: a failure there *is* the measurement, and retrying it would misreport what's actually there.

## Commands

```bash
cargo build                           # debug build
cargo run -- example.com 8.8.8.8      # open with two tabs
cargo run -- check example.com --json # headless run
cargo run -- check example.com --resolver 1.1.1.1 --json # headless run against a specific DNS server
cargo run -- update-data              # refresh provider range lists into the cache
cargo xtask update-data               # regenerate the bundled snapshot in data/snapshot/
cargo xtask lint-signatures           # validate all data/providers/*.toml
cargo xtask update-geo-data           # regenerate data/geo/ (world map bitmaps + cities.csv)
cargo test                            # unit + fixture tests (no network)
cargo test -- --ignored               # network-dependent integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

Before finishing any task, run `cargo fmt`, `cargo clippy` (with no warnings), and `cargo test`. If you touched `data/providers/`, also run `cargo xtask lint-signatures`.

## Code conventions

- No `unwrap()` or `expect()` outside tests and provably infallible cases. Leave a comment when it's the latter.
- Library errors use a `thiserror` enum per module, and messages should be understandable to the end user.
- Keep functions small and name them after what they check, e.g. `spf_lookup_count`, not `process`.
- Keep parsing logic (SPF flattening, DMARC parsing, IP classification, range-list formats) in plain synchronous functions so it can be unit-tested without the network.
- Provider knowledge (ranges, ASNs, patterns, headers) is **data** in `data/providers/`, never hardcoded in Rust.
- Public items get doc comments. Comments explain *why*, not *what*.
- Comments and docs describe the code's **current** behavior only -- never a changelog. Don't write "now does X" (implying it didn't before), "used to be Y", "previously", "was added because", "a bug report showed...", "this fixes...", or reference a prior version, a past bug, or the change that produced the current state. A reader who's never seen the old code should be able to read a comment and learn only what's true today; git history (`git log`, commit messages, blame) is where the story of *how it got that way* belongs, not the code itself. This applies to `CLAUDE.md`/`README.md` too.
- Keep `CLAUDE.md`, `README.md`, and code comments in sync with the code *as part of* every change that affects them, not as a follow-up: a behavior change, a new module, a changed keybinding, or a renamed concept means updating whatever documents it in the same change.
- Commits follow Conventional Commits (`feat:`, `fix:`, `refactor:`, `data:` for signature updates, ...).

## Testing

- Unit tests must not hit the network. Use fixtures in `tests/fixtures/` and trait-based fakes for resolvers and sockets.
- Every range-list parser has a fixture test using a trimmed real sample, including one malformed-input case.
- Provider engine tests are table-driven, with an input set (IPs, CNAMEs, headers, NS, MX) mapped to the expected detections per layer and confidence. At minimum cover:
  - a Cloudflare-proxied site (edge = Cloudflare, origin unknown)
  - CloudFront in front of S3 (edge and origin both AWS, with different service tags)
  - an Azure App Service host (CNAME `*.azurewebsites.net`)
  - a plain Hetzner VPS (ASN only)
  - a domain with DNS on Route 53 and mail on Microsoft 365
  - an IP with no match (must return no detection, not a guess)
- Network tests are marked `#[ignore]` and use only stable public targets (`example.com`, `1.1.1.1`, `8.8.8.8`).
- UI rendering is tested with ratatui's `TestBackend` and buffer assertions for key panes.

## Platform and privilege notes

- **ICMP:** raw sockets need root or `CAP_NET_RAW`. On Linux, try an unprivileged ICMP datagram socket first (`net.ipv4.ping_group_range`). If that fails, fall back to TCP ping and show a hint in the pane instead of crashing.
- **Traceroute** has the same privilege constraints. Degrade gracefully.
- Targets: Linux and macOS first, Windows best effort. Put platform-specific code behind `cfg` in dedicated modules.

## Safety and ethics

- **Port scans** are opt-in per tab and show a confirmation prompt the first time: scanning hosts you don't own may be illegal (e.g. §202c StGB in Germany). Keep the default port list small and rate-limit probes.
- Never do brute-force subdomain enumeration by default.
- Range-list downloads identify themselves with a proper `User-Agent` and respect caching headers, so provider endpoints aren't hammered.
- API keys come from the config file or environment variables only. Never log them and never write them into test fixtures.

## Configuration

Config lives at `$XDG_CONFIG_HOME/netloupe/config.toml`. Every option has a sensible default so the tool runs with no config file at all. It covers:
- resolvers to use (the system resolver by default, plus a comparison set: 1.1.1.1, 8.8.8.8, 9.9.9.9)
- **Per-tab custom DNS server.** Every new-tab flow (`Ctrl+t`, the alt-hostname picker, clicking a link in pane content) prompts for a DNS server via `Mode::ChooseResolver` before opening the tab, pre-filled with the last choice and, as placeholder text, this machine's actual resolver(s) (`checks::dns::system_resolver_ips`). Blank means the system's normal resolver; every check on that tab queries whatever was chosen, threaded through `checks::dns::DnsOpts`. `check <target> --resolver <ip>` is the headless equivalent.
- **In-app settings editor** (`s`, see `src/settings.rs`): edits a curated subset of `Config` fields in place -- `↑`/`↓` selects, Enter edits and commits, Esc cancels. A committed field applies immediately and is written back to `config.toml` right away.
- timeouts per check type
- the port list for scans
- **GeoLite2 databases, downloaded automatically** once `[geoip].account_id`/`license_key` are set (`src/geoip.rs`, MaxMind's GeoIP Update API), cached under `$XDG_CACHE_HOME/netloupe/geoip/` and refreshed on `[geoip].update_interval`. `checks::geo` only ever reads that cache; headless `check` does too, but never triggers a download.
- `[hosting]`: enabled providers, confidence thresholds, max data age before warning, and an extra signature directory for user-defined providers (e.g. an internal company IP range)
- optional API keys for reputation providers
- keybindings and color theme
- `show_country_flags`: off by default, since regional-indicator flag emoji don't render everywhere (notably many Linux terminals, tmux, and SSH); `theme::with_country_flag` is the single place every pane showing a country goes through

## Keybindings (defaults)

| Key | Action |
|---|---|
| `Ctrl+t` / `Ctrl+w` | New tab / close tab |
| `Tab` / `Shift+Tab` | Next / previous host tab |
| `1`–`9`, `0`, `-` or `←` `→` | Switch pane |
| `↑`/`↓` | Move keyboard focus between clickable hostnames/IPs in the pane |
| `Enter` | Open the focused hostname/IP in a new tab |
| `PgUp`/`PgDn` | Scroll the current pane's content |
| `r` | Re-run checks for the current pane |
| `R` | Re-run all checks for the current host |
| `e` | Toggle evidence details (Hosting pane) |
| `a` | Open the alternative-hostname picker (Overview) |
| `w` | Walk an NSEC-signed zone for its full name list (DNS) |
| `Space` | Pause/resume the continuous ICMP/TCP ping (Ping/Trace) |
| `s` | Open the settings editor |
| `y` | Copy the current pane as text |
| `?` | Help overlay |
| `q` | Quit |

Mouse support is additive, not a replacement for the keyboard: click a host/pane tab to switch, scroll to scroll, and every modal popup is click-navigable too (cancel by clicking outside it, click `[y]`/`[N]`, click a list row to select). Decoded in `app.rs`'s `decode_mouse`/`ui::decode_popup_mouse`, hit-testing against the exact geometry each popup's `render_*` already used, so the two can't drift apart. See those functions' doc comments for per-mode specifics.

### Clickable hostnames/IPs in pane content
Every hostname/IP anywhere in the active pane's rendered content is clickable, opening it through the same `Mode::ChooseResolver` prompt as any other new tab. `ui::linkscan::scan` finds these by scanning the already-rendered screen buffer after each frame rather than teaching every pane to track it, validating candidates through `Target::parse_strict`; see its doc comments for the exact matching/false-positive rules. `↑`/`↓` move keyboard focus between them, `Enter` opens the focused one, `PgUp`/`PgDn`/the mouse wheel scroll.

## Roadmap

1. **MVP:** tabs, target parsing, DNS pane, ICMP/TCP ping, Overview
2. IP/ASN + RDAP, Geo (GeoLite2), **Hosting (ranges + ASN + CNAME + NS)**
3. HTTP + TLS panes, with header/cert signals feeding Hosting
4. Mail pane
5. Ports, reputation, `check --json`, user-defined signatures

## Working with Claude

- Before a larger change, outline the plan and the files you'll touch.
- When adding a check, add a `checks/<name>.rs` module, register it, add a `ui/panes/<name>.rs` pane, write fixture tests, and update the pane table in this file.
- When adding a provider, add `data/providers/<id>.toml` (plus a parser in `providers/formats/` if its list uses a new format), add fixture and engine tests, run `cargo xtask lint-signatures`, and update the tables above if relevant.
- Don't add features beyond the request. Suggest them instead.
- If a crate's API or a provider's endpoint is uncertain, check docs.rs or the provider's documentation rather than guessing.