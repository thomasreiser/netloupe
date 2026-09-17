# netloupe

![netloupe](netloupe.png)

A terminal UI for inspecting hosts. Enter a hostname or IP; netloupe runs
DNS, mail security, ping/traceroute, ports, TLS, HTTP, IP/ASN, hosting
provider detection, geolocation, and reputation checks in parallel and
shows the results in panes, with evidence behind every conclusion. Each
host gets its own tab, so several can be inspected side by side.

```
[ example.com ] [ 8.8.8.8 ] [ mail.foo.de ] [+]
 Overview │ DNS │ Mail │ Ping/Trace │ Ports │ TLS │ HTTP │ IP/ASN │ Hosting │ Geo │ Rep
```

See `CLAUDE.md` for the full design (panes, the hosting-detection engine
and its signature file format, architecture rules, roadmap).

## Install / run

Requires a recent stable Rust toolchain (`cargo build` uses edition 2021).

```bash
cargo build --release
./target/release/netloupe example.com 8.8.8.8   # open with two tabs
./target/release/netloupe check example.com --json   # headless, scriptable
./target/release/netloupe check example.com --resolver 1.1.1.1 --json  # query a specific DNS server
./target/release/netloupe update-data                # refresh cached provider IP ranges
```

Hosting-provider detection works offline out of the box (a snapshot of
every provider's IP ranges ships in the binary); `update-data` refreshes
the cache with the latest lists.

GeoIP lookups need a MaxMind account: set `[geoip].account_id` /
`license_key` in the config file (or via the in-app settings editor, `s`)
and netloupe downloads the GeoLite2 City/ASN databases itself, refreshing
them on `[geoip].update_interval` (default 1 day). The current status (no
credentials / updating / database age) shows in the bottom-right of the
status line and at the top of the Geo pane. Once a coordinate is found,
the Geo pane also shows a low-resolution world map -- coastlines, country
borders, and major-city names from Natural Earth's public-domain data,
bundled in the binary -- zoomed in with a pinpoint at the location and
whichever nearby big city fits. Everything else works with no setup and
no API keys; reputation lookups use public DNSBLs and the Tor exit list,
with AbuseIPDB as an optional extra if you configure a key.

Opening a new host always asks which DNS server to query (blank for the
system default); the same server is then used for every check on that
tab, not just the DNS pane, and `check --resolver <ip>` is the headless
equivalent.

Config lives at `$XDG_CONFIG_HOME/netloupe/config.toml` (all optional —
see `Config` in `src/config.rs` for every field and its default).

## Keybindings

| Key                          | Action                                                 |
| ---------------------------- | ------------------------------------------------------ |
| `Ctrl+t` / `Ctrl+w`          | New tab / close tab                                    |
| `Tab` / `Shift+Tab`          | Next / previous host tab                               |
| `1`–`9`, `0`, `-` or `←` `→` | Switch pane                                            |
| `↑`/`↓`, `PgUp`/`PgDn`       | Scroll the current pane's content                      |
| `r`                          | Re-run checks for the current pane                     |
| `R`                          | Re-run all checks for the current host                 |
| `e`                          | Toggle evidence details (Hosting pane)                 |
| `a`                          | Open the alternative-hostname picker (Overview)        |
| `w`                          | Walk an NSEC-signed zone for its full name list (DNS)  |
| `Space`                      | Pause/resume the continuous ICMP/TCP ping (Ping/Trace) |
| `s`                          | Open the settings editor                               |
| `y`                          | Copy the current pane as text                          |
| `?`                          | Help overlay                                           |
| `q`                          | Quit                                                   |

Mouse support is additive: click a host tab or "+ new" to switch/open one, click a pane tab to switch panes, and scroll to scroll the active pane's content. Every popup is click-navigable too — click outside a prompt/picker/the settings editor to cancel it, click `[y]`/`[N]` on a confirm prompt, and click a row in the alt-hostname picker or settings list to select (and open/edit) it.

## Development

```bash
cargo test --workspace              # unit + fixture tests, no network
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo xtask lint-signatures         # validate data/providers/*.toml
cargo xtask update-data             # regenerate the bundled data/snapshot/
```

## Status

Implements the roadmap's MVP and phase-2/3/4 panes (DNS, Ping/Trace,
Overview, IP/ASN, Hosting, Mail, TLS, HTTP, Geo, Rep) plus headless
`check --json` and the opt-in Ports scan. Traceroute uses a real ICMP
hop-by-hop trace when a raw socket is available (root, `CAP_NET_RAW`, or
Linux's unprivileged `ping_group_range`), falling back to a TCP-connect
TTL sweep otherwise — that can only say how many hops away the target is,
not which routers are in between, and the pane says so plainly. RPKI
route-origin validation (via RIPEstat's public validator, which covers
global RPKI data, not just RIPE's own region) shows in the `IP/ASN`
pane once an origin AS and prefix are known.
