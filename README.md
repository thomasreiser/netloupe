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
./target/release/netloupe update-data                # refresh cached provider IP ranges
```

Hosting-provider detection works offline out of the box (a snapshot of
every provider's IP ranges ships in the binary); `update-data` refreshes
the cache with the latest lists.

GeoIP lookups need your own MaxMind GeoLite2 `.mmdb` files (not
redistributable, so none are bundled) — point `[geoip].city_db` /
`asn_db` at them in the config file. Everything else works with no setup
and no API keys; reputation lookups use public DNSBLs and the Tor exit
list, with AbuseIPDB as an optional extra if you configure a key.

Config lives at `$XDG_CONFIG_HOME/netloupe/config.toml` (all optional —
see `Config` in `src/config.rs` for every field and its default).

## Keybindings

| Key                          | Action                                                |
| ---------------------------- | ----------------------------------------------------- |
| `Ctrl+t` / `Ctrl+w`          | New tab / close tab                                   |
| `Tab` / `Shift+Tab`          | Next / previous host tab                              |
| `1`–`9`, `0`, `-` or `←` `→` | Switch pane                                           |
| `↑`/`↓`, `PgUp`/`PgDn`       | Scroll the current pane's content                     |
| `r`                          | Re-run checks for the current pane                    |
| `R`                          | Re-run all checks for the current host                |
| `e`                          | Toggle evidence details (Hosting pane)                |
| `a`                          | Open the alternative-hostname picker (Overview)       |
| `w`                          | Walk an NSEC-signed zone for its full name list (DNS) |
| `s`                          | Open the settings editor              |
| `y`                          | Copy the current pane as text                         |
| `?`                          | Help overlay                                          |
| `q`                          | Quit                                                  |

## Development

```bash
cargo test --workspace              # unit + fixture tests, no network
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo xtask lint-signatures         # validate data/providers/*.toml
cargo xtask update-data             # regenerate the bundled data/snapshot/
```

## Status

Implements the roadmap's MVP and phase-2/3 panes (DNS, Ping, Overview,
IP/ASN, Hosting, Mail, TLS, HTTP, Geo, Rep) plus headless `check --json`
and the opt-in Ports scan. **Traceroute isn't implemented yet** — it needs
a raw ICMP socket to receive `Time Exceeded` replies (the same privilege
constraint as ping, see `CLAUDE.md`'s platform notes) plus hand-rolled
packet parsing that felt too risky to ship without being able to verify it
against real routers; the Ping/Trace pane says so plainly rather than
faking hop data. RPKI route-origin validation is also not implemented
(`IP/ASN` pane shows this explicitly rather than guessing).
