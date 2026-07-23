# linktop

`linktop` is a live terminal instrument for the network path from this host to
the public edge. It paints immediately, keeps every bounded probe visible, and
puts the useful evidence in one place: active link, route, radio state, gateway
latency distribution, DNS, HTTPS, public address, and the native neighbor cache.

![Status: experimental](https://img.shields.io/badge/status-experimental-6b7280)

## What it shows

- The active interface, link type, gateway, resolvers, local addresses, and
  SSID when the platform exposes it.
- Wi-Fi signal/noise, channel, PHY, and link rate when native tools expose
  those fields. Missing platform capabilities show as unavailable; they do not
  abort the rest of the diagnosis.
- Passive active-interface byte/packet rates, totals, errors, and drops from native
  kernel counters. These sit beside gateway RTT so ordinary load-related latency is
  visible without generating a bandwidth test.
- Rolling gateway RTT with p50, p95, mean absolute inter-packet delay
  variation, sample variance in JSON, and packet loss.
- Bounded DNS, HTTPS, and public-edge probes at startup and on manual refresh.
  The rolling active probe is one gateway echo per interval; slow Internet
  checks are not repeated in the background.
- Passive neighbor-cache entries for the active interface and its current
  subnets. This reads what the operating system already knows and excludes
  rows outside the new path's interface or prefixes after a switch; same-prefix
  rows that the kernel retains remain explicitly cache evidence, not proof of
  current presence. Linktop does not scan the LAN or claim that cached peers
  are alive. If only some native cache
  sources complete, Linktop marks the evidence `DEGRADED` instead of implying
  that the view is complete. When a
  local Nmap or Wireshark manufacturer registry is installed, universally
  administered MAC prefixes gain a source-labelled registrant hint. Local or
  randomized MACs are labelled `local/private`; neither label is device
  identity. Kernel states are translated conservatively: for example,
  `REACHABLE` means recently confirmed by the kernel, while `STALE` means the
  cache remains but confirmation has expired.
- Path transitions. A change in interface, link type, SSID, gateway, resolver
  set, IPv4 address, or IPv6 /64 prefix starts a new observation generation.
  Linktop clears path-scoped histories and ignores late results from the old
  Wi-Fi, hotspot, Ethernet, or VPN path.

The default command opens the dashboard when both stdin and stdout are terminals.
With redirected input or output, it prints one bounded snapshot instead of
opening a keyboard-driven alternate screen.
`linktop link` and `linktop peers` also open live focused views on a terminal;
the peers view is scrollable and rereads only the native cache. Redirecting
either command with no lifetime option remains a one-shot snapshot. Use
`--plain` to explicitly choose a timestamped, append-only stream, and
`--dwell SECONDS` to request and bound any live
overview, link, or peers observation. Plain mode is useful for logs, `tee`,
remote shells, and support handoffs; it never emits cursor-control sequences.

```sh
linktop
linktop --plain
linktop --plain --interval 5 | tee linktop.log
linktop --dwell 30
linktop snapshot
linktop snapshot --json
linktop link
linktop link --json
linktop peers
linktop peers --dwell 30
linktop peers --plain --dwell 30 | tee peers.log
linktop peers --json
linktop speed 192.168.1.10
```

`speed` is deliberately explicit: it requires an `iperf3` server chosen by the
operator, runs a fixed-duration TCP test, and compares gateway latency before
and during load. It never selects or contacts a bandwidth-test service on its
own.

The ordinary operator views show the identifiers the host actually exposes,
including SSIDs, addresses, MACs, and registrant hints; Linktop does not redact
them. On recent macOS releases, the operating system may return the literal
`<redacted>` for SSID/BSSID unless the calling application has Location
Services authorization. Linktop reports that as `SSID hidden by macOS` instead
of implying that its own display censored the value. Gateway, resolver, address,
radio, and peer evidence remain available.

## Install

Rust 1.88 or newer is required.

```sh
just install
```

This runs the canonical checks, installs `linktop` into Cargo's bin directory,
and creates `pinglet` and `pingl` compatibility symlinks beside it. Cargo's bin
directory is already on the PATH in the author's dotfiles; on another machine,
add `${CARGO_HOME:-$HOME/.cargo}/bin` to `PATH`.

For development on this machine, run `just install-dev` once. It points the PATH
entry at this checkout's debug binary, so every later `just check`, Cargo build,
or visual capture immediately becomes the `linktop` launched from the shell. Run
`just install` again when a standalone release binary is preferred.

For development without installing:

```sh
cargo run
just check
```

The visual QA loop captures the real alternate-screen TUI in a fixed-size
pseudo-terminal, then writes a text frame and PNG under the private ignored
`.agents/reports/ui-captures/` directory. It requires `tmux`, ImageMagick, and
a local monospace font (Menlo is used on macOS):

```sh
just capture-ui overview 160 26
just capture-ui peers 100 24
just capture-ui link 100 24
```

## Controls

- `q` or `Esc`: quit
- `r`: refresh link and slow probes now
- `p`: pause or resume probes
- `j`/`k` or arrow keys in `peers`: scroll one row
- `PgUp`/`PgDn`, `g`/`G`, or Home/End in `peers`: move through the cache

## Boundary

Linktop diagnoses the current host's active path. It does not capture packets,
manage network controllers, retain history, own credentials, publish telemetry,
or perform identity/presence fusion. Those are separate lifecycles even when
their evidence is useful beside a linktop report. Linktop may later consume a
versioned, policy-neutral Rust evidence/replay API from netmon, but its direct
local diagnosis remains independently usable.

## License

Licensed under the MIT License.
