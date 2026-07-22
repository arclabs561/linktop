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
- Passive neighbor-cache entries. This reads what the operating system already
  knows; it does not scan the LAN or claim that cached peers are alive. When a
  local Nmap or Wireshark manufacturer registry is installed, universally
  administered MAC prefixes gain a source-labelled registrant hint. Local or
  randomized MACs are labelled `local/private`; neither label is device
  identity.

The default command opens the dashboard when stdout is a terminal. In a pipe,
it prints one bounded snapshot instead of emitting terminal control sequences.
Use `--plain` to opt into the same continuing monitor as timestamped,
append-only text. This is useful for logs, `tee`, remote shells, and support
handoffs; it never emits cursor-control sequences.

```sh
linktop
linktop --plain
linktop --plain --interval 5 | tee linktop.log
linktop snapshot
linktop snapshot --json
linktop link --json
linktop peers
linktop speed 192.168.1.10
```

`speed` is deliberately explicit: it requires an `iperf3` server chosen by the
operator, runs a fixed-duration TCP test, and compares gateway latency before
and during load. It never selects or contacts a bandwidth-test service on its
own.

## Install

Rust 1.88 or newer is required.

```sh
just install
```

This runs the canonical checks, installs `linktop` into Cargo's bin directory,
and creates `pinglet` and `pingl` compatibility symlinks beside it. Cargo's bin
directory is already on the PATH in the author's dotfiles; on another machine,
add `${CARGO_HOME:-$HOME/.cargo}/bin` to `PATH`.

For development without installing:

```sh
cargo run
just check
```

## Controls

- `q` or `Esc`: quit
- `r`: refresh link and slow probes now
- `p`: pause or resume probes

## Boundary

Linktop diagnoses the current host's active path. It does not capture packets,
manage network controllers, retain history, own credentials, publish telemetry,
or perform identity/presence fusion. Those are separate lifecycles even when
their evidence is useful beside a linktop report.

## License

Licensed under the MIT License.
