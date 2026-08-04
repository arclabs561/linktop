# linktop

Linktop shows how the host is connected and what changes.

`ping` and `traceroute` test selected targets. Linktop reads the host's route,
physical link, resolvers, addresses, interface counters, process traffic, and
native neighbor cache together. When a connection changes or degrades, it shows
which layer changed and which evidence is missing.

Linktop starts passively. Internet reachability remains `UNTESTED` until an
operator enables bounded probes.

```text
UNTESTED  default route en0 → 192.0.2.1 observed; Internet reachability is not tested
history  +00:04 returned · 1 prior · 2m · known BSSID · 1 variant(s) · place unknown
passive coverage COLLECTING · route observed · neighbor cache pending · radio unavailable · probes off · history cited
fixture-host ──▶ en0 [wifi / Northstar Lab] ──▶ 192.0.2.1
```

This excerpt comes from a public-synthetic replay scene, not an operator's
host. Local output is not redacted. Status: experimental.

## Install

Cargo installation requires Rust 1.88 or newer:

```sh
cargo install linktop --version 0.1.3 --locked
```

Prebuilt archives are available from the
[`linktop-v0.1.3` release](https://github.com/arclabs561/linktop/releases/tag/linktop-v0.1.3).
The macOS archives are not signed or notarized.

From a checkout:

```sh
just install
just install-dev
```

## Quick start

```sh
linktop                         # live passive TUI in a terminal
linktop snapshot                # one passive report
linktop link                    # route, link, resolver, and address evidence
linktop peers                   # native ARP/NDP cache; no LAN scan
linktop probe                   # one bounded active path diagnosis
linktop readiness               # purpose-specific active checks
linktop snapshot --json         # finite machine-readable report
linktop --plain --dwell 30      # bounded live text
linktop --jsonl --dwell 30      # bounded live machine records
```

The default, `link`, and `peers` views are live when stdin and stdout are
terminals. Redirected output is finite unless `--plain` or `--jsonl` selects a
live stream. Use JSON or JSONL for programs rather than parsing the screen.

In the TUI, `q` or `Esc` quits, `a` toggles active probes, and `1`, `2`, `3`, or
`Tab` switches views.

## Passive observation

Passive mode reads operating-system state:

- the effective route, physical underlay, next hop, resolvers, and addresses;
- Wi-Fi association and radio details when the platform exposes them;
- interface traffic, errors, and drops;
- bounded process traffic on supported platforms; and
- the native neighbor cache and its kernel reachability states.

Missing capabilities remain visible and do not abort unrelated checks.
Neighbor-cache entries are not proof that a device is present or active.
Linktop does not resolve peer names or scan the LAN.

## Active diagnosis

Active work is opt-in through `probe`, `readiness`, `speed`, `--active`, or the
TUI `a` key. Depending on the command, it may send next-hop ICMP, resolve DNS,
request `https://example.com`, look up the public-egress address, or run an
operator-selected `iperf3` load test. Every operation has a deadline.

`linktop probe` reports gateway, DNS, and HTTPS results in dependency order.
It exits `1` for a tested path failure and `2` when no verdict is available.

`linktop readiness` evaluates interactive use from a bounded path snapshot.
Calls and bulk transfer remain `not_tested` without purpose-specific
measurements. Idle-background status uses three bounded process-accounting
samples; it does not claim that the host is absolutely idle.

`linktop speed HOST` requires a local `iperf3` binary and a reachable iperf3
server selected by the operator.

## Saved evidence

Live observations are not persisted by default. `--history PATH` or
`LINKTOP_HISTORY` opts into a host-path JSONL log:

```sh
linktop --history ~/.local/state/linktop/host-path.jsonl
linktop history ~/.local/state/linktop/host-path.jsonl
```

History can contain SSIDs, BSSIDs, addresses, gateways, resolvers, and
association metadata. New directories use mode `0700` and logs use `0600` on
Unix.

`review` reads normalized Netbraid saved-capture JSONL. It does not accept raw
PCAP, run TShark, contact the network, or modify the input.

```sh
linktop review records.jsonl
linktop review a.jsonl --compare-with b.jsonl --json
linktop capsule pack history.jsonl --output incident-capsule
linktop capsule verify incident-capsule
```

Comparisons report corroborated, conflicting, or not-comparable packet-shape
evidence. Agreement is not proof of the same event, device, person, service, or
intent.

## Boundaries

Linktop does not capture packets, scan wireless networks or the LAN, manage
controllers, persist without an explicit path, publish telemetry, or perform
identity or presence fusion. Active commands transmit only when selected.

It uses Netbraid's evidence and replay types for history and saved-artifact
workflows. Live host diagnosis does not require a Netbraid service.

## Documentation

- [Architecture](docs/architecture.md)
- [Design decisions](DECISIONS.md)
- [Visual QA](docs/visual-qa.md)
- [Roadmap](docs/roadmap.md)

## Development

```sh
cargo run
just check
```

`just check` runs formatting, tests, clippy, rustdoc warnings, package checks,
and saved-evidence contract checks.

## License

MIT.
