# linktop

`linktop` shows the current network context of the host. It reports the route,
physical link, resolvers, addresses, interface activity, process traffic, and
native neighbor cache. It starts passively and labels Internet reachability
`UNTESTED` until an operator enables bounded probes.

```text
UNTESTED  default route en0 → 192.0.2.1 observed; Internet reachability is not tested
history  +00:04 returned · 1 prior · 2m · known BSSID · 1 variant(s) · place unknown
passive coverage COLLECTING · route observed · neighbor cache pending · radio unavailable
fixture-host ──▶ en0 [wifi / Northstar Lab] ──▶ 192.0.2.1
```

This is an excerpt from the 7-second, 160-column frame produced by the
`wifi-hotspot-wifi` public-synthetic scene. It is test output, not a capture from
an operator's host. Normal operator views show the identifiers the host
actually exposes; Linktop does not redact local output.

Status: experimental.

## Install

Cargo installation requires Rust 1.88 or newer:

```sh
cargo install linktop --version 0.1.2 --locked
```

Checksummed native archives for x86-64 Linux, Intel macOS, and Apple-silicon
macOS are attached to the
[`linktop-v0.1.2` release](https://github.com/arclabs561/linktop/releases/tag/linktop-v0.1.2):

```sh
gh release download linktop-v0.1.2 \
  --repo arclabs561/linktop \
  --dir linktop-v0.1.2
(cd linktop-v0.1.2 && shasum -a 256 --check SHA256SUMS)
```

The macOS archives are not code-signed or notarized. Cargo installation is the
most portable path.

From a checkout:

```sh
just install       # checked release install plus pinglet/pingl aliases
just install-dev   # point the PATH command at this checkout's debug binary
```

The published package installs only `linktop`. `pinglet` and `pingl` are local
compatibility aliases, not separate packages.

## Use

```sh
linktop                         # passive TUI on a terminal; finite text in a pipe
linktop snapshot                # one passive snapshot
linktop link                    # physical-link evidence
linktop peers                   # native ARP/NDP cache, never an active scan
linktop probe                   # bounded active path diagnosis
linktop readiness               # purpose-specific readiness with explicit gaps
linktop speed 192.0.2.10        # explicit iperf3 load experiment
linktop review records.jsonl    # finite saved-evidence projection
linktop history host-path.jsonl  # finite episode summary
linktop capsule pack history.jsonl --output incident-capsule
linktop capsule verify incident-capsule
```

The default dashboard, `link`, and `peers` become live views only when stdin and
stdout are terminals. Redirected output is finite unless a live output mode is
selected explicitly.

| Mode | Intended consumer | Lifetime |
| --- | --- | --- |
| default TUI | operator | explicit quit or `--dwell` |
| finite text | operator or shell | one observation |
| `--plain` | terminal, log, support handoff | live, optionally bounded |
| `--json` | program or agent | one observation or experiment |
| `--jsonl` | program or agent | live checkpoints and transitions, optionally bounded |

Examples:

```sh
linktop --plain --interval 5
linktop --plain --dwell 30
linktop --jsonl --dwell 30
linktop --active
linktop --active --plain --dwell 30
linktop snapshot --json
linktop link --json
linktop peers --plain --dwell 30
linktop peers --json
linktop readiness --json
```

Plain mode emits timestamped records without cursor control. A bounded dwell
ends with a collector-scoped summary and receipts for completed path
generations. JSONL emits versioned, self-contained checkpoints, transitions,
and a bounded final summary. An unbounded stream does not fabricate a terminal
record or persist itself.

Machine consumers should use JSON rather than parse screen text. Finite
observations use `linktop.observation.v1`; load experiments use
`linktop.speed_experiment.v1`; live records use
`linktop.live_observation.v1`; readiness reports use `linktop.readiness.v0`.

Bounded live windows expose a `linktop.traffic_shape_candidate.v0` feature
summary when valid kernel interface-counter intervals exist. It reports
aggregate direction, byte and packet deltas, mean and peak rates, and
aggregate bytes per packet. It is a comparison candidate only—not endpoint,
protocol, application, person, place, or intent evidence.

Completed path windows also expose an optional
`linktop.path_fingerprint_candidate.v0` comparison digest when at least one
path dimension is observed. It includes an explicit observer scope and names
the contributing host-path fields; it is not endpoint, protocol, device,
person, place, or intent identity, and it does not join observations across
hosts or modalities.

## What passive mode observes

- Effective default route, interface, next hop, resolvers, and local addresses.
- The physical underlay when a VPN owns the effective route.
- Wi-Fi association, BSSID, DHCP, subnet, lease, security, signal, channel,
  PHY, and link rate when platform policy exposes them.
- Interface byte/packet rates, errors, and drops from native counters.
- On macOS, busiest local process groups from a bounded `nettop` interval.
- Native ARP/NDP cache entries and kernel reachability states.
- Path changes across interfaces, links, associations, gateways, resolvers, and
  address prefixes.

Missing platform capabilities remain visible as unavailable or partial evidence
and do not abort unrelated diagnostics.

Neighbor entries are cache evidence. They are not proof that a device is
present, alive, or carrying traffic. Manufacturer registry hints are not device
identity. Linktop does not resolve names or scan the LAN.

Linktop starts a new path generation after a meaningful route, interface,
underlay, association, gateway, resolver, or address change. It clears
generation-scoped histories and ignores late asynchronous results from the old
Wi-Fi, hotspot, Ethernet, or VPN path.

## Active diagnosis

Active work is opt-in through `probe`, `speed`, `--active`, or the TUI `a` key.
It can perform:

- one next-hop ICMP echo per interval;
- DNS resolution and an HTTPS request to `example.com`;
- a bounded public-egress address lookup;
- an operator-selected `iperf3` experiment with gateway latency before and
  during load.

Every command and request has a deadline. Disabling probes clears their current
state and fences results still in flight.

Path status follows dependency order: next hop, DNS, then HTTPS. A gateway may
filter ICMP, so a missing echo is unavailable evidence rather than automatic
path failure. `linktop probe` exits `1` for a tested path failure and `2` when
no verdict is available. Live observation commands reserve non-zero status for
process/runtime failure.

`linktop readiness` takes one bounded active path snapshot and evaluates four
purposes separately: interactive use, calls, bulk transfer, and idle background
health. Interactive use requires current path context plus successful gateway,
DNS, and HTTPS measurements. Calls, bulk transfer, and idle background remain
`not_tested` until voice-specific or load-specific measurements are collected.
Idle background uses three bounded host process-accounting windows and reports
only observed per-process traffic; it does not claim absolute idleness or infer
these properties from ordinary path latency or aggregate interface counters.

## Saved evidence and history

`linktop review INPUT` reads a canonical Netbraid normalized saved-capture JSONL
stream and renders a finite triage projection. It does not accept raw PCAP,
invoke TShark or the Netbraid CLI, contact the network, or modify the input.

```sh
linktop review records.jsonl
linktop review records.jsonl --tail-seconds 30
linktop review records.jsonl --json
```

The report preserves artifact and record digests, acquisition and extractor
provenance, coverage, event bounds, normalization and quarantine counts,
conversation evidence, exclusions, limitations, and candidate TShark display
filters. Endpoints and filters remain drill-down pivots, not claims about a
device, person, service, application, or intent.

`history` reads a canonical private Netbraid host-path JSONL stream and emits a
finite observer-scoped episode report. Episodes are contiguous context-key
runs with onset, latest observation, recurrence/return evidence, observation
counts, and changed dimensions. The report does not infer timeouts, place,
identity, traffic shape, or intent, and it never modifies the source.

```sh
linktop history host-path.jsonl
linktop history host-path.jsonl --json
```

An incident capsule is an explicit private handoff of canonical Netbraid
host-path history. `capsule pack` validates the complete source before
publishing a new directory containing `capsule.json` and `host-path.jsonl`;
`capsule verify` checks the manifest, source digest, and canonical replay form.
Version 0 is lossless and uses the `none` redaction profile. It does not collect
new observations, capture packets, infer identity, or overwrite an existing
capsule. Sanitized export and multi-observer capsules require later contracts.

Linktop does not persist live observations by default. `--history PATH` or
`LINKTOP_HISTORY` opts into a private Netbraid host-path JSONL log:

```sh
linktop --history ~/.local/state/linktop/host-path.jsonl
linktop --plain --dwell 30 \
  --history ~/.local/state/linktop/host-path.jsonl
```

History may contain SSIDs, BSSIDs, addresses, gateways, resolvers, and
association metadata. New directories are mode `0700` and logs mode `0600` on
Unix. Malformed or incompatible logs remain unchanged and become an evidence
limitation; current diagnosis continues.

Recurrence does not prove physical place. Linktop reports available anchors and
explicitly says when place is unknown. It does not perform an ambient Wi-Fi scan
or attach a human location label on its own.

## Visual QA

The screenshot command exercises the production reducer and renderer with
fixed terminal sizes, timed resizes, and replayed keys:

```sh
linktop screenshot overview --scene wifi-hotspot-wifi --at 1,3,5,7 \
  --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24 \
  --resize 7:160x30
```

It supports deterministic headless text/SVG frames and native tmux-backed
terminal captures. A successful transaction writes a checksummed completion
manifest last. See
[Visual QA](https://github.com/arclabs561/linktop/blob/main/docs/visual-qa.md).

## Controls

- `q` or `Esc`: quit
- `r`: refresh the sources allowed by the current policy
- `p`: pause or resume
- `a`: toggle active path probes in the overview
- `1`/`2`/`3` or `Tab`: switch overview, link, and peers views
- `j`/`k`, arrows, `PgUp`/`PgDn`, `g`/`G`, Home/End: scroll peers

Direct `link` and `peers` entry points keep their narrower passive collection
plans. Display navigation does not widen a focused command's activity.

## Boundaries

Linktop does not capture packets, trigger wireless scans, perform LAN discovery,
manage controllers, retain history without an explicit path, own credentials,
publish telemetry, or perform identity/presence fusion.

It uses Netbraid 0.3.0's policy-neutral evidence and replay modules through the
published Rust package with CLI and TShark features disabled. Direct local
observation remains independently useful.

See
[Architecture](https://github.com/arclabs561/linktop/blob/main/docs/architecture.md),
[Design decisions](https://github.com/arclabs561/linktop/blob/main/DECISIONS.md),
and the [Roadmap](https://github.com/arclabs561/linktop/blob/main/docs/roadmap.md).

## Development

```sh
cargo run
just check
```

`just check` runs tests, formatting, clippy, rustdoc warnings, dependency
feature checks, package inventory, and extracted-package tests.

To test the current checkout against a local Netbraid source tree without adding
a path dependency to the manifest:

```sh
NETBRAID_SOURCE=/path/to/netbraid/rust just check-netbraid-source
```

`just mutation-check` is an opt-in `cargo-mutants` check for the path-fingerprint
candidate helper.

## License

MIT.
