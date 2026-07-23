---
status: implemented
decisions: ADR-0001, ADR-0002, ADR-0003
---

# Design: focused view lifetimes

## Problem

Linktop's overview owns time: on a terminal it stays live, samples continuously, and
reacts to keys. The `link` and `peers` subcommands instead print one instantaneous
cache view and exit. That is especially weak for neighbors, where a single kernel-cache
read can omit useful entries and says nothing about state changes during an observation
window.

The overview also selects its full multi-panel layout at heights where the address and
neighbor panels have only one or two content rows. A view that reports 16 peers while
showing one, without an overflow marker or drill-down, is not honest enough.

## Context

Linktop has three output contracts already: an alternate-screen TUI for a terminal, a
bounded report when stdout is redirected, and an explicit append-only `--plain`
stream. It also has four different jobs:

- overview: correlate local link state with bounded active path probes;
- link: observe local route, radio, resolver, addresses, and interface counters;
- peers: observe the native neighbor cache without scanning;
- speed: run one explicit bounded load experiment against an operator-selected host.

These jobs should not all have the same lifetime. Snapshot and speed are transactions.
Link and peers become more useful when they dwell. Machine-readable output must remain
bounded unless the caller explicitly asks for a stream.

Netmon is a separate, future Rust evidence/replay library. Linktop may eventually use
its policy-neutral records or replay explanations, but local diagnosis must remain
available without netmon, its stores, or its live fusion deployment.

Linktop is an operator instrument, so the live and ordinary text views show the full
locally observed evidence: SSID, interface and peer addresses, gateways, MAC addresses,
kernel state, and OUI attribution. Sanitization is an export concern. A future share
mode may redact a copied artifact, but the primary display must not silently replace
operator evidence with placeholders.

## Non-goals

- Do not make a pipe silently run forever; bounded output remains the automation
  default.
- Do not populate the neighbor cache with ARP, ICMP, mDNS, or subnet scans. Dwell means
  repeated passive observation, not active discovery.
- Do not turn speed into a persistent monitor or run it without an explicit target.
- Do not add controller credentials, historical stores, private identity, or the live
  fusion plane to Linktop.
- Do not make netmon a required dependency before its Rust schema and replay gates
  pass.
- Do not redact the local operator view. Keep automated capture artifacts private by
  default instead of weakening the instrument.

## Options considered

### Keep every subcommand one-shot

This preserves a simple CLI but makes `peers` and `link` systematically less useful
than the overview. It also gives users no focused interactive path when the overview
cannot allocate enough space.

### Add a separate `watch` subcommand

`linktop watch peers` is explicit, but it duplicates the command hierarchy and makes
the same subject mean different things depending on a wrapper verb. Output mode and
lifetime are orthogonal to subject; the CLI should model them that way.

### Make every subcommand interactive on a TTY

This is mostly right, but snapshot and speed already have natural terminal conditions.
Forcing them into an alternate screen would hide the final artifact and add no useful
interaction.

## Chosen approach

Use subject, output mode, and lifetime as separate axes:

| Invocation | Interactive terminal | Noninteractive output | `--plain` | `--json` |
| --- | --- | --- | --- | --- |
| `linktop` | live overview TUI | one snapshot | live overview stream | not yet global |
| `linktop snapshot` | one report | one report | invalid | one report |
| `linktop link` | live focused TUI | one link snapshot | live focused stream | one snapshot |
| `linktop peers` | live scrollable TUI | one cache snapshot | live focused stream | one snapshot |
| `linktop speed HOST` | bounded progress/result | bounded result | invalid | one result |

Add `--dwell SECONDS` for live overview, link, and peers modes. Without it, an
interactive or plain live view runs until interrupted. With it, the same view exits
after the observation window. `--dwell` never changes a passive command into an active
one. JSON remains a single observation in this slice; a future JSON event stream must
use an explicit `--json-stream` contract rather than overloading `--json`.

Focused monitoring uses workload-specific schedules:

- overview keeps gateway sampling and startup/manual-refresh Internet probes;
- link samples counters every interval and refreshes route/radio state more slowly;
- peers rereads the bounded native cache every interval with single-flight protection,
  and uses local route/interface prefixes to exclude retained entries from a previous
  network on the same interface;
- speed keeps its existing explicit duration and target.

The peers TUI devotes its main body to a scrollable table and keeps evidence source,
cache semantics, gateway role, kernel state, MAC scope, and OUI registrant visible.
It marks partial native-source completion as degraded and says which source failed.
Disappearance is labelled as cache disappearance, never device departure. The overview
shows only a summary and a few rows; every truncated list ends with an explicit
`+N more` handoff to `linktop peers`.

Increase the overview's full-layout height threshold. At intermediate heights it uses
the dense summary rather than constructing technically valid but unreadable panels.
Panel allocation becomes content-aware: local addresses take only the rows they need,
and peers receive the remainder.

### Network transitions

Treat the active path as a generation, identified by the default interface, link type,
SSID, gateway, effective resolver set, IPv4 addresses, and IPv6 /64 prefixes on the
default interface. Using a prefix instead of the full IPv6 address makes privacy-address
rotation stable on every supported platform while still detecting an IPv6 network
change. On macOS, use `scutil --dns` rather than the explicitly non-authoritative
`/etc/resolv.conf`, and mark addresses reported as `temporary` in the operator view.
Re-evaluate that
fingerprint on every link refresh so a switch between house Wi-Fi, a phone hotspot,
Ethernet, or a VPN path becomes an explicit transition rather than a collection of
unrelated failures.

On transition, Linktop increments the path generation, clears gateway latency history,
resets the interface-counter baseline, discards public-edge and radio values from the
old path, refreshes the passive neighbor cache, and schedules fresh Internet probes in
overview mode. Background results carry the generation that launched them; the model
ignores a result from an older generation so a slow public-IP or radio lookup cannot
repopulate the new path with stale evidence. New peer snapshots are bounded to the
current interface and address prefixes. Rows retained across two networks that reuse the
same prefixes cannot be distinguished passively, so they remain labelled as cache
evidence rather than new-path presence. The event bus records the old and new path labels plus the
fingerprint dimensions that changed. A temporarily incomplete route during association is a
transition state, not immediate proof that the new network failed.

### Self-contained visual QA

Ratatui `TestBackend` renders canonical overview, link, and peers fixtures at wide,
shallow, narrow, and tall terminal sizes. Tests assert the important content contract:
the focused subject remains visible, truncation is declared, headers and footers fit,
and no panel is selected merely because its border technically fits.

A repository capture command runs each live view in a fixed-size pseudo-terminal with
`--dwell`, captures its final terminal frame, renders that frame to a PNG, and stores
the text and image under the ignored, private `.agents/reports/ui-captures/` directory.
This gives development a repeatable screenshot loop without making the operator the
manual QA bottleneck or committing observed network identifiers.

## Tradeoffs

TTY behavior for `link` and `peers` changes from one-shot to live. Scripts are
protected by the redirected-stdout and `--json` rules, but a person who wants a
terminal one-shot must use `--json`, redirect output, or a future explicit snapshot
modifier. Repeated passive cache reads add small local process cost, bounded by the
interval, command deadlines, and single-flight scheduling.

The first focused views keep process-local history only. They do not persist first/last
seen facts across runs. Durable evidence and replay belong to the optional future
netmon integration, after its schema gate.

## Implementation plan

1. Add typed overview/link/peers monitor modes and single-flight peer polling. This is
   reversible without changing serialized snapshots.
2. Add focused Ratatui layouts, peer scrolling, overflow markers, and a taller compact
   breakpoint. This is a presentation-only change.
3. Allow `--plain` with `link` and `peers`; add bounded `--dwell` to live modes. Preserve
   existing pipe and JSON behavior.
4. Add generation-tagged path transitions so old asynchronous observations cannot
   cross a Wi-Fi, hotspot, Ethernet, or VPN switch.
5. Add PTY-independent render and CLI-policy tests plus fixed-size private captures for
   shallow terminals, overflow, focus selection, and lifetime validation.
6. Record the implemented behavior in ADR-0002 and ADR-0003, then update README
   examples and install the new binary.

## Decision gates

- If passive peer polling exceeds its interval or overlaps, stop and reduce cadence;
  never stack cache-reader processes.
- If users need durable peer history or cross-source explanations, require a versioned
  netmon Rust API and a separate integration ADR rather than adding a local database.
- If a second machine consumer needs live structured events, add explicit NDJSON with
  a schema version; do not make `--json` continuous.
- If TTY auto-interactivity breaks a real one-shot human workflow, add an explicit
  `--once` modifier without reverting pipe safety.
- If path identity needs evidence beyond interface, SSID, gateway, resolvers, and local
  addresses, extend the typed fingerprint; do not infer network identity from public IP
  alone.

## Open questions

- Whether the focused link view should later include optional gateway RTT is deferred;
  the first version remains local/passive so its activity boundary is unambiguous.
- Netmon crate names and versioned record types remain open until the empirical schema
  gate passes.

---
Decided: 2026-07-22
