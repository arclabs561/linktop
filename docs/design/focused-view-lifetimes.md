---
status: implemented
decisions: ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0008
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

- overview: observe local context passively by default and correlate it with
  bounded path probes only after explicit active enablement;
- link: observe local route, radio, resolver, addresses, and interface counters;
- peers: observe the native neighbor cache without scanning;
- speed: run one explicit bounded load experiment against an operator-selected host.

These jobs should not all have the same lifetime. Snapshot and speed are transactions.
Link and peers become more useful when they dwell. Machine-readable output must remain
bounded unless the caller explicitly asks for a stream.

Netmon is a separate product whose policy-neutral Rust evidence/replay crates Linktop
imports at an exact Git revision for optional prior-context comparison. Local
diagnosis remains available without the Netmon executable, stores, controller, or live
fusion deployment.

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
- Do not add controller credentials, a Linktop-owned historical store, private
  identity policy, or the live fusion plane to Linktop.
- Do not make a Netmon process, store, controller, or deployment a Linktop runtime
  requirement.
- Do not redact the local operator view. Keep automated capture artifacts private by
  default instead of weakening the instrument.

## Options considered

### Keep every subcommand one-shot

This keeps the CLI small but makes `peers` and `link` systematically less useful
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

An explicitly bounded plain stream closes with a human-readable dwell summary.
It reports the current generation plus up to eight completed generations seen
by the process, preserving interface, radio, workload-window, and peer-cache
aggregates only when the command's collector plan acquired them. A link or peers
session says `not collected` for disabled sources rather than presenting absent
collection as zero activity.

Focused monitoring uses workload-specific schedules:

- passive overview keeps route, DHCP/association, counter, radio,
  process-accounting, and neighbor-cache observation;
  active overview adds next-hop sampling plus startup, path-change,
  manual-refresh, and sixty-second DNS/HTTPS checks;
- link samples counters every interval and refreshes route/radio state more slowly;
- peers rereads the bounded native cache every interval with single-flight protection,
  and uses local route/interface prefixes to exclude retained entries from a previous
  network on the same interface;
- speed keeps its existing explicit duration and target.

The live interval does not imply a full platform inventory on every tick. A
lightweight route/interface/address check runs at the sample cadence so a
house-Wi-Fi, hotspot, Ethernet, or VPN transition is detected promptly. Hostname,
SSID, effective resolver, and other full topology evidence refresh at startup,
manual refresh, a lightweight path change, or a ten-second ceiling. Gateway and
interface counters remain on the fast cadence. On macOS the fast path check
also reads `ipconfig getsummary`, while the slower Wi-Fi inventory, peer
collector, and one-second `nettop` workload sample remain single-flight on
their subject-specific schedules. Workload accounting is eligible every five
seconds in the overview and resets on a path generation.

Peer dwell keeps a process-local, path-generation-scoped observation ledger.
For each interface/address binding it records first and last positive
observation, count, latest and prior kernel state, state and MAC-binding
changes, confirmed cache disappearance, and later return. Missing rows are
marked cache-absent only after a complete native-source read; a partial ARP or
NDP result may add positive evidence but cannot support negative evidence.

The peers TUI devotes its main body to a scrollable table and keeps evidence source,
cache semantics, gateway role, kernel state, MAC scope, and OUI registrant visible.
It marks partial native-source completion as degraded and says which source failed.
Disappearance is labelled as cache disappearance, never device departure. The overview
shows only cache count and evidence coverage; detailed rows belong to the focused peers
view.

The overview session also supports `1` overview, `2` link, `3` peers, and `Tab`
cycling without restarting the monitor. Its collection plan remains the overview
superset while a focused view is displayed. Direct `linktop link` and `linktop peers`
sessions keep their narrower passive collection plans; presentation navigation must
not silently change a command's activity boundary.

Increase the overview's full-layout height threshold. At intermediate heights it uses
the dense summary rather than constructing technically valid but unreadable panels.
Panel allocation becomes content-aware: local addresses take only the rows they need,
and peers receive the remainder.

### Network transitions

Treat the active path as a generation, identified by the default interface,
link type, SSID, macOS Wi-Fi connection ID, gateway, effective resolver set,
IPv4 addresses, and IPv6 /64 prefixes on the default interface. The connection
ID detects reassociation even when macOS privacy policy hides the SSID. DHCP
lease timestamps remain context rather than identity so renewal does not create
a false transition. Using a prefix instead of the full IPv6 address makes
privacy-address rotation stable on every supported platform while still
detecting an IPv6 network change. On macOS, use `scutil --dns` rather than the
explicitly non-authoritative `/etc/resolv.conf`, and mark addresses reported as
`temporary` in the operator view.
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
transition state, not immediate proof that the new network failed. If a previously
confirmed path temporarily has no default interface, retain that generation for up to
three seconds, disclose `switching networks`, and launch no new collectors against the
retained topology. A recovered route resumes normal fingerprint comparison; a route
that remains absent after the grace period becomes a new incomplete generation.

Before resetting those live accumulators, Linktop copies the completed
generation's typed identity and dwell aggregates into a bounded, immutable
process-local queue. That queue is output history, not current evidence: late
results cannot update it, it cannot affect the new generation's diagnosis, and
it is discarded when the process exits. Detailed peer rows do not cross this
boundary; only their aggregate cache-dwell summary does.

### Self-contained visual QA

Ratatui `TestBackend` renders canonical overview, link, and peers fixtures at wide,
shallow, narrow, and tall terminal sizes. Tests assert the important content contract:
the focused subject remains visible, truncation is declared, headers and footers fit,
and no panel is selected merely because its border technically fits.

The built-in `screenshot` transaction runs any live subject against the same monitor,
model, and Ratatui renderer in a fixed-size headless terminal. Repeatable,
comma-delimited `--at` values save private text and styled SVG frames at explicit
elapsed times; the latest requested time is the bounded transaction lifetime. The
portable lane needs no TTY, tmux, ImageMagick, or manual operator screenshot.

An optional `--native` lane runs the current executable in a fixed-size tmux PTY and
captures its real alternate-screen output at the same times. It writes plain text,
ANSI, and self-contained HTML so QA can inspect terminal negotiation and colors as
well as geometry. Native capture requires tmux but remains headless and does not
foreground a terminal emulator. Timestamped names keep multiple frames and runs
distinct. Repository development points both lanes at the ignored
`.agents/reports/ui-captures/` directory so observed network identifiers are not
committed.

## Tradeoffs

TTY behavior for `link` and `peers` changes from one-shot to live. Scripts are
protected by the redirected-stdout and `--json` rules, but a person who wants a
terminal one-shot must use `--json`, redirect output, or a future explicit snapshot
modifier. Repeated passive cache reads add small local process cost, bounded by the
interval, command deadlines, and single-flight scheduling.

The focused link and peers views keep process-local history only. Their live
first/last observations reset on every path generation. An explicit bounded
plain dwell may report a completed generation from its in-process queue, but
neither form is persisted across runs. The overview can explicitly read and
append a private Netmon v0 host-path JSONL log; it does not make focused cache
rows into a durable peer inventory.

## Implementation plan

1. Add typed overview/link/peers monitor modes and single-flight peer polling. This is
   reversible without changing serialized snapshots.
2. Add focused Ratatui layouts, peer scrolling, overflow markers, and a taller compact
   breakpoint. This is a presentation-only change.
3. Allow `--plain` with `link` and `peers`; add bounded `--dwell` to live modes. Preserve
   existing pipe and JSON behavior.
4. Add generation-tagged path transitions so old asynchronous observations cannot
   cross a Wi-Fi, hotspot, Ethernet, or VPN switch.
5. Add PTY-independent render and CLI-policy tests plus a built-in fixed-size,
   multi-frame screenshot transaction for shallow terminals, overflow, focus
   selection, and lifetime validation.
6. Record the implemented behavior in ADR-0002 and ADR-0003, then update README
   examples and install the new binary.

## Decision gates

- If passive peer polling exceeds its interval or overlaps, stop and reduce cadence;
  never stack cache-reader processes.
- If users need durable peer history or cross-source explanations, extend the
  versioned Netmon contract under a separate decision rather than adding a Linktop
  database.
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
- Netmon's experimental crate names and v0 host-path records may still change until
  the stable multi-modal schema gate passes.

---
Decided: 2026-07-22
