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

### Projection contracts

Presentation, lifetime, retention, and stability are independent properties.
The supported surfaces are organized by the operator or consumer question, not
by the terminal library that happens to render them:

| Surface | Audience and purpose | Lifetime | Persistence | Stability and permitted machine use |
| --- | --- | --- | --- | --- |
| live TUI | human triage, attention, and navigation | continuous or bounded by `--dwell` | process-local only | responsive human presentation; never parse as an API |
| redirected one-shot text | human report, shell handoff, and scrollback | one observation | caller-owned stdout | bounded expert prose; scripts must not parse wording or columns |
| `--plain` / `--dwell` | human log and supervised temporal observation | explicit stream, optionally bounded | caller-owned stdout | timestamped append-only prose; not a structured event API |
| `--json` | agent or program consuming one observation or experiment | one observation or bounded experiment | caller-owned stdout | versioned schema discriminator; one JSON document |
| `--history` | durable host-path recurrence evidence | live overview session | private Netmon `HostPathObservationV0` JSONL | versioned evidence/replay contract; one writer owns each log |
| `screenshot` | human or agent layout QA | bounded frame transaction | private QA files chosen by caller | text/SVG or text/ANSI/HTML artifacts plus a versioned private completion manifest; never network evidence |
| Netmon finite PCAP text | human inspection of a saved capture | one normalization run | caller-owned stdout | bounded expert prose; not for parsing |
| Netmon `pcap --jsonl` | machine use requiring run provenance | one normalization occurrence | caller-owned stdout | versioned manifest, occurrence receipt, records, and quarantines |
| Netmon `pcap --records-jsonl` | reproducible machine ingestion and replay | one deterministic normalization | caller-owned stdout | versioned content-bound records; byte identity is gated |

Every Linktop human projection and JSON document takes its assessment from the
same typed model. A renderer may rank, abbreviate, page, or disclose overflow;
it must not independently redefine path status or evidence coverage. Human
surfaces are deliberately prioritized and bounded. JSON is the complete
subject projection and carries explicit provenance about what was and was not
collected.

`linktop.observation.v1` identifies one snapshot, probe, link, or peers
observation. It includes the producer version, subject, completion time,
wall-clock acquisition start, monotonic elapsed time, acquisition policy and
lifetime, the typed path assessment and evidence
coverage, and subject
evidence. Link evidence includes interface counters when acquired. Peer
evidence includes the host-visible path context and makes the default-gateway
role explicit instead of requiring a consumer to reproduce presentation
logic. Its typed path-filter result comes from the peer collector's actual
interface-prefix scope read; coverage cannot be declared complete from a
separate link snapshot when that read failed or raced. An additive optional
`path_context.link_evidence` object preserves the
network-name and BSSID visibility state, association, host addresses, derived
default-path prefixes, and effective resolvers supplied by that observation.
It is host-visible link evidence, not a physical-place assertion or a settled
attachment/overlay decomposition.
`linktop.speed_experiment.v1`
separately identifies the explicit bounded active load experiment because it is
not a passive host-path assessment.
Earlier raw, unversioned JSON was experimental implementation serialization and
is not a compatibility contract.

The v1 compatibility rule is additive: existing field names, types, meanings,
and nesting do not change within v1. New optional evidence may be added when a
collector gains evidence, but removing a field, changing its type or meaning,
or changing required nesting requires a new schema discriminator. Exact
pretty-JSON golden documents for snapshot, probe, link, peers, and speed gate
the current complete shape, including model-backed nested evidence.

The TUI, one-shot text, and plain stream are for people, including expert
operators. Agents and programs consume versioned JSON or Netmon records, not
screen text. Screenshot artifact names remain a private QA convention.
Automated capture consumers use the versioned completion manifest rather than
parsing those names.

Presentation never widens acquisition. Switching TUI views does not start a new
collector, JSON does not imply completeness beyond its coverage fields, and a
screenshot transaction cannot read or append durable history. The legacy Go
Netmon `events.jsonl` remains fenced from new integrations while the Rust CLI
name collision is retired.

Netmon's saved-capture output and replay contracts are specified in
[`saved-pcap-normalization.md`](https://github.com/arclabs561/netmon/blob/main/docs/saved-pcap-normalization.md).

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

Repeatable `--key AT:KEY` and `--resize AT:COLSxROWS` actions extend that
transaction to responsive and navigational states. For any shared timestamp the
runner drains already-available observations, resizes first, applies keys in CLI
order through the same reducer as the live TUI, and renders last. Actions after
the final frame, terminating keys, and conflicting same-time resizes are invalid.
The headless lane is the deterministic ordering and content authority.

The named `dense-peers` scene provides a synthetic, passive observation history
for overview and peers captures. Generation-tagged link and peer updates flow
through the real model reducer and include 27 current documentation-range
neighbors plus one cache-absent peer. The snapshots deliberately exercise
IPv4/IPv6 overflow, gateway role, missing MAC evidence, source disagreement,
kernel NUD states, binding change, cache disappearance, and return. This is one
maintained product fixture, not a general scenario language, and it cannot be
combined with active probes or durable history. The scene replaces the host
monitor with an inert control loop, so no live route, radio, process, or
neighbor collector can contaminate the fixture.

An optional `--native` lane runs the current executable in a fixed-size tmux PTY and
captures its real alternate-screen output at the same times. It captures one ANSI
pane snapshot, derives plain text from those same bytes, and writes self-contained
HTML so QA can inspect terminal negotiation and colors as well as geometry. Native
capture requires tmux but remains headless and does not
foreground a terminal emulator. Scheduled keys and resizes are replayed through
tmux after a bounded readiness check; the runner settles briefly after actions
and verifies the pane dimensions before capture. The synthetic scene reaches
the native child through an internal screenshot-only environment value rather
than widening normal live CLI behavior. Frame-indexed names record the scene,
scheduled and actual time, actual rendered view, and actual viewport.

After every requested frame and all of its artifacts succeed, the transaction
atomically publishes one pretty-printed `linktop.qa_capture_manifest.v1`. It
records producer/version and executable SHA-256, deterministic or native lane,
requested subject, scene/stage, policy, normalized frame/key/resize schedules,
and each frame's scheduled/actual time, viewport, and rendered view. Artifact
entries use only relative names and include media type, byte length, and SHA-256.
Artifact creation rejects pre-existing paths. Publication rereads the files and
checks frame completeness, order, byte length, and digest, then installs the
completed private temporary inode at a new final path using an exclusive
same-directory hard link; the native lane also matches the visible header to the
recorded view and policy. Failure or interruption leaves no completion manifest.
Consumers rehash artifacts to detect
changes after the pre-publication verification point. The manifest contains no
absolute paths or captured network facts and remains a private QA receipt, not
Netmon evidence, telemetry, or permission to retain observed data.

The output filesystem must support same-directory hard links. Both lanes probe
that capability inside the private output directory before starting the dwell;
unsupported filesystems fail before any frame artifact is produced.

Repository development points both lanes at the ignored
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
- If a machine consumer needs continuous live state, introduce an explicit
  versioned NDJSON event contract and replay fixture; never overload `--json`
  or make an agent scrape the TUI or plain stream.
- If screenshot artifacts gain a consumer outside private QA, design
  publication, retention, sanitization, and compatibility separately; the
  private completion manifest is not that external evidence boundary.

## Open questions

- Whether the focused link view should later include optional gateway RTT is deferred;
  the first version remains local/passive so its activity boundary is unambiguous.
- Netmon's experimental crate names and v0 host-path records may still change until
  the stable multi-modal schema gate passes.

---
Decided: 2026-07-22
