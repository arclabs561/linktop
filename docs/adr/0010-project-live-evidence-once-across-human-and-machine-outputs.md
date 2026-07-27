---
id: 0010
status: accepted
governs: src/model.rs, src/output.rs, src/main.rs, src/plain.rs, src/ui.rs, README.md, docs/design/focused-view-lifetimes.md, docs/design/network-situation-intelligence.md
why: direct facts and statistical claims become supportable at different evidence horizons, while human and machine live consumers need the same generation-fenced assessment without scraping one another's presentation.
rejected: keep one global warm-up situation (withholds useful direct facts and hides which claim is immature); derive progress independently in each renderer (creates contradictory support and scope); overload finite --json (silently changes automation lifetime); emit delta-only JSONL (requires lossless delivery and hidden reducer state); emit terminal summaries for unbounded streams (fabricates an acquisition end); add scalar confidence (uncalibrated false precision).
supersedes: none
superseded_by: none
extends: 0002, 0003, 0005, 0007
confidence: high
review_trigger: revisit when a stable consumer needs delta or replay semantics, per-peer transition records, cross-process persistence, a new evidence basis, a daemon/service/automatic collector or network publisher is proposed, or a breaking live-v1 field or meaning change.
---

# ADR-0010: project live evidence once across human and machine outputs

**Status**: Accepted
**Date**: 2026-07-26
**Deciders**: operator

## Context

Linktop can know its current route after one observation, cumulative interface
counters after one counter read, an interface rate after two compatible reads,
one probe result after that probe completes, and an RTT variation assessment
only after a larger supported window. Treating all of those as one global
startup phase delays useful facts and makes `uptime` look like evidence.

The TUI and plain stream also grew their own descriptions of readiness. That
made it possible for a diagnosis to use the latest twenty gateway attempts
while a chart described a ninety-attempt session aggregate, or for a machine
consumer to receive a situation without the aggregate that supported it.
Continuous machine consumers otherwise had to scrape prose because `--json`
intentionally remained a finite transaction.

## Decision

Project live Linktop state once as claim-specific, generation-scoped evidence
for both human views and an explicit versioned JSONL stream.

### Claim-specific progress

Every live projection carries the stable ordered claim vector for path context,
interface totals, interface rate, radio link, neighbor cache, workload
attribution, next-hop RTT, DNS reachability, HTTPS reachability, public egress,
and next-hop variation. Each claim names:

- a typed state: `collecting`, `available`, `insufficient`, `stale`,
  `unavailable`, `unsupported`, or `not_collected`;
- a basis: `observed` or `derived`;
- a typed current-sample, current-path-generation, or bounded-assessment scope;
- exact applicable observation, success, required-observation, and valid
  interval counts;
- the source observation span and source age when Linktop actually knows them;
  and
- typed limitation codes with structured counts or source names where needed.

There is no global confidence score. Direct facts become available immediately.
Cumulative counters are useful after the first read; a rate requires the
second compatible read. Each active probe is visible after its first
completion. Next-hop distribution assessment uses the latest twenty attempts,
requires five attempts, and requires at least two successful RTT observations
before adjacent variation is available. A longer RTT sparkline is display
history and is labelled separately from the assessment window.

Process uptime, current path-generation span, source observation span, source
age, and statistical assessment window remain distinct clocks. One must not be
substituted for another.

### One generation-fenced projection

`App` owns the assessment, progress vector, evidence, and optional typed history
context used by TUI, plain, and machine renderers. An asynchronous result is
applied only when its path generation and activity policy are current. Rejected
results cannot alter history or produce a live machine record.

Coverage and evidence payloads are subject-scoped. A focused link view does not
stay collecting because the neighbor or workload collectors were deliberately
not started, and its machine record omits those evidence objects rather than
serializing them as queued. Path context is available only after a default-route
interface is observed; resolver or address evidence alone cannot support the
claim that a default route exists.

Human renderers may rank, abbreviate, page, or group the projection. They
preserve the minimum operator transaction: answer, path, coverage, and next
action. Plain startup groups the collector plan instead of dumping every claim
schema before the first fact. Overview plain output summarizes an initial
neighbor-cache inventory; full rows belong to the focused peers view, while
later material cache changes remain visible.

### Explicit live JSONL

`--jsonl` selects `linktop.live_observation.v1` for live overview, link, and
peers subjects. It is mutually exclusive with human `--plain` and finite
`--json`. It does not change passive or active acquisition policy.

Every line is a self-contained `checkpoint`, path-generation `transition`, or
bounded `final_summary`, with producer, sequence, subject, emission time,
acquisition policy/lifetime/start/elapsed time, generation, assessment,
claim-progress vector, and evidence. The next-hop assessment aggregate is
explicitly named and carries its attempt, success, required, and maximum
window counts. Checkpoints are output snapshots, not deltas. The stream emits
the initial projection, material assessment/progress/path/probe/peer/history
changes, and a full checkpoint at least every five seconds while accepted updates
continue. High-frequency counter, rate, workload, and age-only updates between
those boundaries are suppressed.

Only accepted model updates can emit checkpoints or transitions. A bounded
dwell always emits exactly one final summary, even when it ended before a
second interval. At that terminal boundary, unresolved `collecting` claims
become `insufficient` when they have some support or `unavailable` otherwise,
with a typed bounded-window limitation. An unbounded stream has no natural
terminal boundary and never fabricates a final summary.

An operator-selected unbounded JSONL run is a local stdout projection, not
service or telemetry ownership. It is never implicit, has no built-in
persistence or network publication, and retains Linktop's selected acquisition
policy.

Finite `linktop.observation.v1` and `linktop.speed_experiment.v1` contracts and
their lifetimes do not change. Live v1 is an output contract, not an input or
replay contract; an exact readable golden document gates its current wire
shape. Delta transport, acknowledgements, replay, and typed per-peer
transition records remain separate review-trigger work.

## Options considered

- **One global warm-up state.** Rejected because it withholds route, counter,
  and first-probe facts while unrelated claims mature.
- **Renderer-local progress.** Rejected because support counts, windows, and
  limitations would drift between diagnosis, TUI, prose, and JSONL.
- **Make `--json` continuous.** Rejected because existing pipe consumers rely
  on a bounded document and lifetime.
- **Emit delta-only JSONL.** Rejected because a missed line would make the
  consumer's state unknowable without a replay protocol.
- **Persist live observations by default.** Rejected because Linktop's default
  remains process-local and private; the caller owns stdout and any retention.

## Consequences

Useful facts appear according to their own evidence horizon instead of the
age of the process. Human and machine outputs cite the same current assessment
window and abstention state. Bounded runs end with an honest terminal
projection rather than a forever-collecting snapshot.

The complete JSONL checkpoints can be large, especially when a neighbor cache
contains many rows. Material-change suppression and the periodic ceiling bound
ordinary repetition without creating hidden delta state. Consumers that need
lower-volume deltas, loss recovery, per-peer transition reconstruction, or
replay need a new contract rather than assuming v1 checkpoints are events.
Human wording and responsive layout remain free to improve because machines
have a distinct typed surface.

## Lineage

This fires ADR-0002's structured-live-consumer review trigger, retains
ADR-0003's generation fence, refines ADR-0005's global warm-up language into
claim-specific support, and applies ADR-0007's minimum operator transaction to
progressive evidence.

## Update (2026-07-27): add the just-completed path window

The common projection now carries an additive optional
`evidence.completed_path_window` after a path transition. It joins the newest
immutable completed generation to `last_path_change` and includes prior path
identity and span, transition relation, subject collector scope, typed
interface/radio/workload/neighbor support, source provenance, aggregates, and
limitations. Unsupported radio and unavailable evidence remain distinct;
partial native-cache acquisition names its failed sources. Neighbor
`sources` and `failed_sources` cover the full completed generation; fields
that describe only the terminal collector result are explicitly named
`latest_snapshot_*` so a consumer cannot confuse them with window-wide
provenance.

Live JSONL serializes the object from the same projection used by the wide TUI
and immediate plain transition receipt. Bounded plain output may still show
the entire capped generation ledger. Compact layouts continue to reserve
answer, path, coverage, and action before prior-window detail. Finite
`linktop.observation.v1` is unchanged. This additive live-v1 evidence is not a
delta, acknowledgement, replay, persisted episode, or scalar confidence
contract.
