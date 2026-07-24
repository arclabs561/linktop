---
id: 0005
status: accepted
governs: src/metrics.rs, src/model.rs, src/net.rs, src/plain.rs, src/ui.rs, README.md, docs/design/focused-view-lifetimes.md
why: a single health color currently treats supporting lookups and partial peer coverage as path failures, judges latency spread from too few samples, and makes the operator reconstruct cause from equally weighted rows.
rejected: remain a raw telemetry viewer (honest but leaves the main diagnostic work to the operator); keep one scalar health heuristic and tune thresholds (cannot represent coverage or supporting evidence); add opaque confidence scores or learned labels before durable ground truth exists (false precision without calibration).
supersedes: none
superseded_by: none
extends: 0001, 0002, 0003
confidence: high
review_trigger: revisit when purpose-specific readiness profiles, durable baselines, flow or controller evidence, calibrated fingerprint models, or a versioned netmon replay API exist.
---

# ADR-0005: Rank diagnosis by evidence and causal scope

**Status**: Accepted
**Date**: 2026-07-23
**Deciders**: operator

## Context

Linktop collects several kinds of evidence with different causal roles. Gateway
echo, DNS resolution, and HTTPS reachability exercise successive portions of
the active host path. Public-address lookup identifies observed egress but is
not required for the path to work. Native neighbor-cache completeness describes
passive evidence coverage, not Internet reachability.

The first live model flattened those roles into one health value. Any failed
public-address provider could mark the entire path failed. One missing native
neighbor source could make a successful snapshot degraded. The rolling gateway
distribution could diagnose latency spread after only a few samples, and one
old loss remained health-affecting for the full ninety-sample display window.
The overview then selected the first problem row instead of explaining an
ordered failure chain.

This is especially misleading during startup and Wi-Fi or hotspot transitions,
when evidence is incomplete by design. It also makes future intelligence unsafe:
if a cache binding, an advertisement, a fingerprint candidate, and a verified
identity all become ordinary strings, the interface will eventually present
inference as fact.

## Decision

Model the current result as an evidence-ranked situation rather than deriving
meaning independently in each renderer.

### Separate path health from evidence coverage

Gateway, DNS, and HTTPS are path-critical probes. Their failed or degraded
results can affect path health in dependency order. Public-address lookup is
supporting enrichment: failure or slowness is visible as unavailable evidence
but cannot by itself make the active path failed or degraded.

Passive neighbor and radio availability likewise affect evidence coverage, not
path health. Coverage is typed as collecting, complete, partial, or unavailable
rather than borrowing path-health words such as degraded. Snapshot JSON
preserves the existing summary health field as the path assessment and adds an
explicit evidence-coverage field so automation can distinguish “the tested path
works” from “all supporting evidence was available.”

### Require sufficient and recent evidence

A next-hop probe execution failure remains immediate. Absence of an ICMP echo
reply is `Unavailable`, not `Failed`, because a usable gateway may filter echo;
successful downstream DNS and HTTPS evidence can still establish a responding
path with partial next-hop coverage. Distribution-based latency spread is not
assessed until five replies exist. Health uses the most recent twenty attempts,
while the graph and descriptive distribution may retain up to ninety. This
prevents startup noise and an old isolated event from governing the current
verdict indefinitely.

Loss remains visible at every sample count. Any loss in the bounded rolling
assessment is material; expressing that as a percentage threshold would imply
precision that a window of at most twenty attempts cannot observe. A wide
p50-to-p95 spread affects health only when mean absolute adjacent variation is
also at least fifteen milliseconds. This keeps one isolated startup or Wi-Fi
spike visible in the graph without letting it control the path verdict. These
rules are a general interactive-path default, not a claim about every workload.
A future purpose-specific readiness model crosses the review trigger.

Every settled probe keeps its observation age. A long-lived active overview
refreshes DNS and HTTPS every sixty seconds; those results stop supporting a
current verdict after seventy-five seconds. Renderers disclose age, staleness,
and baseline warm-up rather than presenting old or insufficient evidence as a
fresh conclusion.

### Explain one ordered situation

The live model classifies the leading situation in this precedence:

1. paused observation or a path transition;
2. next-hop probe execution failure;
3. local interface errors or drops observed during the latest interval;
4. stale DNS or HTTPS path evidence;
5. an unlocalized downstream failure when gateway or DNS evidence is
   unavailable;
6. DNS failure after the gateway is reachable;
7. HTTPS failure after gateway and DNS evidence;
8. recent gateway loss or latency variation after baseline warm-up;
9. degraded DNS or HTTPS latency;
10. initial collection or gateway baseline warm-up;
11. usable path with supporting-evidence gaps;
12. usable path with complete current evidence.

The overview renders that classification, the decisive observation, coverage,
and a cause-specific next move. A downstream failure is not promoted above the
earlier failed dependency or localized through an unavailable one. A supporting
evidence gap is never phrased as a path cause.

### Constrain peer intelligence

Peer rows are ordered by operator attention: current source disagreement,
gateway role, binding changes, cache returns, kernel-state changes, recent
kernel-confirmed states, new session observations, then stable cache evidence.
Each attention label names what the source supports, such as
`source disagreement`, `binding changed`, `cache returned`, `kernel-confirmed`,
`kernel checking`, `new in session`, or `cached only`.

These are not application-activity labels. Statements about flows, services,
device roles, people, or intent require a source with that vantage point and
remain observed, advertised, derived, candidate, verified, or unknown. Linktop
does not manufacture a numeric confidence value.

Multiple native sources may report the same interface and address. Linktop
reconciles those rows into one snapshot identity before updating dwell history.
Contradictory bindings become current `source disagreement` evidence and make
coverage partial; they do not become temporal `binding changed` events.

## Options considered

- **Remain a raw telemetry viewer.** This preserves source facts but leaves the
  main job, deciding which fact matters and what to do next, to the operator on
  every incident.
- **Tune the existing scalar health heuristic.** Better constants cannot
  represent path success with partial enrichment, baseline warm-up, source
  coverage, or causal dependency.
- **Add learned scoring now.** There is no representative labelled history
  against which to calibrate confidence, drift, or false-positive rates.
  Deterministic rules with visible evidence are the reversible first step.
- **Treat every failed check as equally important.** Rejected because a
  public-address provider, incomplete peer cache, gateway, resolver, and HTTPS
  service do not have the same causal relationship to the operator's path.

## Consequences

Startup spends several gateway attempts in an explicit warm-up state instead of
calling a sparse distribution healthy or degraded. A public-address lookup may
show `N/A` while the tested path remains healthy. Partial peer or radio evidence
is a visible coverage gap without turning the path amber.

The general health label remains a lossy projection for compatibility. New
renderers and structured consumers should prefer the typed situation and
evidence-coverage fields. Purpose profiles, persistent baselines, application
flows, device fingerprints, multi-vantage correlation, and natural-language
explanations remain later layers; this decision establishes the provenance and
abstention rules they must preserve.

## Lineage

Extends ADR-0001's visible probe lifecycle, ADR-0002's shared output model, and
ADR-0003's path-generation fencing with an evidence and inference contract.
