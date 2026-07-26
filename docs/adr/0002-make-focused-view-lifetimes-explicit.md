---
id: 0002
status: accepted
governs: src/main.rs, src/net.rs, src/ui.rs, src/plain.rs, src/output.rs, README.md
why: link and neighbor-cache observations become more informative while they dwell, but redirected and machine-readable commands must keep a bounded lifetime unless the caller explicitly requests a stream.
rejected: keep focused commands one-shot everywhere (too little observation time for cache and path changes); add a watch wrapper command (duplicates the subject hierarchy); make every output live (unsafe pipe and automation lifetime); make snapshot and speed interactive (their work already has a natural terminal condition).
supersedes: none
superseded_by: none
extends: 0001
confidence: high
review_trigger: revisit if TTY auto-interactivity breaks a demonstrated one-shot workflow, a machine consumer needs structured live events, or another focused subject is added.
---

# ADR-0002: Make focused view lifetimes explicit

**Status**: Accepted
**Date**: 2026-07-22
**Deciders**: operator

## Context

The original dashboard owns time: it samples until the operator quits. The
original `link` and `peers` commands instead read one instant and exit. A single
neighbor-cache read routinely omits entries or catches an uninformative kernel
state, and the overview cannot allocate enough rows to every peer in a shallow
terminal. At the same time, changing a redirected command into an unbounded
stream would hang scripts that rely on the existing snapshot behavior.

Subject, presentation, and lifetime are separate concerns. Link and peers
benefit from dwelling; snapshot and speed are bounded transactions; terminal,
plain text, and JSON consumers have different interaction contracts.

## Decision

Make `linktop link` and `linktop peers` live focused Ratatui views when both
stdin and stdout are terminals. The link view refreshes local route, radio, addresses, and interface
counters without Internet probes. The peers view rereads only native neighbor
caches, never scans, restricts rows to the active interface and current address
prefixes, and supports keyboard scrolling through the complete current-path cache.
It reports partial native-source completion as degraded evidence. During the
current path generation it also retains process-local first/last observation,
observation count, kernel-state changes, MAC binding changes, confirmed cache
disappearance, and later cache return. An incomplete native-source read may add
positive observations but cannot prove that an unseen row disappeared.

An overview TUI may switch its display in-process with `1` overview, `2` link,
`3` peers, or `Tab`. That session retains the overview collection plan while a
focused display is selected because it already owns the superset of evidence.
The direct `link` and `peers` entry points keep their narrower passive plans and
do not silently widen collection merely to enable every display.

Keep noninteractive `link` and `peers` output as one bounded snapshot when neither
`--plain` nor `--dwell` requests an observation lifetime. `--plain` explicitly
selects an append-only live stream for the overview or either focused subject.
`--dwell SECONDS` requests the corresponding live mode and bounds it without
changing its activity policy. JSON remains one observation; a future continuous
structured contract must use a distinct, versioned event-stream option.

Snapshot and speed remain bounded transactions on terminals and in pipes. The
operator view shows identifiers supplied by the host; sanitization, if added,
is an explicit export mode rather than the default display.

## Options considered

- **Keep focused subjects one-shot.** Rejected because observation time is
  essential to link changes and passively evolving cache state.
- **Add `linktop watch link|peers`.** Rejected because lifetime is orthogonal to
  subject and a wrapper verb duplicates the command hierarchy.
- **Make terminal and redirected forms live by default.** Rejected because a
  pipe must not silently acquire an unbounded lifetime.
- **Make snapshot and speed alternate-screen applications.** Rejected because
  their natural result should remain in terminal scrollback.

## Consequences

An operator running `linktop link` or `linktop peers` now quits explicitly or
uses `--dwell`; a script receiving redirected stdout still gets one report.
Focused monitoring has workload-specific schedules and single-flight cache or
platform readers. The overview summarizes peer evidence with a handoff to the
focused view instead of squeezing inventory into its diagnostic surface. An
operator can drill down without restarting an overview session, while direct
focused invocations still make their lower-activity boundary explicit.
Peer dwell now exposes cache evolution that a one-shot row cannot show, but it
remains path-generation-scoped and disappears when the process exits. A cache
absence is labelled as such, never as device or person departure.

The CLI now has a policy matrix that must be tested as a contract. Adding an
NDJSON stream, a one-shot terminal modifier, or a new focused subject crosses
the review trigger rather than overloading `--json` or changing pipe behavior.

## Lineage

Extends ADR-0001's terminal-first instrument with explicit focused-view and
noninteractive lifetime contracts.

## Update (2026-07-26): bounded plain dwell closes with a scoped summary

When an explicitly bounded plain session ends, append one final process-local
dwell summary after the live event stream. The summary includes the current
path generation and up to eight completed generations observed by the same
process. It labels each generation as current or completed and reports only
evidence collected by that command's overview, link, or peers plan; disabled
collectors are reported as `not collected`, not as zero activity.

This closing summary does not change the lifetime of an unbounded plain stream,
make JSON continuous, persist observations, or widen a focused command's
acquisition plan.

## Update (2026-07-26): version finite machine projections

Replace the experimental direct serialization of implementation structs with
explicit finite document contracts. Snapshot, probe, link, and peers emit one
`linktop.observation.v1` document containing the producer version, subject,
completion time, acquisition policy and lifetime, typed path assessment,
evidence coverage, and the complete subject evidence. Link evidence includes interface counters when
available. Peer evidence includes the current path context and an explicit
default-gateway role per binding. An additive optional
`path_context.link_evidence` object carries typed network-name and BSSID
visibility, association, host addresses, derived default-path prefixes, and
effective resolvers when the same one-shot observation supplied link evidence.
It does not claim a physical place or resolve the future
attachment-versus-overlay model.

The explicit load transaction emits `linktop.speed_experiment.v1` because it is
a bounded active experiment rather than another passive path observation.
Earlier unversioned JSON is not retained as a compatibility contract. Human
prose remains intentionally free to improve; agents and programs consume the
versioned JSON documents instead of scraping TUI, finite text, or plain-stream
output. Continuous structured state still requires a distinct versioned NDJSON
decision.

Within v1, existing field names, types, meanings, and nesting remain stable;
new optional evidence is additive. A removal, reinterpretation, type change, or
required-nesting change creates a new schema discriminator. Exact readable
golden documents for every finite JSON subject gate the complete wire shape so
an internal model edit cannot silently alter v1.

## Update (2026-07-26): bind finite JSON to its acquisition window

Add optional `acquisition.started_at` and monotonic `acquisition.elapsed_ms`
fields to every emitted v1 observation and speed experiment. `completed_at`
alone could not tell a machine consumer when a bounded active transaction
started or how long its evidence collection actually took. Wall-clock start
and completion support cross-observer alignment; monotonic elapsed time avoids
claiming duration from wall-clock subtraction.

Also scope live CLI options to the subjects that implement them. Focused link
and peers help advertises interval, plain stream, and dwell controls; screenshot
help advertises only its observation interval; snapshot, probe, and speed help
no longer offers live options that runtime would reject or ignore. This changes
neither acquisition policy nor the existing before-or-after-subcommand
compatibility path.
