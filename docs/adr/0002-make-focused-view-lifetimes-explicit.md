---
id: 0002
status: accepted
governs: src/main.rs, src/net.rs, src/ui.rs, src/plain.rs, README.md
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
It reports partial native-source completion as degraded evidence.

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
platform readers. The overview declares truncated peers with a handoff to the
focused command instead of silently hiding them.

The CLI now has a policy matrix that must be tested as a contract. Adding an
NDJSON stream, a one-shot terminal modifier, or a new focused subject crosses
the review trigger rather than overloading `--json` or changing pipe behavior.

## Lineage

Extends ADR-0001's terminal-first instrument with explicit focused-view and
noninteractive lifetime contracts.
