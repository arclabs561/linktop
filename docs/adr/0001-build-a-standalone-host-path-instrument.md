---
id: 0001
status: accepted
governs: Cargo.toml, Cargo.lock, src/**, README.md, AGENTS.md, justfile, .github/workflows/**
why: a one-shot address dump hides bounded network waits, while host-path diagnosis needs visible probe lifecycle in a live terminal view and a scriptable snapshot without inheriting controller, capture, or deployment authority.
rejected: keep expanding the toolbox script (wrong lifecycle and opaque waits); merge into an adjacent controller/evidence tool (different inputs and release boundary); place the portable application inside an infrastructure repository (no runtime ownership relationship); build a browser dashboard (unnecessary server and browser boundary).
supersedes: none
superseded_by: none
extends: none
confidence: high
review_trigger: revisit if linktop consumes controller or capture evidence, becomes a persistent or implicit collector, owns credentials, or publishes telemetry.
---

# ADR-0001: Build a standalone host-path instrument

**Status**: Accepted
**Date**: 2026-07-22
**Deciders**: operator

## Context

The earlier `pinglet` command prints local addresses and then queries public-IP
providers serially. Each provider has a timeout, but the command renders no
progress while it waits. A partially working public route therefore looks like
a hung process, and the eventual address dump does not identify which network
layer was slow.

The operator wants a continuously useful terminal dashboard implemented in
Rust and owned as a project rather than as one script in a general toolbox.
There is also an adjacent network-analysis project whose current frontend reads
saved controller audit data and whose planned core owns reusable evidence and
replay mechanics. Directly measuring this host's active path is a separate
lifecycle and input boundary.

## Decision

Build linktop as a standalone Rust project. Its default interactive mode paints
before network work finishes and updates the active interface, gateway, public
edge, rolling gateway latency, DNS, and HTTPS probes in place. Every probe has a
visible queued, running, healthy, degraded, failed, or unavailable state.

Own one noninteractive interface over the same bounded diagnosis:
`linktop snapshot --json`. Public-IP providers run concurrently behind one
deadline. Both interfaces remain read-only and host-local: linktop does not scan
the LAN, capture packets, retain history, mutate routes, own credentials, or
publish telemetry.

The name is `linktop`: “link” identifies the active network path and “top” sets
the expectation of a persistent terminal instrument.

## Options considered

- **Keep evolving the toolbox script.** Rejected because a general script
  collection obscures the application's lifecycle and preserves the one-shot
  interaction as its center.
- **Merge it into the adjacent network-analysis project.** Rejected because
  interpreting stored controller or RF evidence and directly probing the
  current host have different inputs, failure modes, and release cadence.
- **Place it inside the infrastructure repository.** Rejected because linktop
  has no infrastructure runtime dependency; that repository may consume or
  deploy it later without owning the application.
- **Build a local web dashboard.** Rejected because it adds a server, browser,
  and exposure boundary to a terminal-native task.

## Consequences

Linktop has its own manifest, lockfile, tests, canonical `just check`, and Git
lifecycle. The TUI and JSON report must evolve together because they express the
same diagnosis. A future integration with controller or RF evidence must cross
the review trigger rather than quietly broadening the project into another
telemetry or fusion plane.

The toolbox command remains intact until linktop's behavior is proven and an
explicit PATH cutover is chosen.

## Lineage

This is the first decision in the linktop ledger.

## Cutover correction (2026-07-22)

The explicit PATH cutover has now been chosen. Cargo's bin directory owns the
installed `linktop` executable, while `pinglet` and `pingl` are compatibility
symlinks to that binary. Toolbox no longer owns an implementation, runtime
dependencies, container image, or publisher for the command.

The initial interface has also been widened within the original host-local
boundary: snapshots carry RTT distribution and loss statistics; platform
adapters expose identifier-free radio telemetry when available; the native
neighbor cache is visible without active probing; and an operator-selected
`iperf3` server can be used for a bounded load test. These are views of the
current host path, not packet capture, telemetry retention, controller access,
or identity fusion.

## Instrument refinement (2026-07-22)

The noninteractive contract now has two lifetimes rather than one overloaded
behavior. Bare output redirected to a pipe remains one bounded snapshot;
`linktop --plain` explicitly chooses the continuing monitor as timestamped,
append-only, ANSI-free text. The TUI and stream share the same state model.

Live activity is sparse and disclosed. Gateway echo supplies the rolling series;
DNS, HTTPS, and public-address probes run at startup or manual refresh instead of
following the sample interval. Public-address services are sequential fallbacks so
one successful service stops further requests. Same-kind probes are single-flight,
and external commands have deadlines.

Passive evidence was expanded where it directly explains path quality. Native
interface byte, packet, error, and drop deltas sit beside gateway latency. Neighbor
records include interface and kernel state plus optional registrant hints from an
installed local Nmap or Wireshark OUI database. A registrant describes a universal
MAC prefix, not a device identity; locally administered addresses are labelled
`local/private`, and cache absence is never described as departure.

The TUI is responsive by available height as well as width. Shallow terminals render
one dense summary instead of compressing the event, address, and peer panels into
unreadable rows.

## Update (2026-07-24): opt-in history preserves the standalone boundary

The history review trigger fired when ADR-0008 added explicit private
cross-session context. The standalone decision remains accepted: Linktop imports
policy-neutral Netbraid Rust types at build time, but it does not require the
Netbraid executable, daemon, controller, store, credentials, or deployment at
runtime. No history is retained unless the operator supplies a path. Automatic
or service-owned collection would be a different lifecycle and remains a review
trigger.
