---
id: 0003
status: accepted
governs: src/model.rs, src/net.rs, src/plain.rs, src/ui.rs
why: asynchronous radio, cache, traffic, and Internet observations can finish after the host has switched Wi-Fi, hotspot, Ethernet, VPN, route, resolver, or address state, and applying those results would combine evidence from different paths.
rejected: overwrite fields in arrival order (permits stale cross-path evidence); identify a network by public IP (late, active, and not unique); cancel worker threads on transition (not reliably available for bounded platform commands); retain old samples until replacement (presents known-stale evidence as current).
supersedes: none
superseded_by: none
extends: 0001
confidence: high
review_trigger: revisit if the path fingerprint proves unstable on a supported platform, monitoring moves to an async runtime with structured cancellation, or observations intentionally span multiple paths.
---

# ADR-0003: Fence observations by path generation

**Status**: Accepted
**Date**: 2026-07-22
**Deciders**: operator

## Context

Linktop launches bounded work concurrently. A public-address request or macOS
radio query can still be running when the default path changes from house Wi-Fi
to a phone hotspot, from Ethernet to Wi-Fi, or through a VPN transition. If the
model accepts results only by arrival order, an old public address, peer set,
counter baseline, or radio observation can appear on the new path.

Interface name alone is insufficient: Wi-Fi networks commonly reuse `en0`, and
VPN and resolver changes can alter effective path behavior without changing the
physical interface. Public IP is also unsuitable because it arrives late,
requires active traffic, and is neither stable nor unique to one local path.

## Decision

Represent the active path as a monotonically increasing process-local
generation. Its fingerprint consists of the default interface, link type, SSID
value or platform-restriction state, gateway, the effective normalized resolver
set, IPv4 addresses, and normalized IPv6 /64 prefixes on the default interface.
Prefix identity prevents IPv6 privacy-address rotation from creating a false
transition on any supported platform while still detecting a prefix change. On
macOS, effective resolvers come from `scutil --dns`, and addresses the platform
marks temporary remain explicitly visible to the operator.

Every asynchronous monitor update carries the generation that launched it. The
model accepts link state for the current or a newer generation and ignores
radio, neighbor, counter, and probe results whose generation is no longer
current. New neighbor snapshots are additionally filtered to the current
interface and local address prefixes. Networks that reuse the same interface and
prefixes remain indistinguishable from retained cache state without active work,
so those rows keep explicit cache-not-liveness semantics rather than being called
new-path presence. A new generation clears gateway history, interface-rate baselines,
public-edge and radio values, passive peers, and settled probe state before
scheduling observations for the new path.

Record the old and new path label and the fingerprint dimensions that changed in
the event bus. A transient incomplete route during association may create an
intermediate generation; safety from cross-path evidence is preferred to
guessing that two incomplete observations are one network.

## Options considered

- **Apply results in arrival order.** Rejected because bounded does not mean a
  worker finishes before a network switch.
- **Use only interface and gateway.** Rejected because resolver, SSID, VPN, and
  address changes can alter the path without both fields changing.
- **Use public IP as network identity.** Rejected because it is active, delayed,
  sometimes unavailable, shared by many networks, and itself subject to the
  stale-result race.
- **Cancel all worker threads.** Rejected because the current bounded blocking
  platform calls do not provide reliable cooperative cancellation. Ignoring a
  typed stale result is deterministic.

## Consequences

Switching networks causes a visible reset rather than a misleading continuous
latency graph. Some values temporarily return to queued or unavailable while
the new path is observed. Slow old-path workers may finish, but cannot mutate
the current model.

Fingerprint stability is now a supported-platform invariant. Tests must cover
transition reset and stale-result rejection; a future async runtime may add
cancellation for efficiency without weakening generation checks at the model
boundary.

## Lineage

Extends ADR-0001's live state model with an isolation boundary between active
paths.

## Route-settling refinement (2026-07-23)

A transient loss of the default interface during Wi-Fi association no longer creates
an immediate intermediate generation. When a previously confirmed path temporarily
has no default interface, Linktop marks the path as switching, retains the last
confirmed generation for up to three seconds, and starts no new probe, peer, radio, or
counter work against that retained topology. A recovered route clears the settling
state and is compared with the confirmed fingerprint normally.

If the route remains absent through the grace period, the incomplete topology becomes
a new generation and receives the same path-scoped reset as any other sustained
transition. This refinement removes a known false transition during house-Wi-Fi and
hotspot handoff without allowing old asynchronous results to cross into the next
confirmed path.
