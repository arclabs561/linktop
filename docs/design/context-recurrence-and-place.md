---
status: implemented
decisions: ADR-0008
---

# Design: context recurrence without location overclaim

## Problem

Repeated Wi-Fi and routed-path observations can tell an operator that a network
context recurred and that the host attached through a known or newly observed
BSSID. They cannot, by themselves, establish a physical location. SSIDs repeat,
private addressing is reused, mesh networks contain several BSSIDs, mobile
hotspots move, routers move or are replaced, and macOS may withhold SSID/BSSID
values.

Calling every distinct serialized key a network or every gateway binding a
place candidate would make missing evidence look more certain than it is. It
would also make later controller or operator evidence difficult to reconcile.

## Chosen approach

Netmon replay owns one deterministic, observer-scoped recurrence reduction over
`HostPathObservationV0`. For the current observation it reports:

- exact prior observations under the durable context key;
- compatible/incomplete prior candidates separately;
- first and last exact observation times;
- distinct associated-BSSID variants among exact prior observations; and
- whether the current BSSID was seen in those exact prior observations.

Compatibility is never transitively clustered. It is an uncertainty relation,
not context identity: record A can be compatible with incomplete B and B with C
even when complete A and C conflict.

Linktop projects those facts using separate vocabulary:

- `network context` for exact recurrence or a supported transition;
- `attachment` for the current association/BSSID episode;
- `context anchor` for a gateway link binding or weaker available boundary
  evidence; and
- `place unknown` until an operator or authoritative controller supplies a
  place assertion.

A new BSSID in an exact recurring context is described as newly observed
attachment evidence. It may support a roam hypothesis, but the tool does not
claim motion, AP identity, or a new site. When macOS restricts BSSID access,
Linktop says the attachment identity is unavailable instead of treating a
missing value as change.

## Non-goals

- No ambient Wi-Fi scan, Core Location request, public-IP geolocation, or
  external positioning lookup in the passive default.
- No automatic physical-place label from SSID, BSSID, OUI, gateway address, or
  gateway link binding.
- No transitive clustering of compatible/incomplete records.
- No claim that a BSSID variant is one verified AP or that a cached gateway
  binding proves current physical presence.
- No Linktop-owned durable identity or place-policy database in this slice.

## Decision gates

- Add a private place label only when its authority, matcher, freshness,
  conflict behavior, and revocation semantics are explicit.
- Revisit the exact context key when multi-location fixtures show false
  recurrence or excessive fragmentation.
- Add controller/site or positioning evidence only through a source that
  preserves acquisition policy, observer, time, coverage, and authority.
- If a future active location transaction is added, it must be separately
  named and disclose permission, network, retention, and external-service
  effects before execution.

## Why not automatic Wi-Fi location?

Wi-Fi positioning can be valuable, but it changes the acquisition and privacy
contract. It generally needs an ambient scan and a positioning database or an
OS location permission. That belongs in an explicit future adapter, not inside
the passive overview.

## Why not a fingerprint ID?

A short hash would be compact, but the current record has open-world fields.
The identifier would churn when macOS reveals a previously hidden field or a
resolver changes, and it would hide the evidence an operator needs to assess
the claim. Evidence-labelled recurrence is more useful than an opaque token.

---
Decided: 2026-07-24 | Session: 019f8544
