---
id: 0007
status: accepted
governs: src/main.rs, src/model.rs, src/net.rs, src/plain.rs, src/ui.rs, README.md, docs/design/focused-view-lifetimes.md, docs/design/network-situation-intelligence.md
why: the overview exposed many correct fields but did not consistently surface the network transition, acquisition context, or host activity that would change an operator's next decision.
rejected: add more permanent panels (increases competition without establishing priority); optimize only for the lowest common platform surface (throws away high-value native evidence); infer peer activity from neighbor-cache state (the source has no flow vantage); enable packet or socket capture in the default overview (silently widens privilege, privacy, and acquisition scope); give Linktop a private history schema or database (duplicates Netbraid replay semantics and creates a second retention owner).
supersedes: none
superseded_by: none
extends: 0002, 0003, 0005, 0006
confidence: high
review_trigger: revisit when Linux or Windows gains an equivalent process-accounting backend, endpoint attribution is proposed, or an overview use case needs a different purpose-specific priority order.
---

# ADR-0007: Prioritize change, context, and consequential workload

**Status**: Accepted
**Date**: 2026-07-24
**Deciders**: operator

## Context

The first responsive overview preserved route, radio, counters, probes,
addresses, neighbor-cache rows, and events at several terminal sizes. It was a
better dashboard, but it still required the operator to synthesize the
situation. Static inventory competed with the last transition. Aggregate
interface traffic did not say which local workload was experiencing or causing
the load. macOS exposed DHCP and association evidence that the top view ignored.

This is most visible while moving between a house Wi-Fi network and a phone
hotspot. The route, gateway, resolver set, address prefix, DHCP lease, Wi-Fi
association, and public egress can change at different times. A list of the
latest values is less useful than a typed before/after transition, its age, and
a guarantee that evidence from the prior path cannot cross into the new one.
If Linktop starts after the switch, it must report only the current acquisition
time and say that it did not observe a transition during this session.

The same evidence-priority lesson appears in established terminal tools.
`iftop` and `bandwhich` rank current traffic rather than presenting only
cumulative counters. TShark separates acquisition, filtering, and statistics.
Termshark keeps summary and selected detail distinct. Nmap exposes active
progress without making its report a raw event stream. The reusable mechanism
is priority and drill-down, not copying any one screen.

## Decision

### Make the overview an operator summary

At every supported terminal size, the overview spends space in this order:

1. the current answer and decisive reason;
2. a route-settling state or the most recent consequential change;
3. evidence coverage and the most important blind spot;
4. current path identity and acquisition context;
5. radio, interface, and local workload consequence;
6. the next bounded operator action; and
7. supporting distributions, probes, events, and source boundaries when space
   remains.

Static address inventories and individual neighbor-cache rows move to the
focused link and peers views. Resolver lists, cache counts, and source
provenance remain in the overview evidence ledger but do not outrank a
transition or anomaly.

The compact overview is not a shrunken grid. At the minimum ten rows it retains
the answer, local path, coverage or blind spot, one complete bounded next
action, passive/active state, and navigation. A salient transition is the next
row admitted as height grows; workload and configuration context follow it.
At normal width the path card omits duplicate process text because the evidence
ledger has a complete workload row. At wide width the card adds the top process
beside radio and interface rates. Zero error/drop deltas do not consume the
primary telemetry row; nonzero deltas do.

### Represent path changes as typed evidence

The model retains the latest path change as:

- the session elapsed time;
- the fingerprint dimensions that changed;
- the prior path label; and
- the current path label.

The diagnosis promotes that object until a newer consequential policy, peer,
or notice event exists. It does not scrape human event prose to reconstruct a
transition.

On macOS the path fingerprint also includes the platform Wi-Fi
`ConnectionID`. This detects a new association even when Location Services
policy causes the SSID to be returned as `<redacted>` and the route happens to
reuse other values. DHCP lease timestamps and duration are context, not path
identity: an ordinary lease renewal must not create a false network
transition. If the slower platform Wi-Fi inventory exposes an SSID that the
fast source hid, it enriches the current generation and the transition label;
it does not invent a new generation.

### Use native passive evidence without overstating it

The macOS overview may read:

- `ipconfig getsummary` for configuration method and state, connection ID,
  DHCP server, subnet mask, lease window, security, and router ARP
  verification;
- `system_profiler SPAirPortDataType -json` for the current SSID when macOS
  exposes it and for RSSI, noise, channel, PHY, MCS, and negotiated transmit
  rate;
- native interface counters for aggregate deltas; and
- `nettop -P -L 2 -d -n -x -s 1 -t external -J
  bytes_in,bytes_out` for numeric one-second per-process byte deltas.

The fast configuration read participates in path refresh. The slower Wi-Fi
inventory remains bounded and single-flight. Process accounting samples for
one second no more often than every five seconds and aggregates rows by
executable label before ranking total bytes. The command disables name
resolution and does not request endpoint, flow, or packet payload fields.

This process row means only that the local kernel attributed external-interface
bytes to that executable during the named window. It is not peer attribution,
application-protocol classification, user intent, blame, or proof that the
process caused a symptom. Process labels and observed network identifiers are
shown to the local operator; Linktop does not redact them. Visual-QA artifacts
remain in an ignored private directory.

Other platforms keep their existing evidence instead of fabricating parity.
An unavailable platform backend is disclosed as an evidence limitation, not a
zero rate.

### Preserve acquisition boundaries

All sources in this decision are passive under ADR-0006: they read host-local
configuration, counters, or accounting already maintained by the operating
system and generate no network query. Linktop still performs no reverse DNS,
socket endpoint enumeration, packet capture, wireless scan, LAN discovery, or
durable storage by default.

Endpoint relationships, protocol fingerprints, device/service candidates,
cross-session baselines, and multi-vantage fusion remain future versioned
Netbraid evidence. Adding them requires source, observer, interval, collection
policy, contradiction, and unknown-state semantics before they can compete for
overview space.

## Options considered

- **Add a workload or DHCP panel.** Rejected. The problem was information
  priority, not a shortage of borders.
- **Show only fields available on every operating system.** Rejected. A
  host-local instrument should use trustworthy native evidence and state
  platform gaps explicitly.
- **Infer activity from ARP/NDP state.** Rejected. Neighbor-cache state says
  what the kernel remembers about address resolution, not who is active or
  exchanging traffic.
- **Use socket or packet inspection for richer attribution.** Deferred to a
  separately named acquisition mode or Netbraid adapter because it changes
  privacy, privilege, and retention concerns.
- **Persist known network signatures in Linktop.** Deferred. Session-local
  transitions are sufficient for the standalone instrument; durable baselines
  and replay belong in Netbraid after the existing schema and second-consumer
  gates.

## Consequences

The primary interface now answers “what network am I on, what changed, and what
local activity is consequential?” before showing supporting inventory. A
Linktop session running across a Wi-Fi/hotspot switch names both paths and the
changed fingerprint dimensions. A session started afterward reports the
current association and lease window honestly without claiming it witnessed
the switch.

macOS operators gain useful evidence with no new privilege and no packet
capture. The cost is bounded local process work: `system_profiler` is slow and
`nettop` occupies a one-second sample window. Single-flight scheduling,
deadlines, low cadence, and generation fencing keep those collectors from
stacking or crossing a path change.

Per-process accounting is intentionally advisory and local. A top process may
be a VPN extension or tunnel owner rather than the originating application.
The UI preserves that ambiguity by naming the source and observation window
and by avoiding endpoint or intent claims.

## Lineage

Extends ADR-0002's lifetime-specific projections, ADR-0003's path-generation
fence, ADR-0005's causal information hierarchy, and ADR-0006's passive
acquisition boundary.

## Update (2026-07-24): prior context earns overview priority

ADR-0008 fired the durable-comparison review trigger without changing Linktop's
information hierarchy. A recurrence or context conflict now outranks static
inventory when no newer in-session transition exists. The data contract and
comparison semantics remain Netbraid-owned; Linktop owns the explicit local path,
live collection, and projection.

## Update (2026-07-26): protect the minimum operator transaction

Native 60×10 qualification exposed that a salient change and sampled workload
could displace both evidence coverage and the next action. The minimum overview
now reserves its four body rows for answer, path, coverage, and action. Context
change, workload, configuration detail, and telemetry enter only when another
row is available. This is a minimum-size safety exception to the normal
information hierarchy, not a demotion of transition evidence at usable
heights. At wide passive sizes, a path-dwell panel with no valid counter, radio,
workload, or neighbor-cache samples collapses to one evidence-gap row so empty
zero/unavailable metrics do not displace consequential events.
