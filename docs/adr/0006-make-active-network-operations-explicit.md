---
id: 0006
status: accepted
governs: src/main.rs, src/model.rs, src/net.rs, src/plain.rs, src/ui.rs, src/capture.rs, README.md, docs/design/network-situation-intelligence.md
why: the default overview transmitted ICMP, DNS, and HTTPS traffic even when the operator only wanted to observe the current network context, while the interface did not make the acquisition boundary prominent enough.
rejected: keep active probes on by default and improve disclosure (still surprises an observer); infer active intent from a focused view or refresh (navigation must not change acquisition); remove active diagnosis entirely (throws away useful bounded localization); call packet capture or cache reads active because they observe network state (conflates observation with transmission and hides materially different side effects).
supersedes: none
superseded_by: none
extends: 0001, 0002, 0003, 0004, 0005
confidence: high
review_trigger: revisit if a platform source transmits as a side effect, an acquisition backend adds packet or RF capture, or active probe targets become configurable.
---

# ADR-0006: Make active network operations explicit

**Status**: Accepted
**Date**: 2026-07-24
**Deciders**: operator

## Context

Linktop began as an active host-path diagnostic. Opening the overview immediately
sent next-hop ICMP echo requests, performed a DNS lookup, made an HTTPS request,
and queried public-address providers. That behavior was bounded and did not scan
the LAN, but it was still an acquisition surprise for an operator who wanted to
observe the current interface, default route, radio, counters, and native
neighbor cache.

The distinction matters operationally. A route read, interface-counter read, or
numeric ARP/NDP cache read observes state already held by the host. ICMP, DNS,
HTTPS, reverse DNS, active discovery, throughput tests, and wireless scan
triggers generate traffic or alter acquisition state. Packet capture can be
passive on the wire while still requiring privilege and changing the host's
capture state. These are different side effects and must not be hidden behind
one generic “network monitor” label.

Several established terminal tools make the same separation useful:

- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) separates
  capture filters from display filters, live acquisition from saved input, and
  packet output from summary-only statistics.
- [Termshark](https://github.com/gcla/termshark/blob/master/docs/UserGuide.md)
  keeps a stable packet index and loads decoded detail for the selected packet;
  changing pane focus does not silently widen capture.
- [Nmap](https://nmap.org/book/man-runtime-interaction.html) exposes progress
  and verbosity as runtime projections over an explicitly active operation.
- [airodump-ng](https://www.aircrack-ng.org/doku.php?id=airodump-ng) uses dense
  AP and station tables with explicit observation windows, but its monitor-mode
  and channel-hopping side effects show why “passive on the air” is not the same
  as “no local acquisition change.”
- [iftop](https://code.blinkace.com/pdw/iftop/-/blob/75d1818129cbb8ff1bb7ca4915b95046f3ed0666/iftop.8)
  warns that name resolution itself can generate traffic. Numeric, cache-native
  identity therefore belongs in Linktop's passive default.

## Decision

### Default to host-local passive observation

Bare `linktop`, `linktop snapshot`, the overview TUI, plain streaming, and
overview screenshots use `ProbePolicy::Passive` unless the operator opts in.
They may read:

- the host's default route, interface, configured resolver set, and addresses;
- platform 802.11 association and radio telemetry;
- host-local DHCP configuration and Wi-Fi association state;
- kernel interface counters and numeric process-accounting deltas;
- numeric native ARP and NDP neighbor caches; and
- local OUI registries already installed on the host.

The passive policy does not perform reverse DNS, enumerate socket endpoints,
send next-hop echo, resolve DNS, make HTTP requests, query public-address
providers, actively discover the LAN, trigger a wireless scan, capture packets,
or test throughput. Numeric per-process byte deltas identify only the local
executable to which the kernel attributed external-interface traffic during a
named window; they do not identify a peer, protocol, person, or intent. A cache
entry is presented as a cached link-layer binding, never as proof that an
endpoint is online, present, owned by a person, or generating traffic.

The passive overview reports path status as `UNTESTED`. Evidence coverage is
qualified as passive coverage and describes completeness within the enabled
observation policy; `COMPLETE` does not imply that end-to-end reachability was
tested.

### Make every active path explicit

Active operations have distinct operator entry points:

- `linktop probe` runs one bounded path diagnosis and exits;
- `linktop --active` enables active probes in the live overview;
- `a` toggles active probes for the current overview session;
- `linktop screenshot overview --active` captures the active view deliberately;
  and
- `linktop speed` remains an explicitly selected bounded `iperf3` transaction.

The active overview sends one next-hop ICMP echo per configured interval. On
enable, path change, or manual refresh it performs a bounded `example.com` DNS
lookup, an HTTPS GET to `https://example.com/`, and a bounded public-egress
address lookup with provider fallback. A long-lived active overview repeats the
DNS and HTTPS checks every sixty seconds and stops using results older than
seventy-five seconds as current path evidence. Public egress is not periodic
because it is supporting identity rather than a path dependency. Each
implementation has an application, process, or HTTP deadline. The interface
names the target class, cadence, and bounded lifetime rather than reducing all
of them to a green “probe” row.

No next-hop ICMP reply is unavailable evidence, not proof of failure. Gateways
may filter echo, and successful downstream DNS and HTTPS checks still support a
responding path. A probe process error or deadline remains a failed operation.

Disabling active probes clears path-probe state and public-egress enrichment.
Results already in flight are ignored by the model when the active policy is no
longer enabled. Path-generation fencing still rejects results from a previous
network context.

### Keep acquisition independent from projection

Switching among overview, link, and neighbor-cache views never enables a new
source or transmission. Manual refresh repeats only the operations permitted by
the current policy. Display filtering, sorting, scrolling, focused views, and
terminal resizing affect projection, not acquisition.

This rule also governs future features:

- packet or RF capture requires an explicit acquisition mode and privilege
  disclosure even when it is passive on the medium;
- active discovery belongs in a named, bounded transaction, not `peers`;
- imported controller, flow, or netmon evidence retains its source-owned
  collection-policy reference; and
- reverse DNS or service enrichment is opt-in unless the result came from an
  already local cache or advertisement.

### Use operator-native vocabulary

All human and structured projections preserve the evidence's networking
meaning:

| Term | Linktop meaning |
| --- | --- |
| default route | the host routing decision currently selected for default traffic |
| next-hop gateway | the route's immediate gateway; not the entire LAN or Internet path |
| neighbor cache | kernel ARP/NDP bindings; not a device inventory or liveness result |
| link-layer address | a MAC binding reported by a source; OUI is registrant enrichment, not identity |
| resolver set | configured recursive resolution endpoints; not proof that resolution works |
| public egress | the public address observed by an explicit external HTTPS lookup |
| RTT | round-trip time for the named active probe and target |
| mean `|ΔRTT|` | mean absolute difference between adjacent RTT samples; not labelled generically as jitter or one-way IPDV |
| rate | a delta over a named observation interval; distinct from cumulative counters |
| process traffic | host-kernel byte attribution to a local executable over a named window; not endpoint, protocol, or intent attribution |
| evidence age | elapsed time since the named source produced the observation |
| coverage | source completeness under the current policy; distinct from path health |

Expert terminology remains visible in the primary interface. Good UX comes from
stable hierarchy, aligned columns, explicit units and windows, progressive
column removal, and evidence drill-down, not from replacing precise terms with
vague prose. At narrow sizes Linktop removes secondary detail while preserving
the same situation, path identity, coverage, active/passive state, and next
operator action.

## Options considered

- **Keep active probes on by default and disclose them better.** Rejected
  because disclosure does not make unexpected transmission an observation
  default.
- **Infer active intent from the current view.** Rejected because navigation,
  resizing, or a screenshot should never change collection.
- **Remove active diagnosis.** Rejected because bounded next-hop, DNS, and HTTPS
  probes are useful when the operator is localizing an actual reachability
  problem.
- **Allow active work only through one-shot subcommands.** Rejected because the
  in-session `a` escalation preserves the passive dwell, current path
  generation, and before/after evidence around an intermittent symptom. The
  monitor fences the resulting mutable state by policy epoch and path
  generation.
- **Add arbitrary per-probe selectors now.** Deferred. The initial active
  transaction is one small dependency-ordered localization bundle. Networks
  that require target allowlists or narrower protocol scope need explicit
  operator-selected targets and probe plans rather than a pile of boolean
  switches; that remains a review trigger.
- **Treat every observation source as equally passive.** Rejected because
  reverse DNS, packet capture, monitor mode, channel hopping, and controller
  queries have materially different wire, host, privilege, and policy effects.

## Consequences

Opening Linktop now provides useful network-context and change evidence without
generating network traffic. It cannot claim that the end-to-end path works until
the operator enables active probes, so `UNTESTED` becomes a first-class state
rather than `N/A`, healthy, or indefinitely collecting.

This deliberately changes the experimental `snapshot` and compatibility-alias
semantics: `snapshot` is passive and the `pinglet`/`pingl` aliases preserve
command discovery, not active-by-default behavior. `linktop probe` is the
automation-oriented diagnosis and maps failed or unavailable path verdicts to
distinct process statuses. Live active views remain observation processes; a
bounded dwell ending is not itself a diagnostic success status.

The passive top view spends its space on current route identity, radio,
interface deltas, resolver configuration, neighbor-cache coverage, path
generation, and relevant events. The active view replaces that acquisition gap
with an ordered path diagnosis and precise RTT distribution.

Future acquisition features incur a deliberate product cost: a named mode,
activity disclosure, bounded lifetime or explicit stop condition, provenance,
and a structured representation that cannot be confused with passive evidence.

## Lineage

Extends ADR-0001's host-path boundary, ADR-0002's shared output semantics,
ADR-0003's path-generation fence, ADR-0004's bounded capture transaction, and
ADR-0005's separation of path health from evidence coverage.

## Update (2026-07-24): imported policy remains non-acquiring

ADR-0008 fired the Netmon collection-policy review trigger. The imported v0
record can describe passive or active provenance, but the libraries initiate no
collection. Linktop writes only its passive host-local context to history; live
active probe results remain separate episode evidence. The existing acquisition
boundary therefore remains accepted.
