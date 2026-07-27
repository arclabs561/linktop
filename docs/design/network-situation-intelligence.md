---
status: proposed
decisions: ADR-0001, ADR-0002, ADR-0003, ADR-0005, ADR-0006, ADR-0007, ADR-0008
---

# Product direction: explain the network situation

## Product thesis

Linktop should become an explainable network situation instrument, not a denser
dashboard and not a smaller clone of a scanner, packet analyzer, or controller.
Its top-level job is to answer:

1. Can the operator trust this path for the activity they care about?
2. If not, which segment is implicated and what evidence supports that answer?
3. What changed before the symptom?
4. Which paths, services, and devices are involved?
5. What is observed, derived, candidate, verified, or still unknown?
6. What bounded experiment would most safely reduce the remaining uncertainty?

The interface should feel like a flight recorder and careful diagnostician. It
recognizes episodes, distinguishes an initiating change from cascade symptoms,
compares current evidence with an appropriate baseline, explains blind spots,
and verifies whether an operator action helped.

The default is passive network-context observation. “Can the operator trust this
path?” is therefore answered `UNTESTED` until an explicit active transaction
supplies reachability evidence. Passive evidence can still identify a route
change, weak radio, interface errors or drops, resolver-set change,
neighbor-cache contradiction, or acquisition gap without pretending to have
tested the Internet.

## Concrete operator decisions

The top view earns space only when it helps an operator decide something:

| Operator question | Evidence worth showing | Concrete circumstances |
| --- | --- | --- |
| Did my network context change? | interface, link type, SSID visibility, Wi-Fi association ID, DHCP lease window, default route, next-hop gateway, address prefix, resolver set, path generation | moving between home Wi-Fi and a hotspot; VPN or DHCP change; interface roam; resolver replacement |
| Is the local host or link already showing trouble? | RSSI, noise, channel, PHY, negotiated rate, interface rate, error/drop deltas, route settling | weak RF, congestion symptoms, driver trouble, counter increase, default-route churn |
| Which local workload is consequential right now? | numeric per-process receive/transmit rate, sample window, accounting source, tunnel caveat | a call freezes during upload; a VPN extension owns most bytes; background transfer competes with an interactive shell |
| Is active localization warranted? | passive coverage gap plus one explicit action naming target, protocol, cadence, and deadline | service is unreachable; shell or call is degrading; passive evidence cannot distinguish next hop from DNS or HTTPS |
| What changed during this dwell? | typed before/after path transitions, first/last cache observation, evidence age, state or binding contradiction, recovery | an intermittent symptom; switching networks; a neighbor-cache entry changes while counts stay constant |
| What supports the inference? | source command/API, observation time, policy, scope, missing sources, contradiction, raw value | deciding whether to act, compare, export, or hand off to a specialist |

Static addresses and cache rows remain valuable evidence. They do not outrank a
change, diagnosis, or acquisition gap merely because they are easy to collect.

## Operator moments

### Before an important activity

- Is this connection ready for an interactive shell, video call, deployment,
  game, or transfer?
- Which claims are already available, which are still collecting or
  insufficient, and what exact support or limitation closes the gap?
- Am I using the expected interface, network, gateway, resolver, VPN, address
  families, and public egress?

### During degradation

- Is the problem at the radio/interface, gateway/LAN, resolver, VPN, ISP,
  remote service, or shared queue?
- Which observation moved first?
- Is the whole path affected or only one family, target, name, protocol, or
  activity profile?
- Did roaming, hotspot switching, resolver or route change, load, signal decay,
  or peer churn precede the symptom?

### After recovery

- What recovered first, and did every implicated signal return to baseline?
- Did the intervention cause a durable improvement or only coincide with one?
- What evidence belongs in a private incident capsule or sanitized handoff?

### Around peers

- Which bindings are currently cached, which changed during this path
  generation, and how fresh is the positive evidence?
- Which names, services, roles, and traffic episodes were actually observed by
  a source with the necessary vantage point?
- Which endpoint is operator- or controller-verified, merely a candidate, or
  unknown?
- What can this host not see on a switched LAN or associated Wi-Fi link?

The last answer is part of the product. Linktop should not fill a coverage gap
with a guess.

## Attachment, network context, and place are different axes

“House” and “hotspot” are examples, not product categories. Linktop and Netbraid
need an open-ended model that can represent a mesh roam inside one building,
the same hotspot moving between cities, repeated hotel or office networks, a
VPN change at a fixed desk, and unrelated sites that reuse the same SSID and
private addressing.

| Object | Meaning | Strong supporting evidence |
| --- | --- | --- |
| attachment | one host association or link episode | interface, association ID, BSSID, link type, event interval |
| network context | the host-visible routed boundary | next hop and cached link binding, address prefix, resolver set, SSID visibility |
| place candidate | a derived hypothesis that observations share a physical site | recurring BSSID set, gateway binding, controller AP/site, multiple observers, explicit operator label |
| verified place | a private authoritative assignment | operator assertion or controller/site inventory with provenance |
| overlay context | a path layered over the attachment | VPN/tunnel interface, routes, resolver and public-egress changes |

These states can change independently:

- a mesh roam changes attachment while network context and place may remain the
  same;
- a phone hotspot can preserve network context while its physical place moves;
- a VPN connection can change overlay context while attachment and place stay
  fixed;
- two venues can advertise the same SSID and private gateway range while being
  different network contexts and places; and
- a session with only one restricted macOS association may know the current
  route but have insufficient evidence for any place claim.

Linktop now represents the effective route and a corroborated physical
underlay as separate typed evidence on macOS. A tunnel route can therefore
retain Wi-Fi association, radio, DHCP, counter, gateway, and cache evidence
from its hardware carrier. The underlay requires active-interface ordering,
hardware-port classification, and a scoped default route; a merely addressed
non-default interface remains labelled conservatively as an
`other addressed interface`. The underlay is topology evidence, not an
attachment identity or place assertion.

The ordinary passive host view may observe only the current association,
platform configuration, and native cache. Ambient AP scans, packet/RF capture,
controller queries, external geolocation, and active discovery each have a
different acquisition or privacy boundary and remain explicit. A place
candidate must cite its features, observation interval, alternatives,
freshness, and authority. The UI says `attachment`, `network context`, `place
candidate`, `verified place`, or `location unknown`; it does not silently turn
an SSID, OUI, public address, or historical nickname into location fact.

## Information hierarchy

The overview should present:

1. **Answer** — ready, at risk, failing, transitioning, or insufficient
   evidence for the current purpose.
2. **Reason** — the leading causal explanation and decisive observations.
3. **Change** — the most relevant recent transition or anomaly.
4. **Path** — the active path identity and implicated segment.
5. **Consequence** — the activity likely to be affected.
6. **Next move** — wait, inspect, hand off, or approve one bounded experiment.
7. **Coverage** — source completeness, evidence age, and the most important
   blind spot.

Graphs, probe rows, addresses, peers, and event logs are supporting evidence.
They belong behind the answer or in focused views rather than competing with it.

The model should expose a small set of durable product objects:

- **situation** — current path answer and coverage;
- **episode** — bounded degradation, transition, recovery, or anomaly;
- **change** — typed before/after evidence;
- **entity** — host, interface, gateway, resolver, service, AP, or peer;
- **relationship** — routed via, resolved by, associated with, advertised by,
  communicated with, or verified as;
- **hypothesis** — support, contradiction, missing evidence, and alternatives;
- **experiment** — explicit action with target, deadline, side effects, and
  expected information gain;
- **story** — ordered trigger, symptom, consequence, and recovery;
- **coverage** — source, observer, protocol/channel, interval, and completeness.

Those objects should project into the TUI, concise text, JSON/JSONL, saved
captures, and replay without acquiring different semantics in each renderer.
The current live Linktop projection implements the claim-level subset:
observed or derived basis; collecting, available, insufficient, stale,
unavailable, unsupported, or not-collected state; typed sample, generation, or
assessment scope; exact applicable counts; and typed limitations. Candidate
and verified objects remain future intelligence layers, not unused live-schema
vocabulary.

## Terminal interaction precedents

Linktop borrows mechanisms, not visual imitation:

- [TShark's capture/display split](https://www.wireshark.org/docs/man-pages/tshark.html):
  a display filter or output projection changes what is decoded or shown, while
  a capture filter changes acquisition. Linktop must use the same distinction
  for views and collectors.
- [tcpdump's timestamped evidence and terminal capture
  counters](https://www.tcpdump.org/manpages/tcpdump.1.html): time, numeric
  identity, capture scope, and dropped-packet accounting are operator facts,
  not optional decoration.
- Termshark's stable index, selected object, and decoded detail: the overview
  ranks situations and entities while focused views expose provenance and raw
  evidence.
- airodump-ng's separate AP/station tables and explicit rate windows: dense
  expert tables are useful when every column has temporal meaning.
- mtr and Trippy's hop distributions and report-shaped output: active
  diagnosis should retain target, sent/received counts, loss, RTT distribution,
  and a bounded summary.
- iftop and bandwhich's ranked tables and responsive column priorities: remove
  secondary columns as width shrinks without changing the semantic object.
- bmon's current interface plus history and bottom's focused-widget expansion:
  one selected subject can consume detail space without adding permanent
  overview panels.
- [Nmap's reason, timing, output, and runtime
  controls](https://nmap.org/book/man-briefoptions.html): active work can name
  why a state was assigned, expose bounded progress, and retain a report-shaped
  output contract without turning the primary interface into a scrolling packet
  log.

Linktop deliberately does not import Bettercap's adjacency between ordinary
observation and intrusive controls, Kismet's daemon/web architecture,
Termshark's packet-dissection scope, or airodump-ng's attack-oriented density.
Specialist acquisition and analysis remain handoffs or optional evidence
providers.

[Kismet's datasource model](https://www.kismetwireless.net/docs/readme/datasources/datasources/)
also makes an important acquisition limit explicit: faster channel hopping can
increase discovery coverage while reducing per-channel completeness, and the
actual tradeoff depends on the protocol, hardware, driver, and collection goal.
Linktop and Netbraid must therefore show observer, interval, channel or protocol
coverage, and gaps rather than presenting every absent device or packet as
negative evidence.

Time has to be named. A value is a current rate over the monitor interval, a
cumulative counter, a rolling distribution over a stated sample count, an
evidence age, or a session first/last observation. An unlabeled sparkline or
generic “jitter” value is not sufficient. Linktop names its current variation
measure mean absolute adjacent RTT difference, `mean |ΔRTT|`; it does not claim
one-way IPDV.

Process uptime is not evidence support. Route context and cumulative counters
can be useful after one observation, an interface rate needs two compatible
counter reads, and each active probe becomes usable on its first completion.
The next-hop assessment uses the latest twenty attempts; distribution requires
five attempts, while adjacent variation additionally requires two successful
RTT observations. A longer sparkline is labelled display history rather than
used as a second verdict window.

## Intelligence horizons

### Now: useful with no new privilege or daemon

- Default to passive default-route, radio, counter, and neighbor-cache
  observation; require `probe`, `--active`, or `a` for transmitted path probes.
- Separate path health, evidence coverage, path transition, and each claim's
  evidence maturity.
- Rank failures in path dependency order and keep supporting enrichment out of
  the path verdict.
- Show evidence age and ignore stale results from earlier path generations.
- Recheck DNS and HTTPS on a disclosed cadence during active monitoring and
  withdraw the current verdict if fresh evidence does not arrive.
- Detect session-scoped episodes, recovery, and relevant path/radio/counter
  changes.
- Promote the latest typed before/after path change, or state explicitly that
  no transition was observed during this session.
- On macOS, show DHCP/association context and rank numeric one-second
  external-interface process accounting beside aggregate link load without
  claiming endpoint, protocol, or intent attribution.
- Rank peer cache rows by gateway role, binding churn, state change, return,
  kernel confirmation, and freshness.
- Say that peer activity is unknown when only cache evidence exists.
- When explicitly configured, compare the completed passive host-path context
  with Netbraid v0 history and distinguish exact recurrence, compatible incomplete
  evidence, and conflicting context without assigning a physical place.
- Within exact recurrence, distinguish known, newly observed, and unavailable
  BSSID attachment evidence; keep gateway bindings as context anchors and say
  `place unknown` without an operator or controller assertion.
- Produce a private incident capsule and an explicitly requested sanitized
  export.

### Next: explicit diagnostic transactions

- Compare address families, resolvers, or operator-selected targets.
- Bracket a selected `iperf3` load with before/during/after gateway evidence.
- Hand the current context to Trippy/MTR, doggo, Wireshark, Nmap, or another
  specialist rather than quietly reproducing its scope.
- Recommend the smallest test that distinguishes the leading hypotheses, then
  ask before sending it.

### Later: broader Netbraid evidence and fusion

- Durable per-path baselines and recurring episode shapes.
- Multi-vantage comparison across host, router/controller, local sensor, and
  remote witness.
- Imported Kismet, Zeek, TShark, DHCP/DNS, flow, and controller records with
  source-native references.
- Advisory device, stack, service, and application fingerprints with conflict,
  drift, and abstention.
- Grounded natural-language questions such as “what changed before the call
  froze?” over cited replay evidence.

## Traffic fingerprinting

Traffic fingerprinting is a high-value future evidence family:

- TCP/IP handshake traits can suggest an operating-system or stack family.
- TLS and QUIC handshake structure can suggest client or server software.
- DNS, certificate, SNI when exposed, ALPN, and protocol metadata can support
  application or service candidates.
- Packet size, direction, burst shape, duration, and timing can support
  encrypted-traffic classification.
- DHCP, mDNS/DNS-SD, SSDP, and other advertisements can add device and service
  features.
- Repeated relationships and flow episodes can support role candidates and
  anomaly detection.

Keep the operator vocabulary split at the derivation boundary:

- a **feature observation** is a typed source fact such as a TLS ClientHello
  field, TCP handshake trait, advertisement field, or bounded timing sequence;
- a **candidate assessment** applies one versioned method to cited feature
  observations and returns ranked alternatives or an explicit abstention; and
- a **binding** is a separately authorized private assertion about a physical
  device or person and is never created by a fingerprint score.

The current macOS `nettop` process row is not traffic fingerprinting. It is a
numeric byte-rate attribution over one second with no endpoint, protocol,
payload, or flow-shape features. It can identify a consequential local
executable or tunnel owner, but it cannot classify the traffic or the remote
entity.

This does not make `fingerprint → identity` a fact. NAT, relays, VPNs, shared
CDNs and libraries, software updates, randomized addresses, encrypted protocol
evolution, and concept drift all create ambiguity. Every candidate needs the
source feature reference, observer, direction, window, extractor and
signature/model versions, alternatives, conflicts, sensitivity, and an
open-world unknown result.

Traffic capture remains explicit and source-owned. Linktop does not silently
gain packet privileges. A future Netbraid adapter may normalize records from
existing acquisition or dissection tools and give Linktop a policy-neutral
projection. That projection must retain collection-policy metadata supplied by
the deployment that acquired it. Purpose, site, retention, export, aliases,
assignments, consent, and credentials remain outside these diagnostic tools.
Neither Linktop nor Netbraid automatically assigns people to unknown devices or
creates a global fingerprint index.

## Evidence language

Every claim uses one of these verbs:

- **observed** — directly reported by the kernel, platform, packet, controller,
  or explicit test;
- **advertised** — asserted by a peer or service protocol;
- **derived** — deterministic reduction from named observations;
- **candidate** — advisory classification or hypothesis with alternatives;
- **verified** — bound by an operator or authoritative private source;
- **unknown** — incomplete, conflicting, stale, or out-of-distribution.

Numeric confidence is omitted until it is calibrated against representative
ground truth. Source, age, coverage, support, contradiction, and abstention are
more useful than an ungrounded percentage.

## Ownership

| Owner | Responsibility |
| --- | --- |
| Linktop | Immediate host-path situation, session episodes, fresh local evidence, focused views, bounded tests, and operator projections. |
| Netbraid Rust core | Versioned observations, source-preserving alignment, deterministic replay, temporal reducers, baselines, advisory candidate assessments, and explanations. |
| Specialist tools and deployments | Packet/RF acquisition, dissection, controller state, active scans, deployed multi-source and identity fusion, collection policy, retention, access control, and operator-verified identity material. |

Linktop remains independently useful without a Netbraid executable, daemon,
controller, database, or cloud account. Its exact-revision Rust library
dependencies perform no collection or deployment work.

## Product gates

- Do not add an overview panel unless it answers a higher-priority operator
  question more clearly than an existing focused view.
- Do not describe a cache entry as liveness, presence, activity, or identity.
- Do not make negative evidence without source and coverage completeness.
- Do not make an application or human-intent claim without a traffic vantage.
- Do not run an active test without naming target, activity, deadline, and
  expected information gain.
- Do not add a learned model without an unknown class, versioned features,
  drift evaluation, and replayable ground truth.
- Do not make a Netbraid process, store, controller, or deployment a Linktop
  runtime requirement; imported libraries remain policy-neutral and pinned
  until stable compatibility gates pass.
- Do not let a language model originate uncited network facts or mutate the
  network.

## Deliberate non-goals

- Panel sprawl presented as intelligence.
- One universal health score for every operator purpose.
- An implicit LAN scan or packet capture.
- Device identity from OUI alone.
- Person presence from an unknown endpoint.
- Human intent from encrypted flow shape.
- Automatic remediation.
- Mandatory durable retention or cloud publication.
