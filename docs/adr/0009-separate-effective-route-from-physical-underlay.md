---
id: 0009
status: accepted
governs: src/**, README.md, docs/design/**
why: a tunnel can own the effective default route while a different physical interface carries its packets, and treating the tunnel as the only active interface hides the radio, DHCP, counters, and neighbor-cache evidence needed to localize an operator's problem.
rejected: keep one active-interface field (loses physical-link evidence under a full tunnel); label any other addressed interface as the underlay (address presence does not prove routing or attachment); infer underlay from interface names alone (platform naming is not sufficient topology evidence); scan Wi-Fi or inspect VPN configuration (widens acquisition and authority beyond passive host state)
supersedes: none
superseded_by: none
extends: 0001, 0003, 0005, 0006, 0007
confidence: medium
review_trigger: macOS reports the wrong underlay with multiple reachable hardware interfaces, another platform exposes equally strong underlay evidence, the observation-v1 additive field is insufficient for a consumer, or a collector needs evidence from both layers simultaneously.
---

# ADR-0009: separate effective route from physical underlay

## Context

A full-tunnel VPN on macOS can select `utun` as the effective default-route
interface while Wi-Fi on `en0` still carries the encrypted packets. The prior
single-interface model correctly named the effective route, but it also sent
radio, DHCP, interface-counter, and neighbor-cache collectors to that tunnel.
The result hid the physical evidence needed to distinguish a tunnel or remote
path problem from a weak or changing Wi-Fi attachment.

An addressed non-default interface is not enough evidence to call it an
underlay. A host may have several addressed hardware, bridge, tunnel, and
service interfaces at once. Linktop previously labelled those rows
conservatively as `other addressed interface` for this reason.

macOS exposes a stronger passive conjunction. `route -n get default` names the
effective route. `scutil --nwi` provides the ordered active network-interface
set. `networksetup -listallhardwareports` identifies hardware interfaces and
their link type. A scoped `route -n get -ifscope INTERFACE default` confirms
that a candidate hardware interface has its own default route and supplies its
physical next hop. None of these reads transmits network traffic.

## Decision

Keep `LinkSnapshot.interface`, `link_type`, and `gateway` as the effective
default-route layer. Add an optional typed `underlay` with its own interface,
link type, and gateway. Human and machine projections derive from that same
model. The optional field is an additive `linktop.observation.v1` extension;
observations with no separately established underlay retain their existing
shape and semantics.

On macOS, Linktop freshly establishes or replaces an underlay only when:

1. the effective interface is a recognized tunnel;
2. the candidate appears in the active `scutil --nwi` ordering;
3. `networksetup` identifies it as a hardware interface; and
4. a scoped default-route lookup returns that same interface.

The first corroborated candidate in the platform ordering becomes the physical
underlay. A refresh may reuse the previously corroborated hardware
classification for that same active candidate, but it still requires the
active-interface ordering and matching scoped route. Linktop does not promote
another interface based only on an address, an `en`-style name, or the
existence of Wi-Fi hardware. If the conjunction is unavailable or
contradictory in a one-shot observation, `underlay` remains absent and
coverage is partial. A live session retains its last corroborated underlay
across a transient source gap only for the three-second path-transition grace
and only while the effective tunnel interface is unchanged; a newly observed
layer still replaces it and enters the generation fingerprint.

The effective layer continues to control active next-hop probes and the
effective resolver set. When an underlay is present, passive physical-link
collectors use it for Wi-Fi association and radio telemetry, DHCP context,
kernel interface counters, and neighbor-cache interface/prefix filtering. The
underlay gateway is the physical default-gateway role in peer projections.
This changes no active-probe cadence and adds no scan, packet capture, name
resolution, controller query, or durable retention.

Path generation fingerprints include both layers. A tunnel change can start a
new generation without a physical switch, and a Wi-Fi/hotspot transition can
start a new generation while the effective tunnel interface stays constant.
Late radio, counter, workload, peer, and probe results remain fenced by the
generation that launched them.

The underlay is topology evidence, not physical-place or identity evidence.
SSID, association ID, BSSID visibility, gateway binding, and recurrence retain
their existing source and interpretation limits.

Netmon's experimental `HostPathObservationV0` has no underlay object. Linktop
keeps its interface, link type, and next hop mapped to the effective route and
retains separately representable Wi-Fi association evidence. It does not
flatten the physical gateway into the effective next-hop field; missing
effective next-hop evidence remains an explicit coverage gap.

## Options considered

- **Keep the singular active interface and show other addresses.** Rejected
  because it preserves the effective route but systematically loses physical
  radio and counter evidence beneath a full tunnel.
- **Choose any non-default addressed interface.** Rejected because bridges,
  inactive services, secondary hardware, and other tunnels can all have
  addresses without carrying the effective path.
- **Infer from interface names.** Rejected because a name can classify a
  tunnel candidate but cannot establish which hardware path carries it.
- **Inspect a VPN application's configuration or process state.** Rejected
  because it couples Linktop to provider-specific lifecycles and may require
  credentials or broader process evidence.
- **Scan Wi-Fi or query a controller.** Rejected because ambient acquisition
  and controller authority remain explicit separate modes.
- **Replace the v1 effective-route fields with a new nested path object.**
  Deferred because the optional underlay is additive and sufficient for the
  current second layer; a deeper multi-layer route graph would require a new
  schema and proven consumers.

## Consequences

An operator can now see a path such as `utun4 [vpn] over en0 [wifi]` while
retaining `en0` radio, DHCP, counters, gateway, and cache evidence. Text, JSON,
plain streams, dwell identities, and the TUI agree on which layer is effective
and which is physical.

The macOS light refresh adds passive local topology reads. Hardware-port
classification is reused while the same candidate remains first in the active
ordering; a changed candidate triggers a fresh hardware mapping. Every command
uses the existing bounded command runner.

Other platforms keep the singular effective-route model until they expose a
comparably corroborated underlay mechanism. An absent underlay means “not
established,” not “no physical carrier exists.”

## Lineage

Extends ADR-0001's standalone host-path model, ADR-0003's generation fence,
ADR-0005's causal evidence ordering, ADR-0006's passive acquisition boundary,
and ADR-0007's priority for consequential radio and interface evidence.
