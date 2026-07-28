# Design decisions

This file records the product decisions a contributor needs in order to change
Linktop without widening its authority or weakening its evidence model.
Implementation history remains in Git; private planning stays outside the
public repository.

## Product boundary

Linktop is a standalone host-path instrument. It owns current host observation,
bounded diagnosis, terminal presentation, and machine-readable projections. It
does not own packet capture, ambient wireless scanning, LAN discovery,
controller access, durable identity fusion, or unattended telemetry.

Netbraid is a library dependency, not a required companion process. Linktop uses
Netbraid's versioned `evidence` and `replay` modules with its CLI and TShark
features disabled. It does not invoke a Netbraid executable or require a
Netbraid service.

## Passive by default

The default command performs host-local, passive observation. It reads operating
system state such as routes, interface counters, resolver configuration, radio
state, process accounting, and neighbor caches. It must not turn cache
inspection into a scan.

Next-hop, DNS, HTTPS, public-egress, and load probes are active operations. They
require `--active`, the `probe` or `speed` command, or an explicit TUI action.
Structured output records the acquisition policy so absence of an active test
cannot be mistaken for success.

## Path generations

A meaningful route, interface, underlay, association, address, gateway, or
resolver change starts a new path generation. Asynchronous results carry the
generation in which they began; late results from a previous generation are
discarded. This prevents Wi-Fi, hotspot, Ethernet, and VPN evidence from being
combined after a switch.

The effective default route and its physical underlay are separate facts. A VPN
may own the effective route while Wi-Fi owns radio, DHCP, counters, and neighbor
evidence.

## Evidence before inference

Every conclusion carries support state, source, scope, age or span, and
limitations. Unknown, unavailable, partial, and untested are distinct states.
Peer-cache entries are cache evidence, not proof of current presence or traffic.
MAC registrant hints are not device identity. A recurring network context is
not automatically a physical place.

Human and machine outputs project the same typed model. The TUI may rank and
compress it for the available space; JSON retains the complete versioned
contract. Machine consumers must not parse terminal prose.

## Explicit lifetimes

Terminal defaults are interactive only when stdin and stdout are terminals.
Redirected output is finite unless the operator selects `--plain`, `--jsonl`,
or a bounded `--dwell`. Focused `link` and `peers` commands keep their narrower
collection plans even though the overview can switch among all three views.

History is opt-in and caller-owned. Saved-capture review is finite and read-only.
Incident capsules are explicit private transactions: v0 packages an existing
canonical host-path log only, publishes atomically into a new directory, and
does not become an automatic record-every-session side effect. Sanitized export
and multi-observer capsules require separate contracts.
The `history` command is also finite and read-only: it reduces canonical
host-path records into observer-scoped context-key episodes without inferring
timeouts, place, identity, traffic shape, or intent.
Completed bounded path windows may expose a versioned traffic-shape candidate
from aggregate kernel interface counters. It is transparent feature evidence
with explicit caveats, never an endpoint, protocol, application, person,
place, or intent identity.
The finite `readiness` command derives purpose-specific assessments from one
fresh bounded active path snapshot. Interactive use requires current path
context plus gateway, DNS, and HTTPS results. Calls, bulk transfer, and idle
background health remain explicitly `not_tested` until their own measurements
exist; no single readiness boolean may collapse those missing prerequisites.

## Reproducible visual QA

Screenshot capture is a bounded transaction over the production reducer and
renderer. Synthetic scenes use documentation identifiers and versioned Netbraid
fixtures. Native capture uses an isolated terminal process. A completion
manifest is written last and binds the frame schedule, viewport, executable,
artifacts, and digests. Screenshot artifacts are QA output, not network evidence.

## Distribution

The public package and executable are both named `linktop`. `pinglet` and
`pingl` remain local compatibility aliases, not separate packages or products.
Releases publish one Cargo package plus native Linux and macOS archives with
checksums and provenance.

The Cargo package includes a documentation-only library target because docs.rs
builds package documentation with `cargo rustdoc --lib`. It exposes no
supported embedding API; reusable evidence and replay primitives belong in
Netbraid.
