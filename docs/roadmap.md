# Roadmap

Linktop should show useful network context without claiming more than its
evidence supports.

## Now

- Passive host-path and physical-link views.
- Explicit evidence coverage and path-generation changes.
- Focused link and neighbor-cache views.
- Bounded DNS, HTTPS, public-egress, and load probes.
- Text, TUI, JSON, JSONL, history, saved-evidence, and capsule views.
- Deterministic terminal and headless capture.

## Next

- Better recurrence and place evidence without automatic location labels.
- More synthetic and reviewed replay scenarios.
- A local evaluation loop with fixtures, properties, fuzzing, mutation runs,
  and bounded live checks for OS and network changes.
- The first fingerprinting step: compare source-preserving candidates from
  more than one vantage and explain disagreement or missing evidence.

## Later

- Versioned Netbraid records for multi-vantage evidence.
- Advisory fingerprints that retain source, extractor, version, and unknowns.
- Separate feature families for BLE, 802.11/radiotap, Wi-Fi CSI, and bounded
  spectrum observations.
- Scoped tracking with identifier rotation and placement uncertainty.
- Cross-modal hypotheses with cited evidence and abstention.
- Bounded before/during/after experiments and sanitized handoff capsules.
- Optional operator assistance only after the evidence and evaluation gates
  are met.

## Gates

New work must preserve the passive default, generation fencing, source and
freshness provenance, bounded resource use, and the separation between
evidence and identity. Active acquisition and persistence remain opt-in.

Before RF or fusion work is promoted, replay must cover identifier rotation,
movement, stale or missing observers, disagreement, partial radiotap headers,
CSI absence, and source-specific gaps. Properties must preserve ordering and
scope. Untrusted parsers need fuzzing. Mutation runs must show that
contradiction and abstention branches are real. Live checks come last.
