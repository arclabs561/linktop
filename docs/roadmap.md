# Roadmap

Linktop should become more useful with each minute it observes a host without
pretending to see traffic, devices, people, or intent that its sources cannot
support.

## Now

- Passive host-path context with explicit evidence coverage.
- Separate effective-route and physical-underlay evidence.
- Path-generation fencing across Wi-Fi, hotspot, Ethernet, and VPN changes.
- Focused link and peer-cache views.
- Explicit next-hop, DNS, HTTPS, public-egress, and load experiments.
- Finite text, TUI, JSON, JSONL, opt-in history, and saved-evidence review.
- Deterministic observer-scoped episode summaries for canonical host-path history.
- Advisory traffic-shape candidate features from bounded kernel counters, with
  explicit non-identity caveats.
- Private, bounded, lossless incident-capsule packaging with verification.
- Purpose-specific readiness reports with explicit interactive-use evidence,
  bounded idle-background accounting, and abstention for calls and bulk
  transfer.
- Reproducible headless and native terminal capture.

## Next

- Clearer recurrence and place evidence without ambient scanning or automatic
  location labels.
- More public synthetic and disclosure-reviewed replay scenarios covering
  degraded, partial, and ambiguous evidence.
- A local-first evaluation ladder: curated fixtures and exhaustive reducer
  properties on every change, focused fuzzing and mutation runs at contract
  checkpoints, and bounded live acceptance for OS/tool/network changes.
- The #5 intelligence path: source-preserving fingerprint candidates,
  multi-vantage fusion, explainable situation hypotheses, and eventually an
  explicit experimental copilot with typed next actions and before/during/after
  comparison.

## Later

- Multi-vantage evidence supplied through versioned Netbraid records.
- Advisory fingerprints that retain the observed signature, extractor,
  version, source, and unknown/ambiguous outcomes rather than forcing identity.
- Cross-source fusion that distinguishes host, local radio/LAN, ISP, and
  remote-service evidence without collapsing coverage gaps into confidence.
- A heterogeneous RF lane, kept as separate feature families until a replay
  contract proves their join: Bermuda-like BLE observations and movement
  episodes; IEEE 802.11/radiotap frame and radio metadata; device-free Wi-Fi
  CSI motion/presence; and bounded spectrum or sub-GHz observations from
  sources such as HackRF and rtl_433. Radiotap signal values remain capture
  metadata, not calibrated location or identity measurements.
- Scoped tracking episodes that preserve observer, source, time, coverage,
  identifier rotation, and movement/placement uncertainty. A repeated signal
  may produce a continuity candidate or a contradiction, never an automatic
  person/device binding or a global unknown-device index.
- Explainable cross-modal hypotheses such as “BLE presence and CSI motion
  co-occurred at one vantage while the host path stayed stable,” or “Wi-Fi
  and spectrum observations disagree,” with cited evidence and abstention.
- Explicit diagnostic experiments that compare before, during, and after
  bounded load or route changes.
- Sanitized capsule projections and explicit source-lineage contracts for
  multi-observer handoffs.

## Gates

Later work must preserve the passive default, generation fencing, typed support
states, source and freshness provenance, bounded resource use, and the
separation between evidence and identity. New active acquisition, persistence,
or authority requires an explicit product decision before implementation.
Live network and host-tool acquisition remain opt-in acceptance lanes, not
default CI inputs. A live observation may supply a new curated case only after
its provenance and contents have been reviewed for disclosure.

The RF/fusion promotion gate is deliberately stronger than a single live
success: curated replay must cover identifier rotation, board movement,
missing or stale vantages, modality disagreement, partial radiotap headers,
CSI absence, and source-specific coverage gaps; property tests must preserve
ordering and source scope; fuzzing must cover each untrusted parser; and
mutation tests must demonstrate that contradiction and abstention branches
are real. Only then does a bounded live calibration lane measure room or
movement utility against operator-approved labels.
