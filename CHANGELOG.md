# Changelog

All notable changes to Linktop's versioned Cargo package and native binary
release are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Linktop ships one binary package; crates.io and native GitHub archives share
one version.

## [Unreleased]

### Added

- Added private, bounded incident-capsule packaging and verification for
  canonical Netbraid host-path history. Version 0 is lossless and does not
  collect, capture packets, or infer identity.
- Added finite observer-scoped episode summaries for canonical host-path
  history, with JSON output and no source mutation.
- Added bounded traffic-shape candidate features to completed path windows
  when valid kernel interface-counter intervals exist; these remain aggregate
  non-identity evidence.
- Added a finite purpose-specific readiness report. Interactive-use status is
  derived from fresh path context and gateway, DNS, and HTTPS measurements;
  calls and bulk transfer abstain until measured, while idle-background status
  uses three bounded host process-accounting windows without claiming absolute
  idleness.

## [0.1.2] - 2026-07-28

### Fixed

- Added a documentation-only library target so docs.rs can render the package
  overview, and changed the documentation gate to reproduce docs.rs's
  `cargo rustdoc --lib` target selection.

## [0.1.1] - 2026-07-28

### Changed

- Reworked the README around install, representative output, command lifetimes,
  evidence boundaries, and normal operator workflows.
- Consolidated contributor-facing architecture and decision rationale into a
  small public documentation set; internal design working notes remain
  local-only.

### Fixed

- Added repository-local ignores for human log output, saved network evidence,
  credential-shaped files, and private development notes so fresh clones do
  not rely on a machine-global ignore file.

## [0.1.0] - 2026-07-27

### Added

- A passive-first terminal dashboard for route, interface, Wi-Fi association,
  resolver, address, counter, workload, and native neighbor-cache evidence.
- Explicit opt-in next-hop, DNS, HTTPS, public-egress, and load experiments
  with bounded deadlines and evidence-ranked diagnosis.
- Responsive overview, link, and peer TUI views plus finite text, JSON, and
  live JSONL projections derived from the same typed observation model.
- Path-generation fencing across Wi-Fi, hotspot, Ethernet, and VPN changes,
  with optional private Netbraid history for evidence-qualified recurrence.
- Finite read-only review of normalized Netbraid saved-capture evidence.
- Deterministic and native-terminal screenshot transactions for repeatable
  visual QA across terminal sizes and network-transition scenes.
- One crates.io binary package and checksummed, attested native archives for
  x86-64 Linux, Intel macOS, and Apple-silicon macOS.

### Changed

- Replaced two exact-Git Netbraid package dependencies with the released
  `netbraid` 0.3.0 registry package. Linktop imports only the policy-neutral
  evidence, replay, and public scenario-fixture surfaces; Netbraid's CLI and
  TShark adapter features remain disabled.

[Unreleased]: https://github.com/arclabs561/linktop/compare/linktop-v0.1.2...HEAD
[0.1.2]: https://github.com/arclabs561/linktop/compare/linktop-v0.1.1...linktop-v0.1.2
[0.1.1]: https://github.com/arclabs561/linktop/compare/linktop-v0.1.0...linktop-v0.1.1
[0.1.0]: https://github.com/arclabs561/linktop/releases/tag/linktop-v0.1.0
