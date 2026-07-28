# Changelog

All notable changes to Linktop's versioned Cargo package and native binary
release are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Linktop ships one binary package; crates.io and native GitHub archives share
one version.

## [Unreleased]

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

[Unreleased]: https://github.com/arclabs561/linktop/compare/linktop-v0.1.0...HEAD
[0.1.0]: https://github.com/arclabs561/linktop/releases/tag/linktop-v0.1.0
