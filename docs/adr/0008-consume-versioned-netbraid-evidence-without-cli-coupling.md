---
id: 0008
status: accepted
governs: Cargo.toml, Cargo.lock, src/history.rs, src/main.rs, src/model.rs, src/net.rs, src/plain.rs, src/ui.rs, README.md, docs/design/**, .github/workflows/**
why: cross-session context and recurrence need one versioned replay contract, while Linktop must remain an independently useful host instrument and must not turn another CLI's output into an internal API
rejected: invoking the Netmon CLI for routine history (process and prose/JSON coupling), copying evidence/replay types into Linktop (semantic drift), cross-repository path dependencies (workstation-layout coupling), merging the repositories (different product lifecycles), creating a third shared repository now (no independent owner or release need)
supersedes: none
superseded_by: none
extends: 0001, 0003, 0005, 0006, 0007
confidence: medium
review_trigger: the v0 contract fails real hotspot/site recurrence fixtures, another ecosystem needs the contract, Netbraid libraries gain collection or deployment dependencies, or the stable multi-modal schema gate passes
---

# ADR-0008: consume versioned Netbraid evidence without CLI coupling

## Context

Linktop can identify a path generation and changes within one process, but it cannot
answer whether the current network context has been seen on a prior day, at another
site, or before a recurring incident. ADR-0007 deliberately deferred durable baselines
to Netmon. Netmon now has an experimental Rust `HostPathObservationV0` record and
deterministic replay library, giving the deferral a concrete second-consumer test
without declaring its broader identity-fusion schema stable.

The tools still have different jobs. Linktop observes and explains the current host's
path. The Netmon CLI inspects durable and multi-source evidence. Requiring one CLI to
spawn the other for ordinary comparison would make executable discovery, process
lifetime, terminal output, and JSON prose part of Linktop's internal semantics. Merging
the repositories would erase useful release and product boundaries.

Network context must also remain distinct from physical place. A household Wi-Fi,
office, hotel, café, vehicle, hotspot, VPN overlay, or unknown network can all produce
contexts. SSIDs are neither unique nor trustworthy location identifiers. One site can
contain many BSSIDs and a hotspot can move. Associated BSSID, SSID, gateway,
DHCP/address prefix, resolver set, controller site evidence, recurrence, and explicit
operator assertions can collectively support a place candidate; none is a universal
place fact by itself.

Durable records contain private operator evidence such as SSIDs, BSSIDs, addresses,
gateways, resolvers, and association metadata. Enabling their storage without an
operator decision would reverse Linktop's no-retention default.

## Decision

Linktop imports `netmon-evidence` and `netmon-replay` as Rust libraries pinned to one
exact HTTPS Git revision. It does not invoke the Netmon CLI for routine evidence
exchange. Netmon workspace crates may use local path dependencies internally; Linktop
must not depend on a sibling checkout path. A future stable semver release replaces
the Git pin only after the governing Netmon schema and compatibility gates pass.

The imported libraries remain policy-neutral:

- `netmon-evidence` owns versioned serialized record types and validation;
- `netmon-replay` owns explicit JSONL I/O, comparison, deduplication, and deterministic
  replay;
- Linktop owns native host collectors, mapping its live model into a record, operator
  interaction, immediate diagnosis, and rendering; and
- the Netmon CLI remains a separate operator projection over shared libraries.

Linktop retains no durable evidence by default. An operator-supplied history path is
the explicit retention transaction. Linktop reads that path, compares the completed
current context with compatible prior records, cites recurrence or changed dimensions,
and appends the new record. A missing or empty path establishes only that this is the
first record in that log. Malformed or incompatible evidence disables history for the
session and is reported as an evidence limitation; it cannot change the current path
diagnosis or be silently overwritten.

The v0 history records only host-path context collected under Linktop's passive policy:
event/acquisition time, source and observer, coverage, interface/link type, network-name
visibility, association ID, associated BSSID when the OS exposes it, next hop, resolver
set, and path address prefixes. Explicit active probes remain separate episode evidence
and are not smuggled into this passive context record merely because the TUI has active
probes enabled.

An association or BSSID change is visible temporal evidence but does not alone define a
new durable network context. Conversely, the same SSID with a different network
boundary can be a different context. Linktop may say that a context recurred or changed.
It must not invent a human place label. Place remains a derived candidate with sources,
interval, alternatives, freshness, and confidence. Controller-verified site data or an
explicit private operator label can outrank a host-only signature.

The direct route, radio, counter, neighbor-cache, and probe behavior remains usable with
no history option and with no Netmon executable, daemon, controller, or store present.
Imported libraries may not initiate network activity.

## Options considered

- **Invoke `netmon evidence` and parse its output.** Rejected for routine integration.
  A CLI is useful for shell composition and non-Rust consumers, but it is the wrong
  in-process semantic boundary for two Rust tools.
- **Copy a JSON schema and comparison code into Linktop.** Rejected because ordering,
  duplicate, context-key, and compatibility behavior would drift.
- **Use `../netmon` path dependencies.** Rejected because a fresh Linktop checkout
  would depend on one workstation's directory layout.
- **Merge Linktop into Netmon.** Rejected because immediate host diagnosis and durable
  replay have different collection, retention, interaction, and release lifecycles.
- **Create a third evidence repository.** Rejected until the contract has an
  independent owner or several consumers whose release cadence is not Netmon's.
- **Store history automatically under a cache directory.** Rejected because this
  silently changes retention of sensitive network identifiers.

## Consequences

Linktop becomes the first real external consumer of Netmon's Rust package boundary.
That provides empirical pressure on provenance, coverage, ordering, and comparison
before the multi-modal schema freezes. Fresh builds fetch the pinned Git revision, but
runtime operation remains standalone and deterministic.

Operators can opt into prior-context intelligence without enabling packet capture,
controller access, scanning, or active probes. First-run and unavailable-history states
remain explicit. History can improve context and next-action ranking but cannot
override fresh host evidence.

Associated BSSID collection improves recurrence and roaming evidence when macOS exposes
it. Location Services policy may return a redacted value; Linktop reports that coverage
gap rather than substituting a guess. Passive ambient-AP scanning is not authorized by
this decision.

The v0 contract will change if real multi-location fixtures expose a bad context key.
That is expected during the experimental Git-pinned phase. Stable publication requires
golden JSONL, backward-compatibility, multi-modal fixtures, deterministic replay CI, and
the governing Netmon schema gate.

## Lineage

Extends ADR-0001's standalone instrument boundary, ADR-0003's path-generation fence,
ADR-0005's evidence-ranked diagnosis, ADR-0006's explicit acquisition policy, and
ADR-0007's decision to keep durable baselines and replay in Netmon.

## Update (2026-07-24): public exact-revision dependency

Netmon is a public source dependency. Clean builds and forks fetch the pinned
revision over ordinary HTTPS without a repository credential. The exact
revision remains the experimental compatibility boundary until the shared
crates meet their semver publication gates.

## Update (2026-07-24): recurrence separates context and attachment

The v0 replay boundary now owns an observer-scoped recurrence reduction in
addition to pairwise comparison. It reports exact prior observations,
compatible/incomplete candidates, first and last exact times, and distinct
associated-BSSID variants separately. Compatibility is not transitively
clustered because missing evidence is not an equivalence relation.

Linktop projects a changed BSSID inside an exact recurring context as
attachment evidence, not a new place or verified AP. A gateway link binding is
a context anchor, not a place candidate by itself. The ordinary projection
says `place unknown` until an operator or authoritative controller assertion
exists. The detailed rationale and reversal gates are in
[`docs/design/context-recurrence-and-place.md`](../design/context-recurrence-and-place.md).

## Update (2026-07-24): exact key equality is not always recurrence

Netmon replay now types exact matches as absent, unanchored, or anchored. Linktop
uses `recurring network context` and `returned` only when the exact key contains
the passively observed gateway next-hop link-layer binding. Equal sparse keys
remain exact host-path key matches with identity unanchored. A repeated BSSID is
separate attachment corroboration and never promotes that result.

The JSONL reader may also return a valid prefix plus a typed warning when the
only malformed content is one unterminated final fragment. Linktop uses that
prefix read-only, reports the interruption, and never appends behind it.
Internal or newline-terminated corruption still disables history. The current
observer ID is the reported hostname and is not claimed as durable hardware
identity.

## Update (2026-07-26): consume the released 0.1.0 commit without widening the contract

Netmon now publishes a checksummed `netmon-v0.1.0` CLI release. Linktop advances
its `netmon-evidence` and `netmon-replay` dependencies to the exact commit
underlying that release so downstream CI and the released executable exercise
one source boundary.

The crates remain experimental, `publish = false`, and outside the stable
multi-modal schema gate. A binary release therefore does not turn their Rust API
into a semver compatibility promise. Linktop retains the exact HTTPS revision
pin until that gate passes; it does not depend on a mutable branch, sibling
checkout, installed Netmon executable, or human-readable CLI output.

## Update (2026-07-26): scope coverage to the serialized passive record

The host-path record's `policy` and `coverage` describe only evidence serialized
into that record. Linktop derives coverage from the declared route, next-hop,
resolver, address, association, BSSID, and gateway-binding source set. Active
probe state, interface counters, radio telemetry, workload accounting, and
other peer-cache health cannot make an otherwise identical passive history
record partial because those observations are not represented in the v0
payload.

This preserves the existing decision that active probes are not smuggled into
passive durable context and prevents the same stored evidence from changing
meaning merely because the enclosing overview enabled another collector.

## Update (2026-07-26): follow the Netbraid product rename without changing the wire protocol

The source repository, Rust package family, and current producer identity are
now Netbraid. Linktop imports `netbraid-evidence` and `netbraid-replay` from the
public Netbraid repository at one exact commit. It still does not invoke the
Netbraid executable, depend on a sibling checkout, or require any runtime
service.

Established serialized identifiers remain `netmon.*`, including
`netmon.host_path_observation.v0`. Those identifiers are compatibility
protocols, not product branding, and this dependency rename must not rewrite
stored history. The exact Git revision remains the source boundary until the
packages are available from crates.io at one compatible release identity and
Linktop can adopt them in a separately verified dependency-only change.

## Update (2026-07-27): consume typed public scenarios without weakening the source pin

Netbraid's first registry release identity is 0.3.0 because its immutable
0.2.0 Git tag predates the bytes prepared for registry publication. That
version correction does not itself satisfy Linktop's dependency gate. Linktop
retains one exact Netbraid Git revision until the registry packages are visible
and their VCS identity is verified.

The same revision now supplies closed `PUBLIC_SYNTHETIC` scenario bundles and a
receipt-bound typed checkpoint-input accessor. Linktop may use those scenarios
in tests to reduce host-path evidence independently. Authored conclusions and
viewport prose remain Netbraid fixture oracles, not Linktop inputs. Linktop
continues to own its peer, counter, probe, workload, generation, and
presentation scenarios because those facts are not represented by the current
Netbraid host-path record.

## Update (2026-07-27): reuse public scenarios in bounded screenshot QA

The scenario-consumer boundary now also covers Linktop's built-in screenshot
transaction. The exact-revision `netbraid-replay` dependency enables
`scenario-fixtures` in the binary so an installed Linktop can run the same
deterministic and native QA scene. This embeds the closed fixture bundles but
adds no Netbraid executable, service, collector, sibling-checkout dependency,
or network activity.

Linktop loads `wifi-hotspot-wifi`, verifies `PUBLIC_SYNTHETIC`, obtains each
checkpoint through a replay receipt, and consumes only typed checkpoint inputs
at its adapter boundary. Netbraid's replay machinery constructs and validates
the complete closed receipt, including authored conclusions and viewport
assertions, before releasing those inputs. Linktop never inspects, branches on,
or renders those oracle fields; an oracle mismatch rejects the scene rather
than becoming operator evidence. The capture-owned adapter maps host,
interface, link type, network-name visibility, next hop, resolvers, association
ID, and BSSID. It does not reverse a network prefix into a host address or
invent radio, peer-cache completeness, place, owner, or 802.11-roam evidence.

The three records drive Linktop's path-generation and history reducers only in
process and only inside the explicit passive screenshot scene. Ordinary
operation does not load a scene and has no Netbraid runtime service dependency;
screenshot continues to reject operator history. The QA clock changes when
records enter the view, not their source evidence timestamps. Revisit the
embedded-fixture footprint if Netbraid provides a narrower evidence-only
built-in API, if fail-closed validation of unrelated fixture oracles becomes an
availability problem, or if the scenario corpus grows materially.

## Update (2026-07-27): require explicit native-child authority for scenes

An environment value alone no longer selects a synthetic scene. The native
screenshot parent must also launch the executable in a hidden internal-child
mode that is valid only for a passive interactive overview, link, or peers
process. Ordinary TUI entry points ignore inherited scene environment values,
so a stale shell variable cannot replace live collection with fixture evidence.
The parent still clears inherited history and scene values before installing
the requested scene.

This mode is an accidental-activation boundary, not authentication against a
deliberate same-user process. The private gate remains a synchronization
primitive for timed scenes, not a credential. A stronger capability-file or
inherited-descriptor protocol is deferred until native screenshot children cross
a user, privilege, or process-trust boundary.
