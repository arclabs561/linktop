---
id: 0011
status: accepted
governs: src/review.rs, src/review/**, src/main.rs, README.md
why: a saved incident needs the same coverage-preserving Netbraid reduction available to a Linktop operator without turning Linktop into a packet collector, normalization process, durable store, or fusion writer
rejected: invoke the Netbraid CLI or TShark (process and deployment coupling); accept raw PCAP directly (duplicates Netbraid's bounded normalization boundary); copy Netbraid projection types into Linktop (schema and abstention drift); add saved evidence to --history (changes a read-only review into a retention transaction); attach capture endpoints to peer identity fields (conflates scoped packet evidence with host-visible cache state and identity)
supersedes: none
superseded_by: none
extends: 0001, 0002, 0006, 0008, 0010
confidence: high
review_trigger: Netbraid changes the saved-capture triage schema, a real operator needs interactive paging over more than the bounded top projection, review needs correlation with live host evidence, or review gains acquisition, persistence, publication, identity mutation, or a second derived schema
---

# ADR-0011: review normalized saved evidence as a finite read-only projection

## Context

Netbraid's pinned Rust replay library now validates canonical normalized
saved-capture JSONL and derives a bounded `netmon.saved_pcap_triage.v1`
projection. The projection retains the full source manifest, optional
occurrence receipt, normalized-record digest, completeness, quarantine
coverage, WLAN disconnect status, a cumulative top conversation, typed
exclusions, event windows, and candidate TShark display filters. Its optional
trailing-window projection distinguishes source-artifact, normalized, and
selected packet-time extents and explicitly qualifies or abstains from negative
claims.

Linktop already consumes the same policy-neutral evidence and replay libraries
for optional host-path recurrence, but that surface is a live overview
retention transaction: it reads prior host-path records and appends the current
generation. Reusing it for an incident artifact would mutate the source and
blur two different lifetimes.

Saved capture normalization remains Netbraid's job. It owns the bounded TShark
and Capinfos process boundary, staging, configuration provenance, packet
envelopes, quarantine, and normalization completeness. Linktop should not need
those executables merely to present an already normalized record stream.

## Decision

Add `linktop review INPUT` as a finite, read-only human projection over a
canonical Netbraid saved-capture JSONL stream. Linktop calls the pinned
`netbraid-replay` file reader and triage reducer directly. It does not invoke a
CLI, TShark, Capinfos, a live Linktop collector, or a network request, and it
never writes to the supplied input.

`INPUT` is normalized JSONL, not raw PCAP or PCAPNG. Reads have an explicit
byte limit. Strict schema validation, canonical serialization, family order,
capture identity, counts, and normalized-record digest remain Netbraid-owned
invariants. Invalid or oversized input fails the finite transaction without
falling back to partial prose.

The default output is a bounded expert-human report. It preserves:

- capture ID, field registry, and normalized-record digest;
- artifact digest and size, observer and acquired time (including unknowns),
  acquisition policy, and extractor adapter/tool/configuration provenance;
- occurrence run and source-file timing when a receipt is present;
- complete-capture or normalized-subset scope;
- normalization, inspection, packet-limit, and quarantine counts;
- typed WLAN status and each supported disconnect observation;
- cumulative top-conversation scope, observation point, endpoints,
  directional frame and octet counts, TCP flag counts, and event window;
- typed exclusion counts; and
- exact candidate display filters for specialist drill-down.

`--tail-seconds SECONDS` requests an exact-decimal trailing packet-time window
from one nanosecond through Netbraid's signed-time projection limit. Linktop
passes the nanosecond value into Netbraid's typed projection. It renders the
interval anchor, requested bounds, source-artifact extent, normalized extent,
selected extent, negative-claim qualification or abstention, selected top
conversation, exclusions, and exact time-bounded candidate pivot. A positive
conversation may still be reported from partial or receiptless evidence while
absence remains abstained.

Human wording may improve, but it cannot promote subset absence to
capture-wide absence or describe the cumulative top conversation as a
time-local episode. Endpoints and display filters are scoped capture evidence,
not peer, device, person, service, application, or intent identity.

`--json` serializes Netbraid's exact typed
`netmon.saved_pcap_triage.v1` value without a Linktop envelope or copied schema.
This keeps one derivation contract across Netbraid and Linktop. It also keeps
finite Linktop snapshot and live-v1 schemas unchanged.

The first surface remains finite text and JSON. A later focused TUI must be
earned by an operator interaction that cannot be handled by the bounded report;
terminal detection alone does not change review lifetime.

## Options considered

- **Invoke `netbraid pcap` or parse its text.** Rejected because an installed
  executable, process lifetime, and human prose would become Linktop runtime
  dependencies.
- **Invoke TShark from Linktop.** Rejected because raw normalization,
  configuration provenance, staging, deadlines, and quarantine already have a
  bounded Netbraid owner.
- **Accept Netbraid output through `--history`.** Rejected because history is a
  host-path comparison and append transaction, not immutable saved-input
  review.
- **Copy the triage types and reducer.** Rejected because coverage,
  abstention, ordering, candidate-pivot, and digest semantics would drift.
- **Merge capture endpoints into the peers view.** Rejected because the native
  neighbor cache and a saved artifact have different observer, time, coverage,
  and identity scopes.
- **Add a Linktop review JSON schema.** Rejected because a wrapper would add no
  claim while creating a second compatibility boundary over the same typed
  projection.

## Consequences

An operator can inspect already normalized incident evidence through Linktop
without granting packet access or installing a Netbraid runtime service.
Netbraid remains the normalization and deterministic-replay authority; Linktop
owns only the finite operator presentation.

The exact Git revision remains load-bearing because the saved-capture triage
types are experimental and unpublished. A dependency update must rerun the
human and exact-JSON goldens and preserve the read-only, no-subprocess smoke
contract.

Review does not correlate a saved artifact with the current host path, create
episodes, classify traffic, attach identities, persist evidence, or mutate a
fusion store. Those require separately versioned evidence and a new ownership
decision.

## Lineage

Extends ADR-0001's standalone host-instrument boundary, ADR-0002's explicit
lifetime contracts, ADR-0006's acquisition separation, ADR-0008's library
integration without CLI coupling, and ADR-0010's rule that a new replay/input
contract must not reinterpret live-v1 output.
