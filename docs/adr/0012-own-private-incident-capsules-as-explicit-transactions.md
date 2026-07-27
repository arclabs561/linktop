---
id: 0012
status: accepted
governs: src/capsule.rs, src/capsule/**, src/main.rs, README.md, docs/design/operator-intelligence-roadmap.md
why: an intermittent incident needs one bounded handoff that preserves Linktop's path generations, evidence gaps, explicit active-operation receipts, and final projections without turning ordinary exit into retention or making Netbraid own an operator transaction
rejected: save every session automatically (implicit sensitive retention); make Netbraid own the container (wrong product and interaction boundary); use live JSONL alone (no atomic completion or artifact inventory); treat stored prose or screenshots as replay truth (presentation is not evidence); start packet capture as a hidden recording side effect (widens acquisition); mutate a capsule while sanitizing it (destroys provenance)
supersedes: none
superseded_by: none
extends: 0001, 0003, 0004, 0006, 0008, 0010, 0011
confidence: medium
review_trigger: a second producer needs the complete container, one-file transport is required, encrypted-at-rest packaging becomes a product responsibility, packet acquisition is proposed, a partial capsule must be recoverable as complete, or sanitization needs a policy authority beyond explicit structural transforms
---

# ADR-0012: own private incident capsules as explicit transactions

## Context

Linktop is useful while an operator is watching it, and its live JSONL surface can
feed an explicitly selected downstream process. Neither surface is a complete handoff
for an intermittent incident that recovered before review. A later operator needs to
know which path generations occurred, what changed, which collectors were absent or
stale, which active operations were explicitly authorized, which artifacts belong to
the run, and whether the recording completed.

Ordinary Linktop operation deliberately retains no durable evidence. Optional history
is one private host-path JSONL append transaction. Saved-capture review is finite and
read-only. A capsule must not silently widen either boundary, and an interrupted
write must not look like a complete incident.

Netbraid owns reusable versioned evidence and deterministic reducers. It does not own
Linktop's invocation, interaction, terminal lifetime, screenshot set, or operator
decision to retain a bounded run. Making its CLI or libraries own the outer container
would invert the established product boundary.

## Decision

Linktop will own an explicit finite recording transaction, initially exposed as
`linktop record OUTPUT`. Ordinary TUI, plain, JSON, and JSONL exits create no capsule.
Recording does not by itself enable active probes, packet capture, ambient discovery,
or a broader collector set. The selected Linktop subject and passive or active policy
remain explicit and are recorded in the capsule.

An interactive recording completes only after the ordinary `q` stop action or a
caught first `SIGINT`/`SIGTERM` requests a final accepted checkpoint. A headless or
non-interactive recording requires an explicit bounded `--dwell`; it cannot wait
forever by accident. Reaching the dwell, completing the final checkpoint, and
publishing the manifest is success. A second signal, uncatchable termination, process
crash, or failure before that boundary leaves the transaction partial.

### Inspectable directory container

The v1 capsule is an inspectable directory rather than an opaque archive. Its
`manifest.json` names the capsule schema and ID, Linktop producer version and
executable digest, normalized invocation, start and completion times, source clocks,
initial and terminal acquisition policy, path generations, sensitivity, artifacts,
embedded record schemas, reducer identities, and final projection digests. Each
reducer identity binds its contract name and version plus the exact Linktop producer
version or Netbraid package version and source revision that supplied the historical
semantics. A verifier never substitutes the reducer in its current checkout merely
because a type name still exists.

Artifacts may include:

- complete Linktop live-v1 checkpoints and transitions as output projections;
- versioned Netbraid records used by Linktop, with their original schema identifiers;
- typed path-generation and active-operation receipts;
- final finite machine and expert-human projections;
- portable or native screenshots with their QA completion manifests; and
- an explicitly attached packet artifact or normalized saved-capture stream.

Each artifact entry carries a relative safe path, media type, byte length, SHA-256,
producer, role, and sensitivity. Relative paths are unique, contain no traversal, and
resolve only inside the capsule. The manifest is canonical JSON for verification;
human text and pretty JSON copies are presentation artifacts, not digest authorities.

Every complete capsule must contain a canonical, versioned replay-input stream. Its
Linktop-owned records preserve each accepted source observation needed to reconstruct
the final path generations, collector coverage and gaps, peer-cache evidence, counter
intervals, explicit probe results, and active-operation receipts. Conclusions cite
those record IDs. Reusable Netbraid records remain embedded under their native
schemas; Linktop-specific live observations use a capsule-input schema rather than
reinterpreting `linktop.live_observation.v1`, which remains an output contract.
Implementation is blocked until the final conclusions' complete supporting input can
be serialized and reduced again; presentation-only capture is not a valid capsule.

The container is Linktop-owned. Netbraid continues to own only the versioned reusable
records and reducers embedded in it. Linktop does not invoke the Netbraid CLI or copy
its schemas.

### Atomic, no-clobber completion

`OUTPUT` must not exist. Linktop creates a mode-0700 sibling working directory whose
name is visibly partial and unpredictable, writes mode-0600 artifacts there, closes
and syncs every file, writes and syncs the manifest last, syncs the directory, and
atomically publishes the working directory as `OUTPUT` on the same filesystem with an
OS no-replace rename primitive. Linux uses `renameat2` with `RENAME_NOREPLACE`; macOS
uses `renamex_np` with `RENAME_EXCL`. The implementation owns a direct, bounded wrapper
or dependency for those operations and fails closed on a target that cannot provide
the guarantee. It must not substitute `std::fs::rename`, whose destination semantics
permit replacement, or a check-then-rename sequence with a race window.

Only the final name plus a valid manifest and matching artifact inventory is a
complete capsule. Interruption, disk exhaustion, serialization failure, or a container
integrity failure leaves a visibly partial working directory that verification and
replay reject. A collector that is unsupported, stale, unavailable, or fails within
its own declared deadline is instead retained as a typed evidence gap; it does not
abort unrelated evidence or capsule completion. Linktop does not silently delete
partial evidence or promote it to complete. A later salvage feature may inspect
partial bytes but cannot claim the original transaction completed.

### Sensitivity and packet retention

The default sensitivity is `private_operator`: route, address, resolver, network-name,
neighbor-cache, workload, and timing evidence can identify a host, network, or
routine. `public_synthetic` is reserved for authored fixtures.

Recording retains no packet artifact by default. A packet artifact can enter a capsule
only through a separately named opt-in attachment that identifies the source path,
content digest, acquisition policy supplied by its producer, and whether the bytes
were copied successfully into the capsule. A path-only external reference is metadata,
not an artifact, and cannot satisfy replay or completion. Linktop treats raw packets
as opaque and does not infer normalization coverage from their presence. Starting or
coordinating packet acquisition remains a later active-operation decision; `record`
cannot hide it.

Filesystem modes are defense in depth, not encryption or access control. Linktop does
not invent a key-management format. Operators who require encryption place the
capsule on an encrypted volume or wrap the completed directory with a separately
owned transport.

### Verification, replay, and sanitization

Verification is finite and read-only. It rejects partial directories, unknown
required schemas, unsafe or undeclared paths, missing or extra artifacts, size or
digest mismatches, and a manifest whose declared final projection does not match its
artifact. Limits bound manifest size, artifact count, individual artifact size, and
total bytes.

Replay derives typed conclusions again from the mandatory replay-input stream and
embedded versioned evidence under the named reducer versions. Stored live-v1 output,
prose, HTML, terminal cells, and screenshots are comparison artifacts, never replay
inputs or oracles. A completed capsule passes only when the replayed typed conclusions
and declared final machine projection agree. Unsupported future evidence fails with
an explicit compatibility limitation rather than falling back to prose.

Sanitization creates a new no-clobber capsule; it never edits the source. Every
removed, generalized, redacted, or retained field and artifact is represented in a
versioned sanitization receipt that cites the source capsule ID and digest, transform
profile and version, source path or typed field, operation, and result digest.
`sanitized` means those enumerated transforms ran successfully, not that the output is
automatically public or anonymous. The new manifest retains its own sensitivity and
the receipt needed to audit that judgment.

The cited source digest is specifically `manifest_sha256`: SHA-256 of the exact
canonical source `manifest.json` bytes. Because that manifest closes over every
artifact's relative path, role, media type, length, and digest, this binds the receipt
to one complete inventory without a self-referential capsule-digest field.

## Options considered

- **Persist every Linktop run.** Rejected because normal observation would become
  implicit retention of sensitive network and workload evidence.
- **Use `--jsonl` redirected to one file.** Rejected because it has no atomic
  completion, multi-artifact inventory, invocation receipt, sanitization lineage, or
  distinction between a truncated stream and a complete incident. Live v1 is also an
  output projection, not the mandatory source-observation stream needed for replay.
- **Make Netbraid own the capsule.** Rejected because the transaction includes
  Linktop-specific lifetime, interaction, and presentation artifacts. Netbraid remains
  the reusable record and reducer owner.
- **Use a tar, zip, or custom binary container first.** Rejected because an
  inspectable directory makes verification, diffing, partial-state semantics, and
  specialist attachments simpler. A deterministic transport wrapper can be added
  without changing the inner contract when a real consumer requires one file.
- **Treat screenshots or final prose as truth.** Rejected because rendering changes
  and truncation must not alter evidence semantics.
- **Capture packets whenever recording starts.** Rejected because recording and
  acquisition are separate permissions with different sensitivity and side effects.
- **Sanitize in place.** Rejected because it destroys source provenance and makes the
  completeness receipt unverifiable.

## Consequences

An operator can deliberately retain a bounded, verifiable incident without changing
Linktop's passive default or requiring a daemon, controller, Netbraid executable, or
cloud service. A complete directory has one unambiguous transaction boundary; a
partial directory cannot masquerade as success.

Capsules are sensitive by default and may be larger than live JSONL because each
checkpoint is self-contained. Explicit artifact and total-byte limits are therefore
part of implementation, not optional hardening. Directory transport is less
convenient than one file, but preserves inspectability until a concrete transport
consumer earns another layer.

The ADR fixes the ownership and integrity contract before implementation. It does not
authorize automatic retention, packet acquisition, background recording, network
publication, identity binding, or an encryption/key-management subsystem.

## Lineage

Extends ADR-0001's standalone instrument, ADR-0003's generation fence, ADR-0004's
bounded screenshot transaction, ADR-0006's explicit activity boundary, ADR-0008's
Netbraid library ownership split, ADR-0010's common typed projection, and ADR-0011's
finite read-only saved-evidence semantics.
