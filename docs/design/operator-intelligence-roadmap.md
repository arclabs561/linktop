---
status: active
scope: Linktop operator experience and projections
decisions:
  - ../adr/0001-build-a-standalone-host-path-instrument.md
  - ../adr/0002-make-focused-view-lifetimes-explicit.md
  - ../adr/0003-fence-observations-by-path-generation.md
  - ../adr/0004-make-ui-screenshots-a-bounded-transaction.md
  - ../adr/0005-rank-diagnosis-by-evidence-and-causal-scope.md
  - ../adr/0006-make-active-network-operations-explicit.md
  - ../adr/0007-prioritize-change-context-and-consequential-workload.md
  - ../adr/0008-consume-versioned-netbraid-evidence-without-cli-coupling.md
  - ../adr/0009-separate-effective-route-from-physical-underlay.md
  - ../adr/0010-project-live-evidence-once-across-human-and-machine-outputs.md
  - ../adr/0011-review-normalized-saved-evidence-read-only.md
grounded_in:
  - network-situation-intelligence.md
  - context-recurrence-and-place.md
  - focused-view-lifetimes.md
review_trigger: a view requires new collection, a machine output cannot project the same typed assessment as the TUI, or Linktop is asked to own durable multi-source fusion
---

# Roadmap: operator network intelligence

## Where we are

Linktop is a standalone Rust host-path instrument. Its default is passive
host-local observation; active probes and load experiments are explicit. It
provides a responsive overview TUI, focused link and peers views, finite text
and JSON, bounded plain and JSONL dwell, deterministic portable screenshots,
native tmux-backed terminal captures, path-generation fencing, macOS physical
underlay evidence, session peer dwell, optional Netbraid host-path history, and
finite review of normalized saved evidence.

The instrument already detects route, interface, resolver, address-prefix,
association, Wi-Fi/hotspot, and overlay changes without reducing every context
to “house” or “hotspot.” It distinguishes the effective route from its physical
underlay, cache presence from device presence, and network context from
physical place.

The remaining product problem is not panel count. The overview still has to
become a consistently excellent answer surface: what matters now, why, what
changed, what is consequential, what is unknown, and which bounded action
would reduce uncertainty. The same semantics then need to survive every
terminal size and every human or machine projection.

## Roadmap split

This document owns the immediate operator product. Netbraid's
[public network-intelligence roadmap](https://github.com/arclabs561/netbraid/blob/main/docs/design/network-intelligence-roadmap.md)
owns reusable evidence, replay, adapters, corpora, and candidate mechanics.
Infra's private fusion roadmap owns deployed collectors, private identity and
consent joins, retention, live writer cutover, and Home Assistant projection.

Linktop remains independently useful without a Netbraid executable, daemon,
database, controller, or cloud account. It imports released Netbraid evidence
and replay libraries when they add cited prior context; it never becomes a
second durable fusion plane.

## Program invariants

- Passive host-local observation remains the default. Selecting a view never
  starts collection that the command did not already authorize.
- Active operations name target, protocol, cadence or duration, deadline,
  side effects, progress, and receipt. They are useful independently of the
  TUI.
- The local operator view is not redacted. Privacy is enforced at capture,
  persistence, export, and sharing boundaries.
- The overview ranks answer, reason, change, path, consequence, next move, and
  coverage. Static inventory appears only when it supports one of those.
- TUI, one-shot text, plain dwell, JSON/JSONL, screenshots, and replay project
  one typed assessment. Renderers may change density, not meaning.
- Every claim is observed, advertised, derived, candidate, verified, or
  unknown and retains source, age, scope, coverage, limitations, and conflicts.
- Path generations fence all asynchronous evidence. A slow result from the
  prior Wi-Fi, hotspot, VPN, or route cannot repopulate the new context.
- Attachment, network context, overlay, place candidate, and verified place
  remain separate. SSID, BSSID, gateway, public egress, or a historical
  nickname alone does not establish location.
- A peer cache row proves only a cache binding under the source's coverage.
  Linktop does not silently infer device presence, activity, identity, person,
  intent, or departure.
- Useful facts appear after the first supported sample. Additional dwell
  improves rates, distributions, change history, and recurrence; it does not
  unlock basic provenance or honesty.
- Linktop does not capture packets, run ambient wireless scans, perform
  default LAN discovery, own credentials, or retain network evidence unless
  the operator explicitly requests a durable output.

## Operator situations that define usefulness

| Situation | First useful answer |
| --- | --- |
| Starting a shell, call, deployment, game, or transfer | whether evidence supports readiness, what is untested, and the current path and workload caveats |
| Switching between Wi-Fi, a hotspot, Ethernet, or VPN | the exact attachment, route, resolver, address, and underlay dimensions that changed |
| Roaming inside one mesh or revisiting a venue | attachment recurrence versus compatible network context, with physical place still unknown unless verified |
| A call freezes during an upload | consequential local process rate, interface load, gateway evidence, and the earliest supported change |
| DNS fails while the local link is healthy | causal-scope ranking that separates radio/interface, gateway, resolver, overlay, and remote edge |
| A peer appears, changes binding, disappears from cache, or returns | source, interface, kernel state, first/last positive observation, and explicit cache semantics |
| An intermittent symptom recovers before inspection | a finite incident capsule with path generations, changes, gaps, and explicit active receipts |
| Encrypted traffic needs coarse attribution | a cited application, service, stack, or role candidate with alternatives and abstention, never an identity fact |

This table is the admission test for overview rows, reducers, and new
collectors. A datum without an operator decision belongs in a focused evidence
view, machine output, or a specialist handoff.

## Phase 0: establish the standalone instrument (complete)

The Rust project, passive default, output/lifetime matrix, path generations,
focused views, active-operation boundary, common typed projection, session
peer dwell, current-path recurrence, saved-evidence review, and bounded
screenshot transactions are implemented.

Gate: passed. Canonical tests and lint are green; deterministic UI and capture
contract tests exercise wide, shallow, narrow, resize, navigation, and
dense-peer cases. The native runner is implemented, and an ignored private QA
transaction has exercised minimum, medium, and wide PTY sizes, resize,
navigation, and peer selection with a completion-last manifest whose artifact
lengths and digests were independently verified. Retained captures without
that manifest still are not authenticated gate evidence.

Value: Linktop is useful immediately as a live instrument, a finite report, a
bounded stream, or a deterministic QA subject.

## Phase 1: make operator scenarios the presentation gate

Consume Netbraid scenario receipts in Linktop tests without teaching the
scenario validator to execute Linktop or interpret authored prose. Independently
derive Linktop's typed assessment at each checkpoint, render the relevant
viewport, and compare both semantics and presentation.

Complete the highest-value scenario matrix:

- Wi-Fi to hotspot and back; same-SSID BSSID attachment changes;
  independently evidenced 802.11 roam/ESS continuity; and unrelated-site or
  unrelated-network variation;
- attachment-stable VPN entry, exit, and split routes;
- gateway, resolver, and remote-edge impairment;
- incomplete and stale peer-cache coverage;
- narrow, short, intermediate, and wide overview/link/peers layouts; and
- saved-capture review with positive, conflicting, quarantined, and abstained
  evidence.

Refine the overview against those cases. At every supported size it must retain
the current answer, decisive reason or coverage gap, path/change context, and
one complete action. More space adds causal evidence and consequential
workload before static inventory. Focused peers keeps navigation, selection,
source semantics, and overflow visible when the overview cannot.

Consumer: a human operator during the first seconds and first transition of a
session.

Gate: each scenario's typed result is independently asserted; portable and
native screenshots agree on the content contract; 60x10 remains the minimum
supported evidence frame; no control or selected row falls outside the
viewport; no view switch widens acquisition.

Checkpoint (2026-07-27): Linktop pins one exact Netbraid 0.3 source revision
and independently reduces typed checkpoint inputs for four public scenarios:
Wi-Fi/hotspot recurrence; a compatible same-SSID BSSID attachment transition
followed by an incompatible reused-label boundary; overlay exit without
provider or intent attribution; and a stale cache-source gap that cannot
become presence or departure. The same-SSID attachment-boundary scenario drives
the same typed history conclusion through plain history output, the live JSON
projection, and deterministic overview rendering above minimum height; at
60x10, the compact overview retains the current diagnosis, path, evidence
coverage, and complete action ahead of history context. Authenticated
deterministic and native captures separately exercise the dense-peer session
at those sizes, including resize, view navigation, and row selection. This is
a real Phase 1 slice. A timed `wifi-hotspot-wifi` scene now drives the same
receipt-bound public-synthetic inputs through real path generations and
process-local history at 0s/2s/4s. Deterministic and native 1s/3s/5s captures
exercise 160x30, minimum 60x10, and 100x24; the returned-context inference is
visible when height permits, while the minimum frame retains diagnosis, path,
coverage, and action. Independently evidenced 802.11 roam/ESS and
unrelated-site variation, split-route detail, impairment combinations,
saved-capture combinations, and scenario-driven rendering across every subject
remain open.

Reversibility: fixtures and ranking can evolve without changing machine schema
meaning or collector policy.

## Phase 2: ratify and build a private incident capsule

Design one explicit finite transaction for handing off an intermittent
incident. It should retain invocation and producer identity, path generations,
typed changes, source and coverage gaps, explicit active-operation receipts,
artifact digests, and final human and machine summaries. Ordinary Linktop exit
must not save packets or silently create a durable history.

ADR-0012 now ratifies the explicit Linktop recording transaction as the
operator-owned container. It fixes the inspectable directory format, OS-level
no-replace completion, interruption boundary, mandatory replay-input stream,
reducer provenance, sensitivity labels, packet-retention opt-in,
sanitization receipts, and replay contract. Implementation remains blocked
until Linktop can serialize every source observation needed to derive its
terminal conclusions again. Versioned Netbraid records remain embedded when
reusable; transaction ownership does not move to Netbraid.

Consumer: the operator, a later shell session, or an agent reviewing a bounded
incident.

Gate: partial output cannot masquerade as complete; a completed capsule
replays to the same typed conclusions; a sanitized export enumerates every
removed or transformed field; default operation retains no packet artifact.

Reversibility: explicit local files only, with no service or implicit
retention.

## Phase 3: finish purpose-aware situations and bounded experiments

Promote the overview from a generic network condition to a purpose-aware
situation for interactive shell, call, deployment, transfer, or
operator-selected target. Purpose changes thresholds and consequence language;
it does not change observed facts.

Complete session-local episode stories: trigger, earliest supported change,
symptom, causal scope, consequence, recovery, and remaining blind spot.
Recommend the smallest experiment that distinguishes the leading hypotheses,
then require explicit approval before transmitting. Bracket active work with
before/during/after evidence and preserve its result as a finite report.

Prefer specialist handoffs when the question is already owned well: Trippy or
MTR for route distributions, doggo for DNS, iperf3 for bounded load, Wireshark
or TShark for packet evidence, and Nmap for explicit discovery. Linktop hands
off the current context and later imports a receipt; it does not copy every
tool.

Consumer: an operator deciding whether to wait, switch paths, stop a workload,
run a test, or hand off.

Gate: readiness can be `UNTESTED` under passive-only evidence; each diagnosis
names causal scope and decisive support; every recommendation states expected
information gain and side effects; disabling active policy prevents all
transmission.

Reversibility: purpose and experiment reducers are projections over the same
observations and can be disabled independently.

## Phase 4: add durable recurrence and cross-session baselines

After Netbraid publishes compatible replay crates and passes longitudinal
scenario gates, import optional path- or site-scoped episodes and baselines.
Associate every imported record with the current Linktop path generation by
observer and interval. Show a prior episode only when its context is compatible
and its provenance materially helps the current decision.

Keep process-local recurrence useful without durable history: one transition,
recovery, cache change, or return is already an episode. Durable evidence adds
cross-session comparison; it does not make the current view depend on long
uptime.

Consumer: repeated intermittent failures and comparison across ordinary
network contexts.

Gate: incremental and batch replay agree; incompatible contexts do not merge;
late evidence cannot rewrite the current generation; disabling history leaves
all direct observation and diagnosis intact.

Reversibility: imported baselines are optional cited evidence and never replace
current host observations.

## Phase 5: project multi-vantage and advisory intelligence

Render Netbraid-owned feature observations, episode comparisons, and advisory
application, service, stack, or device-role candidates in focused evidence
views. A candidate must show source, observer, direction, interval,
extractor/signature/model version, alternatives, conflicts, drift, and why the
method abstained when it did.

Multi-vantage evidence may localize a symptom across host, gateway/controller,
local sensor, and remote witness. It does not give Linktop authority over those
collectors, their retention, private aliases, verified device bindings, or
person labels.

Consumer: an expert deciding which specialist evidence to inspect or whether a
candidate is worth private verification.

Gate: Netbraid's calibration and abstention gates pass; one packet interpreted
by multiple tools is not double-counted; unknown stays visible; Linktop can
remove the candidate panel without changing observed facts or accepted private
bindings.

Reversibility: focused candidate and multi-vantage projections are optional.

## Phase 6: grounded explanation over cited evidence

Only after typed situations, episodes, and source lineage are stable, add
questions such as “what changed before the call froze?” or “have I seen this
failure on another context?” The explanation layer selects and summarizes
cited records; it does not extract packet facts, invent hidden coverage, or
turn a candidate into a verified identity.

Consumer: fast incident comprehension and handoff.

Gate: every material sentence maps to typed evidence or an explicit
uncertainty; deterministic text/JSON remains available without the explanation
layer; sensitive records never leave their authorized boundary.

Reversibility: explanations are derived output and can be removed without
changing evidence or diagnosis.

## Structural forks requiring a decision before code

The incident-capsule fork is resolved by ADR-0012. Remaining forks are:

1. Purpose-profile compatibility if purpose becomes a machine-readable
   contract rather than local presentation configuration.
2. A new collector whose activation depends on the selected view. The default
   answer is no; a new activity boundary requires an ADR.
3. Candidate or place presentation that needs private binding authority.
   Linktop may project cited facts but must not acquire that authority.

## Deferred, not promised

Linktop is not on a path toward ambient packet capture, automatic LAN scanning,
wireless attack controls, a Kismet-style daemon, a controller replacement,
global unknown-device tracking, or a household identity graph. eBPF/BPF,
native packet parsing, additional RF sources, and new active operations may
become explicit evidence providers elsewhere, but none is a hidden prerequisite
for making the top view excellent.
