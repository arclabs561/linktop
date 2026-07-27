# linktop

`linktop` is a terminal instrument for the host's current network context. It
opens in a passive mode that reads the default route, interface, radio,
counters, resolver configuration, and native neighbor cache without generating
network traffic. The overview leads with the current context, evidence coverage,
relevant change, and the next useful operator action.

End-to-end reachability is deliberately `UNTESTED` in passive mode. `linktop
probe`, `linktop --active`, or the TUI `a` key explicitly enables bounded
next-hop, DNS, HTTPS, and public-egress probes when an operator needs path
localization.

![Status: experimental](https://img.shields.io/badge/status-experimental-6b7280)

## Passive observations

- The selected default route, interface, link type, next-hop gateway, resolver
  set, local addresses, and SSID when the platform exposes it. On macOS, when
  a tunnel such as `utun` owns the effective default route, Linktop separately
  reports the corroborated physical underlay (for example, `utun4 [vpn] over
  en0 [wifi]`) and keeps radio, DHCP, counter, and neighbor-cache evidence
  attached to that underlay.
- On macOS, the current Wi-Fi association ID, associated BSSID when Location
  Services policy exposes it, DHCP method/state/server, subnet, lease window,
  security mode, and router-ARP verification from
  `ipconfig getsummary`. The association ID joins the path fingerprint so a
  switch can still create a new generation when macOS hides the SSID; lease
  renewal alone does not.
- Wi-Fi signal/noise, channel, PHY, and link rate when native tools expose
  those fields. Missing platform capabilities show as unavailable; they do not
  abort the rest of the diagnosis.
- Physical-link byte/packet rates plus error and drop deltas from native kernel
  counters when an underlay is established; otherwise rates follow the
  effective interface. Rates are interval deltas; the structured snapshot also
  retains cumulative counters.
- On macOS, the busiest local process groups by numeric receive/transmit bytes
  over a one-second `nettop` external-interface window, sampled no more often
  than every five seconds. This is host-kernel process accounting, not
  endpoint, protocol, peer, person, or intent attribution; a VPN extension may
  own tunneled bytes for another application.
- Numeric ARP/NDP neighbor-cache entries for the physical underlay and its
  current subnets when established, otherwise for the effective interface.
  This reads what the operating system already knows and excludes rows outside
  the new path's interface or prefixes after a switch; same-prefix rows that
  the kernel retains remain explicitly cache evidence, not proof of current
  presence. Linktop does not scan the LAN, resolve names, or claim that
  cached endpoints are alive. If only some native cache sources complete,
  Linktop marks passive coverage `PARTIAL` instead of implying that the view is
  complete. When a
  single snapshot contains contradictory bindings for the same interface and
  address, Linktop shows `source disagreement`; it does not invent a temporal
  binding change. When a local Nmap or Wireshark manufacturer registry is
  installed, universally administered MAC prefixes gain a source-labelled
  registrant hint. Local or
  randomized MACs are labelled `local/private`; neither label is device
  identity. Kernel states are translated conservatively: for example,
  `REACHABLE` means recently confirmed by the kernel, while `STALE` means the
  cache remains but confirmation has expired.
- A path-generation-scoped neighbor attention order: source disagreement,
  next-hop role, observed binding change, address-resolution trouble, cache
  return, state change, kernel-confirmed evidence, then stable cache rows. The
  focused view reports traffic and application activity as unknown because a
  native neighbor cache has no flow vantage.
- Path transitions. A change in effective interface or link type, physical
  underlay interface/link/gateway, SSID, macOS Wi-Fi association ID, effective
  gateway, resolver set, IPv4 address, or IPv6 /64 prefix starts a new
  observation generation.
  Linktop clears path-scoped histories and ignores late results from the old
  Wi-Fi, hotspot, Ethernet, or VPN path. A momentary loss of the default route
  during association is shown as `switching networks` for up to three seconds
  before Linktop accepts a sustained disconnect as a new generation.

Passive coverage means that the expected host-local route, resolver, address,
counter, radio-when-applicable, and neighbor-cache sources completed under the
passive policy. A missing source makes coverage `PARTIAL`; it does not disappear
behind the sources that succeeded. Coverage is separate from path status and
never means that Internet reachability was tested.

## Active diagnosis

Active probes are opt-in:

- One next-hop ICMP echo is sent per `--interval`.
- DNS resolution and an HTTPS GET target `example.com` on enable, path change,
  manual refresh, and every 60 seconds during a long-lived active overview.
  Results older than 75 seconds stop supporting a current verdict.
- Public egress is observed on enable, path change, or manual refresh through a
  bounded HTTPS address lookup with provider fallback. It is supporting
  identity evidence, not a reachability dependency.
- Each command or HTTP request has a deadline. Disabling active probes clears
  their current state and ignores results still in flight.

Path status follows dependency order: next hop, DNS, then HTTPS. Public-egress
lookup, radio telemetry, and neighbor-cache completeness affect evidence
coverage but cannot falsely make the tested path fail. Rolling next-hop RTT
shows p50, p95, packet loss, sample count, and mean absolute adjacent RTT
difference (`mean |ΔRTT|`). Distribution-based degradation waits for five
probes and uses the most recent twenty; the graph may retain ninety.
No ICMP echo reply is reported as unavailable next-hop evidence because a
gateway may filter echo; successful DNS and HTTPS checks can still establish
that the downstream path responded.

The default command opens the passive dashboard when both stdin and stdout are
terminals. With redirected input or output, it prints one passive snapshot
instead of opening a keyboard-driven alternate screen. `--active` is never
inferred from the terminal or selected view.
`linktop link` and `linktop peers` also open live focused views on a terminal;
the peers view is scrollable and rereads only the native cache. Redirecting
either command with no lifetime option remains a one-shot snapshot. Use
`--plain` to explicitly choose a timestamped, append-only human stream,
`--jsonl` to choose the versioned live machine stream, and `--dwell SECONDS`
to request and bound any live
overview, link, or peers observation. Plain mode is useful for logs, `tee`,
remote shells, and support handoffs; it never emits cursor-control sequences.
Plain and JSONL are mutually exclusive and neither changes passive or active
acquisition policy.
Combining `--plain` with `--dwell` closes the stream with a collector-scoped
summary of the current path generation and up to eight completed generations
observed by that process. Evidence a focused command did not collect is
labelled `not collected`; the summary is not persisted. A bounded JSONL dwell
ends with one `final_summary`; an operator-selected unbounded JSONL stream has
no fabricated terminal record, built-in persistence, or network publication.

Live usefulness follows each claim's evidence horizon, not process uptime.
Path context, cumulative counters, and each completed probe are exposed as
soon as observed. Interface rate requires two compatible counter reads.
Next-hop distribution uses the latest twenty attempts, remains insufficient
before five attempts, and requires at least two successful RTT observations
for adjacent variation. Human and machine views report the same support,
scope, source age or span when known, and typed limitations.

Finite text and the TUI are expert human interfaces, not machine APIs.
`--json` emits one versioned JSON document for agents and programs:
`linktop.observation.v1` for snapshot, probe, link, and peers, and
`linktop.speed_experiment.v1` for the explicit load experiment. Observation
documents carry the producer version, subject, wall-clock acquisition start,
monotonic elapsed duration, completion time, acquisition policy/lifetime, typed
path assessment, evidence coverage, and complete subject evidence.
Link JSON includes interface counters when available; peer JSON includes path
context, the collector's actual path-filter result, and an explicit
default-gateway role. Its optional `path_context.link_evidence` records typed
network-name and BSSID visibility, association, host addresses and derived
default-path prefixes, and effective resolvers when the one-shot link
observation supplied them. Use these contracts instead of parsing prose or
terminal columns.

`--jsonl` emits `linktop.live_observation.v1` from that same typed model.
Self-contained records identify an initial or periodic checkpoint, a
path-generation transition, or the bounded final summary and carry sequence,
acquisition lifetime, generation, assessment, claim progress, and evidence.
Material state changes emit immediately; full checkpoints recur at a bounded
cadence while accepted updates continue, and high-frequency non-material
updates between them are suppressed. `--json` remains finite and unchanged.

```sh
linktop
linktop --plain
linktop --plain --interval 5 | tee linktop.log
linktop --jsonl --dwell 30
linktop --dwell 30
linktop --history ~/.local/state/linktop/host-path.jsonl
linktop --plain --dwell 30 --history ~/.local/state/linktop/host-path.jsonl
linktop --active
linktop --active --plain --dwell 30
linktop --active --jsonl
linktop snapshot
linktop snapshot --json
linktop probe
linktop probe --json
linktop link
linktop link --json
linktop peers
linktop peers --dwell 30
linktop peers --plain --dwell 30 | tee peers.log
linktop peers --jsonl --dwell 30
linktop peers --json
linktop review capture-records.jsonl
linktop review capture-records.jsonl --tail-seconds 30
linktop review capture-records.jsonl --json
linktop speed 192.168.1.10
```

## Saved evidence review

`linktop review INPUT` is a finite, read-only projection over a canonical
Netbraid normalized saved-capture JSONL stream. The input is the manifest,
optional occurrence receipt, packet envelopes, and quarantines produced by
Netbraid's versioned `--jsonl` or deterministic `--records-jsonl` contract. It
is not a raw PCAP or PCAPNG file.

The default human report preserves artifact and normalized-record digests,
artifact size, observer and acquisition time (or explicit unknowns), acquisition
policy, extractor adapter/tool/configuration/registry provenance, occurrence run
and source-file timing when a receipt is present, complete-capture or
partial-subset scope, normalization and quarantine counts, WLAN disconnect
status, cumulative top conversation, directional frame/octet and TCP-flag
evidence, typed exclusions, observation point and event window, and exact
candidate TShark display filters. Endpoints and filters remain capture evidence
and drill-down pivots; they are not device, person, service, application, or
intent identity.

`--tail-seconds SECONDS` adds a capture-relative trailing packet-time interval
using exact decimal seconds down to one nanosecond. The report distinguishes
the requested interval, source-artifact extent from the occurrence receipt,
normalized extent, selected packet extent, positive observations, and whether
the evidence qualifies or abstains from negative claims. Its top conversation
is cumulative only within that requested interval, not a flow, session, or
episode; its exact candidate TShark pivot includes the packet-time bounds.

`--json` emits Netbraid's exact typed `netmon.saved_pcap_triage.v1` projection
without a Linktop wrapper. Linktop reads and validates the records through its
pinned `netbraid-replay` Rust library dependency. Review never invokes the
Netbraid CLI, TShark, Capinfos, a live collector, or a network request, and it
does not append to or otherwise modify the input. Input is bounded to 128 MiB
by default; `--max-input-mib` changes that explicit read limit.

## Optional prior-context evidence

Linktop does not persist observations by default. `--history PATH` is an
explicit private-retention choice for the live overview. It reads a Netbraid
`HostPathObservationV0` JSONL log, compares the completed current context with
prior records from this observer ID, cites anchored recurrence, an unanchored
exact key match, compatible/incomplete evidence, or conflicting context, and
appends the new record. A cached gateway link-layer binding is the v0 recurrence
anchor. Equal sparse fields and a repeated BSSID do not manufacture context
identity. Attachment evidence separately distinguishes known, newly observed,
and unavailable associated BSSIDs. Compatibility is not clustered transitively,
and an exact serialized key variant is not presented as a count of physical
networks. The observer ID is currently the reported hostname, so it scopes
comparison but is not a durable hardware identity. The `LINKTOP_HISTORY`
environment variable may supply the same opt-in path for a regular operator
setup.

History records can contain SSIDs, BSSIDs, interface addresses and prefixes,
gateway IP and cached link-layer address, resolver sets, and association
metadata. Linktop creates a new history directory with mode `0700` and sets the
log to `0600` on Unix. A malformed or incompatible log is left unchanged and
reported as an evidence limitation; current live diagnosis continues. If only
the final unterminated JSON fragment is malformed, Linktop can compare against
the valid prefix but keeps the log read-only and reports the interrupted tail.
Internal or newline-terminated corruption remains unavailable rather than being
silently skipped.

The experimental Netbraid v0 history record has no separate underlay object.
Under a VPN, Linktop preserves the effective interface/link fields and
separately representable Wi-Fi association evidence; it does not relabel the
physical gateway as the effective next hop.

A recurring network context is not automatically a physical location. The same
SSID and private gateway address can occur at unrelated sites, one site can
contain many BSSIDs, and a hotspot can move. Associated BSSID, the passively
cached gateway binding, network boundary, recurrence, controller site evidence,
and a private operator assertion can support a place candidate. Linktop reports
the available evidence and explicitly says when no place is asserted. It does
not perform an ambient Wi-Fi scan or attach a human location label on its own.
A gateway link binding is reported as a context anchor, not a place candidate
by itself; the ordinary history projection says `place unknown` until an
operator or authoritative controller supplies that assertion.

`linktop probe` is the automation-oriented active contract: it exits `1` when
the tested path fails and `2` when no path verdict is available. Live TUI and
plain modes, including `--active --plain --dwell`, report observations and use
their exit status only for process/runtime failure.

`speed` is deliberately explicit: it requires an `iperf3` server chosen by the
operator, runs a fixed-duration TCP test, and compares gateway latency before
and during load. It never selects or contacts a bandwidth-test service on its
own.

The ordinary operator views show the identifiers the host actually exposes,
including SSIDs, addresses, MACs, and registrant hints; Linktop does not redact
them. On recent macOS releases, the operating system's platform tools may
return the literal `<redacted>` for SSID/BSSID unless the calling application
has Location Services authorization. Linktop tries both its fast configuration
source and slower Wi-Fi inventory, then reports `SSID hidden by macOS` if
neither exposes the value; Linktop itself does not censor it. Association ID,
DHCP lease, gateway, resolver, address, radio, process-accounting, and peer
evidence remain available.

## Install

Rust 1.88 or newer is required.

```sh
just install
```

This runs the canonical checks, installs `linktop` into Cargo's bin directory,
and creates `pinglet` and `pingl` command-discovery symlinks beside it. The
aliases preserve the old names, not pinglet's old active-by-default behavior;
use `linktop probe` for the explicit replacement diagnosis. Cargo's bin
directory is already on the PATH in the author's dotfiles; on another machine,
add `${CARGO_HOME:-$HOME/.cargo}/bin` to `PATH`.

For development on this machine, run `just install-dev` once. It points the PATH
entry at this checkout's debug binary, so every later `just check`, Cargo build,
or visual capture immediately becomes the `linktop` launched from the shell. Run
`just install` again when a standalone release binary is preferred.

For development without installing:

```sh
cargo run
just check
```

The built-in visual QA transaction has two fidelity lanes. Its default lane
runs the same live monitor and Ratatui renderer headlessly at a fixed terminal
size. Explicit elapsed times produce one or several private text frames and
styled SVG screenshots without requiring tmux, ImageMagick, a TTY, or manual
operator screenshots:

```sh
linktop screenshot overview --at 2,5,12 --columns 160 --rows 26
linktop screenshot overview --active --at 2,5,12 --columns 160 --rows 26
linktop screenshot peers --at 5,15 --columns 100 --rows 24
linktop screenshot link --at 12 --columns 100 --rows 24
linktop screenshot overview --scene dense-peers --at 1,3,5 \
  --key 1:3 --resize 3:80x20 --key 3:page-down --key 5:home
linktop screenshot overview --scene wifi-hotspot-wifi --at 1,3,5 \
  --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24
```

Repeatable `--key AT:KEY` and `--resize AT:COLSxROWS` actions reproduce
operator interactions and terminal breakpoints without manual timing. At one
timestamp Linktop drains available observations, resizes, applies keys in
command-line order, and then renders the requested frame. Supported replay keys
are `r`, `p`, `a`, `1`, `2`, `3`, `tab`, `j`, `k`, `up`, `down`, `page-up`,
`page-down`, `g`, `G`, `home`, and `end`; terminating keys are rejected because
the final `--at` remains the transaction boundary.
Captures may exercise the explicit 40×8 unsupported-size fallback. Evidence
layouts begin at 60×10 and ask the operator to resize below that floor.

`--scene dense-peers` supplies a passive, synthetic ARP/NDP cache history with
27 current documentation-range neighbors, overflow, IPv4 and IPv6 rows,
gateway and no-MAC cases, source disagreement, NUD states, a changed binding,
cache disappearance, and return. The scene enters the same `MonitorUpdate`
reducer as live observations, so it exercises attention ranking and
generation-scoped dwell instead of bypassing the application model. It is
available for overview and peers screenshots and cannot be combined with
active probes or history.

`--scene wifi-hotspot-wifi` uses Netbraid's receipt-bound
`PUBLIC_SYNTHETIC` host-path inputs. It applies an initial Wi-Fi path at 0s, a
hotspot attachment at 2s, and the known Wi-Fi return at 4s, so captures at
1s/3s/5s show each stable stage. The source records retain their own evidence
times; only their application to the QA view is accelerated. Netbraid validates
the closed checkpoint receipt, including its fixture oracles, before releasing
typed inputs; Linktop does not inspect, branch on, or render those authored
conclusions or viewport assertions. Only reversible host-path fields enter the
Linktop model; network prefixes do not become host addresses, and absent radio,
peer-cache, place, owner, or 802.11-roam evidence stays absent. The scene
exercises real path generations, bounded dwell, and the production history
reducer without reading or writing an operator history file. Its timeline and
per-frame stage are recorded in the QA manifest. Timed scenes reject replayed
pause because their accelerated QA clock is intentionally not operator-paused.

Use `--native` to exercise the actual Crossterm alternate-screen application in
a fixed-size tmux PTY. It captures one ANSI terminal frame, derives visible text
from those same bytes, and saves a self-contained HTML reconstruction with the
terminal colors intact:

```sh
linktop screenshot overview --native --at 2,5,12 --columns 100 --rows 24
linktop screenshot peers --native --at 5,15 --columns 80 --rows 20
linktop screenshot overview --native --scene dense-peers --at 1,3 \
  --key 1:3 --resize 3:80x20
linktop screenshot overview --native --scene wifi-hotspot-wifi --at 1,3,5 \
  --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24
```

Native capture requires tmux; it does not require ImageMagick or a foreground
terminal window. It deliberately clears `NO_COLOR` only in the captured child
process so the artifact tests Linktop's own color contract even when the
calling shell disables color. Linktop waits for the child view to become ready,
settles after each replayed action, and verifies the tmux pane dimensions before
writing a frame. The child does not inherit `LINKTOP_HISTORY` or an ambient
fixture selector; an explicit history path remains the only history authority.
Scene environment values are ignored by ordinary TUI entry points and are
accepted only with the native runner's hidden internal-child process mode.
Interrupting the transaction also terminates its isolated tmux server and child.
Timed native scenes render their baseline before readiness, then begin from a
private parent/child start gate. At evidence-capable sizes Linktop waits for the
expected path marker and generation before each frame. The explicit sub-60×10
fallback cannot show a network label, so it exposes and verifies the generation
with the resize guidance instead. The gate is removed when the transaction
exits and is never a manifest artifact.

The command writes to `./linktop-captures/` by default. Repository development
can use `just capture-ui overview 160 26 2,5,12`, which keeps artifacts under
the ignored `.agents/reports/ui-captures/` directory; `just capture-native`
selects the PTY lane. Filenames include the subject, live or synthetic scene,
session, frame index, actual viewport, and scheduled and actual elapsed
milliseconds so frames from different times, sizes, and runs do not overwrite
each other. After replayed view navigation, the filename names the view actually
rendered rather than the requested entry subject.

A successful transaction writes one pretty
`linktop.qa_capture_manifest.v1` JSON document last. It records the normalized
frame, key, and resize schedule, requested subject and initial policy, actual
rendered view, policy, and viewport per frame, a portable transaction ID, UTC
replay start and completion times, monotonic replay duration, the producing
executable's SHA-256, and the relative name, media type, byte length, and
SHA-256 of every artifact. Both lanes freeze the replay completion boundary
immediately after the last frame and before collector or PTY cleanup. Linktop
rejects pre-existing artifact or manifest paths and verifies completed
artifacts immediately before atomically publishing the manifest with an
exclusive same-directory hard link. An interrupted or partial transaction has
no completion manifest; consumers rehash artifacts to detect any later change.
This is a private layout-QA receipt, not network evidence or telemetry, and
contains no absolute paths or captured network facts. The last `--at` value is
the requested replay lifetime; `duration_ms` is the measured monotonic replay
window. The output filesystem must support same-directory hard links; Linktop
probes that capability before the dwell starts so atomic no-clobber publication
cannot fail only after all frames have been produced.

## Controls

- `q` or `Esc`: quit
- `r`: refresh the sources allowed by the current passive or active policy
- `p`: pause or resume observation
- `a`: enable or disable active path probes for the current overview session
- `1`/`2`/`3` or `Tab`: switch among overview, link, and peers inside an
  overview session
- `j`/`k` or arrow keys in `peers`: scroll one row
- `PgUp`/`PgDn`, `g`/`G`, or Home/End in `peers`: move through the cache

The direct `linktop link` and `linktop peers` entry points retain their narrower
passive collection plans. In-process switching is available from the overview
because that session already owns the superset of evidence; changing the
display does not silently widen a focused command's network activity.

## Boundary

Linktop observes the current host's network context and, when explicitly
enabled, diagnoses its active path. It can also render an explicitly supplied
normalized saved-capture record stream without acquiring or retaining it.
Linktop does not capture network packets, trigger wireless scans, perform LAN
discovery, manage network controllers, retain durable history unless an
operator supplies `--history` or `LINKTOP_HISTORY`, own credentials, publish
telemetry, or perform identity/presence fusion. Those are separate lifecycles
even when their evidence is useful beside a Linktop report. Linktop consumes
Netbraid's experimental, versioned, policy-neutral Rust evidence/replay crates
at an exact Git revision; it does not invoke the Netbraid CLI or require a
Netbraid service. Direct local observation and diagnosis remain independently
usable.

The longer product direction, including episode stories, purpose-specific
readiness, explicit diagnostic experiments, multi-vantage Netbraid evidence, and
advisory traffic fingerprints, is recorded in
[`docs/design/network-situation-intelligence.md`](docs/design/network-situation-intelligence.md).
Its dependency-ordered delivery gates and the decisions that must precede later
phases are recorded in
[`docs/design/operator-intelligence-roadmap.md`](docs/design/operator-intelligence-roadmap.md).

## License

Licensed under the MIT License.
