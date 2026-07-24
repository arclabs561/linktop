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
  set, local addresses, and SSID when the platform exposes it.
- On macOS, the current Wi-Fi association ID, associated BSSID when Location
  Services policy exposes it, DHCP method/state/server, subnet, lease window,
  security mode, and router-ARP verification from
  `ipconfig getsummary`. The association ID joins the path fingerprint so a
  switch can still create a new generation when macOS hides the SSID; lease
  renewal alone does not.
- Wi-Fi signal/noise, channel, PHY, and link rate when native tools expose
  those fields. Missing platform capabilities show as unavailable; they do not
  abort the rest of the diagnosis.
- Active-interface byte/packet rates plus error and drop deltas from native
  kernel counters. Rates are interval deltas; the structured snapshot also
  retains cumulative counters.
- On macOS, the busiest local process groups by numeric receive/transmit bytes
  over a one-second `nettop` external-interface window, sampled no more often
  than every five seconds. This is host-kernel process accounting, not
  endpoint, protocol, peer, person, or intent attribution; a VPN extension may
  own tunneled bytes for another application.
- Numeric ARP/NDP neighbor-cache entries for the active interface and its current
  subnets. This reads what the operating system already knows and excludes
  rows outside the new path's interface or prefixes after a switch; same-prefix
  rows that the kernel retains remain explicitly cache evidence, not proof of
  current presence. Linktop does not scan the LAN, resolve names, or claim that
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
- Path transitions. A change in interface, link type, SSID, macOS Wi-Fi
  association ID, gateway, resolver set, IPv4 address, or IPv6 /64 prefix
  starts a new observation generation.
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
`--plain` to explicitly choose a timestamped, append-only stream, and
`--dwell SECONDS` to request and bound any live
overview, link, or peers observation. Plain mode is useful for logs, `tee`,
remote shells, and support handoffs; it never emits cursor-control sequences.

```sh
linktop
linktop --plain
linktop --plain --interval 5 | tee linktop.log
linktop --dwell 30
linktop --history ~/.local/state/linktop/host-path.jsonl
linktop --plain --dwell 30 --history ~/.local/state/linktop/host-path.jsonl
linktop --active
linktop --active --plain --dwell 30
linktop snapshot
linktop snapshot --json
linktop probe
linktop probe --json
linktop link
linktop link --json
linktop peers
linktop peers --dwell 30
linktop peers --plain --dwell 30 | tee peers.log
linktop peers --json
linktop speed 192.168.1.10
```

## Optional prior-context evidence

Linktop does not retain observations by default. `--history PATH` is an
explicit private-retention choice for the live overview. It reads a Netmon
`HostPathObservationV0` JSONL log, compares the completed current context with
prior records from this host, cites exact recurrence, compatible/incomplete
evidence, or conflicting context, and appends the new record. Exact recurrence
also distinguishes known, newly observed, and unavailable associated-BSSID
attachment evidence. Compatibility is not clustered transitively, and an exact
serialized key variant is not presented as a count of physical networks. The
`LINKTOP_HISTORY` environment variable may supply the same opt-in path for a
regular operator setup.

History records can contain SSIDs, BSSIDs, interface addresses and prefixes,
gateway IP and cached link-layer address, resolver sets, and association
metadata. Linktop creates a new history directory with mode `0700` and sets the
log to `0600` on Unix. A malformed or incompatible log is left unchanged and
reported as an evidence limitation; current live diagnosis continues.

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
```

Use `--native` to exercise the actual Crossterm alternate-screen application in
a fixed-size tmux PTY. It saves the visible text, the ANSI terminal frame, and a
self-contained HTML reconstruction with the terminal colors intact:

```sh
linktop screenshot overview --native --at 2,5,12 --columns 100 --rows 24
linktop screenshot peers --native --at 5,15 --columns 80 --rows 20
```

Native capture requires tmux; it does not require ImageMagick or a foreground
terminal window. It deliberately clears `NO_COLOR` only in the captured child
process so the artifact tests Linktop's own color contract even when the
calling shell disables color.

The command writes to `./linktop-captures/` by default. Repository development
can use `just capture-ui overview 160 26 2,5,12`, which keeps artifacts under
the ignored `.agents/reports/ui-captures/` directory; `just capture-native`
selects the PTY lane. Filenames include the subject, session, fixed size, and
actual elapsed milliseconds so frames from different times and runs do not
overwrite each other. The last `--at` value is the transaction lifetime.

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
enabled, diagnoses its active path. It does not capture network packets, trigger
wireless scans, perform LAN discovery, manage network controllers, retain
durable history unless an operator supplies `--history` or
`LINKTOP_HISTORY`, own credentials, publish telemetry, or perform
identity/presence fusion. Those are separate lifecycles even when their evidence
is useful beside a Linktop report. Linktop consumes Netmon's experimental,
versioned, policy-neutral Rust evidence/replay crates at an exact Git revision;
it does not invoke the Netmon CLI or require a Netmon service. Direct local
observation and diagnosis remain independently usable.

The longer product direction, including episode stories, purpose-specific
readiness, explicit diagnostic experiments, multi-vantage netmon evidence, and
advisory traffic fingerprints, is recorded in
[`docs/design/network-situation-intelligence.md`](docs/design/network-situation-intelligence.md).

## License

Licensed under the MIT License.
