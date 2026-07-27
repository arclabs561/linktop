---
id: 0004
status: accepted
governs: src/capture.rs, src/main.rs, src/ui.rs, Cargo.toml, Cargo.lock, README.md, justfile, docs/design/focused-view-lifetimes.md
why: manual screenshots and a heuristic external helper cannot prove how the real live views look after specific observation times, across several sizes, without making the operator the QA bottleneck.
rejected: keep the external tmux and ImageMagick example as the only path (one early monochrome frame and no timing contract); add screenshot flags to every live command (widens the already complex output/lifetime matrix); retain frames or network observations after the command exits (crosses the no-history boundary).
supersedes: none
superseded_by: none
extends: 0002
confidence: high
review_trigger: revisit if terminal-emulator pixel rasterization, subsecond or conditional replay, mouse input, state assertions, or durable screenshot publication or retention is required.
---

# ADR-0004: Make UI screenshots a bounded transaction

**Status**: Accepted
**Date**: 2026-07-23
**Deciders**: operator

## Context

Linktop's overview, link, and peers views change with terminal size and with
evidence that arrives after startup. Unit tests using Ratatui's `TestBackend`
prove selected content, but do not give a human a styled artifact to inspect.
The first repository helper launched the binary in tmux with a twelve-second
dwell, considered any frame containing `LINKTOP` settled, and saved one
monochrome reconstruction around four or nine seconds. It could not capture
several explicit times and its result was not the documented final frame.

Screenshot timing, live-command lifetime, and interactive presentation are
separate concerns. Adding more global flags to overview, link, and peers would
also advertise invalid combinations on snapshot and speed and further expand
the TTY/output policy matrix.

## Decision

Add a bounded `linktop screenshot` transaction with overview, link, and peers
subjects. One or more repeatable, comma-delimited `--at SECONDS` values define
the frame schedule; values are normalized into increasing unique times, and
the latest time defines when the transaction ends. `--columns` and `--rows`
define a fixed terminal viewport.

The default deterministic lane runs the real monitor, state reducer, and
`ui::render` function without entering an alternate screen or requiring a TTY.
At every requested time, render through Ratatui's `TestBackend` and write:

- a fixed-dimension plain-text cell buffer for geometry and diffs; and
- a styled SVG derived from the same completed frame, preserving cell
  foreground/background colors and text modifiers.

An optional `--native` lane launches the current Linktop executable inside a
fixed-size, isolated tmux PTY. It captures the visible alternate-screen pane at
the same explicit times and writes:

- a plain-text frame for quick reading and diffs;
- the ANSI frame, including terminal attributes and truecolor sequences; and
- a self-contained HTML reconstruction of that ANSI frame.

The native child clears an inherited `NO_COLOR` and declares truecolor support
without changing the parent process. This makes the QA artifact exercise
Linktop's own interactive color contract. The native lane has a tmux dependency
because its purpose is to verify the executable, PTY negotiation, alternate
screen, and actual terminal dimensions; the deterministic lane remains the
portable default.

Artifacts are timestamped by subject, session, viewport, and actual elapsed
milliseconds. The output directory and files use private permissions where the
platform supports them. The general default is `./linktop-captures/`; the
repository `just capture-ui` and `just capture-native` recipes choose the
ignored `.agents/reports/ui-captures/` directory.

This is UI screenshot capture, not network packet capture, evidence retention,
or telemetry publication. The transaction holds only process-local state and
ends after its last frame.

## Options considered

- **Keep the external PTY helper as the only path.** Rejected because it added
  tmux, ImageMagick, and font dependencies while discarding terminal styles and
  all but one heuristically selected frame. A bounded native lane remains useful
  beside the deterministic renderer because it verifies the real executable and
  terminal protocol.
- **Add `--capture-at` to every live command.** Rejected because screenshot
  generation is a bounded QA transaction, not another interactive output
  presentation. A dedicated command keeps pipes and TTY auto-selection
  unchanged.
- **Emit PNG directly.** Rejected for the first version because portable
  terminal-font rasterization would add a large rendering dependency. SVG is a
  styled image, remains inspectable and diffable, and can be rasterized by a
  browser or platform tool when needed.
- **Capture only fixture state.** Rejected because fixture renders cannot
  expose late platform commands, probes, path changes, or peer-cache evidence.

## Consequences

Agents and operators can capture several real late-session frames for every
live subject without manually operating the TUI. The deterministic SVG reflects
Ratatui cells, colors, and layout. The native ANSI and HTML artifacts additionally
verify the real alternate-screen path and PTY size, but remain terminal
reconstructions rather than pixel screenshots: neither lane proves a specific
terminal emulator's font rasterization, antialiasing, or window chrome. The
native lane also requires tmux. A later pixel-level or interaction-replay
requirement crosses the review trigger rather than silently changing this
bounded artifact contract.

## Lineage

Extends ADR-0002's explicit subject/presentation/lifetime matrix with a bounded
developer and operator QA transaction.

## Update (2026-07-26): Replay bounded keys, resizes, and a dense peer scene

The interaction-replay trigger fired after responsive-layout and peer-overflow
defects could only be reproduced by a human resizing and navigating the live
TUI. The screenshot transaction now accepts repeatable `--key AT:KEY` and
`--resize AT:COLSxROWS` actions. Times remain integer seconds from 1 through
86400 and no action may occur after the final frame. At each timestamp the
headless lane drains available monitor updates, applies at most one normalized
resize, applies keys in command-line occurrence order, and renders a scheduled
frame last. Identical same-time resizes collapse; conflicting same-time resizes,
unknown keys, and terminating `q` or `Esc` actions fail before capture.

Live Crossterm input and deterministic replay use one interaction reducer, so
navigation, scrolling, refresh, pause, and active-policy changes cannot drift
between production and QA paths. Peer navigation uses the currently visible
page capacity, including after a resize, so `End`, reverse scrolling, and page
movement cannot retain an off-screen offset. The native lane sends the same
bounded actions through tmux, waits for the initial Linktop alternate-screen
view, allows a short bounded render-settle window after actions, and verifies
the pane dimensions before naming and writing each artifact. An interrupt is
handled as a bounded shutdown that kills the isolated tmux server and child
rather than leaving a long scheduled dwell behind. The headless renderer remains
authoritative for deterministic content and ordering; native capture is the
fidelity check for PTY negotiation, Crossterm input, ANSI style, and terminal
resize behavior.

Add one named `dense-peers` scene for overview and peers screenshots. It uses
only documentation-range IPv4/IPv6 addresses and synthetic attribution, and it
enters the normal model through generation-tagged `Link` and `Peers`
`MonitorUpdate` events. Its baseline, transition, and final snapshots exercise
overflow, the path gateway, a missing MAC, source disagreement, NUD states,
binding change, cache disappearance, and cache return. Synthetic scenes remain
passive and cannot be combined with `--active`, history, or a replayed `a` key.
They replace the host monitor with an inert control loop, so live route, radio,
process, and neighbor collectors do not run or leak host evidence into the
scene.
For native capture, the parent selects the scene through a narrowly named
internal child environment value rather than adding a fixture option to normal
live commands. It clears inherited history and stale scene defaults before
starting the child; only the requested synthetic scene can contribute evidence.

This is intentionally not a general event language, macro recorder, or
assertion engine. Frame names now include the subject, scene, session, frame
index, verified viewport, scheduled time, and actual time so resize sequences
remain inspectable. Subsecond timing, conditional actions, mouse events,
state-based assertions, and durable artifact publication cross the updated
review trigger.

## Update (2026-07-26): enforce the no-retention boundary

Reject `--history` for every screenshot subject and remove history from the
capture request passed to both rendering lanes. The native child also clears an
inherited `LINKTOP_HISTORY`. A screenshot may render live host evidence or an
inert synthetic scene, but it cannot read, compare, or append durable recurrence
evidence. This makes the implementation match the original process-local QA
decision.

## Update (2026-07-26): publish a private completion manifest

The automated-consumer review trigger fired when agents began using multi-frame
captures to qualify view navigation and terminal-size behavior. File names alone
could not prove that every requested frame completed, identify the view actually
rendered after replayed navigation, or detect a partial or modified artifact set.

Each successful transaction now writes one pretty-printed
`linktop.qa_capture_manifest.v1` document after all requested frames and
artifacts have completed. The manifest records the Linktop producer, version,
and executable SHA-256, deterministic or native lane, requested subject, scene
and stage, initial passive or active policy, normalized frame/key/resize
schedules, and a portable transaction ID, UTC replay start/completion
timestamps, monotonic replay duration, and per-frame scheduled and actual
elapsed milliseconds, actual viewport, policy after replayed toggles, and
rendered view. Both lanes freeze the replay completion boundary immediately
after the last frame and before collector or PTY cleanup. Each artifact entry
contains a relative file name, media type, byte length, and SHA-256 digest.
Native visible text is derived from the same ANSI pane snapshot used by the
ANSI and HTML artifacts.

Before publication, Linktop verifies that the completed frame count and order
match the normalized request and rereads every artifact to verify its length and
digest. Artifact creation is no-clobber and rejects pre-existing files and
symlinks. It writes the manifest through a private temporary file and installs
the completed inode at the final name with an exclusive same-directory hard
link only after verification, so concurrent publication cannot replace an
existing path and a failed, interrupted, or incomplete capture has no
completion manifest. A consumer must rehash artifacts against the manifest to
detect changes after that verification point. Frame file names now use the
actual rendered view after replayed `1`, `2`, `3`, or `Tab` navigation rather
than the requested entry subject. The native lane checks the captured visible
header against both the rendered view and acquisition policy.

The caller-selected output filesystem must support same-directory hard links.
Linktop probes that capability in the private output directory before starting
the dwell, so an unsupported filesystem fails without producing frame artifacts.

The manifest is a private QA completion contract, not network evidence,
telemetry, or a durable observation record. It contains no absolute paths or
captured network facts; those remain inside the caller-selected private frame
artifacts. Its digest records the artifact bytes verified immediately before
publication and makes later changes detectable, but does not authorize
publication or retention. Wall-clock timestamps order receipts for human QA;
`duration_ms` and frame `actual_ms` remain the monotonic timing authority if the
host clock steps during a capture.

## Update (2026-07-27): make path-transition scenes timed and stage-verifiable

The operator-scenario gate now needs more than a synthetic final state.
`wifi-hotspot-wifi` consumes receipt-bound public-synthetic host-path inputs and
applies its initial Wi-Fi, hotspot, and returned Wi-Fi stages at an accelerated
0s/2s/4s QA timeline. These are generation-tagged model updates followed by
Linktop's production history reduction. Netbraid validates the complete closed
checkpoint receipt, including its fixture oracles, before returning typed
inputs; Linktop neither interprets those authored conclusions and viewport
assertions nor uses them as model updates. Missing host-address role, radio,
peer-cache completeness, place, owner, and roam evidence remains missing.

The deterministic replay plan inserts the two scene transitions before
same-time resize, key, and frame work. The native child renders the baseline
before readiness, then starts its monotonic scene clock only after the parent
creates a private no-clobber gate. Before accepting a native frame, the parent
waits for the expected network label and path generation. The gate is private,
transaction-scoped, removed by its guard, and excluded from the artifact
manifest. Child process startup time is therefore not part of scene semantics.

The replay receipt records the fixed scene timeline, and each frame records its
resolved stage. Timed scenes reject pause replay because the compressed QA
clock is not an operator-controlled live lifetime. They remain passive,
replace host collectors with an inert monitor, reject active probes and
durable history, and do not create a general event language or assertion
engine. Process-local synthetic comparison exercises rendering and reducers;
it does not read, append, or retain private operator evidence.

## Update (2026-07-27): verify timed scenes in the unsupported-size fallback

The explicit sub-60×10 fallback now renders the current path generation beside
its terminal dimensions and resize guidance. Native timed-scene readiness
checks the typed checkpoint's path marker plus generation in evidence-capable
layouts. In the unsupported-size fallback, where the network label is
deliberately absent, it checks the expected generation plus the visible fallback
identity instead. This preserves stage verification at 40×8 without claiming
that an invisible SSID was observed in the frame.
