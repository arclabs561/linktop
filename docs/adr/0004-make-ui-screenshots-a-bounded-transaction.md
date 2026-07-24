---
id: 0004
status: accepted
governs: src/capture.rs, src/main.rs, src/ui.rs, Cargo.toml, Cargo.lock, README.md, justfile
why: manual screenshots and a heuristic external helper cannot prove how the real live views look after specific observation times, across several sizes, without making the operator the QA bottleneck.
rejected: keep the external tmux and ImageMagick example as the only path (one early monochrome frame and no timing contract); add screenshot flags to every live command (widens the already complex output/lifetime matrix); retain frames or network observations after the command exits (crosses the no-history boundary).
supersedes: none
superseded_by: none
extends: 0002
confidence: high
review_trigger: revisit if terminal-emulator pixel rasterization is required, a structured live event contract exists, user input must be replayed, or screenshots need durable publication or retention.
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
