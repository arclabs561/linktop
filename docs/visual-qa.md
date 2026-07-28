# Visual QA

`linktop screenshot` runs the production monitor reducer and Ratatui renderer at
fixed times and terminal sizes. It exists so layout, resize behavior, path
transitions, and peer overflow can be reviewed without manual screenshots.

## Headless frames

```sh
linktop screenshot overview --at 2,5,12 --columns 160 --rows 26
linktop screenshot peers --at 5,15 --columns 100 --rows 24
linktop screenshot overview --scene dense-peers --at 1,3,5 \
  --key 1:3 --resize 3:80x20 --key 3:page-down --key 5:home
linktop screenshot overview --scene wifi-hotspot-wifi --at 1,3,5,7 \
  --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24 \
  --resize 7:160x30
```

The headless lane writes text and styled SVG frames. Repeated `--key` and
`--resize` actions reproduce operator interactions and responsive breakpoints.
Evidence layouts begin at 60×10; smaller viewports show explicit resize
guidance.

`dense-peers` supplies a synthetic cache history with overflow, IPv4 and IPv6
rows, gateway and no-MAC cases, source disagreement, state changes, a changed
binding, disappearance, and return.

`wifi-hotspot-wifi` replays receipt-bound public-synthetic Netbraid host-path
evidence through normal generation fencing and history projection. The fixture
uses documentation identifiers and does not read operator history.

## Native terminal frames

```sh
linktop screenshot overview --native --at 2,5,12 --columns 100 --rows 24
linktop screenshot peers --native --at 5,15 --columns 80 --rows 20
linktop screenshot overview --native --scene wifi-hotspot-wifi --at 1,3,5,7 \
  --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24 \
  --resize 7:160x30
```

The native lane runs the real Crossterm alternate-screen application in an
isolated tmux server. It captures ANSI bytes, visible text, and a self-contained
HTML reconstruction. The runner verifies pane dimensions and expected path
generation before accepting evidence-capable frames.

## Completion contract

Frames never overwrite existing paths. A successful transaction writes one
`linktop.qa_capture_manifest.v1` document last. It records:

- the frame, key, and resize schedule;
- requested and rendered views, policy, and viewport;
- replay start, completion, and monotonic duration;
- the producing executable's SHA-256;
- each artifact's relative name, media type, size, and SHA-256.

An interrupted run has no completion manifest. Consumers should treat the
manifest as a QA receipt and rehash artifacts before review; it is not network
evidence or telemetry.
