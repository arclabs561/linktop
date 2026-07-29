# Architecture

Linktop separates acquisition, evidence, projection, and presentation so that
terminal layout cannot silently change what the program claims.

## Data flow

1. Platform collectors read the current route, interfaces, addresses, resolvers,
   counters, radio state, process accounting, and native neighbor caches.
2. Active collectors run only under an explicit active policy.
3. The monitor reducer fences every update by path generation and maintains
   bounded current-generation histories.
4. The model records observations and assessments with support, provenance,
   scope, freshness, and limitations.
5. Human, JSON, JSONL, history, review, and screenshot surfaces project that
   model for different consumers and lifetimes.

An unavailable collector produces unavailable or partial evidence. It does not
abort unrelated diagnostics.

## Effective path and underlay

The effective default route is the route applications use. The physical
underlay supplies link-local evidence. They are usually the same interface, but
a VPN can make them different:

```text
effective: utun4 [vpn] -> tunnel next hop
underlay:  en0 [wifi] -> local gateway
```

Radio, DHCP, physical counters, and neighbor-cache observations attach to the
corroborated underlay. Linktop does not relabel the physical gateway as the
effective next hop.

## Path-generation fencing

A fingerprint over effective and underlay route state, association, addresses,
gateway, and resolvers identifies the current generation. A collector receives
the generation at launch and its result is accepted only if that generation is
still current.

A short loss of the default route during reassociation is represented as a
transition grace state. A sustained disconnect becomes a new generation. This
keeps transient handoff behavior visible without mixing evidence across paths.

## Output contracts

| Surface | Consumer | Lifetime | Contract |
| --- | --- | --- | --- |
| TUI | operator | live, explicit quit or dwell | adaptive human projection |
| finite text | operator or shell | one observation | stable expert prose |
| `--plain` | operator, log, remote shell | live, optional dwell | timestamped append-only records |
| `--json` | program or agent | one observation or experiment | one versioned document |
| `--jsonl` | program or agent | live, optional dwell | self-contained checkpoints, transitions, and bounded final summary |
| `--history` | later recurrence review | explicit live overview | private Netbraid host-path records |
| `review` | operator or program | finite saved evidence | read-only Netbraid triage projection |
| `screenshot` | layout QA | bounded replay | frames plus completion manifest |

Screen text is not a machine API. JSON schema discriminators and producer
versions are the compatibility boundary.

## Dependency boundary

Linktop depends on the published `netbraid` package with default features
disabled and the `scenario-fixtures` feature enabled. It imports typed evidence,
replay, and policy-neutral fusion semantics only. Linktop may compose those
results with the current host context for an operator view, while preserving
source, freshness, coverage, and disagreement. It does not own canonical
cross-source fusion, collection, deployment, credentials, retention, private
identity, or writer authority.

See [DECISIONS.md](../DECISIONS.md) for the constraints behind this structure.
