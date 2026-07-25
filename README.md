# IronTraffic

A traffic and API manager in Rust. One binary that is an L4 and L7 load balancer, a reverse proxy,
an API gateway, a Kubernetes and Gateway API ingress controller, and a clustered standalone server,
with a dashboard that can actually change things.

> **Status: pre-1.0, foundational development. Nothing here is production ready yet.**
> The plan is public in the issue tracker and the reasoning is in [ARCHITECTURE.md](ARCHITECTURE.md).
> This README will not carry a performance number until a script in this repository reproduces it.

## Why another one

The category has converged on a set of shared gaps. These are not opinions; each is verifiable
against a competitor's source, issue tracker, or documentation:

- **Nobody does zero-downtime for both configuration and binary.** Projects that fork a process per
  configuration change get binary upgrade for free and can never make configuration apply cheap.
  Single-process projects get cheap configuration apply and have no story for replacing the binary.
  IronTraffic does both: an atomic snapshot swap for configuration, and descriptor handoff to the
  successor process for the binary, with connections preserved across each.

- **Distributed rate limiting is usually wrong.** The reference implementation an entire ecosystem
  depends on is a fixed-window counter, which admits twice the configured burst across a window
  boundary. Another product replicates counters between nodes by plain assignment, which is
  last-writer-wins on a counter and therefore not a join-semilattice, making the limit systematically
  permissive in proportion to the node count. The correct version is frequently sold as an
  enterprise add-on.

- **Clustered certificate management is a paywall.** One project removed it from its open source line
  and now documents its commercial tier as the answer for multi-replica deployments. Another has had
  the request open for a decade.

- **Nobody publishes their memory cost.** The request to measure per-connection and per-request
  memory has been open in the largest project in this category since 2020. IronTraffic states its
  per-connection budget, gates it in CI, and publishes the curve.

- **The dashboard is the upsell.** Read-only, or enterprise-gated, or deprecated. IronTraffic's is
  authenticated, write-capable, audited, and able to roll back, in the open source project, forever.

The full analysis, with citations, is what the issue tracker is built from.

## Design in one screen

- **One binary, four modes.** `run` (everything, the default), `proxy` (data plane only), `control`
  (control plane only), `validate` (parse and diff a config, exit code is the answer).
- **One internal representation.** Files, the admin API, Kubernetes CRDs, Gateway API objects,
  Ingress resources, and service discovery all compile to one immutable snapshot. The Kubernetes
  controller is a configuration source, not a second implementation.
- **The request path allocates nothing and locks nothing.** Configuration is read from an immutable
  snapshot published with `arc_swap`. Counters are per-core. Both are CI-gated properties.
- **Routing is O(path length), not O(route count).** A compiled trie with build-time precedence, and
  all regexes in one multi-pattern automaton so catastrophic backtracking is not expressible.
- **The data plane never stops.** If the control plane, the cluster, or the Kubernetes API server is
  gone, every node keeps serving its last known good configuration indefinitely.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the reasoning and the crate graph.

## Promises

[COVENANTS.md](COVENANTS.md) is a set of falsifiable commitments: no paywalled security, no feature
deleted from open source and sold back, no mandatory first-party infrastructure, no unexportable
state, no telemetry, no relicensing. Each is written so that breaking it is unambiguous.

[docs/WILL-NOT-IMPLEMENT.md](docs/WILL-NOT-IMPLEMENT.md) says what we will not build and why, and
which of those answers could change with evidence.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). If you are an AI agent implementing an issue, read
[AGENTS.md](AGENTS.md) first; it is the standing contract.

Run `scripts/gate.sh` before opening a pull request.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
