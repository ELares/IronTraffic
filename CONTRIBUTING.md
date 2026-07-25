# Contributing to IronTraffic

IronTraffic is pre-1.0 and moving along a public plan in the issue tracker. The fastest way to help
is to pick an open issue in the current milestone and say so on the issue.

**If you are an AI agent implementing an issue, read [AGENTS.md](AGENTS.md) first.** It is the
standing contract and it is not optional.

## Ground rules

- **One issue per PR.** Reference it with `Closes #N` in the PR body. CI fails without it.
- **The issue's `## Files` table is the scope.** CI compares your diff against it. If the scope
  genuinely needs to grow, edit the issue and say why in the PR. Growing it silently is not allowed.
- **Green gate before review.** Run `scripts/gate.sh`. It runs the same checks CI does.
- **Every issue is independently mergeable.** The tree must build and all tests must pass after your
  PR merges alone. No `todo!()`, no dead module, no half-wired feature. Inert is allowed when the
  issue says so and names the issue that wires it in; broken is not.
- **Prose rule.** No em dashes and no en dashes anywhere in repository text, including commit
  messages. CI enforces this.
- **Determinism seam.** All time flows through `irontraffic-time`, all entropy through
  `irontraffic-rand`. The invariant lints fail your PR otherwise.
- **Changelogs.** User-visible changes update `CHANGELOG.md` under Unreleased in the same PR.
- **Sign off your commits** with `git commit -s`.

## The admin-API-first rule (mandatory)

Every administrative capability is a documented public API before any user interface exposes it. The
admin API is the single source of truth for administration; the dashboard, `irtctl`, and any future
Terraform provider or MCP server are thin clients of it. This is what prevents console-only features
and secret private endpoints.

A pull request that adds an admin capability must add or extend the endpoint with an accurate
OpenAPI annotation, inherit the cross-cutting discipline (cursor pagination on every list,
idempotency keys on every POST, an audit row in the same transaction as every mutation), and
regenerate the committed specification. A UI that needs a capability the API does not expose is a
signal to add the API first, not to reach past it.

## The threat-model rule (mandatory)

Every PR that ships a **new surface** (a network-facing listener or endpoint family, a new parser
over untrusted input, or a new privileged plane) must extend
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) with that surface's section **in the same PR**.
Reviewers block merges that add a surface without it. If you are unsure whether your change is a new
surface, ask on the issue before opening the PR.

## The benchmark honesty rule (mandatory)

Any performance claim added to the repository carries the hardware, the version, the date, and the
methodology, and is reproducible by a script committed here. Benchmarks are never run with safety
features disabled. See [COVENANTS.md](COVENANTS.md).

## Security

Never open a public issue for a suspected vulnerability. See [SECURITY.md](SECURITY.md).

## Licensing

Dual-licensed MIT or Apache-2.0. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion is dual-licensed as described in [LICENSE](LICENSE), without
any additional terms.
