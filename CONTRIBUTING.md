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

## One bench file and one allocation-gate file per surface (mandatory)

Never append to another issue's bench file or allocation-gate file. A new surface gets its own
`crates/<crate>/benches/<crate-prefix>_<surface>.rs` with its own `criterion_group!` and
`criterion_main!` plus its own `[[bench]]` entry in that crate's `Cargo.toml`, and its own
`crates/<crate>/tests/alloc_gate_<surface>.rs`. Criterion supports many bench targets per crate, so
this costs nothing.

This is not a style preference. `crates/irontraffic-http/benches/http_hot.rs` and
`crates/irontraffic-http/tests/alloc_gate.rs` were shared, append-only files that six separate
issues added to, and every rebase conflicted in them. The conflicts resolved in ways that COMPILE
while silently losing work, three distinct shapes of it, none of which git flagged: a dropped
`criterion_group!` registration (both sides register a different subset, so taking either side
compiles perfectly and simply stops measuring the other), an elided closing brace that cut two
functions off mid-body, and a dropped `use` line that surfaced as `cannot find type` rather than as
anything resembling a merge problem. Issue #630 split both files apart for that reason.

Splitting shrinks the conflict surface; it does not make a dropped registration detectable, so
`scripts/invariant-lints.sh`'s `bench-registration` rule does that. It guards two separate links,
because a merge can clobber either one: in every `benches/*.rs` the set of `fn bench_*` defined must
equal the set registered across that file's `criterion_group!` invocations, in both directions; and
every `criterion_group!` defined in that file must in turn be named by that file's `criterion_main!`.
The second link matters because the first, alone, guards only what the compiler already catches (a
`criterion_group!` naming an undefined function fails to build); the realistic and unguarded shape is
a merge that clobbers the `criterion_main!` group list instead, which drops a whole group silently
while the file still compiles, still passes clippy, and still passes every test.

The rule guards exactly those two links and no more. It does NOT catch every way a benchmark can
be compiled and never measured, and two such files are live in this repository today, so do not
read the two links as a general guarantee:

- a `benches/*.rs` with no `[[bench]]` entry at all is autodiscovered with `harness = true` and
  measures nothing (`crates/irontraffic-resilience/benches/deadline.rs`);
- a target not named `bench_*` is invisible to the rule in both directions, so dropping its
  registration is silent (`crates/irontraffic-filter/benches/chain.rs` defines `phase_mask_has`).

So when adding a bench file, two properties beyond the three above are load bearing and neither is
checked for you: the `[[bench]]` entry MUST carry `harness = false`, and the target functions MUST
be named `bench_*` or the registration rule cannot see them.

## Security

Never open a public issue for a suspected vulnerability. See [SECURITY.md](SECURITY.md).

## Licensing

Dual-licensed MIT or Apache-2.0. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion is dual-licensed as described in [LICENSE](LICENSE), without
any additional terms.
