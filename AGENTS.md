# AGENTS.md

Read this file completely before writing any code in this repository. Your issue is the specific
contract; this is everything that is true for every issue.

## What this repository is

IronTraffic is a traffic and API manager written in Rust: an L4 and L7 load balancer, an API
gateway, a Kubernetes and k3s ingress controller, and a standalone clusterable server, with a
dashboard. It sits in the request path of production traffic. That single fact determines every rule
below.

**A proxy is an adversarial-input system.** Every byte you parse was written by an attacker. Every
allocation you make on the request path is multiplied by a million. Every lock you take is contended
by every core. Every panic is an outage. Code that would be perfectly fine in an application is a
vulnerability here.

## The ten rules

1. **Do exactly what the issue says. Nothing more.** If the issue's `## Files` table lists four
   files, your diff touches four files. CI enforces this by comparing your diff against that table.
   If you believe the issue is wrong, say so in a comment on the issue and stop. Do not fix it
   yourself.
2. **Never leave a stub.** No `todo!()`, no `unimplemented!()`, no function returning
   `Default::default()` so it compiles, no test that asserts nothing. CI rejects all of these. If you
   cannot finish, say so; a partial PR that is honest is fine, a partial PR disguised as a complete
   one is not.
3. **Never `unwrap()` or `expect()` outside tests.** Return an error. If a case is genuinely
   impossible, restructure the types so it cannot be expressed, or prove it in a comment and use the
   escape hatch. Unit tests may unwrap freely; `clippy.toml` allows it there.
4. **Never panic on the request path.** A malformed request is a 4xx. An upstream failure is a 5xx.
   A resource limit is a 429 or 503. Nothing kills the process.
5. **Never allocate on the request path unless the issue says to.** Borrow instead of cloning, use
   `bytes::Bytes` so slicing is a refcount bump, write into a reused buffer instead of formatting a
   new `String`. Modules marked `//! HOT PATH` are lint-enforced.
6. **Never take a lock on the request path.** Configuration is an immutable snapshot published with
   `arc_swap`; counters are per-core; caches are sharded. If you think you need a `Mutex` in a
   request handler, you have misread the design.
7. **Never add a dependency the issue did not authorize.** The dependency tree is a security
   boundary and is reviewed. `cargo deny` rejects unvetted licenses, advisories, and sources anyway.
8. **Never read the clock or generate randomness directly.** All time flows through
   `irontraffic-time` and all entropy through `irontraffic-rand`, so tests are deterministic and a
   failure can be reproduced. The lint greps for the direct forms and fails the build.
9. **Never swallow an error.** No bare `let _ = fallible()`. Handle it, propagate it with `?`, or log
   it with context, and if discarding is genuinely correct say why on the same line.
10. **No em dashes and no en dashes anywhere.** Code, comments, docs, commit messages, PR bodies.
    Plain hyphens only. `scripts/dash-scan.sh` enforces it.

## The escape hatch

A few rules have legitimate exceptions. The escape is always the same shape, on the same line:

```rust
// it-allow: <rule-name> reason: <why this specific line is correct>
```

A marker **without** a written reason suppresses nothing. That is deliberate and it is self-tested:
the escape can never become a silent off switch, and using it always shows up in the diff as prose a
reviewer must accept.

## Before you open a PR

```
scripts/gate.sh
```

It runs everything CI runs that can run locally, in the same order. If it is not green the PR is not
ready. Do not open it hoping CI is more forgiving; it is the same checks.

## What CI checks and why each check exists

| Check | Catches |
| --- | --- |
| `cargo fmt --all --check` | formatting drift |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` at `pedantic` | the whole class of "compiles but is wrong" |
| `cargo test --workspace --all-features` plus doctests | behavior |
| `cargo check --no-default-features` | a control-plane dependency leaking into the edge build |
| msrv (1.85) | using a language feature newer than the floor |
| musl static build | a C dependency breaking the single static binary promise |
| `cargo deny check` | licenses, advisories, duplicate and unvetted sources |
| `cargo fuzz` smoke | parser panics on malformed input; fails closed if a parser crate has no target |
| invariant lints | the structural rules clippy cannot express |
| invariant lint self-test | a lint that silently stopped enforcing anything |
| dash scan | the prose rule |
| PR scope check | a diff touching files the issue did not declare |
| governance files | trust infrastructure being quietly deleted |

## Rust specifics that bite in this codebase

- `async fn` bodies must never block. No `std::fs`, no `std::thread::sleep`, no synchronous DNS, no
  CPU-heavy loop without a yield. Use the async equivalent or `spawn_blocking`, and say which in a
  comment.
- **Never hold a lock guard across an `.await`.** Clippy catches the common form. The subtle form is
  a guard held by a temporary in a `while let` scrutinee, which lives to the end of the loop body and
  silently serializes what looks like a fan-out. Bind the guard in an inner scope so it drops first.
- Prefer `&str` and `&[u8]` over `String` and `Vec<u8>` in request-path arguments. Prefer
  `bytes::Bytes` for anything sliced or shared.
- **Slice retention amplification.** A `Bytes` slice keeps its entire backing allocation alive. A
  20-byte header value sliced out of a 32 KiB read buffer pins all 32 KiB; at 100,000 connections
  that is gigabytes instead of megabytes. Compact parsed headers into an exactly-sized buffer and
  return the read chunk to the pool.
- Integer arithmetic on values from the network must be checked. A length field is
  attacker-controlled: `checked_add`, `try_from`, or an explicit bound check, never a bare cast.
- Comparisons of secrets (API keys, HMAC signatures, tokens) must be constant time. Never `==`.
- **Never use an unbounded channel between the halves of a proxied connection.** It compiles, it
  makes the borrow checker happy, and it is the OOM. Backpressure is structural: read one buffer,
  write it to completion, then read again.
- Any new `pub` item needs a doc comment. `unsafe` is denied workspace-wide with no exception you are
  authorized to make.

## How to ask

If the issue is ambiguous, contradictory, or appears to be wrong, comment on the issue with the
specific ambiguity and what you need to proceed. Do not guess. A guess that compiles is the most
expensive kind of mistake in this repository, because it looks like progress.
