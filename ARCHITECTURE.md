# IronTraffic architecture

This document is the map. It states what IronTraffic is, how it is split, why it is split that way,
and which decisions are settled. Every issue in the tracker assumes you have read it.

## What IronTraffic is

One Rust workspace that produces one server binary and one client binary. The server is
simultaneously an L4 and L7 load balancer, a reverse proxy, an API gateway and API manager, a
Kubernetes and Gateway API ingress controller, a clustered control plane, and a dashboard host.
Which of those it acts as is a runtime mode and a compile-time feature set, not a different product.

## Tenets, in tie-break order

When two goals conflict, the earlier one wins. This ordering is the answer to most design arguments.

1. **Correct.** A proxy is an adversarial-input system. Every byte was written by an attacker.
   Ambiguity is rejected, never normalized and forwarded. We would rather return a 400 than
   participate in a request smuggling chain.
2. **Available.** The data plane keeps serving. A control plane outage, a cluster partition, a
   Kubernetes API server failure, or a config store loss must never stop traffic; the last known
   good configuration keeps running, loudly and indefinitely.
3. **Fast.** Allocation-free and lock-free on the request path, with the worst case bounded rather
   than the average optimized. An algorithm whose worst case is an attacker's choice is a
   vulnerability, not a performance characteristic.
4. **Operable.** The answer to "why did this request do that" is a product feature, not a support
   ticket. Everything an operator can do in the dashboard is a documented public API first.
5. **Honest.** Published numbers are reproducible by a committed script. Covenants are falsifiable.
   Non-goals are written down. Nothing security-relevant is ever paywalled.

## Decision 1: one server binary with runtime modes

`irontraffic <mode>`:

| Mode | Contains | For |
| --- | --- | --- |
| `run` (default) | data plane, control plane, dashboard | standalone, k3s, single node, getting started |
| `proxy` | data plane only | the hardened, horizontally scaled tier |
| `control` | control plane, admin API, dashboard, Kubernetes controller | the scaled control tier |
| `validate` | nothing; parses and diffs a config, exit code is the answer | continuous integration |

Plus `irtctl`, a thin CLI that is a pure client of the admin API and carries none of the proxy.

**Why not separate proxy and control binaries.** Two binaries mean two release artifacts, two
version-skew matrices, and a mandatory multi-process deployment for the single-node case that is
most of the market. Traefik and Caddy both win on "one binary, one config file, it works", and that
is not an accident. The separation that matters is the internal one, and a crate boundary checked by
the compiler is stronger than a process boundary anyway.

**Why the modes still exist.** At scale the data plane should have no Kubernetes client, no
consensus library, no dashboard, and no admin write path in its address space. `proxy` mode plus
`--no-default-features` gives exactly that, and CI builds that configuration on every pull request
so it cannot rot.

## Decision 2: every configuration source compiles to one internal representation

This is the load-bearing idea. Config arrives from a file, the admin API, Kubernetes CRDs and
Gateway API objects, Ingress resources, service discovery, and the environment. All of them compile
into a single versioned, immutable `Snapshot`. Nothing downstream of the compiler knows where
configuration came from.

What falls out for free:

- The Kubernetes controller is a config **source**, not a parallel implementation. There is one
  routing engine, one rate limiter, one TLS store.
- `validate` works identically on a file and on a cluster's CRDs.
- The "why did this request match this route" explain surface has exactly one thing to explain.
- A new source is a new compiler front end and touches nothing else.

Traefik's provider model is the closest prior art and it is the right idea. The correction is that
its internal model leaks provider-specific concepts, so behavior is not uniform across providers.
Ours must be provably uniform, and a lint enforces that no source-specific type appears downstream
of the compiler.

## Decision 3: the request path allocates nothing, locks nothing, and reads an immutable snapshot

- The `Snapshot` is built off the request path and published with `arc_swap`. In-flight requests
  finish against the snapshot they started on. There is no reader lock, ever, and no
  `ArcSwap::load_full` per request.
- Per-request state uses reused per-worker buffers. Steady-state request handling performs zero heap
  allocations. This is a measured property with a CI gate, not an aspiration.
- Monotone counters are per-core and may lose an increment across a task migration. **Balances**
  (in-flight requests, permits, leased tokens, pooled buffers) may not: they are cache-line-padded
  shared atomics behind an RAII guard with **no public decrement API**. A lost counter increment is
  a rounding error; a lost balance decrement is capacity that disappears forever.
- State that must survive a config change (connection pools, TLS session state, rate limit buckets,
  health and ejection state, adaptive concurrency controllers) is keyed by a stable identity and
  carried across snapshots rather than rebuilt. Rebuilding it is what makes competitors' config
  reloads visible in p99.

## Decision 4: routing is O(path length), never O(route count)

A compiled, immutable, arena-backed table with no `&mut self` method:

1. SNI resolved once per connection against a reversed-label radix trie, with a per-request
   certificate mask check and **421 Misdirected Request** on an authority and certificate mismatch.
2. Authority normalized into a stack buffer and resolved through a reversed-label host trie whose
   nodes carry a precomputed fallthrough chain in Gateway API host-specificity order.
3. Path matched by a byte-wise compressed PATRICIA radix with segment-boundary annotations, each
   node carrying an `up` back-pointer to its nearest candidate-owning ancestor so predicate-failure
   backtracking is O(1) space.
4. Predicates as flat bytecode over interned header and query names.

Precedence is a single `u64` computed at build time, so the runtime never sorts or compares.
All path regexes compile into **one** `regex-automata` multi-pattern automaton evaluated at most
once per request, so a route table with r regexes costs O(p), not O(r * p), and catastrophic
backtracking is not expressible. When a node exceeds 32 candidates the builder **automatically**
synthesizes a secondary hash discriminator on the highest-cardinality predicate dimension, which is
Envoy's unified matcher tree except that we synthesize it instead of asking the user to hand-author
it in xDS.

## Decision 5: the crate graph is deliberately fine grained

Small crates are better here specifically because the implementers are small models. Each issue
targets one crate, the compiler enforces the boundary, blast radius is bounded, and incremental
builds stay fast. Crates appear in `Cargo.toml` as the issues that create them land.

**Foundation.** `irontraffic-time` (the one clock seam: four distinct newtypes so a wall clock can
never be compared against a monotonic one), `irontraffic-rand` (the one entropy seam, every consumer
takes `&mut Rng` so tests are seedable), `irontraffic-io` (the transport seam over `hyper::rt`, and
the only place raw syscalls and the `tokio::` namespace may appear), `irontraffic-runtime` (worker
derivation from the cgroup CPU quota, and the `CoreScope` that makes per-core state sound),
`irontraffic-telemetry`.

**Protocol.** `irontraffic-http` (the canonical message model, field validation tables, framing
resolution, path normalization, forwarded and PROXY protocol parsing), `irontraffic-conn`
(connection budget accounting, the forwarding loop, backpressure, splice).

**Request path.** `irontraffic-router`, `irontraffic-balancer`, `irontraffic-upstream`,
`irontraffic-resilience`, `irontraffic-limits` (the data-plane crate holding rate limits,
concurrency limits and admission control), `irontraffic-filter`, `irontraffic-cache`,
`irontraffic-tls`, `irontraffic-l4`, `irontraffic-dataplane`.

**Policy and extension.** `irontraffic-expr` (the compiled expression language that covers most of
what people write plugins for), `irontraffic-wasm` (feature gated).

**API management.** `irontraffic-apim`, `irontraffic-schema`.

**Control plane.** `irontraffic-config`, `irontraffic-store`, `irontraffic-cluster`,
`irontraffic-quota` (durable quota store), `irontraffic-admin`, `irontraffic-k8s`
(feature gated), `irontraffic-dashboard`.

**Binaries.** `irontraffic`, `irtctl`.

## Decision 6: clustering is state-class specific, and the data plane never depends on it

| State | Consistency need | Mechanism |
| --- | --- | --- |
| Configuration | strong, low write rate | the Kubernetes API server in k8s mode; a replicated log in standalone mode |
| Certificates and ACME material | strong, durable, secret | the config store, referenced by URI rather than inlined |
| Membership and health | eventually consistent | SWIM-style gossip |
| Rate limit and quota counters | bounded staleness | local enforcement plus leased shares, with a stated overshoot bound |
| Sticky affinity | best effort | gossip, loss tolerated |
| Outlier ejection | local observation | never globally trusted; a partition must not let one node eject an upstream everywhere |

**The non-negotiable invariant:** if the control plane, the cluster, or the Kubernetes API server is
completely unavailable, every data plane keeps serving its last known good configuration
indefinitely. It logs loudly and reports degraded readiness, and it keeps proxying. Any design that
violates this is rejected.

IronCache and IronBus may be optional accelerators behind traits. They are never prerequisites, and
CI proves the no-dependency path works.

## Decision 7: extensibility is layered, and the top layer is not code

Most "I need a plugin" requests are "I need to conditionally set a header, reject a request, or pick
a route based on some request property". That is an expression, not a program.

1. **Declarative policy and a compiled expression language.** Most needs, near zero cost.
2. **First-party filters compiled in**, behind a stable trait, for anything performance critical.
3. **WASM on wasmtime** with pooled instances, epoch interruption, and memory and fuel metering, for
   operator-supplied extensions. The v1 posture is that modules are operator-trusted, and the threat
   model says so plainly rather than implying an isolation guarantee we have not built.
4. **External processing over gRPC** for the escape hatch, at the cost of a network hop.

Explicitly rejected: an interpreted general-purpose language on the request path (Traefik's Yaegi),
native dynamic-library plugins (Rust has no stable ABI, and KrakenD's Go plugin version lock is the
cautionary tale), and requiring a rebuild to add a module (Caddy's xcaddy).

## Decision 8: the dashboard is a thin client of a public API, and it is free

The admin REST API is the single source of truth for administration. The dashboard, `irtctl`, a
future Terraform provider, and an MCP server are all clients of it. A capability the dashboard has
and the API does not is a defect, and a CI route audit enforces that the dashboard makes no network
call to a path absent from the published OpenAPI document.

It ships embedded in the binary, so there is no second deployment. It is not read only (Traefik's
is), not paywalled (Kong's and Tyk's advanced surfaces are), and not a separate abandoned project
(APISIX's was). Its differentiating feature is **explanation**: given a request, show which routes
were considered, which matched, why the winner won, which filters ran, which upstream was chosen and
by which algorithm, and where the time went.

## Scale targets

These are commitments that become CI gates, not aspirations.

| Property | Target |
| --- | --- |
| Idle plaintext connection | under 2 KiB |
| Idle TLS connection | under 8 KiB |
| 1,000,000 idle plaintext connections | under 4 GiB RSS |
| 100,000 idle TLS connections | under 1.5 GiB RSS |
| Route table | 100,000 routes, with gated build time and memory |
| Route match | allocation-free, O(path length), independent of route count |
| Config apply and binary upgrade | zero dropped connections, measured |

## Platform scope

Linux is the first-class data-plane target: `SO_REUSEPORT`, `splice(2)`, and `SCM_RIGHTS` descriptor
handoff for zero-downtime binary upgrade are all Linux mechanisms and all load-bearing. macOS is
supported for development and testing. Windows is an explicit non-goal for v1; see
`docs/WILL-NOT-IMPLEMENT.md`.
