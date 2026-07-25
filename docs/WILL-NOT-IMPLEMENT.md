# What IronTraffic will not implement

Writing this down is a feature. An ambiguous roadmap invites the request forever; a stated non-goal
answers it once. Each entry says whether it is **hard** (the answer will not change) or
**reversible** (the answer could change with evidence, and what evidence would change it).

## Hard non-goals

**A general-purpose scripting language on the request path.** No Lua, no embedded JavaScript, no
interpreted Go. The extensibility ladder in `ARCHITECTURE.md` covers the real needs at each cost
tier. An interpreter on the hot path is how competitors ended up with per-request costs they cannot
remove and sandboxes they cannot trust.

**Native dynamic-library plugins.** Rust has no stable ABI, so a `dlopen` plugin interface is
unsound across compiler versions and silently so. One competitor's Go plugin system requires the
plugin and host to be built with the identical toolchain and dependency set, which is exactly this
mistake with a different language.

**Requiring a rebuild to add a module.** If extending the product means running a build tool and
producing a custom binary, the extension story has failed.

**Anonymous usage telemetry.** See `COVENANTS.md`. There is nothing to opt out of.

**A mandatory external datastore.** No required Redis, etcd, Postgres, or ZooKeeper. One competitor
hard-fails process startup when its configuration store is unreachable; that is the opposite of the
availability tenet.

**Windows as a first-class data-plane target (v1).** `SO_REUSEPORT`, `splice(2)`, and `SCM_RIGHTS`
descriptor handoff are all load-bearing and all Linux. Supporting Windows would roughly double the
platform seam and would require a different, worse zero-downtime upgrade mechanism. macOS is
supported for development.

**Full service mesh with injected sidecars.** IronTraffic is a gateway and an ingress. Mesh identity
integration (SPIFFE, SPIRE) is in scope; owning a sidecar injector, a per-pod proxy lifecycle, and a
mesh control plane is not.

**Being a certificate authority.** We integrate with ACME and with SPIFFE issuers. We do not become
one.

**Billing and invoicing.** Usage records are exported with a documented contract so a rating engine
can consume them. Plan pricing, invoicing periods, overage rules, and the compliance surface that
comes with them are somebody else's product.

## Reversible non-goals

**io_uring.** Not in v1. The container runtimes most deployments use block the relevant syscalls in
their default seccomp profiles, several large operators disabled it in production on security
grounds, and the ecosystem has no io_uring TCP path we can adopt. The transport seam is designed so
a backend can be added without touching the data plane. *What would change this:* a measured,
reproducible win on a realistic workload plus a container security posture that permits it.

**Kernel TLS offload.** Deferred. It composes badly with L7 body inspection and it removes record
level visibility that debugging depends on. *What would change this:* a workload dominated by
passthrough or large-body transfer where the measured saving is material.

**xDS.** IronTraffic does not speak xDS in either direction in v1. *What would change this:* a
concrete adoption case where being a drop-in control plane or data plane for an existing Envoy fleet
is the deciding factor. Note the cost: committing to xDS constrains how the internal representation
may model filter chains and per-route overrides, forever.

**GraphQL federation.** Schema-aware routing, validation, depth and cost limiting, and persisted
queries are in scope. Federation, `@defer` and `@stream`, and subscription message policy are not.

**Multi-cluster federation.** One cluster in v1. Cross-cluster configuration replication is treated
as an operator concern.

**Untrusted tenant-supplied WASM.** The v1 posture is that modules are operator-trusted, and the
threat model says so plainly rather than implying an isolation guarantee we have not built.
*What would change this:* a multi-tenant deployment that needs it, funded as its own milestone,
because it requires signature verification, per-tenant instance pools, memory protection keys, and a
much larger adversarial test matrix.
