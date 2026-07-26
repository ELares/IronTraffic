# Threat model

IronTraffic terminates traffic from untrusted networks. This document enumerates each surface, what
an attacker can do to it, and the structural control that stops them. It is extended in the same
pull request that ships any new surface; see `CONTRIBUTING.md`.

## Trust zones

| Zone | Trust | Notes |
| --- | --- | --- |
| Downstream client | none | every byte is attacker-chosen, including in TLS |
| Upstream origin | partial | may be compromised, may be slow, may be hostile to us |
| Peer IronTraffic node | authenticated | cluster membership is authenticated; a peer is still not trusted to assert arbitrary state |
| Control plane and admin API | privileged | authenticated and authorized; never reachable on the data listener |
| Extension code (WASM, external processor) | operator-trusted in v1 | metered and bounded, but not treated as hostile; stated plainly rather than implied |

## Surfaces

The sections below are added as each surface ships. Every entry states: what the surface parses or
exposes, the attacker's capabilities against it, the specific abuse cases, and the **structural**
control (a property of the design that makes the abuse unrepresentable) rather than a mitigation
that depends on remembering to check something.

### Surface: the HTTP request parser

*Status: specified, not yet implemented. Milestone 2.*

**Parses:** the request line, field section, and body framing for HTTP/1.1, HTTP/2, and HTTP/3 from
an unauthenticated attacker.

**Abuse cases:** request smuggling in all of its forms (CL.TE, TE.CL, TE.TE obfuscation, CL.0, 0.CL,
H2.CL, H2.TE, h2c upgrade smuggling, request tunnelling); header injection through unvalidated field
names and values; authorization bypass through path confusion between our view of the path and the
origin's; client identity spoofing through forwarding headers; resource exhaustion through header
count, header size, or decompression bombs.

**Structural controls:**

- Framing ambiguity is **not representable**. Every wire protocol parses into one canonical message
  whose framing enum has exactly three variants and no "ambiguous" or "unknown" variant.
  `Content-Length` and `Transfer-Encoding` are hop-by-hop, deleted at ingress unconditionally, and
  regenerated at egress from the bytes we are actually going to send. Smuggling requires two parties
  to disagree about framing; we cannot forward a disagreement we cannot represent.
- We **reject** ambiguity rather than normalizing it. The cost of rejecting is a 400 for requests no
  legitimate client sends. The cost of forwarding is site takeover.
- **Exactly one path value exists** in the system, and routing predicates, authorization policy,
  logging, cache keys, and the forwarded bytes all derive from it. Any rewrite re-runs the full
  normalization pipeline and the request is re-routed and re-authorized before forwarding, with a
  bounded rewrite count.
- Client identity has **one source** and is **fail-closed**: forwarding headers are honored only
  under an explicit trust policy, the default deletes them, and PROXY protocol is parsed only on
  listeners configured for it, never sniffed.

### Surface: the HTTP/2 and HTTP/3 connection

*Status: specified, not yet implemented. Milestone 2.*

**Abuse cases:** Rapid Reset, the CONTINUATION flood, MadeYouReset, HPACK and QPACK decompression
bombs, settings and ping floods, window-update abuse, priority tree churn.

**Structural controls:** one per-connection token bucket debited **before** any per-stream state is
allocated, with two rules that cannot be misread: a stream reset always **debits** and never
credits, and the count of work in flight upstream is released only when the upstream exchange
actually terminates, never by a downstream reset, which must instead propagate cancellation upstream.
Header list size is accounted on the **uncompressed** size incrementally during decode.

### Surface: the admin API and dashboard

*Status: specified, not yet implemented. Milestone 7.*

**Abuse cases:** unauthenticated configuration change; privilege escalation through the dashboard
reaching an undocumented endpoint; audit gaps; secret disclosure through configuration history.

**Structural controls:** the admin API never binds to a data listener; the dashboard is a thin
client with a CI route audit proving it calls no undocumented path; every mutation writes an audit
row in the same transaction; secret material is referenced by URI rather than inlined, so the
configuration history is safe to store and to commit to version control.

## 1. Trust boundary

Everything read from a downstream socket is attacker chosen, namely request bytes, field names,
field values, the request target, the authority, the forwarding chain and the PROXY protocol header.
Everything read from an upstream socket is attacker chosen too, because an origin can be compromised
or can be an attacker-controlled tenant. The `irontraffic-http` crate is the single place where those
bytes become a decision, and no component outside it may re-parse them. One piece of non-coverage
every operator must know about: IronTraffic parses and replaces exactly three families of identity
field (`Forwarded`, `X-Forwarded-*` and `X-Real-IP`), and vendor identity fields that other products
invent (`True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `X-Cluster-Client-IP`,
`X-Original-Forwarded-For`) are forwarded untouched, so an origin that trusts one of them is trusting
a value the client wrote. That set is open ended and is therefore a remove-header filter an operator
configures, not a constant this product guesses at. `hop-by-hop-strip-set` (#26) states the same rule
from the strip side and points here.

## 2. Attacker model

An attacker has unlimited requests, full knowledge of this source, the ability to choose every byte
on a connection, the ability to open many connections, and the ability to select which upstream a
request lands on. The attacker cannot read process memory and cannot change configuration.

## 3. Refusal is not an oracle

Every refusal answers with the status from `RejectReason::status` and closes the connection. The
`RejectReason` variant name, its `metric_label`, the offending byte, the offending field name, and
the byte offset at which parsing failed are NEVER written into the response body, into a response
header, or into a response reason phrase. They go to metrics and to the access log only. A response
that names the failing branch hands an attacker a free desync-probing oracle: the whole technique in
"HTTP/1.1 Must Die" is distinguishing which of two parsers refused and why.

## 4. Bounded state

Every buffer, table, counter map and queue reachable from the network has a named limit with a
default, stated either in `Limits` or in a per-issue constant, and a defined behaviour at the limit.
The subsections under section 5 name each one.

## 5. Per-surface sections

Later issues append one subsection per surface here: `path-normalization` (#29),
`authority-parsing-and-reconciliation` (#30), `forwarded-element-parsing` (#31),
`trust-policy-and-peer-identity` (#32), `h1-head-parser` (#34), `h1-chunked-and-trailers` (#36),
`mplex-pseudo-header-validation` (#38) and `proxy-protocol-parser` (#43) each add one, and
`desync-corpus-and-reject-table` (#47) adds a section 6 that ties every named attack to its corpus
entry.
