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

## Authority normalization

**Parses:** the `Host` header (HTTP/1) or the `:authority` pseudo-header (HTTP/2, HTTP/3), via
`irontraffic-router`'s `normalize_authority`. Every byte of it comes from the downstream client:
the attacker chooses the case, the length, whether a port is present, whether a trailing dot is
present, and whether the IPv6 bracket form is used.

**Equivalence classes collapsed.** `normalize_authority` maps every one of the following spellings
to the same output, so that a route configured under one spelling matches a request made under any
other:

- ASCII case: `EXAMPLE.com`, `example.com` and `Example.COM` all become `example.com`.
- Any port, including an empty one and the IPv6 bracket form: `example.com:443`, `example.com:80`
  and `example.com:` all become `example.com`; `[::1]:8443` becomes `[::1]`.
- One trailing dot, the DNS root label: `example.com.` becomes `example.com`.

Case folding is ASCII only. Unicode case folding has locale-dependent behaviour (the Turkish
dotless-i class), and Gateway API's `Hostname` CRD pattern cannot match a non-ASCII byte, so a
non-ASCII authority is refused rather than mapped. `normalize_authority` never performs IDNA,
punycode, NFC or NFKC normalization: decision ledger entry 16 rejects mapping a non-ASCII authority
at request time, because a mapping proxy in front of a non-mapping origin is a virtual-host
confusion primitive in its own right.

**What is refused, and with which error:**

- A byte at or above 0x80 (`AuthorityError::NonAscii`).
- `*`, or any byte outside the accepted authority byte class (`AuthorityError::InvalidByte`); this
  is also why an `Exact` host pattern can never contain a wildcard.
- Percent-encoding anywhere except inside an IPv6 zone id (`AuthorityError::InvalidByte`); `%` is
  never decoded.
- An empty label, an unclosed IPv6 bracket, or a leading dot (`AuthorityError::Malformed`).
- More than `MAX_AUTHORITY_BYTES` (255) bytes after the port is stripped, or more than 1024 bytes
  before it is even parsed (`AuthorityError::TooLong`); the earlier, cheaper cap exists so that
  finding the port cannot itself scan an unbounded buffer.

**Structural control: one function, both call sites.** `normalize_authority` is the ONLY authority
normalization in the product. The route builder calls it, through `normalize_host_pattern`, when a
`HostPattern` is admitted; the request path calls the identical function on every request's
authority before consulting the host trie. There is no second implementation of this grammar
anywhere in the tree to drift out of sync with the first: a hostname configured as `Example.COM.`
and a request to `example.com:443` are therefore provably the same lookup key, not merely expected
to be by convention. Two independent encodings of one grammar in one system is exactly how a build
path and a match path disagree, and a build/match disagreement here is a virtual-host confusion
bug: a request would match a route its author never configured it to reach.

**Residual risk.** An authority that `normalize_authority` accepts but that matches no configured
`HostPattern` falls through to the listener's catch-all group, the same as any other unmatched
authority on that listener. Accepting an authority is not a claim that it is meaningful, only that
it is well-formed enough to look up; a listener with no catch-all route simply has nothing for it
to fall through to.
### Authority (`authority-parsing-and-reconciliation`, #30)

**Parses:** the `Host` field and the `:authority` pseudo-header, both attacker chosen. The authority
selects the virtual host, the route table and the TLS policy for the request.

**Structural controls:**

- **No IDNA, ever.** `Authority::parse_into` never performs IDNA `ToASCII`, IDNA2003, IDNA2008,
  UTS-46 transitional or non-transitional processing, or Unicode NFC, NFD, NFKC or NFKD
  normalization. Any byte at or above `0x80` is refused with `AuthorityNonAscii`. UTS-46's two
  processing modes disagree on four characters and IDNA2003 disagrees with IDNA2008 on more, so a
  proxy that maps and an origin that does not (or maps with a different table version) is a
  virtual-host confusion primitive: two different requests reach two different vhosts depending on
  which library version each side compiled against. This type is never that proxy.
- **Zone identifiers are refused.** A bracketed IPv6 literal may contain only hex digits, `:` and
  `.`. An RFC 6874 zone identifier (`[fe80::1%25eth0]`, encoded or not) is refused with
  `AuthorityInvalidByte`: it names a local network interface, is meaningless to route on, and would
  let a remote peer choose a link-local scope on a connect path. There is no configuration that
  accepts it.
- **The bound is `max_authority_bytes`** (`Limits::max_authority_bytes`, default 255, hard ceiling
  `Limits::CEILING.max_authority_bytes`). Longer input is refused with `AuthorityTooLong` before any
  other validation runs, and before the whole input is even scanned byte by byte.
- **A `Host` that disagrees with `:authority` is refused, not resolved.** `reconcile_authority`
  refuses with `AuthorityMismatch` when both are present and disagree after scheme-based
  normalization (RFC 3986 Section 6.2.3: drop the scheme's default port). RFC 9113 Section 8.3.1
  states this as a SHOULD; IronTraffic makes it a MUST.
- **Bytes, not addresses.** `Authority` canonicalizes the BYTES of the host, never the ADDRESS it
  might denote. `127.0.0.1`, `127.1`, `0177.0.0.1` and `2130706433` all resolve to loopback and are
  four distinct `Authority` values; `[::1]` and `[0:0:0:0:0:0:0:1]` are two distinct values. Any
  policy that means to match an IP address (an SSRF deny-list, an internal-range check, an
  "is this upstream local" test) MUST parse the host into an `IpAddr` and compare addresses;
  comparing `Authority::host` bytes against a literal is a bypass waiting to be written.
## Listening sockets and socket options

**What the listening socket exposes.** A TCP port reachable by anyone who can route to the bound
address. Binding `0.0.0.0` exposes it on every interface including ones the operator may not have
considered; binding a specific address is the safer default when the deployment allows it.

**`SO_REUSEPORT` and who may join the group.** On Linux the kernel requires every socket in a
reuseport group to have the same effective UID as the socket that created the group, and it hashes
inbound connections across every socket currently in the group, so a local process running as the
same user can join the group and receive a share of inbound connections; a process running as a
different user cannot. That UID check is a Linux behaviour and is not guaranteed on other platforms.
On BSD-derived kernels, including macOS, a same-UID join is not a share: measured against the real
`bind_listener` with `SockOpts::default()`, an ordinary unprivileged same-UID `python3` process that
joined our group received every inbound connection while we received none (`ours=0 attacker=40` over
40 connections), and when that process never called `accept`, every one of those connections was
silently dropped rather than refused (`0/20` accepted by us, `20/20` black-holed), with no error and
no signal visible on our own socket. `SockOpts::default()` sets `reuse_port: true`, so this
precondition is already in effect for every listener created with default options; it is not
something an operator opts into. Consequence: run the proxy as a dedicated, unshared user account so
no untrusted local process can ever share its effective UID, and set `reuse_port: false` on any host
where that cannot be guaranteed. On Linux, failing to do so risks a share of inbound connections going
to the untrusted process; on a BSD-derived host it risks the whole listener being silently redirected
to that process or black-holed outright, with nothing in `BindOutcome` or any log line to distinguish
either outcome from a healthy, fully-shared group.

**`SO_REUSEADDR` and address specificity.** With `SO_REUSEADDR` set on both sides, a second local
process can bind a more specific address on the same port (for example `127.0.0.1:8080` while we
hold `0.0.0.0:8080`), and the kernel delivers matching connections to the more specific socket. That
is a local traffic-hijack path with the same "same host, same or greater privilege" precondition as
the reuseport case. Same mitigation, plus: prefer binding the specific address the traffic actually
arrives on.

**What is out of scope here.** Connection admission, rate limiting, and per-source limits are not
this module's job; it creates the socket and reports what it applied.
