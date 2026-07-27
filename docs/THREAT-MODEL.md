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
default, stated in `Limits`, in a per-issue constant, or in a connection-level balance, and a
defined behaviour at the limit. `Limits` bounds the CONTENT of one message; it does not bound how
many messages, streams or upstream exchanges are in flight on one connection at once, which is a
separate class of bound. `ConnBudget` (`conn-budget-token-bucket` (#40)) prices every frame received
on a connection against a lazily refilled token bucket and closes the connection once the price
exceeds the budget, which bounds the RATE of protocol-level work a connection may cause.
`InflightGauge` (this issue) bounds the COUNT of upstream exchanges in flight on one connection to
`max_inflight_work` (default 256), which is what stops a `RST_STREAM`-based reset from freeing
capacity the upstream is still spending (CERT/CC VU#767506, the MadeYouReset defect class). The
subsections under section 5 name the per-message limits; this paragraph names the per-connection
ones.

## 5. Per-surface sections

Later issues append one subsection per surface here: `path-normalization` (#29),
`authority-parsing-and-reconciliation` (#30), `forwarded-element-parsing` (#31),
`trust-policy-and-peer-identity` (#32), `h1-head-parser` (#34), `h1-chunked-and-trailers` (#36),
`mplex-pseudo-header-validation` (#38) and `proxy-protocol-parser` (#43) each add one, and
`desync-corpus-and-reject-table` (#47) adds a section 6 that ties every named attack to its corpus
entry.

## Binary upgrade handoff

**What the exchange parses.** A predecessor process serialises its listening sockets into a
versioned, length-prefixed frame and sends the frame over a Unix stream socket together with the
file descriptors as `SCM_RIGHTS`. The successor parses the frame, matches each entry's canonical bind
address against its own listeners, registers the inherited descriptors, and replies with a one-byte
acknowledgement before the predecessor stops accepting.

**What an attacker can do.** A peer on the upgrade socket does not merely send a message; it sends
listening sockets, and the receiver then accepts connections on them. A peer that can complete the
exchange therefore chooses which sockets this process serves traffic on. It could hand over a socket
it also holds, and read every request and response that arrives.

**Structural controls.** The frame carries no authentication of any kind. The only controls are who
may connect to the upgrade socket: the socket lives in a directory with mode 0700 owned by the
process's own user, the socket itself is mode 0700, and both sides verify peer credentials and refuse
unless the peer's effective uid equals their own. The receiver also verifies that the number of
descriptors actually received in the control message equals the frame's count before indexing the
array. A checksum inside the frame is a framing check only: it turns a partial write or a version
confusion into a clean rejection, not a security boundary.

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
### Forwarding chain (`forwarded-element-parsing`, #31)

**Parses:** every `Forwarded`, `X-Forwarded-For` and `X-Forwarded-Proto` field line into one
ordered `ForwardedChain`. RFC 7239 Section 8.1 is explicit that every byte of this data is
attacker writable at every hop on the way to this proxy, including by the client itself: "the
'Forwarded' HTTP header field cannot be relied upon to be correct, as it may be modified, whether
mistakenly or for malicious reasons, by every node on the way to the server." This parser makes NO
trust decision; it only records what was claimed, bounded in cost. Picking a client address out of
the recorded chain is `trust-policy-and-peer-identity` (#32)'s job.

**Structural controls:**

- **Two named bounds, both refusals, never a truncation.** `Limits::max_forwarded_elements`
  (default 32) caps the number of elements the chain may hold; `Limits::max_forwarded_bytes`
  (default 4096) caps the total field-value bytes parsed across all three families combined.
  Exceeding either is `RejectReason::ForwardedElementLimit` or `RejectReason::ForwardedBytesLimit`.
  Neither cap truncates the chain: a truncated chain would silently change which entry a later
  trust walk treats as the client, which is a worse failure than refusing the whole message.
- **An over-cap value is refused before it is scanned.** Each field line's byte length is checked
  against the remaining byte budget BEFORE a single byte of it is tokenized. A 100,000-entry
  `X-Forwarded-For` delivered as one field line value costs one length comparison and a refusal,
  not 100,000 pushes into a growing vector: `forwarded::tests::caps_are_enforced_inside_the_loop`
  pins this by engineering the oversized value so that scanning it would have produced a
  *different* error, and asserting the byte-limit error instead.
- **Anything that is not an address terminates the walk.** RFC 7239's `for=unknown` token and its
  `_`-prefixed obfuscated identifiers both parse successfully, as `NodeName::Unknown` and
  `NodeName::Obfuscated`, and both report `terminates_walk() == true`, the fail-closed direction. An
  absent `for` parameter (`NodeName::Absent`) does too. `NodeName::Addr` is produced only for a
  value the standard library's `Ipv4Addr`/`Ipv6Addr` parser actually accepted; a bare, unbracketed
  IPv6 literal and a leading-zero IPv4 octet are both refused as ambiguity primitives rather than
  guessed at, matching `Authority`'s own "bytes, not addresses" stance one layer up.
- **Only three field families are read, and adding a fourth is a trust decision, not a one-line
  change.** `Forwarded`, `X-Forwarded-For` and `X-Forwarded-Proto`, nothing else. In particular this
  parser never reads `X-Real-IP`: it carries a single address with no chain, so there is no way to
  tell a trusted hop's value from a client's, and it is unconditionally deleted at ingress by
  `IDENTITY_STRIP` (`hop-by-hop-strip-set`, #26) before anything downstream could read it either way.
  `X-Forwarded-Host`, `X-Forwarded-Port`, `True-Client-IP` and `CF-Connecting-IP` are refused the
  same way: none of the five is read by this parser, however a deployment happens to spell the
  header name.
- **A `#list` field split across multiple lines is one list.** RFC 7239 Section 7.1 permits a
  `Forwarded` or `X-Forwarded-For` value to be split across several field lines that are
  semantically one comma-joined list; reading only the first or only the last line is a bypass, so
  `ForwardedChain::parse_into` takes every line, in arrival order, for all three families.

### Client identity (`trust-policy-and-peer-identity`, #32)

**Decides:** who the client is, out of a socket peer address, an optional PROXY protocol
declaration, and the `ForwardedChain` recorded above. `resolve_identity` is the single place this
product makes that decision; nothing downstream re-derives it from a header.

**Single source, and it is fail closed.** `TrustPolicy::None`, the default, never reads a
forwarding field at all: every request's client is its socket peer. An operator opts into reading
the chain by choosing `TrustPolicy::HopCount(n)` (trust exactly `n` hops from the right) or
`TrustPolicy::TrustedCidrs` (pop trusted addresses from the right until an untrusted one is found).
Both fail closed to the socket peer, with `IdentitySource::Socket`, on every degenerate input:

- A chain shorter than `HopCount(n)` expects.
- A non-address entry (`for=unknown`, an obfuscated identifier, or an absent `for`) where the walk
  needed an address, under either policy.
- An untrusted socket peer under `TrustedCidrs`: a chain from a peer the policy does not trust is
  worth nothing, however well formed.

`resolve_identity` has no error type and no fail-open branch: every input, degenerate or not,
produces a `PeerIdentity`. The rejected alternative, trusting the leftmost `X-Forwarded-For` entry,
is not merely inferior, it is 100% attacker controlled, because the leftmost entry is whatever the
client itself typed; walking from the right instead is invariant under a client padding its own
end of the chain, because a client can only ever add entries on the left of a single family's own
elements.

**A chain mixing `Forwarded` and `X-Forwarded-For` is refused outright, not walked.** The
"can only add on the left" premise above holds only within one family. `ForwardedChain::parse_into`
places every `Forwarded` element before every `X-Forwarded-For` element regardless of which one
actually arrived on the wire first, so if a trusted proxy speaks `Forwarded` while a client sends
its own `X-Forwarded-For`, the client's entry lands on the RIGHT end of the combined chain, which
is the end this walk trusts. `resolve_identity` fails closed to the socket peer whenever a chain
contains elements from both families, under both `HopCount` and `TrustedCidrs`, exactly as it does
for a too-short chain. Issue #32 did not specify this case; it is documented on the issue
(`trust-policy-and-peer-identity`, #32) as a judgement call rather than a settled requirement, and
a deployment that genuinely needs both families honoured together is not supported by a single
`TrustPolicy` today.

**`peer_trusted` is verified only under `TrustedCidrs`.** It answers one narrow question: was the
immediate base address (the PROXY-declared address when present, otherwise the socket peer)
checked against a configured prefix list and found inside it. Only `TrustedCidrs` has an address
list to check; `HopCount` and `None` leave it false for every input, because an unverified
operator assertion ("there are proxies in front") must not grant a capability an external client
would otherwise not have. `PeerIdentity::trusted_internal` is the one accessor that answers this
question, and the `x-envoy-*` field family (`IDENTITY_STRIP`, `hop-by-hop-strip-set`, #26) is
honoured only on a connection this same value marks trusted; there is no second, independently
configured trust decision anywhere in the product; `TrustedCidrs([0.0.0.0/0])` is a legal
configuration and an operator explicitly choosing to believe the leftmost entry, which is why it
is documented on `TrustPolicy` itself rather than treated as a bypass.

**Egress never passes through what was received.** `write_forwarded_element` synthesizes exactly
one `Forwarded` element from a `PeerIdentity` and the listener's own address; `strip_ingress`
already deleted every inbound `Forwarded`/`X-Forwarded-*`/`X-Real-IP` field before this runs, so
there is no received value to append to. This is what makes the upstream's view of client identity
a function of this proxy's configuration, never of the client's input.

### HTTP/1 head (`h1-head-parser`, #34)

**Parses:** the request line, the status line, and the field section of an HTTP/1.0 or HTTP/1.1
head, from the accumulated read buffer of an unauthenticated attacker. This is the single parse
boundary for HTTP/1 request smuggling: it decides where a message begins and ends, and every
downstream component (routing, forwarding, the next message on the same connection) trusts that
decision without re-deriving it.

**Stateless across calls, and what that costs.** `H1Parser::parse_request_head` and
`parse_response_head` hold no cursor: when the head is not yet complete they return
`ParseStatus::Partial`, and the caller appends more bytes to the SAME buffer and calls again from
offset zero. Statelessness is what makes this parser exhaustively fuzzable and makes the resumption
class of bugs unrepresentable, but it is not free: a head delivered one byte per read is rescanned
once per byte, `O(L^2)` in total bytes scanned. Two limits bound this parser and NEITHER bounds that
quadratic rescan cost:

- `max_head_bytes` (`max_request_line_bytes + max_header_list_bytes + 2`; 73,730 at the defaults)
  bounds the MEMORY one incomplete head may occupy. It says nothing about how many times those bytes
  are re-scanned.
- `header_read_timeout` (the corpus-wide deadline name; not yet armed by any accept-to-first-byte
  read loop in this milestone's plan) bounds the WALL CLOCK a head may occupy a connection. At its
  10 second default it does not help either: the CPU cost of the quadratic rescan (about 0.9 seconds
  for a maximum-size head delivered one byte at a time) is paid and gone long before the deadline
  fires, so 10,000 such connections inside one deadline window buy an attacker roughly 9,000
  CPU-seconds.

**The structural control: `HeadScanBudget`, a third, explicit bound on WORK.** The connection
driver charges `HeadScanBudget::charge(buf.len())` immediately before every `parse_request_head` or
`parse_response_head` call, and the cumulative charge for one head may never exceed
`HeadScanBudget::MAX_BYTES` (4 MiB, about 56x `max_head_bytes` at the defaults) before the connection
is refused with `HeaderListTooLarge`. A maximum-size head drip-fed one byte per read is cut off after
roughly 1.5 ms of CPU instead of 900 ms: the head was never going to be accepted, and refusing it
costs a bounded, constant amount of work regardless of how a peer drips it in. The budget is reset
only after a `Complete`, never after a `Partial`, so a pipelined connection gets a fresh budget per
message rather than a shared one; a driver that forgets to call `reset` eventually refuses a
legitimate connection. `HeadScanBudget` is not configurable: it is a floor on how much CPU a peer can
buy, not an operator-facing feature, and neither `max_head_bytes` nor `header_read_timeout` is a
substitute for it.

**Every name and value byte is validated during the scan**, never assumed safe because it "came from
what we parsed" (the pattern Pingora's `HeaderValue::from_maybe_shared_unchecked` follows, and this
parser deliberately does not). A bare CR, a bare LF, obs-fold, whitespace before a field's colon, and
an empty field name (HAProxy CVE-2023-25725) are all refused rather than tolerated or normalized.

**Refusal is not an oracle here either**, per section 3 above: every one of the refusal reasons this
parser returns (`RequestLineMalformed`, `BareCr`, `BareLf`, `ObsFold`, `WhitespaceBeforeColon`,
`FieldNameEmpty`, and the rest of the reject table) maps to a status and a metric label, never to
response bytes, so a client cannot use the specific refusal reason to distinguish this parser's
behaviour from another's on the same malformed input.

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

## The forwarding data plane

**Everything here is attacker-controlled bytes.** Both peers of a proxied connection can send
arbitrary bytes at arbitrary rates with arbitrary framing, and either can stall or reset at any
moment. The loop never interprets a byte; it moves them.

**Memory is bounded structurally, not by policy.** At most one 32 KiB buffer per direction, held
only between a read that produced bytes and the completion of the write of those bytes. A client
reading at one byte per second cannot make us buffer an upstream response, because we do not poll
the read side while the write side has bytes pending. An idle connection holds zero buffers. There
is no watermark, no queue, and no channel to tune or to get wrong.

**Time is bounded by three deadlines**, and every connection has at least one owning timer at all
times: `idle` (no progress in either direction), `half_close` (one direction ended and the other did
not finish), and the optional `max_lifetime` (an absolute ceiling regardless of progress). With
`max_lifetime` unset, a peer that makes one byte of progress per idle period holds its connection
slot indefinitely; that residual risk and its lever are recorded in the admission section.

**What is not inspected.** No HTTP parsing, so no request framing is enforced and a
request-smuggling payload is forwarded verbatim. Do not place this version where an HTTP-aware
security control is assumed to exist.
## Configuration loading and validation

### Who can supply a document

The operator, through a local path, and in practice a CI pipeline running `irontraffic validate`
over a file from a pull request. Treat the bytes as untrusted even though the path is trusted.

### What bounds the parse

`irontraffic-config`'s `load` enforces three bounds before either parser sees the document, plus a
fourth `serde_json` enforces on its own. A 1 MiB byte cap is enforced twice (a metadata check and a
bounded read, so a growing file cannot slip past). A 64-token YAML alias budget defeats the
billion-laughs expansion the byte cap cannot, by rejecting more than 64 `*` bytes before
`serde_norway` ever sees the text. A separate 32-level YAML nesting-depth budget defeats a distinct,
quadratic cost inside `serde_norway`'s own tokenizer: a flow collection (`[...]` or `{...}`) nested as
the value of a block mapping key costs CPU quadratic in nesting depth while the tokenizer builds its
event stream, before any value exists for `serde` to examine, and it does this with zero alias tokens
involved. Measured directly against this crate: a 1 MiB document built entirely from nested `[` and
`]` characters, with no aliases, cost 475 seconds of CPU before this guard existed. `serde_json` needs
no guard of ours for the equivalent JSON shape: it enforces its own 128-level recursion limit while
building the value, which genuinely bounds the cost of parsing rather than only bounding the outcome.

`deny_unknown_fields` on `BootstrapDoc` is a validation-time control, not a parse-time bound, and an
earlier version of this section listed it as one of the things that bounds the parse. That was false:
`deny_unknown_fields` can only reject a document once the tokenizer has already produced a value for
`serde` to examine, so it does nothing to limit the cost of getting there, and the quadratic nesting
cost above is exactly the cost it does not limit. The paragraph is corrected here rather than left
standing, because a threat model asserting a protection that is not there is worse than one that says
nothing.

### What bounds validation

`validate` is pure: no filesystem, no network, no subprocess, no clock. Its only super-linear work is
two duplicate scans that run after the listener count has been proved at most 64, so the whole
function is bounded at a few thousand comparisons however large the document is. This is the property
that makes it safe to expose from the admin API in a later milestone, and it is the correction to
ingress-nginx rendering attacker-controlled input to a temp file and executing the proxy binary on it.

### What is echoed back

`validate --print` writes the resolved document to stdout verbatim. The M1 bootstrap document
contains no secret, and any future field that does must be redacted by `Loaded::render_json` before
it is added, not afterwards. An unrecognised argument is echoed to stderr through
`sanitize_for_terminal`, so an argument carrying an ASCII escape or a newline cannot move an
operator's cursor or forge a log line.
## Request deadlines

**What is attacker-controlled.** Every inbound timeout signal `deadline::establish` reads is set
by the connecting peer: `grpc-timeout` on every connection (it is a standard gRPC header, never
stripped by the forwarding trust policy), `x-envoy-expected-rq-timeout-ms` when
`respect_expected_rq_timeout` is enabled, and `x-envoy-upstream-rq-timeout-ms` on a connection the
forwarding trust policy has marked trusted-internal. The last of those is stripped at ingress on
every other connection by the trust policy (decision ledger entry 20), but `establish` still
requires `trusted_internal` before honouring it, because "trusted-internal" means "another one of
our hops", not "will never send a hostile value".

**Structural control: an untrusted peer may only shorten its budget.** `grpc-timeout` is not part
of the `x-envoy-*` family and is never stripped, so an anonymous client can set it on any route.
Without a further rule, a route configured for a 1 second timeout would hand any client a 60
second budget for the price of one header, a 60x multiplier on how long that request pins a
downstream stream slot, an upstream connection, an upstream stream slot, a replay buffer, and a
queue entry, across every concurrent request that does it. `establish` caps any budget that came
from an inbound header, on a connection that is not trusted-internal, at the route's own
configured timeout: `budget = min(budget, route_timeout_ms)`. A client-supplied deadline shorter
than the route's is still honoured exactly, because honouring it only ever frees resources sooner.
`deadline_inbound_clipped_to_route` is incremented whenever this clip changes the value, so an
operator can see clients asking for more than the route allows.

**The `[min_timeout_ms, max_timeout_ms]` clamp.** Every established budget, regardless of which
signal produced it, is clamped to `[min_timeout_ms, max_timeout_ms]` (defaults 1 and 60_000)
before it becomes a `Deadline`. An unbounded client-supplied timeout is a resource-exhaustion
vector on its own: a connection, a stream slot, an upstream connection, and a replay buffer all
stay pinned for however long the attacker's header claims.

**The saturating narrowing that stops a wrapping cast.** A legal `grpc-timeout` value can exceed
`u32::MAX` milliseconds by four orders of magnitude (`99999999H` is about 11,415 years). Narrowing
it to the `u32` the rest of this module works in uses `u32::try_from(..).unwrap_or(u32::MAX)`,
never `as u32`. A wrapping cast reduces a huge value modulo 2^32 and can land anywhere in the u32
range, including below `max_timeout_ms`, which would silently hand the client a budget unrelated
to what it asked for; saturating to `u32::MAX` instead guarantees the value is still clamped down
to `max_timeout_ms` afterward, exactly as if the client had asked for the largest timeout the
route allows.

**Bounded parse cost.** `parse_grpc_timeout` scans at most 9 bytes (8 digits plus one unit byte)
and `parse_u32_ms` scans at most 10 bytes (the longest a `u32` can print as decimal); both reject
immediately on a longer value rather than scanning it. Neither parser allocates or calls
`core::str::from_utf8`: a header value is arbitrary bytes, and the digit and unit checks operate
on them directly.
## Listener sharding and connection distribution

**The kernel chooses the shard, and an attacker chooses the input to that choice.** The kernel
selects the receiving socket by hashing the connection 4-tuple. Traffic from one source IP with few
source ports concentrates on one shard, and a peer can arrange that deliberately. In `balanced`
mode this is absorbed, because a connection task is stealable by any worker after accept, so kernel
skew becomes task skew and the work-stealing scheduler resolves it. In a shared-nothing mode it
would be a real denial of service against one core, which is one of the reasons `balanced` is the
default and `shard` refuses to start.

**The descriptor budget is `L x W` listening descriptors plus two per connection.** With the
validator's 64-listener cap and the runtime's 1024-worker cap that is at most 65,536 listening
descriptors before a single connection is served, and each accepted connection adds one downstream
and one upstream descriptor. `serve-and-smoke-test` (#21) is where that total is checked against
`RLIMIT_NOFILE` at startup; this issue's job is to state the arithmetic.

**What is not defended here.** Per-source-IP connection limits do not exist in M1, so one source can
occupy the whole connection cap. That is recorded in the accept-and-admission section rather than
duplicated here.

## Connection admission and accept-error handling

### What a connection flood costs us

A connection that is accepted and cannot be admitted is closed immediately, never queued, and holds
no buffer, so a flood at the cap costs one socket and one compare-exchange each, and the accept loop
pauses 1 millisecond per rejection so it cannot spin. A connection that is admitted holds one socket,
one task, one `ConnGuard`, and zero buffers until its first readable event.

### What bounds the flood

One number: `limits.max_connections` (default 10,000). Through it, at most `2 x max_connections`
descriptors and at most `2 x max_connections x 32 KiB` of read buffers.

### The residual risk, stated plainly: there is no per-source-IP limit in M1

One source address can occupy the entire connection cap, and because M1 does not parse HTTP there is
no header-read deadline to reap a client that connects and says nothing, only the idle deadline. A
client that sends one byte per idle period holds its slot indefinitely; at the default cap that costs
an attacker roughly 170 bytes per second in total to deny service to everyone else. The levers that
exist today are `limits.max_connections` (bounds the damage), `timeouts.idle_ms` (reaps silent
connections), and `timeouts.max_lifetime_ms` (an absolute per-connection ceiling, unset by default).
Per-source connection limits and a header-read deadline arrive with the rate-limiting and HTTP
milestones respectively. Do not describe M1 as slowloris-resistant.

### Accept errors are classified, never retried blindly

`EMFILE`, `ENFILE`, and `ENOBUFS` back off with doubling to a ceiling; `ECONNABORTED`, `EINTR`, and
`EAGAIN` retry immediately; anything else stops that one shard loudly. Without the classification,
descriptor exhaustion is a 100% CPU spin that serves nothing, which is a denial of service an
attacker reaches by opening connections.

## PROXY protocol

**A PROXY protocol header declares a client identity, so it is a trust plane, not merely a
parser.** `ProxyHeader::parse` (`proxy-protocol-parser`, #43) turns the first bytes of a connection
into a claimed source and destination address pair. Trusting that claim from the wrong sender lets
an attacker impersonate any client, including one that would otherwise be refused by an IP
allowlist.

**Read ONLY on a listener explicitly configured for it, and ONLY after the socket-level check.**
`ProxyHeader::parse` is called only when the listener's `trusted_cidrs` is non-empty, and only
after the connection driver has checked the socket's peer address against that list. The parser
itself takes no address and no `trusted_cidrs` parameter: it cannot make the trust decision, and
its signature is written so that omission cannot be mistaken for something it does. If the socket
peer is not in `trusted_cidrs`, the connection is closed before a single header byte is parsed.

**No sniffing, no fallback to raw HTTP.** The PROXY protocol specification requires a receiver to
be configured for exactly one of "PROXY protocol present" or "PROXY protocol absent" and forbids
guessing. If the first bytes are not a valid v1 or v2 header, the connection is closed with no
response, never re-interpreted as an HTTP request. A receiver that sniffs lets an attacker who can
merely reach the listener choose whether to be treated as a trusted proxy.

**The bounds are 107 bytes for v1 and 65551 bytes for v2, with zero allocation.** A v1 line is
refused, never parsed, past 107 bytes including its terminating CRLF. A v2 header's fixed part
plus its declared length is at most 16 + 65535 = 65551 bytes. Neither bound is enforced by
allocating a buffer of that size: `parse` returns `Partial` until the bytes the caller already
holds are enough, and reads nothing past what has arrived, so a v2 header declaring the maximum
65535-byte length while only a handful of bytes have actually arrived costs nothing beyond a
length comparison.

**TLVs are walked and discarded, never interpreted.** A v2 header's trailing TLV list is scanned
only far enough to confirm every entry's declared length fits inside the header's own declared
length; no TLV type is read for meaning anywhere in this parser. Interpreting a TLV (the AWS VPC
endpoint TLV, the SSL TLV, the authority TLV) is out of scope until a future issue does so
deliberately.

**A header from a trusted sender may claim any address, including loopback and an address inside
`trusted_cidrs` itself.** This parser has no opinion about what a trusted sender is allowed to
claim: the socket-level `trusted_cidrs` check already established the sender as trusted, and a
trusted sender is trusted to say who its client was. Refusing a loopback or in-network claim here
would break every sidecar deployment, where the immediate TCP peer legitimately is loopback.

**Two caller obligations this parser cannot enforce itself.** First, a deadline: the connection
driver MUST apply `accept_to_first_byte` to the first byte and `header_read_timeout` (10 s) to the
completion of the header, closing the connection on expiry, because a peer that declares 65535
bytes and sends one byte per minute would otherwise hold a connection indefinitely, and `Partial`
alone never expires anything. Being inside `trusted_cidrs` is not a reason to skip this deadline: a
trusted network position is exactly what a compromised sidecar has. Second, a buffer bound: the
driver's read buffer for this phase must not grow past 65551 bytes while `parse` says `Partial`,
because at that point the bytes cannot be a valid header either.
