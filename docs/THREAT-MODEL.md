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

### Chunked body and trailers (`h1-chunked-and-trailers`, #36)

**Parses:** HTTP/1 chunked transfer coding, `ChunkedDecoder`, and the trailer section that follows the
terminal `0`-size chunk. Every byte of the framing (chunk size, chunk extensions, the trailer
section's field lines) is attacker chosen; chunk **data** bytes are never inspected at all, which is
the structural property this decoder exists around, not merely an optimization.

**Unlike the head parser, this decoder keeps state across calls.** `h1-head-parser` (#34) can afford
to re-run from the start of a bounded buffer on every call because a head is capped at roughly 74 KB;
a chunked body is unbounded (a legitimate upload is gigabytes), so re-scanning it on every read wakeup
would be quadratic in the body size rather than in the (small, fixed) head size. `ChunkedDecoder` is
therefore an explicit state machine fed incrementally, and state-machine resumption bugs are exactly
where chunked parsers break in the wild: every value that can be observed mid-token (a partial
chunk-size, a partial chunk extension including mid-quoted-string, a partial trailer field) is a real,
persisted case, never an assumption that a whole token arrives in one read.

**The bounds, each with a defined refusal:**

- **Chunk size:** at most 16 hex digits, parsed into a `u64` with `checked_mul`/`checked_add`
  overflow rejection (`ChunkSizeOverflow`). No sign, no leading or trailing whitespace, no `0x` prefix
  (`ChunkSizeInvalid`). A 16-digit value of `u64::MAX` is itself accepted as a size; the body then
  never arriving is a body-size-limit and throughput-floor problem for the connection layer, not a
  framing one.
- **Chunk extensions:** capped at `max_chunk_ext_bytes` (default 256) per chunk (`ChunkExtTooLong`).
  Parsed only enough to bound and discard: an empty extension name, an unterminated quoted-string, or
  any byte outside the token and quoted-string grammars is `ChunkExtInvalid`. Extensions are never
  interpreted or forwarded; RFC 9112 Section 7.1.1 requires only that a recipient ignore unrecognized
  ones, and this decoder ignores all of them uniformly.
- **The trailer section gets a FRESH `max_header_list_bytes` and `max_field_count`**, a completely
  separate `HeaderListBudget` from the one the head already spent: a message with a trailer section
  costs up to twice the header budget, by design, rather than sharing one budget across both and
  letting a large head starve the trailer section's own legitimate use of it (or vice versa).
- **The trailer section's own re-scan is bounded by `HeadScanBudget::MAX_BYTES` (4 MiB),** the same
  budget and the same quadratic risk `h1-head-parser` (#34) already documents for the head: a trailer
  line that arrives split across many reads must be re-searched for its terminating CRLF on every
  call until it completes, so a peer drip-feeding one byte per read can otherwise buy an amount of
  re-search work quadratic in the eventual line length. `ChunkedDecoder` carries its own
  `trailer_scan: u64` counter, charged with the bytes actually searched (not the bytes consumed) on
  every pass, and refuses with `FieldLineTooLong` once the cumulative search for one trailer section
  exceeds the budget. Real trailer sections arrive in one or two reads and never come close to it; a
  drip-feeder is cut off after a bounded amount of CPU instead of looping until a deadline fires.

**Trailers are never merged into the header section.** RFC 9110 Section 6.5.1 lists the field
categories a recipient must not let a trailer override: message framing (`transfer-encoding`,
`content-length`), routing (`host`), request modifiers (`expect`, `max-forwards`, `cache-control`,
every `if-*` field, `range`, `te`), authentication (`authorization`, `proxy-authorization`, `cookie`,
`set-cookie`), and response control (`trailer`). `TRAILER_DENIED` refuses exactly those 18 field names
outright with `TrailerFieldForbidden`, never a silent drop: a request that passed an
`Authorization`-based policy on its headers must not be able to smuggle in a `Content-Length` or a
`Host` by moving it to a trailer, and a client sending one of the 18 anyway is either broken or
probing, so the message is refused rather than quietly repaired. The validated trailer section is
reachable only through `ChunkedDecoder::trailers`, a separate `FieldSection` from whatever the caller
built for the request's own header section; there is no method anywhere in this crate that merges the
two, which closes the bypass structurally rather than by convention.

**The exact end of the message is reported, not assumed.** After the terminal CRLF of the trailer
section (or of an empty trailer section, `0\r\n\r\n`), any following bytes are the first bytes of
whatever comes next on the connection: a legitimate pipelined request on keepalive, or garbage. The
decoder reports `Done { consumed }` with `consumed` naming exactly where the message ended, and
leaves the decision of what the trailing bytes mean to the caller, which owns the "is this a valid
next request" question; the decoder never assumes trailing bytes are either safe or an error on its
own.

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

## WebSocket frame relay

**What `irontraffic-ws` parses.** Every WebSocket frame header crossing the relay in either
direction, attacker chosen on the client-to-server side and origin chosen (partially trusted, per
the trust zones table above) on the server-to-client side. A proxy that forwards a malformed frame
and then goes into byte-shovelling mode has created a bidirectional channel in which the two
endpoints disagree about frame boundaries; an attacker who can control that disagreement can inject
a frame the other side attributes to us. That is the smuggling precondition restated for a
framed, bidirectional protocol instead of a request/response one.

**`irontraffic-ws` never reassembles.** The codec has no message buffer: it validates one frame
header, reports the header, and the caller forwards that frame's payload through a pooled buffer
without the codec ever holding it. A relay that reassembled fragmented messages would let an
attacker's 100-fragment message become our buffer; not reassembling means the only cost a
fragmented message imposes on us is rate, which the tunnel budget below bounds.

**Every validation rule, and the RFC 6455 clause it comes from:**

- **Masking direction (Section 5.1).** A client-to-server frame MUST be masked and a
  server-to-client frame MUST NOT be; "The server MUST close the connection upon receiving a frame
  that is not masked." An unmasked client frame is the classic cache-poisoning primitive against an
  intermediary that inspects the stream. `FrameDecoder` takes `Direction` as a constructor argument
  rather than inferring it, because the rule is not inferable from the frame itself.
- **Control frames are at most 125 bytes and are never fragmented (Section 5.5).** A fragmented
  control frame is a frame whose meaning is split across two arrivals, the same ambiguity class
  every other rule here refuses.
- **Minimal length encoding (Section 5.2).** A payload of 200 bytes encoded in the 64-bit length
  form is a second encoding of one value; two encodings of one thing is a canonicalisation
  divergence between our length parser and the origin's. A 64-bit length with its high bit set is
  refused for the same section's requirement that the bit be zero.
- **Reserved bits (RSV1 to RSV3) must be zero unless a negotiated extension claims them.** This
  milestone negotiates no extensions, so `reserved_allowed` is zero and any reserved bit set is a
  protocol error. The decoder takes the allowed mask as a parameter rather than hardcoding zero, so
  a future extension (`permessage-deflate` claims RSV1) does not require editing this check.
- **Continuation ordering.** A continuation frame with no preceding non-final data frame is an
  error, and a new data frame while a fragmented message is already open is an error. A control
  frame interleaved into an open fragmented message is legal and does not close it: RFC 6455
  permits control frames between the fragments of a data message.
- **Reserved opcodes (0x3 to 0x7, 0xB to 0xF).** A relay that forwards one forwards a value neither
  endpoint agreed the wire format defines.

**The close payload is the one payload this codec looks at, and why that is still safe.** A `Close`
frame is a control frame, so RFC 6455 Section 5.5 already bounds it to at most 125 bytes with no
fragmentation: its whole payload arrives in one frame, so validating it costs no buffer and no
reassembly. RFC 6455 Section 5.5.1 and Section 7.4 govern what `validate_close_payload` checks:

- A close payload is either empty or at least 2 bytes; a 1-byte payload is a status code split in
  half and is a protocol error.
- The first two bytes are the status code, and 1005, 1006 and 1015 MUST NOT appear on the wire:
  they are values an implementation reports internally when no code was received or the connection
  failed, and forwarding one lets a peer make the other endpoint report "no status received" for a
  close that carried a status.
- A code below 1000 is unassigned and is a protocol error. Codes in 3000 to 4999 are the library and
  application ranges and are accepted: the code is opaque to a relay, and rejecting them would break
  every application that uses one for no safety benefit.

The status code is read THROUGH the mask (`payload[i] ^ key[i]` for the first two bytes) rather than
by unmasking the buffer: nothing is written back, so the bytes the relay forwards are byte-identical
to the bytes that arrived. This is the ONE place in the codec that inspects payload content, and it
is safe precisely because the 125-byte control-frame bound makes "the whole payload is already in
hand" true without any reassembly.

**Masking is never removed or replaced.** A relay forwards a client frame to an upstream that is
also a server, so the frame stays masked with its original key. Unmasking and remasking with a
different key would produce a different byte stream for the same message, which is what makes the
relay byte-transparent rather than byte-opaque. `mask_in_place` exists only for the RFC 8441
extended-CONNECT bridge (`ws-extended-connect-bridge`, #204), for the one case where a frame arrives
unmasked over an HTTP/2 or HTTP/3 carriage and must be masked before it reaches an HTTP/1 upstream
that requires masking; it has no caller anywhere in `irontraffic-ws` itself.

**The tunnel budget.** A WebSocket tunnel is otherwise an unmetered channel through the gateway:
every other rate limit, quota and body inspection in this product operates on a request, and a
tunnel is one request that lasts for hours. `TunnelBudget` is the same lazily refilled token bucket
shape `ConnBudget` uses for HTTP/2 frames: 1000 frames of capacity refilling at 200 per second, and
16 MiB of capacity refilling at 4 MiB per second, per direction, by default. `Ping` and `Pong` cost 5
frame tokens against an ordinary data frame's 1, because they are the cheapest frames for an
attacker to generate and the ones that force a response. Exceeding either bucket closes the tunnel
with close code 1008 (policy violation) rather than dropping the frame: a silently dropped frame
produces a hung application and no signal, which is a worse outcome than a closed connection because
nothing tells the operator or the client what happened. A refill is clamped to the bucket's
capacity, so a coarse clock that jumps or steps backwards grants at most one full bucket, never more
than the configured capacity, regardless of how large the apparent elapsed time is.

**Two deliberate non-bounds, stated so a later reviewer does not add either reflexively:**

- **No UTF-8 validation of `Text` frames.** Validating text means holding a fragmented message
  until it is complete, which is reassembly, which is the thing this codec exists not to do. RFC
  6455 puts the UTF-8 validation obligation on endpoints, and a relay is not an endpoint.
- **No fragment-count limit.** A peer may send a message as a million one-byte continuation frames.
  That costs the relay no memory, because it never reassembles, so the only resource a
  fragment-count limit could protect is one this codec does not consume; adding one would break a
  legitimate streaming application for no gain. `TunnelBudget` already bounds the RATE (200 frames
  per second sustained by default), which is the resource a flood actually spends.
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

## Retry safety

**The conjunction.** `retry::predicate::retryable` decides whether one failed attempt may be
retried:

```text
retryable(req, failure) =
      matches_configured_retry_on(failure)
  AND ( idempotent(req.method) OR proves_not_processed(failure) )
  AND NOT committed(req)
  AND attempts_remaining(req)
  AND deadline_permits(req)
  AND budget.withdraw()
```

The second clause is the one that matters. Retrying a request the origin already processed
duplicates a side effect, a double charge, a double order, a double write, and that is a
CORRECTNESS bug rather than a performance one: a 503 does not prove the origin did not apply the
mutation before it failed to serialize the response, so an implementation that retries every POST
on any 5xx double-applies it silently, with no test failure that does not assert on side effects.
`proves_not_processed` is therefore the load-bearing predicate in this whole subsystem, and it
fails CLOSED: every unproven or uncertain state, including a per-try timeout, is NOT retryable,
because "we do not know what happened" is not "it did not happen".

**Three of the five proofs are upstream ASSERTIONS, not our own observations.**
`proves_not_processed` is true for exactly five things: a TCP connect or TLS handshake failure, an
HTTP/2 `RST_STREAM(REFUSED_STREAM)`, an HTTP/2 `GOAWAY` with `last_stream_id` strictly below our
stream id, an HTTP/3 `H3_REQUEST_REJECTED`, and our own connection reset before any request byte
was accepted by a write syscall for this stream. Of those, `RefusedStream`, `GoAwayUnprocessed`,
and `H3RequestRejected` are ASSERTIONS BY THE UPSTREAM, delivered in a frame the upstream chose to
send; `ConnectFailure` / `TlsHandshakeFailure` and `ResetBeforeRequest` are OUR OWN observations,
derived from what the transport actually handed to the kernel rather than from what we intended to
write.

**The accepted risk: a dishonest or buggy upstream can induce double-application.** RFC 9113
places the obligation on the server: "A server MUST NOT indicate that a stream has not been
processed unless it can guarantee that fact." We rely on that guarantee and on nothing else. An
upstream that processes a POST and then answers `RST_STREAM(REFUSED_STREAM)` (or the `GOAWAY` or
HTTP/3 equivalent) makes us retry it, and the mutation is applied twice. Nothing in this proxy can
detect that, and no configuration prevents it: the whole mechanism is "believe the peer when it
says it did not act". This is why the upstream origin is inside the trust boundary for retry
correctness, and it is the reason the proof set is never extended with anything softer, in
particular why a 503, a `RST_STREAM(INTERNAL_ERROR)`, and every 4xx (409 and 429 included) can
never prove non-processing: there is no `retriable-4xx` and there never will be, because a 409 is
proof the server DID process the request.

**The `treat_as_idempotent` escape hatch and its blast radius.** `treat_as_idempotent` is a
per-route boolean, defaulting to false, that lets an operator assert a non-idempotent method is
safe to retry anyway (RFC 9110 Section 9.2.2 contemplates exactly this: a client "SHOULD NOT
automatically retry a request with a non-idempotent method unless it has some means to know that
the request semantics are actually idempotent"). It is per route, never per cluster or global, and
it is the only knob in this subsystem that can cause a correctness bug when misused: turning it on
for an endpoint that is not actually idempotent will double-charge customers. The server emits a
startup warning naming every route that enables it.

**The trusted-connection rule for the inbound attempt count.** `retry_only_first_hop` refuses to
retry a request that arrived with `x-envoy-attempt-count` above 1, on the theory that someone
upstream of us is already retrying it. That header is in the `x-envoy-*` family stripped at
ingress on any connection the forwarding trust policy has not classified as trusted-internal, so
the attempt machine MUST treat the inbound count as 1 on an untrusted connection rather than
reading a header value from it. Both directions of getting this wrong matter: honouring a
client-supplied HIGH count would let an untrusted peer disable our retries for its own request, and
honouring a client-supplied LOW count on a request that has genuinely been retried several times
upstream defeats the only mechanism that bounds cross-layer amplification.

**The commit point is the whole property, and it is one-way.** `committed(req)` becomes true, and
is NEVER cleared again, once any response byte has been forwarded downstream, once the buffered
request body exceeds `retry_buffer_limit` (we release the buffer rather than buffering to disk or
stalling the upload), once an `Expect: 100-continue` interim response has been seen, or once the
request is a WebSocket, CONNECT, or other bidirectional upgrade. The instant any byte of the
request body reaches the upstream, or any byte of the response reaches the client, the proof that
the origin never processed the request is gone; there is no way to retract a byte already on a
socket.
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

## Server pushback (`retry-backoff-full-jitter` and `retry-server-pushback-parsers`, #103)

**What this surface parses.** `Retry-After` and `grpc-retry-pushback-ms` are chosen by the upstream origin. Both values are arbitrary bytes that may be well-formed pushback, malformed garbage, or deliberately chosen to suppress or accelerate our retries.

**Structural controls.**

- **A 64-byte parse-length cap** is checked before any template match or digit scan. The longest form this function accepts is the 29-byte IMF-fixdate, so 64 bytes is generous; the check means a multi-megabyte header value is refused after one length comparison, never scanned once per HTTP-date template.
- **The deadline caps the high side.** A pushback that does not fit the remaining request deadline minus the estimated attempt duration is refused with `PushbackExceedsDeadline`, turning a pinned request into an immediate `DoNotRetry`. This is the only cap above: a parseable pushback is used verbatim, never averaged, maxed, or minned with our computed backoff.
- **A jittered floor caps the low side.** A pushback of exactly 0 ms is replaced by a uniform draw in `[0, base_interval_ms]`, so a literal `Retry-After: 0`, an HTTP-date already in the past, or a wall clock ahead of the server's all produce a small, decorrelated delay instead of a synchronized retry-now stampede.
- **The retry budget contains acceleration.** The jittered floor spreads a "retry immediately" signal, but the `retry-budget-tps` (#102) is what prevents an accelerating pushback from becoming an amplifier. `max_attempts` is the final bound.
- **The wall-clock dependency of the HTTP-date form is isolated.** `parse_retry_after` takes `now_wall_ms` as a parameter and never reads the clock itself, so the parser remains pure and testable; the caller supplies the same wall clock the deadline layer already uses.

**Accepted risk.** A compromised upstream can suppress our retries by returning a large pushback (capped above by the deadline) or accelerate them by returning a zero pushback (capped below by the jittered floor and the budget). Those two bounds are the entire containment; the parser's job is only to be total, allocation-free, and length-bounded so the header itself cannot be the attack.

## Certificate revocation (`crl-parser-and-revocation-index`, #123)

*Status: the streaming parser and the compiled index ship in `irontraffic-tls`'s `crl` module;
nothing calls it yet, which is deliberate. The client certificate verifier that consults it is
`mtls-client-auth-fail-closed` (#124); the CRL fetcher that supplies the bytes in the first place
is later work still.*

**What `crl::parse` parses.** A CRL is remote input in the same sense a certificate itself is: a
certificate names a distribution point URL, something outside this module fetches it, and every
byte that comes back is chosen by whatever answered that request, attacker or merely compromised
or misconfigured. `parse` walks the DER once with a size-capped reader and extracts only the
issuer name, the two validity timestamps and each revoked serial, never materializing a parsed
object graph for the fields it discards (the per-entry revocation date and entry extensions). This
module exists because a mass-revocation event can produce a CRL with millions of entries and
hundreds of megabytes of DER, and handing that to `rustls-webpki` as a
`Vec<CertificateRevocationListDer>` is an O(r) linear scan on every client-certificate
verification; at r in the millions and one handshake per millisecond, that scan is not a slow
path, it is an outage.

**The signature is verified before an index is built, and the type system is what enforces the
order.** `RevocationIndex::build` takes `&VerifiedCrl<'_>`, never a `&ParsedCrl<'_>`, and the only
function that produces a `VerifiedCrl` is `verify_signature`, which consumes the `ParsedCrl` it is
given so the same parsed value cannot be handed to `build` twice, once verified and once not.
There is no path from parsed-but-unverified bytes to a built index. An unverified CRL would let an
attacker serve an empty one, silently un-revoking every certificate under that issuer, or one that
revokes everything, a denial of service, and a large unverified one would let them spend hundreds
of megabytes of memory building an index that is about to be thrown away. The expensive work, an
O(r) collection, an O(r log r) sort and a Bloom fill, runs strictly after a signature check that
costs one hash over the input and one public-key verification.

**Peak memory and the two caps that bound it.** `CrlConfig::max_bytes` defaults to 268,435,456
(256 MiB); a CRL larger than that is refused before any parse is attempted at all.
`CrlConfig::max_entries` defaults to 8,000,000; `RevocationIndex::build` counts entries as it
drains the serial iterator and refuses the whole CRL, dropping everything collected so far, on the
entry after the cap. At the default cap the narrow-serial array (serials of 16 bytes or fewer,
packed into a sorted `Box<[u128]>`) tops out at 128 MB. The Bloom prefilter behind `is_revoked` is
sized at 10 bits per entry, floored at 2,048 bytes and capped at 4,194,304 bytes (4 MiB), so it
never grows past that cap no matter how high `max_entries` is configured. At the two defaults
together, one `build` call transiently holds the input slice (up to 256 MiB, owned by the caller),
the narrow-serial vector growing toward its final 128 MB with a further transient spike while its
backing allocation doubles, and the capped Bloom fill; the issue that specifies this module puts
the combined transient peak at roughly 460 MB above the input for a single hostile but correctly
signed CRL. Two consequences follow either way:

1. `build` runs one CRL at a time on the control-plane task. Building several concurrently
   multiplies this figure; nothing inside this module enforces that, so the caller must not.
2. An operator running with a container memory limit below about 1 GB must lower `max_bytes` and
   `max_entries` together. Lowering only `max_bytes` does not bound the index (a CRL with very few,
   very long serials needs little DER), and lowering only `max_entries` does not bound the parse
   (a large `max_bytes` still admits a huge blob before it is refused).

**Residual risk: the wide-serial path is not the same shape as the narrow one.** A serial longer
than 16 bytes (legal up to RFC 5280's own 20-octet ceiling) goes into an overflow
`HashSet<Box<[u8]>>` rather than the packed array, and `max_entries` bounds the count of narrow and
wide serials combined, not the wide fraction specifically. A CRL built entirely out of maximum-length
serials is legal and routes every entry through the overflow set, whose per-entry cost (a scattered
heap allocation plus hash table overhead) is materially higher than the packed array's flat 16
bytes; the peak-memory figure above describes the narrow-heavy shape the design assumes, not this
one. `RevocationIndex::memory_bytes`, the exported `tls_crl_index_bytes` gauge, undercounts a
wide-heavy index for the same reason: it sums each wide serial's own bytes plus a fixed constant,
not the hash table's real bucket and allocator overhead.

**Fail-closed staleness, stated because it surprises everyone.** `rustls-webpki`'s client verifier
defaults are `RevocationCheckDepth::Chain` and `UnknownStatusPolicy::Deny`, and this module keeps
them, which means an intermediate whose CRL could not be refreshed fails every client certificate
on that chain, not only the ones checked while it happens to be stale. A CRL whose `nextUpdate` is
already in the past at install time is refused outright (`CrlError::AlreadyExpired`): installing a
known-stale CRL is worse than having none, because it looks like coverage while proving nothing. A
CRL that later passes its own `nextUpdate` keeps being used for `CrlConfig::stale_grace_secs`
(default 86,400 seconds, one day) with a warn alarm, and once that grace period elapses too,
`RevocationIndex::freshness` reports `Expired` and the issuer must move to fail-closed. Both the
grace period and what happens once it ends are explicit fields on `CrlConfig`, never a silent
default an operator has to go read the source to discover.

**The URL rule any CRL fetcher must apply, stated here because nothing fetches yet.** This module
takes bytes; it has no opinion about where they came from. Whatever fetches a CRL, now or later,
MUST apply the same URL policy `ocsp-staple-validation-and-updater` (#122) requires for OCSP AIA
URLs, and for the identical reason: a CRL distribution point is a URL taken out of a certificate,
so it is not operator-supplied in every deployment, and fetching it unchecked is a server-side
request forgery primitive pointed at the cloud metadata service. `crate::ocsp::validate_aia_url` is
`pub` for exactly this reuse; a fetcher that calls it on the distribution point URL but not on
every redirect target has applied only half the policy.

**Delta CRLs are refused, not partially applied.** `parse` reads only the extension OIDs inside
`crlExtensions` looking for `deltaCRLIndicator` (`2.5.29.27`); finding it is
`CrlError::DeltaCrlUnsupported` rather than an attempt to apply the delta without the base CRL it
presupposes, which would silently under-report revocations.

## The assembled proxy: what M1 defends and what it does not

This is the summary an operator reads before deploying `run` or `proxy`. It is a list of plain
statements about the assembled binary, not an argument; the sections above give the mechanism-level
detail for each of the surfaces named here.

**Defended, with the mechanism named:**

- Connection floods: a hard `limits.max_connections` cap that closes the extra connection rather than
  queuing it, plus a 1 ms pause per rejection so a flood at the cap cannot spin the accept loop.
- Memory exhaustion by a slow reader: structural one-buffer-of-credit backpressure in the forwarding
  loop, so an idle connection holds zero buffers.
- Descriptor exhaustion: a startup clamp of `max_connections` to `(RLIMIT_NOFILE soft limit - 64) / 2`,
  plus classified accept errors with a bounded, doubling backoff instead of a 100%-CPU spin.
- Silent connections: `timeouts.idle_ms`, an idle deadline with no bytes in either direction.
- Half-open connections: `timeouts.half_close_ms`, a deadline after one direction has closed.
- Configuration denial of service: a 1 MiB document cap, a 64-token YAML alias budget, a 32-level YAML
  flow-nesting budget, and a validator whose only super-linear work runs behind a 64-listener check.
- Self-amplification: the validator's `upstream_is_own_listener` check refuses an upstream address that
  is also one of this process's own listeners.
- Unclean shutdown: a two-phase drain (`Draining` then `Closing`) with a configurable graceful deadline
  and a killed-connection count reported at shutdown and in the exit code (6 when it is non-zero).

**Not defended, each with the lever that exists today and the milestone that closes it:**

- Per-source-IP connection limits do not exist, so one source can occupy the whole connection cap.
  Today's levers are `limits.max_connections`, `timeouts.idle_ms`, and `timeouts.max_lifetime_ms`
  (unset by default); closed by the rate-limiting milestone.
- There is no accept-to-first-byte or header-read deadline, because there is no request framing to
  define one against yet; closed by the HTTP milestone.
- Nothing is inspected: no HTTP parsing, no routing, no forwarding headers, no request-framing
  enforcement, so a request-smuggling payload is forwarded verbatim. Do not place this version where an
  HTTP-aware security control is assumed to exist.
- There is no TLS, so everything is plaintext on both sides.
- A local process running as the same user can join our `SO_REUSEPORT` group and take a share of the
  traffic, or use `SO_REUSEADDR` to bind a more specific address on the same port than ours and have the
  kernel deliver matching connections to it instead (see "Listening sockets and socket options" above);
  run as a dedicated, unshared user account.

**Trust boundaries.** The configuration file and the environment are trusted (they are process
identity, set by whoever operates the process). Every byte on every socket, in both directions, downstream
and upstream, is not.

## The ITPL policy expression lexer

**What `irontraffic-policy` parses.** `lex` (`crates/irontraffic-policy/src/lex.rs`) turns the
source bytes of one ITPL expression into a token stream. An ITPL expression is admitted at config
time, never on the request path, but admission input is not always operator authored: the
extensibility design anticipates a Kubernetes deployment where a policy and the limits it is
checked against arrive from a resource a namespace tenant writes. Treat every byte `lex` receives
as attacker chosen.

**Abuse cases.** A crafted expression built to hang the config thread with a pathological scan, to
allocate without bound while decoding an unclosed string literal or a long run of escapes, to
overflow an integer or a byte offset, or to panic the process on malformed UTF-8, an embedded NUL,
or an unterminated literal. A config thread that dies or hangs on one hostile expression stops
every subsequent admission from succeeding, which is why this surface is fuzzed and bounded even
though it never runs on the request path.

**Structural controls.**

- **A compiled DFA, never a backtracking matcher.** The token definitions are a `logos` enum
  compiled to a deterministic automaton at build time, so lexing one source is one linear pass with
  no input shape that goes quadratic or worse. Rewriting these definitions as `regex` patterns
  evaluated at admission time is disallowed by design, not merely undone by today's implementation.
- **Every budget is checked inside the loop, never after it.** `max_source_bytes` is checked once
  before scanning starts; `max_tokens` is checked on every token the scan produces; and
  `max_string_bytes` is checked on every decoded byte of every string literal, so an oversized or
  adversarial input is refused after a bounded amount of work rather than after the whole input has
  already been scanned or decoded.
- **`max_string_bytes` bounds one literal, not the whole expression.** A literal's decoded length is
  checked against the arena offset at which that literal started, not against the arena's running
  total, so an expression built from many small literals is bounded by its largest single literal
  rather than by the sum of all of them.
- **Decoding never expands.** Every escape sequence is at least two source bytes and produces at
  most four decoded bytes, so the decoded string arena for one expression can never exceed
  `max_source_bytes`, however many literals or escapes it contains.
- **No token owns heap memory.** `Tok` and `Spanned` are `Copy` types whose payloads are ranges into
  the source or into the decoded arena, never owned buffers, so the only growth an adversarial
  input can cause is the two `Vec`s `TokenStream` owns, both bounded by the limits above.
- **`#![forbid(unsafe_code)]`.** The crate contains no `unsafe` block, so an out of bounds read on
  an attacker chosen offset is a compile error, not a property a reviewer has to verify by hand.
- **Fuzzed directly.** `crates/irontraffic-policy/fuzz` lexes arbitrary byte input against
  `PolicyLimits::defaults()` on every fuzz lane run and asserts the token count and every span bound
  this section states, not merely the absence of a crash.

**Accepted risk.** `lex` does not call `PolicyLimits::validate()` itself. A caller that admits a
policy without validating its limits first gets whatever bound the caller passed, which may be
looser than the hard caps `docs/ITPL.md` publishes, but this is a config admission bug for that
caller to fix, not a crash in `lex`: every size bounding field of `PolicyLimits` is a `u32`, and the
source length check `lex` runs before anything else already bounds every byte offset it produces to
`u32::MAX` regardless of what limits were passed. Nothing in this crate is wired to the data plane
yet, so the blast radius of a config side defect here is a failed or delayed config push, never a
request.
