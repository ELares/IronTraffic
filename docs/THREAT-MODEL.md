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

### Upgrade handshake (`irontraffic-ws`'s `handshake` module)

**A connection becomes a tunnel only when BOTH directions validate.** After a `101` the connection
has no HTTP framing at all; whatever the two endpoints do with the bytes from then on is by mutual
agreement. If they did not actually agree, because one of them did not think this was a WebSocket,
then one side is framing WebSocket and the other is framing HTTP, and an attacker who controls the
payload controls what the second side parses as a request. A proxy that forwards a malformed
upgrade and then goes into byte-shovelling mode has created a bidirectional smuggling channel, the
same precondition the frame-relay section above states for an already-established tunnel, moved one
step earlier to the handshake that establishes one.

- **The client's `Sec-WebSocket-Extensions` offer is not forwarded upstream.**
  `UpgradeResponse::verify` refuses any extension in the `101` because we negotiate
  none, and that refusal is only correct if the upstream was never handed an offer to
  negotiate from. This field is deliberately not hop-by-hop and is not in
  `RESERVED_PREFIXES`, so it survives `strip_ingress` and a forwarding chain that does
  nothing will pass it on. Chrome and Firefox send `permessage-deflate` on every
  WebSocket connection, so forwarding it verbatim answers every browser upgrade to a
  deflate-capable upstream with `502`, by rule rather than by accident. Pinned by
  `extension_offer_survives_the_strip_and_a_negotiated_extension_is_refused`.

**Every request-side check, and what it closes:**

- **`GET` with no body.** A `POST` upgrade, or a `GET` with `Content-Length: 5`, means there are
  body bytes whose position relative to the `101` is ambiguous. We reject any upgrade request whose
  resolved framing is not `RequestFraming::Empty`.
- **`Upgrade` must be exactly one value, `websocket`, ASCII case-insensitive.** `Upgrade: websocket,
  h2c` is a request to become two things, and honouring the first while an origin honours the second
  is a disagreement. Two `Upgrade` field lines are refused for the same reason: choosing one of them
  is deciding on the client's behalf which of two disagreeing signals to honour.
- **`Connection` must contain the `upgrade` token**, parsed by `irontraffic_http::strip::connection_has_token`,
  the same tokenizer `strip_ingress` uses to decide which fields to delete, so the token that
  authorises an upgrade and the token that strips a field cannot disagree about `Upgrade ` with a
  trailing space.
- **`Sec-WebSocket-Version: 13` exactly.** Any other version means the client expects a different
  handshake; we reply `426` with a `Sec-WebSocket-Version` header, not `400`, because the client can
  act on it.
- **`Sec-WebSocket-Key` must decode to exactly 16 bytes.** The accept computation needs the exact
  bytes, and a key of the wrong length is a client that is not speaking RFC 6455.

**Every response-side check, and what it closes:**

- **`Sec-WebSocket-Accept` must equal `base64(sha1(key_bytes_ascii + GUID))`.** We recompute it from
  the key we forwarded, in constant time (`subtle::ConstantTimeEq`), and compare. An upstream that
  echoes a wrong accept value is an upstream that did not perform the handshake, which usually means
  it is not a WebSocket server and is about to interpret frames as HTTP. **This is the check that
  stops us forwarding frames to something that is not a WebSocket server**, and it is why validating
  only the request (on the theory that "the client will check the accept value anyway") is not
  enough: the client checking it protects the client, not us and not the other tenants of the
  upstream connection pool.
- **`Sec-WebSocket-Extensions` in the response must be a subset of what was requested**, and this
  milestone requests none and therefore accepts none. An upstream that negotiates
  `permessage-deflate` when nobody asked would set RSV1 on frames that the frame-relay codec above,
  configured with `reserved_allowed: 0`, would then reject mid-stream. Refusing at the handshake
  turns a confusing mid-tunnel failure into a clear one.
- **`Sec-WebSocket-Protocol` in the response must be one of the values requested**, or absent. A
  subprotocol the client did not offer is an agreement it is not party to.

**`Upgrade` and `Connection` are consumed, never forwarded; h2c is never honoured, and it is already
impossible.** Both fields are in the hop-by-hop strip set, so a downstream `Upgrade: h2c` plus
`Connection: Upgrade, HTTP2-Settings` cannot even be forwarded: the strip removes them before a
`CanonicalRequest` is built, and `CanonicalRequestBuilder::build` refuses to build a request that
still carries either. The handshake module therefore never looks for `Upgrade` or `Connection` in a
`CanonicalRequest` (doing so would find nothing, every time, and silently disable the feature); the
evidence arrives instead as an `UpgradeTokens` value the caller reads from the wire section BEFORE
the strip, and this module consumes it rather than forwarding it, synthesising a fresh upgrade
toward the upstream when the route is a WebSocket route. Bishop Fox's h2cSmuggler bypasses
path-based routing, authentication and WAF processing precisely by getting an intermediary to
forward an upgrade it should have consumed; refusing `Upgrade: h2c` at the handshake, on top of the
strip already making it unforwardable, is the second, explicit half of the remediation.

**The connection-disposal rules, which protect the OTHER tenants of the upstream pool rather than
us.** Validating the response (above) protects us: it is what stops us forwarding bytes to something
that never agreed to speak WebSocket. Disposing of the connections correctly is a separate rule that
protects everyone else sharing the upstream pool, and it holds regardless of which side failed:

1. An upstream connection that answered `101` is **never** returned to the pool, whether
   verification succeeded or failed. After a `101` the upstream has no HTTP framing, so a pooled
   socket reads the next tenant's request line as a masked binary frame, which is upstream request
   smuggling with us as the vector, exactly the hazard `upstream-pool-purity-ledger` (#45) exists to
   track.
2. A successfully verified `101` makes the connection a tunnel, owned by the tunnel until it ends and
   then closed. It is still never pooled.
3. An unsolicited `101`, one answering a request that was not a validated upgrade at all, is not
   forwarded and its connection is closed. RFC 9110 permits `101` only in response to an `Upgrade`
   request, so an unsolicited one means we and the upstream disagree about which request it just
   answered, which is the desync condition itself.
4. The downstream connection is different: we never sent it a `101`, so its HTTP framing is intact
   and it remains reusable after we answer `400`, `426` or `502` for a failed upgrade. Closing it on
   every failed upgrade would be needless connection churn on every probe.

`UpgradeRequest::parse` and `UpgradeResponse::verify` hold no socket and cannot enforce the
disposal rules themselves; they exist so the rule is written down before the caller that does hold a
socket exists. **Nothing in this corpus yet wires a connection handler to call these functions**;
they are reachable only from their own tests and the fuzz target until a follow-up issue against the
connection handler lands.

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
request forgery primitive pointed at the cloud metadata service. Neither an `ocsp` module nor a
CRL fetcher exists in this tree yet (#122 has not landed as of this writing), so this is a
requirement on work that has not been written, not a claim about a helper that can be checked
today: when #122 lands its URL-validation helper, a CRL fetcher MUST call it on the distribution
point URL and on every redirect target, since calling it only on the first URL applies just half
the policy.

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

## The ITPL parser

**What `irontraffic-policy` parses.** `parse` (`crates/irontraffic-policy/src/parse.rs`) turns
`lex`'s token stream into a flat `Ast` arena, with an explicit depth counter that refuses to
descend past `PolicyLimits::max_depth`. Same admission point, same source of hostile input as
`lex` above: an ITPL expression, and the limits it is checked against, can both arrive from a
Kubernetes resource a namespace tenant writes, never only from an operator's own keyboard. Treat
every token `parse` receives as attacker chosen, exactly like `lex`'s bytes.

**Abuse cases.** A 100,000-term boolean tree built to force deep recursion before the depth cap
can act on it; a list of lists, or a call whose argument is itself a call, built to make the parser
attribute one node's children to another's range; a list or argument list one element past
`max_list_elems`; more nodes than `NodeId` can index. The one this section exists to name
separately from the general "any of these can happen" list: a config admitted with an unvalidated,
oversized `max_depth` and then handed a deeply nested expression is a stack-overflow primitive, not
merely a slow or oversized parse.

**Structural controls.**

- **The depth counter is checked before every recursive descent, not after the tree is built.**
  `Parser::enter` increments `depth` and compares it against `limits.max_depth` before the caller
  is allowed to recurse further, so the deepest input costs `max_depth` re-entries into `expr` and
  no more; a parser that built the tree first and measured depth afterward would have already paid
  the stack cost of the failure mode `max_depth` exists to refuse.
- **Only one production recurses into the depth-tracked entry point.** `expr` is the sole
  production that re-enters itself (through a parenthesized expression, an index expression, a
  ternary branch, or an element of a list or call-argument list), so it is the sole depth-tracked
  function; the rest of the precedence chain (`or`, `and`, `rel`, `unary`, `postfix`, `primary`)
  each call the next one down exactly once per `expr` entry and never recurse on their own. Real
  Rust stack cost per unit of AST depth is therefore a small, fixed number of frames, not one.
- **Repeated unary operators and postfix chains cost one frame, not one per repetition.** `unary`
  counts leading `!` in a loop and `postfix` walks `.field`/`.method()`/`[index]` chains in a loop,
  so 8,000 leading `!` or a 1,000-segment postfix chain each cost a single stack frame regardless of
  length; without this, the depth cap alone would stand between an adversary and deep recursion from
  shapes that are long but not actually nested.
- **Every arena index is a checked `u16::try_from`, never a truncating cast.** `grep -rn " as u16"
  crates/irontraffic-policy/src/parse.rs` returns nothing: a truncated `args_from` would not fail
  loudly, it would silently point a `Call` or `List` at another node's operands, so a policy would
  evaluate a predicate nobody wrote. `elem_list`'s own element count (not the shared argument arena)
  is what a list or call's cap and length are computed from, so a nested list or a call argument
  that is itself a call cannot be miscounted as its parent's own element.
- **`#![forbid(unsafe_code)]`.** Same crate-wide guarantee `lex` relies on: no out of bounds read on
  an attacker-chosen index is possible without an explicit `unsafe` block to review.
- **Covered by the existing fuzz lane, not yet by a dedicated one.** `crates/irontraffic-policy/fuzz`
  fuzzes `lex` directly today; `parse` is not yet an independent fuzz target, so it is exercised only
  through the unit and property tests in `parse.rs`, not through the corpus-guided search the lexer
  gets. Property-testing `parse` against a grammar-shaped generator (not the lexer's byte-level one)
  is the standing coverage for now; a dedicated `fuzz_itpl_parse` target is future work, not a gap
  this section is silent about.

**Accepted risk, and why it is NOT the same shape as `lex`'s.** `parse` does not call
`PolicyLimits::validate()` itself, but unlike `lex`, the argument that makes skipping `validate()`
harmless there does not carry over here. Every size-bounding field `lex` uses is a `u32`, and the
source-length check `lex` runs before anything else already bounds every byte offset to `u32::MAX`
regardless of what limits were passed, so an unvalidated limit only loosens what `lex` accepts, it
never crashes it. `max_depth` is not a size bound on output, it is a bound on live recursion: every
unit of nesting costs one real stack frame group (`expr` plus the fixed chain beneath it), and its
only hard cap (16, published in `PolicyLimits::CAPS`) is enforced by `validate()` alone. A caller
that admits a policy, and the limits it is checked against, without calling `limits.validate()`
first, and then parses a deeply nested expression under that unvalidated `max_depth`, hands whoever
supplied the policy a stack-overflow primitive. Measured directly against a release build with an
8 MiB stack and `max_depth` raised to `u16::MAX`: 8,000 nested parentheses parse without incident;
20,000 nested parentheses overflow the stack and abort the process.

This is documented here as a precondition on `parse` and `parse_expr_at` (see their own doc
comments), not fixed by calling `validate()` from inside `parse`: `parse` takes `&PolicyLimits` by
reference from a caller that owns exactly one validation point, at config admission, before either
`lex`ing or `parse`ing with those limits; a config is validated once when it is loaded, then parsed
once per expression it contains, potentially many times over the life of the process, and folding a
second `validate()` call into every one of those parses would duplicate work the admission-time
caller already does once, for no additional safety once that caller has actually done it. The
requirement is therefore on every caller, not on this function: validate limits before parsing with
them, every time, with no exception for a namespace-tenant-supplied config. `irontraffic-policy`
already carries a fuzz lane (see the lexer section above), so unlike the lexer defect this section's
introduction responds to, this one is not a fuzz-lane gap: the risk here is a caller-discipline gap,
and the discipline it requires is written down here and on the two functions it constrains.

## Health check response parsing

**What `HttpCheckCodec` and `TcpCheckCodec` parse.** The bytes an upstream endpoint sends back to
an active health check probe, in `crates/irontraffic-resilience/src/health/http.rs` and
`crates/irontraffic-resilience/src/health/tcp.rs`. This is an unauthenticated request-response
exchange against a machine that may be compromised: a probe target is not held to the same trust
level as a normal upstream serving real traffic, because reaching it requires none of the
authentication a real request would need, and a broken or hostile probe target is exactly the
condition active health checking exists to detect. The response is therefore attacker chosen in
the same sense as anything read from a downstream socket: an infinite body, a `Content-Length`
that lies, a status line of unbounded length, a header block that never terminates, or a connection
that never sends anything at all.

**Abuse cases.** A malicious or broken upstream that answers a health probe with a multi-gigabyte
body, aiming to make the proxy retain the whole thing in memory. A status line or header block
that never reaches `CRLF CRLF`, aiming to make the proxy scan forever. A `receive` pattern list
configured with long, highly self-similar patterns (`"aaaa...ab"`), aiming to make the per-check
pattern search expensive; this one needs a cooperating configuration as well as a hostile response,
not the response alone. A response engineered to look like it ends cleanly at a message boundary
when it does not, aiming to make the proxy reuse a connection that still has unread bytes on it,
which would make the NEXT check on that connection misparse those bytes as a new status line.

**Structural controls: three independent hard caps, each with a defined behaviour at the limit.**

- **`max_head_bytes`** (default `1024`, maximum `8192`) bounds the status line plus header bytes
  `HttpCheckCodec` will scan before giving up. The 12-byte status-line prefix counts toward it.
  Exceeding it is `Fail(Protocol)` with the connection closed, checked on every byte the instant
  after it is counted, so the cap cannot be bypassed by any status-line or header shape.
- **`response_buffer_size`** (default `1024`, maximum `4096`) bounds the body bytes either codec
  will ever retain. Once the buffer is full, further body bytes offered to `on_bytes` are counted
  but never appended; the codec decides pass or fail from exactly the retained prefix and reports
  `ConnectionFate::Close`. A response of any size, delivered in any chunking, costs at most
  `response_buffer_size` bytes of memory: `infinite_body_bounded` (`health::http::tests`) and
  `tcp_codec_never_allocates_after_construction` (`health::tcp::tests`) each feed 1 MB or more of
  filler through a small buffer and assert the retained length never exceeds the cap and the
  buffer's `Vec::capacity` never changes from what `new` allocated. `prop_never_exceeds_caps`
  (`health::http::tests`) asserts the same property under proptest-generated inputs delivered
  through arbitrary chunkings. Its response generator mixes fully arbitrary byte strings with
  responses seeded with a well-formed HTTP head (a fixed passing status, and a status drawn from
  the full range), because a uniformly random byte string essentially never begins with the 5-byte
  `HTTP/` magic; without that seeding every generated case would fail in the status-line scan and
  the property would never exercise `Phase::Body`, `response_buffer_size`, or `patterns_match` at
  all, which is exactly the gap an earlier version of this section overclaimed as covered. The test
  itself asserts that a nonzero fraction of cases reach `Phase::Body` on every run, so that gap
  cannot reopen silently.
- **`timeout_ms`**, the scheduler's per-check deadline (`HealthCheckConfig::timeout_ms`, default
  `1000`, in `health/schedule.rs`, `health-check-scheduling-policy` #92), bounds the wall time a
  check may occupy regardless of how the two caps above are approached. The codecs themselves read
  no clock; the runner that owns the socket and calls `on_bytes`/`on_eof` is responsible for this
  bound. It is listed here because all three caps together are what make a hostile response cost a
  fixed, small, and bounded amount of the proxy's resources rather than an amount the peer chooses.

**Bounded pattern-match cost, not merely bounded memory.** Retaining the response bytes is not by
itself enough: `patterns_match` (`health/mod.rs`) re-scans the retained buffer with `slice::windows`
each time it runs, so if it ran on every appended byte the cost would be quadratic in
`response_buffer_size` for a pathological single-byte-at-a-time delivery. Both codecs instead run
it only when the retained body has grown by at least 64 bytes since the last run, or when the
buffer just filled, or once on `on_eof`; that batching turns the worst case into
`(response_buffer_size / 64) * response_buffer_size * S`, where `S` is the sum of the configured
`receive` pattern lengths. Validation caps `S` at `512` and `response_buffer_size` at `4096`, which
bounds the worst case at roughly 134 million byte comparisons per check, a number that needs both a
hostile upstream (to keep re-sending the same near-match prefix) and a pathological configuration
(long, self-similar patterns) to approach; an operator running into this cost in practice should
shorten the configured pattern. The bound holds independent of how many endpoints are configured,
because it is a per-check cost and checks run on the check runner's own task, never on the control
task that also owns the ejection and uneject timers.

**The codec-pool memory bound.** Neither codec is allocated one per endpoint. `HttpCheckCodec` and
`TcpCheckCodec` are drawn from a pool sized to `max_concurrent_checks` and `reset` between checks,
so total retained memory is `max_concurrent_checks * (response_buffer_size + a few dozen bytes of
state)`, independent of the endpoint count `H`. One codec per endpoint instead would cost
`H * response_buffer_size`, which at the endpoint ceiling of `1_048_576` and the maximum buffer of
`4096` is 4 GB of idle buffers; at a routine `H = 50_000` with the default `1024` byte buffer it is
still 51 MB of memory in use for microseconds per interval. `reset()` clears parse state and keeps
the buffer's allocated capacity, so drawing a codec from the pool for the next check is
allocation-free.

**The close-on-unresolved-framing rule.** Neither codec decodes `Content-Length` or
`Transfer-Encoding`, and neither decodes chunked transfer coding: `HttpCheckCodec` scans only far
enough to find `CRLF CRLF` and then reads up to `response_buffer_size` body bytes, never resolving
where the body actually ends. Because of that, the codec can prove a connection is at a message
boundary, and therefore safe to reuse, in exactly three cases: the request method was `HEAD`, or
the response status was `204`, or the response status was `304`. All three are responses RFC 9110
guarantees carry no body. Every other `Done` reports `ConnectionFate::Close`, including a passing
check whose body matched every `receive` pattern before the buffer filled, because stopping early
still leaves an unknown number of body bytes unread on the socket. `TcpCheckCodec` has no framing
signal at all and reports `ConnectionFate::Close` unconditionally. Reusing a connection whose
framing did not resolve would let the next check's `HttpCheckCodec::on_bytes` parse the previous
response's leftover body bytes as a new status line, which fails as `Fail(Protocol)` and looks
exactly like an upstream that broke between checks; always closing in the unresolved case is the
only choice that cannot produce that false signal. This is the same connection-purity rule IronTraffic
decision ledger entry 19 states for the forwarding data plane, applied here to the health-check
connection pool.

**Fuzzing.** `fuzz_health_response_parser` (`crates/irontraffic-resilience/fuzz`) drives both
codecs with an `Arbitrary`-derived response byte stream delivered through arbitrary chunk
boundaries, against a spec whose method, status ranges, `receive` patterns, and both caps are
mapped into the valid range rather than passed through unmodified, so every generated input reaches
`on_bytes`/`on_eof` instead of being rejected by `HttpCheckSpec::validate` before the parser runs.
It asserts the retained body never exceeds `response_buffer_size`, the buffer never reallocates
after construction, and both codecs always reach `Done` once `on_eof` is called. Reaching
`on_bytes`/`on_eof` is not the same claim as reaching the parser: an earlier version of this target
fed `HttpCheckCodec` an unconstrained arbitrary byte stream, which almost never begins with the
5-byte `HTTP/` magic, so 500,000 runs completed with the HTTP half never getting past byte 12 while
every one of those runs still technically satisfied "reaches on_bytes/on_eof". `build_http_response`
now gives each generated response an `Arbitrary`-chosen shape (unmodified, a partial `HTTP/1.1 `
prefix, or a full well-formed head with an arbitrary status), so both a bare stream and a real head
are explored in the same corpus, and a process-lifetime counter fails the run outright if the HTTP
half ever again goes back to parsing zero status lines after a meaningful number of executions. The
TCP half is intentionally left driven by the unmodified byte stream: `TcpCheckCodec` has no phase
machine to gate on an HTTP-shaped prefix, so reshaping its input would only cost it entropy.

## Session resumption (`cluster-derived-session-ticketer`, #120)

*Status: `ClusterTicketer` ships in `irontraffic-tls`'s `ticket` module, constructible and fully
tested, but installed into no `ServerConfig` yet. `mtls-client-auth-fail-closed` (#124) is the first
issue able to supply the 16-byte client-authentication context this ticketer requires, and is
therefore the issue that installs it.*

**The ticket format.** `ticket = name_e (16 bytes) || nonce (24 bytes) ||
XChaCha20-Poly1305(key_e, nonce, aad = name_e, plaintext)`, minimum 56 bytes (name plus nonce plus
16-byte AEAD tag), maximum 4,096. Both `key_e` and `name_e` are HKDF-SHA384-derived from one
32-byte cluster root plus a 16-byte context plus an 8-byte big-endian epoch number, never
distributed over any channel: `prk = HKDF-Extract-SHA384("irontraffic/ticket-root/v1", root)`,
`key_e = HKDF-Expand-SHA384(prk, "irontraffic/ticket/v1" || context || be64(e))`, `name_e` the same
with a distinct info label. `e = floor(unix_seconds / rotation_secs)`, and a node accepts the
current epoch plus the two before it, a minimum 12-hour window at the default 6-hour rotation.
Deriving rather than distributing means every node in a fleet holds the same key at the same time
with zero coordination beyond clocks agreeing within a few hours, and rotation happens fleet-wide
simultaneously by construction; every incumbent this design was compared against (Envoy, nginx,
Traefik) instead distributes key material or defaults silently to a per-process key that turns
every cross-node resumption into a full handshake, invisibly, until a traffic spike makes the CPU
cost visible.

**What the three-epoch window bounds, and what it does not, stated because the difference is the
whole security story.** A leaked derived epoch key `key_e` is useless outside its own three-epoch
acceptance window: 12 to 18 hours at the default rotation. It does **not** bound the damage from a
leaked root. Every epoch key that has ever existed or ever will is computable from the root, so an
attacker who records ticket traffic for months and later obtains the root can decrypt every one of
those recorded tickets and recover the resumption master secret of every resumed session in the
recording. This is not forward secrecy with respect to the root; describing it that way anywhere in
operator-facing documentation is a defect. The consequences, all non-optional:

- The root is the highest-value secret in this product. It is stored sealed
  (`sealed-secret-blobs-and-secret-refs`, #333), never written to a log, never returned by the admin
  API (`TicketRoot`'s `Debug` impl prints only an 8-byte fingerprint, never the root), and zeroized
  on drop.
- The root is rotated on a schedule, not only after a suspected compromise. The recommended cadence
  is 90 days, using the two-root overlap `ClusterTicketer::with_previous_root` implements: derive
  from both roots, accept either for decryption, encrypt only with the new one. Rotation is what
  converts "unbounded retroactive decryption" into "at most one rotation period of retroactive
  decryption".
- After a suspected root compromise, rotating the root is the break-glass action, and
  `with_previous_root` must **not** be called with the compromised root in that case: including a
  compromised root in the overlap keeps every ticket it issued decryptable, which is the opposite of
  the point of rotating away from it. The operator command is
  `task-leader-lease-fencing-and-ticket-root-rotation` (#334).

**The context binds a ticket to the configuration it was issued under, closing CVE-2025-68121.** A
resumed TLS 1.3 handshake sends no certificate and does not re-run the client-certificate verifier,
so a ticket issued while one trust bundle was live would otherwise still be accepted after the
bundle changed. That is exactly CVE-2025-68121 in Go's `crypto/tls` ("unexpected session
resumption": a resumed handshake succeeds although `Config.ClientCAs` or `RootCAs` changed between
the original and the resumed handshake; CVSS 9.1; Traefik was an affected downstream under
GHSA-gv8r-9rw9-9697). `ClusterTicketer::new` takes a 16-byte `context` as a mandatory constructor
argument, mixed into both the key and key-name derivation, so a ticket encrypted under one context
produces a key name nothing matches under a different context: `different_context_never_decrypts`
is the test that is this correction, not a comment. `sni-server-config-selection` (#119) supplies 16
zero bytes for `ClientAuthKind::None` and `TrustAnchors::id()` otherwise, so a ticket never
resumes across a client-certificate trust-bundle change. The failure mode when the context does not
match is `decrypt_unknown_key`, which falls back to a full handshake, not an error: a client that
cannot resume simply re-authenticates from scratch, and the client-certificate verifier runs again.
That covers a ticket that outlives a live bundle rotation; it is a separate belt from a second one
added by `mtls-client-auth-fail-closed` (#124)'s own PR review (#773 BLOCKING 1): both
`TlsServerConfig::compile` and `TlsServerConfig::compile_with_client_auth` compare the ticketer they
were handed against the context the CONFIGURATION they are compiling actually calls for (16 zero
bytes, or `auth.anchors().map(TrustAnchors::id)`), and refuse to compile at all
(`ListenerError::TicketerContextMismatch`) on a mismatch, via `ClusterTicketer::context()`. That
catches a caller wiring the wrong ticketer to the wrong listener at configuration time, before any
handshake and before any ticket is ever minted, which is a different failure than a
previously-issued ticket surviving a later bundle rotation.

**Residual risk: resumption skips certificate re-validation, so a ticket can outlive a
certificate.** A resumed TLS 1.3 handshake sends no certificate, so a client that resumes does not
re-validate the server identity, and a certificate that was replaced, expired, or revoked in the
last three epochs is still effectively in force for clients holding a valid ticket. The exposure is
bounded by the acceptance window (12 to 18 hours at the default rotation), and shortening it means
shortening `rotation_secs`, which also shortens the resumption benefit this design exists to
capture. An operator who must cut resumption off immediately after a key compromise rotates the
ticket root; that is the only lever, and it is documented as such here rather than left for an
operator to discover mid-incident. This is a property of TLS session resumption in general, not a
defect specific to this design, and is written down so that "we revoked the certificate" is never
mistaken for "no client can still use it".

**Structural controls on the decrypt path, which is fully attacker controlled.** `decrypt` never
reads a lifetime, an epoch, or any other decision input out of the ticket beyond the 16-byte key
name and the 24-byte nonce, both of which are authenticated (the name as AEAD associated data, the
nonce as the AEAD nonce itself); rustls's own `ProducesTickets` documentation requires exactly this
("this decryption must be side-channel free, panic-proof, and otherwise bullet-proof", and the
lifetime "must be implemented by key rolling and erasure, not by storing a lifetime in the
ticket"). Key-name comparison against all six candidates (2 roots x 3 epochs) runs in constant time
with `subtle::ConstantTimeEq` and no early exit, so an attacker cannot use timing to probe a key
name byte by byte. `ticket/decrypt_unknown_key_near_miss` and `ticket/decrypt_unknown_key` are
benchmarked against each other for exactly this reason, but the binding property is the code
review of step 4 finding no `break` and no `==`, not a single quantitative ratio: across repeated
runs on non-isolated development hardware the two ids tracked each other within about 10%,
sometimes with the near miss id measuring higher and sometimes lower, which is consistent with
comparing two structurally identical code paths under ordinary measurement noise rather than with
a timing side channel. The recorded medians and the per-run ratio are in the PR body that shipped
this section, not restated here as a single number this file cannot keep current.
`decrypt` allocates nothing on the unknown-key path (the path an attacker drives): key selection
happens before the AEAD is ever opened, so a flood of bogus tickets costs six constant-time
comparisons and no heap traffic, enforced by this module's `//! HOT PATH` marker under
`scripts/invariant-lints.sh`'s `hot-path-allocation` rule.

## 0-RTT early data (`early-data-policy-and-replay-filter`, #121)

*Status: `crate::early_data::evaluate` and `crate::replay::EarlyDataFilter` ship in
`irontraffic-tls`, constructible and fully tested, but reachable from no caller yet. `enabled`
defaults to `false` and `EarlyDataConfig::effective_max_early_data_size` is `0`, so nothing behaves
differently until both the unpublished data-plane slug `early-data-request-wiring` and the
listener-compilation call to `EarlyDataConfig::is_permitted_with` exist.*

**Off by default.** A listener negotiates 0-RTT only when an operator explicitly sets
`earlyData.enabled: true`, and even then `maxBytes` defaults to 16,384 bytes and is hard capped at
65,536.

**What an attacker who captures early data can do.** 0-RTT data has no forward secrecy and no
replay protection at the TLS layer (RFC 8446 section 2.3 and appendix E.5): an attacker who
recorded a client's 0-RTT `ClientHello` can resend it, and every node in the fleet that accepts
0-RTT is a candidate target. What that buys the attacker is bounded by what this crate ever agrees
to serve from early data at all: a `GET` or `HEAD` request with no declared body and, by default,
no query string, on a route the operator explicitly marked idempotent and that the configuration
compiler did not force back to `deny` for containing a mutating filter, a counter increment, or a
stateful authorization decision. Replaying such a request is not an action whose meaning changes
because it ran twice.

**The idempotency restriction is the security boundary; the Bloom filter only reduces volume.** A
single node's replay filter cannot see a ticket replayed to a different node before its own answer
is known, and no per-process or best-effort cluster mechanism closes that window completely without
adding a network round trip to the 0-RTT path, which would delete the entire latency benefit 0-RTT
exists to provide. `crate::replay::EarlyDataFilter` is sized so a legitimate client's false-positive
cost (one extra round trip) is rare, comfortably under 1 in 100,000 at the default capacity (measured
under `1e-5`; the derived figure at the blocked layout's parameters is nearer `5e-7`), and an adversarial
attempt to overfill the filter degrades it toward MORE rejections, never toward accepting a replay
it would otherwise have caught: fail closed in both the ordinary and the adversarial case.

**The window asymmetry between the filter (3 to 6 hours) and the ticket (12 to 18 hours).** The
replay filter's two generations, rotating every `replayRotateSecs` (default 3 hours), remember a
ticket for between one and two rotation periods. A ticket from
`cluster-derived-session-ticketer` (#120) stays decryptable for three epochs, 12 to 18 hours at that
ticketer's own default rotation. A replay presented after the filter has forgotten the ticket, but
before the ticket itself has expired, is therefore possible by construction, not by accident.
Widening the filter to cover the full ticket window would cost 3 to 6 times the memory and would
still not close the cross-node case above, which is why the method restriction, not the filter, is
what this section calls the security boundary.

**Mutual TLS and early data are mutually exclusive.** A resumed TLS 1.3 handshake does not
re-present or re-verify a client certificate, so early data on a listener that requests or requires
one would be simultaneously authenticated (by the identity restored from the ticket) and
replayable, the one combination this design refuses to create. `EarlyDataConfig::is_permitted_with`
refuses that configuration at compile time once a later issue wires the call in, and
`crate::early_data::evaluate` refuses it again at run time as defence in depth for as long as that
call is not wired in yet.

See `docs/tls/EARLY-DATA.md` for the operator-facing statement of all seven admission conditions,
the two `Early-Data` header rules (including the deliberate deviation from RFC 8470 section 5.1),
and the `425 Too Early` retry.

## gRPC health checking

**What `health::grpc` and `health::grpc_mode` parse.** The gRPC length-prefixed frame and the
protobuf `HealthCheckResponse` body an upstream `grpc.health.v1.Health` service sends back to an
active `Check` or `Watch` probe, in `crates/irontraffic-resilience/src/health/grpc.rs`, and the
`grpc-status` trailer value that accompanies it. As with the HTTP and TCP checkers above, a probe
target is not held to the same trust level as a normal upstream serving real traffic: reaching it
requires none of the authentication a real request would need, and a broken or hostile probe target
is exactly the condition active health checking exists to detect. Unlike the HTTP and TCP checkers,
a `Watch` probe is a long-lived stream rather than one bounded request-response exchange, which adds
two abuse surfaces neither of the other two codecs has: an unbounded number of open streams, and an
unbounded number of messages on one already-open stream.

**Abuse cases.** A malicious or broken upstream that declares a gRPC frame length of `0xFFFFFFFF`
(4 GiB) in the 5-byte prefix, aiming to make the proxy allocate or buffer toward that length before
ever checking it. A `HealthCheckResponse` body engineered with deeply nested or enormous
length-delimited unknown fields, aiming to make the protobuf reader walk off the end of the message
or loop forever. A backend that answers `Watch` and then never sends another message, aiming to pin
a stream, a connection, and a TLS session open forever while looking alive. A backend that instead
pushes `HealthCheckResponse` messages continuously, aiming to spend the check runner's CPU on decodes
and mode-machine updates. An operator configuration, or a compromised control plane, that would open
one `Watch` stream per endpoint with no process-wide ceiling, aiming to exhaust file descriptors
across the whole proxy through the health-check subsystem alone, which would take request serving
down with it.

**Structural controls: the prefix-enforced 256-byte cap and its fixed reassembly buffer.**

- **`grpc_frame_admissible`** is the control that makes the 4-GiB-declaration abuse case above
  unrepresentable rather than merely rejected late. It takes exactly the 5-byte prefix, before any
  message byte is read, and returns `Err(GrpcDecodeError::TooLong)` the instant the declared length
  exceeds `MAX_MESSAGE_LEN` (256), or `Err(GrpcDecodeError::Compressed)` if the flag byte is nonzero.
  The runner MUST call this the moment it has five bytes and MUST NOT buffer a sixth until it
  returns `Ok`, so the reassembly buffer is a fixed `[u8; 5 + MAX_MESSAGE_LEN]` (261 bytes) that never
  grows regardless of what the peer declares: `frame_admissible_bounds` (`health::grpc::tests`)
  asserts a declared length of `u32::MAX`, and one of exactly 257 (one byte over the cap), both
  return `Err(TooLong)` from the prefix alone, and that a declared length of exactly 256 is accepted,
  proving the cap is reachable from five bytes without needing to buffer the message body first.
- **`decode_health_response`** re-checks the same 256-byte cap on the length embedded in a complete
  frame (`decode_too_long`, `health::grpc::tests`), which matters for any caller that already has a
  whole frame in hand rather than streaming it through the prefix check above; the `TooLong`
  comparison runs before the arithmetic that computes the message's end offset, so a declared length
  of `u32::MAX` cannot overflow that computation on any target.
- The protobuf reader inside `decode_health_response` never reads past the message end: every varint
  read is bounds-checked one byte at a time and is capped at 10 continuation bytes
  (`decode_bad_varint`), and every length-delimited or fixed-width field advances the read position
  with `checked_add` filtered against the message length before the position is trusted again
  (`decode_bad_length`). The read loop always advances by at least one byte before it can loop again,
  which is what makes it terminate on adversarial input rather than spin (`prop_decode_never_panics`
  and the `fuzz_grpc_health_decode` fuzz target both drive this with generated and fuzzed byte
  strings and assert it always returns rather than hangs). Wire types 3, 4, 6, and 7 (the removed
  `group` encoding and the unassigned remainder of the 3-bit wire-type space) are rejected outright
  as `GroupWireType` rather than given any bespoke handling (`decode_group_wire_types`).

**Two more bounds for the `Watch` stream, which is unbounded in both directions that a bounded
request-response exchange is not.**

- **`MAX_WATCH_STREAMS`** (4096) bounds the number of `Watch` streams open at once across the whole
  process. This is a runner-owned budget rather than something `health::grpc`/`health::grpc_mode`
  enforce directly, because neither module speaks HTTP/2 or owns a connection; the constant is
  exported for the runner (`dataplane-resilience-wiring`, outside milestone 5) to enforce. Past the
  budget the runner constructs the endpoint with `prefer_watch: false`, which
  `prefer_watch_false_never_opens` (`health::grpc_mode::tests`) proves keeps `GrpcModeMachine` in
  unary `Check` polling for at least 100 consecutive checks rather than ever attempting to open a
  stream: a `Watch` stream is a connection, a TLS session, and an HTTP/2 stream held open for the
  endpoint's whole life, so falling back to polling under the budget is a freshness cost, while
  opening one per endpoint with no ceiling would be a file-descriptor exhaustion outage that also
  takes down request serving.
- **`MAX_WATCH_MESSAGES_PER_INTERVAL`** (100) bounds how many `HealthCheckResponse` messages the
  runner accepts from one open `Watch` stream per check interval, which is what makes the
  continuous-push abuse case above cost a fixed amount of CPU rather than an amount the peer
  chooses. This is likewise runner-owned (the sans-IO codec has no notion of "per interval" since it
  reads no clock), but the mode machine's contribution is that going over the limit is defined to
  report `Fail(Protocol)` and move the endpoint back to `WatchDesired`, not `UnaryFallback`: a
  backend that pushes without bound is treated the same as any other dead-or-hostile stream
  (retried as a stream once) rather than permanently downgraded to polling, which
  `network_close_retries_watch` (`health::grpc_mode::tests`) exercises for the general
  network-failure case this shares its mode transition with.

**A network failure never becomes a sticky fallback; only `UNIMPLEMENTED` does.** This matters for
the abuse surface because a hostile or overloaded upstream that can merely cause a `Watch` stream to
drop (far easier than answering `UNIMPLEMENTED` correctly) gains nothing from doing so:
`on_watch_closed` routes a non-`UNIMPLEMENTED` closure back to `WatchDesired`, and only
`unimplemented: true` (which requires the peer to have actually and correctly answered gRPC status
12) moves the endpoint to sticky `UnaryFallback` for `watch_retry_after_checks` checks before `Watch`
is retried. `unimplemented_is_sticky` and `network_close_retries_watch`
(`health::grpc_mode::tests`) each exercise one side of this distinction and would fail if the two
were conflated.

**Fuzzing.** `fuzz_grpc_health_decode` (`crates/irontraffic-resilience/fuzz`) drives
`decode_health_response` with an `Arbitrary`-chosen mix of an unmodified byte stream, an arbitrary
payload wrapped in a syntactically valid 5-byte prefix, and a fully well-formed frame carrying one
arbitrary status value, and drives `parse_grpc_status` with an `Arbitrary`-chosen mix of an
unmodified byte stream and one mapped byte-for-byte into ASCII digits. Both mixes exist for the same
reason `fuzz_health_response_parser`'s `build_http_response` does (#739 BLOCKING 2): a uniformly
random byte string essentially never carries a valid 5-byte prefix, let alone a valid protobuf
message behind it, or a valid ASCII-decimal `grpc-status` value, so a generator of nothing but
arbitrary bytes would leave the wire-type dispatch loop, the varint reader, and the status
accumulation loop unexercised. Two process-lifetime counters, mirroring
`assert_http_half_is_reached`, fail the run outright if either target ever again goes back to
completing zero real parses after a meaningful number of executions.

## TLS termination

The listener's acceptor is the first thing an unauthenticated peer reaches. Before any policy
applies, before any certificate is chosen, before the peer has proved anything, it can send bytes
that cost us asymmetric cryptography. Everything below follows from that.

### The attack surface an unauthenticated peer reaches

A peer that has completed a TCP handshake and nothing else can:

- open a connection and send nothing at all
- send a partial `ClientHello` and stop
- send bytes that are not TLS
- send a `ClientHello` with any server name it likes, including names it has no relationship with
- send a `ClientHello` with no server name
- repeat all of the above at whatever rate its network allows

None of these require a certificate, a credential, or a prior relationship. The design assumption
is that every one of them arrives continuously.

### Fail-closed selection

Policy selection resolves the presented server name through the same normalization and the same
two probes as certificate selection: one exact match, then one wildcard match on the parent
domain, case-insensitive, ignoring one trailing dot. A name that matches nothing rejects the
handshake unless the operator explicitly configured a fallback. No SNI rejects unless a no-SNI
policy is explicitly configured. A malformed or truncated `ClientHello` is a hard error and is
never treated as "no SNI".

The threat this closes is a peer choosing which policy applies to it. If option lookup and
certificate lookup disagreed about what "the same name" means, or if a miss inherited a
permissive default, then presenting a name that matches a certificate but misses its policy would
select the default instead. Traefik shipped that four times: CVE-2026-32305 (fragmented
`ClientHello` read as empty SNI), CVE-2026-48491 (wildcard mappings ignored), CVE-2026-53622
(case-sensitive lookup), and Caddy shipped the adjacent one, CVE-2026-27586 (mTLS failing open on
an unreadable CA file). All four are fail-open. Here a miss is a rejection.

A startup lint refuses, at configuration time, an exact binding and a covering wildcard that
disagree on client authentication; a fallback or no-SNI policy weaker than the strongest binding;
and duplicate bindings. Those are configuration errors rather than runtime surprises.

### Handshake-flood limits

The cost asymmetry is roughly 500 bytes and one `write()` for the attacker against one signature
and one key agreement for us. Four limits bound it: a handshake deadline started at accept time,
a cap on handshakes in progress per listener, a cap per source address, and a cap on `KeyUpdate`
messages per connection. A fifth bounds how many bytes are buffered while waiting for a complete
`ClientHello`.

The acceptor is sans-IO and enforces only the byte cap; it has no clock, no connection table and
no view of the peer address. The other four are enforced by the accept loop, and
`docs/tls/SNI-POLICY.md` states that contract. This is a real residual risk until that loop
exists: the limits are values and a written obligation, not running code.

### The cross-name authority re-check

A listener may bind different names to different client-authentication requirements. That is the
mixed public-and-mTLS deployment the design exists to support, and it cannot be linted away,
because the names are disjoint and each binding is individually correct.

The hole: an attacker completes a handshake under a permissive name, then sends a `Host` header
naming a name that requires a client certificate. A certificate-scope check does not catch this,
because one wildcard certificate legitimately covers both names. The connection is authorized for
the authority; it is not authorized for that authority's client-auth requirement.

Every request must therefore be re-checked against the requirement bound to its authority, and
refused when the connection authenticated more weakly. Per request, not per connection: the
authority can change between requests on one connection. This is enforcement the HTTP layer owns;
until it exists, a listener that mixes client-authentication requirements across names is
bypassable by anyone who can send a `Host` header, and that is a residual risk to be aware of.

### Residual risks, stated plainly

- The four handshake-flood limits are not enforced by any running code yet; the accept loop that
  must enforce them is separate work.
- The per-request authority re-check is not enforced by any running code yet; the HTTP layer that
  must enforce it is separate work. Until then, do not deploy a listener that mixes
  client-authentication requirements across different names.
- No client-certificate verifier exists yet, so every compiled configuration authenticates no
  client. The divergence lint reasons about requirement labels, and until verifiers land there is
  only one label in use, which means the lint is correct but has nothing yet to distinguish.
- Session resumption is not bound to the client-auth identity yet, because no ticketer is
  installed. When one is, it must carry that context or CVE-2025-68121 is reproduced.
- A peer still chooses which name it presents, so it chooses which of the configured policies it
  is measured against. Fail-closed selection bounds that to the set the operator configured; it
  does not remove the choice.
- A handshake still costs a signature before any peer identity exists. Every one of the controls
  in this section bounds how much of that cost an attacker can buy; none of them make the cost
  zero, because the asymmetry between an attacker's `write()` and our signature is inherent to
  terminating TLS, not a bug to be fixed.
- 0-RTT replay cannot be fully prevented in a distributed system: a 0-RTT `ClientHello` can be
  replayed to more than one node before any single node can prove it has seen that ticket before,
  and no coordination-free anti-replay scheme closes that window completely. This design does not
  negotiate 0-RTT today, so the risk is not live, but the residual risk is recorded here rather
  than left implicit for whenever it is. `early-data-policy-and-replay-filter` (#121) owns this
  paragraph and the policy that must exist before 0-RTT is turned on.

## OCSP stapling

**No OCSP fetch, DNS lookup or socket operation ever happens on the handshake path.** The only OCSP
work a handshake does is copying an already-validated staple byte slice that rustls sends;
`irontraffic-tls`'s own module docs on `ocsp.rs` and `ocsp_update.rs` state this as a structural
property, and `rg -n 'reqwest|hyper|ureq|isahc|curl|TcpStream|std::net' crates/irontraffic-tls/`
finding nothing is the same property, checked mechanically rather than by convention. Turning one
inbound handshake into one outbound HTTP request would be a connection amplification attack against
both this process and the CA operating the responder: an attacker who can open handshakes for a
must-staple name would otherwise be able to make this process generate an unbounded number of
outbound fetches at will, at both our expense and the responder's. `OcspUpdater::tick` is instead
driven only by the control-plane loop, on a blocking-capable task, never on a data-plane thread,
because each fetch blocks for up to 5 seconds.

**The AIA URL comes out of a certificate, and a certificate is not always operator-written.**
Certificates arrive from the configuration plane, from an ACME CA, and in Kubernetes from a Secret a
namespace owner controls, so "the operator wrote it" is not true in every deployment. A certificate
carrying `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as its OCSP AIA URL
turns the staple updater into a cloud-metadata fetcher; one carrying `http://10.0.0.5:6379/` turns it
into a request generator against an internal service; one carrying `file:///etc/shadow` depends
entirely on what the underlying HTTP client does with an unexpected scheme. This is the standard
shape of server-side request forgery, with a certificate as the delivery vector instead of a request
parameter.

`ocsp::validate_aia_url` is the gate, and it runs before **every** fetch, including every redirect
hop, because a policy that lives only inside the fetcher is a policy the next fetcher forgets:

1. The URL must parse, must be at most 1,024 bytes, and its scheme must be exactly `http` or
   `https`. Everything else, including `file`, `ftp`, `gopher` and a schemeless string, is refused.
   RFC 6960 responders are HTTP.
2. There must be no userinfo component (`http://user:pass@host/`), a credential-smuggling and
   host-confusion vector.
3. The port, if present, must be 80 or 443. A responder on port 6379 is not a responder.
4. The host must not be an IP literal in, and (the fetcher's job, below) must not resolve to,
   loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`, where cloud metadata
   lives), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), unspecified
   (`0.0.0.0`, `::`), or multicast.
5. `OcspConfig::allow_private_responders` (default `false`) relaxes rule 4 only, for the operator
   running an internal CA with an internal responder. It never relaxes rules 1 to 3.

**The DNS-rebinding re-check is split across two components on purpose.** `validate_aia_url` checks
the URL's own literal host, which closes the case where the certificate names an IP address
directly. It cannot close the case where the certificate names an innocuous hostname whose DNS
answer changes between the check and the connection: the fetcher (the in-tree implementation is the
unpublished slug `ocsp-http-fetcher`) is contractually required to re-check the **resolved** peer
address against the same private-address rules immediately before connecting. Neither check alone
closes DNS rebinding; both are required, and the fetcher contract states this obligation rather than
leaving it to be inferred from the URL check having already run once.

**The per-tick fetch budget bounds a restart-shaped flood.** After a restart, every tracked
certificate is due for a refresh at once. Without a cap, one `OcspUpdater::tick` call over a
100,000-certificate store would start 100,000 fetches: a self-inflicted outbound flood, a
CA-hammering event that risks the deployment being rate-limited or blocked outright, and a single
call that blocks its caller for hours at 5 seconds per fetch. `OcspConfig::max_fetches_per_tick`
(default 8) bounds how many fetches one `tick` call may start; entries beyond the budget keep their
scheduled time and are picked up by a later tick, oldest due first, so no certificate can starve.
The initial due time for a freshly tracked certificate is also spread over
`OcspConfig::min_interval_secs` rather than set to "now", so a restart does not synchronise the
whole store onto one instant, and two nodes restarting together do not fetch in lockstep either.

**A must-staple certificate is refused at install, not discovered at handshake time.** RFC 7633's
`id-pe-tlsfeature` with `status_request` obligates a server to staple a response for that
certificate on every handshake; serving it without one is a protocol violation an inspecting client
may treat as a failure on its own. `CertUpdateCoalescer::submit` refuses an `Install`, `Replace` or
`SetDefault` of a must-staple credential with no OCSP staple attached
(`CertError::MustStapleWithoutStaple`), in the same eager-validation step that already checks
names, so the credential never enters the pending list and never becomes part of a published index
at all, through any of the three update kinds that can publish one; the previously installed
material for that name keeps serving. The check lives at `submit` rather than at flush time
because a must-staple credential with no staple is a permanent property of that submission, not a
transient one: it will
never become valid by waiting, and rejecting it at flush time would sit it in the pending list and
abort every later flush behind it, freezing the whole store at its last good generation. Symmetrically,
`OcspUpdater::tick` treats a must-staple certificate whose live staple has gone stale (past
`nextUpdate` plus clock skew, with no successful refresh) as a reason to remove the credential from
the index, so a name with another credential falls through to it and a name with none fails the
handshake instead of serving a certificate the extension says must never appear without a staple.

## Client authentication (`mtls-client-auth-fail-closed`, #124)

**What a peer reaches before any identity exists.** A `ClientHello` is unauthenticated by
construction: the `CertificateRequest` a client-authentication listener sends back, and the identity
of every trust anchor named in it, are both produced before the peer has proven anything at all.
Everything downstream of that first message, chain validation and revocation, only ever runs against
bytes an attacker chose.

**The fail-closed construction.** Caddy shipped CVE-2026-27586: mTLS silently failed open when the CA
certificate file was missing or malformed, because the type an implementation typically reaches for
here, an optional root store plus a boolean "require a certificate", can represent the broken state
"require authentication but trust nothing" with no error. Here that state is not representable.
`TrustAnchors` cannot be constructed empty: its constructor returns a `Result`, and an empty,
missing, or unparseable bundle is an `Err` at configuration compile time, not a runtime surprise on
the first connection. `ClientAuth::Required` and `ClientAuth::Optional` each hold a `TrustAnchors` by
value, so "required but no anchors" cannot be expressed at all, structurally, independent of any
runtime check. A listener whose client-authentication configuration fails to compile never binds,
and a listener that never binds certainly never binds and admits unverified peers.

**The two knobs that can weaken the check, what each costs, and that both are explicit.**
Revocation is checked by walking the whole certificate chain against a compiled revocation index, not
only the presented leaf, matching the underlying verifier's own `RevocationCheckDepth::Chain`
default. Two configuration fields, and only these two, can weaken what that buys:

- `allowUnknownRevocationStatus` (default `false`): when `true`, a certificate whose revocation
  status could not be determined, no coverage for its issuer, or coverage that has gone stale past
  its grace period, is accepted rather than refused. The cost: a revoked certificate whose
  revocation list you failed to load or refresh is admitted exactly as if it were still valid.
- `revocation` (default `enforced`): when set to `disabled`, no revocation check runs for any
  certificate at all. The cost: a revoked certificate is accepted outright. This is the explicit,
  all-the-way-off statement; the default `enforced` additionally refuses to compile a listener
  whose revocation index holds no coverage for any issuer whatsoever, because binding such a
  listener would mean every client certificate gets refused with an opaque alert the moment the
  first one connects, and driving an operator who hits that toward the fail-open knob is a worse
  outcome than either honest option on its own.

Both are operator-facing configuration fields an implementer must set deliberately; neither is a side
effect of an absent resource or a default an operator has to go read the source to discover.

**Root hint disclosure and the amplification bound.** The `CertificateRequest` a client-authentication
listener sends carries the subject name of every trust anchor in its bundle, sent to every connecting
peer before that peer has proven anything. Below 32 anchors this is sent as configured, because it
genuinely helps a client with several certificates choose the one this listener accepts. At 33
anchors and above, the hint list is cleared instead of sent: past that point it both discloses the
full contents of a large trust bundle to an unauthenticated peer and turns a few-hundred-byte
handshake message into a multi-kilobyte one, a bandwidth amplification factor obtainable by opening
connections and never authenticating. At most 32 trust anchor subject names are ever disclosed to an
unauthenticated peer, regardless of how large the configured bundle is.

## Benchmark origin (`it-origin`)

**This binary adds two network listeners and a hand-written HTTP head parser to the repository,
and it is a benchmark fixture, not a production surface.** `it-origin` exists so that a proxy
benchmark's own upstream has a known, constant, allocation-free per-request cost and a measured
throughput ceiling, per `science/benchmarking.md`'s D3. That is its entire job. It has no
authentication of any kind, on either listener, and it must never be reachable from an untrusted
network: it is deployed only on a private benchmark link, co-located with the gateway under test
and the load generator, and an operator who exposes it to anything else has taken it out of the
threat model this document covers.

**What each listener accepts.** The main listener (`--listen`, default `127.0.0.1:8081`, up to
8 addresses) answers every request identically with a preallocated response, regardless of method
or path: the path is never parsed, which is what makes its cost constant rather than
request-dependent. `--stats-listen` (default off) is a second, structurally identical listener: it
answers exactly `GET /stats` with a JSON counter snapshot and everything else with a preallocated
404. Both listeners run the same hand-written head scan (`scan_head`), so there is one parser in
this crate, not two, and one review surface rather than a review surface per listener.

**The four bounds, their defaults, and their behaviour at the bound.** A benchmark fixture is
deliberately driven to scales (100,000 concurrent connections is a published matrix cell) where an
unbounded per-connection allocation is gigabytes of read buffers, and a fixture that runs out of
memory or spins at 100 percent CPU invalidates every cell it appears in, silently. The bound
existing, and being recorded, matters far more than the bound being tight; these defaults are
generous because this is a fixture on a private link.

| Bound | Flag | Default | Behaviour at the bound |
| --- | --- | --- | --- |
| Concurrent connections | `--max-connections` | 200,000 (1..=1,000,000) | A connection over the bound is accepted and immediately closed, and the reject counter rises. `accept` is never stopped: a full kernel backlog reads to the client as a connect timeout, which is indistinguishable from a proxy stall and would be misattributed to the system under test. |
| Head delivery | `--head-timeout-ms` | 10,000 ms (1..=600,000) | A connection that has not delivered a complete request head, and then its declared body, by the deadline is closed with no response written and nothing logged. |
| Idle keepalive | `--idle-timeout-ms` | 60,000 ms (1..=3,600,000) | A keepalive connection with no new request by the deadline is closed. |
| Request head size | fixed | 16,384 bytes | A head that has not delivered the `\r\n\r\n` terminator within 16 KiB is refused with 431 and the connection is closed. The terminator search resumes from where the previous read left off rather than restarting at byte 0, which is what keeps a client that trickles the head in one byte at a time linear work instead of the quadratic work an implementation that rescans from the start would hand it. |

Every one of these is a flag, not a constant, specifically so an operator running the
100,000-connection matrix cell (which needs on the order of 1.6 GiB of read buffers at that
concurrency) can say so explicitly, and so that the same binary stays usable on a laptop at its
defaults.

**The declared body it never inspects is still bounded and still time-boxed.** A `Content-Length`
value is capped at 16,777,216 bytes before this fixture ever tries to read that many bytes from the
socket, and the whole read (head plus declared body) runs under the single head-timeout deadline: a
client that declares 16 MiB and sends one byte is closed on expiry rather than held open
indefinitely. A request carrying both `Content-Length` and `Transfer-Encoding` is refused with 400
rather than resolved by preferring either header, because that combination is the classic
request-smuggling desync pair, and a fixture that picks a side teaches the proxy under test that
the ambiguity is survivable.

**Structural control.** The response path is a `write_all` of a preallocated slice with no
per-request allocation (asserted under a counting allocator, not merely claimed), so `it-origin`'s
own cost is knowable rather than incidental; the per-request delay (`--delay-us`,
`X-Origin-Delay-Us`) is an absolute-instant timer registration, never a blocking sleep, so one
slow-by-request-header connection cannot stall any other connection's response; and the connection
admission gate and the two listeners' shared bounds are exactly what keep a fixture whose only job
is to be a known cost from becoming an unbounded one.

## The benchmark harness's vocabulary (`irontraffic-bench`, #404, hardened #776)

*Status: `CellId`, `Detail` and `BenchError` ship in `irontraffic-bench`, a `publish = false`
development tool that nothing in `crates/irontraffic` may depend on. Nothing in this crate spawns a
process, reads a file or opens a socket yet; the driver binary that does is later M17 work. This
section exists now because the parser and the two foreign-byte error variants are already the
crate's security boundary, and CONTRIBUTING.md's threat-model rule requires the section in the same
PR that ships the surface, not deferred to whichever later issue happens to wire in a caller.*

**`CellId::parse` is a path-traversal boundary in a script a stranger is invited to run.** A cell id
is used verbatim as a result filename stem (`bench/results/<utc-date>-<hw-id>/<cell-id>.json`), so a
cell id that can smuggle a `/`, a `\`, a `..` segment, or a NUL byte is a primitive for writing
outside that directory. The parser closes this by construction rather than by scrubbing afterward:
it accepts only `[a-z0-9_]{1,64}` segments, one to four of them joined by a single dot, at most 128
bytes total, with no decoding step (so a percent-encoded separator like `%2F` is inert, it is just
two more rejected bytes) and no normalisation (so the stored string is always exactly the validated
input, never a lowercased or trimmed variant a caller might not expect). A single-segment id equal to
one of five `RESERVED_STEMS` (`manifest`, `index`, `summary`, `provenance`, `readme`) is also
rejected, because those are the other filenames the harness writes into the same run directory and an
id that collided with one would silently overwrite it. A post-merge adversarial review (#776) ran a
33-mutant campaign against this parser and its fuzz target and found the parsing logic itself sound
(200,000 fuzz runs, no crash, exact round trip, every character-class and reserved-stem rule
individually confirmed live), but found the test suite guarding it was not: five of ten unrelated
`BenchCell::validate` guards, the reserved-stem list itself, and the character class's `-` exclusion
could each be silently weakened or deleted with the suite still green. The fix landed test hardening,
not a parser change: every guard now has a case that exercises it from both sides, `RESERVED_STEMS`
is pinned against a literal array rather than iterated, and `CellId::parse("a-b")` is now a named
rejection.

**`Detail` bounds the two error payloads built from bytes we did not write.**
`BenchError::Parse.detail` is built from an external load generator's or competitor container's
stdout or stderr; `BenchError::Io.path` is built from an operator-supplied `--out` argument. Both are
printed to a terminal and written into a run log a reviewer may later read, so an unbounded payload is
a memory denial of service on the harness and one carrying `\x1b[`, `\r` or a raw `\n` rewrites the
operator's terminal or forges a log line around the real error. `Detail::new` is the only way either
variant's foreign-byte field can be built (the field is private), clips to 256 bytes at a character
boundary before touching a single byte for sanitising (so a two gigabyte tool stdout costs the same as
a short string), then replaces every byte outside `0x20..=0x7E` with `?`. #776 found this guarantee
was unverified in one specific way that mattered: nothing in the crate asserted `Detail::new` returns
the message it was given, only that it excludes a fixed set of bad bytes, so an implementation that
replaced every byte unconditionally (destroying the message entirely) satisfied every existing
assertion. The fix pins literal input/output pairs, for example `Detail::new("wrk: unable to
connect").as_str() == "wrk: unable to connect"`, so content destruction fails loudly. #776 also found
a real gap in the guarantee itself: `BenchError::Io`'s derived `Display` interpolated `source` (a bare
`std::io::Error`, needed unsanitised as a `#[source]` link for error-chain walking) directly, so an
`io::Error` built from foreign bytes rendered raw, unlike `path`. The fix routes `source` through
`Detail::new` at render time in the `Display` format string itself, so the property holds for
everything the variant ever prints, not only for the field that happened to be typed as `Detail`.

**`BenchCell::validate` is advisory, not structural, and callers must know that.** Unlike `CellId`,
`BenchCell` derives `Deserialize` on public fields with no `#[serde(try_from)]`, so a result file can
deserialise into a cell that `validate()` would reject (zero routes, a payload above the 16 MiB cap,
and so on): the type does not make an invalid `BenchCell` unrepresentable the way it makes an invalid
`CellId` unrepresentable. This is a deliberate, documented design choice (the alternative, routing
every field through a fallible constructor, was rejected in #404 because the registry uniqueness check
that matters is deferred to a later issue), not a defect, but it means every future reader of a result
file (the driver binary, `{{bench-xtask-cli-and-run-sh}}`, and the matrix registry) must call
`validate()` itself after deserialising rather than trusting the wire format to have enforced it
already.
