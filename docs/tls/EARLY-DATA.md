# TLS 1.3 early data (0-RTT)

This document is the operator-facing statement of what 0-RTT early data does, what it does not
do, and the two structural controls (the admission policy and the replay filter) this crate ships
so a later issue can wire it up. Off by default; nothing described here changes behavior until a
listener's `earlyData.enabled` is set to `true` AND the data-plane wiring that reads
`crate::early_data::evaluate` exists.

## The honest statement, first

**0-RTT replay cannot be fully prevented in a distributed system: the method restriction is the
security boundary, and the replay filter only reduces volume.** A 0-RTT `ClientHello` carries no
proof that it has never been sent before, and it can be sent to more than one node in a fleet
before any single node's answer is known to the others. No per-process filter and no
coordination-free cluster mechanism closes that window completely: closing it exactly would need a
consulted-before-serving distributed store, which reintroduces the network round trip 0-RTT exists
to avoid. Say this plainly in any future documentation that touches early data; do not describe the
filter as preventing replay.

What actually makes a replay harmless is that early data is restricted to `GET` and `HEAD`
requests with no declared body and (by default) no query string: a second execution of an
idempotent, side-effect-free request is not an action whose meaning changes because it ran twice.
The filter exists only to cut the volume of replays that make it to a backend at all.

## The seven conditions

A request may be served from early data if and only if every one of these holds. Any failure
rejects the early data with `ServerConnection::reject_early_data()` and re-drives the request after
the handshake completes: one extra round trip, always safe.

0. **The listener does not enforce client authentication.** A resumed TLS 1.3 handshake does not
   re-present or re-verify the client certificate; identity is restored from the ticket instead.
   Serving a request from early data on such a listener would make it both authenticated (by the
   restored identity) and replayable, which is worse than either property alone. This is also a
   configuration-compile-time error, not only a runtime rejection: a listener whose client
   authentication is anything other than "none" and whose `earlyData.enabled` is `true` fails to
   compile, per `EarlyDataConfig::is_permitted_with`. **Early data is refused entirely on any
   listener that requests or requires a client certificate.**
1. Method is `GET` or `HEAD`.
2. There is no request body: no `Content-Length` and no `Transfer-Encoding`, including a declared
   `Content-Length: 0`.
3. The matched route carries `earlyData: allow` or `earlyData: allowQuery`. The default is `deny`.
4. The query string is absent, unless the route sets `earlyData: allowQuery`. An empty query
   string (a bare `?`) still counts as present. This mirrors Cloudflare's published 0-RTT policy
   (GET only, no query parameters) and is the conservative default, because a query parameter is
   exactly where a "mutating GET" hides.
5. Total early data received on the connection so far, including this request, is at most
   `earlyData.maxBytes` (default 16,384 bytes, hard cap 65,536).
6. The ticket presented has not already been used for early data on this node, per the replay
   filter below.

**A route marked `allow` can be forced back to `deny` at configuration-compile time.** Any route
whose policy chain contains a mutating filter, a rate-limit counter increment, or a stateful
authorization decision is downgraded regardless of what the operator wrote, because an operator
who marks a route "idempotent" is reasoning about their own handler, not about the filter chain in
front of it. The compiler records which of these reasons applied so the operator can see why
`allow` did not take effect.

## The two header rules

Both of these are security-relevant, and the first is a deliberate deviation from the RFC:

- **Every client-supplied `Early-Data` header is stripped, unconditionally, from every inbound
  request, before this crate's own header is added.** RFC 8470 section 5.1 says an intermediary
  "MUST NOT remove this header field if it is present in a request." That requirement assumes the
  previous hop is a trusted intermediary. At this crate's ingress, the previous hop is an arbitrary,
  unauthenticated client: a client that sends `Early-Data: 1` on a normal, fully handshaked request
  is trying to make the upstream think that request was replayable, and a client that sends
  `Early-Data: 0` on a genuinely early-data request is trying to suppress the upstream's ability to
  veto it. Stripping unconditionally makes neither lie expressible. Preserving the header for a
  specific, genuinely trusted upstream hop is a future `TrustPolicy` decision in the data-plane
  wiring, exactly like every other identity-bearing header, and it is not offered in v1.
- **`Early-Data: 1` is injected on the upstream request whenever it was served from early data**,
  and if the upstream answers `425 Too Early`, the request is held until the handshake completes
  and retried exactly once. That is the RFC-sanctioned escape hatch: it means a correctly written,
  non-idempotent upstream handler can veto being served from early data even when every condition
  above held.

Both rules are stated here, not implemented here: the header injection, stripping, and `425` retry
belong to the data-plane wiring that reads this crate's decision, `crate::early_data::evaluate`,
and its `EARLY_DATA_HEADER` constant is the one spelling both sites use.

## The replay filter

`crate::replay::EarlyDataFilter` is a two-generation blocked Bloom filter over PSK identities,
shared as one instance per process across every listener with early data enabled (never one per
listener: at the default sizing it is 10 MB, and a filter per listener would multiply that for a
structure whose contents are not listener specific). `check_and_insert` answers, in effect
atomically from the caller's point of view, "has this exact ticket already been presented for
early data on this node": the first presentation is admitted and remembered, the second is
rejected. This is the one condition, of the seven above, that has a side effect, and it is checked
last for exactly that reason.

**Sizing.** At the default capacity of 1,000,000 tickets per generation, 40 bits per key and 13
probes per key, the filter is 5,000,000 bytes per generation and 10,000,000 bytes total. The
measured false-positive rate at that sizing is comfortably under 1 in 100,000: a false positive
costs a legitimate client one extra round trip, nothing more.

**The filter key is the whole PSK identity, not a fixed-length prefix.** `cluster-derived-session-
ticketer`'s (#120) ticket format is `name_e (16 bytes) || nonce (24 bytes) || ciphertext`, and
`name_e` is a per-epoch HKDF-derived constant identical for every ticket issued fleet-wide during
that epoch. Hashing only the first 16 bytes of a PSK identity would therefore key the filter on the
epoch, not on the individual ticket, denying 0-RTT to nearly every legitimate client after the
epoch's first request. The filter hashes the entire identity; a minimum-length check on the first
16 bytes only guards against an identity too short to be a real ticket.

**The memory window is deliberately shorter than the ticket window.** Two generations rotating
every `replayRotateSecs` (default 3 hours) remember tickets for between one and two rotation
periods: 3 to 6 hours at the default. A ticket issued by
`cluster-derived-session-ticketer` (#120) stays decryptable for 12 to 18 hours (three 6-hour
epochs). A replay presented after this filter has forgotten the ticket, but before the ticket
itself has expired, is therefore possible **by construction, not by accident**. Sizing the filter
to cover the full ticket window would cost 3 to 6 times the memory and would still not close the
cross-node case, which is the whole reason condition 6 above is a volume reducer and conditions 1
through 5 are the actual boundary.

**Fleet-wide, this is best effort only.** The filter answers for one node. A ticket replayed to a
second node before the first node's filter has recorded it is not caught by this filter at all;
narrowing that window further is the unpublished, cluster-wide slug `early-data-replay-gossip`,
and even that remains a best-effort reduction, never a guarantee, for the reason stated at the top
of this document.

## Operator-facing configuration

```json
{ "enabled": false, "maxBytes": 16384, "replayCapacity": 1000000, "replayRotateSecs": 10800 }
```

`enabled` stays `false` until an operator opts in. `maxBytes` of `0` with `enabled: true` is legal
and means "advertise zero bytes of early data", which is a way to keep 0-RTT negotiated at the TLS
layer without ever actually accepting any early application data. `replayCapacity` and
`replayRotateSecs` trade memory against the length of the replay-detection window; the defaults are
sized for the recommendations above and should not need tuning in the common case.

## Metrics

- `tls_early_data_replay_inserts_total`, `tls_early_data_replay_hits_total`,
  `tls_early_data_replay_rotations_total`: counters on the replay filter.
- `tls_early_data_replay_fill_bits`: the set-bit count of the generation that was just retired,
  written once per rotation. Compare against `blocks * 512` (blocks scales with `replayCapacity`)
  to see whether the configured capacity is undersized for the traffic actually observed.
