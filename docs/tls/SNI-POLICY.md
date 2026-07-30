# Per-SNI TLS policy selection

A listener may bind several TLS policies to different server names: different client
authentication requirements, different ALPN sets, different profiles. This document states which
policy a connection gets, what happens when none matches, and the two obligations the rest of the
system must honour for the guarantee to hold.

## The rule: fail closed

The policy for a connection is chosen by the **same** name-resolution function that chooses the
certificate. One normalization, one exact probe, then exactly one wildcard probe on the parent
domain.

| The `ClientHello` carries | Result |
| --- | --- |
| An SNI matching an exact binding | That binding's policy |
| An SNI matching a wildcard binding's parent | That binding's policy |
| An SNI matching nothing, and a fallback is configured | The fallback |
| An SNI matching nothing, and no fallback is configured | **Handshake rejected** |
| An SNI that fails validation | The fallback if configured, otherwise **rejected** |
| No SNI, and a no-SNI policy is configured | That policy |
| No SNI, and no no-SNI policy is configured | **Handshake rejected** |
| A malformed or truncated `ClientHello` | **Handshake rejected** |

There is no inheritance from a laxer default. If you want a single-certificate listener that
serves everything, configure a fallback explicitly; that is the operator saying so, not the
system guessing.

Name matching is case-insensitive and ignores one trailing dot, because certificate matching is.
`A.Example.COM.` and `a.example.com` are the same name in both.

### Why it is written this way

Traefik shipped four mTLS bypasses in this exact area. Certificate selection used wildcard and
case-folding semantics while TLS-option selection used an exact, case-sensitive map lookup, so a
name could match a certificate and miss its policy. When the policy lookup missed, Traefik fell
back to a default configuration that did not require client certificates. And when a
`ClientHello` was fragmented across TLS records, SNI extraction returned empty, which took the
same permissive default path.

- CVE-2026-32305, fragmented `ClientHello` treated as no SNI (GHSA-wvvq-wgcr-9q48)
- CVE-2026-48491, wildcard mappings ignored by `SNICheck`, fixed in 3.7.3
- CVE-2026-53622, exact case-sensitive HTTP/3 lookup, fixed in 3.7.3
- Caddy CVE-2026-27586, mTLS silently failing open when the CA file is missing or malformed

Every one of those is fail-open. A miss here is a rejection.

## The startup lint

Building a listener fails, at configuration time, when any of these hold. It errors rather than
warns because each shape has a CVE behind it.

1. **Client-auth divergence.** An exact binding and a wildcard binding that covers it disagree on
   client authentication. Two ways to reach the same authority with different authentication is
   CVE-2026-48491's shape.
2. **A weaker fallback.** The fallback authenticates more weakly than the strongest binding. That
   is the Traefik default-config bug expressed as configuration.
3. **A weaker no-SNI policy.** The same check for connections that present no SNI.
4. **Duplicate bindings.** Two bindings for the same name and kind. Silently keeping one of two
   conflicting bindings is how "which one won" becomes unanswerable.

## The obligation the lint cannot discharge

The lint catches two bindings that match the **same** name. It deliberately does not catch two
**different** names on one listener carrying different client authentication, because that is the
mixed public-and-mTLS listener this whole design exists to support.

That configuration has a hole, and it is the real mechanism behind CVE-2026-48491:

1. A listener binds `secure.example.com` requiring a client certificate, and
   `public.example.com` requiring none. The lint passes: the names are disjoint.
2. One `*.example.com` certificate covers both, which is the normal deployment.
3. An attacker connects with SNI `public.example.com` and no client certificate. The handshake
   succeeds under the permissive policy.
4. The attacker then sends `Host: secure.example.com` on that connection.
5. A certificate-scope check passes, because the negotiated certificate genuinely covers
   `secure.example.com`. The request routes. A route that requires a client certificate has just
   been served over a connection that presented none.

**The HTTP layer MUST re-check, on every request:** if the request authority's binding requires
stronger client authentication than the connection provided, refuse the request. Not once per
connection, once per request, because the authority can change between requests on one
connection.

"May this connection carry this authority at all" and "does this authority's client-auth
requirement hold on this connection" are different questions. Both must be asked.

A listener whose bindings all share one client-authentication requirement cannot be attacked this
way, and for that shape the comparison is always false and costs nothing.

## Handshake-flood limits

A `ClientHello` costs an attacker roughly 500 bytes and one `write()`. It costs us one signature
and one key agreement: about 147 microseconds of CPU for ECDSA, about 424 for RSA-2048. That
asymmetry is the single worst thing about terminating TLS.

| Limit | Default | Range |
| --- | --- | --- |
| `handshake_timeout_ms` | 10,000 | 1,000 to 120,000 |
| `max_inflight` | 10,000 | 16 to 1,000,000 |
| `max_inflight_per_source` | 64 | 1 to 65,536 |
| `max_key_updates_per_connection` | 32 | 1 to 1,024 |

Out-of-range values are clamped, never rejected. These are operational dials, and a listener that
refuses to start over a typo in a limit is worse than one that runs with the nearest legal value.

There is also a cap on how many bytes will be buffered while waiting for a complete
`ClientHello`, 32,768 by default, adjustable between 4,096 and 65,536. A connection that exceeds
it is rejected. The comparison is strict, so a `ClientHello` of exactly the cap is accepted.

### These four are a contract, not an implementation

The acceptor is sans-IO: it consumes bytes the caller already read. It cannot read a clock, count
connections, or see a source address, so it enforces none of the four. **The accept loop that
owns the socket must**, and if it does not, the listener is trivially exhaustible and these
numbers are decoration.

1. Start the handshake deadline when the connection is **accepted**, not when the first byte
   arrives. A connection that opens and sends nothing is the cheapest possible attack, and the
   timeout is the only thing that ends it.
2. Refuse a new connection when `max_inflight` handshakes are already in progress on the
   listener, or `max_inflight_per_source` from the same source address. Refuse **before** feeding
   any byte to the TLS library, so the refused connection buys no signature and no key agreement.
   Count handshakes in progress, not connections: an established idle connection is cheap, a
   handshake in progress is not.
3. Count `KeyUpdate` messages on the established connection and close above
   `max_key_updates_per_connection`.

## Session resumption and client authentication

When a cluster session ticketer is installed on a configuration, it is constructed with a 16-byte
context derived from that configuration's client-authentication identity: zero bytes when no
client certificate is requested, and the trust bundle's identity otherwise. The context is mixed
into ticket key derivation, so a ticket issued while one trust bundle was live cannot be decrypted
once the bundle changes, and therefore cannot be resumed.

Without this, a resumed handshake restores the peer's identity from the ticket without re-running
the client-certificate verifier. That is CVE-2025-68121.

The cost is that rotating a CA bundle forces a full handshake for clients holding tickets issued
under the old one. That is the correct trade. Because the context is derived from the bundle
contents rather than from anything node-local, every node in the fleet derives the same key and
cluster-wide resumption is preserved.

**Current status.** No ticketer is installed yet: the cluster ticketer is a separate piece of
work. This section states the binding that must hold when it lands, and it must not be satisfied
by installing a context-free ticketer.
