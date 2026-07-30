# Client certificate authentication (mTLS)

A listener can request or require a client certificate. This document states the operator-facing
configuration surface, the one behavior that surprises everyone (`RevocationCheckDepth::Chain` plus
`UnknownStatusPolicy::Deny`), how revocation is configured deliberately rather than implied, and the
root hint cap and why it exists.

## The fail-closed guarantee

The trust bundle a listener authenticates clients against cannot be empty, cannot be malformed, and
cannot be partially broken. Caddy shipped CVE-2026-27586: a typo in a CA path, a partially written
file during a config push, or a truncated secret mount turned an authenticated listener into an open
one, silently, with no error and no log line. Here that failure mode does not exist as a state the
software can reach. An empty, missing, or unparseable trust bundle is a configuration compile error,
and a listener whose configuration fails to compile never binds. There is no path from "the CA file
was missing" to "accept any client".

A bundle where some anchors parse and others do not is refused as a whole, naming the index of the
first anchor that failed. A bundle that is 75 percent valid is not silently treated as a 75 percent
trust store; it is a broken bundle.

## Configuration

```yaml
clientAuth:
  mode: required          # none (default), optional, or required
  allowUnknownRevocationStatus: false
  revocation: enforced    # enforced (default) or disabled
```

The CA bundle itself is not part of this configuration block. It is referenced as a resource (a
Secret, a file, a bundle name) and resolved to bytes by the configuration layer before the trust
anchors are built. Keeping bundle bytes out of the configuration document is a workspace-wide rule
for anything secret-bearing: configuration history is safe to store and to commit to version control
only if it never carries the secret itself.

- `mode: none` (the default): no client certificate is requested. If a trust bundle is supplied
  alongside `none` anyway, it is ignored; that combination signals a configuration mistake worth
  fixing, but the mode still wins.
- `mode: optional`: a client certificate is requested and verified if presented. A client that sends
  no certificate is still admitted.
- `mode: required`: a client certificate is required and verified. A client that sends no certificate
  never completes the handshake.

`optional` and `required` both require a trust bundle. Supplying no bundle at all is a different
mistake from supplying an empty or broken one, and both are refused with a message naming which
happened, rather than one generic failure that leaves the operator guessing whether the resource
reference was wrong or its contents were.

## The surprise: `Chain` depth plus `Deny` unknown status

The underlying certificate-chain verifier checks revocation across the **whole** chain, not only the
client's own leaf certificate, and a certificate whose revocation status could not be determined is
**denied**, not admitted. Both of these are the correct, safe defaults, and both are kept exactly as
they are rather than loosened to something friendlier.

The consequence operators need to know: **one missing intermediate CRL rejects every client
certificate that chains through that intermediate**, not only the ones that would actually have been
revoked. If your CA hierarchy has an intermediate whose CRL you have not configured, every client
under that intermediate is refused, with an alert that gives the client no detail about why.

The common mistake is assuming an undetermined revocation status defaults to "allow". It does not.
If you see every client certificate under one intermediate failing with an opaque alert, the fix is
either of:

1. Supply a CRL for that issuing CA, so its revocation status is determinable, or
2. Set `allowUnknownRevocationStatus: true` deliberately, understanding exactly what it costs (below).

## `allowUnknownRevocationStatus`

Default `false`. Setting this to `true` means a certificate whose revocation status could not be
determined, because no CRL covers its issuer, or the CRL that does has expired past its stale grace
period, is **accepted** instead of refused. This is a real weakening of the check: a revoked
certificate whose CRL you failed to load or refresh is accepted exactly as if it were still valid.

Do not set this to `true` as a first response to the surprise above. Set it only when you have
deliberately decided that some issuers in your trust bundle will never have CRL coverage, and you
have accepted what that costs.

## `revocation`

Default `enforced`. This is an explicit field rather than "check revocation only if CRLs happen to be
configured", and the reason is the CVE this whole design corrects: an operator who forgets to
configure CRLs must not silently get no revocation checking with no signal that anything changed.

- `enforced`: every chain element's issuing CA must have a usable revocation index. If the CRL set is
  entirely empty, the listener refuses to compile, with a message naming both fixes: supply a CRL for
  each issuing CA, or set `revocation: disabled` and mean it. Finding this at configuration compile
  time is the entire point; finding it when the first client connects, and every client after it is
  rejected with an opaque alert, is the failure mode this field exists to move earlier.
- `disabled`: no revocation check runs at all, for any certificate. This is an explicit operator
  statement. A revoked certificate is accepted, which is exactly what was asked for. Do not set this
  as a workaround for the CRL-coverage refusal above without understanding that it removes revocation
  checking entirely, not just for the issuer that was missing coverage.

## The root hint cap

A listener with client authentication tells connecting clients, before any authentication happens,
which certificate authorities it trusts, so that a client holding several certificates can pick the
one this listener is likely to accept. That hint list is the subject name of every trust anchor in
the bundle, sent in the clear to every peer that reaches the listener, authenticated or not.

Below 32 anchors, the hint list is genuinely useful and is sent as-is. Above 32 anchors, the hint list
is cleared instead: sending it to every unauthenticated peer would disclose the full contents of a
large trust bundle, and it turns a few-hundred-byte handshake message into a multi-kilobyte one, a
bandwidth amplification factor an attacker gets for free by opening connections and never
authenticating. A client with fewer, well-chosen certificates still authenticates correctly either
way; the cap only removes a courtesy hint once the bundle is large enough that the hint becomes a
liability.

## What this does not cover

- Client-certificate OCSP is not implemented. One inbound handshake becoming one outbound OCSP
  request is a self-inflicted amplification vector against this process and against the CA; if that
  capability is ever added, it will be asynchronous and driven by the control plane, never on the
  handshake path.
- Compressed client certificates (RFC 8879) are never accepted. Accepting attacker-supplied
  compressed certificates is a decompression-bomb surface, and nothing here advertises support for
  it.
