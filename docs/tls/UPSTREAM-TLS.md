# Upstream TLS

This document is the operator-facing configuration surface for `UpstreamTls`, the compiled TLS
configuration used when this process dials one upstream cluster. It states the field mapping to
Gateway API `BackendTLSPolicy`, the fail-closed verification default, the identity model, and what
this release does not check.

## Verified by default

An upstream connection is verified unless `insecureSkipVerify` and `iAcceptTheRisk` are both set to
`true`. There is no configuration shape that verifies "if convenient": a missing or empty trust
source with verification on is a configuration compile error, exactly the same correction
`mtls-client-auth-fail-closed` (#124) made for inbound client certificates. Caddy's CVE-2026-27586
was mTLS silently failing open when a CA file was missing or malformed; here that state is not
representable, and neither is its outbound mirror.

`insecureSkipVerify` alone, without `iAcceptTheRisk`, is refused with an error naming exactly what is
missing. `iAcceptTheRisk` alone, without `insecureSkipVerify`, is accepted and changes nothing:
the acknowledgement without the switch is harmless.

## Configuration

The shape is Gateway API `BackendTLSPolicy`'s `validation` block, plus IronTraffic's own additions.

```json
{
  "hostname": "backend.svc.cluster.local",
  "wellKnownCaCertificates": "System",
  "subjectAltNames": [
    { "type": "URI", "uri": "spiffe://example.org/ns/prod/sa/backend" }
  ],
  "alpn": ["h2", "http/1.1"],
  "postQuantum": "off",
  "insecureSkipVerify": false,
  "iAcceptTheRisk": false
}
```

### Field mapping

| `BackendTLSPolicy` field | `UpstreamTlsConfig` field | Notes |
| --- | --- | --- |
| `spec.targetRefs` | not present | resolved by the Kubernetes controller, before this type is ever built |
| `spec.validation.caCertificateRefs` | resolved to bytes and passed as the `anchors` argument to `UpstreamTls::compile` | not a config field: bundles are referenced by resource, resolved to bytes, and never inlined in the document, the same secret-handling rule `mtls-client-auth-fail-closed` follows |
| `spec.validation.wellKnownCACertificates` | `wellKnownCaCertificates` | spelled with a lowercase `a` here, matching this workspace's camelCase rule; the Gateway API translation layer maps the two spellings |
| `spec.validation.hostname` | `hostname` | the SNI sent, and the identity checked when `subjectAltNames` is empty |
| `spec.validation.subjectAltNames` | `subjectAltNames` | up to 5 entries; when non-empty, identity matching uses these and never `hostname` |
| `spec.options` (vendor extension map) | `alpn`, `postQuantum`, `insecureSkipVerify`, `iAcceptTheRisk` | these four fields have no equivalent in the standard `validation` block; a Gateway API controller populating `UpstreamTlsConfig` from a real `BackendTLSPolicy` resource reads them out of that resource's generic `options` string map, which is exactly the extension point the specification provides for fields like these |

`caCertificateRefs` and `wellKnownCACertificates` are mutually exclusive: supplying both, or
neither while verification is on, is a configuration error.

### `subjectAltNames`

Each entry is either:

- `{ "type": "Hostname", "hostname": "..." }`: matched against the peer's `dNSName` subject
  alternative names, with RFC 6125 wildcard rules (`*.example.com` matches `a.example.com`, not
  `example.com` and not `a.b.example.com`).
- `{ "type": "URI", "uri": "..." }`: matched against the peer's `uniformResourceIdentifier`
  subject alternative names, byte for byte. No normalization, no case folding, no trailing slash
  tolerance. This is how a SPIFFE identity (`spiffe://trust-domain/workload-path`) is expressed:
  a SPIFFE ID is not a valid DNS name, so it cannot be sent as the SNI, which is why
  `BackendTLSPolicy` keeps `hostname` and `subjectAltNames` as two separate fields.

When `subjectAltNames` is non-empty, matching any ONE of the configured entries is enough to
accept the peer. A certificate presenting no subject alternative name at all is always rejected;
this implementation never falls back to the subject common name for identity, which RFC 6125
deprecates for exactly this purpose.

### `postQuantum`

`off` (the default), `prefer`, or `require`. Outbound post-quantum hybrid key exchange is off by
default, which is a different decision from the inbound default of `prefer`: our `ClientHello`
with the hybrid key share grows past one MTU and past the 1,500-byte ClientHello some middleboxes
and older TLS terminators mishandle, and a handshake failure to an upstream is a user-visible
outage, unlike an inbound handshake we control both sides of. `prefer` mode offers hybrid, and on
handshake failure remembers the upstream for one hour (`DEFAULT_PQ_SUPPRESS_SECS`) before offering
it again, so a persistently incompatible upstream does not pay a failed handshake on every
connection. `require` on a build with no ML-KEM implementation is a configuration error, never a
silent downgrade to classical; `prefer` on the same build silently becomes `off`.

### `insecureSkipVerify` / `iAcceptTheRisk`

Both fields, together, disable verification entirely: no chain check, no identity check. Every
connection establishment on such an upstream increments
`tls_upstream_unverified_connections_total`, and a warning line is logged at most once per 60
seconds per upstream (the counter carries the true volume; the log line is rate-limited so an
upstream with connection churn cannot turn a security warning into a log flood). The dashboard
shows a non-zero counter here as a red banner.

## What is not checked

**Upstream server certificates are not revocation-checked in this release.** Chain verification
runs; no CRL, no OCSP, and no stapled-response validation of what the upstream presents runs
alongside it. A compromised upstream key whose certificate has since been revoked is accepted
until that certificate expires.

This is the same posture every incumbent proxy ships in its default configuration, and it is
bounded: certificate lifetimes are shrinking industry-wide, and short-lived upstream certificates
directly shrink the exposure window. It is an accepted risk, not an oversight, and it is stated
here so it is discoverable rather than inferred from an absent code path.

What an operator can do about it today:

- Prefer short-lived upstream certificates. A 24-hour leaf, renewed well before expiry, bounds a
  compromised key's usable window to at most a day regardless of revocation.
- Configure `subjectAltNames` explicitly rather than relying on `hostname` alone. A revoked
  certificate for a *different* identity cannot be substituted for the one this upstream accepts,
  because identity matching is independent of which CA happened to sign the presented chain.

Upstream revocation checking is planned as a later, separate issue that reuses
`crl-revocation-index` (#123) on the client side; it is not part of this one.

**Outbound Encrypted Client Hello is not implemented.** There is no `ech` configuration key on
`UpstreamTlsConfig`, deliberately: `deny_unknown_fields` means an `ech` key an operator writes
today, expecting it to do something, is rejected outright rather than silently ignored.

**This document does not cover dialing or connection pooling.** `UpstreamTls::pool_key_component`
and `UpstreamTls::client_config_for_dial` exist and are fully tested, but nothing in this crate
calls them yet: the connector that folds the pool key into `upstream-connection-pool` (#85) and
dials through the compiled `ClientConfig` is a later, separate issue.
