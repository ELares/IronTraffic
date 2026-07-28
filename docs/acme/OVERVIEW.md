# ACME integration in IronTraffic

## What we automate

IronTraffic automates the RFC 8555 ACME lifecycle for certificate issuance
and renewal. This crate handles:

- **Directory discovery**: fetching and caching the CA directory, with a
  configurable TTL to avoid hitting `/directory` rate limits.
- **Account registration**: creating or loading an ACME account, with support
  for External Account Binding (EAB), which is required by ZeroSSL, Google
  Trust Services, and most commercial CAs.
- **Credential management**: returning an opaque credentials blob that the
  caller must persist. Loading an account from persisted credentials performs
  no network request, so a restart with a persisted account creates no new
  registration.

Order handling, challenge provisioning, certificate issuance, and storage are
in a separate crate (`acme-order-state-machine-and-storage`, issue #127).

## What we do not automate

- The ACME protocol client. `instant-acme` 0.8.5 handles JOSE signing, nonce
  management, `badNonce` retry, and the actual HTTP requests to the CA.
- Rate-limit enforcement. We do not retry internally. A rate-limited request
  returns an error with the `Retry-After` value that the caller must respect.
  The full rate-limit mirror is issue `acme-ari-renewal-and-rate-limits`
  (#130).

## Security posture

### Directory URL requirement

The ACME directory URL **must** be `https://`. A plaintext `http://` URL is
rejected, with one narrow exception: when `allowInsecureDirectory` is set AND
the host is a loopback address (`127.0.0.0/8`, `::1`, or `localhost`). This
exception exists solely so the unit test suite can talk to a local Pebble test
server.

Why is this so strict? The CA directory is not a minor piece of metadata. It
returns every URL the client subsequently calls: where to register, where to
create orders, where to fetch challenges, and where to download certificates.
An attacker who can intercept a single plaintext GET to the directory URL can
choose which "CA" we talk to, which challenges we provision, and what
certificate we install and then serve to real clients. That is a complete
compromise of the certificate lifecycle from one unencrypted request.

Even with `allowInsecureDirectory: true`, a non-loopback host is still
rejected. The flag exists only for testing against a local Pebble, and we do
not hand operators a documented way to run production issuance over plaintext.

### Rate-limit posture

- The directory is fetched at most once per `directoryTtlSecs` (default
  86,400 seconds, one day) per configured CA.
- Account creation happens at most once per configured account, keyed on the
  credentials blob the caller persisted.
- A rate-limited request is returned to the caller as an error; this crate
  never retries internally.

## Account key type

ECDSA P-256, matching what every ACME CA supports and what `instant-acme`
generates by default. The account key is not a certificate key and is never
reused as one.

## What must never be logged

- The account private key (contained in the credentials blob).
- The EAB HMAC key.
- Any JWS signature.

The account is identified in logs by its URL and by a fingerprint: the first 8
bytes of `blake3(b"irontraffic/acme-account-fingerprint/v1" || credentials_json)`,
hex-encoded.
