# TLS protocol profiles

`irontraffic-tls` exposes exactly three named TLS profiles for a listener, and no per-suite,
per-group, or per-version configuration key. This document describes what each profile allows,
the cipher suite and key exchange group lists the compiled crypto provider supplies, why server
preference is always on, and why there is no lower level knob.

## The three profiles

### `modern`

TLS 1.3 only (`rustls::version::TLS13`). A client that cannot negotiate TLS 1.3 fails the
handshake with a protocol version alert. Use this profile when every client that needs to reach
the listener is known to support TLS 1.3.

### `intermediate`

TLS 1.3 and TLS 1.2 (`rustls::version::TLS13`, `rustls::version::TLS12`), with TLS 1.3 preferred.
This is the default profile for a listener that does not specify one. It accepts the same clients
`modern` accepts, plus a TLS 1.2 client that offers one of the TLS 1.2 suites listed below.

### `legacy`

Rejected at configuration time with a dedicated error, `PolicyError::LegacyProfile`, whose message
points back at this document. There is no configuration this profile could express that `modern`
or `intermediate` do not already cover: rustls has no TLS 1.0, no TLS 1.1, no CBC suites, no RC4,
no static RSA key exchange, no compression, and no renegotiation, so "legacy" as this project's
incumbents define it (a profile that trades security for compatibility with an older client) has
no code path to attach to. The profile exists in the configuration schema anyway, spelled out and
rejected with an explicit, documented error, so a misconfigured operator sees "this profile is not
supported, see docs/tls/PROFILES.md" instead of a generic unknown value error that reads like a
typo in the key name.

## Cipher suites and key exchange groups

Neither is configurable. Both are taken from the compiled crypto provider's defaults, unchanged,
so the list tracks the provider rather than freezing on the day this document was written. As
verified in this tree against `rustls-aws-lc-rs`:

* TLS 1.3 cipher suites (`DEFAULT_TLS13_CIPHER_SUITES`): AES-128-GCM, AES-256-GCM, and
  ChaCha20-Poly1305.
* TLS 1.2 cipher suites: ECDHE-ECDSA and ECDHE-RSA key exchange, with AES-GCM and ChaCha20-Poly1305
  only. No CBC suite is offered.
* Key exchange groups (`DEFAULT_KX_GROUPS`): X25519MLKEM768 (the post-quantum hybrid), X25519
  (compiled out under the `fips` feature, since FIPS 203 covers ML-KEM but plain X25519 is not a
  FIPS approved group), SECP256R1, and SECP384R1.

A `crypto-ring` build has no ML-KEM implementation, so it never offers X25519MLKEM768 and its
suite and group lists are `ring`'s own defaults instead of `aws-lc-rs`'s.

## Server preference is always on

`ServerConfig::ignore_client_order` is set to `true` unconditionally, on every `ServerConfig` this
crate produces. There is no configuration key that makes it `false`. Left at the rustls default
(client order wins), an attacker controlling the ClientHello's suite order can steer the server
toward the most expensive suite it is willing to accept; server preference removes that lever
entirely.

## Why there is no per-suite, per-group, or per-version knob

The alternative every incumbent proxy ships is a `min_version`, `max_version`, `cipher_suites`,
and `curves` list, each validated against the provider's actual capabilities at runtime. That
surface is the single most common source of operator caused TLS weakness in practice, and its most
requested feature is always "let me turn TLS 1.0 back on." Three named profiles cannot express a
weak configuration: `modern` and `intermediate` are both already correct, and `legacy` is rejected
with a pointer back to this document instead of silently accepting a value nobody can act on.
