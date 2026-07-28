// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory rustls handshakes through `IronResolver`, using `rustls::ClientConnection` and
//! `rustls::ServerConnection` driven directly over `Vec<u8>` byte buffers rather than sockets.
//!
//! `rustls::server::ClientHello` has no public constructor (see the module doc on
//! `crates/irontraffic-tls/src/store/resolver.rs`), so this is the only way to exercise
//! `IronResolver::resolve` (the three-line `rustls::server::ResolvesServerCert` impl) at all. The
//! plain-value decision logic it delegates to (`resolve_parts`, `alpn_verdict`,
//! `caps_from_schemes`) is exercised directly by the unit tests in `store::resolver::tests` and
//! `store::challenge::tests` instead, because those are `pub(crate)` and this file, like every
//! file under `tests/`, compiles as a separate crate that can only see `irontraffic_tls`'s public
//! API.
//!
//! **A note on `handshake_no_allocations_in_resolver` and why it does not match issue #117's
//! Tests section literally.** That section describes it as "10,000 `resolve_parts` invocations".
//! `resolve_parts` is `pub(crate)` (the issue's own Design section requires this: "Do NOT make
//! ... `IronResolver::resolve_parts` `pub`. Both name a `rustls::` type in their signature and
//! would break the crate facade rule"), and a `pub(crate)` item is invisible outside its defining
//! crate under Rust's ordinary privacy rules; there is no `cfg` or visibility spelling that grants
//! a file under `tests/` access to it while keeping it inaccessible to every other external crate,
//! because such a file compiles as a separate crate and links only against `irontraffic_tls`'s
//! public surface. The two requirements ("keep `resolve_parts` `pub(crate)`" and "call
//! `resolve_parts` from `tests/handshake_resolver.rs`") are mutually exclusive, and this is not a
//! rustls-version accessor-naming difference the way the issue's own note about adapting
//! `ClientHello` accessors anticipates; it is a structural Rust privacy fact. This test instead
//! drives real in-memory handshakes across the same four branches the issue names (exact-hit,
//! wildcard-hit, miss, challenge-hit), which is the closest faithful exercise reachable from this
//! file's public-only vantage point, and asserts the functional outcome of every iteration rather
//! than an allocation count, exactly the way `tests/alloc_gate.rs`'s own `alloc_gate` function
//! (a functional flood test, `zero_allocations_in_resolve`, `random_sni_flood_is_flat`,
//! `wildcard_subdomain_flood_is_flat`) is a complement to a SEPARATE static proof rather than an
//! allocation-counting proof on its own. This crate is also not permitted to write a counting
//! `#[global_allocator]` at all: `unsafe` is denied workspace wide with no exception an
//! implementer may grant themselves (see `tests/alloc_gate.rs`'s own module doc for the identical
//! reasoning, and `scripts/invariant-lints.sh` rule 15's failure text, which says so explicitly).
//! The zero-allocation claim for `resolve_parts`, `alpn_verdict`, and `caps_from_schemes` instead
//! rests on two independently CI-enforced things neither of which is this test: `store/resolver.rs`
//! and `store/challenge.rs` both carry the `//! HOT PATH` marker, which puts every function in
//! them under `scripts/invariant-lints.sh`'s `hot-path-allocation` text-scan rule, and issue #117's
//! own acceptance criterion `rg -n 'Vec::|String::|collect\(\)|to_vec|to_owned|format!'
//! crates/irontraffic-tls/src/store/resolver.rs` reporting no match inside those three item
//! bodies, which was checked by hand against the merged source.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test-only helpers on generated inputs, the same pattern tests/alloc_gate.rs uses: \
              clippy.toml's allow-expect-in-tests only exempts functions clippy itself \
              recognizes as tests (#[test] fns and #[cfg(test)] modules), not the ordinary \
              helper functions every test in this file calls"
)]

use std::sync::Arc;

use irontraffic_tls::store::{
    CertIndexBuilder, ChainInterner, ChallengeCertsBuilder, ChallengeKey, Credentials, TimeView,
};
use irontraffic_tls::time::UnixSeconds;
use irontraffic_tls::{ChallengeCerts, IronResolver, TlsPolicy};

fn ensure_provider_installed() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: this is the only test in this binary that needs a provider installed, and either Ok or AlreadyInstalled leaves one installed, which is all this helper promises.
    });
}

/// Returns `(cert_der, key_der)` for a fresh self-signed ECDSA P-256 leaf for `san`.
fn gen_leaf(san: &str) -> (Vec<u8>, Vec<u8>) {
    ensure_provider_installed();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_der())
}

fn load_cred(cert_der: &[u8], key_der: &[u8]) -> Arc<Credentials> {
    let mut interner = ChainInterner::new();
    Arc::new(Credentials::load(&[cert_der], key_der, &mut interner).expect("valid leaf and key"))
}

/// A `TimeView` that never reads a clock, for deterministic expiry.
struct FixedClock(UnixSeconds);
impl TimeView for FixedClock {
    fn unix_seconds(&self) -> UnixSeconds {
        self.0
    }
}

fn build_server_config(resolver: Arc<IronResolver>, alpn: &[&[u8]]) -> rustls::ServerConfig {
    let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = alpn.iter().map(|p| (*p).to_vec()).collect();
    cfg
}

fn build_client(
    server_name: &'static str,
    trust: &[&[u8]],
    alpn: &[&[u8]],
) -> rustls::ClientConnection {
    let mut roots = rustls::RootCertStore::empty();
    for der in trust {
        roots
            .add(rustls::pki_types::CertificateDer::from((*der).to_vec()))
            .expect("valid trust anchor");
    }
    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg.alpn_protocols = alpn.iter().map(|p| (*p).to_vec()).collect();
    rustls::ClientConnection::new(
        Arc::new(client_cfg),
        server_name.try_into().expect("valid server name"),
    )
    .expect("client connection")
}

/// Drives two in-memory TLS endpoints through a handshake, returning the first error either side
/// reports, or `None` if both complete. Same shape as `modern_profile_refuses_tls12_client`'s
/// helper in `tls-protocol-cipher-group-alpn-policy` (#116)'s `crates/irontraffic-tls/src/policy.rs`,
/// copied rather than shared because that helper lives in a `#[cfg(test)]` module inside the
/// library crate and this file, like every file under `tests/`, is a separate crate that cannot
/// see it. 16 rounds is far more than a TLS 1.3 handshake needs and bounds the loop.
fn pump_handshake(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Option<std::io::Error> {
    for _ in 0..16 {
        let mut buf = Vec::new();
        if client.write_tls(&mut buf).is_ok()
            && !buf.is_empty()
            && let Err(e) = server
                .read_tls(&mut buf.as_slice())
                .map(|_| ())
                .and_then(|()| {
                    server
                        .process_new_packets()
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                })
        {
            return Some(e);
        }
        let mut buf = Vec::new();
        if server.write_tls(&mut buf).is_ok()
            && !buf.is_empty()
            && let Err(e) = client
                .read_tls(&mut buf.as_slice())
                .map(|_| ())
                .and_then(|()| {
                    client
                        .process_new_packets()
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                })
        {
            return Some(e);
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    None
}

fn peer_leaf_hash(conn: &rustls::ClientConnection) -> blake3::Hash {
    let chain = conn
        .peer_certificates()
        .expect("server must have sent a certificate chain");
    let leaf = chain.first().expect("chain has a leaf");
    blake3::hash(leaf.as_ref())
}

#[test]
fn handshake_selects_exact_certificate() {
    let (leaf_der, key_der) = gen_leaf("a.example.com");
    let cred = load_cred(&leaf_der, &key_der);
    let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
    certs_builder
        .upsert_exact("a.example.com", cred)
        .expect("valid");
    let certs = Arc::new(certs_builder.build().expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let clock = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(certs, challenge, policy, clock));

    let server_cfg = build_server_config(resolver, &[]);
    let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
    let mut client = build_client("a.example.com", &[&leaf_der], &[]);

    assert!(
        pump_handshake(&mut client, &mut server).is_none(),
        "the handshake must complete when the exact SNI is indexed"
    );
    assert_eq!(peer_leaf_hash(&client), blake3::hash(&leaf_der));
}

#[test]
fn handshake_selects_wildcard_certificate() {
    let (leaf_der, key_der) = gen_leaf("*.example.com");
    let cred = load_cred(&leaf_der, &key_der);
    let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
    certs_builder
        .upsert_wildcard("*.example.com", cred)
        .expect("valid");
    let certs = Arc::new(certs_builder.build().expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let clock = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(certs, challenge, policy, clock));

    let server_cfg = build_server_config(resolver, &[]);
    let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
    let mut client = build_client("x.example.com", &[&leaf_der], &[]);

    assert!(
        pump_handshake(&mut client, &mut server).is_none(),
        "the handshake must complete when the SNI matches an indexed wildcard's coverage"
    );
    assert_eq!(peer_leaf_hash(&client), blake3::hash(&leaf_der));
}

#[test]
fn handshake_unknown_sni_fails_with_unrecognized_name() {
    let (known_der, known_key) = gen_leaf("known.example.com");
    let cred = load_cred(&known_der, &known_key);
    let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
    certs_builder
        .upsert_exact("known.example.com", cred)
        .expect("valid");
    let certs = Arc::new(certs_builder.build().expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let clock = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(certs, challenge, policy, clock));

    let server_cfg = build_server_config(resolver, &[]);
    let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
    let mut client = build_client("unknown.example.com", &[], &[]);

    // Driven by hand rather than through `pump_handshake`: the server fails resolving a
    // certificate while processing the ClientHello, before it would ever reach a step that sends
    // one, and `pump_handshake` returns as soon as either side's `process_new_packets` errors,
    // before ever calling `write_tls` again to flush the queued alert to the peer. rustls queues
    // the fatal alert onto the connection's own outgoing buffer inside `send_fatal_alert`, which
    // runs before `process_new_packets` returns its `Err`, so a `write_tls` call made AFTER that
    // `Err` still flushes it.
    let mut hello = Vec::new();
    client
        .write_tls(&mut hello)
        .expect("client can write its ClientHello");
    server
        .read_tls(&mut hello.as_slice())
        .expect("server can read the ClientHello bytes");
    let process_result = server.process_new_packets();
    assert!(
        process_result.is_err(),
        "the server must fail to process the ClientHello once certificate resolution returns None"
    );

    let mut alert = Vec::new();
    let wrote = server
        .write_tls(&mut alert)
        .expect("the queued fatal alert can still be flushed after the error above");
    assert!(wrote > 0, "a fatal alert must have been queued");

    client
        .read_tls(&mut alert.as_slice())
        .expect("client can read the alert bytes");
    let client_result = client.process_new_packets();
    let err = client_result.expect_err("the client must observe the server's fatal alert");
    // Issue #117 says this fails with an `unrecognized_name` alert. The pinned rustls 0.23.42
    // (`rustls-0.23.42/src/server/hs.rs`, the `resolve` step of the server handshake state
    // machine) instead sends `AlertDescription::AccessDenied` with the error text "no server
    // certificate chain resolved"; `AlertDescription::UnrecognizedName` does not appear anywhere
    // in that source tree. This assertion pins the alert rustls actually sends rather than the
    // one issue #117 names; see this issue's implementation report for the full finding.
    assert_eq!(
        err,
        rustls::Error::AlertReceived(rustls::AlertDescription::AccessDenied)
    );
    assert!(
        client.peer_certificates().is_none(),
        "no certificate may have been sent before certificate resolution failed"
    );
}

#[test]
fn handshake_acme_alpn_gets_challenge_cert() {
    let (challenge_der, challenge_key) = gen_leaf("acme.example.com");
    let mut challenge_builder = ChallengeCertsBuilder::new([9u8; 16]);
    challenge_builder
        .insert(
            "acme.example.com",
            ChallengeKey::from_der(&challenge_der, &challenge_key).expect("valid"),
            UnixSeconds::new(2_000),
        )
        .expect("valid");
    let challenge = Arc::new(challenge_builder.build_with_generation(0).expect("build"));
    let certs = Arc::new(CertIndexBuilder::new([1u8; 16]).build().expect("build"));
    let policy = Arc::new(TlsPolicy::default_https());
    let clock = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(certs, challenge, policy, clock));

    // This test's server config lists `acme-tls/1` directly, standing in for the dedicated
    // challenge `ServerConfig` that `sni-server-config-selection` (#119) builds and hands a
    // connection to only after its acceptor has already confirmed the ClientHello's ALPN list is
    // exactly `["acme-tls/1"]`. A PRODUCTION LISTENER MUST NEVER LIST `acme-tls/1` IN ITS OWN
    // `alpn_protocols`: doing so puts this self-signed challenge certificate one ALPN entry away
    // from every real client, which is the exact outage `tls-protocol-cipher-group-alpn-policy`
    // (#116) refuses at config-compile time. Do not copy this line into listener config code.
    let server_cfg = build_server_config(resolver, &[b"acme-tls/1"]);
    let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
    let mut client = build_client("acme.example.com", &[&challenge_der], &[b"acme-tls/1"]);

    assert!(
        pump_handshake(&mut client, &mut server).is_none(),
        "the handshake must complete on the dedicated acme-tls/1 challenge branch"
    );
    assert_eq!(peer_leaf_hash(&client), blake3::hash(&challenge_der));
    assert_eq!(client.alpn_protocol(), Some(b"acme-tls/1".as_slice()));
}

#[test]
fn handshake_normal_client_gets_real_cert_when_challenge_live() {
    let (real_der, real_key) = gen_leaf("a.example.com");
    let real_cred = load_cred(&real_der, &real_key);
    let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
    certs_builder
        .upsert_exact("a.example.com", real_cred)
        .expect("valid");
    let certs = Arc::new(certs_builder.build().expect("build"));

    let (challenge_der, challenge_key) = gen_leaf("a.example.com");
    let mut challenge_builder = ChallengeCertsBuilder::new([9u8; 16]);
    challenge_builder
        .insert(
            "a.example.com",
            ChallengeKey::from_der(&challenge_der, &challenge_key).expect("valid"),
            UnixSeconds::new(2_000),
        )
        .expect("valid");
    // A second name that has a live challenge entry and NO real certificate at all, so that a
    // mutant which makes the normal branch fall back to the challenge map ONLY when
    // `CertIndex::resolve` misses (rather than never consulting it at all) has somewhere to be
    // caught: the first name above always has a real credential too, so `certs.resolve` never
    // misses there and such a fallback would never fire.
    let (challenge_only_der, challenge_only_key) = gen_leaf("challenge-only.example.com");
    challenge_builder
        .insert(
            "challenge-only.example.com",
            ChallengeKey::from_der(&challenge_only_der, &challenge_only_key).expect("valid"),
            UnixSeconds::new(2_000),
        )
        .expect("valid");

    let challenge = Arc::new(challenge_builder.build_with_generation(0).expect("build"));
    assert_ne!(
        blake3::hash(&real_der),
        blake3::hash(&challenge_der),
        "the fixture must use two distinct leaves so this test can actually distinguish them"
    );

    let policy = Arc::new(TlsPolicy::default_https());
    let clock = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(certs, challenge, policy, clock));

    // A normal listener ALPN policy, deliberately NOT including `acme-tls/1` (see the Do NOT note
    // in `handshake_acme_alpn_gets_challenge_cert` above).
    let server_cfg = Arc::new(build_server_config(resolver, &[b"h2"]));
    let mut server = rustls::ServerConnection::new(Arc::clone(&server_cfg)).expect("server conn");
    let mut client = build_client("a.example.com", &[&real_der], &[b"h2"]);

    assert!(
        pump_handshake(&mut client, &mut server).is_none(),
        "a normal client must still get a working handshake while a challenge is live"
    );
    let served_hash = peer_leaf_hash(&client);
    assert_eq!(
        served_hash,
        blake3::hash(&real_der),
        "a normal ALPN client must be served the real certificate"
    );
    assert_ne!(
        served_hash,
        blake3::hash(&challenge_der),
        "a normal ALPN client must never be served the live challenge certificate"
    );

    // The other half of the same isolation property: a normal-ALPN client asking for a name that
    // has ONLY a live challenge entry (no real certificate anywhere in CertIndex) must get NO
    // certificate at all, never the challenge certificate as a fallback. The client trusts
    // `challenge_only_der` directly: if it did not, this assertion would pass even for a resolver
    // that incorrectly falls back to the challenge map, because the client would then simply
    // reject the (wrongly) served challenge certificate as untrusted rather than because the
    // server sent nothing. Trusting it makes the two failure causes distinguishable, and a
    // correct resolver still fails this handshake regardless of what the client trusts, because
    // it never sends a Certificate message at all.
    let mut miss_server = rustls::ServerConnection::new(server_cfg).expect("server conn");
    let mut miss_client = build_client(
        "challenge-only.example.com",
        &[&challenge_only_der],
        &[b"h2"],
    );
    assert!(
        pump_handshake(&mut miss_client, &mut miss_server).is_some(),
        "a normal ALPN client for a name with only a live challenge entry must fail, not fall \
         back to serving the (here, trusted) challenge certificate"
    );
    assert!(
        miss_client.peer_certificates().is_none(),
        "no certificate, and in particular not the challenge certificate, may have been sent"
    );
}

#[test]
fn handshake_no_allocations_in_resolver() {
    // See this file's module doc for why this does not literally call `resolve_parts` 10,000
    // times the way issue #117's Tests section describes, and what the zero-allocation claim for
    // `resolve_parts` actually rests on instead. What follows is the closest faithful exercise
    // reachable from a file that can only see `irontraffic_tls`'s public API: a real in-memory
    // handshake per iteration, across the same four branches issue #117 names, asserting the
    // functional outcome of every one. Every input (both certificate fixtures, the index, the
    // challenge map, and both server configs) is built once, before any iteration runs, exactly
    // as the issue's "build every input before reading the baseline counter" instruction asks,
    // even though there is no counter here to read a baseline of.
    const ITERATIONS_PER_BRANCH: u32 = 25;

    let (exact_der, exact_key) = gen_leaf("exact.example.com");
    let exact_cred = load_cred(&exact_der, &exact_key);
    let (wild_der, wild_key) = gen_leaf("*.wild.example.com");
    let wild_cred = load_cred(&wild_der, &wild_key);
    let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
    certs_builder
        .upsert_exact("exact.example.com", exact_cred)
        .expect("valid");
    certs_builder
        .upsert_wildcard("*.wild.example.com", wild_cred)
        .expect("valid");
    let certs = Arc::new(certs_builder.build().expect("build"));

    let (challenge_der, challenge_key) = gen_leaf("challenge.example.com");
    let mut challenge_builder = ChallengeCertsBuilder::new([9u8; 16]);
    challenge_builder
        .insert(
            "challenge.example.com",
            ChallengeKey::from_der(&challenge_der, &challenge_key).expect("valid"),
            UnixSeconds::new(2_000),
        )
        .expect("valid");
    let challenge = Arc::new(challenge_builder.build_with_generation(0).expect("build"));

    let policy = Arc::new(TlsPolicy::default_https());
    let clock = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(
        Arc::clone(&certs),
        Arc::clone(&challenge),
        policy,
        clock,
    ));

    let normal_server_cfg = Arc::new(build_server_config(Arc::clone(&resolver), &[b"h2"]));
    let challenge_server_cfg = Arc::new(build_server_config(resolver, &[b"acme-tls/1"]));

    for _ in 0..ITERATIONS_PER_BRANCH {
        // Exact-hit branch.
        let mut server =
            rustls::ServerConnection::new(Arc::clone(&normal_server_cfg)).expect("server conn");
        let mut client = build_client("exact.example.com", &[&exact_der], &[b"h2"]);
        assert!(pump_handshake(&mut client, &mut server).is_none());
        assert_eq!(peer_leaf_hash(&client), blake3::hash(&exact_der));

        // Wildcard-hit branch.
        let mut server =
            rustls::ServerConnection::new(Arc::clone(&normal_server_cfg)).expect("server conn");
        let mut client = build_client("sub.wild.example.com", &[&wild_der], &[b"h2"]);
        assert!(pump_handshake(&mut client, &mut server).is_none());
        assert_eq!(peer_leaf_hash(&client), blake3::hash(&wild_der));

        // Miss branch: no default configured, no matching name.
        let mut server =
            rustls::ServerConnection::new(Arc::clone(&normal_server_cfg)).expect("server conn");
        let mut client = build_client("missing.example.com", &[], &[b"h2"]);
        assert!(pump_handshake(&mut client, &mut server).is_some());

        // Challenge branch.
        let mut server =
            rustls::ServerConnection::new(Arc::clone(&challenge_server_cfg)).expect("server conn");
        let mut client = build_client("challenge.example.com", &[&challenge_der], &[b"acme-tls/1"]);
        assert!(pump_handshake(&mut client, &mut server).is_none());
        assert_eq!(peer_leaf_hash(&client), blake3::hash(&challenge_der));
    }
}
