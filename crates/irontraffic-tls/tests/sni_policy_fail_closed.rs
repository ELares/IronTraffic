// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CVE-shaped tests for per-SNI policy selection, driving real in-memory rustls handshakes.
//!
//! Each test here is named for the failure it prevents. Traefik's four mTLS bypasses all reduce to
//! two mistakes: resolving TLS options by a different rule than certificates, and falling back to a
//! permissive default when resolution missed. A test that only checked the happy path would pass
//! against every one of those CVEs.
//!
//! `mtls_name_requires_client_cert_while_sibling_does_not` is deliberately NOT here: building a
//! `Required` configuration needs a real client-certificate verifier, which is
//! `mtls-client-auth-fail-closed` (#124). It writes that test into this file when it lands.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test code: fixtures are built in the test itself, so a failed unwrap is \
              a broken fixture and must be loud rather than silently reshaping the assertion"
)]

use std::sync::{Arc, Once};

use irontraffic_tls::listener::{
    AcceptStep, ListenerTls, ListenerTlsBuilder, RejectReason, TlsServerConfig,
};
use irontraffic_tls::policy::TlsPolicy;
use irontraffic_tls::store::{
    CertIndexBuilder, ChainInterner, ChallengeCerts, Credentials, IronResolver, TimeView,
};
use irontraffic_tls::time::UnixSeconds;

const SEED: [u8; 16] = [11u8; 16];

fn ensure_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
    });
}

struct FixedClock(UnixSeconds);
impl TimeView for FixedClock {
    fn unix_seconds(&self) -> UnixSeconds {
        self.0
    }
}

fn gen_cred(san: &str) -> Arc<Credentials> {
    ensure_provider_installed();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
    let cert = params.self_signed(&key).expect("sign");
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    )
}

/// A real, compiled configuration serving `san` for `name`.
fn real_config(name: &str, san: &str) -> Arc<TlsServerConfig> {
    real_config_inner(name, san, false)
}

/// The same, but the credential is ALSO the index's default, so a handshake carrying no SNI
/// actually reaches a certificate rather than failing for want of one.
fn real_config_serving_no_sni(name: &str, san: &str) -> Arc<TlsServerConfig> {
    real_config_inner(name, san, true)
}

fn real_config_inner(name: &str, san: &str, as_default: bool) -> Arc<TlsServerConfig> {
    ensure_provider_installed();
    let mut b = CertIndexBuilder::new(SEED);
    let cred = gen_cred(san);
    b.upsert_exact(name, Arc::clone(&cred)).expect("valid");
    if as_default {
        b.set_default(cred);
    }
    let certs = Arc::new(b.build().expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([3u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(
        certs,
        challenge,
        Arc::clone(&policy),
        time,
    ));
    Arc::new(TlsServerConfig::compile(policy, resolver).expect("provider installed"))
}

/// Real `ClientHello` bytes. `None` produces a hello with NO server-name extension.
fn client_hello_bytes(sni: Option<&str>) -> Vec<u8> {
    ensure_provider_installed();
    let roots = rustls::RootCertStore::empty();
    let cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let name: rustls::pki_types::ServerName<'static> = match sni {
        Some(s) => s.to_owned().try_into().expect("valid dns name"),
        None => {
            rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into())
        }
    };
    let mut client = rustls::ClientConnection::new(cfg, name).expect("client connection");
    let mut out = Vec::new();
    while client.wants_write() {
        client
            .write_tls(&mut out)
            .expect("writing to a Vec cannot fail");
    }
    out
}

/// A listener bound only to `a.example.com`, with no fallback and no no-SNI policy.
fn strict_listener() -> Arc<ListenerTls> {
    let mut b = ListenerTlsBuilder::new(SEED);
    b.bind_exact(
        "a.example.com",
        real_config("a.example.com", "a.example.com"),
    )
    .expect("valid");
    Arc::new(b.build().expect("no divergence in a single binding"))
}

#[test]
fn unmatched_sni_is_rejected() {
    let l = strict_listener();
    let mut acc = l.acceptor();
    let step = acc.feed(&client_hello_bytes(Some("nope.example.com")));

    let AcceptStep::Reject { reason, .. } = step else {
        panic!("an SNI matching no binding must REJECT, not inherit a permissive default");
    };
    assert_eq!(reason, RejectReason::NoPolicyForName);

    // No configuration was handed back, so no certificate can have been sent: the only way a
    // certificate reaches the peer is through `AcceptedHello::into_connection`, which needs the
    // `TlsServerConfig` that `Ready` would have carried.
    assert_eq!(
        l.stats().rejects[RejectReason::NoPolicyForName as usize]
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn no_sni_without_policy_is_rejected() {
    let l = strict_listener();
    let mut acc = l.acceptor();
    let step = acc.feed(&client_hello_bytes(None));

    let AcceptStep::Reject { reason, .. } = step else {
        panic!("no SNI with no configured no-SNI policy must REJECT");
    };
    assert_eq!(reason, RejectReason::NoSniPolicy);
}

#[test]
fn no_sni_with_policy_uses_it() {
    let no_sni = real_config_serving_no_sni("default.example.com", "default.example.com");
    let mut b = ListenerTlsBuilder::new(SEED);
    b.bind_exact(
        "a.example.com",
        real_config("a.example.com", "a.example.com"),
    )
    .expect("valid");
    b.set_no_sni(Arc::clone(&no_sni));
    let l = Arc::new(b.build().expect("equal auth"));

    let mut acc = l.acceptor();
    let AcceptStep::Ready { config, accepted } = acc.feed(&client_hello_bytes(None)) else {
        panic!("no SNI with a configured policy must use it");
    };
    assert!(
        Arc::ptr_eq(&config, &no_sni),
        "the configured no-SNI policy must be the one chosen"
    );

    // And it really starts a connection, so the configuration is usable rather than merely
    // selected.
    assert!(
        accepted.into_connection(&config).is_ok(),
        "the chosen configuration must actually start a connection"
    );
}

// `cve_2026_48491_domain_fronting_config_is_refused` is NOT in this file, and the reason is a
// real constraint rather than an omission.
//
// Issue #119 places that test here while also specifying `TlsServerConfig::test_stub` as
// `#[cfg(test)] pub(crate)`. Those two cannot both hold: `tests/` compiles as a separate crate, so
// it sees neither `cfg(test)` items nor `pub(crate)` ones. The lint reasons purely about
// `ClientAuthKind` labels, and until #124 lands every real, compilable configuration is
// `ClientAuthKind::None`, so no divergence can be constructed from this side at all.
//
// Widening the stub to `pub` would fix the reachability and create a worse problem: a
// publicly-constructible configuration that REPORTS `Required` while enforcing nothing is exactly
// the label-without-enforcement shape this whole module exists to prevent, and it would be
// reachable from production code.
//
// The assertion itself is not lost. It lives in `listener.rs`'s unit tests as
// `lint_rejects_client_auth_divergence`, with the same four field values #119 names: `exact ==
// "secure.example.com"`, `wildcard == "example.com"`, `exact_auth == Required`, `wildcard_auth ==
// None`, and no listener produced.

#[test]
fn fragmented_client_hello_resolves_same_policy() {
    // CVE-2026-32305: a ClientHello fragmented across records made Traefik's SNI extraction
    // return empty, and it fell back to the default non-mTLS configuration. Here the same bytes
    // delivered one at a time must select the SAME policy, and every intermediate step must say
    // NeedMore rather than resolving anything.
    let bound = real_config("a.example.com", "a.example.com");
    let mut b = ListenerTlsBuilder::new(SEED);
    b.bind_exact("a.example.com", Arc::clone(&bound))
        .expect("valid");
    let l = Arc::new(b.build().expect("single binding"));

    let hello = client_hello_bytes(Some("a.example.com"));

    let mut whole = l.acceptor();
    let AcceptStep::Ready {
        config: in_one_chunk,
        ..
    } = whole.feed(&hello)
    else {
        panic!("the whole ClientHello in one chunk must become Ready");
    };

    let mut fragmented = l.acceptor();
    let mut chosen = None;
    for (i, byte) in hello.iter().enumerate() {
        match fragmented.feed(&[*byte]) {
            AcceptStep::NeedMore => {}
            AcceptStep::Ready { config, .. } => {
                assert_eq!(
                    i,
                    hello.len() - 1,
                    "Ready must not arrive before the ClientHello is complete"
                );
                chosen = Some(config);
                break;
            }
            AcceptStep::Reject { reason, .. } => {
                panic!("byte {i} of a valid ClientHello rejected the handshake: {reason:?}")
            }
        }
    }
    let byte_at_a_time = chosen.expect("a complete ClientHello must become Ready");

    assert!(
        Arc::ptr_eq(&byte_at_a_time, &in_one_chunk),
        "fragmentation must not change which policy is selected"
    );
    assert!(
        Arc::ptr_eq(&byte_at_a_time, &bound),
        "and the selected policy must be the bound one, not a default"
    );
}

/// Calls that can allocate on the heap, textually. The identical vocabulary
/// `tests/alloc_gate.rs` uses for `CertIndex::resolve`'s call graph in this same crate, kept as a
/// separate copy here rather than a shared `mod` because that file lives in the same `tests/`
/// directory but is outside this issue's Files table.
const ALLOCATING_CALLS: [&str; 14] = [
    "format!",
    ".to_string()",
    ".to_owned()",
    ".to_vec()",
    "vec![",
    "Vec::new()",
    "String::new()",
    "String::from(",
    "Box::new(",
    "HashMap::new()",
    ".collect::<Vec",
    ".collect::<String",
    ".collect::<HashMap",
    ".clone()",
];

/// Returns the source text of the function whose signature contains `signature`, from its opening
/// brace through its matching closing brace, or `None` if not found. A plain brace-depth text
/// scan, not a Rust parser; mirrors `tests/alloc_gate.rs::extract_fn_body` exactly.
fn extract_fn_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let open = source[start..].find('{').map(|offset| start + offset)?;
    let mut depth = 0usize;
    let mut end = open;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + offset + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end > open {
        Some(&source[open..end])
    } else {
        None
    }
}

/// Issue #119's acceptance criterion for invariant 8 ("`resolve_by_name` performs zero heap
/// allocations"), implemented honestly rather than as originally specified.
///
/// THE ORIGINAL DESIGN, AND WHY IT IS NOT HERE. The issue calls for this file to declare a
/// counting `#[global_allocator]` with a thread-local counter, "exactly the shape in
/// `sni-name-normalization` (#113)'s `no_allocations_in_normalize`". That shape does not exist in
/// this tree: `crates/irontraffic-tls/src/name.rs`'s own `no_allocations_in_normalize` test
/// carries a long comment explaining that a counting `#[global_allocator]` needs the keyword this
/// repository denies, because `GlobalAlloc` is declared as an unsafe trait, which
/// `scripts/invariant-lints.sh`'s `no-unsafe` rule forbids outright, with no
/// exception an implementer may self-grant (the root `Cargo.toml`'s `unsafe_code = "deny"` is a
/// POLICY line, not a missing override). #113 reached the same wall this issue's acceptance
/// criterion did not know about when it was written, and settled on the substitute
/// `tests/alloc_gate.rs` in THIS SAME CRATE already documents at length for `CertIndex::resolve`:
/// a per-function text scan for a fixed list of allocating call spellings, stated plainly as a
/// best-effort net rather than a proof, plus a functional test that exercises the shape the issue
/// actually asks for (hits, wildcard hits, and misses) so the counted behaviour is at least
/// checked for correctness even though allocation itself cannot be counted.
///
/// WHAT THIS TEST ACTUALLY DOES. `resolve_by_name` calls `lookup` and `binding_at`; `lookup` calls
/// `name::normalize`, `name::parent` and `self.hasher.hash`, all of which are already covered by
/// `name.rs`'s own `//! HOT PATH` marker and by `tests/alloc_gate.rs`'s scan of the identical
/// functions `CertIndex::resolve` shares with this one. So this test scans `resolve_by_name`,
/// `client_auth_for_name`, `lookup` and `binding_at` themselves, the four functions new to
/// `listener.rs`, then performs the 10,000 calls across hits, wildcard hits and misses the issue's
/// acceptance criterion names, asserting the FUNCTIONAL outcome of each rather than a byte count no
/// safe mechanism in this tree can produce.
#[test]
fn resolve_by_name_allocates_nothing() {
    let source = include_str!("../src/listener.rs");
    let signatures = [
        (
            "resolve_by_name",
            "pub fn resolve_by_name(&self, sni: &str) -> Option<&Arc<TlsServerConfig>> {",
        ),
        (
            "client_auth_for_name",
            "pub fn client_auth_for_name(&self, authority: &str) -> ClientAuthKind {",
        ),
        (
            "lookup",
            "fn lookup(&self, sni: &str, count: bool) -> Result<Option<u32>, ()> {",
        ),
        (
            "binding_at",
            "fn binding_at(&self, i: u32) -> Option<&Binding> {",
        ),
    ];
    for (name, signature) in signatures {
        let body = extract_fn_body(source, signature).unwrap_or_else(|| {
            panic!(
                "`fn {name}` not found via `{signature}`; has it moved, been renamed, or been \
                 reformatted onto a different single-line signature?"
            )
        });
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; resolve_by_name's whole \
                 call graph is documented to perform zero heap allocations per lookup"
            );
        }
    }

    // Without this marker line, scripts/invariant-lints.sh's hot-path-allocation rule does not
    // scan listener.rs at all, and the text scan above becomes the ONLY thing checking this
    // file, ever, rather than the belt to CI's suspenders it is meant to be. Mirrors
    // `name.rs`'s own `no_allocations_in_normalize` test, which guards the identical marker line
    // for the identical reason.
    assert!(
        source.lines().any(|line| line == "//! HOT PATH"),
        "crates/irontraffic-tls/src/listener.rs must carry a line that is exactly `//! HOT PATH` \
         so scripts/invariant-lints.sh's hot-path-allocation rule scans this module at all"
    );

    // The functional shape the issue's acceptance criterion names: 10,000 calls across hits,
    // wildcard hits and misses.
    let bound = real_config("a.example.com", "a.example.com");
    let wild = real_config("wild.example.com", "wild.example.com");
    let mut b = ListenerTlsBuilder::new(SEED);
    b.bind_exact("a.example.com", Arc::clone(&bound))
        .expect("valid");
    b.bind_wildcard("*.wild.example.com", Arc::clone(&wild))
        .expect("valid");
    let l = b.build().expect("disjoint names, no divergence");

    let mut exact_hits = 0u32;
    let mut wildcard_hits = 0u32;
    let mut misses = 0u32;
    for i in 0..10_000u32 {
        match i % 3 {
            0 => {
                assert!(l.resolve_by_name("a.example.com").is_some());
                exact_hits += 1;
            }
            1 => {
                assert!(l.resolve_by_name("sub.wild.example.com").is_some());
                wildcard_hits += 1;
            }
            _ => {
                assert!(l.resolve_by_name("nope.example.com").is_none());
                misses += 1;
            }
        }
    }
    assert_eq!(exact_hits + wildcard_hits + misses, 10_000);
    assert!(exact_hits > 0 && wildcard_hits > 0 && misses > 0);
}

#[test]
fn truncated_client_hello_is_an_error_not_no_sni() {
    // The other half of CVE-2026-32305: a ClientHello that never completes must never be treated
    // as "no SNI" and routed to the no-SNI policy. This listener HAS a no-SNI policy, so if the
    // truncated hello were mistaken for one, it would be admitted.
    let no_sni = real_config("default.example.com", "default.example.com");
    let mut b = ListenerTlsBuilder::new(SEED);
    b.bind_exact(
        "a.example.com",
        real_config("a.example.com", "a.example.com"),
    )
    .expect("valid");
    b.set_no_sni(Arc::clone(&no_sni));
    let l = Arc::new(b.build().expect("equal auth"));

    let hello = client_hello_bytes(Some("a.example.com"));
    let half = hello.len().div_euclid(2);
    let truncated = &hello[..half];

    let mut acc = l.acceptor();
    // NeedMore and Reject are both correct here, and they are the same assertion: neither hands
    // back a configuration. What must never happen is Ready, which would mean the truncated
    // hello was read as "no SNI" and routed to the no-SNI policy this listener has configured.
    assert!(
        !matches!(acc.feed(truncated), AcceptStep::Ready { .. }),
        "a truncated ClientHello must NOT resolve to the no-SNI policy"
    );
}
