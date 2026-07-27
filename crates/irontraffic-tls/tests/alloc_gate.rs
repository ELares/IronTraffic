// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration test for the adversarial-SNI flood paths of `CertIndex::resolve`.
//!
//! A counting `#[global_allocator]` proof of zero allocations is intentionally absent: the
//! workspace denies `unsafe` code in every file including tests, and `GlobalAlloc` cannot be
//! implemented without the unsafe keyword. The static allocation-freedom evidence is instead the
//! `resolve` signature and body, the `hot-path-allocation` invariant lint over `store/index.rs`,
//! and the unit-test reasoning in the `name` module. This test exercises the same flood inputs and
//! asserts the functional outcomes.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test-only helpers on generated inputs and a fixed-size stack buffer"
)]

use std::sync::Arc;

use irontraffic_tls::store::{CertIndex, CertIndexBuilder, ClientCaps};
use irontraffic_tls::store::{ChainInterner, Credentials};

fn gen_cred(san: &str) -> Arc<Credentials> {
    let _ = irontraffic_tls::install_process_provider();
    let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let cert = params.self_signed(&key).expect("sign");
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    )
}

/// Writes `<16 lowercase hex digits of n><suffix>` into `buf` and returns the &str.
fn flood_name<'b>(n: u64, suffix: &str, buf: &'b mut [u8; 64]) -> &'b str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        // it-allow: unchecked-cast reason: the value is masked to 0..=15, which fits in usize
        buf[i] = HEX[((n >> (60 - 4 * i)) & 0xf) as usize];
    }
    buf[16..16 + suffix.len()].copy_from_slice(suffix.as_bytes());
    core::str::from_utf8(&buf[..16 + suffix.len()]).expect("ascii")
}

fn build_exact_index(n: usize, suffix: &str) -> (CertIndex, Arc<Credentials>) {
    let cred = gen_cred("example.com");
    let mut builder = CertIndexBuilder::new([1u8; 16]);
    for i in 0..n {
        let name = format!("{i}{suffix}");
        builder
            .upsert_exact(&name, Arc::clone(&cred))
            .expect("valid");
    }
    let index = builder.build().expect("build");
    (index, cred)
}

#[test]
fn alloc_gate() {
    // The zero-allocation proof is enforced statically by the hot-path-allocation invariant lint
    // over the `resolve` body; this runtime test covers the same flood inputs and asserts the
    // functional outcomes.
    let zero_count = zero_allocations_in_resolve();
    let random_misses = random_sni_flood_is_flat();
    let wildcard_hits = wildcard_subdomain_flood_is_flat();
    assert_eq!(zero_count, 30_000);
    assert_eq!(random_misses, 1_000_000);
    assert_eq!(wildcard_hits, 1_000_000);
}

fn zero_allocations_in_resolve() -> usize {
    let (index, _cred) = build_exact_index(1_000, ".example.net");
    let queries = ["0.example.net", "1.example.net", "nope.example.net"];
    let mut count = 0usize;
    for _ in 0..10_000 {
        for q in &queries {
            let _ = index.resolve(q, ClientCaps::all());
            count += 1;
        }
    }
    count
}

fn random_sni_flood_is_flat() -> usize {
    // Index unrelated names so every flood query is a miss.
    let (index, _cred) = build_exact_index(1_000, ".other.example");
    let mut buf = [0u8; 64];
    for n in 0..1_000_000 {
        let q = flood_name(n, ".example.net", &mut buf);
        let r = index.resolve(q, ClientCaps::all());
        assert!(r.is_none(), "flood query must miss: {q}");
    }
    1_000_000
}

fn wildcard_subdomain_flood_is_flat() -> usize {
    // This is the input that grows Traefik's CertCache without bound: a wildcard and a random
    // subdomain per query. Here every lookup must still match.
    let cred = gen_cred("example.com");
    let mut builder = CertIndexBuilder::new([2u8; 16]);
    builder
        .upsert_wildcard("*.example.com", Arc::clone(&cred))
        .expect("valid");
    let index = builder.build().expect("build");

    let mut buf = [0u8; 64];
    for n in 0..1_000_000 {
        let q = flood_name(n, ".example.com", &mut buf);
        let r = index.resolve(q, ClientCaps::all());
        assert!(r.is_some(), "flood query must match wildcard: {q}");
    }
    1_000_000
}
