// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for `CertIndex::resolve`, the certificate-selection path per TLS handshake.
//!
//! Budgets are recorded here, not gated: `perf-budgets-file-and-raise-lint` (#418) wires up
//! enforcement once its budget file exists. The flatness assertion (max/min ratio under 1.35
//! across n) is the important property and is enforced by the unit test
//! `store::index::tests::resolve_flat_across_n`.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_tls::{CertIndex, CertIndexBuilder, ClientCaps};
use irontraffic_tls::store::{ChainInterner, Credentials};

const NS: [usize; 4] = [1, 100, 10_000, 100_000];

fn gen_cred() -> Arc<Credentials> {
    let _ = irontraffic_tls::install_process_provider();
    let params = rcgen::CertificateParams::new(vec!["example.com".to_owned()])
        .expect("valid SANs");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let cert = params.self_signed(&key).expect("sign");
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    )
}

fn build_exact_index(n: usize, cred: &Arc<Credentials>) -> CertIndex {
    let mut builder = CertIndexBuilder::new([1u8; 16]);
    for i in 0..n {
        let name = format!("host{i}.example.com");
        builder.upsert_exact(&name, Arc::clone(cred)).expect("valid");
    }
    builder.build().expect("build")
}

fn build_wild_index(n: usize, cred: &Arc<Credentials>) -> CertIndex {
    let mut builder = CertIndexBuilder::new([2u8; 16]);
    for i in 0..n {
        let parent = format!("wild{i}.example.com");
        builder
            .upsert_wildcard(&format!("*.{parent}"), Arc::clone(cred))
            .expect("valid");
    }
    builder.build().expect("build")
}

fn build_miss_index(n: usize, cred: &Arc<Credentials>) -> CertIndex {
    // Index unrelated names so the query misses.
    let mut builder = CertIndexBuilder::new([3u8; 16]);
    for i in 0..n {
        let name = format!("other{i}.example.net");
        builder.upsert_exact(&name, Arc::clone(cred)).expect("valid");
    }
    builder.build().expect("build")
}

fn bench_resolve_exact_hit(c: &mut Criterion) {
    let cred = gen_cred();
    for &n in &NS {
        let index = build_exact_index(n, &cred);
        let query = format!("host{}.example.com", n / 2);
        c.bench_function(&format!("resolve/exact_hit/{n}"), |b| {
            b.iter(|| index.resolve(black_box(&query), ClientCaps::all()));
        });
    }
}

fn bench_resolve_wildcard_hit(c: &mut Criterion) {
    let cred = gen_cred();
    for &n in &NS {
        let index = build_wild_index(n, &cred);
        let query = format!("0123456789abcdef.wild{}.example.com", n / 2);
        c.bench_function(&format!("resolve/wildcard_hit/{n}"), |b| {
            b.iter(|| index.resolve(black_box(&query), ClientCaps::all()));
        });
    }
}

fn bench_resolve_miss(c: &mut Criterion) {
    let cred = gen_cred();
    for &n in &NS {
        let index = build_miss_index(n, &cred);
        let query = "no-such-name.example.com";
        c.bench_function(&format!("resolve/miss/{n}"), |b| {
            b.iter(|| index.resolve(black_box(query), ClientCaps::all()));
        });
    }
}

fn long_name() -> String {
    vec!["a"; 127].join(".")
}

fn bench_resolve_exact_hit_253b(c: &mut Criterion) {
    let cred = gen_cred();
    let mut builder = CertIndexBuilder::new([4u8; 16]);
    let name = long_name();
    builder.upsert_exact(&name, Arc::clone(&cred)).expect("valid");
    for i in 0..99_999 {
        let filler = format!("host{i}.example.com");
        builder.upsert_exact(&filler, Arc::clone(&cred)).expect("valid");
    }
    let index = builder.build().expect("build");
    c.bench_function("resolve/exact_hit_253b/100000", |b| {
        b.iter(|| index.resolve(black_box(&name), ClientCaps::all()));
    });
}

fn bench_resolve_invalid_sni(c: &mut Criterion) {
    let cred = gen_cred();
    let mut builder = CertIndexBuilder::new([5u8; 16]);
    for i in 0..100_000 {
        let filler = format!("host{i}.example.com");
        builder.upsert_exact(&filler, Arc::clone(&cred)).expect("valid");
    }
    let index = builder.build().expect("build");
    let query = "a".repeat(254);
    c.bench_function("resolve/invalid_sni/100000", |b| {
        b.iter(|| index.resolve(black_box(&query), ClientCaps::all()));
    });
}

fn bench_select_four_types(c: &mut Criterion) {
    let _ = irontraffic_tls::install_process_provider();
    let mut builder = CertIndexBuilder::new([6u8; 16]);

    let p256 = gen_key_cred(&rcgen::PKCS_ECDSA_P256_SHA256);
    let p384 = gen_key_cred(&rcgen::PKCS_ECDSA_P384_SHA384);
    let rsa = gen_key_cred(&rcgen::PKCS_RSA_SHA256);
    let ed = gen_key_cred(&rcgen::PKCS_ED25519);
    for cred in [&p256, &p384, &rsa, &ed] {
        builder
            .upsert_exact("select.example.com", Arc::clone(cred))
            .expect("valid");
    }
    let index = builder.build().expect("build");
    c.bench_function("select/four_types", |b| {
        b.iter(|| index.resolve(black_box("select.example.com"), ClientCaps::all()));
    });
}

fn gen_key_cred(alg: &'static rcgen::SignatureAlgorithm) -> Arc<Credentials> {
    let params = rcgen::CertificateParams::new(vec!["select.example.com".to_owned()])
        .expect("valid SANs");
    let key = rcgen::KeyPair::generate_for(alg).expect("keygen");
    let cert = params.self_signed(&key).expect("sign");
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    )
}

criterion_group!(
    benches,
    bench_resolve_exact_hit,
    bench_resolve_wildcard_hit,
    bench_resolve_miss,
    bench_resolve_exact_hit_253b,
    bench_resolve_invalid_sni,
    bench_select_four_types
);
criterion_main!(benches);
