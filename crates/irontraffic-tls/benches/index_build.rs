// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for `CertIndexBuilder::from_previous`'s incremental rebuild cost, and for
//! `TlsMaterialCell`'s publish/load pair.
//!
//! Budgets are recorded here, not gated, exactly as this issue's own Benchmarks section states:
//! the 30 ms design-note figure was an unmeasured estimate, and the 20 ms single-update /
//! 1.5x batch-of-16 / 15 ns publish-load figures are numbers for a human to read in the PR body,
//! not enforced by this file. `perf-budgets-file-and-raise-lint` (#418) is what wires up
//! enforcement once its budget file exists, the same note `benches/resolve.rs` already carries.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::integer_division,
    reason = "criterion_group! generates this pub item"
)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_tls::CertIndex;
use irontraffic_tls::policy::TlsPolicy;
use irontraffic_tls::store::{
    CertIndexBuilder, ChainInterner, ChallengeCerts, Credentials, IronResolver, TimeView,
    TlsMaterial, TlsMaterialCell,
};
use irontraffic_tls::time::UnixSeconds;

const NS: [usize; 3] = [1_000, 10_000, 100_000];

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

fn build_index(n: usize, cred: &Arc<Credentials>) -> CertIndex {
    let mut builder = CertIndexBuilder::new([1u8; 16]);
    for i in 0..n {
        let name = format!("host{i}.example.com");
        builder
            .upsert_exact(&name, Arc::clone(cred))
            .expect("valid");
    }
    builder.build().expect("build")
}

fn bench_from_scratch(c: &mut Criterion) {
    let cred = gen_cred("example.com");
    for &n in &NS {
        c.bench_function(&format!("build/from_scratch/{n}"), |b| {
            b.iter(|| build_index(black_box(n), &cred));
        });
    }
}

fn bench_from_previous_single(c: &mut Criterion) {
    let cred = gen_cred("example.com");
    let new_cred = gen_cred("new.example.com");
    for &n in &NS {
        let index = build_index(n, &cred);
        c.bench_function(&format!("update/from_previous_single/{n}"), |b| {
            b.iter(|| {
                let mut cb = CertIndexBuilder::from_previous(black_box(&index));
                cb.upsert_exact("updated.example.com", Arc::clone(&new_cred))
                    .expect("valid");
                cb.build_with_generation(1).expect("build")
            });
        });
    }
}

fn bench_from_previous_batch16(c: &mut Criterion) {
    let cred = gen_cred("example.com");
    let new_cred = gen_cred("new.example.com");
    let index = build_index(100_000, &cred);
    c.bench_function("update/from_previous_batch16/100000", |b| {
        b.iter(|| {
            let mut cb = CertIndexBuilder::from_previous(black_box(&index));
            for i in 0..16 {
                let name = format!("updated{i}.example.com");
                cb.upsert_exact(&name, Arc::clone(&new_cred))
                    .expect("valid");
            }
            cb.build_with_generation(1).expect("build")
        });
    });
}

struct BenchClock;
impl TimeView for BenchClock {
    fn unix_seconds(&self) -> UnixSeconds {
        UnixSeconds::new(1_000)
    }
}

fn bench_publish_load(c: &mut Criterion) {
    let cred = gen_cred("example.com");
    let certs = Arc::new(build_index(1_000, &cred));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let time: Arc<dyn TimeView> = Arc::new(BenchClock);
    let resolver = Arc::new(IronResolver::new(
        Arc::clone(&certs),
        Arc::clone(&challenge),
        Arc::clone(&policy),
        Arc::clone(&time),
    ));
    let material = Arc::new(TlsMaterial {
        certs,
        challenge,
        resolver,
        listeners: Arc::from(Vec::new()),
        generation: 0,
    });
    let cell = TlsMaterialCell::new(material);
    c.bench_function("publish/load", |b| {
        b.iter(|| {
            let guard = cell.load();
            black_box(Arc::clone(&guard));
        });
    });
}

criterion_group!(
    benches,
    bench_from_scratch,
    bench_from_previous_single,
    bench_from_previous_batch16,
    bench_publish_load
);
criterion_main!(benches);
