// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for `normalize` and `NameHasher::hash`, the two functions that
//! run once or twice per TLS handshake on the SNI path.
//!
//! Budgets are recorded here, not gated: `perf-budgets-file-and-raise-lint`
//! (#418) wires up enforcement once its budget file exists. `normalize/20b`
//! under 40 ns, `normalize/253b` and `normalize/uppercase_253b` under 200 ns,
//! `hash/20b` under 30 ns, `hash/253b` under 130 ns.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_tls::NameHasher;
use irontraffic_tls::name::{MAX_NAME_LEN, normalize};

const SHORT: &str = "apiv1.us.example.com";

/// The 127-label, 253-byte name used by the two largest-input benchmarks.
fn long_name() -> String {
    vec!["a"; 127].join(".")
}

fn bench_normalize(c: &mut Criterion) {
    let long = long_name();
    let long_upper = long.to_ascii_uppercase();

    // `buf` is declared inside the outer closure (called once per
    // `bench_function`) rather than passed in from further out: a `FnMut`
    // closure cannot return a borrow of one of its own captures, so the
    // normalized `&str` is consumed by `black_box` inside the timed closure
    // instead of being returned from it.
    c.bench_function("normalize/20b", |b| {
        let mut buf = [0u8; MAX_NAME_LEN];
        b.iter(|| {
            // The `Result` is consumed by `black_box` and dropped inside the
            // timed closure rather than returned from it (a `FnMut` closure
            // cannot return a borrow of one of its own captures), so this is
            // a deliberate discard, not a swallowed error: normalize's
            // Ok/Err behaviour is name.rs's unit tests' job, not this
            // benchmark's.
            let _ = black_box(normalize(black_box(SHORT), &mut buf));
        });
    });

    c.bench_function("normalize/253b", |b| {
        let mut buf = [0u8; MAX_NAME_LEN];
        b.iter(|| {
            let _ = black_box(normalize(black_box(long.as_str()), &mut buf));
        });
    });

    c.bench_function("normalize/uppercase_253b", |b| {
        let mut buf = [0u8; MAX_NAME_LEN];
        b.iter(|| {
            let _ = black_box(normalize(black_box(long_upper.as_str()), &mut buf));
        });
    });
}

fn bench_hash(c: &mut Criterion) {
    let hasher = NameHasher::new([7u8; 16]);
    let long = long_name();

    c.bench_function("hash/20b", |b| {
        b.iter(|| hasher.hash(black_box(SHORT)));
    });

    c.bench_function("hash/253b", |b| {
        b.iter(|| hasher.hash(black_box(long.as_str())));
    });
}

criterion_group!(benches, bench_normalize, bench_hash);
criterion_main!(benches);
