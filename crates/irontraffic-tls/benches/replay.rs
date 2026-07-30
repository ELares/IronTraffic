// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for `EarlyDataFilter` and `early_data::evaluate`.
//!
//! Budgets are recorded here, not gated: `perf-budgets-file-and-raise-lint` (#418) wires up
//! enforcement once its budget file exists. See `early-data-policy-and-replay-filter`'s own
//! Benchmarks section for the budget each id below is checked against; the PR that lands this
//! file records the measured medians and a pass or fail note against every budget in its own
//! body.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

use std::hint::black_box;
use std::sync::atomic::{AtomicU32, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_tls::early_data::{
    EarlyDataConfig, EarlyDataFacts, EarlyDataMethod, RouteEarlyData, evaluate,
};
use irontraffic_tls::replay::EarlyDataFilter;
use irontraffic_tls::time::UnixSeconds;

/// The default configuration this issue specifies: capacity 1,000,000, so a criterion run of a
/// few hundred thousand iterations stays well under it (`early_data/evaluate_accept` needs this,
/// per its own note in the issue's Benchmarks section).
fn default_config() -> EarlyDataConfig {
    EarlyDataConfig {
        enabled: true,
        max_bytes: 16_384,
        replay_capacity: 1_000_000,
        replay_rotate_secs: 10_800,
    }
}

/// A fixed 16-byte key: benchmarks are not a security context, and every other bench and test
/// fixture in this crate uses a fixed key the same way (`ticket.rs`'s `test_ticketer`, `name.rs`'s
/// `NameHasher::new` in tests).
const FILTER_KEY: [u8; 16] = [0x5A; 16];

fn bench_probe_miss(c: &mut Criterion) {
    // Filter at 50% of capacity: 500,000 distinct keys inserted, then probe an absent one.
    let cfg = default_config();
    let f = EarlyDataFilter::new(&cfg, FILTER_KEY, UnixSeconds::new(1_700_000_000));
    for i in 0u32..500_000 {
        let mut key = [0u8; 16];
        key[0] = 0x00;
        key[1..5].copy_from_slice(&i.to_be_bytes());
        f.insert(&key);
    }
    let absent = [0xFFu8; 16];

    c.bench_function("replay/probe_miss", |b| {
        b.iter(|| black_box(f.contains(black_box(&absent))));
    });
}

fn bench_probe_hit(c: &mut Criterion) {
    let cfg = default_config();
    let f = EarlyDataFilter::new(&cfg, FILTER_KEY, UnixSeconds::new(1_700_000_000));
    let present = [0x11u8; 16];
    f.insert(&present);

    c.bench_function("replay/probe_hit", |b| {
        b.iter(|| black_box(f.contains(black_box(&present))));
    });
}

fn bench_insert(c: &mut Criterion) {
    let cfg = default_config();
    let f = EarlyDataFilter::new(&cfg, FILTER_KEY, UnixSeconds::new(1_700_000_000));
    // Each iteration must use a fresh key: reusing one would turn every iteration after the
    // first into a replay hit rather than the insert path this id measures.
    let counter = AtomicU32::new(0);

    c.bench_function("replay/insert", |b| {
        b.iter(|| {
            let i = counter.fetch_add(1, Ordering::Relaxed);
            let mut key = [0u8; 16];
            key[0] = 0x22;
            key[1..5].copy_from_slice(&i.to_be_bytes());
            black_box(f.check_and_insert(black_box(&key)))
        });
    });
}

fn bench_rotate_1m(c: &mut Criterion) {
    let cfg = default_config();
    let f = EarlyDataFilter::new(&cfg, FILTER_KEY, UnixSeconds::new(0));
    let mut now = u64::from(cfg.replay_rotate_secs);

    c.bench_function("replay/rotate/1M", |b| {
        b.iter(|| {
            // Always due: `now` advances by a full rotation period every iteration.
            f.rotate_if_due(UnixSeconds::new(now));
            now += u64::from(cfg.replay_rotate_secs);
        });
    });
}

fn bench_evaluate_accept(c: &mut Criterion) {
    let cfg = default_config();
    let f = EarlyDataFilter::new(&cfg, FILTER_KEY, UnixSeconds::new(1_700_000_000));
    let counter = AtomicU32::new(0);

    c.bench_function("early_data/evaluate_accept", |b| {
        b.iter(|| {
            let i = counter.fetch_add(1, Ordering::Relaxed);
            let mut psk = [0u8; 16];
            psk[0] = 0x33;
            psk[1..5].copy_from_slice(&i.to_be_bytes());
            let facts = EarlyDataFacts {
                client_auth_enforced: false,
                method: EarlyDataMethod::Get,
                has_body_framing: false,
                has_query: false,
                route: RouteEarlyData::Allow,
                bytes_received: 0,
                psk_identity: &psk,
            };
            black_box(evaluate(black_box(&cfg), black_box(&f), black_box(&facts)))
        });
    });
}

fn bench_evaluate_reject_method(c: &mut Criterion) {
    let cfg = default_config();
    let f = EarlyDataFilter::new(&cfg, FILTER_KEY, UnixSeconds::new(1_700_000_000));
    let psk = [0x44u8; 16];
    let facts = EarlyDataFacts {
        client_auth_enforced: false,
        method: EarlyDataMethod::Other,
        has_body_framing: false,
        has_query: false,
        route: RouteEarlyData::AllowQuery,
        bytes_received: 0,
        psk_identity: &psk,
    };

    c.bench_function("early_data/evaluate_reject_method", |b| {
        b.iter(|| black_box(evaluate(black_box(&cfg), black_box(&f), black_box(&facts))));
    });
}

criterion_group!(
    benches,
    bench_probe_miss,
    bench_probe_hit,
    bench_insert,
    bench_rotate_1m,
    bench_evaluate_accept,
    bench_evaluate_reject_method,
);
criterion_main!(benches);
