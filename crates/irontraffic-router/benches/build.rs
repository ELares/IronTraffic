// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Build-path microbenchmarks for `build_group`.
//!
//! Build path, not request path, but it is a published headline number because
//! competitor reload latency is a genuine weakness (Traefik's build is
//! quadratic, NGINX requires a worker generation fork, Kong's incremental
//! rebuild mutates live state and yields per route).
//!
//! `host-trie-and-group-chain` (#55) adds `bench_build_host_trie_10k` here,
//! `builder-admission-and-assemble` (#56) adds the three full-build
//! benchmarks, and `incremental-group-rebuild` (#65) adds the four rebuild
//! benchmarks.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_router::{
    ActionId, CandInput, GroupId, GroupParts, PathKind, Precedence, RouteId, SENTINEL, build_group,
};

/// 100,000 keys drawn from a realistic distribution: 10,000 distinct
/// 3-segment prefixes (`/svc{p}/v1/res{p}`) with 10 paths each.
fn realistic_keys() -> Vec<String> {
    let mut keys = Vec::with_capacity(100_000);
    for p in 0..10_000u32 {
        let prefix = format!("/svc{p}/v1/res{p}");
        for i in 0..10u32 {
            keys.push(format!("{prefix}/{i}"));
        }
    }
    keys
}

/// 5,000 keys nesting 5,000 deep (`/a`, `/aa`, `/aaa`, ...), the shape that
/// catches an accidentally quadratic split path.
fn deep_keys() -> Vec<String> {
    (1..=5000usize)
        .map(|n| format!("/{}", "a".repeat(n)))
        .collect()
}

/// One unconditional `Exact` candidate per key, with distinct ordinals
/// assigned in slice order.
fn keyed_cands(keys: &[String]) -> Vec<CandInput<'_>> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            // `unwrap_or(0)` rather than `expect`: `clippy::expect_used` is
            // denied and benches are not test code, so this file has no
            // exemption. Every ordinal `keyed_cands` is ever called with here
            // fits `u32` easily (at most 100,000), so the fallback never
            // actually triggers; on the (unreachable) `Err` branch it just
            // means a benchmark run demonstrates the same duplicate-ordinal
            // input twice, not a panic.
            let ordinal = u32::try_from(i).unwrap_or(0);
            CandInput {
                key: k.as_bytes(),
                kind: PathKind::Exact,
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, ordinal),
                action: ActionId(ordinal),
                route: RouteId(ordinal),
                preds: SENTINEL,
            }
        })
        .collect()
}

fn fresh_parts() -> GroupParts {
    GroupParts {
        preds: Vec::new(),
        blob: Vec::new(),
        next: GroupId::NONE,
        content_hash: 0,
        max_nodes: 1_000_000,
        max_blob_bytes: 50_000_000,
    }
}

/// Budget: under 200 ms wall time and under 48 MB peak resident for the
/// emitted group, single-threaded, on the reference machine.
fn bench_build_group_100k(c: &mut Criterion) {
    let keys = realistic_keys();
    let cands = keyed_cands(&keys);
    c.bench_function("build/build_group_100k", |b| {
        b.iter(|| {
            // `if let` rather than `.expect(...)`: `clippy::expect_used` is
            // denied and benches carry no test exemption. This input is
            // always well-formed, so the `Err` arm never runs; it is here
            // only so this loop cannot panic if that ever stopped being true.
            if let Ok(group) = build_group(std::hint::black_box(&cands), fresh_parts()) {
                std::hint::black_box(group);
            }
        });
    });
}

/// Budget: under 20 ms. This is the benchmark that catches an accidentally
/// quadratic split path.
fn bench_build_group_deep(c: &mut Criterion) {
    let keys = deep_keys();
    let cands = keyed_cands(&keys);
    c.bench_function("build/build_group_deep", |b| {
        b.iter(|| {
            // See `bench_build_group_100k`'s matching comment.
            if let Ok(group) = build_group(std::hint::black_box(&cands), fresh_parts()) {
                std::hint::black_box(group);
            }
        });
    });
}

criterion_group!(benches, bench_build_group_100k, bench_build_group_deep);
criterion_main!(benches);
