// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Lexer throughput benchmarks for ITPL.
//!
//! These measure config-admission cost, never request-path cost. See
//! `crates/irontraffic-policy/src/lex.rs`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_filter::Phase;
use irontraffic_policy::PolicyLimits;
use irontraffic_policy::check::check;
use irontraffic_policy::lex::lex;
use irontraffic_policy::parse::parse;

fn bench_two_clause_predicate(c: &mut Criterion) {
    let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
    let limits = PolicyLimits::defaults();
    c.bench_function("lex/two_clause_predicate", |b| {
        b.iter(|| {
            let _ = lex(src, &limits);
        });
    });
}

#[allow(
    clippy::indexing_slicing,
    reason = "take <= piece.len() by construction (piece.len().min(remaining))"
)]
fn bench_8kib_source(c: &mut Criterion) {
    let mut src = Vec::with_capacity(8192);
    // Fill 8 KiB with a dense token stream so lexing does real work.
    while src.len() < 8192 {
        let piece = b"a&&";
        let remaining = 8192 - src.len();
        let take = piece.len().min(remaining);
        src.extend_from_slice(&piece[..take]);
    }
    let mut limits = PolicyLimits::defaults();
    limits.max_source_bytes = 8192;
    limits.max_tokens = 8192;
    let mut group = c.benchmark_group("lex/8kib_source");
    group.throughput(Throughput::Bytes(src.len() as u64));
    group.bench_function("full_source", |b| {
        b.iter(|| {
            let _ = lex(&src, &limits);
        });
    });
    group.finish();
}

fn bench_parse_two_clause_predicate(c: &mut Criterion) {
    let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
    let limits = PolicyLimits::defaults();
    // Benchmark setup, not the timed operation: a lex failure here means the
    // fixture itself is broken, not attacker input, so this skips the
    // benchmark rather than unwrapping (production code, including bench
    // code, may not panic).
    let Ok(toks) = lex(src, &limits) else {
        return;
    };
    c.bench_function("parse/two_clause_predicate", |b| {
        b.iter(|| {
            let _ = parse(&toks, src, &limits);
        });
    });
}

fn bench_parse_64_clause_predicate(c: &mut Criterion) {
    let mut clauses = Vec::with_capacity(64);
    for i in 0..64 {
        clauses.push(format!("request.headers.size() == {i}"));
    }
    let src = clauses.join(" && ");
    let mut limits = PolicyLimits::defaults();
    limits.max_tokens = 2048;
    let Ok(toks) = lex(src.as_bytes(), &limits) else {
        return;
    };
    c.bench_function("parse/64_clause_predicate", |b| {
        b.iter(|| {
            let _ = parse(&toks, src.as_bytes(), &limits);
        });
    });
}

fn bench_check_two_clause_predicate(c: &mut Criterion) {
    let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
    let limits = PolicyLimits::defaults();
    let Ok(toks) = lex(src, &limits) else {
        return;
    };
    let Ok(ast) = parse(&toks, src, &limits) else {
        return;
    };
    c.bench_function("check/two_clause_predicate", |b| {
        b.iter(|| {
            let mut strings = toks.strings.clone();
            let _ = check(
                ast.clone(),
                &mut strings,
                src,
                Phase::RequestHeaders,
                &limits,
            );
        });
    });
}

fn bench_check_64_clause_predicate(c: &mut Criterion) {
    // Config-plane budget, not a request-path one: 64 clauses over the SAME
    // attribute, so the program has one distinct attribute slot regardless of
    // clause count (this is `check::slot_reuse`'s shape, not a 64-attribute
    // program, which the default `max_attr_slots` of 16 could not admit at all).
    let mut clauses = Vec::with_capacity(64);
    for i in 0..64 {
        clauses.push(format!("request.size == {i}"));
    }
    let src = clauses.join(" && ");
    let mut limits = PolicyLimits::defaults();
    limits.max_tokens = 2048;
    let Ok(toks) = lex(src.as_bytes(), &limits) else {
        return;
    };
    let Ok(ast) = parse(&toks, src.as_bytes(), &limits) else {
        return;
    };
    c.bench_function("check/64_clause_predicate", |b| {
        b.iter(|| {
            let mut strings = toks.strings.clone();
            let _ = check(
                ast.clone(),
                &mut strings,
                src.as_bytes(),
                Phase::RequestHeaders,
                &limits,
            );
        });
    });
}

criterion_group!(
    benches,
    bench_two_clause_predicate,
    bench_8kib_source,
    bench_parse_two_clause_predicate,
    bench_parse_64_clause_predicate,
    bench_check_two_clause_predicate,
    bench_check_64_clause_predicate
);
criterion_main!(benches);
