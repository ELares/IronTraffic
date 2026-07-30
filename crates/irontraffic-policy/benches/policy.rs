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
use irontraffic_policy::compile::compile;
use irontraffic_policy::lex::lex;
use irontraffic_policy::parse::parse;
use irontraffic_policy::program::verify;

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

// The three benches below deliberately PANIC on a broken fixture, unlike
// every other bench in this file (issue #758 finding 9). The pre-existing
// idiom (`let Ok(x) = f() else { return; }`) makes a fixture failure
// register NO benchmark at all rather than failing loudly, which is
// harmless for a bench with no attached budget but makes the issue's own
// acceptance criterion, "`cargo bench ... -- --test` runs", unfalsifiable
// for exactly the three benchmarks this issue attaches numeric budgets to:
// if `compile` were entirely broken, `bench_verify_256_ops` would silently
// vanish and `--test` would still exit 0. `no-panic` (scripts/invariant-
// lints.sh) does not apply here: it scans `rust_non_test_files`, which
// excludes `benches/` outright. `clippy::expect_used` DOES apply here
// (workspace-wide, not test-scoped, per `clippy.toml`'s `allow-expect-in-
// tests`, which only exempts `#[cfg(test)]` code, not `benches/`), so each
// function below carries its own explicit, reasoned `#[allow]` rather than
// a silent exemption, matching this file's own `bench_8kib_source`
// precedent for `clippy::indexing_slicing`.

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation: a fixture failure here must be LOUD, not skip the benchmark silently (issue #758 finding 9), and this fn is never on the request path"
)]
fn bench_compile_two_clause_predicate(c: &mut Criterion) {
    // Config-plane budget: under 5 microseconds, against `cel`'s measured
    // 12,185.5 ns to compile the same predicate.
    let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
    let limits = PolicyLimits::defaults();
    let toks = lex(src, &limits).expect("fixture must lex");
    let ast = parse(&toks, src, &limits).expect("fixture must parse");
    let checked = check(
        ast,
        &mut toks.strings.clone(),
        src,
        Phase::RequestHeaders,
        &limits,
    )
    .expect("fixture must check");
    c.bench_function("compile/two_clause_predicate", |b| {
        b.iter(|| {
            let _ = compile(&checked, &limits);
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation: a fixture failure here must be LOUD, not skip the benchmark silently (issue #758 finding 9), and this fn is never on the request path"
)]
fn bench_compile_with_one_regex(c: &mut Criterion) {
    // Config-plane budget: under 500 microseconds, dominated by `regex`.
    let src = br#"request.path.matches("^/v[0-9]+/[a-zA-Z0-9_-]+$")"#;
    let limits = PolicyLimits::defaults();
    let toks = lex(src, &limits).expect("fixture must lex");
    let ast = parse(&toks, src, &limits).expect("fixture must parse");
    let checked = check(
        ast,
        &mut toks.strings.clone(),
        src,
        Phase::RequestHeaders,
        &limits,
    )
    .expect("fixture must check");
    c.bench_function("compile/with_one_regex", |b| {
        b.iter(|| {
            let _ = compile(&checked, &limits);
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation: a fixture failure here must be LOUD, not skip the benchmark silently (issue #758 finding 9), and this fn is never on the request path"
)]
fn bench_verify_256_ops(c: &mut Criterion) {
    // Config-plane budget: under 10 microseconds. 64 `&&`-joined comparisons
    // over the same attribute, which compiles to exactly the default
    // `max_ops` of 256 (64 clauses of `LoadAttr, LoadConst, Eq` plus 63
    // `JumpIfFalse` plus `Ret`).
    let mut clauses = Vec::with_capacity(64);
    for i in 0..64 {
        clauses.push(format!("request.size == {i}"));
    }
    let src = clauses.join(" && ");
    let mut limits = PolicyLimits::defaults();
    limits.max_tokens = 2048;
    let toks = lex(src.as_bytes(), &limits).expect("fixture must lex");
    let ast = parse(&toks, src.as_bytes(), &limits).expect("fixture must parse");
    let checked = check(
        ast,
        &mut toks.strings.clone(),
        src.as_bytes(),
        Phase::RequestHeaders,
        &limits,
    )
    .expect("fixture must check");
    let program = compile(&checked, &limits).expect("fixture must compile");
    // Pins the claim the PR for #271 could previously only make in prose:
    // this fixture really does compile to exactly 256 ops, the default
    // `max_ops`, not merely a bench named "256_ops" that happens to compile
    // to some other count (issue #758 finding 9).
    assert_eq!(
        program.ops().len(),
        256,
        "verify/256_ops fixture must compile to exactly 256 ops"
    );
    let ops = program.ops().to_vec();
    let consts = program.consts().to_vec();
    let slots = program.slots().to_vec();
    let regex_count = program.regex_count();
    c.bench_function("verify/256_ops", |b| {
        b.iter(|| {
            let _ = verify(&ops, &consts, &slots, regex_count, &limits);
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
    bench_check_64_clause_predicate,
    bench_compile_two_clause_predicate,
    bench_compile_with_one_regex,
    bench_verify_256_ops
);
criterion_main!(benches);
