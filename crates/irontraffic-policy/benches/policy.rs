// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Throughput benchmarks for ITPL.
//!
//! The lexer, parser, checker, compiler and verifier benchmarks measure
//! config-admission cost, never request-path cost. See
//! `crates/irontraffic-policy/src/lex.rs`.
//!
//! The `eval/*` benchmarks below them are different: `eval` is the one
//! function on the request path, so these ARE the published per-request cost
//! of ITPL, extension layer 1. See `crates/irontraffic-policy/src/vm.rs`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_filter::Phase;
use irontraffic_policy::PolicyLimits;
use irontraffic_policy::check::check;
use irontraffic_policy::compile::compile;
use irontraffic_policy::lex::lex;
use irontraffic_policy::parse::parse;
use irontraffic_policy::program::verify;
use irontraffic_policy::value::Value;
use irontraffic_policy::vm::{AttrSource, Env, FieldOutcome, eval};
use irontraffic_policy::{AttrId, MapId};

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

// ---------------------------------------------------------------------------
// `eval/*`: request-path benchmarks. Unlike everything above, these run once
// per request, so they ARE the published per-request cost of ITPL,
// extension layer 1. The comparison numbers this issue's own science
// document publishes alongside them: `cel` 227.5 ns reused-context and
// 1,492.5 ns fresh-context, Rhai 221 to 331 ns, QuickJS 120.8 ns bare and
// 621.9 ns marshalled.
// ---------------------------------------------------------------------------

/// A hand-built `AttrSource` for the `eval/*` benchmarks: not a real request
/// parser (see `crates/irontraffic-policy/src/vm.rs`'s own test fixture of
/// the same shape; wiring a real one over `irontraffic_filter::Ctx` is
/// `{{itpl-mutation-plan-and-policy-filter}}`'s job, #273, not this one's).
struct BenchFixture {
    method: &'static [u8],
    path: &'static [u8],
    scheme: &'static [u8],
    host: &'static [u8],
    protocol: &'static [u8],
    port: i64,
    size: i64,
    tls: bool,
    headers: Vec<(&'static [u8], &'static [u8])>,
}

impl BenchFixture {
    fn new() -> BenchFixture {
        BenchFixture {
            method: b"GET",
            path: b"/v1/widgets",
            scheme: b"https",
            host: b"example.com",
            protocol: b"HTTP/1.1",
            port: 8080,
            size: 128,
            tls: true,
            headers: Vec::new(),
        }
    }
}

impl<'a> AttrSource<'a> for BenchFixture {
    fn scalar(&self, id: AttrId) -> Value<'a> {
        match id {
            AttrId::RequestMethod => Value::Str(self.method),
            AttrId::RequestPath => Value::Str(self.path),
            AttrId::RequestScheme => Value::Str(self.scheme),
            AttrId::RequestHost => Value::Str(self.host),
            AttrId::RequestProtocol => Value::Str(self.protocol),
            AttrId::RequestPort => Value::Int(self.port),
            AttrId::RequestSize => Value::Int(self.size),
            AttrId::ConnectionTls => Value::Bool(self.tls),
            _ => Value::Null,
        }
    }

    fn field(&self, map: MapId, key: &[u8]) -> FieldOutcome<'a> {
        if map != MapId::RequestHeaders {
            return FieldOutcome::Absent;
        }
        for (name, value) in &self.headers {
            if *name == key {
                return FieldOutcome::Present(value);
            }
        }
        FieldOutcome::Absent
    }
}

/// Lexes, parses, checks and compiles `src` at `phase`, panicking loudly on a
/// broken fixture rather than skipping the benchmark, matching this file's
/// own `bench_compile_two_clause_predicate` precedent for every benchmark
/// below that carries a numeric budget (issue #758 finding 9).
#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation, matching this file's own bench_compile_two_clause_predicate precedent"
)]
fn compile_src(src: &[u8], phase: Phase) -> irontraffic_policy::Program {
    let limits = PolicyLimits::defaults();
    let toks = lex(src, &limits).expect("bench fixture must lex");
    let ast = parse(&toks, src, &limits).expect("bench fixture must parse");
    let mut strings = toks.strings;
    let checked = check(ast, &mut strings, src, phase, &limits).expect("bench fixture must check");
    compile(&checked, &limits).expect("bench fixture must compile")
}

fn bench_eval_1_clause(c: &mut Criterion) {
    // Budget: under 15 ns. `request.method == "GET"`, straight from the
    // science document's own reference measurement for this exact
    // predicate.
    let prog = compile_src(br#"request.method == "GET""#, Phase::RequestHeaders);
    let fixture = BenchFixture::new();
    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/1_clause", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

const EIGHT_CLAUSE_SRC: &[u8] = br#"request.method == "GET"
    && request.path == "/v1/widgets"
    && request.scheme == "https"
    && request.host == "example.com"
    && request.protocol == "HTTP/1.1"
    && request.port == 8080
    && request.size == 128
    && connection.tls == true"#;

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation, matching this file's own bench_compile_two_clause_predicate precedent"
)]
fn bench_eval_8_clause(c: &mut Criterion) {
    // Budget: under 60 ns. Eight distinct attributes, every one of them true
    // for the fixture, so the `&&` chain runs to the end rather than
    // short-circuiting after the first clause.
    let prog = compile_src(EIGHT_CLAUSE_SRC, Phase::RequestHeaders);
    assert_eq!(
        prog.slots().len(),
        8,
        "fixture precondition: eight distinct attribute slots"
    );
    let fixture = BenchFixture::new();
    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/8_clause", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation, matching this file's own bench_compile_two_clause_predicate precedent"
)]
fn bench_eval_64_clause(c: &mut Criterion) {
    // Budget: under 400 ns. 64 conjuncts: the same eight predicates as
    // eval/8_clause above, repeated eight times, all still true for the
    // fixture, so this exercises the full 64-deep `&&` chain rather than
    // short-circuiting early. A single scalar attribute compared against 64
    // DIFFERENT literals (the shape this file's own config-plane
    // `bench_verify_256_ops` uses, where truth does not matter to a
    // `verify`-only benchmark) can be true for at most one of the 64, so at
    // request time it would short-circuit after one clause and measure a
    // one-clause cost under a 64-clause name; deliberately not reused here
    // for that reason.
    let eight = core::str::from_utf8(EIGHT_CLAUSE_SRC).unwrap_or("");
    let clause = format!("({eight})");
    let src = std::iter::repeat_n(clause.as_str(), 8)
        .collect::<Vec<_>>()
        .join(" && ");
    let mut limits = PolicyLimits::defaults();
    limits.max_tokens = 4096;
    let toks = lex(src.as_bytes(), &limits).expect("bench fixture must lex");
    let ast = parse(&toks, src.as_bytes(), &limits).expect("bench fixture must parse");
    let mut strings = toks.strings;
    let checked = check(
        ast,
        &mut strings,
        src.as_bytes(),
        Phase::RequestHeaders,
        &limits,
    )
    .expect("bench fixture must check");
    let prog = compile(&checked, &limits).expect("bench fixture must compile");
    assert_eq!(
        prog.slots().len(),
        8,
        "fixture precondition: still eight distinct slots, each repeated eight times"
    );
    let fixture = BenchFixture::new();
    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/64_clause", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation, matching this file's own bench_compile_two_clause_predicate precedent"
)]
fn bench_eval_regex_1kib(c: &mut Criterion) {
    // Budget: under 2 microseconds. One `matches` against a 1 KiB value.
    let value = vec![b'a'; 1024];
    assert_eq!(value.len(), 1024, "fixture precondition");
    let mut fixture = BenchFixture::new();
    fixture.path = Box::leak(value.into_boxed_slice());
    let prog = compile_src(br#"request.path.matches("^a+$")"#, Phase::RequestHeaders);
    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/regex_1kib", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "benchmark setup, not the timed operation, matching this file's own bench_compile_two_clause_predicate precedent"
)]
fn bench_eval_contains_8kib(c: &mut Criterion) {
    // Budget: under 20 microseconds. The adversarial pair: an 8 KiB haystack
    // of `a` bytes and a 1 KiB needle of `a` bytes ending in `b`, both all
    // `a` otherwise, this is the worst case for a naive nested scan and the
    // three-orders-of-magnitude gap `memchr::memmem` closes.
    let haystack = vec![b'a'; 8192];
    let mut needle = vec![b'a'; 1024];
    if let Some(last) = needle.last_mut() {
        *last = b'b';
    }
    assert_eq!(haystack.len(), 8192, "fixture precondition");
    assert_eq!(needle.len(), 1024, "fixture precondition");
    let mut fixture = BenchFixture::new();
    fixture.path = Box::leak(haystack.into_boxed_slice());
    let needle_str = String::from_utf8(needle).expect("an all-ascii needle is valid UTF-8");
    let src = format!("request.path.contains(\"{needle_str}\")");
    let prog = compile_src(src.as_bytes(), Phase::RequestHeaders);
    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/contains_8kib", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

// `eval/header_first_touch` needs `Program::from_parts` (`AttrRef::Field`
// cannot be built through the real `compile()` pipeline today: see the
// confirmed, pre-existing compiler bug documented at length in
// `crates/irontraffic-policy/src/vm.rs`'s test module and in this issue's
// own PR description). `from_parts` is gated behind the crate's `test-util`
// feature, so these two benchmarks are too: with the feature enabled
// (`cargo bench -p irontraffic-policy --bench policy --features test-util`)
// they run for real; without it, both functions below are still PRESENT
// (the criterion_group! list does not change) but register nothing, so
// `cargo bench ... -- --test` still runs clean either way.
#[cfg(feature = "test-util")]
fn bench_eval_header_first_touch(c: &mut Criterion) {
    // Budget: under 6 ns for the LOOKUP portion, read as the difference
    // between this benchmark and `eval/header_first_touch_scalar_baseline`
    // below: criterion has no built-in "assert this minus that" primitive,
    // so the two numbers are meant to be differenced by whoever reads the
    // report, exactly as this issue's own Benchmarks section phrases it.
    use irontraffic_policy::check::AttrRef;
    use irontraffic_policy::program::{Const, Op, Program};
    use irontraffic_policy::token::Span;

    fn intern(strings: &mut Vec<u8>, s: &[u8]) -> Span {
        let start = u32::try_from(strings.len()).unwrap_or(u32::MAX);
        strings.extend_from_slice(s);
        let end = u32::try_from(strings.len()).unwrap_or(u32::MAX);
        Span { start, end }
    }

    let mut strings = Vec::new();
    let key = AttrRef::Field {
        map: MapId::RequestHeaders,
        key: intern(&mut strings, b"x-api-key"),
    };
    let prog = Program::from_parts(
        vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Ne, Op::Ret],
        vec![Const::Null],
        vec![],
        strings,
        vec![key],
        vec![],
        irontraffic_policy::Ty::Bool,
        Phase::RequestHeaders,
        2,
    );

    let mut fixture = BenchFixture::new();
    // A 20-field section with `x-api-key` last: the worst case for an O(h)
    // scan over the header slots.
    let mut headers: Vec<(&'static [u8], &'static [u8])> = (0u32..19)
        .map(|i| {
            let name: &'static str = Box::leak(format!("x-field-{i}").into_boxed_str());
            (name.as_bytes(), b"v".as_slice())
        })
        .collect();
    headers.push((b"x-api-key", b"secret"));
    assert_eq!(
        headers.len(),
        20,
        "fixture precondition: a 20-field section"
    );
    fixture.headers = headers;

    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/header_first_touch", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

#[cfg(not(feature = "test-util"))]
fn bench_eval_header_first_touch(_c: &mut Criterion) {}

#[cfg(feature = "test-util")]
fn bench_eval_header_first_touch_scalar_baseline(c: &mut Criterion) {
    // The scalar-only half of the `eval/header_first_touch` difference
    // above: the identical bytecode shape (`LoadAttr, LoadConst, Ne, Ret`),
    // but the one attribute slot is a plain scalar rather than a header
    // lookup, isolating the O(h) header-map scan's own cost from the slot
    // cache's ordinary first-touch cost.
    use irontraffic_policy::check::AttrRef;
    use irontraffic_policy::program::{Const, Op, Program};

    let prog = Program::from_parts(
        vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Ne, Op::Ret],
        vec![Const::Null],
        vec![],
        vec![],
        vec![AttrRef::Scalar(AttrId::RequestMethod)],
        vec![],
        irontraffic_policy::Ty::Bool,
        Phase::RequestHeaders,
        2,
    );
    let fixture = BenchFixture::new();
    let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
    c.bench_function("eval/header_first_touch_scalar_baseline", |b| {
        b.iter(|| {
            let mut env = Env::new(&fixture, used);
            let _ = eval(&prog, &mut env);
        });
    });
}

#[cfg(not(feature = "test-util"))]
fn bench_eval_header_first_touch_scalar_baseline(_c: &mut Criterion) {}

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
    bench_verify_256_ops,
    bench_eval_1_clause,
    bench_eval_8_clause,
    bench_eval_64_clause,
    bench_eval_regex_1kib,
    bench_eval_contains_8kib,
    bench_eval_header_first_touch,
    bench_eval_header_first_touch_scalar_baseline
);
criterion_main!(benches);
