// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-allocation proof for `normalize_authority` and `host_key`. Later
//! issues in this milestone APPEND their own zero-allocation tests to this
//! same file rather than creating a new one, for continuity with the file
//! this issue introduces.
//!
//! This issue's own design called for a process-wide counting
//! `#[global_allocator]` here. That does not compile in this tree:
//! `GlobalAlloc` is declared as an `unsafe trait`, so even a pure counter
//! that forwards straight to `std::alloc::System` needs the keyword this
//! repository denies with no exception an implementer may grant (AGENTS.md,
//! and the `no-unsafe` rule in `scripts/invariant-lints.sh`, which scans
//! every tracked `.rs` file, tests included, and has no escape hatch for
//! this rule). A process-wide global allocator is also unsound independent
//! of that ban: it counts allocations made by every other test running in
//! parallel in the same binary, which would make the result depend on which
//! other tests happen to be scheduled alongside this one.
//!
//! An earlier version of this file instead proved the property with a
//! hand-rolled text scan: it extracted the source of `normalize_authority`,
//! `host_key` and the four private helpers it believed were their entire
//! call graph, then grepped those bodies against a locally copied list of
//! allocating calls. An adversarial review of that approach found it
//! unsound in exactly the way a per-crate reimplementation of a shared rule
//! tends to be: the hand-picked call graph omitted `normalize_host_pattern`
//! and `check_label_shape` (an injected `format!` and `vec![` in those two
//! functions survived undetected), and the copied vocabulary had already
//! drifted from the real one by missing `.clone()`. Six of seven injected
//! allocating calls survived; the property this test claimed to prove was
//! not actually being checked for most of the module.
//!
//! The fix is not a better hand-rolled scan, it is not having a second one.
//! `src/normalize.rs` now carries the `//! HOT PATH` marker, which puts the
//! entire file under `scripts/invariant-lints.sh`'s `hot-path-allocation`
//! and `hot-path-lock` rules: a text scan of every function in the file,
//! using the one vocabulary that rule already polices the rest of the
//! workspace with, run in CI on every pull request. That scan is exhaustive
//! over every possible input a `&[u8]` can hold (it is a property of the
//! source text, not of any run), and unlike the bespoke version it cannot
//! silently miss a function added to the module later. This test's only job
//! is to guard against the marker line itself being deleted, which would
//! silently drop this module out of that CI-enforced net; `assertions
//! weakened` and `test removed` in `scripts/test-census.sh` both refuse a
//! change that shrinks this test's body without a written justification, so
//! removing the marker cannot pass unnoticed.

/// The exact line `scripts/invariant-lints.sh`'s `hot_files` helper greps
/// for (`grep -l '^//! HOT PATH'`) to decide which files its hot-path rules
/// cover.
const HOT_PATH_MARKER: &str = "//! HOT PATH";

#[test]
fn normalize_and_host_key_allocate_nothing() {
    // `normalize_authority` and `host_key`, and every function either of
    // them calls (`host_span_and_bracket`, `trim_and_check_shape`,
    // `write_bracket_host`, `write_plain_host`, `normalize_host_pattern`,
    // `check_label_shape`), live in this one file. As long as
    // `src/normalize.rs` carries the marker below, none of them can ever
    // merge a heap allocation or a lock without failing CI's
    // `hot-path-allocation` / `hot-path-lock` rules, because that scan
    // covers the whole file, not a maintained subset of it. Proving that
    // here, in Rust, would mean re-deriving the same call graph and the
    // same vocabulary a second time, which is the exact duplication that
    // let this property go unchecked before: see the module doc above.
    let source = include_str!("../src/normalize.rs");
    assert!(
        source.lines().any(|line| line == HOT_PATH_MARKER),
        "crates/irontraffic-router/src/normalize.rs must carry a line that is \
         exactly `{HOT_PATH_MARKER}` so scripts/invariant-lints.sh's \
         hot-path-allocation and hot-path-lock rules scan this module; without \
         it, normalize_authority, normalize_host_pattern, host_key and every \
         helper they call could allocate or lock with nothing in this repository \
         catching it"
    );
}

#[test]
fn scratch_steady_state_allocates_nothing() {
    // `match-scratch-per-worker` (#58) originally intended to prove this with a
    // process-wide counting `#[global_allocator]`. That does not compile in this
    // tree (`#![forbid(unsafe_code)]`) and would be unsound anyway because it
    // would count allocations made by other tests running in parallel. The
    // module is instead guarded by the same `//! HOT PATH` marker that protects
    // `normalize_authority`: `scripts/invariant-lints.sh` scans the whole file
    // for allocating or locking calls, and any genuine exception must carry an
    // `it-allow: hot-path-allocation` escape with a written reason. This test's
    // only job is to guard against the marker itself being deleted, which would
    // silently drop the module out of that CI-enforced net.
    let source = include_str!("../src/scratch.rs");
    assert!(
        source.lines().any(|line| line == HOT_PATH_MARKER),
        "crates/irontraffic-router/src/scratch.rs must carry a line that is \
         exactly `{HOT_PATH_MARKER}` so scripts/invariant-lints.sh's \
         hot-path-allocation and hot-path-lock rules scan this module; without \
         it, MatchScratch::begin_request, observe_header, index_query and every \
         helper they call could allocate or lock with nothing in this repository \
         catching it"
    );
}

#[test]
fn descend_allocates_nothing() {
    // `path-descent-and-visit-budget` (#54) inherited the same original
    // design intent as the two tests above: a process-wide counting
    // `#[global_allocator]` proving `descend` and `prefix_boundary_ok`
    // allocate nothing. That does not compile in this tree for the identical
    // reason documented above `normalize_and_host_key_allocate_nothing`:
    // `GlobalAlloc` is an `unsafe trait`, this crate's root is
    // `#![forbid(unsafe_code)]` with no per-crate exception, and a
    // process-wide allocator would be unsound here regardless, since it
    // would count every OTHER test's allocations too, whichever happen to
    // run in the same binary at the same time.
    //
    // `src/matching/path.rs` instead carries the same `//! HOT PATH` marker
    // that already protects `normalize_authority` and `MatchScratch`, which
    // puts `descend` and `prefix_boundary_ok` (both production, non-test
    // code in that file) under `scripts/invariant-lints.sh`'s
    // `hot-path-allocation` and `hot-path-lock` rules for every pull
    // request. This test's only job is to guard against that marker line
    // being deleted, which would silently drop the module out of that
    // CI-enforced net; `assertions weakened` and `test removed` in
    // `scripts/test-census.sh` both refuse a change that shrinks this
    // test's body without a written justification.
    let source = include_str!("../src/matching/path.rs");
    assert!(
        source.lines().any(|line| line == HOT_PATH_MARKER),
        "crates/irontraffic-router/src/matching/path.rs must carry a line that \
         is exactly `{HOT_PATH_MARKER}` so scripts/invariant-lints.sh's \
         hot-path-allocation and hot-path-lock rules scan this module; without \
         it, descend and prefix_boundary_ok could allocate or lock with \
         nothing in this repository catching it"
    );
}

#[test]
fn eval_preds_allocates_nothing() {
    // `predicate-bytecode-eval` (#59) originally intended to prove this with
    // a process-wide counting `#[global_allocator]` that builds every table
    // and scratch its own named tests use, resets the counter, replays every
    // `eval_preds` call, and asserts the count stayed zero. That does not
    // compile in this tree for the identical reason documented above
    // `normalize_and_host_key_allocate_nothing`: `GlobalAlloc` is an `unsafe
    // trait`, this crate's root is `#![forbid(unsafe_code)]` with no
    // per-crate exception, and a process-wide allocator would be unsound
    // here regardless, since it would count every OTHER test's allocations
    // too, whichever happen to run in the same binary at the same time. The
    // issue's own dependency list also names `authority-normalization` (#50)
    // as the issue that creates a `tests/common/mod.rs` this test would
    // append to; no such file exists in this tree, and this issue's `##
    // Files` table does not list one either, so creating it here would both
    // touch an undeclared file and resurrect the banned allocator.
    //
    // `src/matching/pred.rs` instead carries the same `//! HOT PATH` marker
    // that already protects `normalize_authority`, `MatchScratch` and
    // `descend`, which puts `eval_preds` (production, non-test code in that
    // file) under `scripts/invariant-lints.sh`'s `hot-path-allocation` and
    // `hot-path-lock` rules for every pull request. This test's only job is
    // to guard against that marker line being deleted, which would silently
    // drop the module out of that CI-enforced net; `assertions weakened` and
    // `test removed` in `scripts/test-census.sh` both refuse a change that
    // shrinks this test's body without a written justification.
    let source = include_str!("../src/matching/pred.rs");
    assert!(
        source.lines().any(|line| line == HOT_PATH_MARKER),
        "crates/irontraffic-router/src/matching/pred.rs must carry a line \
         that is exactly `{HOT_PATH_MARKER}` so scripts/invariant-lints.sh's \
         hot-path-allocation and hot-path-lock rules scan this module; \
         without it, eval_preds could allocate or lock with nothing in this \
         repository catching it"
    );
}
