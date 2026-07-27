// SPDX-License-Identifier: MIT OR Apache-2.0
//! The allocation gate for the authority surface.
//!
//! ONE ALLOCATION-GATE FILE PER SURFACE (issue #630). Do not append a gate for
//! another surface here: add `tests/alloc_gate_<surface>.rs`, which is what
//! stops two issues from ever conflicting in one shared gate file.
//!
//! WHY THIS IS A TEXT SCAN AND NOT A COUNTING ALLOCATOR. `GlobalAlloc` is an
//! `unsafe trait` and this package's `[lints] workspace = true` applies the
//! workspace's `unsafe_code = "deny"` to every target including this one, so a
//! counting `#[global_allocator]` cannot live anywhere in this repository; a
//! process-wide one would in any case count allocations made by every other
//! test running in parallel in the same binary. The full argument, and the
//! limits of what a text scan can prove, is in
//! `tests/alloc_gate_common/mod.rs`, which owns `ALLOCATING_CALLS` and
//! `extract_fn_body`.

mod alloc_gate_common;

use alloc_gate_common::{ALLOCATING_CALLS, extract_fn_body};

/// `authority-parsing-and-reconciliation` (#30)'s one-allocation-per-call
/// gate for `Authority::parse_into`.
///
/// The issue's own design called for proving this at run time: 1000 calls
/// over each of a few inputs through a `count_allocs` helper, each expected
/// to report exactly 1000 allocations (the one `split_off`/`freeze` per
/// call, and no more). That does not compile in this workspace, for the
/// exact reason explained in the module doc comment above: `GlobalAlloc` is
/// an `unsafe trait`, this package's `[lints] workspace = true` applies the
/// workspace's `unsafe_code = "deny"` to every target including this one,
/// and a process-wide counting allocator would in any case count allocations
/// made by every other test running in parallel in the same binary, which
/// makes an exact "1000, no more" assertion meaningless regardless of the
/// ban. There is no `count_allocs` helper anywhere in this crate to call.
///
/// This proves the checkable half of the same claim statically, the same
/// substitution `validate_allocates_nothing` (in `tests/alloc_gate_field.rs`)
/// already makes for `validate_value`: `parse_into`'s own body contains no
/// call from `ALLOCATING_CALLS` other than its one declared `split_off`, so
/// the ONLY way it can touch the allocator is through that one
/// `split_off`/`freeze` pair, and it appears exactly once in the source,
/// never behind a conditional branch that could run it twice for one call.
#[test]
fn authority_parse_into_allocates_only_the_declared_split_off() {
    let authority_source = include_str!("../src/authority.rs");

    let parse_into_body = extract_fn_body(authority_source, "pub fn parse_into(")
        .expect("`fn parse_into` not found in src/authority.rs; has it moved or been renamed?");

    for call in ALLOCATING_CALLS {
        assert!(
            !parse_into_body.contains(call),
            "parse_into's body contains `{call}`, which can allocate; parse_into is \
             documented to allocate only through its one declared split_off/freeze"
        );
    }

    let split_off_count = parse_into_body.matches("split_off").count();
    assert_eq!(
        split_off_count, 1,
        "parse_into must call split_off exactly once, the one declared allocation per \
         call; found {split_off_count} occurrences in its body"
    );
}
