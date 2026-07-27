// SPDX-License-Identifier: MIT OR Apache-2.0
//! The allocation gate for the forwarding-chain surface.
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

/// `forwarded-element-parsing` (#31)'s allocation-freedom gate for
/// `ForwardedChain::parse_into`.
///
/// The issue's own design called for proving this at run time: 1000 parses
/// of a single-entry chain (no `host` parameter) reporting exactly 0
/// allocations through a `count_allocs` helper, because nothing is split off
/// and the 8-inline-element `SmallVec` never spills; and 1000 parses of a
/// 32-entry chain reporting at most 1000 (one spill each). That does not
/// compile in this workspace, for the same reason
/// `authority_parse_into_allocates_only_the_declared_split_off` (in
/// `tests/alloc_gate_authority.rs`) gives:
/// `GlobalAlloc` is an `unsafe trait`, this package's `[lints] workspace =
/// true` denies `unsafe_code` on every target including this one, and a
/// process-wide counting allocator would count allocations made by every
/// other test running in parallel in the same binary regardless of the ban.
/// There is no `count_allocs` helper anywhere in this crate to call.
///
/// This proves the checkable half of the same two claims statically.
/// `ForwardedChain::parse_into`'s only allocating call site in its own body
/// is the conditional `out.split_off`, reached only when at least one
/// element carried a `host` parameter; the other allocating call,
/// `elements.reserve`, lives one level down inside `push_element` and is
/// itself guarded by the `elements.len() == INLINE_ELEMENTS` check, so it
/// can fire at most once per call. Together:
/// - a chain with no `host` parameter and at most 8 elements executes
///   NEITHER call, hence 0 allocations, matching the "exactly 0" claim; and
/// - a chain with no `host` parameter and up to `max_forwarded_elements`
///   elements executes the guarded `reserve` call at most once per parse,
///   matching the "at most 1000" (one per parse, over 1000 parses) claim.
#[test]
fn forwarded_chain_parse_into_allocates_only_through_the_declared_sites() {
    let forwarded_source = include_str!("../src/forwarded.rs");

    let parse_into_body = extract_fn_body(forwarded_source, "pub fn parse_into<'a, I, J, K>(")
        .expect("`fn parse_into` not found in src/forwarded.rs; has it moved or been renamed?");
    let push_element_body = extract_fn_body(forwarded_source, "fn push_element(")
        .expect("`fn push_element` not found in src/forwarded.rs; has it moved or been renamed?");

    // `parse_into`'s own body must allocate through nothing but the
    // conditional `split_off` it declares; `reserve` lives one level down,
    // inside `push_element`, and is checked separately below.
    for call in ALLOCATING_CALLS {
        assert!(
            !parse_into_body.contains(call),
            "parse_into's body contains `{call}`, which can allocate; parse_into is \
             documented to allocate only through its declared conditional split_off and, \
             one level down, push_element's guarded reserve"
        );
    }
    let split_off_count = parse_into_body.matches("split_off").count();
    assert_eq!(
        split_off_count, 1,
        "parse_into must call split_off exactly once (guarded by whether any element \
         carried a host claim), found {split_off_count} occurrences in its body"
    );

    // `push_element`'s only allocating call is its declared, guarded
    // reserve.
    for call in ALLOCATING_CALLS {
        assert!(
            !push_element_body.contains(call),
            "push_element's body contains `{call}`, which can allocate; push_element is \
             documented to allocate only through its declared, guarded reserve call"
        );
    }
    let reserve_count = push_element_body.matches(".reserve(").count();
    assert_eq!(
        reserve_count, 1,
        "push_element must call reserve exactly once, found {reserve_count} occurrences \
         in its body"
    );
    assert!(
        push_element_body.contains("== INLINE_ELEMENTS"),
        "push_element's reserve call must stay guarded by the inline-capacity check, so \
         it fires at most once per parse rather than on every push past it"
    );
}
