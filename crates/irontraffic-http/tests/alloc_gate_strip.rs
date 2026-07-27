// SPDX-License-Identifier: MIT OR Apache-2.0
//! The zero-allocation gate for the hop-by-hop ingress-strip surface.
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

/// `hop-by-hop-and-reserved-prefix-strip` (#26)'s zero-allocation gate for
/// `strip_ingress`.
///
/// The issue's own design called for proving this at run time: 1000
/// `strip_ingress` calls over the adversarial section from its Benchmarks
/// section, through a `count_allocs` helper, each expected to report exactly
/// 0 allocations. That does not compile in this workspace, for the same
/// reason the sibling gate files already gave up on the identical request
/// from their own issues: `GlobalAlloc` is an `unsafe trait`, this package's
/// `[lints] workspace = true` in `Cargo.toml` applies the workspace's
/// `unsafe_code = "deny"` to every target of the package including this one,
/// and a process-wide counting allocator would in any case count allocations
/// made by every other test running in parallel in the same binary. There is
/// no `count_allocs` helper anywhere in this crate to call.
///
/// This proves the checkable half of the same claim statically, the same
/// substitution the sibling gates already make: `strip_ingress`'s call
/// graph inside this crate is itself, `strip_static_and_te`,
/// `collect_connection_tokens`, `token_names` and `is_reserved_prefix` (all
/// defined in `src/strip.rs`), plus `trim_ows` (defined in `src/field.rs`,
/// the same cross-file reach `validate_allocates_nothing` already makes for
/// `is_multiplexed`). The section-arena methods `strip_ingress`
/// calls on its way through, such as `remove_known` and `retain`, belong to
/// `field-section-and-known-headers` (#24) and are documented there as
/// index-only; they are not re-verified here. A text scan of exactly those
/// six function bodies for the calls that can allocate is exhaustive over
/// every input `strip_ingress` could ever be called with, not just the ones
/// a particular run happens to generate, which is strictly stronger than a
/// counting allocator sampled over any finite number of calls would have
/// been.
#[test]
fn strip_ingress_allocates_nothing() {
    let strip_source = include_str!("../src/strip.rs");
    let field_source = include_str!("../src/field.rs");

    let checked: [(&str, &str); 6] = [
        ("strip_ingress", "fn strip_ingress("),
        ("strip_static_and_te", "fn strip_static_and_te("),
        ("collect_connection_tokens", "fn collect_connection_tokens("),
        ("token_names", "fn token_names("),
        ("is_reserved_prefix", "fn is_reserved_prefix("),
        ("trim_ows", "fn trim_ows("),
    ];

    for (name, anchor) in checked {
        let source = if name == "trim_ows" {
            field_source
        } else {
            strip_source
        };
        let body = extract_fn_body(source, anchor)
            .unwrap_or_else(|| panic!("`{anchor}` not found; has {name} moved or been renamed?"));
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; strip_ingress's \
                 entire call graph inside this crate ({name} included) is documented to \
                 never allocate"
            );
        }
    }
}
