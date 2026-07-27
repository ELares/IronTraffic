// SPDX-License-Identifier: MIT OR Apache-2.0
//! The zero-allocation gate for the field-validation surface:
//! `validate_value` is documented to perform no heap allocation.
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
//!
//! `validate_value`'s entire call graph inside this crate is itself,
//! `value_byte_ok`, and `WireVersion::is_multiplexed`, so a text scan of
//! exactly those three function bodies for that set of calls is exhaustive
//! over every possible input, not just the ones a particular run happens to
//! generate.

mod alloc_gate_common;

use alloc_gate_common::{ALLOCATING_CALLS, extract_fn_body};

#[test]
fn validate_allocates_nothing() {
    // Static proof: `validate_value`'s entire call graph inside this crate
    // (itself, `value_byte_ok`, and `WireVersion::is_multiplexed`) contains
    // no call that can allocate, so no input can make `validate_value` touch
    // the heap. This is exhaustive over every possible input, not merely
    // over a sample run, which is strictly stronger than a counting
    // allocator sampled over any finite number of calls would have been.
    //
    // The three loops below are inlined directly in this `#[test]` body
    // rather than factored into a shared helper: `scripts/invariant-lints.sh`'s
    // `no-test-without-assertion` rule scans a test function's own body text
    // for an assertion and cannot see through a call to a separate function
    // that does the asserting, so a helper here would make this test look
    // empty to that rule even though it genuinely asserts.
    let field_source = include_str!("../src/field.rs");
    let scalar_source = include_str!("../src/scalar.rs");

    let validate_value_body = extract_fn_body(
        field_source,
        "pub fn validate_value(value: &[u8], version: WireVersion) -> Result<(), RejectReason> {",
    )
    .expect("`fn validate_value` not found in src/field.rs; has it moved or been renamed?");
    let value_byte_ok_body =
        extract_fn_body(field_source, "pub const fn value_byte_ok(b: u8) -> bool {")
            .expect("`fn value_byte_ok` not found in src/field.rs; has it moved or been renamed?");
    let is_multiplexed_body =
        extract_fn_body(scalar_source, "pub const fn is_multiplexed(self) -> bool {").expect(
            "`fn is_multiplexed` not found in src/scalar.rs; has it moved or been renamed?",
        );

    for call in ALLOCATING_CALLS {
        assert!(
            !validate_value_body.contains(call),
            "validate_value's body contains `{call}`, which can allocate; \
             validate_value is documented to never allocate"
        );
        assert!(
            !value_byte_ok_body.contains(call),
            "value_byte_ok's body contains `{call}`, which can allocate; \
             it is one of validate_value's two callees and validate_value is \
             documented to never allocate"
        );
        assert!(
            !is_multiplexed_body.contains(call),
            "WireVersion::is_multiplexed's body contains `{call}`, which can allocate; \
             it is one of validate_value's two callees and validate_value is \
             documented to never allocate"
        );
    }
}
