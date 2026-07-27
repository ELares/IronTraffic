// SPDX-License-Identifier: MIT OR Apache-2.0
//! The zero-allocation gate for the request-framing surface.
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

/// `request-framing-resolution` (#27)'s zero-allocation gate for
/// `resolve_request_framing`.
///
/// The issue's own design called for proving this at run time: 1000 calls
/// over each of the three benchmark inputs through a `count_allocs` helper
/// from `field-validation-tables` (#23), each expected to report exactly 0
/// allocations. There is no `count_allocs` helper anywhere in this crate to
/// call, and one cannot be written here for the exact reason explained in
/// the module doc comment above: `GlobalAlloc` is an `unsafe trait`, this
/// package's `[lints] workspace = true` applies the workspace's
/// `unsafe_code = "deny"` to every target including this one, and a
/// process-wide counting allocator would in any case count allocations made
/// by every other test running in parallel in the same binary.
///
/// This proves the same property statically, the identical substitution
/// `validate_allocates_nothing` (in `tests/alloc_gate_field.rs`) already
/// makes for `validate_value`: `resolve_request_framing`'s entire call graph
/// inside this crate is itself, `tokenize_transfer_encoding`,
/// `parse_content_length`, and `field::trim_ows`, so a text scan of exactly
/// those four function bodies for the same allocating-call vocabulary is
/// exhaustive over every possible input, not just the three benchmark inputs
/// the issue's design named.
#[test]
fn framing_allocates_nothing() {
    let framing_source = include_str!("../src/framing.rs");
    let field_source = include_str!("../src/field.rs");

    let resolve_body = extract_fn_body(framing_source, "pub fn resolve_request_framing(").expect(
        "`fn resolve_request_framing` not found in src/framing.rs; has it moved or been \
             renamed?",
    );
    let tokenize_body = extract_fn_body(framing_source, "pub fn tokenize_transfer_encoding<")
        .expect(
            "`fn tokenize_transfer_encoding` not found in src/framing.rs; has it moved or been \
             renamed?",
        );
    let parse_cl_body = extract_fn_body(framing_source, "pub fn parse_content_length(").expect(
        "`fn parse_content_length` not found in src/framing.rs; has it moved or been renamed?",
    );
    let trim_ows_body = extract_fn_body(field_source, "pub fn trim_ows(value: &[u8]) -> &[u8] {")
        .expect("`fn trim_ows` not found in src/field.rs; has it moved or been renamed?");

    for call in ALLOCATING_CALLS {
        assert!(
            !resolve_body.contains(call),
            "resolve_request_framing's body contains `{call}`, which can allocate; \
             resolve_request_framing is documented to never allocate"
        );
        assert!(
            !tokenize_body.contains(call),
            "tokenize_transfer_encoding's body contains `{call}`, which can allocate; it is \
             one of resolve_request_framing's callees and resolve_request_framing is \
             documented to never allocate"
        );
        assert!(
            !parse_cl_body.contains(call),
            "parse_content_length's body contains `{call}`, which can allocate; it is one of \
             resolve_request_framing's callees and resolve_request_framing is documented to \
             never allocate"
        );
        assert!(
            !trim_ows_body.contains(call),
            "trim_ows's body contains `{call}`, which can allocate; it is one of \
             resolve_request_framing's callees and resolve_request_framing is documented to \
             never allocate"
        );
    }
}

/// `response-framing-and-expect-policy` (#28)'s zero-allocation gate for
/// `resolve_response_framing`, the response-side twin of
/// `resolve_request_framing` above.
///
/// The same substitution as `framing_allocates_nothing` above, extended by
/// one function: `resolve_response_framing`'s entire call graph inside this
/// crate is itself, its own private `declared_len` helper,
/// `tokenize_transfer_encoding`, `parse_content_length`, and
/// `field::trim_ows` (the last three shared, unchanged, with the request
/// side), so a text scan of exactly those five function bodies for the same
/// allocating-call vocabulary is exhaustive over every possible input, not
/// just the two benchmark inputs the issue's design named.
#[test]
fn response_framing_allocates_nothing() {
    let response_source = include_str!("../src/response.rs");
    let framing_source = include_str!("../src/framing.rs");
    let field_source = include_str!("../src/field.rs");

    let resolve_body = extract_fn_body(response_source, "pub fn resolve_response_framing(").expect(
        "`fn resolve_response_framing` not found in src/response.rs; has it moved or been \
             renamed?",
    );
    let declared_len_body = extract_fn_body(
        response_source,
        "fn declared_len(fields: &FieldSection) -> Result<Option<u64>, RejectReason> {",
    )
    .expect("`fn declared_len` not found in src/response.rs; has it moved or been renamed?");
    let tokenize_body = extract_fn_body(framing_source, "pub fn tokenize_transfer_encoding<")
        .expect(
            "`fn tokenize_transfer_encoding` not found in src/framing.rs; has it moved or been \
             renamed?",
        );
    let parse_cl_body = extract_fn_body(framing_source, "pub fn parse_content_length(").expect(
        "`fn parse_content_length` not found in src/framing.rs; has it moved or been renamed?",
    );
    let trim_ows_body = extract_fn_body(field_source, "pub fn trim_ows(value: &[u8]) -> &[u8] {")
        .expect("`fn trim_ows` not found in src/field.rs; has it moved or been renamed?");

    for call in ALLOCATING_CALLS {
        assert!(
            !resolve_body.contains(call),
            "resolve_response_framing's body contains `{call}`, which can allocate; \
             resolve_response_framing is documented to never allocate"
        );
        assert!(
            !declared_len_body.contains(call),
            "declared_len's body contains `{call}`, which can allocate; it is one of \
             resolve_response_framing's callees and resolve_response_framing is documented to \
             never allocate"
        );
        assert!(
            !tokenize_body.contains(call),
            "tokenize_transfer_encoding's body contains `{call}`, which can allocate; it is \
             one of resolve_response_framing's callees and resolve_response_framing is \
             documented to never allocate"
        );
        assert!(
            !parse_cl_body.contains(call),
            "parse_content_length's body contains `{call}`, which can allocate; it is one of \
             resolve_response_framing's callees and resolve_response_framing is documented to \
             never allocate"
        );
        assert!(
            !trim_ows_body.contains(call),
            "trim_ows's body contains `{call}`, which can allocate; it is one of \
             resolve_response_framing's callees and resolve_response_framing is documented to \
             never allocate"
        );
    }
}
