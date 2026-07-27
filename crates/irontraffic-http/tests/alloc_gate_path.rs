// SPDX-License-Identifier: MIT OR Apache-2.0
//! The allocation gate for the path-normalization surface.
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

/// `path-normalization` (#29)'s own design called for exactly the same
/// process-wide counting `#[global_allocator]` this file's module doc already
/// rejects, wrapping 1000 calls to `NormalizedPath::parse_into` over each of the
/// five benchmark inputs and asserting the count is exactly 1000. That does not
/// compile here for the identical reason `validate_allocates_nothing` (in
/// `tests/alloc_gate_field.rs`) does not: `GlobalAlloc` is `unsafe trait`, this
/// package's `[lints] workspace = true` applies `unsafe_code = "deny"` to every
/// target including this one, and a process-wide allocator would also count
/// every other test running in parallel in the same binary.
///
/// `parse_into` is documented to perform AT MOST one heap allocation per call (the
/// initial `out.reserve`, when the caller-supplied buffer's spare capacity is
/// exhausted, which it always is immediately after a prior call's `split_off`
/// leaves the original buffer with capacity equal to its length): every other
/// operation in its call graph (`BytesMut::extend_from_slice` within already
/// reserved capacity, `BytesMut::get`/`get_mut`/`truncate`/`split_off`,
/// `Bytes::freeze`/`slice`, and the `SmallVec<[u32; 32]>` offset stack while it
/// stays inline) is a refcount bump, a pointer move, or a write into memory
/// already reserved, none of which touch the allocator. A counting allocator
/// could prove the exact number 1; a text scan can only prove the WEAKER but
/// still load-bearing property that no call from `ALLOCATING_CALLS` (or a second,
/// unbounded `BytesMut`/`Vec` construction) appears anywhere in the call graph,
/// which rules out every hidden or per-step allocation an implementation drifting
/// away from the two-cursor design would introduce. That is what this test
/// checks, over `parse_into`'s own body and every function it calls inside this
/// crate.
///
/// A second family of allocating constructs specific to this call graph: building a
/// brand new growable buffer, as opposed to writing into the one `parse_into` was
/// handed. `BytesMut::new()` with no reserved capacity would reallocate on first
/// write; `BytesMut::with_capacity`/`Vec::with_capacity` hide an allocation behind a
/// name `ALLOCATING_CALLS` does not already list.
const EXTRA_ALLOCATING_CALLS: [&str; 3] = [
    "BytesMut::new()",
    "BytesMut::with_capacity(",
    "Vec::with_capacity(",
];

#[test]
fn parse_into_allocates_at_most_the_documented_one() {
    let path_source = include_str!("../src/path.rs");

    // Every function `parse_into` can reach inside this crate, found by its own
    // (stable, single-line) signature text rather than by copying the whole
    // multi-line signature verbatim, so a rustfmt-driven line wrap of a parameter
    // list cannot break this test the way copying the full signature would.
    let signatures = [
        ("parse_into", "pub fn parse_into("),
        (
            "validate_path_syntax",
            "fn validate_path_syntax(path: &[u8]) -> Result<(), RejectReason> {",
        ),
        (
            "decode_path_into",
            "fn decode_path_into(path: &[u8], out: &mut BytesMut) -> Result<(), RejectReason> {",
        ),
        (
            "remove_dot_segments",
            "pub fn remove_dot_segments(buf: &mut [u8], len: usize) -> Result<usize, RejectReason> {",
        ),
        (
            "has_encoded_dot_segment",
            "fn has_encoded_dot_segment(buf: &[u8]) -> bool {",
        ),
        (
            "is_encoded_dot_segment",
            "fn is_encoded_dot_segment(seg: &[u8]) -> bool {",
        ),
        (
            "has_encoded_slash",
            "fn has_encoded_slash(buf: &[u8]) -> bool {",
        ),
        (
            "merge_slashes",
            "fn merge_slashes(buf: &mut [u8], len: usize) -> usize {",
        ),
        (
            "hex_pair_value",
            "const fn hex_pair_value(hi: u8, lo: u8) -> u8 {",
        ),
        ("hex_digit_value", "const fn hex_digit_value(b: u8) -> u8 {"),
        (
            "is_path_byte_ok",
            "const fn is_path_byte_ok(b: u8) -> bool {",
        ),
        (
            "is_unreserved_minus_dot",
            "const fn is_unreserved_minus_dot(b: u8) -> bool {",
        ),
    ];

    for (name, signature) in signatures {
        let body = extract_fn_body(path_source, signature).unwrap_or_else(|| {
            panic!("`fn {name}` not found in src/path.rs via `{signature}`; has it moved, been renamed, or been reformatted onto a different single-line signature?")
        });
        // `SmallVec<[u32; 32]>::new()` never touches the heap while it stays inline
        // (the whole reason `remove_dot_segments` uses it), but its own name embeds
        // the substring `Vec::new()`, which would otherwise read as a false positive
        // against `ALLOCATING_CALLS`'s `Vec::new()` entry. Strip only that exact,
        // known-safe substring before scanning, so a REAL bare `Vec::new()` written
        // anywhere else in the body is still caught.
        let body = body.replace("SmallVec::new()", "");
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; \
                 parse_into's whole call graph is documented to allocate at most once, \
                 via out.reserve, and nothing in its callees"
            );
        }
        for call in EXTRA_ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, a second buffer construction; \
                 parse_into writes only into the caller-supplied `out`, never a new one"
            );
        }
    }
}
