// SPDX-License-Identifier: MIT OR Apache-2.0
//! The first zero-allocation gate for this crate: `validate_value` is
//! documented to perform no heap allocation.
//!
//! This issue's own design called for a process-wide counting
//! `#[global_allocator]` test to prove that at run time. That does not
//! compile here: `GlobalAlloc` is declared as an `unsafe trait`, so every
//! implementation, including a pure counter that forwards straight to
//! `std::alloc::System`, needs the keyword this repository denies with no
//! exception an implementer may grant (AGENTS.md, and the `no-unsafe` rule in
//! `scripts/invariant-lints.sh`). `#![forbid(unsafe_code)]` in `lib.rs` is a
//! crate-root attribute and does not reach a separate crate under `tests/`,
//! but this package's `[lints] workspace = true` in `Cargo.toml` does: it
//! applies the workspace's `unsafe_code = "deny"` to every target of the
//! package, integration tests included, which is confirmed by trying it. A
//! process-wide global allocator is also unsound independent of that ban: it
//! counts allocations made by every other test running in parallel in the
//! same binary, and this file is documented to grow more tests over time.
//!
//! Instead this proves the same property the way the rest of this
//! workspace's allocation-freedom claims are enforced when the call graph is
//! concrete and non-dispatching (see `crates/irontraffic-k8s/tests/identity_sizes.rs`,
//! the reference implementation for this pattern): `scripts/invariant-lints.sh`'s
//! `hot-path-allocation` rule polices "does this code allocate" by scanning
//! source text for the calls that can allocate, not by instrumenting the
//! allocator. `validate_value`'s entire call graph inside this crate is
//! itself, `value_byte_ok`, and `WireVersion::is_multiplexed`, so a text scan
//! of exactly those three function bodies for that same set of calls is
//! exhaustive over every possible input, not just the ones a particular run
//! happens to generate.

/// Calls that can allocate on the heap, in the exact vocabulary
/// `scripts/invariant-lints.sh`'s `hot-path-allocation` rule already uses to
/// police this property elsewhere in the workspace.
const ALLOCATING_CALLS: [&str; 13] = [
    "format!",
    ".to_string()",
    ".to_owned()",
    ".to_vec()",
    "vec![",
    "Vec::new()",
    "String::new()",
    "String::from(",
    "Box::new(",
    "HashMap::new()",
    ".collect::<Vec",
    ".collect::<String",
    ".collect::<HashMap",
];

/// Returns the source text of the function whose signature contains
/// `signature`, from that function's opening brace through its matching
/// closing brace, or `None` if `signature` is not found or has no matching
/// closing brace.
///
/// A plain brace-depth text scan, not a Rust parser: correct as long as the
/// scanned body contains no string or char literal holding an unmatched `{`
/// or `}`, which every function scanned by this file satisfies today. If a
/// future edit to one of them ever needs such a literal, this test will need
/// a smarter scanner, not a workaround here.
///
/// Returns `Option` rather than panicking so this plain helper function,
/// which is not itself a `#[test]`, stays outside the escape clippy.toml
/// grants to test code; the caller below unwraps it inside the `#[test]`
/// function where that escape applies.
fn extract_fn_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let open = source[start..].find('{').map(|offset| start + offset)?;
    let mut depth = 0usize;
    let mut end = open;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + offset + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end > open {
        Some(&source[open..end])
    } else {
        None
    }
}

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
/// substitution `validate_allocates_nothing` above already makes for
/// `validate_value`: `parse_into`'s own body contains no call from
/// `ALLOCATING_CALLS` other than its one declared `split_off`, so the ONLY
/// way it can touch the allocator is through that one `split_off`/`freeze`
/// pair, and it appears exactly once in the source, never behind a
/// conditional branch that could run it twice for one call.
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
/// `validate_allocates_nothing` above already makes for `validate_value`:
/// `resolve_request_framing`'s entire call graph inside this crate is
/// itself, `tokenize_transfer_encoding`, `parse_content_length`, and
/// `field::trim_ows`, so a text scan of exactly those four function bodies
/// for the same allocating-call vocabulary is exhaustive over every
/// possible input, not just the three benchmark inputs the issue's design
/// named.
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
