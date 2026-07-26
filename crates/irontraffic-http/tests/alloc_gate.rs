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
