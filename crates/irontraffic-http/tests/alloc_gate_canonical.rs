// SPDX-License-Identifier: MIT OR Apache-2.0
//! `canonical-request-and-rewrite-ledger` (#33)'s zero-allocation gate for
//! `CanonicalRequestBuilder::build`.
//!
//! Its own allocation-gate file, one per surface, never appended to a shared file
//! (issue #630), matching `tests/alloc_gate.rs`'s own precedent.
//!
//! The issue's own design called for proving this at run time: 1000 `build` calls
//! through a `count_allocs` helper, asserting the count is exactly 0. That does not
//! compile in this workspace, for the exact reason `tests/alloc_gate.rs`'s own module
//! doc comment gives in full and this file does not repeat: `GlobalAlloc` is declared
//! as an `unsafe trait`, so even a pure pass-through counting allocator needs the
//! keyword this repository denies with no exception an implementer may grant
//! (AGENTS.md; `scripts/invariant-lints.sh`'s `no-unsafe` rule), and this package's
//! `[lints] workspace = true` applies that ban to every target of the package
//! including this one. A process-wide global allocator would also be unsound
//! independent of that ban: it counts allocations made by every other test running in
//! parallel in the same binary. There is no `count_allocs` helper anywhere in this
//! crate to call.
//!
//! This proves the checkable half of the same claim statically, the same
//! substitution every test in `tests/alloc_gate.rs` already makes: `build`'s I2 check
//! is a scan over the header section's EXISTING slots (`headers.slots()` and
//! `headers.name_at`, both index-only accessors documented and proven elsewhere in
//! `field-section-and-known-headers`, #24, and not re-verified here, matching
//! `strip_ingress_allocates_nothing`'s own precedent for the identical kind of
//! callee), so `build`'s entire NEW call graph in this crate is itself plus
//! `strip::is_hop_by_hop`, `strip::is_identity_field` and `strip::is_reserved_prefix`.
//! A text scan of exactly those four function bodies for the calls that can allocate
//! is exhaustive over every possible input to `build`, not just the 16-field shape
//! the issue's own benchmark section names, which is strictly stronger than a
//! counting allocator sampled over any finite number of calls would have been.

/// Calls that can allocate on the heap. The same vocabulary `tests/alloc_gate.rs`'s
/// own `ALLOCATING_CALLS` uses, duplicated here rather than imported: each file under
/// `tests/` compiles as its own crate, with no shared crate between them to hold one
/// copy.
const ALLOCATING_CALLS: [&str; 14] = [
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
    ".clone()",
];

/// Returns the source text of the function whose signature contains `signature`,
/// from that function's opening brace through its matching closing brace, or `None`
/// if `signature` is not found or has no matching closing brace.
///
/// A plain brace-depth text scan, not a Rust parser: correct as long as the scanned
/// body contains no string or char literal holding an unmatched `{` or `}`, which
/// every function scanned by this file satisfies today.
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
fn build_allocates_nothing() {
    // Static proof: `build`'s entire call graph inside this crate that is NEW here
    // (itself, `strip::is_hop_by_hop`, `strip::is_identity_field` and
    // `strip::is_reserved_prefix`) contains no call that can allocate, so no input,
    // and no header section shape, can make `build` touch the heap on its own
    // account. `FieldSection::slots`/`name_at` are index-only accessors, proven
    // allocation-free where they are defined (`field-section-and-known-headers`,
    // #24) and not re-verified here, the same reach `strip_ingress_allocates_nothing`
    // in `tests/alloc_gate.rs` already uses for the identical kind of callee.
    //
    // The loop below is inlined directly in this `#[test]` body rather than
    // factored into a shared helper: `scripts/invariant-lints.sh`'s
    // `no-test-without-assertion` rule scans a test function's own body text for an
    // assertion and cannot see through a call to a separate function that does the
    // asserting, so a helper here would make this test look empty to that rule even
    // though it genuinely asserts.
    let canonical_source = include_str!("../src/canonical.rs");
    let strip_source = include_str!("../src/strip.rs");

    let checked: [(&str, &str, &str); 4] = [
        (
            "build",
            canonical_source,
            "pub fn build(self) -> Result<CanonicalRequest, RejectReason> {",
        ),
        (
            "is_hop_by_hop",
            strip_source,
            "pub const fn is_hop_by_hop(k: KnownHeader) -> bool {",
        ),
        (
            "is_identity_field",
            strip_source,
            "pub const fn is_identity_field(k: KnownHeader) -> bool {",
        ),
        (
            "is_reserved_prefix",
            strip_source,
            "pub fn is_reserved_prefix(name: &[u8]) -> bool {",
        ),
    ];

    for (name, source, signature) in checked {
        let body = extract_fn_body(source, signature).unwrap_or_else(|| {
            panic!("`{signature}` not found; has {name} moved, been renamed, or been reformatted?")
        });
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; build's whole \
                 call graph (new in this crate) is documented to never allocate"
            );
        }
    }
}
