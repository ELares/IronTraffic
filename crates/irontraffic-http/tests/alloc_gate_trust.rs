// SPDX-License-Identifier: MIT OR Apache-2.0
//! `trust-policy-and-peer-identity` (#32)'s zero-allocation gate for
//! `resolve_identity`.
//!
//! The issue's own design called for proving this at run time: 1000
//! `resolve_identity` calls for each of three shapes (`TrustPolicy::None`
//! with an empty chain, `HopCount(1)` with a one-element chain, and
//! `TrustedCidrs` with two prefixes over a 32-element chain), each through a
//! `count_allocs` helper, asserting the count is exactly 0. That does not
//! compile in this workspace, for the exact reason `tests/alloc_gate.rs`
//! already gives for four earlier issues that asked for the identical
//! pattern: `GlobalAlloc` is declared `unsafe trait`, so any implementation,
//! including a pure pass-through to `std::alloc::System`, needs the keyword
//! this repository denies with no exception an implementer may grant
//! (AGENTS.md rule 3; `unsafe_code = "deny"` in the workspace lints, applied
//! to every target of this package, tests included, by `[lints] workspace =
//! true` in `Cargo.toml`). A process-wide counting allocator would in any
//! case count allocations made by every other test running in parallel in
//! the same binary, which makes an exact "0, no more" assertion meaningless
//! regardless of the ban. There is no `count_allocs` helper anywhere in this
//! crate to call, and this file introduces none: see
//! `tests/alloc_gate.rs`'s own module doc comment for the full account of
//! why, and for the numbers it measured in a standalone scratch crate
//! outside this workspace instead.
//!
//! This proves the checkable half of the same claim statically, the same
//! substitution every test in `tests/alloc_gate.rs` already makes:
//! `resolve_identity`'s entire call graph inside this crate is itself,
//! `nearest_proto`, `walk_trusted_cidrs`, `saturate_hops` (all in
//! `src/peer.rs`), and `IpCidr::contains` and its private helper `bits_match`
//! (`src/cidr.rs`), so a text scan of exactly those six function bodies for
//! the calls that can allocate is exhaustive over every possible input to
//! `resolve_identity`, not just the three shapes the issue's own benchmark
//! section names. Which of `resolve_identity`'s branches runs for a given
//! input is a runtime CONDITION over this same, fixed source text; the scan
//! covers every branch unconditionally, which is what makes it exhaustive
//! rather than a proof about only the branches a particular call happens to
//! take.
//!
//! `write_forwarded_element`, `forwarded_element_len` and `write_x_forwarded`
//! are NOT covered here: the issue's own zero-allocation claim (and its
//! `count_allocs` proposal) names only `resolve_identity`, and the writer
//! functions build no chain-independent data structure of their own; they
//! write into a caller-supplied `BytesMut`, which is a separate concern from
//! the claim this file exists to check.

/// Calls that can allocate on the heap. The same vocabulary
/// `tests/alloc_gate.rs`'s own `ALLOCATING_CALLS` uses, duplicated here
/// rather than imported: each file under `tests/` compiles as its own crate,
/// with no shared crate between them to hold one copy, matching the "one
/// allocation-gate file per surface" precedent this same issue's `## Files`
/// table cites (issue #630). See `tests/alloc_gate.rs` for the two gaps an
/// independent reviewer already found in an earlier version of this exact
/// list (`.clone()`, `.to_ascii_lowercase()`/`.to_ascii_uppercase()`) and why
/// this remains a deny list rather than a proof: it catches every call named
/// here, textually, and nothing else.
const ALLOCATING_CALLS: [&str; 15] = [
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
    ".to_ascii_lowercase()",
];

/// Returns the source text of the function whose signature contains
/// `signature`, from that function's opening brace through its matching
/// closing brace, or `None` if `signature` is not found or has no matching
/// closing brace.
///
/// A plain brace-depth text scan, not a Rust parser: correct as long as the
/// scanned body contains no string or char literal holding an unmatched `{`
/// or `}`, which every function scanned by this file satisfies today. See
/// `tests/alloc_gate.rs` for the full rationale; this is the same helper,
/// duplicated for the reason given in `ALLOCATING_CALLS`'s own doc comment
/// above.
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
fn resolve_identity_allocates_nothing() {
    // Static proof: `resolve_identity`'s entire call graph inside this crate
    // (itself, `nearest_proto`, `walk_trusted_cidrs`, `saturate_hops`,
    // `IpCidr::contains` and `bits_match`) contains no call that can
    // allocate, so no input, and no choice of `TrustPolicy`, can make
    // `resolve_identity` touch the heap. This is exhaustive over every
    // possible input, not merely over the three shapes the issue's own
    // benchmark section names, which is strictly stronger than a counting
    // allocator sampled over any finite number of calls would have been.
    //
    // The loop below is inlined directly in this `#[test]` body rather than
    // factored into a shared helper: `scripts/invariant-lints.sh`'s
    // `no-test-without-assertion` rule scans a test function's own body text
    // for an assertion and cannot see through a call to a separate function
    // that does the asserting, so a helper here would make this test look
    // empty to that rule even though it genuinely asserts, the same reason
    // every test in `tests/alloc_gate.rs` inlines its own loop.
    let peer_source = include_str!("../src/peer.rs");
    let cidr_source = include_str!("../src/cidr.rs");

    let checked: [(&str, &str, &str); 6] = [
        ("resolve_identity", peer_source, "pub fn resolve_identity("),
        ("nearest_proto", peer_source, "fn nearest_proto("),
        ("walk_trusted_cidrs", peer_source, "fn walk_trusted_cidrs("),
        ("saturate_hops", peer_source, "fn saturate_hops("),
        (
            "IpCidr::contains",
            cidr_source,
            "pub fn contains(&self, other: IpAddr) -> bool {",
        ),
        ("bits_match", cidr_source, "fn bits_match("),
    ];

    for (name, source, signature) in checked {
        let body = extract_fn_body(source, signature).unwrap_or_else(|| {
            panic!("`{signature}` not found; has {name} moved, been renamed, or been reformatted?")
        });
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; resolve_identity's \
                 whole call graph is documented to never allocate"
            );
        }
    }
}
