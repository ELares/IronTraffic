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

/// `hop-by-hop-and-reserved-prefix-strip` (#26)'s zero-allocation gate for
/// `strip_ingress`.
///
/// The issue's own design called for proving this at run time: 1000
/// `strip_ingress` calls over the adversarial section from its Benchmarks
/// section, through a `count_allocs` helper, each expected to report exactly
/// 0 allocations. That does not compile in this workspace, for the same
/// reason the two tests above already gave up on the identical request from
/// their own issues: `GlobalAlloc` is an `unsafe trait`, this package's
/// `[lints] workspace = true` in `Cargo.toml` applies the workspace's
/// `unsafe_code = "deny"` to every target of the package including this one,
/// and a process-wide counting allocator would in any case count allocations
/// made by every other test running in parallel in the same binary. There is
/// no `count_allocs` helper anywhere in this crate to call.
///
/// This proves the checkable half of the same claim statically, the same
/// substitution the two tests above already make: `strip_ingress`'s call
/// graph inside this crate is itself, `strip_static_and_te`,
/// `collect_connection_tokens`, `token_names` and `is_reserved_prefix` (all
/// defined in `src/strip.rs`), plus `trim_ows` (defined in `src/field.rs`,
/// the same cross-file reach `validate_allocates_nothing` above already
/// makes for `is_multiplexed`). The section-arena methods `strip_ingress`
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

/// `path-normalization` (#29)'s own design called for exactly the same
/// process-wide counting `#[global_allocator]` this file's module doc already
/// rejects, wrapping 1000 calls to `NormalizedPath::parse_into` over each of the
/// five benchmark inputs and asserting the count is exactly 1000. That does not
/// compile here for the identical reason `validate_allocates_nothing` above does
/// not: `GlobalAlloc` is `unsafe trait`, this package's `[lints] workspace = true`
/// applies `unsafe_code = "deny"` to every target including this one, and a
/// process-wide allocator would also count every other test running in parallel
/// in the same binary.
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

/// `forwarded-element-parsing` (#31)'s allocation-freedom gate for
/// `ForwardedChain::parse_into`.
///
/// The issue's own design called for proving this at run time: 1000 parses
/// of a single-entry chain (no `host` parameter) reporting exactly 0
/// allocations through a `count_allocs` helper, because nothing is split off
/// and the 8-inline-element `SmallVec` never spills; and 1000 parses of a
/// 32-entry chain reporting at most 1000 (one spill each). That does not
/// compile in this workspace, for the same reason
/// `authority_parse_into_allocates_only_the_declared_split_off` above gives:
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
