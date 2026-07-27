// SPDX-License-Identifier: MIT OR Apache-2.0
//! The allocation gate for the HTTP/1 head-parser surface.
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
//! **What a text scan cannot do, honestly stated (issue #585).** A source
//! scan can only ever be a deny list against a finite vocabulary; it cannot
//! distinguish zero allocations from however many an input drives, because it
//! never runs the code. Two concrete failures of the vocabulary that shipped
//! here, both found by an independent Opus reviewer on PR 557 by executing
//! probes rather than reading the file:
//!
//! 1. `ALLOCATING_CALLS` omitted `.clone()`, even though this file's own
//!    claim was that it matched "the exact vocabulary"
//!    `scripts/invariant-lints.sh`'s `hot-path-allocation` rule uses, and
//!    that rule's regex does include `.clone()`; added below, safe for every
//!    body this file scans; grepped first to confirm none of them already
//!    contain it. It also omitted `.to_ascii_lowercase()` and
//!    `.to_ascii_uppercase()`, which is not a hypothetical gap for the h1
//!    parser specifically: `RawField::needs_lowercase` exists precisely
//!    because a field name's case folding was deferred to the consumer, so a
//!    future edit that folded it here instead, with the obvious one-line
//!    call, would have shipped green. Reproduced directly: inserting
//!    `name_raw.to_ascii_lowercase()` into `parse_field_lines` (ten real heap
//!    allocations per parse of the 400-byte head, a hundred and one for the
//!    hundred-field head, measured with a counting allocator in a scratch
//!    crate outside this workspace, see below) left every test in this file
//!    green, because neither omitted call was in the list.
//!
//!    `.to_ascii_lowercase()`/`.to_ascii_uppercase()` are added to a SECOND,
//!    narrower list (`H1_HEAD_ALLOCATING_CALLS`, below), used only by the h1
//!    parser test, rather than folded into `ALLOCATING_CALLS` itself: a plain
//!    text scan cannot tell `[u8]::to_ascii_lowercase()`/`str::to_ascii_lowercase()`
//!    (both allocate, return an owned `Vec<u8>`/`String`) apart from
//!    `u8::to_ascii_lowercase()` (a `Copy` scalar method, allocates nothing),
//!    because the call SITE reads identically either way; `authority.rs`'s
//!    `parse_into`, one of the functions `ALLOCATING_CALLS` polices (in
//!    `tests/alloc_gate_authority.rs`),
//!    already legitimately calls the scalar form once
//!    (`out.put_u8(b.to_ascii_lowercase())`), so adding the pattern there
//!    would fail a function that has never allocated. Scoping the wider
//!    pattern to the one function pair it was actually found missing from,
//!    neither of which uses the scalar form today, avoids manufacturing a
//!    false failure elsewhere to close a gap that has nothing to do with
//!    that other function. The general problem, an allocating call this
//!    vocabulary has simply never heard of, has no complete solution
//!    available to a text scan and is not claimed to be solved by extending
//!    a list one more time.
//! 2. Changing `parser.rs`'s `if fields.len() == 32` guard (the one place
//!    `SmallVec::reserve` is called, only once a parse's 33rd field line
//!    arrives) to `!= 32` makes `reserve` fire on the very first push of
//!    EVERY parse instead: a five-field head starts allocating that never
//!    should. Every test in this file still passed, because `.reserve(`
//!    still appears exactly once in the source; a text scan cannot see that
//!    the RUNTIME CONDITION governing when a call fires changed, only that
//!    the call is textually present. This is fixed below not by scanning
//!    harder but by asking the actual `SmallVec` whether it spilled to the
//!    heap after a real parse: `SmallVec::spilled()` is a safe, `unsafe`-free
//!    inherent method that reports the container's real storage variant
//!    (inline vs. heap-backed), so it is a genuine EXECUTING measurement of
//!    the one call site this crate's allocation-freedom claim actually rests
//!    on, not a second scan wearing a different hat. It does not generalize
//!    to every possible allocation in the call graph (a temporary allocated
//!    and freed elsewhere, never stored in `fields`, would not move
//!    `spilled()` either), only to this specific, named, headline-invariant
//!    call site; the vocabulary scan above remains the best available
//!    defense for everything else, and it remains a deny list, not a proof.
//!    See `parse_field_storage_spills_only_past_the_inline_32`, below.
//!
//! **The numbers issue #34's own acceptance criterion asks for are true and
//! were measured, just not inside this workspace.** `GlobalAlloc` being an
//! `unsafe trait` and the workspace's blanket `unsafe_code = "deny"` (AGENTS.md
//! rule 3; also see the module doc comment above) rule out a counting
//! `#[global_allocator]` living anywhere in this repository, in a test binary
//! or otherwise: even a pure pass-through to `std::alloc::System` requires the
//! `unsafe` keyword on the trait implementation, and a process-wide allocator
//! would in any case count allocations made by every other test running in
//! parallel in the same binary. A standalone scratch crate outside this
//! workspace, with its own `Cargo.toml` and its own counting
//! `#[global_allocator]`, has no such constraint (it is not part of the tree
//! this repository's gate reviews), and running the issue's own two cases
//! through it against this PR's
//! unmodified code measured exactly what the issue's acceptance criterion
//! names: 0 heap allocations across 1000 parses of a realistic 425-byte,
//! 7-field head, and exactly 1000 allocations (one `SmallVec` spill each)
//! across 1000 parses of a 908-byte, 100-field head. The property is true;
//! this file's job is proving it stays true without that scratch crate's
//! tools, which is strictly less than a live global-allocator count would
//! prove, and is documented as such rather than implied to be equivalent to
//! it.

mod alloc_gate_common;

use alloc_gate_common::{ALLOCATING_CALLS, extract_fn_body};
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::{Limits, ParseStatus};

/// `ALLOCATING_CALLS` plus the two calls issue #585 found missing for the h1
/// parser specifically: `.to_ascii_lowercase()` and `.to_ascii_uppercase()`.
/// Built FROM `ALLOCATING_CALLS` at call time (never a second literal copy),
/// so the two lists cannot silently drift apart the way `ALLOCATING_CALLS`
/// itself already drifted from its own claimed source of truth once. NOT
/// folded permanently into `ALLOCATING_CALLS` itself; see the module doc
/// comment above for why (`authority::parse_into` legitimately calls the
/// non-allocating scalar form of the same method name, and a text scan
/// cannot tell the two apart by the call site alone). Used only by
/// `parse_request_head_allocates_only_the_declared_reserve`, below, whose two
/// scanned bodies (`parse_request_head`, `parse_field_lines`) use neither
/// form today.
fn h1_head_allocating_calls() -> Vec<&'static str> {
    let mut calls = ALLOCATING_CALLS.to_vec();
    calls.push(".to_ascii_lowercase()");
    calls.push(".to_ascii_uppercase()");
    calls
}

/// `h1-head-parser` (#34)'s zero-allocation gate for `H1Parser::parse_request_head`.
///
/// The issue's own design called for proving this at run time: 1000 parses of a
/// 400-byte typical head through a `count_allocs` helper, asserting the count is
/// exactly 0, and 1000 parses of a 100-field head asserting the count is exactly
/// 1000 (one `SmallVec` spill per parse and nothing else). That does not compile
/// in this workspace, for the exact reason explained in the module doc comment
/// above: `GlobalAlloc` is an `unsafe trait`, this package's `[lints] workspace =
/// true` applies the workspace's `unsafe_code = "deny"` to every target
/// including this one, and a process-wide counting allocator would in any case
/// count allocations made by every other test running in parallel in the same
/// binary. There is no `count_allocs` helper anywhere in this crate to call.
///
/// This proves the checkable half of the same claim statically, the same
/// substitution the sibling `alloc_gate_*.rs` gates already make:
/// `parse_request_head`'s own
/// body contains no call from `h1_head_allocating_calls()`, so it cannot
/// itself touch the allocator; the actual field storage lives in
/// `parse_field_lines` (the private helper `parse_request_head` and
/// `parse_response_head` share), whose body ALSO contains no call from that
/// list other than its one declared `SmallVec::reserve`, appearing exactly
/// once in the source. That `reserve` is the "one `SmallVec` spill per parse"
/// the issue's own design names: `SmallVec<[RawField; 32]>` never allocates
/// for the inline 32 entries, and this is what proves the ONLY way a parse
/// can ever touch the heap, THROUGH THIS TEXT SCAN'S OWN VIEW, is through
/// that one, single-occurrence call.
///
/// That last qualifier is the one issue #585 found this test was overstating:
/// a source scan proves the call is textually present once, not that it
/// fires only when it should. `parse_field_storage_spills_only_past_the_inline_32`,
/// below, closes that specific gap with a real measurement instead of a
/// second scan.
#[test]
fn parse_request_head_allocates_only_the_declared_reserve() {
    let parser_source = include_str!("../src/h1/parser.rs");
    let h1_calls = h1_head_allocating_calls();

    let parse_request_head_body = extract_fn_body(parser_source, "pub fn parse_request_head<'b>(")
        .expect(
            "`fn parse_request_head` not found in src/h1/parser.rs; has it moved or been renamed?",
        );
    for call in &h1_calls {
        assert!(
            !parse_request_head_body.contains(call),
            "parse_request_head's body contains `{call}`, which can allocate; \
             parse_request_head is documented to allocate only through the one \
             declared SmallVec::reserve inside parse_field_lines"
        );
    }

    let parse_field_lines_body = extract_fn_body(parser_source, "fn parse_field_lines(").expect(
        "`fn parse_field_lines` not found in src/h1/parser.rs; has it moved or been renamed?",
    );
    for call in &h1_calls {
        assert!(
            !parse_field_lines_body.contains(call),
            "parse_field_lines's body contains `{call}`, which can allocate; \
             parse_field_lines is documented to allocate only through its one \
             declared SmallVec::reserve"
        );
    }

    let reserve_count = parse_field_lines_body.matches(".reserve(").count();
    assert_eq!(
        reserve_count, 1,
        "parse_field_lines must call SmallVec::reserve exactly once, the one declared \
         allocation for a head that spills past 32 fields; found {reserve_count} \
         occurrences in its body"
    );
}

/// The genuine, executing counterpart to the text scan above (issue #585):
/// asks the real `SmallVec<[RawField; 32]>` a real parse produced whether it
/// actually spilled to the heap, rather than trusting that `.reserve(`
/// appearing once in the source means it fires only when it should.
///
/// `SmallVec::spilled()` (`self.capacity > Self::inline_capacity()`, smallvec
/// 1.15.2) is a safe inherent method, no `unsafe`, no `#[global_allocator]`:
/// it reports which storage variant the container is actually using right
/// now. `RawHead::fields` is `pub`, so this integration test crate can read
/// it directly on the value a real `parse_request_head` call returned.
///
/// This is what closes the concrete gap the reviewer named: mutating
/// `parser.rs`'s `if fields.len() == 32` guard to `!= 32` makes `reserve`
/// fire on the very first push of every parse. That mutant leaves
/// `.reserve(` appearing exactly once in the source, so the text-scan test
/// above still passes it; it does NOT leave a five-field parse inline, so
/// `spilled()` on the result catches it directly. Boundary cases both ways:
/// 0, 1 and 32 fields must stay inline; 33 must spill, one past the
/// `SmallVec`'s declared inline capacity.
#[test]
fn parse_field_storage_spills_only_past_the_inline_32() {
    let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);

    let build = |field_count: usize| {
        let mut buf = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..field_count {
            buf.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        buf
    };

    for field_count in [0usize, 1, 5, 32] {
        let raw = build(field_count);
        match parser.parse_request_head(&raw) {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert!(
                    !value.fields.spilled(),
                    "a {field_count}-field head spilled to the heap; it must stay inline \
                     (0 heap allocations) up to and including 32 fields"
                );
            }
            other => panic!("expected Complete for {field_count} fields, got {other:?}"),
        }
    }

    let raw = build(33);
    match parser.parse_request_head(&raw) {
        Ok(ParseStatus::Complete { value, .. }) => {
            assert!(
                value.fields.spilled(),
                "a 33-field head did not spill to the heap; the one declared SmallVec::reserve \
                 must fire once the inline 32 is exceeded"
            );
        }
        other => panic!("expected Complete for 33 fields, got {other:?}"),
    }
}
