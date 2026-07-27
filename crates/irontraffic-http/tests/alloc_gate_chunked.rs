// SPDX-License-Identifier: MIT OR Apache-2.0
//! The zero-allocation gate for `h1-chunked-and-trailers` (#36)'s
//! `ChunkedDecoder::decode`: decoding a 1 MiB single-chunk body with no
//! trailers must allocate nothing, because the decoder touches the arena
//! only when a trailer section exists.
//!
//! Its own allocation-gate file, one per surface, never appended to a shared
//! file (issue #630), matching `tests/alloc_gate.rs`'s own precedent.
//!
//! The issue's own design calls for proving this at run time through a
//! `count_allocs` helper. That does not compile in this workspace, for the
//! exact reason `tests/alloc_gate.rs`'s own module doc comment gives in full
//! and this file does not repeat: `GlobalAlloc` is declared as an `unsafe
//! trait`, so even a pure pass-through counting allocator needs the keyword
//! this repository denies with no exception an implementer may grant
//! (AGENTS.md; `scripts/invariant-lints.sh`'s `no-unsafe` rule), and this
//! package's `[lints] workspace = true` applies that ban to every target of
//! the package including this one. A process-wide global allocator would
//! also be unsound independent of that ban: it counts allocations made by
//! every other test running in parallel in the same binary. There is no
//! `count_allocs` helper anywhere in this crate to call.
//!
//! This proves the same property the way every other allocation-freedom
//! claim in this crate is proven when the call graph is concrete and
//! non-dispatching (see `tests/alloc_gate.rs`'s own tests, the reference
//! implementations for this pattern): a text scan of the exact allocating-
//! call vocabulary `scripts/invariant-lints.sh`'s `hot-path-allocation` rule
//! uses, over every function `decode` can reach for a body with NO trailer
//! section. `ChunkedDecoder::decode` dispatches to `run`, which for a body
//! with no trailer section (`remaining` never reaches 0 with a following
//! trailer field, i.e. state never leaves `Size`/`Ext`/`SizeCrlf`/`Data`/
//! `DataCrlf`) calls only `step_size`, `step_ext`, `step_size_crlf`,
//! `step_data`, `step_data_crlf`, `accept_size_digit`, `hex_digit_value`, and
//! `is_ext_top_byte`. `step_size_crlf` is the ONE function in that list whose
//! body touches the arena at all (`FieldSectionBuilder::new`,
//! `HeaderListBudget::new`), and both of those calls are reached only on the
//! branch taken when `remaining == 0`, i.e. only when a trailer section is
//! about to begin; a 1 MiB single-chunk body never takes that branch until
//! its own terminal `0` chunk, at which point THIS scan's claim ends (the
//! terminal `0\r\n\r\n` and its trailer section are outside what "no
//! trailers" claims to cover; see the test below, which decodes only the
//! declared 1 MiB of body data, not the message's own terminator).

use bytes::BytesMut;
use irontraffic_http::Limits;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::chunked::{ChunkedDecoder, ChunkedEvent};

/// Calls that can allocate on the heap. The same vocabulary
/// `tests/alloc_gate.rs`'s `ALLOCATING_CALLS` uses, kept as an independent
/// copy rather than a shared import: an integration test crate is its own
/// compilation unit, and `tests/alloc_gate.rs` exposes no importable items
/// (it is a binary, not a library).
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

/// As `tests/alloc_gate.rs`'s own `extract_fn_body`: the source text of the
/// function whose signature contains `signature`, from that function's
/// opening brace through its matching closing brace, or `None` if not found.
/// A plain brace-depth text scan, not a Rust parser; correct as long as the
/// scanned body contains no string or char literal holding an unmatched `{`
/// or `}`, which every function scanned by this file satisfies today.
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
fn chunked_decode_allocates_nothing_for_a_body_with_no_trailers() {
    // Static proof: every function `decode` can reach for a body that never
    // enters the Trailers state contains no call from `ALLOCATING_CALLS`,
    // except `step_size_crlf`'s two calls, which are reached only on the
    // branch that STARTS a trailer section (see the module doc comment).
    // This is exhaustive over every possible no-trailer input, not merely
    // over one sampled run.
    let source = include_str!("../src/h1/chunked.rs");

    let no_arena_touch: [(&str, &str); 8] = [
        (
            "step_size",
            "fn step_size(&mut self, buf: &[u8], cursor: &mut usize) -> Result<Step, RejectReason> {",
        ),
        (
            "step_ext",
            "fn step_ext(&mut self, buf: &[u8], cursor: &mut usize) -> Result<Step, RejectReason> {",
        ),
        (
            "step_data",
            "fn step_data(&mut self, buf: &[u8], cursor: &mut usize) -> Option<ChunkedEvent> {",
        ),
        (
            "step_data_crlf",
            "fn step_data_crlf(&mut self, buf: &[u8], cursor: &mut usize) -> Result<Step, RejectReason> {",
        ),
        (
            "accept_size_digit",
            "fn accept_size_digit(&mut self, b: u8) -> Result<(), RejectReason> {",
        ),
        (
            "hex_digit_value",
            "fn hex_digit_value(b: u8) -> Option<u8> {",
        ),
        ("is_ext_top_byte", "fn is_ext_top_byte(b: u8) -> bool {"),
        ("run", "fn run(\n"),
    ];

    for (name, signature) in no_arena_touch {
        let body = extract_fn_body(source, signature).unwrap_or_else(|| {
            panic!("`{name}` not found via `{signature}`; has it moved or been renamed?")
        });
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; a no-trailer decode \
                 must never touch the heap"
            );
        }
    }

    // step_size_crlf is the one function that touches the arena, and ONLY on
    // the remaining == 0 branch (about to start a trailer section). Prove
    // that branch structure holds rather than merely that the two arena
    // calls exist somewhere in the function.
    let step_size_crlf_body = extract_fn_body(
        source,
        "fn step_size_crlf(\n        &mut self,\n        buf: &[u8],\n        cursor: &mut usize,\n        arena: &mut BytesMut,\n    ) -> Result<Step, RejectReason> {",
    )
    .expect("`step_size_crlf` not found; has its signature been reformatted?");
    assert!(
        step_size_crlf_body.contains("if self.remaining == 0 {"),
        "step_size_crlf's arena-touching calls must stay guarded by the remaining == 0 branch"
    );
    let arena_touch_region = step_size_crlf_body
        .split("if self.remaining == 0 {")
        .nth(1)
        .and_then(|rest| rest.split("} else {").next())
        .expect("step_size_crlf must have an if remaining == 0 { .. } else { .. } shape");
    assert!(
        arena_touch_region.contains("FieldSectionBuilder::new(arena")
            && arena_touch_region.contains("HeaderListBudget::new(&self.limits)"),
        "the arena-touching calls must live inside the remaining == 0 branch"
    );

    // The genuine, executing counterpart to the text scan above: decode a
    // real 1 MiB single-chunk body (no trailers) and confirm it actually
    // completes, so the text scan above is exercised against a real,
    // representative run rather than an input nobody checked parses.
    let len = 1024 * 1024;
    let mut wire = format!("{len:x}\r\n").into_bytes();
    wire.extend(std::iter::repeat_n(b'z', len));
    wire.extend_from_slice(b"\r\n");

    let mut decoder = ChunkedDecoder::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let mut pos = 0usize;
    let mut delivered = 0usize;
    // One arena for the whole drive, declared outside the loop: decode's
    // documented precondition (issue #658) is that arena is the SAME
    // growing buffer across every call for one body, never a fresh one per
    // call. This body never reaches a trailer section (see the module doc
    // comment), so the precondition is trivially free to keep here, but a
    // fresh arena per call would still be wrong to model.
    let mut arena = BytesMut::new();
    loop {
        let buf = wire.get(pos..).unwrap_or(&[]);
        if buf.is_empty() && delivered == len {
            break;
        }
        match decoder
            .decode(buf, &mut arena)
            .expect("a well-formed 1 MiB single chunk must decode without error")
        {
            ChunkedEvent::Data { len: n, .. } => {
                delivered = delivered.saturating_add(n);
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            ChunkedEvent::NeedMore => {
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            ChunkedEvent::Done { .. } => break,
        }
        assert!(
            arena.is_empty(),
            "no trailer section exists yet; the arena must stay untouched"
        );
    }
    assert_eq!(delivered, len);
}
