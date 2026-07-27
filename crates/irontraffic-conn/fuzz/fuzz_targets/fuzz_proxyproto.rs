#![no_main]

//! Fuzz target for `irontraffic_conn::proxyproto::ProxyHeader::parse`.
//!
//! Input domain: arbitrary bytes. Every call `data` is fed to `parse` unmodified, exactly as
//! before, so the ORIGINAL contract below still holds for `data` itself. In addition, `data`
//! is reused, unmodified, as a mutation seed over a valid v1 or a valid v2 header template
//! (see `mutated_from_template`) and that second buffer is ALSO fed to `parse`. This second
//! pass is the fix for a review finding on this fuzz target: dispatch commits to v1 only on
//! an exact 6 byte `b"PROXY "` match and to v2 only on an exact 12 byte signature match, and
//! blind byte level mutation essentially never produces either exact prefix on its own. A
//! baseline run of this target BEFORE this change (`-max_total_time=15`, no seed corpus) hit
//! 2.9 million executions, plateaued at 38 of the dispatch function's coverage edges after
//! the first 4623, and never grew a corpus entry past 13 bytes, well short of the shortest
//! legal header (15 bytes for v1 `UNKNOWN`, 16 for v2 `LOCAL`). That means the "500000 runs,
//! no crash" acceptance criterion was, in practice, exercising only the two early rejection
//! branches of `ProxyHeader::parse` in `mod.rs` and never once entering `v1::parse` or
//! `v2::parse` at all: a run that reports success while verifying nothing about either wire
//! format parser, the exact vacuous shape this repository has already found six times
//! elsewhere. Seeding every call with a template mutation makes the two real parsers, and the
//! TLV walker inside `v2::parse`, reachable on essentially every execution, while every byte
//! that reaches `parse` is still entirely determined by `data`, so the fuzzer's own
//! coverage-guided mutation of `data` is what explores the templates' neighbourhood: nothing
//! here hand-writes a fixed set of inputs the way the unit tests do.
//!
//! Contract, for BOTH buffers passed to `parse` (the raw `data` and the template mutation):
//! no panic, no hang, and ZERO allocation for any input, including one that declares a v2
//! length of 65535 with only a handful of bytes actually present (allocation proportional to
//! the DECLARED length rather than the RECEIVED length is exactly the vulnerability this
//! parser exists to avoid). Also asserts, on `Complete`, that `consumed <= buf.len()` and
//! that `value.consumed == consumed`. The input buffer unchanged assertion applies only to
//! `data` itself (the template mutation is a locally owned `Vec`, not the fuzzer's input, so
//! there is nothing outside this file for it to corrupt): this parser only ever borrows its
//! argument as `&[u8]`, never `&mut [u8]`, so that is also enforced by the type system, and
//! the assertion below is a second, independent proof for a fuzz report to point at directly.
//!
//! The counting allocator below is the same shim `field-validation-tables` (#23) specifies
//! for `tests/alloc_gate.rs`, copied here rather than shared, because a fuzz target is its
//! own crate (see `../Cargo.toml`'s independent, empty `[workspace]` table) and cannot
//! import a `#[global_allocator]` from a test binary in a different crate, and because it
//! is not covered by `irontraffic-conn`'s own `#![forbid(unsafe_code)]`, a crate-root
//! attribute that does not reach this separate crate. `GlobalAlloc` is an `unsafe trait`,
//! so even a pure counter forwarding to `std::alloc::System` needs the keyword: the main
//! workspace's `unsafe_code = "deny"` (AGENTS.md rule 3) would refuse it, but THIS crate is
//! its own independent workspace (its own empty `[workspace]` table, no
//! `[lints] workspace = true`) and does not inherit that lint. `scripts/invariant-lints.sh`'s
//! `no-unsafe` rule still scans every tracked `.rs` file regardless of workspace
//! boundaries, so every declaration below that needs the keyword carries the escape hatch
//! on that same line.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use irontraffic_conn::proxyproto::ProxyHeader;
use libfuzzer_sys::fuzz_target;

/// Every allocation and every deallocation made through the process's global allocator
/// while this counter is installed, forwarding the real work to `System` unchanged. A
/// single running total (not separate alloc/dealloc counters) is enough: the contract
/// under test is "no allocator activity at all", and a realloc-via-dealloc-then-alloc
/// pair would still move this counter, which is exactly what should fail the assertion.
static ALLOC_ACTIVITY: AtomicUsize = AtomicUsize::new(0);

/// A pass-through to `std::alloc::System` that additionally counts every call.
/// `Ordering::Relaxed` throughout: libFuzzer drives one input per call on a single thread,
/// so there is no cross-thread visibility requirement here, only a plain counter read back
/// on the same thread that incremented it.
struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc { // it-allow: no-unsafe reason: counting allocator in a fuzz-only crate
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 { // it-allow: no-unsafe reason: counting allocator in a fuzz-only crate
        ALLOC_ACTIVITY.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { // it-allow: no-unsafe reason: counting allocator in a fuzz-only crate
        ALLOC_ACTIVITY.fetch_add(1, Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 { // it-allow: no-unsafe reason: counting allocator in a fuzz-only crate
        ALLOC_ACTIVITY.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

/// A valid, minimal v1 `TCP4` header: `PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n`, 32 bytes.
const V1_TEMPLATE: &[u8] = b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n";

/// A valid v2 header: the 12 byte signature, a `PROXY`/IPv4 version-command and
/// family-protocol byte, a declared length of 12, and a 12 byte IPv4 address block. 28
/// bytes, no TLVs.
const V2_TEMPLATE: &[u8] = &[
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00,
    0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2,
];

/// Builds a mutation of `V1_TEMPLATE` or `V2_TEMPLATE`, chosen and driven entirely by `data`,
/// so libFuzzer's coverage guided search over `data` reliably drives both `v1::parse` and
/// `v2::parse`, including their TLV and address decoding interiors, rather than only ever
/// tripping `ProxyHeader::parse`'s own dispatch in `mod.rs`.
///
/// `data`'s first byte selects the template (even means v1, odd means v2) and every
/// following pair of bytes overwrites one byte of the chosen template's copy: the first byte
/// of the pair picks the position (modulo the template's length) and the second supplies the
/// replacement value. A single stray byte at the very end with no partner is ignored, the
/// same convention `fuzz_budget_events.rs` already uses in this same crate for pairing up
/// fuzzer bytes. `None` only for empty `data`, so the raw pass above still covers `b""` on
/// its own.
fn mutated_from_template(data: &[u8]) -> Option<Vec<u8>> {
    let (&selector, rest) = data.split_first()?;
    let mut buf = if selector % 2 == 0 {
        V1_TEMPLATE.to_vec()
    } else {
        V2_TEMPLATE.to_vec()
    };
    let len = buf.len();
    for pair in rest.chunks_exact(2) {
        if let &[pos_byte, value] = pair {
            if let Some(slot) = buf.get_mut(usize::from(pos_byte) % len) {
                *slot = value;
            }
        }
    }
    Some(buf)
}

/// Calls `ProxyHeader::parse(buf)` and asserts the whole contract: zero allocator activity,
/// and, on `Complete`, that `consumed` never exceeds `buf.len()` and that the returned
/// value's own `consumed` field agrees with it. Shared by both the raw `data` pass and the
/// template mutation pass below so the two calls are checked identically.
fn assert_bounded_parse(buf: &[u8]) {
    let before = ALLOC_ACTIVITY.load(Ordering::Relaxed);
    let result = ProxyHeader::parse(buf);
    let after = ALLOC_ACTIVITY.load(Ordering::Relaxed);
    assert_eq!(
        after, before,
        "ProxyHeader::parse touched the allocator for a {}-byte input, which must never \
         happen regardless of what any v2 length field declares",
        buf.len()
    );

    // `ParseStatus::into_complete` is an inherent method, so this crate never has to name
    // `ParseStatus` itself (it lives in `irontraffic_http`, which this fuzz-only crate does
    // not otherwise depend on) to pattern match on `Complete` versus `Partial`.
    if let Ok(status) = result {
        if let Some((value, consumed)) = status.into_complete() {
            assert!(
                consumed <= buf.len(),
                "consumed must never exceed the input length"
            );
            assert_eq!(
                value.consumed, consumed,
                "ProxyHeader::consumed must equal the enclosing Complete's consumed"
            );
        }
    }
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let original = data.to_vec();

    assert_bounded_parse(data);
    assert_eq!(
        data,
        original.as_slice(),
        "ProxyHeader::parse must never mutate its input buffer"
    );

    // Drive v1::parse and v2::parse directly: see the module doc comment above for why the
    // raw pass on `data` alone essentially never reaches either of them on its own.
    if let Some(mutated) = mutated_from_template(data) {
        assert_bounded_parse(&mutated);
    }
});
