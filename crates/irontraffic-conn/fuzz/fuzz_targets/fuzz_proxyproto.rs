#![no_main]

//! Fuzz target for `irontraffic_conn::proxyproto::ProxyHeader::parse`.
//!
//! Input domain: arbitrary bytes, passed to `parse` unmodified.
//!
//! Contract: no panic, no hang, and ZERO allocation for any input, including one that
//! declares a v2 length of 65535 with only a handful of bytes actually present (allocation
//! proportional to the DECLARED length rather than the RECEIVED length is exactly the
//! vulnerability this parser exists to avoid). Also asserts, on `Complete`, that
//! `consumed <= data.len()` and that `value.consumed == consumed`, and asserts on every
//! call that the input buffer is unchanged (this parser only ever borrows `data`; it is
//! `&[u8]`, never `&mut [u8]`, so this is also enforced by the type system, and the
//! assertion below is a second, independent proof for a fuzz report to point at directly).
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

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let original = data.to_vec();
    let before = ALLOC_ACTIVITY.load(Ordering::Relaxed);

    let result = ProxyHeader::parse(data);

    let after = ALLOC_ACTIVITY.load(Ordering::Relaxed);
    assert_eq!(
        after, before,
        "ProxyHeader::parse touched the allocator for a {}-byte input, which must never \
         happen regardless of what any v2 length field declares",
        data.len()
    );

    assert_eq!(
        data,
        original.as_slice(),
        "ProxyHeader::parse must never mutate its input buffer"
    );

    // `ParseStatus::into_complete` is an inherent method, so this crate never has to name
    // `ParseStatus` itself (it lives in `irontraffic_http`, which this fuzz-only crate does
    // not otherwise depend on) to pattern match on `Complete` versus `Partial`.
    if let Ok(status) = result {
        if let Some((value, consumed)) = status.into_complete() {
            assert!(
                consumed <= data.len(),
                "consumed must never exceed the input length"
            );
            assert_eq!(
                value.consumed, consumed,
                "ProxyHeader::consumed must equal the enclosing Complete's consumed"
            );
        }
    }
});
