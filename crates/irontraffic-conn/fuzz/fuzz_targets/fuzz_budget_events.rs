// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `ConnBudget::on_frame`.
//!
//! Input domain: `data` is consumed two bytes at a time. The first byte of
//! each pair selects one of the eleven `FrameEvent` variants (`% 11`); the
//! second byte is a `now_ms` delta added to a running millisecond counter
//! before the call, so the fuzzer can also explore repeated, advancing and
//! (via `wrapping_add`) wrapping timestamps. A trailing single byte with no
//! partner is ignored.
//!
//! Contract: must not panic, must not hang, and must not overflow (this
//! target builds with debug assertions and `overflow-checks = true`,
//! cargo-fuzz's default, so a wrapped computation is a panic and therefore a
//! finding). Asserts `tokens() <= capacity` after every call, the same
//! invariant `budget.rs`'s own `prop_budget_monotone` property test checks
//! for a proptest-generated sequence; this target explores the same
//! invariant against a much larger, corpus-guided input space.

use irontraffic_conn::{ConnBudget, FrameEvent};
use libfuzzer_sys::fuzz_target;

/// The capacity `ConnBudget::new` builds with by default.
const CAPACITY: i64 = 10_000;

fn event_from_index(index: u8) -> FrameEvent {
    match index % 11 {
        0 => FrameEvent::Ordinary,
        1 => FrameEvent::HeadersOpen,
        2 => FrameEvent::Continuation,
        3 => FrameEvent::EmptyDataNoEndStream,
        4 => FrameEvent::RstStreamReceived,
        5 => FrameEvent::RstStreamSent,
        6 => FrameEvent::Ping,
        7 => FrameEvent::Settings,
        8 => FrameEvent::SmallWindowUpdate,
        9 => FrameEvent::Priority,
        _ => FrameEvent::GoawayReceived,
    }
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let mut budget = ConnBudget::new(0);
    let mut now_ms = 0u32;

    for pair in data.chunks_exact(2) {
        if let &[event_byte, delta_byte] = pair {
            now_ms = now_ms.wrapping_add(u32::from(delta_byte));
            let _ = budget.on_frame(event_from_index(event_byte), now_ms);
            assert!(budget.tokens() <= CAPACITY);
        }
    }
});
