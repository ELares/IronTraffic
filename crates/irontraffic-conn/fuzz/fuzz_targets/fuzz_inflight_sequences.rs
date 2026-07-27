// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `InflightGauge` / `StreamSlot` admit, reset, settle and drop
//! sequences.
//!
//! Input domain: `data` is consumed one byte at a time, as an opcode over a fixed pool of
//! 16 slot handles. `byte % 16` selects the handle; `(byte / 16) % 4` selects the
//! operation: 0 admits into that handle if it is currently empty, 1 calls
//! `on_downstream_reset` on it if it currently holds a slot, 2 calls
//! `on_upstream_settled` on it under the same condition, and 3 drops it under the same
//! condition.
//!
//! Contract: no panic, no hang. Asserts `inflight() <= max` after every operation, and
//! that after the target drops every remaining held slot, `inflight() == 0`. A leaked
//! count is a finding.

use irontraffic_conn::inflight::{InflightGauge, StreamSlot};
use libfuzzer_sys::fuzz_target;

/// The admission limit used for this target. Small on purpose, so a corpus of 16 handles
/// can exhaust it and exercise `Refuse` alongside the successful paths.
const MAX: u32 = 8;

/// The fixed pool of slot handles the opcodes above address.
const POOL: usize = 16;

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let gauge = InflightGauge::new(MAX);
    let mut slots: [Option<StreamSlot>; POOL] = std::array::from_fn(|_| None);

    for &byte in data {
        let index = usize::from(byte % 16);
        let op = (byte / 16) % 4;
        match op {
            0 => {
                if let Some(free) = slots.get_mut(index) {
                    if free.is_none() {
                        if let Ok(slot) = gauge.admit() {
                            *free = Some(slot);
                        }
                    }
                }
            }
            1 => {
                if let Some(Some(slot)) = slots.get_mut(index) {
                    slot.on_downstream_reset();
                }
            }
            2 => {
                if let Some(Some(slot)) = slots.get_mut(index) {
                    slot.on_upstream_settled();
                }
            }
            _ => {
                if let Some(held) = slots.get_mut(index) {
                    held.take();
                }
            }
        }
        assert!(gauge.inflight() <= MAX, "inflight() must never exceed max");
    }

    for slot in &mut slots {
        slot.take();
    }
    assert_eq!(gauge.inflight(), 0, "every dropped slot must return the gauge to zero");
});
