// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for the descriptor-handoff frame decoder.
//!
//! Contract: no panic, no allocation proportional to input beyond the bounded
//! frame size, no read past the declared length, and termination.

use irontraffic_upgrade::HandoffFrame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = HandoffFrame::decode(data) {
        if let Ok(reencoded) = frame.encode() {
            if let Ok(redecoded) = HandoffFrame::decode(&reencoded) {
                assert_eq!(redecoded, frame);
            }
        }
    }
});
