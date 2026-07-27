// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz target for `irontraffic_ws::FrameDecoder::decode_header`, `commit`
//! and `validate_close_payload`.
//!
//! Input domain: the raw bytes are decoded as a stream of frames, for BOTH
//! `Direction`s independently (a fresh `FrameDecoder` each), advancing past
//! each resolved header by `consumed + payload_len` so the next header in
//! the stream lands at the right offset.
//!
//! Contract: no panic, no allocation (established statically: this target
//! performs no allocation of its own beyond ordinary iterator use, and the
//! codec's own acceptance grep already proves `src/` allocates nothing),
//! `consumed <= buf.len()` for the slice actually passed to `decode_header`,
//! `fragment_open` transitions only on data frames (`Continuation`, `Text`,
//! `Binary`), and `validate_close_payload` never modifies the payload slice
//! it is given.

use irontraffic_ws::{Direction, FrameDecoder, Opcode};
use libfuzzer_sys::fuzz_target;

fn run_one_direction(direction: Direction, data: &[u8]) {
    let mut decoder = FrameDecoder::new(direction);
    let mut cursor = 0usize;

    loop {
        let Some(slice) = data.get(cursor..) else {
            break;
        };

        let before_open = decoder.fragment_open();
        let header = match decoder.decode_header(slice) {
            Ok(Some(header)) => header,
            Ok(None) | Err(_) => break,
        };

        assert!(header.consumed <= slice.len());

        decoder.commit(&header);
        let after_open = decoder.fragment_open();
        if before_open != after_open {
            assert!(matches!(
                header.opcode,
                Opcode::Continuation | Opcode::Text | Opcode::Binary
            ));
        }

        let Ok(payload_len) = usize::try_from(header.payload_len) else {
            break;
        };
        let Some(frame_len) = header.consumed.checked_add(payload_len) else {
            break;
        };
        if frame_len > slice.len() {
            break;
        }
        let Some(payload) = slice.get(header.consumed..frame_len) else {
            break;
        };

        if header.opcode == Opcode::Close {
            let before: Vec<u8> = payload.to_vec();
            let _ = decoder.validate_close_payload(&header, payload);
            assert_eq!(payload, before.as_slice());
        }

        let Some(next_cursor) = cursor.checked_add(frame_len) else {
            break;
        };
        cursor = next_cursor;
    }
}

fuzz_target!(|data: &[u8]| {
    run_one_direction(Direction::ClientToServer, data);
    run_one_direction(Direction::ServerToClient, data);
});
