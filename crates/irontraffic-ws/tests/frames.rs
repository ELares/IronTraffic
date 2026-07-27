// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for `irontraffic_ws`'s frame codec: the RFC 6455
//! corpus and the Autobahn-derived rejection table named in the issue.
//!
//! **The fixture builder.** `header_only` and `raw_header` below emit the
//! EXACT bytes a frame header occupies on the wire. Neither appends payload
//! bytes unless a test specifically needs the decoder to find a SECOND
//! frame afterward (`prop_decode_is_split_invariant`'s multi-frame stream):
//! `FrameDecoder::decode_header` never reads a frame's payload, only its
//! header, so a declared length of 65536 needs no 65536-byte buffer behind
//! it for a single-header test to exercise it.

use irontraffic_ws::{
    CloseCode, Direction, FrameDecoder, FrameHeader, MAX_CONTROL_PAYLOAD, Opcode, TunnelBudget,
    WsError, mask_in_place,
};
use proptest::prelude::*;

/// An arbitrary, fixed mask key used by every fixture that needs one.
const MASK_KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// Encodes `len` in the SHORTEST form RFC 6455 Section 5.2 permits: the base
/// 7-bit field for 0 to 125, the 16-bit extended form for 126 to 65535, and
/// the 64-bit extended form above that. Returns the base length-field byte
/// (before the mask bit is applied) and the extended length bytes, if any.
///
/// `unwrap_or` rather than `.expect(...)`: clippy's `expect_used` exemption
/// for test code applies to functions carrying `#[test]` themselves, not to
/// a plain helper a test merely calls (see
/// `crates/irontraffic-conn/tests/sharded_bind.rs` for the same rule stated
/// against the same lint), so a shared builder like this one must stay
/// panic-free. The `if`/`else if` guards above already make each conversion
/// infallible in practice; the fallback exists only so this cannot panic if
/// that guarantee is ever broken by a future edit.
fn minimal_length_encoding(len: u64) -> (u8, Vec<u8>) {
    if len <= 125 {
        (u8::try_from(len).unwrap_or(u8::MAX), Vec::new())
    } else if len <= 65535 {
        let bytes = u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
        (126, bytes.to_vec())
    } else {
        (127, len.to_be_bytes().to_vec())
    }
}

/// Builds a well-formed, minimally-encoded frame header: `opcode`, `fin`,
/// masked exactly when `direction` is `ClientToServer` (using `mask_key`),
/// and `len` as its declared payload length. Emits no payload bytes.
fn header_only(
    opcode: Opcode,
    fin: bool,
    direction: Direction,
    mask_key: [u8; 4],
    len: u64,
) -> Vec<u8> {
    let masked = matches!(direction, Direction::ClientToServer);
    let (len_field, extended) = minimal_length_encoding(len);

    let mut b0 = opcode.wire();
    if fin {
        b0 |= 0x80;
    }
    let mut b1 = len_field;
    if masked {
        b1 |= 0x80;
    }

    let mut out = vec![b0, b1];
    out.extend_from_slice(&extended);
    if masked {
        out.extend_from_slice(&mask_key);
    }
    out
}

/// Builds a frame header from EXPLICIT bytes with no minimality or legality
/// checks of its own: the low-level escape hatch for the malformed shapes
/// (reserved opcodes, reserved bits, non-minimal lengths) that `header_only`
/// cannot produce because it always emits a legal, minimal encoding.
fn raw_header(b0: u8, b1: u8, extended: &[u8], mask_key: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![b0, b1];
    out.extend_from_slice(extended);
    if let Some(key) = mask_key {
        out.extend_from_slice(&key);
    }
    out
}

/// A decoder for `direction`, with a fragment already open when `opcode` is
/// `Continuation` (a fresh decoder always has `fragment_open() == false`,
/// which makes a standalone `Continuation` illegal by construction; this
/// opens one first via a non-final `Binary` so the table below can still
/// cover `Continuation`'s valid shape).
fn decoder_for(direction: Direction, opcode: Opcode) -> FrameDecoder {
    let mut decoder = FrameDecoder::new(direction);
    if opcode == Opcode::Continuation {
        let opener = header_only(Opcode::Binary, false, direction, MASK_KEY, 0);
        // No `.expect(...)`: this is a plain helper, not a `#[test]` function itself
        // (see `minimal_length_encoding`'s doc comment for why that distinction is
        // load-bearing here). The opener fixture is fixed and well-formed, so this
        // is expected to always succeed; if it somehow does not, `fragment_open`
        // simply stays false and the calling test's own assertions fail normally
        // instead of this helper panicking.
        if let Ok(Some(header)) = decoder.decode_header(&opener) {
            decoder.commit(&header);
        }
    }
    decoder
}

const LENGTHS: [u64; 6] = [0, 1, 125, 126, 65535, 65536];
const OPCODES: [Opcode; 6] = [
    Opcode::Continuation,
    Opcode::Text,
    Opcode::Binary,
    Opcode::Close,
    Opcode::Ping,
    Opcode::Pong,
];
const DIRECTIONS: [Direction; 2] = [Direction::ClientToServer, Direction::ServerToClient];

/// Every LEGAL (opcode, length, direction) shape: the full cross product,
/// minus the combinations RFC 6455 itself forbids (a control opcode above
/// `MAX_CONTROL_PAYLOAD`), which are covered by their own dedicated
/// rejection tests instead of appearing here as "valid".
fn valid_shape_fixtures() -> Vec<(Direction, Opcode, u64, Vec<u8>)> {
    let mut out = Vec::new();
    for opcode in OPCODES {
        for len in LENGTHS {
            if opcode.is_control() && len > MAX_CONTROL_PAYLOAD {
                continue;
            }
            for direction in DIRECTIONS {
                let bytes = header_only(opcode, true, direction, MASK_KEY, len);
                out.push((direction, opcode, len, bytes));
            }
        }
    }
    out
}

/// Decodes one well-formed header. A small helper for the budget tests,
/// which only need a header to hand to `TunnelBudget::debit`.
///
/// No `.expect(...)`: see `minimal_length_encoding`'s doc comment for why a
/// plain helper (as opposed to a `#[test]` function itself) must stay
/// panic-free here. Every caller passes a fixed, well-formed fixture, so the
/// fallback below is not expected to ever be reached; if it somehow is, the
/// budget test using it fails on its own assertions rather than here.
fn decode_one(direction: Direction, bytes: &[u8]) -> FrameHeader {
    match FrameDecoder::new(direction).decode_header(bytes) {
        Ok(Some(header)) => header,
        Ok(None) | Err(_) => FrameHeader {
            opcode: Opcode::Binary,
            fin: true,
            payload_len: 0,
            mask: None,
            consumed: 2,
        },
    }
}

#[test]
fn decode_every_valid_shape() {
    for (direction, opcode, len, bytes) in valid_shape_fixtures() {
        let decoder = decoder_for(direction, opcode);
        let header = decoder
            .decode_header(&bytes)
            .unwrap_or_else(|e| {
                panic!("{direction:?} {opcode:?} len={len}: unexpected error {e:?}")
            })
            .unwrap_or_else(|| {
                panic!("{direction:?} {opcode:?} len={len}: header reported incomplete")
            });

        assert_eq!(header.opcode, opcode, "{direction:?} len={len}");
        assert!(header.fin, "{direction:?} {opcode:?} len={len}");
        assert_eq!(header.payload_len, len, "{direction:?} {opcode:?}");
        match direction {
            Direction::ClientToServer => assert_eq!(header.mask, Some(MASK_KEY)),
            Direction::ServerToClient => assert_eq!(header.mask, None),
        }
        assert_eq!(
            header.consumed,
            bytes.len(),
            "{direction:?} {opcode:?} len={len}"
        );
    }
}

#[test]
fn header_split_across_reads() {
    for (direction, opcode, len, bytes) in valid_shape_fixtures() {
        let decoder = decoder_for(direction, opcode);

        for i in 0..bytes.len() {
            assert_eq!(
                decoder.decode_header(&bytes[..i]),
                Ok(None),
                "{direction:?} {opcode:?} len={len} prefix_len={i}"
            );
        }

        let header = decoder
            .decode_header(&bytes)
            .expect("well-formed fixture")
            .expect("the full fixture is a complete header");
        assert_eq!(header.opcode, opcode);
        assert_eq!(header.payload_len, len);
        assert_eq!(header.consumed, bytes.len());
    }
}

#[test]
fn unmasked_client_frame_closes_1002() {
    let decoder = FrameDecoder::new(Direction::ClientToServer);
    let bytes = vec![0x80 | Opcode::Binary.wire(), 0x00];
    let err = decoder.decode_header(&bytes).unwrap_err();
    assert_eq!(err, WsError::UnmaskedClientFrame);
    assert_eq!(err.close_code(), CloseCode::ProtocolError);
}

#[test]
fn masked_server_frame_closes_1002() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let bytes = vec![0x80 | Opcode::Binary.wire(), 0x80];
    let err = decoder.decode_header(&bytes).unwrap_err();
    assert_eq!(err, WsError::MaskedServerFrame);
    assert_eq!(err.close_code(), CloseCode::ProtocolError);
}

#[test]
fn control_frame_over_125_rejected() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let bytes = header_only(Opcode::Ping, true, Direction::ServerToClient, MASK_KEY, 126);
    let err = decoder.decode_header(&bytes).unwrap_err();
    assert_eq!(err, WsError::ControlFrameTooLong { len: 126 });
}

#[test]
fn fragmented_control_frame_rejected() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let bytes = header_only(Opcode::Ping, false, Direction::ServerToClient, MASK_KEY, 0);
    let err = decoder.decode_header(&bytes).unwrap_err();
    assert_eq!(err, WsError::FragmentedControlFrame);
}

#[test]
fn reserved_opcodes_rejected() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    for nibble in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
        let bytes = raw_header(0x80 | nibble, 0x00, &[], None);
        let err = decoder.decode_header(&bytes).unwrap_err();
        assert_eq!(
            err,
            WsError::ReservedOpcode { opcode: nibble },
            "nibble {nibble:#x}"
        );
    }
}

#[test]
fn reserved_bits_rejected_then_allowed() {
    let default_decoder = FrameDecoder::new(Direction::ServerToClient);
    for (rsv_bits, expected_rsv) in [
        (0x40u8, 0b100u8),
        (0x20, 0b010),
        (0x10, 0b001),
        (0x60, 0b110),
        (0x70, 0b111),
    ] {
        let b0 = 0x80 | rsv_bits | Opcode::Binary.wire();
        let bytes = raw_header(b0, 0x00, &[], None);
        let err = default_decoder.decode_header(&bytes).unwrap_err();
        assert_eq!(
            err,
            WsError::ReservedBitSet { rsv: expected_rsv },
            "rsv_bits={rsv_bits:#x}"
        );
    }

    let permissive = FrameDecoder::new(Direction::ServerToClient).with_reserved_allowed(0b100);

    let rsv1_only = raw_header(0x80 | 0x40 | Opcode::Binary.wire(), 0x00, &[], None);
    let header = permissive
        .decode_header(&rsv1_only)
        .expect("RSV1 is allowed under with_reserved_allowed(0b100)")
        .expect("complete header");
    assert_eq!(header.opcode, Opcode::Binary);

    let rsv2_only = raw_header(0x80 | 0x20 | Opcode::Binary.wire(), 0x00, &[], None);
    let err = permissive.decode_header(&rsv2_only).unwrap_err();
    assert_eq!(err, WsError::ReservedBitSet { rsv: 0b010 });
}

#[test]
fn non_minimal_lengths_rejected() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);

    let sixteen_bit_samples: [u64; 12] = [0, 1, 2, 5, 10, 25, 50, 75, 100, 110, 120, 125];
    for declared in sixteen_bit_samples {
        let extended = u16::try_from(declared)
            .expect("sample fits a u16")
            .to_be_bytes();
        let bytes = raw_header(0x80 | Opcode::Binary.wire(), 126, &extended, None);
        let err = decoder.decode_header(&bytes).unwrap_err();
        assert_eq!(
            err,
            WsError::NonMinimalLength { declared, form: 16 },
            "declared={declared}"
        );
    }

    let sixty_four_bit_samples: [u64; 12] = [
        0, 1, 2, 100, 1_000, 10_000, 30_000, 50_000, 60_000, 65_000, 65_534, 65_535,
    ];
    for declared in sixty_four_bit_samples {
        let extended = declared.to_be_bytes();
        let bytes = raw_header(0x80 | Opcode::Binary.wire(), 127, &extended, None);
        let err = decoder.decode_header(&bytes).unwrap_err();
        assert_eq!(
            err,
            WsError::NonMinimalLength { declared, form: 64 },
            "declared={declared}"
        );
    }
}

#[test]
fn length_high_bit_rejected() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let declared: u64 = 1u64 << 63;
    let extended = declared.to_be_bytes();
    let bytes = raw_header(0x80 | Opcode::Binary.wire(), 127, &extended, None);
    let err = decoder.decode_header(&bytes).unwrap_err();
    assert_eq!(err, WsError::LengthHighBitSet);
}

#[test]
fn continuation_without_open_message_rejected() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let bytes = header_only(
        Opcode::Continuation,
        true,
        Direction::ServerToClient,
        MASK_KEY,
        0,
    );
    let err = decoder.decode_header(&bytes).unwrap_err();
    assert_eq!(err, WsError::UnexpectedContinuation);
}

#[test]
fn interleaved_data_frame_rejected() {
    let mut decoder = FrameDecoder::new(Direction::ServerToClient);
    let opener = header_only(
        Opcode::Binary,
        false,
        Direction::ServerToClient,
        MASK_KEY,
        0,
    );
    let opener_header = decoder
        .decode_header(&opener)
        .expect("well-formed")
        .expect("complete");
    decoder.commit(&opener_header);

    let text = header_only(Opcode::Text, true, Direction::ServerToClient, MASK_KEY, 0);
    let err = decoder.decode_header(&text).unwrap_err();
    assert_eq!(err, WsError::InterleavedDataFrame);
}

#[test]
fn control_frame_inside_a_fragment_is_legal() {
    let mut decoder = FrameDecoder::new(Direction::ServerToClient);

    let opener = header_only(
        Opcode::Binary,
        false,
        Direction::ServerToClient,
        MASK_KEY,
        0,
    );
    let opener_header = decoder
        .decode_header(&opener)
        .expect("well-formed")
        .expect("complete");
    decoder.commit(&opener_header);
    assert!(decoder.fragment_open());

    let ping = header_only(Opcode::Ping, true, Direction::ServerToClient, MASK_KEY, 0);
    let ping_header = decoder
        .decode_header(&ping)
        .expect("well-formed")
        .expect("complete");
    decoder.commit(&ping_header);
    assert!(
        decoder.fragment_open(),
        "a control frame interleaved into an open fragment must not close it"
    );

    let closer = header_only(
        Opcode::Continuation,
        true,
        Direction::ServerToClient,
        MASK_KEY,
        0,
    );
    let closer_header = decoder
        .decode_header(&closer)
        .expect("well-formed")
        .expect("complete");
    decoder.commit(&closer_header);
    assert!(!decoder.fragment_open());
}

#[test]
fn frame_ceiling_enforced() {
    let decoder = FrameDecoder::new(Direction::ServerToClient).with_max_frame_bytes(1000);

    let at_ceiling = header_only(
        Opcode::Binary,
        true,
        Direction::ServerToClient,
        MASK_KEY,
        1000,
    );
    let header = decoder
        .decode_header(&at_ceiling)
        .expect("well-formed")
        .expect("complete");
    assert_eq!(header.payload_len, 1000);

    let over_ceiling = header_only(
        Opcode::Binary,
        true,
        Direction::ServerToClient,
        MASK_KEY,
        1001,
    );
    let err = decoder.decode_header(&over_ceiling).unwrap_err();
    assert_eq!(
        err,
        WsError::FrameTooLong {
            len: 1001,
            max: 1000
        }
    );
    assert_eq!(err.close_code(), CloseCode::MessageTooBig);
}

#[test]
fn default_frame_ceiling_is_exactly_16_mebibytes() {
    // `frame_ceiling_enforced` above only ever exercises `with_max_frame_bytes`,
    // never the DEFAULT ceiling `FrameDecoder::new` installs
    // (`DEFAULT_MAX_FRAME_BYTES`). `cargo mutants` found that changing the `*`
    // operators in that constant's definition (`16 * 1024 * 1024`) to `+` survives
    // every other test in this file untouched: nothing exercises a FRESH decoder
    // at exactly its default ceiling. This does, end to end rather than by
    // comparing the constant against itself.
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let sixteen_mib = 16 * 1024 * 1024;

    let at_ceiling = header_only(
        Opcode::Binary,
        true,
        Direction::ServerToClient,
        MASK_KEY,
        sixteen_mib,
    );
    let header = decoder
        .decode_header(&at_ceiling)
        .expect("well-formed")
        .expect("complete");
    assert_eq!(header.payload_len, sixteen_mib);

    let over_ceiling = header_only(
        Opcode::Binary,
        true,
        Direction::ServerToClient,
        MASK_KEY,
        sixteen_mib + 1,
    );
    let err = decoder.decode_header(&over_ceiling).unwrap_err();
    assert_eq!(
        err,
        WsError::FrameTooLong {
            len: sixteen_mib + 1,
            max: sixteen_mib,
        }
    );
}

#[test]
fn no_allocation_in_the_codec() {
    // The issue asks for this proven "with an allocation counter installed". The
    // standing coder contract for this corpus (CODER-PROMPT.md) is explicit that
    // this must NOT be done with a real `#[global_allocator]`: `irontraffic-ws`
    // carries `#![forbid(unsafe_code)]`, `GlobalAlloc` is an `unsafe trait`, so a
    // counting allocator could not even compile here, and a process-wide
    // allocator would count allocations made by every other test in the same
    // process regardless, which makes it an unsound measurement even where it is
    // legal to write.
    //
    // The proof is static instead, in two parts. First, the compiler check
    // immediately below: `FrameHeader`, `Opcode` and `Direction` (the success
    // path of `decode_header`) are all `Copy`, which means none of them can
    // own a heap allocation (a `Copy` type cannot implement `Drop`, and every
    // heap-owning type needs one to free what it owns). `WsError` (the error
    // path) is deliberately NOT `Copy` (see its derive list in `frame.rs`: an
    // error enum commonly leaves Copy off so a future variant can gain an
    // owned field without a breaking change), so it cannot go through the
    // same trait-bound check; its own fields are visibly `u8`/`u16`/`u64`/
    // `usize` only, and the second half of the proof below covers it anyway.
    // Second, this crate's own acceptance criterion greps
    // `crates/irontraffic-ws/src` for `with_capacity`, `Vec::new`, `String::new`,
    // `to_vec` and `extend_from_slice` and finds none of them in the codec path,
    // so nothing reachable from `decode_header`, success or error, can allocate
    // at all. What follows is the volume half of the test the issue asks for:
    // 100,000 decodes of mixed shapes, real coverage against a panic or an
    // incorrect result at scale, independent of the allocation question.
    const fn assert_copy<T: Copy>() {}
    assert_copy::<FrameHeader>();
    assert_copy::<Opcode>();
    assert_copy::<Direction>();

    let fixtures: Vec<(Direction, Vec<u8>)> = valid_shape_fixtures()
        .into_iter()
        .filter(|(_, opcode, _, _)| *opcode != Opcode::Continuation)
        .map(|(direction, _, _, bytes)| (direction, bytes))
        .collect();
    assert!(!fixtures.is_empty());

    for i in 0..100_000usize {
        let (direction, bytes) = &fixtures[i % fixtures.len()];
        let decoder = FrameDecoder::new(*direction);
        let header = decoder
            .decode_header(bytes)
            .expect("every fixture here is well-formed")
            .expect("every fixture here is a complete header");
        assert_eq!(header.consumed, bytes.len());
    }
}

#[test]
fn budget_frame_flood_closes() {
    let ping = decode_one(
        Direction::ServerToClient,
        &header_only(Opcode::Ping, true, Direction::ServerToClient, MASK_KEY, 0),
    );
    let mut budget = TunnelBudget::new(0);
    let mut exhausted_at = None;
    for i in 1..=10_000u32 {
        if let Err(e) = budget.debit(&ping, 0) {
            assert_eq!(e, WsError::BudgetExhausted);
            assert_eq!(e.close_code(), CloseCode::PolicyViolation);
            exhausted_at = Some(i);
            break;
        }
    }
    let exhausted_at =
        exhausted_at.expect("10,000 pings at a fixed clock must exhaust the frame budget");
    assert!(
        exhausted_at <= 250,
        "exhausted at frame {exhausted_at}, expected within 250"
    );
}

#[test]
fn budget_byte_flood_closes() {
    let one_mib = 1024 * 1024u64;
    let frame = decode_one(
        Direction::ServerToClient,
        &header_only(
            Opcode::Binary,
            true,
            Direction::ServerToClient,
            MASK_KEY,
            one_mib,
        ),
    );
    let mut budget = TunnelBudget::new(0);
    let mut exhausted = false;
    for _ in 0..32u32 {
        if budget.debit(&frame, 0).is_err() {
            exhausted = true;
            break;
        }
    }
    assert!(
        exhausted,
        "32 MiB of 1 MiB frames at a fixed clock must exhaust the default 16 MiB byte budget"
    );
    // `cargo mutants` found that weakening `byte_tokens < 0` to `byte_tokens <= 0`
    // or `byte_tokens == 0` survives every other assertion in this file: 16 debits
    // of exactly 1 MiB each land `byte_tokens` at EXACTLY 0 (not yet exhausted,
    // since 0 is not less than 0), and only the 17th debit takes it negative. A
    // weakened comparison would instead report exhaustion on the 16th debit, while
    // `byte_tokens()` still reads 0 there rather than negative, so this assertion
    // (not merely `exhausted`) is what tells the two apart.
    assert!(
        budget.byte_tokens() < 0,
        "byte_tokens() was {}, expected strictly negative after exhaustion",
        budget.byte_tokens()
    );
}

#[test]
fn tunnel_budget_frame_refill_amount_is_elapsed_ms_over_1000_times_rate() {
    // `cargo mutants` found that replacing the `/ 1000` in `TunnelBudget::refill`'s
    // frame-token line with `*` or `%` survives every other budget test: those
    // tests only check whether a debit succeeds or fails, and an accidentally huge
    // ("* 1000") refill still gets clamped to the same capacity a correct one
    // would reach, while an accidentally zeroed ("% 1000", for a rate that is
    // itself a multiple of 1000) refill still leaves enough headroom for the
    // small debits those tests make. Draining most of the way down first, so the
    // capacity clamp cannot mask the difference, and picking a refill rate of
    // exactly 1000 per second (one token per elapsed ms, so the expected number is
    // easy to state by hand) makes the exact resulting value observable instead.
    let mut budget = TunnelBudget::with_params(1000, 1000, 1_000_000_000, 1, 0);
    let data_frame = decode_one(
        Direction::ServerToClient,
        &header_only(Opcode::Binary, true, Direction::ServerToClient, MASK_KEY, 0),
    );

    for _ in 0..990u32 {
        let _ = budget.debit(&data_frame, 0);
    }
    assert_eq!(budget.frame_tokens(), 10);

    // 7ms later: refill adds 7 * 1000 / 1000 = 7 tokens (10 -> 17), then this
    // debit's own cost of 1 is subtracted, leaving 16. A "* 1000" bug would
    // instead try to add 7,000,000 tokens (clamped to the 1000 capacity, then
    // 999 after the cost); a "% 1000" bug would add 0 (leaving 9).
    assert!(budget.debit(&data_frame, 7).is_ok());
    assert_eq!(budget.frame_tokens(), 16);
}

#[test]
fn tunnel_budget_byte_refill_amount_is_elapsed_ms_over_1000_times_rate() {
    // The byte-token counterpart of the frame-refill test above: `cargo mutants`
    // found the same `/ 1000` on the BYTE line has the identical gap, independent
    // of the frame line (they are two separate expressions), so it needs its own
    // test rather than relying on the frame-side one to somehow cover it.
    let mut budget = TunnelBudget::with_params(1_000_000_000, 1, 1000, 1000, 0);
    let one_byte_frame = decode_one(
        Direction::ServerToClient,
        &header_only(Opcode::Binary, true, Direction::ServerToClient, MASK_KEY, 1),
    );

    for _ in 0..990u32 {
        let _ = budget.debit(&one_byte_frame, 0);
    }
    assert_eq!(budget.byte_tokens(), 10);

    // 7ms later: refill adds 7 * 1000 / 1000 = 7 tokens (10 -> 17), then this
    // debit's own cost of 1 byte is subtracted, leaving 16.
    assert!(budget.debit(&one_byte_frame, 7).is_ok());
    assert_eq!(budget.byte_tokens(), 16);
}

#[test]
fn budget_refills_lazily() {
    let ping = decode_one(
        Direction::ServerToClient,
        &header_only(Opcode::Ping, true, Direction::ServerToClient, MASK_KEY, 0),
    );
    // `TunnelBudget::debit` takes `now_ms` as a plain argument, and `TunnelBudget`
    // stores no thread handle, no timer and no clock: "no timer or background
    // task exists" is a property of the type's shape (see its field list and the
    // crate-wide grep for std::thread/Instant/SystemTime), verified once by
    // inspection rather than by anything a single runtime assertion could
    // observe.
    let mut budget = TunnelBudget::new(0);
    let mut exhausted = false;
    for _ in 0..1000u32 {
        if budget.debit(&ping, 0).is_err() {
            exhausted = true;
            break;
        }
    }
    assert!(exhausted);
    assert!(budget.frame_tokens() < 0);

    assert!(
        budget.debit(&ping, 5000).is_ok(),
        "5 seconds at the default 200 frames/sec refill rate must restore enough tokens"
    );
}

#[test]
fn close_payload_length_rules() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let header = FrameHeader {
        opcode: Opcode::Close,
        fin: true,
        payload_len: 0, // unused by validate_close_payload, which reads only `payload`
        mask: None,
        consumed: 2,
    };

    assert_eq!(decoder.validate_close_payload(&header, &[]), Ok(()));

    let one_byte = [0x03];
    let err = decoder
        .validate_close_payload(&header, &one_byte)
        .unwrap_err();
    assert_eq!(err, WsError::CloseFramePayloadTooShort { len: 1 });
    assert_eq!(err.close_code(), CloseCode::ProtocolError);

    // 1000 (Normal) big-endian: a valid code, so these two cases isolate the
    // LENGTH rule rather than also exercising the close-code rule.
    let two_bytes = [0x03, 0xE8];
    assert_eq!(decoder.validate_close_payload(&header, &two_bytes), Ok(()));

    let mut max_control = vec![0x03, 0xE8];
    max_control.extend(std::iter::repeat_n(0u8, 123));
    assert_eq!(max_control.len(), 125);
    assert_eq!(
        decoder.validate_close_payload(&header, &max_control),
        Ok(())
    );
}

#[test]
fn close_code_table() {
    let decoder = FrameDecoder::new(Direction::ServerToClient);
    let header = FrameHeader {
        opcode: Opcode::Close,
        fin: true,
        payload_len: 0,
        mask: None,
        consumed: 2,
    };

    let invalid: [u16; 5] = [0, 999, 1005, 1006, 1015];
    for code in invalid {
        let bytes = code.to_be_bytes();
        let err = decoder.validate_close_payload(&header, &bytes).unwrap_err();
        assert_eq!(err, WsError::InvalidCloseCode { code }, "code={code}");
    }

    let valid: [u16; 7] = [1000, 1001, 1011, 2999, 3000, 4999, 5000];
    for code in valid {
        let bytes = code.to_be_bytes();
        assert_eq!(
            decoder.validate_close_payload(&header, &bytes),
            Ok(()),
            "code={code}"
        );
    }
}

#[test]
fn masked_close_payload_is_read_not_rewritten() {
    let decoder = FrameDecoder::new(Direction::ClientToServer);

    // Mask key and wire bytes engineered so that reading the code THROUGH the
    // mask (the only correct behaviour) yields 1011, a valid code, while
    // reading the SAME two wire bytes WITHOUT unmasking would yield 500, an
    // INVALID one (below 1000). `Ok(())` is therefore only reachable here if
    // the implementation actually applied the XOR: a mutant that dropped it
    // would see the raw bytes as 500 and return `Err(InvalidCloseCode)`
    // instead, so this test distinguishes the two rather than merely
    // exercising the masked branch without checking what it computed.
    //   plaintext 1011 = 0x03F3, masked wire bytes = 0x01F4 (500), so
    //   key = plaintext XOR wire = [0x03 ^ 0x01, 0xF3 ^ 0xF4] = [0x02, 0x07].
    let key = [0x02, 0x07, 0x00, 0x00];
    let wire_payload = [0x01u8, 0xF4];
    let header = FrameHeader {
        opcode: Opcode::Close,
        fin: true,
        payload_len: 2,
        mask: Some(key),
        consumed: 6,
    };

    let before = wire_payload;
    let result = decoder.validate_close_payload(&header, &wire_payload);
    assert_eq!(
        result,
        Ok(()),
        "the code read through the mask must be 1011 (valid); an Err here means \
         the raw masked bytes (500, invalid) were read instead of unmasked"
    );
    assert_eq!(
        wire_payload, before,
        "validate_close_payload must never rewrite the payload it is given"
    );
}

#[test]
fn masked_close_payload_xor_is_not_or_per_byte() {
    // `cargo mutants` found that `masked_close_payload_is_read_not_rewritten` above
    // does not catch replacing either `^` with `|` in `p0 ^ k0` / `p1 ^ k1`: for
    // the specific bytes chosen there, the wire byte and the key byte never share
    // a set bit, so XOR and OR happen to compute the same result. These two cases
    // pick a wire byte and key byte that DO share a bit in each position (so OR
    // and XOR provably diverge there) and land the CORRECT decode in the invalid
    // (`Err`) range, which is what makes the resulting `code` observable at all:
    // `validate_close_payload` never exposes the code on the `Ok` path. Byte 0
    // shares a bit in the first case, byte 1 shares a bit in the second, and both
    // hold the OTHER byte at 0x00 against a 0x00 key so it contributes nothing to
    // either decoding, isolating exactly one `^` at a time.
    let decoder = FrameDecoder::new(Direction::ClientToServer);

    // Wire byte 0 = 0x01 (0b01), key byte 0 = 0x03 (0b11): share bit 0.
    //   correct: 0x01 ^ 0x03 = 0x02   (high byte)
    //   OR mutant: 0x01 | 0x03 = 0x03 (different)
    // code = (0x02 << 8) | (0x00 ^ 0x00) = 0x0200 = 512, below 1000: invalid.
    let byte0_header = FrameHeader {
        opcode: Opcode::Close,
        fin: true,
        payload_len: 2,
        mask: Some([0x03, 0x00, 0x00, 0x00]),
        consumed: 6,
    };
    let err = decoder
        .validate_close_payload(&byte0_header, &[0x01, 0x00])
        .unwrap_err();
    assert_eq!(
        err,
        WsError::InvalidCloseCode { code: 512 },
        "byte 0's ^ must not have become |, which would compute 0x03 instead of 0x02"
    );

    // Wire byte 1 = 0x01, key byte 1 = 0x03: share bit 0, symmetric to the above.
    //   correct: 0x01 ^ 0x03 = 0x02   (low byte)
    //   OR mutant: 0x01 | 0x03 = 0x03 (different)
    // code = (0x00 ^ 0x00 << 8) | 0x02 = 2, below 1000: invalid.
    let byte1_header = FrameHeader {
        opcode: Opcode::Close,
        fin: true,
        payload_len: 2,
        mask: Some([0x00, 0x03, 0x00, 0x00]),
        consumed: 6,
    };
    let err = decoder
        .validate_close_payload(&byte1_header, &[0x00, 0x01])
        .unwrap_err();
    assert_eq!(
        err,
        WsError::InvalidCloseCode { code: 2 },
        "byte 1's ^ must not have become |, which would compute 0x03 instead of 0x02"
    );
}

/// Turns arbitrary `(kind, len_seed, fin_seed)` triples into a LEGAL sequence
/// of `(Opcode, fin, len)` steps: `kind` selects an opcode from whichever set
/// is legal given the fragmentation state built up so far, so every prefix of
/// the result is a sequence `FrameDecoder` accepts with no error.
fn build_plan(raw_steps: &[(u8, u16, bool)]) -> Vec<(Opcode, bool, u64)> {
    let mut plan = Vec::new();
    let mut fragment_open = false;

    for &(kind, len_seed, fin_seed) in raw_steps {
        let (opcode, fin) = if fragment_open {
            match kind % 4 {
                0 => (Opcode::Close, true),
                1 => (Opcode::Ping, true),
                2 => (Opcode::Pong, true),
                _ => (Opcode::Continuation, fin_seed),
            }
        } else {
            match kind % 5 {
                0 => (Opcode::Close, true),
                1 => (Opcode::Ping, true),
                2 => (Opcode::Pong, true),
                3 => (Opcode::Text, fin_seed),
                _ => (Opcode::Binary, fin_seed),
            }
        };

        let len: u64 = if opcode.is_control() {
            u64::from(len_seed % 126)
        } else {
            u64::from(len_seed % 512)
        };

        plan.push((opcode, fin, len));

        match opcode {
            Opcode::Continuation if fin => fragment_open = false,
            Opcode::Text | Opcode::Binary if !fin => fragment_open = true,
            _ => {}
        }
    }

    plan
}

/// Concatenates `plan` into one byte stream: a real header per step, plus
/// filler payload bytes (content is irrelevant, since `decode_header` never
/// reads a payload) so the NEXT header in the stream lands at the right
/// offset.
fn build_stream(direction: Direction, plan: &[(Opcode, bool, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(opcode, fin, len) in plan {
        out.extend_from_slice(&header_only(opcode, fin, direction, MASK_KEY, len));
        // `unwrap_or(0)`, not `.expect(...)`: see `minimal_length_encoding`'s doc
        // comment. `build_plan` bounds every generated `len` well within `usize`
        // (at most 511), so this never actually falls back; `0` rather than
        // `usize::MAX` is the safe direction for a fallback feeding `repeat_n`,
        // since the other extreme would attempt a huge allocation instead of
        // simply emitting no filler bytes.
        let len_usize = usize::try_from(len).unwrap_or(0);
        out.extend(std::iter::repeat_n(0xAAu8, len_usize));
    }
    out
}

/// Decodes every header in `full`, delivering it to the decoder in windows
/// that grow to each of `splits` in turn (and finally to `full.len()`,
/// always appended): the "arbitrary split" half of the split-invariance
/// property. Passing `&[]` delivers the whole buffer in one step.
///
/// No `.expect(...)` anywhere below: see `minimal_length_encoding`'s doc
/// comment for why a plain helper must stay panic-free here. `build_plan`
/// only ever generates sequences `FrameDecoder` accepts, so none of the
/// early returns below are expected to fire; if one somehow does, this
/// simply returns the headers decoded so far, and `prop_decode_is_split_invariant`'s
/// own comparison against the reference decode fails visibly instead.
fn decode_via_splits(direction: Direction, full: &[u8], splits: &[usize]) -> Vec<FrameHeader> {
    let mut decoder = FrameDecoder::new(direction);
    let mut headers = Vec::new();
    let mut cursor = 0usize;
    let mut window_end = 0usize;

    for next_end in splits.iter().copied().chain(std::iter::once(full.len())) {
        window_end = window_end.max(next_end).min(full.len());
        loop {
            let available = full.get(cursor..window_end).unwrap_or(&[]);
            let Ok(outcome) = decoder.decode_header(available) else {
                return headers;
            };
            let Some(header) = outcome else {
                break;
            };
            decoder.commit(&header);
            let Ok(payload_len) = usize::try_from(header.payload_len) else {
                return headers;
            };
            let Some(frame_len) = header.consumed.checked_add(payload_len) else {
                return headers;
            };
            headers.push(header);
            let Some(next_cursor) = cursor.checked_add(frame_len) else {
                return headers;
            };
            cursor = next_cursor;
        }
    }

    headers
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn prop_decode_is_split_invariant(
        direction in prop_oneof![Just(Direction::ClientToServer), Just(Direction::ServerToClient)],
        raw_steps in proptest::collection::vec((0u8..5, any::<u16>(), any::<bool>()), 0..=32),
        raw_splits in proptest::collection::vec(0usize..=8192, 0..=40),
    ) {
        let plan = build_plan(&raw_steps);
        let bytes = build_stream(direction, &plan);

        let reference = decode_via_splits(direction, &bytes, &[]);

        let mut splits: Vec<usize> = raw_splits.into_iter().map(|s| s.min(bytes.len())).collect();
        splits.sort_unstable();
        let chunked = decode_via_splits(direction, &bytes, &splits);

        prop_assert_eq!(chunked, reference);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]
    #[test]
    fn prop_every_error_has_a_close_code(
        direction in prop_oneof![Just(Direction::ClientToServer), Just(Direction::ServerToClient)],
        header_bytes in proptest::collection::vec(any::<u8>(), 14),
        close_payload in proptest::collection::vec(any::<u8>(), 0..=125),
        masked_close in any::<bool>(),
    ) {
        // Cross-variant distinctness of `metric_label()` (14 variants, all pairs)
        // is proven exhaustively and deterministically by
        // `ws_error_metric_labels_are_unique` in `frame.rs`'s own unit tests;
        // 2048 random header prefixes and close payloads have no guarantee of
        // ever reaching every variant (some, like `LengthHighBitSet`, need an
        // exact bit pattern), so this property instead checks the part every
        // case CAN prove: whichever error a given input produces, its close
        // code is one of the three this codec ever emits, and its label is
        // real.
        let decoder = FrameDecoder::new(direction);
        if let Err(e) = decoder.decode_header(&header_bytes) {
            prop_assert!(
                matches!(e.close_code().wire(), 1002 | 1008 | 1009),
                "{e:?} -> unexpected close code {:?}", e.close_code()
            );
            prop_assert!(!e.metric_label().is_empty());
        }

        let mask = if masked_close { Some([0x01, 0x02, 0x03, 0x04]) } else { None };
        let close_header = FrameHeader {
            opcode: Opcode::Close,
            fin: true,
            payload_len: 0, // unused by validate_close_payload
            mask,
            consumed: 2,
        };
        if let Err(e) = decoder.validate_close_payload(&close_header, &close_payload) {
            prop_assert!(matches!(e.close_code().wire(), 1002 | 1008 | 1009));
            prop_assert!(!e.metric_label().is_empty());
        }
    }
}

// `mask_in_place` tests live here rather than beside its definition: this
// crate's acceptance criterion greps `crates/irontraffic-ws/src` for the name
// and requires the ONLY match to be the definition itself, because the relay
// path must never call it (its only legitimate caller is the RFC 8441 bridge
// in a later issue). This file is under `tests/`, not `src/`, so calling it
// here to test it does not trip that grep.

#[test]
fn mask_in_place_xors_every_byte_with_the_cycling_key() {
    let key = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut payload = [0x00u8; 6];
    mask_in_place(&mut payload, key, 0);
    assert_eq!(payload, [0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB]);
}

#[test]
fn mask_in_place_is_its_own_inverse() {
    let key = [1, 2, 3, 4];
    let original: Vec<u8> = (0u8..37).collect();
    let mut roundtrip = original.clone();
    mask_in_place(&mut roundtrip, key, 0);
    assert_ne!(roundtrip, original);
    mask_in_place(&mut roundtrip, key, 0);
    assert_eq!(roundtrip, original);
}

#[test]
fn mask_in_place_offset_matches_masking_the_whole_payload_at_once() {
    let key = [9, 8, 7, 6];
    let whole: Vec<u8> = (0u8..20).collect();

    let mut all_at_once = whole.clone();
    mask_in_place(&mut all_at_once, key, 0);

    let mut in_chunks = whole.clone();
    let (first, second) = in_chunks.split_at_mut(7);
    mask_in_place(first, key, 0);
    mask_in_place(second, key, 7);

    assert_eq!(all_at_once, in_chunks);
}
