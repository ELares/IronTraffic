// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the descriptor-handoff frame.

use irontraffic_upgrade::{
    CHECKSUM_BYTES, FrameError, HEADER_BYTES, HandoffEntry, HandoffFrame, MAX_ADDR_BYTES, MAX_FDS,
    MAX_FRAME_BYTES,
};

// A test that recomputes MAX_FRAME_BYTES from HEADER_BYTES, MAX_FDS, MAX_ADDR_BYTES
// and CHECKSUM_BYTES using the SAME formula the constant is defined by
// (`HEADER_BYTES + MAX_FDS * (4 + MAX_ADDR_BYTES) + CHECKSUM_BYTES`) proves
// nothing: both sides move together, so a `+` mutated to `-` or `*` in that
// formula changes what MAX_FRAME_BYTES computes to and this comparison still
// holds, vacuously, against the mutated value. Every other test in this file
// only ever compares AGAINST MAX_FRAME_BYTES (`encoded_len() <= MAX_FRAME_BYTES`),
// which has the identical problem: the bound moves with the mutation and the
// comparison never notices. Mutation testing confirmed this is not
// theoretical: all three `+` operators in the constant's definition can be
// changed to `*` (and the first and last can also become `-`, the other
// combinations failing to compile from `usize` underflow) with every other
// test in this suite still green. Pinning the literal value the issue's own
// Complexity section computes by hand, "12 + 253 * (4 + 64) + 8 = 17,224
// bytes", is the only check that does not move with the formula.
#[test]
fn max_frame_bytes_matches_the_documented_constants_and_formula() {
    assert_eq!(HEADER_BYTES, 12);
    assert_eq!(MAX_FDS, 253);
    assert_eq!(MAX_ADDR_BYTES, 64);
    assert_eq!(CHECKSUM_BYTES, 8);
    assert_eq!(MAX_FRAME_BYTES, 17_224);
}

#[test]
fn empty_frame_round_trips() {
    let frame = HandoffFrame::new(Vec::new()).expect("empty frame is legal");
    let encoded = frame.encode().expect("empty frame encodes");
    assert_eq!(encoded.len(), 20);
    let decoded = HandoffFrame::decode(&encoded).expect("empty frame decodes");
    assert_eq!(decoded, frame);
}

#[test]
fn single_entry_round_trips() {
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: "0.0.0.0:80".to_owned(),
        fd_index: 0,
    }])
    .expect("single entry frame is legal");
    let encoded = frame.encode().expect("single entry frame encodes");
    let decoded = HandoffFrame::decode(&encoded).expect("single entry frame decodes");
    assert_eq!(decoded, frame);
}

#[test]
fn max_fds_round_trips() {
    let entries: Vec<_> = (0..MAX_FDS)
        .map(|i| HandoffEntry {
            addr: "0.0.0.0:80".to_owned(),
            fd_index: u16::try_from(i).expect("i is below u16::MAX"),
        })
        .collect();
    let frame = HandoffFrame::new(entries).expect("MAX_FDS entries are legal");
    assert!(frame.encoded_len() <= MAX_FRAME_BYTES);
    let encoded = frame.encode().expect("MAX_FDS frame encodes");
    assert_eq!(encoded.len(), frame.encoded_len());
    let decoded = HandoffFrame::decode(&encoded).expect("MAX_FDS frame decodes");
    assert_eq!(decoded, frame);
}

#[test]
fn too_many_descriptors_at_encode_and_decode() {
    let entries: Vec<_> = (0..=MAX_FDS)
        .map(|i| HandoffEntry {
            addr: "0.0.0.0:80".to_owned(),
            fd_index: u16::try_from(i).expect("i is below u16::MAX"),
        })
        .collect();
    let err = HandoffFrame::new(entries).expect_err("MAX_FDS + 1 entries are rejected at encode");
    assert!(matches!(
        err,
        FrameError::TooManyDescriptors { count, max } if count == MAX_FDS + 1 && max == MAX_FDS
    ));

    // Build a frame with MAX_FDS + 1 entries by hand so decode is exercised.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(
        &u16::try_from(MAX_FDS + 1)
            .expect("fits in u16")
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&0u16.to_le_bytes());
    for _ in 0..=MAX_FDS {
        encoded.extend_from_slice(&1u16.to_le_bytes()); // addr_len
        encoded.extend_from_slice(&0u16.to_le_bytes()); // fd_index
        encoded.extend_from_slice(b"a");
    }
    encoded.extend_from_slice(&[0u8; 8]); // checksum placeholder
    let err =
        HandoffFrame::decode(&encoded).expect_err("MAX_FDS + 1 entries are rejected at decode");
    assert!(matches!(
        err,
        FrameError::TooManyDescriptors { count, max } if count == MAX_FDS + 1 && max == MAX_FDS
    ));
}

#[test]
fn address_length_boundaries() {
    let short = "a".to_owned();
    let max = "a".repeat(MAX_ADDR_BYTES);
    let too_long = "a".repeat(MAX_ADDR_BYTES + 1);

    let ok = HandoffFrame::new(vec![HandoffEntry {
        addr: short,
        fd_index: 0,
    }])
    .expect("length 1 address is legal");
    assert_eq!(ok.entries.len(), 1);

    let ok = HandoffFrame::new(vec![HandoffEntry {
        addr: max,
        fd_index: 0,
    }])
    .expect("MAX_ADDR_BYTES address is legal");
    assert_eq!(ok.entries.len(), 1);

    // The checks above only exercise HandoffFrame::new; they say nothing about the
    // decoder's OWN bound, which is a separate `if addr_len_usize == 0 ||
    // addr_len_usize > MAX_ADDR_BYTES` check in `validate_entries`. A decode-time
    // cap raised far above MAX_ADDR_BYTES (or removed) would still pass every
    // assertion above, because none of them ever calls `decode`. These hand-built
    // frames pin the decoder's bound directly, with the declared bytes actually
    // present so a too-loose cap is caught even when the input is otherwise
    // well-formed, not merely truncated.
    let encoded = ok.encode().expect("MAX_ADDR_BYTES address encodes");
    let decoded =
        HandoffFrame::decode(&encoded).expect("MAX_ADDR_BYTES address is accepted at decode");
    assert_eq!(decoded, ok);

    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes()); // version
    encoded.extend_from_slice(&0u16.to_le_bytes()); // flags
    encoded.extend_from_slice(&1u16.to_le_bytes()); // count
    encoded.extend_from_slice(&0u16.to_le_bytes()); // reserved
    let oversized_len = u16::try_from(MAX_ADDR_BYTES + 1).expect("fits in u16");
    encoded.extend_from_slice(&oversized_len.to_le_bytes()); // addr_len = MAX_ADDR_BYTES + 1
    encoded.extend_from_slice(&0u16.to_le_bytes()); // fd_index
    encoded.extend(vec![b'a'; MAX_ADDR_BYTES + 1]); // the declared bytes, actually present
    encoded.extend_from_slice(&[0u8; 8]); // checksum placeholder; rejected before the checksum check
    let err = HandoffFrame::decode(&encoded)
        .expect_err("MAX_ADDR_BYTES + 1 with the bytes present is rejected at decode");
    assert!(matches!(
        err,
        FrameError::BadAddressLength { entry: 0, len, max }
            if len == MAX_ADDR_BYTES + 1 && max == MAX_ADDR_BYTES
    ));

    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes()); // version
    encoded.extend_from_slice(&0u16.to_le_bytes()); // flags
    encoded.extend_from_slice(&1u16.to_le_bytes()); // count
    encoded.extend_from_slice(&0u16.to_le_bytes()); // reserved
    encoded.extend_from_slice(&0u16.to_le_bytes()); // addr_len = 0
    encoded.extend_from_slice(&0u16.to_le_bytes()); // fd_index
    encoded.extend_from_slice(&[0u8; 8]); // checksum placeholder
    let err = HandoffFrame::decode(&encoded).expect_err("addr_len 0 is rejected at decode");
    assert!(matches!(
        err,
        FrameError::BadAddressLength { entry: 0, len: 0, max } if max == MAX_ADDR_BYTES
    ));

    let err = HandoffFrame::new(vec![HandoffEntry {
        addr: String::new(),
        fd_index: 0,
    }])
    .expect_err("empty address is rejected");
    assert!(matches!(
        err,
        FrameError::BadAddressLength { entry: 0, len: 0, max } if max == MAX_ADDR_BYTES
    ));

    let err = HandoffFrame::new(vec![HandoffEntry {
        addr: too_long,
        fd_index: 0,
    }])
    .expect_err("MAX_ADDR_BYTES + 1 address is rejected");
    assert!(matches!(
        err,
        FrameError::BadAddressLength { entry: 0, len, max } if len == MAX_ADDR_BYTES + 1 && max == MAX_ADDR_BYTES
    ));
}

#[test]
fn non_utf8_address_is_rejected() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&3u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&[0xff, 0xff, 0xff]);
    encoded.extend_from_slice(&[0u8; 8]);

    let err = HandoffFrame::decode(&encoded).expect_err("non-UTF-8 address is rejected");
    assert!(matches!(err, FrameError::NotUtf8 { entry: 0 }));
}

#[test]
fn truncation_table() {
    let entries: Vec<_> = (0..3)
        .map(|i| HandoffEntry {
            addr: "0.0.0.0:80".to_owned(),
            fd_index: u16::try_from(i).expect("i is small"),
        })
        .collect();
    let frame = HandoffFrame::new(entries).expect("valid frame");
    let encoded = frame.encode().expect("encodes");
    let len = encoded.len();

    for cut in 0..len {
        let result = HandoffFrame::decode(&encoded[..cut]);
        assert!(result.is_err(), "truncation at {cut} should be rejected");
    }
}

// truncation_table above only asserts `is_err()` at every cut point, which
// cannot distinguish WHICH `Truncated { need, got }` came back, only that
// something did. This test pins the exact values at one specific boundary:
// mutation testing found that changing validate_entries's first per-entry
// check from `rest.len() < 4` to `rest.len() <= 4` survives every existing
// test, because when exactly 4 bytes remain (the second entry's own addr_len
// and fd_index fields, with nothing after them), both the original and the
// mutated code reject the input; they only disagree on the reported `need`.
// The original reads the 4 present bytes, learns the declared addr_len, and
// reports `need = 4 + addr_len` (the true remaining requirement); the mutant
// rejects one check earlier without ever reading them and reports the
// hard-coded `need = 4` instead.
#[test]
fn truncated_exactly_at_an_entrys_fixed_prefix_names_the_declared_address_length() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes()); // version
    encoded.extend_from_slice(&0u16.to_le_bytes()); // flags
    encoded.extend_from_slice(&2u16.to_le_bytes()); // count = 2
    encoded.extend_from_slice(&0u16.to_le_bytes()); // reserved
    // Entry 0: complete, one-byte address.
    encoded.extend_from_slice(&1u16.to_le_bytes()); // addr_len
    encoded.extend_from_slice(&0u16.to_le_bytes()); // fd_index
    encoded.extend_from_slice(b"a");
    // Entry 1: only its 4-byte fixed prefix (addr_len = 10, fd_index = 1) is
    // present; none of the 10 declared address bytes, and no checksum, follow.
    encoded.extend_from_slice(&10u16.to_le_bytes());
    encoded.extend_from_slice(&1u16.to_le_bytes());
    assert_eq!(encoded.len(), 21);

    let err = HandoffFrame::decode(&encoded)
        .expect_err("a declared entry with only its fixed prefix present is truncated");
    assert!(matches!(err, FrameError::Truncated { need: 14, got: 4 }));
}

#[test]
// This test cannot literally measure allocation: this crate is
// `#![forbid(unsafe_code)]` and `[lints] workspace = true` denies
// `unsafe_code` on every target including `tests/`, so a counting
// `#[global_allocator]` will not compile here (verified: it produces 5
// `unsafe_code` errors). The structural argument for why a declared MAX_FDS
// count with little data cannot cause a large allocation is proved in a
// comment on `HandoffFrame::build_entries` in src/frame.rs: `build_entries`,
// the one function that allocates proportionally to `count`, is only called
// after `validate_entries` has already confirmed the input holds that many
// complete, in-bounds entries, so any truncated input returns `Truncated`
// from `validate_entries` first and never reaches an allocation at all. What
// THIS test checks is the mechanically checkable half of that argument: that
// a declared MAX_FDS count with too little data is in fact rejected, at both
// of the two truncation points that matter, the exact `need`/`got` named so
// a change to which byte triggers the rejection is visible, not just that
// SOME `Truncated` error came back.
fn huge_count_allocates_nothing() {
    let mut header = [0u8; HEADER_BYTES];
    header[0..4].copy_from_slice(b"ITFD");
    let mut offset = 4;
    for value in [
        1u16,
        0u16,
        u16::try_from(MAX_FDS).expect("MAX_FDS fits in u16"),
        0u16,
    ] {
        header[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        offset += 2;
    }
    // 8 bytes after the header: one valid-looking entry with a 4-byte address.
    let mut payload = Vec::from(header);
    payload.extend_from_slice(&4u16.to_le_bytes()); // addr_len
    payload.extend_from_slice(&0u16.to_le_bytes()); // fd_index
    payload.extend_from_slice(b"abcd"); // address
    payload.extend_from_slice(&[0u8; 8]); // checksum placeholder
    assert_eq!(payload.len(), 28);

    // Truncate to HEADER_BYTES exactly: the header declares MAX_FDS entries and
    // literally zero bytes of entry data follow. This is the case the previous
    // version of this test's comment claimed the 20-byte cut below already
    // covered; it did not, because 20 bytes includes one complete entry. At only
    // 12 bytes, decode's very first length check (`bytes.len() < HEADER_BYTES +
    // CHECKSUM_BYTES`) rejects it before the header is even parsed, let alone
    // before the entry loop or any count-proportional allocation could start.
    let no_entry_data = &payload[..HEADER_BYTES];
    let err = HandoffFrame::decode(no_entry_data)
        .expect_err("declared MAX_FDS with zero entry bytes is truncated");
    assert!(matches!(err, FrameError::Truncated { need: 20, got: 12 }));

    // Truncate to 20 bytes: header (12) plus one complete 8-byte entry
    // (addr_len, fd_index, the 4-byte address "abcd"), with none of the 8
    // checksum bytes present. The second of the declared MAX_FDS entries is
    // where this is caught: after the first entry is consumed, 0 bytes remain
    // and the next entry needs at least 4.
    let one_entry_no_checksum = &payload[..20];
    let err = HandoffFrame::decode(one_entry_no_checksum)
        .expect_err("declared MAX_FDS with 20 bytes is truncated");
    assert!(matches!(err, FrameError::Truncated { need: 4, got: 0 }));
}

#[test]
fn huge_addr_len_is_rejected_before_reading() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&65_535u16.to_le_bytes()); // addr_len
    encoded.extend_from_slice(&0u16.to_le_bytes()); // fd_index
    encoded.extend_from_slice(&[0u8; 8]); // checksum placeholder

    let err = HandoffFrame::decode(&encoded).expect_err("huge addr_len is rejected");
    assert!(matches!(
        err,
        FrameError::BadAddressLength { entry: 0, len: 65_535, max } if max == MAX_ADDR_BYTES
    ));
}

#[test]
fn fd_index_out_of_range_is_rejected() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&1u16.to_le_bytes()); // addr_len
    encoded.extend_from_slice(&1u16.to_le_bytes()); // fd_index == count
    encoded.extend_from_slice(b"a");
    encoded.extend_from_slice(&[0u8; 8]); // checksum placeholder

    let err = HandoffFrame::decode(&encoded).expect_err("fd_index == count is rejected");
    assert!(matches!(
        err,
        FrameError::FdIndexOutOfRange {
            entry: 0,
            index: 1,
            count: 1
        }
    ));
}

#[test]
fn duplicate_fd_index_is_rejected() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"ITFD");
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&2u16.to_le_bytes());
    encoded.extend_from_slice(&0u16.to_le_bytes());
    for _ in 0..2 {
        encoded.extend_from_slice(&1u16.to_le_bytes()); // addr_len
        encoded.extend_from_slice(&0u16.to_le_bytes()); // fd_index
        encoded.extend_from_slice(b"a");
    }
    encoded.extend_from_slice(&[0u8; 8]); // checksum placeholder

    let err = HandoffFrame::decode(&encoded).expect_err("duplicate fd_index is rejected");
    assert!(matches!(err, FrameError::DuplicateFdIndex { index: 0 }));
}

// Invariant 3 is "decode(encode(x)) == x for every constructible x". A frame that
// `new` and `encode` accept but `decode` refuses breaks that invariant at the
// sender: `encode` returns `Ok`, the bytes go out, and the receiver rejects the
// whole handoff. These two tests pin the construction side of the same
// fd_index rule `fd_index_out_of_range_is_rejected` and
// `duplicate_fd_index_is_rejected` already pin at decode.
#[test]
fn new_rejects_out_of_range_fd_index() {
    let err = HandoffFrame::new(vec![HandoffEntry {
        addr: "0.0.0.0:80".to_owned(),
        fd_index: 7,
    }])
    .expect_err("fd_index 7 with one entry is out of range");
    assert!(matches!(
        err,
        FrameError::FdIndexOutOfRange {
            entry: 0,
            index: 7,
            count: 1
        }
    ));
}

#[test]
fn new_rejects_duplicate_fd_index() {
    let err = HandoffFrame::new(vec![
        HandoffEntry {
            addr: "0.0.0.0:80".to_owned(),
            fd_index: 0,
        },
        HandoffEntry {
            addr: "0.0.0.0:81".to_owned(),
            fd_index: 0,
        },
    ])
    .expect_err("two entries naming fd_index 0 are rejected");
    assert!(matches!(err, FrameError::DuplicateFdIndex { index: 0 }));
}

// `HandoffEntry` and `HandoffFrame` fields are public, so a caller can build a
// `HandoffFrame` by struct literal without going through `new`, skipping its
// check entirely. `encode`'s own doc comment promises it re-checks "so a
// mutated frame cannot produce an invalid encoding"; this test holds it to
// that promise for the exact fd_index hole invariant 3 names, on both the
// out-of-range and the duplicate case.
#[test]
fn encode_rechecks_fd_index_on_a_hand_built_frame() {
    let out_of_range = HandoffFrame {
        entries: vec![HandoffEntry {
            addr: "0.0.0.0:80".to_owned(),
            fd_index: 7,
        }],
    };
    let err = out_of_range
        .encode()
        .expect_err("encode rejects an out-of-range fd_index even without new()");
    assert!(matches!(
        err,
        FrameError::FdIndexOutOfRange {
            entry: 0,
            index: 7,
            count: 1
        }
    ));

    let duplicate = HandoffFrame {
        entries: vec![
            HandoffEntry {
                addr: "0.0.0.0:80".to_owned(),
                fd_index: 0,
            },
            HandoffEntry {
                addr: "0.0.0.0:81".to_owned(),
                fd_index: 0,
            },
        ],
    };
    let err = duplicate
        .encode()
        .expect_err("encode rejects a duplicate fd_index even without new()");
    assert!(matches!(err, FrameError::DuplicateFdIndex { index: 0 }));
}

#[test]
fn permuted_fd_indices_are_accepted() {
    let entries: Vec<_> = (0..5)
        .rev()
        .map(|i| HandoffEntry {
            addr: "0.0.0.0:80".to_owned(),
            fd_index: i,
        })
        .collect();
    let frame = HandoffFrame::new(entries).expect("permuted indices are legal");
    let encoded = frame.encode().expect("encodes");
    let decoded = HandoffFrame::decode(&encoded).expect("decodes");
    assert_eq!(decoded, frame);
}

#[test]
fn reserved_fields_must_be_zero() {
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: "0.0.0.0:80".to_owned(),
        fd_index: 0,
    }])
    .expect("valid frame");
    let mut encoded = frame.encode().expect("encodes");
    // Set flags byte to 1.
    encoded[6] = 1;
    let err = HandoffFrame::decode(&encoded).expect_err("non-zero flags are rejected");
    assert!(matches!(err, FrameError::ReservedNotZero));

    let mut encoded = frame.encode().expect("encodes");
    encoded[10] = 1;
    let err = HandoffFrame::decode(&encoded).expect_err("non-zero reserved are rejected");
    assert!(matches!(err, FrameError::ReservedNotZero));
}

#[test]
fn unsupported_version_is_rejected() {
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: "0.0.0.0:80".to_owned(),
        fd_index: 0,
    }])
    .expect("valid frame");
    let mut encoded = frame.encode().expect("encodes");
    encoded[4] = 2;
    encoded[5] = 0;
    let err = HandoffFrame::decode(&encoded).expect_err("version 2 is rejected");
    assert!(matches!(err, FrameError::UnsupportedVersion { found: 2 }));
}

#[test]
fn flipped_bit_fails_the_checksum() {
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: "0.0.0.0:80".to_owned(),
        fd_index: 0,
    }])
    .expect("valid frame");
    let mut encoded = frame.encode().expect("encodes");
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    let err = HandoffFrame::decode(&encoded).expect_err("flipped bit fails checksum");
    assert!(matches!(err, FrameError::BadChecksum));
}

#[test]
fn trailing_bytes_are_rejected() {
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: "0.0.0.0:80".to_owned(),
        fd_index: 0,
    }])
    .expect("valid frame");
    let mut encoded = frame.encode().expect("encodes");
    encoded.push(0);
    let err = HandoffFrame::decode(&encoded).expect_err("trailing bytes are rejected");
    assert!(matches!(err, FrameError::TrailingBytes { extra: 1 }));
}

#[test]
fn empty_input_is_truncated() {
    let err = HandoffFrame::decode(&[]).expect_err("empty input is truncated");
    assert!(matches!(err, FrameError::Truncated { need: 20, got: 0 }));
}

#[test]
fn find_matches_the_canonical_rendering() {
    use irontraffic_config::BindAddr;

    let v4 = BindAddr::try_from("0.0.0.0:80").expect("valid");
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: v4.canonical_key(),
        fd_index: 0,
    }])
    .expect("valid frame");
    assert!(frame.find("0.0.0.0:80").is_some());
    assert!(frame.find("0.0.0.0:0080").is_none());

    let v6 = BindAddr::try_from("[::ffff]:80").expect("valid");
    let frame = HandoffFrame::new(vec![HandoffEntry {
        addr: v6.canonical_key(),
        fd_index: 0,
    }])
    .expect("valid frame");
    assert!(frame.find("[::ffff]:80").is_some());
    assert!(frame.find("[::FFFF]:80").is_none());
}

#[test]
fn find_all_returns_every_shard() {
    let addr = "0.0.0.0:80".to_owned();
    let entries: Vec<_> = (0..4)
        .map(|i| HandoffEntry {
            addr: addr.clone(),
            fd_index: i,
        })
        .collect();
    let frame = HandoffFrame::new(entries).expect("valid frame");
    assert_eq!(frame.find(&addr).map(|e| e.fd_index), Some(0));
    let all: Vec<_> = frame.find_all(&addr).collect();
    assert_eq!(all.len(), 4);
    let indices: Vec<u16> = all.iter().map(|e| e.fd_index).collect();
    assert_eq!(indices, vec![0u16, 1, 2, 3]);
}

use proptest::prelude::*;

fn valid_address() -> impl Strategy<Value = String> {
    prop::collection::vec(1u8..=127, 1..=MAX_ADDR_BYTES)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap_or_else(|_| String::new()))
}

// Generates entries whose `fd_index` values are an ARBITRARY permutation of
// `0..entries.len()`, not just the ascending identity assignment the previous
// generator produced (`fd_index: u16::try_from(i)` taken straight from
// `enumerate`). This still only ever generates LEGAL permutations (by
// construction, `order` is always a bijection on `0..count`), so it cannot by
// itself catch a missing fd_index validation the way a hand-built illegal
// frame does; `new_rejects_out_of_range_fd_index`,
// `new_rejects_duplicate_fd_index` and
// `encode_rechecks_fd_index_on_a_hand_built_frame` cover that. What this DOES
// add is round-trip coverage for orderings other than strictly ascending: a
// bug that depended on fd_index happening to equal position (for example in
// `find_all`'s ordering guarantee) would previously never have been
// exercised. Deriving the permutation from an independently generated
// priority per address and sorting by it, rather than a fixed transform such
// as reversal, also means proptest shrinking explores the permutation space,
// not just the one ordering a hand-written reversal would cover.
fn permuted_entries() -> impl Strategy<Value = Vec<HandoffEntry>> {
    prop::collection::vec(valid_address(), 0..=MAX_FDS).prop_flat_map(|addrs| {
        let count = addrs.len();
        prop::collection::vec(any::<u16>(), count).prop_map(move |priorities| {
            let mut order: Vec<usize> = (0..count).collect();
            order.sort_by_key(|&original| priorities.get(original).copied().unwrap_or(0));
            // `rank` ranges over `0..count` and `count <= MAX_FDS` (253) is
            // guaranteed by the outer strategy's bound, so `u16::try_from`
            // never fails; `filter_map` with `.ok()` avoids an `unwrap` or
            // `expect` in non-test code rather than asserting that.
            let mut ranked: Vec<(usize, u16)> = order
                .into_iter()
                .enumerate()
                .filter_map(|(rank, original)| u16::try_from(rank).ok().map(|r| (original, r)))
                .collect();
            ranked.sort_by_key(|&(original, _)| original);
            addrs
                .iter()
                .cloned()
                .zip(ranked.into_iter().map(|(_, fd_index)| fd_index))
                .map(|(addr, fd_index)| HandoffEntry { addr, fd_index })
                .collect()
        })
    })
}

// A well-formed frame built from `permuted_entries`, so callers get a frame
// they can `encode` without an error path to fall back on. `new` cannot
// actually fail here: every field `permuted_entries` produces already
// satisfies `validate` (bounded count, in-range address lengths, a genuine
// fd_index permutation), so `unwrap_or_default` never triggers; it is used
// instead of `expect` only because this function is not itself a `#[test]`
// and clippy's unwrap/expect exemption is per-test-function, not per-file.
fn permuted_frame() -> impl Strategy<Value = HandoffFrame> {
    permuted_entries().prop_map(|entries| HandoffFrame::new(entries).unwrap_or_default())
}

/// The exact bytes of a well-formed, checksummed frame.
fn valid_frame_bytes() -> impl Strategy<Value = Vec<u8>> {
    permuted_frame().prop_map(|frame| frame.encode().unwrap_or_default())
}

/// A well-formed frame's bytes with exactly one byte flipped to a different,
/// non-zero-XOR value, so the corruption is guaranteed to change something:
/// the magic, a length, an address byte, or the checksum. This is the "near
/// miss" input decode's error paths (`BadChecksum`, `NotUtf8`,
/// `BadAddressLength`, `TrailingBytes` from a shortened trailing string, and
/// so on) exist for, as opposed to the uniform noise below which almost
/// never gets past `BadMagic`.
fn corrupted_frame_bytes() -> impl Strategy<Value = Vec<u8>> {
    (valid_frame_bytes(), any::<usize>(), 1u8..=255).prop_map(|(mut bytes, index, flip)| {
        let len = bytes.len();
        if len > 0
            && let Some(byte) = bytes.get_mut(index % len)
        {
            *byte ^= flip;
        }
        bytes
    })
}

// Uniform noise almost never starts with b"ITFD" (odds about (1/256)^4), so on
// its own this generator drives `HandoffFrame::decode` into `Err` on
// essentially every case and the `Ok` arm below, the crate's only automated
// statement of the decoder's OUTPUT bounds, never runs; issue #603 measured
// zero hits in 200,000 draws. Mixing in well-formed and near-well-formed
// frames makes the `Ok` arm a real, exercised branch rather than dead code
// disguised as a property test, while the uniform arm is kept so decode is
// still checked against inputs that share no structure with the format at
// all.
fn frame_shaped_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::collection::vec(any::<u8>(), 0..=65_536),
        4 => valid_frame_bytes(),
        3 => corrupted_frame_bytes(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_round_trip(entries in permuted_entries()) {
        let frame = HandoffFrame::new(entries).expect("generated frame is legal");
        let encoded = frame.encode().expect("generated frame encodes");
        let decoded = HandoffFrame::decode(&encoded).expect("generated frame decodes");
        assert_eq!(decoded, frame);
    }

    // Test 21's allocation clause ("never allocate more than MAX_FRAME_BYTES
    // plus a constant") cannot be measured here: this crate is
    // `#![forbid(unsafe_code)]` and `[lints] workspace = true` denies
    // `unsafe_code` on every target including this one, so a counting
    // `#[global_allocator]` will not compile (issue #605 reproduced the 5
    // resulting compiler errors). Per the corpus-wide rule this exact
    // situation calls for ("prove it statically, or stop and report"), the
    // bound is proved in a comment on `HandoffFrame::build_entries` in
    // src/frame.rs instead: every allocation build_entries performs is sized
    // either by the compile-time constant MAX_FDS or by a byte count already
    // checked against bytes physically present in `bytes`, so no declared
    // length past `decode`'s validation step can inflate it. This test's job
    // is the part that IS mechanically checkable: the two bounds on
    // `decode`'s successful OUTPUT, which requires the `Ok` arm to actually
    // run, the defect `frame_shaped_bytes` above exists to fix.
    #[test]
    fn prop_decode_never_panics(bytes in frame_shaped_bytes()) {
        if let Ok(frame) = HandoffFrame::decode(&bytes) {
            assert!(frame.entries.len() <= MAX_FDS);
            assert!(frame.encoded_len() <= MAX_FRAME_BYTES);
        }
    }
}
