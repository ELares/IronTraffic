// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the descriptor-handoff frame.

use irontraffic_upgrade::{
    FrameError, HEADER_BYTES, HandoffEntry, HandoffFrame, MAX_ADDR_BYTES, MAX_FDS, MAX_FRAME_BYTES,
};

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

#[test]
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

    // Truncate to 20 bytes: header + checksum placeholder, no actual entry data.
    let input = &payload[..20];
    let err = HandoffFrame::decode(input).expect_err("declared MAX_FDS with 20 bytes is truncated");
    assert!(matches!(err, FrameError::Truncated { .. }));
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_round_trip(entries in prop::collection::vec(valid_address(), 0..=MAX_FDS)) {
        let entries: Vec<_> = entries
            .into_iter()
            .enumerate()
            .map(|(i, addr)| HandoffEntry {
                addr,
                fd_index: u16::try_from(i).expect("i fits in u16"),
            })
            .collect();
        let frame = HandoffFrame::new(entries).expect("generated frame is legal");
        let encoded = frame.encode().expect("generated frame encodes");
        let decoded = HandoffFrame::decode(&encoded).expect("generated frame decodes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=65_536)) {
        if let Ok(frame) = HandoffFrame::decode(&bytes) {
            assert!(frame.entries.len() <= MAX_FDS);
            assert!(frame.encoded_len() <= MAX_FRAME_BYTES);
        }
    }
}
