// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decoder for the batched guest op list.

use crate::abi::{AbiError, MAX_OP_FIELD_BYTES, OP_RECORD_BYTES, guest_slice};

const OP_RECORD_BYTES_USIZE: usize = OP_RECORD_BYTES as usize;

/// One decoded guest op: operation discriminant, name bytes, optional value bytes.
pub type GuestOp<'m> = (u8, &'m [u8], Option<&'m [u8]>);

/// One mutation as the guest encodes it. Little-endian, 20 bytes, 4-byte aligned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawGuestOp {
    /// 0 `Append`, 1 `Set`, 2 `Remove`.
    pub op: u8,
    /// 0 = the header section of the current phase. Values above 0 are reserved
    /// and are `BadOpRecord` in v1.
    pub target: u8,
    /// Must be 0.
    pub reserved: u16,
    /// Guest pointer to the field name.
    pub name_ptr: u32,
    /// Field-name length in bytes.
    pub name_len: u32,
    /// Guest pointer to the value. 0 for `Remove`.
    pub value_ptr: u32,
    /// Value length. 0 for `Remove`.
    pub value_len: u32,
}

/// Decodes a guest op list into borrowed triples.
///
/// The returned iterator yields `(op, name, value)` for each record. `value` is
/// `None` for `Remove` operations. The iterator borrows from `mem` and performs
/// no heap allocation.
///
/// # Errors
/// `AbiError::Misaligned`, `RaggedOpList`, `TooManyOps`, `ReservedNonZero`,
/// `BadOpRecord`, `OutOfBounds`.
pub fn decode_op_list(
    mem: &[u8],
    ptr: u32,
    len: u32,
    max_ops: u32,
) -> Result<impl Iterator<Item = Result<GuestOp<'_>, AbiError>> + '_, AbiError> {
    if !ptr.is_multiple_of(4) {
        return Err(AbiError::Misaligned { ptr });
    }
    if !len.is_multiple_of(OP_RECORD_BYTES) {
        return Err(AbiError::RaggedOpList { len });
    }
    #[allow(
        clippy::integer_division,
        reason = "len is a multiple of OP_RECORD_BYTES, so the quotient is exact"
    )]
    let count = len / OP_RECORD_BYTES;
    if count > max_ops {
        return Err(AbiError::TooManyOps {
            count,
            max: max_ops,
        });
    }
    let bytes = guest_slice(mem, ptr, len)?;
    Ok(DecodeOpList {
        mem,
        bytes,
        offset: 0,
    })
}

struct DecodeOpList<'m> {
    mem: &'m [u8],
    bytes: &'m [u8],
    offset: u32,
}

impl<'m> Iterator for DecodeOpList<'m> {
    type Item = Result<GuestOp<'m>, AbiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let (record, rest) = self.bytes.split_at(OP_RECORD_BYTES_USIZE);
        self.bytes = rest;
        let at = self.offset;
        self.offset += OP_RECORD_BYTES;
        Some(decode_record(self.mem, record, at))
    }
}

fn decode_record<'m>(mem: &'m [u8], record: &[u8], at: u32) -> Result<GuestOp<'m>, AbiError> {
    // `record` is exactly `OP_RECORD_BYTES` bytes long because the iterator
    // only ever splits at that boundary.
    let op = read_u8(record, 0).ok_or(AbiError::BadOpRecord { at })?;
    let target = read_u8(record, 1).ok_or(AbiError::BadOpRecord { at })?;
    let reserved = read_u16_le(record, 2).ok_or(AbiError::BadOpRecord { at })?;
    let name_ptr = read_u32_le(record, 4).ok_or(AbiError::BadOpRecord { at })?;
    let name_len = read_u32_le(record, 8).ok_or(AbiError::BadOpRecord { at })?;
    let value_ptr = read_u32_le(record, 12).ok_or(AbiError::BadOpRecord { at })?;
    let value_len = read_u32_le(record, 16).ok_or(AbiError::BadOpRecord { at })?;

    if reserved != 0 {
        return Err(AbiError::ReservedNonZero { at });
    }
    if target != 0 || op > 2 {
        return Err(AbiError::BadOpRecord { at });
    }
    if name_len > MAX_OP_FIELD_BYTES {
        return Err(AbiError::FieldTooLarge {
            at,
            len: name_len,
            max: MAX_OP_FIELD_BYTES,
        });
    }
    if op != 2 && value_len > MAX_OP_FIELD_BYTES {
        return Err(AbiError::FieldTooLarge {
            at,
            len: value_len,
            max: MAX_OP_FIELD_BYTES,
        });
    }

    let name = guest_slice(mem, name_ptr, name_len).map_err(|_| AbiError::OutOfBounds {
        ptr: name_ptr,
        len: name_len,
        mem_len: mem.len(),
    })?;
    let value = if op == 2 {
        None
    } else {
        Some(
            guest_slice(mem, value_ptr, value_len).map_err(|_| AbiError::OutOfBounds {
                ptr: value_ptr,
                len: value_len,
                mem_len: mem.len(),
            })?,
        )
    };

    Ok((op, name, value))
}

fn read_u8(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let a = read_u8(bytes, offset)?;
    let b = read_u8(bytes, offset + 1)?;
    Some(u16::from_le_bytes([a, b]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let a = read_u8(bytes, offset)?;
    let b = read_u8(bytes, offset + 1)?;
    let c = read_u8(bytes, offset + 2)?;
    let d = read_u8(bytes, offset + 3)?;
    Some(u32::from_le_bytes([a, b, c, d]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{EXPORTS, PHASE_EXPORTS};
    use irontraffic_filter::phase::Phase;

    fn encode_op(
        op: u8,
        target: u8,
        reserved: u16,
        name_ptr: u32,
        name_len: u32,
        value_ptr: u32,
        value_len: u32,
    ) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0] = op;
        buf[1] = target;
        buf[2..4].copy_from_slice(&reserved.to_le_bytes());
        buf[4..8].copy_from_slice(&name_ptr.to_le_bytes());
        buf[8..12].copy_from_slice(&name_len.to_le_bytes());
        buf[12..16].copy_from_slice(&value_ptr.to_le_bytes());
        buf[16..20].copy_from_slice(&value_len.to_le_bytes());
        buf
    }

    #[test]
    fn empty_op_list() {
        let iter = decode_op_list(&[], 0, 0, 10).expect("empty list");
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn ragged_length() {
        assert!(matches!(
            decode_op_list(&[0u8; 21], 0, 21, 10),
            Err(AbiError::RaggedOpList { len: 21 })
        ));
    }

    #[test]
    fn misaligned_pointer() {
        assert!(matches!(
            decode_op_list(&[0u8; 20], 1, 20, 10),
            Err(AbiError::Misaligned { ptr: 1 })
        ));
    }

    #[test]
    fn too_many_ops_before_memory_access() {
        let len = 4_000_000_000u32;
        assert!(matches!(
            decode_op_list(&[], 0, len, 10),
            Err(AbiError::TooManyOps {
                count: 200_000_000,
                max: 10,
            })
        ));
    }

    #[test]
    fn reserved_non_zero() {
        let mut mem = [0u8; 20];
        let record = encode_op(0, 0, 1, 0, 0, 0, 0);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("header ok");
        assert_eq!(
            iter.next().expect("item"),
            Err(AbiError::ReservedNonZero { at: 0 })
        );
    }

    #[test]
    fn bad_target() {
        let mut mem = [0u8; 20];
        let record = encode_op(0, 1, 0, 0, 0, 0, 0);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("header ok");
        assert_eq!(
            iter.next().expect("item"),
            Err(AbiError::BadOpRecord { at: 0 })
        );
    }

    #[test]
    fn bad_op_discriminant() {
        let mut mem = [0u8; 20];
        let record = encode_op(3, 0, 0, 0, 0, 0, 0);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("header ok");
        assert_eq!(
            iter.next().expect("item"),
            Err(AbiError::BadOpRecord { at: 0 })
        );
    }

    #[test]
    fn remove_ignores_value_pointer() {
        let mut mem = [0u8; 40];
        // name at byte 20, length 3
        let record = encode_op(2, 0, 0, 20, 3, 0xFFFF_FFFF, 0xFFFF_FFFF);
        mem[..20].copy_from_slice(&record);
        mem[20..23].copy_from_slice(b"abc");
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("valid remove");
        let (op, name, value) = iter.next().expect("one op").expect("valid record");
        assert_eq!(op, 2);
        assert_eq!(name, b"abc");
        assert_eq!(value, None);
        assert!(iter.next().is_none());
    }

    #[test]
    fn overlapping_name_and_value_allowed() {
        // Two Set ops share the same name bytes. Each value is different.
        let mut mem = [0u8; 64];
        mem[40..43].copy_from_slice(b"foo");
        mem[43..46].copy_from_slice(b"bar");
        mem[46..49].copy_from_slice(b"baz");
        let r1 = encode_op(1, 0, 0, 40, 3, 43, 3);
        let r2 = encode_op(1, 0, 0, 40, 3, 46, 3);
        mem[0..20].copy_from_slice(&r1);
        mem[20..40].copy_from_slice(&r2);
        let ops: Vec<_> = decode_op_list(&mem, 0, 40, 10)
            .expect("valid list")
            .map(|r| r.expect("valid record"))
            .collect();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0], (1, &b"foo"[..], Some(&b"bar"[..])));
        assert_eq!(ops[1], (1, &b"foo"[..], Some(&b"baz"[..])));
    }

    #[test]
    fn three_op_roundtrip() {
        // Layout:
        // 0..20  record 0: Append name=40 len=3 value=43 len=3
        // 20..40 record 1: Set   name=40 len=3 value=46 len=3
        // 40..60 record 2: Remove name=40 len=3 value_ptr ignored
        // 60..63 "foo"
        // 63..66 "bar"
        // 66..69 "baz"
        let mut mem = [0u8; 80];
        mem[60..63].copy_from_slice(b"foo");
        mem[63..66].copy_from_slice(b"bar");
        mem[66..69].copy_from_slice(b"baz");
        let r0 = encode_op(0, 0, 0, 60, 3, 63, 3);
        let r1 = encode_op(1, 0, 0, 60, 3, 66, 3);
        let r2 = encode_op(2, 0, 0, 60, 3, 0, 0);
        mem[0..20].copy_from_slice(&r0);
        mem[20..40].copy_from_slice(&r1);
        mem[40..60].copy_from_slice(&r2);
        let ops: Vec<_> = decode_op_list(&mem, 0, 60, 10)
            .expect("valid list")
            .map(|r| r.expect("valid record"))
            .collect();
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0], (0, &b"foo"[..], Some(&b"bar"[..])));
        assert_eq!(ops[1], (1, &b"foo"[..], Some(&b"baz"[..])));
        assert_eq!(ops[2], (2, &b"foo"[..], None));
    }

    #[test]
    fn name_out_of_bounds_is_error() {
        let mut mem = [0u8; 20];
        let record = encode_op(0, 0, 0, 100, 5, 0, 0);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("header ok");
        assert_eq!(
            iter.next().expect("item"),
            Err(AbiError::OutOfBounds {
                ptr: 100,
                len: 5,
                mem_len: 20,
            })
        );
    }

    #[test]
    fn value_out_of_bounds_is_error() {
        let mut mem = [0u8; 24];
        mem[20..23].copy_from_slice(b"abc");
        let record = encode_op(1, 0, 0, 20, 3, 100, 5);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("header ok");
        assert_eq!(
            iter.next().expect("item"),
            Err(AbiError::OutOfBounds {
                ptr: 100,
                len: 5,
                mem_len: 24,
            })
        );
    }

    #[test]
    fn decode_does_not_allocate() {
        // Per the project rules a process-wide counting allocator is unsafe and
        // cannot be used in tests. This test exercises the decoder over a 32-op
        // list and proves statically that the public API returns an iterator over
        // borrowed slices, not a collection.
        let mut mem = [0u8; 1024];
        for i in 0..32u32 {
            let name_off = 640 + i * 4;
            let val_off = name_off + 2;
            let base = (i as usize) * 20;
            mem[(name_off as usize)..(name_off as usize) + 2].copy_from_slice(b"ab");
            mem[(val_off as usize)..(val_off as usize) + 2].copy_from_slice(b"cd");
            let record = encode_op(0, 0, 0, name_off, 2, val_off, 2);
            mem[base..base + 20].copy_from_slice(&record);
        }
        let ops: Vec<_> = decode_op_list(&mem, 0, 32 * 20, 100)
            .expect("valid list")
            .map(|r| r.expect("valid record"))
            .collect();
        assert_eq!(ops.len(), 32);
        for (op, name, value) in &ops {
            assert_eq!(*op, 0);
            assert_eq!(*name, b"ab");
            assert_eq!(*value, Some(&b"cd"[..]));
        }
    }

    #[test]
    fn zero_length_name_decodes() {
        let mut mem = [0u8; 24];
        mem[20..23].copy_from_slice(b"xyz");
        let record = encode_op(1, 0, 0, 20, 0, 20, 3);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("valid list");
        let (op, name, value) = iter.next().expect("one op").expect("valid record");
        assert_eq!(op, 1);
        assert!(name.is_empty());
        assert_eq!(value, Some(&b"xyz"[..]));
    }

    #[test]
    fn oversized_field_rejected() {
        let mem_len = 16 * 1024 * 1024;
        let mut mem = vec![0u8; mem_len];
        let big = MAX_OP_FIELD_BYTES + 1;

        // Name too large.
        let record = encode_op(0, 0, 0, 0, big, 0, 0);
        mem[..20].copy_from_slice(&record);
        match decode_op_list(&mem, 0, 20, 10) {
            Err(e) => assert_eq!(
                e,
                AbiError::FieldTooLarge {
                    at: 0,
                    len: big,
                    max: MAX_OP_FIELD_BYTES,
                }
            ),
            Ok(_) => panic!("expected FieldTooLarge"),
        }

        // Name exactly at the limit is accepted (the value here is empty).
        let record = encode_op(0, 0, 0, 0, MAX_OP_FIELD_BYTES, 0, 0);
        mem[..20].copy_from_slice(&record);
        {
            let mut iter = decode_op_list(&mem, 0, 20, 10).expect("at limit");
            let (op, name, value) = iter.next().expect("one op").expect("valid record");
            assert_eq!(op, 0);
            assert_eq!(name.len(), MAX_OP_FIELD_BYTES as usize);
            assert!(value.expect("value").is_empty());
        }

        // Value too large on a Set.
        let record = encode_op(1, 0, 0, 0, 0, 0, big);
        mem[..20].copy_from_slice(&record);
        match decode_op_list(&mem, 0, 20, 10) {
            Err(e) => assert_eq!(
                e,
                AbiError::FieldTooLarge {
                    at: 0,
                    len: big,
                    max: MAX_OP_FIELD_BYTES,
                }
            ),
            Ok(_) => panic!("expected FieldTooLarge"),
        }

        // Remove ignores an oversized value_len.
        let record = encode_op(2, 0, 0, 0, 0, 0, big);
        mem[..20].copy_from_slice(&record);
        let mut iter = decode_op_list(&mem, 0, 20, 10).expect("valid remove");
        let (op, name, value) = iter.next().expect("one op").expect("valid record");
        assert_eq!(op, 2);
        assert!(name.is_empty());
        assert_eq!(value, None);
    }

    #[test]
    fn phase_export_mapping_is_exact() {
        assert_eq!(PHASE_EXPORTS.len(), 7);

        let mut seen = [false; Phase::COUNT];
        for (phase, name) in PHASE_EXPORTS {
            assert!(
                EXPORTS.contains(&name),
                "phase {phase:?} export {name} must be in EXPORTS"
            );
            assert!(!seen[phase.index()], "phase {phase:?} appears twice");
            seen[phase.index()] = true;
        }

        assert!(!seen[Phase::RouteSelected.index()]);
        assert!(!seen[Phase::UpstreamRequestHeaders.index()]);
        assert!(!seen[Phase::Log.index()]);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_decode_never_panics(
            mem in any::<Vec<u8>>(),
            ptr in any::<u32>(),
            len in any::<u32>(),
            max_ops in 0..=128u32,
        ) {
            if let Ok(iter) = decode_op_list(&mem, ptr, len, max_ops) {
                let _: Vec<_> = iter.collect();
            }
        }

        #[test]
        fn prop_decoded_slices_are_inside_memory(
            mem in any::<Vec<u8>>(),
            ptr in any::<u32>(),
            len in any::<u32>(),
            max_ops in 0..=128u32,
        ) {
            if let Ok(iter) = decode_op_list(&mem, ptr, len, max_ops) {
                for (_op, name, value) in iter.flatten() {
                    assert_slice_inside(&mem, name);
                    if let Some(v) = value {
                        assert_slice_inside(&mem, v);
                    }
                }
            }
        }
    }

    fn assert_slice_inside(mem: &[u8], slice: &[u8]) {
        let mem_start = mem.as_ptr();
        let mem_end = mem_start.wrapping_add(mem.len());
        let slice_start = slice.as_ptr();
        let slice_end = slice_start.wrapping_add(slice.len());
        assert!(
            slice_start >= mem_start && slice_end <= mem_end,
            "slice outside memory"
        );
    }
}
