// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `decode_op_list`: arbitrary bytes are treated as a synthetic
//! linear memory and a `(ptr, len)` pair. The contract is no panic, no
//! allocation proportional to input, and every yielded slice lies inside the
//! memory.

use irontraffic_wasm::decode_op_list;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input into memory and an 8-byte (ptr, len) trailer. If the
    // input is shorter than 8 bytes, use an empty memory and zero pointer.
    let (mem, trailer) = if data.len() >= 8 {
        data.split_at(data.len() - 8)
    } else {
        (data, &[] as &[u8])
    };

    let ptr = read_u32_le(trailer, 0).unwrap_or(0);
    let len = read_u32_le(trailer, 4).unwrap_or(0);

    if let Ok(iter) = decode_op_list(mem, ptr, len, 1024) {
        for result in iter {
            if let Ok((_op, name, value)) = result {
                assert_slice_inside(mem, name);
                if let Some(v) = value {
                    assert_slice_inside(mem, v);
                }
            }
        }
    }
});

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let a = bytes.get(offset).copied()?;
    let b = bytes.get(offset + 1).copied()?;
    let c = bytes.get(offset + 2).copied()?;
    let d = bytes.get(offset + 3).copied()?;
    Some(u32::from_le_bytes([a, b, c, d]))
}

fn assert_slice_inside(mem: &[u8], slice: &[u8]) {
    let mem_start = mem.as_ptr();
    let mem_end = mem_start.wrapping_add(mem.len());
    let slice_start = slice.as_ptr();
    let slice_end = slice_start.wrapping_add(slice.len());
    assert!(slice_start >= mem_start && slice_end <= mem_end);
}
