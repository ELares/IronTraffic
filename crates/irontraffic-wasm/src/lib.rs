// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITX core-module WebAssembly ABI: wire-level names, return encoding,
//! the one function that turns a guest pointer into a Rust slice, and the
//! decoder for the batched guest op list.

#![deny(unsafe_code)]

pub mod abi;
pub mod oplist;

pub use abi::{
    AbiError, EXPORTS, GuestAction, IMPORTS, ITX_ABI_VERSION, ITX_ABSENT, ITX_BUDGET,
    ITX_DUPLICATE, ITX_INVALID, ITX_OK, ITX_WRONG_PHASE, MAX_OP_FIELD_BYTES, OP_RECORD_BYTES,
    PHASE_EXPORTS, RESERVED_IMPORTS, guest_slice, guest_slice_mut,
};
pub use oplist::{RawGuestOp, decode_op_list};
