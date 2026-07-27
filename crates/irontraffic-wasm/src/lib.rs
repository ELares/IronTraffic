// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITX core-module WebAssembly ABI: wire-level names, return encoding,
//! the one function that turns a guest pointer into a Rust slice, and the
//! decoder for the batched guest op list.
//!
//! Nothing in this crate depends on a WebAssembly runtime, does I/O, or holds
//! a lock. The functions here are pure transforms over byte slices and will be
//! driven by `{{wasm-host-imports-caller-allocates}}` and
//! `{{wasm-filter-adapter-and-lifecycle}}`.

#![deny(unsafe_code)]

pub mod abi;
pub mod oplist;

pub use abi::{
    guest_slice, guest_slice_mut, AbiError, GuestAction, EXPORTS, IMPORTS, ITX_ABSENT, ITX_BUDGET,
    ITX_DUPLICATE, ITX_INVALID, ITX_OK, ITX_WRONG_PHASE, ITX_ABI_VERSION, MAX_OP_FIELD_BYTES,
    OP_RECORD_BYTES, PHASE_EXPORTS, RESERVED_IMPORTS,
};
pub use oplist::{decode_op_list, RawGuestOp};
