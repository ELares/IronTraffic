// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronTraffic filter vocabulary: phases, actions, and the header-op ledger
//! shared by native, policy, WASM and callout filters.
//!
//! This crate performs no I/O and depends on no runtime; see the attribute below.

#![forbid(unsafe_code)]

pub mod action;
pub mod bytes;
pub mod kind;
pub mod phase;

pub use action::{Action, BodyDisposition, DirectResponse, ResetCode, ShortCircuitReason};
pub use bytes::{Arena, HeaderOp, StrRef};
pub use kind::{FailureMode, FilterKind};
pub use phase::{Phase, PhaseMask};
