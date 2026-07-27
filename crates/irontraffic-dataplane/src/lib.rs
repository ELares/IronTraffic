// SPDX-License-Identifier: MIT OR Apache-2.0

//! The forwarding data plane.
//!
//! One task per connection, no channel, at most one pooled 32 KiB buffer in
//! flight per direction. See [`forward::forward_bidirectional`] for the rule
//! this crate exists to enforce: read at most one buffer, write it to
//! completion, then read again. Backpressure is structural, not a policy
//! enforced by watermarks.

#![deny(missing_docs)]

pub mod forward;

#[cfg(feature = "test-support")]
pub mod duplex;

pub use forward::{
    EndReason, ForwardError, ForwardLimits, ForwardStats, MAX_PUMP_ROUNDS, forward_bidirectional,
};
