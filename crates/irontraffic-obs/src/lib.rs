// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

//! HOT PATH
//!
//! Shared primitives for every IronTraffic observability subsystem.
//!
//! Four modules, each complete and independently exercised, with no consumer yet in
//! this milestone: [`cell`] ([`Cell64`], a relaxed single-writer counter cell),
//! [`shard`] ([`Shards`], one separately allocated, 128 byte aligned block per core),
//! [`epoch`] ([`EpochWitness`], per-core proof that a configuration epoch reached that
//! core), and [`render`] (integer and hex byte formatting plus [`CachedWall`], a
//! per-writer pre-rendered timestamp).
//!
//! This crate is sans IO. It never opens a socket or a file and never spawns a thread.
//! It reads a clock only through a caller-supplied `irontraffic_time::CoarseWall`;
//! nothing in this crate calls `irontraffic_time::TimeSource` itself.
//!
//! **Nothing else in the milestone may allocate a per-core array or format an integer
//! by hand.** [`shard::Shards`] and [`render`] are the one sanctioned way to do each.

pub mod cell;
pub mod epoch;
pub mod render;
pub mod shard;

pub use cell::Cell64;
pub use epoch::{EpochSighting, EpochWitness};
pub use render::{
    CachedWall, render_hex_lower, render_i32, render_millis_fixed, render_u32, render_u64,
};
pub use shard::{MAX_SHARDS, SHARD_ALIGN, ShardBlock, Shards};
