// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic types for this crate. Under `--cfg loom` they are `loom`'s instrumented
//! versions, so the `loom` tests in `tests/loom_balance.rs` actually model-check
//! this crate's own atomics rather than opaque `std` ones. Under every normal
//! build they are the `std` types, byte for byte.
//!
//! `loom` model-checks only the atomics it provides: `std::sync::atomic::AtomicU32`
//! is invisible to it, so a `loom` test written against a struct that imports `std`
//! atomics explores nothing and passes unconditionally, which is worse than having
//! no test at all. Every atomic field of [`crate::stats::EndpointStats`] goes
//! through this module for exactly that reason. `crates/irontraffic-upstream/src/
//! registry.rs` is not required to change, because no `loom` test in this crate
//! touches the registry.

#![allow(
    unexpected_cfgs,
    reason = "cfg(loom) is a deliberate custom cfg for the loom concurrency-model tests, the same #[cfg(loom)] convention loom's own downstream users (tokio, crossbeam) rely on; registering it via a package-level [lints.rust] check-cfg table would conflict with this crate's required [lints] workspace = true, and this crate may not touch the workspace lints table to add it there instead"
)]

#[cfg(not(loom))]
pub use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
#[cfg(loom)]
pub use loom::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
