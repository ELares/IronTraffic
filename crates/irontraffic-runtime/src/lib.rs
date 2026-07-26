// SPDX-License-Identifier: MIT OR Apache-2.0
//! Runtime construction for IronTraffic.
//!
//! This crate and `irontraffic-io` are the only crates permitted to name `tokio`.

pub mod cgroup;
pub mod core;
pub mod plane;

pub use cgroup::{MAX_WORKERS, QuotaSource, WorkerDerivation, derive_workers, host_parallelism};
pub use core::{
    COUNTER_COUNT, CoreInitError, Counter, core_count, install, snapshot, turn_tick, with,
};
pub use plane::{
    ControlPlane, DataPlane, MAX_BLOCKING_THREADS, RuntimeConfig, RuntimeError, RuntimeMode,
};
