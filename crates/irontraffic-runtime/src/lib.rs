// SPDX-License-Identifier: MIT OR Apache-2.0
//! Runtime construction for IronTraffic.
//!
//! This crate and `irontraffic-io` are the only crates permitted to name `tokio`.

pub mod cgroup;

pub use cgroup::{MAX_WORKERS, QuotaSource, WorkerDerivation, derive_workers, host_parallelism};
