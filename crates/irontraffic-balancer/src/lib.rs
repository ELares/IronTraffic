// SPDX-License-Identifier: MIT OR Apache-2.0

//! Upstream selection: snapshots, algorithms, and the per-core pick pipeline.
//!
//! Hot-path crate: no lock, no allocation on the request path, no clock read.

pub mod algo;

pub use algo::p2c::{
    CostKind, MAX_EXCLUDE, pick_excluding, pick_least_request, pick_peak_ewma, sample_two,
};
