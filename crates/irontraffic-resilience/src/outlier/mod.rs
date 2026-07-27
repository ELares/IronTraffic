// SPDX-License-Identifier: MIT OR Apache-2.0
//! Outlier detection for upstream endpoints.
//!
//! This module is the root that [`stats`] extends: the median-and-MAD robust
//! success-rate ejection threshold, with its documented absolute-gap
//! fallback for the degenerate all-identical case. Two follow-on issues
//! build on it: the per-endpoint counters and detectors that call
//! [`robust_success_rate_threshold`] once per cluster per control tick after
//! applying the request-volume gate, and ejection with its cluster-wide
//! safety valves. This root module owns no state of its own.

pub mod stats;

pub use stats::{
    MAD_TO_SIGMA, RobustThresholdConfig, compact_valid, mad_in_place, median_lower_in_place,
    robust_success_rate_threshold,
};
