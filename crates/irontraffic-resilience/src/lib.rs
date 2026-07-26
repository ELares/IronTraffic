// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resilience primitives for IronTraffic: active health checking, outlier detection,
//! resource limits, endpoint circuit breaking, retries, deadlines, adaptive
//! concurrency, and load shedding.
//!
//! This crate never reads a clock and never draws entropy on its own. Every function
//! that needs the current time takes it as a [`clock::Millis`] parameter, and every
//! function that needs randomness takes `&mut irontraffic_rand::Rng`.

pub mod clock;
pub mod config;
pub mod deadline;
pub mod ids;
pub mod limits;
pub mod pressure;
pub mod rng;
