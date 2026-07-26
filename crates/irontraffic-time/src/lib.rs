// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clock types for IronTraffic.
//!
//! This crate is the only place in the workspace permitted to read a clock.
//! The four types below are deliberately not interconvertible: mixing a wall
//! clock with a monotonic clock is a compile error, not a runtime surprise.

#![deny(missing_docs)]

pub mod cache;
pub mod clock;
pub mod source;

pub use cache::{AtomicCoarseCache, CoarseCache};
pub use clock::{Boot, CoarseMono, CoarseWall, PreciseMono};
pub use source::{SharedTime, SystemTimeSource, TestTimeSource, TimeSource};
