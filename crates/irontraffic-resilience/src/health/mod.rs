// SPDX-License-Identifier: MIT OR Apache-2.0

//! Active health checking: scheduling substrate for endpoint checks.
//!
//! [`wheel`] is the four-level hierarchical timing wheel that schedules and
//! reschedules up to hundreds of thousands of endpoint checks without spawning
//! one tokio timer per endpoint. Later issues in this milestone (the endpoint
//! bitmap, the scheduling policy, and the HTTP/TCP checkers) add their own
//! `pub mod` lines here; this issue creates only the wheel.

pub mod bitmap;
pub mod wheel;

pub use bitmap::{ClusterHealth, EndpointHealth, HealthBitmap};
pub use wheel::TimerWheel;
