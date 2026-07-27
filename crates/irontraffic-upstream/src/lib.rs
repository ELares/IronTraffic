// SPDX-License-Identifier: MIT OR Apache-2.0

//! The upstream side of the data plane: endpoint identity, statistics, the
//! process-global endpoint registry, and the single-address connector.
//!
//! Hot-path crate: no lock, no allocation on the request path, no clock read.
//! Every entry point that needs time takes `now_ms: CoarseMillis` from the
//! caller.
//!
//! One configured address, one fresh connection per downstream connection, no pooling,
//! no name resolution, no retries. Load balancing, pooling with the connection-purity
//! rule, health checking, and DNS arrive with the HTTP layer.
//!
//! Descriptor budget: each proxied connection holds one downstream and one upstream
//! descriptor, so the theoretical maximum connection count is
//! `(RLIMIT_NOFILE - reserve) / 2` with a reserve of 64 for listening sockets, file
//! handles, and headroom. The startup path clamps `limits.max_connections` to that
//! figure; a cap above it turns descriptor exhaustion into a stream of upstream
//! connect failures that look exactly like a dead backend.
//!
//! The address dialled is a literal from the configuration file. There is no name to
//! resolve and no attacker-influenced destination, which is why this crate carries no
//! destination policy. The issue that adds a resolver or a dynamic upstream must add
//! one in the same change, applied to the resolved address: loopback, link-local
//! (including 169.254.169.254), and private ranges are otherwise reachable through us.

mod connector;
pub mod health;
pub mod identity;
pub mod registry;
pub mod stats;

pub use connector::{ConnectError, SingleUpstream};
pub use health::EndpointHealth;
pub use identity::{EndpointAddr, EndpointIdentity, MAX_IDENTITY_BYTES};
pub use registry::{
    DEFAULT_CAPACITY, EndpointId, EndpointRegistry, EndpointRegistryWriter, MAX_CAPACITY,
    RECYCLE_BATCH, RECYCLE_GRACE_GENERATIONS, RECYCLE_GRACE_MS, RegistryError,
};
pub use stats::EndpointStats;

/// Milliseconds since process start, as produced by `irontraffic_time`'s
/// `CoarseMono`.
///
/// Wraps every 49.7 days. Every interval derived from it is computed with
/// `wrapping_sub` and is bounded by a window shorter than the wrap period.
pub type CoarseMillis = u32;
