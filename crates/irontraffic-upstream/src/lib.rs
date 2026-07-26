// SPDX-License-Identifier: MIT OR Apache-2.0

//! The upstream side of the data plane.
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

pub use connector::{ConnectError, SingleUpstream};
