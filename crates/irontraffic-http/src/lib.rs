// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]
//! `irontraffic-http`: the sans-IO crate that owns every HTTP parse decision
//! in IronTraffic.
//!
//! IronTraffic sits between an untrusted network and a trusted origin. This
//! crate is the single place where attacker-chosen bytes are turned into a
//! decision about what a request is. Two structural rules govern it and are
//! non-negotiable:
//!
//! 1. **No I/O.** This crate never reads a socket, never touches the
//!    filesystem, never spawns a task and never reads a clock. Every parse
//!    function takes `&[u8]` that the caller already has and returns either a
//!    value or a [`RejectReason`]. That is what makes the parsers fuzzable at
//!    millions of cases per minute, and it is what lets the same parser serve
//!    HTTP/1, HTTP/2 and HTTP/3 ingress.
//! 2. **Every refusal is nameable.** [`RejectReason`] is a closed enum with
//!    one variant per distinct reason a message can be refused, each mapping
//!    to exactly one HTTP status and one stable metric label. See
//!    `docs/THREAT-MODEL.md` section 3 for why the reason never leaves this
//!    process as response bytes.
//!
//! This crate is `std` (later issues in this milestone use the value types
//! `std::net::IpAddr` and `std::net::SocketAddr`) but has zero I/O
//! dependencies: no socket type, no filesystem, no clock, no thread, no
//! process. It is deliberately not `no_std`: the benefit of `no_std` here is
//! zero and the cost is a `#[cfg(test)] extern crate std;` dance in every
//! module.
//!
//! Every value in this crate that is derived from attacker bytes (a length, a
//! count, a running total, a port, a chunk size) is accumulated with
//! `checked_add`, `checked_mul`, `saturating_add` or `saturating_sub`, never
//! with a bare `+`, `*` or `-`; the crate root denies
//! `clippy::arithmetic_side_effects` to enforce that.

pub mod authority;
pub mod error;
pub mod expect;
pub mod field;
pub mod forwarded;
pub mod framing;
pub mod h1;
pub mod hlist;
pub mod known;
pub mod limits;
pub mod response;
pub mod scalar;
pub mod section;
pub mod strip;

pub use error::RejectReason;
pub use limits::{ClampedLimits, Limits};
pub use scalar::{Method, MethodToken, ParseStatus, Scheme, StatusCode, WireVersion};
