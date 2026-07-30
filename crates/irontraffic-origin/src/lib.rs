// SPDX-License-Identifier: MIT OR Apache-2.0
//! `it-origin`: a trivial HTTP/1.1 upstream whose per-request cost is known,
//! constant and allocation-free.
//!
//! `it-origin` is a binary; its API is its command line and its wire
//! behaviour. This library surface exists so tests can drive the handler
//! without a socket, and so `benches/scan.rs` and
//! `fuzz/fuzz_targets/fuzz_scan_head.rs` can link against
//! [`serve::scan_head`] directly. `main.rs` is a thin shell over it, exactly
//! like `crates/irontraffic/src/lib.rs`.
//!
//! Added during implementation rather than present in issue #409's original
//! Files table: a `[[bin]]`-only package exposes nothing to an integration
//! test, a bench, or a separate fuzz crate, and the Public API section's own
//! sentence ("The library surface exists so tests can drive the handler
//! without a socket") requires exactly this file to exist. See the issue's
//! Files table, amended accordingly, and the implementation-note comment on
//! the issue.

pub mod config;
pub mod response;
pub mod serve;
