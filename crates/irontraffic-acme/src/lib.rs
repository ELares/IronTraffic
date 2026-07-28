// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACME client lifecycle for IronTraffic.
//!
//! This crate implements RFC 8555 directory discovery, account
//! registration (with External Account Binding), credential
//! persistence, and account deactivation. It wraps
//! `instant-acme` and adds IronTraffic-specific configuration
//! and error types.
//!
//! # Control-plane only
//!
//! This crate is **control-plane-only**. It is never linked into the
//! request path. The `tokio` dependency is only for the HTTP client
//! (`time` and `fs` features) used by `AcmeDirectory::fetch` and
//! `AcmeAccount::create`; no function in this crate spawns a task.

#![deny(missing_docs)]
#![allow(
    clippy::pedantic,
    reason = "pedantic is warn in workspace; denied in CI"
)]

pub mod account;
pub mod config;
