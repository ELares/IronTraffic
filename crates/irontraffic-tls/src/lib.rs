// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS termination and certificate handling for IronTraffic.
//!
//! This crate is the only crate in the workspace permitted to name a `rustls::` type.
//! Every public item here is an IronTraffic type. rustls 0.24 renames `ResolvesServerCert`
//! to `ServerCredentialResolver` and `ProducesTickets` to `TicketProducer`; that rename must
//! cost one crate, not the whole tree.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod name;
pub mod provider;
pub mod store;
pub mod time;

pub use name::{NameHasher, NameKey};
pub use provider::{
    ProviderError, ProviderKind, fips_active, install_process_provider, post_quantum_available,
    provider_kind,
};
