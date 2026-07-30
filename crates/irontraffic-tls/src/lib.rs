// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS termination and certificate handling for IronTraffic.
//!
//! This crate is the only crate in the workspace permitted to name a `rustls::` type.
//! Every public item here is an IronTraffic type. rustls 0.24 renames `ResolvesServerCert`
//! to `ServerCredentialResolver` and `ProducesTickets` to `TicketProducer`; that rename must
//! cost one crate, not the whole tree.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod crl;
pub mod early_data;
pub mod hkdf;
pub mod listener;
pub mod name;
pub mod ocsp;
pub mod ocsp_update;
pub mod policy;
pub mod provider;
pub mod replay;
pub mod store;
pub mod ticket;
pub mod time;
pub mod upstream;
pub mod verify_client;

pub use listener::{
    AcceptStep, AcceptedHello, ClientAuthKind, DEFAULT_MAX_CLIENT_HELLO_BYTES, HandshakeLimits,
    ListenerError, ListenerStats, ListenerTls, ListenerTlsBuilder, MAX_BINDINGS, RejectReason,
    SniAcceptor, TlsServerConfig,
};
pub use name::{NameHasher, NameKey};
pub use policy::{TlsPolicy, TlsProfile};
pub use provider::{
    ProviderError, ProviderKind, fips_active, install_process_provider, post_quantum_available,
    provider_kind,
};
pub use store::{
    CertIndex, CertIndexBuilder, ChallengeCerts, ChallengeCertsBuilder, ClientCaps, IronResolver,
};
pub use ticket::{ClusterTicketer, TicketRoot};
pub use upstream::{
    DEFAULT_PQ_SUPPRESS_SECS, MAX_ACCEPTED_SANS, MAX_PEER_SANS, MAX_URI_SAN_BYTES, PqState,
    SubjectAltName, UpstreamPq, UpstreamTls, UpstreamTlsConfig, UpstreamTlsError, UpstreamTlsStats,
    UpstreamVerifier, VerifyMode, WellKnownCa,
};
pub use verify_client::{ClientAuth, TrustAnchors};
