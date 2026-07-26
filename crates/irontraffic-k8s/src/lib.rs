// SPDX-License-Identifier: MIT OR Apache-2.0
//! Kubernetes configuration source for IronTraffic.
//!
//! This crate compiles cluster state into the same
//! `irontraffic_config::v1::ConfigDoc` that a YAML file compiles into. It is
//! not a second routing engine and the data plane never depends on it to keep
//! serving.
//!
//! The vocabulary defined here is deliberately small and interned: every later
//! module in this milestone shares `ObjectKey`, `NamespaceId`, `WatchedKind`,
//! `Uid`, `ResourceVersion` and `UnixSeconds`. Keeping the identity vocabulary in
//! one crate makes the whole controller cheap in memory and comparable in one
//! integer compare.

pub mod error;
pub mod identity;

pub use error::{K8sError, sanitize_for_log};
pub use identity::{
    NamespaceId, NsInterner, ObjectKey, ResourceVersion, Uid, UnixSeconds, WatchedKind,
};

/// The `spec.controllerName` value we claim. A GatewayClass naming anything else
/// is not ours and its Gateways and Routes are dropped at the informer transform.
pub const CONTROLLER_NAME: &str = "irontraffic.io/gateway-controller";

/// The domain every annotation, finalizer name and CRD group of ours lives under.
pub const DOMAIN: &str = "irontraffic.io";

/// The largest number of distinct namespaces one process will intern. The
/// interner never shrinks, so this is what bounds its memory: under 8 MB at the
/// cap. Beyond it, `NsInterner::intern` returns `NamespaceId::INVALID` and the
/// object is dropped with a diagnostic.
pub const MAX_NAMESPACES: usize = 65_536;

/// The largest `metadata.name` we accept, in bytes. This is the DNS subdomain
/// limit the API server enforces. Views reject longer names; nothing ever
/// truncates a name, because truncation aliases two distinct objects onto one
/// `ObjectKey`.
pub const MAX_NAME_BYTES: usize = 253;
