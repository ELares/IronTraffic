// SPDX-License-Identifier: MIT OR Apache-2.0

//! Layer 1 of the configuration model: the document an operator writes.
//!
//! Every struct rejects unknown fields. Every scalar is a newtype whose constructor
//! validates it, so a value that exists is a value that is legal.
//!
//! The configuration architecture has three layers and this crate owns the first
//! one: a `SourceDoc` in JSON or YAML, pure `serde` types with
//! `#[serde(deny_unknown_fields)]` and a mandatory `apiVersion` discriminant. The
//! normalised internal representation (layer 2) and the compiled, immutable
//! hot-path snapshot (layer 3) are later milestones and name no type in this
//! crate. Nothing here reads a file, resolves a hostname, or validates a
//! document's meaning (only its shape); the loader and the semantic validator
//! are a later issue.

pub mod model;
pub mod newtypes;

pub use model::{
    BootstrapDoc, DEFAULT_BACKLOG, DEFAULT_CONNECT_MS, DEFAULT_CONTROL_WORKERS,
    DEFAULT_DRAIN_JITTER_MS, DEFAULT_GRACEFUL_MS, DEFAULT_HALF_CLOSE_MS, DEFAULT_IDLE_MS,
    DEFAULT_MAX_CONNECTIONS, LimitSection, ListenerSection, RuntimeSection, ShutdownSection,
    TimeoutSection, UpstreamSection,
};
pub use newtypes::{Backlog, BindAddr, FieldError, ListenerName, Millis, ModeSpec, UpstreamAddr};

/// The only supported `apiVersion` value.
pub const API_VERSION: &str = "irontraffic.io/v1";
