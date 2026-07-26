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
//! crate.
//!
//! This crate also owns the layer above the document shape: [`load`] resolves the
//! `CLI > environment > file > defaults` precedence ladder, and [`validate`] is the
//! pure, total semantic check over the result. Neither reads a hostname or binds a
//! socket; those are the effectful startup checks of a later issue.

pub mod diagnostic;
pub mod load;
pub mod model;
pub mod newtypes;
pub mod validate;
pub mod v1;

pub use diagnostic::{Diagnostic, Diagnostics, Severity};
pub use load::{
    EnvSource, Format, LoadError, Loaded, MAX_DOC_BYTES, MAX_YAML_ALIASES, MapEnv, Overrides,
    ProcessEnv, load,
};
pub use model::{
    BootstrapDoc, DEFAULT_BACKLOG, DEFAULT_CONNECT_MS, DEFAULT_CONTROL_WORKERS,
    DEFAULT_DRAIN_JITTER_MS, DEFAULT_GRACEFUL_MS, DEFAULT_HALF_CLOSE_MS, DEFAULT_IDLE_MS,
    DEFAULT_MAX_CONNECTIONS, LimitSection, ListenerSection, RuntimeSection, ShutdownSection,
    TimeoutSection, UpstreamSection,
};
pub use newtypes::{Backlog, BindAddr, FieldError, ListenerName, Millis, ModeSpec, UpstreamAddr};
pub use validate::{MAX_LISTENERS, validate};
pub use v1::{
    DYNAMIC_API_VERSION, Extensions, Hostname, MAX_ERROR_ECHO_BYTES, MAX_EXTENSION_DEPTH,
    MAX_EXTENSION_KEY_BYTES, MAX_EXTENSION_KEYS, MAX_EXTENSIONS_BYTES, MAX_REF_BYTES, NameError,
    Named, Namespace, ProviderName, ResourceName, ResourceRef, Weight,
};

/// The only supported `apiVersion` value.
pub const API_VERSION: &str = "irontraffic.io/v1";
