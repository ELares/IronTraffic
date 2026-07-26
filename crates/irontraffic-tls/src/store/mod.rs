// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate credential storage: content-addressed chain interning plus load-time key
//! matching.
//!
//! [`Credentials`] is the loaded-and-validated form of one certificate chain and its private
//! key. [`ChainInterner`] is the content-addressed store that lets many chains that share a
//! common intermediate hold one copy of it instead of one copy each.
//!
//! This module is deliberately inert: nothing here builds an index or a name-to-credential
//! map, and nothing in this crate calls [`Credentials::load`] yet. The certificate index that
//! consumes it is a later issue; this module compiles, is fully tested, and is wired in there.

mod arena;
mod cred;

// `MAX_DER_BYTES` is arena's own bound (it caps a single interned blob), but `Credentials::load`
// also uses the identical constant to cap every blob in a chain, leaf included, so it lives in
// arena and is re-exported here rather than duplicated.
pub use arena::{BlobHash, ChainInterner, MAX_DER_BYTES};
pub use cred::{
    CertError, CertFingerprint, Credentials, KeyType, MAX_CHAIN_DEPTH, MAX_SANS, MAX_STAPLE_BYTES,
};
