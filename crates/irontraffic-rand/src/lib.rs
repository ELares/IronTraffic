// SPDX-License-Identifier: MIT OR Apache-2.0
//! Randomness for IronTraffic.
//!
//! Two generators, and the split between them is a security boundary.
//!
//! [`Rng`] is fast, seedable, and NOT cryptographic: use it for load balancing,
//! jitter, and sampling, where every decision must be reproducible from a seed so
//! a deterministic simulation can replay a failure. `WyRand` is trivially
//! invertible, so two observed outputs let an attacker predict the rest of the
//! stream. That is acceptable for choosing which of two healthy endpoints gets a
//! request; it is fatal for anything else.
//!
//! The scheduling consumers that draw from [`Rng`] are: power-of-two-choices
//! endpoint sampling, Maglev fallback fill, retry full jitter, hedge timing,
//! health-check jitter, log and trace sampling, and `Retry-After` jitter.
//!
//! [`SecureRng`] reads the operating system CSPRNG and is the ONLY source for
//! anything an attacker must not predict: TLS ticket nonces and keys, session
//! identifiers, API key material, and cookie values. Nothing in that group is
//! seedable, and no deterministic simulation harness may make it seedable. An
//! entropy failure is a fatal startup error, never a fallback to a fixed seed.

pub mod secure;
pub mod wyrand;

pub use secure::{EntropyError, SecureRng};
pub use wyrand::{Rng, split_mix64, wyrand_step};
