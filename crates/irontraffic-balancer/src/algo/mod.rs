// SPDX-License-Identifier: MIT OR Apache-2.0

//! Algorithm module root.
//!
//! [`p2c`] is power-of-two-choices, this milestone's default selection algorithm. Later
//! issues in this milestone add the alias table, Maglev, ring hash, and rendezvous hashing
//! as sibling modules, and an `AlgoState` dispatch enum here that selects among them; none
//! of them exist yet, and no later issue removes a `pub mod` line this one or a prior one
//! added.

pub mod p2c;
