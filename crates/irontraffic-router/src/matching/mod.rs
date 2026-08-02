// SPDX-License-Identifier: MIT OR Apache-2.0

//! Request matching: the path-trie descent this issue adds
//! ([`path::descend`]), and, beside it in later issues, the candidate scan,
//! predicate evaluation and overall `match_request` orchestration.
//!
//! This module is INERT: nothing in this crate calls [`path::descend`] yet.
//! `match-request-core` (#60) is the caller.

pub mod path;
