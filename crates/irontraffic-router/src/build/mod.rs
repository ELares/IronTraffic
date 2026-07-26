// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds a group's compiled path radix trie from a caller-supplied candidate
//! list.
//!
//! This module is INERT: [`path_trie::build_group`] is called by
//! `builder-admission-and-assemble` (#56), and its output is walked by
//! `path-descent-and-visit-budget` (#54).

use crate::precedence::Precedence;

pub mod path_trie;

pub use path_trie::{CandInput, GroupParts, build_group};

/// Why a group could not be built.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrieBuildError {
    /// More trie nodes than `GroupParts::max_nodes`.
    TooManyNodes {
        /// The limit that was breached.
        limit: u32,
    },
    /// More candidates on one node than a `u16` can count.
    TooManyCandidates,
    /// The literal blob would exceed `GroupParts::max_blob_bytes` (or `u32::MAX`)
    /// bytes. Reported before the offending append, so peak memory stays inside the
    /// budget.
    BlobTooLarge,
    /// A candidate key was longer than `MAX_PATH_BYTES`.
    KeyTooLong,
    /// A candidate key was empty or did not start with `b'/'`. Admission should have
    /// caught this; the builder refuses rather than producing a trie that cannot be
    /// descended.
    KeyNotAbsolute,
    /// Two candidates compared equal on `prec`, which means ordinals were not unique.
    DuplicatePrecedence {
        /// The duplicated value.
        prec: Precedence,
    },
}
