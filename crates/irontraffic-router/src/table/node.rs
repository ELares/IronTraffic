// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-size arena records for the compiled route table.
//!
//! Every record here is `#[repr(C)]` with its size asserted at compile time, because
//! the sizes are load bearing: [`PathNode`] is 24 bytes so two to three fit in a
//! 64-byte cache line, and [`Cand`] and [`Pred`] are 16 bytes so four fit. See
//! `table/mod.rs` for why this crate stores indices into flat arenas instead of
//! pointers.

use crate::ids::{ActionId, GroupId, NameId};
use crate::precedence::Precedence;

/// Maximum predicates one candidate's run may hold. `Group::preds_from` stops
/// scanning after this many records even if no `PRED_LAST` was found, so a
/// corrupted arena cannot make the scan loop forever.
pub const MAX_PREDS_PER_CAND: usize = 64;

/// One node of a group's compressed path radix trie. Exactly 24 bytes.
///
/// `key_len` is the length of the node's FULL key (the concatenation of every edge
/// label from the root), not of its own edge label. The match path needs the full
/// length for the segment-boundary check and for `matched_prefix_len`, and storing
/// it removes an accumulator from the `up` walk.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PathNode {
    /// Offset into `Group::blob` of this node's edge label.
    pub blob_off: u32,
    /// Index into `Group::child_bytes` and `Group::child_nodes` of this node's first
    /// child slot. Meaning depends on `NODE_DENSE`.
    pub children: u32,
    /// Index into `Group::cands` of this node's first candidate.
    pub cands: u32,
    /// Index in `Group::nodes` of the nearest STRICT ancestor that owns at least one
    /// candidate, or `SENTINEL` when no such ancestor exists.
    ///
    /// This field is half of why Gateway API's "Exact beats longest Prefix" and this
    /// crate's "trie depth outranks `PathKind`" cannot disagree in practice: for a
    /// request path P, an Exact match E matches only when E equals P, so its node is
    /// the deepest node on P's walk; any Prefix X matching P has X a segment-prefix
    /// of P, so depth(X) <= depth(P), with equality only when X equals P, at which
    /// point both candidates sit on the SAME node and `Precedence`'s `PathKind` bits
    /// (top of the packed u64, `precedence-u64-and-ordinals` #49) give Exact the win.
    /// That argument holds only while a future descent (`path-descent-and-visit-
    /// budget` #54, `match-request-core` #60) visits the deepest matching node
    /// first, then strictly shallower ancestors, and Exact candidates are attached
    /// at full depth. `up` being constrained to a STRICTLY shallower, non-empty
    /// ancestor (enforced by `validate`'s `UpLink` check) is what makes "then
    /// strictly shallower" true by construction rather than by a descent
    /// implementer's care; the other half (deepest-first, and Exact attached at
    /// full depth) is `#53`'s and `#54`'s to preserve, not this issue's to enforce.
    pub up: u32,
    /// Length of this node's edge label in bytes.
    pub blob_len: u16,
    /// Number of candidates this node owns.
    pub cand_n: u16,
    /// Length of this node's full key in bytes.
    pub key_len: u16,
    /// Number of children.
    pub child_n: u8,
    /// See the `node_flags` constants.
    pub flags: u8,
}

const _: () = assert!(core::mem::size_of::<PathNode>() == 24);
const _: () = assert!(core::mem::align_of::<PathNode>() == 4);

/// Bit flags for `PathNode::flags`.
pub mod node_flags {
    /// `children` indexes a 256-entry dense table in `Group::child_nodes` rather
    /// than a `child_n`-entry pair of parallel arrays. Set when `child_n > 16`.
    pub const NODE_DENSE: u8 = 1 << 0;
    /// This node owns exactly one candidate and that candidate is unconditional
    /// (`Cand::preds == SENTINEL`). The match path branches on this once to reach a
    /// branchless return for the overwhelmingly common shape.
    pub const NODE_SINGLE_UNCOND: u8 = 1 << 1;
    /// This node owns at least one candidate whose path kind is `SegmentPrefix` or
    /// `RootDefault`, so the segment-boundary check is required.
    pub const NODE_HAS_PREFIX: u8 = 1 << 2;
    /// This node owns at least one candidate whose path kind is `Exact`.
    pub const NODE_HAS_EXACT: u8 = 1 << 3;
    /// This node's candidate list is fronted by a synthesized discriminator, and
    /// `Group::disc_for_node(node_idx)` resolves it. Set only by
    /// `discriminator-synthesis` (#62).
    pub const NODE_HAS_DISC: u8 = 1 << 4;
}

/// One route candidate owned by a trie node. Exactly 16 bytes.
///
/// A node's candidates are contiguous in `Group::cands` starting at
/// `PathNode::cands` and are sorted STRICTLY DESCENDING by `prec`. The match path
/// returns the first one whose predicates pass; it never sorts and never compares
/// two `Precedence` values.
///
/// `RouteId` is NOT in `Cand`, because that would make the record 20 bytes and
/// break the four-per-line property. It lives in `Group::cand_routes`, a parallel
/// array read exactly once, on a successful match.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cand {
    /// Build-time precedence. Globally unique across the whole table.
    pub prec: Precedence,
    /// Index into `Group::preds` of this candidate's first predicate, or `SENTINEL`
    /// when the candidate is unconditional.
    pub preds: u32,
    /// Opaque action handle, returned on a match.
    pub action: ActionId,
}

const _: () = assert!(core::mem::size_of::<Cand>() == 16);

/// One predicate. Exactly 16 bytes.
///
/// A candidate's predicates are contiguous in `Group::preds` starting at
/// `Cand::preds`, ordered cheapest and most selective first, and the last one has
/// `PRED_LAST` set in `tag`. There is no length field: the flag terminates the run.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Pred {
    /// See the `pred_flags` constants. Currently only `PRED_LAST`.
    pub tag: u8,
    /// The `PredOp` discriminant. Read through `PredOp::from_u8`.
    pub op: u8,
    /// Interned header or query parameter name, or `NameId::NONE` when the op names
    /// neither.
    pub a: NameId,
    /// Offset into `Group::blob` of the literal this predicate compares against,
    /// or 0 when the op has no literal.
    pub b: u32,
    /// Length of that literal in bytes, or 0.
    pub c: u32,
    /// Method mask for `PredOp::Method`, 0 otherwise.
    pub d: u32,
}

const _: () = assert!(core::mem::size_of::<Pred>() == 16);

/// Bit flags for `Pred::tag`.
pub mod pred_flags {
    /// This is the last predicate of its candidate.
    pub const PRED_LAST: u8 = 1 << 0;
}

/// What a predicate tests. Negation is a distinct op, not a flag, so that there is
/// exactly one spelling of each test and the evaluator has no flag to branch on.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PredOp {
    /// `req.method` intersects `Pred::d`.
    Method = 0,
    /// The header named by `a` is present and its value equals the literal.
    HeaderExact = 1,
    /// The header named by `a` is present, with any value.
    HeaderPresent = 2,
    /// The header named by `a` is absent.
    HeaderAbsent = 3,
    /// The query parameter named by `a` is present and its value equals the literal.
    QueryExact = 4,
    /// The query parameter named by `a` is present, with any value.
    QueryPresent = 5,
}

impl PredOp {
    /// The inverse of the `#[repr(u8)]` discriminant, spelled out as a `match` and
    /// never a transmute. Values 6 and above return `None`, which the evaluator
    /// (a later issue) treats as a failed predicate rather than a panic.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<PredOp> {
        match v {
            0 => Some(PredOp::Method),
            1 => Some(PredOp::HeaderExact),
            2 => Some(PredOp::HeaderPresent),
            3 => Some(PredOp::HeaderAbsent),
            4 => Some(PredOp::QueryExact),
            5 => Some(PredOp::QueryPresent),
            _ => None,
        }
    }
}

/// One node of the reversed-label host trie. Exactly 32 bytes.
///
/// Defined here, even though nothing reads it until `host-trie-and-group-chain`
/// (#55), because its layout is a layout decision and every layout decision in
/// this crate belongs in this one file where the `size_of` assertions live.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HostNode {
    /// Bitmask of the certificates whose SAN set covers the EXACT host pattern that
    /// terminates at this node, or 0 when no exact pattern does. Bits 0 to 62 mean
    /// `CertId(0)` to `CertId(62)`. Bit 63 is NOT a certificate: it is the overflow
    /// marker, set only when at least one covering certificate has an id of 63 or
    /// above, whose ids live in a sorted side list. So 63 certificates fit in the
    /// pure bitmask and a 64th forces the overflow path.
    ///
    /// The mask for the WILDCARD pattern that may terminate at the same node lives in
    /// the parallel `RouteTable::host_wild_cert_mask` array, NOT here, because
    /// `example.com` and `*.example.com` produce the same trie key and their covering
    /// certificate sets are different sets: merging them would let a certificate
    /// issued for the apex authorize every subdomain and vice versa. Masks are also
    /// never inherited from an ancestor node; see `host-trie-and-group-chain` (#55).
    pub cert_mask: u64,
    /// Offset into `RouteTable::host_blob` of this node's edge label.
    pub blob_off: u32,
    /// Index into the host child arrays of this node's first child slot.
    pub children: u32,
    /// Chain head when the request key ends exactly here, or `GroupId::NONE`.
    pub exact_chain: GroupId,
    /// Chain head when the request key extends strictly past here at a label
    /// boundary, or `GroupId::NONE`.
    pub wild_chain: GroupId,
    /// Length of this node's edge label.
    pub blob_len: u16,
    /// Number of children.
    pub child_n: u16,
    /// See `host_flags`.
    pub flags: u16,
    /// Padding, always zero, so that the layout is explicit rather than inferred.
    #[allow(
        clippy::pub_underscore_fields,
        reason = "the leading underscore documents that this field is intentionally unread padding, not a sign it should be private or renamed; it must stay pub and part of HostNode's public 32-byte layout for host-trie-and-group-chain (#55) to construct"
    )]
    pub _pad: u16,
}

const _: () = assert!(core::mem::size_of::<HostNode>() == 32);

/// Bit flags for `HostNode::flags`.
pub mod host_flags {
    /// `children` indexes a 256-entry dense table.
    pub const HOST_DENSE: u16 = 1 << 0;
    /// This node's key ends at a label boundary, so it is eligible to be a wildcard
    /// or exact match target.
    pub const HOST_LABEL_END: u16 = 1 << 1;
    /// The EXACT pattern at this node is covered by at least one certificate whose
    /// `CertId` is 63 or above, so `cert_mask` bit 63 is set as a marker and the real
    /// answer for those ids comes from the sorted overflow list. Never set when the
    /// covering certificates all have ids below 63.
    pub const HOST_CERT_OVERFLOW_EXACT: u16 = 1 << 2;
    /// The listener catch-all pattern (`HostPattern::Any`) terminates at this node.
    /// The catch-all names no hostname, so there is nothing for the certificate
    /// coverage check to compare against and that check is skipped for a request that
    /// resolves through it; see `sni-scope-and-misdirected-request` (#63).
    pub const HOST_CATCH_ALL: u16 = 1 << 3;
    /// As `HOST_CERT_OVERFLOW_EXACT`, but for the WILDCARD pattern at this node,
    /// whose mask lives in `RouteTable::host_wild_cert_mask`.
    pub const HOST_CERT_OVERFLOW_WILD: u16 = 1 << 4;
}

#[cfg(test)]
mod tests {
    use super::{Cand, HostNode, Pred, PredOp};

    #[test]
    fn record_sizes() {
        assert_eq!(core::mem::size_of::<super::PathNode>(), 24);
        assert_eq!(core::mem::align_of::<super::PathNode>(), 4);
        assert_eq!(core::mem::size_of::<Cand>(), 16);
        assert_eq!(core::mem::size_of::<Pred>(), 16);
        assert_eq!(core::mem::size_of::<HostNode>(), 32);
    }

    #[test]
    fn pred_op_round_trip() {
        // No wildcard arm: adding a seventh `PredOp` variant makes this match
        // non-exhaustive and fails to compile, so this test cannot go silently
        // stale the way a `_ => ...` fallback would let it.
        fn all_ops() -> [PredOp; 6] {
            let sample = PredOp::Method;
            match sample {
                PredOp::Method
                | PredOp::HeaderExact
                | PredOp::HeaderPresent
                | PredOp::HeaderAbsent
                | PredOp::QueryExact
                | PredOp::QueryPresent => [
                    PredOp::Method,
                    PredOp::HeaderExact,
                    PredOp::HeaderPresent,
                    PredOp::HeaderAbsent,
                    PredOp::QueryExact,
                    PredOp::QueryPresent,
                ],
            }
        }

        for op in all_ops() {
            let discriminant = op as u8;
            assert_eq!(PredOp::from_u8(discriminant), Some(op));
        }

        for v in 6..=255u8 {
            assert_eq!(PredOp::from_u8(v), None, "mismatch at {v}");
        }
    }
}
