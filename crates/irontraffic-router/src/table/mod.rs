// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compiled, immutable route table: [`RouteTable`], [`Group`], and the
//! bounds-checked accessors every later issue reads the arenas through.
//!
//! The route table is read billions of times and written seconds apart. That
//! ratio demands copy on write: the table is built once, published by a single
//! atomic pointer store, and never touched again. There is no `&mut self` method
//! on [`RouteTable`], no `Cell`, no `RefCell`, no `Mutex`, and no atomic counter
//! embedded in it, which is the structural property that makes a config swap
//! atomic and a torn read impossible. Statistics live outside the table.
//!
//! Everything is an index into a flat arena. There are no pointers, no
//! `Box<Node>`, no `Rc`, and therefore no `unsafe`.
//!
//! This module is INERT: it defines types and accessors, and is called by
//! nothing yet. `match-request-core` (#60) wires it into the matcher.

use std::sync::Arc;

use crate::ids::{ActionId, GroupId, NodeId, RouteId, SENTINEL};
use crate::intern::CompiledNameSet;
use crate::precedence::{PathKind, Precedence};

pub mod node;

pub use node::{
    Cand, HostNode, MAX_PREDS_PER_CAND, PathNode, Pred, PredOp, host_flags, node_flags, pred_flags,
};

/// One `(listener, host pattern)` scope: its own path trie and its own arenas.
///
/// Groups are the unit of incremental rebuild. An unchanged group is `Arc`-cloned
/// into the next table generation, which is why the arenas are per group rather than
/// one arena for the whole table.
#[derive(Debug)]
pub struct Group {
    /// Node arena in preorder. Index 0 is the root, whose `key_len` is 0.
    pub nodes: Box<[PathNode]>,
    /// First byte of each child's edge label, parallel to `child_nodes`. Unused for
    /// nodes with `NODE_DENSE`.
    pub child_bytes: Box<[u8]>,
    /// Child node indices. For a `NODE_DENSE` node, a 256-entry block indexed by the
    /// dispatch byte, holding `SENTINEL` for absent children.
    pub child_nodes: Box<[u32]>,
    /// Candidate arena. Each node's slice is sorted strictly descending by `prec`.
    pub cands: Box<[Cand]>,
    /// Route id per candidate, parallel to `cands`. Read only on a successful match.
    pub cand_routes: Box<[RouteId]>,
    /// Path kind per candidate, parallel to `cands`. Read during the candidate scan
    /// to apply the right path check, so it is a separate byte array rather than a
    /// field in the 16-byte `Cand`.
    pub cand_kinds: Box<[u8]>,
    /// Predicate arena.
    pub preds: Box<[Pred]>,
    /// Literal bytes: every edge label and every predicate literal.
    pub blob: Box<[u8]>,
    /// The next group in this group's fallthrough chain, or `GroupId::NONE`.
    ///
    /// Precomputed at build in Gateway API host-specificity order: an exact
    /// hostname's successor is the longest matching wildcard, a wildcard's successor
    /// is the next shorter matching wildcard, and the last wildcard's successor is
    /// the listener catch-all.
    pub next: GroupId,
    /// Content hash of everything this group was built from. Two builds of the same
    /// input produce the same hash, and `rebuild_from` reuses a group whose hash is
    /// unchanged.
    ///
    /// It is 128 bits and not 64, because the bytes it covers are tenant-supplied in
    /// a Gateway API cluster and a hash equality is what authorizes reusing the
    /// PREVIOUS generation's group. A 64-bit non-cryptographic hash is collidable
    /// with about 2^32 offline work, which would let a tenant who shares a hostname
    /// with another tenant craft a route whose addition leaves the group hash
    /// unchanged, silently suppressing the other tenant's update. At 128 bits that
    /// work is about 2^64 and the attack is not practical.
    pub content_hash: u128,
}

impl Group {
    /// The node at `id`, or `None` if `id` is out of range.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&PathNode> {
        self.nodes.get(id.idx())
    }

    /// This node's edge label, or an empty slice if the arena is inconsistent.
    #[must_use]
    pub fn label(&self, node: &PathNode) -> &[u8] {
        let start = node.blob_off as usize;
        let Some(end) = start.checked_add(node.blob_len as usize) else {
            return &[];
        };
        self.blob.get(start..end).unwrap_or(&[])
    }

    /// This node's candidate slice, empty when it owns none.
    #[must_use]
    pub fn cands_of(&self, node: &PathNode) -> &[Cand] {
        let start = node.cands as usize;
        let Some(end) = start.checked_add(node.cand_n as usize) else {
            return &[];
        };
        self.cands.get(start..end).unwrap_or(&[])
    }

    /// The route id of the candidate at absolute index `i`.
    #[must_use]
    pub fn cand_route(&self, i: u32) -> Option<RouteId> {
        self.cand_routes.get(i as usize).copied()
    }

    /// The path kind of the candidate at absolute index `i`.
    ///
    /// Reads `cand_kinds[i]` and maps it through `PathKind::from_u8`; returns `None`
    /// when `i` is out of range OR when the stored byte is not 1, 3, 5 or 7.
    #[must_use]
    pub fn cand_kind(&self, i: u32) -> Option<PathKind> {
        self.cand_kinds
            .get(i as usize)
            .copied()
            .and_then(PathKind::from_u8)
    }

    /// The predicate run starting at `start`, terminated by `PRED_LAST`, capped at
    /// `MAX_PREDS_PER_CAND` records so a corrupted arena cannot loop forever. Returns
    /// an empty slice when no terminator is found within the cap, which makes the
    /// candidate fail rather than match.
    #[must_use]
    pub fn preds_from(&self, start: u32) -> &[Pred] {
        let start = start as usize;
        let Some(end) = self.pred_run_end(start) else {
            return &[];
        };
        let Some(slice_end) = end.checked_add(1) else {
            return &[];
        };
        self.preds.get(start..slice_end).unwrap_or(&[])
    }

    /// A predicate literal.
    #[must_use]
    pub fn literal(&self, p: &Pred) -> &[u8] {
        let start = p.b as usize;
        let Some(end) = start.checked_add(p.c as usize) else {
            return &[];
        };
        self.blob.get(start..end).unwrap_or(&[])
    }

    /// The child node reached from `node` by byte `b`, or `None`.
    #[must_use]
    pub fn child(&self, node: &PathNode, b: u8) -> Option<NodeId> {
        if node.flags & node_flags::NODE_DENSE != 0 {
            let start = node.children as usize;
            let idx = start.checked_add(b as usize)?;
            let v = *self.child_nodes.get(idx)?;
            if v == SENTINEL { None } else { Some(NodeId(v)) }
        } else {
            let start = node.children as usize;
            let end = start.checked_add(node.child_n as usize)?;
            let bytes = self.child_bytes.get(start..end)?;
            let pos = bytes.iter().position(|&x| x == b)?;
            let idx = start.checked_add(pos)?;
            let v = *self.child_nodes.get(idx)?;
            Some(NodeId(v))
        }
    }

    /// Scans forward from `start` for the record with `PRED_LAST` set, stopping
    /// after at most `MAX_PREDS_PER_CAND` records or at the end of the arena.
    /// Returns the inclusive end index, or `None` when no terminator was found
    /// within the cap. Shared by `preds_from` and `validate` so the two cannot
    /// drift apart.
    fn pred_run_end(&self, start: usize) -> Option<usize> {
        for i in 0..MAX_PREDS_PER_CAND {
            let idx = start.checked_add(i)?;
            let p = self.preds.get(idx)?;
            if p.tag & pred_flags::PRED_LAST != 0 {
                return Some(idx);
            }
        }
        None
    }

    /// Every present child id of `node`, in arena order. Used only by `validate`'s
    /// reachability walk, so it may allocate; the request-path `child` accessor
    /// above never does.
    fn child_ids(&self, node: PathNode) -> Vec<NodeId> {
        let start = node.children as usize;
        let extent = if node.flags & node_flags::NODE_DENSE != 0 {
            256usize
        } else {
            node.child_n as usize
        };
        let Some(end) = start.checked_add(extent) else {
            return Vec::new();
        };
        let Some(slice) = self.child_nodes.get(start..end) else {
            return Vec::new();
        };
        if node.flags & node_flags::NODE_DENSE != 0 {
            slice
                .iter()
                .filter(|&&v| v != SENTINEL)
                .map(|&v| NodeId(v))
                .collect()
        } else {
            slice.iter().map(|&v| NodeId(v)).collect()
        }
    }
}

/// The compiled, immutable route table.
///
/// Built once per configuration generation, published with a single atomic pointer
/// store, and NEVER mutated. There is deliberately no `&mut self` method on this
/// type, no interior mutability, and no embedded counter: statistics live outside.
/// An in-flight request holds its `Arc`, so a swap cannot tear its view.
///
/// `RouteTable` grows exactly three more times in this milestone, and each addition
/// is declared in the Files table of the issue that makes it: `host-trie-and-group-chain`
/// (#55) adds the five host trie arena fields, `interned-header-name-set` (#52) adds
/// the two `CompiledNameSet` fields, and `path-regex-multipattern` (#61) adds the
/// multi-pattern automaton.
#[derive(Debug)]
pub struct RouteTable {
    groups: Box<[Arc<Group>]>,
    generation: u64,
    needs_query: bool,
    header_names: CompiledNameSet,
    query_names: CompiledNameSet,
}

// I17: RouteTable is Send + Sync because every field is, and it has no interior
// mutability. A swap publishes a new Arc<RouteTable>; an in-flight request holds
// its own Arc and cannot observe a torn table.
const _: fn() = || {
    fn f<T: Send + Sync>() {}
    f::<RouteTable>();
};

impl RouteTable {
    /// The configuration generation this table was built for. Strictly increasing
    /// across published tables; `MatchScratch` resizes when it changes.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// The group at `id`, or `None`.
    #[must_use]
    pub fn group(&self, id: GroupId) -> Option<&Group> {
        self.groups.get(id.idx()).map(|g| &**g)
    }

    /// True when at least one predicate in the table inspects a query parameter.
    /// When false the match path never parses the query string at all.
    #[must_use]
    pub fn needs_query(&self) -> bool {
        self.needs_query
    }

    /// The interned header-name set. Header parsing calls `lookup` on it once per
    /// header.
    #[must_use]
    pub fn header_names(&self) -> &CompiledNameSet {
        &self.header_names
    }

    /// The interned query-parameter-name set.
    #[must_use]
    pub fn query_names(&self) -> &CompiledNameSet {
        &self.query_names
    }

    /// Number of interned header names, which is the length `MatchScratch` sizes its
    /// slot array to.
    #[must_use]
    pub fn interned_header_count(&self) -> usize {
        self.header_names.count()
    }

    /// Structural self-check. Returns every violation found, empty on success.
    /// Called behind `debug_assert!` at the end of `build()` and unconditionally by
    /// tests. O(N + C + P); never call it on the request path.
    #[must_use]
    pub fn validate(&self) -> Vec<ValidateError> {
        let mut errors = Vec::new();
        let mut all_precedences: Vec<Precedence> = Vec::new();
        for (group_idx, group) in self.groups.iter().enumerate() {
            validate_group(group, group_idx, &mut errors, &mut all_precedences);
        }
        validate_global_precedence(&all_precedences, &mut errors);
        errors
    }

    /// Test-only constructor that assembles a table from raw arenas.
    ///
    /// This exists so that the trie, descent, predicate and discriminator issues can
    /// unit-test against hand-built tables before the builder exists. It is
    /// `#[cfg(any(test, feature = "test-util"))]` and is NOT part of the shipped API.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn from_parts(parts: TableParts) -> RouteTable {
        RouteTable {
            groups: parts.groups.into_iter().map(Arc::new).collect(),
            generation: parts.generation,
            needs_query: parts.needs_query,
            header_names: parts.header_names,
            query_names: parts.query_names,
        }
    }
}

/// What a successful match returns. `Copy`, borrows nothing, so the caller can drop
/// its table handle immediately after matching.
///
/// Returning a `Copy` value rather than a borrowed `Action` is deliberate. The
/// router does not own actions, so it has nothing to lend; and a borrow of the
/// table would force every caller to keep its `Arc` alive for the whole request
/// even when it only needs a `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MatchOutcome {
    /// Precedence of the winning candidate. Exposed for the explain surface and for
    /// the differential oracle; the match path itself never compares it.
    pub precedence: Precedence,
    /// The action the winner selects.
    pub action: ActionId,
    /// The route the winner came from.
    pub route: RouteId,
    /// Length of the literal path prefix that matched, which is what a
    /// `ReplacePrefixMatch` URL rewrite replaces. Equals the winning node's
    /// `key_len` for a prefix match and the full path length for an exact match.
    pub matched_prefix_len: u16,
    /// The group the winner came from, for the explain surface.
    pub group: GroupId,
}

/// The raw arenas `from_parts` assembles. Every field has a `Default`, so a test
/// sets only what it cares about.
///
/// Later issues add fields here as they add fields to `RouteTable`:
/// `interned-header-name-set` (#52) adds `header_names` and `query_names`,
/// `host-trie-and-group-chain` (#55) adds the five host arena fields, and
/// `path-regex-multipattern` (#61) adds `regexes`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct TableParts {
    /// The groups, in `GroupId` order.
    pub groups: Vec<Group>,
    /// The configuration generation.
    pub generation: u64,
    /// Whether any predicate inspects a query parameter.
    pub needs_query: bool,
    /// The interned header-name set. Defaults to `CompiledNameSet::empty()`.
    pub header_names: CompiledNameSet,
    /// The interned query-parameter-name set. Defaults to `CompiledNameSet::empty()`.
    pub query_names: CompiledNameSet,
}

/// A structural violation found by `RouteTable::validate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidateError {
    /// Candidate order or uniqueness violated at this group and node.
    CandidateOrder {
        /// Group index.
        group: u32,
        /// Node index.
        node: u32,
    },
    /// Two candidates anywhere in the table share a `Precedence`.
    PrecedenceNotUnique {
        /// The duplicated value.
        prec: Precedence,
    },
    /// `up` pointed at a non-ancestor, a candidate-less node, or formed a cycle.
    UpLink {
        /// Group index.
        group: u32,
        /// Node index.
        node: u32,
    },
    /// A `SegmentPrefix` candidate sits on a node whose key is not segment aligned.
    PrefixNotSegmentAligned {
        /// Group index.
        group: u32,
        /// Node index.
        node: u32,
    },
    /// An index or extent left its arena.
    ArenaBounds {
        /// Group index.
        group: u32,
        /// A short static description of which arena.
        what: &'static str,
    },
    /// A node was unreachable from the root, or reachable more than once.
    Reachability {
        /// Group index.
        group: u32,
        /// Node index.
        node: u32,
    },
    /// A predicate run had no `PRED_LAST` within `MAX_PREDS_PER_CAND`.
    PredRunUnterminated {
        /// Group index.
        group: u32,
        /// Starting predicate index.
        start: u32,
    },
    /// A flag bit disagreed with the arena content it summarizes.
    FlagMismatch {
        /// Group index.
        group: u32,
        /// Node index.
        node: u32,
    },
}

/// Implements invariant I5: a `SegmentPrefix` candidate's node key must be either
/// exactly `b"/"` or must not end with `b'/'`. The last byte of a node's OWN edge
/// label is also the last byte of its full key (the edge label is the tail of the
/// concatenation every ancestor contributes), so this only needs the node's own
/// label, never the reconstructed full key.
fn segment_prefix_aligned(node: PathNode, label: &[u8]) -> bool {
    match label.last() {
        Some(&b'/') => node.key_len == 1,
        None | Some(_) => true,
    }
}

/// Checks invariant I4's one-hop shape: `up` is either `SENTINEL` or an index whose
/// node has a strictly smaller `key_len` and owns at least one candidate.
///
/// PINNED INVARIANT (see `PathNode::up`'s doc for the full argument): trie depth
/// outranking `PathKind` cannot disagree with Gateway API's "Exact beats longest
/// Prefix" only while a descent visits the deepest matching node first, then
/// strictly shallower ancestors, and Exact candidates sit at full depth. This check
/// is what makes "then strictly shallower" a structural fact rather than a hope: it
/// rejects any `up` that is not strictly shallower before the table is ever
/// published, so `match-request-core` (#60) inherits the property for free instead
/// of having to prove it at every descent.
///
/// This single per-edge check, applied to every node, is also what proves the WHOLE
/// group's `up` graph acyclic in one linear pass: `key_len` is a bounded, unsigned
/// quantity that strictly decreases at every edge this check accepts, so a cycle
/// would require it to decrease all the way around back to its own starting value,
/// which is impossible. An explicit bounded walk from every node would prove the
/// same fact in O(N) per node, O(N^2) over the whole group, which would blow the
/// O(N + C + P) budget `validate` documents the moment a group has one long but
/// perfectly valid `up` chain.
fn validate_up_link(
    group: &Group,
    group_u32: u32,
    node_u32: u32,
    node: PathNode,
    errors: &mut Vec<ValidateError>,
) {
    if node.up == SENTINEL {
        return;
    }
    let bad = match group.node(NodeId(node.up)) {
        None => true,
        Some(target) => target.key_len >= node.key_len || target.cand_n == 0,
    };
    if bad {
        errors.push(ValidateError::UpLink {
            group: group_u32,
            node: node_u32,
        });
    }
}

/// Checks the arena extents that involve `node` directly: its children slot, its
/// blob label, and its candidate slice. Every extent is computed with
/// `checked_add`, matching the discipline the request-path accessors use.
///
/// `ArenaBounds` carries no node index (only `group` and a `what` label), so this
/// takes no node index either.
fn validate_node_arena_bounds(
    group: &Group,
    group_u32: u32,
    node: PathNode,
    errors: &mut Vec<ValidateError>,
) {
    let blob_start = node.blob_off as usize;
    let blob_ok = blob_start
        .checked_add(node.blob_len as usize)
        .is_some_and(|end| end <= group.blob.len());
    if !blob_ok {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "blob",
        });
    }

    let cands_start = node.cands as usize;
    let cands_ok = cands_start
        .checked_add(node.cand_n as usize)
        .is_some_and(|end| end <= group.cands.len());
    if !cands_ok {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "cands",
        });
    }

    let children_start = node.children as usize;
    let extent = if node.flags & node_flags::NODE_DENSE != 0 {
        256usize
    } else {
        node.child_n as usize
    };
    let children_ok = children_start
        .checked_add(extent)
        .is_some_and(|end| end <= group.child_nodes.len() && end <= group.child_bytes.len());
    if !children_ok {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "children",
        });
    }
}

/// Walks one node's candidate list, checking I3 (strict descending order), the
/// per-candidate path-kind checks (I5 and the `NODE_HAS_*` flags), and every
/// candidate's predicate run (termination, op validity, literal bounds).
/// Every candidate's `prec` is also appended to `all_precedences` for the
/// whole-table uniqueness check `validate_global_precedence` performs afterward.
fn validate_node_candidates(
    group: &Group,
    group_u32: u32,
    node_u32: u32,
    node: PathNode,
    errors: &mut Vec<ValidateError>,
    all_precedences: &mut Vec<Precedence>,
) {
    let cands = group.cands_of(&node);

    let mut order_ok = true;
    let mut prev: Option<Precedence> = None;
    let mut has_prefix_actual = false;
    let mut has_exact_actual = false;
    let mut node_label: Option<&[u8]> = None;

    for (local_idx, cand) in cands.iter().enumerate() {
        all_precedences.push(cand.prec);

        if let Some(prev_prec) = prev
            && cand.prec >= prev_prec
        {
            order_ok = false;
        }
        prev = Some(cand.prec);

        let Ok(local_u32) = u32::try_from(local_idx) else {
            continue;
        };
        let Some(abs_idx) = node.cands.checked_add(local_u32) else {
            errors.push(ValidateError::ArenaBounds {
                group: group_u32,
                what: "cand index",
            });
            continue;
        };

        if let Some(kind) = group.cand_kind(abs_idx) {
            match kind {
                PathKind::SegmentPrefix => {
                    has_prefix_actual = true;
                    let label = *node_label.get_or_insert_with(|| group.label(&node));
                    if !segment_prefix_aligned(node, label) {
                        errors.push(ValidateError::PrefixNotSegmentAligned {
                            group: group_u32,
                            node: node_u32,
                        });
                    }
                }
                PathKind::RootDefault => has_prefix_actual = true,
                PathKind::Exact => has_exact_actual = true,
                PathKind::Regex => {}
            }
        }

        if cand.preds != SENTINEL {
            validate_pred_run(group, group_u32, cand.preds, errors);
        }
    }

    if !order_ok {
        errors.push(ValidateError::CandidateOrder {
            group: group_u32,
            node: node_u32,
        });
    }

    let single_uncond_actual =
        cands.len() == 1 && cands.first().is_some_and(|c| c.preds == SENTINEL);
    let single_uncond_flag = node.flags & node_flags::NODE_SINGLE_UNCOND != 0;
    if single_uncond_actual != single_uncond_flag {
        errors.push(ValidateError::FlagMismatch {
            group: group_u32,
            node: node_u32,
        });
    }

    let has_prefix_flag = node.flags & node_flags::NODE_HAS_PREFIX != 0;
    let has_exact_flag = node.flags & node_flags::NODE_HAS_EXACT != 0;
    if has_prefix_actual != has_prefix_flag || has_exact_actual != has_exact_flag {
        errors.push(ValidateError::FlagMismatch {
            group: group_u32,
            node: node_u32,
        });
    }
}

/// Checks one candidate's predicate run: termination within `MAX_PREDS_PER_CAND`,
/// every op decoding through `PredOp::from_u8`, and every literal's `b + c` extent
/// within `blob`.
fn validate_pred_run(group: &Group, group_u32: u32, start: u32, errors: &mut Vec<ValidateError>) {
    let Some(end) = group.pred_run_end(start as usize) else {
        errors.push(ValidateError::PredRunUnterminated {
            group: group_u32,
            start,
        });
        return;
    };
    let Some(run) = group.preds.get(start as usize..=end) else {
        return;
    };
    for p in run {
        if PredOp::from_u8(p.op).is_none() {
            errors.push(ValidateError::ArenaBounds {
                group: group_u32,
                what: "pred_op",
            });
        }
        let lit_start = p.b as usize;
        let lit_ok = lit_start
            .checked_add(p.c as usize)
            .is_some_and(|end| end <= group.blob.len());
        if !lit_ok {
            errors.push(ValidateError::ArenaBounds {
                group: group_u32,
                what: "pred_literal",
            });
        }
    }
}

/// Walks the tree from the root, counting how many times each node is reached by
/// exactly one child edge. Every node but the root must be reached exactly once.
fn validate_reachability(group: &Group, group_u32: u32, errors: &mut Vec<ValidateError>) {
    let n = group.nodes.len();
    if n == 0 {
        return;
    }
    let mut visit_count = vec![0u32; n];
    let mut stack = vec![NodeId(0)];
    while let Some(current) = stack.pop() {
        let Some(node) = group.node(current) else {
            continue;
        };
        for child_id in group.child_ids(*node) {
            if let Some(count) = visit_count.get_mut(child_id.idx()) {
                *count = count.saturating_add(1);
                if *count == 1 {
                    stack.push(child_id);
                }
            } else {
                errors.push(ValidateError::ArenaBounds {
                    group: group_u32,
                    what: "child index",
                });
            }
        }
    }
    for (idx, &count) in visit_count.iter().enumerate().skip(1) {
        if count != 1 {
            let Ok(node_u32) = u32::try_from(idx) else {
                continue;
            };
            errors.push(ValidateError::Reachability {
                group: group_u32,
                node: node_u32,
            });
        }
    }
}

/// Runs every per-group structural check: the parallel-array length invariants, the
/// root node's shape, and every node's arena bounds, up-link, and candidates.
fn validate_group(
    group: &Group,
    group_idx: usize,
    errors: &mut Vec<ValidateError>,
    all_precedences: &mut Vec<Precedence>,
) {
    let Ok(group_u32) = u32::try_from(group_idx) else {
        return;
    };

    if group.cand_routes.len() != group.cands.len() || group.cand_kinds.len() != group.cands.len() {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "cand_routes/cand_kinds length",
        });
    }
    if group.child_bytes.len() != group.child_nodes.len() {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "child_bytes/child_nodes length",
        });
    }

    if group.nodes.is_empty() {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "empty node arena",
        });
        return;
    }

    if let Some(root) = group.nodes.first()
        && (root.key_len != 0 || root.blob_len != 0 || root.up != SENTINEL)
    {
        errors.push(ValidateError::ArenaBounds {
            group: group_u32,
            what: "root",
        });
    }

    for (node_idx, node) in group.nodes.iter().enumerate() {
        let Ok(node_u32) = u32::try_from(node_idx) else {
            continue;
        };
        validate_node_arena_bounds(group, group_u32, *node, errors);
        validate_up_link(group, group_u32, node_u32, *node, errors);
        validate_node_candidates(group, group_u32, node_u32, *node, errors, all_precedences);
    }

    validate_reachability(group, group_u32, errors);
}

/// The whole-table precedence uniqueness check (the second half of I3): a
/// duplicate is reported once regardless of how many extra copies exist, and in
/// a deterministic order so a test can assert on it without depending on scan
/// order.
fn validate_global_precedence(all: &[Precedence], errors: &mut Vec<ValidateError>) {
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = std::collections::HashSet::new();
    for &p in all {
        if !seen.insert(p) {
            duplicates.insert(p);
        }
    }
    let mut dup_vec: Vec<Precedence> = duplicates.into_iter().collect();
    dup_vec.sort_unstable();
    for prec in dup_vec {
        errors.push(ValidateError::PrecedenceNotUnique { prec });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::ids::{ActionId, GroupId, NodeId, RouteId, SENTINEL};
    use crate::precedence::{PathKind, Precedence};

    use super::node::{Cand, Pred, node_flags, pred_flags};
    use super::{Group, PathNode, RouteTable, TableParts, ValidateError};

    /// Assembles a `Group` from raw arenas, for tests that need a specific or a
    /// deliberately corrupted shape. `content_hash` is set to 0 and `next` is taken
    /// from the argument; every other field is exactly what was passed.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors Group's own field list one-for-one, which the issue's contract fixes exactly so later issues in this milestone can all call it the same way; a builder would only move these same nine values into chained setters with no real reduction in what a caller supplies"
    )]
    pub(crate) fn tiny_group(
        nodes: Vec<PathNode>,
        child_bytes: Vec<u8>,
        child_nodes: Vec<u32>,
        cands: Vec<Cand>,
        cand_routes: Vec<RouteId>,
        cand_kinds: Vec<u8>,
        preds: Vec<Pred>,
        blob: Vec<u8>,
        next: GroupId,
    ) -> Group {
        Group {
            nodes: nodes.into_boxed_slice(),
            child_bytes: child_bytes.into_boxed_slice(),
            child_nodes: child_nodes.into_boxed_slice(),
            cands: cands.into_boxed_slice(),
            cand_routes: cand_routes.into_boxed_slice(),
            cand_kinds: cand_kinds.into_boxed_slice(),
            preds: preds.into_boxed_slice(),
            blob: blob.into_boxed_slice(),
            next,
            content_hash: 0,
        }
    }

    fn one_group_table(group: Group) -> RouteTable {
        RouteTable::from_parts(TableParts {
            groups: vec![group],
            ..Default::default()
        })
    }

    fn root_node(cands: u32, cand_n: u16) -> PathNode {
        PathNode {
            blob_off: 0,
            children: 0,
            cands,
            up: SENTINEL,
            blob_len: 0,
            cand_n,
            key_len: 0,
            child_n: 0,
            flags: 0,
        }
    }

    #[test]
    fn child_sparse() {
        let node = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 0,
            child_n: 3,
            flags: 0,
        };
        let group = tiny_group(
            vec![node],
            vec![b'a', b'x', b'/'],
            vec![1, 2, 3],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        assert_eq!(group.child(&node, b'x'), Some(NodeId(2)));
        assert_eq!(group.child(&node, b'z'), None);
    }

    #[test]
    fn child_dense() {
        let mut child_nodes = vec![SENTINEL; 256];
        child_nodes[usize::from(b'/')] = 5;
        let node_dense_full = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 0,
            child_n: 200,
            flags: node_flags::NODE_DENSE,
        };
        let group = tiny_group(
            vec![node_dense_full],
            vec![0u8; 256],
            child_nodes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        assert_eq!(group.child(&node_dense_full, b'/'), Some(NodeId(5)));
        assert_eq!(group.child(&node_dense_full, b'a'), None);

        let node_dense_zero = PathNode {
            child_n: 0,
            ..node_dense_full
        };
        assert_eq!(group.child(&node_dense_zero, b'/'), Some(NodeId(5)));
        assert_eq!(group.child(&node_dense_zero, b'a'), None);
    }

    #[test]
    fn preds_run_terminates() {
        let preds = vec![
            Pred {
                tag: 0,
                op: 2,
                a: crate::ids::NameId(0),
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: 0,
                op: 2,
                a: crate::ids::NameId(0),
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: pred_flags::PRED_LAST,
                op: 2,
                a: crate::ids::NameId(0),
                b: 0,
                c: 0,
                d: 0,
            },
        ];
        let group = tiny_group(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            preds,
            Vec::new(),
            GroupId::NONE,
        );
        assert_eq!(group.preds_from(0).len(), 3);
        assert_eq!(group.preds_from(2).len(), 1);
    }

    #[test]
    fn preds_run_unterminated_is_empty() {
        let preds = vec![
            Pred {
                tag: 0,
                op: 2,
                a: crate::ids::NameId(0),
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: 0,
                op: 2,
                a: crate::ids::NameId(0),
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: 0,
                op: 2,
                a: crate::ids::NameId(0),
                b: 0,
                c: 0,
                d: 0,
            },
        ];
        let root = root_node(0, 1);
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            preds: 0,
            action: ActionId(0),
        }];
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            cands,
            vec![RouteId(0)],
            vec![PathKind::Exact.to_u8()],
            preds,
            Vec::new(),
            GroupId::NONE,
        );
        assert!(group.preds_from(0).is_empty());
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::PredRunUnterminated { group: 0, start: 0 }));
    }

    #[test]
    fn literal_out_of_bounds_is_empty() {
        let pred = Pred {
            tag: pred_flags::PRED_LAST,
            op: 1,
            a: crate::ids::NameId(0),
            b: 100,
            c: 10,
            d: 0,
        };
        let root = root_node(0, 1);
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            preds: 0,
            action: ActionId(0),
        }];
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            cands,
            vec![RouteId(0)],
            vec![PathKind::Exact.to_u8()],
            vec![pred],
            vec![0u8; 4],
            GroupId::NONE,
        );
        assert!(group.literal(&pred).is_empty());
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "pred_literal"
        }));

        // Edge case 13a: overflowing extents on a 64-bit target must not panic
        // and must resolve to "not found" via checked_add, exactly as they would
        // on a 32-bit target where the addition genuinely wraps.
        let overflow_pred = Pred {
            tag: pred_flags::PRED_LAST,
            op: 1,
            a: crate::ids::NameId(0),
            b: u32::MAX,
            c: 10,
            d: 0,
        };
        let overflow_group = tiny_group(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![0u8; 4],
            GroupId::NONE,
        );
        assert!(overflow_group.literal(&overflow_pred).is_empty());

        let dense_overflow_node = PathNode {
            blob_off: 0,
            children: u32::MAX,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 0,
            child_n: 4,
            flags: node_flags::NODE_DENSE,
        };
        assert_eq!(
            overflow_group.child(&dense_overflow_node, b'a'),
            None,
            "dense dispatch must not panic on an overflowing extent"
        );
        let sparse_overflow_node = PathNode {
            flags: 0,
            ..dense_overflow_node
        };
        assert_eq!(
            overflow_group.child(&sparse_overflow_node, b'a'),
            None,
            "sparse dispatch must not panic on an overflowing extent"
        );
    }

    /// A three-node group: root -> "/api" (an `Exact` candidate) -> "/api/v1"
    /// (a leaf), with correct `up` links, flags and candidate ordering.
    fn wellformed_group() -> Group {
        let nodes = vec![
            PathNode {
                blob_off: 0,
                children: 0,
                cands: 0,
                up: SENTINEL,
                blob_len: 0,
                cand_n: 0,
                key_len: 0,
                child_n: 1,
                flags: 0,
            },
            PathNode {
                blob_off: 0,
                children: 1,
                cands: 0,
                up: SENTINEL,
                blob_len: 4,
                cand_n: 1,
                key_len: 4,
                child_n: 1,
                flags: node_flags::NODE_HAS_EXACT | node_flags::NODE_SINGLE_UNCOND,
            },
            PathNode {
                blob_off: 4,
                children: 0,
                cands: 0,
                up: 1,
                blob_len: 3,
                cand_n: 0,
                key_len: 7,
                child_n: 0,
                flags: 0,
            },
        ];
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            preds: SENTINEL,
            action: ActionId(0),
        }];
        tiny_group(
            nodes,
            vec![b'/', b'/'],
            vec![1, 2],
            cands,
            vec![RouteId(0)],
            vec![PathKind::Exact.to_u8()],
            Vec::new(),
            b"/api/v1".to_vec(),
            GroupId::NONE,
        )
    }

    #[test]
    fn validate_accepts_wellformed() {
        let table = one_group_table(wellformed_group());
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn validate_rejects_candidate_order() {
        let mut group = wellformed_group();
        let node = group.nodes[1];
        group.nodes[1] = PathNode { cand_n: 2, ..node };
        group.cands = vec![
            Cand {
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, 5),
                preds: SENTINEL,
                action: ActionId(0),
            },
            Cand {
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, 3),
                preds: SENTINEL,
                action: ActionId(1),
            },
        ]
        .into_boxed_slice();
        group.cand_routes = vec![RouteId(0), RouteId(1)].into_boxed_slice();
        group.cand_kinds =
            vec![PathKind::Exact.to_u8(), PathKind::Exact.to_u8()].into_boxed_slice();
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidateError::CandidateOrder { group: 0, node: 1 }))
        );
    }

    #[test]
    fn validate_rejects_up_cycle() {
        let mut group = wellformed_group();
        let node2 = group.nodes[1];
        let node3 = group.nodes[2];
        group.nodes[1] = PathNode { up: 2, ..node2 };
        group.nodes[2] = PathNode {
            up: 1,
            cand_n: 0,
            ..node3
        };
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidateError::UpLink { .. }))
        );
    }

    #[test]
    fn validate_rejects_duplicate_precedence() {
        let mut group = wellformed_group();
        let node0 = group.nodes[0];
        group.nodes[0] = PathNode {
            cands: 1,
            cand_n: 1,
            ..node0
        };
        let shared = Precedence::pack(PathKind::Exact, false, 0, 0, 0);
        group.cands = vec![
            Cand {
                prec: shared,
                preds: SENTINEL,
                action: ActionId(0),
            },
            Cand {
                prec: shared,
                preds: SENTINEL,
                action: ActionId(1),
            },
        ]
        .into_boxed_slice();
        group.cand_routes = vec![RouteId(0), RouteId(1)].into_boxed_slice();
        group.cand_kinds =
            vec![PathKind::Exact.to_u8(), PathKind::Exact.to_u8()].into_boxed_slice();
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::PrecedenceNotUnique { prec: shared }));
    }

    #[test]
    fn validate_rejects_prefix_on_unaligned_node() {
        let root = PathNode {
            child_n: 1,
            ..root_node(0, 0)
        };
        let leaf = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 4,
            cand_n: 1,
            key_len: 4,
            child_n: 0,
            flags: node_flags::NODE_HAS_PREFIX,
        };
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::SegmentPrefix, false, 0, 0, 0),
            preds: SENTINEL,
            action: ActionId(0),
        }];
        let group = tiny_group(
            vec![root, leaf],
            vec![b'/'],
            vec![1],
            cands,
            vec![RouteId(0)],
            vec![PathKind::SegmentPrefix.to_u8()],
            Vec::new(),
            b"/ab/".to_vec(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidateError::PrefixNotSegmentAligned { group: 0, node: 1 }
        )));
    }

    // The tests below were added after mutation testing the tests named in the
    // issue: they close gaps a mutation survived, each documented with the
    // specific mutant it catches.

    /// Catches `RouteTable::generation/group_count/group/needs_query` each being
    /// replaced with a constant: none of the 12 named tests call these directly.
    #[test]
    fn route_table_accessors_read_their_fields() {
        let table = RouteTable::from_parts(TableParts {
            groups: vec![wellformed_group()],
            generation: 7,
            needs_query: true,
            ..Default::default()
        });
        assert_eq!(table.generation(), 7);
        assert_eq!(table.group_count(), 1);
        assert!(table.group(GroupId(0)).is_some());
        assert!(table.group(GroupId(1)).is_none());
        assert!(table.needs_query());

        let empty_table = RouteTable::from_parts(TableParts::default());
        assert_eq!(empty_table.group_count(), 0);
        assert!(empty_table.group(GroupId(0)).is_none());
        assert!(!empty_table.needs_query());
    }

    /// Catches `Group::cand_route` being replaced with `None` or a default value:
    /// no named test calls it directly.
    #[test]
    fn cand_route_bounds() {
        let group = tiny_group(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![RouteId(9), RouteId(3)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        assert_eq!(group.cand_route(0), Some(RouteId(9)));
        assert_eq!(group.cand_route(1), Some(RouteId(3)));
        assert_eq!(group.cand_route(2), None);
    }

    /// Catches `Group::literal` being replaced with a constant empty or one-byte
    /// slice: `literal_out_of_bounds_is_empty` only exercises the out-of-bounds
    /// path, never a successful in-bounds read.
    #[test]
    fn literal_returns_correct_bytes() {
        let blob = b"GET-only".to_vec();
        let pred = Pred {
            tag: pred_flags::PRED_LAST,
            op: 0,
            a: crate::ids::NameId(0),
            b: 4,
            c: 4,
            d: 0,
        };
        let group = tiny_group(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            blob,
            GroupId::NONE,
        );
        assert_eq!(group.literal(&pred), b"only");
    }

    /// Catches `Group::child_ids`'s dense/sparse dispatch and its `SENTINEL`
    /// filter being mutated: every named test's trie is sparse only, so the dense
    /// branch used by `validate`'s reachability walk is otherwise never taken.
    #[test]
    fn validate_accepts_dense_node_reachable() {
        let root = PathNode {
            child_n: 1,
            ..root_node(0, 0)
        };
        let mut child_nodes = vec![1u32]; // root's single sparse child -> node 1
        child_nodes.extend(std::iter::repeat_n(SENTINEL, 256));
        child_nodes[1 + usize::from(b'a')] = 2;
        child_nodes[1 + usize::from(b'b')] = 3;
        child_nodes[1 + usize::from(b'c')] = 4;
        let mut child_bytes = vec![b'x'];
        child_bytes.extend(std::iter::repeat_n(0u8, 256));
        let dense = PathNode {
            blob_off: 0,
            children: 1,
            cands: 0,
            up: SENTINEL,
            blob_len: 1,
            cand_n: 0,
            key_len: 1,
            child_n: 3,
            flags: node_flags::NODE_DENSE,
        };
        let leaf = PathNode {
            blob_off: 1,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 1,
            cand_n: 0,
            key_len: 2,
            child_n: 0,
            flags: 0,
        };
        let group = tiny_group(
            vec![root, dense, leaf, leaf, leaf],
            child_bytes,
            child_nodes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            b"xa".to_vec(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        assert_eq!(table.validate(), Vec::new());
    }

    /// Catches `segment_prefix_aligned` being replaced with a constant `false`:
    /// `validate_rejects_prefix_on_unaligned_node` only exercises the rejecting
    /// path, never a `SegmentPrefix` candidate that IS correctly aligned.
    #[test]
    fn validate_accepts_wellaligned_prefix() {
        let root = PathNode {
            child_n: 1,
            ..root_node(0, 0)
        };
        let leaf = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 4,
            cand_n: 1,
            key_len: 4,
            child_n: 0,
            flags: node_flags::NODE_HAS_PREFIX | node_flags::NODE_SINGLE_UNCOND,
        };
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::SegmentPrefix, false, 0, 0, 0),
            preds: SENTINEL,
            action: ActionId(0),
        }];
        let group = tiny_group(
            vec![root, leaf],
            vec![b'/'],
            vec![1],
            cands,
            vec![RouteId(0)],
            vec![PathKind::SegmentPrefix.to_u8()],
            Vec::new(),
            b"/api".to_vec(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        assert_eq!(table.validate(), Vec::new());
    }

    /// Catches `validate_up_link`'s `||` being mutated to `&&`:
    /// `validate_rejects_up_cycle` only violates the `key_len` half of I4, never
    /// the `cand_n > 0` half in isolation.
    #[test]
    fn validate_rejects_up_link_zero_cand_ancestor() {
        let root = PathNode {
            child_n: 1,
            ..root_node(0, 0)
        };
        let mid = PathNode {
            blob_off: 0,
            children: 1,
            cands: 0,
            up: SENTINEL,
            blob_len: 2,
            cand_n: 0,
            key_len: 2,
            child_n: 1,
            flags: 0,
        };
        let leaf = PathNode {
            blob_off: 2,
            children: 0,
            cands: 0,
            up: 1,
            blob_len: 3,
            cand_n: 0,
            key_len: 5,
            child_n: 0,
            flags: 0,
        };
        let group = tiny_group(
            vec![root, mid, leaf],
            vec![b'/', b'a'],
            vec![1, 2],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            b"/xabc".to_vec(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert_eq!(
            errors,
            vec![ValidateError::UpLink { group: 0, node: 2 }],
            "mid has key_len < leaf's, so only the missing candidate makes the up link invalid"
        );
    }

    /// Catches `validate_node_arena_bounds` being replaced with a no-op, and its
    /// internal comparisons being flipped: no named test drives an out-of-bounds
    /// node-level `children`, `blob`, or `cands` extent (only a `Pred` literal's
    /// extent, checked by `validate_pred_run`, a different function).
    #[test]
    fn validate_rejects_node_arena_out_of_bounds() {
        let root = PathNode {
            child_n: 1,
            ..root_node(0, 0)
        };
        let bad = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 50,
            cand_n: 50,
            key_len: 1,
            child_n: 50,
            flags: 0,
        };
        let group = tiny_group(
            vec![root, bad],
            vec![b'/'],
            vec![1],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![0u8; 2],
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "blob"
        }));
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "cands"
        }));
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "children"
        }));
    }

    /// Catches `validate_group`'s `cand_routes`/`cand_kinds` length check being
    /// weakened: no named test builds a group where those parallel arrays
    /// disagree in length with `cands`.
    #[test]
    fn validate_rejects_cand_array_length_mismatch() {
        let root = PathNode {
            cand_n: 1,
            ..root_node(0, 0)
        };
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            preds: SENTINEL,
            action: ActionId(0),
        }];
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            cands,
            vec![RouteId(0), RouteId(1)],
            vec![PathKind::Exact.to_u8()],
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "cand_routes/cand_kinds length"
        }));
    }

    /// Catches `validate_reachability` being replaced with a no-op, and its
    /// `visit_count` comparison being flipped: no named test contains a node the
    /// root cannot reach.
    #[test]
    fn validate_rejects_unreachable_node() {
        let root = root_node(0, 0);
        let orphan = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 3,
            child_n: 0,
            flags: 0,
        };
        let group = tiny_group(
            vec![root, orphan],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::Reachability { group: 0, node: 1 }));
    }

    /// Catches `validate_node_candidates`'s `NODE_HAS_PREFIX`/`NODE_HAS_EXACT`
    /// mismatch check having its `||` mutated to `&&`: isolates a mismatch on
    /// exactly one side (`has_exact`) while the other side (`has_prefix`) agrees.
    #[test]
    fn validate_rejects_isolated_has_exact_flag_mismatch() {
        let root = PathNode {
            cand_n: 1,
            flags: node_flags::NODE_SINGLE_UNCOND,
            ..root_node(0, 0)
        };
        let cands = vec![Cand {
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            preds: SENTINEL,
            action: ActionId(0),
        }];
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            cands,
            vec![RouteId(0)],
            vec![PathKind::Exact.to_u8()],
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::FlagMismatch { group: 0, node: 0 }));
    }

    /// Catches `validate_node_candidates`'s `NODE_SINGLE_UNCOND` computation
    /// having its `&&` mutated to `||`: a node with two unconditional candidates
    /// (so the first one alone looks "single and unconditional") must NOT set
    /// `NODE_SINGLE_UNCOND`, and `validate` must not demand it either.
    #[test]
    fn validate_accepts_multi_candidate_node_without_single_uncond_flag() {
        let root = PathNode {
            cand_n: 2,
            flags: node_flags::NODE_HAS_EXACT,
            ..root_node(0, 0)
        };
        let cands = vec![
            Cand {
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
                preds: SENTINEL,
                action: ActionId(0),
            },
            Cand {
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, 1),
                preds: SENTINEL,
                action: ActionId(1),
            },
        ];
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            cands,
            vec![RouteId(0), RouteId(1)],
            vec![PathKind::Exact.to_u8(), PathKind::Exact.to_u8()],
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        assert_eq!(table.validate(), Vec::new());
    }

    /// Catches the root-shape check's inner `||` (between `key_len != 0` and
    /// `blob_len != 0`) being mutated to `&&`: isolates `key_len` alone.
    #[test]
    fn validate_rejects_root_with_nonzero_key_len() {
        let root = PathNode {
            key_len: 3,
            ..root_node(0, 0)
        };
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "root"
        }));
    }

    /// Catches the root-shape check's outer `||` (between the `key_len`/`blob_len`
    /// pair and `up != SENTINEL`) being mutated to `&&`: isolates `up` alone.
    #[test]
    fn validate_rejects_root_with_bad_up() {
        let root = PathNode {
            up: 0,
            ..root_node(0, 0)
        };
        let group = tiny_group(
            vec![root],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "root"
        }));
    }

    /// Catches `validate_node_arena_bounds`'s children-extent check having its
    /// `&&` mutated to `||`: the invariant is that the extent fits BOTH parallel
    /// arrays independently, so this isolates a case where `child_nodes` is long
    /// enough but `child_bytes` is not.
    #[test]
    fn validate_rejects_children_extent_when_only_one_array_short() {
        let root = PathNode {
            child_n: 1,
            ..root_node(0, 0)
        };
        let bad = PathNode {
            blob_off: 0,
            children: 1,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 1,
            child_n: 5,
            flags: 0,
        };
        let mut child_nodes = vec![1u32];
        child_nodes.extend(std::iter::repeat_n(SENTINEL, 5));
        let group = tiny_group(
            vec![root, bad],
            vec![0u8; 2],
            child_nodes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let table = one_group_table(group);
        let errors = table.validate();
        assert!(errors.contains(&ValidateError::ArenaBounds {
            group: 0,
            what: "children"
        }));
    }
}
