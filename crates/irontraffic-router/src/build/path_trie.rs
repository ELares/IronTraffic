// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds one group's byte-wise compressed radix trie over candidates' literal
//! path keys.
//!
//! [`build_group`] takes a group's candidate list and produces the finished
//! immutable [`Group`](crate::table::Group): nodes laid out in preorder with
//! children sorted by descending subtree size, every node's `up` back-pointer
//! computed, every node's candidates sorted descending by precedence, and
//! child dispatch emitted as either a sparse scan array or a dense table.
//!
//! Build-time only: this module allocates freely and runs on a dedicated
//! thread, seconds apart from the request path. It is INERT: nothing in this
//! crate calls [`build_group`] yet. `builder-admission-and-assemble` (#56) is
//! the caller; `path-descent-and-visit-budget` (#54) walks the result.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{ActionId, GroupId, RouteId, SENTINEL};
use crate::limits::MAX_PATH_BYTES;
use crate::precedence::{PathKind, Precedence};
use crate::table::{Cand, Group, PathNode, Pred, node_flags};

use super::TrieBuildError;

/// One candidate offered to the group builder, already fully resolved: its
/// precedence is packed, its predicates are already in the group's predicate arena,
/// and its literal key is decided.
#[derive(Copy, Clone, Debug)]
pub struct CandInput<'a> {
    /// The literal path key this candidate attaches to. Starts with `b'/'`. For a
    /// `SegmentPrefix` candidate it is the prefix with any single trailing `/`
    /// already stripped by admission, except for the root, whose key is `b"/"`.
    pub key: &'a [u8],
    /// Which path check applies at match time.
    pub kind: PathKind,
    /// Packed precedence. Must be unique across the whole table.
    pub prec: Precedence,
    /// Opaque action handle.
    pub action: ActionId,
    /// The route this candidate came from.
    pub route: RouteId,
    /// Index into `GroupParts::preds` of this candidate's first predicate, or
    /// `SENTINEL` when the candidate is unconditional.
    pub preds: u32,
}

/// Everything about a group that is not derived from the trie: the predicate arena
/// the caller already built, the blob it wrote its literals into, the fallthrough
/// successor and the content hash.
#[derive(Debug)]
pub struct GroupParts {
    /// The predicate arena, already ordered cheapest-first per candidate with
    /// `PRED_LAST` set on the last record of each run.
    pub preds: Vec<Pred>,
    /// Literal bytes. Predicate literals are already in it; `build_group` APPENDS
    /// every edge label to it and never rewrites what is already there.
    pub blob: Vec<u8>,
    /// The next group in the fallthrough chain, or `GroupId::NONE`.
    pub next: GroupId,
    /// Content hash of the inputs this group was built from. 128 bits because a hash
    /// equality authorizes reusing this group across generations; see
    /// `table-arena-and-node-layout` (#51).
    pub content_hash: u128,
    /// Hard cap on nodes in this group. Exceeding it fails the build rather than
    /// producing a table that will not fit in the memory ceiling.
    pub max_nodes: u32,
    /// Hard cap on the total length of `blob` after this group's edge labels have
    /// been appended, in bytes.
    ///
    /// It is checked INSIDE the emission loop, before each append, and not once at
    /// the end. The sum of the edge labels is bounded only by the input, so at the
    /// `BuildBudget::DEFAULT` ceilings a hostile route set (200,000 matches whose
    /// keys are each 8 KiB) would allocate about 1.6 GB before an end-of-build check
    /// could fire. A budget you check after allocating is not a budget.
    pub max_blob_bytes: u32,
}

/// Build-time-only intermediate trie node. Allocates freely; nothing here survives
/// past `build_group`'s return.
struct BuildNode {
    /// Edge label: the bytes consumed from the parent to reach this node.
    label: Vec<u8>,
    /// First label byte to index in this arena. A `BTreeMap` (never a hash-keyed
    /// map) so iteration is sorted and the build is deterministic.
    children: BTreeMap<u8, usize>,
    /// Indices into the input candidate slice.
    cands: Vec<usize>,
    /// Length of this node's FULL key.
    key_len: u32,
    /// Number of nodes in this node's subtree, including itself. Computed by
    /// `sizes` after every key is inserted.
    subtree: u32,
}

/// Fetches `arena[idx]` by shared reference without ever writing `arena[idx]`.
///
/// Every index this module dereferences through `node_ref`/`node_mut` is either
/// `0` (the root, pushed by `build_group` before any call to `insert`) or an index
/// `push_node` itself returned earlier in the same build; `arena` only ever grows
/// (nothing is ever removed), so the `Option` returned by `get`/`get_mut` is always
/// `Some` for any index this module produces itself. `get`/`get_mut` (never `[]`,
/// which `clippy::indexing_slicing` denies crate wide, see `lib.rs`) are used
/// anyway so a future bug in this file surfaces as an `Err` return instead of a
/// panic, per `AGENTS.md` rule 4. `max_nodes` is threaded in only so the
/// (unreachable in practice) `None` branch has a real, in-scope value to report;
/// no test can reach it, because reaching it requires this module's own indexing
/// invariant to already be broken.
fn node_ref(arena: &[BuildNode], idx: usize, max_nodes: u32) -> Result<&BuildNode, TrieBuildError> {
    arena
        .get(idx)
        .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })
}

/// The mutable counterpart of [`node_ref`]. See its doc comment.
fn node_mut(
    arena: &mut [BuildNode],
    idx: usize,
    max_nodes: u32,
) -> Result<&mut BuildNode, TrieBuildError> {
    arena
        .get_mut(idx)
        .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })
}

/// Pushes `node` onto `arena` and checks the node-count budget immediately
/// afterward, exactly once per push, as the issue's insertion algorithm requires.
/// Returns the new node's index.
fn push_node(
    arena: &mut Vec<BuildNode>,
    node: BuildNode,
    max_nodes: u32,
) -> Result<usize, TrieBuildError> {
    arena.push(node);
    match u32::try_from(arena.len()) {
        Ok(len) if len <= max_nodes => Ok(arena.len().saturating_sub(1)),
        _ => Err(TrieBuildError::TooManyNodes { limit: max_nodes }),
    }
}

/// Converts a byte length that is bounded by `MAX_PATH_BYTES` (checked by the
/// caller, directly or transitively) into a `u32`. The only way this can fail is a
/// bug elsewhere in this file, since `MAX_PATH_BYTES` is far below `u32::MAX`;
/// `KeyTooLong` is the closest of the documented errors to "a key-derived length
/// does not fit where it must".
fn key_len_u32(n: usize) -> Result<u32, TrieBuildError> {
    u32::try_from(n).map_err(|_| TrieBuildError::KeyTooLong)
}

/// Number of leading bytes `a` and `b` share. `common >= 1` whenever `a` and `b`
/// were chosen because they agree on at least their first byte, which is the only
/// way `insert` ever calls this.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// Inserts `key` into `arena`, splitting an existing edge if `key` diverges
/// partway through one, and returns the index of the node whose FULL key equals
/// `key`. Mirrors this issue's `insert` pseudocode step by step, translated into
/// `get`/`get_mut` for the reason documented on [`node_ref`].
fn insert(arena: &mut Vec<BuildNode>, key: &[u8], max_nodes: u32) -> Result<usize, TrieBuildError> {
    let mut node = 0usize;
    let mut pos = 0usize;
    loop {
        if pos == key.len() {
            return Ok(node);
        }
        let Some(&b) = key.get(pos) else {
            return Ok(node);
        };
        let existing = node_ref(arena, node, max_nodes)?.children.get(&b).copied();
        match existing {
            None => {
                let rest = key.get(pos..).unwrap_or(&[]);
                let new_key_len = key_len_u32(key.len())?;
                let new_idx = push_node(
                    arena,
                    BuildNode {
                        label: rest.to_vec(),
                        children: BTreeMap::new(),
                        cands: Vec::new(),
                        key_len: new_key_len,
                        subtree: 0,
                    },
                    max_nodes,
                )?;
                node_mut(arena, node, max_nodes)?
                    .children
                    .insert(b, new_idx);
                return Ok(new_idx);
            }
            Some(child) => {
                let rest = key.get(pos..).unwrap_or(&[]);
                // Common case first, and cheap: read the label through a
                // borrow that ends with this block, without cloning it. A
                // nested-key chain (`/a`, `/aa`, `/aaa`, ...) takes this
                // branch on every one of the O(depth) nodes it walks through
                // on EVERY insertion, so an unconditional `.clone()` here
                // once made the whole build O(depth^2) heap allocations
                // instead of O(depth^2) plain byte comparisons: measured on
                // the 5,000-deep benchmark, that difference was the entire
                // gap between 190 ms and the issue's 20 ms budget. The clone
                // below is reached only when a split actually happens, which
                // is at most `K` times over the whole build, never once per
                // hop.
                let (common, child_label_len) = {
                    let child_ref = node_ref(arena, child, max_nodes)?;
                    (
                        common_prefix_len(&child_ref.label, rest),
                        child_ref.label.len(),
                    )
                };
                if common == child_label_len {
                    pos = pos.checked_add(common).ok_or(TrieBuildError::KeyTooLong)?;
                    node = child;
                    continue;
                }
                // Split: `child` keeps the tail, a new intermediate takes the
                // head. Only reached at most `K` times total, so the clone
                // here (needed because we are about to overwrite
                // `arena[child].label` while still needing its old bytes) is
                // not on the hot path the comment above describes.
                let child_label = node_ref(arena, child, max_nodes)?.label.clone();
                let parent_key_len = node_ref(arena, node, max_nodes)?.key_len;
                let head = child_label.get(..common).unwrap_or(&[]).to_vec();
                let &tail_first = child_label.get(common).ok_or(TrieBuildError::KeyTooLong)?;
                let new_child_label = child_label.get(common..).unwrap_or(&[]).to_vec();
                node_mut(arena, child, max_nodes)?.label = new_child_label;
                let common_u32 = key_len_u32(common)?;
                let mid_key_len = parent_key_len
                    .checked_add(common_u32)
                    .ok_or(TrieBuildError::KeyTooLong)?;
                let mut mid_children = BTreeMap::new();
                mid_children.insert(tail_first, child);
                let mid_idx = push_node(
                    arena,
                    BuildNode {
                        label: head,
                        children: mid_children,
                        cands: Vec::new(),
                        key_len: mid_key_len,
                        subtree: 0,
                    },
                    max_nodes,
                )?;
                node_mut(arena, node, max_nodes)?
                    .children
                    .insert(b, mid_idx);
                pos = pos.checked_add(common).ok_or(TrieBuildError::KeyTooLong)?;
                if pos == key.len() {
                    return Ok(mid_idx);
                }
                let Some(&b2) = key.get(pos) else {
                    return Ok(mid_idx);
                };
                let rest2 = key.get(pos..).unwrap_or(&[]);
                let leaf_key_len = key_len_u32(key.len())?;
                let new_idx = push_node(
                    arena,
                    BuildNode {
                        label: rest2.to_vec(),
                        children: BTreeMap::new(),
                        cands: Vec::new(),
                        key_len: leaf_key_len,
                        subtree: 0,
                    },
                    max_nodes,
                )?;
                node_mut(arena, mid_idx, max_nodes)?
                    .children
                    .insert(b2, new_idx);
                return Ok(new_idx);
            }
        }
    }
}

/// Step 3: subtree sizes, via an explicit post-order stack. Never recursive: a
/// several-hundred-thousand-node trie would overflow the call stack.
fn sizes(arena: &mut [BuildNode], max_nodes: u32) -> Result<(), TrieBuildError> {
    let mut stack: Vec<(usize, bool)> = vec![(0, false)];
    while let Some((idx, expanded)) = stack.pop() {
        if expanded {
            let child_ids: Vec<usize> = node_ref(arena, idx, max_nodes)?
                .children
                .values()
                .copied()
                .collect();
            let mut total: u32 = 1;
            for child in child_ids {
                let child_subtree = node_ref(arena, child, max_nodes)?.subtree;
                total = total.saturating_add(child_subtree);
            }
            node_mut(arena, idx, max_nodes)?.subtree = total;
        } else {
            stack.push((idx, true));
            let child_ids: Vec<usize> = node_ref(arena, idx, max_nodes)?
                .children
                .values()
                .copied()
                .collect();
            for child in child_ids {
                stack.push((child, false));
            }
        }
    }
    Ok(())
}

/// Step 4: `up` links, via an explicit pre-order stack carrying the nearest
/// strict candidate-owning ancestor's INTERMEDIATE index (or `SENTINEL`). Named
/// `visit` after this issue's own pseudocode. Returns a `Vec<u32>` indexed by
/// INTERMEDIATE node index; `build_group` remaps it to final indices during
/// emission, as the issue directs ("carry the intermediate index and remap").
fn visit(arena: &[BuildNode], max_nodes: u32) -> Result<Vec<u32>, TrieBuildError> {
    let mut up = vec![SENTINEL; arena.len()];
    let mut stack: Vec<(usize, u32)> = vec![(0, SENTINEL)];
    while let Some((idx, owner)) = stack.pop() {
        let slot = up
            .get_mut(idx)
            .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
        *slot = owner;
        let node = node_ref(arena, idx, max_nodes)?;
        let next_owner = if node.cands.is_empty() {
            owner
        } else {
            u32::try_from(idx).map_err(|_| TrieBuildError::TooManyNodes { limit: max_nodes })?
        };
        for &child in node.children.values() {
            stack.push((child, next_owner));
        }
    }
    Ok(up)
}

/// Every child of `idx`, as `(first label byte, child index, child subtree size)`,
/// ordered descending by subtree size with ties broken by ascending first byte.
///
/// The tie break falls out for free: `BuildNode::children` is a `BTreeMap<u8,
/// usize>`, so iterating it already yields ascending-byte order, and
/// `sort_by_key` is a stable sort, so it preserves that relative order among
/// equal subtree sizes. Shared by `number` (step 5) and emission (step 6) so the
/// two orders cannot drift apart, which is what the issue requires: "for each
/// child in the same descending-subtree order used in step 5".
fn sorted_children(
    arena: &[BuildNode],
    idx: usize,
    max_nodes: u32,
) -> Result<Vec<(u8, usize, u32)>, TrieBuildError> {
    let node = node_ref(arena, idx, max_nodes)?;
    let mut out = Vec::with_capacity(node.children.len());
    for (&b, &child) in &node.children {
        let subtree = node_ref(arena, child, max_nodes)?.subtree;
        out.push((b, child, subtree));
    }
    out.sort_by_key(|&(_, _, subtree)| Reverse(subtree));
    Ok(out)
}

/// Step 5: final preorder numbering, via an explicit stack. Named `number` after
/// this issue's own "final numbering" step. Returns `(order, old_to_new)`: `order`
/// is the sequence of INTERMEDIATE indices in final visiting order (so `order[f]`
/// is the intermediate index that becomes final index `f`), and `old_to_new` maps
/// an intermediate index to its final one.
fn number(arena: &[BuildNode], max_nodes: u32) -> Result<(Vec<usize>, Vec<u32>), TrieBuildError> {
    let mut order: Vec<usize> = Vec::with_capacity(arena.len());
    let mut old_to_new: Vec<u32> = vec![SENTINEL; arena.len()];
    let mut stack: Vec<usize> = vec![0];
    while let Some(idx) = stack.pop() {
        let new_idx = u32::try_from(order.len())
            .map_err(|_| TrieBuildError::TooManyNodes { limit: max_nodes })?;
        let slot = old_to_new
            .get_mut(idx)
            .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
        *slot = new_idx;
        order.push(idx);
        let child_list = sorted_children(arena, idx, max_nodes)?;
        // Pushed in reverse so the stack (LIFO) pops them back in ascending
        // descending-subtree order: the first child in `child_list` is the next
        // one visited.
        for &(_, child, _) in child_list.iter().rev() {
            stack.push(child);
        }
    }
    Ok((order, old_to_new))
}

/// Fails with `BlobTooLarge` before `label_len` bytes would be appended to a blob
/// currently `blob.len()` bytes long, if doing so would exceed `max_blob_bytes` or
/// `u32::MAX`, whichever is smaller. The sum is computed with `checked_add` (in a
/// widening `u64` domain, so the addition itself cannot wrap) so the check can
/// never be fooled by the overflow it exists to prevent.
fn check_blob_budget(
    blob_len: usize,
    label_len: usize,
    max_blob_bytes: u32,
) -> Result<(), TrieBuildError> {
    let blob_len_u64 = u64::try_from(blob_len).map_err(|_| TrieBuildError::BlobTooLarge)?;
    let label_len_u64 = u64::try_from(label_len).map_err(|_| TrieBuildError::BlobTooLarge)?;
    let projected = blob_len_u64
        .checked_add(label_len_u64)
        .ok_or(TrieBuildError::BlobTooLarge)?;
    let cap = u64::from(max_blob_bytes).min(u64::from(u32::MAX));
    if projected > cap {
        return Err(TrieBuildError::BlobTooLarge);
    }
    Ok(())
}

/// Step 6: emission. Walks the final order, appending every node's edge label to
/// the blob, sorting and appending its candidates, and computing its child
/// dispatch, flags, `up` and `key_len`.
#[allow(
    clippy::too_many_lines,
    reason = "one linear emission pass over the final node order, matching the issue's single numbered step 6; splitting it would scatter the seven sub-steps it documents across multiple functions that only this call site would ever use"
)]
fn emit(
    arena: &[BuildNode],
    order: &[usize],
    old_to_new: &[u32],
    up_old: &[u32],
    cands: &[CandInput<'_>],
    mut parts: GroupParts,
) -> Result<Group, TrieBuildError> {
    let max_nodes = parts.max_nodes;
    let mut nodes: Vec<PathNode> = Vec::with_capacity(order.len());
    let mut child_bytes: Vec<u8> = Vec::new();
    let mut child_nodes: Vec<u32> = Vec::new();
    let mut cands_out: Vec<Cand> = Vec::new();
    let mut cand_routes: Vec<RouteId> = Vec::new();
    let mut cand_kinds: Vec<u8> = Vec::new();

    for &o in order {
        let bnode = node_ref(arena, o, max_nodes)?;
        let label = bnode.label.clone();
        let node_cand_idxs = bnode.cands.clone();
        let key_len_old = bnode.key_len;

        // 1. Append the edge label, checked BEFORE the append.
        check_blob_budget(parts.blob.len(), label.len(), parts.max_blob_bytes)?;
        let blob_off = u32::try_from(parts.blob.len()).map_err(|_| TrieBuildError::BlobTooLarge)?;
        let blob_len = u16::try_from(label.len()).map_err(|_| TrieBuildError::KeyTooLong)?;
        parts.blob.extend_from_slice(&label);

        // 2 and 3. Sort this node's candidates descending by prec and append
        // them. No equal-precedence check is needed here: `build_group` already
        // rejected any duplicate `prec` ACROSS THE WHOLE INPUT before any node
        // was ever built (see the comment there for why a per-node-only check,
        // as the issue's step 6.2 pseudocode literally shows, would miss two
        // candidates that land on two DIFFERENT nodes), so by the time this
        // runs every `prec` here is already known unique.
        let mut sorted_cands: Vec<(usize, Precedence)> = Vec::with_capacity(node_cand_idxs.len());
        for &ci in &node_cand_idxs {
            let c = cands.get(ci).ok_or(TrieBuildError::TooManyCandidates)?;
            sorted_cands.push((ci, c.prec));
        }
        sorted_cands.sort_unstable_by_key(|&(_, prec)| Reverse(prec));

        let cands_start =
            u32::try_from(cands_out.len()).map_err(|_| TrieBuildError::TooManyCandidates)?;
        let cand_n =
            u16::try_from(sorted_cands.len()).map_err(|_| TrieBuildError::TooManyCandidates)?;

        let mut has_prefix = false;
        let mut has_exact = false;
        let mut first_preds: Option<u32> = None;
        for &(ci, prec) in &sorted_cands {
            let c = cands.get(ci).ok_or(TrieBuildError::TooManyCandidates)?;
            if first_preds.is_none() {
                first_preds = Some(c.preds);
            }
            cands_out.push(Cand {
                prec,
                preds: c.preds,
                action: c.action,
            });
            cand_routes.push(c.route);
            cand_kinds.push(c.kind.to_u8());
            match c.kind {
                PathKind::SegmentPrefix | PathKind::RootDefault => has_prefix = true,
                PathKind::Exact => has_exact = true,
                PathKind::Regex => {}
            }
        }
        let single_uncond = sorted_cands.len() == 1 && first_preds == Some(SENTINEL);

        // 4. Children: sparse (<=16) or dense (>16), in descending-subtree order,
        // the same order `number` used to number them.
        let child_list = sorted_children(arena, o, max_nodes)?;
        let children_offset = u32::try_from(child_bytes.len())
            .map_err(|_| TrieBuildError::TooManyNodes { limit: max_nodes })?;
        let mut dense = false;
        let child_n = if child_list.len() <= 16 {
            for &(b, child, _) in &child_list {
                child_bytes.push(b);
                let new_child = old_to_new
                    .get(child)
                    .copied()
                    .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
                child_nodes.push(new_child);
            }
            u8::try_from(child_list.len())
                .map_err(|_| TrieBuildError::TooManyNodes { limit: max_nodes })?
        } else {
            dense = true;
            let mut dense_nodes = vec![SENTINEL; 256];
            for &(b, child, _) in &child_list {
                let new_child = old_to_new
                    .get(child)
                    .copied()
                    .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
                let slot = dense_nodes
                    .get_mut(usize::from(b))
                    .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
                *slot = new_child;
            }
            child_bytes.extend(std::iter::repeat_n(0u8, 256));
            child_nodes.extend_from_slice(&dense_nodes);
            0u8
        };

        // 5. Flags.
        let mut flags = 0u8;
        if dense {
            flags |= node_flags::NODE_DENSE;
        }
        if single_uncond {
            flags |= node_flags::NODE_SINGLE_UNCOND;
        }
        if has_prefix {
            flags |= node_flags::NODE_HAS_PREFIX;
        }
        if has_exact {
            flags |= node_flags::NODE_HAS_EXACT;
        }

        // 6. `up`, remapped from the intermediate index `visit` produced to the
        // final index `number` assigned it.
        let up_old_val = *up_old
            .get(o)
            .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
        let up = if up_old_val == SENTINEL {
            SENTINEL
        } else {
            let owner_idx = usize::try_from(up_old_val)
                .map_err(|_| TrieBuildError::TooManyNodes { limit: max_nodes })?;
            *old_to_new
                .get(owner_idx)
                .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?
        };

        // 7. key_len.
        let key_len_usize = usize::try_from(key_len_old).map_err(|_| TrieBuildError::KeyTooLong)?;
        if key_len_usize > MAX_PATH_BYTES {
            return Err(TrieBuildError::KeyTooLong);
        }
        let key_len = u16::try_from(key_len_old).map_err(|_| TrieBuildError::KeyTooLong)?;

        nodes.push(PathNode {
            blob_off,
            children: children_offset,
            cands: cands_start,
            up,
            blob_len,
            cand_n,
            key_len,
            child_n,
            flags,
        });
    }

    Ok(Group {
        nodes: nodes.into_boxed_slice(),
        child_bytes: child_bytes.into_boxed_slice(),
        child_nodes: child_nodes.into_boxed_slice(),
        cands: cands_out.into_boxed_slice(),
        cand_routes: cand_routes.into_boxed_slice(),
        cand_kinds: cand_kinds.into_boxed_slice(),
        preds: parts.preds.into_boxed_slice(),
        blob: parts.blob.into_boxed_slice(),
        next: parts.next,
        content_hash: parts.content_hash,
    })
}

/// Builds one group's compressed path radix trie and emits the finished `Group`.
///
/// Deterministic: the same `cands` (in any order) and the same `parts` always produce
/// byte-identical arenas, because every intermediate map is a `BTreeMap` and every
/// tie-break is on a value, never on an iteration order.
///
/// Build-time only. Allocates freely; it runs on a dedicated thread, seconds apart
/// from the last build.
///
/// # Errors
/// See `TrieBuildError`.
pub fn build_group(cands: &[CandInput<'_>], parts: GroupParts) -> Result<Group, TrieBuildError> {
    // Step 0: validate every candidate key, before touching the arena.
    for c in cands {
        if c.key.is_empty() || c.key.first() != Some(&b'/') {
            return Err(TrieBuildError::KeyNotAbsolute);
        }
        if c.key.len() > MAX_PATH_BYTES {
            return Err(TrieBuildError::KeyTooLong);
        }
    }

    // Global precedence uniqueness. The issue's step 6.2 sorts and checks for a
    // duplicate PER NODE, which only catches two candidates that land on the
    // SAME node. `CandInput::prec` is documented to be unique across the WHOLE
    // TABLE, and `tests::duplicate_precedence_rejected` puts its two colliding
    // candidates on two DIFFERENT keys, so a per-node-only check would let that
    // case through uncaught, because the two candidates never share a node's
    // sorted slice. This does the same adjacent-pair-after-sort check
    // `assign_ordinals` (`precedence.rs`) uses, but over every candidate this
    // call was given, once, before any node's own slice is ever built.
    let mut by_prec: Vec<Precedence> = cands.iter().map(|c| c.prec).collect();
    by_prec.sort_unstable_by_key(|&p| Reverse(p));
    for pair in by_prec.windows(2) {
        if let [a, b] = pair
            && a == b
        {
            return Err(TrieBuildError::DuplicatePrecedence { prec: *a });
        }
    }

    let max_nodes = parts.max_nodes;

    let mut arena: Vec<BuildNode> = Vec::new();
    push_node(
        &mut arena,
        BuildNode {
            label: Vec::new(),
            children: BTreeMap::new(),
            cands: Vec::new(),
            key_len: 0,
            subtree: 0,
        },
        max_nodes,
    )?;

    // Step 1: insert the DISTINCT keys in ascending byte order. Insertion order
    // is therefore a function of the key set alone, never of the order `cands`
    // arrived in, which is what makes `tests::insertion_order_independent` hold.
    //
    // Both `BTreeSet`/`BTreeMap` below are built via `.collect()` from a
    // sequence rather than a per-element `.insert()` loop, which is the same
    // `BTreeSet<&[u8]>` / `BTreeMap<&[u8], usize>` the issue specifies (never a
    // hash-keyed map) but measurably faster: the standard library's bulk
    // `FromIterator` for these types recognizes already-ordered input and
    // builds the tree bottom-up in linear time, where a loop of individual
    // `.insert()` calls always re-descends from the root, and comparing two
    // of the pathologically prefix-sharing keys `bench_build_group_deep`
    // exercises is itself O(depth) in the worst case. Measured on that
    // 5,000-deep benchmark, this took the combined cost of building these two
    // maps from about 54 ms down to under 1 ms. The dominant remaining cost
    // on that same benchmark is `insert` itself walking from the root on
    // every one of the `K` keys, which this optimization does not touch; see
    // the finding filed against this issue for the measurements and why that
    // remainder looks structural rather than a bug in this file.
    let distinct: BTreeSet<&[u8]> = cands.iter().map(|c| c.key).collect();
    let mut node_of_pairs: Vec<(&[u8], usize)> = Vec::with_capacity(distinct.len());
    for key in &distinct {
        let idx = insert(&mut arena, key, max_nodes)?;
        node_of_pairs.push((key, idx));
    }
    // `node_of_pairs` is already ascending by key, because it was built by
    // iterating `distinct` (a `BTreeSet`) in order, so this `.collect()` gets
    // the same bulk fast path as `distinct`'s own construction above.
    let node_of: BTreeMap<&[u8], usize> = node_of_pairs.into_iter().collect();

    // Step 2: attach candidates.
    for (i, c) in cands.iter().enumerate() {
        let node_idx = *node_of
            .get(c.key)
            .ok_or(TrieBuildError::TooManyNodes { limit: max_nodes })?;
        // PINNED INVARIANT, the other half of `PathNode::up`'s doc comment
        // (`table/node.rs`), which is THIS issue's to preserve. `insert` only
        // ever returns from a point where `pos == key.len()`, so the node it
        // returns for `key` always has `key_len == key.len()`: the node
        // `node_of` maps every key to is that key's FULL-DEPTH node, never a
        // shallower proxy such as a split's intermediate. Attaching every
        // candidate here, at `node_of[c.key]`, is therefore always attaching it
        // at full depth, for every `PathKind` including `Exact`.
        //
        // This is what the argument in `PathNode::up`'s doc comment needs to be
        // true: an `Exact` candidate's node is the deepest node on its own
        // key's walk only because it IS that key's full-depth node, never a
        // prefix of it. Combined with `up` being constrained to a strictly
        // shallower, candidate-owning ancestor (`table/mod.rs`'s `UpLink`
        // check, #51's half), a descent that visits the deepest matching node
        // first and then walks `up` can never skip past an `Exact` match to a
        // shallower `Prefix` one at a different depth, and when both sit on the
        // SAME node (an `Exact` and a `Prefix` on the same literal key), the
        // `PathKind` bits in `Precedence` give `Exact` the win, which is
        // Gateway API's rule 1. If a future change ever attached an `Exact`
        // candidate anywhere other than `node_of[c.key]` (for instance to the
        // node `insert` returned for a DIFFERENT, shorter key, or to a split's
        // intermediate before it descends further), routing would silently
        // disagree with the specification on exactly the requests where an
        // `Exact` and a `Prefix` rule collide, and no test that fails to
        // straddle that exact boundary would notice.
        node_mut(&mut arena, node_idx, max_nodes)?.cands.push(i);
    }

    // Step 3: subtree sizes.
    sizes(&mut arena, max_nodes)?;

    // Step 4: `up` links, by intermediate index.
    let up_old = visit(&arena, max_nodes)?;

    // Step 5: final preorder numbering.
    let (order, old_to_new) = number(&arena, max_nodes)?;

    // Step 6: emission.
    emit(&arena, &order, &old_to_new, &up_old, cands, parts)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::ids::{ActionId, NodeId, RouteId, SENTINEL};
    use crate::precedence::{PathKind, Precedence};
    use crate::table::{Cand, Group, PathNode, RouteTable, TableParts, ValidateError, node_flags};

    use super::{BuildNode, CandInput, GroupParts, TrieBuildError, build_group, insert};

    /// One unconditional candidate on `key` with the given kind, whose `prec` is
    /// `Precedence::pack(kind, false, 0, 0, ordinal)`, `action` is `ActionId(ordinal)`,
    /// `route` is `RouteId(ordinal)` and `preds` is `SENTINEL`.
    fn cand(key: &str, kind: PathKind, ordinal: u32) -> CandInput<'_> {
        CandInput {
            key: key.as_bytes(),
            kind,
            prec: Precedence::pack(kind, false, 0, 0, ordinal),
            action: ActionId(ordinal),
            route: RouteId(ordinal),
            preds: SENTINEL,
        }
    }

    /// Generous defaults every test starts from, overriding only what it cares
    /// about. `GroupParts` has no `Default` (see the issue's Public API), so a
    /// local helper keeps every test from repeating the same six fields.
    fn default_parts() -> GroupParts {
        GroupParts {
            preds: Vec::new(),
            blob: Vec::new(),
            next: crate::ids::GroupId::NONE,
            content_hash: 0,
            max_nodes: 1_000_000,
            max_blob_bytes: 10_000_000,
        }
    }

    /// Wraps one group into a table, the shape every test in this module uses to
    /// exercise `validate()` per the issue's shared test preamble.
    fn wrap(group: Group) -> RouteTable {
        RouteTable::from_parts(TableParts {
            groups: vec![group],
            ..Default::default()
        })
    }

    /// `["/", "/<first>", ..., "/<last>"]` for an inclusive ASCII byte range, used
    /// by the dense-threshold tests to build a key set of a chosen width without
    /// repeating the same construction twice.
    fn path_keys(letters: std::ops::RangeInclusive<u8>) -> Vec<String> {
        let mut keys = vec!["/".to_owned()];
        for byte in letters {
            keys.push(format!("/{}", char::from(byte)));
        }
        keys
    }

    /// One unconditional `SegmentPrefix` candidate per key, with distinct
    /// ordinals assigned in slice order.
    fn keyed_cands(keys: &[String]) -> Vec<CandInput<'_>> {
        keys.iter()
            .enumerate()
            .map(|(i, k)| {
                let ordinal = u32::try_from(i).unwrap();
                cand(k, PathKind::SegmentPrefix, ordinal)
            })
            .collect()
    }

    /// The seven arrays `tests::insertion_order_independent` and any future test
    /// needing to compare two builds must agree on byte for byte.
    #[derive(Debug, PartialEq)]
    struct Snapshot {
        nodes: Vec<PathNode>,
        child_bytes: Vec<u8>,
        child_nodes: Vec<u32>,
        cands: Vec<Cand>,
        cand_routes: Vec<RouteId>,
        cand_kinds: Vec<u8>,
        blob: Vec<u8>,
    }

    impl Snapshot {
        fn of(group: &Group) -> Snapshot {
            Snapshot {
                nodes: group.nodes.to_vec(),
                child_bytes: group.child_bytes.to_vec(),
                child_nodes: group.child_nodes.to_vec(),
                cands: group.cands.to_vec(),
                cand_routes: group.cand_routes.to_vec(),
                cand_kinds: group.cand_kinds.to_vec(),
                blob: group.blob.to_vec(),
            }
        }
    }

    #[test]
    fn empty_group_has_one_node() {
        let group = build_group(&[], default_parts()).unwrap();
        assert_eq!(group.nodes.len(), 1);
        assert!(group.cands.is_empty());
        assert!(group.blob.is_empty());
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn single_root_prefix() {
        let cands = [cand("/", PathKind::SegmentPrefix, 0)];
        let group = build_group(&cands, default_parts()).unwrap();
        assert_eq!(group.nodes.len(), 2);
        let child = *group.node(NodeId(1)).unwrap();
        assert_eq!(child.key_len, 1);
        assert_eq!(group.label(&child), b"/");
        assert_eq!(child.cand_n, 1);
        assert_ne!(child.flags & node_flags::NODE_SINGLE_UNCOND, 0);
        assert_ne!(child.flags & node_flags::NODE_HAS_PREFIX, 0);
        assert_eq!(child.up, SENTINEL);
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn two_candidates_same_key_sorted() {
        let cands = [
            cand("/api", PathKind::Exact, 5),
            cand("/api", PathKind::Exact, 1),
        ];
        let group = build_group(&cands, default_parts()).unwrap();
        let node = *group.node(NodeId(1)).unwrap();
        assert_eq!(node.cand_n, 2);
        let node_cands = group.cands_of(&node);
        assert!(node_cands[0].prec > node_cands[1].prec);
        assert_eq!(node_cands[0].prec.ordinal(), 1);
        assert_eq!(node_cands[0].action, ActionId(1));
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn split_creates_intermediate() {
        let cands = [
            cand("/abc", PathKind::Exact, 0),
            cand("/abd", PathKind::Exact, 1),
        ];
        let group = build_group(&cands, default_parts()).unwrap();
        assert_eq!(group.nodes.len(), 4);
        let mid = group
            .nodes
            .iter()
            .find(|n| n.key_len == 3)
            .expect("the split must produce one key_len-3 intermediate");
        assert_eq!(mid.cand_n, 0);
        let leaves: Vec<&PathNode> = group.nodes.iter().filter(|n| n.key_len == 4).collect();
        assert_eq!(leaves.len(), 2);
        for leaf in leaves {
            assert_eq!(
                leaf.up, SENTINEL,
                "the intermediate owns no candidate, so there is nothing shallower to fall back to"
            );
        }
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn nested_keys_set_up_links() {
        let cands = [
            cand("/a", PathKind::Exact, 0),
            cand("/a/b", PathKind::Exact, 1),
            cand("/a/b/c", PathKind::Exact, 2),
        ];
        let group = build_group(&cands, default_parts()).unwrap();
        assert_eq!(group.nodes.len(), 4);
        let a = group.node(NodeId(1)).unwrap();
        let ab = group.node(NodeId(2)).unwrap();
        let abc = group.node(NodeId(3)).unwrap();
        assert_eq!(a.key_len, 2);
        assert_eq!(ab.key_len, 4);
        assert_eq!(abc.key_len, 6);
        assert_eq!(ab.up, 1, "the /a/b node's up must be the /a node");
        assert_eq!(abc.up, 2, "the /a/b/c node's up must be the /a/b node");
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn insertion_order_independent() {
        let base = [
            cand("/a", PathKind::Exact, 0),
            cand("/a/b", PathKind::Exact, 1),
            cand("/a/b/c", PathKind::Exact, 2),
        ];
        let perms: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut reference: Option<Snapshot> = None;
        for perm in perms {
            let ordered: Vec<CandInput<'_>> = perm.iter().map(|&i| base[i]).collect();
            let group = build_group(&ordered, default_parts()).unwrap();
            let snapshot = Snapshot::of(&group);
            let table = wrap(group);
            assert_eq!(table.validate(), Vec::new());
            match &reference {
                None => reference = Some(snapshot),
                Some(r) => assert_eq!(
                    *r, snapshot,
                    "build must be independent of candidate submission order"
                ),
            }
        }
    }

    #[test]
    fn dense_threshold() {
        let sparse_keys = path_keys(b'a'..=b'p');
        let sparse_cands = keyed_cands(&sparse_keys);
        let sparse_group = build_group(&sparse_cands, default_parts()).unwrap();
        let sparse_root_child = *sparse_group.node(NodeId(1)).unwrap();
        assert_eq!(sparse_root_child.flags & node_flags::NODE_DENSE, 0);
        assert_eq!(sparse_root_child.child_n, 16);
        for byte in b'a'..=b'p' {
            assert!(sparse_group.child(&sparse_root_child, byte).is_some());
        }
        assert!(sparse_group.child(&sparse_root_child, b'A').is_none());
        let sparse_table = wrap(sparse_group);
        assert_eq!(sparse_table.validate(), Vec::new());

        let dense_keys = path_keys(b'a'..=b'q');
        let dense_cands = keyed_cands(&dense_keys);
        let dense_group = build_group(&dense_cands, default_parts()).unwrap();
        let dense_root_child = *dense_group.node(NodeId(1)).unwrap();
        assert_ne!(dense_root_child.flags & node_flags::NODE_DENSE, 0);
        assert_eq!(dense_root_child.child_n, 0);
        for byte in b'a'..=b'q' {
            assert!(dense_group.child(&dense_root_child, byte).is_some());
        }
        assert!(dense_group.child(&dense_root_child, b'A').is_none());
        let dense_table = wrap(dense_group);
        assert_eq!(dense_table.validate(), Vec::new());
    }

    #[test]
    fn children_sorted_by_subtree_size() {
        let keys = [
            "/a".to_owned(),
            "/b/1".to_owned(),
            "/b/2".to_owned(),
            "/b/3".to_owned(),
        ];
        let cands = keyed_cands(&keys);
        let group = build_group(&cands, default_parts()).unwrap();
        let mid = *group.node(NodeId(1)).unwrap();
        let start = mid.children as usize;
        let end = start + usize::from(mid.child_n);
        assert_eq!(&group.child_bytes[start..end], [b'b', b'a']);
        let b_child = group.child(&mid, b'b').unwrap();
        let a_child = group.child(&mid, b'a').unwrap();
        assert!(
            b_child.0 < a_child.0,
            "preorder must visit the larger /b subtree before /a"
        );
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn blob_prefix_preserved() {
        let mut parts = default_parts();
        parts.blob = b"PREDLITERAL".to_vec();
        let cands = [cand("/api", PathKind::Exact, 0)];
        let group = build_group(&cands, parts).unwrap();
        assert!(group.blob.starts_with(b"PREDLITERAL"));
        for node in &group.nodes {
            assert!(node.blob_off >= 11);
        }
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn key_too_long() {
        let mut key = vec![b'/'];
        key.extend(std::iter::repeat_n(b'a', crate::limits::MAX_PATH_BYTES));
        let c = CandInput {
            key: &key,
            kind: PathKind::Exact,
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            action: ActionId(0),
            route: RouteId(0),
            preds: SENTINEL,
        };
        let err = build_group(&[c], default_parts()).unwrap_err();
        assert_eq!(err, TrieBuildError::KeyTooLong);
    }

    /// The other half of edge case 10 ("Key with a 8192-byte length.
    /// Accepted. 8193: `KeyTooLong`."), which `key_too_long` above does not
    /// cover: it only exercises the REJECT side. Mutation-testing gap found
    /// by `cargo mutants`: both `c.key.len() > MAX_PATH_BYTES` in this
    /// function's Step 0 and `key_len_usize > MAX_PATH_BYTES` in `emit`'s
    /// step 7 survived being mutated to `==` or `>=`, because no test built
    /// a key of EXACTLY `MAX_PATH_BYTES` bytes and asserted it succeeds.
    /// `>` and `==`/`>=` only disagree exactly at that boundary; a key one
    /// byte longer (already covered by `key_too_long`) cannot distinguish
    /// them, because every one of `>`, `==` and `>=` correctly reject it.
    #[test]
    fn key_at_max_length_is_accepted() {
        let mut key = vec![b'/'];
        key.extend(std::iter::repeat_n(b'a', crate::limits::MAX_PATH_BYTES - 1));
        assert_eq!(key.len(), crate::limits::MAX_PATH_BYTES);
        let c = CandInput {
            key: &key,
            kind: PathKind::Exact,
            prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            action: ActionId(0),
            route: RouteId(0),
            preds: SENTINEL,
        };
        let group = build_group(&[c], default_parts()).unwrap();
        let leaf = group
            .nodes
            .iter()
            .find(|n| usize::from(n.key_len) == crate::limits::MAX_PATH_BYTES)
            .expect("the single candidate's node must carry the full key length");
        assert_eq!(usize::from(leaf.key_len), crate::limits::MAX_PATH_BYTES);
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn key_not_absolute() {
        for bad_key in [&b""[..], &b"abc"[..]] {
            let c = CandInput {
                key: bad_key,
                kind: PathKind::Exact,
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
                action: ActionId(0),
                route: RouteId(0),
                preds: SENTINEL,
            };
            let err = build_group(&[c], default_parts()).unwrap_err();
            assert_eq!(err, TrieBuildError::KeyNotAbsolute);
        }
    }

    #[test]
    fn too_many_nodes() {
        let cands = [
            cand("/abc", PathKind::Exact, 0),
            cand("/abd", PathKind::Exact, 1),
        ];
        let mut parts = default_parts();
        parts.max_nodes = 2;
        let err = build_group(&cands, parts).unwrap_err();
        assert_eq!(err, TrieBuildError::TooManyNodes { limit: 2 });
    }

    #[test]
    fn blob_budget_is_checked_before_appending() {
        // The check happens INSIDE the emission loop, before each append, and
        // not once at the end: the total edge-label size is bounded only by the
        // input, so a post-hoc check would let a hostile route set allocate
        // gigabytes before ever reporting the failure. `max_blob_bytes` is set
        // below either label's own length here, so a post-hoc implementation
        // would have had to append at least one oversized label, growing `blob`
        // past the cap, before it could report what this test expects to never
        // observe.
        let key_a = format!("/{}", "a".repeat(10));
        let key_b = format!("/{}", "b".repeat(9));
        let cands = [
            cand(&key_a, PathKind::Exact, 0),
            cand(&key_b, PathKind::Exact, 1),
        ];
        let mut parts = default_parts();
        parts.max_blob_bytes = 8;
        let err = build_group(&cands, parts).unwrap_err();
        assert_eq!(err, TrieBuildError::BlobTooLarge);
    }

    /// Mutation-testing gap found by `cargo mutants`: `check_blob_budget`'s
    /// `projected > cap` compiles and passes every other named test even when
    /// mutated to `projected >= cap`, because no test lands `blob.len()`
    /// exactly ON the cap. The budget is a ceiling a build may legitimately
    /// reach, not a value it must stay strictly under, so a blob that ends up
    /// exactly `max_blob_bytes` bytes long must still build successfully.
    /// `/api` is 4 bytes, the only key, so with an empty `GroupParts::blob`
    /// the emitted blob is exactly those 4 bytes: `max_blob_bytes: 4` is
    /// therefore an exact fit, not a breach.
    #[test]
    fn blob_budget_boundary_allows_exact_fit() {
        let cands = [cand("/api", PathKind::Exact, 0)];
        let mut parts = default_parts();
        parts.max_blob_bytes = 4;
        let group = build_group(&cands, parts).unwrap();
        assert_eq!(group.blob.len(), 4);
        assert_eq!(&*group.blob, b"/api");
        let table = wrap(group);
        assert_eq!(table.validate(), Vec::new());
    }

    #[test]
    fn duplicate_precedence_rejected() {
        let shared = Precedence::pack(PathKind::Exact, false, 0, 0, 7);
        let a = CandInput {
            key: b"/a",
            kind: PathKind::Exact,
            prec: shared,
            action: ActionId(0),
            route: RouteId(0),
            preds: SENTINEL,
        };
        let b = CandInput {
            key: b"/b",
            kind: PathKind::Exact,
            prec: shared,
            action: ActionId(1),
            route: RouteId(1),
            preds: SENTINEL,
        };
        let err = build_group(&[a, b], default_parts()).unwrap_err();
        assert_eq!(err, TrieBuildError::DuplicatePrecedence { prec: shared });
    }

    #[test]
    fn deep_chain_no_stack_overflow() {
        // Width: 50,000 candidates on "/p/{i:05}". The "/p/" node has 5 children
        // (leading digits 0..=4) and every level below has 10, so every node
        // sits on the sparse path: about 55,500 nodes total.
        let wide_keys: Vec<String> = (0..50_000u32).map(|i| format!("/p/{i:05}")).collect();
        let wide_cands = keyed_cands(&wide_keys);
        let wide_group = build_group(&wide_cands, default_parts()).unwrap();
        let wide_table = wrap(wide_group);
        assert_eq!(wide_table.validate(), Vec::new());

        // Depth: 5,000 candidates nesting 5,000 deep ("/a", "/aa", "/aaa", ...),
        // the shape that actually exercises walk depth; the longest key is
        // 5,001 bytes, under MAX_PATH_BYTES.
        let deep_keys: Vec<String> = (1..=5000usize)
            .map(|n| format!("/{}", "a".repeat(n)))
            .collect();
        let deep_cands = keyed_cands(&deep_keys);
        let deep_group = build_group(&deep_cands, default_parts()).unwrap();
        let deep_table = wrap(deep_group);
        assert_eq!(deep_table.validate(), Vec::new());
    }

    #[test]
    fn segment_prefix_on_unaligned_node_is_loud() {
        let c = cand("/ab/", PathKind::SegmentPrefix, 0);
        let group = build_group(&[c], default_parts()).unwrap();
        let node = *group.node(NodeId(1)).unwrap();
        assert_eq!(group.label(&node), b"/ab/");
        let table = wrap(group);
        let errors = table.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidateError::PrefixNotSegmentAligned { .. })),
            "a SegmentPrefix candidate on an unaligned key must be loud, not silently fixed up"
        );
    }

    #[test]
    fn insert_split_returns_intermediate() {
        let mut arena: Vec<BuildNode> = vec![BuildNode {
            label: Vec::new(),
            children: std::collections::BTreeMap::new(),
            cands: Vec::new(),
            key_len: 0,
            subtree: 0,
        }];
        let first = insert(&mut arena, b"/a/b", 1000).unwrap();
        let second = insert(&mut arena, b"/a", 1000).unwrap();
        assert_ne!(first, second);
        let mid = arena.get(second).unwrap();
        assert_eq!(mid.key_len, 2);
        let child_idx = *mid.children.get(&b'/').unwrap();
        let child = arena.get(child_idx).unwrap();
        assert_eq!(child.label.as_slice(), b"/b");
    }

    /// Path-shaped strings: 1 to 4 segments, each drawn from a fixed set, joined
    /// with `/` and prefixed with one, matching `tests::up_chain_terminates`'s
    /// generator description.
    fn arb_key() -> impl Strategy<Value = String> {
        let segment = prop::sample::select(vec!["a", "b", "ab", "abc", "x1"]);
        prop::collection::vec(segment, 1..=4).prop_map(|segments| {
            let mut key = String::new();
            for segment in segments {
                key.push('/');
                key.push_str(segment);
            }
            key
        })
    }

    proptest! {
        #[test]
        fn up_chain_terminates(keys in prop::collection::vec(arb_key(), 1..=40)) {
            let cand_inputs: Vec<CandInput<'_>> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let ordinal = u32::try_from(i).expect("proptest bounds the vector to 40 elements");
                    cand(k, PathKind::Exact, ordinal)
                })
                .collect();
            let group = build_group(&cand_inputs, default_parts()).unwrap();

            for node in &*group.nodes {
                let mut current = *node;
                let mut steps = 0usize;
                while current.up != SENTINEL {
                    steps += 1;
                    prop_assert!(steps <= group.nodes.len());
                    let next = *group.node(NodeId(current.up)).unwrap();
                    prop_assert!(next.key_len < current.key_len);
                    current = next;
                }
            }
        }
    }
}
