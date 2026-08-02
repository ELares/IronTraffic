// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Byte-wise descent of a group's compiled path radix trie, and the Gateway
//! API `PathPrefix` segment-boundary rule the candidate scan applies to
//! whatever node the descent returns.
//!
//! [`descend`] walks `path` byte by byte from a group's root, following the
//! child whose edge label the next bytes match, and stops the moment nothing
//! matches further. It returns the DEEPEST node whose full key is a prefix of
//! `path`: if the final edge label only partially matched, that node is not
//! returned, the last FULLY matched node is. `match-request-core` (#60) then
//! walks `PathNode::up` from there, evaluating candidates and predicates;
//! this module performs none of that, and it has no wildcard or `{id}`
//! parameter support at all: adding one would reintroduce the backtracking
//! class the visit budget below exists to bound.
//!
//! The descent is bounded by a caller-supplied node-visit `budget`
//! (`4 * path.len() + 64`, `crate::limits::visit_budget`), decremented and
//! checked at the TOP of every loop iteration, before any arena access. On
//! exhaustion the descent reports [`Descent::exhausted`] rather than
//! continuing, so a crafted path can never spend more than a budget's worth
//! of node visits regardless of how the route table is shaped. A budget
//! checked only after the loop, or once every few iterations, is not a
//! budget.
//!
//! [`prefix_boundary_ok`] is the ONLY prefix semantics this crate offers.
//! Envoy's original `prefix` field is a raw string prefix and therefore
//! matches `/abcd` against `/abc`; Envoy had to add `path_separated_prefix`
//! to fix it. A raw, non-segment-boundary string prefix is an authorization
//! bypass wherever a prefix guards a protected subtree, and this crate does
//! not offer it, not even behind a flag.
//!
//! The `HOT PATH` marker above puts this whole file, every function in it,
//! under `scripts/invariant-lints.sh`'s `hot-path-allocation` and
//! `hot-path-lock` rules: a text scan of the entire production-code body for
//! every call that can allocate or lock, run in CI on every pull request.
//! `tests/no_alloc.rs`'s `descend_allocates_nothing` guards the marker line
//! itself, the same mechanism `src/normalize.rs` and `src/scratch.rs`
//! already use. A process-wide counting `#[global_allocator]` does not
//! compile in this tree (`GlobalAlloc` is an `unsafe trait`, and this crate
//! is `#![forbid(unsafe_code)]`) and would be unsound here regardless, since
//! it would count every other test's allocations too.
//!
//! This module is INERT: [`descend`] is called by `match-request-core` (#60).

use crate::ids::NodeId;
use crate::limits::MAX_PATH_BYTES;
use crate::table::Group;

/// The result of a path-trie descent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Descent {
    /// The deepest node whose FULL key is a prefix of the path. [`NodeId::ROOT`]
    /// when no edge from the root matched.
    pub node: NodeId,
    /// That node's `key_len`, which is also the number of path bytes consumed.
    pub key_len: u16,
    /// Budget remaining after the descent.
    pub budget: u32,
    /// True when the budget hit zero during the descent. The caller must treat
    /// this as a hard no-match and increment its exhaustion counter; it must
    /// NOT continue into the `up` walk or the next group.
    pub exhausted: bool,
}

/// Descends `group`'s path trie byte-wise, returning the deepest node whose
/// full key is a prefix of `path`.
///
/// Allocation-free and panic-free. `budget` is decremented once per node
/// visit and checked at the top of the loop, so an exhausted budget stops the
/// descent immediately. The caller must check [`Descent::exhausted`] and
/// treat it as a hard no-match; continuing would let a crafted path spend an
/// unbounded number of visits across the group fallthrough chain.
///
/// Performs NO candidate, predicate or segment-boundary check. The caller
/// does that, starting at `Descent::node` and following `PathNode::up`.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "path.len() is refused above MAX_PATH_BYTES (8192) before the loop starts, and `consumed` never exceeds path.len(), so casting it to u16 is always lossless"
)]
pub fn descend(group: &Group, path: &[u8], budget: u32) -> Descent {
    if path.len() > MAX_PATH_BYTES {
        return Descent {
            node: NodeId::ROOT,
            key_len: 0,
            budget,
            exhausted: true,
        };
    }

    let mut node_idx: u32 = 0;
    let mut best: u32 = 0;
    let mut consumed: usize = 0;
    let mut budget = budget;

    loop {
        if budget == 0 {
            return Descent {
                node: NodeId(best),
                key_len: consumed as u16, // it-allow: unchecked-cast reason: path.len() was refused above MAX_PATH_BYTES (8192) before this loop starts, and consumed never exceeds path.len(), so this cannot truncate
                budget: 0,
                exhausted: true,
            };
        }
        budget -= 1;

        if consumed == path.len() {
            break;
        }

        let Some(parent) = group.node(NodeId(node_idx)) else {
            break;
        };
        let Some(&byte) = path.get(consumed) else {
            break;
        };
        let Some(child) = group.child(parent, byte) else {
            break;
        };
        let Some(child_node) = group.node(child) else {
            break;
        };
        let label = group.label(child_node);
        if label.is_empty() {
            // Corrupted arena: a zero-length label would never advance
            // `consumed`, so looping on it would never terminate. Treat it
            // as "nothing matched further" instead.
            break;
        }
        let Some(rest) = path.get(consumed..) else {
            break;
        };
        if rest.len() < label.len() {
            // The path ends inside the label: a partial match, not a full one.
            break;
        }
        if rest.get(..label.len()) != Some(label) {
            // Partial label match.
            break;
        }

        consumed += label.len();
        node_idx = child.0;
        best = child.0;
    }

    Descent {
        node: NodeId(best),
        key_len: consumed as u16, // it-allow: unchecked-cast reason: path.len() was refused above MAX_PATH_BYTES (8192) before this loop starts, and consumed never exceeds path.len(), so this cannot truncate
        budget,
        exhausted: false,
    }
}

/// Gateway API `PathPrefix` semantics: a node whose full key is `key_len`
/// bytes long matches the path as a prefix if and only if the path ends
/// exactly there, or the next path byte is `/`, or the key is the root
/// prefix.
///
/// `PathPrefix: /abc` therefore matches `/abc`, `/abc/` and `/abc/def`, and
/// never `/abcd`.
///
/// A `key_len` of 0 or 1 (the root node and the `/` node) is ALWAYS at a
/// boundary, and that case is not decoration: the key `/` already ends with
/// the separator, so the "next byte is `/`" test would fail for `/abc`, and
/// `PathPrefix: /`, the default match Gateway API gives every rule that
/// specifies no matches, would then match nothing at all.
#[must_use]
#[allow(
    clippy::cast_lossless,
    reason = "u16 to usize is a lossless widening; From is not yet callable in a const fn"
)]
pub const fn prefix_boundary_ok(path_len: usize, key_len: u16, next_byte: Option<u8>) -> bool {
    // `matches!`, not `next_byte == Some(b'/')`: `PartialEq` is not callable
    // in a const fn on stable Rust, and this function is const.
    key_len <= 1 || key_len as usize == path_len || matches!(next_byte, Some(b'/'))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;

    use crate::ids::{ActionId, GroupId, NodeId, RouteId, SENTINEL};
    use crate::limits::{MAX_PATH_BYTES, visit_budget};
    use crate::precedence::{PathKind, Precedence};
    use crate::table::{Group, PathNode};
    use crate::{CandInput, GroupParts, build_group};

    use super::{descend, prefix_boundary_ok};

    /// Generous defaults every test starts from, mirroring
    /// `build::path_trie::tests::default_parts`.
    fn default_parts() -> GroupParts {
        GroupParts {
            preds: Vec::new(),
            blob: Vec::new(),
            next: GroupId::NONE,
            content_hash: 0,
            max_nodes: 1_000_000,
            max_blob_bytes: 10_000_000,
        }
    }

    /// Builds a group from `keys`, giving each key one unconditional
    /// `SegmentPrefix` candidate with a distinct ordinal. The candidate scan
    /// itself is out of scope for this module; every key just needs SOME
    /// candidate to be a legal insertion into the trie.
    fn group_of(keys: &[&str]) -> Group {
        let cands: Vec<CandInput<'_>> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let ordinal = u32::try_from(i).unwrap();
                CandInput {
                    key: key.as_bytes(),
                    kind: PathKind::SegmentPrefix,
                    prec: Precedence::pack(PathKind::SegmentPrefix, false, 0, 0, ordinal),
                    action: ActionId(ordinal),
                    route: RouteId(ordinal),
                    preds: SENTINEL,
                }
            })
            .collect();
        build_group(&cands, default_parts()).unwrap()
    }

    /// Reconstructs every reachable node's full key by a forward walk from
    /// the root, concatenating each edge label as it is followed. `descend`
    /// never does this itself (it would make the descent O(depth * length));
    /// this exists only so the property tests below have an oracle to check
    /// `descend`'s answer against.
    fn full_keys(g: &Group) -> HashMap<NodeId, Vec<u8>> {
        let mut map = HashMap::new();
        let mut stack: Vec<(NodeId, Vec<u8>)> = vec![(NodeId::ROOT, Vec::new())];
        while let Some((id, prefix)) = stack.pop() {
            let Some(node) = g.node(id) else { continue };
            for byte in 0u8..=255 {
                if let Some(child) = g.child(node, byte)
                    && let Some(child_node) = g.node(child)
                {
                    let mut child_key = prefix.clone();
                    child_key.extend_from_slice(g.label(child_node));
                    stack.push((child, child_key));
                }
            }
            map.insert(id, prefix);
        }
        map
    }

    #[test]
    fn empty_path() {
        let g = group_of(&["/"]);
        let d = descend(&g, b"", 100);
        assert_eq!(d.node, NodeId::ROOT);
        assert_eq!(d.key_len, 0);
        assert!(!d.exhausted);
        assert_eq!(d.budget, 99);
    }

    #[test]
    fn root_key_exact() {
        let g = group_of(&["/"]);
        let d = descend(&g, b"/", 100);
        assert_eq!(d.key_len, 1);
        assert!(!d.exhausted);
    }

    #[test]
    fn shorter_path_than_label() {
        let g = group_of(&["/api"]);
        let d = descend(&g, b"/a", 100);
        assert_eq!(d.node, NodeId::ROOT);
        assert_eq!(d.key_len, 0);
    }

    #[test]
    fn longer_path_stops_at_node() {
        let g = group_of(&["/abc"]);
        let d = descend(&g, b"/abcd", 100);
        assert_eq!(d.key_len, 4);
        assert!(!prefix_boundary_ok(5, 4, Some(b'd')));
        assert!(prefix_boundary_ok(4, 4, None));
        assert!(prefix_boundary_ok(8, 4, Some(b'/')));
    }

    /// `PathPrefix: /` is the default match for every rule with no matches,
    /// so a `key_len` of 1 failing here would 404 the most common route in
    /// any Gateway API config.
    #[test]
    fn root_prefix_is_always_at_a_boundary() {
        assert!(prefix_boundary_ok(4, 1, Some(b'a')));
        assert!(prefix_boundary_ok(1, 1, None));
        assert!(prefix_boundary_ok(9000, 0, Some(b'x')));
    }

    #[test]
    fn deepest_wins() {
        let g = group_of(&["/abc", "/abc/def"]);
        let d = descend(&g, b"/abc/def", 100);
        assert_eq!(d.key_len, 8);
        assert!(!d.exhausted);
    }

    #[test]
    fn partial_label_falls_back() {
        let g = group_of(&["/abc", "/abc/def"]);
        let d = descend(&g, b"/abc/de", 100);
        assert_eq!(d.key_len, 4);
    }

    #[test]
    fn label_mismatch() {
        let g = group_of(&["/abc"]);
        let d = descend(&g, b"/abz", 100);
        assert_eq!(d.node, NodeId::ROOT);
        assert_eq!(d.key_len, 0);
    }

    #[test]
    fn deep_path_within_budget() {
        let keys: Vec<String> = (1..=512usize).map(|n| "/a".repeat(n)).collect();
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let g = group_of(&key_refs);

        let path = "/a".repeat(512);
        let path_bytes = path.as_bytes();
        assert_eq!(path_bytes.len(), 1024);

        let budget_in = visit_budget(path_bytes.len());
        assert_eq!(budget_in, 4160);

        let d = descend(&g, path_bytes, budget_in);
        assert!(!d.exhausted);
        assert_eq!(d.key_len, 1024);

        let spent = budget_in - d.budget;
        assert!(spent <= u32::try_from(path_bytes.len()).unwrap() + 2);
    }

    /// Mutation-testing gap found by `cargo mutants` (`-j 1`, scoped to this
    /// file): line 0's `path.len() > MAX_PATH_BYTES` survived being mutated
    /// to `>=`, because no named test lands `path.len()` exactly ON the
    /// ceiling. `MAX_PATH_BYTES` is a value the descent may legitimately
    /// receive, not one it must refuse; `oversize_path_is_refused` below only
    /// exercises the strictly-longer side, which cannot distinguish `>` from
    /// `>=`.
    #[test]
    fn path_at_max_length_is_accepted() {
        let key = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(key.len(), MAX_PATH_BYTES);
        let g = group_of(&[key.as_str()]);

        let path = key.as_bytes();
        let budget = visit_budget(path.len());
        let d = descend(&g, path, budget);
        assert!(!d.exhausted);
        assert_eq!(usize::from(d.key_len), MAX_PATH_BYTES);
    }

    /// Edge case 8a: a path longer than `MAX_PATH_BYTES`, with a huge budget.
    /// Without the line-0 guard, `consumed as u16` would wrap and report a
    /// `key_len` that does not describe the matched prefix.
    #[test]
    fn oversize_path_is_refused() {
        let g = group_of(&["/a"]);
        let big_path = "/a".repeat(50_000);
        assert_eq!(big_path.len(), 100_000);

        let d = descend(&g, big_path.as_bytes(), u32::MAX);
        assert!(d.exhausted);
        assert_eq!(d.key_len, 0);
        assert_eq!(d.node, NodeId::ROOT);
        assert_eq!(d.budget, u32::MAX);
    }

    #[test]
    fn budget_zero() {
        let g = group_of(&["/abc"]);
        let d = descend(&g, b"/abc", 0);
        assert!(d.exhausted);
        assert_eq!(d.budget, 0);
        assert_eq!(d.node, NodeId::ROOT);
    }

    #[test]
    fn budget_exhausted_midway() {
        let keys: Vec<String> = (1..=20usize).map(|n| "/a".repeat(n)).collect();
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let g = group_of(&key_refs);
        let path = "/a".repeat(20);

        let d = descend(&g, path.as_bytes(), 5);
        assert!(d.exhausted);
        assert!(usize::from(d.key_len) < path.len());
    }

    /// A hand-built group whose single child has a corrupted, zero-length
    /// label. `descend` returning at all (rather than looping forever) is
    /// itself the assertion; `node == ROOT` pins the exact shape of that
    /// return.
    #[test]
    fn corrupt_zero_length_label_terminates() {
        let root = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 0,
            child_n: 1,
            flags: 0,
        };
        let bad_child = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 0, // corrupted: a zero-length label
            cand_n: 0,
            key_len: 1,
            child_n: 0,
            flags: 0,
        };
        let g = crate::table::tests::tiny_group(
            vec![root, bad_child],
            vec![b'a'],
            vec![1],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            GroupId::NONE,
        );
        let d = descend(&g, b"aaaa", 1000);
        assert_eq!(d.node, NodeId::ROOT);
    }

    /// A hand-built group whose root's child for byte `a` is node 1, and node
    /// 1's own child for byte `a` is node 1 itself. Each iteration still
    /// consumes one path byte (labels are non-empty), so the loop terminates
    /// in at most `path.len()` iterations regardless of the cycle: 8 bytes
    /// consumed one per iteration, then a ninth iteration spends its budget
    /// and breaks because `consumed == path.len()`, so exactly 9 budget is
    /// spent.
    #[test]
    fn corrupt_cycle_terminates() {
        let root = PathNode {
            blob_off: 0,
            children: 0,
            cands: 0,
            up: SENTINEL,
            blob_len: 0,
            cand_n: 0,
            key_len: 0,
            child_n: 1,
            flags: 0,
        };
        let node1 = PathNode {
            blob_off: 0,
            children: 1,
            cands: 0,
            up: SENTINEL,
            blob_len: 1,
            cand_n: 0,
            key_len: 1,
            child_n: 1,
            flags: 0,
        };
        let g = crate::table::tests::tiny_group(
            vec![root, node1],
            vec![b'a', b'a'],
            vec![1, 1],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            b"a".to_vec(),
            GroupId::NONE,
        );
        let d = descend(&g, b"aaaaaaaa", 1000);
        assert_eq!(d.budget, 991);
    }

    #[test]
    fn binary_and_percent_bytes() {
        let g = group_of(&["/a%2Fb", "/a/b"]);

        let d1 = descend(&g, b"/a%2Fb", 100);
        assert_eq!(usize::from(d1.key_len), "/a%2Fb".len());

        let d2 = descend(&g, b"/a/b", 100);
        assert_eq!(usize::from(d2.key_len), "/a/b".len());

        assert_ne!(d1.node, d2.node);

        let mut weird = b"/a".to_vec();
        weird.push(0xff);
        let d3 = descend(&g, &weird, 100);
        // No particular match is required; not panicking is the assertion.
        let _ = d3;
    }

    /// Path-shaped strings for the property tests: 0 to 5 segments drawn
    /// from a small alphabet, joined with `/`, always prefixed with a
    /// leading `/` so every generated value is a legal candidate key or a
    /// legal request path.
    fn arb_key_segment_path() -> impl Strategy<Value = String> {
        let segment = prop::sample::select(vec!["a", "b", "ab", "x"]);
        prop::collection::vec(segment, 0..=5).prop_map(|segments| {
            let mut s = String::from("/");
            s.push_str(&segments.join("/"));
            s
        })
    }

    proptest! {
        #[test]
        fn key_is_a_prefix_of_path(
            keys in prop::collection::vec(arb_key_segment_path(), 1..=20),
            path in arb_key_segment_path(),
        ) {
            let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            let g = group_of(&key_refs);
            let path_bytes = path.as_bytes();
            let budget = visit_budget(path_bytes.len());
            let d = descend(&g, path_bytes, budget);
            prop_assert!(!d.exhausted);

            let keymap = full_keys(&g);
            let winner_key = keymap.get(&d.node).cloned().unwrap_or_default();
            prop_assert_eq!(winner_key.len(), usize::from(d.key_len));
            prop_assert!(path_bytes.starts_with(winner_key.as_slice()));

            for key in keymap.values() {
                if key.len() > winner_key.len() {
                    prop_assert!(!path_bytes.starts_with(key.as_slice()));
                }
            }
        }
    }

    proptest! {
        #[test]
        fn segment_prefix_soundness(q in arb_key_segment_path(), p in arb_key_segment_path()) {
            let g = group_of(&[q.as_str()]);
            let path_bytes = p.as_bytes();
            let budget = visit_budget(path_bytes.len());
            let d = descend(&g, path_bytes, budget);
            prop_assert!(!d.exhausted);

            let qlen = q.len();
            let reaches_q = usize::from(d.key_len) == qlen;
            let next_byte = path_bytes.get(qlen).copied();
            let boundary_ok = reaches_q && prefix_boundary_ok(path_bytes.len(), d.key_len, next_byte);

            let expected = if q == "/" {
                p.starts_with('/')
            } else {
                p == q || p.starts_with(&format!("{q}/"))
            };

            prop_assert_eq!(boundary_ok, expected);
        }
    }
}
