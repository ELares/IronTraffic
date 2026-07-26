// SPDX-License-Identifier: MIT OR Apache-2.0

//! A four-level, 256-slot-per-level hierarchical timing wheel at 1 ms base
//! resolution, covering 2^32 ms (49.7 days), which is exactly the wrap period of
//! [`Millis`].
//!
//! Built for the active health checker, which reschedules every endpoint after
//! every check: at H = 50,000 endpoints and a 2-second interval that is 25,000
//! reschedules per second, forever. A `BinaryHeap` costs O(log H) plus a
//! sift-down pointer chase across the whole heap array on every reschedule; this
//! wheel costs a few stores into an intrusive, doubly-linked list it is already
//! holding, and touches exactly one cache-resident slot per tick.
//!
//! This module performs no I/O, creates no background tasks, and reads no
//! clock: every function that needs the current time takes it as a [`Millis`]
//! parameter. The wheel is on the health-check control path, not the request
//! path.

use crate::clock::Millis;

/// Sentinel for "no node". The wheel therefore supports ids `0..u32::MAX`.
const NIL: u32 = u32::MAX;

/// Marks [`WheelNode::slot`] as "not scheduled".
const NO_SLOT: u16 = u16::MAX;

/// Number of slots per level.
const SLOTS: usize = 256;
/// Number of levels.
const LEVELS: usize = 4;

/// Default ceiling on the number of distinct ids one wheel will allocate node
/// state for: 1,048,576, which is 16 MB of node array.
pub const DEFAULT_MAX_IDS: usize = 1 << 20;

/// One entry in the wheel's flat node array, addressed by caller-assigned id.
#[derive(Clone, Copy, Debug)]
struct WheelNode {
    /// Next node in the same slot, or [`NIL`].
    next: u32,
    /// Previous node in the same slot, or [`NIL`] when this node is the slot head.
    prev: u32,
    /// Absolute deadline. Meaningless until the node is scheduled; `slot ==
    /// NO_SLOT` is the only marker of "not scheduled".
    deadline: Millis,
    /// Flat slot index in `0..SLOTS * LEVELS`, or [`NO_SLOT`] when this node is
    /// not scheduled.
    slot: u16,
}

/// Why a schedule request was refused.
///
/// There is deliberately no "deadline too far" variant. [`Millis`] reserves the
/// upper half of the wrapping range for the past, so an instant more than
/// `Millis::HORIZON_MS` ahead is not representable as a future instant and is
/// indistinguishable from one in the past. Both are clamped to `now + 1`.
/// Intervals that large are rejected by the configuration validation of
/// whichever subsystem owns the interval.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WheelError {
    /// The id is `u32::MAX`, which is reserved as the list sentinel.
    IdTooLarge,
    /// The id is at or above the wheel's `max_ids` ceiling. The node array is
    /// not grown, so a caller cannot turn one sparse id into a multi-gigabyte
    /// allocation.
    IdOutOfRange,
}

impl core::fmt::Display for WheelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WheelError::IdTooLarge => {
                write!(
                    f,
                    "id is u32::MAX, which is reserved as the wheel's list sentinel"
                )
            }
            WheelError::IdOutOfRange => {
                write!(f, "id is at or above the wheel's max_ids ceiling")
            }
        }
    }
}

impl core::error::Error for WheelError {}

/// What one call to [`TimerWheel::advance`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdvanceStats {
    /// Number of ids appended to the caller's output vector.
    pub fired: usize,
    /// Milliseconds the wheel time moved.
    pub advanced_ms: u32,
    /// Number of higher-level slot cascades performed.
    pub cascades: u32,
    /// True when the gap exceeded `max_catchup_ms`, so a bounded sweep ran
    /// instead of a tick loop. Export this as the `timer_catchup_clamped`
    /// counter.
    pub swept: bool,
}

/// A four-level, 256-slot-per-level hierarchical timing wheel at 1 ms
/// resolution, covering 2^32 ms.
///
/// Ids are caller-assigned dense `u32` values (in this crate, `EndpointIdx`).
/// The wheel owns 16 bytes of link state per id in a flat array, so
/// rescheduling allocates nothing. Not `Sync`: it is owned by the single
/// control task.
pub struct TimerWheel {
    /// Flat slot heads, level-major: `heads[level * SLOTS + slot]`.
    heads: Box<[u32; SLOTS * LEVELS]>,
    /// Node storage indexed by caller-assigned id. Grown by `ensure_capacity`,
    /// never past `max_ids`.
    nodes: Vec<WheelNode>,
    /// Hard ceiling on `nodes.len()`. Default [`DEFAULT_MAX_IDS`].
    max_ids: usize,
    /// Current wheel time.
    now: Millis,
    /// Number of scheduled nodes.
    len: usize,
    /// Maximum milliseconds `advance` will tick one at a time before sweeping
    /// instead.
    max_catchup_ms: u32,
    /// Count of sweeps caused by a gap larger than `max_catchup_ms`.
    catchup_clamped: u64,
    /// Reused by `sweep` to hold the ids unlinked from all `SLOTS * LEVELS`
    /// slots before they are re-evaluated against the new `now`. Never freed,
    /// so a steady-state sweep allocates nothing after the first one.
    sweep_scratch: Vec<u32>,
}

/// Returns the level (`0..LEVELS`) and slot (`0..SLOTS`) a deadline belongs in,
/// relative to `now`.
///
/// | Condition | Level | Slot index |
/// | --- | --- | --- |
/// | `delta < 2^8` | 0 | `deadline.0 & 0xFF` |
/// | `delta < 2^16` | 1 | `(deadline.0 >> 8) & 0xFF` |
/// | `delta < 2^24` | 2 | `(deadline.0 >> 16) & 0xFF` |
/// | otherwise | 3 | `(deadline.0 >> 24) & 0xFF` |
fn level_and_slot(now: Millis, deadline: Millis) -> (usize, usize) {
    let delta = deadline.since(now);
    if delta < 256 {
        (0, (deadline.0 & 0xFF) as usize)
    } else if delta < 65_536 {
        (1, ((deadline.0 >> 8) & 0xFF) as usize)
    } else if delta < 16_777_216 {
        (2, ((deadline.0 >> 16) & 0xFF) as usize)
    } else {
        (3, ((deadline.0 >> 24) & 0xFF) as usize)
    }
}

/// Narrows a flat slot index (`level * SLOTS + slot`, always `< SLOTS * LEVELS`
/// by construction: `level` comes from [`level_and_slot`] and is one of
/// `0..LEVELS`, and `slot` is one of `0..SLOTS`) to the `u16` stored in
/// [`WheelNode::slot`]. One proof site for the file's only narrowing cast.
#[allow(
    clippy::cast_possible_truncation,
    reason = "flat < SLOTS * LEVELS (1024) by construction: level_and_slot only ever \
              returns level < LEVELS (4) and slot < SLOTS (256), so flat is far inside \
              u16::MAX; the debug_assert below re-checks this in every test build"
)]
fn flat_slot_as_u16(flat: usize) -> u16 {
    debug_assert!(flat < SLOTS * LEVELS, "flat slot index out of range");
    flat as u16 // it-allow: unchecked-cast reason: flat = level * SLOTS + slot with level < LEVELS (4) and slot < SLOTS (256), so flat < 1024, far inside u16::MAX; proven by construction and re-checked by the debug_assert above in every test build
}

impl TimerWheel {
    /// A wheel starting at `start`, preallocated for ids `0..capacity`, with the
    /// default `max_catchup_ms` of 5000 and `max_ids` of
    /// `capacity.max(DEFAULT_MAX_IDS)`.
    ///
    /// `capacity` is clamped to `u32::MAX as usize` so that the preallocation
    /// itself cannot be a denial of service through a mistaken argument.
    #[must_use]
    pub fn new(start: Millis, capacity: usize) -> Self {
        let capacity = capacity.min(u32::MAX as usize);
        let heads = Box::new([NIL; SLOTS * LEVELS]);
        let template = WheelNode {
            next: NIL,
            prev: NIL,
            deadline: start,
            slot: NO_SLOT,
        };
        let nodes = vec![template; capacity];
        TimerWheel {
            heads,
            nodes,
            max_ids: capacity.max(DEFAULT_MAX_IDS),
            now: start,
            len: 0,
            max_catchup_ms: 5_000,
            catchup_clamped: 0,
            sweep_scratch: Vec::new(),
        }
    }

    /// Raise or lower the ceiling on distinct ids.
    ///
    /// [`TimerWheel::schedule`] returns [`WheelError::IdOutOfRange`] for any id
    /// at or above this value, without growing the node array, so the wheel's
    /// memory is bounded by `16 * max_ids` bytes no matter what ids the caller
    /// supplies. Lowering it below the current node array length does not
    /// shrink or unschedule anything; it only refuses future ids.
    pub fn set_max_ids(&mut self, max_ids: usize) {
        self.max_ids = max_ids;
    }

    /// Override the catch-up clamp. Values below 1 are raised to 1.
    ///
    /// This value bounds the tick loop: `advance` iterates once per
    /// millisecond of gap up to this many milliseconds before switching to the
    /// O(1024 + H) sweep, so a large value is a large loop. No configuration
    /// value, admin request, or cluster message may reach this setter
    /// unclamped: every caller outside this module's own tests MUST clamp to
    /// at most 60,000 first, which is what `HealthScheduler::set_max_catchup_ms`
    /// does. The setter itself accepts any value only because the wheel's own
    /// tests raise it to `u32::MAX` to exercise the tick and cascade path
    /// instead of the sweep path.
    pub fn set_max_catchup_ms(&mut self, ms: u32) {
        self.max_catchup_ms = ms.max(1);
    }

    /// The wheel's current time.
    #[inline]
    #[must_use]
    pub fn now(&self) -> Millis {
        self.now
    }

    /// Number of scheduled ids.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when nothing is scheduled.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many times a gap larger than `max_catchup_ms` forced a sweep.
    #[inline]
    #[must_use]
    pub fn catchup_clamped(&self) -> u64 {
        self.catchup_clamped
    }

    /// Schedule, or reschedule, `id` to fire at `at`.
    ///
    /// Rescheduling an already-scheduled id moves it; it never creates a
    /// duplicate. A deadline at or before `now` fires on the next
    /// [`TimerWheel::advance`].
    ///
    /// # Errors
    /// [`WheelError::IdTooLarge`] when `id == u32::MAX`, the reserved list
    /// sentinel. [`WheelError::IdOutOfRange`] when `id` is at or above the
    /// wheel's `max_ids` ceiling; neither case grows the node array.
    pub fn schedule(&mut self, id: u32, at: Millis) -> Result<(), WheelError> {
        if id == NIL {
            return Err(WheelError::IdTooLarge);
        }
        if id as usize >= self.max_ids {
            return Err(WheelError::IdOutOfRange);
        }
        // The RAW wrapping delta, not `Millis::since`: `since` already collapses
        // everything above `HORIZON_MS` to 0, so a check written against it would
        // be dead code that can never fire. See `WheelError`'s doc comment for
        // why there is no separate "too far in the future" error.
        let raw = at.0.wrapping_sub(self.now.0);
        self.ensure_capacity(id);
        let was_scheduled = self.node(id).is_some_and(|n| n.slot != NO_SLOT);
        if was_scheduled {
            self.unlink(id);
        }
        let effective_at = if raw == 0 || raw > Millis::HORIZON_MS {
            self.now.add_ms(1)
        } else {
            at
        };
        let (level, slot) = level_and_slot(self.now, effective_at);
        let flat = level * SLOTS + slot;
        let old_head = self.heads.get(flat).copied().unwrap_or(NIL);
        if let Some(node) = self.node_mut(id) {
            node.deadline = effective_at;
            node.slot = flat_slot_as_u16(flat);
            node.prev = NIL;
            node.next = old_head;
        }
        if old_head != NIL
            && let Some(next_node) = self.node_mut(old_head)
        {
            next_node.prev = id;
        }
        if let Some(head) = self.heads.get_mut(flat) {
            *head = id;
        }
        if !was_scheduled {
            self.len += 1;
        }
        Ok(())
    }

    /// Remove `id`. Returns true when it was scheduled.
    pub fn cancel(&mut self, id: u32) -> bool {
        if id as usize >= self.nodes.len() {
            return false;
        }
        let scheduled = self.node(id).is_some_and(|n| n.slot != NO_SLOT);
        if !scheduled {
            return false;
        }
        self.unlink(id);
        if let Some(node) = self.node_mut(id) {
            node.slot = NO_SLOT;
        }
        self.len = self.len.saturating_sub(1);
        true
    }

    /// The scheduled deadline for `id`, or `None` when it is not scheduled.
    #[must_use]
    pub fn deadline_of(&self, id: u32) -> Option<Millis> {
        let node = self.node(id)?;
        (node.slot != NO_SLOT).then_some(node.deadline)
    }

    /// Move wheel time to `now`, appending every id whose deadline is at or
    /// before `now` to `out`.
    ///
    /// `out` is not cleared. When the gap exceeds `max_catchup_ms` this
    /// performs one bounded sweep instead of a tick loop and sets
    /// [`AdvanceStats::swept`].
    pub fn advance(&mut self, now: Millis, out: &mut Vec<u32>) -> AdvanceStats {
        let out_len_before = out.len();
        let mut cascades = 0u32;
        let gap = now.since(self.now);
        if gap == 0 {
            return AdvanceStats::default();
        }
        let swept = if gap > self.max_catchup_ms {
            self.sweep(now, out);
            self.catchup_clamped += 1;
            true
        } else {
            for _ in 0..gap {
                self.now = self.now.add_ms(1);
                // Cascades happen BEFORE draining level 0 below, in the same
                // tick, so an entry that cascades into the current slot still
                // fires on this tick.
                if self.now.0.trailing_zeros() >= 8 {
                    let idx = ((self.now.0 >> 8) & 0xFF) as usize;
                    self.cascade(1, idx);
                    cascades += 1;
                }
                if self.now.0.trailing_zeros() >= 16 {
                    let idx = ((self.now.0 >> 16) & 0xFF) as usize;
                    self.cascade(2, idx);
                    cascades += 1;
                }
                if self.now.0.trailing_zeros() >= 24 {
                    let idx = ((self.now.0 >> 24) & 0xFF) as usize;
                    self.cascade(3, idx);
                    cascades += 1;
                }
                // Drain level 0's current slot. Inlined here, rather than
                // factored into a named helper, so that the only allocating
                // calls in this file (`.push` included) live in `new`,
                // `advance`, `sweep`, and `ensure_capacity`.
                let flat = (self.now.0 & 0xFF) as usize;
                let mut id = self.heads.get(flat).copied().unwrap_or(NIL);
                while id != NIL {
                    let Some(node) = self.node(id).copied() else {
                        break;
                    };
                    let next = node.next;
                    self.unlink(id);
                    if let Some(n) = self.node_mut(id) {
                        n.slot = NO_SLOT;
                    }
                    self.len = self.len.saturating_sub(1);
                    out.push(id);
                    id = next;
                }
            }
            false
        };
        AdvanceStats {
            fired: out.len() - out_len_before,
            advanced_ms: gap,
            cascades,
            swept,
        }
    }

    /// Debug-only structural check of invariants 1, 2, 3, 4, 5, and 8.
    /// Compiled out in release builds.
    #[cfg(debug_assertions)]
    pub fn debug_assert_structure(&self) {
        // Invariant 1: len == number of nodes whose slot != NO_SLOT.
        let scheduled_count = self.nodes.iter().filter(|n| n.slot != NO_SLOT).count();
        debug_assert_eq!(
            self.len, scheduled_count,
            "len does not match the number of scheduled nodes"
        );

        // Invariant 3: every slot value is NO_SLOT or a valid flat index.
        for node in &self.nodes {
            debug_assert!(
                node.slot == NO_SLOT || (node.slot as usize) < SLOTS * LEVELS,
                "node slot out of range: {node:?}"
            );
        }

        // Invariant 2 (a node appears in at most one slot list), 4, 5, and 8:
        // walk every flat slot's list.
        let mut total_visited = 0usize;
        for flat in 0..SLOTS * LEVELS {
            #[allow(
                clippy::integer_division,
                reason = "flat decodes into (level, slot) by construction: SLOTS is a \
                          nonzero compile-time constant and flat < SLOTS * LEVELS, so this \
                          is exact, not lossy, integer division"
            )]
            let level = flat / SLOTS;
            let s = flat % SLOTS;
            let head = self.heads.get(flat).copied().unwrap_or(NIL);
            if head != NIL {
                let head_prev = self.node(head).map(|n| n.prev);
                debug_assert_eq!(head_prev, Some(NIL), "slot head has a non-NIL prev");
            }
            let mut id = head;
            let mut guard = 0usize;
            while id != NIL {
                let Some(node) = self.node(id) else { break };
                debug_assert_eq!(
                    node.slot as usize, flat,
                    "node linked into slot {flat} does not name that slot itself"
                );
                let bound: u64 = match level {
                    0 => 256,
                    1 => 65_536,
                    2 => 16_777_216,
                    _ => 4_294_967_296,
                };
                let delta = u64::from(node.deadline.since(self.now));
                debug_assert!(delta < bound, "invariant 4b violated at level {level}");
                if level == 0 {
                    let decoded = (node.deadline.0 & 0xFF) as usize;
                    debug_assert_eq!(decoded, s, "invariant 4a/5 violated at level 0");
                } else {
                    let shift = 8 * level;
                    let decoded = ((node.deadline.0 >> shift) & 0xFF) as usize;
                    debug_assert_eq!(decoded, s, "invariant 4a violated at level {level}");
                    debug_assert_ne!(
                        self.now.0 >> shift,
                        node.deadline.0 >> shift,
                        "invariant 4c violated: wheel time already entered this node's own block"
                    );
                }
                total_visited += 1;
                guard += 1;
                debug_assert!(guard <= self.nodes.len() + 1, "cycle detected in slot list");
                id = node.next;
            }
        }
        debug_assert_eq!(
            total_visited, self.len,
            "total nodes visited across all slots does not match len"
        );
    }

    fn node(&self, id: u32) -> Option<&WheelNode> {
        self.nodes.get(id as usize)
    }

    fn node_mut(&mut self, id: u32) -> Option<&mut WheelNode> {
        self.nodes.get_mut(id as usize)
    }

    fn ensure_capacity(&mut self, id: u32) {
        let idx = id as usize;
        if idx >= self.nodes.len() {
            let template = WheelNode {
                next: NIL,
                prev: NIL,
                deadline: self.now,
                slot: NO_SLOT,
            };
            self.nodes.resize(idx + 1, template);
        }
    }

    /// Splices `id` out of the slot list its own `slot` field names. Does not
    /// touch `id`'s `slot` field: callers that are permanently removing the
    /// node (`cancel`, the tick-path drain) set it to `NO_SLOT` themselves, and
    /// callers that are about to re-link it elsewhere (`schedule`, `cascade`)
    /// overwrite it with the new flat index.
    fn unlink(&mut self, id: u32) {
        let Some(node) = self.node(id).copied() else {
            return;
        };
        let prev = node.prev;
        let next = node.next;
        let flat = node.slot as usize;
        if prev == NIL {
            if let Some(head) = self.heads.get_mut(flat) {
                *head = next;
            }
        } else if let Some(prev_node) = self.node_mut(prev) {
            prev_node.next = next;
        }
        if next != NIL
            && let Some(next_node) = self.node_mut(next)
        {
            next_node.prev = prev;
        }
    }

    /// Re-links every node in flat slot `level * SLOTS + slot` against the
    /// wheel's current `now`, using each node's OWN unchanged deadline. Does
    /// NOT go through `schedule`: a node cascading with `delta == 0` must land
    /// in the current level-0 slot and fire on this same tick, and rewriting
    /// its deadline would corrupt `deadline_of`. A cascaded node always lands
    /// in a strictly lower level, so this cannot loop.
    fn cascade(&mut self, level: usize, slot: usize) {
        let flat = level * SLOTS + slot;
        let mut id = self.heads.get(flat).copied().unwrap_or(NIL);
        while id != NIL {
            let Some(node) = self.node(id).copied() else {
                break;
            };
            let next = node.next;
            self.unlink(id);
            let (new_level, new_slot) = level_and_slot(self.now, node.deadline);
            let new_flat = new_level * SLOTS + new_slot;
            let old_head = self.heads.get(new_flat).copied().unwrap_or(NIL);
            if let Some(n) = self.node_mut(id) {
                n.slot = flat_slot_as_u16(new_flat);
                n.prev = NIL;
                n.next = old_head;
            }
            if old_head != NIL
                && let Some(h) = self.node_mut(old_head)
            {
                h.prev = id;
            }
            if let Some(head) = self.heads.get_mut(new_flat) {
                *head = id;
            }
            id = next;
        }
    }

    /// One bounded sweep: unlinks every node from every slot, emits the ones
    /// that are due, and re-inserts the rest against the new `now`.
    /// Re-inserting the not-yet-due nodes is mandatory, because their slot
    /// assignment is relative to `now` and a jump invalidates it; skipping
    /// that step is a silent "timers never fire again" bug.
    fn sweep(&mut self, target: Millis, out: &mut Vec<u32>) {
        self.sweep_scratch.clear();
        for flat in 0..SLOTS * LEVELS {
            let mut id = self.heads.get(flat).copied().unwrap_or(NIL);
            while id != NIL {
                let Some(node) = self.node(id).copied() else {
                    break;
                };
                let next = node.next;
                if let Some(n) = self.node_mut(id) {
                    n.prev = NIL;
                    n.next = NIL;
                    n.slot = NO_SLOT;
                }
                self.len = self.len.saturating_sub(1);
                self.sweep_scratch.push(id);
                id = next;
            }
            if let Some(head) = self.heads.get_mut(flat) {
                *head = NIL;
            }
        }
        self.now = target;
        let scratch_len = self.sweep_scratch.len();
        for i in 0..scratch_len {
            let Some(id) = self.sweep_scratch.get(i).copied() else {
                continue;
            };
            let deadline = self.node(id).map_or(target, |n| n.deadline);
            if deadline.is_at_or_before(target) {
                out.push(id);
            } else {
                // `id` was already present in `nodes` before this sweep, so it
                // was already validated against `max_ids` at its original
                // `schedule` call; this can only fail if `set_max_ids` lowered
                // the ceiling below `id` in between, a narrow interaction
                // tracked in issue #524 rather than worked around here.
                let _ = self.schedule(id, deadline); // it-allow: no-swallowed-error reason: id was already stored in `nodes` before the sweep, so this only fails if set_max_ids lowered the ceiling below id afterward; matches the issue's specified sweep algorithm ("else schedule(id, nodes[id].deadline)") exactly, and the resulting drop-on-lowered-ceiling interaction is tracked separately in issue #524
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdvanceStats, Millis, TimerWheel, WheelError};
    use proptest::prelude::*;
    use std::cmp::Reverse;
    use std::collections::{BinaryHeap, HashMap};

    #[test]
    fn new_wheel_is_empty() {
        let start = Millis(1_000);
        let wheel = TimerWheel::new(start, 8);
        assert_eq!(wheel.len(), 0);
        assert!(wheel.is_empty());
        assert_eq!(wheel.now(), start);
        assert_eq!(wheel.catchup_clamped(), 0);
        wheel.debug_assert_structure();
    }

    #[test]
    fn schedule_then_advance_fires_once() {
        let start = Millis(1_000);
        let mut wheel = TimerWheel::new(start, 8);
        wheel.schedule(7, start.add_ms(5)).expect("schedule");
        assert!(
            !wheel.is_empty(),
            "is_empty must be false once something is scheduled"
        );
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(4), &mut out);
        assert!(out.is_empty());
        assert_eq!(stats.fired, 0);
        wheel.debug_assert_structure();

        let stats = wheel.advance(start.add_ms(5), &mut out);
        assert_eq!(out, vec![7]);
        assert_eq!(stats.fired, 1);
        wheel.debug_assert_structure();

        out.clear();
        let stats = wheel.advance(start.add_ms(100), &mut out);
        assert!(out.is_empty());
        assert_eq!(stats.fired, 0);
        wheel.debug_assert_structure();
    }

    #[test]
    fn level_boundaries() {
        for (id, offset) in [
            (0u32, 255u32),
            (1, 256),
            (2, 65_535),
            (3, 65_536),
            // The level-2/level-3 boundary at 2^24, exercised the same way as
            // the two boundaries above: this is the pair that catches a
            // `level_and_slot` off-by-one in its THIRD comparison, which
            // neither of the first two pairs can reach.
            (4, 16_777_215),
            (5, 16_777_216),
        ] {
            let start = Millis(2_000_000);
            let mut wheel = TimerWheel::new(start, 8);
            wheel.set_max_catchup_ms(u32::MAX);
            wheel.schedule(id, start.add_ms(offset)).expect("schedule");
            assert_eq!(wheel.deadline_of(id), Some(start.add_ms(offset)));
            wheel.debug_assert_structure();

            let mut out = Vec::new();
            let stats_before = wheel.advance(start.add_ms(offset - 1), &mut out);
            assert!(
                out.is_empty(),
                "id {id} fired before its deadline at offset {offset}"
            );
            assert_eq!(stats_before.fired, 0);
            wheel.debug_assert_structure();

            let stats_at = wheel.advance(start.add_ms(offset), &mut out);
            assert_eq!(
                out,
                vec![id],
                "id {id} did not fire exactly at offset {offset}"
            );
            assert_eq!(stats_at.fired, 1);
            wheel.debug_assert_structure();
        }
    }

    #[test]
    fn cascade_from_level_one() {
        let start = Millis(500_000);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.schedule(1, start.add_ms(300)).expect("schedule");
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let mut total_cascades = 0u32;
        for _ in 0..300 {
            let now = wheel.now().add_ms(1);
            let stats = wheel.advance(now, &mut out);
            total_cascades += stats.cascades;
            wheel.debug_assert_structure();
        }
        assert_eq!(out, vec![1]);
        assert!(
            total_cascades >= 1,
            "expected at least one cascade over 300 single-ms ticks, got {total_cascades}"
        );
    }

    #[test]
    fn cascade_boundary_precise_level1_and_level2() {
        // `start` is chosen so the wheel's own time starts at exactly a
        // level-1 AND level-2 boundary (0 is a multiple of both 256 and
        // 65,536), which makes every subsequent boundary crossing land on a
        // round, easy-to-predict tick number: single-ms ticks from 1 to
        // 65,536 cross the level-1 boundary at every multiple of 256 and the
        // level-2 boundary at 65,536 itself (which is ALSO a multiple of
        // 256, so both fire on that one tick). This is deliberately far more
        // exact than `cascade_from_level_one`'s "at least one cascade over
        // 300 ticks": it checks EVERY tick, one below and one at each
        // boundary, in both directions, which is what actually catches an
        // off-by-one in the `trailing_zeros() >= N` condition or in the
        // per-level cascade counter, as opposed to merely happening to see a
        // nonzero total somewhere in a long run.
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.set_max_catchup_ms(u32::MAX);
        // No node is scheduled: this test is purely about the CASCADE
        // bookkeeping (`AdvanceStats::cascades`), not about anything firing.
        let mut out = Vec::new();
        for tick in 1u32..=65_536 {
            let now = wheel.now().add_ms(1);
            let stats = wheel.advance(now, &mut out);
            let expected = match (tick % 256 == 0, tick % 65_536 == 0) {
                (_, true) => 2,
                (true, false) => 1,
                (false, false) => 0,
            };
            assert_eq!(
                stats.cascades,
                expected,
                "wrong cascade count at tick {tick} (now = {})",
                wheel.now().0
            );
        }
        wheel.debug_assert_structure();
    }

    #[test]
    fn cascade_from_level_three() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.set_max_catchup_ms(u32::MAX);
        wheel.schedule(1, Millis(20_000_000)).expect("schedule");
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(Millis(20_000_000), &mut out);
        assert_eq!(out, vec![1]);
        assert_eq!(stats.fired, 1);
        // Exact expected cascade count, not just "at least one": one cascade
        // for every multiple of 256 (level 1), every multiple of 65,536
        // (level 2), and every multiple of 16,777,216 (level 3) crossed while
        // ticking from 0 to 20,000,000 inclusive. This pins down the
        // boundary conditions AND the per-level counter arithmetic at once;
        // any off-by-one in either changes this exact total.
        #[allow(
            clippy::integer_division,
            reason = "deliberate floor division: counts how many multiples of each \
                      level's period fall within the advanced range, an independent \
                      derivation of the expected cascade count rather than a copy of \
                      the implementation's own counter logic"
        )]
        let expected_cascades =
            20_000_000u32 / 256 + 20_000_000u32 / 65_536 + 20_000_000u32 / 16_777_216;
        assert_eq!(stats.cascades, expected_cascades);
        wheel.debug_assert_structure();
    }

    #[test]
    fn reschedule_moves_not_duplicates() {
        let start = Millis(10_000);
        let mut wheel = TimerWheel::new(start, 8);
        wheel.schedule(4, start.add_ms(10)).expect("schedule");
        wheel.debug_assert_structure();
        wheel.schedule(4, start.add_ms(50)).expect("reschedule");
        wheel.debug_assert_structure();
        assert_eq!(wheel.len(), 1);

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(10), &mut out);
        assert!(out.is_empty());
        assert_eq!(stats.fired, 0);
        assert_eq!(wheel.len(), 1);
        wheel.debug_assert_structure();

        let stats = wheel.advance(start.add_ms(50), &mut out);
        assert_eq!(out, vec![4]);
        assert_eq!(stats.fired, 1);
        wheel.debug_assert_structure();
    }

    #[test]
    fn cancel_removes() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 8);
        wheel.schedule(9, start.add_ms(20)).expect("schedule");
        wheel.debug_assert_structure();
        assert!(wheel.cancel(9));
        assert_eq!(wheel.len(), 0);
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(100), &mut out);
        assert!(out.is_empty());
        assert_eq!(stats.fired, 0);
        wheel.debug_assert_structure();
        assert!(!wheel.cancel(9));
        wheel.debug_assert_structure();
    }

    #[test]
    fn cancel_unknown_id() {
        let mut wheel = TimerWheel::new(Millis(0), 4);
        assert!(!wheel.cancel(12_345));
        assert_eq!(
            wheel.nodes.len(),
            4,
            "cancel of an unknown id must not grow the node array"
        );
        wheel.debug_assert_structure();
    }

    #[test]
    fn schedule_id_max_rejected() {
        let mut wheel = TimerWheel::new(Millis(0), 4);
        assert_eq!(
            wheel.schedule(u32::MAX, Millis(10)),
            Err(WheelError::IdTooLarge)
        );
        wheel.debug_assert_structure();
        assert!(!wheel.cancel(u32::MAX));
        wheel.debug_assert_structure();
    }

    #[test]
    fn wheel_error_display_messages() {
        assert_eq!(
            WheelError::IdTooLarge.to_string(),
            "id is u32::MAX, which is reserved as the wheel's list sentinel"
        );
        assert_eq!(
            WheelError::IdOutOfRange.to_string(),
            "id is at or above the wheel's max_ids ceiling"
        );
    }

    #[test]
    fn schedule_beyond_max_ids_rejected_without_growth() {
        let mut wheel = TimerWheel::new(Millis(0), 8);
        let before = wheel.nodes.len();
        assert_eq!(
            wheel.schedule(4_000_000_000, Millis(0).add_ms(1)),
            Err(WheelError::IdOutOfRange)
        );
        assert_eq!(wheel.len(), 0);
        assert_eq!(
            wheel.nodes.len(),
            before,
            "a rejected id must not grow the node array"
        );
        assert_eq!(wheel.deadline_of(1_000_000), None);
        wheel.debug_assert_structure();
    }

    #[test]
    fn set_max_ids_allows_higher_id() {
        let mut wheel = TimerWheel::new(Millis(0), 8);
        wheel.set_max_ids(2_000_000);
        wheel
            .schedule(1_500_000, Millis(0).add_ms(5))
            .expect("schedule");
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(Millis(0).add_ms(5), &mut out);
        assert_eq!(out, vec![1_500_000]);
        assert_eq!(stats.fired, 1);
        wheel.debug_assert_structure();
    }

    #[test]
    fn schedule_beyond_horizon_clamps() {
        let start = Millis(1_000);
        let mut wheel = TimerWheel::new(start, 8);
        let far = Millis(start.0.wrapping_add(Millis::HORIZON_MS + 1));
        wheel.schedule(3, far).expect("schedule");
        assert_eq!(wheel.deadline_of(3), Some(start.add_ms(1)));
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(1), &mut out);
        assert_eq!(out, vec![3]);
        assert_eq!(stats.fired, 1);
        wheel.debug_assert_structure();
    }

    #[test]
    fn schedule_exactly_at_horizon_not_clamped() {
        // Edge case 17: a deadline exactly `HORIZON_MS` ahead is the LARGEST
        // representable future instant and must be accepted as-is, in
        // contrast to `schedule_beyond_horizon_clamps` one ms further out
        // (edge case 18), which is indistinguishable from the past and gets
        // clamped. The two tests together bracket the boundary on both
        // sides, which is what actually catches an off-by-one in the clamp
        // condition (`raw > HORIZON_MS` vs `raw >= HORIZON_MS`): a boundary
        // test placed on only one side of it would not.
        let start = Millis(1_000);
        let mut wheel = TimerWheel::new(start, 8);
        let far = Millis(start.0.wrapping_add(Millis::HORIZON_MS));
        wheel.schedule(6, far).expect("schedule");
        assert_eq!(
            wheel.deadline_of(6),
            Some(far),
            "an exactly-at-horizon deadline must not be clamped"
        );
        wheel.debug_assert_structure();
    }

    #[test]
    fn past_deadline_clamped_to_next_ms() {
        let start = Millis(5_000);
        let mut wheel = TimerWheel::new(start, 8);
        wheel.schedule(2, start).expect("schedule");
        assert_eq!(wheel.deadline_of(2), Some(start.add_ms(1)));
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(1), &mut out);
        assert_eq!(out, vec![2]);
        assert_eq!(stats.fired, 1);
        wheel.debug_assert_structure();
    }

    #[test]
    fn advance_backwards_is_noop() {
        let start = Millis(1_000);
        let mut wheel = TimerWheel::new(start, 4);
        let mut out = Vec::new();
        let stats = wheel.advance(Millis(start.0.wrapping_sub(10)), &mut out);
        assert_eq!(stats, AdvanceStats::default());
        assert_eq!(wheel.now(), start);
        assert!(out.is_empty());
        wheel.debug_assert_structure();
    }

    #[test]
    fn advance_zero_gap_is_noop() {
        let start = Millis(1_000);
        let mut wheel = TimerWheel::new(start, 4);
        let mut out = Vec::new();
        let stats = wheel.advance(start, &mut out);
        assert_eq!(stats, AdvanceStats::default());
        assert_eq!(wheel.now(), start);
        assert!(out.is_empty());
        wheel.debug_assert_structure();
    }

    #[test]
    fn wrap_across_u32_max() {
        let start = Millis(u32::MAX - 10);
        let mut wheel = TimerWheel::new(start, 16);
        for id in 0u32..=15 {
            wheel.schedule(id, start.add_ms(id + 1)).expect("schedule");
            wheel.debug_assert_structure();
        }

        let mut out = Vec::new();
        let stats = wheel.advance(Millis(5), &mut out);
        // Deliberately NOT sorted before comparison: every deadline here is
        // distinct, so the wheel must fire them in exactly deadline order, and
        // sorting first would hide a permutation bug.
        assert_eq!(out, (0u32..=15).collect::<Vec<u32>>());
        assert_eq!(stats.fired, 16);
        assert_eq!(wheel.now(), Millis(5));
        wheel.debug_assert_structure();
    }

    #[test]
    fn set_max_catchup_ms_takes_effect() {
        // A gap that sits ABOVE the default 5000 but at or below a RAISED
        // `max_catchup_ms` must still take the tick path. Checking only a
        // gap that also exceeds the default would not tell "the setter
        // worked" apart from "the setter is a no-op and the default alone
        // already explains this run", since both would look identical for a
        // gap under 5000. Using a gap strictly above the default is what
        // makes the two distinguishable.
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.set_max_catchup_ms(6_000);
        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(5_500), &mut out);
        assert!(
            !stats.swept,
            "a gap of 5500 under a raised max_catchup_ms of 6000 must not sweep"
        );
        assert_eq!(wheel.catchup_clamped(), 0);
        wheel.debug_assert_structure();
    }

    #[test]
    fn catchup_boundary_exact_vs_plus_one() {
        // Edge cases 13 and 14: the sweep condition is STRICTLY greater than
        // `max_catchup_ms`, so a gap of exactly that value ticks, and a gap
        // one millisecond larger sweeps. Tested on two fresh wheels rather
        // than one continued wheel so each gap is measured from the same
        // starting point instead of compounding.
        let start = Millis(0);

        let mut at_boundary = TimerWheel::new(start, 4);
        at_boundary.set_max_catchup_ms(500);
        let mut out = Vec::new();
        let stats = at_boundary.advance(start.add_ms(500), &mut out);
        assert!(
            !stats.swept,
            "a gap exactly equal to max_catchup_ms must tick, not sweep"
        );
        assert_eq!(at_boundary.catchup_clamped(), 0);
        at_boundary.debug_assert_structure();

        let mut past_boundary = TimerWheel::new(start, 4);
        past_boundary.set_max_catchup_ms(500);
        out.clear();
        let stats = past_boundary.advance(start.add_ms(501), &mut out);
        assert!(stats.swept, "a gap one ms past max_catchup_ms must sweep");
        assert_eq!(past_boundary.catchup_clamped(), 1);
        past_boundary.debug_assert_structure();
    }

    #[test]
    fn sweep_on_large_gap() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 8);
        wheel.set_max_catchup_ms(100);
        wheel.schedule(0, start.add_ms(10)).expect("schedule 0");
        wheel.debug_assert_structure();
        wheel.schedule(1, start.add_ms(200)).expect("schedule 1");
        wheel.debug_assert_structure();
        wheel.schedule(2, start.add_ms(5_000)).expect("schedule 2");
        wheel.debug_assert_structure();
        wheel
            .schedule(3, start.add_ms(100_000))
            .expect("schedule 3");
        wheel.debug_assert_structure();
        wheel
            .schedule(4, start.add_ms(20_000_000))
            .expect("schedule 4");
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(100_000), &mut out);
        assert!(stats.swept);
        assert_eq!(wheel.catchup_clamped(), 1);
        let mut sorted = out.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3]);
        assert_eq!(stats.fired, 4);
        assert_eq!(wheel.deadline_of(4), Some(start.add_ms(20_000_000)));
        assert_eq!(wheel.len(), 1);
        wheel.debug_assert_structure();
    }

    #[test]
    fn sweep_reinserts_survivors_correctly() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 8);
        wheel.set_max_catchup_ms(100);
        wheel.schedule(0, start.add_ms(10)).expect("schedule 0");
        wheel.debug_assert_structure();
        wheel.schedule(1, start.add_ms(200)).expect("schedule 1");
        wheel.debug_assert_structure();
        wheel.schedule(2, start.add_ms(5_000)).expect("schedule 2");
        wheel.debug_assert_structure();
        wheel
            .schedule(3, start.add_ms(100_000))
            .expect("schedule 3");
        wheel.debug_assert_structure();
        wheel
            .schedule(4, start.add_ms(20_000_000))
            .expect("schedule 4");
        wheel.debug_assert_structure();

        let mut out = Vec::new();
        let stats1 = wheel.advance(start.add_ms(100_000), &mut out);
        assert!(stats1.swept);
        wheel.debug_assert_structure();

        wheel.set_max_catchup_ms(u32::MAX);
        out.clear();
        let stats2 = wheel.advance(start.add_ms(20_000_000), &mut out);
        assert_eq!(out, vec![4]);
        assert_eq!(stats2.fired, 1);
        assert_eq!(wheel.len(), 0);
        wheel.debug_assert_structure();
    }

    #[test]
    fn out_vector_is_appended_not_cleared() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.schedule(7, start.add_ms(5)).expect("schedule");
        wheel.debug_assert_structure();
        let mut out = vec![99];
        let stats = wheel.advance(start.add_ms(5), &mut out);
        assert_eq!(out, vec![99, 7]);
        assert_eq!(stats.fired, 1);
        wheel.debug_assert_structure();
    }

    #[test]
    fn many_nodes_same_slot() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 1_000);
        for id in 0u32..1_000 {
            wheel.schedule(id, start.add_ms(1)).expect("schedule");
            wheel.debug_assert_structure();
        }

        let mut out = Vec::new();
        let stats = wheel.advance(start.add_ms(1), &mut out);
        assert_eq!(stats.fired, 1_000);
        assert_eq!(out.len(), 1_000, "no duplicates or omissions");
        let mut sorted = out.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0u32..1_000).collect::<Vec<u32>>());
        wheel.debug_assert_structure();
    }

    /// Three tests that corrupt one scheduled node's `deadline` directly
    /// (reaching into the private `nodes` field, which the wheel's own
    /// public API can never produce, since `level_and_slot` is the only
    /// thing that ever assigns a slot) while leaving its slot linkage
    /// untouched, to prove `debug_assert_structure`'s per-level invariant 4b
    /// bound actually fires rather than merely existing as dead code. Each
    /// adds a multiple of that level's OWN period to the deadline, which
    /// preserves the bits invariant 4a decodes (so 4a stays satisfied) while
    /// pushing the delta from `now` past the bound invariant 4b requires for
    /// that level. Without these, a bug that loosened one level's bound (for
    /// example by dropping its `match` arm so it fell through to a much
    /// larger default) would change no OTHER test's outcome: nothing else in
    /// this suite constructs a node whose recorded slot and recorded
    /// deadline disagree only about how loose the bound is.
    #[test]
    #[should_panic(expected = "invariant 4b")]
    fn debug_assert_structure_catches_loose_level0_bound() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.schedule(0, start.add_ms(5)).expect("schedule");
        wheel.debug_assert_structure();
        if let Some(node) = wheel.nodes.get_mut(0) {
            node.deadline = node.deadline.add_ms(256 * 1_000);
        }
        wheel.debug_assert_structure();
    }

    #[test]
    #[should_panic(expected = "invariant 4b")]
    fn debug_assert_structure_catches_loose_level1_bound() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.schedule(0, start.add_ms(300)).expect("schedule");
        wheel.debug_assert_structure();
        if let Some(node) = wheel.nodes.get_mut(0) {
            node.deadline = node.deadline.add_ms(65_536 * 1_000);
        }
        wheel.debug_assert_structure();
    }

    #[test]
    #[should_panic(expected = "invariant 4b")]
    fn debug_assert_structure_catches_loose_level2_bound() {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.schedule(0, start.add_ms(70_000)).expect("schedule");
        wheel.debug_assert_structure();
        if let Some(node) = wheel.nodes.get_mut(0) {
            node.deadline = node.deadline.add_ms(16_777_216 * 2);
        }
        wheel.debug_assert_structure();
    }

    #[test]
    #[should_panic(expected = "cycle detected")]
    fn debug_assert_structure_catches_a_cycle() {
        // Corrupts the slot list into a genuine cycle, rather than merely a
        // wrong field, to prove the walk's own cycle guard (bounded by
        // `nodes.len() + 1`) actually fires instead of being unreachable
        // dead code: without it, a real linking bug that produced a cycle
        // would hang `debug_assert_structure` forever instead of failing
        // loudly, in every test and property test that calls it.
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 4);
        wheel.schedule(0, start.add_ms(5)).expect("schedule 0");
        wheel.schedule(1, start.add_ms(5)).expect("schedule 1");
        wheel.debug_assert_structure();
        // Both land in the same slot; front insertion makes the list
        // `1 -> 0 -> NIL`. Point node 0's `next` (normally `NIL`, since it
        // is the tail) back at node 1, so the walk alternates
        // `1 -> 0 -> 1 -> 0 -> ...` and never reaches `NIL` on its own.
        if let Some(node) = wheel.nodes.get_mut(0) {
            node.next = 1;
        }
        wheel.debug_assert_structure();
    }

    /// One operation drawn by the property tests below: reschedule (`Schedule`
    /// also covers a fresh schedule, since the wheel does not distinguish the
    /// two), cancel, or advance.
    #[derive(Clone, Copy, Debug)]
    enum Op {
        Schedule { id: u32, delta: u32 },
        Cancel { id: u32 },
        Advance { gap: u32 },
    }

    /// Weighted so that `Advance`, whose cost with `max_catchup_ms = u32::MAX`
    /// is proportional to `gap` (up to 70,000 ticks), does not dominate the
    /// wall-clock cost of the property test suite: `Schedule` and `Cancel` are
    /// each five times as likely, which still draws plenty of `Advance`
    /// operations per sequence (roughly one in eleven) while keeping the
    /// worst-case total tick count tractable.
    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            5 => (0..64u32, 0..100_000u32).prop_map(|(id, delta)| Op::Schedule { id, delta }),
            5 => (0..64u32).prop_map(|id| Op::Cancel { id }),
            1 => (1..70_000u32).prop_map(|gap| Op::Advance { gap }),
        ]
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(op_strategy(), 200..=200)
    }

    /// Runs `ops` against both the wheel and a `BinaryHeap` plus `HashMap`
    /// reference model (lazy deletion: a reschedule pushes a new heap entry
    /// and leaves the old one to be discarded as stale when popped), asserting
    /// after every operation that the two agree on `len`, and after every
    /// `Advance` that the two agree on the SET of fired ids.
    ///
    /// Returns the model's final scheduled-id count, which the caller uses to
    /// cross-check the tick-path and sweep-path runs of the SAME `ops` against
    /// each other: the model's own bookkeeping never depends on
    /// `max_catchup_ms`, so both runs must end with the same count.
    fn run_against_heap_reference(ops: &[Op], max_catchup_ms: u32) -> usize {
        let start = Millis(0);
        let mut wheel = TimerWheel::new(start, 64);
        wheel.set_max_catchup_ms(max_catchup_ms);

        let mut model_now: u32 = 0;
        let mut model_deadlines: HashMap<u32, u32> = HashMap::new();
        let mut model_heap: BinaryHeap<Reverse<(u32, u32)>> = BinaryHeap::new();
        let mut out = Vec::new();

        for op in ops {
            match *op {
                Op::Schedule { id, delta } => {
                    // Mirrors `schedule`'s own "at or before now" clamp: a
                    // delta of 0 is clamped to 1 in both the wheel and the
                    // model, since delta here is always well within the
                    // horizon (max 99,999), so the "too far ahead" clamp
                    // never applies.
                    let effective_delta = if delta == 0 { 1 } else { delta };
                    let at = wheel.now().add_ms(delta);
                    wheel
                        .schedule(id, at)
                        .expect("id < 64 is always within max_ids");
                    let deadline = model_now.wrapping_add(effective_delta);
                    model_deadlines.insert(id, deadline);
                    model_heap.push(Reverse((deadline, id)));
                }
                Op::Cancel { id } => {
                    let wheel_cancelled = wheel.cancel(id);
                    let model_cancelled = model_deadlines.remove(&id).is_some();
                    assert_eq!(
                        wheel_cancelled, model_cancelled,
                        "cancel result diverged for id {id}"
                    );
                }
                Op::Advance { gap } => {
                    out.clear();
                    let now = wheel.now().add_ms(gap);
                    wheel.advance(now, &mut out);
                    model_now = model_now.wrapping_add(gap);

                    let mut model_fired = Vec::new();
                    while let Some(&Reverse((deadline, id))) = model_heap.peek() {
                        if deadline > model_now {
                            break;
                        }
                        model_heap.pop();
                        if model_deadlines.get(&id) == Some(&deadline) {
                            model_deadlines.remove(&id);
                            model_fired.push(id);
                        }
                    }

                    let mut wheel_fired = out.clone();
                    wheel_fired.sort_unstable();
                    model_fired.sort_unstable();
                    assert_eq!(
                        wheel_fired, model_fired,
                        "fired id set diverged after Advance(gap={gap})"
                    );
                }
            }
            assert_eq!(
                wheel.len(),
                model_deadlines.len(),
                "len diverged after {op:?}"
            );
            wheel.debug_assert_structure();
        }
        model_deadlines.len()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn prop_matches_binary_heap_reference(ops in ops_strategy()) {
            let tick_path_final_len = run_against_heap_reference(&ops, u32::MAX);
            let sweep_path_final_len = run_against_heap_reference(&ops, 50);
            assert_eq!(
                tick_path_final_len, sweep_path_final_len,
                "the tick-path and sweep-path runs of the same ops ended with \
                 different scheduled-id counts"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn prop_structure_holds(ops in ops_strategy()) {
            let start = Millis(0);
            let mut wheel = TimerWheel::new(start, 64);
            let mut out = Vec::new();
            for op in &ops {
                match *op {
                    Op::Schedule { id, delta } => {
                        let at = wheel.now().add_ms(delta);
                        let _ = wheel.schedule(id, at);
                    }
                    Op::Cancel { id } => {
                        let _ = wheel.cancel(id);
                    }
                    Op::Advance { gap } => {
                        out.clear();
                        let now = wheel.now().add_ms(gap);
                        let _ = wheel.advance(now, &mut out);
                    }
                }
                wheel.debug_assert_structure();
                // A weak but real invariant, checked directly in this test's
                // own body rather than only inside a called helper: only
                // `Schedule` can ever grow `len`, and by at most one, so it
                // can never exceed the number of ops processed so far.
                assert!(
                    wheel.len() <= ops.len(),
                    "len {} exceeds the {} ops that could have scheduled it",
                    wheel.len(),
                    ops.len()
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn prop_never_fires_early_or_twice(ops in ops_strategy()) {
            let start = Millis(0);
            let mut wheel = TimerWheel::new(start, 64);
            let mut scheduled: HashMap<u32, Millis> = HashMap::new();
            let mut out = Vec::new();
            for op in &ops {
                match *op {
                    Op::Schedule { id, delta } => {
                        let at = wheel.now().add_ms(delta);
                        if wheel.schedule(id, at).is_ok() {
                            let effective = wheel.deadline_of(id).unwrap_or(at);
                            scheduled.insert(id, effective);
                        }
                    }
                    Op::Cancel { id } => {
                        if wheel.cancel(id) {
                            scheduled.remove(&id);
                        }
                    }
                    Op::Advance { gap } => {
                        out.clear();
                        let now = wheel.now().add_ms(gap);
                        wheel.advance(now, &mut out);
                        for &id in &out {
                            let deadline = scheduled.remove(&id);
                            assert!(
                                deadline.is_some_and(|d| d.is_at_or_before(wheel.now())),
                                "id {id} fired without a matching, due schedule entry"
                            );
                        }
                    }
                }
                wheel.debug_assert_structure();
            }
        }
    }
}
