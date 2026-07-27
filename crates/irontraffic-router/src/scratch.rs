// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Per-worker reusable match scratch and the lazy header/query indexes the
//! matcher reads.
//!
//! The scratch is owned by exactly one worker, acquired inside a `CoreScope`
//! closure, and reused across every request that worker handles. It is per
//! WORKER, not per connection: a per-connection scratch sized by the interned
//! name count would be more than 8 GB at one million concurrent connections.
//! Matching is fully synchronous with no await point, so one scratch per worker
//! is sound.
//!
//! Header values are stored as `(offset, len)` into the caller's contiguous
//! `RequestView::head` buffer, never as borrowed slices or raw pointers. That
//! keeps `MatchScratch` free of lifetime parameters and lets it be reused across
//! requests.
//!
//! Duplicate header names overwrite the same slot: the LAST occurrence wins.
//! Header values are never merged with commas; merging with commas is only
//! correct for `#list` fields and is never correct for policy matching.

use crate::ids::NameId;
use crate::limits::{AUTHORITY_BUF_BYTES, MAX_AUTHORITY_BYTES, MAX_QUERY_BYTES, MAX_QUERY_PARAMS};
use crate::normalize::HOST_KEY_BUF_BYTES;
use crate::table::RouteTable;

/// One interned header's location in the request head buffer.
///
/// Live if and only if `gen == MatchScratch::gen`. `gen == 0` means never written.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderSlot {
    /// The generation this slot was written in.
    pub r#gen: u32,
    /// Offset of the value in `RequestView::head`.
    pub off: u32,
    /// Length of the value in bytes.
    pub len: u32,
}

/// One query parameter's name id and value location.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QuerySlot {
    /// Interned query name id.
    pub name: NameId,
    /// Offset of the value within the query string, relative to `RequestView::query`.
    pub off: u32,
    /// Length of the value in bytes.
    pub len: u32,
}

/// What the last `match_request` call did, for metrics. The table is immutable and
/// holds no counters, so the status is reported here and the caller increments its own
/// per-core counter.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum MatchStatus {
    /// No match attempted yet on this scratch.
    #[default]
    Idle,
    /// A route matched.
    Matched,
    /// Every candidate on every visited node in every group failed.
    NoMatch,
    /// The authority could not be normalized.
    AuthorityRejected,
    /// The host trie resolved to no chain.
    NoHostMatch,
    /// The path was longer than `MAX_PATH_BYTES`.
    PathTooLong,
    /// The node-visit budget was exhausted. Increment
    /// `route_match_budget_exhausted_total` on this.
    BudgetExhausted,
    /// The negotiated certificate does not cover the request authority. The caller
    /// answers 421 Misdirected Request. Produced once `sni-scope-and-misdirected-request`
    /// (#63) has landed.
    MisdirectedRequest,
    /// The scratch was prepared for a different table generation than the one the
    /// match was asked to run against, so its header slots are indexed by a `NameId`
    /// space that does not belong to this table. The match refuses rather than
    /// reading a slot that may hold a different header's value; the caller answers
    /// the same way it answers `NoMatch` and increments `route_scratch_stale_total`,
    /// which should always be zero.
    ScratchStale,
}

/// Per-worker reusable match state.
///
/// Acquired inside a `CoreScope` closure and reused across every request that worker
/// handles. It is per WORKER, not per connection: at one million concurrent
/// connections a per-connection scratch would be more than 8 GB, and matching is fully
/// synchronous with no await point, so one scratch per worker is sound.
///
/// `MatchScratch` is `Send` because a worker owns it and may move it to its thread.
/// The type is technically also `Sync` because every field is plain data, but the
/// safety argument is ownership (exactly one worker touches it at a time), not a type
/// marker. It is deliberately not shared across threads.
#[derive(Debug)]
pub struct MatchScratch {
    r#gen: u32,
    table_gen: u64,
    hdr_slots: Box<[HeaderSlot]>,
    query_slots: Box<[QuerySlot]>,
    query_n: u16,
    query_indexed: bool,
    status: MatchStatus,
    host_buf: [u8; AUTHORITY_BUF_BYTES],
    host_len: u16,
    key_buf: [u8; HOST_KEY_BUF_BYTES],
}

impl MatchScratch {
    /// A new scratch.
    ///
    /// Allocates exactly once, for the fixed `MAX_QUERY_PARAMS`-entry `query_slots`
    /// array (64 x 12 = 768 bytes). `hdr_slots` starts empty and is allocated by the
    /// first `begin_request`, which is also the only other allocation this type ever
    /// performs. `gen` starts at 0 ("never written") and `table_gen` starts at
    /// `u64::MAX` so that a table at generation 0 still triggers the resize.
    #[must_use]
    pub fn new() -> MatchScratch {
        MatchScratch {
            r#gen: 0,
            table_gen: u64::MAX,
            hdr_slots: Box::<[HeaderSlot]>::default(),
            query_slots: vec![QuerySlot::default(); MAX_QUERY_PARAMS].into_boxed_slice(), // it-allow: hot-path-allocation reason: one-time construction of the fixed query slot array, not per request
            query_n: 0,
            query_indexed: false,
            status: MatchStatus::Idle,
            host_buf: [0u8; AUTHORITY_BUF_BYTES],
            host_len: 0,
            key_buf: [0u8; HOST_KEY_BUF_BYTES],
        }
    }

    /// Starts a request. Call exactly once, after the head is parsed and before any
    /// `observe_header`. Bumps the generation, handles wraparound, and resizes the slot
    /// array when the table generation changed.
    pub fn begin_request(&mut self, table: &RouteTable) {
        let table_gen = table.generation();
        if self.table_gen != table_gen {
            let n = table.interned_header_count();
            self.hdr_slots = vec![HeaderSlot::default(); n].into_boxed_slice(); // it-allow: hot-path-allocation reason: resized only when the route table generation changes, not once per request
            self.table_gen = table_gen;
            self.r#gen = 1;
        } else if self.r#gen == u32::MAX {
            for slot in &mut self.hdr_slots {
                *slot = HeaderSlot::default();
            }
            self.r#gen = 1;
        } else {
            self.r#gen = self.r#gen.wrapping_add(1);
        }
        self.query_n = 0;
        self.query_indexed = false;
        self.status = MatchStatus::Idle;
        self.host_len = 0;
    }

    /// Records one request header. Call once per header from the parsing loop, with the
    /// name already ASCII-lowercased and the value's offset and length within
    /// `RequestView::head`.
    ///
    /// A repeated header name overwrites the slot: the LAST occurrence wins. Values are
    /// never merged into a single byte string.
    pub fn observe_header(
        &mut self,
        table: &RouteTable,
        name: &[u8],
        value_off: u32,
        value_len: u32,
    ) {
        debug_assert!(
            self.r#gen != 0,
            "observe_header called before begin_request"
        );
        let Some(id) = table.header_names().lookup(name) else {
            return;
        };
        let Some(slot) = self.hdr_slots.get_mut(id.idx()) else {
            return;
        };
        *slot = HeaderSlot {
            r#gen: self.r#gen,
            off: value_off,
            len: value_len,
        };
    }

    /// Records the normalized authority so the matcher and the caller share one
    /// normalization.
    ///
    /// A `host` longer than `MAX_AUTHORITY_BYTES` records NOTHING, leaves `host()`
    /// empty, sets `status` to `MatchStatus::AuthorityRejected` and returns `false`.
    /// It does NOT truncate: a truncated authority is a different hostname, and a
    /// prefix of a long attacker-chosen authority that happens to equal a configured
    /// one would route to that host's routes. `normalize_authority` already refuses
    /// anything this long, so the branch is unreachable from the intended caller and
    /// exists so that a second caller cannot introduce host confusion.
    ///
    /// A caller that gets `false` should answer 400 and not call `match_request` at
    /// all; a caller that ignores it gets a `NoHostMatch` (or a catch-all match, if
    /// one is configured, exactly as an empty authority would).
    pub fn set_host(&mut self, host: &[u8]) -> bool {
        if host.len() > MAX_AUTHORITY_BYTES {
            self.status = MatchStatus::AuthorityRejected;
            self.host_len = 0;
            return false;
        }
        for (dst, src) in self.host_buf.iter_mut().zip(host.iter()) {
            *dst = *src;
        }
        self.host_len = u16::try_from(host.len()).unwrap_or(0);
        true
    }

    /// The normalized authority recorded by `set_host`.
    #[must_use]
    pub fn host(&self) -> &[u8] {
        self.host_buf
            .get(..usize::from(self.host_len))
            .unwrap_or(&[])
    }

    /// The value of interned header `id`, or `None` when absent this request.
    #[must_use]
    pub fn header_value<'h>(&self, id: NameId, head: &'h [u8]) -> Option<&'h [u8]> {
        let slot = self.hdr_slots.get(id.idx())?;
        if slot.r#gen != self.r#gen {
            return None;
        }
        let start = usize::try_from(slot.off).ok()?;
        let end = start.checked_add(usize::try_from(slot.len).ok()?)?;
        head.get(start..end)
    }

    /// True when interned header `id` is present this request.
    #[must_use]
    pub fn header_present(&self, id: NameId) -> bool {
        self.hdr_slots
            .get(id.idx())
            .is_some_and(|slot| slot.r#gen == self.r#gen)
    }

    /// Length of the header slot array, which is the table's interned header count as
    /// of the last `begin_request`.
    ///
    /// `predicate-bytecode-eval` (#59) uses it to tell "this header is absent" apart
    /// from "this predicate names a `NameId` this scratch has no slot for", because
    /// the second is a corrupted or mismatched table and must fail closed rather
    /// than satisfy a `HeaderAbsent` predicate.
    #[must_use]
    pub fn header_slot_count(&self) -> usize {
        self.hdr_slots.len()
    }

    /// The table generation this scratch was prepared for by the last
    /// `begin_request`, or `u64::MAX` before the first one.
    ///
    /// `match-request-core` (#60) compares it with the table it was handed and
    /// refuses to match when they differ: the header slots are indexed by a `NameId`
    /// space that belongs to one specific table generation, so evaluating them
    /// against a different table can read the value of a different header entirely.
    #[must_use]
    pub fn table_generation(&self) -> u64 {
        self.table_gen
    }

    /// Indexes the query string. Idempotent within one request. Called by the matcher
    /// on the first query predicate; callers do not need to call it.
    ///
    /// `query_indexed` is set only once the `needs_query()` gate is passed, so it
    /// tracks "the query string was actually parsed", not merely "this method was
    /// called". That is what lets `query_indexed()` serve its documented purpose:
    /// a test (or the explain surface) can tell a genuine parse apart from a call
    /// that was gated away, which is otherwise unobservable from outside.
    pub fn index_query(&mut self, table: &RouteTable, query: &[u8]) {
        if self.query_indexed {
            return;
        }
        if !table.needs_query() {
            return;
        }
        self.query_indexed = true;
        let q_len = query.len().min(MAX_QUERY_BYTES);
        let q = query.get(..q_len).unwrap_or(&[]);
        let mut pos = 0usize;
        // Both bounds are intentionally strict. The `<=` mutation is equivalent:
        // at `pos == q.len()` the pair is empty and is skipped; at
        // `query_n == MAX_QUERY_PARAMS` the `get_mut` returns None and the slot
        // count is not incremented, so no recorded value changes.
        while pos < q.len() && (usize::from(self.query_n) < MAX_QUERY_PARAMS) {
            let rest = q.get(pos..).unwrap_or(&[]);
            let end = match rest.iter().position(|&b| b == b'&') {
                Some(i) => pos.checked_add(i).unwrap_or(q.len()),
                None => q.len(),
            };
            let pair = q.get(pos..end).unwrap_or(&[]);
            let (name, voff, vlen) = if let Some(i) = pair.iter().position(|&b| b == b'=') {
                let name = pair.get(..i).unwrap_or(&[]);
                let voff = u32::try_from(pos.saturating_add(i).saturating_add(1)).unwrap_or(0);
                let vlen =
                    u32::try_from(pair.len().saturating_sub(i).saturating_sub(1)).unwrap_or(0);
                (name, voff, vlen)
            } else {
                let name = pair;
                let voff = u32::try_from(pos.saturating_add(pair.len())).unwrap_or(0);
                let vlen = 0u32;
                (name, voff, vlen)
            };
            if !name.is_empty()
                && let Some(id) = table.query_names().lookup(name)
                && let Some(slot) = self.query_slots.get_mut(usize::from(self.query_n))
            {
                *slot = QuerySlot {
                    name: id,
                    off: voff,
                    len: vlen,
                };
                self.query_n += 1;
            }
            pos = end.checked_add(1).unwrap_or(q.len());
        }
    }

    /// The value of the first occurrence of interned query parameter `id`, or `None`.
    #[must_use]
    pub fn query_value<'q>(&self, id: NameId, query: &'q [u8]) -> Option<&'q [u8]> {
        let n = usize::from(self.query_n);
        let slots = self.query_slots.get(..n).unwrap_or(&[]);
        for slot in slots {
            if slot.name == id {
                let start = usize::try_from(slot.off).ok()?;
                let end = start.checked_add(usize::try_from(slot.len).ok()?)?;
                return query.get(start..end);
            }
        }
        None
    }

    /// True when interned query parameter `id` is present.
    #[must_use]
    pub fn query_present(&self, id: NameId) -> bool {
        let n = usize::from(self.query_n);
        let slots = self.query_slots.get(..n).unwrap_or(&[]);
        slots.iter().any(|slot| slot.name == id)
    }

    /// True when the query string has actually been parsed for the current
    /// request, as opposed to `index_query` merely having been called.
    ///
    /// It exists so a test can assert that a table whose `needs_query()` is false
    /// never parses the query string, which is otherwise unobservable. The explain
    /// surface reads it too.
    #[must_use]
    pub fn query_indexed(&self) -> bool {
        self.query_indexed
    }

    /// What the last match did.
    #[must_use]
    pub fn status(&self) -> MatchStatus {
        self.status
    }

    /// Sets the status. Called by the matcher; exposed because the matcher lives in a
    /// different module.
    pub fn set_status(&mut self, status: MatchStatus) {
        self.status = status;
    }

    /// The scratch's mutable host-key buffer, lent to `resolve_host` so the key is
    /// built without a stack copy per group.
    pub fn key_buf_mut(&mut self) -> &mut [u8; HOST_KEY_BUF_BYTES] {
        &mut self.key_buf
    }

    /// The current generation, for tests and for the explain surface.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.r#gen
    }
}

impl Default for MatchScratch {
    fn default() -> Self {
        MatchScratch::new()
    }
}

#[cfg(test)]
impl MatchScratch {
    /// Test-only setter to drive the generation to an exact value.
    pub fn force_gen(&mut self, g: u32) {
        self.r#gen = g;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use proptest::prelude::*;

    use super::MatchScratch;
    use crate::ids::NameId;
    use crate::intern::NameSetBuilder;
    use crate::scratch::MatchStatus;
    use crate::table::{RouteTable, TableParts};

    /// Build a table with the requested header and query names.
    ///
    /// These tests use `RouteTable::from_parts` directly rather than waiting for
    /// `builder-admission-and-assemble` (#56), because this issue is mergeable
    /// without the builder and only needs the two interned name sets.
    fn build_table(
        header_names: &[&[u8]],
        query_names: &[&[u8]],
        needs_query: bool,
        generation: u64,
    ) -> (RouteTable, Vec<NameId>, Vec<NameId>) {
        let mut hb = NameSetBuilder::new();
        let mut hids = Vec::new();
        for name in header_names {
            hids.push(hb.insert(name).unwrap());
        }
        let mut qb = NameSetBuilder::new();
        let mut qids = Vec::new();
        for name in query_names {
            qids.push(qb.insert(name).unwrap());
        }
        let table = RouteTable::from_parts(TableParts {
            header_names: hb.finish(),
            query_names: qb.finish(),
            needs_query,
            generation,
            ..Default::default()
        });
        (table, hids, qids)
    }

    #[test]
    fn fresh_scratch_has_no_values() {
        // Use a non-zero generation so `table_generation()` cannot be replaced
        // with a constant 0 and still pass.
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 7);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        for id in &hids {
            assert_eq!(scratch.header_value(*id, &[]), None);
            assert!(!scratch.header_present(*id));
        }
        assert_eq!(scratch.status(), MatchStatus::Idle);
        assert_eq!(scratch.table_generation(), table.generation());
        assert_eq!(scratch.header_slot_count(), 1);
        assert_eq!(scratch.generation(), 1);
    }

    #[test]
    fn observe_then_read() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let tenant = hids[0];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let mut head = [0u8; 64];
        head[10..14].copy_from_slice(b"acme");
        scratch.observe_header(&table, b"x-tenant", 10, 4);
        assert_eq!(scratch.header_value(tenant, &head), Some(&b"acme"[..]));
        assert!(scratch.header_present(tenant));
    }

    #[test]
    fn unreferenced_header_is_ignored() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.observe_header(&table, b"user-agent", 0, 10);
        assert_eq!(scratch.header_value(hids[0], &[]), None);
        assert!(!scratch.header_present(hids[0]));
    }

    #[test]
    fn duplicate_header_last_wins() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let mut head = [0u8; 64];
        head[0..4].copy_from_slice(b"aaaa");
        head[4..8].copy_from_slice(b"bbbb");
        scratch.observe_header(&table, b"x-tenant", 0, 4);
        scratch.observe_header(&table, b"x-tenant", 4, 4);
        assert_eq!(scratch.header_value(hids[0], &head), Some(&b"bbbb"[..]));
    }

    #[test]
    fn new_request_invalidates_slots() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.observe_header(&table, b"x-tenant", 0, 4);
        scratch.begin_request(&table);
        assert_eq!(scratch.header_value(hids[0], &[]), None);
        assert!(!scratch.header_present(hids[0]));
    }

    #[test]
    fn gen_wraparound_invalidates_slots() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.force_gen(u32::MAX);
        let mut head = [0u8; 64];
        head[0..4].copy_from_slice(b"valu");
        scratch.observe_header(&table, b"x-tenant", 0, 4);
        assert_eq!(scratch.header_value(hids[0], &head), Some(&b"valu"[..]));
        scratch.begin_request(&table);
        assert_eq!(scratch.header_value(hids[0], &head), None);
        assert!(!scratch.header_present(hids[0]));
        assert_eq!(scratch.generation(), 1);
        // The check above is satisfied by the generation reset ALONE: the
        // stale slot still holds `gen: u32::MAX` and the fresh counter is 1,
        // so `1 != u32::MAX` hides a missing clear just as well as a real
        // one. Drive the counter back to `u32::MAX` (simulating another
        // 2^32 requests on this worker) without going through
        // `begin_request` again, which would itself re-trigger the clear.
        // If the wraparound clear at the previous `begin_request` did not
        // run, the stale slot is still `{ gen: u32::MAX, off: 0, len: 4 }`
        // and is live again the moment `self.gen` climbs back to
        // `u32::MAX`, which is exactly the authorization bypass this test
        // exists to catch.
        scratch.force_gen(u32::MAX);
        assert_eq!(scratch.header_value(hids[0], &head), None);
        assert!(!scratch.header_present(hids[0]));
    }

    #[test]
    fn table_generation_change_resizes() {
        let (t2, _, _) = build_table(&[b"a", b"b"], &[], false, 0);
        let (t5, _, _) = build_table(&[b"a", b"b", b"c", b"d", b"e"], &[], false, 1);
        let (t1, _, _) = build_table(&[b"a"], &[], false, 2);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&t2);
        assert_eq!(scratch.table_generation(), 0);
        scratch.observe_header(&t2, b"a", 0, 1);
        scratch.begin_request(&t5);
        assert_eq!(scratch.table_generation(), 1);
        assert_eq!(scratch.header_slot_count(), 5);
        assert_eq!(scratch.generation(), 1);
        assert_eq!(scratch.header_value(NameId(0), &[]), None);
        scratch.begin_request(&t1);
        assert_eq!(scratch.table_generation(), 2);
        assert_eq!(scratch.header_slot_count(), 1);
        assert_eq!(scratch.header_value(NameId(4), &[]), None);
    }

    #[test]
    fn table_generation_same_size_swap_invalidates_slots() {
        // Two consecutive table generations that intern the SAME COUNT of
        // names (2) but different actual names. `begin_request` must
        // reallocate `hdr_slots` on every table generation change, not only
        // when the count differs: if a same-size swap instead retained the
        // array, `NameId(0)` would still hold whatever the OLD table's first
        // name last observed, and the new table's first name (a different
        // header entirely) would read that stale value. That is exactly the
        // cross-table read this issue's "do NOT let a scratch prepared
        // against one table be used to match against another" forbids.
        let (t_old, hids_old, _) = build_table(&[b"m", b"n"], &[], false, 3);
        let (t_new, hids_new, _) = build_table(&[b"p", b"q"], &[], false, 4);
        let mut scratch = MatchScratch::new();
        let mut head = [0u8; 8];
        head[0..4].copy_from_slice(b"data");

        scratch.begin_request(&t_old);
        scratch.observe_header(&t_old, b"m", 0, 4);
        assert_eq!(scratch.header_value(hids_old[0], &head), Some(&b"data"[..]));

        scratch.begin_request(&t_new);
        assert_eq!(scratch.header_slot_count(), 2);
        assert_eq!(scratch.table_generation(), 4);
        // `hids_new[0]` is `NameId(0)`, the same index `hids_old[0]` used,
        // but it names "p", a header nothing observed this request.
        assert_eq!(scratch.header_value(hids_new[0], &head), None);
        assert!(!scratch.header_present(hids_new[0]));
    }

    #[test]
    fn observe_without_begin_is_not_live() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        // In debug builds the `debug_assert!` in `observe_header` fires because
        // this is a caller bug. The release behaviour is what matters: the slot
        // is written with `gen: 0`, which can never equal a live generation.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            scratch.observe_header(&table, b"x-tenant", 0, 4);
        }));
        scratch.begin_request(&table);
        assert_eq!(scratch.header_value(hids[0], &[]), None);
        assert!(!scratch.header_present(hids[0]));
    }

    #[test]
    fn empty_and_out_of_range_values() {
        let (table, hids, _) = build_table(&[b"x-tenant"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.observe_header(&table, b"x-tenant", 0, 0);
        assert_eq!(scratch.header_value(hids[0], &[]), Some(&[][..]));

        let mut head = [0u8; 8];
        head[0..4].copy_from_slice(b"abcd");
        scratch.observe_header(&table, b"x-tenant", 8, 4);
        assert_eq!(scratch.header_value(hids[0], &head), None);

        scratch.observe_header(&table, b"x-tenant", 1, u32::MAX);
        assert_eq!(scratch.header_value(hids[0], &head), None);
    }

    #[test]
    fn oversize_host_is_refused_not_truncated() {
        let (_table, _, _) = build_table(&[], &[], false, 0);
        let mut scratch = MatchScratch::new();
        let long = vec![b'a'; 300];
        let ok255 = vec![b'b'; 255];
        assert!(!scratch.set_host(&long));
        assert_eq!(scratch.host(), &[][..]);
        assert_eq!(scratch.status(), MatchStatus::AuthorityRejected);
        assert!(scratch.set_host(&ok255));
        assert_eq!(scratch.host(), &ok255[..]);
        assert_eq!(scratch.host().len(), 255);
        // Truncating would let a long attacker-chosen authority whose 255-byte
        // prefix equals a configured hostname route to that hostname.
    }

    #[test]
    fn begin_request_bumps_generation() {
        let (table, _, _) = build_table(&[b"x"], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        assert_eq!(scratch.generation(), 1);
        scratch.begin_request(&table);
        assert_eq!(scratch.generation(), 2);
    }

    #[test]
    fn set_status_is_stored() {
        let (table, _, _) = build_table(&[], &[], false, 0);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        assert_eq!(scratch.status(), MatchStatus::Idle);
        scratch.set_status(MatchStatus::NoMatch);
        assert_eq!(scratch.status(), MatchStatus::NoMatch);
    }

    #[test]
    fn key_buf_mut_is_reused() {
        let mut scratch = MatchScratch::new();
        let buf = scratch.key_buf_mut();
        buf[0] = 0xAB;
        let buf = scratch.key_buf_mut();
        assert_eq!(buf[0], 0xAB);
        // A mutation that returns a different buffer would leave the default
        // value here instead of the byte we wrote.
    }

    #[test]
    fn query_basic() {
        let (table, _, qids) = build_table(&[], &[b"a", b"b", b"c"], true, 0);
        let a = qids[0];
        let b = qids[1];
        let c = qids[2];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        assert!(!scratch.query_indexed());
        scratch.index_query(&table, b"a=1&b=2");
        assert_eq!(scratch.query_value(a, b"a=1&b=2"), Some(&b"1"[..]));
        assert_eq!(scratch.query_value(b, b"a=1&b=2"), Some(&b"2"[..]));
        assert!(scratch.query_present(a));
        assert!(scratch.query_indexed());
        assert!(!scratch.query_present(c));
        assert_eq!(scratch.query_value(c, b"a=1&b=2"), None);
    }

    #[test]
    fn index_query_second_call_is_noop() {
        // Edge case 17: `index_query` called twice. The second call must
        // return immediately, guarded by `query_indexed`.
        let (table, _, qids) = build_table(&[], &[b"a", b"c"], true, 0);
        let a = qids[0];
        let c = qids[1];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"a=1");
        assert_eq!(scratch.query_n, 1);
        assert!(scratch.query_present(a));

        // A second call, even with a query string that references a
        // DIFFERENT interned name, must be a no-op: `index_query` is
        // idempotent within one request. If the `query_indexed` guard were
        // deleted, this call would parse "c=9" and query_n would grow to 2.
        scratch.index_query(&table, b"c=9");
        assert_eq!(scratch.query_n, 1);
        assert!(scratch.query_present(a));
        assert!(!scratch.query_present(c));
    }

    #[test]
    fn index_query_skipped_when_table_does_not_need_it() {
        // Edge case 18: `needs_query() == false`. `index_query` must not parse
        // the query string at all, even though "a" is an interned query name
        // that WOULD be recorded if the string were parsed. If the
        // `!table.needs_query()` guard were deleted, query_n would become 1
        // and `query_indexed()` would report the parse as having happened.
        let (table, _, qids) = build_table(&[], &[b"a"], false, 0);
        let a = qids[0];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        assert!(!table.needs_query());
        scratch.index_query(&table, b"a=1");
        assert_eq!(scratch.query_n, 0);
        assert!(!scratch.query_present(a));
        assert_eq!(scratch.query_value(a, b"a=1"), None);
        // `query_indexed()` now tracks "the query was actually parsed", not
        // "index_query was called", so a call gated away by `needs_query()`
        // must leave it false.
        assert!(!scratch.query_indexed());
    }

    #[test]
    fn query_edge_forms() {
        let (table, _, qids) = build_table(&[], &[b"a"], true, 0);
        let a = qids[0];

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"");
        assert_eq!(scratch.query_value(a, b""), None);
        assert_eq!(scratch.query_n, 0);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"a");
        assert_eq!(scratch.query_value(a, b"a"), Some(&b""[..]));
        assert_eq!(scratch.query_n, 1);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"=v");
        assert_eq!(scratch.query_value(a, b"=v"), None);
        assert_eq!(scratch.query_n, 0);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"a=1&a=2");
        assert_eq!(scratch.query_value(a, b"a=1&a=2"), Some(&b"1"[..]));
        assert_eq!(scratch.query_n, 2);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"a=");
        assert_eq!(scratch.query_value(a, b"a="), Some(&b""[..]));
        assert_eq!(scratch.query_n, 1);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        scratch.index_query(&table, b"&&a=1&&");
        assert_eq!(scratch.query_value(a, b"&&a=1&&"), Some(&b"1"[..]));
        assert_eq!(scratch.query_n, 1);
    }

    #[test]
    fn query_slot_exhaustion_resistance() {
        let (table, _, qids) = build_table(&[], &[b"tenant"], true, 0);
        let tenant = qids[0];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);

        let mut query = Vec::new();
        for i in 0..64 {
            query.extend_from_slice(format!("x{i}=1&").as_bytes());
        }
        query.extend_from_slice(b"tenant=x");
        scratch.index_query(&table, &query);
        assert_eq!(scratch.query_value(tenant, &query), Some(&b"x"[..]));
        assert_eq!(scratch.query_n, 1);

        // Now fill all 64 slots with referenced names and assert the 65th is dropped.
        let mut qb = NameSetBuilder::new();
        let mut ids = Vec::new();
        for i in 0..65 {
            ids.push(qb.insert(format!("a{i}").as_bytes()).unwrap());
        }
        let t = RouteTable::from_parts(TableParts {
            query_names: qb.finish(),
            needs_query: true,
            ..Default::default()
        });
        scratch.begin_request(&t);
        let mut query2 = Vec::new();
        for i in 0..65 {
            query2.extend_from_slice(format!("a{i}=v&").as_bytes());
        }
        query2.pop(); // remove trailing &
        scratch.index_query(&t, &query2);
        assert_eq!(scratch.query_value(ids[0], &query2), Some(&b"v"[..]));
        assert_eq!(scratch.query_value(ids[64], &query2), None);
        assert_eq!(scratch.query_n, 64);
    }

    #[test]
    fn query_truncated_at_4kib() {
        let (table, _, qids) = build_table(&[], &[b"tenant"], true, 0);
        let tenant = qids[0];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);

        // 1022 repetitions of "x=1&" is 4088 bytes, leaving 8 bytes before the
        // 4096-byte cap. Appending "tenant=val" puts the '=' at byte 4094, so
        // the truncated query ends with "tenant=v" and the recorded value is
        // the single byte "v".
        let mut query = b"x=1&".repeat(1022);
        query.extend_from_slice(b"tenant=val");
        scratch.index_query(&table, &query);
        assert_eq!(scratch.query_value(tenant, &query), Some(&b"v"[..]));
        assert_eq!(scratch.query_n, 1);
        assert!(scratch.query_indexed());
    }

    #[derive(Debug, Clone)]
    enum Op {
        BeginRequest,
        Observe(usize),
        ReadAll,
    }

    fn any_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            1 => Just(Op::BeginRequest),
            3 => (0usize..8).prop_map(Op::Observe),
            2 => Just(Op::ReadAll),
        ]
    }

    proptest! {
        #[test]
        fn slot_liveness_is_exactly_this_request(ops in prop::collection::vec(any_op(), 1..=50)) {
            let name_bytes: Vec<Vec<u8>> = (0..8)
                .map(|i| format!("x-{i}").into_bytes())
                .collect();
            let mut hb = NameSetBuilder::new();
            let mut ids = Vec::new();
            for n in &name_bytes {
                ids.push(hb.insert(n).unwrap());
            }
            let table = RouteTable::from_parts(TableParts {
                header_names: hb.finish(),
                ..Default::default()
            });

            let mut scratch = MatchScratch::new();
            scratch.begin_request(&table);
            let mut live = HashSet::new();
            for op in ops {
                match op {
                    Op::BeginRequest => {
                        scratch.begin_request(&table);
                        live.clear();
                    }
                    Op::Observe(idx) => {
                        let id = ids[idx];
                        let off = u32::try_from(idx).unwrap_or(0);
                        scratch.observe_header(&table, &name_bytes[idx], off, 1);
                        live.insert(id);
                    }
                    Op::ReadAll => {
                        for id in &ids {
                            assert_eq!(scratch.header_present(*id), live.contains(id));
                        }
                    }
                }
            }
        }
    }
}
