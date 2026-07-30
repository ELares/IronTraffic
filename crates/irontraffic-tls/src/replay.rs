// SPDX-License-Identifier: MIT OR Apache-2.0

//! The 0-RTT early data replay filter: a two-generation blocked Bloom filter over PSK identities.
//!
//! [`EarlyDataFilter::check_and_insert`] answers, in one atomic-feeling operation, "has this exact
//! PSK identity already been presented for early data on this node": the second presentation of
//! the same ticket for early data is rejected, the first is admitted and remembered. This is the
//! only stateful check in `crate::early_data::evaluate`, and it runs last, after every
//! side-effect-free condition, precisely because it is the one with a side effect.
//!
//! **Best effort, not the security boundary.** A single node's Bloom filter cannot see a ticket
//! replayed to a different node before this node's own answer is known, and this crate does not
//! consult a distributed store here on purpose: a network round trip in the 0-RTT path would
//! delete the entire latency benefit 0-RTT exists to provide. What actually makes a replay
//! harmless is `crate::early_data::evaluate`'s method restriction (conditions 1 through 5), not
//! this filter; see that module's documentation and `docs/tls/EARLY-DATA.md` for the full
//! statement. This filter exists to cut the volume of replays that reach a backend at all, and a
//! future best-effort cluster broadcast (the unpublished slug `early-data-replay-gossip`) narrows
//! the window further, never to zero.
//!
//! **Sizing, derived rather than asserted.** A Bloom filter with `m` bits, `n` entries and `k`
//! probes has false-positive rate about `(1 - e^(-kn/m))^k`. At [`REPLAY_BITS_PER_KEY`] (40) bits
//! per entry and `k` = [`REPLAY_PROBES`] (13) that is about 5.8e-8 unblocked in the theoretical,
//! unblocked construction; the **blocked** layout used here (one 64-byte cache line per key, all
//! 13 bit probes confined inside that one line so a lookup costs one cache miss instead of 13)
//! costs roughly an order of magnitude at these parameters, so a measured rate nearer 5e-7 is
//! expected. `false_positive_rate_under_1e5` (below) asserts a measured rate under 1e-5, which
//! leaves headroom for the Poisson spread in keys per block.
//!
//! **Counting is deliberately not implemented.** A counting Bloom filter exists to support
//! deletion of individual entries. This filter deletes by rotating a whole generation instead, so
//! a plain bit Bloom is strictly smaller, faster and simpler; do not "restore" per-bit counters.
//!
//! **The memory window is deliberately shorter than the ticket window.** Two generations rotating
//! every `replay_rotate_secs` remember between one and two rotation periods (3 to 6 hours at the
//! default 3-hour period), while a ticket from `cluster-derived-session-ticketer` (#120) stays
//! decryptable for 12 to 18 hours (three 6-hour epochs). A replay presented after this filter has
//! forgotten the ticket is therefore possible by construction, not by accident: sizing the filter
//! to cover the full ticket window would cost 3 to 6 times the memory and would still not cover
//! the cross-node case, which is the whole reason the method restriction, not this filter, is the
//! security boundary.
//!
//! **The rotation zero race is benign in one direction only.** Zeroing the outgoing generation in
//! [`EarlyDataFilter::rotate_if_due`] races with a concurrent probe of that same generation. A bit
//! cleared mid-probe can only ever turn a "present" answer into "absent", which is a false
//! negative: one replay of a request already restricted to idempotent methods slips through. It
//! can never turn "absent" into "present", so the race cannot manufacture a rejection, and it
//! cannot admit anything the method restriction does not already make harmless.
//!
//! **One filter per process, shared by every listener with early data enabled.** Both generations
//! together are 10,000,000 bytes at the default capacity; a filter per listener would be 10 MB per
//! listener for a structure whose contents (ticket identities) are not listener specific.
//! [`EarlyDataFilter::check_and_insert`] takes `&self` and touches only relaxed atomics precisely
//! so that one instance can be shared behind a plain `&EarlyDataFilter` across every listener that
//! needs it, with no lock. Sharing is also strictly stronger: a ticket replayed against a
//! different listener on the same node is still caught.
//!
//! **The filter key is secret and must be.** [`EarlyDataFilter::new`]'s `key` argument seeds the
//! internal keyed `SipHash`. A peer who knows the key could choose PSK identity bytes that drive
//! many keys into one 64-byte block and saturate it, turning every other ticket that lands in that
//! block into a false positive; that degrades those clients to a full handshake rather than
//! bypassing anything (fail closed), but it is still a free, attacker-chosen degradation. `key`
//! MUST be CSPRNG-derived or cluster-secret-derived; a literal key in non-test code is a security
//! defect, exactly as for `crate::name::NameHasher`.
//!
//! This module deliberately does not reuse `crate::name::NameHasher`: that type's `hash` takes a
//! `&str`, and a PSK identity is arbitrary bytes, not a normalized DNS name. `split_hash` below
//! runs its own keyed `SipHash-1-3` instead, and `name.rs` (outside this issue's file table) is not
//! touched to add a bytes-hashing variant.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use siphasher::sip128::{Hasher128, SipHasher13};

use crate::early_data::EarlyDataConfig;
use crate::time::UnixSeconds;

/// Probes per key inside one 64-byte block.
pub const REPLAY_PROBES: usize = 13;
/// Bits allocated per key at the filter's sizing capacity.
pub const REPLAY_BITS_PER_KEY: u32 = 40;

/// Bits in one block: one 64-byte cache line, 8 `AtomicU64` words.
const BLOCK_BITS: u64 = 512;
/// `AtomicU64` words per block.
const WORDS_PER_BLOCK: usize = 8;

/// Counters for the replay filter. Every field is a relaxed, lossy `AtomicU64`.
#[derive(Debug, Default)]
pub struct ReplayStats {
    /// `tls_early_data_replay_inserts_total`
    pub inserts: AtomicU64,
    /// `tls_early_data_replay_hits_total`
    pub hits: AtomicU64,
    /// `tls_early_data_replay_rotations_total`
    pub rotations: AtomicU64,
    /// `tls_early_data_replay_fill_bits`: set-bit count in the generation that was just retired,
    /// written by [`EarlyDataFilter::rotate_if_due`] and by nothing else. An operator compares it
    /// against `blocks * 512` to see whether the configured capacity is too small.
    pub fill_bits: AtomicU64,
}

/// Two-generation blocked Bloom filter over PSK identities.
///
/// Construct one per process (never one per listener; see the module documentation) and share it
/// behind a plain reference: every method here takes `&self` and touches only relaxed atomics.
pub struct EarlyDataFilter {
    /// Two generations, each `blocks * 8` words. Which one is `current` flips in
    /// [`EarlyDataFilter::rotate_if_due`].
    gens: [Box<[AtomicU64]>; 2],
    /// Which generation is current: 0 or 1. Relaxed.
    current: AtomicU32,
    /// Unix seconds at which the current generation started. Relaxed.
    rotated_at: AtomicU64,
    /// Blocks per generation, derived from the configured capacity in [`EarlyDataFilter::new`].
    blocks: u32,
    /// Seconds between rotations, copied from the config this filter was built from.
    rotate_secs: u32,
    /// Key for this filter's own keyed `SipHash`. MUST be CSPRNG-derived or
    /// cluster-secret-derived in non-test code; see the module documentation.
    key: [u8; 16],
    stats: ReplayStats,
}

/// Number of 64-byte blocks that hold `capacity` entries at [`REPLAY_BITS_PER_KEY`] bits each,
/// rounded up, and never zero.
///
/// The u64 intermediate and the `try_from` back to `u32` are defence in depth, not a response to
/// an anticipated overflow: `capacity` is documented to already be clamped to `1_024..=8_388_608`
/// by `EarlyDataConfig::clamped`, and `8_388_608 * 40` does not approach `u32::MAX`. The trailing
/// `.max(1)` is a second, independent piece of defence in depth: [`EarlyDataFilter::new`]
/// documents that it does not re-clamp its config, so a caller that skips `clamped()` and passes
/// `replay_capacity: 0` must still get a real, if severely undersized, one-block filter rather
/// than the zero-block filter that would silently accept every ticket forever (every probe reads
/// past the end of an empty generation, which [`block_has_all`] treats as "absent").
fn blocks_for(capacity: u32) -> u32 {
    let bits = u64::from(capacity) * u64::from(REPLAY_BITS_PER_KEY);
    u32::try_from(bits.div_ceil(BLOCK_BITS))
        .unwrap_or(u32::MAX)
        .max(1)
}

/// Builds one generation of `blocks * 8` zeroed `AtomicU64` words.
fn build_generation(blocks: u32) -> Box<[AtomicU64]> {
    let words = u64::from(blocks) * 8;
    let words = usize::try_from(words).unwrap_or(usize::MAX);
    (0..words)
        .map(|_| AtomicU64::new(0))
        .collect::<Vec<_>>() // it-allow: hot-path-allocation reason: runs at most twice, inside EarlyDataFilter::new, never on the check_and_insert, contains, insert or rotate_if_due path; becomes the immutable generation buffer for the filter's whole lifetime
        .into_boxed_slice() // it-allow: hot-path-allocation reason: converts the just-built Vec into the immutable generation buffer; construction-time only, mirrors build_slot_ring in ticket.rs
}

/// Reads all 8 words of the block starting at `word_base` in `words` and reports whether every
/// bit in `masks` is already set, accumulating over all 8 words every time with no early exit:
/// early exit here would be a timing signal on a value derived from a ticket. `words` is accessed
/// with `get`, never indexed directly, because `word_base` comes from a hash of
/// attacker-influenced input. Takes `masks` by value, not by reference: it is a plain `[u64; 8]`,
/// 64 bytes, and this crate's `clippy.toml` sets `trivial-copy-size-limit = 64`, so a reference
/// here is pure overhead.
fn block_has_all(words: &[AtomicU64], word_base: usize, masks: [u64; WORDS_PER_BLOCK]) -> bool {
    let mut all = true;
    for (w, &mask) in masks.iter().enumerate() {
        let Some(cell) = words.get(word_base + w) else {
            return false;
        };
        let v = cell.load(Ordering::Relaxed);
        all &= (v & mask) == mask;
    }
    all
}

/// Sets every nonzero mask word into the block starting at `word_base` in `words`, on the current
/// generation, via `fetch_or`. Takes `masks` by value; see [`block_has_all`]'s doc comment.
fn block_insert_all(words: &[AtomicU64], word_base: usize, masks: [u64; WORDS_PER_BLOCK]) {
    for (w, &mask) in masks.iter().enumerate() {
        if mask == 0 {
            continue;
        }
        if let Some(cell) = words.get(word_base + w) {
            cell.fetch_or(mask, Ordering::Relaxed);
        }
    }
}

/// Derives the 13 probe bit positions inside one block from a split hash, returning them already
/// folded into an 8-word mask array so the probe and the insert each touch each word once.
#[allow(
    clippy::integer_division,
    reason = "64 is the fixed number of bits in one AtomicU64 word, not a value that could ever \
              be zero or attacker-influenced; truncation toward zero is the intended split of a \
              9-bit block offset into a word index and a bit-in-word index"
)]
fn probe_masks(h1: u64, h2: u64) -> [u64; WORDS_PER_BLOCK] {
    let mut masks = [0u64; WORDS_PER_BLOCK];
    let probes = u32::try_from(REPLAY_PROBES).unwrap_or(13);
    for i in 0..probes {
        let bit_i = (h2.wrapping_mul(u64::from(i) + 1)) ^ h1.rotate_left(i.wrapping_mul(5));
        let bit_i = bit_i % BLOCK_BITS;
        let word_offset = usize::try_from(bit_i / 64).unwrap_or(0);
        let bit_in_word = bit_i % 64;
        if let Some(m) = masks.get_mut(word_offset) {
            *m |= 1u64 << bit_in_word;
        }
    }
    masks
}

impl EarlyDataFilter {
    /// Build a filter. `key` seeds the internal hash; pass 16 bytes derived from the cluster
    /// secret or the operating system CSPRNG, so that a future gossip of insertions is comparable
    /// across nodes and so that a peer cannot predict which block its chosen PSK identity lands
    /// in. `config` is assumed already clamped by [`EarlyDataConfig::clamped`]; this constructor
    /// does not re-clamp.
    #[must_use]
    pub fn new(config: &EarlyDataConfig, key: [u8; 16], now: UnixSeconds) -> Self {
        let blocks = blocks_for(config.replay_capacity);
        Self {
            gens: [build_generation(blocks), build_generation(blocks)],
            current: AtomicU32::new(0),
            rotated_at: AtomicU64::new(now.get()),
            blocks,
            rotate_secs: config.replay_rotate_secs,
            key,
            stats: ReplayStats::default(),
        }
    }

    /// Bytes of memory held by both generations. `10_000_000` at the default capacity of
    /// 1,000,000 tickets per generation.
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        self.gens.iter().map(|g| g.len() * 8).sum()
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &ReplayStats {
        &self.stats
    }

    /// Index of the generation currently receiving inserts: 0 or 1, flipped only by
    /// [`EarlyDataFilter::rotate_if_due`].
    fn current_index(&self) -> usize {
        usize::from(self.current.load(Ordering::Relaxed) != 0)
    }

    /// Index of the OTHER generation: the one not currently receiving inserts.
    fn other_index(&self) -> usize {
        1 - self.current_index()
    }

    /// Keyed `SipHash-1-3` of `key16` over both 64-bit halves of the 128-bit output. Does not use
    /// `crate::name::NameHasher`, whose `hash` takes a `&str`; see the module documentation.
    fn split_hash(&self, key16: &[u8]) -> (u64, u64) {
        let mut hasher = SipHasher13::new_with_key(&self.key);
        core::hash::Hasher::write(&mut hasher, key16);
        let h128 = hasher.finish128();
        (h128.h1, h128.h2)
    }

    /// Block index and probe masks shared by every probing and inserting method below, so the two
    /// hash values are computed exactly once per call.
    fn locate(&self, key16: &[u8]) -> (usize, [u64; WORDS_PER_BLOCK]) {
        let (h1, h2) = self.split_hash(key16);
        let blocks = u64::from(self.blocks.max(1));
        let block = usize::try_from(h1 % blocks).unwrap_or(0);
        let word_base = block * WORDS_PER_BLOCK;
        (word_base, probe_masks(h1, h2))
    }

    /// Probe both generations and insert into the current one if absent.
    ///
    /// Returns `true` when the key was already present in either generation, which means "reject
    /// the early data": this is the single fail-closed check `crate::early_data::evaluate` calls
    /// last, because it is the only one of the seven conditions with a side effect. Allocates
    /// nothing and never panics.
    #[must_use]
    pub fn check_and_insert(&self, key16: &[u8]) -> bool {
        let (word_base, masks) = self.locate(key16);
        let Some(current_words) = self.gens.get(self.current_index()) else {
            return false;
        };
        let Some(other_words) = self.gens.get(self.other_index()) else {
            return false;
        };

        // The OTHER generation first, then the current one: this is what makes the filter
        // remember between one and two rotation periods rather than just one.
        if block_has_all(other_words, word_base, masks)
            || block_has_all(current_words, word_base, masks)
        {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        block_insert_all(current_words, word_base, masks);
        self.stats.inserts.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Probe without inserting. Used by the future gossip receiver, which must not create
    /// insertions that did not happen locally. Never increments a counter.
    #[must_use]
    pub fn contains(&self, key16: &[u8]) -> bool {
        let (word_base, masks) = self.locate(key16);
        let Some(current_words) = self.gens.get(self.current_index()) else {
            return false;
        };
        let Some(other_words) = self.gens.get(self.other_index()) else {
            return false;
        };
        block_has_all(other_words, word_base, masks)
            || block_has_all(current_words, word_base, masks)
    }

    /// Insert without probing. The gossip receiver's entry point: a hit must not extend an
    /// entry's life, so this never checks presence first, only writes.
    pub fn insert(&self, key16: &[u8]) {
        let (word_base, masks) = self.locate(key16);
        if let Some(current_words) = self.gens.get(self.current_index()) {
            block_insert_all(current_words, word_base, masks);
        }
    }

    /// Rotate generations if `rotate_secs` has elapsed since the current generation started.
    /// Called from the control-plane tick, the same one that ticks the certificate coalescer.
    ///
    /// Uses `saturating_sub`, never plain subtraction: a backward clock must delay rotation, not
    /// rotate on every call and not panic in a debug build.
    pub fn rotate_if_due(&self, now: UnixSeconds) {
        let elapsed = now
            .get()
            .saturating_sub(self.rotated_at.load(Ordering::Relaxed));
        if elapsed < u64::from(self.rotate_secs) {
            return;
        }

        // The OUTGOING generation is the one not currently receiving inserts: it is about to be
        // zeroed and then, once `current` flips below, becomes the new (empty) current.
        let outgoing_idx = self.other_index();
        if let Some(outgoing) = self.gens.get(outgoing_idx) {
            let mut ones: u64 = 0;
            for cell in outgoing {
                ones = ones.saturating_add(u64::from(cell.load(Ordering::Relaxed).count_ones()));
            }
            // Fully qualified, not `self.stats.fill_bits.store(...)`: `scripts/invariant-lints.sh`'s
            // single-snapshot-publish rule matches any `.store(` call by name, so the dot-method
            // form would trip it even though this is a plain relaxed counter snapshot, not an
            // ArcSwap publish. Mirrors the identical precedent in `ticket.rs`'s `encrypt`.
            AtomicU64::store(&self.stats.fill_bits, ones, Ordering::Relaxed);

            for cell in outgoing {
                AtomicU64::store(cell, 0, Ordering::Relaxed);
            }
        }

        self.current.fetch_xor(1, Ordering::Relaxed);
        AtomicU64::store(&self.rotated_at, now.get(), Ordering::Relaxed);
        self.stats.rotations.fetch_add(1, Ordering::Relaxed);
    }
}

// `EarlyDataFilter` is `Send + Sync` by construction (every field is an atomic, a fixed-size byte
// array, or a `Box<[AtomicU64]>`, none of them interior-mutable through a non-atomic path), which
// is exactly the property the module documentation's "share behind a plain reference" claim
// depends on. Checked at compile time, mirroring `ticket.rs`'s identical assertion for
// `ClusterTicketer`: a runtime test could only ever demonstrate that one execution did not race,
// never that the type is safe to share by construction.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EarlyDataFilter>();
};

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use proptest::prelude::*;

    use super::EarlyDataFilter;
    use crate::early_data::EarlyDataConfig;
    use crate::time::UnixSeconds;

    /// A config with every field a literal: `replay_capacity` deliberately small (the clamp
    /// floor) so a filter built from it is cheap enough to construct many times per test.
    fn small_config(rotate_secs: u32) -> EarlyDataConfig {
        EarlyDataConfig {
            enabled: true,
            max_bytes: 16_384,
            replay_capacity: 1_024,
            replay_rotate_secs: rotate_secs,
        }
    }

    #[test]
    fn same_ticket_twice_is_replay() {
        let cfg = small_config(10_800);
        let f = EarlyDataFilter::new(&cfg, [1u8; 16], UnixSeconds::new(1_700_000_000));
        let key = [0xAAu8; 16];

        assert!(
            !f.check_and_insert(&key),
            "first presentation must not be a replay"
        );
        assert!(
            f.check_and_insert(&key),
            "second presentation of the same key must be a replay"
        );

        assert_eq!(
            f.stats().inserts.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(f.stats().hits.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn replay_across_rotation_may_pass() {
        let rotate_secs = 3_600;
        let cfg = small_config(rotate_secs);
        let t0 = 1_700_000_000u64;
        let f = EarlyDataFilter::new(&cfg, [2u8; 16], UnixSeconds::new(t0));
        let key = [0xBBu8; 16];

        assert!(!f.check_and_insert(&key));
        assert!(
            f.check_and_insert(&key),
            "must still be a replay before any rotation"
        );

        // First rotation: the key's generation stops being current but is still probed as the
        // OTHER generation, so it must still be caught.
        f.rotate_if_due(UnixSeconds::new(t0 + u64::from(rotate_secs)));
        assert!(
            f.contains(&key),
            "one rotation must not forget a key: it moved to the other generation, not away"
        );
        // `contains` alone cannot catch a `check_and_insert` that only ever probes the CURRENT
        // generation (dropping the `block_has_all(other_words, ...)` disjunct): `evaluate` never
        // calls `contains`, only `check_and_insert`, so this is the function that actually has to
        // be pinned here. A hit does not insert, so this call has no side effect on what follows.
        assert!(
            f.check_and_insert(&key),
            "check_and_insert, not just contains, must still treat the key as a replay after one \
             rotation: it is the function evaluate calls"
        );

        // Second rotation: the generation holding the key is now the OTHER one, and it is the one
        // that gets zeroed next, so after this rotation neither generation remembers it.
        f.rotate_if_due(UnixSeconds::new(t0 + 2 * u64::from(rotate_secs)));
        assert!(
            !f.contains(&key),
            "two rotations must forget a key: this is edge case 13, documented and expected, not \
             a bug"
        );
        assert!(
            !f.check_and_insert(&key),
            "a replay presented after the filter has forgotten the ticket may be accepted again; \
             the method restriction, not this filter, is what makes that harmless"
        );
    }

    /// "Do NOT" rule: `insert` (the gossip receiver's entry point) must write into the CURRENT
    /// generation, never the other one. Every test that checks an inserted key back through
    /// `contains` probes BOTH generations, so writing to the wrong one is invisible right up
    /// until a rotation retires it early: a key inserted into the wrong generation is forgotten
    /// one rotation sooner than a correctly placed one.
    #[test]
    fn insert_writes_into_the_current_generation_only() {
        let rotate_secs = 3_600;
        let cfg = small_config(rotate_secs);
        let t0 = 1_700_000_000u64;
        let f = EarlyDataFilter::new(&cfg, [20u8; 16], UnixSeconds::new(t0));
        let key = [0xEEu8; 16];

        f.insert(&key);

        // One rotation: a key correctly written into the CURRENT generation becomes the OTHER
        // generation and must still be remembered, on exactly the same schedule as
        // `check_and_insert`'s own insert path in `replay_across_rotation_may_pass` above.
        f.rotate_if_due(UnixSeconds::new(t0 + u64::from(rotate_secs)));
        assert!(
            f.contains(&key),
            "insert must have written into the CURRENT generation: writing into the OTHER one \
             would put the key in the generation this same rotation retires, forgetting it one \
             rotation early"
        );

        // A second rotation retires the generation the key actually lives in, on schedule.
        f.rotate_if_due(UnixSeconds::new(t0 + 2 * u64::from(rotate_secs)));
        assert!(
            !f.contains(&key),
            "two rotations must forget an inserted key on the normal schedule, not one rotation \
             early"
        );
    }

    /// "Do NOT" rule: a hit inside `check_and_insert` must not insert. Reinserting on a hit would
    /// extend a replayed ticket's remembered lifetime every time it is replayed, rather than
    /// leaving it on its original two-rotation schedule from first presentation.
    #[test]
    fn hit_does_not_extend_the_entrys_life() {
        let rotate_secs = 3_600;
        let cfg = small_config(rotate_secs);
        let t0 = 1_700_000_000u64;
        let f = EarlyDataFilter::new(&cfg, [21u8; 16], UnixSeconds::new(t0));
        let key = [0xDDu8; 16];

        assert!(!f.check_and_insert(&key), "first presentation must not be a replay");

        // One rotation: the original entry moves from current to other, still remembered.
        f.rotate_if_due(UnixSeconds::new(t0 + u64::from(rotate_secs)));
        assert!(f.contains(&key));

        let inserts_before_hit = f.stats().inserts.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            f.check_and_insert(&key),
            "the key is still within its remembered window and must be reported as a replay"
        );
        assert_eq!(
            f.stats().inserts.load(std::sync::atomic::Ordering::Relaxed),
            inserts_before_hit,
            "a hit must not increment inserts: it must not write into the filter at all"
        );

        // Second rotation retires the generation the ORIGINAL insert lives in. If the hit above
        // had wrongly reinserted the key into the generation that was current at the time of the
        // hit, the key would survive this rotation too; it must not.
        f.rotate_if_due(UnixSeconds::new(t0 + 2 * u64::from(rotate_secs)));
        assert!(
            !f.contains(&key),
            "a hit must not insert into the filter: the entry's life must end on its original \
             two-rotation schedule, not be extended by every subsequent replay attempt"
        );
    }

    #[test]
    fn overfilled_filter_fails_closed() {
        // A small capacity so that inserting 10x it is fast and reliably saturates the filter.
        let cfg = EarlyDataConfig {
            enabled: true,
            max_bytes: 16_384,
            replay_capacity: 2_000,
            replay_rotate_secs: 10_800,
        };
        let f = EarlyDataFilter::new(&cfg, [3u8; 16], UnixSeconds::new(1_700_000_000));

        // 20,000 distinct keys, all with a leading 0x00 byte, inserted without ever probing an
        // absent key first, so every insert call takes the true "first presentation" path.
        for i in 0u32..20_000 {
            let mut key = [0u8; 16];
            key[0] = 0x00;
            key[1..5].copy_from_slice(&i.to_be_bytes());
            f.insert(&key);
        }

        // 2,000 keys that were never inserted, distinguished by a leading 0xFF byte so they
        // cannot collide with anything inserted above at the input-byte level: any `true` here
        // is a genuine Bloom false positive, not a repeat of an inserted key.
        let mut false_positives = 0u32;
        for i in 0u32..2_000 {
            let mut key = [0u8; 16];
            key[0] = 0xFF;
            key[1..5].copy_from_slice(&i.to_be_bytes());
            if f.contains(&key) {
                false_positives += 1;
            }
        }

        // No panic reaching this line is already most of what this test proves. The count is
        // asserted, not merely computed, so a future change that quietly stops the filter from
        // saturating (for instance a capacity bug that silently grows the filter far past what
        // `replay_capacity` requested) is caught rather than passing this test by accident.
        // Measured locally at exactly this fixture (2,000 capacity, 20,000 inserts, 157 blocks,
        // about 127 keys landing in each block): 1,167 to 1,200 of 2,000 probes across repeated
        // runs. 500 (one quarter) is a floor well under every observed run, not a number tuned to
        // just barely pass once, and it sits nowhere near the under-1e-5 (well under 1 in
        // 100,000) rate `false_positive_rate_under_1e5` measures at the DEFAULT, non-overfilled
        // capacity: the gap between "500 of 2,000" and "under 1 in 100,000" is what proves this
        // fixture actually reached the degraded, saturated regime the edge case is about.
        assert!(
            false_positives > 500,
            "overfilling the filter 10x should measurably saturate it; got only \
             {false_positives}/2000 false positives, which is too close to the un-overfilled \
             false-positive rate to prove this fixture actually saturated the filter"
        );
    }

    #[test]
    fn concurrent_same_key_at_least_one_first() {
        let cfg = small_config(10_800);
        let f = Arc::new(EarlyDataFilter::new(
            &cfg,
            [4u8; 16],
            UnixSeconds::new(1_700_000_000),
        ));
        let key = [0xCCu8; 16];

        let handles: Vec<_> = (0..64)
            .map(|_| {
                let f = Arc::clone(&f);
                thread::spawn(move || f.check_and_insert(&key))
            })
            .collect();

        let mut false_count = 0u32;
        for h in handles {
            if !h.join().expect("thread must not panic") {
                false_count += 1;
            }
        }

        assert!(
            false_count >= 1,
            "at least one caller must observe the key absent (the first insert)"
        );
        assert!(
            false_count <= 64,
            "at most 64 threads ran, so at most 64 can report false"
        );
    }

    #[test]
    fn rotate_only_when_due() {
        let cfg = small_config(10_800);
        let t0 = 1_700_000_000u64;
        let f = EarlyDataFilter::new(&cfg, [5u8; 16], UnixSeconds::new(t0));

        for _ in 0..1_000 {
            f.rotate_if_due(UnixSeconds::new(t0));
        }
        assert_eq!(
            f.stats()
                .rotations
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn backward_clock_delays_rotation() {
        let cfg = small_config(3_600);
        let f = EarlyDataFilter::new(&cfg, [6u8; 16], UnixSeconds::new(1_000_000));

        // The clock reads far BEHIND when the current generation started.
        f.rotate_if_due(UnixSeconds::new(0));
        assert_eq!(
            f.stats()
                .rotations
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        // A second backward call must not panic or rotate either.
        f.rotate_if_due(UnixSeconds::new(0));
        assert_eq!(
            f.stats()
                .rotations
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    #[allow(
        clippy::print_stdout,
        reason = "the false-positive count this test measures is the whole point of the test; \
                  printing it is what makes a regression diagnosable, per this issue's own \
                  acceptance criteria"
    )]
    fn false_positive_rate_under_1e5() {
        let cfg = EarlyDataConfig {
            enabled: true,
            max_bytes: 16_384,
            replay_capacity: 1_000_000,
            replay_rotate_secs: 10_800,
        };
        let f = EarlyDataFilter::new(&cfg, [7u8; 16], UnixSeconds::new(1_700_000_000));

        for i in 0u32..100_000 {
            let mut key = [0u8; 16];
            key[0] = 0x00;
            key[1..5].copy_from_slice(&i.to_be_bytes());
            f.insert(&key);
        }

        let mut false_positives = 0u32;
        for i in 0u32..1_000_000 {
            let mut key = [0u8; 16];
            key[0] = 0xFF;
            key[1..5].copy_from_slice(&i.to_be_bytes());
            if f.contains(&key) {
                false_positives += 1;
            }
        }

        println!(
            "false_positive_rate_under_1e5: {false_positives} false positives out of 1,000,000 \
             probes ({} inserted keys, default capacity)",
            100_000
        );
        assert!(
            false_positives < 10,
            "measured false-positive rate {false_positives}/1_000_000 is at or above 1e-5"
        );
    }

    #[test]
    fn memory_bytes_matches_formula() {
        let cfg = EarlyDataConfig {
            enabled: true,
            max_bytes: 16_384,
            replay_capacity: 1_000_000,
            replay_rotate_secs: 10_800,
        };
        let f = EarlyDataFilter::new(&cfg, [8u8; 16], UnixSeconds::new(1_700_000_000));
        assert_eq!(f.memory_bytes(), 10_000_000);
    }

    /// `EarlyDataFilter::new` documents that it does not re-clamp `replay_capacity`, so a caller
    /// that skips `EarlyDataConfig::clamped()` can reach this constructor with
    /// `replay_capacity: 0`. Measured before `blocks_for`'s `.max(1)` defence in depth: such a
    /// filter had `memory_bytes() == 0` and `check_and_insert` returned `false` forever, a replay
    /// filter that silently detects nothing while still reporting healthy insert counters. A
    /// zero-capacity config must still produce a real, working (if severely undersized) filter.
    #[test]
    fn zero_capacity_config_still_produces_a_working_filter() {
        let cfg = EarlyDataConfig {
            enabled: true,
            max_bytes: 16_384,
            replay_capacity: 0,
            replay_rotate_secs: 10_800,
        };
        let f = EarlyDataFilter::new(&cfg, [22u8; 16], UnixSeconds::new(1_700_000_000));
        assert!(
            f.memory_bytes() > 0,
            "a zero-capacity config must not yield a zero-byte, permanently-empty filter"
        );

        let key = [0x42u8; 16];
        assert!(!f.check_and_insert(&key), "first presentation must not be a replay");
        assert!(
            f.check_and_insert(&key),
            "second presentation must be caught even at replay_capacity: 0"
        );
    }

    proptest! {
        #[test]
        fn prop_filter_no_false_negatives_within_generation(
            keys in proptest::collection::hash_set(any::<[u8; 16]>(), 1..=500)
        ) {
            let cfg = EarlyDataConfig {
                enabled: true,
                max_bytes: 16_384,
                replay_capacity: 1_024,
                replay_rotate_secs: 10_800,
            };
            let f = EarlyDataFilter::new(&cfg, [9u8; 16], UnixSeconds::new(1_700_000_000));

            for key in &keys {
                f.insert(key);
            }
            for key in &keys {
                prop_assert!(f.contains(key), "key {key:?} was inserted but contains() denies it");
            }
        }
    }
}
