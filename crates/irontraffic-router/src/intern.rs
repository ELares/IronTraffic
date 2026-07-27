// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`CompiledNameSet`], the interned header-name and query-parameter-name set,
//! and [`NameSetBuilder`], which constructs one from the names a built route
//! table references.
//!
//! The naive router design looks a header name up in the request's header map
//! once per predicate per candidate: at 100 candidates with 2 header
//! predicates each, that is 200 header-map lookups, each a hash plus a bucket
//! probe or a linear scan with `eq_ignore_ascii_case`. This module inverts
//! that. At build time every name any route references is interned into a
//! dense [`NameId`]. During header parsing, which already touches every
//! header name exactly once, [`CompiledNameSet::lookup`] resolves a name to
//! its id (or determines it names nothing a route cares about) in a handful
//! of loads, and predicate evaluation becomes two loads and a `memcmp`.
//!
//! The structure is Envoy's `CompiledStringMap` idea (`source/common/common/
//! compiled_string_map.md`): bucket by string length, then within a length
//! bucket branch on the single character index that produces the MOST
//! distinct branches (not the first differing index, which is useless for
//! header names that all begin with `x-`), then a leaf holding the full
//! string for final validation. This adds one thing Envoy does not have: a
//! three-load prefilter (`len_bits`, then a first-byte bitmap, then a
//! last-byte bitmap) that rejects the overwhelming majority of request
//! headers, which no route references, before touching any bucket at all.
//!
//! Header names are matched case-insensitively, which is free: HTTP/2 and
//! HTTP/3 field names are lowercase by protocol, and the HTTP/1 parser
//! lowercases a name before validating it. `lookup` therefore requires an
//! already-lowercase input and does not fold case itself; folding here would
//! double the cost of the comparison for a property the caller already
//! guarantees. Query parameter names are matched case-sensitively, per
//! Gateway API. The same structure serves both, but the router holds two
//! independent [`CompiledNameSet`] instances and never mixes their [`NameId`]
//! spaces.
//!
//! [`MAX_NAMES_PER_LENGTH`] is the bound that makes `lookup` worst case a
//! constant rather than a function of the route table. Without it, a tenant
//! could configure [`MAX_NAMES`] names of one length that agree at every byte
//! position but a few, so the chosen discriminating index would split them
//! into sub-buckets of about half the set, and every request header of that
//! length, first byte and last byte would then cost that many full
//! comparisons. With the cap, the worst case is [`MAX_NAMES_PER_LENGTH`]
//! comparisons of at most [`MAX_FAST_NAME_LEN`] bytes per header lookup (or
//! [`MAX_NAMES_PER_LENGTH`] comparisons of at most `MAX_NAME_BYTES` bytes on
//! the long path), and the sorted, early-exiting bucket scan usually makes it
//! one or two. The HTTP layer caps a request at 100 header fields, so the
//! ceiling on interning work for one request is 100 lookups times that bound,
//! about 400 KiB of byte comparison in the deliberately hostile configuration
//! (100 headers, each forced down the worst-case 64-entry, 63-byte bucket
//! scan) and a handful of loads in every real one. That arithmetic is the
//! whole justification for [`MAX_NAMES_PER_LENGTH`].
//!
//! This module is INERT: it defines the structure, the builder and their
//! tests, and adds the two `CompiledNameSet` fields to `RouteTable`.
//! `match-scratch-per-worker` (#58) calls `lookup`; `builder-admission-and-
//! assemble` (#56) calls the builder.

use std::collections::BTreeMap;

use crate::ids::NameId;
use crate::limits::MAX_NAME_BYTES;

/// True when `b` is an RFC 9110 `tchar`: `A`-`Z`, `a`-`z`, `0`-`9`, or one of
/// the fifteen bytes ``! # $ % & ' * + - . ^ _ ` | ~``. Every other byte,
/// including `:`, space, `"`, and every byte below `0x21` or at or above
/// `0x7f`, is outside it.
///
/// This is the one definition of `tchar` this crate uses; `router-crate-and-
/// core-types` (#48) documents the same byte set for
/// `AdmissionErrorKind::NameInvalid`, and both must agree with this function
/// rather than with an independently written-out copy of the set.
#[must_use]
pub const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || b.is_ascii_alphanumeric()
}

/// `disc_at` value meaning "this bucket has at most one entry, skip straight
/// to the full comparison".
const NO_DISC: u8 = u8::MAX;

/// Longest name the fast path handles. Longer names go to the `long` list.
pub const MAX_FAST_NAME_LEN: usize = 63;

/// Number of length buckets the fast path indexes: lengths `0..=MAX_FAST_NAME_LEN`.
const LEN_BUCKETS: usize = MAX_FAST_NAME_LEN + 1;

/// Maximum distinct names in one set. [`NameId`] is a `u16` and `NameId::NONE`
/// is `u16::MAX`, so the last usable id is 65534. This is far below that
/// ceiling because the per-worker slot array `match-scratch-per-worker` (#58)
/// builds is sized by it: 4096 slots at 12 bytes is 48 KiB per worker, and no
/// sane route table references four thousand distinct header names.
pub const MAX_NAMES: usize = 4096;

/// Maximum distinct names sharing one length, and separately the maximum
/// number of names in the `long` list. See the module documentation for the
/// per-request arithmetic this bound makes possible; it is a refusal
/// (`NameSetError::TooManyOfLength`), never a silent truncation, because a
/// name that failed to intern would make every predicate referencing it fail,
/// which changes routing rather than degrading it.
pub const MAX_NAMES_PER_LENGTH: usize = 64;

/// One interned name: an `(offset, length)` pair into
/// [`CompiledNameSet::blob`], plus its assigned id.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct NameEntry {
    /// Offset into `CompiledNameSet::blob`.
    off: u32,
    /// Length in bytes.
    len: u16,
    /// The assigned id.
    id: NameId,
}

/// An immutable, perfect-hash-free map from a byte string to a dense
/// [`NameId`].
///
/// Built from the set of names any route references, by [`NameSetBuilder`].
/// [`CompiledNameSet::lookup`] is a three-load prefilter, then one indexed
/// load to find the discriminating character position for that length, then
/// a small linear scan over the entries sharing that `(length, discriminating
/// character)` pair, then one final full comparison. See the module
/// documentation for why this beats a hashed map or a perfect hash for this
/// key distribution.
#[derive(Debug)]
pub struct CompiledNameSet {
    /// Bit `i` is set when some name has length `i`. Names longer than
    /// [`MAX_FAST_NAME_LEN`] are held in `long` and always take the slow path.
    len_bits: u64,
    /// Per length `0..=MAX_FAST_NAME_LEN`: the byte index the length bucket
    /// discriminates on, or [`NO_DISC`] when the bucket holds 0 or 1 entries.
    disc_at: Box<[u8]>,
    /// Per length `0..=MAX_FAST_NAME_LEN`: `(start, len)` into `entries` of
    /// that length's bucket.
    buckets: Box<[(u32, u32)]>,
    /// All fast-path entries, grouped by length, and within a length sorted
    /// ascending by `(discriminating byte, full name bytes)` so the build is
    /// deterministic.
    entries: Box<[NameEntry]>,
    /// Names longer than [`MAX_FAST_NAME_LEN`], sorted by `(len, bytes)`.
    /// Linear scan.
    long: Box<[NameEntry]>,
    /// Concatenated name bytes.
    blob: Box<[u8]>,
    /// Per length `0..=MAX_FAST_NAME_LEN`: bitmap over the 256 possible first
    /// bytes, as four `u64`s.
    first_filter: Box<[[u64; 4]]>,
    /// Per length `0..=MAX_FAST_NAME_LEN`: bitmap over the 256 possible last
    /// bytes.
    last_filter: Box<[[u64; 4]]>,
    /// Number of distinct names, which is the number of valid [`NameId`]s.
    count: u16,
    /// FNV-1a 128 over the canonical encoding of the inserted set. See
    /// [`fnv1a128_of_set`].
    content_hash: u128,
}

// I17-style invariant: CompiledNameSet is Send + Sync because every field is,
// and it has no interior mutability, so it can be shared behind the RouteTable
// it is embedded in without extra synchronization.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CompiledNameSet>();
};

impl Default for CompiledNameSet {
    /// Equivalent to [`CompiledNameSet::empty`]. Written by hand rather than
    /// derived: a derived, field-wise `Default` would leave `disc_at`,
    /// `buckets`, `first_filter` and `last_filter` as zero-length boxed
    /// slices, and every later issue that reads this type is entitled to
    /// assume those four arrays always span the full `0..=MAX_FAST_NAME_LEN`
    /// range, exactly as a set built through [`NameSetBuilder`] always does.
    fn default() -> CompiledNameSet {
        CompiledNameSet::empty()
    }
}

impl CompiledNameSet {
    /// An empty set. `lookup` always returns `None` and `count()` is 0.
    #[must_use]
    pub fn empty() -> CompiledNameSet {
        NameSetBuilder::new().finish()
    }

    /// Looks up an interned name.
    ///
    /// `name` MUST already be ASCII lowercase for a header-name set: HTTP/2
    /// and HTTP/3 field names are lowercase by protocol, and the HTTP/1
    /// parser lowercases a name before validating it, so folding case here
    /// would be redundant work on the hot path for a property the caller
    /// already guarantees. A name that violates this contract simply misses,
    /// which is fail-closed: the caller's predicate does not match, rather
    /// than matching the wrong header.
    ///
    /// This is deliberately not a runtime `debug_assert!` on that contract:
    /// this workspace's default dev and test profiles build with debug
    /// assertions enabled, so a `debug_assert!` here would panic on exactly
    /// the input `tests::uppercase_lookup_misses` (named by this issue's own
    /// test list) passes to pin the fail-closed behaviour, making that named
    /// test unrunnable under a plain `cargo test`. The contract is therefore
    /// enforced in this doc comment and by the fail-closed miss below in
    /// every build configuration, not by a runtime assertion that only one of
    /// them could observe. See the filed defect, issue #529, for the full
    /// argument.
    ///
    /// Allocation-free. Three loads to reject an unreferenced name.
    #[must_use]
    pub fn lookup(&self, name: &[u8]) -> Option<NameId> {
        let n = name.len();
        if n > MAX_FAST_NAME_LEN {
            return self.lookup_long(name);
        }
        if !len_is_referenced(self.len_bits, n) {
            return None;
        }
        let &first = name.first()?;
        let &last = name.last()?;
        if !bit_test(*self.first_filter.get(n)?, first) {
            return None;
        }
        if !bit_test(*self.last_filter.get(n)?, last) {
            return None;
        }
        let &(start, count) = self.buckets.get(n)?;
        let d = *self.disc_at.get(n)?;
        let start = start as usize;
        let end = start.checked_add(count as usize)?;
        let bucket = self.entries.get(start..end)?;

        if d == NO_DISC {
            let entry = bucket.first()?;
            return if self.entry_bytes(*entry)? == name {
                Some(entry.id)
            } else {
                None
            };
        }

        let key = *name.get(usize::from(d))?;
        for entry in bucket {
            let Some(entry_bytes) = self.entry_bytes(*entry) else {
                continue;
            };
            let Some(&disc_byte) = entry_bytes.get(usize::from(d)) else {
                continue;
            };
            // Entries are sorted ascending by discriminating byte, so once
            // one is strictly past `key` no later entry in the bucket can
            // equal it either.
            if disc_byte > key {
                break;
            }
            if disc_byte == key {
                record_compare_for_test();
                if entry_bytes == name {
                    return Some(entry.id);
                }
            }
        }
        None
    }

    /// Number of distinct interned names, which is the length the per-worker
    /// slot array must have.
    #[must_use]
    pub fn count(&self) -> usize {
        usize::from(self.count)
    }

    /// The bytes of an interned name, for the explain surface and for
    /// diagnostics. Never called on the request path.
    #[must_use]
    pub fn name_of(&self, id: NameId) -> Option<&[u8]> {
        self.entries
            .iter()
            .chain(self.long.iter())
            .find(|entry| entry.id == id)
            .and_then(|entry| self.entry_bytes(*entry))
    }

    /// Content hash of everything this set was built from. Used by
    /// `incremental-group-rebuild` (#65) to decide in one comparison whether
    /// interned ids are still valid, which is why it is 128 bits: a collision
    /// there means a reused group's predicates would read a different header
    /// than the one they name, which is an authorization bypass.
    #[must_use]
    pub fn content_hash(&self) -> u128 {
        self.content_hash
    }

    /// `entry`'s bytes in `blob`, or `None` if its `(off, len)` extent left
    /// the blob (only reachable from a corrupted structure; this type is only
    /// ever built by `NameSetBuilder::finish`, which never produces one).
    fn entry_bytes(&self, entry: NameEntry) -> Option<&[u8]> {
        let start = entry.off as usize;
        let end = start.checked_add(usize::from(entry.len))?;
        self.blob.get(start..end)
    }

    /// The slow path for a name longer than [`MAX_FAST_NAME_LEN`]: a linear
    /// scan of `long`, which [`NameSetBuilder::finish`] sorts by `(len,
    /// bytes)` ascending, so the scan can stop as soon as an entry's length
    /// exceeds `name`'s.
    fn lookup_long(&self, name: &[u8]) -> Option<NameId> {
        for entry in &*self.long {
            let entry_len = usize::from(entry.len);
            if entry_len > name.len() {
                break;
            }
            if entry_len != name.len() {
                continue;
            }
            let Some(entry_bytes) = self.entry_bytes(*entry) else {
                continue;
            };
            if entry_bytes == name {
                return Some(entry.id);
            }
        }
        None
    }
}

/// True when some interned name has length `n`: bit `n` of `len_bits`.
/// Pulled out of `lookup` into its own function, rather than inlined, so it
/// has a directly testable unit apart from `lookup`'s end-to-end behaviour:
/// every other input this length's bucket, entries and filter arrays would
/// produce for an unreferenced length is ALSO correctly empty, so a mutation
/// of this one check alone cannot be observed through `lookup`'s return value
/// on any input, only through a direct test of this function.
fn len_is_referenced(len_bits: u64, n: usize) -> bool {
    len_bits & (1u64 << n) != 0
}

/// Tests whether bit `b` is set in a 256-bit filter packed as four `u64`s.
fn bit_test(bits: [u64; 4], b: u8) -> bool {
    let word = usize::from(b >> 6);
    bits.get(word).is_some_and(|w| w & (1u64 << (b & 63)) != 0)
}

/// Sets bit `b` in a 256-bit filter packed as four `u64`s.
fn set_bit(bits: &mut [u64; 4], b: u8) {
    let word = usize::from(b >> 6);
    if let Some(slot) = bits.get_mut(word) {
        *slot |= 1u64 << (b & 63);
    }
}

/// Calls `record_compare_for_test` only under `#[cfg(test)]`; a plain
/// function call so that release builds pay nothing and so that no bare
/// `#[cfg(test)]` statement sits in `lookup`'s body (an attribute directly on
/// a statement with no immediately following `{` can confuse
/// `scripts/invariant-lints.sh`'s `#[cfg(test)]`-blanking scan into blanking
/// past this function into unrelated code; attaching it only to this
/// function's own block, which starts right after it, cannot).
fn record_compare_for_test() {
    #[cfg(test)]
    {
        COMPARE_COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only count of full-name comparisons `lookup` performed, used by
    /// `tests::worst_case_bucket_scan_is_bounded` to prove the bucket scan
    /// really is bounded by `MAX_NAMES_PER_LENGTH`, not merely sized that way.
    static COMPARE_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_compare_count_for_test() {
    COMPARE_COUNT.with(|c| c.set(0));
}

#[cfg(test)]
fn compare_count_for_test() -> u32 {
    COMPARE_COUNT.with(std::cell::Cell::get)
}

/// FNV-1a 128 offset basis.
const FNV1A128_OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
/// FNV-1a 128 prime.
const FNV1A128_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

/// Folds every byte of `bytes` into `h` with FNV-1a: XOR the byte in, then
/// `wrapping_mul` by [`FNV1A128_PRIME`].
fn fnv1a128_step(mut h: u128, bytes: &[u8]) -> u128 {
    for &b in bytes {
        h ^= u128::from(b);
        h = h.wrapping_mul(FNV1A128_PRIME);
    }
    h
}

/// The content hash of an inserted-name map: FNV-1a 128 over, for every
/// `(name, id)` pair in ascending name order, the name's length as a
/// little-endian `u32`, the name's bytes, then the id as a little-endian
/// `u16`. Iterating a `BTreeMap` is already ascending-key order, so this
/// needs no separate sort.
///
/// `builder-admission-and-assemble` (#56) delivers this same function as
/// `fnv1a128`; this issue lands first and defines it here with the constants
/// written out, and #56 does not change it.
fn fnv1a128_of_set(names: &BTreeMap<Vec<u8>, NameId>) -> u128 {
    let mut h = FNV1A128_OFFSET;
    for (name, id) in names {
        let len_bytes = u32::try_from(name.len()).unwrap_or(u32::MAX).to_le_bytes();
        h = fnv1a128_step(h, &len_bytes);
        h = fnv1a128_step(h, name);
        h = fnv1a128_step(h, &id.0.to_le_bytes());
    }
    h
}

/// One length bucket during `finish`: every inserted name of one exact
/// length, in ascending name-byte order, paired with its assigned id.
type LenBucket = Vec<(Vec<u8>, NameId)>;

/// The byte a bucket entry sorts by: its own byte at the bucket's
/// discriminating index `d`, or 0 when `d` is [`NO_DISC`] (0 or 1 entries, so
/// the key never has to distinguish anything).
fn disc_sort_key(name: &[u8], d: u8) -> u8 {
    if d == NO_DISC {
        0
    } else {
        name.get(usize::from(d)).copied().unwrap_or(0)
    }
}

/// Counts the number of distinct byte values at index `i` across every entry
/// in `bucket`. Every entry in a length bucket shares one length, so `i` is
/// always in range for all of them or none of them.
fn count_distinct_at(bucket: &LenBucket, i: usize) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for (name, _) in bucket {
        let Some(&b) = name.get(i) else { continue };
        let slot = usize::from(b);
        if let Some(s) = seen.get_mut(slot)
            && !*s
        {
            *s = true;
            count += 1;
        }
    }
    count
}

/// Chooses the discriminating byte index for one length bucket: the index `i`
/// with the highest number of distinct byte values across the bucket, ties
/// broken by the lowest index. [`NO_DISC`] for a bucket of 0 or 1 entries, or
/// in the unreachable case (ruled out by the builder's own no-duplicate-key
/// invariant) that every entry agrees at every position.
fn choose_disc(bucket: &LenBucket) -> u8 {
    if bucket.len() < 2 {
        return NO_DISC;
    }
    let len = bucket.first().map_or(0, |(name, _)| name.len());
    let mut best_count = 0usize;
    let mut best_idx = 0usize;
    for i in 0..len {
        let c = count_distinct_at(bucket, i);
        if c > best_count {
            best_count = c;
            best_idx = i;
        }
    }
    if best_count < 2 {
        return NO_DISC;
    }
    u8::try_from(best_idx).unwrap_or(NO_DISC)
}

/// Appends `name`'s bytes to `blob` and pushes the resulting entry onto
/// `entries`, so an offset is never computed in one place and consumed in
/// another.
fn push_entry(entries: &mut Vec<NameEntry>, blob: &mut Vec<u8>, name: &[u8], id: NameId) {
    let off = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    blob.extend_from_slice(name);
    let len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    entries.push(NameEntry { off, len, id });
}

/// The four fast-path arrays `finish` assembles: everything a length
/// `0..=MAX_FAST_NAME_LEN` lookup indexes.
struct FastArrays {
    len_bits: u64,
    disc_at: Box<[u8]>,
    buckets: Box<[(u32, u32)]>,
    entries: Box<[NameEntry]>,
    first_filter: Box<[[u64; 4]]>,
    last_filter: Box<[[u64; 4]]>,
}

/// Builds the fast-path arrays from `by_len` (index `n` holds every name of
/// length `n`, in ascending name-byte order) and appends every fast-path
/// name's bytes to `blob`.
fn build_fast_arrays(mut by_len: Vec<LenBucket>, blob: &mut Vec<u8>) -> FastArrays {
    let mut len_bits: u64 = 0;
    let mut disc_at = vec![NO_DISC; LEN_BUCKETS];
    let mut buckets = vec![(0u32, 0u32); LEN_BUCKETS];
    let mut first_filter = vec![[0u64; 4]; LEN_BUCKETS];
    let mut last_filter = vec![[0u64; 4]; LEN_BUCKETS];
    let mut entries: Vec<NameEntry> = Vec::new();

    for len in 0..LEN_BUCKETS {
        let Some(bucket) = by_len.get_mut(len) else {
            continue;
        };
        if bucket.is_empty() {
            continue;
        }

        let d = choose_disc(bucket);
        if let Some(slot) = disc_at.get_mut(len) {
            *slot = d;
        }
        bucket.sort_unstable_by(|a, b| {
            disc_sort_key(&a.0, d)
                .cmp(&disc_sort_key(&b.0, d))
                .then_with(|| a.0.cmp(&b.0))
        });

        let start = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        let bucket_len = u32::try_from(bucket.len()).unwrap_or(u32::MAX);
        if let Some(slot) = buckets.get_mut(len) {
            *slot = (start, bucket_len);
        }
        len_bits |= 1u64 << len;

        let mut first_bits = [0u64; 4];
        let mut last_bits = [0u64; 4];
        for (name, id) in bucket.iter() {
            push_entry(&mut entries, blob, name, *id);
            if let (Some(&first), Some(&last)) = (name.first(), name.last()) {
                set_bit(&mut first_bits, first);
                set_bit(&mut last_bits, last);
            }
        }
        if let Some(slot) = first_filter.get_mut(len) {
            *slot = first_bits;
        }
        if let Some(slot) = last_filter.get_mut(len) {
            *slot = last_bits;
        }
    }

    FastArrays {
        len_bits,
        disc_at: disc_at.into_boxed_slice(),
        buckets: buckets.into_boxed_slice(),
        entries: entries.into_boxed_slice(),
        first_filter: first_filter.into_boxed_slice(),
        last_filter: last_filter.into_boxed_slice(),
    }
}

/// Builds a [`CompiledNameSet`].
#[derive(Debug)]
pub struct NameSetBuilder {
    /// Every inserted name, keyed by its bytes, in insertion order of value
    /// (the map's own iteration order is by key, ascending).
    names: BTreeMap<Vec<u8>, NameId>,
    /// The id the next genuinely new name will be assigned. Always equal to
    /// `names.len()`: it only advances on an actual insertion, never on an
    /// idempotent hit.
    next: u16,
    /// Per length `0..=MAX_FAST_NAME_LEN`: how many distinct names of that
    /// length have been inserted so far.
    len_counts: [u16; LEN_BUCKETS],
    /// How many distinct names longer than `MAX_FAST_NAME_LEN` have been
    /// inserted so far.
    long_count: u16,
}

impl Default for NameSetBuilder {
    /// Written by hand because `[u16; LEN_BUCKETS]` (64 elements) has no
    /// standard-library `Default` impl to derive from; `[0u16; LEN_BUCKETS]`
    /// is an ordinary array-repeat expression and needs none.
    fn default() -> NameSetBuilder {
        NameSetBuilder {
            names: BTreeMap::new(),
            next: 0,
            len_counts: [0u16; LEN_BUCKETS],
            long_count: 0,
        }
    }
}

impl NameSetBuilder {
    /// A new, empty builder.
    #[must_use]
    pub fn new() -> NameSetBuilder {
        NameSetBuilder::default()
    }

    /// Interns `name`, returning its id. Idempotent: inserting the same bytes
    /// twice returns the same id, which is what lets two routes referencing
    /// `x-tenant` end up with one shared id.
    ///
    /// # Errors
    /// `Empty` for an empty name, `InvalidByte` for a byte outside RFC 9110
    /// `tchar`, `NameTooLong` past `MAX_NAME_BYTES`, `TooMany` past
    /// [`MAX_NAMES`], and `TooManyOfLength` past [`MAX_NAMES_PER_LENGTH`]
    /// names of one length (or, for a name longer than
    /// [`MAX_FAST_NAME_LEN`], past that many names in the `long` list).
    pub fn insert(&mut self, name: &[u8]) -> Result<NameId, NameSetError> {
        if name.is_empty() {
            return Err(NameSetError::Empty);
        }
        for &b in name {
            if !is_tchar(b) {
                return Err(NameSetError::InvalidByte);
            }
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(NameSetError::NameTooLong);
        }
        if let Some(&id) = self.names.get(name) {
            return Ok(id);
        }
        if self.names.len() >= MAX_NAMES {
            return Err(NameSetError::TooMany);
        }

        let bucket_count = if name.len() <= MAX_FAST_NAME_LEN {
            self.len_counts.get(name.len()).copied().unwrap_or(u16::MAX)
        } else {
            self.long_count
        };
        if usize::from(bucket_count) >= MAX_NAMES_PER_LENGTH {
            return Err(NameSetError::TooManyOfLength);
        }

        let id = NameId(self.next);
        self.names.insert(name.to_vec(), id);
        self.next = self.next.saturating_add(1);
        if name.len() <= MAX_FAST_NAME_LEN {
            if let Some(slot) = self.len_counts.get_mut(name.len()) {
                *slot = slot.saturating_add(1);
            }
        } else {
            self.long_count = self.long_count.saturating_add(1);
        }
        Ok(id)
    }

    /// Number of distinct names inserted so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// True when nothing has been inserted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Compiles the set. Deterministic: the same inserted set, inserted in
    /// the same order, always produces byte-identical output, because every
    /// step from here on either reads the `BTreeMap` in its own sorted key
    /// order or sorts explicitly (never relying on hashing or on a
    /// nondeterministic iteration order).
    #[must_use]
    pub fn finish(self) -> CompiledNameSet {
        let content_hash = fnv1a128_of_set(&self.names);
        let count = u16::try_from(self.names.len()).unwrap_or(u16::MAX);

        let mut by_len: Vec<LenBucket> = (0..LEN_BUCKETS).map(|_| Vec::new()).collect();
        let mut long: LenBucket = Vec::new();
        for (name, id) in self.names {
            if name.len() < LEN_BUCKETS {
                if let Some(bucket) = by_len.get_mut(name.len()) {
                    bucket.push((name, id));
                }
            } else {
                long.push((name, id));
            }
        }
        long.sort_unstable_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));

        let mut blob: Vec<u8> = Vec::new();
        let fast = build_fast_arrays(by_len, &mut blob);

        let mut long_entries: Vec<NameEntry> = Vec::with_capacity(long.len());
        for (name, id) in &long {
            push_entry(&mut long_entries, &mut blob, name, *id);
        }

        CompiledNameSet {
            len_bits: fast.len_bits,
            disc_at: fast.disc_at,
            buckets: fast.buckets,
            entries: fast.entries,
            long: long_entries.into_boxed_slice(),
            blob: blob.into_boxed_slice(),
            first_filter: fast.first_filter,
            last_filter: fast.last_filter,
            count,
            content_hash,
        }
    }
}

/// Why a name could not be interned.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum NameSetError {
    /// The name was empty.
    Empty,
    /// The name contained a byte outside RFC 9110 `tchar`.
    InvalidByte,
    /// The name was longer than `MAX_NAME_BYTES`.
    NameTooLong,
    /// More than [`MAX_NAMES`] distinct names.
    TooMany,
    /// More than [`MAX_NAMES_PER_LENGTH`] distinct names of one length, or in
    /// the long list. This is the per-lookup worst-case bound, so it is a
    /// refusal and never a truncation.
    TooManyOfLength,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::{
        CompiledNameSet, MAX_FAST_NAME_LEN, MAX_NAME_BYTES, MAX_NAMES, MAX_NAMES_PER_LENGTH,
        NO_DISC, NameSetBuilder, NameSetError, compare_count_for_test,
        reset_compare_count_for_test,
    };

    /// 77 distinct RFC 9110 `tchar` bytes: more than `MAX_NAMES_PER_LENGTH`
    /// (64), so the stress tests below can generate that many distinct names
    /// of one exact length by varying only the last byte.
    fn tchar_pool() -> Vec<u8> {
        let mut pool: Vec<u8> = (b'0'..=b'9')
            .chain(b'a'..=b'z')
            .chain(b'A'..=b'Z')
            .collect();
        pool.extend_from_slice(b"!#$%&'*+-.^_`|~");
        pool
    }

    /// A distinct tchar name of exactly `len` bytes: `len - 1` filler `'x'`
    /// bytes followed by one byte from `tchar_pool()` chosen by `variant`.
    /// Distinct `variant` values (0..77) at a fixed `len` produce distinct
    /// names; distinct `len` values produce distinct names regardless of
    /// `variant`.
    fn name_of_len(len: usize, variant: usize) -> Vec<u8> {
        let pool = tchar_pool();
        let mut name = vec![b'x'; len.saturating_sub(1)];
        let idx = variant % pool.len();
        if let Some(&b) = pool.get(idx) {
            name.push(b);
        }
        name
    }

    fn any_name_pattern() -> &'static str {
        "[a-z][a-z0-9-]{0,20}"
    }

    /// Like `any_name_pattern`, but roughly half its draws are 63 to 91 bytes
    /// long: one byte short of `MAX_FAST_NAME_LEN`, exactly at it, and past it
    /// into the `long` list. `any_name_pattern` alone never exceeds 21 bytes,
    /// so a generator built only from it can never populate `ordered` with a
    /// name that takes `CompiledNameSet::lookup_long`'s path at all, which is
    /// exactly how issue #579 found `exhaustive_membership` silent on that
    /// path: it cannot pick, as its base name, something the mutated code
    /// under test never even routes to the code being mutated.
    fn membership_name_pattern() -> &'static str {
        "[a-z][a-z0-9-]{0,20}|[a-z][a-z0-9-]{62,90}"
    }

    #[test]
    fn empty_set_misses_everything() {
        let set = CompiledNameSet::empty();
        assert!(set.lookup(b"host").is_none());
        assert_eq!(set.count(), 0);
        assert!(set.lookup(b"").is_none());
    }

    #[test]
    fn single_name_round_trip() {
        let mut b = NameSetBuilder::new();
        let id = b.insert(b"host").unwrap();
        let set = b.finish();
        assert_eq!(set.lookup(b"host"), Some(id));
        assert_eq!(set.lookup(b"hos"), None);
        assert_eq!(set.lookup(b"hosts"), None);
        assert_eq!(set.name_of(id), Some(&b"host"[..]));
    }

    #[test]
    fn same_length_last_byte_discriminator() {
        let mut b = NameSetBuilder::new();
        let a = b.insert(b"x-a").unwrap();
        let bee = b.insert(b"x-b").unwrap();
        let c = b.insert(b"x-c").unwrap();
        let set = b.finish();
        assert_eq!(set.lookup(b"x-a"), Some(a));
        assert_eq!(set.lookup(b"x-b"), Some(bee));
        assert_eq!(set.lookup(b"x-c"), Some(c));
        assert_eq!(set.lookup(b"x-d"), None);
        assert_eq!(set.disc_at[3], 2);
    }

    #[test]
    fn common_prefix_picks_max_distinct() {
        let mut b = NameSetBuilder::new();
        let id_tenant = b.insert(b"x-tenant").unwrap();
        let id_region = b.insert(b"x-region").unwrap();
        let id_canary = b.insert(b"x-canary").unwrap();
        let set = b.finish();

        assert_eq!(set.lookup(b"x-tenant"), Some(id_tenant));
        assert_eq!(set.lookup(b"x-region"), Some(id_region));
        assert_eq!(set.lookup(b"x-canary"), Some(id_canary));
        assert_eq!(set.lookup(b"x-tenant2"), None);
        assert_eq!(
            set.count(),
            3,
            "catches CompiledNameSet::count being replaced with a constant"
        );

        let names: [&[u8]; 3] = [b"x-tenant", b"x-region", b"x-canary"];
        let mut best_count = 0usize;
        for i in 0..8 {
            let mut seen = HashSet::new();
            for n in names {
                seen.insert(n[i]);
            }
            best_count = best_count.max(seen.len());
        }

        let chosen = set.disc_at[8];
        assert_ne!(chosen, NO_DISC);
        let mut seen_at_chosen = HashSet::new();
        for n in names {
            seen_at_chosen.insert(n[usize::from(chosen)]);
        }
        assert_eq!(
            seen_at_chosen.len(),
            best_count,
            "the chosen index must achieve the maximum distinct-byte count over the bucket"
        );
    }

    #[test]
    fn prefilter_rejects() {
        let mut b = NameSetBuilder::new();
        b.insert(b"x-tenant").unwrap();
        let set = b.finish();
        assert_eq!(set.lookup(b"y-tenant"), None, "first-byte filter");
        assert_eq!(set.lookup(b"x-tenanu"), None, "last-byte filter");
        assert_eq!(set.lookup(b"x-tenan"), None, "length filter");
    }

    #[test]
    fn long_names() {
        let n63 = vec![b'a'; 63];
        let n64 = vec![b'b'; 64];
        let n65 = vec![b'c'; 65];
        let mut b = NameSetBuilder::new();
        let id63 = b.insert(&n63).unwrap();
        let id64 = b.insert(&n64).unwrap();
        let id65 = b.insert(&n65).unwrap();
        let set = b.finish();

        assert_eq!(set.lookup(&n63), Some(id63));
        assert_eq!(set.lookup(&n64), Some(id64));
        assert_eq!(set.lookup(&n65), Some(id65));
        assert_ne!(
            set.len_bits & (1u64 << 63),
            0,
            "the 63-byte name must be on the fast path"
        );
        assert_eq!(
            set.entries.len(),
            1,
            "only the 63-byte name is a fast-path entry"
        );
        assert_eq!(set.long.len(), 2, "the 64- and 65-byte names are both long");
    }

    #[test]
    fn idempotent_insert() {
        let mut b = NameSetBuilder::new();
        let id1 = b.insert(b"host").unwrap();
        let id2 = b.insert(b"host").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn rejects_bad_names() {
        let mut b = NameSetBuilder::new();
        assert_eq!(b.insert(b""), Err(NameSetError::Empty));
        assert_eq!(b.insert(b"a:b"), Err(NameSetError::InvalidByte));
        assert_eq!(b.insert(b"a b"), Err(NameSetError::InvalidByte));
        assert_eq!(b.insert(b"a\xffb"), Err(NameSetError::InvalidByte));
    }

    #[test]
    fn rejects_too_many() {
        let mut b = NameSetBuilder::new();
        let mut total = 0usize;
        for len in 1..=MAX_FAST_NAME_LEN {
            for variant in 0..MAX_NAMES_PER_LENGTH {
                b.insert(&name_of_len(len, variant)).unwrap();
                total += 1;
            }
        }
        for variant in 0..MAX_NAMES_PER_LENGTH {
            b.insert(&name_of_len(64, variant)).unwrap();
            total += 1;
        }
        assert_eq!(total, MAX_NAMES, "the 4096th name must succeed");
        assert_eq!(b.len(), MAX_NAMES);

        let extra = name_of_len(65, 0);
        assert_eq!(b.insert(&extra), Err(NameSetError::TooMany));
    }

    #[test]
    fn rejects_too_many_of_one_length() {
        let mut b = NameSetBuilder::new();
        for variant in 0..MAX_NAMES_PER_LENGTH {
            assert!(b.insert(&name_of_len(8, variant)).is_ok());
        }
        assert_eq!(
            b.insert(&name_of_len(8, MAX_NAMES_PER_LENGTH)),
            Err(NameSetError::TooManyOfLength)
        );
        assert!(
            b.insert(&name_of_len(9, 0)).is_ok(),
            "a different length is unaffected by the length-8 bucket being full"
        );

        for variant in 0..MAX_NAMES_PER_LENGTH {
            assert!(b.insert(&name_of_len(64, variant)).is_ok());
        }
        assert_eq!(
            b.insert(&name_of_len(64, MAX_NAMES_PER_LENGTH)),
            Err(NameSetError::TooManyOfLength),
            "the long list is capped independently of the fast-path buckets"
        );

        let too_long = vec![b'z'; MAX_NAME_BYTES + 1];
        assert_eq!(b.insert(&too_long), Err(NameSetError::NameTooLong));

        // A fresh builder, because the one above has already filled its long
        // bucket to MAX_NAMES_PER_LENGTH: a name of exactly MAX_NAME_BYTES
        // must succeed on its own terms (only strictly longer is refused),
        // which the length-cap check just above cannot isolate on `b`.
        let mut fresh = NameSetBuilder::new();
        let exactly_max = vec![b'q'; MAX_NAME_BYTES];
        assert!(
            fresh.insert(&exactly_max).is_ok(),
            "a name of exactly MAX_NAME_BYTES must succeed; only strictly longer is refused"
        );
    }

    #[test]
    fn worst_case_bucket_scan_is_bounded() {
        // The shape no single discriminating index can split: 64 names of
        // length 8 spelled only from 'a' and 'b', so at most 2 distinct
        // values ever appear at any byte position and the best any
        // discriminator can do is roughly halve the bucket.
        let mut b = NameSetBuilder::new();
        let mut members: Vec<(Vec<u8>, super::NameId)> = Vec::new();
        for i in 0u8..64 {
            let mut name = vec![0u8; 8];
            for p in 0..8usize {
                if let Some(slot) = name.get_mut(p) {
                    *slot = if (i >> p) & 1 == 0 { b'a' } else { b'b' };
                }
            }
            let id = b.insert(&name).unwrap();
            members.push((name, id));
        }
        let set = b.finish();

        let (member_name, member_id) = members[0].clone();
        reset_compare_count_for_test();
        assert_eq!(set.lookup(&member_name), Some(member_id));
        let hit_compares = usize::try_from(compare_count_for_test()).unwrap_or(usize::MAX);
        assert!(
            hit_compares <= MAX_NAMES_PER_LENGTH,
            "a hit must not compare more than MAX_NAMES_PER_LENGTH full names"
        );
        assert!(
            hit_compares > 0,
            "a hit must reach at least one full comparison; a zero count here would also \
             pass a same-or-fewer check even with the counter disabled entirely"
        );

        // A near-miss of the same length, first byte and last byte as a real
        // member (an interior byte outside {a, b}), so the prefilter cannot
        // reject it cheaply and the bounded bucket scan is really exercised.
        let mut near_miss = member_name.clone();
        if let Some(slot) = near_miss.get_mut(3) {
            *slot = b'z';
        }
        reset_compare_count_for_test();
        assert_eq!(set.lookup(&near_miss), None);
        let miss_compares = usize::try_from(compare_count_for_test()).unwrap_or(usize::MAX);
        assert!(
            miss_compares <= MAX_NAMES_PER_LENGTH,
            "a near miss must not compare more than MAX_NAMES_PER_LENGTH full names"
        );
        assert!(
            miss_compares > 0,
            "a near miss that passes every prefilter must still reach the bucket scan"
        );
    }

    /// Catches `bit_test` being replaced with a constant, and its internal
    /// `&` being mutated to `|`: no named test calls `bit_test` directly, and
    /// every named test's prefilter checks still resolve to the right
    /// `lookup` answer even if the prefilter itself always said "maybe",
    /// because the exact bucket scan downstream is independently correct.
    #[test]
    fn bit_test_and_set_bit_round_trip() {
        for b in [0u8, 1, 5, 63, 64, 127, 128, 191, 192, 255] {
            let empty = [0u64; 4];
            assert!(
                !super::bit_test(empty, b),
                "an all-zero filter must reject byte {b}"
            );
            let mut bits = [0u64; 4];
            super::set_bit(&mut bits, b);
            assert!(
                super::bit_test(bits, b),
                "the bit just set for byte {b} must read back set"
            );
        }
        // Setting one bit must not set any other bit in the same word.
        let mut bits = [0u64; 4];
        super::set_bit(&mut bits, 5);
        assert!(!super::bit_test(bits, 4));
        assert!(!super::bit_test(bits, 6));
    }

    /// Catches `len_is_referenced`'s `&` being mutated to `|`: as documented
    /// on the function itself, no test of `lookup`'s return value can
    /// distinguish this mutation, because every other array this crate reads
    /// for an unreferenced length is independently empty or all-zero.
    #[test]
    fn len_is_referenced_reads_the_correct_bit() {
        use super::len_is_referenced;
        assert!(!len_is_referenced(0, 0));
        assert!(len_is_referenced(0b1, 0));
        assert!(!len_is_referenced(0b1, 1));
        assert!(len_is_referenced(1u64 << 63, 63));
        assert!(!len_is_referenced(1u64 << 62, 63));
    }

    /// Catches `choose_disc`'s tie-break `>` being mutated to `>=`: both `ab`
    /// and `ba` have exactly 2 distinct bytes at index 0 AND at index 1, so a
    /// tie-break toward the highest index would pick 1 instead of 0.
    #[test]
    fn discriminator_tie_break_prefers_lowest_index() {
        let mut b = NameSetBuilder::new();
        b.insert(b"ab").unwrap();
        b.insert(b"ba").unwrap();
        let set = b.finish();
        assert_eq!(
            set.disc_at[2], 0,
            "both byte positions tie at 2 distinct values; the lower index must win"
        );
    }

    /// Catches `NameSetBuilder::is_empty` being replaced with a constant
    /// `true` or `false`: no named test calls it.
    #[test]
    fn is_empty_reflects_builder_state() {
        let mut b = NameSetBuilder::new();
        assert!(b.is_empty());
        b.insert(b"host").unwrap();
        assert!(!b.is_empty());
    }

    #[test]
    fn uppercase_lookup_misses() {
        // Release-build (and, per this implementation's deliberate choice
        // documented on `lookup`, every build's) fail-closed behaviour: a
        // name that violates the "already lowercase" contract simply misses
        // rather than matching the wrong header.
        let mut b = NameSetBuilder::new();
        b.insert(b"host").unwrap();
        let set = b.finish();
        assert_eq!(set.lookup(b"HOST"), None);
    }

    #[test]
    fn content_hash_is_stable_and_sensitive() {
        let mut b1 = NameSetBuilder::new();
        b1.insert(b"host").unwrap();
        b1.insert(b"x-tenant").unwrap();
        let hash1 = b1.finish().content_hash();

        let mut b2 = NameSetBuilder::new();
        b2.insert(b"host").unwrap();
        b2.insert(b"x-tenant").unwrap();
        let hash2 = b2.finish().content_hash();
        assert_eq!(
            hash1, hash2,
            "the same names inserted in the same order must hash identically"
        );

        let mut b3 = NameSetBuilder::new();
        b3.insert(b"x-tenant").unwrap();
        b3.insert(b"host").unwrap();
        let hash3 = b3.finish().content_hash();
        assert_ne!(
            hash1, hash3,
            "the same names in a different order assign different ids, so the hash must differ"
        );

        let mut b4 = NameSetBuilder::new();
        b4.insert(b"host").unwrap();
        b4.insert(b"x-tenant").unwrap();
        b4.insert(b"x-region").unwrap();
        let hash4 = b4.finish().content_hash();
        assert_ne!(
            hash1, hash4,
            "inserting one extra name must change the hash"
        );

        assert_eq!(
            CompiledNameSet::empty().content_hash(),
            NameSetBuilder::new().finish().content_hash()
        );
    }

    proptest! {
        #[test]
        fn finish_is_deterministic(
            names in prop::collection::hash_set(any_name_pattern(), 1..40),
            probes in proptest::collection::vec(any_name_pattern(), 20),
        ) {
            let mut ordered: Vec<String> = names.into_iter().collect();
            ordered.sort();

            let build = |order: &[String]| -> CompiledNameSet {
                let mut builder = NameSetBuilder::new();
                for n in order {
                    builder
                        .insert(n.as_bytes())
                        .expect("generator only produces valid tchar names well under every cap");
                }
                builder.finish()
            };

            let a = build(&ordered);
            let same_order_again = build(&ordered);
            let mut reversed = ordered.clone();
            reversed.reverse();
            let reverse_order = build(&reversed);

            // Byte-identical arenas: asserted only between the two SAME-ORDER
            // builds. Ids are assigned in insertion order (not sorted order,
            // see NameSetBuilder::insert's doc), so the reverse-order build
            // legitimately assigns different ids to the same names and its
            // arenas differ from `a`'s on purpose; only membership, not the
            // exact assigned id, can be compared against it below.
            prop_assert_eq!(&a.blob, &same_order_again.blob);
            prop_assert_eq!(&a.entries, &same_order_again.entries);
            prop_assert_eq!(&a.buckets, &same_order_again.buckets);
            prop_assert_eq!(&a.disc_at, &same_order_again.disc_at);
            prop_assert_eq!(&a.first_filter, &same_order_again.first_filter);
            prop_assert_eq!(&a.last_filter, &same_order_again.last_filter);

            for n in &ordered {
                let expected = a.lookup(n.as_bytes());
                prop_assert_eq!(same_order_again.lookup(n.as_bytes()), expected);
                prop_assert_eq!(reverse_order.lookup(n.as_bytes()).is_some(), expected.is_some());
            }
            for p in &probes {
                let expected = a.lookup(p.as_bytes());
                prop_assert_eq!(same_order_again.lookup(p.as_bytes()), expected);
                prop_assert_eq!(reverse_order.lookup(p.as_bytes()).is_some(), expected.is_some());
            }
        }

        #[test]
        fn exhaustive_membership(
            names in prop::collection::hash_set(membership_name_pattern(), 1..40),
            pick in 0usize..1000,
            mutation in 0u8..6,
            mutation_idx in 0usize..1000,
            mutation_byte in proptest::prelude::any::<u8>(),
        ) {
            let ordered: Vec<String> = {
                let mut v: Vec<String> = names.into_iter().collect();
                v.sort();
                v
            };
            let mut builder = NameSetBuilder::new();
            for n in &ordered {
                builder
                    .insert(n.as_bytes())
                    .expect("generator only produces valid tchar names well under every cap");
            }
            let set = builder.finish();

            let idx = pick % ordered.len();
            let base = ordered[idx].clone();
            let base_bytes = base.into_bytes();
            let len = base_bytes.len();
            // Each arm below targets a different set of byte positions
            // `CompiledNameSet::lookup` reads, worked out from the code: the
            // three-load prefilter (length, first byte, last byte) only ever
            // screens byte 0, the last byte, and a length change, so a near
            // miss built only from those three primitives can never reach a
            // final full comparison with an interior difference. Deleting
            // that final comparison on any of `lookup`'s three paths (the
            // NO_DISC single-entry return, the disc-scan bucket loop, or
            // `lookup_long`) is exactly the false positive issue #579 names:
            // a header predicate matching the wrong header.
            let candidate: Vec<u8> = match mutation {
                0 => base_bytes,
                1 => {
                    // Rewrite one byte at a position chosen uniformly across
                    // the whole name, including position 0 and the last
                    // byte, the two positions the prefilter loads directly.
                    let mut bytes = base_bytes;
                    let at = mutation_idx % len;
                    if let Some(slot) = bytes.get_mut(at) {
                        *slot = mutation_byte;
                    }
                    bytes
                }
                2 => {
                    // Rewrite a byte strictly between the first and last, so
                    // the candidate agrees with `base` on every byte the
                    // prefilter reads (length, first byte, last byte). Only
                    // the final full comparison can reject a candidate built
                    // this way. Needs len >= 3; a shorter name has no
                    // interior byte at all, so it falls back to appending,
                    // still a genuine near miss.
                    let mut bytes = base_bytes;
                    if len >= 3 {
                        let at = 1 + (mutation_idx % (len - 2));
                        if let Some(slot) = bytes.get_mut(at) {
                            *slot = mutation_byte;
                        }
                    } else {
                        bytes.push(mutation_byte);
                    }
                    bytes
                }
                3 => {
                    // Rewrite only the final byte. The last-byte filter is a
                    // 256-bit bitmap shared by every entry of this length, so
                    // a candidate whose last byte collides with a DIFFERENT
                    // entry's last byte (not `base`'s) still passes the
                    // filter even though it does not match `base`; this is
                    // the exact shape of the cross-header collision issue
                    // #579's reproduction demonstrates.
                    let mut bytes = base_bytes;
                    if let Some(last) = len.checked_sub(1)
                        && let Some(slot) = bytes.get_mut(last)
                    {
                        *slot = mutation_byte;
                    }
                    bytes
                }
                4 => {
                    let mut bytes = base_bytes;
                    bytes.push(mutation_byte);
                    bytes
                }
                _ => {
                    let mut bytes = base_bytes;
                    bytes.pop();
                    bytes
                }
            };

            let expected = ordered.iter().any(|n| n.as_bytes() == candidate.as_slice());
            prop_assert_eq!(set.lookup(&candidate).is_some(), expected);
        }
    }
}
