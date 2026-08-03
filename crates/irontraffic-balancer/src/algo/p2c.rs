// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Power-of-two-choices (P2C) selection: the Lemire multiply-shift reduction, sampling
//! without replacement from one 64-bit draw, the peak-EWMA and least-request pickers, and
//! the bounded-exclusion retry path.
//!
//! This is a direct correction of a verified defect in Envoy's least-request load balancer,
//! which samples its two candidates WITH replacement (a plain `rand % hosts.len()` drawn
//! twice), so the two draws collide with probability `1 / u` and, on a collision, degrade to
//! uniform random with no load information at all. At `u == 2` that is half of every pick
//! made blind. [`sample_two`] fixes this the way `linkerd2-proxy` does, by drawing a second
//! index from `n - 1` candidates and shifting it past the first, so the two are always
//! distinct, and improves on it by replacing `linkerd2-proxy`'s rejection-sampling,
//! range-drawing calls (the `rand` crate's own uniform-range helper) with [`reduce`], a
//! single multiply and shift with no division and no retry loop.
//!
//! Every function here takes its randomness as a plain `u64` argument. None of them own an
//! RNG, call one, allocate, take a lock, or read a clock: see I-P2 below. The caller (a later
//! issue) takes exactly one `next_u64()` per pick from the per-core generator.
//!
//! # Invariants
//!
//! - **I1.** Every `Some(i)` returned by a picker in this file satisfies `i < slice.len() as
//!   u32`. Asserted in debug at the return site of every function that returns a slice
//!   index, and property-tested.
//! - **I-P1.** [`sample_two`]`(draw, n)` returns `(a, b)` with `a != b`, `a < n`, and `b < n`,
//!   for every `draw: u64` and every `n >= 2`.
//! - **I-P2.** No function in this file allocates, blocks, takes a lock, reads a clock, or
//!   calls an RNG.
//! - **I-P3.** [`pick_excluding`] never returns an index whose local index appears in
//!   `exclude`.

use irontraffic_upstream::{CostCtx, EndpointId, EndpointStats};

/// Maximum number of endpoints a retry may exclude. Matches the retry attempt ceiling.
///
/// Never raise this constant. [`pick_excluding`]'s deterministic fallback scan is `O(u * r)`
/// in the worst case, and its cost stays bounded only because `r` is capped here at a small
/// constant; see the module-level comment on that function's release-mode rejection of an
/// oversized `exclude` for the full argument.
pub const MAX_EXCLUDE: usize = 3;

/// Which cost function a picker uses. Selected by the snapshot's algorithm state.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CostKind {
    /// `decayed_rtt * (inflight + 1) / w_eff`. The HTTP, HTTP/2, HTTP/3 and gRPC default.
    PeakEwma,
    /// `(inflight + 1) / w_eff`. The TCP and TLS default.
    LeastRequest,
}

/// The low 32 bits of a 64-bit draw.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "called at most twice per pick, inside the 25 ns P2C pick budget"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "intentionally takes the low 32 bits of a 64-bit random draw; this is a bit \
              split of an already-random value, not a bounded value being narrowed, so no \
              information a caller relies on is lost"
)]
fn low_u32(draw: u64) -> u32 {
    draw as u32 // it-allow: unchecked-cast reason: intentionally takes the low 32 bits of a 64-bit random draw, a bit split rather than a bounded value being narrowed
}

/// The high 32 bits of a 64-bit draw.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "called at most once per pick, inside the 25 ns P2C pick budget"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "draw >> 32 is already < 2^32 because the shift discarded the low bits, so this \
              narrowing is exact, never lossy"
)]
fn high_u32(draw: u64) -> u32 {
    (draw >> 32) as u32 // it-allow: unchecked-cast reason: draw >> 32 is already < 2^32 because the shift discarded the low bits, so this narrowing is exact
}

/// Converts a slice length to `u32`.
///
/// `n` is bounded by the endpoint registry's capacity ceiling of `2^20`
/// (`irontraffic_upstream::MAX_CAPACITY`), far below `u32::MAX`, so this never truncates in
/// practice; the debug assertion documents that bound rather than merely relying on it.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "called on every pick past the two-candidate fast path, inside the 25 ns budget"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "n is bounded by the endpoint registry's capacity ceiling of 2^20 \
              (irontraffic_upstream::MAX_CAPACITY), far below u32::MAX; the debug assertion \
              below documents that bound rather than merely relying on it"
)]
fn n_as_u32(n: usize) -> u32 {
    debug_assert!(
        u32::try_from(n).is_ok(),
        "slice length {n} exceeds u32::MAX; unreachable given the endpoint registry's \
         capacity ceiling of 2^20"
    );
    n as u32 // it-allow: unchecked-cast reason: n is bounded by the endpoint registry's capacity ceiling of 2^20, far below u32::MAX; the debug_assert above documents this bound
}

/// Lemire multiply-shift reduction: maps a uniform `u32` to `[0, n)` with a bias of at
/// most `n / 2^32`, using one multiply and one shift and no division and no branch.
///
/// `pub(crate)`, not private: the alias-table, Maglev and priority issues all reduce a draw
/// into a range and MUST call this one rather than writing a second copy or using `%`.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "the reduction every candidate index in this file is drawn through, inside the \
              25 ns P2C pick budget; not inlining it adds a call clippy's default heuristic \
              might decline to take"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "product >> 32 is provably < 2^32 because product itself is < 2^64 (the product \
              of two u32 values fits in 64 bits), so the shift discards exactly the bits that \
              would not fit; this narrowing is exact, never lossy"
)]
pub(crate) fn reduce(x: u32, n: u32) -> u32 {
    ((u64::from(x) * u64::from(n)) >> 32) as u32 // it-allow: unchecked-cast reason: product is < 2^64 (two u32 values multiplied), so shifting right by 32 leaves a value provably < 2^32
}

/// Two distinct indices in `[0, n)` from one 64-bit draw. Requires `n >= 2`.
///
/// Sampling is WITHOUT replacement: `b` is drawn from `n - 1` candidates and shifted past
/// `a`, so the two are always distinct. This is the correction of the Envoy defect described
/// at the top of this module: Envoy draws both indices independently with replacement, so
/// they collide with probability `1 / n`.
///
/// # Panics
/// Never in release. Debug-asserts `n >= 2`; callers must handle `n < 2` before calling.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "one P2C pick draws exactly one pair from this function, inside the 25 ns \
              per-pick budget; not inlining it adds a call clippy's default heuristic might \
              decline to take"
)]
#[must_use]
pub fn sample_two(draw: u64, n: u32) -> (u32, u32) {
    debug_assert!(n >= 2, "sample_two requires at least two candidates");
    let a = reduce(low_u32(draw), n);
    let mut b = reduce(high_u32(draw), n - 1);
    if b >= a {
        b += 1;
    }
    (a, b)
}

/// Resolves candidate `i` (an index INTO `slice`) to its cost key, or `None` if `i`, the
/// local index it names, or the `EndpointId` it names is out of range.
///
/// Indexing uses `get()` throughout rather than `[]`, because `clippy::indexing_slicing` is
/// denied and because a malformed snapshot must degrade to `None` (the caller's 503), never a
/// panic. The debug assertion on `i` itself documents that THIS particular bound cannot fail:
/// every caller in this file only ever passes an `i` already proven `< slice.len()`, by `0`,
/// `1`, or [`sample_two`]'s own I-P1 guarantee. The bounds below it, on the local index
/// `slice` itself carries and on the `EndpointId` that names, are not asserted the same way,
/// because a corrupt snapshot (edge case 8) is a real possibility this function must survive
/// without panicking, not an internal invariant of this file.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "resolves one candidate's cost key inside the 25 ns P2C pick budget; called at \
              most twice per pick outside the bounded exclusion fallback scan"
)]
#[allow(
    clippy::cast_precision_loss,
    reason = "w is an effective endpoint weight, realistically small and bounded by \
              configuration; converting it to f32 loses only bits below f32's 24-bit \
              mantissa, immaterial next to order_key's own bit-pattern ordering, matching \
              EndpointStats::cost_key's identical allow in irontraffic-upstream"
)]
fn key<K>(
    slice: &[u32],
    ids: &[EndpointId],
    weights: &[u32],
    stats: &[EndpointStats],
    cx: &CostCtx,
    key_fn: &K,
    i: u32,
) -> Option<u32>
where
    K: Fn(&EndpointStats, f32, &CostCtx) -> u32,
{
    debug_assert!(
        (i as usize) < slice.len(),
        "key: index out of range for a slice of length {}; every caller in this file must \
         only pass i < slice.len()",
        slice.len()
    );
    let &local = slice.get(i as usize)?;
    let local = local as usize;
    let &w = weights.get(local)?;
    let id = ids.get(local)?;
    let st = stats.get(id.0 as usize)?;
    let w_eff = w as f32;
    Some(key_fn(st, w_eff, cx))
}

/// Compares candidates `a` and `b` by [`key`] and returns the better of the two.
///
/// Ties go to `a`, the first sampled index. `None` is treated as "worse than any key": if
/// exactly one candidate's key exists the other wins, and if neither key exists this returns
/// `None` so the caller emits a 503 rather than dereferencing a corrupt index.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "the two-candidate comparison at the heart of every pick, inside the 25 ns budget"
)]
fn better_of<K>(
    slice: &[u32],
    ids: &[EndpointId],
    weights: &[u32],
    stats: &[EndpointStats],
    cx: &CostCtx,
    key_fn: &K,
    a: u32,
    b: u32,
) -> Option<u32>
where
    K: Fn(&EndpointStats, f32, &CostCtx) -> u32,
{
    match (
        key(slice, ids, weights, stats, cx, key_fn, a),
        key(slice, ids, weights, stats, cx, key_fn, b),
    ) {
        (Some(ka), Some(kb)) => Some(if kb < ka { b } else { a }),
        (Some(_), None) => Some(a),
        (None, Some(_)) => Some(b),
        (None, None) => None,
    }
}

/// Shared body of [`pick_peak_ewma`] and [`pick_least_request`]. Generic over the key
/// function, so it monomorphises into two copies with the key call inlined at each call
/// site, and there is never an indirect call through a function pointer.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "shared body of pick_peak_ewma and pick_least_request; must monomorphise into \
              each caller with the key comparator inlined, or the 25 ns pick budget is missed"
)]
fn pick_with<K>(
    slice: &[u32],
    ids: &[EndpointId],
    weights: &[u32],
    stats: &[EndpointStats],
    cx: &CostCtx,
    draw: u64,
    key_fn: K,
) -> Option<u32>
where
    K: Fn(&EndpointStats, f32, &CostCtx) -> u32,
{
    let n = slice.len();
    let result = if n == 0 {
        // F1: caller emits 503, never panics.
        None
    } else if n == 1 {
        // No statistics read at all.
        Some(0)
    } else if n == 2 {
        // Exact two-way compare, not an approximation: with two candidates, sampling
        // without replacement IS the exhaustive comparison.
        better_of(slice, ids, weights, stats, cx, &key_fn, 0, 1)
    } else {
        let (a, b) = sample_two(draw, n_as_u32(n));
        better_of(slice, ids, weights, stats, cx, &key_fn, a, b)
    };
    debug_assert!(
        result.is_none_or(|i| (i as usize) < n),
        "I1 violated: pick_with returned an index outside slice"
    );
    result
}

/// Power-of-two-choices over the peak-EWMA cost `decayed_rtt * (inflight + 1) / w_eff`.
///
/// `slice` holds local indices that the snapshot builder already resolved to be eligible;
/// this function never re-checks health. Returns an index INTO `slice`, or `None` when
/// `slice` is empty. Allocation-free, lock-free, clock-free.
///
/// `u == 1` returns index 0 without reading any statistics. `u == 2` compares both, which
/// is exact least-cost rather than an approximation.
#[must_use]
pub fn pick_peak_ewma(
    slice: &[u32],
    ids: &[EndpointId],
    weights: &[u32],
    stats: &[EndpointStats],
    cx: &CostCtx,
    draw: u64,
) -> Option<u32> {
    let result = pick_with(
        slice,
        ids,
        weights,
        stats,
        cx,
        draw,
        EndpointStats::cost_key,
    );
    debug_assert!(
        result.is_none_or(|i| (i as usize) < slice.len()),
        "I1 violated: pick_peak_ewma returned an index outside slice"
    );
    result
}

/// Power-of-two-choices over `(inflight + 1) / w_eff`. The L4 and RTT-sampling-disabled
/// default. Same contract as [`pick_peak_ewma`].
#[must_use]
pub fn pick_least_request(
    slice: &[u32],
    ids: &[EndpointId],
    weights: &[u32],
    stats: &[EndpointStats],
    cx: &CostCtx,
    draw: u64,
) -> Option<u32> {
    let result = pick_with(
        slice,
        ids,
        weights,
        stats,
        cx,
        draw,
        EndpointStats::load_key,
    );
    debug_assert!(
        result.is_none_or(|i| (i as usize) < slice.len()),
        "I1 violated: pick_least_request returned an index outside slice"
    );
    result
}

/// Whether `local` (a local index, not a slice index) appears in `exclude`.
///
/// `exclude.len() <= MAX_EXCLUDE`, so this is a bounded, three-element-or-fewer linear scan,
/// never a heap-allocated hashed set.
#[inline(always)]
#[allow(
    clippy::inline_always,
    reason = "membership check inside pick_excluding's hot path; at most MAX_EXCLUDE entries, \
              so this must stay a straight-line scan with no call overhead"
)]
fn excluded(exclude: &[u32], local: u32) -> bool {
    exclude.contains(&local)
}

/// Power-of-two-choices excluding local indices already tried on this request.
///
/// `exclude` holds LOCAL indices (the values found in `slice`), not slice indices, and
/// must contain at most `MAX_EXCLUDE` entries. Performs at most three bounded resamples and
/// then one deterministic `O(u)` scan.
///
/// Returns `None` when `slice` is empty, when every entry of `slice` is excluded, or when
/// `exclude.len() > MAX_EXCLUDE`. That last case is a caller bug and is rejected rather than
/// truncated: [`excluded`] is an `O(r)` scan run once per slice entry, so an unbounded `r`
/// makes the pick `O(u * r)`. Truncating the list to `MAX_EXCLUDE` entries instead would
/// return an endpoint the caller has already established is unusable, which violates I-P3 and
/// sends the retry back where it came from; failing the request is the fail-closed answer.
#[must_use]
pub fn pick_excluding(
    kind: CostKind,
    slice: &[u32],
    ids: &[EndpointId],
    weights: &[u32],
    stats: &[EndpointStats],
    cx: &CostCtx,
    draw: u64,
    exclude: &[u32],
) -> Option<u32> {
    let n = slice.len();
    // Step 2 is not decoration: this function is reached from the retry path, which can be
    // entered with an empty slice after a membership change, and `n - 1` below would
    // underflow at `n == 0`.
    if n == 0 {
        return None;
    }
    debug_assert!(
        exclude.len() <= MAX_EXCLUDE,
        "pick_excluding: exclude.len() = {} exceeds MAX_EXCLUDE = {MAX_EXCLUDE}; this is a \
         caller bug, rejected rather than risking O(u * r) work",
        exclude.len()
    );
    if exclude.len() > MAX_EXCLUDE {
        // Enforced in RELEASE, not only in debug: see the module comment on this function.
        return None;
    }
    if exclude.is_empty() {
        let result = match kind {
            CostKind::PeakEwma => pick_peak_ewma(slice, ids, weights, stats, cx, draw),
            CostKind::LeastRequest => pick_least_request(slice, ids, weights, stats, cx, draw),
        };
        debug_assert!(
            result.is_none_or(|i| (i as usize) < n),
            "I1 violated: pick_excluding returned an index outside slice"
        );
        return result;
    }

    // `kind` is a runtime value, not known at compile time the way pick_with's `K` is, so the
    // dispatch below is a match rather than a second generic instantiation. It is still never
    // an indirect call: this closure captures `kind` by value and is monomorphised into `key`
    // and `better_of` below exactly like pick_with's own `key_fn`.
    let key_fn = |st: &EndpointStats, w: f32, cx: &CostCtx| -> u32 {
        match kind {
            CostKind::PeakEwma => st.cost_key(w, cx),
            CostKind::LeastRequest => st.load_key(w, cx),
        }
    };

    if n == 1 {
        let &local = slice.first()?;
        return if excluded(exclude, local) {
            None
        } else {
            Some(0)
        };
    }

    let n_u32 = n_as_u32(n);

    // Bounded resample: three independent attempts from one draw, rotating it. Reuses the
    // same 64-bit draw for three samples rather than demanding three draws, because the
    // caller has already spent its RNG step and three correlated-but-distinct samples are
    // statistically sufficient for a path taken on fewer than 1 in 1000 requests.
    for attempt in 0..3u32 {
        let d = draw.rotate_left(attempt * 21);
        let (a, b) = sample_two(d, n_u32);
        let Some(cand) = better_of(slice, ids, weights, stats, cx, &key_fn, a, b) else {
            break;
        };
        debug_assert!(
            (cand as usize) < n,
            "I1 violated: better_of returned an index outside slice"
        );
        let &local = slice.get(cand as usize)?;
        if !excluded(exclude, local) {
            return Some(cand);
        }
    }

    // Deterministic fallback: scan from a draw-derived offset and take the non-excluded
    // index with the lowest key. O(u), only reachable when three independent samples all hit
    // an excluded endpoint; see the module comment on this function for why that cannot be
    // turned into an amplifier.
    let start = reduce(low_u32(draw), n_u32) as usize;
    let mut best: Option<(u32, u32)> = None;
    for step in 0..n {
        let i = (start + step) % n;
        let &local = slice.get(i)?;
        if excluded(exclude, local) {
            continue;
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "i < n and n is bounded by the endpoint registry's capacity ceiling of \
                      2^20 (see n_as_u32 above), so i always fits in u32"
        )]
        let i_u32 = i as u32; // it-allow: unchecked-cast reason: i < n and n is bounded by the registry's capacity ceiling of 2^20 (see n_as_u32 above), so i always fits in u32
        let Some(k) = key(slice, ids, weights, stats, cx, &key_fn, i_u32) else {
            continue;
        };
        // `<`, strictly: on an exact tie the entry the scan visits FIRST from `start` keeps
        // `best`. This direction is deliberate but not load-bearing: the design commits to a
        // tie-break direction for the resample comparator (`better_of`, "ties go to a", edge
        // case 5), but leaves the scan's tie-break among several EXACTLY equal-cost entries
        // unspecified, because either direction returns an equally valid minimal-cost,
        // non-excluded candidate. `<=` here would visit-order tie-break the other way
        // (LAST-visited wins) with no effect on correctness, only on which of several tied
        // endpoints a vanishingly rare exact tie happens to prefer.
        if best.is_none_or(|(_, bk)| k < bk) {
            best = Some((i_u32, k));
        }
    }
    let result = best.map(|(i, _)| i);
    debug_assert!(
        result.is_none_or(|i| (i as usize) < n),
        "I1 violated: pick_excluding returned an index outside slice"
    );
    result
}
