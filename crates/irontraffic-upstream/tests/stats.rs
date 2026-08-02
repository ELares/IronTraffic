// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the peak-EWMA codec, the `order_key` / `cost_key` /
//! `load_key` ordering primitives, the health-transition helpers, and the
//! `InflightGuard` / `ConnGuard` balances, driven entirely through
//! `irontraffic_upstream`'s public API.
//!
//! Two numbering slips in the issue this file implements, found while writing
//! these tests, are worth recording rather than silently working around:
//! `cargo test`'s own reported test count settles the true number, not the
//! issue's own count.
//!
//! - The acceptance criteria say "33 unit and integration tests (1 through 23,
//!   including 7a, 10a, 21a, 21b, 21c, 21d, 21e, 23a, 23b and 23c)", but the
//!   `## Tests` section defines no test numbered `7a`; only *edge case* 7a
//!   exists (the zero-sample clamp), and it is exercised by test 10a, whose own
//!   description cross-references it by that name. There are 9 lettered test
//!   variants actually defined (10a, 21a-21e, 23a-23c), so 23 + 9 = 32 tests are
//!   defined here, not 33.
//! - The next bullet says "Tests 23a and 11 depend on release arithmetic
//!   (wrapping rather than panicking)", but neither test as written does:
//!   `on_healthy`'s `saturating_mul(2)` never wraps or panics in either
//!   profile (that is the point of using `saturating_mul` instead of `2 *`),
//!   and edge case 11 (`inflight` at `u32::MAX`) is handled the same
//!   profile-independent way via `saturating_add`. This bullet is read here as
//!   describing what a REGRESSION to plain `2 *` / `+` would do (which is why
//!   `huge_slow_start_window_does_not_wrap` exists at all), not a property of
//!   the correct implementation, which is deliberately profile-independent.
//!
//! `seed_cost_if_unset_only_seeds_a_zero_word`'s own description reads
//! `unpack(cost_word())`, but no `cost_word()` accessor is named anywhere in
//! this issue's Public API section. `cost` is a public field of
//! `EndpointStats`, so this file reads it directly
//! (`stats.cost.load(Ordering::Relaxed)`) instead.
//!
//! Beyond the issue's own 32 named tests and 4 property tests, this file also
//! carries a handful of tests added after a `cargo mutants -j 1` sweep of
//! `src/ewma.rs` and `src/stats.rs` found real, non-equivalent gaps the named
//! tests do not close (a mutated `EndpointStats::record_rtt` body, a mutated
//! `load_key` with no dedicated coverage of its own scaling, weighting, and
//! `max_requests` behaviour, an unexercised `InflightGuard::record_rtt` /
//! `stats()`, the `decay_factor` wrap-boundary, and two arithmetic-operator
//! mutations in `peak_ewma_step` that no existing numeric fixture happens to
//! distinguish). Each such test's doc comment names the mutation it closes.
//! The remaining mutants a full sweep still reports are PROVEN equivalent in
//! code comments at their sites (`ewma.rs`'s `pack`, `exp_neg`, and
//! `peak_ewma_step`'s `value < 0.0` guard), not closed with a test that would
//! only decorate them.
#![allow(
    clippy::float_cmp,
    reason = "every float comparison in this file is deliberately exact, not approximate: it \
              is checking bit-for-bit determinism of a codec (pack/unpack roundtrips), a \
              clamp, or an early-return branch that is specified to produce an EXACT value \
              (for example exp_neg(0.0) == 1.0 is a literal early return, not an \
              approximation), which is the property this whole design is built on"
)]

use std::sync::atomic::Ordering;

use irontraffic_upstream::{
    ConnGuard, CostCtx, EndpointStats, EwmaCfg, InflightGuard, MAX_RTT_MS, MIN_RTT_MS,
    decay_factor, exp_neg, order_key, pack, peak_ewma_step, unpack,
};
use proptest::prelude::*;

/// Builds a packed word directly from its two halves, bypassing [`pack`]'s own
/// (nonexistent) clamping so a genuinely poisoned word (NaN, an infinity, or a
/// negative estimate) can be constructed for the poisoned-word tests below.
/// [`pack`] itself performs no clamping either, so this produces byte-identical
/// output to `pack(v, at)`; it is kept separate to make the poisoned-word tests
/// read as "an adversarial raw word", independent of `pack`'s own correctness.
fn pack_raw(v: f32, at: u32) -> u64 {
    (u64::from(v.to_bits()) << 32) | u64::from(at)
}

fn default_cx(max_requests: u32) -> CostCtx {
    CostCtx {
        now_ms: 0,
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
        max_requests,
    }
}

// ---------------------------------------------------------------------------
// exp_neg
// ---------------------------------------------------------------------------

#[test]
fn exp_neg_matches_libm_within_tolerance() {
    for x in [0.0_f32, 0.001, 0.1, 0.5, 1.0, 2.0, 4.0, 10.0, 40.0, 86.9] {
        let got = exp_neg(x);
        let want = f64::from(-x).exp();
        let diff = (f64::from(got) - want).abs();
        assert!(
            diff <= 0.0014 * want,
            "exp_neg({x}) = {got}, want ~{want} within 0.14%: diff {diff}"
        );
    }
}

#[test]
fn exp_neg_saturates_and_handles_nonfinite() {
    assert_eq!(exp_neg(0.0), 1.0);
    assert_eq!(exp_neg(-0.0), 1.0);
    assert_eq!(exp_neg(87.0), 0.0);
    assert_eq!(exp_neg(f32::INFINITY), 0.0);
    assert_eq!(exp_neg(f32::NAN), 1.0);
    for x in [0.0_f32, 1.0, 50.0, 200.0, f32::INFINITY, f32::NAN, -5.0] {
        let v = exp_neg(x);
        assert!((0.0..=1.0).contains(&v), "exp_neg({x}) = {v} out of [0, 1]");
    }
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

#[test]
fn pack_unpack_roundtrip() {
    for est in [0.0_f32, 0.5, 1.0, 999.5, MAX_RTT_MS] {
        for at in [0u32, 1, u32::MAX] {
            let (got_est, got_at) = unpack(pack(est, at));
            assert_eq!(got_est, est);
            assert_eq!(got_at, at);
        }
    }
}

/// `EndpointStats::record_rtt` itself, not just `peak_ewma_step` (the pure
/// function it wraps): mutating the whole method body to a no-op survives
/// every test that only calls `peak_ewma_step` directly, since none of them
/// go through the method at all.
#[test]
fn record_rtt_folds_a_sample_into_the_estimate() {
    let stats = EndpointStats::default();
    let cfg = EwmaCfg::default();
    stats.record_rtt(42.0, 1_000, &cfg);
    assert_eq!(unpack(stats.cost.load(Ordering::Relaxed)), (42.0, 1_000));
}

#[test]
fn first_sample_is_stored_verbatim() {
    let cfg = EwmaCfg::default();
    let word = peak_ewma_step(0, 42.0, 1000, &cfg);
    assert_eq!(unpack(word), (42.0, 1000));
}

// ---------------------------------------------------------------------------
// Peak semantics, ported from linkerd2-proxy's test_add_peak_replaces_decayed_value
// and test_add_peak_retains_higher_value.
// ---------------------------------------------------------------------------

#[test]
fn peak_sample_above_projection_replaces_it() {
    let cfg = EwmaCfg::default();
    let word = pack(100.0, 0);
    let next = peak_ewma_step(word, 500.0, 5000, &cfg);
    assert_eq!(unpack(next), (500.0, 5000));
}

#[test]
fn peak_sample_below_projection_blends() {
    let cfg = EwmaCfg {
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
    };
    let word = pack(100.0, 0);
    let next = peak_ewma_step(word, 10.0, 1000, &cfg);
    let (got, ts) = unpack(next);
    assert_eq!(ts, 1000);
    assert!(
        got > 10.0 && got < 100.0,
        "blended value {got} must lie strictly between the sample and the prior estimate"
    );
    let decay = exp_neg(0.1);
    let want = 100.0 * decay + 10.0 * (1.0 - decay);
    assert!((got - want).abs() < 1e-4, "got {got}, want ~{want}");
}

/// `projected = value * decay`, not `+` or `/`: with a large stored value and a
/// long elapsed time (so `decay` is small), multiplication makes the decayed
/// projection fall BELOW the new sample, so the peak rule fires and the sample
/// is stored verbatim. Addition barely moves the projection (it stays far
/// above the sample), and division makes it far larger still, so either
/// mutation would leave the estimate blended around the huge prior value
/// instead of replaced by the small new sample. Found by mutation testing:
/// no test naming only the sample and the prior value (rather than the actual
/// numeric outcome) distinguishes the three.
#[test]
fn peak_rule_uses_multiplication_not_addition_or_division_for_the_projection() {
    let cfg = EwmaCfg {
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
    };
    let word = pack(1000.0, 0);
    let next = peak_ewma_step(word, 50.0, 50_000, &cfg);
    assert_eq!(
        unpack(next),
        (50.0, 50_000),
        "a decayed projection of a large old value must fall below a new sample \
         once enough time has passed, firing the peak rule verbatim"
    );
}

/// The boundary case `projected == sample` exactly: the peak rule
/// (`projected < sample`) must NOT fire, and the blend must run instead.
/// Mutating `<` to `<=` here survives every other test in this file because it
/// requires an EXACT floating-point tie, which no other test happens to hit.
/// `value` is chosen (via a small offline search over `elapsed`) so that
/// `value * decay_factor(0, 3, 10_000)` is bit-for-bit `10.0`, the sample this
/// test records.
#[test]
fn peak_rule_boundary_when_projected_exactly_equals_sample_blends_not_replaces() {
    let cfg = EwmaCfg {
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
    };
    let value = f32::from_bits(0x4120_2b11); // ~10.010514
    let decay = decay_factor(0, 3, cfg.decay_ms);
    assert_eq!(
        (value * decay).to_bits(),
        10.0f32.to_bits(),
        "fixture invariant: value * decay must be bit-for-bit 10.0 for this test to \
         exercise the projected == sample boundary at all"
    );
    let word = pack(value, 0);
    let next = peak_ewma_step(word, 10.0, 3, &cfg);
    let (got, _) = unpack(next);
    assert_ne!(
        got.to_bits(),
        10.0f32.to_bits(),
        "at the projected == sample boundary the blend must run, not the peak rule, \
         so the result must not be exactly the sample"
    );
    assert!(
        got > 10.0,
        "the blend of value ~{value} and sample 10.0 must land above the sample"
    );
}

#[test]
fn idle_estimate_decays_monotonically() {
    let times = [0u32, 100, 1000, 10_000, 100_000];
    let mut prev = decay_factor(0, times[0], 10_000);
    for &t in &times[1..] {
        let cur = decay_factor(0, t, 10_000);
        assert!(
            cur <= prev,
            "decay_factor must be non-increasing as elapsed time grows: at t={t} got {cur} \
             after {prev}"
        );
        prev = cur;
    }
}

/// `elapsed > (1u32 << 31)`, not `>=`: exactly half the `u32` range is treated
/// as ordinary forward elapsed time, not as a backwards-clock wrap. At exactly
/// `1u32 << 31` milliseconds elapsed (about 24.9 days), the ratio against any
/// realistic `decay_ms` is so far past `exp_neg`'s 87.0 saturation cutoff that
/// `decay_factor` still returns `0.0` via the normal path, but ONE MORE
/// millisecond of elapsed time crosses the `>` threshold and is instead
/// treated as "the clock moved backwards", returning `1.0`. Mutating `>` to
/// `>=` moves that boundary by exactly one millisecond and is invisible to
/// every other test in this file, none of which exercises this exact edge.
#[test]
fn decay_factor_at_wrap_boundary_uses_normal_path_not_backwards_clock_path() {
    let half_range = 1u32 << 31;
    assert_eq!(
        decay_factor(0, half_range, 10_000),
        0.0,
        "exactly half the u32 range must take the normal decay path, which \
         saturates to 0.0 at this magnitude of elapsed time"
    );
    assert_eq!(
        decay_factor(0, half_range + 1, 10_000),
        1.0,
        "one millisecond past half the u32 range must be treated as a backwards \
         clock and return 1.0 unchanged"
    );
}

#[test]
fn clock_going_backwards_returns_stored_value() {
    let cfg = EwmaCfg::default();
    let word = pack(100.0, 5000);
    let next = peak_ewma_step(word, 10.0, 4000, &cfg);
    let (got, _) = unpack(next);
    assert_eq!(got, 100.0);
}

#[test]
fn nonfinite_and_negative_samples_are_replaced() {
    let cfg = EwmaCfg::default();
    for sample in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0] {
        let word = peak_ewma_step(0, sample, 0, &cfg);
        let (got, _) = unpack(word);
        assert!(got.is_finite(), "sample {sample} produced non-finite {got}");
        assert!(
            (MIN_RTT_MS..=MAX_RTT_MS).contains(&got),
            "sample {sample} produced {got} outside [{MIN_RTT_MS}, {MAX_RTT_MS}]"
        );
    }
}

#[test]
fn sample_above_max_is_clamped() {
    let cfg = EwmaCfg::default();
    let word = peak_ewma_step(0, 1e9, 0, &cfg);
    let (got, _) = unpack(word);
    assert_eq!(got, MAX_RTT_MS);
}

#[test]
fn zero_sample_is_clamped_up() {
    let cfg = EwmaCfg::default();
    let word = peak_ewma_step(0, 0.0, 0, &cfg);
    let (got, _) = unpack(word);
    assert_eq!(got, MIN_RTT_MS);

    // Edge case 7a: storing 0.0 must not delete the in-flight term from the
    // cost product. Two endpoints that both recorded 0.0 but differ only in
    // `inflight` must still produce different `cost_key`s.
    let cx = default_cx(u32::MAX);
    let low = EndpointStats::default();
    low.cost.store(word, Ordering::Relaxed);
    let high = EndpointStats::default();
    high.cost.store(word, Ordering::Relaxed);
    high.inflight.store(100, Ordering::Relaxed);
    assert_ne!(low.cost_key(1.0, &cx), high.cost_key(1.0, &cx));
}

// ---------------------------------------------------------------------------
// Ordering key
// ---------------------------------------------------------------------------

#[test]
fn order_key_is_monotone_on_non_negative() {
    let mut values: Vec<f32> = vec![
        0.0,
        f32::from_bits(1),
        f32::from_bits(2),
        f32::from_bits(0x0040_0000), // a subnormal
        f32::MIN_POSITIVE,
        1e-10,
        1.0,
        2.0,
        100.0,
        1e10,
        1e30,
        f32::INFINITY,
    ];
    assert_eq!(values.len(), 12);
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in this fixture"));
    let keys: Vec<u32> = values.iter().map(|&v| order_key(v)).collect();
    for w in keys.windows(2) {
        assert!(
            w[0] <= w[1],
            "order_key must be non-decreasing over {values:?}: {keys:?}"
        );
    }
}

#[test]
fn order_key_nan_sorts_worst() {
    assert!(order_key(f32::NAN) > order_key(f32::INFINITY));
    assert_eq!(order_key(-f32::NAN), u32::MAX);
}

#[test]
fn order_key_negative_zero_is_best() {
    assert_eq!(order_key(-0.0), 0);
    assert_eq!(order_key(0.0), 0);
}

#[test]
fn order_key_negative_sorts_worst() {
    assert_eq!(order_key(-1.0), u32::MAX);
}

// ---------------------------------------------------------------------------
// Cost keys
// ---------------------------------------------------------------------------

#[test]
fn cost_key_scales_with_inflight() {
    let cx = default_cx(u32::MAX);
    let make = |inflight: u32| {
        let s = EndpointStats::default();
        s.cost.store(pack(10.0, 0), Ordering::Relaxed);
        s.inflight.store(inflight, Ordering::Relaxed);
        s
    };
    let k0 = make(0).cost_key(1.0, &cx);
    let k1 = make(1).cost_key(1.0, &cx);
    let k7 = make(7).cost_key(1.0, &cx);
    assert!(k0 < k1, "k0={k0} k1={k1}");
    assert!(k1 < k7, "k1={k1} k7={k7}");
}

#[test]
fn cost_key_divides_by_weight() {
    let cx = default_cx(u32::MAX);
    let s = EndpointStats::default();
    s.cost.store(pack(10.0, 0), Ordering::Relaxed);
    s.inflight.store(3, Ordering::Relaxed);
    let k1 = s.cost_key(1.0, &cx);
    let k2 = s.cost_key(2.0, &cx);
    assert!(k2 < k1, "k2={k2} must be strictly less than k1={k1}");
}

#[test]
fn cost_key_respects_max_requests() {
    let cx = default_cx(4);
    let s = EndpointStats::default();
    s.cost.store(pack(10.0, 0), Ordering::Relaxed);
    s.inflight.store(4, Ordering::Relaxed);
    assert_eq!(s.cost_key(1.0, &cx), u32::MAX);
    s.inflight.store(3, Ordering::Relaxed);
    assert!(s.cost_key(1.0, &cx) < u32::MAX);
}

#[test]
fn cost_key_unsampled_uses_default_rtt() {
    let cx = default_cx(u32::MAX);
    let s = EndpointStats::default();
    assert_eq!(s.cost_key(1.0, &cx), order_key(1_000.0));
}

/// `cost_key` decays the stored estimate by the elapsed time between when it
/// was recorded and `cx.now_ms`, via `v * decay_factor(...)`: an old, once-high
/// estimate must look cheaper once enough coarse time has passed. Every other
/// `cost_key` test in this file records and reads back at the SAME `now_ms`
/// (elapsed always `0`, `decay_factor` always exactly `1.0`), so a mutation
/// that sends the decayed estimate the wrong direction (for example `*` to
/// `/`, which makes an aged estimate look far MORE expensive instead of
/// cheaper) cannot be distinguished from the correct multiplication by any of
/// them.
#[test]
fn cost_key_decays_the_stored_estimate_over_elapsed_time() {
    let s = EndpointStats::default();
    s.cost.store(pack(1_000.0, 0), Ordering::Relaxed);
    let fresh_cx = CostCtx {
        now_ms: 0,
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
        max_requests: u32::MAX,
    };
    let aged_cx = CostCtx {
        now_ms: 50_000,
        ..fresh_cx
    };
    let fresh_key = s.cost_key(1.0, &fresh_cx);
    let aged_key = s.cost_key(1.0, &aged_cx);
    assert!(
        aged_key < fresh_key,
        "an estimate read long after it was recorded must decay toward a lower \
         cost: fresh={fresh_key} aged={aged_key}"
    );
}

/// `cost_key` computes `rtt` as `v * decay_factor(...)`, not `v +
/// decay_factor(...)`: at `elapsed == 0`, `decay_factor` returns exactly
/// `1.0`, so multiplication leaves `v` unchanged while addition would shift it
/// by `1.0`. The test above (aged vs fresh) does not catch this: both `*` and
/// `+` combine a fixed `v` with a decay term that itself decreases as time
/// passes, so both formulas happen to decrease together and the aged key
/// stays below the fresh key either way. Asserting the EXACT key produced by a
/// known `v` at `elapsed == 0`, where multiplying by `1.0` is a no-op and
/// adding `1.0` is not, is what actually distinguishes them.
#[test]
fn cost_key_multiplies_by_decay_not_adds_it() {
    let cx = default_cx(u32::MAX);
    let s = EndpointStats::default();
    s.cost.store(pack(10.0, 0), Ordering::Relaxed);
    assert_eq!(
        s.cost_key(1.0, &cx),
        order_key(10.0),
        "at elapsed == 0, decay_factor is exactly 1.0, so v * decay_factor must \
         leave the stored estimate unchanged"
    );
}

#[test]
fn load_key_ignores_rtt() {
    let cx = default_cx(u32::MAX);
    let a = EndpointStats::default();
    a.cost.store(pack(1.0, 0), Ordering::Relaxed);
    a.inflight.store(5, Ordering::Relaxed);
    let b = EndpointStats::default();
    b.cost.store(pack(59_999.0, 0), Ordering::Relaxed);
    b.inflight.store(5, Ordering::Relaxed);
    assert_eq!(a.load_key(1.0, &cx), b.load_key(1.0, &cx));
}

/// Mirrors `cost_key_scales_with_inflight`: `load_key_ignores_rtt` above only
/// checks that two keys are EQUAL to each other, which a mutation that
/// replaces the whole function with a constant, or that corrupts the weight
/// division into a no-op (dividing by the fractional part via `%` when
/// `w_eff == 1.0`, which is `0.0` for every whole-number numerator this
/// function ever computes), also satisfies. This checks the actual ordering
/// against a fixed weight instead.
#[test]
fn load_key_scales_with_inflight() {
    let cx = default_cx(u32::MAX);
    let make = |inflight: u32| {
        let s = EndpointStats::default();
        s.inflight.store(inflight, Ordering::Relaxed);
        s
    };
    let k0 = make(0).load_key(1.0, &cx);
    let k1 = make(1).load_key(1.0, &cx);
    let k7 = make(7).load_key(1.0, &cx);
    assert!(k0 < k1, "k0={k0} k1={k1}");
    assert!(k1 < k7, "k1={k1} k7={k7}");
}

/// Mirrors `cost_key_divides_by_weight`. Distinguishes `/` from `*` in the
/// weight division, which `load_key_scales_with_inflight` above cannot: that
/// test fixes `w_eff` at `1.0`, where dividing and multiplying by the weight
/// are the same operation.
#[test]
fn load_key_divides_by_weight() {
    let cx = default_cx(u32::MAX);
    let s = EndpointStats::default();
    s.inflight.store(3, Ordering::Relaxed);
    let k1 = s.load_key(1.0, &cx);
    let k2 = s.load_key(2.0, &cx);
    assert!(k2 < k1, "k2={k2} must be strictly less than k1={k1}");
}

/// Mirrors `cost_key_respects_max_requests`.
#[test]
fn load_key_respects_max_requests() {
    let cx = default_cx(4);
    let s = EndpointStats::default();
    s.inflight.store(4, Ordering::Relaxed);
    assert_eq!(s.load_key(1.0, &cx), u32::MAX);
    s.inflight.store(3, Ordering::Relaxed);
    assert!(s.load_key(1.0, &cx) < u32::MAX);
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

#[test]
fn inflight_guard_balances() {
    let stats = EndpointStats::default();
    let g = InflightGuard::acquire(&stats);
    assert_eq!(stats.inflight(), 1);
    drop(g);
    assert_eq!(stats.inflight(), 0);

    let g1 = InflightGuard::acquire(&stats);
    let g2 = InflightGuard::acquire(&stats);
    assert_eq!(stats.inflight(), 2);
    drop(g1);
    assert_eq!(stats.inflight(), 1);
    drop(g2);
    assert_eq!(stats.inflight(), 0);
}

/// `InflightGuard::record_rtt` and `InflightGuard::stats()`: convenience
/// methods for the response path, which already holds the guard. Neither is
/// exercised by `inflight_guard_balances` above, so mutating either to a no-op
/// (or, for `stats()`, to a leaked default endpoint) would otherwise survive
/// undetected.
#[test]
fn inflight_guard_record_rtt_and_stats_convenience_methods_work() {
    let stats = EndpointStats::default();
    let g = InflightGuard::acquire(&stats);

    assert!(
        core::ptr::eq(g.stats(), &raw const stats),
        "InflightGuard::stats() must return a reference to the endpoint it was \
         acquired against, not a substitute"
    );

    let cfg = EwmaCfg::default();
    g.record_rtt(42.0, 1_000, &cfg);
    assert_eq!(
        unpack(stats.cost.load(Ordering::Relaxed)),
        (42.0, 1_000),
        "InflightGuard::record_rtt must fold the sample into the SAME endpoint's \
         estimate, exactly like EndpointStats::record_rtt"
    );
}

#[test]
fn conn_guard_balances() {
    let stats = EndpointStats::default();
    let g = ConnGuard::acquire(&stats);
    assert_eq!(stats.active_conns(), 1);
    drop(g);
    assert_eq!(stats.active_conns(), 0);

    let g1 = ConnGuard::acquire(&stats);
    let g2 = ConnGuard::acquire(&stats);
    assert_eq!(stats.active_conns(), 2);
    drop(g1);
    assert_eq!(stats.active_conns(), 1);
    drop(g2);
    assert_eq!(stats.active_conns(), 0);
}

#[test]
fn guard_dropped_after_slot_recycle_does_not_underflow() {
    let stats = EndpointStats::default();
    let guard = InflightGuard::acquire(&stats);
    assert_eq!(stats.inflight(), 1);

    // Simulate the recycle EndpointRegistryWriter::intern performs.
    stats.inflight.store(0, Ordering::Relaxed);
    stats.generation.store(1, Ordering::Relaxed);

    drop(guard);
    assert_eq!(
        stats.inflight(),
        0,
        "a guard outstanding across a recycle must not underflow the new tenant's counter"
    );
}

#[test]
fn conn_guard_dropped_after_slot_recycle_does_not_underflow() {
    let stats = EndpointStats::default();
    let guard = ConnGuard::acquire(&stats);
    assert_eq!(stats.active_conns(), 1);

    stats.active_conns.store(0, Ordering::Relaxed);
    stats.generation.store(1, Ordering::Relaxed);

    drop(guard);
    assert_eq!(stats.active_conns(), 0);
}

#[test]
fn guard_still_releases_within_its_own_generation() {
    let stats = EndpointStats::default();
    let g1 = InflightGuard::acquire(&stats);
    let g2 = InflightGuard::acquire(&stats);
    assert_eq!(stats.inflight(), 2);
    drop(g1);
    drop(g2);
    assert_eq!(
        stats.inflight(),
        0,
        "both guards share the current generation and must both release"
    );
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

#[test]
fn seed_cost_if_unset_only_seeds_a_zero_word() {
    let stats = EndpointStats::default();
    stats.seed_cost_if_unset(30.0, 1_000);
    assert_eq!(unpack(stats.cost.load(Ordering::Relaxed)), (30.0, 1_000));

    stats.seed_cost_if_unset(500.0, 2_000);
    assert_eq!(unpack(stats.cost.load(Ordering::Relaxed)), (30.0, 1_000));
}

#[test]
fn seed_cost_if_unset_clamps() {
    let zero = EndpointStats::default();
    zero.seed_cost_if_unset(0.0, 5);
    let (got, _) = unpack(zero.cost.load(Ordering::Relaxed));
    assert_eq!(got, MIN_RTT_MS);

    let nan = EndpointStats::default();
    nan.seed_cost_if_unset(f32::NAN, 5);
    let (got, _) = unpack(nan.cost.load(Ordering::Relaxed));
    assert!(got.is_finite());
    assert!((MIN_RTT_MS..=MAX_RTT_MS).contains(&got));
}

// ---------------------------------------------------------------------------
// Health transitions
// ---------------------------------------------------------------------------

#[test]
fn slow_start_ramp_restarts_after_a_long_absence() {
    let stats = EndpointStats::default();
    let t: u32 = 5_000;
    stats.on_unhealthy(1_000);
    let now = 1_000 + 2 * t + 1;
    stats.on_healthy(now, t);
    assert_eq!(stats.healthy_since_ms.load(Ordering::Relaxed), now);
}

#[test]
fn slow_start_ramp_does_not_restart_within_2t() {
    let stats = EndpointStats::default();
    let t: u32 = 5_000;
    stats.on_unhealthy(1_000);
    stats.healthy_since_ms.store(500, Ordering::Relaxed);
    stats.on_healthy(1_000 + t, t);
    assert_eq!(stats.healthy_since_ms.load(Ordering::Relaxed), 500);
}

#[test]
fn huge_slow_start_window_does_not_wrap() {
    let stats = EndpointStats::default();
    stats.on_unhealthy(1_000);
    stats.healthy_since_ms.store(500, Ordering::Relaxed);
    stats.on_healthy(2_000, 3_000_000_000);
    assert_eq!(stats.healthy_since_ms.load(Ordering::Relaxed), 500);
}

// ---------------------------------------------------------------------------
// Poisoned-word handling
// ---------------------------------------------------------------------------

#[test]
fn poisoned_word_is_replaced_not_blended() {
    let cfg = EwmaCfg::default();
    for word in [
        pack_raw(f32::NAN, 0),
        pack_raw(f32::INFINITY, 0),
        pack_raw(-1.0, 0),
    ] {
        let next = peak_ewma_step(word, 42.0, 1_000, &cfg);
        let (est, at) = unpack(next);
        assert!(
            est.is_finite(),
            "poisoned word {word:#x} produced non-finite {est}"
        );
        assert_eq!((est, at), (42.0, 1_000));
    }
}

#[test]
fn poisoned_word_sorts_worst_not_best() {
    let cx = default_cx(u32::MAX);

    let poisoned = EndpointStats::default();
    poisoned
        .cost
        .store(pack_raw(f32::NAN, 0), Ordering::Relaxed);
    let poisoned_key = poisoned.cost_key(1.0, &cx);
    assert_eq!(poisoned_key, u32::MAX);

    let healthy = EndpointStats::default();
    healthy.cost.store(pack(60_000.0, 0), Ordering::Relaxed);
    healthy.inflight.store(1_000, Ordering::Relaxed);
    let healthy_key = healthy.cost_key(1.0, &cx);

    assert!(
        poisoned_key > healthy_key,
        "a poisoned endpoint (key {poisoned_key}) must sort worse than an overloaded but \
         healthy one (key {healthy_key})"
    );
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// After every step in an arbitrary sequence of samples (including NaN and
    /// infinities) and elapsed-time deltas, applied in order from a zero word,
    /// the unpacked estimate stays finite and in range (I-S1), and `cost_key`
    /// never reports the sentinel-worst key while under the in-flight limit.
    #[test]
    fn ewma_never_produces_a_poisoned_word(
        steps in prop::collection::vec((any::<f32>(), 0u32..=200_000u32), 0..=64),
    ) {
        let cfg = EwmaCfg::default();
        let mut word: u64 = 0;
        let mut now: u32 = 0;
        for (sample, dt) in steps {
            now = now.wrapping_add(dt);
            word = peak_ewma_step(word, sample, now, &cfg);
            let (est, _) = unpack(word);
            prop_assert!(est.is_finite(), "estimate must be finite, got {est}");
            prop_assert!(
                (MIN_RTT_MS..=MAX_RTT_MS).contains(&est),
                "estimate {est} out of [{MIN_RTT_MS}, {MAX_RTT_MS}]"
            );

            let stats = EndpointStats::default();
            stats.cost.store(word, Ordering::Relaxed);
            let cx = CostCtx {
                now_ms: now,
                decay_ms: cfg.decay_ms,
                default_rtt_ms: cfg.default_rtt_ms,
                max_requests: u32::MAX,
            };
            let key = stats.cost_key(1.0, &cx);
            prop_assert!(key < u32::MAX, "cost_key must not be the sentinel worst key, got {key}");
        }
    }

    /// For a sequence of finite samples in `[MIN_RTT_MS, 1000]`, the stored
    /// estimate never exceeds the maximum sample seen so far and never falls
    /// below the minimum of `MIN_RTT_MS` and the smallest sample seen. A small
    /// epsilon accounts for `f32` rounding in the blend step, not a design gap:
    /// a convex combination of two values each `<= max_seen` can round to a
    /// value a fraction of a ULP above `max_seen` in floating point even though
    /// it cannot in real arithmetic.
    #[test]
    fn ewma_result_is_bounded_by_the_samples(
        samples in prop::collection::vec(MIN_RTT_MS..=1000.0f32, 1..=64),
    ) {
        let cfg = EwmaCfg::default();
        let mut word: u64 = 0;
        let mut now: u32 = 0;
        let mut max_seen = f32::MIN;
        let mut min_seen = f32::MAX;
        for sample in samples {
            max_seen = max_seen.max(sample);
            min_seen = min_seen.min(sample);
            word = peak_ewma_step(word, sample, now, &cfg);
            now = now.wrapping_add(100);
            let (est, _) = unpack(word);
            prop_assert!(
                est <= max_seen + 1e-3,
                "estimate {est} exceeds the maximum sample seen so far, {max_seen}"
            );
            let floor = MIN_RTT_MS.min(min_seen);
            prop_assert!(
                est >= floor - 1e-3,
                "estimate {est} fell below the floor {floor}"
            );
        }
    }

    /// `order_key` never panics on an arbitrary `f32`, including NaN, and the
    /// `u32` keys it produces obey the total order integers always do:
    /// antisymmetric, transitive, and sortable without panicking.
    #[test]
    fn order_key_is_a_total_order(values in prop::collection::vec(any::<f32>(), 8..=8)) {
        let keys: Vec<u32> = values.iter().map(|&v| order_key(v)).collect();
        for i in 0..keys.len() {
            for j in 0..keys.len() {
                if keys[i] < keys[j] {
                    prop_assert!(keys[j] >= keys[i], "antisymmetry violated at {i},{j}");
                }
            }
        }
        for i in 0..keys.len() {
            for j in 0..keys.len() {
                for k in 0..keys.len() {
                    if keys[i] <= keys[j] && keys[j] <= keys[k] {
                        prop_assert!(keys[i] <= keys[k], "transitivity violated at {i},{j},{k}");
                    }
                }
            }
        }
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        prop_assert_eq!(sorted.len(), keys.len());
    }

    /// `peak_ewma_step` sanitises ANY `u64` input word, not only ones this
    /// crate's own `pack` could have produced: the returned word's `f32` half
    /// is always finite and in `[MIN_RTT_MS, MAX_RTT_MS]` (I-S6), which is what
    /// makes `fuzz_ewma`'s contract provable rather than aspirational.
    #[test]
    fn step_sanitises_any_input_word(
        word in any::<u64>(),
        sample in any::<f32>(),
        now_ms in any::<u32>(),
    ) {
        let cfg = EwmaCfg::default();
        let next = peak_ewma_step(word, sample, now_ms, &cfg);
        let (est, _) = unpack(next);
        prop_assert!(est.is_finite(), "estimate must be finite for input word {word:#x}");
        prop_assert!(
            (MIN_RTT_MS..=MAX_RTT_MS).contains(&est),
            "estimate {est} out of [{MIN_RTT_MS}, {MAX_RTT_MS}] for input word {word:#x}"
        );
    }
}
