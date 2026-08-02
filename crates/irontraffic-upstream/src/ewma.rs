// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peak-EWMA: the packed codec, the deterministic `exp_neg` approximation, and
//! the `peak_ewma_step` state transition.
//!
//! A time-decayed exponentially weighted moving average of observed round-trip
//! time, with one modification: a sample that exceeds the decayed projection
//! replaces it outright instead of blending. A latency spike is registered
//! immediately and then decays away, while a run of fast responses moves the
//! estimate only gradually. The cost estimate and the `CoarseMillis` timestamp
//! it was recorded at are packed into one `AtomicU64` (see
//! [`crate::stats::EndpointStats::cost`]) so that reading or updating both is a
//! single cache-line touch rather than a lock protecting two separate words.
//!
//! `exp_neg` is a pure `f32` polynomial approximation rather than a call to
//! `f32::exp`, because a libm call costs 15 to 40 ns against a 25 ns budget for
//! an entire P2C pick, which contains two of these. It is deterministic on
//! every platform (IEEE-754 `f32` add and multiply are exactly specified, and
//! Rust does not contract to FMA), which matters twice over: the simulation
//! harness must be reproducible, and two replicas must not disagree.

use crate::CoarseMillis;

/// Upper clamp on any recorded round-trip sample, in milliseconds.
pub const MAX_RTT_MS: f32 = 60_000.0;

/// Lower clamp on any recorded round-trip sample, in milliseconds.
///
/// This is load-bearing, not hygiene. The cost is `rtt * (inflight + 1)`, so an
/// `rtt` of exactly `0.0` makes the cost `0.0` for every value of `inflight`,
/// which silently deletes the in-flight term from the default algorithm. Round-trip
/// samples derived from the coarse millisecond clock are `0` for any sub-millisecond
/// upstream, which is the common case on a local network, so this is reachable in
/// normal operation rather than only adversarially. One microsecond is far below any
/// real service time and keeps the product monotone in `inflight`.
pub const MIN_RTT_MS: f32 = 0.001;

/// Tuning for the peak-EWMA cost function. Defaults come from linkerd2-proxy's
/// `DEFAULT_RTT = 1s` and `DEFAULT_RTT_DECAY = 10s`.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct EwmaCfg {
    /// Decay window in milliseconds. Default `10_000`.
    pub decay_ms: u32,
    /// Cost assigned to an endpoint that has never been sampled and has no fleet
    /// median to seed from, in milliseconds. Default `1_000.0`.
    pub default_rtt_ms: f32,
}

impl Default for EwmaCfg {
    fn default() -> Self {
        Self {
            decay_ms: 10_000,
            default_rtt_ms: 1_000.0,
        }
    }
}

/// Splits the packed word. Returns `(estimate_ms, recorded_at)`.
///
/// The all-zero word (`word == 0`) unpacks to `(0.0, 0)`, which is the "never
/// sampled" sentinel rather than a genuine `0.0` ms sample recorded at millisecond
/// `0`; the two are indistinguishable only in the first millisecond of process
/// life, which is harmless and documented rather than encoded around.
#[allow(
    clippy::inline_always,
    reason = "one P2C sample of one endpoint must cost exactly one cache-line touch; this \
              function sits on that path and the 25 ns pick budget has no room for a call \
              clippy's default inlining heuristic might decline to take"
)]
#[inline(always)]
#[must_use]
pub fn unpack(word: u64) -> (f32, CoarseMillis) {
    // Shifting a `u64` right by 32 and masking to the low 32 bits both provably
    // fit in a `u32`, so `try_from` never takes the fallback; it is used instead
    // of `as` so this file contains no int-narrowing `as` cast at all, rather than
    // pairing every one with a `cast_possible_truncation` allow.
    let hi = u32::try_from(word >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(word & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    (f32::from_bits(hi), lo)
}

/// Builds the packed word. `est_ms` must already be clamped and finite.
#[allow(
    clippy::inline_always,
    reason = "one P2C sample of one endpoint must cost exactly one cache-line touch; this \
              function sits on that path and the 25 ns pick budget has no room for a call \
              clippy's default inlining heuristic might decline to take"
)]
#[inline(always)]
#[must_use]
pub fn pack(est_ms: f32, at: CoarseMillis) -> u64 {
    // `|`, not `^`: the two operands never share a set bit (the left one occupies
    // only bits 32..=63 after the shift, the right one, a `u32` widened to `u64`,
    // only bits 0..=31), so bitwise OR and XOR are provably identical here for
    // every input, and mutation testing confirms no test can tell them apart.
    (u64::from(est_ms.to_bits()) << 32) | u64::from(at)
}

/// Returns `exp(-x)` for `x >= 0` with a maximum relative error of 0.14%.
///
/// Deterministic on every platform: pure IEEE-754 `f32` add, multiply, `floor`,
/// and `from_bits`, with no libm call and no FMA contraction.
#[allow(
    clippy::inline_always,
    reason = "the P2C pick budget is 25 ns and contains two calls to this function; a libm \
              f32::exp call alone costs 15 to 40 ns, which is the whole reason this \
              polynomial exists, so it must not regress to an un-inlined call either"
)]
#[allow(
    clippy::many_single_char_names,
    reason = "x, y, k, f, and p are the algorithm's own notation (x the input, y = -x*log2(e), \
              k its integer part, f its fractional part, p the Taylor-series polynomial in f); \
              renaming them to longer words would make this harder to check against the \
              derivation in the doc comments and the reference this is ported from, not easier"
)]
#[inline(always)]
#[must_use]
pub fn exp_neg(x: f32) -> f32 {
    #[allow(
        clippy::neg_cmp_op_on_partial_ord,
        reason = "deliberately NOT `x <= 0.0`: every comparison against NaN is false, so \
                  `x <= 0.0` would let a NaN input fall through to the polynomial below and \
                  propagate NaN into a cost estimate. `!(x > 0.0)` is true for NaN precisely \
                  because `x > 0.0` is false for NaN, which is the point of writing it this \
                  way instead of the more obviously equivalent-looking direct comparison"
    )]
    let non_positive_or_nan = !(x > 0.0);
    if non_positive_or_nan {
        // Covers x == 0.0, -0.0, and NaN: `exp(0) == 1` and a poisoned or
        // non-finite input must not propagate NaN further into a cost estimate.
        //
        // `>`, not `>=`, in the guard above: this is a second, independent choice
        // from the negation itself. Mutation testing found that `x >= 0.0` here
        // is EQUIVALENT, not merely untested: at x == 0.0 the polynomial path
        // below computes y = 0.0, k = 0.0, f = 0.0, so p = 1.0 and
        // f32::from_bits((127) << 23) is exactly 1.0, giving the identical
        // result the early return hardcodes. `>` is kept anyway because it
        // states the function's actual domain (`x >= 0`, per this function's
        // own doc comment) rather than relying on this coincidence, and because
        // a future change to the polynomial's exact-zero behaviour would make
        // `>=` silently wrong while `>` stays correct by construction.
        return 1.0;
    }
    // Cutoff, derived: the exponent is built directly as `((k + 127) << 23)`,
    // which needs `k >= -126`. Since `k = floor(-x * log2(e))`, that requires
    // `x * log2(e) <= 126`, i.e. `x <= 87.33`. The cutoff is 87.0, safely inside
    // it: at x = 87, `x * log2(e) = 125.5`, so `k = -126` and the exponent field
    // is 1. A cutoff at 88 would admit `k = -127`, whose exponent field is 0, and
    // `f32::from_bits(0)` is 0.0, so the function would silently return 0 instead
    // of ~1e-38. At x = 87 the true value is exp(-87) = 1.65e-38, a hair above
    // `f32::MIN_POSITIVE` (1.175e-38), so returning 0.0 from here costs at most
    // 1.7e-38 of absolute error and keeps `k` in the normal range.
    if x >= 87.0 {
        return 0.0;
    }
    let y = -x * core::f32::consts::LOG2_E; // y in (-125.6, 0) for x in (0, 87)
    let k = y.floor(); // integer part, <= 0
    let f = y - k; // fractional part in [0, 1)
    // 2^f by its Taylor series in f * ln 2, degree 4. Truncation error at f -> 1
    // is (ln 2)^5 / 120 = 1.33e-3. The degree-1 coefficient is written as the
    // named constant rather than as a literal (unlike the degree-2 through
    // degree-4 coefficients, which are not named constants clippy recognises):
    // `core::f32::consts::LN_2.to_bits() == 0.693_147_2f32.to_bits()`, so this
    // is the identical bit pattern, not a behaviour change.
    let p = 1.0
        + f * (core::f32::consts::LN_2 + f * (0.240_226_5 + f * (0.055_504_1 + f * 0.009_618_1)));
    // 2^k by direct exponent construction. k is in -126..=0 here (see the cutoff
    // derivation above), so converting it to a signed 32-bit integer truncates no
    // fractional part beyond what `.floor()` already removed and cannot overflow;
    // `+ 127` then lies in 1..=127, always non-negative, so the following
    // conversion to an unsigned 32-bit integer loses no sign bit.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "k = floor(-x * log2(e)) for x in (0, 87) is an integer in -126..=0 (see the \
                  cutoff derivation above the x >= 87.0 guard), so converting it to a signed \
                  32-bit integer is exact and adding 127 lies in 1..=127, always non-negative, \
                  so the following conversion to an unsigned 32-bit integer loses no sign"
    )]
    let bits = (((k as i32) + 127) as u32) << 23; // it-allow: unchecked-cast reason: k is a floor() result proven above to be an integer in -126..=0, not network input; converting it to a signed 32-bit width is therefore exact, and adding 127 lands in 1..=127, always non-negative, so converting that sum to an unsigned 32-bit width loses no sign bit
    p * f32::from_bits(bits)
}

/// Multiplier that decays a stored estimate from `recorded_at` to `now_ms`.
///
/// Returns `1.0` when no coarse millisecond has elapsed and when the subtraction
/// wrapped past half the range, which means the caller's clock moved backwards.
#[allow(
    clippy::inline_always,
    reason = "shared by both cost_key and record_rtt's hot paths; a call clippy declined to \
              inline here would appear twice on the pick path this crate budgets at 25 ns"
)]
#[inline(always)]
#[must_use]
pub fn decay_factor(recorded_at: CoarseMillis, now_ms: CoarseMillis, decay_ms: u32) -> f32 {
    let elapsed = now_ms.wrapping_sub(recorded_at);
    if elapsed == 0 || elapsed > (1u32 << 31) {
        return 1.0;
    }
    // `elapsed` is bounded above by `2^31` by the guard above and `decay_ms` is a
    // millisecond configuration value; converting either to `f32` loses only bits
    // below its 24-bit mantissa, which is immaterial input to `exp_neg`'s own
    // 0.14% relative error budget and does not change which side of `exp_neg`'s
    // saturation cutoff the ratio falls on for any pair a real deployment
    // configures.
    #[allow(
        clippy::cast_precision_loss,
        reason = "elapsed is bounded above by 2^31 by the guard above and decay_ms is a \
                  millisecond configuration value; converting either to f32 loses only \
                  bits below f32's 24-bit mantissa, which is immaterial input to \
                  exp_neg's 0.14% relative error budget"
    )]
    let ratio = elapsed as f32 / decay_ms.max(1) as f32;
    exp_neg(ratio)
}

/// Folds one round-trip sample into a packed peak-EWMA word.
///
/// `sample_ms` is clamped into `[MIN_RTT_MS, MAX_RTT_MS]` before recording, and a
/// non-finite sample is replaced by `cfg.default_rtt_ms`. A stored word whose `f32`
/// half is non-finite, negative, or below `MIN_RTT_MS` (which this function never
/// produces, but which can arrive via [`pack`] built from an arbitrary `u64`, as
/// `fuzz_ewma` does) is treated as "never sampled" and replaced outright rather
/// than blended: `projected = NaN * decay` would otherwise be NaN, `NaN < sample`
/// is `false`, control would fall into the blend, and `f32::clamp` returns `self`
/// rather than clamping a NaN `self`, so a NaN word would persist forever.
#[allow(
    clippy::inline_always,
    reason = "the sole state transition on the record_rtt hot path, budgeted well under \
              the 25 ns P2C pick cost; a non-inlined call here is a function-call overhead \
              this crate cannot afford on every recorded sample"
)]
#[inline(always)]
#[must_use]
pub fn peak_ewma_step(word: u64, sample_ms: f32, now_ms: CoarseMillis, cfg: &EwmaCfg) -> u64 {
    let sample = if sample_ms.is_finite() {
        sample_ms.clamp(MIN_RTT_MS, MAX_RTT_MS)
    } else {
        cfg.default_rtt_ms.clamp(MIN_RTT_MS, MAX_RTT_MS)
    };
    if word == 0 {
        return pack(sample, now_ms);
    }
    let (value, ts) = unpack(word);
    // `value < 0.0`, not `<=` or `==`: mutation testing found both alternatives
    // are EQUIVALENT here, not merely untested, because `sample` is always
    // positive by this point (clamped into `[MIN_RTT_MS, MAX_RTT_MS]` above) and
    // `decay` is always in `[0.0, 1.0]` (I-S3). Whenever `value <= 0.0`,
    // `projected = value * decay` is therefore always `<= 0.0`, which is always
    // `< sample`, so the `projected < sample` peak rule a few lines below fires
    // anyway and produces the identical `pack(sample, now_ms)` this branch
    // returns directly. Every choice of comparison operator that agrees with
    // `<` on strictly negative `value` (and disagrees only at `value == 0.0`,
    // where the peak rule still produces the same output) is therefore
    // observationally identical for every input.
    if !value.is_finite() || value < 0.0 {
        return pack(sample, now_ms);
    }
    let decay = decay_factor(ts, now_ms, cfg.decay_ms);
    let projected = value * decay;
    if projected < sample {
        return pack(sample, now_ms);
    }
    let alpha = 1.0 - decay;
    let blended = value * (1.0 - alpha) + sample * alpha;
    pack(blended.clamp(MIN_RTT_MS, MAX_RTT_MS), now_ms)
}
