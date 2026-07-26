// SPDX-License-Identifier: MIT OR Apache-2.0
//! `WyRand`-based fast, seedable, non-cryptographic randomness.
//!
//! This module is the hot-path generator for scheduling decisions. It is NOT for
//! tokens, nonces, keys, session identifiers, or any other value an attacker must
//! not predict.

use crate::{EntropyError, SecureRng};

const WY_P0: u64 = 0xa076_1d64_78bd_642f;
const WY_P1: u64 = 0xe703_7ed1_a0b4_28db;

/// Advances a `WyRand` state, returning `(new_state, output)`.
///
/// Pure, so per-core state can live in an `AtomicU64` and be stepped with a
/// relaxed load, this call, and a relaxed store. Do not add a `&mut` variant.
#[rustfmt::skip]
#[allow(clippy::cast_lossless, reason = "widening u64 to u128 in a const function")]
#[allow(clippy::cast_possible_truncation, reason = "WyRand output is the lower 64 bits of the mix")]
#[must_use]
pub const fn wyrand_step(state: u64) -> (u64, u64) {
    let s = state.wrapping_add(WY_P0);
    let t = (s as u128).wrapping_mul((s ^ WY_P1) as u128);
    let out = ((t >> 64) ^ t) as u64;
    (s, out)
}

/// One `SplitMix64` step over `state`, advancing it in place.
///
/// Used for seeding and for deterministic hash phases where the caller wants a
/// stateless mixing step rather than a generator.
pub const fn split_mix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A seedable, non-cryptographic generator. Eight bytes of state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Seeds from `seed` through one `SplitMix64` step, so adjacent seeds
    /// (0, 1, a worker index) produce well separated streams.
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        let mut s = seed;
        Self {
            state: split_mix64(&mut s),
        }
    }

    /// Seeds from the operating system CSPRNG.
    ///
    /// # Errors
    /// Returns [`EntropyError`] when the operating system entropy source fails.
    /// There is deliberately no fallback to a clock, a process id, an address, or
    /// a compiled-in constant. A caller that receives this error at startup must
    /// refuse to start; substituting a constant makes every stream in every
    /// deployment of the binary identical and therefore predictable.
    pub fn from_entropy() -> Result<Self, EntropyError> {
        SecureRng::seed().map(|state| Self { state })
    }

    /// The current state, so a deterministic simulation can record a seed and
    /// replay a failure.
    ///
    /// Do NOT log this from a production path. The state fully determines every
    /// future draw, so publishing it lets anyone who reads the log predict every
    /// subsequent endpoint choice, sampling decision, and jitter value this
    /// generator will make. It exists for a test harness that already knows the
    /// seed it supplied. In M1 there is no production caller.
    #[must_use]
    pub const fn state(&self) -> u64 {
        self.state
    }

    /// Next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let (s, out) = wyrand_step(self.state);
        self.state = s;
        out
    }

    /// Next 32 bits, taken from the high half of a 64-bit draw.
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32 // it-allow: unchecked-cast reason: a u64 shifted right by 32 has at most 32 significant bits
    }

    /// Uniform in `0..n` by Lemire multiply-shift reduction. Returns 0 when `n == 0`.
    ///
    /// Bias is at most `n / 2^32`, about 2.3e-7 at n = 1000. There is deliberately
    /// no rejection loop: this call is on the endpoint selection path and must be
    /// branch free and division free.
    pub fn bounded_u32(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let x = u64::from(self.next_u32());
        let m = x.wrapping_mul(u64::from(n));
        (m >> 32) as u32 // it-allow: unchecked-cast reason: m is u64 and the shift by 32 leaves at most 32 significant bits
    }

    /// Uniform in `0..n`. Returns 0 when `n == 0`. Bias is at most `n / 2^64`.
    pub fn bounded_u64(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let x = u128::from(self.next_u64());
        let m = x.wrapping_mul(u128::from(n));
        (m >> 64) as u64
    }

    /// Uniform in `[0.0, 1.0)`, using the top 53 bits of one draw.
    #[rustfmt::skip]
    #[allow(clippy::cast_precision_loss, reason = "top 53 bits of a u64 fit exactly in an f64 mantissa")]
    pub fn f64_unit(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
    }

    /// Uniform in `0..=base_ms`. The "full jitter" backoff shape.
    ///
    /// The one exception is `base_ms == u32::MAX`, where the result is uniform in
    /// `0..u32::MAX` because `base_ms + 1` would overflow.
    pub fn full_jitter_ms(&mut self, base_ms: u32) -> u32 {
        if base_ms == u32::MAX {
            return self.bounded_u32(u32::MAX);
        }
        self.bounded_u32(base_ms + 1)
    }

    /// Fills `out` with non-cryptographic bytes, little-endian per draw.
    /// Never use for tokens, nonces, or keys.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut chunks = out.chunks_exact_mut(8);
        for slot in chunks.by_ref() {
            slot.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let word = self.next_u64().to_le_bytes();
            let n = tail.len(); // 1..=7 by construction
            if let Some(src) = word.get(..n) {
                tail.copy_from_slice(src);
            }
        }
    }
}

const fn assert_send<T: Send>() -> bool {
    let _ = std::marker::PhantomData::<T>;
    true
}

const fn assert_sync<T: Sync>() -> bool {
    let _ = std::marker::PhantomData::<T>;
    true
}

const _: () = {
    assert!(std::mem::size_of::<Rng>() == 8);
    assert!(assert_send::<Rng>());
    assert!(assert_sync::<Rng>());
};

#[cfg(test)]
mod tests {
    use super::{Rng, wyrand_step};
    use proptest::prelude::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::from_seed(0xdead_beef);
        let mut b = Rng::from_seed(0xdead_beef);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge_immediately() {
        let a = Rng::from_seed(0).next_u64();
        let b = Rng::from_seed(1).next_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn seed_zero_is_usable() {
        let mut rng = Rng::from_seed(0);
        let mut first = [0u64; 10];
        for slot in &mut first {
            *slot = rng.next_u64();
        }
        assert!(!first.contains(&0), "seed 0 produced a zero");
        let all_equal = first.iter().all(|&v| v == first[0]);
        assert!(!all_equal, "seed 0 produced ten identical values");
    }

    #[test]
    fn wyrand_step_is_pure() {
        let a = wyrand_step(12345);
        let b = wyrand_step(12345);
        assert_eq!(a, b);
    }

    #[test]
    fn next_u32_uses_high_half() {
        let mut a = Rng::from_seed(0x1234_5678);
        let mut b = Rng::from_seed(0x1234_5678);
        let u32_a = a.next_u32();
        let u32_b = (b.next_u64() >> 32) as u32;
        assert_eq!(u32_a, u32_b);
    }

    #[test]
    fn bounded_zero_returns_zero() {
        let mut rng = Rng::from_seed(0xabc);
        for _ in 0..100 {
            assert_eq!(rng.bounded_u32(0), 0);
            assert_eq!(rng.bounded_u64(0), 0);
        }
    }

    #[test]
    fn bounded_one_returns_zero() {
        let mut rng = Rng::from_seed(0xabc);
        for _ in 0..100 {
            assert_eq!(rng.bounded_u32(1), 0);
        }
    }

    #[test]
    fn bounded_stays_in_range_for_small_n() {
        let mut rng = Rng::from_seed(0xabc);
        for n in 2..=64_u32 {
            for _ in 0..10_000 {
                let v = rng.bounded_u32(n);
                assert!(v < n, "bounded_u32({n}) returned {v}");
            }
        }
    }

    #[test]
    fn bounded_covers_the_range() {
        let mut rng = Rng::from_seed(0xabc);
        let n = 8_u32;
        let mut counts = [0_usize; 8];
        for _ in 0..100_000 {
            let v = rng.bounded_u32(n);
            counts[v as usize] += 1;
        }
        for (i, &c) in counts.iter().enumerate() {
            assert!(c >= 8_000, "value {i} occurred only {c} times");
        }
    }

    #[test]
    fn f64_unit_is_in_unit_interval() {
        let mut rng = Rng::from_seed(0xabc);
        for _ in 0..100_000 {
            let v = rng.f64_unit();
            assert!((0.0..1.0).contains(&v));
        }
    }

    #[test]
    fn full_jitter_bounds() {
        let mut rng = Rng::from_seed(0xabc);
        let mut saw_min = false;
        let mut saw_max = false;
        for _ in 0..10_000 {
            let v = rng.full_jitter_ms(10);
            assert!(v <= 10);
            if v == 0 {
                saw_min = true;
            }
            if v == 10 {
                saw_max = true;
            }
        }
        assert!(saw_min, "full_jitter_ms(10) never returned 0");
        assert!(saw_max, "full_jitter_ms(10) never returned 10");
        assert_eq!(rng.full_jitter_ms(0), 0);
    }

    #[test]
    fn fill_bytes_empty_consumes_nothing() {
        let mut rng = Rng::from_seed(0xabc);
        let before = rng.state();
        rng.fill_bytes(&mut []);
        assert_eq!(rng.state(), before);
    }

    #[test]
    fn fill_bytes_tail_is_written() {
        let mut a = Rng::from_seed(0xabc);
        let mut b = Rng::from_seed(0xabc);
        let mut buf_a = [0u8; 13];
        let mut buf_b = [0u8; 13];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
        assert!(
            !buf_a.iter().all(|&v| v == 0),
            "fill_bytes produced all zeros"
        );
    }

    proptest! {
        #[test]
        fn prop_bounded_u32_in_range(seed: u64, n in 1..=u32::MAX) {
            let mut rng = Rng::from_seed(seed);
            let v = rng.bounded_u32(n);
            assert!(v < n);
        }

        #[test]
        fn prop_bounded_u64_in_range(seed: u64, n in 1..=u64::MAX) {
            let mut rng = Rng::from_seed(seed);
            let v = rng.bounded_u64(n);
            assert!(v < n);
        }

        #[test]
        fn prop_stream_is_seed_determined(seed: u64, k in 0..=256usize) {
            let mut a = vec![0u8; k];
            let mut b = vec![0u8; k];
            Rng::from_seed(seed).fill_bytes(&mut a);
            Rng::from_seed(seed).fill_bytes(&mut b);
            assert_eq!(a, b);
        }
    }
}
