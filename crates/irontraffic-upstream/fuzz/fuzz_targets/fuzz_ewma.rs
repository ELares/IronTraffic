// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `peak_ewma_step`. Contract, per invariant I-S6: the
//! function must sanitise ANY `u64` input word, not only ones this crate's own
//! `pack` could have produced, and must never panic. Input is an initial
//! packed word plus up to 256 `(sample, now_ms)` steps applied in order, so
//! this also exercises samples arriving on top of an already-corrupt word
//! rather than only a fresh one.
//!
//! Contract: never panics; after every step the returned word's `f32` half is
//! finite and in `[MIN_RTT_MS, MAX_RTT_MS]` (I-S1). `peak_ewma_step` itself
//! allocates nothing; the `Vec` this target decodes its input into is the
//! fuzzing harness materialising its input, not the function under test.

use irontraffic_upstream::{EwmaCfg, MAX_RTT_MS, MIN_RTT_MS, peak_ewma_step, unpack};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u64, Vec<(f32, u32)>)| {
    let (initial_word, samples) = input;
    let cfg = EwmaCfg::default();
    let mut word = initial_word;
    for (sample, now_ms) in samples.into_iter().take(256) {
        word = peak_ewma_step(word, sample, now_ms, &cfg);
        let (est, _) = unpack(word);
        assert!(
            est.is_finite(),
            "peak_ewma_step produced a non-finite estimate: {est}"
        );
        assert!(
            (MIN_RTT_MS..=MAX_RTT_MS).contains(&est),
            "peak_ewma_step produced {est}, outside [{MIN_RTT_MS}, {MAX_RTT_MS}]"
        );
    }
});
