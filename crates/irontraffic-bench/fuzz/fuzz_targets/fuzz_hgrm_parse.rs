// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `LatencyRecorder::read_hgrm`.
//!
//! `.hgrm` is a committed run artifact that any pull request author can edit
//! by hand, so `read_hgrm` is an untrusted-input parser exactly like
//! `CellId::parse` (see `fuzz_cell_id.rs`), and gets the same treatment.
//! Contract: no panic, no hang, no unbounded allocation, regardless of input.
//! On `Ok`, the returned recorder must still satisfy the monotone percentile
//! chain and both of `read_hgrm`'s own bounds.
//!
//! Seed the corpus (`fuzz/corpus/fuzz_hgrm_parse/`, not committed: CI runs
//! this target from an empty corpus, see the module doc in `tests/hist.rs`)
//! with a valid `write_hgrm` output, a file containing `nan` in the `Value`
//! column, and a file whose `TotalCount` column is `18446744073709551615`,
//! so the fuzzer starts adjacent to the three inputs this parser is most
//! likely to get wrong.

use irontraffic_bench::{HIGH_NS, LatencyRecorder, MAX_HGRM_TOTAL_COUNT};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(recorder) = LatencyRecorder::read_hgrm(data) else {
        return;
    };

    let p = recorder.percentiles();
    assert!(p.p50_ns <= p.p90_ns);
    assert!(p.p90_ns <= p.p99_ns);
    assert!(p.p99_ns <= p.p999_ns);
    assert!(p.p999_ns <= p.p9999_ns);
    assert!(p.p9999_ns <= p.max_ns);
    assert!(recorder.len() + recorder.out_of_range() <= MAX_HGRM_TOTAL_COUNT);
    assert!(p.max_ns <= HIGH_NS);
});
