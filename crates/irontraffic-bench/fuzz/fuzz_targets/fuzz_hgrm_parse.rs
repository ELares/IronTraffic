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
//! CI runs this target from an empty `corpus/fuzz_hgrm_parse/` (see the
//! module doc in `tests/hist.rs`: `fuzz/.gitignore` excludes `/corpus`, and
//! the CI job passes no positional corpus directory, so nothing committed
//! reaches an automated run today). `crates/irontraffic-bench/fuzz/seed_corpus/fuzz_hgrm_parse/`
//! holds three committed seeds, the same convention
//! `fuzz_crl_parse.rs`'s own module doc establishes in this crate's sibling
//! `irontraffic-tls`: a valid `write_hgrm` output that itself contains a
//! sample recorded AT `HIGH_NS` (issue #782 BLOCKING 1's own regression
//! case: `write_hgrm`'s own output used to be rejected by `read_hgrm` for
//! exactly this shape of row), a file containing `nan` in the `Value`
//! column, and a file whose `TotalCount` column is `18446744073709551615`,
//! so a LOCAL run starts adjacent to the three inputs this parser is most
//! likely to get wrong:
//! `cargo fuzz run fuzz_hgrm_parse corpus/fuzz_hgrm_parse seed_corpus/fuzz_hgrm_parse -- -runs=200000`
//! (paths relative to `crates/irontraffic-bench/fuzz/`).

use irontraffic_bench::{LatencyRecorder, MAX_HGRM_TOTAL_COUNT, high_ns_ceiling};
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
    // NOT `<= HIGH_NS`: `hdrhistogram` reports `max()` as a bucket's highest
    // equivalent value, and a genuinely in-range sample recorded at or near
    // `HIGH_NS` reads back up to `high_ns_ceiling()`, ABOVE `HIGH_NS` itself.
    // See issue #782 BLOCKING 1 and `high_ns_ceiling`'s own doc: this used to
    // be `<= HIGH_NS` and crashed on a 15 byte input, `6e10 0.5 1 2.0\n`.
    // `high_ns_ceiling()` returns `Result` only because the crate's OWN
    // fixed constants could theoretically change; it cannot fail against
    // TODAY's constants, but this target still bails rather than unwrap, the
    // same as the `read_hgrm` call above.
    let Ok(ceiling) = high_ns_ceiling() else {
        return;
    };
    assert!(p.max_ns <= ceiling);
});
