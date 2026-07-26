#![no_main]
//! Fuzz target for `irontraffic_http::forwarded::ForwardedChain::parse_into`.
//!
//! Input domain: `data` is split on the `0xFF` delimiter byte into segments;
//! the first up to four segments become `Forwarded` field line values and
//! the next up to four segments become `X-Forwarded-For` field line values.
//! No `X-Forwarded-Proto` values are generated: its own last-token-wins
//! logic is a small, separately unit-tested corner of the parse, and
//! dedicating one of a bounded number of fuzz segments to a third family
//! would starve the two families (the element and byte caps) that carry the
//! actual denial-of-service risk this target exists to catch.
//!
//! Contract: must not panic, must not hang, must not allocate more than a
//! bounded amount (`chain.len() <= 32` on `Ok`, the same bound
//! `forwarded::tests::prop_bounded_and_total` asserts under proptest, here
//! exercised over inputs libFuzzer chooses rather than ones a human wrote),
//! and must not be quadratic in its input size: a 64 KiB input must complete
//! in under 10 ms.

use bytes::BytesMut;
use irontraffic_http::Limits;
use irontraffic_http::forwarded::ForwardedChain;
use libfuzzer_sys::fuzz_target;

/// The number of `0xFF`-delimited segments handed to each of the two
/// generated field families.
const MAX_SEGMENTS_PER_FAMILY: usize = 4;

/// A 64 KiB input must complete the whole parse in under this many
/// milliseconds. Chosen loosely (this is a fuzz-time sanity guard against an
/// accidental quadratic blowup, not a tight performance budget like
/// `benches/http_hot.rs`'s), so ordinary scheduler jitter on a shared CI
/// runner cannot make an honestly-linear parse flake.
const MAX_MILLIS_FOR_64_KIB: u128 = 10;

/// The input size, in bytes, at or above which the timing assertion applies.
const TIMING_GUARD_THRESHOLD: usize = 65_536;

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let segments: Vec<&[u8]> = data.split(|&b| b == 0xFF).collect();
    let forwarded_values: Vec<&[u8]> = segments
        .iter()
        .copied()
        .take(MAX_SEGMENTS_PER_FAMILY)
        .collect();
    let xff_values: Vec<&[u8]> = segments
        .iter()
        .copied()
        .skip(MAX_SEGMENTS_PER_FAMILY)
        .take(MAX_SEGMENTS_PER_FAMILY)
        .collect();

    let limits = Limits::DEFAULT.clamped();
    let mut out = BytesMut::new();

    // This is the one place in this crate where reading a clock is
    // permitted: a fuzz-only quadratic-time guard, never library code.
    let start = std::time::Instant::now(); // it-allow: determinism-seam reason: fuzz-only quadratic-time guard, not library code
    let result = ForwardedChain::parse_into(
        forwarded_values.into_iter(),
        xff_values.into_iter(),
        core::iter::empty(),
        &limits,
        &mut out,
    );
    let elapsed = start.elapsed();

    if let Ok(chain) = result {
        assert!(chain.len() <= 32, "chain exceeded the element cap: {}", chain.len());
    }

    if data.len() >= TIMING_GUARD_THRESHOLD {
        assert!(
            elapsed.as_millis() < MAX_MILLIS_FOR_64_KIB,
            "a {}-byte input took {elapsed:?}, expected under {MAX_MILLIS_FOR_64_KIB} ms",
            data.len()
        );
    }
});
