// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `scan_head`, the hand-written HTTP head parser reading
//! bytes off a socket: the single most panic-prone shape in this repository,
//! and this crate opens two listeners onto it.
//!
//! Contract: never panics, never hangs, never reads out of bounds. On
//! `Ok(Some(intent))`, `intent.head_len <= data.len()`,
//! `intent.content_length <= 16_777_216`, and
//! `intent.delay_us.map_or(true, |d| d <= 5_000_000)`; calling `scan_head`
//! again on `&data[..intent.head_len]` must yield the same intent, which
//! pins that the parser does not depend on bytes past the head it claimed to
//! consume. Additionally, over a bounded sample of prefix lengths, the
//! answer for any prefix of `data` must be `Ok(None)` or exactly the
//! terminal answer the full input gives: a parser whose answer depends on
//! how a client chunked its writes behaves differently for a fuzzer than for
//! a real client, which is precisely the gap a `memchr`-based resumed scan
//! must not open.
//!
//! **The `>= 16 KiB` (`HEAD_CAP`) regime is exercised on a GUARANTEED
//! cadence, never gated on `data.len()` (mirrors #601's
//! `crates/irontraffic-http/fuzz/fuzz_targets/fuzz_forwarded.rs`).**
//! libFuzzer defaults to `-max_len=4096` with no corpus and no explicit
//! override, and even an explicitly raised `-max_len` only grows its length
//! schedule gradually: measured directly, `-runs=500000` with no `-max_len`
//! topped out at an input of 5,164 bytes, and `-max_len=20000` over the same
//! run count still topped out at 15 bytes past that (`L: 15/5164`, i.e. no
//! new coverage from the extra length). Neither the issue's own acceptance
//! command nor CI's fuzz-smoke lane (`-max_total_time=60 -timeout=10`, no
//! `-max_len`) would otherwise ever generate an input anywhere near
//! `HEAD_CAP`, so `ScanError::HeadTooLarge` -- a bound this issue makes a
//! contract -- would never be reached by the fuzzer at all. Building the
//! large input locally instead of waiting for libFuzzer to grow one means
//! this regime is exercised on every `GUARD_PERIOD`-th call, independent of
//! whatever length libFuzzer happens to pick that run.

use irontraffic_origin::serve::{ScanError, scan_head};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

/// The request head cap `scan_head` enforces. Kept as a local literal
/// (rather than importing `irontraffic_origin::serve::HEAD_CAP`, which is
/// not part of this crate's public surface) so this guard's own contract
/// reads independently of the library's internal constant; the discrepancy
/// test below (`terminator_beyond_cap` vs `terminator_at_the_cap`) would
/// itself fail if the two ever drifted apart.
const HEAD_CAP: usize = 16_384;

/// One byte past `HEAD_CAP`, and safely clear of it: long enough that the
/// terminator this guard places at the very end can never land within the
/// first `HEAD_CAP` bytes.
const GUARD_LEN: usize = 17_477;

/// The guard input is built and exercised once every this many calls, per
/// `fuzz_forwarded.rs`'s own `GUARD_PERIOD` doc comment: often enough that
/// even a short smoke run reaches it many times over, without paying its
/// cost on every single one of potentially millions of calls.
const GUARD_PERIOD: u64 = 64;

/// Builds a `GUARD_LEN`-byte buffer of `filler` bytes with `b"\r\n\r\n"`
/// spliced in at `terminator_at`, which must leave room for all four bytes.
/// `filler` must not be `b'\r'` or `b'\n'`, so the buffer's own filler bytes
/// never accidentally form a second, earlier terminator.
fn buffer_with_terminator_at(filler: u8, terminator_at: usize) -> Vec<u8> {
    debug_assert!(!matches!(filler, b'\r' | b'\n'));
    let mut buf = vec![filler; GUARD_LEN];
    if let Some(slot) = buf.get_mut(terminator_at..terminator_at.saturating_add(4)) {
        slot.copy_from_slice(b"\r\n\r\n");
    }
    buf
}

/// A `data`-seeded filler byte guaranteed not to be `\r` or `\n`, so guard
/// inputs built from it carry only ONE real terminator, at the position this
/// guard places it, while still varying with `data` for libFuzzer's own
/// coverage feedback.
fn filler_byte(data: &[u8]) -> u8 {
    match data.first().copied().unwrap_or(b'a') {
        b'\r' | b'\n' => b'a',
        other => other,
    }
}

fuzz_target!(|data: &[u8]| {
    let result = scan_head(data);

    if let Ok(Some(intent)) = result {
        assert!(intent.head_len <= data.len());
        assert!(intent.content_length <= 16_777_216);
        assert!(intent.delay_us.is_none_or(|delay| delay <= 5_000_000));

        let exact_head = data.get(..intent.head_len).unwrap_or(data);
        let repeat = scan_head(exact_head);
        assert_eq!(
            repeat,
            Ok(Some(intent)),
            "scan_head must not depend on bytes past the head it claimed to consume"
        );
    }

    for &n in &sample_prefix_lengths(data.len()) {
        let prefix = data.get(..n).unwrap_or(data);
        let prefix_result = scan_head(prefix);
        if prefix_result != Ok(None) {
            assert_eq!(
                prefix_result, result,
                "a prefix's answer must be Ok(None) or exactly the full input's terminal answer"
            );
        }
    }

    // The >= HEAD_CAP guard (see this file's own module doc comment for why
    // it cannot rely on `data` growing large on its own).
    static GUARD_COUNTER: AtomicU64 = AtomicU64::new(0);
    let call_index = GUARD_COUNTER.fetch_add(1, Ordering::Relaxed);
    if call_index.is_multiple_of(GUARD_PERIOD) {
        let filler = filler_byte(data);

        // Case A: no terminator anywhere in the first HEAD_CAP bytes; the
        // only one in the whole GUARD_LEN-byte buffer sits at the very end.
        // This is the exact crash reproduction that motivated this guard:
        // `scan_head` must answer `HeadTooLarge` regardless of what a
        // terminator located past the cap would have parsed as, and must
        // agree with its own answer on the cap-length prefix of this same
        // buffer.
        let beyond_cap = buffer_with_terminator_at(filler, GUARD_LEN - 4);
        let beyond_cap_result = scan_head(&beyond_cap);
        assert_eq!(
            beyond_cap_result,
            Err(ScanError::HeadTooLarge),
            "a {GUARD_LEN}-byte input with no terminator in its first {HEAD_CAP} bytes must be HeadTooLarge"
        );
        let capped_prefix = beyond_cap.get(..HEAD_CAP).unwrap_or(&beyond_cap);
        assert_eq!(
            scan_head(capped_prefix),
            beyond_cap_result,
            "the HEAD_CAP-length prefix of a too-large head must agree with the full buffer's answer"
        );

        // Case B: a terminator landing exactly at the cap boundary (the
        // last four bytes of the first HEAD_CAP bytes) must still be
        // accepted: the fix for case A must not overcorrect into rejecting
        // every long buffer regardless of where its terminator falls.
        let at_cap = buffer_with_terminator_at(filler, HEAD_CAP - 4);
        let at_cap_result = scan_head(&at_cap);
        assert!(
            matches!(at_cap_result, Ok(Some(intent)) if intent.head_len == HEAD_CAP),
            "a terminator exactly at the HEAD_CAP boundary must be accepted, got {at_cap_result:?}"
        );
    }
});

/// Sample lengths spread evenly across `data`, deduplicated: fuzzing runs
/// this target millions of times, so the incremental check below samples a
/// bounded number of prefixes rather than every one of `data.len()` of them.
fn sample_prefix_lengths(len: usize) -> [usize; 17] {
    let mut lengths = [0usize; 17];
    for (step, slot) in lengths.iter_mut().enumerate() {
        *slot = len.saturating_mul(step) / 16;
    }
    lengths
}
