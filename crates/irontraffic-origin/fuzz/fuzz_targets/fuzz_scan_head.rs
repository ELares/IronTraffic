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

use irontraffic_origin::serve::scan_head;
use libfuzzer_sys::fuzz_target;

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
});
