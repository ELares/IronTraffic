#![no_main]
//! Fuzz target for `irontraffic_http::path::NormalizedPath::parse_into`.
//!
//! Input domain: the first byte of `data` selects one of the eight `PathPolicy`
//! combinations (`EncodedDot` x `EncodedSlash` x `merge_slashes`, 2 x 2 x 2); the
//! remainder is the raw origin-form target passed to `parse_into` unchanged.
//! `data` shorter than one byte is a no-op.
//!
//! Contract: must not panic, must not hang, and must not allocate proportional to
//! anything other than the input length. `tests/alloc_gate.rs` carries the static
//! proof that `parse_into`'s call graph allocates at most once per call; a counting
//! allocator cannot be built here at all, because `GlobalAlloc` is `unsafe trait`
//! and this crate denies `unsafe_code` with no exception. On `Ok`, this target
//! additionally asserts the same three invariants the crate's own property tests
//! pin, so the fuzzer is checking behaviour and not merely the absence of a panic:
//! P-SHRINK (the output is never longer than the input), P-NO-TRAVERSAL (the
//! output starts with `/` and no segment is exactly `.` or `..`), and
//! P-IDEMPOTENT (re-normalizing the output under the same policy is a no-op).

use bytes::BytesMut;
use irontraffic_http::Limits;
use irontraffic_http::path::{EncodedDot, EncodedSlash, NormalizedPath, PathPolicy};
use libfuzzer_sys::fuzz_target;

fn policy_from_byte(b: u8) -> PathPolicy {
    PathPolicy {
        encoded_dot: if b & 0b001 == 0 {
            EncodedDot::Reject
        } else {
            EncodedDot::Keep
        },
        encoded_slash: if b & 0b010 == 0 {
            EncodedSlash::Reject
        } else {
            EncodedSlash::Keep
        },
        merge_slashes: b & 0b100 != 0,
    }
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let Some((&policy_byte, target)) = data.split_first() else {
        return;
    };
    let policy = policy_from_byte(policy_byte);
    let limits = Limits::DEFAULT.clamped();

    let mut out = BytesMut::with_capacity(target.len());
    let Ok((path, _query)) = NormalizedPath::parse_into(target, &policy, &limits, &mut out) else {
        return;
    };

    // P-SHRINK.
    assert!(path.as_bytes().len() <= target.len());

    // P-NO-TRAVERSAL.
    assert_eq!(path.as_bytes().first(), Some(&b'/'));
    for seg in path.segments() {
        assert_ne!(seg, b"..");
        assert_ne!(seg, b".");
    }

    // P-IDEMPOTENT: re-normalizing the output under the SAME policy must be a
    // no-op and must not newly fail, since the output is already in normal form.
    let first = path.as_bytes().to_vec();
    let mut out2 = BytesMut::with_capacity(first.len());
    let reparsed = NormalizedPath::parse_into(&first, &policy, &limits, &mut out2);
    assert!(
        reparsed.is_ok(),
        "re-parsing already-normalized output must not fail"
    );
    if let Ok((second, _)) = reparsed {
        assert_eq!(second.as_bytes(), first.as_slice());
    }
});
