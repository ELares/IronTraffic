#![no_main]
//! Fuzz target for `irontraffic_http::h1::H1Parser::parse_request_head`.
//!
//! Input domain: arbitrary bytes, fed directly as the read buffer.
//!
//! Contract: no panic, no hang, no unbounded allocation (bounded by
//! `Limits::CEILING` regardless of `data`). Asserts `consumed <= data.len()`
//! on `Complete`, that every externally reachable span (`method_bytes`, and
//! every field's `field_name`/`field_value`) resolves against the input
//! buffer, and that the input buffer is unchanged after the call (compare a
//! copy), which is what proves the parser never mutates `buf` rather than
//! merely reading its doc comment.
//!
//! `RawHead::target` is deliberately NOT checked here: it is `pub(crate)`
//! (invariant P1 says no code outside this crate may read the raw request
//! target), so it is unreachable from this separate fuzz crate by design.
//! The same span-validity property for `target` is proven in-crate by
//! `h1::parser::tests::prop_never_panics_and_consumed_in_range`, which has
//! `pub(crate)` visibility.

use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::{Limits, ParseStatus};
use libfuzzer_sys::fuzz_target;

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let before = data.to_vec();

    if let Ok(ParseStatus::Complete { value, consumed }) = parser.parse_request_head(data) {
        assert!(consumed <= data.len());
        assert!(!value.method_bytes().is_empty());
        for i in 0..value.field_count() {
            assert!(value.field_name(i).is_some());
            assert!(value.field_value(i).is_some());
        }
    }

    assert_eq!(
        data,
        before.as_slice(),
        "parse_request_head must never mutate its input buffer"
    );
});
