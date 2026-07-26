#![no_main]
//! Fuzz target for `irontraffic_http::authority::Authority::parse_into`.
//!
//! Input domain: `data` shorter than one byte is a no-op. Otherwise the
//! first byte selects the `Scheme` (even is `Http`, odd is `Https`); the
//! remaining bytes are the candidate authority.
//!
//! Contract: must not panic, must not hang, and must not allocate more than
//! the one `split_off`/`freeze` per successful call (the same claim
//! `tests/alloc_gate.rs` proves statically for every input, here exercised
//! over inputs libFuzzer chooses rather than ones a human wrote). Asserts
//! the same properties `authority::tests::prop_parse_never_panics` asserts,
//! so this checks the invariants and not merely the absence of a panic: on
//! `Ok`, the host is non-empty, every byte is below `0x80`, no byte is an
//! uppercase ASCII letter, `port()` is never `Some(scheme.default_port())`,
//! and re-parsing the bytes `write_to` produces yields an equal value (the
//! idempotence property a mutation in the bracket or port handling breaks).

use bytes::BytesMut;
use irontraffic_http::authority::Authority;
use irontraffic_http::{Limits, Scheme};
use libfuzzer_sys::fuzz_target;

fn scheme_from_byte(b: u8) -> Scheme {
    if b % 2 == 0 {
        Scheme::Http
    } else {
        Scheme::Https
    }
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let Some((&scheme_byte, raw)) = data.split_first() else {
        return;
    };
    let scheme = scheme_from_byte(scheme_byte);
    let limits = Limits::DEFAULT.clamped();

    let mut out = BytesMut::new();
    let Ok(authority) = Authority::parse_into(raw, scheme, &limits, &mut out) else {
        return;
    };

    assert!(!authority.host().is_empty());
    assert!(authority.host().iter().all(|b| *b < 0x80));
    assert!(authority.host().iter().all(|b| !b.is_ascii_uppercase()));
    assert_ne!(authority.port(), Some(scheme.default_port()));

    let mut written = BytesMut::new();
    authority.write_to(&mut written);
    let mut reparse_buf = BytesMut::new();
    let reparsed = Authority::parse_into(&written, scheme, &limits, &mut reparse_buf);
    assert!(
        reparsed.is_ok(),
        "re-parsing write_to's own output for a value that already parsed once must succeed"
    );
    if let Ok(reparsed) = reparsed {
        assert_eq!(reparsed, authority);
    }
});
