#![no_main]
//! Differential fuzz target: `irontraffic_http::h1::H1Parser::parse_request_head`
//! against `httparse::Request::parse` on the same input.
//!
//! `httparse` is a dev/fuzz-only dependency (`fuzz/Cargo.toml`); it MUST NOT
//! be added to `crates/irontraffic-http/Cargo.toml`. It is a good, fast
//! tokenizer that deliberately tolerates input this crate must refuse (a
//! bare LF terminator, obs-fold), so it is used here as an oracle for "are we
//! ever LAXER than a well-regarded parser", never as the library's own
//! framing decision maker.
//!
//! **Fails the case if we accept and `httparse` rejects.** The reverse
//! (`httparse` accepts, we refuse) is expected and fine: this parser is
//! strictly stricter on bare CR/LF, obs-fold, whitespace before the colon,
//! and the empty-field-name case (HAProxy CVE-2023-25725), none of which
//! `httparse` refuses by design. When BOTH accept, the method bytes, the
//! version, and the field count must agree, so a divergence in WHAT was
//! parsed (not merely in whether it parsed) is also caught.
//!
//! One narrower exception to "fails if we accept and httparse rejects":
//! `httparse` validates the request-target's own byte class (rejecting a
//! control byte or a non-ASCII byte there), and this crate's own issue is
//! explicit that this parser must NOT parse the target beyond the `#` check,
//! because target-byte safety is validated exactly once, later, by
//! `NormalizedPath::parse_into` (invariant P1). A target byte outside
//! `httparse`'s accepted class is therefore a second, deliberate one-way
//! divergence, checked for directly against the raw input rather than
//! assumed; anything else that makes `httparse` reject still fails the case.
//!
//! `RawHead::target` is not compared: it has no public accessor (invariant
//! P1), so it is unreachable from this separate fuzz crate. Comparing the
//! request path against `httparse`'s `req.path` is therefore out of reach
//! here by the same design that keeps the raw target from ever being read
//! outside this crate. `target_slice_of`, below, does not work around that:
//! it recomputes the target span from `data`, which this fuzz harness
//! already holds in full, the same way `httparse`'s own `req.path` does.

use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::{Limits, ParseStatus, WireVersion};
use libfuzzer_sys::fuzz_target;

/// Is `b` a byte `httparse` accepts inside a request-target? Measured directly
/// against `httparse` 1.x by feeding it `GET <byte> HTTP/1.0\r\n\r\n` for every
/// byte value: it accepts HTAB (0x09) and 0x21..=0x7E, and rejects everything
/// else (0x00..=0x08, 0x0B..=0x1F, 0x7F..=0xFF). Used only to recognize the one
/// documented, deliberate divergence below; this is not a claim about what any
/// other version of `httparse` does.
fn httparse_accepts_as_target_byte(b: u8) -> bool {
    b == 0x09 || (0x21..=0x7e).contains(&b)
}

/// The request-target slice of a well-formed `METHOD SP TARGET SP VERSION`
/// request line, found the same mechanical way `H1Parser` itself does (split
/// on the first two SP bytes), but computed independently here from the raw
/// `data` this fuzz target already holds in full. This is NOT a use of
/// `RawHead::target`, which has no accessor outside the crate by design
/// (invariant P1); it is the fuzz harness reading its own input.
fn target_slice_of(data: &[u8]) -> Option<&[u8]> {
    let first_sp = data.iter().position(|&b| b == b' ')?;
    let after_method = data.get(first_sp.checked_add(1)?..)?;
    let second_sp = after_method.iter().position(|&b| b == b' ')?;
    after_method.get(..second_sp)
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let ours = parser.parse_request_head(data);

    let mut header_storage = [httparse::EMPTY_HEADER; 128];
    let mut theirs = httparse::Request::new(&mut header_storage);
    let their_result = theirs.parse(data);

    match (&ours, &their_result) {
        (Ok(ParseStatus::Complete { .. }), Err(_)) => {
            // One documented, deliberate exception (issue #34's own "Do NOT
            // parse the request target beyond the `#` check" and invariant
            // P1: target-byte safety is validated exactly once, later, by
            // `NormalizedPath::parse_into`, issue #29). `httparse` validates
            // the target's byte class itself and rejects a control byte or a
            // non-ASCII byte there; this parser is required not to duplicate
            // that check here, so it will always accept some inputs httparse
            // refuses for that reason alone, forever, no matter how this
            // parser is written. That is a different thing from being
            // laxer on the request line's own grammar (a bare LF, an extra
            // SP, a malformed method), which this assertion still catches:
            // the exception fires only when the target itself carries a byte
            // outside httparse's accepted class, not merely because httparse
            // rejected for some other reason.
            let target_is_the_reason = target_slice_of(data)
                .is_some_and(|t| t.iter().any(|&b| !httparse_accepts_as_target_byte(b)));
            assert!(
                target_is_the_reason,
                "we accepted input httparse rejected as {their_result:?}: {data:?}"
            );
        }
        (Ok(ParseStatus::Complete { value, .. }), Ok(httparse::Status::Complete(_))) => {
            if let Some(their_method) = theirs.method {
                assert_eq!(
                    value.method_bytes(),
                    their_method.as_bytes(),
                    "method disagreement for {data:?}"
                );
            }
            if let Some(their_version) = theirs.version {
                let our_version_byte = u8::from(value.version == WireVersion::Http11);
                assert_eq!(
                    their_version, our_version_byte,
                    "version disagreement for {data:?}"
                );
            }
            assert_eq!(
                value.field_count(),
                theirs.headers.len(),
                "field count disagreement for {data:?}"
            );
        }
        _ => {}
    }
});
