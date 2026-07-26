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
//! `RawHead::target` is not compared: it has no public accessor (invariant
//! P1), so it is unreachable from this separate fuzz crate. Comparing the
//! request path against `httparse`'s `req.path` is therefore out of reach
//! here by the same design that keeps the raw target from ever being read
//! outside this crate.

use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::{Limits, ParseStatus, WireVersion};
use libfuzzer_sys::fuzz_target;

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let ours = parser.parse_request_head(data);

    let mut header_storage = [httparse::EMPTY_HEADER; 128];
    let mut theirs = httparse::Request::new(&mut header_storage);
    let their_result = theirs.parse(data);

    match (&ours, &their_result) {
        (Ok(ParseStatus::Complete { .. }), Err(_)) => {
            assert!(
                false,
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
