// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `irontraffic_policy::lex::lex`.
//!
//! Input domain: arbitrary bytes, lexed against `PolicyLimits::defaults()`, the
//! same limits every operator gets unless they override them. This is the
//! substance behind #268's invariant 6, "Lexing never panics for any input,
//! including invalid UTF-8, unterminated literals and 8 KiB of backslashes.
//! Asserted by the fuzz target in `{{itpl-differential-oracle-and-fuzz}}`."
//! `{{itpl-differential-oracle-and-fuzz}}` is a later issue that adds a
//! differential oracle against the `cel` crate; this target is the standing
//! panic-safety fuzz coverage #268 itself requires and does not wait for it.
//!
//! Contract: no panic and no hang, for every input, and whenever `lex` returns
//! `Ok`, the invariants #268 states for `TokenStream` hold: the token count
//! never exceeds `max_tokens`, every `Tok::Str` span lies inside the decoded
//! string arena, every `Tok::Ident` span lies inside the source, and
//! `span.start <= span.end` for every token.

use irontraffic_policy::lex::lex;
use irontraffic_policy::{PolicyLimits, Tok};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = PolicyLimits::defaults();
    let Ok(stream) = lex(data, &limits) else {
        return;
    };

    assert!(stream.toks.len() <= usize::try_from(limits.max_tokens).unwrap_or(usize::MAX));

    for spanned in &stream.toks {
        assert!(spanned.span.start <= spanned.span.end);
        match spanned.tok {
            Tok::Str(span) => {
                assert!(span.start <= span.end);
                assert!(span.end as usize <= stream.strings.len());
            }
            Tok::Ident(span) => {
                assert!(span.start <= span.end);
                assert!(span.end as usize <= data.len());
            }
            _ => {}
        }
    }
});
