// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITPL lexer.
//!
//! `lex` turns one ITPL expression into a `TokenStream`. String literals are
//! decoded here so no later stage sees an escape sequence.

use crate::limits::PolicyLimits;
use crate::token::{LexError, Span, Spanned, Tok, TokenStream};
use logos::Logos;

/// Lexes one ITPL expression.
///
/// String literals are decoded here, once: no later stage sees an escape sequence.
///
/// `lex` never calls `limits.validate()` and works correctly for any `PolicyLimits`
/// value, including one that would fail validation. Every size bounding field of
/// `PolicyLimits` is a `u32`, and the source length check this function runs before
/// anything else already refuses any `src` longer than `limits.max_source_bytes`, so
/// every byte offset `lex` produces is bounded by `u32::MAX` on its own, regardless of
/// whether the caller validated `limits` first. Skipping `validate()` therefore never
/// risks a panic or a truncated offset here; it only means the admission limits in
/// effect are whatever the caller passed, not the documented hard caps in
/// `PolicyLimits::CAPS`. A caller that wants those caps enforced must call
/// `limits.validate()` itself before calling `lex`.
///
/// # Errors
/// Every `LexError` variant, each naming a source offset.
pub fn lex(src: &[u8], limits: &PolicyLimits) -> Result<TokenStream, LexError> {
    if src.len() > usize::try_from(limits.max_source_bytes).unwrap_or(usize::MAX) {
        return Err(LexError::SourceTooLong {
            len: src.len(),
            max: limits.max_source_bytes,
        });
    }

    let src_str = match core::str::from_utf8(src) {
        Ok(s) => s,
        Err(e) => {
            return Err(LexError::NotUtf8 {
                at: offset_to_u32(e.valid_up_to()),
            });
        }
    };

    let mut out = TokenStream {
        toks: Vec::with_capacity(src.len() >> 2),
        strings: Vec::with_capacity(src.len() >> 2),
    };

    let lexer = RawTok::lexer(src_str).spanned();
    for (token, span) in lexer {
        if out.toks.len() >= usize::try_from(limits.max_tokens).unwrap_or(usize::MAX) {
            return Err(LexError::TooManyTokens {
                max: limits.max_tokens,
            });
        }

        let start = offset_to_u32(span.start);
        let end = offset_to_u32(span.end);
        let tok_span = Span { start, end };

        match token {
            Err(()) => {
                let byte = src.get(span.start).copied().unwrap_or(0);
                if byte == b'"' || byte == b'\'' {
                    return Err(LexError::UnterminatedString { at: start });
                }
                return Err(LexError::UnexpectedByte { at: start, byte });
            }
            Ok(RawTok::RawStr) => {
                let arena_start = out.strings.len();
                decode_string(
                    src,
                    tok_span,
                    &mut out.strings,
                    arena_start,
                    limits.max_string_bytes,
                )?;
                let arena_end = out.strings.len();
                push_tok(
                    &mut out,
                    Tok::Str(Span {
                        start: offset_to_u32(arena_start),
                        end: offset_to_u32(arena_end),
                    }),
                    tok_span,
                );
            }
            Ok(RawTok::RawInt) => {
                let v = parse_i64(src, tok_span).ok_or(LexError::IntOverflow { at: start })?;
                push_tok(&mut out, Tok::Int(v), tok_span);
            }
            Ok(RawTok::Ident) => {
                push_tok(&mut out, keyword_or_ident(src, tok_span), tok_span);
            }
            Ok(punct) => {
                push_tok(&mut out, raw_to_tok(punct), tok_span);
            }
        }
    }

    Ok(out)
}

fn push_tok(out: &mut TokenStream, tok: Tok, span: Span) {
    out.toks.push(Spanned { tok, span });
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "every offset comes from src, and the length check at the top of lex already refuses any src.len() above limits.max_source_bytes, itself a u32, so the offset cannot exceed u32::MAX regardless of whether the caller ran PolicyLimits::validate()"
)]
fn offset_to_u32(offset: usize) -> u32 {
    debug_assert!(u32::try_from(offset).is_ok());
    offset as u32 // it-allow: unchecked-cast reason: bounded by the src.len() check at the top of lex against limits.max_source_bytes, a u32, independent of whether PolicyLimits::validate() ran
}

#[derive(logos::Logos, Clone, Copy, PartialEq, Eq, Debug)]
#[logos(skip r"[ \t\r\n]+")]
enum RawTok {
    #[regex(r#""([^"\\]|\\.)*""#)]
    #[regex(r#"'([^'\\]|\\.)*'"#)]
    RawStr,

    #[regex(r"-?[0-9]+")]
    RawInt,

    #[regex(r"[A-Za-z_][A-Za-z0-9_]*")]
    Ident,

    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token(",")]
    Comma,
    #[token(".")]
    Dot,
    #[token("?")]
    Question,
    #[token(":")]
    Colon,
    #[token("!=")]
    BangEq,
    #[token("!")]
    Bang,
    #[token("&&")]
    AndAnd,
    #[token("||")]
    OrOr,
    #[token("==")]
    EqEq,
    #[token("<=")]
    Le,
    #[token("<")]
    Lt,
    #[token(">=")]
    Ge,
    #[token(">")]
    Gt,
}

fn raw_to_tok(raw: RawTok) -> Tok {
    match raw {
        RawTok::LParen => Tok::LParen,
        RawTok::RParen => Tok::RParen,
        RawTok::LBracket => Tok::LBracket,
        RawTok::RBracket => Tok::RBracket,
        RawTok::Comma => Tok::Comma,
        RawTok::Dot => Tok::Dot,
        RawTok::Question => Tok::Question,
        RawTok::Colon => Tok::Colon,
        RawTok::BangEq => Tok::BangEq,
        RawTok::Bang => Tok::Bang,
        RawTok::AndAnd => Tok::AndAnd,
        RawTok::OrOr => Tok::OrOr,
        RawTok::EqEq => Tok::EqEq,
        RawTok::Le => Tok::Le,
        RawTok::Lt => Tok::Lt,
        RawTok::Ge => Tok::Ge,
        RawTok::Gt => Tok::Gt,
        RawTok::RawStr | RawTok::RawInt | RawTok::Ident => {
            // These variants are handled in `lex` before `raw_to_tok` is called,
            // so this arm is unreachable today. It must stay a hard failure, not
            // fall back to a token: a future `RawTok` variant added without its
            // own `lex` arm would otherwise land here and silently inject a
            // `Bang` (a logical NOT) into the token stream, which in a policy
            // language inverts a predicate instead of erroring loudly.
            unreachable!("RawStr, RawInt and Ident are dispatched inside `lex`, never here") // it-allow: no-panic reason: exhaustive match over RawTok; these three variants are consumed by lex before raw_to_tok runs, so no input, valid or not, can reach this arm
        }
    }
}

fn keyword_or_ident(src: &[u8], span: Span) -> Tok {
    match span.slice(src) {
        Some(b"true") => Tok::Bool(true),
        Some(b"false") => Tok::Bool(false),
        Some(b"null") => Tok::Null,
        Some(b"in") => Tok::In,
        _ => Tok::Ident(span),
    }
}

fn parse_i64(src: &[u8], span: Span) -> Option<i64> {
    let bytes = span.slice(src)?;
    let s = core::str::from_utf8(bytes).ok()?;
    s.parse::<i64>().ok()
}

#[allow(
    clippy::too_many_lines,
    reason = "the escape dispatch table is long by nature and breaking it up would add a helper that is only callable from here"
)]
fn decode_string(
    src: &[u8],
    span: Span,
    out: &mut Vec<u8>,
    arena_start: usize,
    max_string_bytes: u32,
) -> Result<(), LexError> {
    let bytes = span
        .slice(src)
        .ok_or(LexError::UnterminatedString { at: span.start })?;
    if bytes.len() < 2 {
        return Err(LexError::UnterminatedString { at: span.start });
    }

    let content = bytes
        .get(1..bytes.len().saturating_sub(1))
        .ok_or(LexError::UnterminatedString { at: span.start })?;
    let quote_offset = span.start;
    let max = usize::try_from(max_string_bytes).unwrap_or(usize::MAX);

    // `out` is the whole expression's shared string arena, not this literal's
    // own buffer: earlier literals in the same expression have already grown
    // it past `arena_start`. Every length check below must compare the bytes
    // decoded FOR THIS LITERAL (`out.len() - arena_start`), never `out.len()`
    // itself, or `max_string_bytes` silently becomes a cumulative budget over
    // the whole expression instead of a per-literal one.
    let mut pos = 0_usize;
    while pos < content.len() {
        if out.len() - arena_start >= max {
            return Err(LexError::StringTooLong {
                at: quote_offset,
                max: max_string_bytes,
            });
        }

        let byte = content
            .get(pos)
            .copied()
            .ok_or(LexError::UnterminatedString { at: quote_offset })?;

        if byte != b'\\' {
            out.push(byte);
            pos = pos.saturating_add(1);
            continue;
        }

        let slash_offset = quote_offset
            .saturating_add(1)
            .saturating_add(u32::try_from(pos).unwrap_or(u32::MAX));
        let esc = content
            .get(pos.saturating_add(1))
            .copied()
            .ok_or(LexError::BadEscape { at: slash_offset })?;

        match esc {
            b'n' => {
                out.push(b'\n');
                pos = pos.saturating_add(2);
            }
            b'r' => {
                out.push(b'\r');
                pos = pos.saturating_add(2);
            }
            b't' => {
                out.push(b'\t');
                pos = pos.saturating_add(2);
            }
            b'\\' => {
                out.push(b'\\');
                pos = pos.saturating_add(2);
            }
            b'"' => {
                out.push(b'"');
                pos = pos.saturating_add(2);
            }
            b'\'' => {
                out.push(b'\'');
                pos = pos.saturating_add(2);
            }
            b'0' => {
                out.push(0);
                pos = pos.saturating_add(2);
            }
            b'x' => {
                let hi = content.get(pos.saturating_add(2)).copied();
                let lo = content.get(pos.saturating_add(3)).copied();
                let decoded = hex_byte(hi, lo).ok_or(LexError::BadEscape { at: slash_offset })?;
                if out.len() - arena_start >= max {
                    return Err(LexError::StringTooLong {
                        at: quote_offset,
                        max: max_string_bytes,
                    });
                }
                out.push(decoded);
                pos = pos.saturating_add(4);
            }
            b'u' => {
                let a = content.get(pos.saturating_add(2)).copied();
                let b = content.get(pos.saturating_add(3)).copied();
                let c = content.get(pos.saturating_add(4)).copied();
                let d = content.get(pos.saturating_add(5)).copied();
                let code = hex_u16(a, b, c, d).ok_or(LexError::BadEscape { at: slash_offset })?;
                if (0xD800..=0xDFFF).contains(&code) {
                    return Err(LexError::BadUnicodeEscape { at: slash_offset });
                }
                let ch = char::from_u32(u32::from(code))
                    .ok_or(LexError::BadUnicodeEscape { at: slash_offset })?;
                let mut buf = [0_u8; 4];
                let encoded = ch.encode_utf8(&mut buf);
                for decoded_byte in encoded.as_bytes() {
                    if out.len() - arena_start >= max {
                        return Err(LexError::StringTooLong {
                            at: quote_offset,
                            max: max_string_bytes,
                        });
                    }
                    out.push(*decoded_byte);
                }
                pos = pos.saturating_add(6);
            }
            _ => return Err(LexError::BadEscape { at: slash_offset }),
        }
    }

    Ok(())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(hi: Option<u8>, lo: Option<u8>) -> Option<u8> {
    let hi = hex_digit(hi?)?;
    let lo = hex_digit(lo?)?;
    Some((hi << 4) | lo)
}

fn hex_u16(a: Option<u8>, b: Option<u8>, c: Option<u8>, d: Option<u8>) -> Option<u16> {
    let a = u16::from(hex_digit(a?)?);
    let b = u16::from(hex_digit(b?)?);
    let c = u16::from(hex_digit(c?)?);
    let d = u16::from(hex_digit(d?)?);
    Some((a << 12) | (b << 8) | (c << 4) | d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn default_limits() -> PolicyLimits {
        PolicyLimits::defaults()
    }

    fn ident_at(_src: &[u8], start: u32, end: u32) -> Tok {
        Tok::Ident(Span { start, end })
    }

    fn str_at(start: u32, end: u32) -> Tok {
        Tok::Str(Span { start, end })
    }

    #[test]
    fn empty_source_is_empty_stream() {
        let out = lex(b"", &default_limits()).unwrap();
        assert!(out.toks.is_empty());
        assert!(out.strings.is_empty());
    }

    #[test]
    fn whitespace_only_is_empty_stream() {
        let out = lex(b"   \n\t\r  ", &default_limits()).unwrap();
        assert!(out.toks.is_empty());
        assert!(out.strings.is_empty());
    }

    #[test]
    fn simple_predicate_tokens() {
        let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
        let out = lex(src, &default_limits()).unwrap();
        assert_eq!(out.toks.len(), 14);

        assert_eq!(out.toks[0].tok, ident_at(src, 0, 7));
        assert_eq!(out.toks[1].tok, Tok::Dot);
        assert_eq!(out.toks[2].tok, ident_at(src, 8, 12));
        assert_eq!(out.toks[3].tok, Tok::Dot);
        assert_eq!(out.toks[4].tok, ident_at(src, 13, 23));
        assert_eq!(out.toks[5].tok, Tok::LParen);
        assert_eq!(out.toks[6].tok, str_at(0, 4));
        assert_eq!(&out.strings[0..4], b"/v1/");
        assert_eq!(out.toks[7].tok, Tok::RParen);
        assert_eq!(out.toks[8].tok, Tok::AndAnd);
        assert_eq!(out.toks[9].tok, ident_at(src, 35, 42));
        assert_eq!(out.toks[10].tok, Tok::Dot);
        assert_eq!(out.toks[11].tok, ident_at(src, 43, 49));
        assert_eq!(out.toks[12].tok, Tok::EqEq);
        assert_eq!(out.toks[13].tok, str_at(4, 7));
        assert_eq!(&out.strings[4..7], b"GET");
    }

    #[test]
    fn keywords_are_not_identifiers() {
        let out = lex(b"true false null in", &default_limits()).unwrap();
        assert_eq!(out.toks.len(), 4);
        assert_eq!(out.toks[0].tok, Tok::Bool(true));
        assert_eq!(out.toks[1].tok, Tok::Bool(false));
        assert_eq!(out.toks[2].tok, Tok::Null);
        assert_eq!(out.toks[3].tok, Tok::In);
    }

    #[test]
    fn identifier_with_underscore_and_digits() {
        let src = b"_a1";
        let out = lex(src, &default_limits()).unwrap();
        assert_eq!(out.toks.len(), 1);
        assert_eq!(out.toks[0].tok, ident_at(src, 0, 3));
    }

    #[test]
    fn two_char_operators() {
        for (src, expected) in [
            (b"==", Tok::EqEq),
            (b"!=", Tok::BangEq),
            (b"<=", Tok::Le),
            (b">=", Tok::Ge),
            (b"&&", Tok::AndAnd),
            (b"||", Tok::OrOr),
        ] {
            let out = lex(src, &default_limits()).unwrap();
            assert_eq!(out.toks.len(), 1);
            assert_eq!(out.toks[0].tok, expected);
        }

        assert_eq!(
            lex(b"=", &default_limits()),
            Err(LexError::UnexpectedByte { at: 0, byte: b'=' })
        );
    }

    #[test]
    fn single_and_double_quoted_strings_agree() {
        let single = lex(b"'a'", &default_limits()).unwrap();
        let double = lex(b"\"a\"", &default_limits()).unwrap();
        assert_eq!(single.strings, double.strings);
        assert_eq!(single.strings, b"a");
    }

    #[test]
    fn string_escapes() {
        let src = r#""\n\r\t\\\"\0""#;
        let out = lex(src.as_bytes(), &default_limits()).unwrap();
        assert_eq!(out.strings, vec![0x0A, 0x0D, 0x09, 0x5C, 0x22, 0x00]);
    }

    #[test]
    fn hex_escape_full_range() {
        let out = lex(b"\"\\x00\"", &default_limits()).unwrap();
        assert_eq!(out.strings, vec![0]);
        let out = lex(b"\"\\xff\"", &default_limits()).unwrap();
        assert_eq!(out.strings, vec![255]);
    }

    #[test]
    fn unicode_escape() {
        let out = lex(b"\"\\u0041\"", &default_limits()).unwrap();
        assert_eq!(out.strings, b"A");
        let out = lex(b"\"\\u00e9\"", &default_limits()).unwrap();
        assert_eq!(out.strings, vec![0xc3, 0xa9]);
    }

    #[test]
    fn unicode_surrogate_rejected() {
        assert_eq!(
            lex(b"\"\\uD800\"", &default_limits()),
            Err(LexError::BadUnicodeEscape { at: 1 })
        );
    }

    #[test]
    fn bad_escape_rejected() {
        assert_eq!(
            lex(b"\"\\q\"", &default_limits()),
            Err(LexError::BadEscape { at: 1 })
        );
    }

    #[test]
    fn unterminated_string() {
        assert_eq!(
            lex(b"\"abc", &default_limits()),
            Err(LexError::UnterminatedString { at: 0 })
        );
    }

    #[test]
    fn string_with_newline_is_legal() {
        let out = lex(b"\"a\nb\"", &default_limits()).unwrap();
        assert_eq!(out.strings, b"a\nb");
    }

    #[test]
    fn int_max_and_overflow() {
        let out = lex(b"9223372036854775807", &default_limits()).unwrap();
        assert_eq!(out.toks.len(), 1);
        assert_eq!(out.toks[0].tok, Tok::Int(i64::MAX));

        assert_eq!(
            lex(b"9223372036854775808", &default_limits()),
            Err(LexError::IntOverflow { at: 0 })
        );
    }

    #[test]
    fn int_min_literal() {
        let out = lex(b"-9223372036854775808", &default_limits()).unwrap();
        assert_eq!(out.toks.len(), 1);
        assert_eq!(out.toks[0].tok, Tok::Int(i64::MIN));
    }

    #[test]
    fn source_too_long() {
        let mut limits = default_limits();
        limits.max_source_bytes = 4;
        let src = b"12345";
        assert_eq!(
            lex(src, &limits),
            Err(LexError::SourceTooLong {
                len: src.len(),
                max: 4
            })
        );
    }

    #[test]
    fn source_length_exactly_at_limit_is_accepted() {
        // #268 edge case 3: "Source at exactly max_source_bytes. Accepted;
        // one byte more is SourceTooLong." `source_too_long` above pins only
        // the second half.
        let mut limits = default_limits();
        limits.max_source_bytes = 4;
        let src = b"1234";
        let out = lex(src, &limits).unwrap();
        assert_eq!(out.toks.len(), 1);
    }

    #[test]
    fn too_many_tokens() {
        let mut limits = default_limits();
        limits.max_tokens = 3;
        let out = lex(b"a b c d", &limits);
        assert_eq!(out, Err(LexError::TooManyTokens { max: 3 }));
    }

    #[test]
    fn token_count_exactly_at_limit_is_accepted() {
        let mut limits = default_limits();
        limits.max_tokens = 3;
        let out = lex(b"a b c", &limits).unwrap();
        assert_eq!(out.toks.len(), 3);
    }

    #[test]
    fn string_too_long() {
        let mut limits = default_limits();
        limits.max_string_bytes = 2;
        assert_eq!(
            lex(b"\"abc\"", &limits),
            Err(LexError::StringTooLong { at: 0, max: 2 })
        );
    }

    #[test]
    fn string_too_long_is_per_literal_not_cumulative_across_the_expression() {
        // Test `string_too_long` above lexes a single literal into an empty
        // arena, where "this literal's decoded length" and "the arena's
        // running total" are indistinguishable. Four 300-byte literals at the
        // default 1024-byte cap must all succeed: 300 < 1024 four times over,
        // and the arena's total (1200) is irrelevant to any one literal's cap.
        let limits = default_limits();
        assert_eq!(limits.max_string_bytes, 1024);
        let literal = format!("\"{}\"", "a".repeat(300));
        let src = format!("{literal} && {literal} && {literal} && {literal}");
        let out = lex(src.as_bytes(), &limits).unwrap();
        assert_eq!(out.strings.len(), 1200);
    }

    #[test]
    fn string_too_long_still_rejects_the_offending_literal_after_an_earlier_short_one() {
        // The per-literal fix must not stop enforcing the cap; it must only
        // stop enforcing it cumulatively. A short first literal followed by a
        // literal that is itself over the cap must still fail, even though
        // the arena's running total at the point of failure is small.
        let mut limits = default_limits();
        limits.max_string_bytes = 300;
        let short = "\"ok\"";
        let long = format!("\"{}\"", "a".repeat(301));
        let src = format!("{short} && {long}");
        assert!(matches!(
            lex(src.as_bytes(), &limits),
            Err(LexError::StringTooLong { max: 300, .. })
        ));
    }

    #[test]
    fn string_length_exactly_at_limit_is_accepted() {
        // #268 edge case: "a 4 KiB string literal with max_string_bytes =
        // 1024 gives StringTooLong after 1,024 decoded bytes", which only
        // pins the reject side. The accept side, exactly at the cap, is
        // untested without this.
        let mut limits = default_limits();
        limits.max_string_bytes = 2;
        let out = lex(b"\"ab\"", &limits).unwrap();
        assert_eq!(out.strings, b"ab");
    }

    #[test]
    fn not_utf8_source() {
        assert_eq!(
            lex(&[0xff, 0xfe], &default_limits()),
            Err(LexError::NotUtf8 { at: 0 })
        );
    }

    #[test]
    fn comment_syntax_is_rejected() {
        assert_eq!(
            lex(b"// x", &default_limits()),
            Err(LexError::UnexpectedByte { at: 0, byte: b'/' })
        );
        assert_eq!(
            lex(b"# x", &default_limits()),
            Err(LexError::UnexpectedByte { at: 0, byte: b'#' })
        );
    }

    #[test]
    fn lexing_is_deterministic() {
        // Built from valid ITPL, not a cycling run of printable ASCII that
        // opens a string literal and never closes it: the old source aborted
        // at the first backslash and compared `Err(BadEscape { .. })` to
        // itself 100 times, which never exercises `TokenStream`'s
        // `PartialEq` on an `Ok` value (vector ordering, arena contents, span
        // stability). A real predicate is repeated whole (never truncated
        // mid-token, which could cut a string literal or a `&&`/`||` pair in
        // half) and the remainder padded to exactly 4096 bytes with `!`: a
        // run of `!` bytes not followed by `=` always lexes as that many
        // separate, valid `Bang` tokens, one per byte, so the padding cannot
        // land mid-token either.
        let unit = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\" || ";
        let mut src = Vec::with_capacity(4096);
        while src.len() + unit.len() <= 4096 {
            src.extend_from_slice(unit);
        }
        src.resize(4096, b'!');
        assert_eq!(src.len(), 4096);

        let limits = default_limits();
        let first = lex(&src, &limits);
        assert!(first.is_ok(), "expected valid ITPL to lex, got {first:?}");
        for _ in 0..99 {
            assert_eq!(lex(&src, &limits), first);
        }
    }

    proptest! {
        #[test]
        fn prop_lex_never_panics_on_itpl_shaped_input(
            src in "[A-Za-z0-9_ \t\r\n.,()\\[\\]?:!&|=<>'\"\\\\-]{0,512}"
        ) {
            // A uniform random byte vector is essentially never valid UTF-8,
            // so it dies at the UTF-8 gate before a single token is scanned
            // and exercises nothing past it (see the sibling property below,
            // which covers that path on purpose). This alphabet is drawn
            // from ITPL's own token set, identifier and digit characters,
            // whitespace, every punctuation and operator byte the grammar
            // defines, and the quote and backslash bytes that drive string
            // decoding, so generated inputs actually reach `decode_string`,
            // `keyword_or_ident`, `parse_i64` and the punctuation dispatch.
            let limits = default_limits();
            let src_bytes = src.into_bytes();
            if let Ok(stream) = lex(&src_bytes, &limits) {
                prop_assert!(stream.toks.len() <= usize::try_from(limits.max_tokens).unwrap_or(usize::MAX));
                for spanned in &stream.toks {
                    prop_assert!(spanned.span.start <= spanned.span.end);
                    match spanned.tok {
                        Tok::Str(span) => {
                            prop_assert!(span.start <= span.end);
                            prop_assert!(span.end as usize <= stream.strings.len());
                        }
                        Tok::Ident(span) => {
                            prop_assert!(span.start <= span.end);
                            prop_assert!(span.end as usize <= src_bytes.len());
                        }
                        _ => {}
                    }
                }
            }
        }

        #[test]
        fn prop_lex_never_panics_on_arbitrary_bytes(
            src in proptest::collection::vec(any::<u8>(), 0..=8192)
        ) {
            // Kept alongside the ITPL-shaped property above: this is the one
            // that actually reaches invalid UTF-8, embedded NUL, and other
            // byte shapes no ITPL-shaped generator produces. It asserts the
            // same real invariants, not merely `is_ok() || is_err()`, on the
            // rare input that clears the UTF-8 gate.
            let limits = default_limits();
            if let Ok(stream) = lex(&src, &limits) {
                prop_assert!(stream.toks.len() <= usize::try_from(limits.max_tokens).unwrap_or(usize::MAX));
                for spanned in &stream.toks {
                    prop_assert!(spanned.span.start <= spanned.span.end);
                    match spanned.tok {
                        Tok::Str(span) => {
                            prop_assert!(span.start <= span.end);
                            prop_assert!(span.end as usize <= stream.strings.len());
                        }
                        Tok::Ident(span) => {
                            prop_assert!(span.start <= span.end);
                            prop_assert!(span.end as usize <= src.len());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
