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
                decode_string(src, tok_span, &mut out.strings, limits.max_string_bytes)?;
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
    reason = "source length is bounded by PolicyLimits::max_source_bytes, which is capped at 65_536"
)]
fn offset_to_u32(offset: usize) -> u32 {
    debug_assert!(u32::try_from(offset).is_ok());
    offset as u32 // it-allow: unchecked-cast reason: source length is bounded by PolicyLimits::max_source_bytes, which is capped at 65_536
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
            // These variants are handled in `lex` before `raw_to_tok` is called.
            Tok::Bang
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

    let mut pos = 0_usize;
    while pos < content.len() {
        if out.len() >= max {
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
                if out.len() >= max {
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
                    if out.len() >= max {
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
    fn too_many_tokens() {
        let mut limits = default_limits();
        limits.max_tokens = 3;
        let out = lex(b"a b c d", &limits);
        assert_eq!(out, Err(LexError::TooManyTokens { max: 3 }));
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
    #[allow(
        clippy::cast_possible_truncation,
        reason = "i % 95 + 32 is always in 0..127, safe to cast"
    )]
    fn lexing_is_deterministic() {
        let mut src = Vec::with_capacity(4096);
        for i in 0usize..4096 {
            src.push((i % 95 + 32) as u8); // it-allow: unchecked-cast reason: i % 95 + 32 is at most 126, safe to cast
        }
        let limits = default_limits();
        let first = lex(&src, &limits);
        for _ in 0..99 {
            assert_eq!(lex(&src, &limits), first);
        }
    }

    proptest! {
        #[test]
        fn prop_lex_never_panics(src in proptest::collection::vec(any::<u8>(), 0..=8192)) {
            let result = lex(&src, &default_limits());
            // The test's purpose is verifying lex never panics; reaching here proves it.
            // lint assertion: the result is always Ok or Err for any byte input.
            assert!(result.is_ok() || result.is_err());
        }
    }
}
