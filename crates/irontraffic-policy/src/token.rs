// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tokens and spans for the ITPL lexer.

/// Byte range in the source, for error reporting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    /// Offset of the first byte.
    pub start: u32,
    /// Offset one past the last byte.
    pub end: u32,
}

/// One token plus where it came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Spanned {
    /// The token.
    pub tok: Tok,
    /// Its extent in the source.
    pub span: Span,
}

/// The token alphabet. String and identifier payloads are ranges into the source or
/// into the decoded-string arena, never owned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tok {
    /// An identifier, as a source range.
    Ident(Span),
    /// An integer literal, already parsed.
    Int(i64),
    /// A string literal, as a range into the decoded-string arena.
    Str(Span),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `?`
    Question,
    /// `:`
    Colon,
    /// `!`
    Bang,
    /// `&&`
    AndAnd,
    /// `||`
    OrOr,
    /// `==`
    EqEq,
    /// `!=`
    BangEq,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `in`
    In,
}

/// Everything the lexer produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenStream {
    /// Tokens in source order.
    pub toks: Vec<Spanned>,
    /// Decoded string-literal bytes, referenced by `Tok::Str` spans. Decoding happens
    /// once, here, so no later stage ever sees an escape sequence.
    pub strings: Vec<u8>,
}

/// A lexer error, naming a source offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LexError {
    /// A byte that starts no token.
    UnexpectedByte {
        /// Source offset of the byte.
        at: u32,
        /// The byte that starts no token.
        byte: u8,
    },
    /// A string literal without a closing quote.
    UnterminatedString {
        /// Source offset of the opening quote.
        at: u32,
    },
    /// An escape sequence that is not in the grammar.
    BadEscape {
        /// Source offset of the backslash.
        at: u32,
    },
    /// A `\u` escape naming a surrogate or a value above U+10FFFF.
    BadUnicodeEscape {
        /// Source offset of the backslash.
        at: u32,
    },
    /// An integer literal that does not fit in `i64`.
    IntOverflow {
        /// Source offset of the integer.
        at: u32,
    },
    /// The source is longer than `PolicyLimits::max_source_bytes`.
    SourceTooLong {
        /// Length of the source.
        len: usize,
        /// Maximum allowed length.
        max: u32,
    },
    /// More tokens than `PolicyLimits::max_tokens`.
    TooManyTokens {
        /// Maximum allowed tokens.
        max: u32,
    },
    /// A string literal longer than `PolicyLimits::max_string_bytes`.
    StringTooLong {
        /// Source offset of the opening quote.
        at: u32,
        /// Maximum allowed decoded bytes.
        max: u32,
    },
    /// The source is not valid UTF-8.
    NotUtf8 {
        /// Source offset of the first invalid byte.
        at: u32,
    },
}

impl Span {
    /// A span covering nothing at `at`.
    #[must_use]
    pub const fn empty(at: u32) -> Span {
        Span { start: at, end: at }
    }

    /// Length in bytes.
    ///
    /// Returns 0 for an inverted span (`end < start`) rather than panicking or
    /// wrapping. `Span` has public fields and no constructor besides `empty`
    /// enforces `start <= end`, so a caller assembling one from two positions
    /// (the parser this crate feeds is the first one that will) can hand this
    /// an inverted span; a total function here is cheaper than proving every
    /// caller never will be wrong.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// True when the span covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// The bytes this span names inside `src`, or `None` when it is out of range.
    #[must_use]
    pub fn slice(self, src: &[u8]) -> Option<&[u8]> {
        let start = usize::try_from(self.start).ok()?;
        let end = usize::try_from(self.end).ok()?;
        src.get(start..end)
    }
}

impl Tok {
    /// A stable name for error messages.
    ///
    /// Every punctuation and operator token returns its own spelling. The four
    /// payload-carrying tokens return their category. The payload is never part of
    /// the string, so error messages built from `describe` are `&'static str` and
    /// never allocate.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Tok::Ident(_) => "identifier",
            Tok::Int(_) => "integer",
            Tok::Str(_) => "string",
            Tok::Bool(_) => "boolean",
            Tok::Null => "null",
            Tok::LParen => "(",
            Tok::RParen => ")",
            Tok::LBracket => "[",
            Tok::RBracket => "]",
            Tok::Comma => ",",
            Tok::Dot => ".",
            Tok::Question => "?",
            Tok::Colon => ":",
            Tok::Bang => "!",
            Tok::AndAnd => "&&",
            Tok::OrOr => "||",
            Tok::EqEq => "==",
            Tok::BangEq => "!=",
            Tok::Lt => "<",
            Tok::Le => "<=",
            Tok::Gt => ">",
            Tok::Ge => ">=",
            Tok::In => "in",
        }
    }
}

impl LexError {
    /// The source offset the error refers to, for the caret in the config error.
    #[must_use]
    pub const fn at(self) -> u32 {
        match self {
            LexError::UnexpectedByte { at, .. }
            | LexError::UnterminatedString { at }
            | LexError::BadEscape { at }
            | LexError::BadUnicodeEscape { at }
            | LexError::IntOverflow { at }
            | LexError::StringTooLong { at, .. }
            | LexError::NotUtf8 { at } => at,
            LexError::SourceTooLong { .. } | LexError::TooManyTokens { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_empty_and_slice() {
        let s = Span::empty(5);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        let src = b"hello";
        assert_eq!(s.slice(src), Some(b"".as_slice()));
        assert_eq!(
            Span { start: 1, end: 4 }.slice(src),
            Some(b"ell".as_slice())
        );
        assert_eq!(Span { start: 10, end: 12 }.slice(src), None);
    }

    #[test]
    fn span_len_saturates_on_an_inverted_span() {
        // `Span` has public fields and no constructor enforces `start <=
        // end`, so this must not overflow-panic in debug or wrap to roughly
        // 4 billion in release; `len` returning 0 for a span that names no
        // real range is the total, always-correct answer.
        let s = Span { start: 5, end: 0 };
        assert_eq!(s.len(), 0);
        assert!(!s.is_empty(), "is_empty is start == end, not len == 0");
    }

    #[test]
    fn tok_describe_static() {
        assert_eq!(Tok::LParen.describe(), "(");
        assert_eq!(Tok::BangEq.describe(), "!=");
        assert_eq!(Tok::In.describe(), "in");
        assert_eq!(Tok::Ident(Span::empty(0)).describe(), "identifier");
        assert_eq!(Tok::Str(Span::empty(0)).describe(), "string");
    }

    #[test]
    fn lex_error_at() {
        assert_eq!(LexError::UnexpectedByte { at: 7, byte: b'x' }.at(), 7);
        assert_eq!(LexError::SourceTooLong { len: 10, max: 8 }.at(), 0);
    }
}
