// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITPL parser: a hand-written Pratt (precedence-climbing) parser that turns a
//! `TokenStream` into a flat `Ast` arena.
//!
//! # Depth
//!
//! `PolicyLimits::max_depth` bounds the nesting depth of the parsed AST, not the raw
//! count of internal parse-function calls: `expr` is the only production that can
//! recurse into itself (through a parenthesized expression, an index expression, or
//! a ternary branch), so it is the only function that increments and checks the
//! depth counter. The other productions in the precedence chain (`or`, `and`, `rel`,
//! `unary`, `postfix`, `primary`) each call the next one down exactly once per
//! `expr` entry and never recurse on their own, so the real Rust stack cost of one
//! unit of AST depth is a small, fixed number of frames (this chain), not one frame.
//! Total stack use is therefore `O(max_depth)` with that fixed constant, which is
//! the property the depth cap exists to guarantee: the deepest input costs
//! `max_depth` recursive entries into `expr`, never more, regardless of how long the
//! input is.
//!
//! The counter is incremented on entry to `expr`, before any further parsing, and
//! checked before the recursive call is allowed to proceed: a 100,000-term boolean
//! tree parsed through the flat `or`/`and` loops never touches the counter at all
//! (repeated `&&`/`||` terms are sequential calls at the same depth, not nested
//! recursion), and a deeply parenthesized or deeply ternary-nested expression is
//! refused at the `max_depth + 1`th attempt to descend, before that descent
//! recurses.

use crate::ast::{Ast, BinOp, Method, Node, NodeId};
use crate::limits::PolicyLimits;
use crate::token::{Span, Spanned, Tok, TokenStream};

/// Why a token stream could not be parsed as one ITPL expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// The token stream ended while a production was incomplete.
    UnexpectedEof {
        /// Source offset where the missing token was expected.
        at: u32,
    },
    /// A token that cannot start or continue the current production.
    Unexpected {
        /// Source offset of the offending token.
        at: u32,
        /// The token that could not be used here.
        found: Tok,
    },
    /// Nesting deeper than `PolicyLimits::max_depth`.
    TooDeep {
        /// Source offset where the excess nesting was detected.
        at: u32,
        /// The configured `max_depth`.
        max: u16,
    },
    /// A method name that is not in the closed set, or a CEL macro.
    NotImplemented {
        /// Source offset of the construct.
        at: u32,
        /// The span naming the construct, for the caret in the config error.
        construct: Span,
    },
    /// A method called with the wrong number of arguments.
    BadArity {
        /// Source offset of the method name.
        at: u32,
        /// The method that was called.
        method: Method,
        /// How many arguments the method takes.
        expected: u8,
        /// How many arguments were given.
        found: u8,
    },
    /// A list literal with more than `max_list_elems` elements.
    ListTooLong {
        /// Source offset where the excess element was detected.
        at: u32,
        /// The configured `max_list_elems`.
        max: u16,
    },
    /// More nodes than `NodeId` can index.
    TooManyNodes {
        /// The largest index `NodeId` can represent.
        max: u16,
    },
    /// Tokens remain after a complete expression.
    TrailingTokens {
        /// Source offset of the first unconsumed token.
        at: u32,
    },
}

impl ParseError {
    /// The source offset for the caret in the config error.
    ///
    /// `TooManyNodes` names no position (arena exhaustion is a property of the
    /// whole parse, not one offset), and reports 0.
    #[must_use]
    pub const fn at(self) -> u32 {
        match self {
            ParseError::UnexpectedEof { at }
            | ParseError::Unexpected { at, .. }
            | ParseError::TooDeep { at, .. }
            | ParseError::NotImplemented { at, .. }
            | ParseError::BadArity { at, .. }
            | ParseError::ListTooLong { at, .. }
            | ParseError::TrailingTokens { at } => at,
            ParseError::TooManyNodes { .. } => 0,
        }
    }
}

/// The relational operator a token spells, or `None` when it spells none.
fn relop_of(t: Tok) -> Option<BinOp> {
    match t {
        Tok::EqEq => Some(BinOp::Eq),
        Tok::BangEq => Some(BinOp::Ne),
        Tok::Lt => Some(BinOp::Lt),
        Tok::Le => Some(BinOp::Le),
        Tok::Gt => Some(BinOp::Gt),
        Tok::Ge => Some(BinOp::Ge),
        Tok::In => Some(BinOp::In),
        _ => None,
    }
}

/// The span at token index `pos`, total for every `pos` including one past the
/// last token: `enter` and the trailing-token check in `parse` can both name a
/// position that is legitimately one past the end, and indexing `toks` there is a
/// panic on an input an operator can write. Past the end, this returns an empty
/// span at the end of the source.
fn span_at(toks: &[Spanned], src: &[u8], pos: usize) -> Span {
    if let Some(s) = toks.get(pos) {
        s.span
    } else {
        let end = u32::try_from(src.len()).unwrap_or(u32::MAX);
        Span::empty(end)
    }
}

struct Parser<'a> {
    toks: &'a [Spanned],
    /// The original source, so `Ident` spans can be resolved to bytes for
    /// `Method::from_name` and for the `NotImplemented` construct name.
    src: &'a [u8],
    limits: &'a PolicyLimits,
    /// Index of the next token.
    pos: usize,
    /// Current nesting depth: the number of `expr` calls currently on the stack.
    depth: u16,
    /// Deepest value `depth` ever reached, reported as `Ast::depth`.
    max_reached: u16,
    nodes: Vec<Node>,
    args: Vec<NodeId>,
}

impl Parser<'_> {
    fn span_at(&self, pos: usize) -> Span {
        span_at(self.toks, self.src, pos)
    }

    fn peek(&self) -> Option<Tok> {
        self.toks.get(self.pos).map(|s| s.tok)
    }

    fn peek_relop(&self) -> Option<BinOp> {
        self.toks.get(self.pos).and_then(|s| relop_of(s.tok))
    }

    fn eat(&mut self, want: Tok) -> bool {
        if self.peek() == Some(want) {
            self.pos = self.pos.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn eat_relop(&mut self) -> Option<BinOp> {
        let op = self.peek_relop()?;
        self.pos = self.pos.saturating_add(1);
        Some(op)
    }

    /// The error for "the token at the current position cannot be used here",
    /// total over the end of the stream. Every error constructor that names a
    /// position goes through `span_at`, directly or via this helper, so none of
    /// them indexes `self.toks` directly.
    fn err_here(&self) -> ParseError {
        match self.toks.get(self.pos) {
            Some(s) => ParseError::Unexpected {
                at: self.span_at(self.pos).start,
                found: s.tok,
            },
            None => ParseError::UnexpectedEof {
                at: self.span_at(self.pos).start,
            },
        }
    }

    fn next(&mut self) -> Result<Tok, ParseError> {
        match self.toks.get(self.pos) {
            Some(s) => {
                let tok = s.tok;
                self.pos = self.pos.saturating_add(1);
                Ok(tok)
            }
            None => Err(ParseError::UnexpectedEof {
                at: self.span_at(self.pos).start,
            }),
        }
    }

    fn expect(&mut self, want: Tok) -> Result<(), ParseError> {
        if self.eat(want) {
            Ok(())
        } else {
            Err(self.err_here())
        }
    }

    fn expect_ident(&mut self) -> Result<Span, ParseError> {
        match self.toks.get(self.pos) {
            Some(&Spanned {
                tok: Tok::Ident(span),
                ..
            }) => {
                self.pos = self.pos.saturating_add(1);
                Ok(span)
            }
            _ => Err(self.err_here()),
        }
    }

    fn push(&mut self, n: Node) -> Result<NodeId, ParseError> {
        let id = NodeId::new(self.nodes.len()).ok_or(ParseError::TooManyNodes { max: u16::MAX })?;
        self.nodes.push(n);
        Ok(id)
    }

    /// Increments `depth`, checking it against `limits.max_depth` before the
    /// caller is allowed to recurse. On failure, decrements before returning:
    /// the caller's `?` skips the matching decrement in `expr`, so `enter` must
    /// leave `depth` exactly as it found it on every path, not only the success
    /// path.
    ///
    /// This is a plain counter, not an RAII guard: a guard holding `&mut
    /// self.depth` would borrow the parser for the rest of `expr`, and `expr`
    /// calls `self.or()?` in that same scope, a second mutable borrow that does
    /// not compile. The two-line outer/inner split in `expr` gets the same
    /// "decrement on every path including `?`" guarantee with no borrow at all,
    /// because `expr_inner`'s `Result` is bound to a local before the decrement
    /// runs.
    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.limits.max_depth {
            self.depth = self.depth.saturating_sub(1);
            return Err(ParseError::TooDeep {
                at: self.span_at(self.pos).start,
                max: self.limits.max_depth,
            });
        }
        if self.depth > self.max_reached {
            self.max_reached = self.depth;
        }
        Ok(())
    }

    /// `expr = ternary`. The sole recursive re-entry point into the grammar
    /// (through a parenthesized expression in `primary`, an index expression in
    /// `postfix`, or a ternary branch here), so it is the sole depth-tracked
    /// production. See the module docs for why the other six productions in the
    /// chain do not each track depth independently.
    fn expr(&mut self) -> Result<NodeId, ParseError> {
        self.enter()?;
        let r = self.expr_inner();
        self.depth = self.depth.saturating_sub(1);
        r
    }

    fn expr_inner(&mut self) -> Result<NodeId, ParseError> {
        let cond = self.or()?;
        if self.eat(Tok::Question) {
            let then_ = self.expr()?; // right associative
            self.expect(Tok::Colon)?; // it-allow: no-panic reason: Parser::expect returns Result and propagates via ?; not Result::expect/Option::expect.
            let else_ = self.expr()?;
            return self.push(Node::Ternary { cond, then_, else_ });
        }
        Ok(cond)
    }

    /// `or = and { "||" and }`, left associative.
    fn or(&mut self) -> Result<NodeId, ParseError> {
        let mut lhs = self.and()?;
        while self.eat(Tok::OrOr) {
            let rhs = self.and()?;
            lhs = self.push(Node::Or { lhs, rhs })?;
        }
        Ok(lhs)
    }

    /// `and = rel { "&&" rel }`, left associative.
    fn and(&mut self) -> Result<NodeId, ParseError> {
        let mut lhs = self.rel()?;
        while self.eat(Tok::AndAnd) {
            let rhs = self.rel()?;
            lhs = self.push(Node::And { lhs, rhs })?;
        }
        Ok(lhs)
    }

    /// `rel = unary [ relop unary ]`, deliberately non-associative: `a < b < c`
    /// is refused rather than parsed as `(a < b) < c`, which would compare a
    /// `Bool` result against an integer several stages later with a confusing
    /// message. Refusing it here gives the second operator the right message.
    fn rel(&mut self) -> Result<NodeId, ParseError> {
        let lhs = self.unary()?;
        if let Some(op) = self.eat_relop() {
            let rhs = self.unary()?;
            if self.peek_relop().is_some() {
                return Err(self.err_here());
            }
            return self.push(Node::Bin { op, lhs, rhs });
        }
        Ok(lhs)
    }

    /// `unary = { "!" } postfix`. Consecutive `!` are counted in a loop rather
    /// than recursed, so thousands of leading `!` cost one frame: without this,
    /// the depth cap would be the only thing standing between an adversary and
    /// deep recursion, and it would reject a program that is not actually deep.
    fn unary(&mut self) -> Result<NodeId, ParseError> {
        let mut bangs: usize = 0;
        while self.eat(Tok::Bang) {
            bangs = bangs.saturating_add(1);
        }
        let mut n = self.postfix()?;
        for _ in 0..bangs {
            n = self.push(Node::Not { inner: n })?;
        }
        Ok(n)
    }

    /// `postfix = primary { field | index | call }`. The chain is a loop, not
    /// recursion, so a long run of `.field` accesses costs one frame. Only
    /// `index`'s bracketed expression recurses, through `expr`, and that
    /// recursion is depth-counted there.
    fn postfix(&mut self) -> Result<NodeId, ParseError> {
        let mut base = self.primary()?;
        loop {
            if self.eat(Tok::Dot) {
                let name = self.expect_ident()?;
                if self.eat(Tok::LParen) {
                    let bytes = name.slice(self.src).ok_or(ParseError::Unexpected {
                        at: name.start,
                        found: Tok::Ident(name),
                    })?;
                    let method = Method::from_name(bytes).ok_or(ParseError::NotImplemented {
                        at: name.start,
                        construct: name,
                    })?;
                    let (from, len) = self.arg_list()?;
                    if len != u16::from(method.arity()) {
                        let found = u8::try_from(len).unwrap_or(u8::MAX);
                        return Err(ParseError::BadArity {
                            at: name.start,
                            method,
                            expected: method.arity(),
                            found,
                        });
                    }
                    base = self.push(Node::Call {
                        base,
                        method,
                        args_from: from,
                        args_len: len,
                    })?;
                } else {
                    base = self.push(Node::Field { base, name })?;
                }
            } else if self.eat(Tok::LBracket) {
                let index = self.expr()?;
                self.expect(Tok::RBracket)?; // it-allow: no-panic reason: Parser::expect returns Result and propagates via ?; not Result::expect/Option::expect.
                base = self.push(Node::Index { base, index })?;
            } else {
                return Ok(base);
            }
        }
    }

    /// `primary = IDENT | INT | STRING | "true" | "false" | "null" | "(" expr ")"
    /// | list`. Parentheses produce no node: they only change grouping.
    fn primary(&mut self) -> Result<NodeId, ParseError> {
        let start_pos = self.pos;
        match self.next()? {
            Tok::Bool(b) => self.push(Node::Bool(b)),
            Tok::Int(v) => self.push(Node::Int(v)),
            Tok::Str(s) => self.push(Node::Str(s)),
            Tok::Null => self.push(Node::Null),
            Tok::LParen => {
                let inner = self.expr()?;
                self.expect(Tok::RParen)?; // it-allow: no-panic reason: Parser::expect returns Result and propagates via ?; not Result::expect/Option::expect.
                Ok(inner)
            }
            Tok::LBracket => {
                let (from, len) = self.list_elems()?;
                self.push(Node::List { from, len })
            }
            Tok::Ident(s) => {
                if self.peek() == Some(Tok::LParen) {
                    // A bare call: `has(x)`, `all(x, y)`, `size(x)`. ITPL has no
                    // bare functions, so this is the landing site for every CEL
                    // macro and every other bare-call syntax.
                    return Err(ParseError::NotImplemented {
                        at: s.start,
                        construct: s,
                    });
                }
                self.push(Node::Ident(s))
            }
            other => Err(ParseError::Unexpected {
                at: self.span_at(start_pos).start,
                found: other,
            }),
        }
    }

    /// Parses the comma-separated expression list following an already-consumed
    /// opening delimiter, expecting `close` to end it, and returns `(from, len)`
    /// into `self.args`. Shared by `arg_list` (parens) and `list_elems`
    /// (brackets): the grammar for the two is otherwise identical. Enforces
    /// `limits.max_list_elems` inside the loop, before parsing the element that
    /// would exceed it, not after parsing every element and counting.
    fn elem_list(&mut self, close: Tok) -> Result<(u16, u16), ParseError> {
        let from = self.args.len();
        let from_id =
            u16::try_from(from).map_err(|_| ParseError::TooManyNodes { max: u16::MAX })?;

        if self.eat(close) {
            return Ok((from_id, 0));
        }

        let max = usize::from(self.limits.max_list_elems);
        loop {
            if self.args.len().saturating_sub(from) >= max {
                return Err(ParseError::ListTooLong {
                    at: self.span_at(self.pos).start,
                    max: self.limits.max_list_elems,
                });
            }
            let e = self.expr()?;
            self.args.push(e);
            if self.eat(Tok::Comma) {
                continue;
            }
            self.expect(close)?; // it-allow: no-panic reason: Parser::expect returns Result and propagates via ?; not Result::expect/Option::expect.
            break;
        }

        let len = self.args.len().saturating_sub(from);
        let len_id = u16::try_from(len).map_err(|_| ParseError::TooManyNodes { max: u16::MAX })?;
        Ok((from_id, len_id))
    }

    /// `call = "." IDENT "(" [ expr { "," expr } ] ")"`, the argument list only:
    /// the leading `.` `IDENT` `(` is already consumed by the caller.
    fn arg_list(&mut self) -> Result<(u16, u16), ParseError> {
        self.elem_list(Tok::RParen)
    }

    /// `list = "[" [ expr { "," expr } ] "]"`, the element list only: the
    /// leading `[` is already consumed by the caller.
    fn list_elems(&mut self) -> Result<(u16, u16), ParseError> {
        self.elem_list(Tok::RBracket)
    }
}

/// Parses one ITPL expression from a token stream, requiring that it consumes the
/// whole stream.
///
/// # Errors
/// Every `ParseError` variant. `NotImplemented` names the construct and the config
/// error surfaces it with a pointer to `docs/ITPL.md`.
pub fn parse(toks: &TokenStream, src: &[u8], limits: &PolicyLimits) -> Result<Ast, ParseError> {
    let (ast, pos) = parse_expr_at(toks, src, limits, 0)?;
    if pos == toks.toks.len() {
        Ok(ast)
    } else {
        Err(ParseError::TrailingTokens {
            at: span_at(&toks.toks, src, pos).start,
        })
    }
}

/// Parses ONE expression starting at token index `from` and returns it together with
/// the index of the first token it did not consume. Does not require the stream to
/// end, so it never returns `TrailingTokens`.
///
/// This is what a rule grammar (`when <expr> then <action>`) calls: the expression
/// ends where the `then` identifier begins, and the rule parser needs that position
/// back. `parse` is exactly `parse_expr_at(toks, src, limits, 0)` plus the check
/// that the returned position equals `toks.toks.len()`.
///
/// # Errors
/// Every `ParseError` variant except `TrailingTokens`.
pub fn parse_expr_at(
    toks: &TokenStream,
    src: &[u8],
    limits: &PolicyLimits,
    from: usize,
) -> Result<(Ast, usize), ParseError> {
    let mut p = Parser {
        toks: &toks.toks,
        src,
        limits,
        pos: from,
        depth: 0,
        max_reached: 0,
        nodes: Vec::new(),
        args: Vec::new(),
    };
    let root = p.expr()?;
    Ok((
        Ast {
            nodes: p.nodes,
            args: p.args,
            root,
            depth: p.max_reached,
        },
        p.pos,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lex::lex;
    use proptest::prelude::*;

    fn default_limits() -> PolicyLimits {
        PolicyLimits::defaults()
    }

    fn parse_src(src: &[u8], limits: PolicyLimits) -> Result<Ast, ParseError> {
        let toks = lex(src, &limits).expect("valid ITPL source must lex");
        parse(&toks, src, &limits)
    }

    #[test]
    fn empty_is_eof() {
        let toks = lex(b"", &default_limits()).unwrap();
        let err = parse(&toks, b"", &default_limits()).unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEof { at: 0 });
    }

    #[test]
    fn single_literal() {
        let ast = parse_src(b"true", default_limits()).unwrap();
        assert_eq!(ast.nodes, vec![Node::Bool(true)]);
        assert_eq!(ast.root, NodeId(0));
        assert_eq!(ast.depth, 1);
    }

    #[test]
    fn and_is_left_associative() {
        // `a && b && c` must be `And { And { a, b }, c }`, never
        // `And { a, And { b, c } }`: a permutation-blind test (for example one
        // that only counts `And` nodes) cannot catch a right-associative
        // regression, so this asserts the exact arena.
        let ast = parse_src(b"a && b && c", default_limits()).unwrap();
        assert_eq!(
            ast.nodes,
            vec![
                Node::Ident(Span { start: 0, end: 1 }), // 0: a
                Node::Ident(Span { start: 5, end: 6 }), // 1: b
                Node::And {
                    lhs: NodeId(0),
                    rhs: NodeId(1)
                }, // 2: a && b
                Node::Ident(Span { start: 10, end: 11 }), // 3: c
                Node::And {
                    lhs: NodeId(2),
                    rhs: NodeId(3)
                }, // 4: (a && b) && c
            ]
        );
        assert_eq!(ast.root, NodeId(4));
    }

    #[test]
    fn or_binds_looser_than_and() {
        // `a || b && c` must be `Or { a, And { b, c } }`.
        let ast = parse_src(b"a || b && c", default_limits()).unwrap();
        assert_eq!(
            ast.nodes,
            vec![
                Node::Ident(Span { start: 0, end: 1 }),   // 0: a
                Node::Ident(Span { start: 5, end: 6 }),   // 1: b
                Node::Ident(Span { start: 10, end: 11 }), // 2: c
                Node::And {
                    lhs: NodeId(1),
                    rhs: NodeId(2)
                }, // 3: b && c
                Node::Or {
                    lhs: NodeId(0),
                    rhs: NodeId(3)
                }, // 4: a || (b && c)
            ]
        );
        assert_eq!(ast.root, NodeId(4));
    }

    #[test]
    fn not_binds_tighter_than_relational() {
        // `!a == b` is CEL's precedence: `Bin { Eq, Not { a }, b }`, not
        // `Not { Bin { Eq, a, b } }`, which is the common misconception this
        // test exists to pin.
        let ast = parse_src(b"!a == b", default_limits()).unwrap();
        assert_eq!(
            ast.nodes,
            vec![
                Node::Ident(Span { start: 1, end: 2 }), // 0: a
                Node::Not { inner: NodeId(0) },         // 1: !a
                Node::Ident(Span { start: 6, end: 7 }), // 2: b
                Node::Bin {
                    op: BinOp::Eq,
                    lhs: NodeId(1),
                    rhs: NodeId(2)
                }, // 3: (!a) == b
            ]
        );
        assert_eq!(ast.root, NodeId(3));
    }

    #[test]
    fn ternary_is_right_associative() {
        // `a ? b : c ? d : e` must be `Ternary { a, b, Ternary { c, d, e } }`.
        let ast = parse_src(b"a ? b : c ? d : e", default_limits()).unwrap();
        let Node::Ternary { cond, then_, else_ } = ast.nodes[ast.root.index()] else {
            panic!("root is not a Ternary: {:?}", ast.nodes[ast.root.index()]);
        };
        assert_eq!(ast.node(cond), Some(Node::Ident(Span { start: 0, end: 1 })));
        assert_eq!(
            ast.node(then_),
            Some(Node::Ident(Span { start: 4, end: 5 }))
        );
        let Some(Node::Ternary {
            cond: cond2,
            then_: then2,
            else_: else2,
        }) = ast.node(else_)
        else {
            panic!("else_ is not a Ternary");
        };
        assert_eq!(
            ast.node(cond2),
            Some(Node::Ident(Span { start: 8, end: 9 }))
        );
        assert_eq!(
            ast.node(then2),
            Some(Node::Ident(Span { start: 12, end: 13 }))
        );
        assert_eq!(
            ast.node(else2),
            Some(Node::Ident(Span { start: 16, end: 17 }))
        );
    }

    #[test]
    fn chained_relational_rejected() {
        let toks = lex(b"a < b < c", &default_limits()).unwrap();
        let err = parse(&toks, b"a < b < c", &default_limits()).unwrap_err();
        assert_eq!(
            err,
            ParseError::Unexpected {
                at: 6,
                found: Tok::Lt
            }
        );
    }

    #[test]
    fn parens_produce_no_node() {
        let ast = parse_src(b"(true)", default_limits()).unwrap();
        assert_eq!(ast.nodes, vec![Node::Bool(true)]);
        assert_eq!(ast.root, NodeId(0));
    }

    #[test]
    fn unbalanced_open_paren_is_eof() {
        let toks = lex(b"(a", &default_limits()).unwrap();
        let err = parse(&toks, b"(a", &default_limits()).unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEof { at: 2 });
    }

    #[test]
    fn unbalanced_close_paren_is_trailing() {
        let toks = lex(b"a)", &default_limits()).unwrap();
        let err = parse(&toks, b"a)", &default_limits()).unwrap_err();
        assert_eq!(err, ParseError::TrailingTokens { at: 1 });
    }

    #[test]
    fn empty_list_literal() {
        let ast = parse_src(b"[]", default_limits()).unwrap();
        assert_eq!(ast.nodes, vec![Node::List { from: 0, len: 0 }]);
        assert!(ast.args.is_empty());
    }

    #[test]
    fn list_too_long() {
        let mut limits = default_limits();
        limits.max_list_elems = 64;
        let elems: Vec<String> = (0..65).map(|i| i.to_string()).collect();
        let src = format!("[{}]", elems.join(", "));
        let toks = lex(src.as_bytes(), &limits).unwrap();
        let err = parse(&toks, src.as_bytes(), &limits).unwrap_err();
        assert!(matches!(err, ParseError::ListTooLong { max: 64, .. }));
    }

    #[test]
    fn list_at_exactly_the_cap_is_accepted() {
        // The reject side alone cannot tell a per-item cap from an
        // off-by-one: pin the accept side at exactly the limit too.
        let mut limits = default_limits();
        limits.max_list_elems = 64;
        let elems: Vec<String> = (0..64).map(|i| i.to_string()).collect();
        let src = format!("[{}]", elems.join(", "));
        let ast = parse_src(src.as_bytes(), limits).unwrap();
        // 64 `Int` literal nodes are pushed first, one per element, then the
        // `List` node referencing all of them through `args`.
        assert_eq!(ast.nodes.len(), 65);
        assert_eq!(ast.nodes[ast.root.index()], Node::List { from: 0, len: 64 });
        assert_eq!(ast.args.len(), 64);
        assert_eq!(ast.args_of(0, 64).len(), 64);
    }

    #[test]
    fn has_macro_not_implemented() {
        let toks = lex(b"has(request.headers)", &default_limits()).unwrap();
        let err = parse(&toks, b"has(request.headers)", &default_limits()).unwrap_err();
        assert_eq!(
            err,
            ParseError::NotImplemented {
                at: 0,
                construct: Span { start: 0, end: 3 }
            }
        );
    }

    #[test]
    fn all_macro_not_implemented() {
        let src = b"request.headers.all(x, x != \"\")";
        let toks = lex(src, &default_limits()).unwrap();
        let err = parse(&toks, src, &default_limits()).unwrap_err();
        assert_eq!(
            err,
            ParseError::NotImplemented {
                at: 16,
                construct: Span { start: 16, end: 19 }
            }
        );
    }

    #[test]
    fn unknown_method_not_implemented() {
        let src = b"a.unknownMethod(b)";
        let toks = lex(src, &default_limits()).unwrap();
        let err = parse(&toks, src, &default_limits()).unwrap_err();
        assert_eq!(
            err,
            ParseError::NotImplemented {
                at: 2,
                construct: Span { start: 2, end: 15 }
            }
        );
    }

    #[test]
    fn arity_errors() {
        let src = b"a.startsWith()";
        let toks = lex(src, &default_limits()).unwrap();
        let err = parse(&toks, src, &default_limits()).unwrap_err();
        assert_eq!(
            err,
            ParseError::BadArity {
                at: 2,
                method: Method::StartsWith,
                expected: 1,
                found: 0,
            }
        );

        let src = b"a.size(1)";
        let toks = lex(src, &default_limits()).unwrap();
        let err = parse(&toks, src, &default_limits()).unwrap_err();
        assert_eq!(
            err,
            ParseError::BadArity {
                at: 2,
                method: Method::Size,
                expected: 0,
                found: 1,
            }
        );
    }

    #[test]
    fn depth_cap_trips() {
        // #269 names 17 nested parens against the default max_depth of 16 as
        // the rejected case.
        let src = format!("{}true{}", "(".repeat(17), ")".repeat(17));
        let toks = lex(src.as_bytes(), &default_limits()).unwrap();
        let err = parse(&toks, src.as_bytes(), &default_limits()).unwrap_err();
        // The 17th call to `expr` fails at `enter` before consuming the 17th
        // `(`: 16 opening parens have already been consumed (byte offsets
        // 0..16), so the still-unconsumed 17th `(` sits at offset 16.
        assert_eq!(err, ParseError::TooDeep { at: 16, max: 16 });
    }

    #[test]
    fn depth_cap_accepts_at_the_boundary_and_rejects_one_over() {
        // #721 found three untested accept-side boundaries in the lexer, where
        // a `>` flipped to `>=` left the suite green. This is the same class
        // of test for the depth cap, with a small deliberate `max_depth` so
        // the exact accept/reject boundary is checked precisely rather than
        // merely "some N well past the default is rejected".
        let mut limits = default_limits();
        limits.max_depth = 3;

        // Each level of paren nesting costs one recursive `expr` entry, and
        // parsing the innermost literal costs one entry on its own, so N
        // nested parens reaches depth N + 1. depth == 3 is therefore 2
        // parens, accepted; 3 parens reaches depth 4, rejected.
        let accepted_src = format!("{}true{}", "(".repeat(2), ")".repeat(2));
        let ast = parse_src(accepted_src.as_bytes(), limits).unwrap();
        assert_eq!(ast.depth, 3);

        let rejected_src = format!("{}true{}", "(".repeat(3), ")".repeat(3));
        let toks = lex(rejected_src.as_bytes(), &limits).unwrap();
        let err = parse(&toks, rejected_src.as_bytes(), &limits).unwrap_err();
        assert_eq!(err, ParseError::TooDeep { at: 3, max: 3 });
    }

    #[test]
    fn depth_is_reported() {
        // A "5-deep" expression: 4 nested parens plus the literal itself
        // reaches depth 5 (see the boundary test above for the arithmetic).
        let src = format!("{}true{}", "(".repeat(4), ")".repeat(4));
        let ast = parse_src(src.as_bytes(), default_limits()).unwrap();
        assert_eq!(ast.depth, 5);
    }

    #[test]
    fn many_bangs_one_frame() {
        let mut src = vec![b'!'; 8000];
        src.extend_from_slice(b"true");

        let mut limits = default_limits();
        limits.max_tokens = 8_001;

        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let toks = lex(&src, &limits).expect("lex must accept 8000 bangs");
                parse(&toks, &src, &limits)
            })
            .expect("spawn 128 KiB thread");
        let result = handle.join().expect("must not stack overflow or panic");
        assert!(result.is_ok(), "8000 leading ! must parse: {result:?}");
    }

    #[test]
    fn long_postfix_chain_one_frame() {
        let mut src = String::from("x");
        for _ in 0..1000 {
            src.push_str(".a");
        }

        let mut limits = default_limits();
        limits.max_tokens = 2_001;

        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let toks = lex(src.as_bytes(), &limits).expect("lex must accept the chain");
                parse(&toks, src.as_bytes(), &limits)
            })
            .expect("spawn 128 KiB thread");
        let result = handle.join().expect("must not stack overflow or panic");
        assert!(result.is_ok(), "1000-segment postfix chain must parse");
        let ast = result.unwrap();
        assert_eq!(ast.depth, 1, "a flat postfix chain never recurses expr");
    }

    #[test]
    fn index_with_string_literal() {
        let src = br#"request.headers["x-a"]"#;
        let ast = parse_src(src, default_limits()).unwrap();
        let Node::Index { index, .. } = ast.nodes[ast.root.index()] else {
            panic!("root is not an Index");
        };
        assert!(matches!(ast.node(index), Some(Node::Str(_))));
    }

    #[test]
    fn index_with_dynamic_expression_parses() {
        let src = b"request.headers[request.method]";
        let ast = parse_src(src, default_limits()).unwrap();
        let Node::Index { index, .. } = ast.nodes[ast.root.index()] else {
            panic!("root is not an Index");
        };
        assert!(matches!(ast.node(index), Some(Node::Field { .. })));
    }

    #[test]
    fn node_children_have_smaller_ids() {
        // Exercises every variant that carries a `NodeId`, including `Call`
        // and `List`, whose children are reached through `args_of` rather
        // than a direct field.
        use std::fmt::Write as _;

        let mut src = String::from(r#"a.startsWith("x") && b0"#);
        for i in 1..48 {
            write!(src, " && b{i}").expect("write! to a String never fails");
        }
        src.push_str(" && (c in [1, 2, 3])");
        let mut limits = default_limits();
        limits.max_tokens = 4096;
        let ast = parse_src(src.as_bytes(), limits).unwrap();
        assert!(ast.nodes.len() >= 50);
        for (i, node) in ast.nodes.iter().enumerate() {
            let children: Vec<NodeId> = match *node {
                Node::Field { base, .. } | Node::Not { inner: base } => vec![base],
                Node::Index { base, index } => vec![base, index],
                Node::Bin { lhs, rhs, .. } | Node::And { lhs, rhs } | Node::Or { lhs, rhs } => {
                    vec![lhs, rhs]
                }
                Node::Ternary { cond, then_, else_ } => vec![cond, then_, else_],
                Node::Call {
                    base,
                    args_from,
                    args_len,
                    ..
                } => {
                    let mut c = vec![base];
                    c.extend_from_slice(ast.args_of(args_from, args_len));
                    c
                }
                Node::List { from, len } => ast.args_of(from, len).to_vec(),
                Node::Bool(_) | Node::Int(_) | Node::Str(_) | Node::Null | Node::Ident(_) => {
                    vec![]
                }
            };
            for child in children {
                assert!(
                    child.index() < i,
                    "node {i} ({node:?}) has a child {child:?} whose index is not smaller"
                );
            }
        }
    }

    #[test]
    fn root_is_last_node() {
        let ast = parse_src(b"a && b || c", default_limits()).unwrap();
        assert_eq!(ast.root.index(), ast.nodes.len() - 1);
    }

    #[test]
    fn parse_is_deterministic() {
        let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
        let limits = default_limits();
        let first = parse_src(src, limits).unwrap();
        for _ in 0..100 {
            let again = parse_src(src, limits).unwrap();
            assert_eq!(again.nodes, first.nodes);
            assert_eq!(again.args, first.args);
            assert_eq!(again.root, first.root);
            assert_eq!(again.depth, first.depth);
        }
    }

    #[test]
    fn span_at_past_the_end_is_total() {
        // `enter` and the trailing-tokens check in `parse` can both name a
        // position that is legitimately one past the last token (an
        // `UnexpectedEof` or a `TooDeep` raised at end of input, for
        // example), and every error constructor goes through `span_at`
        // rather than indexing `toks` directly. This pins `span_at` itself:
        // both `toks.len()` and comfortably past it return an empty span at
        // the end of the source, never a panic.
        let toks: [Spanned; 0] = [];
        let src = b"abc";
        assert_eq!(span_at(&toks, src, 0), Span::empty(3));
        assert_eq!(span_at(&toks, src, 100), Span::empty(3));

        let real = lex(b"a", &default_limits()).unwrap();
        assert_eq!(span_at(&real.toks, b"a", real.toks.len()), Span::empty(1));
        assert_eq!(
            span_at(&real.toks, b"a", real.toks.len() + 100),
            Span::empty(1)
        );
    }

    #[test]
    fn parse_expr_at_stops_at_an_unconsumable_token() {
        let src = b"request.method == \"GET\" then";
        let toks = lex(src, &default_limits()).unwrap();
        let (ast, next_pos) = parse_expr_at(&toks, src, &default_limits(), 0).unwrap();
        assert_eq!(next_pos, 5);
        assert_eq!(
            toks.toks[next_pos].tok,
            Tok::Ident(Span { start: 24, end: 28 })
        );
        assert!(matches!(
            ast.nodes[ast.root.index()],
            Node::Bin { op: BinOp::Eq, .. }
        ));

        let err = parse(&toks, src, &default_limits()).unwrap_err();
        assert!(matches!(err, ParseError::TrailingTokens { .. }));
    }

    proptest! {
        #[test]
        fn prop_parse_never_panics(
            toks in token_stream_strategy(),
            src in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            let limits = default_limits();
            let stream = TokenStream { toks, strings: Vec::new() };
            // Must never panic for any input, which `#[test]` alone already
            // enforces (a panic fails the case). The real, checkable
            // invariants beyond mere totality: every accepted arena is
            // bounded by `NodeId`'s own range and the root is a valid index
            // into it. `prop_depth_never_exceeds_cap` below covers the depth
            // cap specifically, so it is not duplicated here.
            if let Ok(ast) = parse(&stream, &src, &limits) {
                prop_assert!(u16::try_from(ast.nodes.len()).is_ok());
                prop_assert!(ast.root.index() < ast.nodes.len());
            }
        }

        #[test]
        fn prop_depth_never_exceeds_cap(
            toks in token_stream_strategy(),
            src in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            let limits = default_limits();
            let stream = TokenStream { toks, strings: Vec::new() };
            if let Ok(ast) = parse(&stream, &src, &limits) {
                prop_assert!(ast.depth <= limits.max_depth);
                prop_assert!(ast.root.index() == ast.nodes.len().saturating_sub(1));
            }
        }
    }

    fn span_strategy() -> impl Strategy<Value = Span> {
        (0u32..300, 0u32..300).prop_map(|(a, b)| {
            if a <= b {
                Span { start: a, end: b }
            } else {
                Span { start: b, end: a }
            }
        })
    }

    /// Draws from the closed `Tok` alphabet the grammar defines, the shape
    /// #721 named as the fix for a property test that dies at a gate before
    /// it: every variant `parse` can actually see, none excluded, so a
    /// generated stream exercises `primary`, `postfix`, `rel`'s
    /// double-relop check, `elem_list`'s cap and every other branch, not
    /// only the ones a byte-level generator happens to stumble into.
    fn tok_strategy() -> impl Strategy<Value = Tok> {
        prop_oneof![
            span_strategy().prop_map(Tok::Ident),
            any::<i64>().prop_map(Tok::Int),
            span_strategy().prop_map(Tok::Str),
            any::<bool>().prop_map(Tok::Bool),
            Just(Tok::Null),
            Just(Tok::LParen),
            Just(Tok::RParen),
            Just(Tok::LBracket),
            Just(Tok::RBracket),
            Just(Tok::Comma),
            Just(Tok::Dot),
            Just(Tok::Question),
            Just(Tok::Colon),
            Just(Tok::Bang),
            Just(Tok::AndAnd),
            Just(Tok::OrOr),
            Just(Tok::EqEq),
            Just(Tok::BangEq),
            Just(Tok::Lt),
            Just(Tok::Le),
            Just(Tok::Gt),
            Just(Tok::Ge),
            Just(Tok::In),
        ]
    }

    fn spanned_strategy() -> impl Strategy<Value = Spanned> {
        (tok_strategy(), span_strategy()).prop_map(|(tok, span)| Spanned { tok, span })
    }

    fn token_stream_strategy() -> impl Strategy<Value = Vec<Spanned>> {
        proptest::collection::vec(spanned_strategy(), 0..=1024)
    }
}
