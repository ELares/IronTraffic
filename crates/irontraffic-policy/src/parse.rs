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
    /// (brackets): the grammar for the two is otherwise identical.
    ///
    /// Element ids are buffered in a local `Vec`, never pushed into `self.args`
    /// as they are parsed. `self.args` is the SHARED arena: the element being
    /// parsed here is `self.expr()`, which for a list-of-lists or a call whose
    /// argument is itself a call re-enters `elem_list` before this one
    /// returns, and that nested call pushes into the same `self.args`. Taking
    /// `from` before the loop and `len` from `self.args.len()` after it (the
    /// shape this replaced) counts every one of those nested pushes as this
    /// list's own element: a two-element list whose second element is a call
    /// reports three elements, and the cap enforces against the arena instead
    /// of against the list. Counting locally in `elems` and appending it to
    /// `self.args` in one contiguous slice ONLY after the loop finishes fixes
    /// both: the cap check below counts exactly this list's own elements, and
    /// every already-fixed inner range (built by a nested `elem_list` call
    /// that already returned) stays valid because appending happens once, in
    /// creation order, after every nested contribution is already committed.
    fn elem_list(&mut self, close: Tok) -> Result<(u16, u16), ParseError> {
        if self.eat(close) {
            let from_id = u16::try_from(self.args.len())
                .map_err(|_| ParseError::TooManyNodes { max: u16::MAX })?;
            return Ok((from_id, 0));
        }

        let max = usize::from(self.limits.max_list_elems);
        let mut elems: Vec<NodeId> = Vec::new();
        loop {
            if elems.len() >= max {
                return Err(ParseError::ListTooLong {
                    at: self.span_at(self.pos).start,
                    max: self.limits.max_list_elems,
                });
            }
            let e = self.expr()?;
            elems.push(e);
            if self.eat(Tok::Comma) {
                continue;
            }
            self.expect(close)?; // it-allow: no-panic reason: Parser::expect returns Result and propagates via ?; not Result::expect/Option::expect.
            break;
        }

        let from_id = u16::try_from(self.args.len())
            .map_err(|_| ParseError::TooManyNodes { max: u16::MAX })?;
        let len_id =
            u16::try_from(elems.len()).map_err(|_| ParseError::TooManyNodes { max: u16::MAX })?;
        self.args.extend(elems);
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
    fn false_literal_parses_to_bool_false() {
        // #738 SHOULD_FIX 4: every boolean literal in the test module was
        // `true` before this test existed, so `Tok::Bool(b) =>
        // push(Bool(b))` degrading to `Tok::Bool(_) => push(Bool(true))`
        // survived every mutation. In a policy language that turns `when
        // false then deny` into `when true then deny`.
        let ast = parse_src(b"false", default_limits()).unwrap();
        assert_eq!(ast.nodes, vec![Node::Bool(false)]);
        assert_eq!(ast.root, NodeId(0));
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
    fn every_relational_operator_maps_to_its_own_binop() {
        // #738 SHOULD_FIX 3: only `Eq` was asserted anywhere, and `In` was
        // pinned incidentally by a test that needs `in` to parse at all, not
        // by anything checking what it maps to. `Ne`, `Lt`, `Le`, `Gt`, `Ge`
        // were pinned by nothing: a one-character `relop_of` regression
        // (`Lt` mapping to `Le`, say) could turn `x < 10` into `x <= 10` in
        // a security predicate with the whole suite green. One table over
        // all seven closes every one of those gaps at once.
        let cases: [(&[u8], BinOp); 7] = [
            (b"a == b", BinOp::Eq),
            (b"a != b", BinOp::Ne),
            (b"a < b", BinOp::Lt),
            (b"a <= b", BinOp::Le),
            (b"a > b", BinOp::Gt),
            (b"a >= b", BinOp::Ge),
            (b"a in b", BinOp::In),
        ];
        for (src, expected_op) in cases {
            let ast = parse_src(src, default_limits()).unwrap();
            let Node::Bin { op, .. } = ast.nodes[ast.root.index()] else {
                panic!("{src:?} did not parse to a Bin node: {:?}", ast.nodes);
            };
            assert_eq!(
                op,
                expected_op,
                "{} did not map to {expected_op:?}",
                String::from_utf8_lossy(src)
            );
        }
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
    fn list_element_that_is_a_call_does_not_inflate_len() {
        // #738 BLOCKING 1: `elem_list` used to count `self.expr()`'s nested
        // pushes into the shared `self.args` arena as if they belonged to
        // the outer list. `x.startsWith("/b")` pushes one entry into
        // `self.args` for its own argument; before the fix that entry was
        // miscounted as a second element of the outer two-element list.
        let src = br#"["/a", x.startsWith("/b")]"#;
        let ast = parse_src(src, default_limits()).unwrap();
        let Node::List { from, len } = ast.nodes[ast.root.index()] else {
            panic!("root is not a List: {:?}", ast.nodes[ast.root.index()]);
        };
        assert_eq!(len, 2, "the source has exactly two elements");
        let elems = ast.args_of(from, len);
        assert_eq!(elems.len(), 2);
        assert!(matches!(ast.node(elems[0]), Some(Node::Str(_))));
        assert!(matches!(ast.node(elems[1]), Some(Node::Call { .. })));
    }

    #[test]
    fn nested_list_in_list_counts_outer_elements_only() {
        // #738 BLOCKING 1's other example: the inner lists' own two elements
        // each must not leak into the outer list's count. The outer list has
        // exactly two elements, the two inner `List` nodes, never six.
        let ast = parse_src(b"[[1, 2], [3, 4]]", default_limits()).unwrap();
        let Node::List { from, len } = ast.nodes[ast.root.index()] else {
            panic!("root is not a List: {:?}", ast.nodes[ast.root.index()]);
        };
        assert_eq!(len, 2, "the outer list has exactly two elements");
        let outer = ast.args_of(from, len);
        assert_eq!(outer.len(), 2);
        for &id in outer {
            let Some(Node::List { len: inner_len, .. }) = ast.node(id) else {
                panic!("outer element is not a List");
            };
            assert_eq!(inner_len, 2, "each inner list has exactly two elements");
        }
    }

    #[test]
    fn list_of_call_elements_respects_cap_by_element_count_not_arena_size() {
        // #738 BLOCKING 1's third symptom: with the arena-counting bug, a
        // list of 33 one-argument-call elements (66 arena entries) was
        // refused at `max_list_elems = 64`, a cap the list is 31 elements
        // short of. Pin the real, corrected boundary: 64 call elements
        // (128 arena entries once every call's own argument is counted) is
        // accepted, and 65 is rejected, both against a per-item cap counted
        // per element, not per arena entry.
        let mut limits = default_limits();
        limits.max_list_elems = 64;
        limits.max_tokens = 4096;

        let elems_64: Vec<String> = (0..64).map(|i| format!("a.startsWith(\"{i}\")")).collect();
        let src_64 = format!("[{}]", elems_64.join(", "));
        let ast = parse_src(src_64.as_bytes(), limits).unwrap();
        let Node::List { len, .. } = ast.nodes[ast.root.index()] else {
            panic!("root is not a List");
        };
        assert_eq!(len, 64, "64 call elements must count as 64, not 128");

        let elems_65: Vec<String> = (0..65).map(|i| format!("a.startsWith(\"{i}\")")).collect();
        let src_65 = format!("[{}]", elems_65.join(", "));
        let toks = lex(src_65.as_bytes(), &limits).unwrap();
        let err = parse(&toks, src_65.as_bytes(), &limits).unwrap_err();
        assert!(
            matches!(err, ParseError::ListTooLong { max: 64, .. }),
            "expected ListTooLong at the 65th call element, got {err:?}"
        );
    }

    #[test]
    fn bang_chain_beyond_u16_max_is_too_many_nodes() {
        // #738 SHOULD_FIX 2 / #269 edge case 21: "More nodes than u16::MAX...
        // tested by constructing the parser with a raised token limit."
        // `unary` pushes one `Not` node per leading `!`, with no recursion
        // (see `many_bangs_one_frame`), so a long enough bang chain drives
        // `Parser::push`'s own `NodeId::new` guard past its limit without
        // needing a deliberately raised `max_depth`.
        let n = 70_000;
        let mut src = "!".repeat(n);
        src.push_str("true");

        let mut limits = default_limits();
        limits.max_source_bytes = 200_000;
        limits.max_tokens = 200_000;

        let toks = lex(src.as_bytes(), &limits).expect("lex must accept 70_000 bangs");
        let err = parse(&toks, src.as_bytes(), &limits).unwrap_err();
        assert_eq!(err, ParseError::TooManyNodes { max: u16::MAX });
    }

    #[test]
    fn list_elements_beyond_u16_max_is_too_many_nodes() {
        // #269 edge case 21b: "More argument entries than u16::MAX... the
        // same treatment and the same error: arg_list and list_elems narrow
        // with u16::try_from, so the failure is a diagnostic and never a
        // wrapped index." This drives the SAME `TooManyNodes` error, but
        // reached while `elem_list` is parsing a list's elements (each `!x`
        // element pushes two nodes, an `Ident` and a `Not`) rather than by a
        // bare literal, so the failure is exercised from inside `elem_list`'s
        // own loop and not only from `Parser::push`'s bang-chain path above.
        let n = 40_000;
        let elems: Vec<&str> = std::iter::repeat_n("!x", n).collect();
        let src = format!("[{}]", elems.join(", "));

        let mut limits = default_limits();
        limits.max_source_bytes = 500_000;
        limits.max_tokens = 500_000;
        limits.max_list_elems = u16::MAX;

        let toks = lex(src.as_bytes(), &limits).expect("lex must accept 40_000 `!x` elements");
        let err = parse(&toks, src.as_bytes(), &limits).unwrap_err();
        assert_eq!(err, ParseError::TooManyNodes { max: u16::MAX });
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
    fn max_depth_nested_parens_within_128_kib_stack_is_ok() {
        // #738 SHOULD_FIX 1: #269's acceptance criterion is "a test runs
        // parse on a MAXIMALLY DEEP input inside a thread with a 128 KiB
        // stack and asserts no overflow". `many_bangs_one_frame` and
        // `long_postfix_chain_one_frame` above are the only tests that use
        // a 128 KiB stack, and neither is deep (both reach `ast.depth ==
        // 1`); the two tests that actually reach the default `max_depth`
        // (`depth_cap_trips` and `depth_cap_accepts_at_the_boundary_and_
        // rejects_one_over`) run on the default 8 MiB stack. This is the
        // missing combination: 15 nested parens reaches depth 16, exactly
        // `PolicyLimits::defaults().max_depth`, inside a 128 KiB stack.
        let mut src = "(".repeat(15);
        src.push_str("true");
        src.push_str(&")".repeat(15));
        let limits = default_limits();

        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let toks = lex(src.as_bytes(), &limits).expect("lex must accept 15 nested parens");
                parse(&toks, src.as_bytes(), &limits)
            })
            .expect("spawn 128 KiB thread");
        let result = handle.join().expect("must not stack overflow or panic");
        let ast = result.expect("15 nested parens must parse within a 128 KiB stack");
        assert_eq!(
            ast.depth, 16,
            "15 parens plus the literal itself reaches max_depth"
        );
    }

    #[test]
    fn max_depth_plus_one_nested_parens_within_128_kib_stack_is_too_deep() {
        // The "one over" half of the same criterion, same small stack: 16
        // nested parens needs a 17th `expr` entry just to parse the
        // literal, one past the default `max_depth` of 16, so it must be
        // refused with `TooDeep` rather than overflow the 128 KiB stack.
        let mut src = "(".repeat(16);
        src.push_str("true");
        src.push_str(&")".repeat(16));
        let limits = default_limits();

        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let toks = lex(src.as_bytes(), &limits).expect("lex must accept 16 nested parens");
                parse(&toks, src.as_bytes(), &limits)
            })
            .expect("spawn 128 KiB thread");
        let result = handle.join().expect("must not stack overflow or panic");
        let err = result.expect_err("16 nested parens exceeds max_depth = 16");
        assert_eq!(err, ParseError::TooDeep { at: 16, max: 16 });
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

    // ------------------------------------------------------------------
    // #738 BLOCKING 2: `token_stream_strategy` and its supporting
    // strategies used to draw independent, uniformly random tokens from the
    // closed `Tok` alphabet. Random token soup is never a complete, fully
    // consumed ITPL expression, so `parse` returned `Err` on every one of
    // proptest's 256 default cases, `if let Ok(ast) = parse(..)` never ran,
    // and every `prop_assert!` inside it was dead code: replacing either
    // one with `prop_assert!(false)` left the suite green (#738 M57, M58).
    // The doc comment that used to sit on `tok_strategy` claimed this
    // generator was "the shape #721 named as the fix" for exactly that
    // failure mode; measurement proved the opposite, so that claim and the
    // generator it described are both gone, replaced by one that builds a
    // small expression tree shaped like the grammar and renders it to real
    // ITPL source `lex` and `parse` can actually consume.
    // ------------------------------------------------------------------

    /// A small expression tree, shaped like the ITPL grammar. `render`
    /// turns one of these into source text.
    #[derive(Clone, Debug)]
    enum GenExpr {
        Bool(bool),
        Int(i64),
        Str(String),
        Null,
        Ident(&'static str),
        Field(Box<GenExpr>, &'static str),
        Index(Box<GenExpr>, Box<GenExpr>),
        Call(Box<GenExpr>, Method, Vec<GenExpr>),
        Not(Box<GenExpr>),
        Bin(BinOp, Box<GenExpr>, Box<GenExpr>),
        And(Box<GenExpr>, Box<GenExpr>),
        Or(Box<GenExpr>, Box<GenExpr>),
        Ternary(Box<GenExpr>, Box<GenExpr>, Box<GenExpr>),
        List(Vec<GenExpr>),
    }

    /// A handful of safe identifiers, none of them a keyword (`true`,
    /// `false`, `null`, `in`): the lexer would hand any of those back as
    /// their own token, never as `Tok::Ident`.
    const GEN_IDENTS: &[&str] = &["a", "b", "c", "x", "y", "req", "hdr"];

    const GEN_METHODS: &[Method] = &[
        Method::StartsWith,
        Method::EndsWith,
        Method::Contains,
        Method::Matches,
        Method::EqualsIgnoreCase,
        Method::StartsWithIgnoreCase,
        Method::Size,
    ];

    const GEN_BINOPS: &[BinOp] = &[
        BinOp::Eq,
        BinOp::Ne,
        BinOp::Lt,
        BinOp::Le,
        BinOp::Gt,
        BinOp::Ge,
        BinOp::In,
    ];

    /// The grammar level a `GenExpr` renders at: 0 is loosest (ternary), 6
    /// is tightest (an atomic primary, or a list, which is a primary too).
    /// `render` wraps a child in parentheses exactly when its level is
    /// looser than the minimum level the calling production allows in that
    /// slot, mirroring the real precedence chain (`expr > or > and > rel >
    /// unary > postfix > primary`) instead of wrapping every child and
    /// paying extra parser depth for parentheses the grammar never needed.
    fn expr_level(e: &GenExpr) -> u8 {
        match e {
            GenExpr::Ternary(..) => 0,
            GenExpr::Or(..) => 1,
            GenExpr::And(..) => 2,
            GenExpr::Bin(..) => 3,
            GenExpr::Not(..) => 4,
            GenExpr::Field(..) | GenExpr::Index(..) | GenExpr::Call(..) => 5,
            GenExpr::Bool(_)
            | GenExpr::Int(_)
            | GenExpr::Str(_)
            | GenExpr::Null
            | GenExpr::Ident(_)
            | GenExpr::List(_) => 6,
        }
    }

    fn binop_spelling(op: BinOp) -> &'static str {
        match op {
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::In => "in",
        }
    }

    fn render(e: &GenExpr, min_level: u8, out: &mut String) {
        use std::fmt::Write as _;

        if expr_level(e) < min_level {
            out.push('(');
            render(e, 0, out);
            out.push(')');
            return;
        }
        match e {
            GenExpr::Bool(true) => out.push_str("true"),
            GenExpr::Bool(false) => out.push_str("false"),
            GenExpr::Int(v) => {
                let _ = write!(out, "{v}");
            }
            GenExpr::Str(s) => {
                out.push('"');
                out.push_str(s);
                out.push('"');
            }
            GenExpr::Null => out.push_str("null"),
            GenExpr::Ident(name) => out.push_str(name),
            GenExpr::Field(base, name) => {
                render(base, 5, out);
                out.push('.');
                out.push_str(name);
            }
            GenExpr::Index(base, idx) => {
                render(base, 5, out);
                out.push('[');
                render(idx, 0, out);
                out.push(']');
            }
            GenExpr::Call(base, method, args) => {
                render(base, 5, out);
                out.push('.');
                out.push_str(method.as_str());
                out.push('(');
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    render(a, 0, out);
                }
                out.push(')');
            }
            GenExpr::Not(inner) => {
                out.push('!');
                render(inner, 5, out);
            }
            GenExpr::Bin(op, l, r) => {
                render(l, 4, out);
                out.push(' ');
                out.push_str(binop_spelling(*op));
                out.push(' ');
                render(r, 4, out);
            }
            GenExpr::And(l, r) => {
                render(l, 3, out);
                out.push_str(" && ");
                render(r, 3, out);
            }
            GenExpr::Or(l, r) => {
                render(l, 2, out);
                out.push_str(" || ");
                render(r, 2, out);
            }
            GenExpr::Ternary(c, t, e2) => {
                render(c, 1, out);
                out.push_str(" ? ");
                render(t, 0, out);
                out.push_str(" : ");
                render(e2, 0, out);
            }
            GenExpr::List(elems) => {
                out.push('[');
                for (i, el) in elems.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    render(el, 0, out);
                }
                out.push(']');
            }
        }
    }

    fn arb_method() -> impl Strategy<Value = Method> {
        (0..GEN_METHODS.len()).prop_map(|i| GEN_METHODS[i])
    }

    fn arb_binop() -> impl Strategy<Value = BinOp> {
        (0..GEN_BINOPS.len()).prop_map(|i| GEN_BINOPS[i])
    }

    /// A call generated with exactly the argument count its method's arity
    /// demands (0 for `size`, 1 for everything else). `arity_errors` already
    /// pins `BadArity` directly; this property is about the invariants a
    /// well-formed program must hold, so generated calls are well formed.
    fn arb_call(budget: u32) -> BoxedStrategy<GenExpr> {
        arb_method()
            .prop_flat_map(move |method| {
                let arity = usize::from(method.arity());
                (
                    arb_expr(budget),
                    proptest::collection::vec(arb_expr(budget), arity..=arity),
                )
                    .prop_map(move |(base, args)| GenExpr::Call(Box::new(base), method, args))
            })
            .boxed()
    }

    /// Recursive expression-tree strategy. `budget` bounds how many more
    /// levels of composite nesting are allowed; only leaves are drawn once
    /// it reaches 0. Kept small (`arb_itpl_src` calls this with 3): only
    /// `Ternary`, `Index`, a non-empty `Call`'s arguments and a non-empty
    /// `List`'s elements cost the parser's own depth counter (each re-enters
    /// `expr`), so even a modest budget can chain a few of those before
    /// approaching `PolicyLimits::defaults().max_depth` (16), and a small
    /// budget keeps the rendered source easy to reason about.
    fn arb_expr(budget: u32) -> BoxedStrategy<GenExpr> {
        let leaf = prop_oneof![
            3 => any::<bool>().prop_map(GenExpr::Bool),
            3 => any::<i32>().prop_map(|v| GenExpr::Int(i64::from(v))),
            2 => "[a-zA-Z ]{0,8}".prop_map(GenExpr::Str),
            1 => Just(GenExpr::Null),
            4 => (0..GEN_IDENTS.len()).prop_map(|i| GenExpr::Ident(GEN_IDENTS[i])),
        ];

        if budget == 0 {
            return leaf.boxed();
        }

        let next = budget - 1;
        prop_oneof![
            6 => leaf,
            2 => (arb_expr(next), 0..GEN_IDENTS.len())
                .prop_map(|(base, i)| GenExpr::Field(Box::new(base), GEN_IDENTS[i])),
            1 => (arb_expr(next), arb_expr(next))
                .prop_map(|(base, idx)| GenExpr::Index(Box::new(base), Box::new(idx))),
            2 => arb_call(next),
            1 => arb_expr(next).prop_map(|inner| GenExpr::Not(Box::new(inner))),
            2 => (arb_binop(), arb_expr(next), arb_expr(next))
                .prop_map(|(op, l, r)| GenExpr::Bin(op, Box::new(l), Box::new(r))),
            2 => (arb_expr(next), arb_expr(next))
                .prop_map(|(l, r)| GenExpr::And(Box::new(l), Box::new(r))),
            2 => (arb_expr(next), arb_expr(next))
                .prop_map(|(l, r)| GenExpr::Or(Box::new(l), Box::new(r))),
            1 => (arb_expr(next), arb_expr(next), arb_expr(next))
                .prop_map(|(c, t, e)| GenExpr::Ternary(Box::new(c), Box::new(t), Box::new(e))),
            1 => proptest::collection::vec(arb_expr(next), 0..4).prop_map(GenExpr::List),
        ]
        .boxed()
    }

    /// Renders a generated tree to ITPL source, then sometimes damages it:
    /// about one case in eight gets a trailing identifier appended (a
    /// guaranteed `TrailingTokens`, since `parse` requires the whole stream
    /// consumed) and about one in eight is truncated by one byte (usually
    /// `UnexpectedEof` or `Unexpected`, occasionally still a shorter valid
    /// program). The rest renders untouched. This keeps the property
    /// exercising real `Err` paths too, without making `Err` the only
    /// reachable outcome the way the byte-soup generator it replaced did.
    fn arb_itpl_src() -> impl Strategy<Value = Vec<u8>> {
        (arb_expr(3), 0u8..8).prop_map(|(expr, roll)| {
            let mut src = String::new();
            render(&expr, 0, &mut src);
            match roll {
                0 => src.push_str(" then"),
                1 => {
                    src.pop();
                }
                _ => {}
            }
            src.into_bytes()
        })
    }

    /// The `(from, len)` arg-range a `Call` or `List` names, or `None` for
    /// every other variant.
    fn args_range_of(node: Node) -> Option<(u16, u16)> {
        match node {
            Node::Call {
                args_from,
                args_len,
                ..
            } => Some((args_from, args_len)),
            Node::List { from, len } => Some((from, len)),
            _ => None,
        }
    }

    /// Every `NodeId` a node carries directly or through `Ast::args_of`, for
    /// the "every child id is strictly less than its own" invariant.
    /// Mirrors `node_children_have_smaller_ids`'s inline match, generalized
    /// to run against whatever tree the property generator produced rather
    /// than one fixed 50-node expression.
    fn node_children_ids(ast: &Ast, node: Node) -> Vec<NodeId> {
        match node {
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
            Node::Bool(_) | Node::Int(_) | Node::Str(_) | Node::Null | Node::Ident(_) => vec![],
        }
    }

    proptest! {
        #[test]
        fn prop_parse_never_panics(src in arb_itpl_src()) {
            let limits = default_limits();
            // `lex` failing is a legitimate outcome (the truncation and
            // trailing-token damage in `arb_itpl_src` can produce that), not
            // something to route around: only a successfully lexed,
            // successfully parsed program is checked below.
            if let Ok(toks) = lex(&src, &limits)
                && let Ok(ast) = parse(&toks, &src, &limits)
            {
                prop_assert!(u16::try_from(ast.nodes.len()).is_ok());
                prop_assert!(ast.root.index() < ast.nodes.len());
                for (i, node) in ast.nodes.iter().enumerate() {
                    if let Some((from, len)) = args_range_of(*node) {
                        let end = usize::from(from) + usize::from(len);
                        prop_assert!(
                            end <= ast.args.len(),
                            "node {i} args range {from}..{end} exceeds args.len() {}",
                            ast.args.len()
                        );
                    }
                    for child in node_children_ids(&ast, *node) {
                        prop_assert!(child.index() < i, "node {i} has child {child:?}");
                    }
                }
            }
        }

        #[test]
        fn prop_depth_never_exceeds_cap(src in arb_itpl_src()) {
            let limits = default_limits();
            if let Ok(toks) = lex(&src, &limits)
                && let Ok(ast) = parse(&toks, &src, &limits)
            {
                prop_assert!(ast.depth <= limits.max_depth);
                prop_assert!(ast.root.index() == ast.nodes.len().saturating_sub(1));
            }
        }
    }
}
