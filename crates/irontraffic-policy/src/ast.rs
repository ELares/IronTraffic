// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITPL AST: a flat arena of `Node` values indexed by `NodeId`.
//!
//! The tree owns nothing. Every child reference is a `NodeId` into `Ast::nodes`, so
//! building or dropping an `Ast` never recurses: it is two `Vec`s. See `crate::parse`
//! for how the arena is built and why a flat arena was chosen over a boxed tree.

use crate::token::Span;

/// Index into `Ast::nodes`. `u16`, because `PolicyLimits::max_tokens` caps the
/// token count at 1024 by default (hard cap 8192) and a node count above
/// `u16::MAX` is unreachable for a well-formed program under any limits this
/// crate's `parse` accepts without a deliberately raised `max_tokens`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct NodeId(pub u16);

impl NodeId {
    /// A `NodeId` for a raw index, or `None` when the index would leave no
    /// room to keep `Ast::nodes.len()` within `u16::MAX`.
    ///
    /// #738 should-fix 5: this used to accept `i == 0xFFFF` (`u16::MAX`)
    /// too, which let the arena reach 65,536 nodes, one more than
    /// invariant 1 (`ast.nodes.len() <= u16::MAX`) allows; the shipped
    /// property assertion encoding that invariant
    /// (`u16::try_from(ast.nodes.len()).is_ok()`) could be made false by
    /// parsing exactly that many nodes. Fixed here, in `NodeId::new`,
    /// rather than by weakening the invariant: `0xFFFF` itself is now
    /// reserved and never assigned to a real node, so the largest valid
    /// index is `0xFFFE` (65,534) and `Ast::nodes.len()` can never exceed
    /// `u16::MAX` (65,535). Nothing keys off the exact boundary elsewhere
    /// in this crate (the reachable node count under any limit this crate
    /// accepts without a deliberately raised `max_tokens` is far smaller
    /// than either number), so tightening this one comparison is the
    /// smaller, more local change.
    #[must_use]
    pub const fn new(i: usize) -> Option<NodeId> {
        // `u16::try_from` is not yet usable in a `const fn` on this crate's
        // MSRV, so the bound is a literal and the narrowing cast below is
        // guarded by the check on the line above it rather than expressed
        // with `try_from`.
        if i >= 0xFFFF {
            None
        } else {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "guarded by the i >= 0xFFFF check immediately above: i is proven to fit in u16, strictly less than u16::MAX, before this cast runs"
            )]
            {
                Some(NodeId(i as u16)) // it-allow: unchecked-cast reason: guarded by the i >= 0xFFFF check above; i is proven to fit in u16, strictly less than u16::MAX, before this line runs.
            }
        }
    }

    /// The raw index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// The closed set of methods ITPL understands. A `.` call whose name is not one of
/// these is `ParseError::NotImplemented`, never a call the type checker sees.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Method {
    /// `a.startsWith(b)`: byte prefix.
    StartsWith = 0,
    /// `a.endsWith(b)`: byte suffix.
    EndsWith = 1,
    /// `a.contains(b)`: byte substring.
    Contains = 2,
    /// `a.matches(b)`: regex, compiled at admission.
    Matches = 3,
    /// `a.equalsIgnoreCase(b)`: ASCII case-insensitive equality.
    EqualsIgnoreCase = 4,
    /// `a.startsWithIgnoreCase(b)`: ASCII case-insensitive prefix.
    StartsWithIgnoreCase = 5,
    /// `a.size()`: byte length of a string, element count of a list.
    Size = 6,
}

impl Method {
    /// The method for a name, or `None` when the name is outside the closed set.
    /// Case sensitive: `startswith` is not a method.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Method> {
        match name {
            b"startsWith" => Some(Method::StartsWith),
            b"endsWith" => Some(Method::EndsWith),
            b"contains" => Some(Method::Contains),
            b"matches" => Some(Method::Matches),
            b"equalsIgnoreCase" => Some(Method::EqualsIgnoreCase),
            b"startsWithIgnoreCase" => Some(Method::StartsWithIgnoreCase),
            b"size" => Some(Method::Size),
            _ => None,
        }
    }

    /// The spelling, for error messages and the config-dump surface. It is exactly
    /// the source spelling `from_name` accepts, so the two are inverses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::StartsWith => "startsWith",
            Method::EndsWith => "endsWith",
            Method::Contains => "contains",
            Method::Matches => "matches",
            Method::EqualsIgnoreCase => "equalsIgnoreCase",
            Method::StartsWithIgnoreCase => "startsWithIgnoreCase",
            Method::Size => "size",
        }
    }

    /// How many arguments this method takes: 0 for `size`, 1 for the rest.
    #[must_use]
    pub const fn arity(self) -> u8 {
        match self {
            Method::Size => 0,
            Method::StartsWith
            | Method::EndsWith
            | Method::Contains
            | Method::Matches
            | Method::EqualsIgnoreCase
            | Method::StartsWithIgnoreCase => 1,
        }
    }
}

/// Binary operators that are not `&&`, `||` or the ternary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum BinOp {
    /// `==`
    Eq = 0,
    /// `!=`
    Ne = 1,
    /// `<`
    Lt = 2,
    /// `<=`
    Le = 3,
    /// `>`
    Gt = 4,
    /// `>=`
    Ge = 5,
    /// `in`, membership in a list literal.
    In = 6,
}

/// One AST node. Children are `NodeId`s into the same arena, so the tree owns
/// nothing and dropping it is dropping two `Vec`s.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Node {
    /// `true` or `false`.
    Bool(bool),
    /// An integer literal.
    Int(i64),
    /// A string literal, as a range into `TokenStream::strings`.
    Str(Span),
    /// `null`.
    Null,
    /// A bare identifier, as a range into the source.
    Ident(Span),
    /// `base.name`
    Field {
        /// The receiver.
        base: NodeId,
        /// The field name, as a range into the source.
        name: Span,
    },
    /// `base[index]`
    Index {
        /// The receiver.
        base: NodeId,
        /// The index expression.
        index: NodeId,
    },
    /// `base.method(args)`, `args` a range into `Ast::args`.
    Call {
        /// The receiver.
        base: NodeId,
        /// The closed-set method invoked.
        method: Method,
        /// Start of this call's arguments in `Ast::args`.
        args_from: u16,
        /// Number of arguments in `Ast::args` starting at `args_from`.
        args_len: u16,
    },
    /// `!inner`
    Not {
        /// The negated expression.
        inner: NodeId,
    },
    /// `lhs op rhs` for the relational operators.
    Bin {
        /// The relational operator.
        op: BinOp,
        /// The left operand.
        lhs: NodeId,
        /// The right operand.
        rhs: NodeId,
    },
    /// `lhs && rhs`, short circuiting.
    And {
        /// The left operand.
        lhs: NodeId,
        /// The right operand.
        rhs: NodeId,
    },
    /// `lhs || rhs`, short circuiting.
    Or {
        /// The left operand.
        lhs: NodeId,
        /// The right operand.
        rhs: NodeId,
    },
    /// `cond ? then_ : else_`
    Ternary {
        /// The condition.
        cond: NodeId,
        /// The value when `cond` is true.
        then_: NodeId,
        /// The value when `cond` is false.
        else_: NodeId,
    },
    /// A list literal, a range into `Ast::args`.
    List {
        /// Start of this list's elements in `Ast::args`.
        from: u16,
        /// Number of elements in `Ast::args` starting at `from`.
        len: u16,
    },
}

const _: () = assert!(core::mem::size_of::<Node>() <= 16);

/// A parsed expression: a flat arena of `Node`s in creation order.
///
/// There is no `Ast::default()` and `Ast` derives no `Default`: `root` has no
/// meaningful zero value, and an `Ast` with zero nodes and a root of `NodeId(0)`
/// is a dangling index waiting to be dereferenced. `Ast` is only ever built by
/// `crate::parse::parse` and `crate::parse::parse_expr_at`.
#[derive(Clone, Debug)]
pub struct Ast {
    /// Nodes in creation order. The root is the last node created.
    pub nodes: Vec<Node>,
    /// Child index lists for `Call` and `List`.
    pub args: Vec<NodeId>,
    /// The root node.
    pub root: NodeId,
    /// Maximum nesting depth actually reached while parsing, for the config-dump
    /// surface. Always `<= PolicyLimits::max_depth`.
    pub depth: u16,
}

impl Ast {
    /// The node at `id`, or `None` when the id is out of range.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<Node> {
        self.nodes.get(id.index()).copied()
    }

    /// The argument list a `Call` or `List` names, or an empty slice.
    ///
    /// The range is computed in `usize` (`from as usize + len as usize`, which
    /// cannot overflow from two `u16`s) and resolved with `get`, never with
    /// `[a..b]`. A consumer that receives fewer arguments than the node's arity
    /// promises must treat it as a compile error and must not proceed with the
    /// arguments it got: an empty slice where one argument was expected would
    /// turn `a.startsWith(b)` into something with no operand rather than into a
    /// diagnostic.
    #[must_use]
    pub fn args_of(&self, from: u16, len: u16) -> &[NodeId] {
        let start = usize::from(from);
        let end = start.saturating_add(usize::from(len));
        self.args.get(start..end).unwrap_or(&[])
    }

    /// Number of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True when the arena holds no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_new_accepts_zero_and_u16_max() {
        // #738 should-fix 5: `NodeId::new(65_535)` used to be `Some`, which
        // let `Ast::nodes.len()` reach 65,536, one more than invariant 1
        // (`ast.nodes.len() <= u16::MAX`) allows. `0xFFFF` (`u16::MAX`,
        // 65,535) is now reserved: the largest valid index is `0xFFFE`
        // (65,534), so `Ast::nodes.len()` can never exceed `u16::MAX`.
        assert_eq!(NodeId::new(0), Some(NodeId(0)));
        assert_eq!(NodeId::new(65_534), Some(NodeId(65_534)));
        assert_eq!(NodeId::new(65_535), None);
        assert_eq!(NodeId::new(65_536), None);
        assert_eq!(NodeId::new(usize::MAX), None);
    }

    #[test]
    fn node_id_index_round_trips() {
        assert_eq!(NodeId(42).index(), 42);
    }

    #[test]
    fn method_from_name_is_case_sensitive_and_closed() {
        assert_eq!(Method::from_name(b"startsWith"), Some(Method::StartsWith));
        assert_eq!(Method::from_name(b"endsWith"), Some(Method::EndsWith));
        assert_eq!(Method::from_name(b"contains"), Some(Method::Contains));
        assert_eq!(Method::from_name(b"matches"), Some(Method::Matches));
        assert_eq!(
            Method::from_name(b"equalsIgnoreCase"),
            Some(Method::EqualsIgnoreCase)
        );
        assert_eq!(
            Method::from_name(b"startsWithIgnoreCase"),
            Some(Method::StartsWithIgnoreCase)
        );
        assert_eq!(Method::from_name(b"size"), Some(Method::Size));

        assert_eq!(Method::from_name(b"startswith"), None);
        assert_eq!(Method::from_name(b"StartsWith"), None);
        assert_eq!(Method::from_name(b"unknownMethod"), None);
        assert_eq!(Method::from_name(b""), None);
    }

    #[test]
    fn method_as_str_is_the_inverse_of_from_name() {
        let methods = [
            Method::StartsWith,
            Method::EndsWith,
            Method::Contains,
            Method::Matches,
            Method::EqualsIgnoreCase,
            Method::StartsWithIgnoreCase,
            Method::Size,
        ];
        for m in methods {
            assert_eq!(Method::from_name(m.as_str().as_bytes()), Some(m));
        }
    }

    #[test]
    fn method_arity_is_zero_for_size_and_one_for_everything_else() {
        assert_eq!(Method::Size.arity(), 0);
        assert_eq!(Method::StartsWith.arity(), 1);
        assert_eq!(Method::EndsWith.arity(), 1);
        assert_eq!(Method::Contains.arity(), 1);
        assert_eq!(Method::Matches.arity(), 1);
        assert_eq!(Method::EqualsIgnoreCase.arity(), 1);
        assert_eq!(Method::StartsWithIgnoreCase.arity(), 1);
    }

    #[test]
    fn ast_args_of_resolves_a_valid_range() {
        let ast = Ast {
            nodes: vec![Node::Bool(true), Node::Bool(false)],
            args: vec![NodeId(0), NodeId(1)],
            root: NodeId(1),
            depth: 1,
        };
        assert_eq!(ast.args_of(0, 2), &[NodeId(0), NodeId(1)]);
        let empty: &[NodeId] = &[];
        assert_eq!(ast.args_of(0, 0), empty);
    }

    #[test]
    fn ast_args_of_returns_empty_slice_out_of_range_never_panics() {
        let ast = Ast {
            nodes: vec![Node::Bool(true)],
            args: vec![NodeId(0)],
            root: NodeId(0),
            depth: 1,
        };
        let empty: &[NodeId] = &[];
        assert_eq!(ast.args_of(5, 3), empty);
        assert_eq!(ast.args_of(0, u16::MAX), empty);
        assert_eq!(ast.args_of(u16::MAX, u16::MAX), empty);
    }

    #[test]
    fn ast_len_and_is_empty() {
        let ast = Ast {
            nodes: vec![Node::Bool(true), Node::Null],
            args: vec![],
            root: NodeId(1),
            depth: 1,
        };
        assert_eq!(ast.len(), 2);
        assert!(!ast.is_empty());

        let empty = Ast {
            nodes: vec![],
            args: vec![],
            root: NodeId(0),
            depth: 0,
        };
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn ast_node_returns_none_out_of_range() {
        let ast = Ast {
            nodes: vec![Node::Bool(true)],
            args: vec![],
            root: NodeId(0),
            depth: 1,
        };
        assert_eq!(ast.node(NodeId(0)), Some(Node::Bool(true)));
        assert_eq!(ast.node(NodeId(1)), None);
        assert_eq!(ast.node(NodeId(u16::MAX)), None);
    }
}
