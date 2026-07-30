// SPDX-License-Identifier: MIT OR Apache-2.0

//! ITPL, the IronTraffic Policy Language: a CEL-syntax-compatible, statically typed,
//! total expression language compiled to flat bytecode at config-admission time.
//!
//! ITPL has no loops, no recursion and no user-defined functions, so every expression
//! terminates in time linear in its bytecode length. See `docs/ITPL.md`.
//!
//! # Grammar
//!
//! ```ebnf
//! expr        = ternary ;
//! ternary     = or [ "?" expr ":" expr ] ;
//! or          = and { "||" and } ;
//! and         = rel { "&&" rel } ;
//! rel         = unary [ relop unary ] ;
//! relop       = "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" ;
//! unary       = { "!" } postfix ;
//! postfix     = primary { field | index | call } ;
//! field       = "." IDENT ;
//! index       = "[" expr "]" ;
//! call        = "." IDENT "(" [ expr { "," expr } ] ")" ;
//! primary     = IDENT | INT | STRING | "true" | "false" | "null" | "(" expr ")" | list ;
//! list        = "[" [ expr { "," expr } ] "]" ;
//!
//! IDENT       = ( ALPHA | "_" ) { ALPHA | DIGIT | "_" } ;
//! INT         = [ "-" ] DIGIT { DIGIT } ;
//! STRING      = '"' { CHAR | ESCAPE } '"' | "'" { CHAR | ESCAPE } "'" ;
//! ESCAPE      = "\\" ( "n" | "r" | "t" | "\\" | '"' | "'" | "0"
//!                    | "x" HEX HEX | "u" HEX HEX HEX HEX ) ;
//! ```
//!
//! Precedence, loosest to tightest: ternary, `||`, `&&`, relational, unary `!`, postfix.
//! `&&` and `||` are left associative and short circuit. The ternary is right associative.
//! There is no arithmetic in v1.
//!
//! The closed method set is: `startsWith`, `endsWith`, `contains`, `matches`,
//! `equalsIgnoreCase`, `startsWithIgnoreCase`, `size`.

#![forbid(unsafe_code)]

pub mod ast;
pub mod attrs;
pub mod check;
pub mod compile;
pub mod lex;
pub mod limits;
pub mod parse;
pub mod program;
pub mod token;
pub mod value;
pub mod vm;

pub use ast::{Ast, BinOp, Method, Node, NodeId};
pub use attrs::{ATTRS, AttrEntry, AttrId, MAX_PATH_BYTES, MapId, NAMESPACES, Ty, resolve_path};
pub use check::{AttrRef, CheckError, Checked, check};
pub use compile::{CompileError, compile};
pub use limits::PolicyLimits;
pub use parse::{ParseError, parse, parse_expr_at};
pub use program::{Const, Op, Program, VerifyError, verify};
pub use token::{LexError, Span, Spanned, Tok, TokenStream};
pub use value::Value;
pub use vm::{
    AttrSource, Env, EvalError, FieldOutcome, duplicate_header_count, eval, record_duplicate_header,
};
