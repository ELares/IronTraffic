// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compiles a type-checked ITPL expression to a flat, verified `Program`.
//!
//! One forward pass over the checked arena emits a post-order instruction
//! sequence with no recursion, no splicing, and no backward jump: see
//! `crate::program` for the artifact this produces and the verifier that
//! proves it total. `compile` never trusts its own output; every program it
//! builds is run through `crate::program::verify` before it is returned, so a
//! compiler bug shows up as a `CompileError::Verify`, never as a silently
//! wrong `Program`.

use crate::ast::{Ast, BinOp, Method, Node, NodeId};
use crate::check::Checked;
use crate::limits::PolicyLimits;
use crate::program::{Const, Op, Program, VerifyError, verify};

/// Why a checked expression could not be compiled.
#[derive(Clone, Debug)]
pub enum CompileError {
    /// A regex that `regex` refused, with its message verbatim.
    BadRegex {
        /// Source offset of the pattern literal.
        at: u32,
        /// The crate's own error message, or ours when the pattern's decoded
        /// bytes are not valid UTF-8 and never reached the crate at all.
        message: Box<str>,
    },
    /// More regexes than `PolicyLimits::max_regex`.
    TooManyRegexes {
        /// The configured limit.
        max: u16,
    },
    /// More constants than `PolicyLimits::max_consts`.
    TooManyConsts {
        /// The configured limit.
        max: u16,
    },
    /// The emitted program failed verification. Always a compiler bug, never bad
    /// input, and the message says so.
    Verify(VerifyError),
}

/// Where a forward placeholder jump instruction must be reserved, and which
/// opcode it eventually becomes. Filled in by `build_hole_before`, one entry
/// per node id, and consumed (patched) when the forward sweep reaches the
/// `And`/`Or`/`Ternary` node that owns the hole.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HoleKind {
    JumpIfFalse,
    JumpIfTrue,
    BranchIfFalse,
    Jump,
}

fn placeholder_for(kind: HoleKind) -> Op {
    match kind {
        HoleKind::JumpIfFalse => Op::JumpIfFalse(0),
        HoleKind::JumpIfTrue => Op::JumpIfTrue(0),
        HoleKind::BranchIfFalse => Op::BranchIfFalse(0),
        HoleKind::Jump => Op::Jump(0),
    }
}

fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn mark_hole(hole_before: &mut [Option<HoleKind>], idx: usize, kind: HoleKind) {
    if let Some(slot) = hole_before.get_mut(idx) {
        *slot = Some(kind);
    }
}

fn mark_bool(flags: &mut [bool], idx: usize) {
    if let Some(slot) = flags.get_mut(idx) {
        *slot = true;
    }
}

/// Pass zero: for every `And`/`Or`/`Ternary` node, records where its
/// short-circuit jump's placeholder must be reserved. The placeholder sits
/// before the FIRST node of the right operand's subtree (`lhs.index() + 1`,
/// `cond.index() + 1`, `then_.index() + 1`), never before the operand's own
/// root, which is the one thing an implementer gets wrong: see the module
/// doc and the issue's own worked example for why.
fn build_hole_before(ast: &Ast, n: usize) -> Vec<Option<HoleKind>> {
    let mut hole_before = vec![None; n];
    for node in &ast.nodes {
        match *node {
            Node::And { lhs, .. } => {
                mark_hole(&mut hole_before, lhs.index() + 1, HoleKind::JumpIfFalse);
            }
            Node::Or { lhs, .. } => {
                mark_hole(&mut hole_before, lhs.index() + 1, HoleKind::JumpIfTrue);
            }
            Node::Ternary { cond, then_, .. } => {
                mark_hole(&mut hole_before, cond.index() + 1, HoleKind::BranchIfFalse);
                mark_hole(&mut hole_before, then_.index() + 1, HoleKind::Jump);
            }
            _ => {}
        }
    }
    hole_before
}

/// Marks every node id whose own code emission is folded away by a parent
/// instead of emitted directly: a LITERAL element of a list literal (folded
/// into `Const::List`/`Const::Int` by the `List` and `.size()` cases below)
/// and the pattern argument of a `matches` call (folded into the regex
/// table, never pushed onto the operand stack).
///
/// **Only a literal (`Bool`/`Int`/`Str`/`Null`) list element is suppressed.**
/// A list element that is a bare attribute reference (`Ident`/`Field`/
/// `Index`), or any other non-literal expression, is deliberately left
/// UNSUPPRESSED, so the forward sweep emits its `LoadAttr` (or whatever code
/// it has) exactly as it would for any other node. The type checker
/// (`{{itpl-attribute-schema-and-typecheck}}`, #270, frozen; not touched by
/// this issue) constrains a list literal's elements by TYPE only
/// (`check_list`), not by "is this a literal", so `[request.method, "GET"]`
/// type checks even though `Const::List` has no representation for a value
/// that is not known until request time. Emitting that element's `LoadAttr`
/// anyway leaves a dangling, un-popped value on the operand stack (the
/// `List` node itself pushes nothing, and nothing downstream consumes it),
/// which `verify` catches as `StackNotSingleton` and turns into
/// `CompileError::Verify`: admission is refused, uniformly with how a
/// COMPOUND list element (`a && b`, `x.startsWith("y")`, a nested ternary)
/// already fails today, rather than the element silently degrading to
/// `Const::Null` and changing what an admitted policy means. This crate must
/// never admit a policy whose compiled meaning differs from its source; see
/// the PR for #271 / issue #758 finding 3 for the full account of why the
/// previous, suppress-everything behaviour was wrong.
fn build_suppressed(ast: &Ast, n: usize) -> Vec<bool> {
    let mut suppressed = vec![false; n];
    for node in &ast.nodes {
        match *node {
            Node::List { from, len } => {
                for &elem in ast.args_of(from, len) {
                    if is_literal_node(ast, elem) {
                        mark_bool(&mut suppressed, elem.index());
                    }
                }
            }
            Node::Call {
                method: Method::Matches,
                args_from,
                args_len,
                ..
            } => {
                if let Some(&pat) = ast.args_of(args_from, args_len).first() {
                    mark_bool(&mut suppressed, pat.index());
                }
            }
            _ => {}
        }
    }
    suppressed
}

/// Whether `id` is one of the four literal node kinds `const_of_leaf` can
/// fold without loss: exactly the shapes a list element must be for
/// suppressing its own code emission to be safe. See `build_suppressed`'s
/// doc comment for why every other node kind must NOT be suppressed.
fn is_literal_node(ast: &Ast, id: NodeId) -> bool {
    matches!(
        ast.node(id),
        Some(Node::Bool(_) | Node::Int(_) | Node::Str(_) | Node::Null)
    )
}

/// Resolves a `(from, len)` byte range, or an empty slice when it is invalid.
fn slice_of(buf: &[u8], from: u32, len: u32) -> &[u8] {
    let start = usize::try_from(from).unwrap_or(usize::MAX);
    let want = usize::try_from(len).unwrap_or(usize::MAX);
    let end = start.saturating_add(want);
    buf.get(start..end).unwrap_or(&[])
}

/// Byte-content equality for constant interning, per "interning is by exact
/// byte equality over the decoded string arena": two `Const::Str` values with
/// different `(from, len)` ranges that happen to name the same bytes are the
/// SAME constant, and a `Const::List` is equal to another when its elements
/// are, recursively.
fn const_eq(a: &Const, b: &Const, strings: &[u8], list_elems: &[Const]) -> bool {
    match (a, b) {
        (Const::Bool(x), Const::Bool(y)) => x == y,
        (Const::Int(x), Const::Int(y)) => x == y,
        (Const::Null, Const::Null) => true,
        (Const::Str { from: f1, len: l1 }, Const::Str { from: f2, len: l2 }) => {
            slice_of(strings, *f1, *l1) == slice_of(strings, *f2, *l2)
        }
        (Const::List { from: f1, len: l1 }, Const::List { from: f2, len: l2 }) => {
            let a_elems = elems_of(list_elems, *f1, *l1);
            let b_elems = elems_of(list_elems, *f2, *l2);
            a_elems.len() == b_elems.len()
                && a_elems
                    .iter()
                    .zip(b_elems.iter())
                    .all(|(x, y)| const_eq(x, y, strings, list_elems))
        }
        _ => false,
    }
}

fn elems_of(buf: &[Const], from: u32, len: u32) -> &[Const] {
    let start = usize::try_from(from).unwrap_or(usize::MAX);
    let want = usize::try_from(len).unwrap_or(usize::MAX);
    let end = start.saturating_add(want);
    buf.get(start..end).unwrap_or(&[])
}

/// Converts a list element node directly to the `Const` it folds to.
/// `Bool`/`Int`/`Str`/`Null` are the only shapes reachable here in a program
/// that goes on to compile `Ok`: every other node kind is a non-literal list
/// element (see `build_suppressed`'s doc comment), which is now left
/// UNSUPPRESSED, so its own dangling code always trips `verify`'s
/// `StackNotSingleton` before `Ok` is ever returned. The `_ => Const::Null`
/// arm below therefore only ever contributes to a `list_elems` array that a
/// FAILED `compile` call throws away; it stays as a total, panic-free
/// fallback (this function has no `Result` to report through, and a bogus
/// intermediate value is harmless when the program that would carry it is
/// never admitted) rather than because a real, successfully compiled program
/// can still reach it.
fn const_of_leaf(ast: &Ast, id: NodeId) -> Const {
    match ast.node(id) {
        Some(Node::Bool(b)) => Const::Bool(b),
        Some(Node::Int(v)) => Const::Int(v),
        Some(Node::Str(sp)) => Const::Str {
            from: sp.start,
            len: sp.len(),
        },
        _ => Const::Null,
    }
}

fn is_list_node(ast: &Ast, id: NodeId) -> bool {
    matches!(ast.node(id), Some(Node::List { .. }))
}

fn list_len_of(ast: &Ast, id: NodeId) -> u16 {
    match ast.node(id) {
        Some(Node::List { len, .. }) => len,
        _ => 0,
    }
}

/// The comparison opcode for the six ordinary `BinOp`s. `In` is peeled off by
/// `Compiler::emit_node`'s own dedicated arm before this is ever called;
/// folded into the same arm as `Eq` (rather than kept as its own, separate
/// fallback arm that panics on nothing) because clippy's `match_same_arms`
/// otherwise flags two arms with identical bodies. `In` never actually
/// reaches this match.
fn comparison_op(op: BinOp) -> Op {
    match op {
        BinOp::Eq | BinOp::In => Op::Eq,
        BinOp::Ne => Op::Ne,
        BinOp::Lt => Op::Lt,
        BinOp::Le => Op::Le,
        BinOp::Gt => Op::Gt,
        BinOp::Ge => Op::Ge,
    }
}

/// The opcode for the five `Method`s that always emit directly. `Size` and
/// `Matches` are peeled off by their own dedicated arms in
/// `Compiler::emit_node` before this is ever called; see `comparison_op`'s
/// comment for why the fallback below is still total rather than a panic.
fn method_op(method: Method) -> Op {
    match method {
        Method::StartsWith => Op::StartsWith,
        Method::EndsWith => Op::EndsWith,
        Method::Contains => Op::Contains,
        Method::EqualsIgnoreCase => Op::EqIgnoreCase,
        Method::StartsWithIgnoreCase => Op::StartsWithIgnoreCase,
        Method::Size | Method::Matches => Op::Not,
    }
}

/// Holds every array the forward sweep builds, plus the borrows it needs
/// throughout. Mirrors `crate::check::Checker`'s shape for the same reason:
/// one struct threading state through a flat, non-recursive forward pass.
struct Compiler<'a> {
    checked: &'a Checked,
    limits: &'a PolicyLimits,
    hole_before: Vec<Option<HoleKind>>,
    /// Where each subtree's placeholder actually landed in `code`.
    hole_pos: Vec<u16>,
    suppressed: Vec<bool>,
    /// Written only by the `List` case, read only by the `Bin { op: In, .. }`
    /// case: the constant index a `List` node interned, keyed by that node's
    /// own id.
    node_const: Vec<u16>,
    code: Vec<Op>,
    consts: Vec<Const>,
    list_elems: Vec<Const>,
    regexes: Vec<regex::bytes::Regex>,
}

impl<'a> Compiler<'a> {
    /// `self.checked`, decoupled from `&self`'s own (shorter) elided
    /// lifetime. `&'a Checked` is `Copy`, so reading it out of `self` first
    /// and using THAT local instead of `self.checked.x` everywhere is what
    /// lets an `&'a Ast`/`&'a [u8]` borrowed through it outlive a later
    /// `&mut self` call in the same expression, which `self.checked.x`
    /// (tied to `&self`) cannot.
    fn checked(&self) -> &'a Checked {
        self.checked
    }

    fn ast(&self) -> &'a Ast {
        &self.checked().ast
    }

    fn intern_const(&mut self, want: Const) -> Result<u16, CompileError> {
        let strings = &self.checked().strings;
        let found = self
            .consts
            .iter()
            .position(|c| const_eq(c, &want, strings, &self.list_elems));
        if let Some(i) = found {
            return Ok(to_u16(i));
        }
        if self.consts.len() >= usize::from(self.limits.max_consts) {
            return Err(CompileError::TooManyConsts {
                max: self.limits.max_consts,
            });
        }
        self.consts.push(want);
        Ok(to_u16(self.consts.len().saturating_sub(1)))
    }

    fn intern_regex(&mut self, pattern: &str, at: u32) -> Result<u16, CompileError> {
        if let Some(i) = self.regexes.iter().position(|r| r.as_str() == pattern) {
            return Ok(to_u16(i));
        }
        if self.regexes.len() >= usize::from(self.limits.max_regex) {
            return Err(CompileError::TooManyRegexes {
                max: self.limits.max_regex,
            });
        }
        let size_limit = usize::try_from(self.limits.max_regex_size).unwrap_or(usize::MAX);
        let built = regex::bytes::RegexBuilder::new(pattern)
            .size_limit(size_limit)
            .dfa_size_limit(size_limit)
            .unicode(false)
            .case_insensitive(false)
            .build()
            .map_err(|e| CompileError::BadRegex {
                at,
                message: e.to_string().into_boxed_str(),
            })?;
        self.regexes.push(built);
        Ok(to_u16(self.regexes.len().saturating_sub(1)))
    }

    fn open_hole(&mut self, i: usize) {
        let Some(kind) = self.hole_before.get(i).copied().flatten() else {
            return;
        };
        let pos = to_u16(self.code.len());
        if let Some(slot) = self.hole_pos.get_mut(i) {
            *slot = pos;
        }
        self.code.push(placeholder_for(kind));
    }

    fn patch(&mut self, key: usize, target: u16) {
        let Some(&pos) = self.hole_pos.get(key) else {
            return;
        };
        let Some(slot) = self.code.get_mut(usize::from(pos)) else {
            return;
        };
        match slot {
            Op::Jump(t) | Op::JumpIfFalse(t) | Op::JumpIfTrue(t) | Op::BranchIfFalse(t) => {
                *t = target;
            }
            _ => {}
        }
    }

    fn is_suppressed(&self, i: usize) -> bool {
        self.suppressed.get(i).copied().unwrap_or(false)
    }

    fn emit_leaf(&mut self, i: usize, want: Const) -> Result<(), CompileError> {
        if self.is_suppressed(i) {
            return Ok(());
        }
        let c = self.intern_const(want)?;
        self.code.push(Op::LoadConst(c));
        Ok(())
    }

    fn emit_attr(&mut self, i: usize) {
        if self.is_suppressed(i) {
            return;
        }
        let slot = self
            .checked
            .node_slot
            .get(i)
            .copied()
            .unwrap_or(Checked::NO_SLOT);
        if slot != Checked::NO_SLOT {
            self.code.push(Op::LoadAttr(slot));
        }
    }

    fn emit_size_call(&mut self, base: NodeId) -> Result<(), CompileError> {
        let ast = self.ast();
        if is_list_node(ast, base) {
            // #26: `.size()` on a list literal is constant-folded, never a
            // bare `Op::Size` on a stack the `List` node itself never pushed
            // to (see `build_suppressed`'s doc comment and the `List` case
            // below: a `List` node emits nothing of its own).
            let len = list_len_of(ast, base);
            let c = self.intern_const(Const::Int(i64::from(len)))?;
            self.code.push(Op::LoadConst(c));
        } else {
            self.code.push(Op::Size);
        }
        Ok(())
    }

    fn emit_matches_call(&mut self, args_from: u16, args_len: u16) -> Result<(), CompileError> {
        let ast = self.ast();
        let strings = &self.checked().strings;
        let args = ast.args_of(args_from, args_len);
        let (pattern_bytes, at) = match args.first().and_then(|&a| ast.node(a).map(|nd| (nd, a))) {
            Some((Node::Str(sp), _)) => (slice_of(strings, sp.start, sp.len()), sp.start),
            // The checker's `NonConstantRegex` rejects any `matches` argument
            // that is not a string literal, so this arm is unreachable for a
            // `Checked` built by `check`. Kept total (an empty pattern
            // compiles and matches only the empty string) rather than
            // panicking, in case a test constructs an adversarial `Checked`
            // directly, which `Checked`'s public fields allow.
            _ => (&[][..], 0u32),
        };
        let Ok(pattern) = core::str::from_utf8(pattern_bytes) else {
            return Err(CompileError::BadRegex {
                at,
                message: "regex pattern is not valid UTF-8".into(),
            });
        };
        let idx = self.intern_regex(pattern, at)?;
        self.code.push(Op::RegexMatch(idx));
        Ok(())
    }

    fn emit_list(&mut self, i: usize, from: u16, len: u16) -> Result<(), CompileError> {
        let ast = self.ast();
        let elems = ast.args_of(from, len);
        let built: Vec<Const> = elems.iter().map(|&e| const_of_leaf(ast, e)).collect();
        let from_idx = to_u32(self.list_elems.len());
        self.list_elems.extend(built);
        let len_u32 = to_u32(elems.len());
        let c = self.intern_const(Const::List {
            from: from_idx,
            len: len_u32,
        })?;
        if let Some(slot) = self.node_const.get_mut(i) {
            *slot = c;
        }
        Ok(())
    }

    fn emit_node(&mut self, i: usize, node: Node) -> Result<(), CompileError> {
        match node {
            Node::Bool(b) => self.emit_leaf(i, Const::Bool(b))?,
            Node::Int(v) => self.emit_leaf(i, Const::Int(v))?,
            Node::Str(sp) => self.emit_leaf(
                i,
                Const::Str {
                    from: sp.start,
                    len: sp.len(),
                },
            )?,
            Node::Null => self.emit_leaf(i, Const::Null)?,
            Node::Ident(_) | Node::Field { .. } | Node::Index { .. } => self.emit_attr(i),
            Node::Not { .. } => self.code.push(Op::Not),
            Node::Bin {
                op: BinOp::In, rhs, ..
            } => {
                let c = self.node_const.get(rhs.index()).copied().unwrap_or(0);
                self.code.push(Op::InSet(c));
            }
            Node::Bin { op, .. } => self.code.push(comparison_op(op)),
            Node::Call {
                method: Method::Size,
                base,
                ..
            } => self.emit_size_call(base)?,
            Node::Call {
                method: Method::Matches,
                args_from,
                args_len,
                ..
            } => self.emit_matches_call(args_from, args_len)?,
            Node::Call { method, .. } => self.code.push(method_op(method)),
            // `And` and `Or` patch an identical shape (their own hole,
            // reserved before the right operand's first node, targets
            // "after the right operand", which is exactly `code.len()` right
            // here): one merged arm, not two with identical bodies.
            Node::And { lhs, .. } | Node::Or { lhs, .. } => {
                let target = to_u16(self.code.len());
                self.patch(lhs.index() + 1, target);
            }
            Node::Ternary { cond, then_, .. } => {
                // 14a: the `Jump` past `else_` targets "after the whole
                // ternary", which is exactly here: `else_`'s code (and any
                // hole it owns) is already fully emitted, and the `Ternary`
                // node itself emits nothing.
                let after_else = to_u16(self.code.len());
                self.patch(then_.index() + 1, after_else);
                // 14b: the `BranchIfFalse` targets the instruction right
                // after the `Jump`, which is where `else_`'s code begins.
                let jump_pos = self
                    .hole_pos
                    .get(then_.index() + 1)
                    .copied()
                    .unwrap_or(u16::MAX);
                self.patch(cond.index() + 1, jump_pos.saturating_add(1));
            }
            Node::List { from, len } => self.emit_list(i, from, len)?,
        }
        Ok(())
    }
}

/// Compiles a type-checked expression.
///
/// # Errors
/// `CompileError::BadRegex`, `TooManyRegexes`, `TooManyConsts`, `Verify`.
pub fn compile(checked: &Checked, limits: &PolicyLimits) -> Result<Program, CompileError> {
    let ast = &checked.ast;
    let n = ast.nodes.len();

    let hole_before = build_hole_before(ast, n);
    let suppressed = build_suppressed(ast, n);

    let mut compiler = Compiler {
        checked,
        limits,
        hole_before,
        hole_pos: vec![u16::MAX; n],
        suppressed,
        node_const: vec![0; n],
        code: Vec::new(),
        consts: Vec::new(),
        list_elems: Vec::new(),
        regexes: Vec::new(),
    };

    for i in 0..n {
        let Some(node) = ast.nodes.get(i).copied() else {
            break;
        };
        compiler.open_hole(i);
        compiler.emit_node(i, node)?;
    }

    compiler.code.push(Op::Ret);

    let regex_count = compiler.regexes.len();
    let max_stack = verify(
        &compiler.code,
        &compiler.consts,
        &checked.slots,
        regex_count,
        limits,
    )
    .map_err(CompileError::Verify)?;

    // This clone is the one that is structurally unavoidable: `compile` takes
    // `checked: &Checked` (a borrow, per this issue's own `## Public API`),
    // so it cannot move `checked.strings` out of its caller's value without
    // either an owned parameter (which the issue's signature forecloses) or
    // an `Rc`/`Arc` (a representation change to `Checked` itself, which is
    // #270's frozen file). `check`'s own clone was the avoidable one and was
    // removed with `mem::take`; this second copy pays for `Program` becoming
    // the long-lived, independently owned artifact every worker shares
    // through the configuration snapshot, once per admitted policy.
    Ok(Program::new(
        compiler.code.into_boxed_slice(),
        compiler.consts.into_boxed_slice(),
        compiler.list_elems.into_boxed_slice(),
        checked.strings.clone().into_boxed_slice(),
        checked.slots.clone().into_boxed_slice(),
        compiler.regexes.into_boxed_slice(),
        checked.result,
        checked.phase,
        max_stack,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::check;
    use crate::lex::lex;
    use crate::parse::parse;
    use irontraffic_filter::Phase;
    use proptest::prelude::*;

    fn default_limits() -> PolicyLimits {
        PolicyLimits::defaults()
    }

    /// Lexes, parses, checks and compiles `src` at `phase` with default limits.
    fn compile_src(src: &[u8], phase: Phase) -> Result<Program, String> {
        let limits = default_limits();
        let toks = lex(src, &limits).map_err(|e| format!("{e:?}"))?;
        let ast = parse(&toks, src, &limits).map_err(|e| format!("{e:?}"))?;
        let mut strings = toks.strings;
        let checked =
            check(ast, &mut strings, src, phase, &limits).map_err(|e| format!("{e:?}"))?;
        compile(&checked, &limits).map_err(|e| format!("{e:?}"))
    }

    fn compile_src_with_limits(
        src: &[u8],
        phase: Phase,
        limits: PolicyLimits,
    ) -> Result<Program, CompileError> {
        let toks = lex(src, &limits).expect("valid ITPL source must lex");
        let ast = parse(&toks, src, &limits).expect("valid ITPL source must parse");
        let mut strings = toks.strings;
        let checked =
            check(ast, &mut strings, src, phase, &limits).expect("valid ITPL source must check");
        compile(&checked, &limits)
    }

    // ------------------------------------------------------------------
    // Named tests 1-16b.
    // ------------------------------------------------------------------

    #[test]
    fn constant_only_program() {
        // Test 1 / edge case 1: `true` compiles to one `LoadConst` and `Ret`,
        // no jumps, `max_stack == 1`.
        let program = compile_src(b"true", Phase::Log).unwrap();
        assert_eq!(program.ops(), &[Op::LoadConst(0), Op::Ret]);
        assert_eq!(program.consts(), &[Const::Bool(true)]);
        assert_eq!(program.max_stack(), 1);
    }

    #[test]
    fn and_lowering() {
        // Test 2: exact instruction sequence for
        // `request.method == "GET" && request.port == 80`.
        let program = compile_src(
            br#"request.method == "GET" && request.port == 80"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[
                Op::LoadAttr(0),
                Op::LoadConst(0),
                Op::Eq,
                Op::JumpIfFalse(7),
                Op::LoadAttr(1),
                Op::LoadConst(1),
                Op::Eq,
                Op::Ret,
            ]
        );
    }

    #[test]
    fn and_chain_lowering() {
        // Test 3: `a && b && c` (three same-attribute-typed comparisons).
        // The first `JumpIfFalse` targets the second, and the second targets
        // `Ret`; targets are never threaded to skip an intermediate jump.
        // Hand-computed from the compiler's own algorithm (see the PR for the
        // full node-by-node trace): two clauses of `LoadAttr, LoadConst, Eq`
        // separated and followed by a `JumpIfFalse`, then `Ret`.
        let program = compile_src(
            br#"request.method == "a" && request.path == "b" && request.query == "c""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[
                Op::LoadAttr(0),
                Op::LoadConst(0),
                Op::Eq,
                Op::JumpIfFalse(7),
                Op::LoadAttr(1),
                Op::LoadConst(1),
                Op::Eq,
                Op::JumpIfFalse(11),
                Op::LoadAttr(2),
                Op::LoadConst(2),
                Op::Eq,
                Op::Ret,
            ]
        );
    }

    #[test]
    fn or_lowering() {
        // Test 4.
        let program = compile_src(
            br#"request.method == "GET" || request.method == "POST""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        let ops = program.ops();
        assert_eq!(
            ops,
            &[
                Op::LoadAttr(0),
                Op::LoadConst(0),
                Op::Eq,
                Op::JumpIfTrue(7),
                Op::LoadAttr(0),
                Op::LoadConst(1),
                Op::Eq,
                Op::Ret,
            ]
        );
    }

    #[test]
    fn ternary_lowering() {
        // Test 5: both jumps forward, targets asserted.
        let program = compile_src(
            br#"request.port == 1 ? request.method == "a" : request.path == "b""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        let ops = program.ops();
        // cond: LoadAttr, LoadConst, Eq (0,1,2); BranchIfFalse (3);
        // then_: LoadAttr, LoadConst, Eq (4,5,6); Jump (7);
        // else_: LoadAttr, LoadConst, Eq (8,9,10); Ret (11).
        assert_eq!(
            ops,
            &[
                Op::LoadAttr(0),
                Op::LoadConst(0),
                Op::Eq,
                Op::BranchIfFalse(8),
                Op::LoadAttr(1),
                Op::LoadConst(1),
                Op::Eq,
                Op::Jump(11),
                Op::LoadAttr(2),
                Op::LoadConst(2),
                Op::Eq,
                Op::Ret,
            ]
        );
        for (i, op) in ops.iter().enumerate() {
            if let Op::Jump(t) | Op::BranchIfFalse(t) = *op {
                assert!(
                    usize::from(t) > i,
                    "jump at {i} must target strictly forward"
                );
            }
        }
    }

    #[test]
    fn no_jumps_without_short_circuit() {
        // Test 6.
        let program = compile_src(b"request.port == 80", Phase::RequestHeaders).unwrap();
        assert!(
            !program.ops().iter().any(|op| matches!(
                op,
                Op::Jump(_) | Op::JumpIfFalse(_) | Op::JumpIfTrue(_) | Op::BranchIfFalse(_)
            )),
            "a program with no &&, || or ternary must contain no jump"
        );
    }

    #[test]
    fn constants_are_interned() {
        // Test 7 / edge case 7: two occurrences of "GET" share one constant.
        let program = compile_src(
            br#"request.method == "GET" || request.path.startsWith("GET")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(program.consts().len(), 1, "one interned \"GET\" constant");
    }

    #[test]
    fn regexes_are_interned() {
        // Test 8 / edge case 8: two occurrences of the same regex compile once.
        let program = compile_src(
            br#"request.path.matches("^/v[0-9]+") || request.query.matches("^/v[0-9]+")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(program.regex_count(), 1);
    }

    #[test]
    fn too_many_ops() {
        // Test 9 / edge case 6: 64 clauses (`request.size == N`, joined with
        // `&&`) compile under the default `max_ops` of 256. A more expensive
        // 65-clause shape trips `TooManyOps` with the exact configured limit.
        let mut clauses = Vec::with_capacity(64);
        for i in 0..64 {
            clauses.push(format!("request.size == {i}"));
        }
        let src = clauses.join(" && ");
        let mut limits = default_limits();
        limits.max_tokens = 2048;
        limits.max_consts = 1024;
        let program = compile_src_with_limits(src.as_bytes(), Phase::RequestHeaders, limits)
            .expect("64 clauses must compile under the default max_ops");
        assert!(program.ops().len() <= usize::from(limits.max_ops));

        // A more expensive per-clause shape (each clause costs more than one
        // instruction more than a bare comparison) pushes a smaller clause
        // count over `max_ops`. `max_ops` is lowered here instead, which is
        // the same boundary from the other side and does not depend on
        // guessing exactly how many `startsWith` clauses it takes to cross
        // the default 256.
        let mut low = default_limits();
        low.max_ops = 8;
        low.max_tokens = 2048;
        let err = compile_src_with_limits(src.as_bytes(), Phase::RequestHeaders, low)
            .expect_err("64 clauses must exceed a max_ops of 8");
        let CompileError::Verify(VerifyError::TooManyOps { max, .. }) = err else {
            panic!("expected CompileError::Verify(TooManyOps), got {err:?}");
        };
        assert_eq!(max, 8);
    }

    #[test]
    fn too_many_consts() {
        // Test 9: 129 distinct constants with `max_consts = 128` (edge case 15).
        let mut clauses = Vec::with_capacity(129);
        for i in 0..129 {
            clauses.push(format!("request.size == {i}"));
        }
        let src = clauses.join(" || ");
        let mut limits = default_limits();
        limits.max_tokens = 4096;
        limits.max_ops = 4096;
        let err = compile_src_with_limits(src.as_bytes(), Phase::RequestHeaders, limits)
            .expect_err("129 distinct constants must exceed max_consts");
        let CompileError::TooManyConsts { max } = err else {
            panic!("expected CompileError::TooManyConsts, got {err:?}");
        };
        assert_eq!(max, 128);

        // Accept side of the same boundary: 128 distinct constants must compile.
        let src_128 = clauses[..128].join(" || ");
        let program =
            compile_src_with_limits(src_128.as_bytes(), Phase::RequestHeaders, limits).unwrap();
        assert_eq!(program.consts().len(), 128);
    }

    #[test]
    fn too_many_regexes() {
        // Test 9 / edge case 14: 9 distinct regexes with `max_regex = 8`.
        let mut clauses = Vec::with_capacity(9);
        for i in 0..9 {
            clauses.push(format!(r#"request.path.matches("^/v{i}[0-9]+")"#));
        }
        let src = clauses.join(" || ");
        let mut limits = default_limits();
        limits.max_tokens = 2048;
        let err = compile_src_with_limits(src.as_bytes(), Phase::RequestHeaders, limits)
            .expect_err("9 distinct regexes must exceed max_regex of 8");
        let CompileError::TooManyRegexes { max } = err else {
            panic!("expected CompileError::TooManyRegexes, got {err:?}");
        };
        assert_eq!(max, 8);
    }

    #[test]
    fn regex_lookahead_rejected() {
        // Test 10 / edge case 9: the crate's own message names look-around.
        let err = compile_src(br#"request.path.matches("(?=x)")"#, Phase::RequestHeaders)
            .expect_err("lookahead must be rejected");
        assert!(
            err.contains("look-around") || err.contains("lookahead") || err.contains("look around"),
            "expected the regex crate's own wording naming look-around, got: {err}"
        );
    }

    #[test]
    fn regex_backreference_rejected() {
        // Test 11 / edge case 10.
        let err = compile_src(br#"request.path.matches("(a)\\1")"#, Phase::RequestHeaders)
            .expect_err("a backreference must be rejected");
        assert!(!err.is_empty());
    }

    #[test]
    fn regex_size_limit_rejected() {
        // Test 12 / edge case 11: a pattern with a large bounded repetition
        // exceeds a small `max_regex_size`.
        let src = br#"request.path.matches("a{1,60000}")"#;
        let mut limits = default_limits();
        limits.max_regex_size = 64;
        let err = compile_src_with_limits(src, Phase::RequestHeaders, limits)
            .expect_err("a pattern exceeding max_regex_size must be rejected");
        let CompileError::BadRegex { message, .. } = err else {
            panic!("expected CompileError::BadRegex");
        };
        assert!(!message.is_empty());
    }

    #[test]
    fn regex_bomb_is_linear() {
        // Test 13 / edge case 12: `(a+)+b` against 10,000 `a` characters
        // completes in under 1 ms, timed over 100 iterations to avoid
        // single-sample noise. This is the concrete refutation of the
        // regex-bomb failure mode: the `regex` crate has no backtracking.
        let program =
            compile_src(br#"request.path.matches("(a+)+b")"#, Phase::RequestHeaders).unwrap();
        let regex = program.regex(0).expect("one compiled regex");
        let haystack = vec![b'a'; 10_000];

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = regex.is_match(&haystack);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "100 iterations of a catastrophic-backtracking pattern took {elapsed:?}, \
             expected well under 100ms total (under 1ms per call) from a linear-time engine"
        );
    }

    #[test]
    fn regex_dfa_cache_fallback_completes() {
        // Edge case 12b: a wide alternation (200 branches) matched against a
        // 10,000-byte haystack that shares no substring with any branch, so
        // the lazy DFA has to explore many states before concluding no
        // match. `size_limit` and `dfa_size_limit` are tied to the same
        // `PolicyLimits::max_regex_size` field (there is no separate knob to
        // starve only the DFA cache while leaving the compiled-program size
        // generous), so this cannot literally set "dfa_size_limit to its
        // minimum" while still letting a 200-branch pattern compile; it
        // demonstrates the property edge case 12b is really about instead:
        // when the lazy DFA's cache is exhausted, the crate falls back to a
        // slower engine and still COMPLETES, rather than hanging or
        // panicking. There is no timing bound here (`regex_bomb_is_linear`
        // already asserts the timing property elsewhere); the assertion
        // below is on the actual match OUTCOME, which is real and
        // meaningful (the haystack is uniform `z` bytes and shares no
        // substring with any `patternNNN` branch, so it cannot match), not
        // merely "did not panic".
        //
        // HONEST LIMIT (issue #758 finding 7): this test does NOT, and
        // cannot, observably distinguish the configured `dfa_size_limit`
        // from `usize::MAX` through any purely functional assertion.
        // Whether the lazy DFA falls back to the slower engine early (small
        // limit) or keeps growing (no limit) changes performance, never the
        // match OUTCOME: the `regex` crate's byte-mode search is correct
        // either way. A mutation that replaces `.dfa_size_limit(size_limit)`
        // with `.dfa_size_limit(usize::MAX)` therefore survives this test,
        // and every other test in this file, and that is disclosed here
        // rather than hidden behind a name that implies otherwise. Closing
        // this for real would need a timing assertion tight enough to be
        // flaky on shared CI hardware, which this crate's own house rules
        // on unmeasured assumptions counsel against.
        let mut alternatives = Vec::with_capacity(200);
        for i in 0..200 {
            alternatives.push(format!("pattern{i:03}"));
        }
        let pattern = format!("({})", alternatives.join("|"));
        let src = format!(r#"request.path.matches("{pattern}")"#);
        let mut limits = default_limits();
        limits.max_regex_size = 1_048_576;
        // The pattern itself is a single ITPL string literal well over the
        // default 1024-byte `max_string_bytes`; this test is about the
        // regex engine's DFA-cache fallback, not that limit, so it is raised
        // to its hard cap.
        limits.max_string_bytes = 8_192;
        let program = compile_src_with_limits(src.as_bytes(), Phase::RequestHeaders, limits)
            .expect("a wide alternation must compile under the default size limit");
        let regex = program.regex(0).expect("one compiled regex");
        let haystack = vec![b'z'; 10_000];
        assert!(
            !regex.is_match(&haystack),
            "a haystack of all 'z' bytes shares no substring with any patternNNN branch"
        );
    }

    #[test]
    fn eight_distinct_regexes_compile_under_the_default_budget() {
        // Edge case 14's accept side: exactly `max_regex` (8) distinct
        // patterns must compile, not just fail past it. This does not try to
        // hit `max_regex_size`'s exact byte ceiling (edge case 12c's stated
        // 512 KiB product of the two default limits): predicting the
        // `regex` crate's compiled-program size for a specific pattern by
        // hand is exactly the kind of unmeasured assumption this crate's own
        // house rules warn against, so this test instead confirms the
        // COUNT boundary, which `too_many_regexes` already measures from the
        // reject side at 9.
        let mut clauses = Vec::with_capacity(8);
        for i in 0..8 {
            clauses.push(format!(r#"request.path.matches("^/v{i}[0-9]+$")"#));
        }
        let src = clauses.join(" || ");
        let mut limits = default_limits();
        limits.max_tokens = 2048;
        let program = compile_src_with_limits(src.as_bytes(), Phase::RequestHeaders, limits)
            .expect("eight distinct regexes must compile at the default max_regex");
        assert_eq!(program.regex_count(), 8);
    }

    #[test]
    fn regex_byte_mode_matches_non_utf8() {
        // Test 14 / edge case 13: a byte class naming a non-UTF-8 range,
        // spelled in valid regex syntax (`\x80` to `\xFF`), matches a
        // non-UTF-8 haystack byte in byte mode.
        let program = compile_src(
            br#"request.path.matches("[\\x80-\\xFF]")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        let regex = program.regex(0).expect("one compiled regex");
        assert!(regex.is_match(&[0xFF]));
        assert!(!regex.is_match(b"a"));
    }

    #[test]
    fn regex_is_case_sensitive() {
        // Pins `.case_insensitive(false)` (issue #758 finding 7): flipping it
        // to `true` silently changes what every operator-supplied pattern
        // matches (`^/ADMIN` would start matching `/admin`), and it survived
        // every other test before this one existed.
        let program =
            compile_src(br#"request.path.matches("^/ADMIN")"#, Phase::RequestHeaders).unwrap();
        let regex = program.regex(0).expect("one compiled regex");
        assert!(regex.is_match(b"/ADMIN"));
        assert!(!regex.is_match(b"/admin"));
    }

    #[test]
    fn compile_is_deterministic() {
        // Test 15 / invariant 6: 100 separate `compile` calls on the same
        // checked program produce byte-identical output.
        let limits = default_limits();
        let src = br#"request.path.startsWith("/v1/") && request.method == "GET""#;
        let toks = lex(src, &limits).unwrap();
        let ast = parse(&toks, src, &limits).unwrap();
        let mut strings = toks.strings;
        let checked = check(ast, &mut strings, src, Phase::RequestHeaders, &limits).unwrap();

        let first = compile(&checked, &limits).unwrap();
        for _ in 0..100 {
            let again = compile(&checked, &limits).unwrap();
            assert_eq!(again.ops(), first.ops());
            assert_eq!(again.consts(), first.consts());
            assert_eq!(again.max_stack(), first.max_stack());
        }
    }

    #[test]
    fn content_hash_discriminates() {
        // Test 16: two programs differing in one constant have different
        // hashes; two programs built from the same source in two separate
        // `compile` calls have equal hashes.
        let limits = default_limits();
        let a = compile_src(br#"request.method == "GET""#, Phase::RequestHeaders).unwrap();
        let b = compile_src(br#"request.method == "POST""#, Phase::RequestHeaders).unwrap();
        assert_ne!(a.content_hash(), b.content_hash());

        let src = br#"request.method == "GET" && request.port == 80"#;
        let toks = lex(src, &limits).unwrap();
        let ast = parse(&toks, src, &limits).unwrap();
        let mut strings = toks.strings;
        let checked = check(ast, &mut strings, src, Phase::RequestHeaders, &limits).unwrap();
        let one = compile(&checked, &limits).unwrap();
        let two = compile(&checked, &limits).unwrap();
        assert_eq!(one.content_hash(), two.content_hash());
    }

    #[test]
    fn list_size_is_folded() {
        // Test 16b: `["a","b"].size() == 2` compiles to
        // `[LoadConst(c), LoadConst(c), Eq, Ret]` for a single shared index
        // `c` naming `Const::Int(2)`: the two constants (the folded `.size()`
        // and the literal `2`) are interned to one index, and there is no
        // `Op::Size`. `consts()` also carries the list literal's OWN
        // `Const::List`, at a different index: `["a","b"]`'s `List` node is
        // still visited and interned by the same unconditional forward sweep
        // that folds `.size()`, exactly as `x in ["a","b"]` may name the same
        // list elsewhere, even though nothing in THIS expression reads it
        // through `InSet`. The fixture asserts that precondition explicitly
        // (`consts().len() == 2`) rather than assuming the folded index is 0.
        let program = compile_src(br#"["a","b"].size() == 2"#, Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.consts().len(),
            2,
            "the list literal's own Const::List plus the folded Const::Int(2)"
        );
        let Some(Op::LoadConst(c)) = program.ops().first().copied() else {
            panic!(
                "expected the first op to be LoadConst, got {:?}",
                program.ops()
            );
        };
        assert_eq!(
            program.ops(),
            &[Op::LoadConst(c), Op::LoadConst(c), Op::Eq, Op::Ret]
        );
        assert_eq!(program.consts().get(usize::from(c)), Some(&Const::Int(2)));
        assert!(!program.ops().contains(&Op::Size));
    }

    // ------------------------------------------------------------------
    // Edge cases not already covered by a named test above.
    // ------------------------------------------------------------------

    #[test]
    fn edge_case_25_in_set_variants() {
        // Edge case 25: `x in []` still evaluates `x` (`InSet` pops one
        // value, so the left operand's own code is never skipped), then
        // compiles the empty list literal to `InSet` on an empty list
        // constant: always false, no jump. `LoadAttr(0)` here is `x` itself,
        // not a folded-away list element (the fixture's own precondition:
        // the list literal `[]` has zero elements, so `build_suppressed`'s
        // pre-pass marks nothing here).
        let program = compile_src(b"request.method in []", Phase::RequestHeaders).unwrap();
        assert_eq!(program.ops(), &[Op::LoadAttr(0), Op::InSet(0), Op::Ret]);
        assert_eq!(program.list_of(0), Some(&[][..]));
    }

    #[test]
    fn edge_case_27_size_on_attribute() {
        // Edge case 27: `request.method.size()` compiles to `LoadAttr, Size,
        // Ret` (the fold applies only when the receiver node is a `List`).
        let program = compile_src(b"request.method.size()", Phase::RequestHeaders).unwrap();
        assert_eq!(program.ops(), &[Op::LoadAttr(0), Op::Size, Op::Ret]);
    }

    #[test]
    fn in_set_over_a_populated_list() {
        // `request.method` (the left operand) is still evaluated first, so
        // `InSet` is the SECOND op, after the `LoadAttr` `InSet` pops.
        let program = compile_src(
            br#"request.method in ["GET", "HEAD"]"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(program.ops().len(), 3, "LoadAttr, InSet, Ret");
        let c = match program.ops().get(1) {
            Some(Op::InSet(n)) => *n,
            other => panic!("expected InSet as the second op, got {other:?}"),
        };
        let elems = program.list_of(c).expect("InSet must name a Const::List");
        assert_eq!(elems.len(), 2);
        assert_eq!(program.const_str(&elems[0]), b"GET");
        assert_eq!(program.const_str(&elems[1]), b"HEAD");
    }

    // ------------------------------------------------------------------
    // Opcode lowering table: one exact-instruction-sequence test per
    // operator (issue #758 finding 2). Every arm of `comparison_op` and
    // `method_op`, plus `Not`, `InSet` and `RegexMatch`, is pinned here
    // against a literal expected sequence, the same shape as `and_lowering`.
    // ------------------------------------------------------------------

    #[test]
    fn ne_lowering() {
        let program = compile_src(br#"request.method != "GET""#, Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::Ne, Op::Ret]
        );
    }

    #[test]
    fn lt_lowering() {
        let program = compile_src(b"request.port < 80", Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::Lt, Op::Ret]
        );
    }

    #[test]
    fn le_lowering() {
        let program = compile_src(b"request.port <= 80", Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::Le, Op::Ret]
        );
    }

    #[test]
    fn gt_lowering() {
        let program = compile_src(b"request.port > 80", Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::Gt, Op::Ret]
        );
    }

    #[test]
    fn ge_lowering() {
        let program = compile_src(b"request.port >= 80", Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::Ge, Op::Ret]
        );
    }

    #[test]
    fn starts_with_lowering() {
        let program = compile_src(
            br#"request.path.startsWith("/admin")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::StartsWith, Op::Ret]
        );
    }

    #[test]
    fn ends_with_lowering() {
        let program =
            compile_src(br#"request.path.endsWith("/admin")"#, Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::EndsWith, Op::Ret]
        );
    }

    #[test]
    fn contains_lowering() {
        let program =
            compile_src(br#"request.path.contains("/admin")"#, Phase::RequestHeaders).unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::Contains, Op::Ret]
        );
    }

    #[test]
    fn equals_ignore_case_lowering() {
        let program = compile_src(
            br#"request.method.equalsIgnoreCase("get")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[Op::LoadAttr(0), Op::LoadConst(0), Op::EqIgnoreCase, Op::Ret]
        );
    }

    #[test]
    fn starts_with_ignore_case_lowering() {
        let program = compile_src(
            br#"request.path.startsWithIgnoreCase("/Admin")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[
                Op::LoadAttr(0),
                Op::LoadConst(0),
                Op::StartsWithIgnoreCase,
                Op::Ret
            ]
        );
    }

    #[test]
    fn not_lowering() {
        // `!x` must lower to `Op::Not`, never `Op::Size` (both are unary,
        // pop-one-push-one, which is exactly why this mutation survived
        // every other test in the suite: see issue #758 finding 2).
        let program = compile_src(b"!connection.tls", Phase::RequestHeaders).unwrap();
        assert_eq!(program.ops(), &[Op::LoadAttr(0), Op::Not, Op::Ret]);
    }

    #[test]
    fn in_set_operand_is_not_zero() {
        // `in_set_over_a_populated_list` above only ever exercises `InSet(0)`
        // (the fixture's one and only interned list happens to land at index
        // 0), which is exactly why hardcoding the `InSet` operand to 0
        // survived (#758 finding 2). Here the list is the SECOND constant
        // interned (index 0 is `1`, the int literal from the left clause),
        // so a correct compile must emit `InSet(1)`.
        let program = compile_src(
            br#"request.port == 1 && request.method in ["GET", "HEAD"]"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[
                Op::LoadAttr(0),
                Op::LoadConst(0),
                Op::Eq,
                Op::JumpIfFalse(6),
                Op::LoadAttr(1),
                Op::InSet(1),
                Op::Ret,
            ]
        );
        assert_eq!(program.consts().first(), Some(&Const::Int(1)));
        let elems = program
            .list_of(1)
            .expect("InSet(1) must name a Const::List at index 1");
        assert_eq!(program.const_str(&elems[0]), b"GET");
        assert_eq!(program.const_str(&elems[1]), b"HEAD");
    }

    #[test]
    fn regex_match_index_is_not_zero() {
        // `regex_bomb_is_linear`, `regex_dfa_cache_fallback_completes` and
        // `regex_byte_mode_matches_non_utf8` each compile exactly ONE regex,
        // so every existing test's only `RegexMatch` names index 0, which is
        // exactly why hardcoding the operand to 0 survived (#758 finding 2).
        // Two DISTINCT patterns here must intern to two DISTINCT indices.
        let program = compile_src(
            br#"request.path.matches("^/a") || request.path.matches("^/b")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            program.ops(),
            &[
                Op::LoadAttr(0),
                Op::RegexMatch(0),
                Op::JumpIfTrue(5),
                Op::LoadAttr(0),
                Op::RegexMatch(1),
                Op::Ret,
            ]
        );
        assert_eq!(program.regex_count(), 2);
        let first = program.regex(0).expect("regex 0");
        let second = program.regex(1).expect("regex 1");
        assert!(first.is_match(b"/a"));
        assert!(!first.is_match(b"/b"));
        assert!(second.is_match(b"/b"));
        assert!(!second.is_match(b"/a"));
    }

    #[test]
    fn list_int_elements_are_not_folded_to_null() {
        // Pins `const_of_leaf`'s `Some(Node::Int(v)) => Const::Int(v)` arm:
        // mutating it to `Const::Null` survived every other test (#758
        // finding 2) because `in_set_over_a_populated_list` and
        // `edge_case_25_in_set_variants` only ever build `Str` list elements.
        let program = compile_src(b"request.size in [1, 2, 3]", Phase::RequestHeaders).unwrap();
        let c = match program.ops().get(1) {
            Some(Op::InSet(n)) => *n,
            other => panic!("expected InSet as the second op, got {other:?}"),
        };
        let elems = program.list_of(c).expect("InSet must name a Const::List");
        assert_eq!(
            elems,
            &[Const::Int(1), Const::Int(2), Const::Int(3)],
            "list elements must be the real Int constants, not Const::Null"
        );
    }

    // ------------------------------------------------------------------
    // A list element naming an attribute must be rejected, not silently
    // compiled to `Const::Null` (issue #758 finding 3, BLOCKING).
    // ------------------------------------------------------------------

    #[test]
    fn list_element_naming_an_attribute_is_rejected() {
        // `request.path` inside the list must not silently degrade to
        // `Const::Null` (which would admit a policy meaning
        // `request.method in [null, "GET"]`, not what its source says).
        // Consistent with a COMPOUND list element (already fail-closed),
        // this must be refused at compile time.
        let limits = default_limits();
        let err = compile_src_with_limits(
            br#"request.method in [request.path, "GET"]"#,
            Phase::RequestHeaders,
            limits,
        )
        .expect_err("a list element naming an attribute must be rejected");
        assert!(
            matches!(
                err,
                CompileError::Verify(VerifyError::StackNotSingleton { .. })
            ),
            "expected CompileError::Verify(StackNotSingleton), got {err:?}"
        );
    }

    #[test]
    fn two_distinct_attribute_naming_lists_do_not_silently_collide() {
        // Companion to the test above: before the fix, two source-distinct
        // lists that each named a different attribute both degraded to a
        // list of `Const::Null`s and interned onto ONE shared `Const::List`
        // slot (issue #758 finding 3's interning-collision evidence). With
        // the fix, the first offending list is rejected before any
        // constant is even interned, so there is nothing left to collide.
        let err = compile_src(
            br#"request.method in [request.path, "GET"] && request.method in [request.query, "GET"]"#,
            Phase::RequestHeaders,
        )
        .expect_err("must be rejected, not silently compiled with colliding constants");
        assert!(
            err.contains("StackNotSingleton"),
            "expected a StackNotSingleton failure, got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Property tests.
    // ------------------------------------------------------------------

    // Widened per issue #758 finding 2: the ORIGINAL generator rendered
    // every leaf as `({path} == {rhs})`, which reached only 9 of the 22
    // `Op` variants over 256 draws (measured; see the PR for #271 for the
    // instrumented run) and is exactly why the opcode lowering table had no
    // property-test coverage behind it. Every leaf kind below draws a
    // DIFFERENT operator, so the combined generator can reach all 22.
    // `prop_generator_opcode_reach` below measures and reports the real
    // number rather than assuming it.

    /// The six relational comparison operators, all rendered by their own
    /// source symbol so the generator draws every one of them, not just `==`.
    #[derive(Clone, Copy, Debug)]
    enum CmpOp {
        Eq,
        Ne,
        Lt,
        Le,
        Gt,
        Ge,
    }

    impl CmpOp {
        fn symbol(self) -> &'static str {
            match self {
                CmpOp::Eq => "==",
                CmpOp::Ne => "!=",
                CmpOp::Lt => "<",
                CmpOp::Le => "<=",
                CmpOp::Gt => ">",
                CmpOp::Ge => ">=",
            }
        }
    }

    /// The five string methods that lower directly through `method_op`.
    /// `Matches` and `Size` are drawn separately below because they each
    /// have their own dedicated render shape (a regex pattern, a numeric
    /// comparison).
    #[derive(Clone, Copy, Debug)]
    enum StrMethod {
        StartsWith,
        EndsWith,
        Contains,
        EqualsIgnoreCase,
        StartsWithIgnoreCase,
    }

    impl StrMethod {
        fn name(self) -> &'static str {
            match self {
                StrMethod::StartsWith => "startsWith",
                StrMethod::EndsWith => "endsWith",
                StrMethod::Contains => "contains",
                StrMethod::EqualsIgnoreCase => "equalsIgnoreCase",
                StrMethod::StartsWithIgnoreCase => "startsWithIgnoreCase",
            }
        }
    }

    const STR_ATTRS: &[&str] = &["request.method", "request.path"];
    const INT_ATTRS: &[&str] = &["request.port", "request.size"];
    const BOOL_ATTRS: &[&str] = &["connection.tls"];
    const STR_LITERALS: &[&str] = &["GET", "POST", "HEAD"];
    const REGEX_LITERALS: &[&str] = &["^/a", "^/b", "x+"];

    #[derive(Clone, Debug)]
    enum GenExpr {
        IntCmp(&'static str, CmpOp, i64),
        StrCmp(&'static str, CmpOp, &'static str),
        BoolCmp(&'static str, CmpOp, bool),
        StrMethodCall(&'static str, StrMethod, &'static str),
        Matches(&'static str, &'static str),
        SizeCmp(&'static str, i64),
        InSetStr(&'static str, Vec<&'static str>),
        InSetInt(&'static str, Vec<i64>),
        Not(Box<GenExpr>),
        And(Box<GenExpr>, Box<GenExpr>),
        Or(Box<GenExpr>, Box<GenExpr>),
        Ternary(Box<GenExpr>, Box<GenExpr>, Box<GenExpr>),
    }

    fn render(e: &GenExpr, out: &mut String) {
        use std::fmt::Write as _;
        match *e {
            GenExpr::IntCmp(attr, op, v) => {
                let _ = write!(out, "({attr} {} {v})", op.symbol());
            }
            GenExpr::StrCmp(attr, op, s) => {
                let _ = write!(out, "({attr} {} \"{s}\")", op.symbol());
            }
            GenExpr::BoolCmp(attr, op, b) => {
                let _ = write!(out, "({attr} {} {b})", op.symbol());
            }
            GenExpr::StrMethodCall(attr, m, s) => {
                let _ = write!(out, "({attr}.{}(\"{s}\"))", m.name());
            }
            GenExpr::Matches(attr, pat) => {
                let _ = write!(out, "({attr}.matches(\"{pat}\"))");
            }
            GenExpr::SizeCmp(attr, n) => {
                let _ = write!(out, "({attr}.size() == {n})");
            }
            GenExpr::InSetStr(attr, ref vals) => {
                let list = vals
                    .iter()
                    .map(|v| format!("\"{v}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = write!(out, "({attr} in [{list}])");
            }
            GenExpr::InSetInt(attr, ref vals) => {
                let list = vals
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = write!(out, "({attr} in [{list}])");
            }
            GenExpr::Not(ref inner) => {
                out.push('!');
                render(inner, out);
            }
            GenExpr::And(ref l, ref r) => {
                out.push('(');
                render(l, out);
                out.push_str(" && ");
                render(r, out);
                out.push(')');
            }
            GenExpr::Or(ref l, ref r) => {
                out.push('(');
                render(l, out);
                out.push_str(" || ");
                render(r, out);
                out.push(')');
            }
            GenExpr::Ternary(ref cond, ref then_, ref else_) => {
                out.push('(');
                render(cond, out);
                out.push_str(" ? ");
                render(then_, out);
                out.push_str(" : ");
                render(else_, out);
                out.push(')');
            }
        }
    }

    fn pick(pool: &'static [&'static str]) -> impl Strategy<Value = &'static str> {
        (0..pool.len()).prop_map(move |i| pool[i])
    }

    fn arb_int_cmp() -> BoxedStrategy<GenExpr> {
        (
            pick(INT_ATTRS),
            prop_oneof![
                Just(CmpOp::Eq),
                Just(CmpOp::Ne),
                Just(CmpOp::Lt),
                Just(CmpOp::Le),
                Just(CmpOp::Gt),
                Just(CmpOp::Ge),
            ],
            0i64..1000,
        )
            .prop_map(|(attr, op, v)| GenExpr::IntCmp(attr, op, v))
            .boxed()
    }

    fn arb_str_cmp() -> BoxedStrategy<GenExpr> {
        (
            pick(STR_ATTRS),
            prop_oneof![Just(CmpOp::Eq), Just(CmpOp::Ne)],
            pick(STR_LITERALS),
        )
            .prop_map(|(attr, op, s)| GenExpr::StrCmp(attr, op, s))
            .boxed()
    }

    fn arb_bool_cmp() -> BoxedStrategy<GenExpr> {
        (
            pick(BOOL_ATTRS),
            prop_oneof![Just(CmpOp::Eq), Just(CmpOp::Ne)],
            any::<bool>(),
        )
            .prop_map(|(attr, op, b)| GenExpr::BoolCmp(attr, op, b))
            .boxed()
    }

    fn arb_str_method() -> BoxedStrategy<GenExpr> {
        (
            pick(STR_ATTRS),
            prop_oneof![
                Just(StrMethod::StartsWith),
                Just(StrMethod::EndsWith),
                Just(StrMethod::Contains),
                Just(StrMethod::EqualsIgnoreCase),
                Just(StrMethod::StartsWithIgnoreCase),
            ],
            pick(STR_LITERALS),
        )
            .prop_map(|(attr, m, s)| GenExpr::StrMethodCall(attr, m, s))
            .boxed()
    }

    fn arb_matches() -> BoxedStrategy<GenExpr> {
        (pick(STR_ATTRS), pick(REGEX_LITERALS))
            .prop_map(|(attr, pat)| GenExpr::Matches(attr, pat))
            .boxed()
    }

    fn arb_size_cmp() -> BoxedStrategy<GenExpr> {
        (pick(STR_ATTRS), 0i64..100)
            .prop_map(|(attr, n)| GenExpr::SizeCmp(attr, n))
            .boxed()
    }

    fn arb_in_set_str() -> BoxedStrategy<GenExpr> {
        (
            pick(STR_ATTRS),
            proptest::collection::vec(pick(STR_LITERALS), 1..=3),
        )
            .prop_map(|(attr, vals)| GenExpr::InSetStr(attr, vals))
            .boxed()
    }

    fn arb_in_set_int() -> BoxedStrategy<GenExpr> {
        (
            pick(INT_ATTRS),
            proptest::collection::vec(0i64..1000, 1..=3),
        )
            .prop_map(|(attr, vals)| GenExpr::InSetInt(attr, vals))
            .boxed()
    }

    fn arb_leaf() -> BoxedStrategy<GenExpr> {
        prop_oneof![
            arb_int_cmp(),
            arb_str_cmp(),
            arb_bool_cmp(),
            arb_str_method(),
            arb_matches(),
            arb_size_cmp(),
            arb_in_set_str(),
            arb_in_set_int(),
        ]
        .boxed()
    }

    fn arb_expr(budget: u32) -> BoxedStrategy<GenExpr> {
        let leaf = arb_leaf();
        if budget == 0 {
            return leaf;
        }
        let next = budget - 1;
        prop_oneof![
            4 => leaf,
            2 => (arb_expr(next), arb_expr(next))
                .prop_map(|(l, r)| GenExpr::And(Box::new(l), Box::new(r))),
            2 => (arb_expr(next), arb_expr(next))
                .prop_map(|(l, r)| GenExpr::Or(Box::new(l), Box::new(r))),
            2 => arb_expr(next).prop_map(|e| GenExpr::Not(Box::new(e))),
            1 => (arb_expr(next), arb_expr(next), arb_expr(next))
                .prop_map(|(c, t, e)| GenExpr::Ternary(Box::new(c), Box::new(t), Box::new(e))),
        ]
        .boxed()
    }

    /// Every draw is well typed BY CONSTRUCTION (unlike `check::tests`'s
    /// generator, which deliberately also draws type mismatches to exercise
    /// `check`'s error paths): this generator exists only to feed `compile`,
    /// which requires an already-`Ok` `Checked`, so there is nothing for a
    /// rejected draw to test here. `prop_generator_reaches_compile_ok` below
    /// measures and asserts this directly rather than assuming it.
    fn arb_itpl_src() -> impl Strategy<Value = Vec<u8>> {
        arb_expr(3).prop_map(|expr| {
            let mut src = String::new();
            render(&expr, &mut src);
            src.into_bytes()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_compiler_output_always_verifies(src in arb_itpl_src()) {
            // Test 29.
            let limits = default_limits();
            let mut checked_limits = limits;
            checked_limits.max_tokens = 4096;
            if let Ok(toks) = lex(&src, &checked_limits) {
                let src_clone = src.clone();
                if let Ok(ast) = parse(&toks, &src_clone, &checked_limits) {
                    let mut strings = toks.strings.clone();
                    if let Ok(checked) = check(ast, &mut strings, &src_clone, Phase::RequestHeaders, &checked_limits) {
                        let result = compile(&checked, &checked_limits);
                        prop_assert!(result.is_ok(), "{result:?}");
                    }
                }
            }
        }

        #[test]
        fn prop_verified_programs_have_only_forward_jumps(src in arb_itpl_src()) {
            // Test 30, stated over real compiler output.
            let mut limits = default_limits();
            limits.max_tokens = 4096;
            if let Ok(toks) = lex(&src, &limits) {
                let src_clone = src.clone();
                if let Ok(ast) = parse(&toks, &src_clone, &limits) {
                    let mut strings = toks.strings.clone();
                    if let Ok(checked) = check(ast, &mut strings, &src_clone, Phase::RequestHeaders, &limits)
                        && let Ok(program) = compile(&checked, &limits)
                    {
                        for (i, op) in program.ops().iter().enumerate() {
                            if let Op::Jump(t) | Op::JumpIfFalse(t) | Op::JumpIfTrue(t) | Op::BranchIfFalse(t) = *op {
                                prop_assert!(usize::from(t) > i, "jump at {i} targets {t}, not strictly forward");
                            }
                        }
                    }
                }
            }
        }
    }

    /// Measures how `arb_itpl_src`'s draws land, over 256 cases, per this
    /// crate's own house lesson (#268/#269: a property test whose generator
    /// never reaches the code under test is decorative) applied one stage
    /// further down the pipeline than `check::tests`'s own measurement:
    /// every draw here is well typed by construction, so the number that
    /// matters is how many reach a successful `compile`, not merely a
    /// successful `check`.
    #[test]
    fn prop_generator_reaches_compile_ok() {
        use proptest::strategy::ValueTree as _;

        let mut limits = default_limits();
        limits.max_tokens = 4096;
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
        let strategy = arb_itpl_src();
        let mut compiled_ok = 0u32;
        let mut total = 0u32;
        for _ in 0..256 {
            let Ok(tree) = strategy.new_tree(&mut runner) else {
                continue;
            };
            let src = tree.current();
            total += 1;
            if let Ok(toks) = lex(&src, &limits)
                && let Ok(ast) = parse(&toks, &src, &limits)
            {
                let mut strings = toks.strings;
                if let Ok(checked) = check(ast, &mut strings, &src, Phase::RequestHeaders, &limits)
                    && compile(&checked, &limits).is_ok()
                {
                    compiled_ok += 1;
                }
            }
        }
        assert!(total > 0);
        // The floor is asserted, not merely reported, so a future regression
        // that collapses this back toward zero fails the build. This
        // generator is well typed by construction (no deliberate mismatch
        // arm), so the expected floor is high; measured locally this landed
        // at 256/256 across several runs, and the assertion below is set
        // comfortably below that measured value rather than pinned to it.
        assert!(
            compiled_ok * 4 >= total * 3,
            "expected at least 75% of generated programs to compile, got {compiled_ok}/{total}"
        );
    }

    fn opcode_tag(op: Op) -> &'static str {
        match op {
            Op::LoadAttr(_) => "LoadAttr",
            Op::LoadConst(_) => "LoadConst",
            Op::Eq => "Eq",
            Op::Ne => "Ne",
            Op::Lt => "Lt",
            Op::Le => "Le",
            Op::Gt => "Gt",
            Op::Ge => "Ge",
            Op::InSet(_) => "InSet",
            Op::StartsWith => "StartsWith",
            Op::EndsWith => "EndsWith",
            Op::Contains => "Contains",
            Op::EqIgnoreCase => "EqIgnoreCase",
            Op::StartsWithIgnoreCase => "StartsWithIgnoreCase",
            Op::RegexMatch(_) => "RegexMatch",
            Op::Size => "Size",
            Op::Not => "Not",
            Op::JumpIfFalse(_) => "JumpIfFalse",
            Op::JumpIfTrue(_) => "JumpIfTrue",
            Op::BranchIfFalse(_) => "BranchIfFalse",
            Op::Jump(_) => "Jump",
            Op::Ret => "Ret",
        }
    }

    /// Measures how many of the 22 `Op` variants the widened generator
    /// reaches over 256 draws (issue #758 finding 2's own house lesson: a
    /// property test's generator reach must be measured, never assumed).
    /// MEASURED (this exact loop, run directly, reported in the PR for
    /// #271): 22 of 22 opcodes reached. The floor below is set comfortably
    /// below that measured value, per this file's own convention for a
    /// floor assertion (see `prop_generator_reaches_compile_ok` just above).
    #[test]
    fn prop_generator_opcode_reach() {
        use proptest::strategy::ValueTree as _;
        use std::collections::HashSet;

        let mut limits = default_limits();
        limits.max_tokens = 4096;
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
        let strategy = arb_itpl_src();
        let mut reached: HashSet<&'static str> = HashSet::new();
        for _ in 0..256 {
            let Ok(tree) = strategy.new_tree(&mut runner) else {
                continue;
            };
            let src = tree.current();
            if let Ok(toks) = lex(&src, &limits)
                && let Ok(ast) = parse(&toks, &src, &limits)
            {
                let mut strings = toks.strings;
                if let Ok(checked) = check(ast, &mut strings, &src, Phase::RequestHeaders, &limits)
                    && let Ok(program) = compile(&checked, &limits)
                {
                    for &op in program.ops() {
                        reached.insert(opcode_tag(op));
                    }
                }
            }
        }
        assert!(
            reached.len() >= 20,
            "expected at least 20 of 22 opcodes reached by the widened generator, \
             got {}/22: {reached:?}",
            reached.len()
        );
    }
}
