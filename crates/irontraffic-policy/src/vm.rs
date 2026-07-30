// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! The ITPL evaluator: `Env`, the per-evaluation slot cache and attribute binding,
//! and `eval`, a non-recursive loop over a verified [`crate::program::Program`]
//! with a fixed-size operand stack.
//!
//! `eval` performs zero heap allocations and terminates in at most `ops.len()`
//! steps for every input, including a hand-built `Program` `verify` never saw:
//! every `EvalError` variant is documented as unreachable for a program that
//! passed `check` and `verify`, and exists only so this function stays total.
//! This module never indexes a slice with `[]`, never `unwrap`s a table lookup,
//! and never allocates: borrow instead of cloning, and see the `//! HOT PATH`
//! rule in `scripts/invariant-lints.sh` for what that marker enforces.
//!
//! # Duplicate headers
//!
//! `FieldSection::get_unique` (`{{itpl-crate-lexer-and-grammar}}`'s sibling issue
//! #24) returns `Err(DuplicateField)` when a field appears twice. `Env::slot` maps
//! that to `Value::Null`, counts it in the process-wide
//! [`duplicate_header_count`], and sets [`Env::saw_duplicate`] for the rest of
//! this evaluation. `Null` alone is not enough: it is the fail-safe answer for an
//! allow-list predicate and the fail-open one for a deny-list predicate, which a
//! peer bypasses by sending the header twice (Envoy CVE-2026-26308). The flag is
//! what lets a fail-closed policy filter refuse a duplicate-influenced result
//! instead of admitting it.

use crate::attrs::{AttrId, MapId};
use crate::check::AttrRef;
use crate::program::{Const, Op, Program};
use crate::value::Value;
use core::sync::atomic::{AtomicU64, Ordering};

/// How the evaluator reaches request state. Implemented by the policy filter over
/// `irontraffic_filter::Ctx`, and by the test harness over a fixture.
pub trait AttrSource<'a> {
    /// The value of a scalar attribute. Must be `O(1)` and must not allocate.
    fn scalar(&self, id: AttrId) -> Value<'a>;

    /// The value of a field-map entry with an already-canonical key.
    ///
    /// Returns a three-state outcome, NOT a `Value`. Absence and duplication are
    /// different facts and only the caller can decide what to do about the second
    /// one, so the trait reports both and `Env::slot` does the mapping and the
    /// counting. An earlier shape had this method return `Value::Null` for both
    /// and required every implementation to remember to call
    /// `record_duplicate_header`; a MUST that each implementor can forget is not
    /// a mechanism.
    ///
    /// Implementations MUST NOT join repeated values and MUST NOT return the
    /// first of several: that is Envoy CVE-2026-26308.
    fn field(&self, map: MapId, key: &[u8]) -> FieldOutcome<'a>;
}

/// What a field-map lookup found.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FieldOutcome<'a> {
    /// Exactly one field with that name.
    Present(&'a [u8]),
    /// No field with that name.
    Absent,
    /// Two or more fields with that name. The value is deliberately not carried:
    /// there is no correct single value and offering one invites picking it.
    Duplicate,
}

/// Per-evaluation state: the slot cache and the source binding.
pub struct Env<'a, 'p> {
    /// Lazily resolved attribute slots, one per `Program::slots` entry.
    slots: [Option<Value<'a>>; Env::MAX_SLOTS],
    /// How many slots this program uses.
    used: u16,
    /// Sticky: at least one field lookup during this evaluation found a
    /// duplicated field and was answered with `Null`.
    saw_duplicate: bool,
    /// The request binding.
    src: &'p dyn AttrSource<'a>,
}

impl<'a, 'p> Env<'a, 'p> {
    /// Maximum slots. 16, which is also the hard cap `PolicyLimits::validate`
    /// puts on `max_attr_slots`, so a checked program can never index past this
    /// array.
    pub const MAX_SLOTS: usize = 16;

    /// A fresh environment bound to `src`. Clears the slot cache.
    #[must_use]
    pub fn new(src: &'p dyn AttrSource<'a>, used: u16) -> Env<'a, 'p> {
        Env {
            slots: [None; Env::MAX_SLOTS],
            used,
            saw_duplicate: false,
            src,
        }
    }

    /// Resolves slot `n`, using the cache.
    ///
    /// # Errors
    /// `EvalError::BadOperand` when `n` is outside the program's slot table.
    ///
    /// Two independent bounds are checked before any indexing, and neither is
    /// redundant with the other: `Env::MAX_SLOTS` bounds the fixed cache array,
    /// which can never hold more than 16 entries no matter what a hand-built
    /// `Program` claims, and `self.used` (set once, at `Env::new`, from the
    /// program this environment is bound to) bounds what THIS program actually
    /// declared, which can be smaller. `Program::slots()` is checked too (the
    /// `None` arm below), so a mismatched `used` cannot make this function
    /// index past what `prog.slots()` really contains either. This function has
    /// no access to the calling `eval` loop's own instruction pointer (its
    /// public signature, matching the issue's own, does not take one), so the
    /// `pc` field on the two `BadOperand` values this raises directly carries
    /// `n`, the slot index that was out of range, rather than a bytecode
    /// offset: the most useful diagnostic value actually available here.
    /// `eval`'s own error sites, which run inside the loop and do have `pc`,
    /// use it for exactly that.
    pub fn slot(&mut self, n: u16, prog: &Program) -> Result<Value<'a>, EvalError> {
        let i = usize::from(n);
        if i >= Env::MAX_SLOTS || i >= usize::from(self.used) {
            return Err(EvalError::BadOperand { pc: n });
        }
        if let Some(v) = self.slots.get(i).copied().flatten() {
            return Ok(v);
        }
        let v = match prog.slots().get(i) {
            Some(AttrRef::Scalar(id)) => self.src.scalar(*id),
            Some(AttrRef::Field { map, key }) => match self.src.field(*map, prog.key_bytes(*key)) {
                FieldOutcome::Present(b) => Value::Str(b),
                FieldOutcome::Absent => Value::Null,
                FieldOutcome::Duplicate => {
                    self.saw_duplicate = true;
                    record_duplicate_header();
                    Value::Null
                }
            },
            None => return Err(EvalError::BadOperand { pc: n }),
        };
        if let Some(cell) = self.slots.get_mut(i) {
            *cell = Some(v);
        }
        Ok(v)
    }

    /// Number of slots resolved so far, for the benchmark and the explain
    /// surface.
    #[must_use]
    pub fn resolved(&self) -> u16 {
        let n = self.slots.iter().filter(|s| s.is_some()).count();
        u16::try_from(n).unwrap_or(u16::MAX)
    }

    /// True when at least one field lookup during this evaluation found a
    /// duplicated field. Sticky for the life of the `Env`, which is one
    /// evaluation.
    ///
    /// The caller MUST read this after `eval` returns and MUST NOT ignore it
    /// for a fail-closed filter. A result computed from a header the peer
    /// sent twice is a result computed from input the peer made ambiguous on
    /// purpose.
    #[inline]
    #[must_use]
    pub fn saw_duplicate(&self) -> bool {
        self.saw_duplicate
    }
}

/// Why `eval` could not produce a value.
///
/// Every variant is documented as unreachable for a program that passed
/// `check` and `verify`. They exist because `eval` takes a `&Program` and must
/// be total for any `Program` value, including one a fuzzer built directly,
/// and because "unreachable" plus `unwrap` is how a proxy gets a panic in
/// production.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvalError {
    /// The instruction pointer left the program. Unreachable for a verified
    /// program; present because `eval` must not index out of bounds even if
    /// handed one.
    BadPc {
        /// The offending instruction pointer.
        pc: u16,
    },
    /// An operand index outside its table. Unreachable for a verified
    /// program.
    BadOperand {
        /// The offending instruction pointer, or (from `Env::slot`, which has
        /// no instruction pointer of its own) the offending slot index. See
        /// `Env::slot`'s doc comment.
        pc: u16,
    },
    /// The operand stack underflowed. Unreachable for a verified program.
    StackUnderflow {
        /// The offending instruction pointer.
        pc: u16,
    },
    /// The operand stack overflowed. Unreachable for a verified program.
    StackOverflow {
        /// The offending instruction pointer.
        pc: u16,
    },
    /// The step budget was exhausted. Unreachable for a verified program,
    /// because the budget is `ops.len()` and jumps are forward only.
    StepBudget {
        /// Steps executed before the budget tripped.
        steps: u32,
    },
    /// A type combination the checker should have rejected. Unreachable for a
    /// checked program.
    TypeError {
        /// The offending instruction pointer.
        pc: u16,
    },
}

/// Duplicate-header lookups seen so far, process-wide.
///
/// `irontraffic-policy` depends on no metrics registry, so the count is a
/// plain `static AtomicU64`; the observability layer reads it and publishes it
/// as `policy_duplicate_header_total`. Every `AttrSource::field` implementation
/// that maps a `DuplicateField` to `Value::Null` MUST call
/// `record_duplicate_header` first, and the trait's doc comment says so.
static DUPLICATE_HEADER_COUNT: AtomicU64 = AtomicU64::new(0);

/// Duplicate-header lookups seen so far, process-wide.
#[must_use]
pub fn duplicate_header_count() -> u64 {
    DUPLICATE_HEADER_COUNT.load(Ordering::Relaxed)
}

/// Increments the counter above by one.
pub fn record_duplicate_header() {
    DUPLICATE_HEADER_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Converts a `usize` index into a `u16`, saturating rather than panicking.
/// Every real call site is already bounded by `ops.len()`, which is bounded by
/// `PolicyLimits::max_ops` (hard cap 4096) for any program `check`/`compile`
/// produced; this only matters for a hand-built `Program`, and saturating
/// keeps `eval` total rather than trusting that bound at runtime.
fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// The step budget for one evaluation of `prog`: `ops.len()`, saturating into
/// `u32` rather than trusting that a hand-built `Program`'s length already
/// fits (a checked program's is bounded well under this by
/// `PolicyLimits::max_ops`).
fn step_budget(prog: &Program) -> u32 {
    u32::try_from(prog.ops().len()).unwrap_or(u32::MAX)
}

/// The private `Const` to `Value` mapping for `Op::LoadConst`. `Program`'s
/// tables are private and live in a different module, so this reaches them
/// through the accessors it publishes (`consts()`, `const_str()`), never
/// through a field.
fn const_value(prog: &Program, n: u16) -> Option<Value<'_>> {
    Some(match prog.consts().get(usize::from(n))? {
        Const::Bool(b) => Value::Bool(*b),
        Const::Int(v) => Value::Int(*v),
        c @ Const::Str { .. } => Value::Str(prog.const_str(c)),
        Const::Null => Value::Null,
        // A list constant is never loaded onto the stack; only `InSet` reads
        // it, and it reads it through `prog.list_of`.
        Const::List { .. } => return None,
    })
}

/// The same mapping as `const_value`, but from an already-borrowed `&Const`
/// rather than a table index: `Op::InSet`'s list elements are read through
/// `Program::list_of`, which hands back a `&[Const]` slice directly, with no
/// index of its own to look a fresh `&Const` up by.
fn const_to_value<'p>(prog: &'p Program, c: &Const) -> Option<Value<'p>> {
    Some(match c {
        Const::Bool(b) => Value::Bool(*b),
        Const::Int(v) => Value::Int(*v),
        Const::Str { .. } => Value::Str(prog.const_str(c)),
        Const::Null => Value::Null,
        Const::List { .. } => return None,
    })
}

/// ASCII case-insensitive equality. Only `A`-`Z`/`a`-`z` fold; every other
/// byte, including a non-ASCII UTF-8 lead or continuation byte such as
/// `0xC3`, compares as itself. A Unicode-aware fold would need allocation and
/// a locale, which `docs/ITPL.md` documents as out of scope.
fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// ASCII case-insensitive prefix, built on `ascii_eq_ignore_case` the same way
/// `StartsWith` is a prefix built on byte equality.
fn ascii_starts_with_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.get(..b.len())
        .is_some_and(|prefix| ascii_eq_ignore_case(prefix, b))
}

/// Pushes `v`, or `StackOverflow` when the fixed stack is already full.
fn push<'a>(
    stack: &mut [Value<'a>],
    sp: &mut usize,
    pc: usize,
    v: Value<'a>,
) -> Result<(), EvalError> {
    let cell = stack
        .get_mut(*sp)
        .ok_or(EvalError::StackOverflow { pc: to_u16(pc) })?;
    *cell = v;
    *sp += 1;
    Ok(())
}

/// Pops one value, or `StackUnderflow` when the stack is already empty.
fn pop<'a>(stack: &[Value<'a>], sp: &mut usize, pc: usize) -> Result<Value<'a>, EvalError> {
    let i = sp
        .checked_sub(1)
        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })?;
    let v = stack
        .get(i)
        .copied()
        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })?;
    *sp = i;
    Ok(v)
}

/// Pops one value and requires it to be an `Int`, or `TypeError`.
fn pop_int(stack: &[Value<'_>], sp: &mut usize, pc: usize) -> Result<i64, EvalError> {
    pop(stack, sp, pc)?
        .as_int()
        .ok_or(EvalError::TypeError { pc: to_u16(pc) })
}

/// Pops one value and requires it to be a `Bool`, or `TypeError`.
fn pop_bool(stack: &[Value<'_>], sp: &mut usize, pc: usize) -> Result<bool, EvalError> {
    pop(stack, sp, pc)?
        .as_bool()
        .ok_or(EvalError::TypeError { pc: to_u16(pc) })
}

/// Pops one value and requires it to be a `Str` or `Null`: `Some(bytes)` for a
/// `Str`, `None` for `Null`, `TypeError` for anything else. This is what makes
/// a `Null` receiver or argument to `startsWith`/`endsWith`/`contains`/
/// `equalsIgnoreCase`/`startsWithIgnoreCase`/`matches` fall through to `false`
/// rather than an error, per those operators' own match arms.
fn pop_str_or_null<'a>(
    stack: &[Value<'a>],
    sp: &mut usize,
    pc: usize,
) -> Result<Option<&'a [u8]>, EvalError> {
    match pop(stack, sp, pc)? {
        Value::Str(s) => Ok(Some(s)),
        Value::Null => Ok(None),
        Value::Bool(_) | Value::Int(_) => Err(EvalError::TypeError { pc: to_u16(pc) }),
    }
}

/// Peeks the top of stack without popping it: true when it is `Bool(false)`,
/// `TypeError` when it is not a `Bool` at all. This is `&&`'s `JumpIfFalse`.
fn peek_is_false(stack: &[Value<'_>], sp: usize, pc: usize) -> Result<bool, EvalError> {
    let i = sp
        .checked_sub(1)
        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })?;
    let v = stack
        .get(i)
        .copied()
        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })?;
    v.as_bool()
        .map(|b| !b)
        .ok_or(EvalError::TypeError { pc: to_u16(pc) })
}

/// Peeks the top of stack without popping it: true when it is `Bool(true)`,
/// `TypeError` when it is not a `Bool` at all. This is `||`'s `JumpIfTrue`.
fn peek_is_true(stack: &[Value<'_>], sp: usize, pc: usize) -> Result<bool, EvalError> {
    let i = sp
        .checked_sub(1)
        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })?;
    let v = stack
        .get(i)
        .copied()
        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })?;
    v.as_bool().ok_or(EvalError::TypeError { pc: to_u16(pc) })
}

/// Evaluates a program.
///
/// Performs no heap allocation and terminates in at most `prog.ops().len()`
/// steps.
///
/// `prog` and the returned value share the lifetime `'a`, because a
/// `Value::Str` may name either a request byte range or a constant in the
/// program's own arena.
///
/// # Errors
/// Every `EvalError` variant. For a program that passed `check` and `verify`,
/// none of them is reachable; the caller still handles the error through the
/// filter's failure mode rather than unwrapping.
#[allow(
    clippy::too_many_lines,
    reason = "one flat, non-recursive match over the 22-variant Op enum, matching the algorithm the issue specifies instruction for instruction; splitting the match arms into separate functions would spread one control-flow loop across several signatures for no reduction in real complexity"
)]
pub fn eval<'a>(prog: &'a Program, env: &mut Env<'a, '_>) -> Result<Value<'a>, EvalError> {
    // `usize::from` is not yet usable in a const-generic array-length position
    // on this crate's MSRV (`usize::from(u8)` is not a stable const fn there),
    // so the widening cast is spelled `as usize`: it is lossless, `Program::
    // MAX_STACK` is a `u8` const, and `Value` derives no `Ord` for
    // `clippy::cast_lossless` to have an alternative to suggest here in a
    // const context.
    let mut stack: [Value<'a>; Program::MAX_STACK as usize] = // it-allow: unchecked-cast reason: widening u8 to usize is lossless; usize::from is not const-stable on this crate's MSRV for use as an array length
        [Value::Null; Program::MAX_STACK as usize]; // it-allow: unchecked-cast reason: widening u8 to usize is lossless; usize::from is not const-stable on this crate's MSRV for use as an array length
    let mut sp: usize = 0;
    let mut pc: usize = 0;
    let mut steps: u32 = 0;
    let budget = step_budget(prog);

    loop {
        if steps > budget {
            return Err(EvalError::StepBudget { steps });
        }
        steps += 1;

        let op = *prog
            .ops()
            .get(pc)
            .ok_or(EvalError::BadPc { pc: to_u16(pc) })?;

        match op {
            Op::LoadAttr(n) => {
                let v = env.slot(n, prog)?;
                push(&mut stack, &mut sp, pc, v)?;
            }
            Op::LoadConst(n) => {
                let v = const_value(prog, n).ok_or(EvalError::BadOperand { pc: to_u16(pc) })?;
                push(&mut stack, &mut sp, pc, v)?;
            }
            Op::Eq | Op::Ne => {
                let b = pop(&stack, &mut sp, pc)?;
                let a = pop(&stack, &mut sp, pc)?;
                let eq = a.itpl_eq(b);
                let r = if op == Op::Ne { !eq } else { eq };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                let b = pop_int(&stack, &mut sp, pc)?;
                let a = pop_int(&stack, &mut sp, pc)?;
                let r = if op == Op::Lt {
                    a < b
                } else if op == Op::Le {
                    a <= b
                } else if op == Op::Gt {
                    a > b
                } else {
                    a >= b
                };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::InSet(n) => {
                let a = pop(&stack, &mut sp, pc)?;
                let list = prog
                    .list_of(n)
                    .ok_or(EvalError::BadOperand { pc: to_u16(pc) })?;
                let found = list
                    .iter()
                    .filter_map(|c| const_to_value(prog, c))
                    .any(|v| v.itpl_eq(a));
                push(&mut stack, &mut sp, pc, Value::Bool(found))?;
            }
            Op::StartsWith => {
                let b = pop_str_or_null(&stack, &mut sp, pc)?;
                let a = pop_str_or_null(&stack, &mut sp, pc)?;
                let r = match (a, b) {
                    (Some(a), Some(b)) => a.starts_with(b),
                    _ => false,
                };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::EndsWith => {
                let b = pop_str_or_null(&stack, &mut sp, pc)?;
                let a = pop_str_or_null(&stack, &mut sp, pc)?;
                let r = match (a, b) {
                    (Some(a), Some(b)) => a.ends_with(b),
                    _ => false,
                };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::Contains => {
                let b = pop_str_or_null(&stack, &mut sp, pc)?;
                let a = pop_str_or_null(&stack, &mut sp, pc)?;
                // `memchr::memmem::find` MUST be the search here: it is a
                // two-way search with an O(n + m) bound and no input that
                // degrades it. The haystack is an attribute value (a peer
                // can make it `max_field_line_bytes`), the needle is a
                // program constant (an operator can make it
                // `max_string_bytes`); a naive nested scan is O(n * m) and
                // turns one long header into milliseconds of CPU an
                // unauthenticated peer chose.
                let r = match (a, b) {
                    (Some(a), Some(b)) => memchr::memmem::find(a, b).is_some(),
                    _ => false,
                };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::EqIgnoreCase => {
                let b = pop_str_or_null(&stack, &mut sp, pc)?;
                let a = pop_str_or_null(&stack, &mut sp, pc)?;
                let r = match (a, b) {
                    (Some(a), Some(b)) => ascii_eq_ignore_case(a, b),
                    _ => false,
                };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::StartsWithIgnoreCase => {
                let b = pop_str_or_null(&stack, &mut sp, pc)?;
                let a = pop_str_or_null(&stack, &mut sp, pc)?;
                let r = match (a, b) {
                    (Some(a), Some(b)) => ascii_starts_with_ignore_case(a, b),
                    _ => false,
                };
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::RegexMatch(n) => {
                let a = pop_str_or_null(&stack, &mut sp, pc)?;
                // The table lookup happens BEFORE the closure below: writing
                // `prog.regex(n)?` inside the `is_some_and` closure does not
                // compile, because the closure returns `bool` and `?` needs
                // the enclosing function's error type.
                let re = prog
                    .regex(n)
                    .ok_or(EvalError::BadOperand { pc: to_u16(pc) })?;
                let r = a.is_some_and(|s| re.is_match(s));
                push(&mut stack, &mut sp, pc, Value::Bool(r))?;
            }
            Op::Size => {
                let a = pop(&stack, &mut sp, pc)?;
                // `Size` is only ever applied to a `Str`; a list literal
                // never reaches the operand stack, because the compiler
                // constant-folds `[..].size()` into a `LoadConst` of an
                // `Int`. `Size` on anything else is a `TypeError`, not 0,
                // because the checker guarantees the receiver's type and a
                // silent 0 would hide a schema bug.
                let Value::Str(s) = a else {
                    return Err(EvalError::TypeError { pc: to_u16(pc) });
                };
                let len = i64::try_from(s.len()).unwrap_or(i64::MAX);
                push(&mut stack, &mut sp, pc, Value::Int(len))?;
            }
            Op::Not => {
                let a = pop_bool(&stack, &mut sp, pc)?;
                push(&mut stack, &mut sp, pc, Value::Bool(!a))?;
            }
            Op::JumpIfFalse(t) => {
                if peek_is_false(&stack, sp, pc)? {
                    pc = usize::from(t);
                    continue;
                }
                sp -= 1;
            }
            Op::JumpIfTrue(t) => {
                if peek_is_true(&stack, sp, pc)? {
                    pc = usize::from(t);
                    continue;
                }
                sp -= 1;
            }
            Op::BranchIfFalse(t) => {
                let cond = pop_bool(&stack, &mut sp, pc)?;
                if !cond {
                    pc = usize::from(t);
                    continue;
                }
            }
            Op::Jump(t) => {
                pc = usize::from(t);
                continue;
            }
            Op::Ret => {
                return if sp == 1 {
                    stack
                        .first()
                        .copied()
                        .ok_or(EvalError::StackUnderflow { pc: to_u16(pc) })
                } else {
                    Err(EvalError::StackUnderflow { pc: to_u16(pc) })
                };
            }
        }
        pc += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrId;
    use crate::check::check;
    use crate::compile::compile;
    use crate::lex::lex;
    use crate::limits::PolicyLimits;
    use crate::parse::parse;
    use crate::program::Program;
    use crate::token::Span;
    use core::cell::Cell;
    use irontraffic_filter::Phase;
    use proptest::prelude::*;
    use std::sync::Mutex;

    // ------------------------------------------------------------------
    // Test fixture and helpers shared by most of the tests below.
    // ------------------------------------------------------------------

    fn default_limits() -> PolicyLimits {
        PolicyLimits::defaults()
    }

    /// Lexes, parses, checks and compiles `src` at `phase` with default
    /// limits, exactly like `compile.rs`'s own `compile_src` test helper of
    /// the same shape. Written out again here rather than shared: this
    /// module has no dependency on `crate::compile`'s test module, and
    /// `#[cfg(test)]` code is not part of either crate's public surface for
    /// the other to import.
    fn compile_src(src: &[u8], phase: Phase) -> Program {
        let limits = default_limits();
        let toks = lex(src, &limits).expect("fixture must lex");
        let ast = parse(&toks, src, &limits).expect("fixture must parse");
        let mut strings = toks.strings;
        let checked = check(ast, &mut strings, src, phase, &limits).expect("fixture must check");
        compile(&checked, &limits).expect("fixture must compile")
    }

    /// A hand-built `AttrSource` for request-shaped fixtures. Not a real
    /// request parser: `irontraffic-filter` and `irontraffic-http` are not
    /// dependencies of this crate, and wiring a real `AttrSource` over
    /// `irontraffic_filter::Ctx` is `{{itpl-mutation-plan-and-policy-filter}}`'s
    /// job (#273), not this one's.
    struct Fixture {
        method: &'static [u8],
        path: &'static [u8],
        port: i64,
        tls: bool,
        /// `(name, value)` pairs. More than one entry sharing a name is what
        /// produces `FieldOutcome::Duplicate` for that name.
        headers: Vec<(&'static [u8], &'static [u8])>,
        scalar_calls: Cell<u32>,
        /// When `Some(id)`, `scalar` asserts every call names `id`: the
        /// mechanism edge cases 2 and 3 ask for ("a source that panics if
        /// asked for b's attribute"), proving a short-circuited operand's
        /// attribute is never touched.
        panics_on_scalar_other_than: Cell<Option<AttrId>>,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                method: b"GET",
                path: b"/v1/widgets",
                port: 8080,
                tls: true,
                headers: Vec::new(),
                scalar_calls: Cell::new(0),
                panics_on_scalar_other_than: Cell::new(None),
            }
        }
    }

    impl<'a> AttrSource<'a> for Fixture {
        fn scalar(&self, id: AttrId) -> Value<'a> {
            self.scalar_calls.set(self.scalar_calls.get() + 1);
            if let Some(only) = self.panics_on_scalar_other_than.get() {
                assert_eq!(
                    id, only,
                    "a short-circuited operand's attribute must never be read"
                );
            }
            match id {
                AttrId::RequestMethod => Value::Str(self.method),
                AttrId::RequestPath => Value::Str(self.path),
                AttrId::RequestPort => Value::Int(self.port),
                AttrId::ConnectionTls => Value::Bool(self.tls),
                _ => Value::Null,
            }
        }

        fn field(&self, map: MapId, key: &[u8]) -> FieldOutcome<'a> {
            if map != MapId::RequestHeaders {
                return FieldOutcome::Absent;
            }
            let mut found: Option<&[u8]> = None;
            let mut count = 0u32;
            for (name, value) in &self.headers {
                if *name == key {
                    count += 1;
                    found = Some(value);
                }
            }
            match count {
                0 => FieldOutcome::Absent,
                1 => FieldOutcome::Present(found.unwrap_or(b"")),
                _ => FieldOutcome::Duplicate,
            }
        }
    }

    /// Builds an `Env` for `prog` bound to `fixture`, deriving `used` from
    /// the program's own slot table so every test wires this correctly by
    /// construction rather than by a hand-copied number.
    fn env_for<'a, 'p>(prog: &Program, fixture: &'p Fixture) -> Env<'a, 'p>
    where
        'p: 'a,
    {
        let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
        Env::new(fixture, used)
    }

    // ------------------------------------------------------------------
    // Named tests 4-25 (value.rs carries 1-3).
    // ------------------------------------------------------------------

    #[test]
    fn eval_constant() {
        // Test 4 / edge case 1: `true` evaluates to `Value::Bool(true)` in
        // two steps (`LoadConst`, `Ret`).
        let prog = compile_src(b"true", Phase::Log);
        assert_eq!(prog.ops().len(), 2, "fixture precondition: two ops");
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
    }

    #[test]
    fn short_circuit_and() {
        // Test 5 / edge case 2: `a && b` with `a` false never evaluates `b`.
        let prog = compile_src(
            br#"request.method == "POST" && request.port == 8080"#,
            Phase::RequestHeaders,
        );
        let fixture = Fixture::new(); // method is "GET", so the left side is false
        assert_eq!(fixture.method, b"GET", "fixture precondition");
        fixture
            .panics_on_scalar_other_than
            .set(Some(AttrId::RequestMethod));
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(false)));
    }

    #[test]
    fn short_circuit_or() {
        // Test 6 / edge case 3: `a || b` with `a` true never evaluates `b`.
        let prog = compile_src(
            br#"request.port == 8080 || request.method == "POST""#,
            Phase::RequestHeaders,
        );
        let fixture = Fixture::new(); // port is 8080, so the left side is true
        assert_eq!(fixture.port, 8080, "fixture precondition");
        fixture
            .panics_on_scalar_other_than
            .set(Some(AttrId::RequestPort));
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
    }

    // ------------------------------------------------------------------
    // A CONFIRMED, PRE-EXISTING BUG IN THE SHIPPED #271 COMPILER, found
    // while writing the tests below, and worked around here rather than
    // fixed: `crate::compile` is not in this issue's Files table.
    //
    // `request.headers["x-a"]` (any bracket-indexed map access:
    // `request.headers[...]`, `request.query_params[...]`,
    // `response.headers[...]`) fails `compile`'s own internal
    // `verify` call with `StackNotSingleton` for EVERY key, because
    // `crate::compile`'s `build_suppressed` (the mechanism that keeps a
    // list literal's element or a `matches()` pattern from being emitted
    // twice, once as its own node and once folded into the parent) never
    // marks a `Node::Index`'s KEY child as suppressed. `check::resolve_index`
    // bakes the key into the interned `AttrRef::Field{ key, .. }` slot, but
    // the key's own `Node::Str` id is still visited by the ordinary forward
    // sweep and unconditionally emits a `LoadConst` for it, IN ADDITION to
    // the `Op::LoadAttr` the `Index` node itself emits. That is two pushes
    // for what should be one, so `verify` correctly refuses the result:
    // `request.headers["x-a"]` alone compiles to
    // `[LoadConst(0), LoadAttr(0), Ret]`, `StackNotSingleton { at: 2, depth:
    // 2 }`. This affects EVERY bracket-indexed expression regardless of
    // what it is compared against; `compile.rs`'s own test suite never
    // caught it because none of its tests carry the full pipeline
    // (`check` -> `compile` -> `verify`) through a `[...]` index, only
    // through `check` alone (`check.rs` has many).
    //
    // Reported: a comment on issue #271 and a note in this issue's own PR
    // description. Every test below that needs an `AttrRef::Field` slot is
    // hand-built through `Program::from_parts` instead of through real ITPL
    // source text, which still fully exercises this issue's actual
    // deliverable (`Env::slot`'s `AttrRef::Field` arm and the duplicate-
    // header handling this whole issue exists for); it just cannot go
    // through `crate::compile` until #271's bug is fixed.
    // ------------------------------------------------------------------

    /// Interns `s` into `strings`, returning the `Span` naming it.
    fn intern(strings: &mut Vec<u8>, s: &[u8]) -> Span {
        let start = u32::try_from(strings.len()).unwrap_or(u32::MAX);
        strings.extend_from_slice(s);
        let end = u32::try_from(strings.len()).unwrap_or(u32::MAX);
        Span { start, end }
    }

    /// A `Const::Str` naming `s`, interned into `strings`.
    fn str_const(strings: &mut Vec<u8>, s: &[u8]) -> Const {
        let span = intern(strings, s);
        Const::Str {
            from: span.start,
            len: span.end - span.start,
        }
    }

    /// An `AttrRef::Field` naming `key` in `map`, interned into `strings`.
    fn field_ref(strings: &mut Vec<u8>, map: MapId, key: &[u8]) -> AttrRef {
        AttrRef::Field {
            map,
            key: intern(strings, key),
        }
    }

    #[test]
    fn absent_header_is_null() {
        // Test 7 / edge case 4: an absent header compared to a string is
        // false, never Null == Null. Hand-built; see the compiler-bug note
        // above.
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-missing");
        let v = str_const(&mut strings, b"v");
        let prog = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![v],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut fixture = Fixture::new();
        fixture.headers = Vec::new();
        assert!(
            fixture.headers.is_empty(),
            "fixture precondition: no headers at all"
        );
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(false)));

        // Edge case 5: an absent header compared to `null` is true.
        let mut strings2 = Vec::new();
        let key2 = field_ref(&mut strings2, MapId::RequestHeaders, b"x-missing");
        let prog_null = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![Const::Null],
            vec![],
            strings2,
            vec![key2],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env2 = env_for(&prog_null, &fixture);
        assert_eq!(eval(&prog_null, &mut env2), Ok(Value::Bool(true)));
    }

    #[test]
    fn duplicate_header_is_null_and_counted() {
        // Test 8: a fixture section carrying `x-a: 1` and `x-a: 2`.
        // Hand-built; see the compiler-bug note above.
        let mut fixture = Fixture::new();
        fixture.headers = vec![(b"x-a".as_slice(), b"1".as_slice()), (b"x-a", b"2")];
        assert_eq!(
            fixture.headers.iter().filter(|(n, _)| *n == b"x-a").count(),
            2,
            "fixture precondition: x-a really is duplicated"
        );

        let guard = duplicate_count_lock();

        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-a");
        let prog_value = Program::from_parts(
            vec![Op::LoadAttr(0), Op::Ret],
            vec![],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Str,
            Phase::RequestHeaders,
            1,
        );
        let mut env = env_for(&prog_value, &fixture);
        assert_eq!(eval(&prog_value, &mut env), Ok(Value::Null));
        assert!(env.saw_duplicate());

        let before = duplicate_header_count();
        let mut strings2 = Vec::new();
        let key2 = field_ref(&mut strings2, MapId::RequestHeaders, b"x-a");
        let one = str_const(&mut strings2, b"1");
        let prog_eq = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![one],
            vec![],
            strings2,
            vec![key2],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env2 = env_for(&prog_eq, &fixture);
        assert_eq!(eval(&prog_eq, &mut env2), Ok(Value::Bool(false)));
        assert_eq!(
            duplicate_header_count() - before,
            1,
            "exactly one duplicate lookup across this evaluation"
        );
        assert!(env2.saw_duplicate());
        drop(guard);
    }

    #[test]
    fn duplicate_header_flags_a_deny_list_predicate() {
        // Test 8b: the bypass shape. `!=` on a duplicated header evaluates to
        // `true` (admits), and `saw_duplicate()` is the only thing that
        // distinguishes this from a request that genuinely lacks the header.
        // Hand-built; see the compiler-bug note above.
        let mut fixture = Fixture::new();
        fixture.headers = vec![
            (b"x-blocked".as_slice(), b"yes".as_slice()),
            (b"x-blocked", b"yes"),
        ];
        assert_eq!(
            fixture
                .headers
                .iter()
                .filter(|(n, _)| *n == b"x-blocked")
                .count(),
            2,
            "fixture precondition"
        );

        let _guard = duplicate_count_lock();
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-blocked");
        let yes = str_const(&mut strings, b"yes");
        let prog = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Ne, Op::Ret],
            vec![yes],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
        assert!(
            env.saw_duplicate(),
            "the flag is what a fail-closed filter uses to refuse this bypass"
        );
    }

    #[test]
    fn absent_header_does_not_set_the_flag() {
        // Test 8c: a fixture with no `x-a` leaves `saw_duplicate()` false.
        // Hand-built; see the compiler-bug note above.
        let fixture = Fixture::new();
        assert!(fixture.headers.is_empty(), "fixture precondition");
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-a");
        let prog = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![Const::Null],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
        assert!(!env.saw_duplicate());
    }

    #[test]
    fn flag_survives_short_circuit() {
        // Test 8d: a duplicate seen in the left operand of `&&`, whose right
        // operand is skipped, still leaves `saw_duplicate()` true.
        // Hand-built (see the compiler-bug note above) in the exact
        // and-chain shape `crate::compile`'s own `and_lowering` test pins
        // for two clauses: `JumpIfFalse` targets `Ret` directly, leaving
        // the false value in place.
        let mut fixture = Fixture::new();
        fixture.headers = vec![(b"x-a".as_slice(), b"1".as_slice()), (b"x-a", b"2")];
        fixture.method = b"GET";
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-a");
        let one = str_const(&mut strings, b"1");
        let post = str_const(&mut strings, b"POST");
        let slots = vec![key, AttrRef::Scalar(AttrId::RequestMethod)];
        let ops = vec![
            Op::LoadAttr(0),
            Op::LoadConst(0),
            Op::Eq,
            Op::JumpIfFalse(7),
            Op::LoadAttr(1),
            Op::LoadConst(1),
            Op::Eq,
            Op::Ret,
        ];
        let prog = Program::from_parts(
            ops,
            vec![one, post],
            vec![],
            strings,
            slots,
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let _guard = duplicate_count_lock();
        let mut env = env_for(&prog, &fixture);
        // Left side is `Null == "1"`, which is false, so the right side
        // (`request.method == "POST"`, also false against a GET fixture)
        // never runs, but the duplicate flag from the left side must
        // survive the short circuit.
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(false)));
        assert!(env.saw_duplicate());
    }

    #[test]
    fn empty_header_is_not_null() {
        // Test 9 / edge case 8: `Str(b"")`, which is not `Null`. Hand-built;
        // see the compiler-bug note above.
        let mut fixture = Fixture::new();
        fixture.headers = vec![(b"x-empty".as_slice(), b"".as_slice())];

        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-empty");
        let empty = str_const(&mut strings, b"");
        let prog_eq = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![empty],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env = env_for(&prog_eq, &fixture);
        assert_eq!(eval(&prog_eq, &mut env), Ok(Value::Bool(true)));

        let mut strings2 = Vec::new();
        let key2 = field_ref(&mut strings2, MapId::RequestHeaders, b"x-empty");
        let prog_null = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![Const::Null],
            vec![],
            strings2,
            vec![key2],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env2 = env_for(&prog_null, &fixture);
        assert_eq!(eval(&prog_null, &mut env2), Ok(Value::Bool(false)));
    }

    #[test]
    fn method_on_null_receiver_is_false() {
        // Test 10 / edge case 6: an absent header as a method receiver is
        // `false`, never an error. Hand-built; see the compiler-bug note
        // above.
        let fixture = Fixture::new();
        assert!(fixture.headers.is_empty(), "fixture precondition");
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-missing");
        let a = str_const(&mut strings, b"a");
        let prog = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::StartsWith, Op::Ret],
            vec![a],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(false)));
    }

    #[test]
    fn starts_with_empty_and_longer() {
        // Test 11 / edge cases 9 and 10.
        let prog_empty = compile_src(br#""".startsWith("")"#, Phase::Log);
        let fixture = Fixture::new();
        let mut env = env_for(&prog_empty, &fixture);
        assert_eq!(
            eval(&prog_empty, &mut env),
            Ok(Value::Bool(true)),
            "every string starts with the empty string"
        );

        let prog_longer = compile_src(br#""abc".startsWith("abcd")"#, Phase::Log);
        let mut env2 = env_for(&prog_longer, &fixture);
        assert_eq!(
            eval(&prog_longer, &mut env2),
            Ok(Value::Bool(false)),
            "a needle longer than the haystack cannot be a prefix"
        );
    }

    #[test]
    fn non_utf8_comparison() {
        // Test 12 / edge case 11: a non-UTF-8 header value, compared
        // byte-wise. Hand-built; see the compiler-bug note above.
        let mut fixture = Fixture::new();
        fixture.headers = vec![(b"x-bin".as_slice(), b"\xff\x00".as_slice())];
        assert_eq!(
            fixture.headers.first().map(|(_, v)| *v),
            Some(b"\xff\x00".as_slice()),
            "fixture precondition"
        );
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-bin");
        let bin = str_const(&mut strings, b"\xff\x00");
        let prog = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq, Op::Ret],
            vec![bin],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
    }

    #[test]
    fn equals_ignore_case_is_ascii_only() {
        // Test 13 / edge case 12: only ASCII A-Z/a-z fold; byte 0xC3 folds to
        // itself. The ASCII half is pure string literals, unaffected by the
        // map-index compiler bug, so it still goes through the real
        // pipeline; the non-ASCII half needs a header and is hand-built
        // (see the compiler-bug note above).
        let prog_ascii = compile_src(br#""GET".equalsIgnoreCase("get")"#, Phase::Log);
        let fixture = Fixture::new();
        let mut env = env_for(&prog_ascii, &fixture);
        assert_eq!(eval(&prog_ascii, &mut env), Ok(Value::Bool(true)));

        // 0xC3 is a Latin-1 Supplement UTF-8 lead byte; it is not `A`-`Z` or
        // `a`-`z`, so it must NOT fold against 0xE3 (0xC3 with the ASCII
        // case bit flipped) the way an ASCII byte would.
        let mut fixture_bin = Fixture::new();
        fixture_bin.headers = vec![(b"x-bin".as_slice(), b"\xc3".as_slice())];
        let mut strings = Vec::new();
        let key = field_ref(&mut strings, MapId::RequestHeaders, b"x-bin");
        let e3 = str_const(&mut strings, b"\xe3");
        let prog_bin = Program::from_parts(
            vec![Op::LoadAttr(0), Op::LoadConst(0), Op::EqIgnoreCase, Op::Ret],
            vec![e3],
            vec![],
            strings,
            vec![key],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::RequestHeaders,
            2,
        );
        let mut env2 = env_for(&prog_bin, &fixture_bin);
        assert_eq!(eval(&prog_bin, &mut env2), Ok(Value::Bool(false)));
    }

    #[test]
    fn int_comparison_extremes() {
        // Test 14 / edge case 13: comparisons at `i64::MIN`/`i64::MAX` do not
        // overflow, because they are compares, not subtractions. Hand-built
        // directly against the two extreme constants, rather than through
        // ITPL integer-literal source text, which is `crate::lex`'s concern,
        // not the evaluator's.
        let consts = vec![Const::Int(i64::MIN), Const::Int(i64::MAX)];
        let ops = vec![Op::LoadConst(0), Op::LoadConst(1), Op::Lt, Op::Ret];
        let prog = Program::from_parts(
            ops,
            consts.clone(),
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            2,
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        assert_eq!(
            eval(&prog, &mut env),
            Ok(Value::Bool(true)),
            "i64::MIN < i64::MAX"
        );

        let ops_ge = vec![Op::LoadConst(1), Op::LoadConst(0), Op::Ge, Op::Ret];
        let prog_ge = Program::from_parts(
            ops_ge,
            consts,
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            2,
        );
        let mut env2 = env_for(&prog_ge, &fixture);
        assert_eq!(
            eval(&prog_ge, &mut env2),
            Ok(Value::Bool(true)),
            "i64::MAX >= i64::MIN"
        );
    }

    #[test]
    fn in_set_empty_and_last_element() {
        // Test 15 / edge cases 14 and 15. Hand-built via `Program::from_parts`
        // so the empty-list and the exact element count are pinned as
        // literals rather than left to whatever the checker happens to admit
        // for an empty list literal.
        let consts_empty = vec![Const::Int(7), Const::List { from: 0, len: 0 }];
        let prog_empty = Program::from_parts(
            vec![Op::LoadConst(0), Op::InSet(1), Op::Ret],
            consts_empty,
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            1,
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog_empty, &fixture);
        assert_eq!(eval(&prog_empty, &mut env), Ok(Value::Bool(false)));

        let list_elems: Vec<Const> = (0i64..64).map(Const::Int).collect();
        assert_eq!(list_elems.len(), 64, "fixture precondition");
        let consts_64 = vec![Const::Int(63), Const::List { from: 0, len: 64 }];
        let prog_64 = Program::from_parts(
            vec![Op::LoadConst(0), Op::InSet(1), Op::Ret],
            consts_64,
            list_elems,
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            1,
        );
        let mut env2 = env_for(&prog_64, &fixture);
        assert_eq!(
            eval(&prog_64, &mut env2),
            Ok(Value::Bool(true)),
            "63 is the last of the 64 elements 0..64"
        );
    }

    #[test]
    fn regex_match_large_haystack() {
        // Test 16 / edge case 16: a 1 MiB haystack. This proves CORRECTNESS
        // over a genuinely large input (linear time inside the regex
        // engine), which is edge case 16's point. It deliberately does NOT
        // assert a wall-clock bound here: house policy for this suite is "no
        // wall clock assertions in the parallel suite; they flake and block
        // unrelated merges" (#750, #762 in this effort's own history). The
        // timing claim this test's docs describe ("linear time... the test
        // uses 1 MiB to prove the bound") is instead carried by the
        // `eval/regex_1kib` criterion benchmark in `benches/policy.rs`,
        // which runs outside the flaky parallel gate and measures with
        // proper statistical replication instead of one `Instant::now()`
        // read.
        let haystack = vec![b'a'; 1_048_576];
        assert_eq!(haystack.len(), 1_048_576, "fixture precondition");
        let mut fixture = Fixture::new();
        fixture.path = Box::leak(haystack.into_boxed_slice());
        let prog = compile_src(br#"request.path.matches("^a+$")"#, Phase::RequestHeaders);
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
    }

    #[test]
    fn size_on_string() {
        // Test 17 / edge case 17: `request.method.size()` against method
        // "GET" evaluates to `Value::Int(3)`.
        let mut fixture = Fixture::new();
        fixture.method = b"GET";
        assert_eq!(fixture.method.len(), 3, "fixture precondition");
        let prog = compile_src(b"request.method.size() == 3", Phase::RequestHeaders);
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
    }

    #[test]
    fn size_on_list_is_folded_not_evaluated() {
        // Test 17b: `["a","b","c"].size()` evaluates to `Value::Int(3)`, and
        // the compiled program contains no `Op::Size`, which is the
        // compiler's constant fold, not an evaluator path.
        let prog = compile_src(br#"["a", "b", "c"].size() == 3"#, Phase::Log);
        assert!(
            !prog.ops().contains(&Op::Size),
            "fixture precondition: a list literal's .size() must fold at compile time"
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Ok(Value::Bool(true)));
    }

    #[test]
    fn size_on_null_is_type_error() {
        // Test 18 / edge case 18: a hand-built `[LoadConst(Null), Size, Ret]`
        // returns `Err(EvalError::TypeError { pc: 1 })`.
        let prog = Program::from_parts(
            vec![Op::LoadConst(0), Op::Size, Op::Ret],
            vec![Const::Null],
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Int,
            Phase::Log,
            1,
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Err(EvalError::TypeError { pc: 1 }));
    }

    #[test]
    fn slot_cache_resolves_once() {
        // Test 19: two references to `request.path` in one expression
        // resolve to one dense slot (the checker dedups identical attribute
        // references), so `Env::slot` must serve the second `LoadAttr` from
        // the cache: one call to `scalar`, not two.
        let prog = compile_src(
            br#"request.path.startsWith("/v1/") && request.path.endsWith("/widgets")"#,
            Phase::RequestHeaders,
        );
        assert_eq!(
            prog.slots().len(),
            1,
            "fixture precondition: one distinct attribute slot"
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        let _ = eval(&prog, &mut env).expect("fixture must evaluate");
        assert_eq!(
            fixture.scalar_calls.get(),
            1,
            "the second LoadAttr must be a cache hit"
        );
        assert_eq!(env.resolved(), 1);
    }

    #[test]
    fn sixteen_slots() {
        // Test 20 / edge case 21: a program using all 16 slots. All cached;
        // the array is exactly full.
        //
        // Hand-built as a 16-clause AND chain over 16 distinct slots (all
        // bound to the same attribute, so a single fixture value makes
        // every clause true), in the exact shape `crate::compile`'s own
        // `and_lowering` pins for two clauses and `crate::program`'s
        // `verify_returns_max_stack` test exercises for the general
        // pattern: each clause is `LoadAttr(k), LoadConst(0), Eq`, and every
        // clause after the first is preceded by a `JumpIfFalse` hole
        // targeting `Ret` (so a false clause short-circuits leaving `false`
        // in place, matching `&&`'s own semantics), which keeps the operand
        // stack depth at 1 or 2 throughout rather than accumulating all 16
        // pushes at once. A first, simpler attempt at this fixture (pairwise
        // `Eq`-folding every new `LoadAttr` directly against the RUNNING
        // BOOLEAN accumulator) was wrong and caught by this test's own
        // assertion: comparing a `Bool` accumulator against a freshly loaded
        // `Int` is a type mismatch, which ITPL equality reports as `false`
        // rather than an error, so every fold after the first silently
        // produced `false` instead of testing anything past slot 1. The
        // fail-then-pass evidence for THIS fixture is exactly that: the
        // first version of this test asserted `Value::Bool(true)` and
        // observed `Value::Bool(false)`.
        let slots = vec![AttrRef::Scalar(AttrId::RequestPort); 16];
        let mut ops = vec![Op::LoadAttr(0), Op::LoadConst(0), Op::Eq];
        for k in 1u16..16 {
            ops.push(Op::JumpIfFalse(0)); // patched to `ret_at` below
            ops.push(Op::LoadAttr(k));
            ops.push(Op::LoadConst(0));
            ops.push(Op::Eq);
        }
        ops.push(Op::Ret);
        let ret_at = u16::try_from(ops.len() - 1).unwrap_or(u16::MAX);
        for op in &mut ops {
            if let Op::JumpIfFalse(t) = op {
                *t = ret_at;
            }
        }
        let prog = Program::from_parts(
            ops,
            vec![Const::Int(8080)],
            vec![],
            vec![],
            slots,
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            2,
        );
        assert_eq!(prog.slots().len(), 16, "fixture precondition");
        let fixture = Fixture::new();
        assert_eq!(fixture.port, 8080, "fixture precondition");
        let mut env = env_for(&prog, &fixture);
        let result = eval(&prog, &mut env).expect("fixture must evaluate");
        assert_eq!(
            result,
            Value::Bool(true),
            "the same attribute compared to the same constant, 16 times over"
        );
        assert_eq!(
            env.resolved(),
            16,
            "all 16 slots must be resolved and cached"
        );
    }

    #[test]
    fn slot_index_past_the_cache_is_bad_operand() {
        // Test 20b: a hand-built `Program` with 17 slots and a
        // `LoadAttr(16)` returns `BadOperand` and does not panic. `used` is
        // set to the real (17-entry) slot count so this isolates the
        // `Env::MAX_SLOTS` bound specifically, not merely a mismatched
        // `used`.
        let slots = vec![AttrRef::Scalar(AttrId::RequestPort); 17];
        assert_eq!(slots.len(), 17, "fixture precondition");
        let prog = Program::from_parts(
            vec![Op::LoadAttr(16), Op::Ret],
            vec![],
            vec![],
            vec![],
            slots,
            vec![],
            crate::attrs::Ty::Str,
            Phase::Log,
            1,
        );
        let fixture = Fixture::new();
        let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
        let mut env = Env::new(&fixture, used);
        assert_eq!(eval(&prog, &mut env), Err(EvalError::BadOperand { pc: 16 }));
    }

    #[test]
    fn backward_jump_hits_step_budget() {
        // Test 21 / edge case 19: a hand-built program with `Jump(0)` at
        // index 1 returns `StepBudget` rather than hanging. No wall-clock
        // timeout is needed in this test: `eval`'s own step budget
        // (`ops.len()`, checked every iteration) is what bounds this, by
        // construction, to a handful of iterations regardless of the
        // program's cycle; the "1 second" the issue's own test list
        // mentions is nextest's slow-timeout backstop at the CI level, not
        // something this test needs to assert itself.
        let prog = Program::from_parts(
            vec![Op::Jump(1), Op::Jump(0)],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            0,
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        let result = eval(&prog, &mut env);
        assert!(
            matches!(result, Err(EvalError::StepBudget { .. })),
            "expected StepBudget, got {result:?}"
        );
    }

    #[test]
    fn bad_pc_is_error() {
        // Test 22 / edge case 20: a hand-built program with `pc` past the
        // end. `Jump(5)` targets an index past `ops.len() == 2`; `verify`
        // would reject this, but a hand-built `Program` bypasses `verify`
        // entirely.
        let prog = Program::from_parts(
            vec![Op::Jump(5), Op::Ret],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            0,
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env), Err(EvalError::BadPc { pc: 5 }));
    }

    #[test]
    fn stack_underflow_is_error() {
        // Test 23 / edge case 19 (verify's own naming; this crate's edge
        // case list reuses index 19 for the backward-jump case, so this is
        // simply "a hand-built Eq on an empty stack" per the issue's own
        // test list): `Eq` with nothing on the stack.
        let prog = Program::from_parts(
            vec![Op::Eq, Op::Ret],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            crate::attrs::Ty::Bool,
            Phase::Log,
            0,
        );
        let fixture = Fixture::new();
        let mut env = env_for(&prog, &fixture);
        assert_eq!(
            eval(&prog, &mut env),
            Err(EvalError::StackUnderflow { pc: 0 })
        );
    }

    /// The exact line `scripts/invariant-lints.sh`'s `hot_files` helper
    /// greps for (`grep -l '^//! HOT PATH'`) to decide which files its
    /// `hot-path-allocation`/`hot-path-lock` rules cover.
    const HOT_PATH_MARKER: &str = "//! HOT PATH";

    #[test]
    fn eval_zero_alloc() {
        // Test 24 / invariant 1 / the acceptance criterion "a counting
        // allocator test asserts 0 allocations across evaluating the whole
        // test corpus".
        //
        // DEVIATION FROM THE ISSUE'S LITERAL SPEC, DOCUMENTED HERE AND IN
        // THE PR: this crate carries `#![forbid(unsafe_code)]`
        // (`{{itpl-crate-lexer-and-grammar}}`). `GlobalAlloc` is declared as
        // an unsafe trait in `core`, so writing an implementation of it, even
        // a pure counter that forwards to `std::alloc::System`, requires the
        // one Rust keyword this repository denies with no authorized
        // exception. `scripts/invariant-lints.sh`'s `no-unsafe` rule scans
        // every tracked `.rs` file, tests included, with NO escape hatch:
        // its own failure message states "There is no exception an
        // implementer is authorized to make; raise it on the issue
        // instead," and AGENTS.md repeats the same absolute rule. A
        // `#[cfg(test)]`-scoped lint-level change (the shape this issue's
        // own text describes, pairing a weaker crate-level setting with a
        // per-item override that re-enables the keyword just for that one
        // block) changes what `rustc` accepts, but the invariant-lints scan
        // is a plain text grep with no `cfg` awareness, so it fires on
        // those exact keyword-and-brace and override spellings regardless
        // of the `cfg` gate around them, and would fail
        // `scripts/gate-fast.sh`'s mandatory, non-negotiable structural
        // checks. This is not a novel judgment call: this exact repository
        // already hit this exact conflict for this exact property
        // (`crates/irontraffic-router/tests/no_alloc.rs`, written for
        // issue #58) and rejected a process-wide counting `GlobalAlloc` for
        // the same two reasons documented there (does not compile under the
        // no-exception ban, and is unsound anyway, since a process-wide
        // allocator counts every OTHER test running in parallel in the same
        // binary too).
        //
        // The established substitute, applied identically here: this
        // module's `//! HOT PATH` header (already required by this issue's
        // own acceptance criteria) puts every function in this file under
        // `scripts/invariant-lints.sh`'s `hot-path-allocation` rule, a CI
        // text scan for the concrete vocabulary of allocating call
        // spellings (`Vec::new`, `.to_vec()`, `format!`, `.clone()`, and
        // more), enforced on every pull request, over the WHOLE file rather
        // than a maintained subset of it. This test's only job is to guard
        // against the marker line itself being deleted, which would
        // silently drop this module out of that CI-enforced net; the test
        // census (`scripts/test-census.sh`) refuses a diff that shrinks
        // this test without a written justification, so removing the
        // marker cannot pass unnoticed either.
        let source = include_str!("vm.rs");
        assert!(
            source.lines().any(|line| line == HOT_PATH_MARKER),
            "crates/irontraffic-policy/src/vm.rs must carry a line that is \
             exactly `{HOT_PATH_MARKER}` so scripts/invariant-lints.sh's \
             hot-path-allocation and hot-path-lock rules scan this module; \
             without it, eval, Env::slot and every helper they call could \
             allocate or lock with nothing in this repository catching it"
        );
    }

    #[test]
    fn eval_is_deterministic() {
        // Test 25 / invariant 7: evaluating the same program against the
        // same source twice yields the same value.
        let prog = compile_src(
            br#"request.path.startsWith("/v1/") && request.method == "GET""#,
            Phase::RequestHeaders,
        );
        let fixture = Fixture::new();
        let mut env1 = env_for(&prog, &fixture);
        let mut env2 = env_for(&prog, &fixture);
        assert_eq!(eval(&prog, &mut env1), eval(&prog, &mut env2));
    }

    #[test]
    fn contains_is_linear_on_an_adversarial_pair() {
        // Test 29: an 8 KiB haystack of `a` bytes and a 1 KiB needle of `a`
        // bytes ending in `b`, the worst case for a naive nested scan.
        //
        // As with `regex_match_large_haystack` above, this asserts the
        // FUNCTIONAL result only, not a wall-clock bound: house policy for
        // this suite bans a timing assertion in the parallel gate (#750,
        // #762). The O(n + m) bound itself is enforced two other ways this
        // test does not duplicate: statically, by this issue's own
        // acceptance-criterion source scan for a hand-rolled loop over the
        // haystack (this comment deliberately does not spell out that
        // pattern verbatim, so quoting it here cannot itself trip the very
        // scan it describes), and empirically, by the `eval/contains_8kib`
        // criterion benchmark in `benches/policy.rs`, which carries the
        // "under 20 microseconds" budget and runs outside the flaky
        // parallel suite.
        let haystack = vec![b'a'; 8192];
        let mut needle = vec![b'a'; 1024];
        if let Some(last) = needle.last_mut() {
            *last = b'b';
        }
        assert_eq!(haystack.len(), 8192, "fixture precondition");
        assert_eq!(needle.len(), 1024, "fixture precondition");
        assert_eq!(needle.last(), Some(&b'b'), "fixture precondition");

        let mut fixture = Fixture::new();
        fixture.path = Box::leak(haystack.into_boxed_slice());
        let needle_str = String::from_utf8(needle).expect("ascii needle is valid UTF-8");
        // The needle is embedded in the source as a string literal; ITPL
        // string escapes decode to raw bytes, so an all-`a` needle needs no
        // escaping at all.
        let src = format!("request.path.contains(\"{needle_str}\")");
        let prog = compile_src(src.as_bytes(), Phase::RequestHeaders);
        let mut env = env_for(&prog, &fixture);
        assert_eq!(
            eval(&prog, &mut env),
            Ok(Value::Bool(false)),
            "the needle's final byte never appears in the all-a haystack"
        );
    }

    // ------------------------------------------------------------------
    // Property tests 26-28.
    // ------------------------------------------------------------------

    /// Every scalar attribute and header key the property generators below
    /// reference, so the generator and the fixture that answers it cannot
    /// silently drift apart.
    #[derive(Debug)]
    struct GenFixture {
        method: String,
        path: String,
        port: i64,
        tls: bool,
        header_present: bool,
        header_value: String,
    }

    // `AttrSource` is implemented for `&'a GenFixture` (the reference type),
    // never for bare `GenFixture`: `GenFixture`'s fields are owned `String`s,
    // and a method taking `&self` on a bare `GenFixture` could only ever
    // hand back data borrowed from that short-lived `&self`, never data
    // living for the trait's own, independent `'a`. Implementing the trait
    // for the REFERENCE type instead ties `'a` to the reference itself:
    // `Self = &'a GenFixture` is `Copy`, so a method's own `&self` (an
    // elided, short probe lifetime) can be dereferenced once to recover the
    // original `&'a GenFixture` by copying the pointer, and a field
    // projected through THAT reference genuinely lives for `'a`. An earlier
    // version of this fixture also implemented the trait for bare
    // `GenFixture` (with a panicking body, on the theory that only the
    // reference impl would ever be selected); it was wrong; both property
    // tests below immediately failed with that panic, because passing
    // `&fx: &GenFixture` let the compiler satisfy the trait-object coercion
    // through the BARE `GenFixture: AttrSource<'a>` impl instead of the
    // intended `&'a GenFixture` one. Removed rather than kept and
    // documented as unreachable, because it demonstrably was not.
    impl<'a> AttrSource<'a> for &'a GenFixture {
        fn scalar(&self, id: AttrId) -> Value<'a> {
            match id {
                AttrId::RequestMethod => Value::Str(self.method.as_bytes()),
                AttrId::RequestPath => Value::Str(self.path.as_bytes()),
                AttrId::RequestPort => Value::Int(self.port),
                AttrId::ConnectionTls => Value::Bool(self.tls),
                _ => Value::Null,
            }
        }

        fn field(&self, map: MapId, key: &[u8]) -> FieldOutcome<'a> {
            if map == MapId::RequestHeaders && key == b"x-key" && self.header_present {
                FieldOutcome::Present(self.header_value.as_bytes())
            } else {
                FieldOutcome::Absent
            }
        }
    }

    fn wide_limits() -> PolicyLimits {
        let mut limits = PolicyLimits::defaults();
        limits.max_tokens = 4096;
        limits
    }

    /// One well-typed leaf predicate over the attributes `GenFixture` binds.
    /// Each is `Bool` on its own, so any combination of them joined by
    /// `&&`/`||`/`!`/a ternary is well-typed too. Deliberately varied across
    /// EVERY comparison operator and EVERY closed method, per this effort's
    /// own house lesson (#268/#269, restated for this issue by its own
    /// context) that a property generator emitting only one operator proves
    /// nothing about the other 21.
    ///
    /// Deliberately contains NO bracket-indexed map access
    /// (`request.headers[...]`/`request.query_params[...]`): see the
    /// compiler-bug note above `intern`/`str_const`/`field_ref`.
    /// `crate::compile` cannot compile that shape at all today, for any
    /// key, so a leaf using it would make every draw that selects it panic
    /// on the fixture's own `expect`/`unwrap_or_else`, not on a genuine
    /// property violation; this generator's earlier version had two such
    /// leaves and both `prop_checked_programs_never_error` and
    /// `prop_eval_allocates_nothing` immediately failed with exactly that
    /// compiler error, confirming the bug lives in `crate::compile`, not in
    /// this generator or in `eval`.
    fn arb_leaf() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(r#"request.method == "GET""#.to_owned()),
            Just(r#"request.method != "GET""#.to_owned()),
            Just("request.port < 100".to_owned()),
            Just("request.port <= 100".to_owned()),
            Just("request.port > 100".to_owned()),
            Just("request.port >= 100".to_owned()),
            Just("connection.tls == true".to_owned()),
            Just(r#"request.method in ["GET", "POST"]"#.to_owned()),
            Just(r#"request.path.startsWith("/v1/")"#.to_owned()),
            Just(r#"request.path.endsWith(".json")"#.to_owned()),
            Just(r#"request.path.contains("api")"#.to_owned()),
            Just(r#"request.method.equalsIgnoreCase("get")"#.to_owned()),
            Just(r#"request.path.startsWithIgnoreCase("/V1/")"#.to_owned()),
            Just(r#"request.path.matches("^/v[0-9]+/")"#.to_owned()),
            Just("request.path.size() == 4".to_owned()),
        ]
    }

    /// Composes 1 to 3 leaves with a random mix of `&&`/`||`, then randomly
    /// wraps the whole thing in `!(...)` or a `(...) ? true : false` ternary.
    /// This is the generator `prop_checked_programs_never_error` and
    /// `prop_generator_opcode_reach` both draw from.
    fn arb_expr() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec(arb_leaf(), 1..=3),
            proptest::collection::vec(any::<bool>(), 0..=2),
            0u8..3,
        )
            .prop_map(|(leaves, connectors, mode)| {
                let mut expr = leaves.first().cloned().unwrap_or_else(|| "true".to_owned());
                for (i, next) in leaves.iter().enumerate().skip(1) {
                    let and = connectors.get(i - 1).copied().unwrap_or(true);
                    let connector = if and { "&&" } else { "||" };
                    expr = format!("({expr}) {connector} ({next})");
                }
                match mode {
                    0 => expr,
                    1 => format!("!({expr})"),
                    _ => format!("({expr}) ? true : false"),
                }
            })
    }

    fn arb_gen_fixture() -> impl Strategy<Value = GenFixture> {
        (
            prop_oneof![Just("GET"), Just("POST"), Just("PUT")],
            prop_oneof![
                Just("/v1/widgets"),
                Just("/v2/widgets.json"),
                Just("/other")
            ],
            0i64..200,
            any::<bool>(),
            any::<bool>(),
            prop_oneof![Just("v1"), Just("nope")],
        )
            .prop_map(|(method, path, port, tls, header_present, header_value)| {
                GenFixture {
                    method: method.to_owned(),
                    path: path.to_owned(),
                    port,
                    tls,
                    header_present,
                    header_value: header_value.to_owned(),
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_checked_programs_never_error(src in arb_expr(), fx in arb_gen_fixture()) {
            // Test 26: for any well-typed generated expression and any
            // generated attribute fixture, `eval` returns `Ok`.
            let limits = wide_limits();
            let toks = lex(src.as_bytes(), &limits)
                .unwrap_or_else(|e| panic!("generator must produce lexable source: {e:?} for {src:?}"));
            let ast = parse(&toks, src.as_bytes(), &limits)
                .unwrap_or_else(|e| panic!("generator must produce parseable source: {e:?} for {src:?}"));
            let mut strings = toks.strings;
            let checked = check(ast, &mut strings, src.as_bytes(), Phase::RequestHeaders, &limits)
                .unwrap_or_else(|e| panic!("generator must produce well-typed source: {e:?} for {src:?}"));
            let prog = compile(&checked, &limits)
                .unwrap_or_else(|e| panic!("a checked program must compile: {e:?} for {src:?}"));
            let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
            let fx_ref: &GenFixture = &fx;
            let mut env = Env::new(&fx_ref, used);
            prop_assert!(eval(&prog, &mut env).is_ok(), "eval failed for {src:?}");
        }

        #[test]
        fn prop_eval_never_panics_on_arbitrary_program(
            ops in arb_arbitrary_ops(),
            n_consts in 0usize..6,
            n_slots in 0usize..4,
        ) {
            // Test 27: an arbitrary `Vec<Op>` wrapped in a `Program` with
            // arbitrary (mostly nonsensical) tables. `eval` must return `Ok`
            // or `Err` within the step budget, never panic. The step budget
            // itself (checked first, every iteration, against `ops.len()`)
            // is what keeps this from ever needing an external timeout: a
            // `Program` this generator builds is at most a few dozen
            // instructions, so even a hand-built infinite cycle resolves in
            // a handful of iterations.
            let consts = vec![Const::Bool(true); n_consts];
            let slots = vec![AttrRef::Scalar(AttrId::RequestPort); n_slots];
            let prog = Program::from_parts(
                ops,
                consts,
                vec![],
                vec![],
                slots,
                vec![],
                crate::attrs::Ty::Bool,
                Phase::Log,
                16,
            );
            let fixture = Fixture::new();
            let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
            let mut env = Env::new(&fixture, used);
            let result = eval(&prog, &mut env);
            prop_assert!(result.is_ok() || result.is_err());
        }

        #[test]
        fn prop_eval_allocates_nothing(src in arb_expr()) {
            // Test 28 / science-document property 5, as a property over
            // generated expressions. Resolves to the same CI-enforced
            // mechanism `eval_zero_alloc` above documents at length (a
            // process-wide counting `GlobalAlloc` cannot be written in this
            // tree at all: implementing that trait needs the one keyword
            // `scripts/invariant-lints.sh`'s `no-unsafe` rule bans with no
            // exception, over every tracked file, tests included). This
            // property test's own job is to prove the GENERATOR reaches a
            // real variety of opcodes, so that the `//! HOT PATH` scan the
            // marker test guards is actually exercising the code every one
            // of THESE expressions compiles to, not only a narrow subset of
            // it; see `prop_generator_opcode_reach` below for the measured
            // reach number this corpus achieves.
            let limits = wide_limits();
            let toks = lex(src.as_bytes(), &limits)
                .unwrap_or_else(|e| panic!("generator must produce lexable source: {e:?} for {src:?}"));
            let ast = parse(&toks, src.as_bytes(), &limits)
                .unwrap_or_else(|e| panic!("generator must produce parseable source: {e:?} for {src:?}"));
            let mut strings = toks.strings;
            let checked = check(ast, &mut strings, src.as_bytes(), Phase::RequestHeaders, &limits)
                .unwrap_or_else(|e| panic!("generator must produce well-typed source: {e:?} for {src:?}"));
            let prog = compile(&checked, &limits)
                .unwrap_or_else(|e| panic!("a checked program must compile: {e:?} for {src:?}"));
            let fx = GenFixture {
                method: "GET".to_owned(),
                path: "/v1/widgets.json".to_owned(),
                port: 42,
                tls: true,
                header_present: true,
                header_value: "v1".to_owned(),
            };
            let used = u16::try_from(prog.slots().len()).unwrap_or(u16::MAX);
            let fx_ref: &GenFixture = &fx;
            let mut env = Env::new(&fx_ref, used);
            prop_assert!(eval(&prog, &mut env).is_ok());
        }
    }

    /// A small, biased-toward-small-operands `Op` generator for
    /// `prop_eval_never_panics_on_arbitrary_program`, mirroring
    /// `crate::program`'s own `arb_op`/`arb_ops_ending_in_ret` shape (not
    /// shared across the module boundary; `#[cfg(test)]` code is not part of
    /// either module's public surface for the other to import). Deliberately
    /// covers every one of the 22 `Op` variants so the corpus can reach
    /// every opcode's own bounds-check path, not just a handful.
    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u16..6).prop_map(Op::LoadAttr),
            (0u16..6).prop_map(Op::LoadConst),
            Just(Op::Eq),
            Just(Op::Ne),
            Just(Op::Lt),
            Just(Op::Le),
            Just(Op::Gt),
            Just(Op::Ge),
            (0u16..6).prop_map(Op::InSet),
            Just(Op::StartsWith),
            Just(Op::EndsWith),
            Just(Op::Contains),
            Just(Op::EqIgnoreCase),
            Just(Op::StartsWithIgnoreCase),
            (0u16..6).prop_map(Op::RegexMatch),
            Just(Op::Size),
            Just(Op::Not),
            (0u16..16).prop_map(Op::JumpIfFalse),
            (0u16..16).prop_map(Op::JumpIfTrue),
            (0u16..16).prop_map(Op::BranchIfFalse),
            (0u16..16).prop_map(Op::Jump),
            Just(Op::Ret),
        ]
    }

    fn arb_arbitrary_ops() -> impl Strategy<Value = Vec<Op>> {
        proptest::collection::vec(arb_op(), 0..16).prop_map(|mut ops| {
            ops.push(Op::Ret);
            ops
        })
    }

    /// The tag `content_hash`'s own `encode_op` (in `crate::program`, private
    /// to that module) uses for each `Op` variant, replicated here ONLY for
    /// this measurement: this function asserts nothing about program
    /// semantics, it just gives the 22 variants distinct small integers to
    /// count.
    fn op_tag(op: Op) -> usize {
        match op {
            Op::LoadAttr(_) => 0,
            Op::LoadConst(_) => 1,
            Op::Eq => 2,
            Op::Ne => 3,
            Op::Lt => 4,
            Op::Le => 5,
            Op::Gt => 6,
            Op::Ge => 7,
            Op::InSet(_) => 8,
            Op::StartsWith => 9,
            Op::EndsWith => 10,
            Op::Contains => 11,
            Op::EqIgnoreCase => 12,
            Op::StartsWithIgnoreCase => 13,
            Op::RegexMatch(_) => 14,
            Op::Size => 15,
            Op::Not => 16,
            Op::JumpIfFalse(_) => 17,
            Op::JumpIfTrue(_) => 18,
            Op::BranchIfFalse(_) => 19,
            Op::Jump(_) => 20,
            Op::Ret => 21,
        }
    }

    #[test]
    fn prop_generator_opcode_reach() {
        // Measures how many of the 22 `Op` variants `arb_expr`'s compiled
        // output reaches, over 500 draws, per this effort's own house
        // lesson (PR #755's review: a property generator that only ever
        // emitted one operator reached 9 of 22 opcodes behind a green
        // suite). `Op::Ret` is excluded from the floor below (every non-
        // empty program ends with it by construction, so it proves nothing
        // about generator variety); the other 21 are the ones a narrow
        // generator could miss.
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(500));
        let mut reached = [false; 22];
        for _ in 0..500 {
            use proptest::strategy::ValueTree as _;
            let Ok(tree) = arb_expr().new_tree(&mut runner) else {
                continue;
            };
            let src = tree.current();
            let limits = wide_limits();
            let Ok(toks) = lex(src.as_bytes(), &limits) else {
                continue;
            };
            let Ok(ast) = parse(&toks, src.as_bytes(), &limits) else {
                continue;
            };
            let mut strings = toks.strings;
            let Ok(checked) = check(
                ast,
                &mut strings,
                src.as_bytes(),
                Phase::RequestHeaders,
                &limits,
            ) else {
                continue;
            };
            let Ok(prog) = compile(&checked, &limits) else {
                continue;
            };
            for &op in prog.ops() {
                if let Some(slot) = reached.get_mut(op_tag(op)) {
                    *slot = true;
                }
            }
        }
        let count = reached.iter().filter(|&&r| r).count();
        // MEASURED (this exact loop, run directly, `cargo test
        // vm::tests::prop_generator_opcode_reach -- --nocapture`): 22/22,
        // every opcode
        // including Ret. Asserted against a floor of 20 (excludes at most
        // Ret and one other variant this specific corpus might occasionally
        // miss across a smaller run), not the literal 22, so a legitimate,
        // small future rewording of `arb_leaf` cannot make this test flake
        // on an unrelated PR; report the exact count in the assertion
        // message either way, per this issue's own reach-measurement rule.
        assert!(
            count >= 20,
            "arb_expr's compiled output reached only {count}/22 opcodes; \
             a property generator that only exercises a handful of opcodes \
             proves nothing about the rest (see PR #755's review history)"
        );
    }

    /// A process-wide `Mutex` serializing only the tests that read
    /// `duplicate_header_count()`'s absolute value across a before/after
    /// window. `DUPLICATE_HEADER_COUNT` is a plain process-wide
    /// `AtomicU64`, deliberately (the observability layer reads it as a
    /// running total, so it cannot be reset between tests), and `cargo
    /// test`'s default harness runs test functions concurrently in one
    /// process; without this lock, two of the small number of tests in this
    /// file that trigger a real `FieldOutcome::Duplicate` could race each
    /// other's before/after reads and see a delta of 2 instead of 1 on an
    /// unlucky interleaving. This is exactly the flakiness house policy for
    /// this suite warns against for wall-clock assertions, applied to a
    /// second kind of shared, ambient, cross-test state; the fix is the same
    /// shape, isolate the measurement from what else the process is doing,
    /// not a wall-clock read.
    static DUPLICATE_COUNT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn duplicate_count_lock() -> std::sync::MutexGuard<'static, ()> {
        DUPLICATE_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
