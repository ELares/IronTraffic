// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compiled ITPL artifact: a flat forward-jump-only bytecode array, an interned
//! constant table, and a verifier that proves the array can never loop.
//!
//! This module is self-contained: `Op`, `Const`, `Program` and `verify` carry no
//! dependency on `crate::compile`. `verify` is what proves a compiled program is
//! total, and it is also what the fuzz target in
//! `{{itpl-differential-oracle-and-fuzz}}` attacks with hand-built, adversarial
//! bytecode, so it never trusts that its input came from `crate::compile`.

use crate::attrs::Ty;
use crate::check::AttrRef;
use crate::limits::PolicyLimits;
use crate::token::Span;
use irontraffic_filter::Phase;

/// One bytecode instruction. Four bytes: a one-byte discriminant and a `u16`
/// operand, with one byte of padding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// Push the value of attribute slot `n`, resolving it on first touch.
    LoadAttr(u16),
    /// Push constant `n`.
    LoadConst(u16),
    /// Pop two, push `a == b`. `Null` equals only `Null`.
    Eq,
    /// Pop two, push `a != b`.
    Ne,
    /// Pop two ints, push `a < b`.
    Lt,
    /// Pop two ints, push `a <= b`.
    Le,
    /// Pop two ints, push `a > b`.
    Gt,
    /// Pop two ints, push `a >= b`.
    Ge,
    /// Pop one, push whether it is a member of constant list `n`.
    InSet(u16),
    /// Pop two strings, push whether `a` starts with `b`.
    StartsWith,
    /// Pop two strings, push whether `a` ends with `b`.
    EndsWith,
    /// Pop two strings, push whether `a` contains `b`.
    Contains,
    /// Pop two strings, push ASCII case-insensitive equality.
    EqIgnoreCase,
    /// Pop two strings, push ASCII case-insensitive prefix.
    StartsWithIgnoreCase,
    /// Pop one string, push whether it matches compiled regex `n`.
    RegexMatch(u16),
    /// Pop one string or list, push its length as an int.
    Size,
    /// Pop one bool, push its negation.
    Not,
    /// Peek the top. When it is false, jump to `n` leaving it. Otherwise pop and
    /// continue. This is `&&`.
    JumpIfFalse(u16),
    /// Peek the top. When it is true, jump to `n` leaving it. Otherwise pop and
    /// continue. This is `||`.
    JumpIfTrue(u16),
    /// Pop one bool. When it is false, jump to `n`. This is the ternary.
    BranchIfFalse(u16),
    /// Jump to `n` unconditionally. Always forward.
    Jump(u16),
    /// Stop. The top of stack is the result.
    Ret,
}

const _: () = assert!(core::mem::size_of::<Op>() == 4);

/// A compile-time constant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Const {
    /// A boolean literal.
    Bool(bool),
    /// An integer literal.
    Int(i64),
    /// A byte string, as a range into `Program::strings`.
    Str {
        /// Start offset into `Program::strings`.
        from: u32,
        /// Length in bytes.
        len: u32,
    },
    /// The `null` literal.
    Null,
    /// A homogeneous list, as a range into `Program::list_elems`.
    List {
        /// Start offset into `Program::list_elems`.
        from: u32,
        /// Number of elements.
        len: u32,
    },
}

/// A verified, executable ITPL program. Immutable, shared by every worker through
/// the configuration snapshot.
#[derive(Debug)]
pub struct Program {
    /// Instructions in execution order.
    ops: Box<[Op]>,
    /// Interned constants.
    consts: Box<[Const]>,
    /// Elements of every list constant, flattened.
    list_elems: Box<[Const]>,
    /// Decoded bytes every `Const::Str` indexes.
    strings: Box<[u8]>,
    /// Attribute references, indexed by `Op::LoadAttr`.
    slots: Box<[AttrRef]>,
    /// Compiled regexes, indexed by `Op::RegexMatch`.
    regexes: Box<[regex::bytes::Regex]>,
    /// Static type of the result.
    result: Ty,
    /// Phase this program is bound to.
    phase: Phase,
    /// Maximum operand-stack depth, computed at verification.
    max_stack: u8,
}

/// Why a hand-built or fuzzed bytecode array is not a valid program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyError {
    /// A jump target at or before the jumping instruction. This is the check that
    /// makes evaluation total.
    BackwardJump {
        /// Index of the jumping instruction.
        at: u16,
        /// The target it named.
        target: u16,
    },
    /// A jump target past the end of the program.
    JumpOutOfRange {
        /// Index of the jumping instruction.
        at: u16,
        /// The target it named.
        target: u16,
        /// Number of instructions in the program.
        len: u16,
    },
    /// An operand index outside the constant, slot or regex table.
    OperandOutOfRange {
        /// Index of the offending instruction.
        at: u16,
        /// The operand it named.
        operand: u16,
    },
    /// The program does not end with `Ret`.
    MissingRet,
    /// The operand stack would underflow.
    StackUnderflow {
        /// Index of the offending instruction.
        at: u16,
    },
    /// The operand stack would exceed `Program::MAX_STACK`.
    StackOverflow {
        /// Index of the offending instruction.
        at: u16,
        /// `Program::MAX_STACK`.
        max: u8,
    },
    /// More than one value on the stack at `Ret`.
    StackNotSingleton {
        /// Index of the `Ret` instruction, or of the instruction where two paths
        /// merged at different depths.
        at: u16,
        /// The conflicting depth, clamped to `u8`.
        depth: u8,
    },
    /// More instructions than `PolicyLimits::max_ops`.
    TooManyOps {
        /// The actual instruction count.
        len: usize,
        /// The configured limit.
        max: u16,
    },
}

/// Converts a `usize` index into a `u16` for an error field, saturating rather
/// than panicking. Every real call site is already bounded by `ops.len()`,
/// which `verify` itself caps below `u16::MAX` via `TooManyOps` before this is
/// ever reached, so the saturation never actually triggers; it exists so this
/// stays total under `-D warnings`' `clippy::indexing_slicing`-adjacent casting
/// rules without an `unwrap`.
fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Clamps a signed depth into `0..=255` and converts, total and panic-free.
fn clamp_u8(d: i16) -> u8 {
    u8::try_from(d.clamp(0, 255)).unwrap_or(255)
}

/// `(pops, pushes)` for one instruction. `JumpIfFalse` and `JumpIfTrue` report
/// their FALL-THROUGH effect only; the taken-branch depth is `depth_after_jump`.
fn effect(op: Op) -> (i16, i16) {
    match op {
        Op::LoadAttr(_) | Op::LoadConst(_) => (0, 1),
        Op::Not | Op::Size | Op::RegexMatch(_) | Op::InSet(_) => (1, 1),
        Op::Eq
        | Op::Ne
        | Op::Lt
        | Op::Le
        | Op::Gt
        | Op::Ge
        | Op::StartsWith
        | Op::EndsWith
        | Op::Contains
        | Op::EqIgnoreCase
        | Op::StartsWithIgnoreCase => (2, 1),
        // `BranchIfFalse`'s fall-through pops the tested bool (the ternary's
        // `cond`); `JumpIfFalse`/`JumpIfTrue`'s fall-through pops it too
        // (`&&`/`||` continuing to evaluate their right operand). Both are
        // `(1, 0)` for this reason, not by coincidence, so they share one arm.
        Op::BranchIfFalse(_) | Op::JumpIfFalse(_) | Op::JumpIfTrue(_) => (1, 0),
        Op::Jump(_) | Op::Ret => (0, 0),
    }
}

/// Depth on the TAKEN branch. `JumpIfFalse` and `JumpIfTrue` leave the tested value
/// on the stack when they jump, and `Jump` carries the depth through unchanged, so
/// every jump op except `BranchIfFalse` (which pops on every path, taken or not)
/// leaves the depth exactly as it entered.
fn depth_after_jump(op: Op, d: i16) -> i16 {
    match op {
        Op::BranchIfFalse(_) => d - 1,
        _ => d,
    }
}

/// Records the stack depth on entry to instruction `at`. Returns an error when a
/// second path reaches it at a different depth, which cannot happen for
/// compiler-generated code and can happen for a fuzzed program.
fn merge(depth: &mut [i16], at: usize, incoming: i16) -> Result<(), VerifyError> {
    let Some(slot) = depth.get_mut(at) else {
        // `at` is always a validated index by the time `merge` is called: a
        // jump target is checked against `ops.len()` immediately above this
        // call, and `i + 1` is never `ops.len()` for the non `Ret`, non jump
        // instructions that reach the other call site, because the
        // `MissingRet` check at the top of `verify` guarantees `ops`'s LAST
        // element is `Op::Ret`, which never takes this path. Kept as a
        // total, panic-free fallback rather than trusting that argument at
        // runtime, the same style `check::assemble_path` uses for its own
        // analogous, structurally guaranteed precondition.
        return Ok(());
    };
    if *slot < 0 {
        *slot = incoming;
        Ok(())
    } else if *slot == incoming {
        Ok(())
    } else {
        Err(VerifyError::StackNotSingleton {
            at: to_u16(at),
            depth: clamp_u8(incoming),
        })
    }
}

/// Checks one instruction's operand against the table it names, or
/// `OperandOutOfRange`. `InSet(n)` additionally requires `consts[n]` to be a
/// `Const::List`, per invariant 4: a hand-built `InSet` naming a non-list
/// constant is exactly this error, never a panic when the evaluator later
/// reads it.
fn check_operand(
    op: Op,
    at: usize,
    consts: &[Const],
    slots: &[AttrRef],
    regexes: usize,
) -> Result<(), VerifyError> {
    let bad = |operand: u16| VerifyError::OperandOutOfRange {
        at: to_u16(at),
        operand,
    };
    match op {
        Op::LoadConst(n) => {
            if consts.get(usize::from(n)).is_none() {
                return Err(bad(n));
            }
        }
        Op::LoadAttr(n) => {
            if slots.get(usize::from(n)).is_none() {
                return Err(bad(n));
            }
        }
        Op::RegexMatch(n) => {
            if usize::from(n) >= regexes {
                return Err(bad(n));
            }
        }
        Op::InSet(n) => {
            if !matches!(consts.get(usize::from(n)), Some(Const::List { .. })) {
                return Err(bad(n));
            }
        }
        Op::Eq
        | Op::Ne
        | Op::Lt
        | Op::Le
        | Op::Gt
        | Op::Ge
        | Op::StartsWith
        | Op::EndsWith
        | Op::Contains
        | Op::EqIgnoreCase
        | Op::StartsWithIgnoreCase
        | Op::Size
        | Op::Not
        | Op::JumpIfFalse(_)
        | Op::JumpIfTrue(_)
        | Op::BranchIfFalse(_)
        | Op::Jump(_)
        | Op::Ret => {}
    }
    Ok(())
}

/// Verifies a bytecode array against its tables.
///
/// Returns the maximum operand-stack depth.
///
/// # Errors
/// Every `VerifyError` variant.
pub fn verify(
    ops: &[Op],
    consts: &[Const],
    slots: &[AttrRef],
    regexes: usize,
    limits: &PolicyLimits,
) -> Result<u8, VerifyError> {
    let len = ops.len();
    if len > usize::from(limits.max_ops) {
        return Err(VerifyError::TooManyOps {
            len,
            max: limits.max_ops,
        });
    }
    if ops.last() != Some(&Op::Ret) {
        return Err(VerifyError::MissingRet);
    }

    // `len >= 1` here: an empty `ops` has `ops.last() == None`, which the
    // `MissingRet` check above already rejected.
    let mut depth: Vec<i16> = vec![-1; len];
    if let Some(first) = depth.get_mut(0) {
        *first = 0;
    }

    for (i, op) in ops.iter().copied().enumerate() {
        let Some(&d) = depth.get(i) else { continue };
        if d < 0 {
            // Unreachable instruction: no path reaches it, so it never
            // executes and is not checked. Edge case 22.
            continue;
        }

        check_operand(op, i, consts, slots, regexes)?;

        let (pops, pushes) = effect(op);
        if d < pops {
            return Err(VerifyError::StackUnderflow { at: to_u16(i) });
        }
        let next = d - pops + pushes;
        if next > i16::from(Program::MAX_STACK) {
            return Err(VerifyError::StackOverflow {
                at: to_u16(i),
                max: Program::MAX_STACK,
            });
        }

        match op {
            Op::Ret => {
                if d != 1 {
                    return Err(VerifyError::StackNotSingleton {
                        at: to_u16(i),
                        depth: clamp_u8(d),
                    });
                }
            }
            Op::Jump(t) | Op::JumpIfFalse(t) | Op::JumpIfTrue(t) | Op::BranchIfFalse(t) => {
                let target = usize::from(t);
                // The totality check: this is the single most important
                // line in this crate. A jump target at or before the
                // jumping instruction would make the instruction pointer
                // non-monotonic, which is what a loop is.
                if target <= i {
                    return Err(VerifyError::BackwardJump {
                        at: to_u16(i),
                        target: t,
                    });
                }
                if target >= len {
                    return Err(VerifyError::JumpOutOfRange {
                        at: to_u16(i),
                        target: t,
                        len: to_u16(len),
                    });
                }
                merge(&mut depth, target, depth_after_jump(op, d))?;
                if !matches!(op, Op::Jump(_)) {
                    merge(&mut depth, i.saturating_add(1), next)?;
                }
            }
            _ => {
                merge(&mut depth, i.saturating_add(1), next)?;
            }
        }
    }

    Ok(depth
        .into_iter()
        .filter(|&d| d >= 0)
        .max()
        .map_or(0, clamp_u8))
}

/// Resolves a `(from, len)` range into `buf`, or an empty slice when the range is
/// invalid. Shared by every `u32`-range accessor in this module.
fn slice_range(buf: &[u8], from: u32, len: u32) -> &[u8] {
    let start = usize::try_from(from).unwrap_or(usize::MAX);
    let want = usize::try_from(len).unwrap_or(usize::MAX);
    let end = start.saturating_add(want);
    buf.get(start..end).unwrap_or(&[])
}

/// Resolves a `(from, len)` range into a `Const` slice, or an empty slice when the
/// range is invalid.
fn const_range(buf: &[Const], from: u32, len: u32) -> &[Const] {
    let start = usize::try_from(from).unwrap_or(usize::MAX);
    let want = usize::try_from(len).unwrap_or(usize::MAX);
    let end = start.saturating_add(want);
    buf.get(start..end).unwrap_or(&[])
}

/// FNV-1a offset basis, per `Program::content_hash`'s contract.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime, per `Program::content_hash`'s contract.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Feeds `bytes` into a running FNV-1a hash, one byte at a time.
fn fnv1a(hash: u64, bytes: &[u8]) -> u64 {
    let mut h = hash;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Feeds `bytes`' own length (four little-endian bytes), then `bytes` itself.
/// This is what keeps two adjacent variable-length items from hashing the same
/// as a different split of the same total bytes.
fn fnv1a_len_prefixed(hash: u64, bytes: &[u8]) -> u64 {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    fnv1a(fnv1a(hash, &len.to_le_bytes()), bytes)
}

/// Canonical, hand-defined 4-byte encoding for one `Op`, used only by
/// `content_hash`. This is deliberately NOT a memory transmute of `Op`'s actual
/// layout: `content_hash`'s own contract is that it is "compared across config
/// generations and across processes," and Rust's automatic enum layout (which
/// only promises `size_of::<Op>() == 4`, asserted above, never a specific byte
/// order) is not part of any stability guarantee this crate makes. A stable
/// hash needs a stable, explicitly written encoding independent of however the
/// compiler happens to lay the enum out today.
fn encode_op(op: Op) -> [u8; 4] {
    let (tag, operand): (u8, u16) = match op {
        Op::LoadAttr(n) => (0, n),
        Op::LoadConst(n) => (1, n),
        Op::Eq => (2, 0),
        Op::Ne => (3, 0),
        Op::Lt => (4, 0),
        Op::Le => (5, 0),
        Op::Gt => (6, 0),
        Op::Ge => (7, 0),
        Op::InSet(n) => (8, n),
        Op::StartsWith => (9, 0),
        Op::EndsWith => (10, 0),
        Op::Contains => (11, 0),
        Op::EqIgnoreCase => (12, 0),
        Op::StartsWithIgnoreCase => (13, 0),
        Op::RegexMatch(n) => (14, n),
        Op::Size => (15, 0),
        Op::Not => (16, 0),
        Op::JumpIfFalse(n) => (17, n),
        Op::JumpIfTrue(n) => (18, n),
        Op::BranchIfFalse(n) => (19, n),
        Op::Jump(n) => (20, n),
        Op::Ret => (21, 0),
    };
    let o = operand.to_le_bytes();
    [tag, o[0], o[1], 0]
}

impl Program {
    /// Maximum operand-stack depth. 16, which matches `PolicyLimits::max_depth` and
    /// lets the evaluator use a fixed array.
    /// It is the same 16 that `PolicyLimits::validate` caps `max_depth` at, and the
    /// same 16 the evaluator's `[Value; 16]` operand stack is sized to. The three move
    /// together or none of them move.
    pub const MAX_STACK: u8 = 16;

    /// Builds a `Program` from already-verified parts. Crate-private: the only two
    /// callers are `crate::compile::compile`, which just called `verify` on exactly
    /// these `ops`/`consts`/`slots`/`regexes`, and `from_parts` below, which makes no
    /// such promise and is test-only.
    #[allow(
        clippy::too_many_arguments,
        reason = "one field per Program field, matching from_parts's public shape below exactly; a builder would be a second, parallel way to construct the same nine-field struct for no reduction in real complexity"
    )]
    pub(crate) fn new(
        ops: Box<[Op]>,
        consts: Box<[Const]>,
        list_elems: Box<[Const]>,
        strings: Box<[u8]>,
        slots: Box<[AttrRef]>,
        regexes: Box<[regex::bytes::Regex]>,
        result: Ty,
        phase: Phase,
        max_stack: u8,
    ) -> Program {
        Program {
            ops,
            consts,
            list_elems,
            strings,
            slots,
            regexes,
            result,
            phase,
            max_stack,
        }
    }

    /// Instructions, for the explain surface and the differential oracle.
    #[must_use]
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Constants.
    #[must_use]
    pub fn consts(&self) -> &[Const] {
        &self.consts
    }

    /// Attribute references, in slot order.
    #[must_use]
    pub fn slots(&self) -> &[AttrRef] {
        &self.slots
    }

    /// The static result type.
    #[must_use]
    pub fn result_ty(&self) -> Ty {
        self.result
    }

    /// The phase this program is bound to.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Maximum operand-stack depth this program reaches.
    #[must_use]
    pub fn max_stack(&self) -> u8 {
        self.max_stack
    }

    /// The bytes a `Const::Str` names, or an empty slice when the range is invalid.
    #[must_use]
    pub fn const_str(&self, c: &Const) -> &[u8] {
        match *c {
            Const::Str { from, len } => slice_range(&self.strings, from, len),
            _ => &[],
        }
    }

    /// Compiled regex `n`, or `None` when the index is outside the table. The
    /// evaluator needs this and `regexes` is private, so it is an accessor rather
    /// than a field.
    #[must_use]
    pub fn regex(&self, n: u16) -> Option<&regex::bytes::Regex> {
        self.regexes.get(usize::from(n))
    }

    /// The bytes an `AttrRef::Field` key names inside `strings`, or an empty slice
    /// when the range is invalid. Used by `Env::slot` to hand a canonical header
    /// name to `AttrSource::field`.
    #[must_use]
    pub fn key_bytes(&self, key: Span) -> &[u8] {
        key.slice(&self.strings).unwrap_or(&[])
    }

    /// The elements of the `Const::List` at constant index `n`, or `None` when `n`
    /// is out of range or names a constant that is not a list. `Op::InSet(n)` reads
    /// this; returning `None` is what makes an `InSet` naming a non-list a clean
    /// `BadOperand` instead of a panic.
    #[must_use]
    pub fn list_of(&self, n: u16) -> Option<&[Const]> {
        match self.consts.get(usize::from(n))? {
            Const::List { from, len } => Some(const_range(&self.list_elems, *from, *len)),
            _ => None,
        }
    }

    /// Number of compiled regexes, for the verifier and the fuzz harness.
    #[must_use]
    pub fn regex_count(&self) -> usize {
        self.regexes.len()
    }

    /// Builds a `Program` from raw, UNVERIFIED parts.
    ///
    /// Test-only, because it is the one way to construct a `Program` that `compile`
    /// would never produce, which is exactly what `verify`'s unit tests and
    /// `{{itpl-differential-oracle-and-fuzz}}`'s `fuzz_itpl_verify_eval` target need.
    /// It performs no checking at all: the caller is asserting something about what
    /// happens to a malformed program.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "this is the issue's specified public shape, one argument per Program field, so a caller can build any combination a real compile could never produce"
    )]
    pub fn from_parts(
        ops: Vec<Op>,
        consts: Vec<Const>,
        list_elems: Vec<Const>,
        strings: Vec<u8>,
        slots: Vec<AttrRef>,
        regexes: Vec<regex::bytes::Regex>,
        result: Ty,
        phase: Phase,
        max_stack: u8,
    ) -> Program {
        Program::new(
            ops.into_boxed_slice(),
            consts.into_boxed_slice(),
            list_elems.into_boxed_slice(),
            strings.into_boxed_slice(),
            slots.into_boxed_slice(),
            regexes.into_boxed_slice(),
            result,
            phase,
            max_stack,
        )
    }

    /// A stable content hash, so identical programs are interned by the config
    /// compiler exactly as identical chains are.
    ///
    /// 64-bit FNV-1a (offset basis `0xcbf2_9ce4_8422_2325`, prime
    /// `0x0000_0100_0000_01b3`), fed in this exact order, every variable-length item
    /// preceded by its length as four little-endian bytes:
    /// `ops` as its raw 4-byte-per-instruction encoding; `strings`; each `Const` as
    /// one discriminant byte followed by its payload (`Bool` one byte, `Int` eight
    /// little-endian bytes, `Str` the bytes it names, `Null` nothing, `List` its
    /// element count then each element encoded the same way); each `AttrRef` as one
    /// discriminant byte plus either the `AttrId` byte or the `MapId` byte and the
    /// key bytes; each regex's pattern as `Regex::as_str().as_bytes()`; then
    /// `result`'s discriminant byte and `phase.index()`'s dense index byte.
    ///
    /// Do not use `DefaultHasher`, `RandomState` or `ahash`: this value is compared
    /// across config generations and across processes. Feed `Const::Str` and
    /// `AttrRef::Field` by their BYTES, never by their `from`/`len` ranges, for the
    /// same reason chain interning hashes filter names by bytes.
    ///
    /// Like `CompiledChain::config_hash`, this is a lookup accelerator and NOT a
    /// proof of identity. FNV-1a is unkeyed and not collision resistant, and policy
    /// source can come from a tenant-writable resource, so any table that interns
    /// programs by this value MUST compare the full canonical encoding before it
    /// shares a `Program`. Two policies that collide and are treated as one means one
    /// tenant's route evaluates another tenant's predicate.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        let mut h = FNV_OFFSET;

        let mut op_bytes = Vec::with_capacity(self.ops.len().saturating_mul(4));
        for &op in &self.ops {
            op_bytes.extend_from_slice(&encode_op(op));
        }
        h = fnv1a_len_prefixed(h, &op_bytes);
        h = fnv1a_len_prefixed(h, &self.strings);

        for c in &self.consts {
            h = self.hash_const(h, c);
        }
        for r in &self.slots {
            h = hash_attr_ref(h, *r, &self.strings);
        }
        for r in &self.regexes {
            h = fnv1a_len_prefixed(h, r.as_str().as_bytes());
        }

        // `Ty` and `Phase` are both `#[repr(u8)]` fieldless enums (`Phase`'s
        // `index()` is its own dense `0..10` discriminant), so this cast is
        // exact for every value either type can hold.
        h = fnv1a(h, &[self.result as u8]); // it-allow: unchecked-cast reason: Ty is repr(u8); this reads the existing discriminant byte rather than truncating a wider value
        let phase_byte = u8::try_from(self.phase.index()).unwrap_or(0);
        fnv1a(h, &[phase_byte])
    }

    /// Feeds one `Const` (and, recursively, a `List`'s elements) into `h`.
    fn hash_const(&self, h: u64, c: &Const) -> u64 {
        match *c {
            Const::Bool(b) => fnv1a(fnv1a(h, &[0]), &[u8::from(b)]),
            Const::Int(v) => fnv1a(fnv1a(h, &[1]), &v.to_le_bytes()),
            Const::Str { .. } => fnv1a_len_prefixed(fnv1a(h, &[2]), self.const_str(c)),
            Const::Null => fnv1a(h, &[3]),
            Const::List { from, len } => {
                let mut acc = fnv1a(h, &[4]);
                acc = fnv1a(acc, &len.to_le_bytes());
                for elem in const_range(&self.list_elems, from, len) {
                    acc = self.hash_const(acc, elem);
                }
                acc
            }
        }
    }
}

/// Feeds one `AttrRef` into `h`. A free function (not a `Program` method) because
/// `content_hash` calls it before `self.strings` and `self.slots` are otherwise
/// entangled; it takes the string arena directly instead.
fn hash_attr_ref(h: u64, r: AttrRef, strings: &[u8]) -> u64 {
    match r {
        AttrRef::Scalar(id) => {
            // `AttrId` is `#[repr(u8)]`; see `content_hash`'s own note on `Ty`.
            fnv1a(fnv1a(h, &[0]), &[id as u8]) // it-allow: unchecked-cast reason: AttrId is repr(u8); this reads the existing discriminant byte rather than truncating a wider value
        }
        AttrRef::Field { map, key } => {
            let acc = fnv1a(h, &[1]);
            // `MapId` is `#[repr(u8)]`; see `content_hash`'s own note on `Ty`.
            let acc = fnv1a(acc, &[map as u8]); // it-allow: unchecked-cast reason: MapId is repr(u8); this reads the existing discriminant byte rather than truncating a wider value
            fnv1a_len_prefixed(acc, key.slice(strings).unwrap_or(&[]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrId;
    use proptest::prelude::*;

    fn limits() -> PolicyLimits {
        PolicyLimits::defaults()
    }

    fn empty_slots() -> Vec<AttrRef> {
        Vec::new()
    }

    // ------------------------------------------------------------------
    // 17-28: hand-built bytecode, calling `verify` directly.
    // ------------------------------------------------------------------

    #[test]
    fn verify_rejects_backward_jump() {
        // Test 17 / edge case 16: a jump whose target is BEFORE the jumping
        // instruction. `Jump(0)` at index 2 targets index 0, which is `<= 2`.
        // The array still ends with `Ret` (a precondition `MissingRet`
        // otherwise reports first, which would prove nothing about the
        // backward-jump check specifically).
        let ops = vec![Op::LoadConst(0), Op::LoadConst(0), Op::Jump(0), Op::Ret];
        let consts = vec![Const::Bool(true)];
        let err = verify(&ops, &consts, &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::BackwardJump { at: 2, target: 0 });
    }

    #[test]
    fn verify_rejects_self_jump() {
        // Test 18: a jump whose target equals its own index (0 <= 0).
        let ops = vec![Op::Jump(0), Op::Ret];
        let err = verify(&ops, &[], &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::BackwardJump { at: 0, target: 0 });
    }

    #[test]
    fn verify_rejects_out_of_range_jump() {
        // Test 19 / edge case 17: a forward jump past the end of the array.
        let ops = vec![Op::Jump(5), Op::Ret];
        let err = verify(&ops, &[], &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(
            err,
            VerifyError::JumpOutOfRange {
                at: 0,
                target: 5,
                len: 2
            }
        );
    }

    #[test]
    fn verify_rejects_missing_ret() {
        // Test 20 / edge case 18: the array does not end with `Ret`.
        let ops = vec![Op::LoadConst(0), Op::LoadConst(0), Op::Eq];
        let consts = vec![Const::Bool(true)];
        let err = verify(&ops, &consts, &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::MissingRet);
    }

    #[test]
    fn verify_rejects_empty_program() {
        // Test 21 / edge case 24: an empty array has no last element, so it is
        // `MissingRet`, not some other error naming index 0.
        let ops: Vec<Op> = Vec::new();
        let err = verify(&ops, &[], &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::MissingRet);
    }

    #[test]
    fn verify_rejects_stack_underflow() {
        // Test 22 / edge case 19: `Eq` on an empty stack.
        let ops = vec![Op::Eq, Op::Ret];
        let err = verify(&ops, &[], &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::StackUnderflow { at: 0 });
    }

    #[test]
    fn verify_rejects_stack_overflow() {
        // Test 23 / edge case 20: pushing 17 values, one past `MAX_STACK`.
        let mut ops = vec![Op::LoadConst(0); 17];
        ops.push(Op::Ret);
        let consts = vec![Const::Bool(true)];
        let err = verify(&ops, &consts, &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(
            err,
            VerifyError::StackOverflow {
                at: 16,
                max: Program::MAX_STACK
            }
        );
    }

    #[test]
    fn verify_rejects_two_values_at_ret() {
        // Test 24 / edge case 21: two live values at `Ret`.
        let ops = vec![Op::LoadConst(0), Op::LoadConst(0), Op::Ret];
        let consts = vec![Const::Bool(true)];
        let err = verify(&ops, &consts, &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::StackNotSingleton { at: 2, depth: 2 });
    }

    #[test]
    fn verify_rejects_operand_out_of_range_load_const() {
        // Test 25, LoadConst case: `consts` has one entry (index 0), so
        // index 3 is out of range.
        let err = verify(
            &[Op::LoadConst(3), Op::Ret],
            &[Const::Bool(true)],
            &empty_slots(),
            0,
            &limits(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::OperandOutOfRange { at: 0, operand: 3 });
    }

    #[test]
    fn verify_rejects_operand_out_of_range_load_attr() {
        // Test 25, LoadAttr case: `slots` is empty, so any index is out of range.
        let err = verify(
            &[Op::LoadAttr(3), Op::Ret],
            &[],
            &empty_slots(),
            0,
            &limits(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::OperandOutOfRange { at: 0, operand: 3 });
    }

    #[test]
    fn verify_rejects_operand_out_of_range_regex_match() {
        // Test 25, RegexMatch case: `regexes` names a table of 1 compiled
        // pattern (index 0), so index 2 is out of range.
        let err = verify(
            &[Op::LoadAttr(0), Op::RegexMatch(2), Op::Ret],
            &[],
            &[AttrRef::Scalar(AttrId::RequestMethod)],
            1,
            &limits(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::OperandOutOfRange { at: 1, operand: 2 });
    }

    #[test]
    fn verify_rejects_operand_out_of_range_in_set_non_list() {
        // Test 25, InSet case: `InSet(0)` names a constant that EXISTS (index
        // 0 is in range) but is not a `Const::List`, per invariant 4. This is
        // the case a plain bounds check would miss: the index is valid, the
        // TYPE at that index is not.
        let err = verify(
            &[Op::LoadConst(0), Op::InSet(0), Op::Ret],
            &[Const::Bool(true)],
            &empty_slots(),
            0,
            &limits(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::OperandOutOfRange { at: 1, operand: 0 });
    }

    #[test]
    fn verify_allows_unreachable_code() {
        // Test 26 / edge case 22: `Jump` past a bogus instruction that would
        // fail every other check (an out-of-range `LoadConst`). It must never
        // execute and must not be checked.
        let ops = vec![
            Op::LoadConst(0),
            Op::Jump(3),
            Op::LoadConst(99), // unreachable; would be OperandOutOfRange if checked
            Op::Ret,
        ];
        let consts = vec![Const::Bool(true)];
        let max_stack = verify(&ops, &consts, &empty_slots(), 0, &limits()).unwrap();
        assert_eq!(max_stack, 1);
    }

    #[test]
    fn verify_rejects_conflicting_depths() {
        // Test 27: two paths reach the same instruction (index 5, the shared
        // `Ret`) at different depths.
        //
        //   0: LoadConst   depth 0 -> next 1
        //   1: JumpIfFalse(5)  depth 1; TAKEN path merges depth 1 into index 5
        //   2: LoadConst   fall-through from 1, depth 0 -> next 1
        //   3: LoadConst   depth 1 -> next 2
        //   4: Jump(5)     depth 2; merges depth 2 into index 5, CONFLICTING
        //                  with the depth 1 index 1 already recorded there
        //   5: Ret
        let ops = vec![
            Op::LoadConst(0),
            Op::JumpIfFalse(5),
            Op::LoadConst(0),
            Op::LoadConst(0),
            Op::Jump(5),
            Op::Ret,
        ];
        let consts = vec![Const::Bool(true)];
        let err = verify(&ops, &consts, &empty_slots(), 0, &limits()).unwrap_err();
        assert_eq!(err, VerifyError::StackNotSingleton { at: 5, depth: 2 });
    }

    #[test]
    fn verify_returns_max_stack() {
        // Test 28: `(a == b) && (c == d)`, hand-computed peak depth 2 (two
        // loads before each `Eq`), never 3 or more since the `&&`'s
        // `JumpIfFalse` sits between the two comparisons.
        let ops = vec![
            Op::LoadAttr(0),
            Op::LoadAttr(0),
            Op::Eq,
            Op::JumpIfFalse(7),
            Op::LoadAttr(0),
            Op::LoadAttr(0),
            Op::Eq,
            Op::Ret,
        ];
        let slots = vec![AttrRef::Scalar(AttrId::RequestPort)];
        let max_stack = verify(&ops, &[], &slots, 0, &limits()).unwrap();
        assert_eq!(max_stack, 2);
    }

    // ------------------------------------------------------------------
    // Property tests.
    // ------------------------------------------------------------------

    /// A small, well-formed generator: builds a RANDOM but VALID stack machine
    /// program by construction (never by fuzzing token soup), so the property
    /// below actually exercises `verify`'s accept path, not just its
    /// total-function guarantee. Chains 1 to 4 comparisons with `&&`, mirroring
    /// `crate::compile`'s own `and_chain_lowering` shape.
    fn arb_and_chain() -> impl Strategy<Value = Vec<Op>> {
        (1usize..=4).prop_map(|n| {
            let mut code = Vec::new();
            let mut holes = Vec::new();
            for k in 0..n {
                if k > 0 {
                    holes.push(code.len());
                    code.push(Op::JumpIfFalse(0));
                }
                code.push(Op::LoadAttr(0));
                code.push(Op::LoadConst(0));
                code.push(Op::Eq);
            }
            code.push(Op::Ret);
            let ret_at = to_u16(code.len() - 1);
            for h in holes {
                if let Some(Op::JumpIfFalse(t)) = code.get_mut(h) {
                    *t = ret_at;
                }
            }
            code
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_compiler_output_always_verifies(ops in arb_and_chain()) {
            // Test 29, using the hand-shaped generator above (this module has
            // no dependency on `crate::compile`, so it cannot call `compile`
            // itself; `compile.rs`'s own `prop_compiler_output_always_verifies`
            // is the one that feeds real compiler output through `verify`).
            let consts = vec![Const::Bool(true)];
            let slots = vec![AttrRef::Scalar(AttrId::RequestPort)];
            let result = verify(&ops, &consts, &slots, 0, &limits());
            prop_assert!(result.is_ok(), "{result:?}");
        }

        #[test]
        fn prop_verified_programs_have_only_forward_jumps(ops in arb_and_chain()) {
            // Test 30: the totality property stated directly. Every jump `verify`
            // accepted must target strictly past its own index.
            let consts = vec![Const::Bool(true)];
            let slots = vec![AttrRef::Scalar(AttrId::RequestPort)];
            if verify(&ops, &consts, &slots, 0, &limits()).is_ok() {
                for (i, op) in ops.iter().enumerate() {
                    if let Op::Jump(t) | Op::JumpIfFalse(t) | Op::JumpIfTrue(t) | Op::BranchIfFalse(t) = *op {
                        prop_assert!(usize::from(t) > i, "jump at {i} targets {t}, not strictly forward");
                    }
                }
            }
        }

        #[test]
        fn prop_verify_never_panics(
            ops in proptest::collection::vec(arb_op(), 0..24),
            n_consts in 0usize..6,
            n_slots in 0usize..4,
            n_regexes in 0usize..3,
        ) {
            // Test 31: arbitrary, mostly-invalid bytecode and tables. `verify`
            // must return `Ok` or `Err`, never panic.
            let consts = vec![Const::Bool(true); n_consts];
            let slots = vec![AttrRef::Scalar(AttrId::RequestPort); n_slots];
            let result = verify(&ops, &consts, &slots, n_regexes, &limits());
            prop_assert!(result.is_ok() || result.is_err());
        }
    }

    /// An arbitrary single `Op`, biased toward small operands so a fair share
    /// land in range against the small tables `prop_verify_never_panics` uses,
    /// without which the fuzz-shaped property would only ever exercise the
    /// immediate `OperandOutOfRange`/`BackwardJump` rejects and never reach a
    /// live `merge` or stack-effect check.
    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u16..8).prop_map(Op::LoadAttr),
            (0u16..8).prop_map(Op::LoadConst),
            Just(Op::Eq),
            Just(Op::Ne),
            Just(Op::Lt),
            Just(Op::Le),
            Just(Op::Gt),
            Just(Op::Ge),
            (0u16..8).prop_map(Op::InSet),
            Just(Op::StartsWith),
            Just(Op::EndsWith),
            Just(Op::Contains),
            Just(Op::EqIgnoreCase),
            Just(Op::StartsWithIgnoreCase),
            (0u16..8).prop_map(Op::RegexMatch),
            Just(Op::Size),
            Just(Op::Not),
            (0u16..24).prop_map(Op::JumpIfFalse),
            (0u16..24).prop_map(Op::JumpIfTrue),
            (0u16..24).prop_map(Op::BranchIfFalse),
            (0u16..24).prop_map(Op::Jump),
            Just(Op::Ret),
        ]
    }

    /// Measures how `prop_verify_never_panics`'s generator lands, per this
    /// crate's own house lesson (#268/#269) that a property test's generator
    /// reach must be measured, never assumed.
    ///
    /// MEASURED (this exact loop, run directly): 0 of 256 draws verify `Ok`.
    /// That is expected, not a defect, and it is the reason
    /// `prop_verify_never_panics` and this measurement are a DIFFERENT
    /// property from `prop_compiler_output_always_verifies` /
    /// `prop_verified_programs_have_only_forward_jumps` above: a fully
    /// uniform `Vec<Op>` of length 0 to 24 has to satisfy several
    /// independent, narrow conditions at once to verify (end in `Ret`,
    /// roughly a 1-in-22 chance on its own, AND have every jump op's target
    /// land strictly forward and in range), so the compound probability is
    /// small enough that 256 draws routinely see zero. That is FINE here:
    /// property 31 is "never panics", which every one of those 256 rejected
    /// draws already exercises by returning `Err` cleanly rather than
    /// panicking, and it does not depend on ever reaching `Ok`. The
    /// generator that DOES need, and has, a measured high accept rate for
    /// the accept-path properties is `arb_and_chain` above, at 100% (traced
    /// and asserted by `prop_compiler_output_always_verifies`, which uses
    /// only well-formed output). Asserting `err` stays high (rather than an
    /// `ok` floor this generator cannot meet) is what would catch this
    /// specific generator drifting to produce mostly `Ok`s instead, which
    /// would be the mirror-image regression: a "never panics" fuzz property
    /// silently degrading into a second, redundant, and less honest copy of
    /// the accept-path property.
    #[test]
    fn prop_generator_reaches_verify_ok() {
        use proptest::strategy::ValueTree as _;

        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
        let strategy = proptest::collection::vec(arb_op(), 0..24);
        let mut ok = 0u32;
        let mut err = 0u32;
        for _ in 0..256 {
            let Ok(tree) = strategy.new_tree(&mut runner) else {
                continue;
            };
            let ops = tree.current();
            let consts = vec![Const::Bool(true); 4];
            let slots = vec![AttrRef::Scalar(AttrId::RequestPort); 2];
            match verify(&ops, &consts, &slots, 2, &limits()) {
                Ok(_) => ok += 1,
                Err(_) => err += 1,
            }
        }
        assert_eq!(ok + err, 256);
        assert!(
            err * 4 >= 256 * 3,
            "expected the large majority of fully arbitrary programs to be \
             rejected (measured 256/256 in development), got {err}/256 \
             rejected ({ok} accepted)"
        );
    }

    // ------------------------------------------------------------------
    // `Program::from_parts` / `content_hash` smoke coverage local to this
    // module (the exhaustive `content_hash` tests live in `compile.rs`,
    // which can build real, varied programs through `compile`).
    // ------------------------------------------------------------------

    #[test]
    fn from_parts_builds_an_unverified_program_directly() {
        let program = Program::from_parts(
            vec![Op::LoadConst(0), Op::Ret],
            vec![Const::Bool(true)],
            vec![],
            vec![],
            vec![],
            vec![],
            Ty::Bool,
            Phase::RequestHeaders,
            1,
        );
        assert_eq!(program.ops(), &[Op::LoadConst(0), Op::Ret]);
        assert_eq!(program.max_stack(), 1);
        assert_eq!(program.result_ty(), Ty::Bool);
        assert_eq!(program.phase(), Phase::RequestHeaders);
    }

    #[test]
    fn list_of_none_for_a_non_list_constant() {
        let program = Program::from_parts(
            vec![Op::Ret],
            vec![Const::Bool(true)],
            vec![],
            vec![],
            vec![],
            vec![],
            Ty::Bool,
            Phase::RequestHeaders,
            0,
        );
        assert_eq!(program.list_of(0), None);
        assert_eq!(program.list_of(5), None);
    }

    /// `content_hash_discriminates` in `compile.rs` builds its two programs
    /// through `compile`, so every one of its cases also differs in the raw
    /// `strings` ARENA (a different source string decodes to different
    /// bytes), which `content_hash` also feeds directly. That test alone
    /// cannot tell "the hash reads `Const::Str`'s own bytes" apart from "the
    /// hash would have differed anyway from the whole-arena feed": a mutant
    /// that drops `Const::Str`'s content from `hash_const` entirely (tried
    /// and reverted while implementing this) still passes it. This test
    /// isolates exactly that: two `Program`s built directly through
    /// `from_parts` sharing the IDENTICAL `strings` arena and every other
    /// field, differing ONLY in which byte range their one `Const::Str`
    /// names, with the two ranges naming DIFFERENT content ("GET" vs
    /// "POST", packed into one shared arena). Only `hash_const`'s own
    /// `Const::Str` handling can distinguish them.
    #[test]
    fn content_hash_reads_str_bytes_not_just_the_shared_arena() {
        let strings = b"GETPOST".to_vec();
        let program_get = Program::from_parts(
            vec![Op::LoadConst(0), Op::Ret],
            vec![Const::Str { from: 0, len: 3 }], // "GET"
            vec![],
            strings.clone(),
            vec![],
            vec![],
            Ty::Bool,
            Phase::RequestHeaders,
            1,
        );
        let program_post = Program::from_parts(
            vec![Op::LoadConst(0), Op::Ret],
            vec![Const::Str { from: 3, len: 4 }], // "POST"
            vec![],
            strings,
            vec![],
            vec![],
            Ty::Bool,
            Phase::RequestHeaders,
            1,
        );
        // Fixture precondition: the shared arena really is identical between
        // the two programs, and only the `Const::Str` range differs.
        assert_eq!(program_get.const_str(&program_get.consts()[0]), b"GET");
        assert_eq!(program_post.const_str(&program_post.consts()[0]), b"POST");
        assert_ne!(
            program_get.content_hash(),
            program_post.content_hash(),
            "two Const::Str values naming different bytes in the SAME shared \
             arena must hash differently"
        );

        // The complementary case named in `content_hash`'s own doc comment:
        // two DIFFERENT `(from, len)` ranges naming the SAME bytes hash the
        // SAME, because the hash reads bytes, never raw ranges.
        let strings_repeated = b"GETGET".to_vec();
        let first_get = Program::from_parts(
            vec![Op::LoadConst(0), Op::Ret],
            vec![Const::Str { from: 0, len: 3 }],
            vec![],
            strings_repeated.clone(),
            vec![],
            vec![],
            Ty::Bool,
            Phase::RequestHeaders,
            1,
        );
        let second_get = Program::from_parts(
            vec![Op::LoadConst(0), Op::Ret],
            vec![Const::Str { from: 3, len: 3 }],
            vec![],
            strings_repeated,
            vec![],
            vec![],
            Ty::Bool,
            Phase::RequestHeaders,
            1,
        );
        assert_eq!(
            first_get.content_hash(),
            second_get.content_hash(),
            "two different (from, len) ranges naming the same bytes must hash the same"
        );
    }
}
