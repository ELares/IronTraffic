// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ITPL type checker: resolves every identifier path to an attribute, assigns a
//! type to every AST node, rejects dynamic indexing, and allocates the dense
//! attribute slots the compiler and evaluator index.
//!
//! `check` is one forward pass over the flat [`Ast`] arena. Because every child id is
//! strictly less than its parent's (`crate::parse`'s arena invariant), a forward loop
//! visits children before parents and the checker never recurses.
//!
//! Absent means `null`, never empty string: a missing header is `Null` at runtime, so
//! `request.headers["x-a"] == ""` is false for a request that never sent the header.
//! Reading that comparison as "absent equals empty" is the bypass this crate exists to
//! refuse at admission instead of at 3 a.m.: a `Null` receiver is legal for the string
//! methods below (`request.headers["x"].startsWith("y")` on an absent header type
//! checks and evaluates to `false`) and `Null` unifies with `Str`, `Int` or `Bool` for
//! equality only, never for anything else.
//!
//! A header appearing twice in a request is runtime behaviour, not a check error: the
//! evaluator maps `FieldSection::get_unique`'s `DuplicateField` to `null`, counts it,
//! and records that the result was duplicate-influenced so a fail-closed policy filter
//! can refuse it. That second half matters: an allow-list predicate
//! (`request.headers["x-key"] == "secret"`) becomes `false` and denies under
//! duplication, which is safe, but a deny-list predicate
//! (`request.headers["x-blocked"] != "yes"`) becomes `true` and ADMITS, so `null` alone
//! does not close the bypass a duplicated header opens against a deny-list policy; the
//! duplicate-influenced failure rule in `{{itpl-mutation-plan-and-policy-filter}}` is
//! what does.

use crate::ast::{Ast, BinOp, Method, Node, NodeId};
use crate::attrs::{AttrId, MAX_PATH_BYTES, MapId, NAMESPACES, Ty, resolve_path};
use crate::limits::PolicyLimits;
use crate::token::Span;
use irontraffic_filter::Phase;

/// A resolved attribute reference occupying one evaluation slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttrRef {
    /// A scalar attribute.
    Scalar(AttrId),
    /// A map lookup with a constant key, as a range into the decoded-string arena.
    Field {
        /// Which of the three maps.
        map: MapId,
        /// The key, as a range into the `strings` arena `check` was given.
        key: Span,
    },
}

/// The type-checked program, ready for the compiler.
#[derive(Clone, Debug)]
pub struct Checked {
    /// The AST, unchanged.
    pub ast: Ast,
    /// Static type of every node, parallel to `ast.nodes`.
    pub types: Vec<Ty>,
    /// Dense slot table: every distinct attribute reference in the program, once.
    pub slots: Vec<AttrRef>,
    /// For each node, its slot index, or `Checked::NO_SLOT`.
    pub node_slot: Vec<u16>,
    /// The phase this expression is bound to.
    pub phase: Phase,
    /// The type of the root node.
    pub result: Ty,
}

impl Checked {
    /// `node_slot` value meaning "this node reads no attribute".
    pub const NO_SLOT: u16 = u16::MAX;
}

/// Why an expression was rejected at admission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckError {
    /// An identifier path that names no attribute.
    UnknownAttribute {
        /// Source offset for the caret.
        at: u32,
        /// The whole path, for the config error.
        path: Span,
    },
    /// The attribute exists but has no value in this phase.
    NotAvailableInPhase {
        /// Source offset for the caret.
        at: u32,
        /// The attribute that was referenced.
        attr: AttrId,
        /// The phase the expression is bound to.
        phase: Phase,
        /// The earliest phase the attribute has a value in.
        from: Phase,
    },
    /// The map exists but has no value in this phase.
    MapNotAvailableInPhase {
        /// Source offset for the caret.
        at: u32,
        /// The map that was referenced.
        map: MapId,
        /// The phase the expression is bound to.
        phase: Phase,
        /// The earliest phase the map has values in.
        from: Phase,
    },
    /// Operand types do not match the operator.
    TypeMismatch {
        /// Source offset for the caret.
        at: u32,
        /// The type the position expected.
        expected: Ty,
        /// The type actually found.
        found: Ty,
    },
    /// An ordered comparison on a type that has no order.
    NotOrdered {
        /// Source offset for the caret.
        at: u32,
        /// The type actually found.
        found: Ty,
    },
    /// Indexing something that is not one of the three maps.
    NotIndexable {
        /// Source offset for the caret.
        at: u32,
        /// The type actually found.
        found: Ty,
    },
    /// A map index that is not a string literal.
    DynamicIndex {
        /// Source offset for the caret.
        at: u32,
    },
    /// A method receiver of the wrong type.
    BadReceiver {
        /// Source offset for the caret.
        at: u32,
        /// The method that was called.
        method: Method,
        /// The type actually found.
        found: Ty,
    },
    /// A method argument of the wrong type.
    BadArgument {
        /// Source offset for the caret.
        at: u32,
        /// The method that was called.
        method: Method,
        /// The type actually found.
        found: Ty,
    },
    /// A list literal whose elements are not all the same type.
    HeterogeneousList {
        /// Source offset for the caret.
        at: u32,
        /// The type the first element (or the `in` operator's left side) has.
        first: Ty,
        /// The type actually found.
        found: Ty,
    },
    /// `in` whose right operand is not a list literal.
    InRequiresList {
        /// Source offset for the caret.
        at: u32,
        /// The type actually found.
        found: Ty,
    },
    /// A regex argument that is not a string literal.
    NonConstantRegex {
        /// Source offset for the caret.
        at: u32,
    },
    /// More distinct attribute references than `max_attr_slots`.
    TooManyAttrSlots {
        /// The configured limit.
        max: u16,
    },
    /// A field access on something that is not a namespace.
    NotANamespace {
        /// Source offset for the caret.
        at: u32,
    },
}

/// The identifier at `sp` must be one of the five closed namespace prefixes.
fn namespace_or_error(sp: Span, src: &[u8]) -> Result<(), CheckError> {
    let err = || CheckError::UnknownAttribute {
        at: sp.start,
        path: sp,
    };
    let bytes = sp.slice(src).ok_or_else(err)?;
    if NAMESPACES.contains(&bytes) {
        Ok(())
    } else {
        Err(err())
    }
}

/// Writes `seg` into `buf[..cursor]` from the right, prefixed by a `.` unless
/// `first`, and returns the new cursor, or `None` if it would not fit.
fn push_segment(
    buf: &mut [u8; MAX_PATH_BYTES],
    cursor: usize,
    seg: &[u8],
    first: bool,
) -> Option<usize> {
    let need = seg.len().saturating_add(usize::from(!first));
    if need > cursor {
        return None;
    }
    let mut c = cursor;
    if !first {
        c -= 1;
        *buf.get_mut(c)? = b'.';
    }
    c -= seg.len();
    buf.get_mut(c..c.checked_add(seg.len())?)?
        .copy_from_slice(seg);
    Some(c)
}

/// Walks back through `Field`/`Ident` nodes starting at `(base, name)`, assembling
/// the dotted path into a fixed buffer written from the end, per `resolve_field`'s
/// design: the walk runs from the leaf back to the root, so it produces the segments
/// in reverse, and writing them into the buffer from the end and taking the tail
/// slice avoids building a `String` or reversing in place.
///
/// Returns the buffer, the offset into it where the assembled path begins, and the
/// whole path's span (for the caret in a later error).
///
/// Callers must have already checked that `base`'s type is `Ty::Map`: the walk's own
/// fallback for a node that is neither `Ident` nor `Field` is total (never panics)
/// but is unreachable under that precondition, since the only node kinds ever typed
/// `Map` are `Ident` and a `Field` whose own base was itself `Map`-typed, all the way
/// down to the root `Ident`.
fn assemble_path(
    ast: &Ast,
    src: &[u8],
    base: NodeId,
    name: Span,
) -> Result<([u8; MAX_PATH_BYTES], usize, Span), CheckError> {
    let mut buf = [0u8; MAX_PATH_BYTES];
    let mut cursor = MAX_PATH_BYTES;
    let mut seg = name;
    let mut cur = base;
    let mut first = true;

    loop {
        let bytes = seg.slice(src).ok_or(CheckError::UnknownAttribute {
            at: seg.start,
            path: seg,
        })?;
        cursor =
            push_segment(&mut buf, cursor, bytes, first).ok_or(CheckError::UnknownAttribute {
                at: seg.start,
                path: Span {
                    start: seg.start,
                    end: name.end,
                },
            })?;
        first = false;

        match ast.node(cur) {
            Some(Node::Ident(root_span)) => {
                let root_bytes = root_span.slice(src).ok_or(CheckError::UnknownAttribute {
                    at: root_span.start,
                    path: root_span,
                })?;
                cursor = push_segment(&mut buf, cursor, root_bytes, false).ok_or(
                    CheckError::UnknownAttribute {
                        at: root_span.start,
                        path: Span {
                            start: root_span.start,
                            end: name.end,
                        },
                    },
                )?;
                let path_span = Span {
                    start: root_span.start,
                    end: name.end,
                };
                return Ok((buf, cursor, path_span));
            }
            Some(Node::Field { base: b2, name: n2 }) => {
                seg = n2;
                cur = b2;
            }
            // Unreachable given the precondition documented above. Kept as a total,
            // panic-free fallback rather than relying on that argument at runtime.
            _ => return Err(CheckError::NotANamespace { at: seg.start }),
        }
    }
}

/// Slot reuse compares the key BYTES, never the `Span`. Lowercasing a header key
/// appends a copy to the string arena, so `request.headers["X-A"]` and
/// `request.headers["x-a"]` produce two different `Span`s naming two different
/// offsets that hold the same three bytes; `AttrRef` derives `PartialEq`, which
/// compares the `Span` fields, so a plain `slots.contains(&want)` would allocate two
/// slots for the same header.
fn intern_slot(slots: &mut Vec<AttrRef>, strings: &[u8], want: AttrRef) -> Option<u16> {
    let key_bytes = |r: AttrRef| match r {
        AttrRef::Scalar(_) => &[][..],
        AttrRef::Field { key, .. } => {
            let start = usize::try_from(key.start).ok();
            let end = usize::try_from(key.end).ok();
            match (start, end) {
                (Some(s), Some(e)) => strings.get(s..e).unwrap_or(&[]),
                _ => &[],
            }
        }
    };
    let same = |a: AttrRef, b: AttrRef| match (a, b) {
        (AttrRef::Scalar(x), AttrRef::Scalar(y)) => x == y,
        (AttrRef::Field { map: m1, .. }, AttrRef::Field { map: m2, .. }) => {
            m1 == m2 && key_bytes(a) == key_bytes(b)
        }
        _ => false,
    };
    if let Some(i) = slots.iter().position(|&s| same(s, want)) {
        return u16::try_from(i).ok();
    }
    slots.push(want);
    u16::try_from(slots.len() - 1).ok()
}

/// Holds every array the forward pass builds, plus the borrows it needs throughout.
struct Checker<'a> {
    ast: &'a Ast,
    src: &'a [u8],
    phase: Phase,
    limits: &'a PolicyLimits,
    strings: &'a mut Vec<u8>,
    types: Vec<Ty>,
    /// Source offset used for the caret in an error raised against this node or its
    /// consumer. Only `Str` and `Ident` nodes carry a real span in the AST; every
    /// other node propagates the offset of a representative child (already computed,
    /// since children are visited first), and a bare `Bool`/`Int`/`Null` leaf, which
    /// carries no span at all, reports 0.
    starts: Vec<u32>,
    node_slot: Vec<u16>,
    /// `Some(map)` for a node whose type is `Ty::Map` because it names one of the
    /// three indexable maps specifically (as opposed to a bare namespace, which is
    /// also `Ty::Map` but is not itself indexable). Consulted by `resolve_index`.
    node_map: Vec<Option<MapId>>,
    /// `true` for a node that is some `Field` node's `base`, computed once, before
    /// the main pass, by scanning `ast.nodes`.
    ///
    /// A bare `Ident` that is a `Field`'s base defers its own namespace validation
    /// entirely to that `Field`'s `resolve_field`, which re-walks the whole dotted
    /// path and can report `UnknownAttribute` naming the FULL path (`nope.path`, not
    /// just `nope`). Without this, the flat forward pass would independently visit
    /// the `Ident` node first (it always has a strictly smaller id than the `Field`
    /// built on top of it) and fail there with a narrower span, so the fuller,
    /// whole-path error the `Field` level is built to produce would be unreachable
    /// whenever the path's root segment is itself invalid.
    is_field_base: Vec<bool>,
    slots: Vec<AttrRef>,
}

impl Checker<'_> {
    fn ty_of(&self, id: NodeId) -> Ty {
        self.types.get(id.index()).copied().unwrap_or(Ty::Null)
    }

    fn start_of(&self, id: NodeId) -> u32 {
        self.starts.get(id.index()).copied().unwrap_or(0)
    }

    fn intern(&mut self, want: AttrRef) -> Result<u16, CheckError> {
        intern_slot(&mut self.slots, self.strings, want).ok_or(CheckError::TooManyAttrSlots {
            max: self.limits.max_attr_slots,
        })
    }

    fn expect(&self, id: NodeId, want: Ty) -> Result<(), CheckError> {
        let found = self.ty_of(id);
        if found == want {
            Ok(())
        } else {
            Err(CheckError::TypeMismatch {
                at: self.start_of(id),
                expected: want,
                found,
            })
        }
    }

    /// `resolve_field(base, name, i)`: builds the dotted path by walking back through
    /// `Field` and `Ident` nodes into a fixed stack buffer, then resolves it against
    /// [`ATTRS`](crate::attrs::ATTRS).
    fn resolve_field(&mut self, i: usize, base: NodeId, name: Span) -> Result<Ty, CheckError> {
        // The receiver must already be a namespace (a bare namespace identifier, or
        // another Field that itself resolved to one of the three maps). Anything
        // else, a `Str`/`Int`/`Bool`/`Null`/`List`-typed value already fully
        // resolved lower in the arena, cannot be dotted into further: `.` is only
        // ever how a dotted attribute path is spelled, never a general
        // field-of-a-value operator.
        if self.ty_of(base) != Ty::Map {
            return Err(CheckError::NotANamespace {
                at: self.start_of(base),
            });
        }

        let (buf, cursor, path_span) = assemble_path(self.ast, self.src, base, name)?;
        let path_bytes = buf.get(cursor..).unwrap_or(&[]);
        match resolve_path(path_bytes) {
            Some(entry) => match (entry.attr, entry.map) {
                (Some(attr), _) => {
                    if !attr.available_in(self.phase) {
                        return Err(CheckError::NotAvailableInPhase {
                            at: path_span.start,
                            attr,
                            phase: self.phase,
                            from: attr.from_phase(),
                        });
                    }
                    let slot = self.intern(AttrRef::Scalar(attr))?;
                    if let Some(dst) = self.node_slot.get_mut(i) {
                        *dst = slot;
                    }
                    Ok(attr.ty())
                }
                (None, Some(map)) => {
                    if let Some(dst) = self.node_map.get_mut(i) {
                        *dst = Some(map);
                    }
                    Ok(Ty::Map)
                }
                (None, None) => Err(CheckError::UnknownAttribute {
                    at: path_span.start,
                    path: path_span,
                }),
            },
            None => Err(CheckError::UnknownAttribute {
                at: path_span.start,
                path: path_span,
            }),
        }
    }

    /// `resolve_index(base, index, i)`.
    fn resolve_index(&mut self, i: usize, base: NodeId, index: NodeId) -> Result<Ty, CheckError> {
        let base_ty = self.ty_of(base);
        let Some(map) = self.node_map.get(base.index()).copied().flatten() else {
            return Err(CheckError::NotIndexable {
                at: self.start_of(base),
                found: base_ty,
            });
        };

        let Some(Node::Str(key_span)) = self.ast.node(index) else {
            return Err(CheckError::DynamicIndex {
                at: self.start_of(index),
            });
        };

        // Case handling happens before the phase check, as a side effect on
        // `strings`: field names are case insensitive for the two header maps and
        // `FieldSection` stores them canonical, and getting this backwards is a
        // security bug (matching the wrong, or every, header), not a cosmetic one.
        let key_span = if map.lowercase_keys() {
            let start = usize::try_from(key_span.start).unwrap_or(usize::MAX);
            let end = usize::try_from(key_span.end).unwrap_or(usize::MAX);
            let original: Vec<u8> = self.strings.get(start..end).unwrap_or(&[]).to_vec();
            let new_start = self.strings.len();
            self.strings
                .extend(original.iter().map(u8::to_ascii_lowercase));
            let new_end = self.strings.len();
            Span {
                start: u32::try_from(new_start).unwrap_or(u32::MAX),
                end: u32::try_from(new_end).unwrap_or(u32::MAX),
            }
        } else {
            key_span
        };

        if !self.phase_available(map.from_phase()) {
            return Err(CheckError::MapNotAvailableInPhase {
                at: self.start_of(index),
                map,
                phase: self.phase,
                from: map.from_phase(),
            });
        }

        let slot = self.intern(AttrRef::Field { map, key: key_span })?;
        if let Some(dst) = self.node_slot.get_mut(i) {
            *dst = slot;
        }
        Ok(Ty::Str)
    }

    fn phase_available(&self, from: Phase) -> bool {
        self.phase.index() >= from.index()
    }

    /// `check_call(base, method, args)`.
    fn check_call(
        &mut self,
        base: NodeId,
        method: Method,
        args_from: u16,
        args_len: u16,
    ) -> Result<Ty, CheckError> {
        let base_ty = self.ty_of(base);

        if method == Method::Size {
            return if matches!(base_ty, Ty::Str | Ty::List) {
                Ok(Ty::Int)
            } else {
                Err(CheckError::BadReceiver {
                    at: self.start_of(base),
                    method,
                    found: base_ty,
                })
            };
        }

        // Every other method: receiver Str, single argument Str, result Bool. A
        // `Null` receiver is allowed and evaluates to `false`, because
        // `request.headers["x"].startsWith("y")` on an absent header must be false
        // rather than a config error.
        if !matches!(base_ty, Ty::Str | Ty::Null) {
            return Err(CheckError::BadReceiver {
                at: self.start_of(base),
                method,
                found: base_ty,
            });
        }

        let call_args = self.ast.args_of(args_from, args_len);
        let Some(&arg0) = call_args.first() else {
            return Err(CheckError::BadArgument {
                at: self.start_of(base),
                method,
                found: Ty::Null,
            });
        };
        let arg_ty = self.ty_of(arg0);
        if arg_ty != Ty::Str {
            return Err(CheckError::BadArgument {
                at: self.start_of(arg0),
                method,
                found: arg_ty,
            });
        }

        if method == Method::Matches && !matches!(self.ast.node(arg0), Some(Node::Str(_))) {
            return Err(CheckError::NonConstantRegex {
                at: self.start_of(arg0),
            });
        }

        Ok(Ty::Bool)
    }

    /// `check_bin(op, lhs, rhs)`.
    fn check_bin(&mut self, op: BinOp, lhs: NodeId, rhs: NodeId) -> Result<Ty, CheckError> {
        let lty = self.ty_of(lhs);
        let rty = self.ty_of(rhs);
        match op {
            BinOp::Eq | BinOp::Ne => {
                // Equal types unify, except a `Map` or `List` operand is always a
                // mismatch even against its own type. `lty == rty` here already
                // implies checking just one side names both, so there is no `||`
                // against `rty` to get backwards: that would only ever be
                // consulted with `lty == rty` already established.
                let ok = if lty == rty {
                    !matches!(lty, Ty::Map | Ty::List)
                } else {
                    (lty == Ty::Null && matches!(rty, Ty::Str | Ty::Int | Ty::Bool))
                        || (rty == Ty::Null && matches!(lty, Ty::Str | Ty::Int | Ty::Bool))
                };
                if ok {
                    Ok(Ty::Bool)
                } else {
                    Err(CheckError::TypeMismatch {
                        at: self.start_of(lhs),
                        expected: lty,
                        found: rty,
                    })
                }
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                if lty == Ty::Int && rty == Ty::Int {
                    Ok(Ty::Bool)
                } else {
                    let found = if lty == Ty::Int { rty } else { lty };
                    Err(CheckError::NotOrdered {
                        at: self.start_of(lhs),
                        found,
                    })
                }
            }
            BinOp::In => {
                let Some(Node::List { from, len }) = self.ast.node(rhs) else {
                    return Err(CheckError::InRequiresList {
                        at: self.start_of(rhs),
                        found: rty,
                    });
                };
                // The left operand must be a scalar, and this is checked BEFORE
                // the element scan so that it applies to the empty list too.
                // Reading the constraint off `elems.first()` alone would let
                // `response.headers in []` through, which is not merely a stray
                // `Ty::Map` node with `NO_SLOT` inside an accepted program: it
                // also routes around the per-phase gate, because `resolve_field`
                // records no phase check for a map row (that check lives in
                // `resolve_index`, which an unindexed map never reaches).
                if matches!(lty, Ty::Map | Ty::List) {
                    return Err(CheckError::HeterogeneousList {
                        at: self.start_of(lhs),
                        first: lty,
                        found: lty,
                    });
                }
                let elems = self.ast.args_of(from, len);
                if let Some(&first_id) = elems.first() {
                    let first_ty = self.ty_of(first_id);
                    if first_ty != lty {
                        return Err(CheckError::HeterogeneousList {
                            at: self.start_of(rhs),
                            first: first_ty,
                            found: lty,
                        });
                    }
                }
                Ok(Ty::Bool)
            }
        }
    }

    /// `check_list(node)`.
    fn check_list(&mut self, from: u16, len: u16) -> Result<Ty, CheckError> {
        let elems = self.ast.args_of(from, len);
        if let Some(&first_id) = elems.first() {
            let first_ty = self.ty_of(first_id);
            if !matches!(first_ty, Ty::Str | Ty::Int | Ty::Bool) {
                return Err(CheckError::HeterogeneousList {
                    at: self.start_of(first_id),
                    first: first_ty,
                    found: first_ty,
                });
            }
            for &elem in elems.iter().skip(1) {
                let ty = self.ty_of(elem);
                if ty != first_ty {
                    return Err(CheckError::HeterogeneousList {
                        at: self.start_of(elem),
                        first: first_ty,
                        found: ty,
                    });
                }
            }
        }
        Ok(Ty::List)
    }

    /// `unify(then_, else_)` for the ternary.
    fn unify(&mut self, then_: NodeId, else_: NodeId) -> Result<Ty, CheckError> {
        let t = self.ty_of(then_);
        let e = self.ty_of(else_);
        if t == e {
            return Ok(t);
        }
        if t == Ty::Null && matches!(e, Ty::Str | Ty::Int | Ty::Bool) {
            return Ok(e);
        }
        if e == Ty::Null && matches!(t, Ty::Str | Ty::Int | Ty::Bool) {
            return Ok(t);
        }
        Err(CheckError::TypeMismatch {
            at: self.start_of(then_),
            expected: t,
            found: e,
        })
    }

    /// One arm of `check`'s per-node match, returning the node's type and the source
    /// offset later errors should cite when this node (or something built on it) is
    /// the culprit.
    fn check_node(&mut self, i: usize, node: Node) -> Result<(Ty, u32), CheckError> {
        match node {
            Node::Bool(_) => Ok((Ty::Bool, 0)),
            Node::Int(_) => Ok((Ty::Int, 0)),
            Node::Str(sp) => Ok((Ty::Str, sp.start)),
            Node::Null => Ok((Ty::Null, 0)),
            Node::Ident(sp) => {
                // Deferred when this Ident is some Field's base: see
                // `is_field_base`'s doc comment for why.
                if !self.is_field_base.get(i).copied().unwrap_or(false) {
                    namespace_or_error(sp, self.src)?;
                }
                Ok((Ty::Map, sp.start))
            }
            Node::Field { base, name } => {
                let ty = self.resolve_field(i, base, name)?;
                Ok((ty, self.start_of(base)))
            }
            Node::Index { base, index } => {
                let ty = self.resolve_index(i, base, index)?;
                Ok((ty, self.start_of(base)))
            }
            Node::Call {
                base,
                method,
                args_from,
                args_len,
            } => {
                let ty = self.check_call(base, method, args_from, args_len)?;
                Ok((ty, self.start_of(base)))
            }
            Node::Not { inner } => {
                self.expect(inner, Ty::Bool)?; // it-allow: no-panic reason: Checker::expect returns Result and propagates via ?; not Result::expect/Option::expect.
                Ok((Ty::Bool, self.start_of(inner)))
            }
            Node::And { lhs, rhs } | Node::Or { lhs, rhs } => {
                self.expect(lhs, Ty::Bool)?; // it-allow: no-panic reason: Checker::expect returns Result and propagates via ?; not Result::expect/Option::expect.
                self.expect(rhs, Ty::Bool)?; // it-allow: no-panic reason: Checker::expect returns Result and propagates via ?; not Result::expect/Option::expect.
                Ok((Ty::Bool, self.start_of(lhs)))
            }
            Node::Bin { op, lhs, rhs } => {
                let ty = self.check_bin(op, lhs, rhs)?;
                Ok((ty, self.start_of(lhs)))
            }
            Node::Ternary { cond, then_, else_ } => {
                self.expect(cond, Ty::Bool)?; // it-allow: no-panic reason: Checker::expect returns Result and propagates via ?; not Result::expect/Option::expect.
                let ty = self.unify(then_, else_)?;
                Ok((ty, self.start_of(cond)))
            }
            Node::List { from, len } => {
                let ty = self.check_list(from, len)?;
                let start = self
                    .ast
                    .args_of(from, len)
                    .first()
                    .map_or(0, |&e| self.start_of(e));
                Ok((ty, start))
            }
        }
    }
}

/// Type checks one parsed expression against the schema for `phase`.
///
/// String-literal keys for header maps are ASCII-lowercased into `strings` as a side
/// effect, so the compiler and the evaluator only ever see canonical names.
///
/// # Errors
/// Every `CheckError` variant, each naming a source offset.
pub fn check(
    ast: Ast,
    strings: &mut Vec<u8>,
    src: &[u8],
    phase: Phase,
    limits: &PolicyLimits,
) -> Result<Checked, CheckError> {
    let n = ast.nodes.len();

    // One linear pre-pass, no recursion: mark every node that is some `Field`
    // node's `base`, so the main pass can defer a Field-base `Ident`'s namespace
    // validation to that `Field`'s own `resolve_field` call. See
    // `Checker::is_field_base`'s doc comment.
    let mut is_field_base = vec![false; n];
    for node in &ast.nodes {
        if let Node::Field { base, .. } = node
            && let Some(slot) = is_field_base.get_mut(base.index())
        {
            *slot = true;
        }
    }

    let mut chk = Checker {
        ast: &ast,
        src,
        phase,
        limits,
        strings,
        types: vec![Ty::Null; n],
        starts: vec![0u32; n],
        node_slot: vec![Checked::NO_SLOT; n],
        node_map: vec![None; n],
        is_field_base,
        slots: Vec::new(),
    };

    for i in 0..n {
        let Some(node) = chk.ast.nodes.get(i).copied() else {
            break;
        };
        let (ty, start) = chk.check_node(i, node)?;
        if let Some(dst) = chk.types.get_mut(i) {
            *dst = ty;
        }
        if let Some(dst) = chk.starts.get_mut(i) {
            *dst = start;
        }
    }

    if chk.slots.len() > usize::from(limits.max_attr_slots) {
        return Err(CheckError::TooManyAttrSlots {
            max: limits.max_attr_slots,
        });
    }

    let root_ty = chk.types.get(ast.root.index()).copied().unwrap_or(Ty::Null);
    let root_start = chk.starts.get(ast.root.index()).copied().unwrap_or(0);
    if root_ty == Ty::Map {
        return Err(CheckError::TypeMismatch {
            at: root_start,
            expected: Ty::Bool,
            found: Ty::Map,
        });
    }

    let Checker {
        types,
        node_slot,
        slots,
        ..
    } = chk;

    Ok(Checked {
        ast,
        types,
        slots,
        node_slot,
        phase,
        result: root_ty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lex::lex;
    use crate::parse::parse;
    use proptest::prelude::*;

    fn default_limits() -> PolicyLimits {
        PolicyLimits::defaults()
    }

    /// Lexes, parses and type checks `src` at `phase` with default limits.
    fn check_src(src: &[u8], phase: Phase) -> Result<Checked, CheckError> {
        let limits = default_limits();
        let toks = lex(src, &limits).expect("valid ITPL source must lex");
        let ast = parse(&toks, src, &limits).expect("valid ITPL source must parse");
        let mut strings = toks.strings;
        check(ast, &mut strings, src, phase, &limits)
    }

    fn check_src_with_limits(
        src: &[u8],
        phase: Phase,
        limits: PolicyLimits,
    ) -> Result<Checked, CheckError> {
        let toks = lex(src, &limits).expect("valid ITPL source must lex");
        let ast = parse(&toks, src, &limits).expect("valid ITPL source must parse");
        let mut strings = toks.strings;
        check(ast, &mut strings, src, phase, &limits)
    }

    // ------------------------------------------------------------------
    // Named tests 7-27.
    // ------------------------------------------------------------------

    #[test]
    fn phase_availability_request_in_stream_start() {
        // Edge case 1: `request.path` in a `StreamStart` policy.
        let err = check_src(b"request.path", Phase::StreamStart).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotAvailableInPhase {
                at: 0,
                attr: AttrId::RequestPath,
                phase: Phase::StreamStart,
                from: Phase::RequestHeaders,
            }
        );
    }

    #[test]
    fn phase_availability_response_in_request_phase() {
        // Edge case 2: `response.status` in an `on_request_headers` policy.
        let err = check_src(b"response.status", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotAvailableInPhase {
                at: 0,
                attr: AttrId::ResponseStatus,
                phase: Phase::RequestHeaders,
                from: Phase::ResponseHeaders,
            }
        );
    }

    #[test]
    fn map_not_available_in_phase() {
        // MapNotAvailableInPhase has no coverage anywhere else: every other test
        // that indexes a map does so at or after that map's own `from_phase`. Both
        // sides of the boundary, for `response.headers`, whose `from` is
        // `ResponseHeaders`: rejected one phase early, accepted exactly at it.
        let err = check_src(br#"response.headers["x"] == "1""#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::MapNotAvailableInPhase {
                at: 0,
                map: MapId::ResponseHeaders,
                phase: Phase::RequestHeaders,
                from: Phase::ResponseHeaders,
            }
        );

        let checked =
            check_src(br#"response.headers["x"] == "1""#, Phase::ResponseHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn phase_availability_exact_boundary_is_accepted() {
        // The accept side of the same boundary `phase_availability_request_in_stream_start`
        // rejects one phase early for: `request.path`'s `from_phase` is
        // `RequestHeaders`, so checking it AT that exact phase must succeed. A
        // reject-only test cannot distinguish `>=` from `>` in the availability
        // comparison.
        let checked = check_src(b"request.path == \"/x\"", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn stream_duration_ms_outside_log_is_rejected() {
        // Edge case 3: `stream.duration_ms` outside `on_log`.
        let err = check_src(b"stream.duration_ms", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotAvailableInPhase {
                at: 0,
                attr: AttrId::StreamDurationMs,
                phase: Phase::RequestHeaders,
                from: Phase::Log,
            }
        );
    }

    #[test]
    fn connection_sni_available_in_every_phase() {
        // Edge case 4: `connection.sni` in every phase.
        for phase in [
            Phase::StreamStart,
            Phase::RequestHeaders,
            Phase::RequestBody,
            Phase::RequestTrailers,
            Phase::RouteSelected,
            Phase::UpstreamRequestHeaders,
            Phase::ResponseHeaders,
            Phase::ResponseBody,
            Phase::ResponseTrailers,
            Phase::Log,
        ] {
            let checked = check_src(b"connection.sni", phase).unwrap();
            assert_eq!(checked.result, Ty::Str);
        }
    }

    #[test]
    fn header_key_is_lowercased() {
        // Test 9. Fails if slot reuse compares Spans instead of key bytes: the
        // lowercasing appends a second copy of the key at a different arena offset.
        let checked = check_src(
            br#"request.headers["X-A"] == "1" && request.headers["x-a"] == "2""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(checked.slots.len(), 1, "both keys must reuse the same slot");
        assert!(matches!(
            checked.slots[0],
            AttrRef::Field {
                map: MapId::RequestHeaders,
                ..
            }
        ));

        // Both `Index` nodes must carry the same node_slot.
        let index_slots: Vec<u16> = checked
            .ast
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| matches!(n, Node::Index { .. }))
            .map(|(i, _)| checked.node_slot[i])
            .collect();
        assert_eq!(index_slots.len(), 2);
        assert_eq!(index_slots[0], index_slots[1]);
        assert_ne!(index_slots[0], Checked::NO_SLOT);
    }

    #[test]
    fn query_key_is_case_sensitive() {
        // Test 10: two slots, because query parameter names are case sensitive.
        let checked = check_src(
            br#"request.query_params["Token"] == "a" && request.query_params["token"] == "b""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(checked.slots.len(), 2);
    }

    #[test]
    fn dynamic_index_rejected() {
        // Edge case 8.
        let err = check_src(b"request.headers[request.method]", Phase::RequestHeaders).unwrap_err();
        assert!(matches!(err, CheckError::DynamicIndex { .. }));
    }

    #[test]
    fn double_index_rejected() {
        // Edge case 9: indexing a Str result is NotIndexable{found: str}.
        let err = check_src(br#"request.headers["a"]["b"]"#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotIndexable {
                at: 0,
                found: Ty::Str
            }
        );
    }

    #[test]
    fn unknown_attribute_names_full_path() {
        // Edge cases 10 and 11: the caret sits at the start of the whole path.
        let err = check_src(b"request.nope", Phase::Log).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownAttribute {
                at: 0,
                path: Span { start: 0, end: 12 }
            }
        );

        let err = check_src(b"nope.path", Phase::Log).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownAttribute {
                at: 0,
                path: Span { start: 0, end: 9 }
            }
        );
    }

    #[test]
    fn standalone_unknown_identifier_is_unknown_attribute() {
        // A gap `cargo mutants` found: replacing namespace_or_error's whole body
        // with `Ok(())` left every other test green, because every other test's
        // invalid identifier is some Field's base and so defers to
        // resolve_field's own check instead of calling namespace_or_error
        // directly. A bare, standalone identifier that is nobody's Field base
        // (here, the entire program) is the one shape that calls
        // namespace_or_error's own failure path, and without it "nope" would
        // type as Map and fail via the root-is-Map guard with a different error
        // (TypeMismatch, not UnknownAttribute).
        let err = check_src(b"nope", Phase::Log).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownAttribute {
                at: 0,
                path: Span { start: 0, end: 4 }
            }
        );
    }

    #[test]
    fn int_vs_str_mismatch() {
        // Edge case 12.
        let err = check_src(br#"request.port == "80""#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 0,
                expected: Ty::Int,
                found: Ty::Str
            }
        );
    }

    #[test]
    fn null_unifies_for_equality() {
        // Edge case 13: always false for a scalar that always has a value, but it
        // type checks.
        let checked = check_src(b"request.path == null", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn absent_header_is_not_empty_string() {
        // Edge cases 14 and 15: both comparisons type check. The runtime behaviour
        // (false for an absent header on both sides, never conflated) is the
        // evaluator's contract, tested there; this only asserts admission accepts
        // both spellings.
        let checked = check_src(br#"request.headers["x"] == null"#, Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
        let checked = check_src(br#"request.headers["x"] == """#, Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn ordered_comparison_requires_int() {
        // Edge case 16.
        let err = check_src(br#"request.path < "/b""#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotOrdered {
                at: 0,
                found: Ty::Str
            }
        );

        // Edge case 17: the accept side of the same rule.
        let checked = check_src(b"request.size < 100", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn ordered_comparison_rejects_a_mixed_int_and_str_pair() {
        // The case above has BOTH sides Str, which cannot distinguish
        // `lty == Int && rty == Int` from `lty == Int || rty == Int`: neither
        // side is Int, so both the real check and an `&&`-to-`||` mutant reject
        // it the same way. This is the case where exactly one side is Int: the
        // real check (both sides required) must still reject it.
        let err = check_src(br#"request.port < "80""#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotOrdered {
                at: 0,
                found: Ty::Str
            }
        );
    }

    #[test]
    fn in_requires_homogeneous_list() {
        // Edge case 18: accept side.
        let checked = check_src(
            br#"request.method in ["GET", "HEAD"]"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(checked.result, Ty::Bool);

        // Edge case 19: reject side, a heterogeneous list.
        let err = check_src(br#"request.method in ["GET", 1]"#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::HeterogeneousList {
                at: 0,
                first: Ty::Str,
                found: Ty::Int
            }
        );

        // Edge case 20: `in` against a non-list.
        let err = check_src(br#"request.method in "GET""#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::InRequiresList {
                at: 0,
                found: Ty::Str
            }
        );
    }

    /// The `In` arm's own element-type guard, which nothing else exercised.
    ///
    /// `in_requires_homogeneous_list`'s heterogeneous case is caught one level
    /// earlier, by `check_list`'s homogeneity loop, with a byte identical error
    /// value, so deleting this arm's guard entirely used to leave the suite
    /// green. A HOMOGENEOUS list of the wrong element type reaches only this
    /// guard, so it is the discriminating input.
    #[test]
    fn in_rejects_a_homogeneous_list_of_the_wrong_element_type() {
        let err = check_src(br#"request.method in [1, 2]"#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::HeterogeneousList {
                at: 0,
                first: Ty::Int,
                found: Ty::Str
            }
        );
    }

    /// `in` against an EMPTY list must still constrain its left operand.
    ///
    /// Reading the constraint off `elems.first()` alone admitted a `Ty::Map`
    /// node carrying `NO_SLOT` into an accepted program, and, because a map that
    /// is never indexed never reaches `resolve_index`, it also bypassed the per
    /// phase availability gate: `response.headers in []` type checked in
    /// `stream_start`, the earliest phase, before any response exists.
    #[test]
    fn in_an_empty_list_still_rejects_a_map_or_list_operand() {
        for (src, phase) in [
            (&br#"response.headers in []"#[..], Phase::StreamStart),
            (&br#"request.headers in []"#[..], Phase::StreamStart),
            (&br#"request.query_params in []"#[..], Phase::RequestHeaders),
            (&br#"[1, 2] in []"#[..], Phase::RequestHeaders),
        ] {
            let err = check_src(src, phase).unwrap_err();
            let found = match err {
                CheckError::HeterogeneousList { found, .. } => found,
                other => panic!(
                    "{} must be rejected as a non scalar `in` operand, got {other:?}",
                    core::str::from_utf8(src).unwrap()
                ),
            };
            assert!(
                matches!(found, Ty::Map | Ty::List),
                "{} was rejected, but for the wrong reason: found {found:?}",
                core::str::from_utf8(src).unwrap()
            );
        }

        // The accept side, so the guard above cannot be widened into rejecting
        // every `in`: a scalar left operand against an empty list is legal and
        // simply always false.
        let checked = check_src(br#"request.method in []"#, Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    /// `intern_slot` must not merge a scalar attribute with a map lookup.
    ///
    /// The `_ => false` arm of its `same` closure is what keeps an
    /// `AttrRef::Scalar` and an `AttrRef::Field` in separate slots. Flipping it
    /// to `_ => true` used to leave the whole suite green, because no test mixed
    /// the two kinds in one program and asserted the slot count: `slot_reuse` is
    /// 50 scalars, `header_key_is_lowercased` is two fields, and
    /// `too_many_attr_slots` is 16 scalars. With the arm flipped, the header's
    /// `node_slot` points at the scalar's slot, so an evaluator reads
    /// `request.path` where the policy asked for a header.
    #[test]
    fn a_scalar_and_a_map_lookup_never_share_a_slot() {
        let checked = check_src(
            br#"request.path == "/x" && request.headers["a"] == "v""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(
            checked.slots.len(),
            2,
            "a scalar attribute and a header lookup are two distinct values"
        );

        // Kind alone is not enough: the two slots must also name different
        // things, so that merging them in the other direction is caught too.
        assert_ne!(
            checked.slots[0], checked.slots[1],
            "the two slots must reference different attributes"
        );
    }

    #[test]
    fn empty_list_in_is_always_legal() {
        // check_list's design note: "x in [] is legal and always false; it is not an
        // error, and the HeterogeneousList check is vacuous for it."
        let checked = check_src(b"request.method in []", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
        let checked = check_src(b"true in []", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn matches_requires_literal() {
        // Edge case 21.
        let err = check_src(
            b"request.path.matches(request.query)",
            Phase::RequestHeaders,
        )
        .unwrap_err();
        assert!(matches!(err, CheckError::NonConstantRegex { .. }));

        // Accept side: a literal regex.
        let checked = check_src(
            br#"request.path.matches("^/v[0-9]+")"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(checked.result, Ty::Bool);
    }

    #[test]
    fn method_receiver_and_argument_types() {
        // Edge case 22: a Null receiver (the literal, not a map index, whose static
        // type is always Str) type checks and is not a config error.
        let checked = check_src(br#"null.startsWith("a")"#, Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);

        // A Str receiver, the ordinary case.
        let checked =
            check_src(br#"request.method.startsWith("G")"#, Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Bool);

        // A bad receiver: Int is neither Str nor Null.
        let err = check_src(br#"request.port.startsWith("8")"#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::BadReceiver {
                at: 0,
                method: Method::StartsWith,
                found: Ty::Int
            }
        );

        // A bad argument: an Int argument to a Str-argument method.
        let err = check_src(b"request.method.startsWith(1)", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::BadArgument {
                at: 0,
                method: Method::StartsWith,
                found: Ty::Int
            }
        );
    }

    #[test]
    fn size_on_str_and_list() {
        // Edge cases 23 and 24.
        let checked = check_src(b"request.method.size()", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Int);
        let checked = check_src(br#"["a","b"].size()"#, Phase::RequestHeaders).unwrap();
        assert_eq!(checked.result, Ty::Int);

        // A bad receiver for size: a Bool has no size.
        let err = check_src(b"true.size()", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::BadReceiver {
                at: 0,
                method: Method::Size,
                found: Ty::Bool
            }
        );
    }

    #[test]
    fn slot_reuse() {
        // Test 22: 50 references to request.path produce one slot.
        let mut clauses = Vec::with_capacity(50);
        for _ in 0..50 {
            clauses.push("request.path == \"/x\"".to_owned());
        }
        let src = clauses.join(" || ");
        let mut limits = default_limits();
        limits.max_tokens = 2048;
        let checked = check_src_with_limits(src.as_bytes(), Phase::RequestHeaders, limits).unwrap();
        assert_eq!(checked.slots.len(), 1);
    }

    #[test]
    fn too_many_attr_slots() {
        // 16 distinct attributes, exactly at the default max_attr_slots: the ACCEPT
        // side of the boundary. A reject-only test cannot tell `>` from `>=`.
        let attrs_16 = [
            "request.method",
            "request.path",
            "request.query",
            "request.scheme",
            "request.authority",
            "request.host",
            "request.port",
            "request.protocol",
            "request.size",
            "request.id",
            "request.header_count",
            "connection.remote_addr",
            "connection.remote_port",
            "connection.local_addr",
            "connection.tls",
            "connection.sni",
        ];
        assert_eq!(attrs_16.len(), 16);
        // Every attribute above is Str, Int or Bool (never Map/List), so comparing
        // each to itself is always a legal, always-true clause.
        let self_eq_16: Vec<String> = attrs_16.iter().map(|a| format!("{a} == {a}")).collect();
        let src_16 = self_eq_16.join(" && ");
        let mut limits = default_limits();
        limits.max_tokens = 2048;
        let checked = check_src_with_limits(src_16.as_bytes(), Phase::Log, limits).unwrap();
        assert_eq!(checked.slots.len(), 16);

        // Edge case 25: 17 distinct attributes with max_attr_slots = 16, the REJECT
        // side, one past the boundary just accepted above.
        let mut attrs_17 = attrs_16.to_vec();
        attrs_17.push("connection.alpn");
        assert_eq!(attrs_17.len(), 17);
        let self_eq_17: Vec<String> = attrs_17.iter().map(|a| format!("{a} == {a}")).collect();
        let src_17 = self_eq_17.join(" && ");
        let mut limits = default_limits();
        limits.max_tokens = 2048;
        let err = check_src_with_limits(src_17.as_bytes(), Phase::Log, limits).unwrap_err();
        assert_eq!(err, CheckError::TooManyAttrSlots { max: 16 });
    }

    #[test]
    fn ternary_branches_must_unify() {
        // Edge case 27.
        let err = check_src(br#"true ? 1 : "a""#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 0,
                expected: Ty::Int,
                found: Ty::Str
            }
        );

        // Null unifies with the non-null branch.
        let checked = check_src(
            br#"true ? request.headers["x"] : null"#,
            Phase::RequestHeaders,
        )
        .unwrap();
        assert_eq!(checked.result, Ty::Str);
    }

    #[test]
    fn not_and_or_and_ternary_cond_each_require_bool() {
        // `Checker::expect` backs all four of these call sites (`Not`, both sides
        // of `And`/`Or`, and the ternary condition). Stubbing `expect` itself to
        // always `Ok(())` left every other test green: none of them independently
        // exercises a non-Bool operand at each of the four call sites, only the
        // ternary's `unify` (a different function) for its non-cond branches.
        let err = check_src(b"!request.method", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 1,
                expected: Ty::Bool,
                found: Ty::Str
            }
        );

        let err = check_src(b"request.method && true", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 0,
                expected: Ty::Bool,
                found: Ty::Str
            }
        );

        let err = check_src(b"true || request.method", Phase::RequestHeaders).unwrap_err();
        assert!(matches!(
            err,
            CheckError::TypeMismatch {
                expected: Ty::Bool,
                found: Ty::Str,
                ..
            }
        ));

        let err = check_src(b"1 ? 2 : 3", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 0,
                expected: Ty::Bool,
                found: Ty::Int
            }
        );
    }

    #[test]
    fn error_offset_is_not_always_zero() {
        // Nearly every other test in this module puts the offending construct at
        // the very start of the source, so `at: 0` is what almost all of them
        // expect. That cannot distinguish a real source offset from a stub that
        // always returns 0. `request.path` here starts at byte 8, after `true &&
        // `.
        let err = check_src(b"true && request.path", Phase::StreamStart).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotAvailableInPhase {
                at: 8,
                attr: AttrId::RequestPath,
                phase: Phase::StreamStart,
                from: Phase::RequestHeaders,
            }
        );
    }

    #[test]
    fn field_chain_through_a_map_attribute_reaches_the_field_arm() {
        // `assemble_path`'s walk-back has two arms once past the initial
        // `Ty::Map` gate: the terminal `Ident` (every other test in this module
        // that reaches the walk at all), and a `Field` whose OWN base was already
        // `Map`-typed, which is only reachable through one of the three MAP
        // attributes (a scalar attribute's Field, like `request.method`, gates
        // out one level higher, in `NotANamespace`, before the walk ever
        // starts). `request.headers.foo` walks: "foo" (this node's own name),
        // then back through the `request.headers` Field node (Map-typed, the
        // Field arm), then to the `request` Ident (the terminal arm), assembling
        // the full 3-segment path.
        let err = check_src(b"request.headers.foo", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownAttribute {
                at: 0,
                path: Span { start: 0, end: 19 }
            }
        );
    }

    #[test]
    fn path_length_boundary() {
        // MAX_PATH_BYTES's accept side: nothing in the real schema comes anywhere
        // near 64 bytes (the longest real path, `connection.mtls_verified`, is
        // 24), so the buffer's own overflow guard has no coverage from realistic
        // attribute names, and a reject-only test cannot tell `push_segment`'s
        // `need > cursor` from `>=` or from a `!first` typo that shifts which
        // call the extra separator byte is charged to.
        //
        // A single field-name segment of exactly 64 bytes sits precisely on
        // that seam: `push_segment`'s FIRST call (the name itself, `first =
        // true`, no separator charged) computes `need = 64`, which is accepted
        // (`64 > 64` is false) against the fresh 64-byte buffer, so the walk
        // proceeds to its second call (for "request" plus a separator dot,
        // `need = 8`) against a now-EMPTY buffer (`cursor == 0`), which
        // overflows there instead, reporting the root's own start (0). A
        // `!first` typo charges the separator to the FIRST call instead
        // (`need = 65`), which overflows immediately, reporting the *segment's*
        // start (8) rather than the root's: a different, distinguishing `at`.
        let name_64 = "a".repeat(64);
        let src_64 = format!("request.{name_64}");
        let err = check_src(src_64.as_bytes(), Phase::Log).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownAttribute {
                at: 0,
                path: Span { start: 0, end: 72 }
            }
        );

        // One segment alone, one byte longer (65 bytes), already exceeds
        // MAX_PATH_BYTES on its own: the walk bails at the segment's own start
        // (8) on the very first call, before ever attempting the root.
        let name_65 = "a".repeat(65);
        let src_65 = format!("request.{name_65}");
        let err = check_src(src_65.as_bytes(), Phase::Log).unwrap_err();
        assert_eq!(
            err,
            CheckError::UnknownAttribute {
                at: 8,
                path: Span { start: 8, end: 73 }
            }
        );
    }

    #[test]
    fn map_without_index_is_type_error() {
        // Edge case 5 and test 25: `request.headers` used without an index, both as
        // the whole program (Invariant 4: a complete expression is never Map) and as
        // an operand.
        let err = check_src(b"request.headers", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 0,
                expected: Ty::Bool,
                found: Ty::Map
            }
        );

        let err = check_src(b"request.headers == null", Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::TypeMismatch {
                at: 0,
                expected: Ty::Map,
                found: Ty::Null
            }
        );
    }

    #[test]
    fn bare_namespace_is_not_indexable() {
        let err = check_src(br#"request["x"]"#, Phase::RequestHeaders).unwrap_err();
        assert_eq!(
            err,
            CheckError::NotIndexable {
                at: 0,
                found: Ty::Map
            }
        );
    }

    #[test]
    fn field_on_a_non_namespace_is_not_a_namespace() {
        let err = check_src(br"request.method.foo", Phase::RequestHeaders).unwrap_err();
        assert!(matches!(err, CheckError::NotANamespace { .. }));
    }

    #[test]
    fn checker_never_recurses() {
        // Test 26: a maximally deep accepted AST is checked inside a 128 KiB stack
        // thread. 15 nested parens around a leaf reaches the default max_depth (16)
        // while parsing; checking a flat forward loop over the arena costs no extra
        // stack regardless of how the parser produced it.
        let mut src = "(".repeat(15);
        src.push_str("request.path == \"/x\"");
        src.push_str(&")".repeat(15));
        let limits = default_limits();

        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let toks = lex(src.as_bytes(), &limits).expect("lex must accept 15 nested parens");
                let ast = parse(&toks, src.as_bytes(), &limits)
                    .expect("parse must accept 15 nested parens");
                let mut strings = toks.strings;
                check(
                    ast,
                    &mut strings,
                    src.as_bytes(),
                    Phase::RequestHeaders,
                    &limits,
                )
            })
            .expect("spawn 128 KiB thread");
        let result = handle.join().expect("must not stack overflow or panic");
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn check_is_deterministic() {
        // Test 27.
        let src = b"request.path.startsWith(\"/v1/\") && request.method == \"GET\"";
        let first = check_src(src, Phase::RequestHeaders).unwrap();
        for _ in 0..100 {
            let again = check_src(src, Phase::RequestHeaders).unwrap();
            assert_eq!(again.types, first.types);
            assert_eq!(again.slots, first.slots);
            assert_eq!(again.node_slot, first.node_slot);
            assert_eq!(again.result, first.result);
        }
    }

    #[test]
    fn invariant_types_len_matches_nodes_len() {
        let checked = check_src(b"request.path == \"/x\"", Phase::RequestHeaders).unwrap();
        assert_eq!(checked.types.len(), checked.ast.nodes.len());
    }

    #[test]
    fn invariant_slots_within_max_attr_slots() {
        let checked = check_src(b"request.path == \"/x\"", Phase::RequestHeaders).unwrap();
        assert!(checked.slots.len() <= usize::from(default_limits().max_attr_slots));
    }

    #[test]
    fn invariant_slotted_nodes_are_never_map_typed() {
        let checked = check_src(
            br#"request.headers["x"] == "1" && request.path == "/y""#,
            Phase::RequestHeaders,
        )
        .unwrap();
        for (i, &slot) in checked.node_slot.iter().enumerate() {
            if slot != Checked::NO_SLOT {
                assert_ne!(
                    checked.types[i],
                    Ty::Map,
                    "a slotted node must never be Map-typed"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Property tests. #738 BLOCKING 2 found both required property tests in the
    // parser vacuous: a uniformly random token generator produced 256 of 256 parse
    // failures, so every `if let Ok(..)` body was dead code. `parse.rs`'s fix was a
    // grammar-shaped generator that builds an expression tree and renders it to real
    // source. This generator follows the same technique, adapted so the LEAVES name
    // real schema paths: a tree built purely from arbitrary identifiers would fail at
    // `check`'s namespace/attribute gate on almost every run for a different reason
    // than the parser's, which would just move the vacuousness one gate later
    // instead of fixing it. The measured `Ok` fraction is asserted directly below, not
    // merely reported, so a future regression that collapses it back to near zero
    // fails the build instead of shipping a green, useless test.
    // ------------------------------------------------------------------

    /// One schema leaf the generator can pick: a scalar attribute path (with its
    /// static type, so the generator can build type-correct comparisons), or one of
    /// the two request-phase-available header/query maps indexed by a literal key.
    #[derive(Clone, Copy, Debug)]
    enum GenAttr {
        Scalar(&'static str, Ty),
        HeaderIndex(&'static str),
    }

    const GEN_ATTRS: &[GenAttr] = &[
        GenAttr::Scalar("request.method", Ty::Str),
        GenAttr::Scalar("request.path", Ty::Str),
        GenAttr::Scalar("request.port", Ty::Int),
        GenAttr::Scalar("request.size", Ty::Int),
        GenAttr::Scalar("connection.tls", Ty::Bool),
        GenAttr::Scalar("connection.mtls_verified", Ty::Bool),
        GenAttr::HeaderIndex("request.headers"),
        GenAttr::HeaderIndex("response.headers"),
    ];

    const GEN_KEYS: &[&str] = &["x-a", "x-b", "authorization"];

    /// A small expression tree, shaped like the ITPL grammar and biased toward
    /// well-typed programs so a healthy fraction of generated programs reach `Ok` in
    /// `check`, not merely in `parse`.
    #[derive(Clone, Debug)]
    enum GenExpr {
        BoolLit(bool),
        IntLit(i64),
        StrLit(String),
        NullLit,
        Attr(GenAttr),
        HeaderGet(&'static str, &'static str),
        Eq(Box<GenExpr>, Box<GenExpr>),
        Cmp(Box<GenExpr>, Box<GenExpr>),
        And(Box<GenExpr>, Box<GenExpr>),
        Or(Box<GenExpr>, Box<GenExpr>),
        Not(Box<GenExpr>),
    }

    fn render(e: &GenExpr, out: &mut String) {
        use std::fmt::Write as _;
        match e {
            GenExpr::BoolLit(b) => {
                out.push_str(if *b { "true" } else { "false" });
            }
            GenExpr::IntLit(v) => {
                let _ = write!(out, "{v}");
            }
            GenExpr::StrLit(s) => {
                out.push('"');
                out.push_str(s);
                out.push('"');
            }
            GenExpr::NullLit => out.push_str("null"),
            GenExpr::Attr(GenAttr::Scalar(path, _)) => out.push_str(path),
            GenExpr::Attr(GenAttr::HeaderIndex(path)) => {
                let _ = write!(out, "{path}[\"x-a\"]");
            }
            GenExpr::HeaderGet(path, key) => {
                let _ = write!(out, "{path}[\"{key}\"]");
            }
            GenExpr::Eq(l, r) => {
                out.push('(');
                render(l, out);
                out.push_str(" == ");
                render(r, out);
                out.push(')');
            }
            GenExpr::Cmp(l, r) => {
                out.push('(');
                render(l, out);
                out.push_str(" < ");
                render(r, out);
                out.push(')');
            }
            GenExpr::And(l, r) => {
                out.push('(');
                render(l, out);
                out.push_str(" && ");
                render(r, out);
                out.push(')');
            }
            GenExpr::Or(l, r) => {
                out.push('(');
                render(l, out);
                out.push_str(" || ");
                render(r, out);
                out.push(')');
            }
            GenExpr::Not(inner) => {
                out.push('!');
                render(inner, out);
            }
        }
    }

    fn arb_attr() -> impl Strategy<Value = GenAttr> {
        (0..GEN_ATTRS.len()).prop_map(|i| GEN_ATTRS[i])
    }

    fn arb_key() -> impl Strategy<Value = &'static str> {
        (0..GEN_KEYS.len()).prop_map(|i| GEN_KEYS[i])
    }

    /// A well-typed comparison: an attribute (or header lookup) against a literal of
    /// a plausible type, biased so most draws produce matching types and therefore an
    /// `Ok` check result, with a minority of intentional mismatches so `Err` paths
    /// stay exercised too.
    fn arb_comparison() -> BoxedStrategy<GenExpr> {
        prop_oneof![
            3 => (arb_attr(), any::<bool>()).prop_map(|(a, matched)| {
                let rhs = match (a, matched) {
                    (GenAttr::Scalar(_, Ty::Str), true) => GenExpr::StrLit("GET".to_owned()),
                    (GenAttr::Scalar(_, Ty::Int), true) => GenExpr::IntLit(80),
                    (GenAttr::Scalar(_, Ty::Bool), true) => GenExpr::BoolLit(true),
                    (GenAttr::HeaderIndex(_), true) => GenExpr::StrLit("v".to_owned()),
                    (_, false) | (GenAttr::Scalar(_, _), true) => GenExpr::NullLit,
                };
                GenExpr::Eq(Box::new(GenExpr::Attr(a)), Box::new(rhs))
            }),
            1 => arb_key().prop_map(|k| {
                GenExpr::Eq(
                    Box::new(GenExpr::HeaderGet("request.headers", k)),
                    Box::new(GenExpr::StrLit("v".to_owned())),
                )
            }),
            1 => Just(GenExpr::Cmp(
                Box::new(GenExpr::Attr(GenAttr::Scalar("request.size", Ty::Int))),
                Box::new(GenExpr::IntLit(1000)),
            )),
        ]
        .boxed()
    }

    fn arb_expr(budget: u32) -> BoxedStrategy<GenExpr> {
        let leaf = arb_comparison();
        if budget == 0 {
            return leaf;
        }
        let next = budget - 1;
        prop_oneof![
            4 => leaf,
            2 => (arb_expr(next), arb_expr(next)).prop_map(|(l, r)| GenExpr::And(Box::new(l), Box::new(r))),
            2 => (arb_expr(next), arb_expr(next)).prop_map(|(l, r)| GenExpr::Or(Box::new(l), Box::new(r))),
            1 => arb_expr(next).prop_map(|e| GenExpr::Not(Box::new(e))),
        ]
        .boxed()
    }

    /// Renders a generated tree to ITPL source. About one case in eight gets a
    /// trailing identifier appended (guaranteed `TrailingTokens` at parse time),
    /// keeping the property honest about `Err` paths without making random token
    /// soup (which never reaches `check` at all) the generator.
    fn arb_itpl_src() -> impl Strategy<Value = Vec<u8>> {
        (arb_expr(2), 0u8..8).prop_map(|(expr, roll)| {
            let mut src = String::new();
            render(&expr, &mut src);
            if roll == 0 {
                src.push_str(" then");
            }
            src.into_bytes()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_check_never_panics(src in arb_itpl_src()) {
            // Test 29. `check` returning `Ok` or `Err` for every input is trivially
            // true of a `Result`-typed function and proves nothing on its own (see
            // this crate's own house lesson about `assert!(r.is_ok() || r.is_err())`);
            // what this property actually exercises is that `check` never panics
            // while reaching a real verdict, over a generator that reaches `check` at
            // all (measured below), unlike a uniform byte/token generator.
            let limits = default_limits();
            if let Ok(toks) = lex(&src, &limits) {
                let src_clone = src.clone();
                if let Ok(ast) = parse(&toks, &src_clone, &limits) {
                    let mut strings = toks.strings.clone();
                    let result = check(ast, &mut strings, &src_clone, Phase::Log, &limits);
                    prop_assert!(result.is_ok() || result.is_err());
                }
            }
        }

        #[test]
        fn prop_typed_nodes_have_a_type(src in arb_itpl_src()) {
            // Test 30: for any accepted program, every node's type is not `Map`
            // unless the node is an `Ident` or a `Field` on the path to a map (i.e.
            // unless it names a namespace or a map attribute before indexing).
            let limits = default_limits();
            if let Ok(toks) = lex(&src, &limits) {
                let src_clone = src.clone();
                if let Ok(ast) = parse(&toks, &src_clone, &limits) {
                    let mut strings = toks.strings.clone();
                    if let Ok(checked) = check(ast, &mut strings, &src_clone, Phase::Log, &limits) {
                        for (i, node) in checked.ast.nodes.iter().enumerate() {
                            if checked.types[i] == Ty::Map {
                                prop_assert!(
                                    matches!(node, Node::Ident(_) | Node::Field { .. }),
                                    "node {i} ({node:?}) is Map-typed but is not an Ident or a Field"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Measures the fraction of `arb_itpl_src` draws that reach a successful
    /// `check`, over proptest's default 256 cases, and asserts it stays well above
    /// zero. This is the check this crate's own house lesson demands: a property
    /// test whose generator never reaches the code under test is decorative, and a
    /// bare `Ok`-or-`Err` assertion cannot tell the difference between "the
    /// generator reaches real programs" and "every case fails at a gate before
    /// `check` runs". Asserting a concrete minimum fails the build the moment the
    /// generator regresses back to that state, rather than merely reporting a number
    /// nobody reads.
    #[test]
    fn prop_generator_reaches_check_ok() {
        use proptest::strategy::ValueTree as _;

        let limits = default_limits();
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
        let strategy = arb_itpl_src();
        let mut ok = 0u32;
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
                if check(ast, &mut strings, &src, Phase::Log, &limits).is_ok() {
                    ok += 1;
                }
            }
        }
        assert!(total > 0);
        // Measured on this generator: 224/256 (87%) reach a successful `check`,
        // well above the floor below. That number is reported in the PR
        // description rather than printed here (this crate denies
        // `print_stdout`/`print_stderr` even in tests), and this assertion pins
        // the floor a future regression must not fall below.
        assert!(
            ok * 4 >= total,
            "expected at least 25% of generated programs to reach a successful check, got {ok}/{total}"
        );
    }
}
