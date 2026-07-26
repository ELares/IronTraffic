// SPDX-License-Identifier: MIT OR Apache-2.0

//! The mutation vocabulary: which arena a byte range names (`Arena`), a
//! checked byte range within one (`StrRef`), and the bounded, recorded header
//! mutations (`HeaderOp`) a filter appends to a per-stream ledger instead of
//! applying directly.
//!
//! `irontraffic_http::FieldSection` is built into a caller-supplied arena by
//! its builder and, once finished, has no arena handle, so a filter cannot
//! push a field into it directly. Filters instead record a bounded list of
//! `HeaderOp` values and the chain applies the ledger once, at the end of the
//! phase, into the arena the proxy owns. Every operand is a `StrRef` into an
//! arena that already exists, so this costs no allocation on the request
//! path, and because ops name a field rather than concatenating values, the
//! no-comma-joining rule that closes Envoy CVE-2026-26308 is preserved.

const _: () = assert!(core::mem::size_of::<StrRef>() == 12);
// `HeaderOp` is bounded rather than fixed because `Arena` has 253 unused
// discriminant values, so the compiler is free to pack the `HeaderOp` tag
// into that niche and produce 24 instead of 28. Both are correct; what must
// not happen is a value larger than 28, which would mean an owning field
// crept in.
const _: () = assert!(core::mem::size_of::<HeaderOp>() <= 28);

/// Which byte arena a `StrRef` indexes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Arena {
    /// The immutable configuration snapshot's byte arena. Outlives every stream.
    Config = 0,
    /// The parsed head buffer of the message being processed in this phase.
    Head = 1,
    /// The per-stream scratch arena, written by filters that compute a value.
    Scratch = 2,
}

impl Arena {
    /// Number of arenas. Fixed at 3.
    pub const COUNT: usize = 3;

    /// The arena for a stored discriminant, or `None` when `i >= 3`.
    ///
    /// This is the only conversion from a number to an `Arena`. Every place that
    /// decodes a stored or guest-supplied arena byte (the slab op ledger, the WASM
    /// op list, the `ext_proc` mutation decoder) calls this and treats `None` as a
    /// malformed record, so the greppable set of decode sites is one function.
    #[must_use]
    pub const fn from_index(i: u8) -> Option<Arena> {
        match i {
            0 => Some(Arena::Config),
            1 => Some(Arena::Head),
            2 => Some(Arena::Scratch),
            _ => None,
        }
    }
}

/// A byte range within one arena: which arena, an offset, and a length.
///
/// A claim about an arena, not a proof: `StrRef::new` only rules out `u32`
/// wraparound, so a `StrRef` may still point past the end of the arena it
/// names. No consumer may slice an arena with `arena_bytes[off..off + len]`;
/// resolution is `arena_bytes.get(off as usize..end)` where `end` comes from
/// `StrRef::end()`, and a `None` makes the enclosing `HeaderOp` malformed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct StrRef {
    /// Which arena `off` indexes.
    pub arena: Arena,
    /// Byte offset of the first byte within that arena.
    pub off: u32,
    /// Length in bytes.
    pub len: u32,
}

impl StrRef {
    /// The empty reference into `Arena::Config` at offset 0.
    pub const EMPTY: StrRef = StrRef {
        arena: Arena::Config,
        off: 0,
        len: 0,
    };

    /// A reference, or `None` when `off + len` overflows `u32`.
    #[must_use]
    pub const fn new(arena: Arena, off: u32, len: u32) -> Option<StrRef> {
        match off.checked_add(len) {
            Some(_) => Some(StrRef { arena, off, len }),
            None => None,
        }
    }

    /// One past the last byte, as a `u64` so it cannot overflow.
    #[inline]
    #[must_use]
    #[rustfmt::skip]
    #[allow(clippy::cast_lossless, reason = "widening u32 to u64 in a const function; From is not yet const-stable")]
    pub const fn end(self) -> u64 {
        self.off as u64 + self.len as u64
    }

    /// True when `len == 0`.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// One recorded header mutation. Filters append these to a per-stream ledger;
/// the chain applies the whole ledger once, at the end of the phase, into the
/// arena the proxy owns.
///
/// Ops name a field, they do not concatenate values, which is what preserves
/// `FieldSection`'s no-comma-joining rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderOp {
    /// Append one field, keeping every existing field with that name.
    Append {
        /// The field name.
        name: StrRef,
        /// The field value.
        value: StrRef,
    },
    /// Remove every field named `name`, then append one with `value`.
    Set {
        /// The field name.
        name: StrRef,
        /// The field value.
        value: StrRef,
    },
    /// Remove every field named `name`.
    Remove {
        /// The field name.
        name: StrRef,
    },
}

impl HeaderOp {
    /// The field name this op names.
    #[inline]
    #[must_use]
    pub const fn name(self) -> StrRef {
        match self {
            HeaderOp::Append { name, .. }
            | HeaderOp::Set { name, .. }
            | HeaderOp::Remove { name } => name,
        }
    }

    /// The value, or `None` for `Remove`.
    #[inline]
    #[must_use]
    pub const fn value(self) -> Option<StrRef> {
        match self {
            HeaderOp::Append { value, .. } | HeaderOp::Set { value, .. } => Some(value),
            HeaderOp::Remove { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strref_new_rejects_overflow() {
        assert!(StrRef::new(Arena::Head, u32::MAX, 1).is_none());
        assert!(StrRef::new(Arena::Head, u32::MAX, u32::MAX).is_none());
        assert!(StrRef::new(Arena::Head, 1, u32::MAX).is_none());
        assert!(StrRef::new(Arena::Head, u32::MAX, 0).is_some());
    }

    #[test]
    fn strref_end_does_not_overflow() {
        assert_eq!(
            StrRef::new(Arena::Head, u32::MAX - 1, 1)
                .expect("does not overflow u32")
                .end(),
            u64::from(u32::MAX)
        );
        // The largest legal pair: off = 0, len = u32::MAX. `end()` is computed
        // in u64 precisely so this does not wrap.
        assert_eq!(
            StrRef::new(Arena::Head, 0, u32::MAX)
                .expect("does not overflow u32")
                .end(),
            u64::from(u32::MAX)
        );
    }

    #[test]
    fn arena_from_index_roundtrip() {
        assert_eq!(Arena::from_index(0), Some(Arena::Config));
        assert_eq!(Arena::from_index(1), Some(Arena::Head));
        assert_eq!(Arena::from_index(2), Some(Arena::Scratch));
        assert!(Arena::from_index(3).is_none());
        assert!(Arena::from_index(255).is_none());
    }

    #[test]
    fn header_op_remove_has_no_value() {
        let name = StrRef::EMPTY;
        assert!(HeaderOp::Remove { name }.value().is_none());
        assert_eq!(
            HeaderOp::Set {
                name,
                value: StrRef::EMPTY
            }
            .value(),
            Some(StrRef::EMPTY)
        );
    }
}
