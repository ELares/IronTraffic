// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Value`, the ITPL runtime value.
//!
//! `Value` is a 24-byte `Copy` enum that borrows from the request: it never owns a
//! `String`, a `Vec` or an `Rc`. No operator in ITPL produces a new string
//! (`crate::lex`, `crate::parse`), so there is nowhere in `crate::vm::eval` for an
//! allocation to happen as long as `Value` itself never allocates. That is the
//! whole reason this type exists as its own module rather than as a variant of
//! some richer, owned value type a general-purpose interpreter would reach for.

use crate::attrs::Ty;

/// An ITPL runtime value. `Copy`, at most 24 bytes, and it borrows from the
/// request: it must never own a `String`, a `Vec` or an `Rc`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Value<'a> {
    /// A boolean.
    Bool(bool),
    /// A 64-bit signed integer.
    Int(i64),
    /// A byte string borrowed from the request, the head buffer, or the program's
    /// constant arena.
    Str(&'a [u8]),
    /// Absent: a missing header, a missing query parameter, or the `null` literal.
    Null,
}

const _: () = assert!(core::mem::size_of::<Value<'_>>() <= 24);

impl<'a> Value<'a> {
    /// The bytes of a `Str`, or `None` for anything else.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> Option<&'a [u8]> {
        match self {
            Value::Str(s) => Some(s),
            Value::Bool(_) | Value::Int(_) | Value::Null => None,
        }
    }

    /// The integer of an `Int`, or `None`.
    #[inline]
    #[must_use]
    pub const fn as_int(self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(v),
            Value::Bool(_) | Value::Str(_) | Value::Null => None,
        }
    }

    /// The boolean of a `Bool`, or `None`.
    #[inline]
    #[must_use]
    pub const fn as_bool(self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(b),
            Value::Int(_) | Value::Str(_) | Value::Null => None,
        }
    }

    /// True for `Null`.
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        matches!(self, Value::Null)
    }

    /// The static type this value inhabits.
    #[inline]
    #[must_use]
    pub const fn ty(self) -> Ty {
        match self {
            Value::Bool(_) => Ty::Bool,
            Value::Int(_) => Ty::Int,
            Value::Str(_) => Ty::Str,
            Value::Null => Ty::Null,
        }
    }

    /// ITPL equality: same type and same contents, or both `Null`. `Null` is never
    /// equal to a non-`Null`, which is what makes an absent header different from an
    /// empty one.
    ///
    /// Written as an explicit match rather than delegated to the derived
    /// `PartialEq` so the ITPL semantics stay spelled out here even if a future
    /// variant changes what the derive would do; the two happen to agree for the
    /// four variants above them today.
    #[inline]
    #[must_use]
    pub fn itpl_eq(self, other: Value<'a>) -> bool {
        // `Null` unifies only with `Null`: handled first and separately so
        // the type-mismatch fallback below never has to repeat that same
        // `false` body under a second, redundant arm.
        if self.is_null() || other.is_null() {
            return self.is_null() && other.is_null();
        }
        match (self, other) {
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Named tests 1-3.
    // ------------------------------------------------------------------

    #[test]
    fn value_size() {
        // Test 1. Pinned against a literal, not against
        // `core::mem::size_of::<Value>()` compared to itself: invariant 4 is
        // `assert!(size_of::<Value>() <= 24)`, and this is the same claim,
        // stated as a runtime test rather than only the crate's const
        // assertion above, so a regression shows up in `cargo test` output
        // too, not only as a compile error somewhere else in the crate.
        assert!(
            core::mem::size_of::<Value<'_>>() <= 24,
            "Value must stay at or under 24 bytes, got {}",
            core::mem::size_of::<Value<'_>>()
        );
    }

    #[test]
    fn itpl_eq_null_rules() {
        // Test 2. `Null == Null` is true; `Null` unifies with nothing else,
        // not even a same-typed "empty" value.
        assert!(Value::Null.itpl_eq(Value::Null));
        assert!(!Value::Null.itpl_eq(Value::Str(b"")));
        assert!(!Value::Str(b"").itpl_eq(Value::Null));
        assert!(!Value::Null.itpl_eq(Value::Int(0)));
        assert!(!Value::Int(0).itpl_eq(Value::Null));
        assert!(!Value::Null.itpl_eq(Value::Bool(false)));
        assert!(!Value::Bool(false).itpl_eq(Value::Null));
    }

    #[test]
    fn itpl_eq_type_mismatch_is_false() {
        // Test 3: `Int(1) == Str("1")` is false rather than an error. ITPL
        // equality never coerces across types.
        assert!(!Value::Int(1).itpl_eq(Value::Str(b"1")));
        assert!(!Value::Str(b"1").itpl_eq(Value::Int(1)));
        assert!(!Value::Bool(true).itpl_eq(Value::Int(1)));
    }

    #[test]
    fn accessors_match_the_constructing_variant() {
        // Fixture/behaviour sanity for the four accessor methods: each
        // returns `Some` only for its own variant and `None` for the other
        // three, over every variant, not just one hand-picked case.
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert_eq!(Value::Bool(true).as_int(), None);
        assert_eq!(Value::Bool(true).as_str(), None);
        assert!(!Value::Bool(true).is_null());

        assert_eq!(Value::Int(7).as_int(), Some(7));
        assert_eq!(Value::Int(7).as_bool(), None);
        assert_eq!(Value::Int(7).as_str(), None);
        assert!(!Value::Int(7).is_null());

        assert_eq!(Value::Str(b"x").as_str(), Some(b"x".as_slice()));
        assert_eq!(Value::Str(b"x").as_int(), None);
        assert_eq!(Value::Str(b"x").as_bool(), None);
        assert!(!Value::Str(b"x").is_null());

        assert_eq!(Value::Null.as_str(), None);
        assert_eq!(Value::Null.as_int(), None);
        assert_eq!(Value::Null.as_bool(), None);
        assert!(Value::Null.is_null());
    }

    #[test]
    fn ty_matches_the_variant() {
        assert_eq!(Value::Bool(true).ty(), Ty::Bool);
        assert_eq!(Value::Int(1).ty(), Ty::Int);
        assert_eq!(Value::Str(b"x").ty(), Ty::Str);
        assert_eq!(Value::Null.ty(), Ty::Null);
    }
}
