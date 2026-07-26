// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gateway API match precedence packed into a single comparable `u64`.
//!
//! [`Precedence`] encodes every precedence criterion Gateway API defines except
//! hostname specificity and path prefix length. Those two are encoded
//! structurally elsewhere, hostname specificity by the group fallthrough
//! chain and path prefix length by trie depth, rather than in this integer,
//! so the two encodings can never disagree with each other. Deriving `Ord` on
//! the wrapped `u64` means a precedence comparison on the request path is one
//! `cmp` instruction and cannot drift from the bit layout below.
//!
//! Bit layout, most significant bit first, larger value wins:
//!
//! | bits | width | meaning |
//! |---|---|---|
//! | 63..61 | 3 | [`PathKind`] |
//! | 60 | 1 | a method match is specified |
//! | 59..52 | 8 | header match count, saturating at 255 |
//! | 51..44 | 8 | query parameter match count, saturating at 255 |
//! | 43..32 | 12 | reserved for vendor precedence extensions, always zero in v1 |
//! | 31..0 | 32 | the bitwise complement of the match's global ordinal |
//!
//! [`assign_ordinals`] assigns that global ordinal by sorting every match in a
//! built table by the Gateway API tie-break key (creation time, then
//! qualified name, then rule index, then match index) and numbering from 0,
//! so the oldest, alphabetically first match gets ordinal 0. Storing the
//! bitwise complement of the ordinal in the low bits makes "smaller ordinal
//! wins" fall out of "larger integer wins", so the winner between any two
//! matches in one build is fully determined by one integer comparison and no
//! tie-break code needs to run on the request path at all: candidate arrays
//! are sorted once at build time and the request path returns the first
//! candidate whose predicates pass.
//!
//! This module is inert: nothing in this crate calls [`Precedence::pack`] or
//! [`assign_ordinals`] yet. The route table builder wires them in.

/// The path-condition class, occupying the top three bits of `Precedence`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PathKind {
    /// The implicit `PathPrefix: /` that Gateway API applies when a rule has no
    /// matches, and any explicitly configured `Prefix("/")`.
    RootDefault = 1,
    /// `PathPrefix`, at a segment boundary.
    SegmentPrefix = 3,
    /// `RegularExpression`.
    Regex = 5,
    /// `Exact`.
    Exact = 7,
}

impl PathKind {
    /// The inverse of the `#[repr(u8)]` discriminant, spelled out as a `match` and
    /// never a transmute. `Group::cand_kinds` (the byte array added by
    /// `table-arena-and-node-layout` (#51)) stores these bytes, so this is how the
    /// candidate scan turns one back into a `PathKind`. Nothing in THIS issue stores
    /// them; the round-trip is tested directly.
    ///
    /// Returns `None` for every value other than 1, 3, 5 and 7, which is only
    /// reachable from a corrupted arena; the caller treats `None` as a candidate that
    /// cannot match rather than panicking.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<PathKind> {
        match v {
            1 => Some(PathKind::RootDefault),
            3 => Some(PathKind::SegmentPrefix),
            5 => Some(PathKind::Regex),
            7 => Some(PathKind::Exact),
            _ => None,
        }
    }

    /// The discriminant, for storing into `Group::cand_kinds`.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8 // it-allow: unchecked-cast reason: PathKind is #[repr(u8)] with discriminants 1, 3, 5 and 7, so this cast is exact and never truncates
    }
}

/// Bit position of the low edge of the path-kind field (bits 63..61).
const KIND_SHIFT: u32 = 61;
/// Bit position of the method-match flag (bit 60).
const METHOD_SHIFT: u32 = 60;
/// Bit position of the low edge of the header match count field (bits 59..52).
const HEADER_SHIFT: u32 = 52;
/// Bit position of the low edge of the query match count field (bits 51..44).
const QUERY_SHIFT: u32 = 44;
/// Bit position of the low edge of the reserved field (bits 43..32).
const RESERVED_SHIFT: u32 = 32;
/// Mask for the 3-bit path-kind field.
const KIND_MASK: u64 = 0x7;
/// Mask for an 8-bit saturating count field (header or query).
const COUNT_MASK: u64 = 0xff;
/// Mask for the 12-bit reserved field.
const RESERVED_MASK: u64 = 0xfff;
/// Mask for the 32-bit ordinal-complement field.
const ORDINAL_MASK: u64 = 0xffff_ffff;

// Field widths, named so that the relationship between a field's width and the
// maximum value it must hold is an equality the compiler checks on every
// build, not a claim left in a comment for a reviewer to take on faith. A
// one-bit error in any shift above breaks one of the equalities below and
// fails the build instead of silently misrouting whichever inputs happen to
// land on the wrong side of the mistake.
const KIND_WIDTH: u32 = 3;
const METHOD_WIDTH: u32 = 1;
const HEADER_WIDTH: u32 = 8;
const QUERY_WIDTH: u32 = 8;
const RESERVED_WIDTH: u32 = 12;
const ORDINAL_WIDTH: u32 = 32;

const _: () = assert!(
    KIND_WIDTH + METHOD_WIDTH + HEADER_WIDTH + QUERY_WIDTH + RESERVED_WIDTH + ORDINAL_WIDTH == 64,
    "the six fields must exactly fill one u64: no gap, no overlap"
);
const _: () = assert!(
    ORDINAL_WIDTH == u32::BITS,
    "the ordinal field must be exactly as wide as the u32 ordinal it stores"
);
const _: () = assert!(
    RESERVED_SHIFT == ORDINAL_WIDTH,
    "the reserved field must start exactly where the ordinal field ends"
);
const _: () = assert!(
    QUERY_SHIFT == RESERVED_SHIFT + RESERVED_WIDTH,
    "the query count field must start exactly where the reserved field ends"
);
const _: () = assert!(
    HEADER_SHIFT == QUERY_SHIFT + QUERY_WIDTH,
    "the header count field must start exactly where the query count field ends"
);
const _: () = assert!(
    METHOD_SHIFT == HEADER_SHIFT + HEADER_WIDTH,
    "the method bit must start exactly where the header count field ends"
);
const _: () = assert!(
    KIND_SHIFT == METHOD_SHIFT + METHOD_WIDTH,
    "the kind field must start exactly where the method bit ends"
);
const _: () = assert!(
    KIND_SHIFT + KIND_WIDTH == 64,
    "the kind field's top bit must land on bit 63, the top of the u64"
);
const _: () = assert!(
    COUNT_MASK == (1u64 << HEADER_WIDTH) - 1,
    "the count mask must cover exactly the values an 8-bit field can hold"
);
const _: () = assert!(
    KIND_MASK == (1u64 << KIND_WIDTH) - 1,
    "the kind mask must cover exactly the three kind bits"
);
const _: () = assert!(
    RESERVED_MASK == (1u64 << RESERVED_WIDTH) - 1,
    "the reserved mask must cover exactly its twelve bits"
);
const _: () = assert!(
    ORDINAL_MASK == u32::MAX as u64, // it-allow: unchecked-cast reason: widening u32::MAX to u64, and u64::from is not usable in a const context on this toolchain (rust-lang/rust#143874)
    "the ordinal mask must cover exactly the range of the u32 ordinal it stores"
);
const _: () = assert!(
    PathKind::Exact as u64 <= KIND_MASK,
    "the largest PathKind discriminant must fit inside the 3-bit kind field"
);
const _: () = assert!(
    COUNT_MASK == u8::MAX as u64, // it-allow: unchecked-cast reason: widening u8::MAX to u64, and u64::from is not usable in a const context on this toolchain (rust-lang/rust#143874)
    "the count field must be exactly wide enough for the saturating maximum, u8::MAX"
);

/// Build-time precedence of one route match, packed into a single `u64` so that the
/// request path never compares precedence at all: candidate arrays are pre-sorted.
///
/// `Ord` is derived on the `u64`, which compiles to one `cmp` instruction and cannot
/// drift from the bit layout. Larger wins.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Precedence(pub u64);

const _: () = assert!(core::mem::size_of::<Precedence>() == 8);

impl Precedence {
    /// The lowest possible precedence. Used as the initial value of a maximum scan
    /// in the reference oracle; never stored in a table.
    pub const MIN: Precedence = Precedence(0);

    /// Packs the six precedence fields.
    ///
    /// `header_count` and `query_count` saturate at 255. `ordinal` is stored
    /// complemented, so a smaller ordinal produces a larger `Precedence`.
    #[must_use]
    pub const fn pack(
        kind: PathKind,
        has_method: bool,
        header_count: usize,
        query_count: usize,
        ordinal: u32,
    ) -> Precedence {
        let kind_bits = (kind as u64) & KIND_MASK;
        // `u64::from(has_method)` is the natural spelling, but `From::from` is
        // not yet usable in a const fn on this toolchain (the trait impl is
        // only "conditionally const", tracked at rust-lang/rust#143874), so
        // this uses a plain `as` cast, which is unconditionally const and
        // never truncates going from a 1-bit domain to 64 bits.
        let m = has_method as u64;
        let h = if header_count > 255 {
            255u64
        } else {
            header_count as u64
        };
        let q = if query_count > 255 {
            255u64
        } else {
            query_count as u64
        };
        // Same const-fn restriction as above: `!ordinal` is a `u32`, and
        // widening it to `u64` with `as` never truncates.
        let inv = (!ordinal) as u64;
        Precedence(
            (kind_bits << KIND_SHIFT)
                | (m << METHOD_SHIFT)
                | (h << HEADER_SHIFT)
                | (q << QUERY_SHIFT)
                | inv,
        )
    }

    /// The path kind field.
    ///
    /// Returns `None` when the three kind bits do not name a `PathKind` (that is,
    /// when they are 0, 2, 4 or 6), which cannot happen for a value produced by
    /// `pack` and is therefore only reachable from a corrupted table.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits is masked with KIND_MASK (0x7) above, so it fits u8 exactly"
    )]
    pub const fn kind(self) -> Option<PathKind> {
        let bits = (self.0 >> KIND_SHIFT) & KIND_MASK;
        PathKind::from_u8(bits as u8) // it-allow: unchecked-cast reason: masked with KIND_MASK (0x7) above, so it fits u8 exactly
    }

    /// True when the method bit is set.
    #[must_use]
    pub const fn has_method(self) -> bool {
        ((self.0 >> METHOD_SHIFT) & 1) != 0
    }

    /// The header match count field, 0 to 255.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked with COUNT_MASK (0xff) above, so it fits u8 exactly"
    )]
    pub const fn header_count(self) -> u8 {
        ((self.0 >> HEADER_SHIFT) & COUNT_MASK) as u8 // it-allow: unchecked-cast reason: masked with COUNT_MASK (0xff) above, so it fits u8 exactly
    }

    /// The query match count field, 0 to 255.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked with COUNT_MASK (0xff) above, so it fits u8 exactly"
    )]
    pub const fn query_count(self) -> u8 {
        ((self.0 >> QUERY_SHIFT) & COUNT_MASK) as u8 // it-allow: unchecked-cast reason: masked with COUNT_MASK (0xff) above, so it fits u8 exactly
    }

    /// The reserved vendor field. Always 0 in v1.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked with RESERVED_MASK (0xfff) above, so it fits u16 exactly"
    )]
    pub const fn reserved(self) -> u16 {
        ((self.0 >> RESERVED_SHIFT) & RESERVED_MASK) as u16 // it-allow: unchecked-cast reason: masked with RESERVED_MASK (0xfff) above, so it fits u16 exactly
    }

    /// The global ordinal this precedence was built from.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked with ORDINAL_MASK (u32::MAX) above, so it fits u32 exactly"
    )]
    pub const fn ordinal(self) -> u32 {
        !((self.0 & ORDINAL_MASK) as u32) // it-allow: unchecked-cast reason: masked with ORDINAL_MASK (u32::MAX) above, so it fits u32 exactly
    }
}

/// The Gateway API tie-break key for one match, used only to assign ordinals.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MatchOrdinalKey<'a> {
    /// Resource creation time in Unix milliseconds, 0 when the source has none.
    pub created_unix_millis: u64,
    /// Namespace, possibly empty.
    pub namespace: &'a str,
    /// Resource name, non-empty.
    pub name: &'a str,
    /// Index of the rule within the route.
    pub rule_idx: u16,
    /// Index of the match within the rule.
    pub match_idx: u16,
    /// Caller-chosen slot: `assign_ordinals` writes this key's ordinal to
    /// `out[slot as usize]`.
    pub slot: u32,
}

/// Compares the concatenated byte sequence `namespace ++ b"/" ++ name`, without
/// ever building the concatenation.
///
/// This disagrees with comparing the pair `(namespace, name)` whenever one
/// namespace is a byte-for-byte prefix of another: `"a"` sorts before `"a-x"`
/// as a bare namespace, but `"a-x/y"` sorts before `"a/b"` once the `/`
/// separator is taken into account, because `-` (0x2D) is less than `/`
/// (0x2F). The Gateway API specification's wording is `{namespace}/{name}`,
/// so this function, not the pair comparison, is the authoritative order.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "called both directly and as part of order_key_cmp, which sort_unstable_by requires to take &T; matching that shape here avoids a copy at every recursive call"
)]
fn qname_cmp(a: &MatchOrdinalKey<'_>, b: &MatchOrdinalKey<'_>) -> core::cmp::Ordering {
    a.namespace
        .bytes()
        .chain(core::iter::once(b'/'))
        .chain(a.name.bytes())
        .cmp(
            b.namespace
                .bytes()
                .chain(core::iter::once(b'/'))
                .chain(b.name.bytes()),
        )
}

/// The full Gateway API tie-break comparator: creation time, then the
/// qualified name, then rule index, then match index.
///
/// `assign_ordinals` uses this same function for both the sort that orders
/// every match and the adjacent-duplicate check that follows it, so the two
/// comparisons cannot drift apart: there is exactly one place this chain is
/// written.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "used directly as the sort_unstable_by comparator, which the standard library requires to be FnMut(&T, &T) -> Ordering"
)]
fn order_key_cmp(a: &MatchOrdinalKey<'_>, b: &MatchOrdinalKey<'_>) -> core::cmp::Ordering {
    a.created_unix_millis
        .cmp(&b.created_unix_millis)
        .then_with(|| qname_cmp(a, b))
        .then_with(|| a.rule_idx.cmp(&b.rule_idx))
        .then_with(|| a.match_idx.cmp(&b.match_idx))
}

/// Why `assign_ordinals` refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OrdinalError {
    /// More matches than a `u32` ordinal can number.
    OrdinalOverflow,
    /// Two matches shared a complete tie-break key. The `slot` of the second is
    /// given so the caller can name the offending route.
    DuplicateOrderKey {
        /// The slot of the colliding key.
        slot: u32,
    },
    /// A key's `slot` was past the end of `out`.
    SlotOutOfRange {
        /// The offending slot.
        slot: u32,
    },
}

/// Sorts `keys` into Gateway API tie-break order and writes each key's ordinal into
/// `out[key.slot]`.
///
/// `keys` is reordered in place. `out` must be at least as long as the highest slot
/// plus one; the caller sizes it to the match count.
///
/// # Errors
/// See `OrdinalError`. Every error leaves `out` partially written, so the caller
/// must discard the whole build on error, which it does: a failed build changes
/// nothing observable.
#[allow(
    clippy::cast_possible_truncation,
    reason = "keys.len() is checked <= u32::MAX above, and i ranges over 0..keys.len(), so the cast from i is lossless"
)]
pub fn assign_ordinals(
    keys: &mut [MatchOrdinalKey<'_>],
    out: &mut [u32],
) -> Result<(), OrdinalError> {
    if keys.len() > u32::MAX as usize {
        return Err(OrdinalError::OrdinalOverflow);
    }

    // sort_unstable_by is pattern-defeating quicksort with a heapsort
    // fallback: O(n log n) worst case, and an adversary who controls the
    // input order (these keys are tenant supplied in a Gateway API cluster)
    // cannot force quadratic behaviour the way they could against a plain
    // quicksort. Do not replace this with a hand-written quicksort.
    keys.sort_unstable_by(order_key_cmp);

    // The four-component key is a total order over distinct matches: within
    // one route (rule_idx, match_idx) is unique, and across routes the
    // qualified name is unique, so two matches can share every component only
    // if they are the same match submitted twice or two routes collided on
    // their order key. Either way that is a duplicate this build must refuse,
    // which is exactly what this walk checks: sort_unstable is safe here only
    // because uniqueness is verified immediately afterward rather than
    // assumed.
    for pair in keys.windows(2) {
        if let [a, b] = pair
            && order_key_cmp(a, b) == core::cmp::Ordering::Equal
        {
            return Err(OrdinalError::DuplicateOrderKey { slot: b.slot });
        }
    }

    for (i, key) in keys.iter().enumerate() {
        let ordinal = i as u32; // it-allow: unchecked-cast reason: keys.len() <= u32::MAX was checked above, and i < keys.len()
        let slot = key.slot as usize;
        match out.get_mut(slot) {
            Some(o) => *o = ordinal,
            None => return Err(OrdinalError::SlotOutOfRange { slot: key.slot }),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::{MatchOrdinalKey, OrdinalError, PathKind, Precedence, assign_ordinals};

    #[test]
    fn layout_round_trips() {
        let kinds = [
            PathKind::RootDefault,
            PathKind::SegmentPrefix,
            PathKind::Regex,
            PathKind::Exact,
        ];
        let header_counts = [0usize, 1, 16, 255];
        let query_counts = [0usize, 1, 16, 255];
        let ordinals = [0u32, 1, 12345, u32::MAX];

        for kind in kinds {
            for has_method in [false, true] {
                for header_count in header_counts {
                    for query_count in query_counts {
                        for ordinal in ordinals {
                            let p = Precedence::pack(
                                kind,
                                has_method,
                                header_count,
                                query_count,
                                ordinal,
                            );
                            assert_eq!(p.kind(), Some(kind));
                            assert_eq!(p.has_method(), has_method);
                            assert_eq!(usize::from(p.header_count()), header_count);
                            assert_eq!(usize::from(p.query_count()), query_count);
                            assert_eq!(p.reserved(), 0);
                            assert_eq!(p.ordinal(), ordinal);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn kind_dominates_everything() {
        assert!(
            Precedence::pack(PathKind::Exact, false, 0, 0, u32::MAX)
                > Precedence::pack(PathKind::Regex, true, 255, 255, 0)
        );
        assert!(
            Precedence::pack(PathKind::Regex, false, 0, 0, u32::MAX)
                > Precedence::pack(PathKind::SegmentPrefix, true, 255, 255, 0)
        );
        assert!(
            Precedence::pack(PathKind::SegmentPrefix, false, 0, 0, u32::MAX)
                > Precedence::pack(PathKind::RootDefault, true, 255, 255, 0)
        );
    }

    #[test]
    fn method_beats_header_count() {
        assert!(
            Precedence::pack(PathKind::Exact, true, 0, 0, 5)
                > Precedence::pack(PathKind::Exact, false, 16, 16, 0)
        );
    }

    #[test]
    fn header_count_beats_query_count() {
        assert!(
            Precedence::pack(PathKind::Exact, true, 1, 0, 5)
                > Precedence::pack(PathKind::Exact, true, 0, 16, 0)
        );
    }

    #[test]
    fn older_route_wins() {
        let older = Precedence::pack(PathKind::Exact, true, 2, 2, 0);
        let newer = Precedence::pack(PathKind::Exact, true, 2, 2, 1);
        assert!(older > newer);
        let diff = older.0 ^ newer.0;
        assert_ne!(diff, 0, "the two values must actually differ");
        assert_eq!(
            diff,
            diff & 0xffff_ffff,
            "only bits in the low 32 (the ordinal field) may differ when every other field is equal"
        );
    }

    #[test]
    fn saturation() {
        let p = Precedence::pack(PathKind::Exact, false, 300, usize::MAX, 0);
        assert_eq!(p.header_count(), 255);
        assert_eq!(p.query_count(), 255);
    }

    #[test]
    fn assign_ordinals_orders_by_timestamp_then_name() {
        let mut keys = vec![
            MatchOrdinalKey {
                created_unix_millis: 1000,
                namespace: "b",
                name: "r1",
                rule_idx: 0,
                match_idx: 0,
                slot: 0,
            },
            MatchOrdinalKey {
                created_unix_millis: 1000,
                namespace: "a",
                name: "r1",
                rule_idx: 0,
                match_idx: 0,
                slot: 1,
            },
            MatchOrdinalKey {
                created_unix_millis: 500,
                namespace: "z",
                name: "r9",
                rule_idx: 0,
                match_idx: 0,
                slot: 2,
            },
            MatchOrdinalKey {
                created_unix_millis: 1000,
                namespace: "a",
                name: "r1",
                rule_idx: 0,
                match_idx: 1,
                slot: 3,
            },
        ];
        let mut out = [0u32; 4];
        assign_ordinals(&mut keys, &mut out).unwrap();
        assert_eq!(out, [3, 1, 0, 2]);

        // Distinguishes the qualified-name order (namespace ++ "/" ++ name)
        // from the pair order (namespace, name): "a" < "a-x" as a bare
        // namespace, but "a-x/y" < "a/b" once the "/" separator is
        // considered, because '-' (0x2D) is less than '/' (0x2F). A sort by
        // the pair would put slot 0 first; the specification's wording puts
        // slot 1 first.
        let mut keys2 = vec![
            MatchOrdinalKey {
                created_unix_millis: 0,
                namespace: "a",
                name: "b",
                rule_idx: 0,
                match_idx: 0,
                slot: 0,
            },
            MatchOrdinalKey {
                created_unix_millis: 0,
                namespace: "a-x",
                name: "y",
                rule_idx: 0,
                match_idx: 0,
                slot: 1,
            },
        ];
        let mut out2 = [0u32; 2];
        assign_ordinals(&mut keys2, &mut out2).unwrap();
        assert_eq!(out2, [1, 0]);
    }

    #[test]
    fn assign_ordinals_zero_timestamps_are_lexicographic() {
        let names = ["r9", "r8", "r7", "r6", "r5", "r4", "r3", "r2", "r1", "r0"];
        let slots: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut keys: Vec<MatchOrdinalKey<'_>> = names
            .iter()
            .zip(slots)
            .map(|(&name, slot)| MatchOrdinalKey {
                created_unix_millis: 0,
                namespace: "",
                name,
                rule_idx: 0,
                match_idx: 0,
                slot,
            })
            .collect();
        let mut out = [0u32; 10];
        assign_ordinals(&mut keys, &mut out).unwrap();
        let expected: [u32; 10] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        assert_eq!(
            out, expected,
            "order must be lexicographic, independent of submission order"
        );
    }

    #[test]
    fn assign_ordinals_rejects_duplicates() {
        let mut keys = vec![
            MatchOrdinalKey {
                created_unix_millis: 10,
                namespace: "a",
                name: "b",
                rule_idx: 0,
                match_idx: 0,
                slot: 0,
            },
            MatchOrdinalKey {
                created_unix_millis: 10,
                namespace: "a",
                name: "b",
                rule_idx: 0,
                match_idx: 0,
                slot: 1,
            },
        ];
        let mut out = [0u32; 2];
        let result = assign_ordinals(&mut keys, &mut out);
        assert_eq!(result, Err(OrdinalError::DuplicateOrderKey { slot: 1 }));
    }

    /// One partial tie-break key: everything except `name`, which the
    /// property test derives from each key's position so that names are
    /// always distinct and `assign_ordinals` never sees a real collision.
    fn arb_partial_key() -> impl Strategy<Value = (u64, &'static str, u16, u16)> {
        (
            prop_oneof![Just(0u64), 0u64..3],
            prop::sample::select(&["", "a", "b"]),
            0u16..3,
            0u16..3,
        )
    }

    proptest! {
        #[test]
        fn precedence_totality(
            partials in prop::collection::vec(arb_partial_key(), 1..=200),
            kind_idx in 0usize..4,
            has_method in any::<bool>(),
            header_count in 0usize..=255usize,
            query_count in 0usize..=255usize,
        ) {
            let kinds = [
                PathKind::RootDefault,
                PathKind::SegmentPrefix,
                PathKind::Regex,
                PathKind::Exact,
            ];
            let kind = kinds[kind_idx];

            // Every name is distinct by construction (it encodes its own
            // index), so the qualified name alone already makes every
            // key's four-component tie-break key unique regardless of what
            // the other, independently sampled fields turned out to be.
            let names: Vec<String> = (0..partials.len()).map(|i| format!("r{i}")).collect();
            let mut keys: Vec<MatchOrdinalKey<'_>> = Vec::with_capacity(partials.len());
            for (i, partial) in partials.iter().enumerate() {
                let (created_unix_millis, namespace, rule_idx, match_idx) = *partial;
                let slot = u32::try_from(i).expect("proptest bounds the vector to 200 elements");
                keys.push(MatchOrdinalKey {
                    created_unix_millis,
                    namespace,
                    name: &names[i],
                    rule_idx,
                    match_idx,
                    slot,
                });
            }

            let mut out = vec![0u32; keys.len()];
            let result = assign_ordinals(&mut keys, &mut out);
            prop_assert!(result.is_ok());

            let mut seen = HashSet::new();
            for &ordinal in &out {
                let value = Precedence::pack(kind, has_method, header_count, query_count, ordinal).0;
                prop_assert!(seen.insert(value), "two distinct ordinals packed to the same Precedence");
            }
        }
    }

    #[test]
    fn path_kind_round_trip() {
        // No wildcard arm: adding a fifth `PathKind` variant makes this match
        // non-exhaustive and fails to compile, so this test cannot go
        // silently stale the way a `_ => ...` fallback would let it.
        fn all_kinds() -> [PathKind; 4] {
            let sample = PathKind::RootDefault;
            match sample {
                PathKind::RootDefault
                | PathKind::SegmentPrefix
                | PathKind::Regex
                | PathKind::Exact => [
                    PathKind::RootDefault,
                    PathKind::SegmentPrefix,
                    PathKind::Regex,
                    PathKind::Exact,
                ],
            }
        }

        for kind in all_kinds() {
            assert_eq!(PathKind::from_u8(kind.to_u8()), Some(kind));
        }

        assert_eq!(PathKind::RootDefault.to_u8(), 1);
        assert_eq!(PathKind::SegmentPrefix.to_u8(), 3);
        assert_eq!(PathKind::Regex.to_u8(), 5);
        assert_eq!(PathKind::Exact.to_u8(), 7);

        for v in 0..=255u8 {
            let expected = match v {
                1 => Some(PathKind::RootDefault),
                3 => Some(PathKind::SegmentPrefix),
                5 => Some(PathKind::Regex),
                7 => Some(PathKind::Exact),
                _ => None,
            };
            assert_eq!(PathKind::from_u8(v), expected, "mismatch at {v}");
        }
    }
}
