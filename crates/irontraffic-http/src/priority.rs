// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 9218 extensible priorities: two integers, no graph.
//!
//! RFC 9113 Section 5.3.1 deprecates the RFC 7540 priority-tree scheme, and
//! CVE-2019-9513 is exactly what a tree costs: unbounded priority-tree churn.
//! A dependency tree is a pointer-chasing hot-path data structure for a
//! deprecated feature, so this crate does not implement one, anywhere. What
//! it implements instead is RFC 9218 extensible priorities: an urgency `u` in
//! 0 to 7 (default 3) and an incremental boolean `i` (default false), carried
//! in the `Priority` header field or in a `PRIORITY_UPDATE` frame. A client
//! that only speaks the deprecated scheme gets [`Priority::DEFAULT`], which
//! is the compliant behaviour.
//!
//! [`Priority`] is a plain two-field value: `urgency() <= 7` always, and
//! nothing in this module can construct one outside that range.
//!
//! # The `Priority` field grammar this module accepts
//!
//! The `Priority` field is an RFC 8941 structured-field dictionary, but only
//! two members of it matter here, so [`parse_priority_field`] parses a
//! deliberately restricted subset rather than pulling in a general
//! structured-fields implementation: a comma-separated list of `key` or
//! `key=value` members, where `key` is 1 to 8 lowercase ASCII letters,
//! `value` is either an integer (`-?1*DIGIT`) or a boolean (`?0` or `?1`),
//! and parameters after a `;` are skipped. Unknown keys are ignored (RFC 9218
//! Section 4.1 requires that). A malformed member makes the whole field
//! ignored rather than an error: RFC 8941 Section 4.2 says a field that fails
//! to parse must be treated as if it were not present, and refusing a
//! request over a priority hint would be a denial of service handed to the
//! client.
//!
//! [`parse_priority_field`]'s algorithm:
//! 1. Start from [`Priority::DEFAULT`].
//! 2. A `"` byte anywhere in the value makes the whole field unparseable
//!    (there are no quoted strings in the subset this module accepts, so any
//!    quote is definitionally outside it); otherwise split the value on `,`
//!    at the top level.
//! 3. For each member: trim leading and trailing OWS, drop everything from
//!    the first `;`, then split at the first `=`. An out-of-shape or
//!    out-of-range value ignores the MEMBER, never the field, per RFC 9218
//!    Section 4.1.
//! 4. Return the accumulated [`Priority`].
//!
//! # `PRIORITY_UPDATE`
//!
//! [`parse_priority_update`] decodes the RFC 9218 Section 7.1 (HTTP/2) and
//! Section 7.2 (HTTP/3) frame payload: a prioritized element ID followed by
//! the same field-value syntax as above. On HTTP/2 the ID is a 4-byte
//! big-endian value with a reserved high bit that must be masked off; on
//! HTTP/3 it is a QUIC variable-length integer (RFC 9000 Section 16). The
//! variable-length integer decoder lives here, rather than coming from a
//! dependency, because this is the only place in this crate that needs one
//! and because it must never read past the end of a truncated input.

use crate::error::RejectReason;
use crate::field::trim_ows;
use crate::scalar::WireVersion;

/// An RFC 9218 extensible priority signal. Two integers, no graph.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Priority {
    /// Urgency, 0 (most urgent) to 7. Default 3.
    urgency: u8,
    /// Incremental delivery is useful for this response. Default false.
    incremental: bool,
}

impl Priority {
    /// `urgency: 3, incremental: false`, the RFC 9218 Section 4 defaults.
    pub const DEFAULT: Priority = Priority {
        urgency: 3,
        incremental: false,
    };

    /// Urgency, 0 (most urgent) to 7.
    #[must_use]
    pub const fn urgency(self) -> u8 {
        self.urgency
    }

    /// True when incremental delivery was requested.
    #[must_use]
    pub const fn incremental(self) -> bool {
        self.incremental
    }
}

/// Parses the restricted `sf-integer` subset this module accepts: an
/// optional leading `-` followed by one or more ASCII digits, and nothing
/// else. Returns `None` for anything outside that shape, including an empty
/// slice: that folds the empty-value edge case and the wrong-shape edge case
/// into the same outcome, which is exactly right, because the only caller
/// treats both identically (ignore the member).
///
/// Digits accumulate with `saturating_mul`/`saturating_add`, never a bare
/// `*`/`+`, so an arbitrarily long digit run saturates at `i64::MAX` (or, for
/// a leading `-`, negates to `i64::MIN`) instead of panicking on overflow. A
/// saturated magnitude is still outside the `0..=7` range the only caller
/// checks, so the difference between "very large" and "too large to
/// represent exactly" is never observable.
fn parse_restricted_integer(value: &[u8]) -> Option<i64> {
    // Equivalent mutant, confirmed by hand: deleting the `Some((&b'-', ..))`
    // arm here (so a leading `-` is scanned as an ordinary, non-digit byte
    // and the whole value is rejected as malformed) changes NOTHING
    // observable. The only caller, `apply_member`'s `u` arm, immediately
    // narrows the result through `u8::try_from`, which fails for every
    // negative value exactly as it fails for `None`; a negative urgency is
    // never in `0..=7` under either outcome, so "syntactically invalid" and
    // "syntactically valid but negative" are indistinguishable from outside
    // this function.
    let (negative, digits) = match value.split_first() {
        Some((&b'-', rest)) => (true, rest),
        _ => (false, value),
    };
    if digits.is_empty() {
        return None;
    }
    let mut magnitude: i64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = i64::from(b.saturating_sub(b'0'));
        magnitude = magnitude.saturating_mul(10).saturating_add(digit);
    }
    Some(if negative {
        magnitude.saturating_neg()
    } else {
        magnitude
    })
}

/// Applies one already-trimmed, semicolon-truncated dictionary member to
/// `priority`. Step 3 of the algorithm in the module doc comment.
///
/// An unknown key, and a known key whose value is the wrong shape or out of
/// range, leave `priority` untouched: RFC 9218 Section 4.1 requires ignoring
/// both, never the whole field.
fn apply_member(member: &[u8], priority: &mut Priority) {
    let (key, value): (&[u8], Option<&[u8]>) =
        member
            .iter()
            .position(|&b| b == b'=')
            .map_or((member, None), |idx| {
                let key = member.get(..idx).unwrap_or(&[]);
                let val = member.get(idx.saturating_add(1)..).unwrap_or(&[]);
                (key, Some(val))
            });

    // "1 to 8 lowercase ASCII letters": RFC 9218 defines only `u` and `i`,
    // both a single letter, so this bound never excludes a key this module
    // acts on. It exists so an unrecognized key is rejected in bounded work
    // rather than by a scan to the next delimiter.
    //
    // Equivalent mutants, confirmed by hand: every one of `||` to `&&` on
    // this line, and `>` to `==` or `>=` in the length comparison, is
    // unobservable. The `match` below recognizes only the exact one-byte
    // slices `b"u"` and `b"i"`, both of which trivially satisfy every
    // clause of this guard (non-empty, length 1, lowercase) under any
    // rewrite of it; every OTHER key falls to the match's `_` arm whether
    // or not this guard fires first. Weakening or disabling this guard
    // therefore cannot change which key reaches which match arm, only how
    // much work is spent before an unrecognized key is dropped.
    if key.is_empty() || key.len() > 8 || !key.iter().all(u8::is_ascii_lowercase) {
        return;
    }

    match key {
        b"u" => {
            let Some(raw) = value else { return };
            let Some(parsed) = parse_restricted_integer(raw) else {
                return;
            };
            if let Ok(urgency) = u8::try_from(parsed)
                && urgency <= 7
            {
                priority.urgency = urgency;
            }
        }
        b"i" => match value {
            // RFC 8941 Section 3.2: a bare dictionary key (no `=`) has the
            // boolean value `?1`, so a bare `i` and an explicit `i=?1` are
            // the same case.
            None | Some(b"?1") => priority.incremental = true,
            Some(b"?0") => priority.incremental = false,
            Some(_) => {}
        },
        _ => {}
    }
}

/// Parses an RFC 9218 `Priority` field value.
///
/// Never fails: an unparseable field yields [`Priority::DEFAULT`], because
/// RFC 8941 Section 4.2 says a field that fails to parse is treated as if it
/// were not present, and because refusing a request over a priority hint
/// would hand the client a denial of service. Unknown dictionary keys and
/// out-of-range values are ignored per RFC 9218 Section 4.1.
#[must_use]
pub fn parse_priority_field(value: &[u8]) -> Priority {
    // Step 2, the bail-out half: the restricted subset this module accepts
    // has no quoted strings, so a `"` byte anywhere puts the field outside
    // that subset. RFC 8941 Section 4.2 then treats the whole field as
    // absent.
    if value.contains(&b'"') {
        return Priority::DEFAULT;
    }

    let mut priority = Priority::DEFAULT;

    // Step 2, the split half: comma separated at the top level. No quoted
    // string can remain past the check above, so a plain byte split is exact
    // for this restricted subset.
    for member in value.split(|&b| b == b',') {
        // Step 3: trim OWS, then drop everything from the first `;`.
        let trimmed = trim_ows(member);
        let truncated = trimmed
            .iter()
            .position(|&b| b == b';')
            .map_or(trimmed, |idx| trimmed.get(..idx).unwrap_or(trimmed));
        apply_member(truncated, &mut priority);
    }

    priority
}

/// Reads a big-endian `u32` from the first 4 bytes of `bytes`, or `None` if
/// fewer than 4 bytes are present. Never reads past `bytes.len()`.
fn read_u32_be(bytes: &[u8]) -> Option<u32> {
    let b0 = *bytes.first()?;
    let b1 = *bytes.get(1)?;
    let b2 = *bytes.get(2)?;
    let b3 = *bytes.get(3)?;
    // Equivalent mutant, confirmed by hand: every `|` below stays `|` to
    // `^` at the same three join points forever, for any input, because
    // each shifted term occupies its own 8-bit lane (bits 24 to 31, 16 to
    // 23, 8 to 15, and 0 to 7 respectively) and two operands with disjoint
    // set bits produce the same result whether combined with `|` or `^`.
    // Only a `|` to `&` rewrite is a real bug (it can zero out an already
    // computed lane), which `update_frame_corpus`'s all-distinct-bytes case
    // exists to catch.
    Some((u32::from(b0) << 24) | (u32::from(b1) << 16) | (u32::from(b2) << 8) | u32::from(b3))
}

/// Decodes one QUIC variable-length integer (RFC 9000 Section 16) from the
/// start of `input`. Returns the decoded value and the number of bytes it
/// occupied, or `None` if `input` does not hold that many bytes. Never reads
/// past `input.len()`.
fn decode_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len: usize = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let bytes = input.get(..len)?;
    let mut value = u64::from(first & 0x3F);
    for &b in bytes.iter().skip(1) {
        // Equivalent mutant, confirmed by hand: `|` to `^` here changes
        // nothing observable, for any input, because `value << 8` always
        // clears its own low 8 bits immediately before this combines them
        // with `b` (which occupies only those same 8 bits), so the two
        // operands never share a set bit and `|`/`^` agree by construction.
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

/// Parses a `PRIORITY_UPDATE` frame payload: a prioritized element ID
/// followed by the same syntax as the `Priority` field.
///
/// On HTTP/2 the ID is a 4-byte big-endian value with a reserved high bit;
/// on HTTP/3 it is a QUIC variable-length integer.
///
/// # Errors
/// `RequestLineMalformed` when the ID is truncated. The caller maps that to
/// `FRAME_SIZE_ERROR` on HTTP/2 or `H3_FRAME_ERROR` on HTTP/3.
pub fn parse_priority_update(
    payload: &[u8],
    version: WireVersion,
) -> Result<(u64, Priority), RejectReason> {
    let (id, rest): (u64, &[u8]) = match version {
        WireVersion::H2 => {
            let raw = read_u32_be(payload).ok_or(RejectReason::RequestLineMalformed)?;
            let id = u64::from(raw & 0x7FFF_FFFF);
            (id, payload.get(4..).unwrap_or(&[]))
        }
        WireVersion::H3 => {
            let (value, len) = decode_varint(payload).ok_or(RejectReason::RequestLineMalformed)?;
            (value, payload.get(len..).unwrap_or(&[]))
        }
        WireVersion::Http10 | WireVersion::Http11 => {
            // PRIORITY_UPDATE (RFC 9218 Section 7) exists only on the two
            // multiplexed wire formats. A caller reaching this function with
            // an HTTP/1 version has already misidentified the frame layer
            // upstream; refusing as malformed is the safe default rather
            // than treating an input that cannot occur as well formed.
            return Err(RejectReason::RequestLineMalformed);
        }
    };
    Ok((id, parse_priority_field(rest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4096-byte field of `u=1,` repeated: edge case 18, the adversarial
    /// input that keeps the linear-time claim checkable. Built as a fixed
    /// array with a manually cycled index rather than a dynamically grown
    /// heap buffer: this file's zero-allocation claim is checked by a grep
    /// over the whole file, tests included.
    fn adversarial_4096b_field() -> [u8; 4096] {
        let pattern = *b"u=1,";
        let mut buf = [0u8; 4096];
        let mut p = 0usize;
        for slot in &mut buf {
            *slot = pattern[p];
            p = if p == 3 { 0 } else { p.saturating_add(1) };
        }
        buf
    }

    #[test]
    fn field_corpus() {
        // Edge cases 1 through 19. One table entry per case, including the
        // generated case (18) and the non-UTF-8 case (19), so a change to
        // the parser cannot dodge coverage by targeting whichever case lives
        // outside "the table".
        let adversarial = adversarial_4096b_field();
        let cases: [(&[u8], (u8, bool)); 24] = [
            (b"", (3, false)),               // 1
            (b"u=0", (0, false)),            // 2
            (b"u=7", (7, false)),            // 2
            (b"u=8", (3, false)),            // 3
            (b"u=-1", (3, false)),           // 3
            (b"u=99", (3, false)),           // 3
            (b"u=3.5", (3, false)),          // 4
            (b"i", (3, true)),               // 5
            (b"i=?1", (3, true)),            // 6
            (b"i=?0", (3, false)),           // 6
            (b"i=1", (3, false)),            // 7
            (b"u=1, i", (1, true)),          // 8
            (b"i, u=1", (1, true)),          // 9
            (b"u=1, u=5", (5, false)),       // 10
            (b"U=1", (3, false)),            // 11
            (b"u=1;p=9", (1, false)),        // 12
            (b"unknown=4, u=2", (2, false)), // 13
            (b"u=\"1\"", (3, false)),        // 14
            (b"   u=1   ", (1, false)),      // 15
            (b"u=", (3, false)),             // 16
            (b",,,", (3, false)),            // 17
            (&adversarial, (1, false)),      // 18
            (b"\xffbad=1,u=2", (2, false)),  // 19
            // Beyond the specified edge cases: case 12 covers a `;` alone
            // and case 15 covers leading OWS alone, but neither combines
            // them. Hand mutation found that computing the `;` position
            // against the TRIMMED member but then slicing the UNTRIMMED
            // one survives every one of cases 1 through 19: the two bases
            // only disagree when there is leading OWS before a `;` in the
            // same member, which is exactly this input.
            (b"   u=1;p=9", (1, false)),
        ];

        for (idx, (input, (urgency, incremental))) in cases.into_iter().enumerate() {
            let got = parse_priority_field(input);
            assert_eq!(got.urgency(), urgency, "case {idx}: urgency mismatch");
            assert_eq!(
                got.incremental(),
                incremental,
                "case {idx}: incremental mismatch"
            );
        }
    }

    #[test]
    fn out_of_range_ignores_the_member_not_the_field() {
        // Edge cases 3 and 4: none of these change urgency away from the
        // default, and none of them touch incremental.
        let cases: [&[u8]; 4] = [b"u=8", b"u=-1", b"u=99", b"u=3.5"];
        for input in cases {
            let got = parse_priority_field(input);
            assert_eq!(got.urgency(), 3, "{input:?} must leave urgency at default");
            assert!(!got.incremental(), "{input:?} must leave incremental false");
        }

        // The out-of-range `u` member is ignored on its own; the `i` member
        // in the same field is still applied.
        let got = parse_priority_field(b"u=8, i");
        assert_eq!(got.urgency(), 3);
        assert!(got.incremental());
    }

    #[test]
    fn update_frame_corpus() {
        // Edge case 20.
        assert_eq!(
            parse_priority_update(b"", WireVersion::H2),
            Err(RejectReason::RequestLineMalformed)
        );
        // Edge case 21.
        assert_eq!(
            parse_priority_update(b"\x00\x00\x00\x05", WireVersion::H2),
            Ok((5, Priority::DEFAULT))
        );
        // Edge case 22: the reserved high bit is masked off.
        assert_eq!(
            parse_priority_update(b"\x80\x00\x00\x05", WireVersion::H2),
            Ok((5, Priority::DEFAULT))
        );
        // Edge case 23.
        let (id, priority) = parse_priority_update(b"\x00\x00\x00\x05u=1", WireVersion::H2)
            .expect("a well formed H2 PRIORITY_UPDATE payload must parse");
        assert_eq!(id, 5);
        assert_eq!(priority.urgency(), 1);

        // Edge case 24: a 1-byte varint.
        assert_eq!(
            parse_priority_update(b"\x05", WireVersion::H3),
            Ok((5, Priority::DEFAULT))
        );
        // Edge case 25: a 2-byte varint.
        assert_eq!(
            parse_priority_update(b"\x40\x05", WireVersion::H3),
            Ok((5, Priority::DEFAULT))
        );
        // Edge case 26: an 8-byte varint with only 2 bytes present.
        assert_eq!(
            parse_priority_update(b"\xc0\x00", WireVersion::H3),
            Err(RejectReason::RequestLineMalformed)
        );
        // Edge case 27.
        assert_eq!(
            parse_priority_update(b"", WireVersion::H3),
            Err(RejectReason::RequestLineMalformed)
        );

        // Beyond the specified edge cases: `cargo mutants` (serial, -j 1)
        // found that edge cases 20 through 23 use only 0x00 and 0x80 for
        // every byte but the last, so every mutation to `read_u32_be`'s
        // shift amounts or its first two `|` joins is invisible (0 shifted
        // either direction is still 0, and ORing or ANDing with 0 both give
        // the other operand back). A byte sequence with four distinct
        // nonzero bytes closes that gap: the reserved bit is 0 here, so no
        // masking happens, and the expected value below is
        // `0x01 << 24 | 0x02 << 16 | 0x03 << 8 | 0x04`.
        assert_eq!(
            parse_priority_update(b"\x01\x02\x03\x04", WireVersion::H2),
            Ok((16_909_060, Priority::DEFAULT))
        );

        // Same reasoning for HTTP/3: edge cases 24 through 26 never
        // exercise the `2 => 4` length-4 varint arm (`cargo mutants` deleted
        // it and nothing failed), and their multi-byte case (edge case 26,
        // truncated) never reaches the accumulation loop with more than one
        // trailing zero byte, so a `<<` to `>>` mutation there was also
        // invisible. `0x80` selects the 4-byte form (top two bits `10`);
        // `0x01, 0x02, 0x03` are distinct and nonzero, so the expected
        // value below, `0x01 << 16 | 0x02 << 8 | 0x03`, is only reachable
        // through correct left shifts accumulating in the correct order.
        assert_eq!(
            parse_priority_update(b"\x80\x01\x02\x03", WireVersion::H3),
            Ok((66_051, Priority::DEFAULT))
        );
    }

    #[test]
    fn varint_never_reads_past_the_end() {
        let full: [u8; 8] = [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        for len in 0..full.len() {
            let prefix = &full[..len];
            assert_eq!(
                parse_priority_update(prefix, WireVersion::H3),
                Err(RejectReason::RequestLineMalformed),
                "a prefix of length {len} must be rejected as truncated, never read past"
            );
        }
        assert_eq!(
            parse_priority_update(&full, WireVersion::H3),
            Ok((5, Priority::DEFAULT))
        );
    }

    proptest::proptest! {
        #[test]
        fn prop_field_never_panics(
            v in proptest::collection::vec(
                proptest::prop_oneof![
                    b'a'..=b'z',
                    proptest::prelude::Just(b'='),
                    proptest::prelude::Just(b','),
                    proptest::prelude::Just(b';'),
                    proptest::prelude::Just(b'?'),
                    b'0'..=b'9',
                    proptest::prelude::any::<u8>(),
                ],
                0..=256,
            )
        ) {
            let p = parse_priority_field(&v);
            proptest::prop_assert!(p.urgency() <= 7);
        }
    }
}
