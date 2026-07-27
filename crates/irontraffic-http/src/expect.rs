// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`check_expect`], the exact-match `Expect: 100-continue` policy, and
//! [`InterimBudget`], which bounds the interim (1xx) responses relayed for
//! one request.
//!
//! **`check_expect` is an exact-match policy, not a token-list parse.** RFC
//! 9110 Section 10.1.1 defines exactly one expectation, `100-continue`. This
//! crate refuses any `Expect` value that is not, byte for byte after ASCII
//! case folding and OWS trimming, `100-continue`: not a prefix, not a
//! substring, not a comma-separated list containing it. `Expect: y
//! 100-continue`, `Expect: 100-continue, x`, `Expect: 100-continue\t` and
//! the rest of that family are the obfuscated-`Expect` desync gadget
//! described in CVE-2025-32094 (Akamai, 74 bounties totalling $221,000) and
//! the `PortSwigger` research describing the escape from a 0.CL deadlock
//! (GitLab, `LastPass`, T-Mobile findings): an intermediary that tolerates an
//! expectation it does not fully understand hands the origin, which may
//! parse it differently, the exact disagreement smuggling needs. Refusing
//! the obfuscated form removes the gadget outright rather than mitigating
//! it, which is stricter than RFC 9110's own MAY-417 permission for a
//! server and its MUST-417-when-the-next-hop-cannot-meet-it rule for a
//! proxy; that is a deliberate choice, not a reading of either rule.
//!
//! **A 1xx is not a final response,** and an upstream is free to send more
//! than one (RFC 8297's `103 Early Hints` is the standing example with no
//! natural size bound). [`InterimBudget`] bounds the interim responses
//! relayed for one request so an upstream cannot turn that freedom into an
//! unbounded memory and CPU cost on this proxy and on a downstream client
//! that must buffer every one it is handed. It is charged on RECEIPT of
//! every interim response, whether or not that response is actually
//! relayable (see [`InterimBudget::may_relay`]): dropping an unrelayable 1xx
//! without charging it would make an HTTP/1.0 client the cheapest way to
//! open an unmetered 1xx channel to this proxy.

use crate::error::RejectReason;
use crate::field::trim_ows;
use crate::known::KnownHeader;
use crate::limits::ClampedLimits;
use crate::scalar::WireVersion;
use crate::section::FieldSection;

/// What to do about an inbound `Expect` field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExpectAction {
    /// No `Expect` field was present. Forward as-is.
    None,
    /// `Expect: 100-continue` and the body will be streamed: forward the
    /// field and relay the upstream's interim response.
    ForwardToUpstream,
    /// `Expect: 100-continue` and the body will be buffered: answer
    /// `100 Continue` ourselves and strip the field before forwarding.
    AnswerLocally,
}

/// Decides what to do about an inbound `Expect` field.
///
/// Any value that is not ASCII-case-insensitively `100-continue` after OWS
/// trimming is refused with 417 rather than ignored or forwarded. This
/// removes the obfuscated-`Expect` desync gadget family instead of
/// mitigating it: see the module doc comment above.
///
/// The comparison is a single trimmed, whole-value, case-insensitive
/// equality check: not a token-list parse, not a prefix match, and never
/// `contains`, `starts_with`, or `split`. `Expect: 100-continue, x` fails
/// because the OWS-trimmed value is `100-continue, x`, the whole value,
/// compared as one string against `100-continue`.
///
/// # Errors
/// `ExpectUnsupported` for any other value, and for a duplicated `Expect`
/// field.
pub fn check_expect(
    fields: &FieldSection,
    will_buffer: bool,
) -> Result<ExpectAction, RejectReason> {
    let v = fields
        .get_unique_known(KnownHeader::Expect)
        .map_err(|_| RejectReason::ExpectUnsupported)?;
    let Some(v) = v else {
        return Ok(ExpectAction::None);
    };
    let t = trim_ows(v);
    if !t.eq_ignore_ascii_case(b"100-continue") {
        return Err(RejectReason::ExpectUnsupported);
    }
    Ok(if will_buffer {
        ExpectAction::AnswerLocally
    } else {
        ExpectAction::ForwardToUpstream
    })
}

/// Bounds the interim (1xx) responses relayed for one request.
///
/// Deliberately NOT `Copy`, for the same reason as `HeaderListBudget` in
/// `uncompressed-header-list-budget` (#25): a relay loop written `fn
/// relay(mut budget: InterimBudget)` charges a copy, the owner's budget
/// never moves, and an upstream can then emit unbounded `103 Early Hints`
/// with no error and no failing test. Pass `&mut`.
#[derive(Clone, Debug)]
pub struct InterimBudget {
    count: u32,
    bytes: u64,
    max_count: u32,
    max_bytes: u64,
}

impl InterimBudget {
    /// A budget from the configured limits.
    ///
    /// Not a `const fn`: `ClampedLimits` exposes its fields only through a
    /// (non-const) `Deref` impl, and reading `limits.max_interim_responses`
    /// or `limits.max_interim_bytes` therefore requires calling that
    /// `deref`, which the language does not permit inside a `const fn`
    /// (`error[E0015]: cannot perform non-const deref coercion`); see
    /// `HeaderListBudget::new` in `hlist.rs` for the identical constraint
    /// hit first, on the same type, in `uncompressed-header-list-budget`
    /// (#25).
    #[must_use]
    pub fn new(limits: &ClampedLimits) -> Self {
        InterimBudget {
            count: 0,
            bytes: 0,
            max_count: limits.max_interim_responses,
            max_bytes: u64::from(limits.max_interim_bytes),
        }
    }

    /// Charges one received interim response by its head size in bytes.
    /// Call this on RECEIPT, before deciding whether to relay: see the
    /// module doc comment on why an unrelayable 1xx must still be charged.
    ///
    /// # Errors
    /// `InterimResponseCountExceeded`, `InterimResponseBytesExceeded`.
    pub fn charge(&mut self, head_bytes: usize) -> Result<(), RejectReason> {
        // Saturating throughout: a plain `+= 1` or `+=` panics on overflow in
        // a debug build, and no arithmetic on an attacker-influenced count or
        // byte total may panic.
        self.count = self.count.saturating_add(1);
        if self.count > self.max_count {
            return Err(RejectReason::InterimResponseCountExceeded);
        }
        let head_bytes = u64::try_from(head_bytes).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(head_bytes);
        if self.bytes > self.max_bytes {
            return Err(RejectReason::InterimResponseBytesExceeded);
        }
        Ok(())
    }

    /// False for an HTTP/1.0 client, which must never be sent a 1xx: 1xx was
    /// introduced by HTTP/1.1, and RFC 7231 Section 6.2 states "a server
    /// MUST NOT send a 1xx response to an HTTP/1.0 client except under
    /// experimental conditions" (the corresponding RFC 9110 section is
    /// 15.2, Informational 1xx; RFC 9112 Section 5 is Field Syntax and has
    /// no relevant subsection).
    #[must_use]
    pub const fn may_relay(client_version: WireVersion) -> bool {
        !matches!(client_version, WireVersion::Http10)
    }

    /// Interim responses charged so far.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Interim bytes charged so far.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::UnderscorePolicy;
    use crate::limits::Limits;
    use crate::section::FieldSectionBuilder;
    use bytes::BytesMut;

    /// Builds a `FieldSection` from `fields` under `WireVersion::Http11`,
    /// which (unlike the strict H2 profile `FieldSectionBuilder::push`
    /// always double-checks against) does not reject a value carrying
    /// leading or trailing OWS. That is what lets
    /// `exact_value_accepted` construct a field whose value still has its
    /// surrounding whitespace, to prove `check_expect` trims it itself
    /// rather than relying on an upstream caller having done so already.
    fn section_with(fields: &[(&[u8], &[u8])]) -> FieldSection {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for (name, value) in fields {
            builder
                .push_normalized(
                    &mut arena,
                    name,
                    UnderscorePolicy::Reject,
                    value,
                    WireVersion::Http11,
                )
                .expect("test fixture fields must be well formed under HTTP/1.1 rules");
        }
        builder.finish(&mut arena)
    }

    #[test]
    fn absent_expect() {
        let section = section_with(&[]);
        assert_eq!(check_expect(&section, false), Ok(ExpectAction::None));
        assert_eq!(check_expect(&section, true), Ok(ExpectAction::None));
    }

    #[test]
    fn exact_value_accepted() {
        for value in [&b"100-continue"[..], b"100-Continue", b"  100-continue  "] {
            let section = section_with(&[(b"expect", value)]);
            assert_eq!(
                check_expect(&section, false),
                Ok(ExpectAction::ForwardToUpstream),
                "{value:?}"
            );
            assert_eq!(
                check_expect(&section, true),
                Ok(ExpectAction::AnswerLocally),
                "{value:?}"
            );
        }
    }

    #[test]
    fn obfuscated_expect_rejected() {
        // CVE-2025-32094 (Akamai obfuscated-Expect CL.0 smuggling) and the
        // PortSwigger-documented GitLab/LastPass/T-Mobile findings: none of
        // these eight values is a case-insensitive, OWS-trimmed exact match
        // for `100-continue`, so every one of them must be refused rather
        // than tolerated.
        let cases: [&[u8]; 8] = [
            b"100-continue, x",
            b"y 100-continue",
            b"100continue",
            b"100-continue;x",
            b"",
            b"100-continue\t100-continue",
            b"\x0b100-continue",
            b"100-continue\x0c",
        ];
        for case in cases {
            let section = section_with(&[(b"expect", case)]);
            assert_eq!(
                check_expect(&section, false),
                Err(RejectReason::ExpectUnsupported),
                "{case:?}"
            );
        }
    }

    #[test]
    fn duplicate_expect_rejected() {
        let section = section_with(&[(b"expect", b"100-continue"), (b"expect", b"100-continue")]);
        assert_eq!(
            check_expect(&section, false),
            Err(RejectReason::ExpectUnsupported)
        );
    }

    #[test]
    fn interim_budget_bounds() {
        // Charging through a &mut borrow is visible to the owner: the
        // assertion below that fails if InterimBudget is ever made Copy and
        // passed by value, since a by-value budget would let the caller's
        // own copy silently diverge from what `six` charged. Defined first,
        // before any statement in this test, because clippy's
        // items-after-statements lint (correctly) treats a later item
        // definition as confusing regardless of what it depends on.
        fn six(b: &mut InterimBudget) {
            for _ in 0..6 {
                b.charge(1)
                    .expect("wide_count's max_interim_responses (1000) covers six charges");
            }
        }

        // Default limits: max_interim_responses = 5, max_interim_bytes =
        // 16384. The fifth charge succeeds; the sixth fails on count before
        // it ever looks at bytes.
        let limits = Limits::DEFAULT.clamped();
        let mut budget = InterimBudget::new(&limits);
        for i in 1..=5 {
            assert_eq!(budget.charge(100), Ok(()), "charge {i}");
        }
        assert_eq!(
            budget.charge(100),
            Err(RejectReason::InterimResponseCountExceeded)
        );

        // Raise max_count so the byte cap can be exercised on its own: a
        // charge that reaches exactly 16384 bytes succeeds, and the next
        // byte fails.
        let wide_count = Limits {
            max_interim_responses: 1000,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut budget2 = InterimBudget::new(&wide_count);
        assert_eq!(budget2.charge(16_384), Ok(()));
        assert_eq!(budget2.bytes(), 16_384);
        assert_eq!(
            budget2.charge(1),
            Err(RejectReason::InterimResponseBytesExceeded)
        );

        // usize::MAX saturates rather than wrapping.
        let mut budget3 = InterimBudget::new(&wide_count);
        assert_eq!(
            budget3.charge(usize::MAX),
            Err(RejectReason::InterimResponseBytesExceeded)
        );
        assert_eq!(budget3.bytes(), u64::MAX);

        assert!(!InterimBudget::may_relay(WireVersion::Http10));
        assert!(InterimBudget::may_relay(WireVersion::Http11));
        assert!(InterimBudget::may_relay(WireVersion::H2));
        assert!(InterimBudget::may_relay(WireVersion::H3));

        let mut owner = InterimBudget::new(&wide_count);
        six(&mut owner);
        assert_eq!(owner.count(), 6);
    }
}
