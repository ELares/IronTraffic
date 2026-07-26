// SPDX-License-Identifier: MIT OR Apache-2.0
//! The HPACK and QPACK decompression bomb defense.
//!
//! HPACK and QPACK are compression formats: a small number of compressed
//! bytes can expand into a large number of uncompressed bytes. A limit
//! checked *after* decode bounds nothing, because the memory was already
//! allocated to produce the value that failed the check. Everything in this
//! module exists to charge the uncompressed size of a header list as it is
//! decoded, incrementally, so a decode loop can abandon a hostile block
//! before it finishes materializing.
//!
//! [`HeaderListBudget`] is the sink an HPACK or QPACK decoder feeds every
//! emitted header into. [`CookieAccumulator`] concatenates `cookie` crumbs
//! per RFC 9113 Section 8.2.3 without charging anything, because every
//! crumb was already charged on emission: charging on concatenation instead
//! is Envoy CVE-2026-47774, an HTTP/2 header size limit that did not
//! account for uncompressed cookie bytes and gave an HPACK amplification
//! path to memory exhaustion. [`TableSizePolicy`] validates a dynamic table
//! size update against the value we advertised (RFC 7541 Section 6.3), the
//! other half of the same defense.
//!
//! This crate does not contain an HPACK or QPACK decoder; the decoders are
//! `h2`'s and `h3`'s, wired to this sink in a later milestone.

use bytes::BytesMut;
use smallvec::SmallVec;

use crate::error::RejectReason;
use crate::limits::ClampedLimits;

/// Charges the UNCOMPRESSED size of a header list as it is decoded.
///
/// One instance per header block. `charge` is called once per header the
/// decoder emits, before the header is stored anywhere and before any
/// cookie concatenation. The first call that would exceed the limit returns
/// an error and the caller MUST abandon the decode immediately: the point
/// of this type is that work is bounded by the limit, not by the input
/// size.
///
/// A trailer section is a SECOND block and gets its own instance, so one
/// message can charge up to `2 * max_header_list_bytes` (131072 by default)
/// across its lifetime. That is the number to size memory against; do not
/// assume one.
///
/// Deliberately NOT `Copy`. A `Copy` budget is silently bypassable: a
/// decode loop written `fn decode(mut budget: HeaderListBudget)` charges a
/// copy, the caller's budget never grows, and the bomb defense is off with
/// no compile error and no test failure. Pass `&mut`.
#[derive(Clone, Debug)]
pub struct HeaderListBudget {
    used: u64,
    limit: u64,
    count: u32,
    max_count: u32,
}

impl HeaderListBudget {
    /// Starts a budget for one header block.
    ///
    /// Not a `const fn`: `ClampedLimits` exposes its fields only through a
    /// (non-const) `Deref` impl, and reading `limits.max_header_list_bytes`
    /// or `limits.max_field_count` therefore requires calling that `deref`,
    /// which the language does not permit inside a `const fn` (`error[E0015]:
    /// cannot perform non-const deref coercion`). [`HeaderListBudget::with_limits`]
    /// below, which takes the two values directly, stays `const`.
    #[must_use]
    pub fn new(limits: &ClampedLimits) -> Self {
        Self::with_limits(limits.max_header_list_bytes, limits.max_field_count)
    }

    /// Starts a budget with explicit values, for tests and for the QPACK
    /// blocked-bytes path.
    #[must_use]
    #[allow(
        clippy::cast_lossless,
        reason = "u32 to u64 is a lossless widening; From is not yet callable in a const fn"
    )]
    pub const fn with_limits(max_header_list_bytes: u32, max_field_count: u32) -> Self {
        Self {
            used: 0,
            limit: max_header_list_bytes as u64,
            count: 0,
            max_count: max_field_count,
        }
    }

    /// Charges one decoded header. Call once per header the decoder emits,
    /// before storing it and before any cookie concatenation.
    ///
    /// # Errors
    /// `FieldCountExceeded` when the field count limit is passed;
    /// `HeaderListTooLarge` when the uncompressed byte limit is passed. On
    /// either error the caller MUST abandon the decode; the budget stays
    /// failed for every later call.
    pub fn charge(&mut self, name_len: usize, value_len: usize) -> Result<(), RejectReason> {
        // Step 1: the field count bounds index size and per-field work,
        // independently of the byte total below.
        self.count = self.count.saturating_add(1);
        if self.count > self.max_count {
            return Err(RejectReason::FieldCountExceeded);
        }

        // Step 2/3: RFC 7541 Section 4.1's entry-size formula. Every
        // addition saturates, including this one: a plain `name_len as u64
        // + value_len as u64 + 32` overflows and panics in a debug build
        // for `charge(usize::MAX, usize::MAX)`, exactly the input the
        // saturating form exists to survive.
        let entry = (name_len as u64)
            .saturating_add(value_len as u64)
            .saturating_add(32);
        self.used = self.used.saturating_add(entry);

        // Step 4: the byte total bounds memory. Checked separately from the
        // count above because the two limits bound different resources.
        if self.used > self.limit {
            return Err(RejectReason::HeaderListTooLarge);
        }

        debug_assert!(self.used <= self.limit);
        debug_assert!(self.count <= self.max_count);
        Ok(())
    }

    /// Bytes charged so far.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Headers charged so far.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Bytes still available against the byte budget. Zero once a `charge`
    /// has failed with `HeaderListTooLarge`.
    ///
    /// This tracks the BYTE budget only. A `charge` that failed with
    /// `FieldCountExceeded` instead leaves `used` untouched (the two
    /// limits bound different resources; see `charge`'s step order), so
    /// `remaining()` can still be nonzero after a failed charge. Check the
    /// `Result` `charge` returned, not `remaining() == 0`, to learn whether
    /// the budget has failed.
    ///
    /// Computed as `self.limit.saturating_sub(self.used)`. A failed
    /// `charge` deliberately leaves `used > limit`, so a plain
    /// `limit - used` would panic in a debug build on exactly the input
    /// this type exists to survive.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}

/// The accumulator's own ceiling on recorded crumbs, independent of any
/// budget. That ceiling exists so the accumulator's own index cannot grow
/// without bound even if a caller forgets to charge the budget.
pub const MAX_COOKIE_CRUMBS: usize = 256;

/// Joins `cookie` crumbs per RFC 9113 Section 8.2.3.
///
/// RFC 9113 Section 8.2.3 permits a client to split the `cookie` field into
/// multiple crumbs so that individual crumbs can be HPACK-indexed, and
/// requires an intermediary that forwards to HTTP/1 to concatenate them
/// with `"; "` (a semicolon then a space). Every crumb was already charged
/// against [`HeaderListBudget::charge`] before reaching here. This type
/// therefore charges NOTHING, and that is deliberate: charging on
/// concatenation instead of on emission is precisely Envoy CVE-2026-47774.
///
/// It stores `(offset, len)` pairs into a caller-supplied staging buffer,
/// so it does not own bytes: no `Vec<Vec<u8>>`, no `BytesMut` field.
#[derive(Debug, Default)]
pub struct CookieAccumulator {
    crumbs: SmallVec<[(u32, u32); 8]>,
    total_len: u32,
}

/// Returns the sub-slice of `staging` a recorded `(offset, len)` pair
/// names, or `None` if the pair falls outside `staging`. `offset` and
/// `len` are attacker-influenced (they describe HPACK/QPACK-decoded
/// cookie crumbs), so both are converted with `try_from` and combined with
/// `checked_add` rather than a bare cast or `+`.
fn crumb_slice(staging: &[u8], offset: u32, len: u32) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let length = usize::try_from(len).ok()?;
    let end = start.checked_add(length)?;
    staging.get(start..end)
}

impl CookieAccumulator {
    /// A new, empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one crumb as an `(offset, len)` pair into the caller's
    /// staging buffer.
    ///
    /// # Errors
    /// `FieldCountExceeded` when more than [`MAX_COOKIE_CRUMBS`] (256)
    /// crumbs are pushed.
    pub fn push(&mut self, offset: u32, len: u32) -> Result<(), RejectReason> {
        if self.crumbs.len() >= MAX_COOKIE_CRUMBS {
            return Err(RejectReason::FieldCountExceeded);
        }
        self.crumbs.push((offset, len));
        self.total_len = self.total_len.saturating_add(len);
        Ok(())
    }

    /// Number of crumbs recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.crumbs.len()
    }

    /// The recorded `(offset, len)` pairs, in push order. Exposed so a
    /// caller with exactly one crumb can push it directly without
    /// materializing a join buffer, which is the common case and the one
    /// that must not allocate.
    #[must_use]
    pub fn crumbs(&self) -> &[(u32, u32)] {
        &self.crumbs
    }

    /// True when no crumbs were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.crumbs.is_empty()
    }

    /// Exact number of bytes [`CookieAccumulator::join_into`] will write:
    /// `sum(len_i) + 2 * (n - 1)`, or 0 when empty.
    ///
    /// `total_len` is a running sum maintained by `push`, so this is O(1)
    /// and never re-walks the crumb index.
    #[must_use]
    pub fn joined_len(&self) -> u32 {
        let n = u32::try_from(self.crumbs.len()).unwrap_or(u32::MAX);
        self.total_len
            .saturating_add(2_u32.saturating_mul(n.saturating_sub(1)))
    }

    /// Writes the crumbs joined with `"; "` into `out`, reading them from
    /// `staging`.
    ///
    /// Returns the number of bytes written, which always equals
    /// [`CookieAccumulator::joined_len`]. Calling this twice on the same
    /// accumulator and staging buffer writes the same bytes both times;
    /// the accumulator is not consumed and holds no cursor.
    ///
    /// # Errors
    /// `HeaderListTooLarge` when any recorded `(offset, len)` pair is out
    /// of range for `staging`. That is a caller bug, and this function
    /// reports it instead of panicking. Every pair is checked before any
    /// byte is written, so a bad pair never leaves a truncated join in
    /// `out`.
    pub fn join_into(&self, staging: &[u8], out: &mut BytesMut) -> Result<u32, RejectReason> {
        for &(offset, len) in &self.crumbs {
            if crumb_slice(staging, offset, len).is_none() {
                return Err(RejectReason::HeaderListTooLarge);
            }
        }

        let before = out.len();
        for (i, &(offset, len)) in self.crumbs.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b"; ");
            }
            let slice =
                crumb_slice(staging, offset, len).ok_or(RejectReason::HeaderListTooLarge)?;
            out.extend_from_slice(slice);
        }

        // Derived from the bytes actually appended to `out`, not from
        // `joined_len()`. `joined_len` is a prediction the caller can check
        // BEFORE calling this; returning it here instead of the true
        // written count would make it impossible for any test, or any
        // future change to this function, to ever disagree with itself.
        u32::try_from(out.len().saturating_sub(before))
            .map_err(|_| RejectReason::HeaderListTooLarge)
    }
}

/// The compression dynamic-table sizes we advertise and enforce.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TableSizePolicy {
    /// Value advertised in `SETTINGS_HEADER_TABLE_SIZE` (H2) or
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (H3). Default 4096.
    pub advertised_max: u32,
}

impl TableSizePolicy {
    /// The shipped default: a 4096-byte dynamic table.
    pub const DEFAULT: TableSizePolicy = TableSizePolicy {
        advertised_max: 4096,
    };

    /// Validates a dynamic table size update received from the peer.
    ///
    /// RFC 7541 Section 6.3: an update larger than the value the decoder
    /// advertised is a decoding error.
    ///
    /// # Errors
    /// `HeaderListTooLarge` when `requested > advertised_max`. The HTTP/2
    /// wrapper maps this to `COMPRESSION_ERROR`. The HTTP/3 wrapper maps it
    /// to `QPACK_ENCODER_STREAM_ERROR`, not `QPACK_DECODER_STREAM_ERROR`:
    /// the offending `Set Dynamic Table Capacity` instruction arrives on
    /// the peer's ENCODER stream, and `QPACK_DECODER_STREAM_ERROR` is the
    /// code for bad data on the decoder stream.
    pub const fn check_update(&self, requested: u32) -> Result<(), RejectReason> {
        if requested > self.advertised_max {
            Err(RejectReason::HeaderListTooLarge)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    #[test]
    fn empty_budget_state() {
        let budget = HeaderListBudget::new(&Limits::DEFAULT.clamped());
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.count(), 0);
        assert_eq!(budget.remaining(), 65_536);
    }

    #[test]
    fn entry_overhead_is_32() {
        let mut budget = HeaderListBudget::with_limits(1_000, 10);
        assert_eq!(budget.charge(1, 1), Ok(()));
        assert_eq!(budget.used(), 34);
    }

    #[test]
    fn exact_limit_is_accepted() {
        let mut budget = HeaderListBudget::with_limits(100, 10);
        assert_eq!(budget.charge(34, 34), Ok(()));
        assert_eq!(budget.used(), 100);
        assert_eq!(budget.charge(0, 0), Err(RejectReason::HeaderListTooLarge));
    }

    #[test]
    fn failed_charge_poisons_the_budget() {
        let mut budget = HeaderListBudget::with_limits(100, 10);
        assert_eq!(budget.charge(34, 34), Ok(()));
        assert_eq!(budget.charge(0, 0), Err(RejectReason::HeaderListTooLarge));
        assert!(budget.used() > 100);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.charge(0, 0), Err(RejectReason::HeaderListTooLarge));
    }

    #[test]
    fn saturates_instead_of_wrapping() {
        let mut budget = HeaderListBudget::with_limits(65_536, 10);
        let result = budget.charge(usize::MAX, usize::MAX);
        assert_eq!(result, Err(RejectReason::HeaderListTooLarge));
        assert!(budget.used() > 65_536);
        // On a 32-bit target `usize::MAX as u64` is 4_294_967_295, so the
        // saturating sum below tops out at 8_589_934_622, not `u64::MAX`.
        // The unconditional form of this assertion would fail there while
        // the code under test was correct, so it is gated to 64-bit.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(budget.used(), u64::MAX);
    }

    #[test]
    fn count_limit_fires_before_byte_limit() {
        let mut budget = HeaderListBudget::with_limits(u32::MAX, 2);
        assert_eq!(budget.charge(1, 1), Ok(()));
        assert_eq!(budget.charge(1, 1), Ok(()));
        assert_eq!(budget.charge(1, 1), Err(RejectReason::FieldCountExceeded));
    }

    #[test]
    fn count_check_runs_before_any_byte_accounting() {
        // Design step order (1 then 2/3/4): the count check must run, and
        // must be able to fire, BEFORE the byte total is ever touched. A
        // charge that would fail BOTH checks distinguishes the two possible
        // orders: with `max_field_count = 0` the very first charge already
        // exceeds it, so if the count check truly runs first, `used()` is
        // never incremented at all. A mutant that swapped the two checks
        // would still return an `Err`, but a different reason and a
        // nonzero `used()`, so asserting only `is_err()` here would not
        // have caught it; both the exact reason and the untouched byte
        // total are checked. This also exercises edge case 6 (`max_count`
        // of 0): the first charge returns `FieldCountExceeded`.
        let mut budget = HeaderListBudget::with_limits(1, 0);
        let result = budget.charge(100, 100);
        assert_eq!(result, Err(RejectReason::FieldCountExceeded));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn cookie_crumbs_are_charged_individually() {
        // Envoy CVE-2026-47774: HTTP/2 header size limits did not account
        // for uncompressed cookie bytes, because the "cookie" special case
        // that concatenates crumbs per RFC 9113 Section 8.2.3 escaped the
        // accounting. 4000 crumbs of 1 byte each concatenate to
        // `4000 + 2 * 3999 = 11998` bytes, which passes a 64 KiB post-join
        // check; charged honestly at decode time, each crumb costs
        // `6 + 1 + 32 = 39` bytes and the true total is 156000, which does
        // not. This test proves the byte accounting fires long before the
        // join would.
        // CookieAccumulator::MAX_COOKIE_CRUMBS (256) is a separate,
        // independent ceiling and is far smaller than the 1680 crumbs the
        // byte budget accepts here, so this loop counts acceptances
        // directly against the budget rather than routing them through a
        // real accumulator (whose own ceiling would fire first and would
        // be testing a different defense than this test is about).
        let mut budget = HeaderListBudget::with_limits(65_536, u32::MAX);
        let mut accepted = 0_u32;
        for i in 0..4000_u32 {
            match budget.charge(6, 1) {
                Ok(()) => accepted += 1,
                Err(err) => {
                    assert_eq!(err, RejectReason::HeaderListTooLarge);
                    assert_eq!(
                        i, 1680,
                        "crumb 1681 (index 1680) is the one that crosses the limit"
                    );
                    break;
                }
            }
        }
        assert_eq!(accepted, 1680);
        // The joined length of the 1680 accepted crumbs, per
        // CookieAccumulator::joined_len's own `sum(len_i) + 2 * (n - 1)`
        // formula (each crumb here is 1 byte): far below the byte limit,
        // which proves that charging after concatenation would have let
        // all 4000 crumbs through.
        let joined_len_of_accepted = accepted + 2 * (accepted - 1);
        assert_eq!(joined_len_of_accepted, 5038);
        assert!(joined_len_of_accepted < 65_536);

        // The count limit under Limits::DEFAULT (max_field_count = 100)
        // fires first instead, because a crumb is a separate emitted
        // field.
        let mut default_budget = HeaderListBudget::new(&Limits::DEFAULT.clamped());
        for i in 0..4000_u32 {
            let result = default_budget.charge(6, 1);
            if i < 100 {
                assert_eq!(result, Ok(()), "crumb {i} should fit under max_field_count");
            } else {
                assert_eq!(result, Err(RejectReason::FieldCountExceeded));
                break;
            }
        }
    }

    #[test]
    fn joined_len_matches_bytes_written() {
        // Distinct, position-identifiable bytes: a wrong offset or a
        // swapped crumb changes the joined string instead of silently
        // producing the same bytes as the correct one.
        let staging: Vec<u8> = (0_u32..100).map(|i| b'a' + (i % 26) as u8).collect();

        let cases: [&[(u32, u32)]; 4] = [
            &[],
            &[(0, 7)],
            &[(10, 0), (20, 1)],
            &[
                (0, 7),
                (10, 0),
                (20, 1),
                (30, 7),
                (40, 0),
                (50, 1),
                (60, 7),
                (70, 0),
            ],
        ];

        for crumbs in cases {
            let mut accumulator = CookieAccumulator::new();
            for &(offset, len) in crumbs {
                accumulator
                    .push(offset, len)
                    .expect("well under MAX_COOKIE_CRUMBS");
            }

            let mut expected = Vec::new();
            for (i, &(offset, len)) in crumbs.iter().enumerate() {
                if i > 0 {
                    expected.extend_from_slice(b"; ");
                }
                let start = offset as usize;
                let end = start + len as usize;
                expected.extend_from_slice(&staging[start..end]);
            }

            let mut out = BytesMut::new();
            let written = accumulator
                .join_into(&staging, &mut out)
                .expect("every pair here is in range");
            assert_eq!(written, accumulator.joined_len());
            assert_eq!(written as usize, expected.len());
            assert_eq!(&out[..], &expected[..]);
        }
    }

    #[test]
    fn join_into_rejects_out_of_range_pairs() {
        let mut accumulator = CookieAccumulator::new();
        accumulator.push(10, 5).expect("well under the ceiling");
        let staging = [0_u8; 4];
        let mut out = BytesMut::new();
        let result = accumulator.join_into(&staging, &mut out);
        assert_eq!(result, Err(RejectReason::HeaderListTooLarge));
        assert!(out.is_empty());
    }

    #[test]
    fn join_into_validates_every_pair_before_writing_any_byte() {
        // A single out-of-range pair (as in
        // `join_into_rejects_out_of_range_pairs` above) cannot distinguish
        // "validate every pair, then write" from "validate and write one
        // pair at a time, stop at the first bad one": both produce the
        // same observable result (an error, nothing written) when the
        // very first pair is the bad one. Push a GOOD crumb first and a
        // BAD one second: a write-as-you-go implementation would already
        // have appended the good crumb's bytes to `out` by the time it
        // discovers the bad one, so `out` would be non-empty on return
        // despite the overall call failing. `staging` is long enough for
        // the good crumb and too short for the bad one.
        let staging = [b'x'; 4];
        let mut accumulator = CookieAccumulator::new();
        accumulator.push(0, 4).expect("fits staging exactly");
        accumulator.push(100, 5).expect("well under the ceiling");
        let mut out = BytesMut::new();
        let result = accumulator.join_into(&staging, &mut out);
        assert_eq!(result, Err(RejectReason::HeaderListTooLarge));
        assert!(
            out.is_empty(),
            "no byte may be written before every pair is validated"
        );
    }

    #[test]
    fn accumulator_crumb_ceiling() {
        let mut accumulator = CookieAccumulator::new();
        for i in 0..MAX_COOKIE_CRUMBS {
            assert_eq!(accumulator.push(0, 1), Ok(()), "crumb {i} should fit");
        }
        assert_eq!(
            accumulator.push(0, 1),
            Err(RejectReason::FieldCountExceeded)
        );
    }

    #[test]
    fn table_size_update_policy() {
        let policy = TableSizePolicy::DEFAULT;
        assert_eq!(policy.check_update(0), Ok(()));
        assert_eq!(policy.check_update(4096), Ok(()));
        assert_eq!(
            policy.check_update(4097),
            Err(RejectReason::HeaderListTooLarge)
        );
        assert_eq!(
            policy.check_update(u32::MAX),
            Err(RejectReason::HeaderListTooLarge)
        );
    }

    #[test]
    fn remaining_saturates_after_failure() {
        let mut budget = HeaderListBudget::with_limits(64, 10);
        assert_eq!(budget.charge(64, 64), Err(RejectReason::HeaderListTooLarge));
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn budget_is_not_copy() {
        // Compile-time marker only: Copy implies Clone, so this bound alone
        // would still compile even if HeaderListBudget were made Copy. It
        // names the property; the runtime assertion below is what actually
        // catches a regression.
        fn assert_not_copy<T: Clone>() {}

        // If HeaderListBudget were ever made Copy and a caller passed it by
        // value, charge_twice would charge a copy and `budget.count()`
        // below would read 0, not 2.
        fn charge_twice(budget: &mut HeaderListBudget) {
            budget.charge(1, 1).expect("fits under the default limit");
            budget.charge(1, 1).expect("fits under the default limit");
        }

        assert_not_copy::<HeaderListBudget>();
        let mut budget = HeaderListBudget::new(&Limits::DEFAULT.clamped());
        charge_twice(&mut budget);
        assert_eq!(budget.count(), 2);
    }

    proptest::proptest! {
        #[test]
        fn prop_budget_never_exceeds_limit(
            pairs in proptest::collection::vec((0_usize..=1024, 0_usize..=1024), 0..=200)
        ) {
            let mut budget = HeaderListBudget::with_limits(4096, 200);
            let mut already_failed = false;
            for (name_len, value_len) in pairs {
                let result = budget.charge(name_len, value_len);
                if already_failed {
                    assert!(result.is_err());
                } else {
                    match result {
                        Ok(()) => assert!(budget.used() <= 4096),
                        Err(_) => already_failed = true,
                    }
                }
            }
        }
    }

    // ---------- reviewer-proposed closing tests (append inside `mod tests`) ----------

    #[test]
    fn byte_ceiling_is_exact_to_one_byte() {
        // `exact_limit_is_accepted` proves the NEXT charge crosses, but the
        // smallest possible charge is 32 bytes, so it cannot distinguish
        // `used > limit` from `used > limit + k` for any k in 1..=31. Vary
        // the LIMIT by one byte with the charge held fixed instead.
        let mut at = HeaderListBudget::with_limits(33, 10);
        assert_eq!(at.charge(0, 1), Ok(()));
        assert_eq!(at.used(), 33);
        assert_eq!(at.remaining(), 0);

        let mut over = HeaderListBudget::with_limits(32, 10);
        assert_eq!(over.charge(0, 1), Err(RejectReason::HeaderListTooLarge));
    }

    #[test]
    fn saturated_budget_stays_failed_forever() {
        // `saturates_instead_of_wrapping` charges once, so step 3's
        // `self.used.saturating_add(entry)` can be a `wrapping_add` and the
        // suite stays green: `0.wrapping_add(u64::MAX)` is the same value. It
        // is the SECOND charge that tells them apart, and a wrapping
        // accumulator carries `used` back UNDER the limit there
        // (`u64::MAX.wrapping_add(32) == 31`), silently un-poisoning a budget
        // the caller was told stays failed.
        let mut budget = HeaderListBudget::with_limits(65_536, u32::MAX);
        assert_eq!(
            budget.charge(usize::MAX, usize::MAX),
            Err(RejectReason::HeaderListTooLarge)
        );
        let saturated = budget.used();
        for _ in 0..4 {
            assert_eq!(budget.charge(0, 0), Err(RejectReason::HeaderListTooLarge));
            assert!(budget.used() >= saturated);
            assert_eq!(budget.remaining(), 0);
        }
    }

    #[test]
    fn empty_field_still_costs_the_32_byte_overhead() {
        // Edge case 2: the overhead is per entry, not per byte.
        let mut budget = HeaderListBudget::with_limits(100, 10);
        assert_eq!(budget.charge(0, 0), Ok(()));
        assert_eq!(budget.used(), 32);
        assert_eq!(budget.count(), 1);
        assert_eq!(budget.remaining(), 68);
    }

    #[test]
    fn remaining_is_byte_headroom_not_a_health_flag() {
        // A count failure leaves `used` deliberately untouched (bytes and
        // count bound different resources), so `remaining()` is NOT zero
        // after one. That contradicts `remaining`'s summary line, "Zero once
        // the budget has failed", and edge case 17. Pin the real behaviour so
        // the doc is what changes, not the accounting.
        let mut budget = HeaderListBudget::with_limits(65_536, 1);
        assert_eq!(budget.charge(10, 10), Ok(()));
        assert_eq!(budget.charge(10, 10), Err(RejectReason::FieldCountExceeded));
        assert_eq!(budget.used(), 52);
        assert_eq!(budget.count(), 2);
        assert_eq!(budget.remaining(), 65_484);
    }

    #[test]
    fn crumb_ceiling_is_256_exactly() {
        // `accumulator_crumb_ceiling` loops `0..MAX_COOKIE_CRUMBS`, so it is
        // true for whatever that constant happens to be and pins no value.
        // Edge case 8 names 256 and 257; spell them.
        assert_eq!(MAX_COOKIE_CRUMBS, 256);
        let mut accumulator = CookieAccumulator::new();
        for i in 0..256_u32 {
            assert_eq!(accumulator.push(0, 1), Ok(()), "crumb {i} must fit");
        }
        assert_eq!(accumulator.len(), 256);
        assert_eq!(
            accumulator.push(0, 1),
            Err(RejectReason::FieldCountExceeded)
        );
    }

    #[test]
    fn accessors_report_the_recorded_crumbs() {
        // `len`, `is_empty` and `crumbs` are public and asserted nowhere.
        // `crumbs` is the one that matters: the documented single-crumb fast
        // path forwards the cookie straight out of it without building a join
        // buffer, so a `crumbs` that reported the wrong pairs would drop or
        // corrupt the cookie with no other test noticing.
        let mut accumulator = CookieAccumulator::new();
        assert!(accumulator.is_empty());
        assert_eq!(accumulator.len(), 0);
        assert!(accumulator.crumbs().is_empty());

        accumulator.push(3, 7).expect("first crumb");
        assert!(!accumulator.is_empty());
        assert_eq!(accumulator.len(), 1);
        assert_eq!(accumulator.crumbs(), &[(3, 7)]);

        accumulator.push(11, 0).expect("second crumb");
        assert_eq!(accumulator.len(), 2);
        assert_eq!(accumulator.crumbs(), &[(3, 7), (11, 0)]);
    }

    #[test]
    fn join_into_appends_and_never_clears_the_caller_buffer() {
        // `out` is caller-supplied and may already hold serialized headers, so
        // join_into must APPEND. Every other join test starts from an empty
        // BytesMut, which cannot tell append from overwrite.
        let staging = b"abcdefgh";
        let mut accumulator = CookieAccumulator::new();
        accumulator.push(0, 3).expect("first crumb");
        accumulator.push(4, 2).expect("second crumb");

        let mut out = BytesMut::from(&b"PRIOR"[..]);
        let written = accumulator.join_into(staging, &mut out).expect("in range");
        assert_eq!(&out[..], &b"PRIORabc; ef"[..]);
        // The returned length must describe only the bytes appended.
        assert_eq!(written as usize, out.len().saturating_sub(5));
    }

    #[test]
    fn two_empty_crumbs_join_to_just_the_separator() {
        // Edge case 10. `joined_len_matches_bytes_written` has no case where
        // two zero-length crumbs are adjacent.
        let staging = [b'z'; 4];
        let mut accumulator = CookieAccumulator::new();
        accumulator.push(0, 0).expect("first crumb");
        accumulator.push(4, 0).expect("second crumb");
        assert_eq!(accumulator.joined_len(), 2);
        let mut out = BytesMut::new();
        assert_eq!(accumulator.join_into(&staging, &mut out), Ok(2));
        assert_eq!(&out[..], b"; ");
    }

    #[test]
    fn join_into_is_repeatable() {
        // Edge case 12: the accumulator is not consumed and holds no cursor.
        let staging = b"abcdefgh";
        let mut accumulator = CookieAccumulator::new();
        accumulator.push(0, 3).expect("first crumb");
        accumulator.push(4, 2).expect("second crumb");

        let mut first = BytesMut::new();
        let a = accumulator
            .join_into(staging, &mut first)
            .expect("in range");
        let mut second = BytesMut::new();
        let b = accumulator
            .join_into(staging, &mut second)
            .expect("in range");
        assert_eq!(a, b);
        assert_eq!(first, second);
        assert_eq!(accumulator.len(), 2);
    }

    #[test]
    fn check_update_uses_this_policys_max_not_the_default() {
        // `table_size_update_policy` only ever exercises DEFAULT, so a
        // check_update that ignored `self` and compared against a hard-coded
        // 4096 passes it. A deployment advertising a SMALLER table would then
        // advertise one number and enforce another: the peer's encoder sets
        // capacity to 4096, we accept, and the dynamic table grows past the
        // size we advertised and sized memory for.
        let strict = TableSizePolicy { advertised_max: 0 };
        assert_eq!(strict.check_update(0), Ok(()));
        assert_eq!(
            strict.check_update(1),
            Err(RejectReason::HeaderListTooLarge)
        );

        let generous = TableSizePolicy {
            advertised_max: 8192,
        };
        assert_eq!(generous.check_update(4097), Ok(()));
        assert_eq!(generous.check_update(8192), Ok(()));
        assert_eq!(
            generous.check_update(8193),
            Err(RejectReason::HeaderListTooLarge)
        );
    }

    #[test]
    fn budget_is_not_copy_at_compile_time() {
        // `budget_is_not_copy`'s `T: Clone` bound is satisfied by a Copy type
        // too, and its runtime half passes `&mut`, which works either way.
        // This probe actually answers the question: the inherent const is
        // selected over the trait const only when `T: Copy` holds.
        struct Probe<T>(core::marker::PhantomData<T>);
        trait NotCopy {
            const IS_COPY: bool = false;
        }
        impl<T> NotCopy for Probe<T> {}
        impl<T: Copy> Probe<T> {
            const IS_COPY: bool = true;
        }
        // `const` blocks so a regression is a COMPILE error, not a test
        // failure. `TableSizePolicy` is the positive control and proves the
        // probe can still say "yes".
        const { assert!(!<Probe<HeaderListBudget>>::IS_COPY) }
        const { assert!(<Probe<TableSizePolicy>>::IS_COPY) }
    }
}
