// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `SETTINGS` values IronTraffic advertises, and [`QpackBlockedBytes`],
//! the byte ceiling that makes raising `qpack_blocked_streams` above zero
//! safe.
//!
//! [`SettingsPolicy`] is one flat table of values we ADVERTISE to a peer.
//! [`SettingsPolicy::validate`] exists so a configuration that advertises one
//! number and enforces another fails at load time rather than at traffic
//! time: advertising a limit we do not enforce, or enforcing a limit we did
//! not advertise, is how a peer gets refused for obeying us.
//!
//! `qpack_blocked_streams` defaults to 0 (RFC 9204 Section 2.1.2: more
//! blocked streams than promised is a connection error of type
//! `QPACK_DECOMPRESSION_FAILED`). Zero blocked streams means an encoder may
//! never reference a dynamic-table entry that is still in flight, which
//! closes the whole class of bug behind Envoy GHSA-p7c7-7c47-pwch: bytes
//! retained by a blocked QPACK decode were released from QUIC flow-control
//! accounting while still held in a heap buffer, so flow control did not
//! bound memory. Raising the setting is safe only once [`QpackBlockedBytes`]
//! is wired to charge those retained bytes against the same
//! `max_header_list_size` the header-list budget already enforces; there is
//! deliberately no separate `qpack_blocked_bytes` configuration field, since
//! a second knob for the same quantity could only disagree with the first.
//!
//! `SettingsPolicy::validate` runs once, at configuration load time, never
//! per request, so it carries no benchmark.

use irontraffic_http::hlist::TableSizePolicy;
use irontraffic_http::{ClampedLimits, RejectReason};

/// The `SETTINGS` values IronTraffic advertises, and the matching local
/// limits.
///
/// Advertised and enforced values are the SAME numbers: advertising a header
/// list size we do not enforce, or enforcing a concurrency limit we did not
/// advertise, is how a peer gets refused for obeying us.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SettingsPolicy {
    /// `SETTINGS_HEADER_TABLE_SIZE` (H2). Must equal `qpack_max_table_capacity`
    /// and the compression-table policy's `advertised_max`.
    pub header_table_size: u32,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`. Must equal the connection budget's
    /// protocol concurrency limit.
    pub max_concurrent_streams: u32,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`: the per-stream flow-control window, in
    /// bytes. Must not exceed the RFC 9113 Section 6.9.1 limit of
    /// `2^31 - 1`.
    pub initial_stream_window: u32,
    /// The connection-level flow-control window, in bytes. This is the
    /// number that bounds per-connection receive memory, not the sum of the
    /// stream windows.
    pub initial_connection_window: u32,
    /// `SETTINGS_MAX_FRAME_SIZE`. Must be within the RFC 9113 Section 6.5.2
    /// range 16384 to 16777215 inclusive.
    pub max_frame_size: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`. Must equal the header-list budget's
    /// enforced ceiling.
    pub max_header_list_size: u32,
    /// `SETTINGS_ENABLE_PUSH`. Server push is dead; this is always false in
    /// the shipped default.
    pub enable_push: bool,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (identifier `0x8` on both H2 and
    /// H3): extended CONNECT, which is how WebSocket works over H2 and H3.
    pub enable_connect_protocol: bool,
    /// `SETTINGS_NO_RFC7540_PRIORITIES` (identifier `0x9`). True means the
    /// deprecated RFC 7540 priority-tree scheme is not honoured; only RFC
    /// 9218 extensible priorities are.
    pub no_rfc7540_priorities: bool,
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (H3). Must equal
    /// `header_table_size` and the compression-table policy's
    /// `advertised_max`.
    pub qpack_max_table_capacity: u32,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`. Zero by default; see the module doc
    /// for why raising it needs [`QpackBlockedBytes`].
    pub qpack_blocked_streams: u16,
    /// The number of unacknowledged PINGs tolerated before treating another
    /// one as a ping flood.
    pub max_outstanding_pings: u8,
    /// `WINDOW_UPDATE` is emitted once consumption reaches this percentage of
    /// the window, never per DATA frame. Must be in 1 to 100 inclusive.
    pub window_update_high_water_percent: u8,
}

impl SettingsPolicy {
    /// The shipped defaults, written as a literal so no field has to be
    /// matched to a position in a prose list.
    pub const DEFAULT: SettingsPolicy = SettingsPolicy {
        header_table_size: 4096,
        max_concurrent_streams: 128,
        initial_stream_window: 262_144,
        initial_connection_window: 1_048_576,
        max_frame_size: 16_384,
        max_header_list_size: 65_536,
        enable_push: false,
        enable_connect_protocol: true,
        no_rfc7540_priorities: true,
        qpack_max_table_capacity: 4096,
        qpack_blocked_streams: 0,
        max_outstanding_pings: 2,
        window_update_high_water_percent: 50,
    };

    /// The RFC 9113 Section 6.5.2 range `SETTINGS_MAX_FRAME_SIZE` is legal in.
    const MAX_FRAME_SIZE_RANGE: core::ops::RangeInclusive<u32> = 16_384..=16_777_215;

    /// RFC 9113 Section 6.9.1: a flow-control window may never exceed
    /// `2^31 - 1`.
    const MAX_FLOW_CONTROL_WINDOW: u32 = 2_147_483_647;

    /// Checks the policy for internal consistency: that every value this
    /// type advertises agrees with the value the rest of the connection
    /// stack actually enforces.
    ///
    /// This runs once, at configuration load time, never per request, so it
    /// carries no benchmark.
    ///
    /// # Errors
    /// `HeaderListTooLarge` when `max_header_list_size` disagrees with
    /// `limits.max_header_list_bytes`, or when `header_table_size` or
    /// `qpack_max_table_capacity` disagrees with `table`'s `advertised_max`
    /// (the value `TableSizePolicy::check_update` actually enforces);
    /// `FieldCountExceeded` when `max_concurrent_streams` disagrees with
    /// `max_concurrent_proto`; `ContentLengthInvalid` when `max_frame_size`
    /// is outside the RFC 9113 range 16384 to 16777215, when
    /// `initial_stream_window` exceeds 2147483647, or when
    /// `window_update_high_water_percent` is 0 or above 100.
    ///
    /// Three distinct disagreements share `HeaderListTooLarge`. That is
    /// deliberate (no new variant may be added for a configuration fault),
    /// and it costs nothing because `validate` runs at load time over a
    /// value the operator wrote: perturb one field at a time and the cases
    /// stay distinguishable by construction.
    pub fn validate(
        &self,
        limits: &ClampedLimits,
        table: &TableSizePolicy,
        max_concurrent_proto: u32,
    ) -> Result<(), RejectReason> {
        if self.max_header_list_size != limits.max_header_list_bytes {
            return Err(RejectReason::HeaderListTooLarge);
        }
        if self.header_table_size != table.advertised_max {
            return Err(RejectReason::HeaderListTooLarge);
        }
        if self.qpack_max_table_capacity != table.advertised_max {
            return Err(RejectReason::HeaderListTooLarge);
        }
        if self.max_concurrent_streams != max_concurrent_proto {
            return Err(RejectReason::FieldCountExceeded);
        }
        if !Self::MAX_FRAME_SIZE_RANGE.contains(&self.max_frame_size) {
            return Err(RejectReason::ContentLengthInvalid);
        }
        if self.initial_stream_window > Self::MAX_FLOW_CONTROL_WINDOW {
            return Err(RejectReason::ContentLengthInvalid);
        }
        if self.window_update_high_water_percent == 0 || self.window_update_high_water_percent > 100
        {
            return Err(RejectReason::ContentLengthInvalid);
        }
        Ok(())
    }
}

/// Bounds the bytes retained by blocked QPACK header blocks on one
/// connection.
///
/// Only meaningful when an operator raises `qpack_blocked_streams` above 0.
/// The bytes a blocked block retains are charged HERE as well as against
/// `max_header_list_bytes`, and released only when the block decodes. Envoy
/// GHSA-p7c7-7c47-pwch was exactly this: the retained bytes were released
/// from QUIC flow-control accounting while still held in a heap buffer, so
/// flow control did not bound memory.
///
/// Deliberately NOT `Copy`. `held` is a BALANCE: a decode loop that charges a
/// copy leaves the connection's own `held` at zero, and the ceiling that
/// exists to bound retained memory bounds nothing. Same rule as
/// `HeaderListBudget`, `ConnBudget` and every other balance type in this
/// tree.
#[derive(Clone, Debug)]
pub struct QpackBlockedBytes {
    held: u64,
    max: u64,
    blocked_streams: u16,
    max_blocked_streams: u16,
}

impl QpackBlockedBytes {
    /// A ceiling from the policy. `max` comes from `max_header_list_size`,
    /// not from a separate configuration field: the retained bytes of a
    /// blocked block are bounded by the same number the header-list budget
    /// already enforces, so a second knob could only disagree with the
    /// first.
    #[must_use]
    #[allow(
        clippy::cast_lossless,
        reason = "u32 to u64 is a lossless widening; From is not yet callable in a const fn"
    )]
    pub const fn new(policy: &SettingsPolicy) -> Self {
        Self {
            held: 0,
            max: policy.max_header_list_size as u64,
            blocked_streams: 0,
            max_blocked_streams: policy.qpack_blocked_streams,
        }
    }

    /// Charges the bytes a newly blocked header block retains.
    ///
    /// # Errors
    /// `HeaderListTooLarge` when the byte ceiling or the blocked-stream
    /// count is passed. With the default `qpack_blocked_streams: 0` this
    /// ALWAYS errors, which is the RFC 9204 Section 2.1.2 connection error
    /// the caller maps to `QPACK_DECOMPRESSION_FAILED`.
    pub fn block(&mut self, bytes: u64) -> Result<(), RejectReason> {
        let new_held = self.held.saturating_add(bytes);
        let new_blocked_streams = self.blocked_streams.saturating_add(1);
        if new_held > self.max || new_blocked_streams > self.max_blocked_streams {
            return Err(RejectReason::HeaderListTooLarge);
        }
        self.held = new_held;
        self.blocked_streams = new_blocked_streams;
        Ok(())
    }

    /// Releases the bytes a block retained, when it decodes. Saturates at
    /// zero: releasing more than was ever charged never underflows.
    pub fn unblock(&mut self, bytes: u64) {
        self.held = self.held.saturating_sub(bytes);
        self.blocked_streams = self.blocked_streams.saturating_sub(1);
    }

    /// Bytes currently retained by blocked blocks.
    #[must_use]
    pub const fn held(&self) -> u64 {
        self.held
    }

    /// Currently blocked streams.
    #[must_use]
    pub const fn blocked_streams(&self) -> u16 {
        self.blocked_streams
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::ConnBudget;
    use irontraffic_http::Limits;

    #[test]
    fn defaults_are_the_security_bearing_ones() {
        // The two security-bearing defaults. Both sides are compile-time
        // constants, so a bare `assert!` is constant-folded and clippy flags
        // it; a `const` block keeps the same check without that warning
        // while still pinning the bound this test's name promises.
        assert_eq!(SettingsPolicy::DEFAULT.qpack_blocked_streams, 0);
        const { assert!(SettingsPolicy::DEFAULT.no_rfc7540_priorities) };

        // Agreement with the header-list budget's enforced ceiling.
        assert_eq!(
            SettingsPolicy::DEFAULT.max_header_list_size,
            Limits::DEFAULT.max_header_list_bytes
        );

        // Agreement with the compression-table policy's advertised_max, in
        // both directions (H2's SETTINGS_HEADER_TABLE_SIZE and H3's
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY).
        assert_eq!(
            SettingsPolicy::DEFAULT.header_table_size,
            TableSizePolicy::DEFAULT.advertised_max
        );
        assert_eq!(
            SettingsPolicy::DEFAULT.qpack_max_table_capacity,
            TableSizePolicy::DEFAULT.advertised_max
        );

        // Agreement with ConnBudget's own concurrency default: read through
        // ConnBudget's real behaviour, the limit a genuine TooManyStreams
        // reports once the default budget is exhausted, rather than a
        // second hardcoded 128 that could silently drift from the first.
        let mut budget = ConnBudget::new(0);
        for _ in 0..SettingsPolicy::DEFAULT.max_concurrent_streams {
            assert_eq!(budget.open_stream(), Ok(()));
        }
        match budget.open_stream() {
            Err(too_many) => assert_eq!(
                too_many.limit,
                SettingsPolicy::DEFAULT.max_concurrent_streams
            ),
            Ok(()) => panic!(
                "ConnBudget::new(0)'s concurrency limit must be exhausted after \
                 max_concurrent_streams admissions"
            ),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one flat perturb-one-field-at-a-time matrix covering edge cases 28 through 33b (including issue #660's under-advertise addition); splitting it would scatter the 1:1 mapping between this test and that numbered list"
    )]
    #[test]
    fn validate_rejects_inconsistency() {
        let limits = Limits::DEFAULT.clamped();
        let table = TableSizePolicy::DEFAULT;

        // Edge case 28: the shipped default is internally consistent.
        assert_eq!(
            SettingsPolicy::DEFAULT.validate(&limits, &table, 128),
            Ok(())
        );

        // Edge case 29.
        assert_eq!(
            SettingsPolicy {
                max_header_list_size: 1024,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::HeaderListTooLarge)
        );

        // Edge case 30.
        assert_eq!(
            SettingsPolicy {
                max_concurrent_streams: 64,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::FieldCountExceeded)
        );

        // Edge case 31.
        assert_eq!(
            SettingsPolicy {
                max_frame_size: 1024,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::ContentLengthInvalid)
        );
        assert_eq!(
            SettingsPolicy {
                max_frame_size: 16_777_216,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::ContentLengthInvalid)
        );

        // Edge case 32.
        assert_eq!(
            SettingsPolicy {
                initial_stream_window: 2_147_483_648,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::ContentLengthInvalid)
        );
        // Beyond edge case 32: `cargo mutants` (serial, -j 1) found that
        // `initial_stream_window > MAX_FLOW_CONTROL_WINDOW` mutated to
        // `>=` still fails, because 2147483648 alone cannot distinguish
        // the two. The boundary value itself, 2147483647 (`2^31 - 1`),
        // must be ACCEPTED: RFC 9113 Section 6.9.1 bounds the window at
        // that value, not below it.
        assert_eq!(
            SettingsPolicy {
                initial_stream_window: 2_147_483_647,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Ok(())
        );

        // Edge case 33.
        assert_eq!(
            SettingsPolicy {
                window_update_high_water_percent: 0,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::ContentLengthInvalid)
        );
        assert_eq!(
            SettingsPolicy {
                window_update_high_water_percent: 101,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::ContentLengthInvalid)
        );
        // Beyond edge case 33: `cargo mutants` (serial, -j 1) found that
        // `> 100` mutated to `>= 100` still fails every specified case,
        // because 101 alone cannot distinguish the two. 100 itself is the
        // boundary that does: it must be ACCEPTED ("0 or above 100" is
        // rejected, so 100 is the last accepted value).
        assert_eq!(
            SettingsPolicy {
                window_update_high_water_percent: 100,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Ok(())
        );

        // Edge case 33b: advertising a compression table we refuse to grow.
        assert_eq!(
            SettingsPolicy {
                header_table_size: 65_536,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::HeaderListTooLarge)
        );
        assert_eq!(
            SettingsPolicy {
                qpack_max_table_capacity: 65_536,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::HeaderListTooLarge)
        );

        // Issue #660: the under-advertise direction. A policy that
        // advertises LESS than `table.advertised_max` must be rejected too,
        // not only the over-advertise direction covered by 33b. A `<=`
        // check (what `TableSizePolicy::check_update` computes, since it
        // exists to accept any peer update up to the advertised ceiling)
        // wrongly accepts this: `validate` must instead require exact
        // agreement with `table.advertised_max`.
        assert_eq!(
            SettingsPolicy {
                header_table_size: 1024,
                ..SettingsPolicy::DEFAULT
            }
            .validate(&limits, &table, 128),
            Err(RejectReason::HeaderListTooLarge)
        );
    }

    /// Charges two blocks through a `&mut` borrow, so the caller can observe
    /// the debit landing on its own connection state rather than on a value
    /// that was taken by copy and discarded.
    fn hold(q: &mut QpackBlockedBytes) {
        assert_eq!(q.block(1024), Ok(()));
        assert_eq!(q.block(1024), Ok(()));
        assert_eq!(q.held(), 2048);
    }

    #[test]
    fn qpack_blocked_bytes() {
        // Edge case 34: the default blocked-stream count is 0, so the very
        // first block always fails.
        let mut default_ceiling = QpackBlockedBytes::new(&SettingsPolicy::DEFAULT);
        assert_eq!(
            default_ceiling.block(1),
            Err(RejectReason::HeaderListTooLarge)
        );

        // Edge case 35.
        let policy_4 = SettingsPolicy {
            qpack_blocked_streams: 4,
            ..SettingsPolicy::DEFAULT
        };
        let mut four_streams = QpackBlockedBytes::new(&policy_4);
        for _ in 0..4 {
            assert_eq!(four_streams.block(1024), Ok(()));
        }
        // Beyond edge case 35: `blocked_streams()` returning a genuinely
        // nonzero value here is what fails if the accessor is ever
        // hardcoded to 0; every other assertion in this test either reads
        // `held()` or checks a state that starts and stays at zero.
        assert_eq!(four_streams.blocked_streams(), 4);
        assert_eq!(
            four_streams.block(1024),
            Err(RejectReason::HeaderListTooLarge)
        );
        assert_eq!(four_streams.held(), 4096);

        // Edge case 36.
        let policy_4_small_max = SettingsPolicy {
            qpack_blocked_streams: 4,
            max_header_list_size: 4096,
            ..SettingsPolicy::DEFAULT
        };
        // Beyond edge case 36: `cargo mutants` (serial, -j 1) found that
        // `new_held > self.max` mutated to `new_held >= self.max` still
        // fails every specified edge case, because none of them charge
        // EXACTLY up to the ceiling. A block landing exactly on the
        // ceiling must succeed; only crossing it must fail.
        let mut boundary = QpackBlockedBytes::new(&policy_4_small_max);
        assert_eq!(boundary.block(4096), Ok(()));
        assert_eq!(boundary.held(), 4096);

        let mut small_max = QpackBlockedBytes::new(&policy_4_small_max);
        assert_eq!(small_max.block(4097), Err(RejectReason::HeaderListTooLarge));

        // Edge case 37: unblocking more than was ever charged saturates at
        // zero rather than underflowing. Charging first and unblocking
        // exactly that amount proves a REAL decrement happened (an
        // `unblock` that silently did nothing would also leave an
        // already-zero balance at zero, so that alone cannot tell a no-op
        // apart from a working saturating_sub); only then does the second
        // `unblock`, past what remains, exercise the saturation itself.
        let mut drain = QpackBlockedBytes::new(&policy_4);
        assert_eq!(drain.block(1024), Ok(()));
        assert_eq!(drain.held(), 1024);
        assert_eq!(drain.blocked_streams(), 1);
        drain.unblock(1024);
        assert_eq!(drain.held(), 0);
        assert_eq!(drain.blocked_streams(), 0);
        drain.unblock(100);
        assert_eq!(drain.held(), 0);
        assert_eq!(drain.blocked_streams(), 0);

        // The &mut-borrow assertion: charging through `hold`'s `&mut`
        // parameter is visible on the owner's own value afterward, which is
        // what fails if `QpackBlockedBytes` is ever made `Copy` and a caller
        // starts taking it by value.
        let mut owner = QpackBlockedBytes::new(&policy_4);
        hold(&mut owner);
        assert_eq!(owner.held(), 2048);
    }
}
