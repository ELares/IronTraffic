// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unit and property tests for `Schedule` and `StallTracker`.
//!
//! # The property that matters: absolute, not relative
//!
//! `Schedule` computes every due time from `origin_ns` and `rate_hz` alone;
//! it never accumulates from a previous send or a previous call. `no_drift`,
//! `due_ns_survives_a_long_history_of_stalls_and_repayment` and
//! `next_wake_ns_is_absolute_not_relative` pin this directly: the first
//! shows the formula is exact from a cold start, the second shows a request
//! far in the future is due at EXACTLY the same instant whether or not the
//! schedule spent the time in between falling behind and catching back up
//! (and, since it was widened to raise the stakes far above `burst_cap`,
//! also that history), and the third asserts `next_wake_ns` itself, the one
//! field a caller actually reads to know when to send next, against
//! hand-computed literals at an off-period instant where the absolute and
//! relative forms diverge. A relative implementation (`next_due =
//! last_send_time + interval`, a `Release` built from `now_ns + interval`
//! instead of the index's own due time, or a `Schedule` whose `due_ns` reads
//! `self.next_index` instead of only its `index` argument) would drift away
//! from the literals pinned in these tests the moment any call to
//! `releasable_at` fell behind, or the moment a caller polled at an instant
//! that does not fall exactly on a period boundary; every mutation this
//! file's own development watched fail is recorded on the test that catches
//! it.
//!
//! # What these tests do NOT prove
//!
//! Every distribution and delay sequence here is a fixed, checked-in
//! `SplitMix64` pseudo-random stream (used only as a deterministic value
//! generator, never as a production entropy source): the module under test
//! reads no clock and no random source itself, so nothing here needs the
//! `irontraffic-time` / `irontraffic-rand` seams, and every `now_ns` this
//! file passes in is a plain literal or a value derived from one.

use irontraffic_bench::{BenchError, HIGH_NS, LOW_NS, MAX_BURST_CAP, Schedule, StallTracker};
use proptest::prelude::*;

/// Deterministic pseudo-random sequence generator (`SplitMix64`), used only
/// to build property-test-adjacent fixtures that still need to be
/// reproducible. Not a production entropy source, matching
/// `benches/harness.rs`'s own copy of this exact generator.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---------------------------------------------------------------------------
// Unit tests, numbered as in issue #406's Tests section.
// ---------------------------------------------------------------------------

#[test]
fn no_drift() {
    // 1. Schedule::new(0, 1_000_000, 64); due_ns(i) == Some(i * 1000) exactly
    // for every i in 0..10_000_000. Exact equality in integer nanoseconds,
    // no tolerance.
    let schedule = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
    for i in 0..10_000_000u64 {
        assert_eq!(schedule.due_ns(i), Some(i * 1000), "drifted at index {i}");
    }
}

#[test]
fn non_dividing_rate_is_exact_at_period() {
    // 2. At R = 3: due_ns(1) == Some(333_333_333) and due_ns(3) ==
    // Some(1_000_000_000), because the multiply precedes the divide.
    let schedule = Schedule::new(0, 3, 64).expect("valid schedule");
    assert_eq!(schedule.due_ns(1), Some(333_333_333));
    assert_eq!(schedule.due_ns(3), Some(1_000_000_000));
}

#[test]
fn debt_accumulation() {
    // 3. Schedule::new(0, 10_000, 64); releasable_at(0) releases index 0;
    // then releasable_at(100_000_000) (100 ms later) has debt == 1_000 and
    // count == 64. Keep calling with the same now_ns until count == 0:
    // exactly fifteen calls of 64, one call of 40, one call of 0
    // (64 * 15 + 40 == 1_000), and catchup_burst_count() == 15 (the
    // sixteenth call has debt == 40, at or below the cap, so it is not
    // capped).
    let mut schedule = Schedule::new(0, 10_000, 64).expect("valid schedule");

    let first = schedule.releasable_at(0);
    assert_eq!(first.first_index, 0);
    assert_eq!(first.count, 1);

    let jumped = schedule.releasable_at(100_000_000);
    assert_eq!(
        jumped.debt, 1_000,
        "100 ms at 10 kHz owes exactly 1,000 requests"
    );
    assert_eq!(
        jumped.count, 64,
        "first post-jump call is capped at burst_cap"
    );

    let mut counts = vec![jumped.count];
    loop {
        let release = schedule.releasable_at(100_000_000);
        counts.push(release.count);
        if release.count == 0 {
            break;
        }
    }

    let mut expected = vec![64u64; 15];
    expected.push(40);
    expected.push(0);
    assert_eq!(counts, expected, "exactly fifteen 64s, one 40, one 0");
    assert_eq!(
        schedule.catchup_burst_count(),
        15,
        "the sixteenth call (debt 40) is at or below burst_cap and is not a capped release"
    );
}

#[test]
fn burst_cap_is_never_exceeded() {
    // 4. Drive a 10 second jump at R = 1,000,000: every count is at most
    // burst_cap, and the total released equals the entitlement.
    let burst_cap = 64u32;
    let mut schedule = Schedule::new(0, 1_000_000, burst_cap).expect("valid schedule");
    let now_ns = 10 * 1_000_000_000u64;

    let mut total_released = 0u64;
    loop {
        let release = schedule.releasable_at(now_ns);
        assert!(
            release.count <= u64::from(burst_cap),
            "count {} exceeded burst_cap {burst_cap}",
            release.count
        );
        total_released += release.count;
        if release.count == 0 {
            break;
        }
    }

    // Entitlement at a 10 second jump on a rate that divides 10^9 exactly is
    // exactly 10_000_001 requests (indices 0..=10_000_000, i.e. every index
    // whose due_ns is <= now_ns).
    assert_eq!(total_released, 10_000_001);
    assert_eq!(schedule.next_index(), 10_000_001);
}

#[test]
fn releasable_is_idempotent_for_same_now() {
    // 5. Two calls with identical now_ns; the second has count == 0.
    //
    // R = 1,000 and now_ns = 5,000,000 entitles exactly 6 requests (indices
    // 0..=5, due_ns(5) == 5,000,000), well under burst_cap == 64, so the
    // FIRST call is not capped and fully drains the debt in one call: this
    // is what makes the second call's count == 0 a proof of idempotence
    // rather than just another capped release.
    let mut schedule = Schedule::new(0, 1_000, 64).expect("valid schedule");
    let first = schedule.releasable_at(5_000_000);
    assert_eq!(first.count, 6, "must not read as an empty, healthy run");
    assert_eq!(first.debt, 6, "uncapped: debt equals count");

    let second = schedule.releasable_at(5_000_000);
    assert_eq!(second.count, 0);
    assert_eq!(second.debt, 0);
}

#[test]
fn now_before_origin_releases_nothing() {
    // 6. releasable_at(origin_ns - 1) gives count == 0 and next_wake_ns ==
    // origin_ns.
    let origin_ns = 1_000_000_000u64;
    let mut schedule = Schedule::new(origin_ns, 1_000_000, 64).expect("valid schedule");
    let release = schedule.releasable_at(origin_ns - 1);
    assert_eq!(release.count, 0);
    assert_eq!(release.next_wake_ns, origin_ns);
}

#[test]
fn catchup_is_o1_after_a_long_stall() {
    // 7. Jump forward one hour at R = 1,000,000: the single releasable_at
    // call completes in under 1 millisecond, which fails loudly if someone
    // wrote the entitlement as a loop (an hour at this rate owes
    // 3,600,000,000 requests; a loop would iterate that many times).
    let mut schedule = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
    let one_hour_ns = 3_600 * 1_000_000_000u64;

    let start = std::time::Instant::now();
    let release = schedule.releasable_at(one_hour_ns);
    let elapsed = start.elapsed();

    assert_eq!(
        release.count, 64,
        "capped release, same as the steady-state cost"
    );
    // The bound is wall-clock, not a call- or allocation-count, so it is the
    // one test in this file with a nonzero flake probability from scheduler
    // preemption between the two Instant::now() reads (issue #795 NOTE 9).
    // Measured headroom on the actual closed-form implementation is roughly
    // 4,800x (worst of 20,000 debug-build samples: 209 ns); a loop-based
    // entitlement computation would iterate 3,600,000,000 times here and
    // take seconds, not milliseconds. 50 ms keeps that separation decisive
    // while giving CI noise far more room than the original 1 ms bound.
    assert!(
        elapsed < std::time::Duration::from_millis(50),
        "releasable_at after a one hour stall took {elapsed:?}, which means entitlement was \
         computed as a loop rather than in closed form"
    );
}

#[test]
fn max_index_boundary() {
    // 8. For origin_ns = 0 at R = 1_000_000: max_index() is
    // u64::MAX / 1000 == 18_446_744_073_709_551, due_ns(max_index()) is
    // Some, due_ns(max_index() + 1) is None. Repeat at R = 1: max_index() is
    // u64::MAX / 1_000_000_000 == 18_446_744_073, proving the bound scales
    // with the rate instead of being a constant.
    let schedule_fast = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
    assert_eq!(schedule_fast.max_index(), 18_446_744_073_709_551);
    assert!(schedule_fast.due_ns(schedule_fast.max_index()).is_some());
    assert!(
        schedule_fast
            .due_ns(schedule_fast.max_index() + 1)
            .is_none()
    );

    let schedule_slow = Schedule::new(0, 1, 64).expect("valid schedule");
    assert_eq!(schedule_slow.max_index(), 18_446_744_073);
    assert!(schedule_slow.due_ns(schedule_slow.max_index()).is_some());
    assert!(
        schedule_slow
            .due_ns(schedule_slow.max_index() + 1)
            .is_none()
    );

    assert_ne!(
        schedule_fast.max_index(),
        schedule_slow.max_index(),
        "max_index must scale with the rate, not be a fixed constant"
    );
}

#[test]
fn latency_is_measured_from_due_time() {
    // 9. Due time 1,000, completion 5,000: latency_ns == 4,000, and a
    // hand-computed send-relative value of 1,000 (send at 4,000) is strictly
    // smaller, pinning the direction.
    let schedule = Schedule::new(1_000, 1_000_000, 64).expect("valid schedule");
    let latency_from_due = schedule.latency_ns(0, 5_000).expect("index 0 is in range");
    assert_eq!(latency_from_due, 4_000);

    let send_ns = 4_000u64;
    let latency_from_send = 5_000u64.saturating_sub(send_ns);
    assert_eq!(latency_from_send, 1_000);
    assert!(
        latency_from_due > latency_from_send,
        "the due-time correction must be strictly larger here, never smaller"
    );
}

#[test]
fn completion_before_due_saturates() {
    // 10. latency_ns(0, 0) with origin_ns = 100 is Some(0), not a panic.
    let schedule = Schedule::new(100, 1_000_000, 64).expect("valid schedule");
    assert_eq!(schedule.latency_ns(0, 0), Some(0));
}

#[test]
fn latency_is_measured_from_this_indexs_own_due_time_not_from_origin() {
    // 9a. Nonzero-index regression for issue #406 rule 3 ("the recorded
    // latency of request i is completion_time_i - due_time_i, NOT
    // completion_time_i - send_time_i"), which the module doc calls the
    // entire methodology in one line. `latency_is_measured_from_due_time`
    // and `completion_before_due_saturates` above both call `latency_ns` at
    // index 0, where `due_ns(0) == origin_ns` identically, so neither can
    // tell "measured from this index's due time" apart from "measured from
    // origin_ns for every index" (issue #795 finding 2).
    //
    // Hand computed at a nonzero index: Schedule::new(1_000, 1_000_000, 64)
    // has due_ns(7) == origin_ns + 7 * (1e9 / 1_000_000) == 1_000 + 7_000 ==
    // 8_000, strictly greater than origin_ns (1_000), so measuring from
    // due_ns(7) (12_000 - 8_000 == 4_000) and measuring from origin_ns
    // (12_000 - 1_000 == 11_000) give different answers: this is exactly the
    // fixture that separates the two, which index 0 cannot.
    let schedule = Schedule::new(1_000, 1_000_000, 64).expect("valid schedule");
    assert_eq!(
        schedule.due_ns(7),
        Some(8_000),
        "hand-computed due time of index 7"
    );
    assert_eq!(
        schedule.latency_ns(7, 12_000),
        Some(4_000),
        "latency must be measured from due_ns(7) (8_000), not from origin_ns (1_000)"
    );
    assert_ne!(
        schedule.latency_ns(7, 12_000),
        Some(12_000 - 1_000),
        "measuring from origin_ns instead of this index's own due time must not match"
    );
}

#[test]
fn stall_tracker_brackets_outermost() {
    // 11. on_blocked(100), on_blocked(200), on_unblocked(500) records
    // exactly one sample of 400 ns; a second on_unblocked(600) records
    // nothing.
    let mut tracker = StallTracker::new().expect("valid tracker");
    tracker.on_blocked(100);
    tracker.on_blocked(200);
    tracker.on_unblocked(500);
    assert_eq!(
        tracker.recorder().len(),
        1,
        "must not read as an empty, healthy run"
    );
    assert_eq!(tracker.recorder().percentiles().max_ns, 400);

    tracker.on_unblocked(600);
    assert_eq!(
        tracker.recorder().len(),
        1,
        "an on_unblocked with no open interval is a no-op"
    );
}

#[test]
fn stall_tracker_survives_backwards_time() {
    // 11a. on_blocked(1_000) then on_unblocked(500) records one sample of
    // 0 ns, leaves out_of_range() == 0, and gives backwards_count() == 1.
    // Runs in a debug build (where a bare subtraction panics) and asserts no
    // panic, and asserts the recorded sample reads back as LOW_NS rather
    // than about 1.8e19, which is what a release-build wrap would produce.
    //
    // The computed duration IS exactly 0 (`now_ns.saturating_sub(1_000) ==
    // 0`), but `LatencyRecorder::record_n_ns` floors any value below LOW_NS
    // to LOW_NS by its own documented contract (see hist.rs), so 0 itself is
    // never an observable reading through `percentiles()`: LOW_NS is the
    // smallest value that CAN read back, and it is worlds away from a
    // wrapped ~1.8e19, which is the discriminating property this test pins.
    let mut tracker = StallTracker::new().expect("valid tracker");
    tracker.on_blocked(1_000);
    tracker.on_unblocked(500);

    assert_eq!(tracker.backwards_count(), 1);
    assert_eq!(tracker.out_of_range(), 0);
    assert_eq!(
        tracker.recorder().len(),
        1,
        "the backwards call must still record a sample"
    );
    assert_eq!(
        tracker.recorder().percentiles().max_ns,
        LOW_NS,
        "a backwards now_ns must saturate to 0 ns (which floors to LOW_NS), never wrap to \
         roughly 1.8e19"
    );
}

#[test]
fn stall_beyond_sixty_seconds_is_counted_not_dropped() {
    // 11b. on_blocked(0) then on_unblocked(61_000_000_000) leaves the stall
    // recorder empty and out_of_range() == 1. A client blocked for a minute
    // must not be able to pass validity invariant I8 by falling off the end
    // of the histogram.
    let mut tracker = StallTracker::new().expect("valid tracker");
    tracker.on_blocked(0);
    tracker.on_unblocked(61_000_000_000);

    assert_eq!(
        tracker.out_of_range(),
        1,
        "a lost stall sample must never read as zero"
    );
    assert!(
        tracker.recorder().is_empty(),
        "the sample must not be clamped into the top bucket"
    );

    // What this test does NOT prove: that a nonzero out_of_range() actually
    // fails a published run. `RunResult` and its validity guards do not
    // exist in this crate yet (they are specified by a later issue,
    // {{bench-run-result-and-validity-guards}}); asserting a local boolean
    // computed from the same `out_of_range()` call two lines above would be
    // a tautology, not a check on that link (issue #795 finding 6). This
    // test's job ends at proving the sample is counted and not silently
    // folded into the histogram; the publishability wiring is that later
    // issue's job.
}

#[test]
fn stall_out_of_range_boundary_is_pinned_exactly_at_high_ns() {
    // Companion to stall_beyond_sixty_seconds_is_counted_not_dropped, which
    // probes a full second past HIGH_NS and so pins nothing about where the
    // edge actually is. This test pins both sides of the exact boundary:
    // a stall of exactly HIGH_NS is still recorded into the histogram, and
    // HIGH_NS + 1 ns is the first duration counted lost. `stall_ns > HIGH_NS`
    // changed to `>=`, or the threshold widened by even 1 ns, changes one of
    // these two outcomes (issue #795 finding 4).
    let mut at_edge = StallTracker::new().expect("valid tracker");
    at_edge.on_blocked(0);
    at_edge.on_unblocked(HIGH_NS);
    assert_eq!(
        at_edge.out_of_range(),
        0,
        "a stall of exactly HIGH_NS must still be recorded, not booked as lost"
    );
    assert_eq!(at_edge.recorder().len(), 1);

    let mut one_past = StallTracker::new().expect("valid tracker");
    one_past.on_blocked(0);
    one_past.on_unblocked(HIGH_NS + 1);
    assert_eq!(
        one_past.out_of_range(),
        1,
        "one nanosecond past HIGH_NS must be the first duration counted lost"
    );
    assert!(one_past.recorder().is_empty());
}

#[test]
fn rate_and_cap_validation() {
    // 12. (0, 0, 64), (0, 50_000_001, 64), (0, 1000, 0) and
    // (0, 1000, MAX_BURST_CAP + 1) are all Err(BenchError::Cell(_)); (0,
    // 1000, MAX_BURST_CAP) is Ok.
    assert!(matches!(Schedule::new(0, 0, 64), Err(BenchError::Cell(_))));
    assert!(matches!(
        Schedule::new(0, 50_000_001, 64),
        Err(BenchError::Cell(_))
    ));
    assert!(matches!(
        Schedule::new(0, 1000, 0),
        Err(BenchError::Cell(_))
    ));
    assert!(matches!(
        Schedule::new(0, 1000, MAX_BURST_CAP + 1),
        Err(BenchError::Cell(_))
    ));
    assert!(Schedule::new(0, 1000, MAX_BURST_CAP).is_ok());

    // The documented rate ceiling itself must be ACCEPTED, not just values
    // strictly below it: `rate_hz > MAX_RATE_HZ` changed to `>=` rejects
    // exactly this value while every assertion above still passes, because
    // the only property test that samples 50_000_000 does not reliably hit
    // its own inclusive upper bound (issue #795 NOTE 7).
    assert!(
        Schedule::new(0, 50_000_000, 64).is_ok(),
        "the documented maximum rate, 50_000_000 Hz, must be accepted"
    );

    // `Schedule::new(0, 1000, MAX_BURST_CAP)` above and the rejection two
    // lines above it are both expressions recomputed from MAX_BURST_CAP
    // itself, so they hold for ANY value of the constant: raising it does
    // not move either literal. Pin the constant's actual value, and pin the
    // rejection against a literal one past it, so raising MAX_BURST_CAP
    // (issue #406: "do NOT raise that constant either") cannot pass
    // silently (issue #795 finding 5).
    assert_eq!(
        MAX_BURST_CAP, 65_536,
        "MAX_BURST_CAP moved; it must stay a fixed ceiling, never a configured value"
    );
    assert!(matches!(
        Schedule::new(0, 1000, 65_537),
        Err(BenchError::Cell(_))
    ));
}

#[test]
fn entitlement_is_exact_at_a_non_dividing_rate() {
    // 13. Schedule::new(0, 3, 64); release request 0 at now_ns = 0; then
    // releasable_at(333_333_333), exactly due_ns(1), gives count == 1. The
    // naive delta * rate / 1e9 closed form answers 0 here and makes the
    // caller spin on a next_wake_ns already in the past.
    let mut schedule = Schedule::new(0, 3, 64).expect("valid schedule");
    let first = schedule.releasable_at(0);
    assert_eq!(first.count, 1);

    let second = schedule.releasable_at(333_333_333);
    assert_eq!(
        second.count, 1,
        "request 1 is exactly due at 333_333_333 ns"
    );
}

#[test]
fn exhausted_schedule_stops_releasing() {
    // 14. Schedule::new(u64::MAX - 5_000, 1_000_000, 64), whose max_index()
    // is 5; releasable_at(u64::MAX) repeatedly releases exactly 6 (indices 0
    // through 5), every call after that returns count == 0, debt == 0 and
    // next_wake_ns == u64::MAX, and no call panics or wraps.
    let origin_ns = u64::MAX - 5_000;
    let mut schedule = Schedule::new(origin_ns, 1_000_000, 64).expect("valid schedule");
    assert_eq!(schedule.max_index(), 5);

    let mut total_released = 0u64;
    for _ in 0..8 {
        let release = schedule.releasable_at(u64::MAX);
        total_released += release.count;
    }
    assert_eq!(
        total_released, 6,
        "indices 0 through 5, six requests in total"
    );

    for _ in 0..4 {
        let release = schedule.releasable_at(u64::MAX);
        assert_eq!(release.count, 0);
        assert_eq!(release.debt, 0);
        assert_eq!(release.next_wake_ns, u64::MAX);
    }
}

#[test]
fn next_wake_ns_is_absolute_not_relative() {
    // `next_wake_ns` is the ONLY field through which `Schedule` tells a
    // caller when to send next; every other test that mentions it hits an
    // edge case (`now_before_origin_releases_nothing`'s early return, or
    // `exhausted_schedule_stops_releasing`'s exhausted sentinel), so the
    // steady, behind, and just-caught-up arms had zero assertions on this
    // field (issue #795 finding 1). This test pins hand-computed literals on
    // all three.

    // (a) Steady, on-time case. R = 1_000 Hz (a 1_000_000 ns period);
    // releasable_at(0) is exactly on time for index 0 (due_ns(0) == 0), so
    // the release is uncapped and the next wake is the absolute due time of
    // the next index: due_ns_raw(1) == 1 * 1e9 / 1_000 == 1_000_000.
    let mut on_time = Schedule::new(0, 1_000, 64).expect("valid schedule");
    let steady = on_time.releasable_at(0);
    assert_eq!(steady.count, 1);
    assert_eq!(
        steady.next_wake_ns, 1_000_000,
        "on-time wake must be the absolute due time of the next index"
    );

    // (b) Still-behind after a capped release. Same fixture as
    // `debt_accumulation`: R = 10_000 Hz, a 100 ms jump owes 1_000 requests,
    // burst_cap (64) caps the release, and the client is still 936 requests
    // behind afterwards. A caller that is still behind must be told to wake
    // immediately (next_wake_ns == now_ns), never one interval later, which
    // would insert an idle gap into an active catch-up and slow the
    // client's return to on-schedule.
    let mut behind = Schedule::new(0, 10_000, 64).expect("valid schedule");
    let _ = behind.releasable_at(0);
    let jumped = behind.releasable_at(100_000_000);
    assert_eq!(
        jumped.debt, 1_000,
        "100 ms at 10 kHz owes exactly 1,000 requests"
    );
    assert_eq!(jumped.count, 64, "capped at burst_cap");
    assert_eq!(
        jumped.next_wake_ns, 100_000_000,
        "a capped, still-behind release must wake immediately at now_ns, not now_ns + interval"
    );

    // (c) The discriminating case. R = 1_000_000 Hz (a 1_000 ns period),
    // now_ns = 5_000_500, an OFF-PERIOD instant (not a multiple of the
    // 1,000 ns period). due_ns(5_000) == 5_000_000 <= 5_000_500 <
    // 5_001_000 == due_ns(5_001), so entitlement is exactly indices 0..=5_000
    // (5_001 requests); burst_cap (6_000) does not cap this release, so
    // next_index becomes 5_001, past entitled, and the schedule must report
    // the ABSOLUTE due time of index 5_001: due_ns_raw(5_001) ==
    // 5_001 * 1_000 == 5_001_000. A relative implementation
    // (`now_ns + 1e9/rate_hz`) would instead answer
    // 5_000_500 + 1_000 == 5_001_500, which is the canonical drift bug this
    // whole module exists to make unrepresentable, and the exact fixture an
    // independent adversarial review measured on the shipped code (issue
    // #795 finding 1, evidence block).
    let mut caught_up = Schedule::new(0, 1_000_000, 6_000).expect("valid schedule");
    let release = caught_up.releasable_at(5_000_500);
    assert_eq!(
        release.debt, 5_001,
        "indices 0..=5_000 are due at or before 5_000_500"
    );
    assert_eq!(
        release.count, 5_001,
        "burst_cap 6_000 does not cap this release"
    );
    assert_eq!(
        release.next_wake_ns, 5_001_000,
        "next_wake_ns must be the absolute due_ns_raw(5_001), not the relative form \
         now_ns + interval"
    );
    assert_ne!(
        release.next_wake_ns,
        5_000_500 + 1_000,
        "next_wake_ns must not equal the relative now_ns + interval (5_001_500)"
    );
}

// ---------------------------------------------------------------------------
// Additional test: the absolute-vs-relative property, driven adversarially.
// ---------------------------------------------------------------------------

#[test]
fn due_ns_survives_a_long_history_of_stalls_and_repayment() {
    // The property the whole module exists for: due_ns(i) is a pure function
    // of (origin_ns, rate_hz, i) and is NEVER a function of the schedule's
    // release history. A client that repeatedly falls behind and catches
    // back up must still see request i due at EXACTLY t0 + i / R: not one
    // nanosecond later because the client was slow, not one nanosecond
    // earlier because it caught up fast.
    //
    // Pin literals, not an expression derived from the same computation
    // under test: the far-future index's due time is asserted against the
    // hand-computed literal 10_000_000 * 1_000 == 10_000_000_000, not
    // against a second call to the formula under test.
    //
    // Deltas run up to 500,000 ns at R = 1,000,000 Hz (a 1,000 ns period),
    // which routinely owes several hundred requests per step, far more than
    // burst_cap (64): `catchup_burst_count() > 0` below is the load-bearing
    // assertion that this test actually drives the capped, behind-schedule
    // branch, not just the fully-repaid steady state. The original version
    // of this test used deltas up to 10,000 ns, which owed at most 10
    // requests per step against the same cap of 64: every one of its 4,000
    // releasable_at calls fully repaid in the same call, the debt carried
    // across calls was always exactly 0, and 0 calls ever reached the
    // capped branch, despite this test's own prior comment claiming it
    // "drives 4,000 releasable_at calls carrying accumulated lateness"
    // (issue #795 finding 3: the fixture could not express the state the
    // comment claimed to test).
    let rate_hz = 1_000_000u64;
    let mut schedule = Schedule::new(0, rate_hz, 64).expect("valid schedule");
    let far_future_index = 10_000_000u64;
    let expected_due_ns = 10_000_000_000u64;
    assert_eq!(
        schedule.due_ns(far_future_index),
        Some(expected_due_ns),
        "pinned before any releasable_at call"
    );

    // Drive an adversarial mix of stalls (a jump far past the client's
    // current entitlement) and immediate re-polls (the same now_ns twice
    // in a row) using a fixed pseudo-random sequence of deltas, none of
    // which reach far_future_index's own due time. Worst case cumulative
    // now_ns is 2_000 * 499_999 < 1_000_000_000, an order of magnitude below
    // expected_due_ns, so the in-loop assertion below cannot trip no matter
    // what the fixed seed draws.
    let mut rng = SplitMix64(0xF00D_F00D_F00D_F00D);
    let mut now_ns = 0u64;
    for _ in 0..2_000 {
        let jump_ns = rng.next() % 500_000; // up to 500 us: hundreds of
        // requests owed at R = 1_000_000, far more than burst_cap (64)
        now_ns += jump_ns;
        assert!(
            now_ns < expected_due_ns,
            "test setup must not reach far_future_index's due time"
        );
        let _ = schedule.releasable_at(now_ns);
        // Immediate re-poll at the identical instant, the shape a caller
        // spinning on a stale next_wake_ns would produce.
        let _ = schedule.releasable_at(now_ns);
    }

    assert!(
        schedule.catchup_burst_count() > 0,
        "this test must actually reach the capped, behind-schedule branch, or it proves \
         nothing about a client that falls behind (see issue #795 finding 3)"
    );

    assert_eq!(
        schedule.due_ns(far_future_index),
        Some(expected_due_ns),
        "due_ns drifted after {} releasable_at calls carrying accumulated lateness; an \
         absolute schedule's due times must never depend on release history",
        4_000
    );
}

#[test]
fn released_indices_include_a_capped_multi_index_release() {
    // A deterministic, non-flaky companion to
    // `released_indices_are_dense_and_monotone`'s generator shape: proves
    // that the same (R = 1,000,000, deltas up to 200,000 ns) parameters
    // actually drive AT LEAST ONE capped, multi-index release (not just the
    // trivial "index 0, then always 0" case a weaker generator would
    // silently degrade to), so the property test above is measured to
    // exercise contiguity across a real capped release rather than passing
    // vacuously on an empty or single-index run.
    let mut schedule = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
    let release = schedule.releasable_at(200_000);
    assert_eq!(release.first_index, 0);
    assert_eq!(release.count, 64, "capped at burst_cap");
    assert!(
        release.debt > release.count,
        "debt must exceed count for this to be a real cap"
    );

    let mut expected_next = release.count;
    let mut total_released = release.count;
    loop {
        let next = schedule.releasable_at(200_000);
        assert_eq!(
            next.first_index, expected_next,
            "released indices must stay contiguous"
        );
        expected_next += next.count;
        total_released += next.count;
        if next.count == 0 {
            break;
        }
    }
    assert_eq!(
        total_released, 201,
        "indices 0..=200, due_ns(200) == 200_000 exactly"
    );
    assert!(
        total_released > 64,
        "must not read as a healthy, uncapped single release"
    );
}

// ---------------------------------------------------------------------------
// Property tests.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn due_times_are_strictly_monotone(rate_hz in 1u64..=50_000_000u64, i in 0u64..10_000_000u64) {
        let schedule = Schedule::new(0, rate_hz, 64).expect("valid schedule");
        let due_i = schedule.due_ns(i).expect("i is far below max_index at every accepted rate");
        let due_next = schedule
            .due_ns(i + 1)
            .expect("i + 1 is far below max_index at every accepted rate");
        prop_assert!(due_next > due_i);
    }

    #[test]
    fn coordinated_omission_correction_is_one_directional(
        rate_hz in 1u64..=50_000_000u64,
        index in 0u64..1_000u64,
        send_delay_ns in 0u64..1_000_000_000u64,
        service_ns in 0u64..1_000_000_000u64,
    ) {
        let schedule = Schedule::new(0, rate_hz, 64).expect("valid schedule");
        let due_ns = schedule.due_ns(index).expect("index is far below max_index");
        let send_ns = due_ns.saturating_add(send_delay_ns);
        let completion_ns = send_ns.saturating_add(service_ns);

        let latency_from_due = schedule
            .latency_ns(index, completion_ns)
            .expect("index is far below max_index");
        let latency_from_send = completion_ns.saturating_sub(send_ns);

        // Independently derive this index's due time from the raw formula
        // (index * 1e9 / rate_hz, origin_ns is 0 here) rather than reusing
        // `due_ns` above a second time: an assertion built only from the
        // function under test can catch a mutation only if it ALSO breaks
        // `due_ns` itself. `latency_ns` measuring from `origin_ns` instead of
        // this index's own due time (issue #795 finding 2, mutation M11)
        // leaves `due_ns` correct and only breaks `latency_ns`, and the
        // one-directional `>=` below cannot see that: origin-relative
        // latency is LARGER than send-relative latency for every index > 0,
        // same direction as the correct answer, so the inequality alone
        // still holds under that mutation. The equality against this
        // independently computed due time is what closes the gap.
        #[expect(
            clippy::integer_division,
            reason = "deliberately mirrors the floor division Schedule::due_ns_raw performs, \
                      computed independently here rather than by calling into the function \
                      under test"
        )]
        let independent_due_u128 = u128::from(index) * 1_000_000_000u128 / u128::from(rate_hz);
        let independent_due_ns = u64::try_from(independent_due_u128)
            .expect("index < 1_000 and rate_hz >= 1 keep this far below u64::MAX");
        prop_assert_eq!(
            independent_due_ns,
            due_ns,
            "sanity: the independent formula must agree with Schedule::due_ns"
        );
        prop_assert_eq!(
            latency_from_due,
            completion_ns.saturating_sub(independent_due_ns),
            "latency_ns must equal completion_ns minus THIS index's own due time, not origin_ns \
             or any other index's"
        );

        prop_assert!(latency_from_due >= latency_from_send);
    }

    #[test]
    fn released_indices_are_dense_and_monotone(
        // R = 1,000,000 (a 1,000 ns period) with deltas up to 200,000 ns is
        // deliberately chosen so a single step is likely to cross far more
        // than burst_cap (64) indices at once: at these bounds, measured
        // over 500 sampled runs of this exact shape (a standalone Python
        // model of the same closed-form entitlement formula, driven by
        // `random`, not by this crate), 94.6% of simulated `releasable_at`
        // calls were capped and 98% of runs ended with a final index beyond
        // 64, so this property is exercised against real multi-call,
        // capped, contiguous releases rather than the near-vacuous
        // single-index-0 case a smaller rate or a smaller delta ceiling
        // would produce. The ORIGINAL parameters this test shipped with
        // first (R = 1,000, deltas 0..2,000 ns over up to 80 steps) were
        // measured at 0% reachability of even index 1 over 2,000 samples:
        // due_ns(1) at that rate is 1,000,000 ns and the largest possible
        // cumulative now_ns was 80 * 1,999 == 159,920 ns, so index 1 could
        // never become due at all and this property test was exercising
        // only the trivial, always-true "one release of index 0, then
        // count == 0 forever after" case. See
        // `released_indices_include_a_capped_multi_index_release` below for
        // the same reachability property pinned as a deterministic,
        // non-flaky regression guard on this generator's shape.
        deltas in prop::collection::vec(0u64..200_000u64, 1..50)
    ) {
        let mut schedule = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
        let mut now_ns = 0u64;
        let mut expected_next = 0u64;
        for delta in deltas {
            now_ns += delta;
            let release = schedule.releasable_at(now_ns);
            prop_assert_eq!(release.first_index, expected_next);
            expected_next += release.count;
        }
        prop_assert_eq!(schedule.next_index(), expected_next);
    }
}
