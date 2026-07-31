// SPDX-License-Identifier: MIT OR Apache-2.0
//! `Schedule`, the sans-IO core of open-loop load generation, and
//! `StallTracker`, its coordinated-omission detector.
//!
//! # Coordinated omission, restated
//!
//! A closed-loop load generator (`loop { send(); recv(); record(); }`)
//! cannot observe the latency it causes: when the system under test stalls,
//! the client stops sending, so the stall is under-sampled precisely when it
//! matters, and closed-loop p99 numbers are systematically and sometimes
//! catastrophically optimistic. `Schedule` fixes this by making the closed
//! loop unrepresentable: it has no response input at all, so nothing a
//! server does can move a due time.
//!
//! Three rules, restated so they cannot be paraphrased away:
//!
//! 1. Request `i` is **due** at `t0 + i * (1 / R)`, computed in integer
//!    nanoseconds from an absolute origin, never as an accumulated sum of
//!    sleeps.
//! 2. A slow response never delays a later request's due time.
//! 3. The recorded latency of request `i` is `completion_time_i -
//!    due_time_i`, **not** `completion_time_i - send_time_i`.
//!
//! # Why integer nanoseconds and never a loop
//!
//! A 64-bit binary floating point nanosecond count loses precision above
//! `2^53` ns, and the accumulated rounding shows up in the inter-arrival
//! distribution long before that: all arithmetic here is `u64` nanoseconds
//! with `u128` intermediates, and no binary floating point type of any
//! width appears anywhere in this module. Computing how many requests are
//! owed after a stall by looping `while due_ns(j) <= now {
//! j += 1 }` costs one iteration per owed request: at `R = 1,000,000` a
//! 100 ms stall owes 100,000 requests, and an hour-long stall owes
//! 3,600,000,000. [`Schedule::releasable_at`] computes entitlement in closed
//! form instead, so recovering from an arbitrarily long stall costs the same
//! O(1) as the steady-state case; see `catchup_is_o1_after_a_long_stall` and
//! the `schedule/releasable_at/after_1s_stall` benchmark, which is also the
//! regression test for this.
//!
//! # The catch-up burst
//!
//! An absolute-schedule client that stalls owes every request whose due time
//! passed while it could not send. Released uncapped, that debt fires as one
//! burst, and the resulting latency spike is the client's own fault but gets
//! attributed to the system under test. [`Schedule::releasable_at`] caps a
//! single call's release at the schedule's `burst_cap` (never above
//! [`MAX_BURST_CAP`]) and counts each capped call in
//! [`Schedule::catchup_burst_count`], so a run that fell behind says so
//! instead of hiding it inside a plausible-looking latency number. The
//! mechanism mirrors Nighthawk's `LinearRateLimiter` /
//! `BurstingRateLimiter`: entitlement is `floor(elapsed / interval) -
//! already_acquired`, a pure function of elapsed time, never of anything the
//! system under test did.
//!
//! # Splitting one rate across many workers
//!
//! [`Schedule`] advances with `&mut self`, so two threads cannot advance one
//! schedule; each client worker owns its own. To split a total rate `R`
//! across `W` workers:
//!
//! - **When `W` divides `R` exactly**, worker `w` in `0..W` uses `rate_hz =
//!   R / W` and `origin_ns = t0 + (w as u128 * 1_000_000_000 / R as u128) as
//!   u64`. This interleaves the workers exactly: worker `w` serves global
//!   indices `w, w + W, w + 2W, ...` at exactly their global due times. A
//!   shared `t0` with no per-worker offset instead produces `W` synchronised
//!   bursts per global interval rather than a uniform arrival process.
//! - **When `W` does not divide `R`**, the exact interleaving above is
//!   unavailable. Worker `w` instead uses `rate_hz = R / W + if (w as u64) <
//!   R % W { 1 } else { 0 }`, with the same `origin_ns` offset formula. The
//!   aggregate rate is then exactly `R` and the arrival process is still
//!   spread across the interval, but the per-worker sequences no longer line
//!   up with a single global index sequence. Rounding every worker down
//!   instead would make the aggregate rate silently undershoot by up to `W -
//!   1` requests per second.
//!
//! # What this module deliberately does not do
//!
//! It reads no clock: every function here that needs "now" takes `now_ns` as
//! a plain parameter, which is what makes every test in
//! `tests/schedule.rs` deterministic. It has no function that takes a send
//! time or a response: [`Schedule::latency_ns`] takes only an index and a
//! completion instant, so a caller cannot accidentally record latency
//! relative to when a request was sent instead of when it was due. A client
//! that crashes mid-run restarts with a fresh origin; this module carries no
//! persistent state and no resume path.

use crate::error::BenchError;
use crate::hist::{HIGH_NS, LatencyRecorder};

/// Nanoseconds per second, the fixed conversion factor every due-time and
/// entitlement computation in this module divides by.
const NANOS_PER_SEC: u128 = 1_000_000_000;

/// Smallest rate [`Schedule::new`] accepts, in requests per second.
const MIN_RATE_HZ: u64 = 1;

/// Largest rate [`Schedule::new`] accepts, in requests per second. Above
/// this the smallest inter-request period would be under 20 ns, which is
/// finer than [`Schedule::due_ns`]'s strict-monotonicity guarantee (invariant
/// 1) can hold at `u64` nanosecond resolution for two adjacent indices.
const MAX_RATE_HZ: u64 = 50_000_000;

/// Largest `burst_cap` the schedule will accept.
///
/// At the 50,000,000 Hz rate ceiling this is roughly 1.3 milliseconds of
/// debt released at once, which is enough to absorb a scheduler hiccup and
/// far too small to manufacture a spike a reader would attribute to the
/// proxy. This bound is a `const`, not a configured value: raising it back
/// out is exactly the uncapped catch-up this design exists to prevent,
/// dressed as a configured cap, so [`Schedule::new`] rejects anything above
/// it and this module never reads an environment variable to widen it.
pub const MAX_BURST_CAP: u32 = 65_536;

/// What a client may release at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    /// Index of the first request to release. Indices are dense and
    /// monotone.
    pub first_index: u64,
    /// How many requests to release now. Never exceeds the burst cap.
    pub count: u64,
    /// How many requests were owed before the cap was applied. `debt >
    /// count` means the client is behind and this call was capped.
    pub debt: u64,
    /// The absolute nanosecond instant the caller should wait until before
    /// calling again. Always in the future or equal to `now_ns`. `u64::MAX`
    /// means the schedule is exhausted and the caller must stop.
    pub next_wake_ns: u64,
}

/// An absolute open-loop request schedule.
///
/// Request `i` is due at `t0 + i / R` in integer nanoseconds from an
/// absolute origin. Nothing the system under test does can move a due time:
/// `Schedule` has no response input, so a closed loop is not expressible
/// here. `Schedule` is plain data (no interior mutability, no shared state),
/// so it is both `Send` and `Sync`; the mutation guard against two threads
/// advancing one schedule concurrently is that [`Schedule::releasable_at`]
/// takes `&mut self`. See the module docs for how to split one total rate
/// across several workers, each owning its own `Schedule`.
#[derive(Debug, Clone)]
pub struct Schedule {
    origin_ns: u64,
    rate_hz: u64,
    burst_cap: u32,
    next_index: u64,
    max_index: u64,
    catchup_bursts: u64,
}

/// The largest index `i` for which `origin_ns + floor(i * 1e9 / rate_hz)`
/// fits in a `u64`, computed once per `(origin_ns, rate_hz)` pair.
///
/// `capacity_ns = u64::MAX - origin_ns` is the most nanoseconds of headroom
/// `due_ns` could ever add. `capacity_ns * rate_hz / 1e9`, computed with a
/// `u128` intermediate, is the largest `i` such that `i * 1e9 / rate_hz <=
/// capacity_ns` as real numbers; `due_ns`'s own `floor` only ever rounds
/// that quantity DOWN, so `origin_ns + due_ns_raw(result)` is provably `<=
/// u64::MAX`. The `.min(u64::MAX as u128)` is defence in depth: for every
/// `rate_hz` this module accepts (at most [`MAX_RATE_HZ`]) the computed
/// value is already far below `u64::MAX` (at most `u64::MAX * 50_000_000 /
/// 1_000_000_000`, i.e. `u64::MAX / 20`), so the clamp is never the thing
/// that keeps the cast below safe, but it is what makes that true by
/// construction rather than by an argument that stops being checked the
/// moment the rate ceiling changes.
fn max_index_for(origin_ns: u64, rate_hz: u64) -> u64 {
    let capacity_ns = u64::MAX - origin_ns;
    #[expect(
        clippy::integer_division,
        reason = "this is the deliberate floor at the heart of the schedule's fixed-point \
                  nanosecond arithmetic (see the module docs' \"why integer nanoseconds\" \
                  section); floats are the alternative this design rejects, not a missing cast"
    )]
    let scaled = u128::from(capacity_ns) * u128::from(rate_hz) / NANOS_PER_SEC;
    let clamped = scaled.min(u128::from(u64::MAX));
    #[expect(
        clippy::cast_possible_truncation,
        reason = "clamped is `.min(u128::from(u64::MAX))` immediately above, so it can never \
                  exceed u64::MAX and this cast never truncates"
    )]
    let result = clamped as u64;
    result
}

impl Schedule {
    /// Builds a schedule.
    ///
    /// `burst_cap` bounds how many owed requests a single `releasable_at`
    /// call may release, which is what stops a stalled client from firing
    /// its whole debt as one flood and blaming the proxy for the resulting
    /// spike.
    ///
    /// The upper bound on `burst_cap` is what makes "do not raise the cap" a
    /// rule the type enforces rather than a rule the reviewer has to
    /// remember. A `burst_cap` of `u32::MAX` is an uncapped catch-up written
    /// in a way that looks capped.
    ///
    /// # Errors
    /// `BenchError::Cell` when `rate_hz` is 0 or above 50,000,000, when
    /// `burst_cap` is 0, or when `burst_cap` is above [`MAX_BURST_CAP`].
    pub fn new(origin_ns: u64, rate_hz: u64, burst_cap: u32) -> Result<Self, BenchError> {
        if rate_hz < MIN_RATE_HZ {
            return Err(BenchError::Cell("zero rate"));
        }
        if rate_hz > MAX_RATE_HZ {
            return Err(BenchError::Cell("rate too high"));
        }
        if burst_cap == 0 {
            return Err(BenchError::Cell("zero burst cap"));
        }
        if burst_cap > MAX_BURST_CAP {
            return Err(BenchError::Cell("burst cap too high"));
        }

        Ok(Self {
            origin_ns,
            rate_hz,
            burst_cap,
            next_index: 0,
            max_index: max_index_for(origin_ns, rate_hz),
            catchup_bursts: 0,
        })
    }

    /// `due_ns(index)`'s computation, without the `index <= max_index`
    /// bounds check `due_ns` performs before calling this.
    ///
    /// This is a private helper: every call site in this module only ever
    /// reaches it after establishing `index <= self.max_index`, which by
    /// `max_index_for`'s own derivation is exactly the condition that makes
    /// the final `+` below provably not overflow. It is not exposed
    /// publicly; the public, safe entry point is [`Schedule::due_ns`].
    fn due_ns_raw(&self, index: u64) -> u64 {
        #[expect(
            clippy::integer_division,
            reason = "this is the deliberate floor at the heart of the schedule's fixed-point \
                      nanosecond arithmetic (see the module docs' \"why integer nanoseconds\" \
                      section); floats are the alternative this design rejects, not a missing \
                      cast"
        )]
        let offset_ns = u128::from(index) * NANOS_PER_SEC / u128::from(self.rate_hz);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the caller established index <= self.max_index before reaching this \
                      helper, and max_index_for derives max_index as exactly the largest index \
                      for which this floor division fits in u64::MAX - origin_ns, so offset_ns \
                      here is always <= u64::MAX - self.origin_ns and this cast never truncates"
        )]
        let offset_ns_u64 = offset_ns as u64;
        self.origin_ns + offset_ns_u64
    }

    /// The absolute due time of request `index`, or `None` past
    /// [`Schedule::max_index`].
    ///
    /// Computed as `origin_ns + (index * 1e9) / rate_hz` with a `u128`
    /// intermediate: the multiply happens before the divide, so the result
    /// is exact for every rate that divides `10^9` and has bounded error of
    /// at most 1 ns per index otherwise, with no accumulation across calls.
    /// Never an accumulated sum, never floating point.
    #[must_use]
    pub fn due_ns(&self, index: u64) -> Option<u64> {
        if index > self.max_index {
            return None;
        }
        Some(self.due_ns_raw(index))
    }

    /// The largest index whose due time fits in `u64` nanoseconds for THIS
    /// origin and rate. Computed once in [`Schedule::new`]; it is not a
    /// constant, because it scales with the rate: at a higher rate, more
    /// indices fit before the due time overflows `u64`.
    #[must_use]
    pub fn max_index(&self) -> u64 {
        self.max_index
    }

    /// Advances the schedule to `now_ns` and reports what may be released.
    ///
    /// Idempotent for an unchanged `now_ns` once the debt is repaid: further
    /// calls return `count == 0` and `debt == 0`.
    ///
    /// Once `next_index()` exceeds `max_index()` the schedule is exhausted
    /// and every further call returns `count == 0`, `debt == 0` and
    /// `next_wake_ns == u64::MAX`. It never wraps and never panics.
    #[must_use]
    pub fn releasable_at(&mut self, now_ns: u64) -> Release {
        // Step 0: an exhausted schedule releases nothing, forever, and never
        // computes a due time for an index past max_index.
        if self.next_index > self.max_index {
            return Release {
                first_index: self.next_index,
                count: 0,
                debt: 0,
                next_wake_ns: u64::MAX,
            };
        }

        // Past this point next_index <= max_index, so due_ns_raw(next_index)
        // is always defined.
        let next_due_ns = self.due_ns_raw(self.next_index);

        // Step 1: not yet due. Also handles `now_ns` before `origin_ns`,
        // since due_ns_raw(0) == origin_ns exactly and next_index starts at
        // 0: this branch alone yields `next_wake_ns == origin_ns` with no
        // separate case.
        if now_ns < next_due_ns {
            return Release {
                first_index: self.next_index,
                count: 0,
                debt: 0,
                next_wake_ns: next_due_ns,
            };
        }

        // Step 2: entitlement, in closed form, never a loop. `entitled` is
        // the largest `j` such that `due_ns(j) <= now_ns`.
        //
        // The `+1` and `-1` below are load bearing, not decoration:
        // `due_ns(j) <= delta` means `floor(j * 1e9 / R) <= delta`, which is
        // `j * 1e9 / R < delta + 1`, which is `j <= ceil((delta + 1) * R /
        // 1e9) - 1`, and that is exactly the expression below. The naive
        // `delta * R / 1e9` is off by one whenever `R` does not divide
        // `10^9`: at `R = 3` and `delta = 333_333_333` (exactly `due_ns(1) -
        // origin_ns`) the naive form answers 0 while request 1 is due,
        // which would make step 3 below produce `count == 0` while step 7
        // sets `next_wake_ns` to an instant already in the past, so the
        // caller would spin. `entitlement_is_exact_at_a_non_dividing_rate`
        // pins this.
        let delta = u128::from(now_ns.saturating_sub(self.origin_ns));
        let numerator = (delta + 1) * u128::from(self.rate_hz) - 1;
        #[expect(
            clippy::integer_division,
            reason = "this is the deliberate floor half of the ceil-via-floor identity this \
                      comment block derives above; floats are the alternative this design \
                      rejects, not a missing cast"
        )]
        let entitled_u128 = numerator / NANOS_PER_SEC;
        // Step 2b: never release past the representable range.
        let entitled_u128 = entitled_u128.min(u128::from(self.max_index));
        #[expect(
            clippy::cast_possible_truncation,
            reason = "entitled_u128 is clamped to self.max_index (a u64) via .min() \
                      immediately above, so it can never exceed u64::MAX and this cast never \
                      truncates"
        )]
        let entitled = entitled_u128 as u64;

        // Step 3. `entitled + 1` cannot overflow: step 2b clamped `entitled`
        // to `max_index`, and `max_index` is at most `u64::MAX * 50_000_000
        // / 1_000_000_000`, which is `u64::MAX / 20`. This stops being true
        // the moment somebody raises MAX_RATE_HZ above `10^9`; this comment,
        // not a runtime guard, is what makes them notice, so this is a
        // deliberate plain `+`, not a `saturating_add`.
        let debt = (entitled + 1).saturating_sub(self.next_index);

        // Step 4 and 5.
        let burst_cap_u64 = u64::from(self.burst_cap);
        let count = debt.min(burst_cap_u64);
        if debt > burst_cap_u64 {
            self.catchup_bursts = self.catchup_bursts.saturating_add(1);
        }

        // Step 6.
        let first_index = self.next_index;
        self.next_index = self.next_index.saturating_add(count);

        // Step 7. `self.next_index <= max_index` in the second arm is
        // guaranteed by the first arm's negation, so due_ns_raw is safe to
        // call directly there.
        let next_wake_ns = if self.next_index > self.max_index {
            u64::MAX
        } else if self.next_index > entitled {
            self.due_ns_raw(self.next_index)
        } else {
            now_ns
        };

        Release {
            first_index,
            count,
            debt,
            next_wake_ns,
        }
    }

    /// Latency of request `index`, measured from its DUE time.
    ///
    /// This is the definition of open-loop latency. There is deliberately no
    /// variant taking a send time: if a caller wants the send-relative value
    /// for diagnostics it computes it itself, and the type name here does
    /// not lend it credibility.
    #[must_use]
    pub fn latency_ns(&self, index: u64, completion_ns: u64) -> Option<u64> {
        let due = self.due_ns(index)?;
        Some(completion_ns.saturating_sub(due))
    }

    /// How many times a release was capped because the client was behind. A
    /// nonzero value is reported in every run result.
    #[must_use]
    pub fn catchup_burst_count(&self) -> u64 {
        self.catchup_bursts
    }

    /// Index of the next request that has not yet been released.
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
}

/// Measures the interval a client was entitled to send but could not.
///
/// This is our `sequencer.blocking`: the quantity a closed-loop tool
/// silently discards, recorded as a histogram and published with every run.
/// The client calls [`StallTracker::on_blocked`] when a [`Release::count`]
/// is nonzero but no connection is free to send on, and
/// [`StallTracker::on_unblocked`] when it finally sends.
#[derive(Debug)]
pub struct StallTracker {
    recorder: LatencyRecorder,
    blocked_since: Option<u64>,
    out_of_range: u64,
    backwards: u64,
}

impl StallTracker {
    /// Creates a tracker with an empty recorder.
    ///
    /// # Errors
    /// Propagates `LatencyRecorder::new`.
    pub fn new() -> Result<Self, BenchError> {
        Ok(Self {
            recorder: LatencyRecorder::new()?,
            blocked_since: None,
            out_of_range: 0,
            backwards: 0,
        })
    }

    /// Marks the start of a blocked interval. Repeated calls while already
    /// blocked do nothing, so the interval is the outermost bracket.
    pub fn on_blocked(&mut self, now_ns: u64) {
        if self.blocked_since.is_none() {
            self.blocked_since = Some(now_ns);
        }
    }

    /// Closes an open blocked interval and records its duration. A call with
    /// no interval open does nothing.
    ///
    /// `now_ns` is a caller-supplied parameter, not a value this tracker
    /// read from a monotone clock itself, so it is never assumed to be `>=`
    /// the instant [`StallTracker::on_blocked`] recorded: the duration is a
    /// `saturating_sub`, and a `now_ns` below that instant is counted in
    /// [`StallTracker::backwards_count`] rather than produced as a wrapped,
    /// enormous duration that a debug build would panic on and a release
    /// build would silently mis-measure.
    ///
    /// A duration longer than [`HIGH_NS`] (60 seconds) is counted in
    /// [`StallTracker::out_of_range`], not recorded into
    /// [`StallTracker::recorder`] and not clamped into the top bucket: the
    /// longest client stall is exactly the sample that must not be lost, and
    /// `out_of_range` is this tracker's OWN counter, reported separately
    /// from [`LatencyRecorder::out_of_range`] so a reader always knows which
    /// histogram lost a sample.
    pub fn on_unblocked(&mut self, now_ns: u64) {
        let Some(blocked_since) = self.blocked_since.take() else {
            return;
        };
        if now_ns < blocked_since {
            self.backwards = self.backwards.saturating_add(1);
        }
        let stall_ns = now_ns.saturating_sub(blocked_since);
        if stall_ns > HIGH_NS {
            self.out_of_range = self.out_of_range.saturating_add(1);
        } else {
            self.recorder.record_ns(stall_ns);
        }
    }

    /// The recorded stall distribution.
    #[must_use]
    pub fn recorder(&self) -> &LatencyRecorder {
        &self.recorder
    }

    /// Stall intervals longer than [`HIGH_NS`] (60 seconds), which were
    /// counted but not recorded into [`StallTracker::recorder`].
    ///
    /// Reported separately from the latency recorder's own out-of-range
    /// count and carried into a published run result as
    /// `stall_out_of_range`. A nonzero value invalidates the run: the
    /// longest client stall is precisely the sample whose loss would let a
    /// run with, say, a two minute stall pass validity invariant I8
    /// (`stall.p99_ns * 20 <= latency.p99_ns`) by having its worst sample
    /// fall off the end of the histogram.
    #[must_use]
    pub fn out_of_range(&self) -> u64 {
        self.out_of_range
    }

    /// How many [`StallTracker::on_unblocked`] calls supplied a `now_ns`
    /// below the instant [`StallTracker::on_blocked`] recorded.
    ///
    /// Always zero for a caller driving this tracker from one monotone
    /// clock, which is every caller this crate ships. A nonzero value is a
    /// defect in the CALLER, not in this tracker, and is reported in the run
    /// result rather than hidden, because the alternative to noticing it is
    /// a wrapped interval landing in [`StallTracker::out_of_range`] and
    /// silently dropping a stall sample.
    #[must_use]
    pub fn backwards_count(&self) -> u64 {
        self.backwards
    }
}
