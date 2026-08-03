// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adaptive concurrency: [`GradientController`], a per-(cluster, priority) controller
//! that publishes its computed limit into a [`LeasedSemaphore`].
//!
//! # Why not Envoy's design
//!
//! Envoy's `GradientController` measures the unloaded round trip time by pinning
//! concurrency down to its configured floor (3 by default) for `min_rtt_aggregate_request_count`
//! (default 50) samples, once at startup and again whenever the limit sits at that
//! floor for five consecutive windows. That measurement IS an outage: at
//! 10,000 requests per second against a cluster whose real limit is 400, dropping to 3
//! in flight collapses throughput to `3 / p50_latency` for the whole sampling window,
//! and a genuinely overloaded upstream can put the filter into a recalculation loop
//! that repeats the outage. Envoy also shares one `GradientController` across every
//! worker behind a single mutex taken on every request completion.
//!
//! This controller never forces a synthetic measurement window. Its baseline,
//! [`GradientController::rtt_base_us`], is the windowed minimum of an already-collected
//! p50 latency ([`MonotonicMinDeque`]), which costs nothing to maintain and never
//! restricts traffic. Each controller belongs to exactly one worker's per-core state and
//! is reached only inside that worker's `CoreScope`, so there is no shared mutable state
//! and no lock.
//!
//! # Wiring: one [`LeasedSemaphore`] per worker, never one shared across workers
//!
//! `GradientController` is per (worker, cluster, priority): [`GradientConfig::min_limit`]
//! and [`GradientConfig::max_limit`] are documented as PER-WORKER figures, and
//! [`GradientController::maybe_close_window`] calls `sem.set_limit` with that worker's
//! own limit, unmultiplied and unsummed. [`LeasedSemaphore`], in
//! contrast, CAN be constructed either way: `ResourceLimits::new(cfg, workers)` builds
//! one instance meant to be shared by `workers` callers (its `credits` array has one
//! cache-padded cell per worker specifically so many workers can draw permits from ONE
//! shared ceiling without contending on the same cache line), but nothing stops calling
//! it with `workers == 1` to build a private, per-worker instance instead.
//!
//! **The wiring MUST use the second shape for a gradient-controlled pair: one
//! `LeasedSemaphore` per worker per (cluster, priority), never the single semaphore
//! shared by every worker that the static, non-adaptive `max_requests` config path
//! uses.** Concretely, when [`GradientConfig::enabled`] is set for a (cluster, priority),
//! the assembly component that builds `ResourceLimits` for it must call
//! `ResourceLimits::new(cfg, 1)` once per worker rather than once per cluster, and route
//! each worker's requests through only its own instance. [`GradientController::note_inflight`]
//! must then be fed THAT SAME per-worker semaphore's `LeasedSemaphore::in_use()`, not a
//! cluster-wide sum, so the `inflight < limit / 2` app-limited gate compares two
//! per-worker quantities rather than a cluster-wide count against a per-worker one.
//!
//! This is the shape the rest of the module already assumes: every test below
//! constructs its own single-worker `LeasedSemaphore::new(limit, 1, 1, ..)`, and the
//! "aggregate floor an operator observes is `min_limit * workers`" note on
//! [`GradientConfig::min_limit`] is true only when each worker enforces its own
//! independent floor through its own semaphore, so a cluster's realized ceiling is the
//! SUM of `workers` independent per-worker ceilings rather than one shared value that
//! the last worker to call `set_limit` happens to win. The alternative (one shared
//! semaphore, with each worker multiplying its limit by `workers` before publishing)
//! was considered and rejected: it still has one worker's write clobber another's on
//! every window (`set_limit` is not additive), it does not match the per-worker figures
//! `min_limit`/`max_limit` are documented as, and no code in this module multiplies by
//! `workers` anywhere. This module has no caller today, so nothing breaks by shipping
//! with the ambiguity unresolved in code; this section is the resolution the wiring
//! issue must follow.
//!
//! # The residual attack, and its bound
//!
//! A slow-request flood cannot raise the baseline: [`MonotonicMinDeque`] tracks a
//! MINIMUM, so an artificially slow request can only be ignored, never used to inflate
//! the floor. A CHEAP-request flood is different: a client that can reach the same
//! (cluster, priority) with fast-to-serve requests (a 404, a cache hit, a HEAD, a
//! health path) can drive the window p50 down, and if that value entered the
//! baseline, every subsequent window against REAL traffic would compute a gradient of
//! 0.5, contracting the limit to `min_limit` and holding it there for up to
//! `base_windows` after the flood stopped. Three things bound this, and all three are
//! required:
//!
//! 1. [`GradientConfig::window_min_samples`] gates the baseline push: a poisoning
//!    value must be the p50 of a full window, not of one request.
//! 2. [`GradientConfig::min_limit`] is a FLOOR, so the worst case is a throttle to
//!    `min_limit * workers` in flight, not a stall.
//! 3. A controller is per (cluster, priority): an attacker's traffic only moves the
//!    classes its route and credentials place it in.
//!
//! The residual risk is real and accepted: a client that can send cheap requests into
//! the same class as expensive ones can still reduce that class's concurrency limit
//! toward the floor. This is one reason [`GradientConfig::enabled`] defaults to
//! `false`, and an operator turning it on should put expensive and cheap routes in
//! different clusters or different priority classes. The windowed minimum resists a
//! slow-request flood; it does NOT make the controller unattackable.
//!
//! # Memory bounding
//!
//! A controller is roughly 160 KB, not 30 KB: `hdrhistogram::Histogram::<u64>::
//! new_with_bounds(1, 60_000_000, 3)` (the exact construction [`GradientController::new`]
//! uses) has `distinct_values() == 17_408`, and the crate's `resize()` allocates its
//! `Vec<u64>` counts array EAGERLY, in the constructor, before a single sample is
//! recorded: `17_408 * size_of::<u64>() == 139_264` bytes (136 KB) on their own. Add the
//! 600-entry [`MonotonicMinDeque`] (up to `600 * size_of::<(u64, u64)>() == 9_600` bytes
//! of payload, more once the allocator's own bucket rounding is counted) and the fixed
//! struct fields, and a real `GradientController`, measured end to end (process
//! `ru_maxrss` growth over 1024 real instances, each driven through the public API to a
//! fully retained 600-entry baseline, not estimated from field sizes) costs about 160 KB,
//! matching the 136 KB histogram component to within the deque and allocator overhead.
//! `workers * clusters * priorities` controllers at that size would not fit if every pair
//! that is ever addressed kept one forever: 256 controllers is about 41 MB per worker,
//! and 656 MB at `workers = 16`, which is the number the memory budget has to
//! accommodate, not the 123 MB a 30 KB estimate would suggest. The histogram's bounds
//! (1 microsecond to 60 seconds at 3 significant figures) are load-bearing elsewhere in
//! this module and MUST NOT change to shrink this figure; if the budget above is too
//! large for a target deployment, lower `max_controllers_per_worker` instead. The owner
//! of the map from `(cluster, priority)` to controller (a data-plane assembly component,
//! not this module) enforces three rules together, because lazy creation and idle
//! dropping alone are not a bound: a client sending one request per second to every pair
//! keeps every one of them alive.
//!
//! 1. A controller is created LAZILY, on the first request to a pair on that worker.
//! 2. It is dropped once [`GradientController::is_idle`] reports true for the
//!    recommended `idle_drop_windows` of 10.
//! 3. The owner keeps a HARD CAP of `max_controllers_per_worker` (default 256) live
//!    controllers. At the cap, a new pair runs with its configured static
//!    `max_requests` limit instead of getting a controller, which is the safe,
//!    pre-adaptive behaviour, and a `gradient_controller_budget_exhausted` counter is
//!    incremented.

mod window;

pub use window::MonotonicMinDeque;

use crate::clock::{Micros, Millis};
use crate::config::{ConfigError, in_half_open_f64, in_range_f64, in_range_u32, ordered_u32};
use crate::limits::LeasedSemaphore;

/// The histogram's lowest trackable value, in microseconds.
const HISTOGRAM_LOW_US: u64 = 1;
/// The histogram's highest trackable value, in microseconds (60 seconds).
const HISTOGRAM_HIGH_US: u64 = 60_000_000;
/// The histogram's significant figures.
const HISTOGRAM_SIGFIG: u8 = 3;

/// Controller tuning.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct GradientConfig {
    /// Per-worker floor. Default 4. Note the aggregate floor an operator observes is
    /// `min_limit * workers`.
    pub min_limit: u32,
    /// Per-worker ceiling. Default 1000.
    pub max_limit: u32,
    /// Smoothing factor. MUST be in `(0, 1]`: the branch-2 slope is `1 - alpha`, so
    /// `alpha > 1` overshoots and `alpha = 1` tracks measurement noise 1:1. Default 0.2,
    /// giving a noise-rejection time constant of 5 windows.
    pub alpha: f64,
    /// Latency headroom multiplier. MUST be at least 1.0. With 1.5, steady-state p50
    /// sits at roughly 1.5x the no-load latency; that is the documented price of
    /// keeping the pipe full. Default 1.5.
    pub tolerance: f64,
    /// Minimum window duration in milliseconds. Default 100.
    pub window_min_ms: u32,
    /// Minimum samples per window. Default 50.
    pub window_min_samples: u32,
    /// Windows retained in the baseline minimum. Default 600, so 60 seconds at 100 ms
    /// windows.
    pub base_windows: usize,
    /// Multiplier applied immediately on a loss signal. Default 0.85.
    pub fast_down_factor: f64,
    /// Whether the controller adjusts the limit at all. Default `false`.
    ///
    /// The controller is materially safer than Envoy's because it never pins the limit
    /// down to take a measurement, but enabling it changes observed latency (the
    /// tolerance overshoot puts p50 at roughly 1.5x no-load), so the flip is a
    /// deliberate owner decision rather than a side effect of merging this module.
    pub enabled: bool,
}

impl Default for GradientConfig {
    fn default() -> Self {
        Self {
            min_limit: 4,
            max_limit: 1000,
            alpha: 0.2,
            tolerance: 1.5,
            window_min_ms: 100,
            window_min_samples: 50,
            base_windows: 600,
            fast_down_factor: 0.85,
            enabled: false,
        }
    }
}

impl GradientConfig {
    /// Largest value accepted for `max_limit`.
    pub const MAX_LIMIT_CEILING: u32 = 1_000_000;
    /// Largest value accepted for `window_min_ms`.
    pub const MAX_WINDOW_MIN_MS: u32 = 10_000;
    /// Largest value accepted for `base_windows`.
    pub const MAX_BASE_WINDOWS: usize = 10_000;
    /// Largest value accepted for `tolerance`.
    pub const MAX_TOLERANCE: f64 = 10.0;

    /// Validate every field.
    ///
    /// Rejects: `min_limit == 0`; `min_limit > max_limit`; `max_limit` above
    /// [`GradientConfig::MAX_LIMIT_CEILING`]; `alpha` not finite or outside `(0, 1]`;
    /// `tolerance` not finite or outside `[1.0, 10.0]`; `window_min_ms` equal to 0 or
    /// above [`GradientConfig::MAX_WINDOW_MIN_MS`]; `window_min_samples == 0`;
    /// `base_windows` equal to 0 or above [`GradientConfig::MAX_BASE_WINDOWS`]; and
    /// `fast_down_factor` not finite or outside `(0.0, 1.0)`.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32("gradient.min_limit", self.min_limit, 1, u32::MAX)?;
        ordered_u32(
            "gradient.min_limit",
            self.min_limit,
            "gradient.max_limit",
            self.max_limit,
        )?;
        in_range_u32(
            "gradient.max_limit",
            self.max_limit,
            self.min_limit,
            Self::MAX_LIMIT_CEILING,
        )?;
        in_half_open_f64("gradient.alpha", self.alpha, 0.0, 1.0)?;
        in_range_f64(
            "gradient.tolerance",
            self.tolerance,
            1.0,
            Self::MAX_TOLERANCE,
        )?;
        in_range_u32(
            "gradient.window_min_ms",
            self.window_min_ms,
            1,
            Self::MAX_WINDOW_MIN_MS,
        )?;
        in_range_u32(
            "gradient.window_min_samples",
            self.window_min_samples,
            1,
            u32::MAX,
        )?;
        if self.base_windows == 0 || self.base_windows > Self::MAX_BASE_WINDOWS {
            return Err(ConfigError::new(
                "gradient.base_windows",
                &self.base_windows.to_string(),
                "must be in 1..=10000",
            ));
        }
        if !self.fast_down_factor.is_finite()
            || self.fast_down_factor <= 0.0
            || self.fast_down_factor >= 1.0
        {
            return Err(ConfigError::new(
                "gradient.fast_down_factor",
                &self.fast_down_factor.to_string(),
                "must be finite and in (0.0, 1.0)",
            ));
        }
        Ok(())
    }
}

/// What one closed window observed. Every field is exported as a metric.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WindowSignals {
    /// p50 of this window's attempt latencies, in microseconds.
    pub rtt_short_us: u64,
    /// Minimum `rtt_short_us` over the last `base_windows` windows.
    pub rtt_base_us: u64,
    /// `clamp(tolerance * rtt_base / rtt_short, 0.5, 1.0)`.
    pub gradient: f64,
    /// The limit after this window's update.
    pub limit: f64,
    /// True when the app-limited hold suppressed the update.
    pub app_limited: bool,
    /// True when a loss signal triggered the fast-down.
    pub fast_down: bool,
    /// True when slow start doubled the limit instead of applying the smoothed law.
    pub slow_start: bool,
    /// Samples in the window.
    pub samples: u32,
}

/// Cumulative controller counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GradientStats {
    /// Windows closed.
    pub windows: u64,
    /// Windows where the app-limited hold suppressed the update.
    pub app_limited_holds: u64,
    /// Fast-down applications.
    pub fast_downs: u64,
    /// Windows spent in slow start.
    pub slow_start_windows: u64,
    /// Windows clamped at `max_limit`.
    pub clamped_high: u64,
    /// Windows clamped at `min_limit`.
    pub clamped_low: u64,
    /// Histogram record errors. Must stay 0; a nonzero value means the clamp was
    /// removed.
    pub histogram_errors: u64,
    /// Windows closed with no samples.
    pub empty_windows: u64,
    /// Windows whose p50 was NOT pushed into the baseline because the window held
    /// fewer than `window_min_samples` samples. A high value means the cluster's
    /// traffic is too sparse for the adaptive controller to have a trustworthy
    /// baseline.
    pub baseline_push_skipped: u64,
}

/// One adaptive concurrency controller for one (cluster, priority) pair on one worker.
///
/// Created lazily on the first request to that pair on that worker, and dropped after
/// `idle_drop_windows` idle windows, because a controller is roughly 160 KB, not 30 KB
/// (the `hdrhistogram::Histogram`'s counts array alone is a deterministic 136 KB; see
/// the module documentation for the measurement), and `workers * clusters * priorities`
/// instances would not fit. See the module documentation for the full memory-bounding
/// rule.
///
/// There is no forced measurement window. The baseline is the windowed minimum of an
/// already-collected p50, so measuring costs nothing and never restricts traffic.
pub struct GradientController {
    limit: f64,
    /// Per-worker latency histogram for the current window, in microseconds.
    hist: hdrhistogram::Histogram<u64>,
    base: MonotonicMinDeque,
    cfg: GradientConfig,
    window_started: Millis,
    samples_this_window: u32,
    /// Set when the window saw a loss signal, cleared at the window boundary.
    loss_this_window: bool,
    /// True until the first window with `gradient < 1.0`.
    slow_start: bool,
    /// Highest `inflight` observed during the window, for the app-limited hold.
    inflight_peak: u32,
    /// Consecutive CLOSED windows that saw zero samples. Reset to 0 by any window with
    /// at least one sample. `is_idle(n)` is `self.idle_windows >= n`, and it is the
    /// only thing that field exists for.
    idle_windows: u64,
    stats: GradientStats,
}

/// The ratio side of the gradient formula, isolated so the lossy `u64` to `f64`
/// conversion is justified in exactly one place.
#[allow(
    clippy::cast_precision_loss,
    reason = "rtt_base and rtt_short are microsecond latencies clamped by record_sample \
              to at most 60_000_000 (60 seconds), far below f64's 2^53 exact-integer \
              range, so this conversion never loses precision"
)]
fn gradient_of(tolerance: f64, rtt_base: u64, rtt_short: u64) -> f64 {
    (tolerance * (rtt_base as f64) / (rtt_short as f64)).clamp(0.5, 1.0)
}

impl GradientController {
    /// A controller starting at `min_limit` in slow start. `Err` for an invalid
    /// config.
    ///
    /// The histogram is `hdrhistogram::Histogram::<u64>::new_with_bounds(1,
    /// 60_000_000, 3)`, that is 1 microsecond to 60 seconds at 3 significant figures.
    /// Its `Err` (which can only occur for an invalid `sigfig` or an inverted range,
    /// neither of which these literals produce) is mapped to a [`ConfigError`] rather
    /// than unwrapped. `base` is `MonotonicMinDeque::new(cfg.base_windows)`,
    /// `idle_windows` is 0, and `window_started` is `now`.
    ///
    /// # Errors
    /// Returns the [`ConfigError`] from [`GradientConfig::validate`], or one naming
    /// `gradient.histogram` if the histogram bounds above are ever invalid.
    pub fn new(now: Millis, cfg: GradientConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        let hist = hdrhistogram::Histogram::<u64>::new_with_bounds(
            HISTOGRAM_LOW_US,
            HISTOGRAM_HIGH_US,
            HISTOGRAM_SIGFIG,
        )
        .map_err(|_| ConfigError {
            field: "gradient.histogram",
            value: "1..60000000/3".to_owned(),
            constraint: "hdrhistogram bounds must be valid",
        })?;
        Ok(Self {
            limit: f64::from(cfg.min_limit),
            hist,
            base: MonotonicMinDeque::new(cfg.base_windows),
            cfg,
            window_started: now,
            samples_this_window: 0,
            loss_this_window: false,
            slow_start: true,
            inflight_peak: 0,
            idle_windows: 0,
            stats: GradientStats::default(),
        })
    }

    /// Record one completed upstream attempt's latency. Request path; allocation-free.
    ///
    /// `rtt` is clamped to `[1, 60_000_000]` microseconds before being recorded, which
    /// is inside the histogram's own range, so [`GradientStats::histogram_errors`]
    /// never increments; a nonzero value there would mean this clamp had been removed.
    #[inline]
    pub fn record_sample(&mut self, rtt: Micros) {
        let us = rtt.0.clamp(HISTOGRAM_LOW_US, HISTOGRAM_HIGH_US);
        if self.hist.record(us).is_err() {
            self.stats.histogram_errors = self.stats.histogram_errors.saturating_add(1);
        }
        self.samples_this_window = self.samples_this_window.saturating_add(1);
    }

    /// Record a loss signal: a per-try timeout, a connection reset, or a 503 carrying
    /// `x-envoy-overloaded`. Triggers the fast-down at the next window boundary.
    #[inline]
    pub fn note_loss(&mut self) {
        self.loss_this_window = true;
    }

    /// Record the current in-flight count, read from `LeasedSemaphore::in_use` on THIS
    /// worker's own semaphore instance, not a cluster-wide sum shared across workers.
    /// See the module's "Wiring" section: the semaphore this count comes from and the
    /// one [`GradientController::maybe_close_window`] publishes into must be the same
    /// per-worker instance, or the `inflight < limit / 2` app-limited gate compares
    /// incompatible quantities. Feeds the app-limited hold.
    #[inline]
    pub fn note_inflight(&mut self, inflight: u32) {
        self.inflight_peak = self.inflight_peak.max(inflight);
    }

    /// Reset the per-window state, returning the sample count the window closed with.
    fn reset_window(&mut self, now: Millis) -> u32 {
        let samples = self.samples_this_window;
        self.hist.reset();
        self.samples_this_window = 0;
        self.loss_this_window = false;
        self.inflight_peak = 0;
        self.window_started = now;
        samples
    }

    /// Apply the smoothed control law with the given gradient, updating `self.limit`
    /// and the clamp-direction stats. The clamp is the anti-windup: the next call
    /// recomputes from the already-clamped value, so no error accumulates outside the
    /// configured range.
    fn apply_smoothed_update(&mut self, gradient: f64) {
        let q = self.limit.sqrt().max(4.0);
        let raw = self.limit * gradient + q;
        let next = (1.0 - self.cfg.alpha) * self.limit + self.cfg.alpha * raw;
        let min_limit_f = f64::from(self.cfg.min_limit);
        let max_limit_f = f64::from(self.cfg.max_limit);
        if next > max_limit_f {
            self.stats.clamped_high = self.stats.clamped_high.saturating_add(1);
        } else if next < min_limit_f {
            self.stats.clamped_low = self.stats.clamped_low.saturating_add(1);
        }
        self.limit = next.clamp(min_limit_f, max_limit_f);
    }

    /// Close the window if it is due, apply the control law, and publish the new limit
    /// into `sem`. `sem` MUST be a [`LeasedSemaphore`] instance private to this
    /// controller's own worker (see the module's "Wiring" section), not one shared
    /// with other workers: this call writes the whole limit, unmultiplied and
    /// unsummed, so a semaphore shared across workers would have each worker's write
    /// clobber the others'. Returns the window's signals, or `None` when the window is
    /// not due or had no samples.
    ///
    /// Does nothing to `sem` when `cfg.enabled` is false, but still maintains the
    /// signals, so an operator can observe what the controller WOULD have done before
    /// enabling it.
    ///
    /// The window is due when `elapsed >= window_min_ms AND samples >=
    /// window_min_samples`, OR when `elapsed >= 10 * window_min_ms` regardless of
    /// sample count: an escape hatch so a nearly idle cluster still closes windows
    /// instead of accumulating a stale histogram forever.
    ///
    /// `gradient` is computed once the baseline is known and is always in `[0.5,
    /// 1.0]`, whether or not the app-limited hold or slow start end up changing the
    /// limit: every field of [`WindowSignals`] is exported as a metric, so an operator
    /// can see what the controller measured even on a window where it did not act on
    /// it.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "self.limit is clamped to [min_limit, max_limit] as f64 before every \
                  publish, so it is always non-negative and within u32 range; this \
                  truncation only drops an already-applied clamp's fractional part"
    )]
    pub fn maybe_close_window(
        &mut self,
        now: Millis,
        sem: &LeasedSemaphore,
    ) -> Option<WindowSignals> {
        let elapsed = now.since(self.window_started);
        let due = (elapsed >= self.cfg.window_min_ms
            && self.samples_this_window >= self.cfg.window_min_samples)
            || elapsed >= 10 * self.cfg.window_min_ms;
        if !due {
            return None;
        }
        self.stats.windows = self.stats.windows.saturating_add(1);

        if self.samples_this_window == 0 {
            self.stats.empty_windows = self.stats.empty_windows.saturating_add(1);
            self.idle_windows = self.idle_windows.saturating_add(1);
            self.reset_window(now);
            return None;
        }
        self.idle_windows = 0;

        let rtt_short = self.hist.value_at_quantile(0.5).max(1);
        let samples = self.samples_this_window;

        if samples >= self.cfg.window_min_samples {
            self.base.push(rtt_short);
        } else {
            self.stats.baseline_push_skipped = self.stats.baseline_push_skipped.saturating_add(1);
        }

        let Some(rtt_base) = self.base.min() else {
            // Before the first representative window there is no baseline to compute
            // a gradient against: this window's own p50 was not representative
            // (fewer than window_min_samples), and no prior window pushed one either.
            // Report a neutral gradient of 1.0 and leave the limit untouched, rather
            // than synthesizing a baseline from a sample count too small to trust.
            let signals = WindowSignals {
                rtt_short_us: rtt_short,
                rtt_base_us: rtt_short,
                gradient: 1.0,
                limit: self.limit,
                app_limited: false,
                fast_down: false,
                slow_start: false,
                samples,
            };
            self.reset_window(now);
            return Some(signals);
        };

        let fast_down = self.loss_this_window;
        if fast_down {
            self.limit =
                (self.limit * self.cfg.fast_down_factor).max(f64::from(self.cfg.min_limit));
            self.stats.fast_downs = self.stats.fast_downs.saturating_add(1);
        }

        // Computed once the baseline is known, regardless of which branch below
        // actually acts on it: every WindowSignals field is a metric, so an
        // app-limited window still reports what the gradient WAS even though the
        // app-limited hold (not this value) is what kept the limit from moving.
        let gradient = gradient_of(self.cfg.tolerance, rtt_base, rtt_short);

        let app_limited = f64::from(self.inflight_peak) < self.limit / 2.0;
        let mut slow_start_fired = false;

        if app_limited {
            self.stats.app_limited_holds = self.stats.app_limited_holds.saturating_add(1);
        } else if self.slow_start {
            if gradient < 1.0 {
                self.slow_start = false;
                self.apply_smoothed_update(gradient);
            } else {
                let max_limit_f = f64::from(self.cfg.max_limit);
                let doubled = self.limit * 2.0;
                if doubled > max_limit_f {
                    self.stats.clamped_high = self.stats.clamped_high.saturating_add(1);
                }
                self.limit = doubled.min(max_limit_f);
                self.stats.slow_start_windows = self.stats.slow_start_windows.saturating_add(1);
                slow_start_fired = true;
            }
        } else {
            self.apply_smoothed_update(gradient);
        }

        if self.cfg.enabled {
            sem.set_limit(self.limit as u32); // it-allow: unchecked-cast reason: self.limit is clamped to [min_limit, max_limit] as f64 immediately before every publish (apply_smoothed_update, the fast-down floor, and slow start's doubling all clamp before returning), so it is always non-negative and within u32 range
        }

        self.reset_window(now);

        Some(WindowSignals {
            rtt_short_us: rtt_short,
            rtt_base_us: rtt_base,
            gradient,
            limit: self.limit,
            app_limited,
            fast_down,
            slow_start: slow_start_fired,
            samples,
        })
    }

    /// The current limit.
    #[must_use]
    pub fn limit(&self) -> f64 {
        self.limit
    }

    /// The current baseline, in microseconds.
    #[must_use]
    pub fn rtt_base_us(&self) -> Option<u64> {
        self.base.min()
    }

    /// True when the last `idle_windows` consecutive CLOSED windows all had zero
    /// samples, so the caller may drop this controller. Exactly `self.idle_windows >=
    /// idle_windows`, where the field counts consecutive empty closed windows and is
    /// reset to 0 by any window with at least one sample. The recommended argument is
    /// 10, the `idle_drop_windows` figure in the module's memory-bounding rule.
    #[must_use]
    pub fn is_idle(&self, idle_windows: u64) -> bool {
        self.idle_windows >= idle_windows
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> GradientStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::{GradientConfig, GradientController, Micros, Millis, WindowSignals};
    use crate::limits::LeasedSemaphore;

    /// Records `n` samples of `us` microseconds each.
    fn feed(controller: &mut GradientController, us: u64, n: u32) {
        for _ in 0..n {
            controller.record_sample(Micros(us));
        }
    }

    /// Test 10: the documented defaults, pinned as literals.
    #[test]
    fn default_config_values() {
        let cfg = GradientConfig::default();
        assert_eq!(cfg.min_limit, 4);
        assert_eq!(cfg.max_limit, 1000);
        assert!((cfg.alpha - 0.2).abs() < f64::EPSILON);
        assert!((cfg.tolerance - 1.5).abs() < f64::EPSILON);
        assert_eq!(cfg.window_min_ms, 100);
        assert_eq!(cfg.window_min_samples, 50);
        assert_eq!(cfg.base_windows, 600);
        assert!((cfg.fast_down_factor - 0.85).abs() < f64::EPSILON);
        assert!(!cfg.enabled);
    }

    /// Test 11: one row per clause of invariant 8, with `alpha = 0.0`, `alpha = 1.5`,
    /// and `tolerance = 0.5` called out explicitly, plus the boundary values that must
    /// still validate.
    #[test]
    fn validate_rejects_table() {
        let base = GradientConfig::default();

        let mut c = base;
        c.min_limit = 0;
        assert!(c.validate().is_err());

        let mut c = base;
        c.min_limit = c.max_limit + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.max_limit = GradientConfig::MAX_LIMIT_CEILING + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.alpha = f64::NAN;
        assert!(c.validate().is_err());
        let mut c = base;
        c.alpha = 0.0;
        assert!(
            c.validate().is_err(),
            "alpha = 0.0 must be rejected: slope 1 is not a contraction"
        );
        let mut c = base;
        c.alpha = 1.5;
        assert!(
            c.validate().is_err(),
            "alpha = 1.5 must be rejected: it overshoots"
        );

        let mut c = base;
        c.tolerance = f64::NAN;
        assert!(c.validate().is_err());
        let mut c = base;
        c.tolerance = 0.5;
        assert!(
            c.validate().is_err(),
            "tolerance = 0.5 must be rejected: the fixed point would fall below the \
             bandwidth-delay product"
        );
        let mut c = base;
        c.tolerance = GradientConfig::MAX_TOLERANCE + 1.0;
        assert!(c.validate().is_err());

        let mut c = base;
        c.window_min_ms = 0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.window_min_ms = GradientConfig::MAX_WINDOW_MIN_MS + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.window_min_samples = 0;
        assert!(c.validate().is_err());

        let mut c = base;
        c.base_windows = 0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.base_windows = GradientConfig::MAX_BASE_WINDOWS + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.fast_down_factor = f64::NAN;
        assert!(c.validate().is_err());
        let mut c = base;
        c.fast_down_factor = 0.0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.fast_down_factor = 1.0;
        assert!(c.validate().is_err());

        // The boundary values themselves must still validate.
        let mut c = base;
        c.max_limit = GradientConfig::MAX_LIMIT_CEILING;
        c.alpha = 1.0;
        c.tolerance = GradientConfig::MAX_TOLERANCE;
        c.window_min_ms = GradientConfig::MAX_WINDOW_MIN_MS;
        c.base_windows = GradientConfig::MAX_BASE_WINDOWS;
        assert!(c.validate().is_ok());

        assert!(base.validate().is_ok());
    }

    /// Test 12: closing an empty window leaves the limit unchanged, increments
    /// `empty_windows`, and returns `None`.
    #[allow(
        clippy::float_cmp,
        reason = "the empty-window path never touches self.limit, so the value read \
                  back is bit-for-bit the same f64, not merely numerically close"
    )]
    #[test]
    fn empty_window_no_update() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(1_000, 1, 1, 100);
        let before = controller.limit();

        let result = controller.maybe_close_window(Millis(10 * cfg.window_min_ms), &sem);

        assert!(result.is_none());
        assert_eq!(controller.stats().empty_windows, 1);
        assert_eq!(controller.limit(), before);
    }

    /// Test 13: the window closes exactly when both `elapsed >= window_min_ms` and
    /// `samples >= window_min_samples` hold, OR when `elapsed >= 10 * window_min_ms`
    /// regardless of sample count.
    #[test]
    fn window_closes_on_time_and_samples() {
        let cfg = GradientConfig::default();
        let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);

        let mut under_samples = GradientController::new(Millis(0), cfg).expect("valid config");
        feed(&mut under_samples, 1_000, 49);
        assert!(
            under_samples
                .maybe_close_window(Millis(200), &sem)
                .is_none()
        );

        let mut enough_samples = GradientController::new(Millis(0), cfg).expect("valid config");
        feed(&mut enough_samples, 1_000, 50);
        assert!(
            enough_samples
                .maybe_close_window(Millis(200), &sem)
                .is_some()
        );

        let mut escape_hatch = GradientController::new(Millis(0), cfg).expect("valid config");
        feed(&mut escape_hatch, 1_000, 1);
        assert!(
            escape_hatch
                .maybe_close_window(Millis(10 * cfg.window_min_ms), &sem)
                .is_some()
        );
    }

    /// Test 14: recording `10_000` samples including `Micros(0)` and `Micros(u64::MAX)`
    /// never increments `histogram_errors`, because `record_sample`'s own clamp keeps
    /// every value inside the histogram's configured range.
    #[test]
    fn histogram_errors_stay_zero() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.record_sample(Micros(0));
        controller.record_sample(Micros(u64::MAX));
        for i in 0..9_998u32 {
            controller.record_sample(Micros(1_000 + u64::from(i % 100)));
        }
        assert_eq!(controller.stats().histogram_errors, 0);
    }

    /// Test 15: from `min_limit = 4` with all samples equal (so `rtt_short ==
    /// rtt_base` and `gradient == 1.0` every window), three windows of slow start give
    /// limits 8, 16, 32.
    #[test]
    fn slow_start_doubles() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);
        let mut limits = Vec::new();

        for _ in 0..3 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 1_000, cfg.window_min_samples);
            let signals = controller
                .maybe_close_window(now, &sem)
                .expect("window due");
            limits.push(signals.limit);
        }

        assert_eq!(limits, vec![8.0, 16.0, 32.0]);
    }

    /// Test 16: a window whose `rtt_short` is 4x the established `rtt_base` produces
    /// `gradient == 0.5` (clamped), which exits slow start AND applies the smoothed
    /// law in that same window, rather than wasting a window on the doubling branch.
    #[test]
    fn slow_start_exits_on_gradient() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        // Window 1: establishes rtt_base = 1_000 us via the first, self-referential
        // push, and doubles the limit (gradient == 1.0) to 8.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let first = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(first.slow_start);

        // Window 2: rtt_short = 4_000 us is 4x rtt_base (1_000 us).
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 4_000, cfg.window_min_samples);
        let second = controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        assert!(
            !second.slow_start,
            "the smoothed law ran, not the doubling branch"
        );
        assert!((second.gradient - 0.5).abs() < f64::EPSILON);

        // `second.slow_start` is `slow_start_fired` (whether the DOUBLING branch ran
        // in window 2), which is already false whether or not `self.slow_start` was
        // actually cleared: deleting `self.slow_start = false;` at the point gradient
        // first drops below 1.0 leaves every assertion above unchanged, because the
        // smoothed law still runs in window 2 either way (gradient < 1.0 takes the
        // smoothed branch regardless of `self.slow_start`'s value). Assert the
        // CONTROLLER's own state directly, the way `anti_windup_at_max` and
        // `slow_start_doubling_clamped_at_max` already do for `limit`.
        assert!(
            !controller.slow_start,
            "self.slow_start must be cleared once gradient first drops below 1.0, not \
             merely have its doubling branch skipped for one window"
        );

        // Window 3: rtt_short = rtt_base (1_000 us, still the deque's minimum), so
        // gradient clamps back to 1.0. With slow_start correctly cleared this must
        // take the ADDITIVE smoothed-update branch (limit 8.0 -> 8.8), never the
        // doubling branch (which would give 16.0): this is what an uncleared
        // self.slow_start would actually do differently from here, since gradient ==
        // 1.0 re-enters the doubling arm whenever self.slow_start is (incorrectly)
        // still true.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let third = controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        assert!(
            (third.gradient - 1.0).abs() < f64::EPSILON,
            "window 3 must reproduce gradient == 1.0"
        );
        assert!(
            !third.slow_start,
            "gradient == 1.0 in window 3 must not re-enter the doubling branch"
        );
        assert!(
            (third.limit - 8.8).abs() < 1e-9,
            "expected the additive smoothed update (8.0 -> 8.8), got {} (16.0 would \
             mean the doubling branch ran instead, i.e. self.slow_start was never \
             actually cleared)",
            third.limit
        );
    }

    /// Test 17: with `inflight_peak = 1` and `limit = 100`, the limit is unchanged and
    /// `app_limited_holds == 1`.
    #[allow(
        clippy::float_cmp,
        reason = "the app-limited path never touches self.limit, so 100.0 read back \
                  is bit-for-bit the literal set above, not merely numerically close"
    )]
    #[test]
    fn app_limited_holds() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.limit = 100.0;
        controller.inflight_peak = 1;
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);

        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(signals.app_limited);
        assert_eq!(controller.limit(), 100.0);
        assert_eq!(controller.stats().app_limited_holds, 1);
    }

    /// Test 18: `inflight_peak = 50` with `limit = 100` does NOT hold, because the
    /// gate is `inflight < limit / 2`, not `<=`.
    #[test]
    fn app_limited_boundary() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.limit = 100.0;
        controller.inflight_peak = 50;
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);

        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(!signals.app_limited);
    }

    /// Test 19: `note_loss()` with `inflight_peak = 1` and `limit = 100` applies the
    /// fast-down FIRST (limit becomes 85), and the app-limited hold still fires on top
    /// of that.
    #[allow(
        clippy::float_cmp,
        reason = "100.0 * 0.85 rounds to exactly 85.0 in f64 (verified: no intervening \
                  representable value lies between them), and the fast-down path is the \
                  ONLY thing that touches self.limit before this assertion"
    )]
    #[test]
    fn fast_down_applies_before_hold() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.limit = 100.0;
        controller.inflight_peak = 1;
        controller.note_loss();
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);

        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(signals.fast_down);
        assert!(signals.app_limited);
        assert_eq!(controller.limit(), 85.0);
        assert_eq!(controller.stats().app_limited_holds, 1);
    }

    /// Test 20: from `limit == min_limit`, `note_loss()` leaves the limit at
    /// `min_limit` (the `max(min_limit)` floor).
    #[allow(
        clippy::float_cmp,
        reason = "the fast-down `.max(min_limit)` floor returns its argument bit-for-\
                  bit unchanged when it wins, so this is exact, not merely numerically close"
    )]
    #[test]
    fn fast_down_floors_at_min() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.note_loss();
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);

        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(signals.fast_down);
        assert_eq!(controller.limit(), f64::from(cfg.min_limit));
    }

    /// Test 21: driven to `max_limit` and past it for ten more growth windows, the
    /// limit stays exactly `max_limit`, `clamped_high >= 10`, and one contraction
    /// window immediately brings it below `max_limit`, proving no accumulated windup
    /// has to unwind first.
    #[allow(
        clippy::float_cmp,
        reason = "the smoothed update's `.clamp(min_limit, max_limit)` returns its \
                  argument bit-for-bit unchanged when the ceiling wins, so these are \
                  exact, not merely numerically close"
    )]
    #[test]
    fn anti_windup_at_max() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.limit = f64::from(cfg.max_limit);
        controller.slow_start = false;
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        for _ in 0..10 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 1_000, cfg.window_min_samples);
            let signals = controller
                .maybe_close_window(now, &sem)
                .expect("window due");
            assert_eq!(signals.limit, f64::from(cfg.max_limit));
        }
        assert!(controller.stats().clamped_high >= 10);
        assert_eq!(controller.limit(), f64::from(cfg.max_limit));

        now = now.add_ms(cfg.window_min_ms);
        controller.note_loss();
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let signals = controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        assert!(signals.limit < f64::from(cfg.max_limit));
    }

    /// Edge case 11: slow start reaching `max_limit`. The doubling is clamped,
    /// `clamped_high` increments, and `slow_start` remains true (no window has yet
    /// shown a gradient below 1.0 to exit it), because the limit cannot grow further
    /// anyway. A fresh controller's first window is self-referential (`rtt_base ==
    /// rtt_short`, since nothing was in the baseline before this push), so gradient
    /// is exactly 1.0 regardless of the fed latency, keeping the doubling branch live.
    #[allow(
        clippy::float_cmp,
        reason = "self.limit after a doubling-then-.min(max_limit) clamp is bit-for-\
                  bit the max_limit literal when the clamp wins, not merely close"
    )]
    #[test]
    fn slow_start_doubling_clamped_at_max() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.limit = 600.0;
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(signals.slow_start, "the doubling branch fired");
        assert_eq!(signals.limit, f64::from(cfg.max_limit));
        assert_eq!(controller.stats().clamped_high, 1);
        assert!(
            controller.slow_start,
            "slow start has not exited: gradient never dropped below 1.0"
        );

        // Doubling to land EXACTLY on max_limit (not past it) must NOT count as a
        // clamp: distinguishes the strict `>` this branch uses from `>=`, which the
        // scenario above (doubling well past max_limit) cannot, since both are true
        // once the doubled value already exceeds the ceiling.
        let mut exact = GradientController::new(Millis(0), cfg).expect("valid config");
        exact.limit = 500.0; // doubled == 1000.0 == the default max_limit, exactly.
        exact.note_inflight(1_000_000);
        feed(&mut exact, 1_000, cfg.window_min_samples);
        let exact_signals = exact
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");
        assert!(exact_signals.slow_start, "the doubling branch fired");
        assert_eq!(exact_signals.limit, f64::from(cfg.max_limit));
        assert_eq!(exact.stats().clamped_high, 0);
    }

    /// A mutation-testing gap: `apply_smoothed_update`'s clamp-direction stats must
    /// fire only on a STRICT crossing (`next > max_limit` / `next < min_limit`), never
    /// merely landing exactly ON the boundary, and must fire when genuinely past it.
    /// `alpha = 1.0` is used throughout so `next` equals `raw` exactly, with no
    /// averaging against the prior limit to introduce rounding.
    #[allow(
        clippy::float_cmp,
        reason = "every operand below is chosen so the control law's arithmetic lands \
                  on an exactly representable f64 value, not merely a close one"
    )]
    #[test]
    fn smoothed_update_clamp_boundaries() {
        // High: landing exactly ON max_limit must NOT count as a clamp. limit = 8.0
        // gives q = max(4, sqrt(8)) = 4, so raw = 8 * 1.0 + 4 = 12 == max_limit.
        let cfg_high = GradientConfig {
            max_limit: 12,
            alpha: 1.0,
            ..GradientConfig::default()
        };
        let mut exact_high = GradientController::new(Millis(0), cfg_high).expect("valid config");
        exact_high.limit = 8.0;
        exact_high.apply_smoothed_update(1.0);
        assert_eq!(exact_high.limit(), 12.0);
        assert_eq!(exact_high.stats().clamped_high, 0);

        // High: genuinely exceeding max_limit MUST count as a clamp. limit = 9.0
        // gives raw = 9 * 1.0 + 4 = 13 > max_limit (12).
        let mut over_high = GradientController::new(Millis(0), cfg_high).expect("valid config");
        over_high.limit = 9.0;
        over_high.apply_smoothed_update(1.0);
        assert_eq!(over_high.limit(), 12.0);
        assert_eq!(over_high.stats().clamped_high, 1);

        // Low: landing exactly ON min_limit must NOT count as a clamp. limit = 0.0
        // makes the `limit * gradient` term vanish regardless of gradient, so
        // raw = q = max(4, sqrt(0)) = 4 == the default min_limit.
        let cfg_low = GradientConfig {
            alpha: 1.0,
            ..GradientConfig::default()
        };
        let mut exact_low = GradientController::new(Millis(0), cfg_low).expect("valid config");
        exact_low.limit = 0.0;
        exact_low.apply_smoothed_update(0.5);
        assert_eq!(exact_low.limit(), 4.0);
        assert_eq!(exact_low.stats().clamped_low, 0);

        // Low: genuinely falling below min_limit MUST count as a clamp. The DEFAULT
        // min_limit (4) can never be undercut through the public API, because q's own
        // floor of 4 keeps raw >= 4 always regardless of limit or gradient; raising
        // min_limit above that floor makes the low clamp reachable at all.
        let cfg_low_raised = GradientConfig {
            min_limit: 10,
            alpha: 1.0,
            ..GradientConfig::default()
        };
        let mut under_low =
            GradientController::new(Millis(0), cfg_low_raised).expect("valid config");
        under_low.limit = 0.0;
        under_low.apply_smoothed_update(0.5);
        assert_eq!(under_low.limit(), 10.0);
        assert_eq!(under_low.stats().clamped_low, 1);
    }

    /// A mutation-testing gap: `reset_window`'s `self.loss_this_window = false` must
    /// run at the end of EVERY window that takes the normal (baseline-established)
    /// path, or a loss noted in one window keeps fast-downing every window after it
    /// even though `note_loss` is never called again.
    #[test]
    fn reset_window_clears_loss_flag_between_windows() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        now = now.add_ms(cfg.window_min_ms);
        controller.note_loss();
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let first = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(
            first.fast_down,
            "window 1 noted a loss, so fast_down must fire"
        );

        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let second = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(
            !second.fast_down,
            "window 2 noted no loss; a stale loss flag surviving from window 1 must \
             not fast-down it"
        );
    }

    /// A mutation-testing gap: `reset_window`'s `self.inflight_peak = 0` must run
    /// every window, or a high peak observed in one window keeps suppressing the
    /// app-limited hold in every window after it, even one that never calls
    /// `note_inflight` at all.
    #[test]
    fn reset_window_clears_inflight_peak_between_windows() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let first = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(
            !first.app_limited,
            "window 1's high inflight must not app-limit"
        );

        // Window 2 never calls note_inflight at all: with the peak correctly reset to
        // 0, `0 < limit / 2` holds and the app-limited hold must fire.
        now = now.add_ms(cfg.window_min_ms);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let second = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(
            second.app_limited,
            "window 2 called note_inflight zero times; a stale peak surviving from \
             window 1 must not suppress the app-limited hold"
        );
    }

    /// A mutation-testing gap: `reset_window`'s `self.window_started = now` must run
    /// every window, or the escape hatch (`elapsed >= 10 * window_min_ms`, measured
    /// from a STALE `window_started`) fires on a later window that has neither enough
    /// elapsed time since its own start nor enough samples.
    #[test]
    fn reset_window_resets_window_started_for_the_escape_hatch() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        // Window 1: a full window, closing normally at t = window_min_ms and (if
        // correct) resetting window_started to that value.
        let mut now = Millis(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        // Window 2: fewer than window_min_samples, so the sample-count condition
        // cannot fire it, and only 900 ms elapse since window_started was (correctly)
        // reset to 100 ms, short of the escape hatch's 1_000 ms threshold. If
        // window_started were NOT reset (stuck at its pre-construction value of 0),
        // elapsed-since-0 at t = 1_000 already reaches the escape hatch and the
        // window closes anyway.
        feed(&mut controller, 1_000, cfg.window_min_samples - 1);
        now = Millis(10 * cfg.window_min_ms);
        let result = controller.maybe_close_window(now, &sem);

        assert!(
            result.is_none(),
            "window 2 is due neither by sample count nor by elapsed time since its \
             own start; a stale window_started measuring elapsed time from window 1's \
             start instead would make the escape hatch fire early"
        );
    }

    /// A mutation-testing gap: `note_inflight` must track the PEAK inflight observed
    /// during the window (`max`), not merely overwrite with the latest call's value.
    /// Feeding a high value first and a much lower value second must still report the
    /// high peak at window close.
    #[test]
    fn note_inflight_tracks_peak_not_last_call() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.limit = 100.0;
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        controller.note_inflight(1_000_000);
        controller.note_inflight(1); // a later, much smaller reading in the same window
        feed(&mut controller, 1_000, cfg.window_min_samples);

        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(
            !signals.app_limited,
            "note_inflight must retain the window's PEAK (1_000_000), not the last \
             call's value (1): limit / 2 = 50 must not exceed the tracked peak"
        );
    }

    /// A mutation-testing gap: the empty-window branch's `self.reset_window(now)` call
    /// must run even though the window recorded zero samples, or a loss noted before
    /// an empty window closes leaks into the next, unrelated window's fast-down
    /// decision.
    #[test]
    fn empty_window_close_still_resets_loss_flag() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        // A loss is noted, but the window records zero samples and closes empty via
        // the escape hatch.
        controller.note_loss();
        let mut now = Millis(10 * cfg.window_min_ms);
        let empty = controller.maybe_close_window(now, &sem);
        assert!(empty.is_none(), "zero samples: the empty-window path");
        assert_eq!(controller.stats().empty_windows, 1);

        // A full, ordinary window follows, with no new loss noted.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let signals = controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        assert!(
            !signals.fast_down,
            "the loss was noted before an EMPTY window; if the empty-window branch \
             skipped resetting loss_this_window, it would incorrectly fast-down this \
             later, unrelated window"
        );
    }

    /// A mutation-testing gap: the no-baseline early-return branch's
    /// `self.reset_window(now)` call must run even though the baseline is not yet
    /// established, or a loss noted during an unrepresentative window leaks into the
    /// FIRST window that goes on to establish a baseline.
    #[test]
    fn no_baseline_window_close_still_resets_loss_flag() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        // A loss is noted, then the window closes via the escape hatch with a single
        // sample: fewer than window_min_samples, so nothing is pushed to the (still
        // empty) baseline, and this is the no-baseline early-return branch, not the
        // empty-window branch (samples_this_window == 1, not 0).
        controller.note_loss();
        controller.record_sample(Micros(1));
        let mut now = Millis(10 * cfg.window_min_ms);
        let sparse = controller
            .maybe_close_window(now, &sem)
            .expect("window due via escape hatch");
        assert!(
            !sparse.fast_down,
            "the no-baseline branch hardcodes fast_down: false regardless of the loss \
             flag"
        );
        assert_eq!(controller.stats().baseline_push_skipped, 1);

        // The very next window establishes the baseline for the first time (samples
        // >= window_min_samples), with no new loss noted.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let signals = controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        assert!(
            !signals.fast_down,
            "the loss was noted before the no-baseline window; if that branch skipped \
             resetting loss_this_window, it would incorrectly fast-down the first \
             window that establishes a baseline"
        );
    }

    /// `stats().windows` counts every window CLOSE (`due == true`), regardless of
    /// which of the three return paths (empty, no-baseline, normal) it takes; every
    /// other test only asserts the path-specific counter (`empty_windows`,
    /// `baseline_push_skipped`), never this one.
    #[test]
    fn stats_windows_counts_every_closed_window() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        // 1: the empty-window path.
        let mut now = Millis(10 * cfg.window_min_ms);
        assert!(controller.maybe_close_window(now, &sem).is_none());
        assert_eq!(controller.stats().windows, 1);

        // 2: the no-baseline path (one sample, closed via the escape hatch).
        controller.record_sample(Micros(1));
        now = now.add_ms(10 * cfg.window_min_ms);
        assert!(controller.maybe_close_window(now, &sem).is_some());
        assert_eq!(controller.stats().windows, 2);

        // 3: the normal path.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        assert!(controller.maybe_close_window(now, &sem).is_some());
        assert_eq!(controller.stats().windows, 3);
    }

    /// `stats().fast_downs` increments once per window that actually applies the
    /// fast-down, and only that many: it is not driven by `note_loss()` calls, by
    /// windows closed, or by any other counter.
    #[test]
    fn stats_fast_downs_counts_fast_down_windows() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        now = now.add_ms(cfg.window_min_ms);
        controller.note_loss();
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert_eq!(controller.stats().fast_downs, 1);

        // No note_loss() this time: the counter must not move.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert_eq!(controller.stats().fast_downs, 1);
    }

    /// `stats().slow_start_windows` increments once per window that actually takes
    /// the doubling branch, and stops moving the moment slow start exits, even
    /// though the controller keeps closing windows afterward.
    #[test]
    fn stats_slow_start_windows_counts_doubling_windows() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        // Window 1: self-referential baseline, gradient == 1.0, doubles.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert_eq!(controller.stats().slow_start_windows, 1);

        // Window 2: rtt_short 4x rtt_base exits slow start via the smoothed branch,
        // not the doubling branch.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 4_000, cfg.window_min_samples);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert_eq!(controller.stats().slow_start_windows, 1);
    }

    /// `WindowSignals::rtt_base_us` must be the deque's own baseline, distinct from
    /// `rtt_short_us` (this window's own p50) the moment the two diverge.
    #[test]
    fn window_signals_report_distinct_rtt_short_and_rtt_base() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        // Window 1: self-referential, rtt_short_us == rtt_base_us == 1_000.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let first = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert_eq!(first.rtt_short_us, 1_000);
        assert_eq!(first.rtt_base_us, 1_000);

        // Window 2: rtt_short_us tracks ~4_000 (the histogram's 3-significant-figure
        // quantization can round this slightly, hence the tolerance below), but
        // rtt_base_us stays at the deque's minimum, ~1_000: the two fields must now
        // read DIFFERENT values, an order of magnitude apart.
        now = now.add_ms(cfg.window_min_ms);
        controller.note_inflight(1_000_000);
        feed(&mut controller, 4_000, cfg.window_min_samples);
        let second = controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(
            second.rtt_short_us.abs_diff(4_000) <= 4,
            "rtt_short_us should track this window's own p50 (~4_000), got {}",
            second.rtt_short_us
        );
        assert!(
            second.rtt_base_us.abs_diff(1_000) <= 4,
            "rtt_base_us must report the baseline (~1_000), not this window's own p50 \
             (~4_000); got {}",
            second.rtt_base_us
        );
    }

    /// `WindowSignals::slow_start` reports THIS window's action (`slow_start_fired`:
    /// did the doubling branch run), not the controller's persistent
    /// `self.slow_start` state, which can remain `true` on a window that did NOT
    /// double because the app-limited hold ran first and pre-empted it.
    #[test]
    fn signals_slow_start_reports_this_windows_action_not_persistent_state() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        // limit starts at min_limit (4), so limit / 2 == 2; never calling
        // note_inflight leaves inflight_peak at its default of 0, well under that,
        // so the app-limited hold fires on this very first window, before slow
        // start's own branch ever runs.
        feed(&mut controller, 1_000, cfg.window_min_samples);
        let signals = controller
            .maybe_close_window(Millis(cfg.window_min_ms), &sem)
            .expect("window due");

        assert!(
            signals.app_limited,
            "the app-limited hold must fire this window"
        );
        assert!(
            !signals.slow_start,
            "the doubling branch did not run this window (the app-limited hold ran \
             first), so slow_start_fired must be false"
        );
        assert!(
            controller.slow_start,
            "the controller is still internally in slow start (no window has yet \
             shown gradient < 1.0 to clear it); this must differ from signals.slow_start \
             above to prove the field reports slow_start_fired, not self.slow_start"
        );
    }

    /// `is_idle(n)` is exactly `self.idle_windows >= n`: false before any window has
    /// closed, true only once `n` CONSECUTIVE closed windows in a row had zero
    /// samples, false one short of that count, and reset to false the moment a
    /// non-empty window closes.
    #[test]
    fn is_idle_tracks_consecutive_empty_windows() {
        let cfg = GradientConfig::default();
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(1_000, 1, 1, 100);
        let mut now = Millis(0);

        assert!(!controller.is_idle(1), "no window has closed yet");

        for _ in 0..2 {
            now = now.add_ms(10 * cfg.window_min_ms);
            let result = controller.maybe_close_window(now, &sem);
            assert!(result.is_none(), "an empty window returns None");
        }
        assert!(
            controller.is_idle(2),
            "two consecutive empty windows closed"
        );
        assert!(
            !controller.is_idle(3),
            "only two, not three, consecutive empty windows"
        );

        now = now.add_ms(cfg.window_min_ms);
        feed(&mut controller, 1_000, cfg.window_min_samples);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due");
        assert!(
            !controller.is_idle(1),
            "a non-empty window resets the idle streak"
        );
    }

    /// Test 22: with `enabled: false`, driving twenty windows never touches the
    /// semaphore's limit, even though `WindowSignals::limit` moves.
    #[test]
    fn disabled_does_not_publish() {
        let cfg = GradientConfig {
            enabled: false,
            ..GradientConfig::default()
        };
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(500, 1, 1, 100);
        let initial_sem_limit = sem.limit();
        let mut now = Millis(0);
        let mut moved = false;
        let mut last = controller.limit();

        for _ in 0..20 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 1_000, cfg.window_min_samples);
            let signals = controller
                .maybe_close_window(now, &sem)
                .expect("window due");
            if (signals.limit - last).abs() > f64::EPSILON {
                moved = true;
            }
            last = signals.limit;
        }

        assert_eq!(sem.limit(), initial_sem_limit);
        assert!(
            moved,
            "WindowSignals::limit should move even while disabled"
        );
    }

    /// Test 23: with `enabled: true`, the semaphore's `limit()` equals the
    /// controller's own limit, floored to `u32`, after each window.
    #[allow(
        clippy::float_cmp,
        reason = "both sides are round-tripped through the same truncating u32 \
                  conversion (the semaphore stores a u32, widened back losslessly with \
                  f64::from), so this is an exact integer-valued comparison in f64 clothing"
    )]
    #[test]
    fn publishes_when_enabled() {
        let cfg = GradientConfig {
            enabled: true,
            ..GradientConfig::default()
        };
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);
        let mut now = Millis(0);

        for _ in 0..5 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 1_000, cfg.window_min_samples);
            controller
                .maybe_close_window(now, &sem)
                .expect("window due");
            assert_eq!(
                f64::from(sem.limit()),
                controller.limit().trunc(),
                "the published limit must track the controller's own limit, floored"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Deterministic simulation tests (24-30). Each drives the controller
    // against a Little's law upstream model: no-load latency `r0_us` while
    // the simulated concurrency `c` is at or below the bandwidth-delay
    // product `c* = capacity_c * r0_us / 1_000_000`, and `c / capacity_c`
    // (in microseconds) beyond it. `note_inflight` is always given the exact
    // `c` the model just used, which is always at least `limit`, so the
    // app-limited hold never fires in these tests: they exist to check the
    // gradient control law itself, not the hold.
    // -----------------------------------------------------------------------

    /// Casts the controller's own `limit()` (already clamped to `[min_limit,
    /// max_limit]`) to the `u32` `note_inflight` and the semaphore take.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the value passed here is always GradientController::limit(), which is \
                  clamped to [min_limit, max_limit] as f64 by the control law itself, \
                  comfortably within u32 range and non-negative"
    )]
    fn as_u32(v: f64) -> u32 {
        v as u32
    }

    /// Casts a simulated round trip time to the `u64` `record_sample` takes.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "record_sample clamps its argument to [1, 60_000_000] before \
                  recording, so truncation here cannot escape that bound"
    )]
    fn as_u64(v: f64) -> u64 {
        v as u64
    }

    /// Little's law upstream model: no-load latency `r0_us` for `c <= c*`, and
    /// `c / capacity_c` beyond it (converted to microseconds), where
    /// `c* = capacity_c * r0_us / 1_000_000` is the bandwidth-delay product.
    fn model_rtt_us(c: f64, capacity_c: f64, r0_us: f64) -> f64 {
        let c_star = capacity_c * r0_us / 1_000_000.0;
        if c <= c_star {
            r0_us
        } else {
            c / capacity_c * 1_000_000.0
        }
    }

    /// Drives one simulated window: computes the upstream's observed latency for the
    /// controller's CURRENT limit under the model above, feeds it as
    /// `window_min_samples` identical samples, reports the current limit as the
    /// in-flight count (the model assumes traffic saturates the configured limit so
    /// the app-limited hold never fires), and closes the window.
    fn simulate_window(
        controller: &mut GradientController,
        sem: &LeasedSemaphore,
        now: &mut Millis,
        cfg: GradientConfig,
        capacity_c: f64,
        r0_us: f64,
    ) -> WindowSignals {
        let c = controller.limit();
        let rtt = as_u64(model_rtt_us(c, capacity_c, r0_us).max(1.0));
        controller.note_inflight(as_u32(c));
        feed(controller, rtt, cfg.window_min_samples);
        *now = now.add_ms(cfg.window_min_ms);
        controller
            .maybe_close_window(*now, sem)
            .expect("window due: exactly window_min_ms elapsed with window_min_samples recorded")
    }

    /// Test 24: from five different starting limits, the controller converges to
    /// within 10 percent of the branch-2 fixed point within 30 windows. The baseline
    /// is pre-seeded with the model's own `R0` before the run starts: the stability
    /// proof assumes `rtt_base == R0` (its definition), which holds only once the
    /// baseline has actually observed an unsaturated window. A start above `c*` that
    /// began instead with an EMPTY baseline would anchor the baseline on its own
    /// first (already saturated) observation, which is a property of a cold,
    /// empty-baseline start, not of the contraction this test checks.
    #[test]
    fn stability_converges_from_any_start() {
        let cfg = GradientConfig::default();
        let capacity_c = 4_000.0;
        let r0_us = 100_000.0;
        let c_star = 400.0_f64;
        let fp = 1.5 * c_star;
        let expected = fp + fp.sqrt();

        for &start in &[
            f64::from(cfg.min_limit),
            50.0,
            400.0,
            900.0,
            f64::from(cfg.max_limit),
        ] {
            let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
            controller.base.push(as_u64(r0_us));
            controller.limit = start;
            let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
            let mut now = Millis(0);
            let mut converged_within: Option<u32> = None;

            for window_idx in 1..=60u32 {
                let signals =
                    simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
                let rel_err = (signals.limit - expected).abs() / expected;
                if converged_within.is_none() && rel_err <= 0.10 {
                    converged_within = Some(window_idx);
                }
            }

            let final_rel_err = (controller.limit() - expected).abs() / expected;
            assert!(
                final_rel_err <= 0.10,
                "start {start}: final limit {} not within 10% of fixed point {expected}",
                controller.limit()
            );
            assert!(
                converged_within.is_some_and(|w| w <= 30),
                "start {start}: did not converge to within 10% within 30 windows (got {converged_within:?})"
            );
        }
    }

    /// Test 25: after convergence, 100 more windows of constant upstream traffic keep
    /// the limit's coefficient of variation below 0.05: the controller settles rather
    /// than hunting.
    #[allow(
        clippy::cast_precision_loss,
        reason = "n is this test's own fixed sample count (100), far below f64's exact-integer range"
    )]
    #[test]
    fn stability_no_limit_cycle() {
        let cfg = GradientConfig::default();
        let capacity_c = 4_000.0;
        let r0_us = 100_000.0;
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.base.push(as_u64(r0_us));
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        for _ in 0..60 {
            simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
        }

        let mut limits = Vec::with_capacity(100);
        for _ in 0..100 {
            let signals = simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
            limits.push(signals.limit);
        }

        let n = limits.len() as f64;
        let mean = limits.iter().sum::<f64>() / n;
        let variance = limits.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n;
        let cv = variance.sqrt() / mean;

        assert!(
            cv < 0.05,
            "coefficient of variation {cv} was not below 0.05 (mean {mean})"
        );
    }

    /// Test 26: halving `C` after convergence, the limit converges to within 10
    /// percent of the NEW fixed point within 30 more windows. `R0` (the no-load
    /// latency) is a property of the upstream's own service time and is unaffected by
    /// a capacity change, matching the model in the science plan.
    #[test]
    fn stability_tracks_capacity_halving() {
        let cfg = GradientConfig::default();
        let r0_us = 100_000.0;
        let mut capacity_c = 4_000.0;
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.base.push(as_u64(r0_us));
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        for _ in 0..60 {
            simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
        }

        capacity_c /= 2.0;
        let c_star2 = capacity_c * r0_us / 1_000_000.0;
        let fp2 = 1.5 * c_star2;
        let expected2 = fp2 + fp2.sqrt();

        let mut converged_within: Option<u32> = None;
        for window_idx in 1..=30u32 {
            let signals = simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
            let rel_err = (signals.limit - expected2).abs() / expected2;
            if converged_within.is_none() && rel_err <= 0.10 {
                converged_within = Some(window_idx);
            }
        }

        assert!(
            converged_within.is_some(),
            "did not converge to within 10% of the new fixed point {expected2} within 30 windows"
        );
    }

    /// Test 27: after convergence, one window whose `rtt_short` is 10x normal moves
    /// the limit by at most `alpha * 0.5 * limit`, the worst case allowed by the
    /// gradient's own lower clamp of 0.5.
    #[test]
    fn stability_spike_rejection() {
        let cfg = GradientConfig::default();
        let capacity_c = 4_000.0;
        let r0_us = 100_000.0;
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.base.push(as_u64(r0_us));
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        for _ in 0..60 {
            simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
        }

        let limit_before = controller.limit();
        let normal_rtt = model_rtt_us(limit_before, capacity_c, r0_us);
        let spike_rtt = as_u64((normal_rtt * 10.0).max(1.0));
        controller.note_inflight(as_u32(limit_before));
        feed(&mut controller, spike_rtt, cfg.window_min_samples);
        now = now.add_ms(cfg.window_min_ms);
        let signals = controller
            .maybe_close_window(now, &sem)
            .expect("window due");

        let bound = cfg.alpha * 0.5 * limit_before;
        assert!(
            (signals.limit - limit_before).abs() <= bound,
            "spike moved the limit by {} but the bound is {bound}",
            (signals.limit - limit_before).abs()
        );
    }

    /// Test 28: a bimodal mix (90 percent cheap, 10 percent expensive requests, same
    /// split every window) settles rather than oscillating. BOTH modes' latency is
    /// modeled against the ONE shared controller's own current limit via the same
    /// Little's law upstream (`model_rtt_us`) the single-mode stability tests use, so
    /// the fed latency genuinely responds to load: a fixed, load-INDEPENDENT latency
    /// (as an earlier version of this test used) can never oscillate because there is
    /// no feedback loop for it to oscillate through, which made a coefficient-of-
    /// variation check on it pass vacuously (cv == 0 on 200 identical values, every
    /// one of them `max_limit`, because a load-blind mixture keeps `gradient == 1.0`
    /// forever and the controller just doubles until the ceiling clamps it). After
    /// warming up (not part of the measured span, so the initial ramp from
    /// `min_limit` does not contaminate the measurement) 200 more windows of the same
    /// mix keep the coefficient of variation below 0.1, and the mean must land
    /// strictly between `min_limit` and `max_limit`, ruling out the previous defect's
    /// specific failure mode of a vacuous pass at a boundary. Two SEPARATE
    /// controllers, one per mode against its OWN Little's law model, converge to
    /// distinct steady limits: this is the executable form of "a client that can mix
    /// cheap and expensive requests can move the shared control signal", and the
    /// mitigation is that a controller is per (cluster, priority), never shared
    /// across a route mix.
    #[allow(
        clippy::cast_precision_loss,
        reason = "n is this test's own fixed sample count (200), far below f64's exact-integer range"
    )]
    #[allow(
        clippy::integer_division,
        reason = "computing a 90% split of window_min_samples; truncation only matters \
                  when window_min_samples is not a multiple of 10, and the default \
                  (50) used by this test divides evenly, giving exactly 45/5"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "this test drives a shared-mixture controller through warm-up and a \
                  measured span AND two separately-modelled single-mode controllers \
                  through their own convergence and settling checks in one function, \
                  because the second half depends on constants (capacity_c, the two \
                  r0 values) established in the first; splitting it would only move \
                  the line count into parameters threaded across two functions"
    )]
    #[test]
    fn adversarial_bimodal_no_oscillation() {
        let cfg = GradientConfig::default();
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let capacity_c = 4_000.0;
        let cheap_r0_us = 1_000.0;
        let expensive_r0_us = 500_000.0;

        // 90% cheap, 10% expensive: with window_min_samples == 50, 45 cheap and 5
        // expensive samples is exactly that split, and the p50 falls inside the cheap
        // majority every window (the expensive class's modeled latency never exceeds
        // its own bandwidth-delay product within max_limit, so it never displaces the
        // cheap class from the median; see the per-window feed below).
        let cheap_count = cfg.window_min_samples * 9 / 10;
        let expensive_count = cfg.window_min_samples - cheap_count;

        // Feeds one window of the bimodal mix, with BOTH modes' latency computed
        // against the controller's own CURRENT limit, and closes the window.
        let feed_mixed_window = |mixed: &mut GradientController| {
            let c = mixed.limit();
            mixed.note_inflight(as_u32(c));
            let cheap_rtt = as_u64(model_rtt_us(c, capacity_c, cheap_r0_us).max(1.0));
            let expensive_rtt = as_u64(model_rtt_us(c, capacity_c, expensive_r0_us).max(1.0));
            feed(mixed, cheap_rtt, cheap_count);
            feed(mixed, expensive_rtt, expensive_count);
        };

        let mut mixed = GradientController::new(Millis(0), cfg).expect("valid config");
        let mut now = Millis(0);
        for _ in 0..30 {
            now = now.add_ms(cfg.window_min_ms);
            feed_mixed_window(&mut mixed);
            mixed.maybe_close_window(now, &sem).expect("window due");
        }

        let mut limits = Vec::with_capacity(200);
        for _ in 0..200 {
            now = now.add_ms(cfg.window_min_ms);
            feed_mixed_window(&mut mixed);
            let signals = mixed.maybe_close_window(now, &sem).expect("window due");
            limits.push(signals.limit);
        }

        let n = limits.len() as f64;
        let mean = limits.iter().sum::<f64>() / n;
        let variance = limits.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n;
        let cv = variance.sqrt() / mean;
        assert!(
            mean > f64::from(cfg.min_limit) + f64::EPSILON
                && mean < f64::from(cfg.max_limit) - f64::EPSILON,
            "the mean {mean} sits AT a clamp boundary ({}..{}): a load-independent \
             mixture pins the limit at max_limit and would satisfy cv < 0.1 vacuously; \
             this bound rules that failure mode out",
            cfg.min_limit,
            cfg.max_limit
        );
        assert!(
            cv < 0.1,
            "bimodal coefficient of variation {cv} was not below 0.1 (mean {mean})"
        );

        let mut cheap_controller = GradientController::new(Millis(0), cfg).expect("valid config");
        cheap_controller.base.push(as_u64(1_000.0));
        let mut expensive_controller =
            GradientController::new(Millis(0), cfg).expect("valid config");
        expensive_controller.base.push(as_u64(500_000.0));
        let mut now_cheap = Millis(0);
        let mut now_expensive = Millis(0);

        for _ in 0..60 {
            simulate_window(
                &mut cheap_controller,
                &sem,
                &mut now_cheap,
                cfg,
                capacity_c,
                1_000.0,
            );
            simulate_window(
                &mut expensive_controller,
                &sem,
                &mut now_expensive,
                cfg,
                capacity_c,
                500_000.0,
            );
        }

        let cheap_a = cheap_controller.limit();
        simulate_window(
            &mut cheap_controller,
            &sem,
            &mut now_cheap,
            cfg,
            capacity_c,
            1_000.0,
        );
        let cheap_b = cheap_controller.limit();
        assert!(
            (cheap_b - cheap_a).abs() / cheap_a.max(1.0) < 0.05,
            "cheap controller did not settle: {cheap_a} -> {cheap_b}"
        );

        let expensive_a = expensive_controller.limit();
        simulate_window(
            &mut expensive_controller,
            &sem,
            &mut now_expensive,
            cfg,
            capacity_c,
            500_000.0,
        );
        let expensive_b = expensive_controller.limit();
        assert!(
            (expensive_b - expensive_a).abs() / expensive_a.max(1.0) < 0.05,
            "expensive controller did not settle: {expensive_a} -> {expensive_b}"
        );

        assert!(
            (cheap_controller.limit() - expensive_controller.limit()).abs() > 10.0,
            "cheap ({}) and expensive ({}) controllers converged to indistinguishable limits",
            cheap_controller.limit(),
            expensive_controller.limit()
        );
    }

    /// Test 29: closing a window through the `10 * window_min_ms` escape hatch with
    /// exactly ONE 1-microsecond sample cannot poison the baseline, because the push
    /// is gated on `window_min_samples`, not merely on the window having closed. The
    /// same value pushed as a FULL window (this time meeting the sample gate) DOES
    /// move the baseline, which shows the gate is on sample count, not on value.
    #[test]
    fn sparse_window_cannot_poison_baseline() {
        let cfg = GradientConfig::default();
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);

        // Converge against a steady 100 ms upstream so the baseline holds a
        // representative, non-trivial value.
        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        let mut now = Millis(0);
        for _ in 0..10 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 100_000, cfg.window_min_samples);
            controller
                .maybe_close_window(now, &sem)
                .expect("window due");
        }
        let rtt_base_before = controller.rtt_base_us().expect("baseline established");
        let skipped_before = controller.stats().baseline_push_skipped;

        // The poisoning attempt: exactly one 1-microsecond sample, closed through the
        // escape hatch rather than the sample-count gate.
        controller.record_sample(Micros(1));
        now = now.add_ms(10 * cfg.window_min_ms);
        controller
            .maybe_close_window(now, &sem)
            .expect("window due via escape hatch");

        assert_eq!(controller.rtt_base_us(), Some(rtt_base_before));
        assert_eq!(controller.stats().baseline_push_skipped, skipped_before + 1);

        // Fifty more windows of normal traffic: the limit must not begin contracting
        // because of the rejected poisoning attempt.
        let limit_before_recovery_check = controller.limit();
        for _ in 0..50 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 100_000, cfg.window_min_samples);
            controller
                .maybe_close_window(now, &sem)
                .expect("window due");
        }
        assert!(
            controller.limit() >= limit_before_recovery_check,
            "the limit contracted after a rejected one-sample poisoning attempt"
        );

        // Repeat with a FULL window of 1-microsecond samples: this time the sample
        // gate is met, so the baseline DOES move.
        let mut fresh = GradientController::new(Millis(0), cfg).expect("valid config");
        let mut now2 = Millis(0);
        for _ in 0..10 {
            now2 = now2.add_ms(cfg.window_min_ms);
            fresh.note_inflight(1_000_000);
            feed(&mut fresh, 100_000, cfg.window_min_samples);
            fresh.maybe_close_window(now2, &sem).expect("window due");
        }
        let fresh_rtt_base_before = fresh.rtt_base_us().expect("baseline established");

        now2 = now2.add_ms(cfg.window_min_ms);
        fresh.note_inflight(1_000_000);
        feed(&mut fresh, 1, cfg.window_min_samples);
        fresh.maybe_close_window(now2, &sem).expect("window due");

        let fresh_rtt_base_after = fresh.rtt_base_us().expect("baseline still established");
        assert!(
            fresh_rtt_base_after < fresh_rtt_base_before,
            "a full window of cheap samples must move the baseline down: {fresh_rtt_base_before} -> {fresh_rtt_base_after}"
        );
    }

    /// Test 30: converging against a 100 ms upstream, then a 200-window flood of
    /// 1-microsecond samples (a cheap request that does not respond to load), then a
    /// return to the SAME upstream. The limit never falls below `min_limit`.
    ///
    /// NOTE ON THE RECOVERY BOUND. The issue text for this test asserts recovery
    /// "within `base_windows` + 60 windows after the flood stops". A direct simulation
    /// of the algorithm exactly as specified (`sim2.py`, run against these same
    /// defaults) shows that bound does not hold: every flood window pushes the SAME
    /// value, so the monotonic deque's `>=` pop rule keeps only the MOST RECENT such
    /// push, meaning the poisoned entry is only `base_windows` pushes from aging out
    /// as measured from the LAST flood window, not the first. It then sits at the
    /// front of the deque for the full `base_windows` (600 by default), pinning the
    /// gradient at its 0.5 floor and contracting the limit down to a self-consistent
    /// floor around `2 * min_limit_slow_start_q` (empirically 8.0 at the defaults),
    /// well below the fixed point. Only once the poisoned entry ages out does the
    /// gradient return to normal; slow start has already fired once (permanently, by
    /// design) and does not re-engage, so the climb back up is the SLOW additive law
    /// (`limit += alpha * sqrt(limit)` per window), the same law the science plan's
    /// own settling-time analysis calls "too slow" and cites as the reason slow start
    /// exists in the first place. Measured recovery to within 20% of the fixed point
    /// is close to `base_windows + 194` windows, not `base_windows + 60`. Filed as
    /// issue #852; this test pins the ACTUAL measured bound instead of the one stated
    /// in the issue text, per the same "PINS the bound, does not re-derive it from a
    /// proof" rationale the issue gives for the test's own purpose.
    #[test]
    fn adversarial_cheap_flood_bounded() {
        let cfg = GradientConfig::default();
        let capacity_c = 4_000.0_f64;
        let r0_us = 100_000.0_f64;
        let c_star = capacity_c * r0_us / 1_000_000.0;
        let fp = 1.5 * c_star;
        let expected = fp + fp.sqrt();

        let mut controller = GradientController::new(Millis(0), cfg).expect("valid config");
        controller.base.push(as_u64(r0_us));
        let sem = LeasedSemaphore::new(10_000_000, 1, 1, 100);
        let mut now = Millis(0);

        for _ in 0..60 {
            simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
        }

        let mut worst: f64 = controller.limit();
        for _ in 0..200 {
            now = now.add_ms(cfg.window_min_ms);
            controller.note_inflight(1_000_000);
            feed(&mut controller, 1, cfg.window_min_samples);
            let signals = controller
                .maybe_close_window(now, &sem)
                .expect("window due");
            worst = worst.min(signals.limit);
            assert!(
                signals.limit >= f64::from(cfg.min_limit),
                "the limit fell below min_limit during the flood: {}",
                signals.limit
            );
        }

        // See the NOTE above: base_windows + 60 is the issue's stated bound, but it
        // does not hold under direct simulation of the algorithm as specified.
        // base_windows + 260 is the measured bound plus a safety margin.
        let recovery_windows = cfg.base_windows + 260;
        let mut recovered_within = None;
        for window_idx in 1..=recovery_windows {
            let signals = simulate_window(&mut controller, &sem, &mut now, cfg, capacity_c, r0_us);
            worst = worst.min(signals.limit);
            assert!(
                signals.limit >= f64::from(cfg.min_limit),
                "the limit fell below min_limit during recovery: {}",
                signals.limit
            );
            let rel_err = (signals.limit - expected).abs() / expected;
            // Require the band to be reached and held for the rest of the run, not
            // merely touched once while passing through it on the way down: a
            // transient crossing during the collapse toward the poisoned floor would
            // otherwise satisfy a naive "ever within 20%" check without the
            // controller having recovered anything.
            if rel_err <= 0.20 && recovered_within.is_none() {
                recovered_within = Some(window_idx);
            } else if rel_err > 0.20 {
                recovered_within = None;
            }
        }

        assert!(
            recovered_within.is_some(),
            "did not recover to within 20% of the fixed point {expected} and stay there \
             within {recovery_windows} windows after the flood stopped; worst observed \
             limit during the whole run was {worst}"
        );
    }
}
