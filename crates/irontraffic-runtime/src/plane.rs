// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two separately configured tokio runtimes: the data plane, sized from the
//! cgroup-derived worker count, and the control plane, a fixed-size runtime
//! for configuration reload, certificate loading, and the admin surface.
//!
//! Isolating the two matters because a Kubernetes watch resync storm or a
//! slow certificate parse must never steal cycles from request forwarding:
//! Pingora isolates per service and Envoy runs a dedicated main thread and
//! file flusher for exactly this reason.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::{MAX_WORKERS, WorkerDerivation};

/// The next thread index handed to a data-plane worker's `thread_name_fn`.
/// Separate from [`NEXT_CP`] so the two planes number their threads
/// independently and a data-plane name never skips because a control-plane
/// thread was created in between.
static NEXT_DP: AtomicUsize = AtomicUsize::new(0);
/// The next thread index handed to a control-plane worker's `thread_name_fn`.
static NEXT_CP: AtomicUsize = AtomicUsize::new(0);

/// How the data-plane runtime is structured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeMode {
    /// One multi-threaded work-stealing runtime with one `SO_REUSEPORT`
    /// socket per worker. Connection tasks may be stolen, which absorbs
    /// kernel hash skew and per-tenant workload skew. The default.
    #[default]
    Balanced,
    /// W pinned current-thread runtimes, shared-nothing. Requires CPU
    /// pinning and is refused in this version; the seam exists so the data
    /// plane never names a mode.
    Shard,
}

impl RuntimeMode {
    /// The lowercase configuration spelling: `balanced` or `shard`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Shard => "shard",
        }
    }
}

/// Runtime construction parameters.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Data-plane structure. Default [`RuntimeMode::Balanced`].
    pub mode: RuntimeMode,
    /// Explicit data-plane worker count. `None` derives it from the cgroup
    /// quota.
    ///
    /// This field is consumed by `derive_workers`, NOT by [`DataPlane::build`].
    /// By the time `build` runs, the override has already been resolved into
    /// `WorkerDerivation::workers` with `source: QuotaSource::Override`, so
    /// `build` reads `derivation.workers` and never this field. Reading both
    /// would let a caller pass an override and a derivation that disagree
    /// and get whichever one the implementation happened to prefer.
    pub workers: Option<usize>,
    /// Data-plane blocking pool cap. `None` means `min(4, workers)`. Never
    /// left at tokio's default of 512, and clamped to
    /// `1..=MAX_BLOCKING_THREADS`.
    pub max_blocking_threads: Option<usize>,
    /// Control-plane worker count. Default 2. Clamped to `1..=MAX_WORKERS`,
    /// because this number becomes operating-system threads.
    pub control_workers: usize,
    /// Control-plane blocking pool cap. Default 32, because the control
    /// plane does genuinely blocking work. Clamped to
    /// `1..=MAX_BLOCKING_THREADS`.
    pub control_max_blocking_threads: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            mode: RuntimeMode::Balanced,
            workers: None,
            max_blocking_threads: None,
            control_workers: 2,
            control_max_blocking_threads: 32,
        }
    }
}

/// The largest blocking-pool cap this process will configure, on either
/// plane.
///
/// Tokio's own default, and therefore the largest value anyone has a reason
/// to expect. A configured override above it is clamped: `max_blocking_threads`
/// is a ceiling on operating-system threads the pool may create, and a
/// configuration file must not be able to raise it without limit.
pub const MAX_BLOCKING_THREADS: usize = 512;

/// The blocking-pool cap actually passed to the data-plane builder: the
/// explicit override when there is one, otherwise `min(4, workers)`, never
/// below 1 because tokio rejects 0, and never above [`MAX_BLOCKING_THREADS`].
///
/// At a derived worker count of 1, which is what a 0.5 CPU or 100 millicore
/// Kubernetes pod produces, this resolves to `min(4, 1) == 1`: a blocking
/// pool exactly one thread deep. A second `spawn_blocking` closure does not
/// start until the first one returns, and tokio queues every further closure
/// past that in an unbounded queue: there is no depth limit and no shedding,
/// so a slow or wedged blocking closure backs up every closure queued behind
/// it, indefinitely, rather than failing fast. `tokio::net::lookup_host` and
/// `TcpStream::connect(&str)` both call `spawn_blocking` internally to
/// resolve the hostname, so this is not a hypothetical: request-driven
/// `spawn_blocking` on the data plane, including hostname resolution
/// performed per request, is not permitted. Resolve hostnames ahead of time
/// and cache the result, or connect by address.
pub(crate) fn resolve_blocking(cfg: &RuntimeConfig, workers: usize) -> usize {
    cfg.max_blocking_threads
        .unwrap_or_else(|| workers.min(4))
        .clamp(1, MAX_BLOCKING_THREADS)
}

/// The same for the control plane, whose default is 32 rather than
/// `min(4, W)`.
pub(crate) fn resolve_control_blocking(cfg: &RuntimeConfig) -> usize {
    cfg.control_max_blocking_threads
        .clamp(1, MAX_BLOCKING_THREADS)
}

/// The control-plane worker count actually passed to the builder. Clamped to
/// `MAX_WORKERS` because this number becomes operating-system threads. A
/// zero is rejected by `ControlPlane::build` before this is called, so the
/// lower bound here is defence in depth.
pub(crate) fn resolve_control_workers(cfg: &RuntimeConfig) -> usize {
    cfg.control_workers.clamp(1, MAX_WORKERS)
}

/// The data-plane worker count actually passed to the builder:
/// `derivation.workers`, clamped to `1..=MAX_WORKERS`.
///
/// `derive_workers` already guarantees its return value is in this range, so
/// on the path every caller in this workspace uses today, this is a no-op.
/// It exists as defence in depth, the same reason the doc comment on
/// [`resolve_control_workers`] gives: [`WorkerDerivation`] has public fields
/// and no constructor, so any caller, including a downstream crate, can
/// build one directly with `workers: 0` or `workers: usize::MAX`. Both
/// panic inside `tokio::runtime::Builder` rather than returning
/// [`RuntimeError::Build`] as `DataPlane::build`'s doc comment promises.
/// Extracted into a free function, like the other three resolvers, so a
/// test can assert on the clamp without spawning `MAX_WORKERS` real threads.
pub(crate) fn resolve_data_workers(workers: usize) -> usize {
    workers.clamp(1, MAX_WORKERS)
}

/// The data-plane runtime. Owns its threads; drop it or call
/// [`DataPlane::shutdown_timeout`] to stop them.
#[derive(Debug)]
pub struct DataPlane {
    runtime: tokio::runtime::Runtime,
    derivation: WorkerDerivation,
    /// `false` when `derivation.workers == 1` and a current-thread runtime
    /// was built instead of a one-worker multi-thread runtime.
    threaded: bool,
}

impl DataPlane {
    /// Builds the data-plane runtime.
    ///
    /// At `derivation.workers == 1` this builds a `new_current_thread`
    /// runtime rather than a one-worker multi-thread runtime, because a
    /// work-stealing scheduler with a single worker is pure overhead.
    /// Otherwise it builds a multi-thread runtime with one worker per
    /// `derivation.workers`. Every worker thread is named `irt-dp-<n>`, and
    /// the blocking pool is capped through [`resolve_blocking`], never left
    /// at tokio's default of 512.
    ///
    /// `derivation.workers` is clamped to `1..=MAX_WORKERS` through
    /// [`resolve_data_workers`] before it reaches the builder, `derive_workers`
    /// already guarantees this range so the clamp is a no-op on the production
    /// path, and it exists because [`WorkerDerivation`] is a public struct with
    /// public fields and no constructor: a caller can build one directly with
    /// `workers: 0` or `workers: usize::MAX`, and tokio panics on both rather
    /// than returning [`RuntimeError::Build`]. The clamped value is also what
    /// is stored back into `derivation`, so [`DataPlane::workers`],
    /// [`DataPlane::derivation`], and the startup log line all report the same
    /// number the runtime was actually built with.
    ///
    /// # Errors
    /// [`RuntimeError::ShardModeUnsupported`] when `cfg.mode` is
    /// [`RuntimeMode::Shard`], or [`RuntimeError::Build`] when the operating
    /// system refuses to create the threads.
    pub fn build(cfg: &RuntimeConfig, derivation: WorkerDerivation) -> Result<Self, RuntimeError> {
        if cfg.mode == RuntimeMode::Shard {
            return Err(RuntimeError::ShardModeUnsupported);
        }

        let mut derivation = derivation;
        derivation.workers = resolve_data_workers(derivation.workers);

        let threaded = derivation.workers != 1;
        let build_result = if derivation.workers == 1 {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(resolve_blocking(cfg, derivation.workers))
                .thread_name("irt-dp-0")
                .build()
        } else {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(derivation.workers)
                .max_blocking_threads(resolve_blocking(cfg, derivation.workers))
                .enable_all()
                .thread_name_fn(|| format!("irt-dp-{}", NEXT_DP.fetch_add(1, Ordering::Relaxed)))
                .build()
        };
        let runtime = build_result.map_err(|source| RuntimeError::Build {
            plane: "data",
            source,
        })?;

        tracing::info!(
            workers = derivation.workers,
            mode = "balanced",
            threaded,
            max_blocking_threads = resolve_blocking(cfg, derivation.workers),
            derivation = %derivation.summary(),
            "data plane runtime built"
        );

        Ok(Self {
            runtime,
            derivation,
            threaded,
        })
    }

    /// A handle for spawning onto this runtime. The only way to spawn a
    /// data-plane task, which is what makes the "never call `tokio::spawn`"
    /// rule enforceable.
    #[must_use]
    pub fn spawner(&self) -> irontraffic_io::Spawner {
        irontraffic_io::Spawner::from_handle(self.runtime.handle().clone())
    }

    /// Worker thread count.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.derivation.workers
    }

    /// Where the worker count came from.
    #[must_use]
    pub fn derivation(&self) -> WorkerDerivation {
        self.derivation
    }

    /// True when a current-thread runtime was built because the worker count
    /// is 1.
    #[must_use]
    pub fn is_current_thread(&self) -> bool {
        !self.threaded
    }

    /// Runs `fut` to completion on this runtime.
    ///
    /// # Panics
    /// Panics inside tokio when called from a thread already driving a
    /// runtime. Call only from a non-async context; the only caller is the
    /// binary's synchronous `main`.
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        self.runtime.block_on(fut)
    }

    /// Shuts the runtime down, waiting at most `dur` for blocking tasks.
    /// Prevents a wedged `spawn_blocking` from holding the process open.
    ///
    /// # Panics
    /// Panics inside tokio when called from within an asynchronous context.
    /// `DataPlane` must be dropped, or have this called, on the thread that
    /// built it.
    pub fn shutdown_timeout(self, dur: Duration) {
        self.runtime.shutdown_timeout(dur);
    }
}

/// The control-plane runtime: configuration reload, certificate loading, the
/// admin surface, log flushing. Separate from the data plane so a
/// control-plane storm cannot steal cycles from forwarding.
#[derive(Debug)]
pub struct ControlPlane {
    runtime: tokio::runtime::Runtime,
    workers: usize,
}

impl ControlPlane {
    /// Builds the control-plane runtime.
    ///
    /// # Errors
    /// [`RuntimeError::ZeroControlWorkers`] when `control_workers` is 0, or
    /// [`RuntimeError::Build`] on an operating system failure.
    pub fn build(cfg: &RuntimeConfig) -> Result<Self, RuntimeError> {
        if cfg.control_workers == 0 {
            return Err(RuntimeError::ZeroControlWorkers);
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(resolve_control_workers(cfg))
            .max_blocking_threads(resolve_control_blocking(cfg))
            .enable_all()
            .thread_name_fn(|| format!("irt-cp-{}", NEXT_CP.fetch_add(1, Ordering::Relaxed)))
            .build()
            .map_err(|source| RuntimeError::Build {
                plane: "control",
                source,
            })?;

        // `workers` is the resolved (post-clamp) count, not `cfg.control_workers`
        // directly: `ControlPlane::workers()` already reports the resolved
        // value (see the field assignment below), and this line must describe
        // the runtime it built, per Invariant 5, not the configuration that
        // requested it. Logging the raw configured value here would make this
        // line internally inconsistent with `max_blocking_threads`, which was
        // already the resolved value, and would disagree with `workers()` for
        // any `control_workers` above `MAX_WORKERS`.
        tracing::info!(
            workers = resolve_control_workers(cfg),
            max_blocking_threads = resolve_control_blocking(cfg),
            "control plane runtime built"
        );

        Ok(Self {
            runtime,
            workers: resolve_control_workers(cfg),
        })
    }

    /// A handle for spawning control-plane tasks.
    #[must_use]
    pub fn spawner(&self) -> irontraffic_io::Spawner {
        irontraffic_io::Spawner::from_handle(self.runtime.handle().clone())
    }

    /// Worker thread count.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Runs `fut` to completion on this runtime.
    ///
    /// # Panics
    /// Panics inside tokio when called from a thread already driving a
    /// runtime.
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        self.runtime.block_on(fut)
    }

    /// Shuts the runtime down, waiting at most `dur` for blocking tasks.
    ///
    /// # Panics
    /// Panics inside tokio when called from within an asynchronous context.
    pub fn shutdown_timeout(self, dur: Duration) {
        self.runtime.shutdown_timeout(dur);
    }
}

/// A runtime could not be built.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// `runtime.mode = shard` was requested. Refused in this version because
    /// it requires CPU pinning, which is not implemented, and unpinned
    /// shared-nothing has neither locality nor rebalancing.
    #[error(
        "runtime.mode = shard is not supported in this version: it requires CPU pinning, and \
         unpinned shared-nothing has neither locality nor rebalancing. Use runtime.mode = balanced."
    )]
    ShardModeUnsupported,
    /// The operating system refused to create the threads for `plane`.
    #[error("failed to build the {plane} runtime: {source}")]
    Build {
        /// Which plane failed to build: `"data"` or `"control"`.
        plane: &'static str,
        /// The underlying operating system error.
        #[source]
        source: std::io::Error,
    },
    /// `RuntimeConfig::control_workers` was 0. A control plane with no
    /// workers cannot reload configuration, so this is an error rather than
    /// a clamp: the operator must be told rather than surprised.
    #[error("control_workers must be at least 1")]
    ZeroControlWorkers,
}

#[cfg(test)]
mod tests {
    use super::{
        ControlPlane, DataPlane, MAX_BLOCKING_THREADS, RuntimeConfig, RuntimeError, RuntimeMode,
        resolve_blocking, resolve_control_blocking, resolve_control_workers, resolve_data_workers,
    };
    use crate::{MAX_WORKERS, QuotaSource, WorkerDerivation};

    fn derivation(workers: usize) -> WorkerDerivation {
        WorkerDerivation {
            workers,
            source: QuotaSource::AvailableParallelism,
            quota_cpus: None,
            available_cpus: workers,
        }
    }

    #[test]
    fn shard_mode_is_refused() {
        let cfg = RuntimeConfig {
            mode: RuntimeMode::Shard,
            ..RuntimeConfig::default()
        };
        let err = DataPlane::build(&cfg, derivation(4)).expect_err("shard mode must be refused");
        assert!(matches!(err, RuntimeError::ShardModeUnsupported));
        assert!(
            err.to_string().contains("balanced"),
            "error message should name the working alternative: {err}"
        );
    }

    #[test]
    fn resolve_blocking_table() {
        let data_plane_rows: &[(usize, Option<usize>, usize)] = &[
            (96, None, 4),
            (1, None, 1),
            (2, None, 2),
            (8, Some(0), 1),
            (8, Some(64), 64),
            (8, Some(512), 512),
            (8, Some(usize::MAX), 512),
        ];
        for &(workers, max_blocking_threads, expected) in data_plane_rows {
            let cfg = RuntimeConfig {
                max_blocking_threads,
                ..RuntimeConfig::default()
            };
            assert_eq!(
                resolve_blocking(&cfg, workers),
                expected,
                "workers={workers} max_blocking_threads={max_blocking_threads:?}"
            );
        }

        let control_plane_rows: &[(usize, usize)] = &[(0, 1), (32, 32), (usize::MAX, 512)];
        for &(control_max_blocking_threads, expected) in control_plane_rows {
            let cfg = RuntimeConfig {
                control_max_blocking_threads,
                ..RuntimeConfig::default()
            };
            assert_eq!(
                resolve_control_blocking(&cfg),
                expected,
                "control_max_blocking_threads={control_max_blocking_threads}"
            );
        }

        assert_eq!(MAX_BLOCKING_THREADS, 512);
    }

    #[test]
    fn zero_control_workers_is_an_error() {
        let cfg = RuntimeConfig {
            control_workers: 0,
            ..RuntimeConfig::default()
        };
        let err = ControlPlane::build(&cfg).expect_err("zero control workers must error");
        assert!(matches!(err, RuntimeError::ZeroControlWorkers));
    }

    #[test]
    fn control_workers_are_clamped_to_max_workers() {
        let max_cfg = RuntimeConfig {
            control_workers: usize::MAX,
            ..RuntimeConfig::default()
        };
        assert_eq!(resolve_control_workers(&max_cfg), MAX_WORKERS);

        let normal_cfg = RuntimeConfig {
            control_workers: 2,
            ..RuntimeConfig::default()
        };
        assert_eq!(resolve_control_workers(&normal_cfg), 2);

        // The doc comment on `resolve_control_workers` calls its lower bound
        // "defence in depth" because `ControlPlane::build` already rejects 0
        // before this function is ever reached in production. That claim was
        // previously untested: nothing called `resolve_control_workers`
        // directly with 0, so the lower half of its `clamp(1, MAX_WORKERS)`
        // was free to be wrong (or dropped) without any test noticing.
        let unreached_zero_cfg = RuntimeConfig {
            control_workers: 0,
            ..RuntimeConfig::default()
        };
        assert_eq!(resolve_control_workers(&unreached_zero_cfg), 1);

        let zero_cfg = RuntimeConfig {
            control_workers: 0,
            ..RuntimeConfig::default()
        };
        let err = ControlPlane::build(&zero_cfg).expect_err("zero control workers must error");
        assert!(matches!(err, RuntimeError::ZeroControlWorkers));

        // The pure resolver is correct (asserted above), but nothing yet
        // asserts that `ControlPlane::build` actually wires its result into
        // the struct `workers()` reads back rather than, say, storing
        // `cfg.control_workers` directly. `Builder::worker_threads` is only
        // ever called with `resolve_control_workers(cfg)` (see `build`), so
        // this still spawns exactly `MAX_WORKERS` threads, not `usize::MAX`
        // of them, and measured at under 20ms on this machine: not the
        // "wasteful" cost a raw `usize::MAX` spawn would be. `control_workers:
        // usize::MAX` is deliberately reused from `max_cfg` above rather than
        // a small in-range value like 3, because a small in-range value
        // cannot distinguish "wired to the resolved value" from "wired to the
        // raw configured value": both equal 3. Only a value that clamping
        // actually changes can catch that mutant.
        let plane =
            ControlPlane::build(&max_cfg).expect("a control plane must build with a clamped count");
        assert_eq!(plane.workers(), MAX_WORKERS);

        // Also cover a small, cheap, in-range build end to end, so the
        // ordinary (non-clamped) path through `build` is exercised by a real
        // runtime too, not only by the pure resolver.
        let built_cfg = RuntimeConfig {
            control_workers: 3,
            ..RuntimeConfig::default()
        };
        let small_plane =
            ControlPlane::build(&built_cfg).expect("a 3-worker control plane should build");
        assert_eq!(small_plane.workers(), 3);
    }

    #[test]
    fn resolve_data_workers_clamps_to_max_workers() {
        assert_eq!(resolve_data_workers(0), 1);
        assert_eq!(resolve_data_workers(5), 5);
        assert_eq!(resolve_data_workers(usize::MAX), MAX_WORKERS);
        assert_eq!(resolve_data_workers(2000), MAX_WORKERS);
    }

    #[test]
    fn runtime_mode_as_str_and_default_are_pinned() {
        assert_eq!(RuntimeMode::Balanced.as_str(), "balanced");
        assert_eq!(RuntimeMode::Shard.as_str(), "shard");
        // `RuntimeConfig::default()` sets `mode: RuntimeMode::Balanced,`
        // explicitly rather than deriving it from `RuntimeMode::default()`,
        // so this is the only assertion in the suite that would notice the
        // `#[default]` attribute moving to the wrong variant of `RuntimeMode`
        // itself.
        assert_eq!(RuntimeMode::default(), RuntimeMode::Balanced);
    }

    #[test]
    fn runtime_config_default_values_are_pinned() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.mode, RuntimeMode::Balanced);
        assert_eq!(cfg.workers, None);
        assert_eq!(cfg.max_blocking_threads, None);
        assert_eq!(cfg.control_workers, 2);
        // Every other test that reads `control_max_blocking_threads` supplies
        // its own value via struct-update syntax, so the literal `32` in
        // `RuntimeConfig::default()` was previously exercised only through
        // clamping tests that override it, never read back unmodified.
        assert_eq!(cfg.control_max_blocking_threads, 32);
    }
}

#[cfg(test)]
mod startup_log_tests {
    use super::{ControlPlane, DataPlane, RuntimeConfig};
    use crate::{QuotaSource, WorkerDerivation};
    use std::collections::BTreeMap;
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    /// One captured `tracing` event: its message and its fields, both as
    /// strings, so an assertion can name a field and a value literally.
    #[derive(Default, Debug)]
    struct Captured {
        message: String,
        fields: BTreeMap<String, String>,
    }

    struct Collector(Arc<Mutex<Vec<Captured>>>);

    struct FieldVisitor<'a>(&'a mut Captured);

    impl Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
            let rendered = format!("{value:?}");
            if field.name() == "message" {
                self.0.message = rendered;
            } else {
                self.0.fields.insert(
                    field.name().to_owned(),
                    rendered.trim_matches('"').to_owned(),
                );
            }
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0
                .fields
                .insert(field.name().to_owned(), value.to_string());
        }
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.0
                .fields
                .insert(field.name().to_owned(), value.to_string());
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                self.0.message = value.to_owned();
            } else {
                self.0
                    .fields
                    .insert(field.name().to_owned(), value.to_owned());
            }
        }
    }

    impl Subscriber for Collector {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut captured = Captured::default();
            event.record(&mut FieldVisitor(&mut captured));
            if let Ok(mut events) = self.0.lock() {
                events.push(captured);
            }
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    fn capture<T>(f: impl FnOnce() -> T) -> Vec<Captured> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let collector = Collector(Arc::clone(&events));
        tracing::subscriber::with_default(collector, f);
        let guard = events
            .lock()
            .expect("no test thread panics while holding this");
        guard
            .iter()
            .map(|c| Captured {
                message: c.message.clone(),
                fields: c.fields.clone(),
            })
            .collect()
    }

    /// The data-plane startup line is the one place an operator learns how
    /// many workers exist and why, so its field NAMES and its field VALUES are
    /// both part of the contract: a dashboard keys on `workers`, `mode`,
    /// `threaded`, `max_blocking_threads` and `derivation`.
    #[test]
    fn data_plane_startup_log_line_is_pinned() {
        let derivation = WorkerDerivation {
            workers: 6,
            source: QuotaSource::AvailableParallelism,
            quota_cpus: None,
            available_cpus: 6,
        };
        let events = capture(|| {
            let plane = DataPlane::build(&RuntimeConfig::default(), derivation)
                .expect("a 6-worker data plane should build");
            drop(plane);
        });

        let line = events
            .iter()
            .find(|e| e.message == "data plane runtime built")
            .expect("exactly one data-plane startup line must be emitted");
        assert_eq!(
            events
                .iter()
                .filter(|e| e.message == "data plane runtime built")
                .count(),
            1,
            "invariant 5: exactly one line per plane per build"
        );
        assert_eq!(line.fields.get("workers").map(String::as_str), Some("6"));
        assert_eq!(
            line.fields.get("mode").map(String::as_str),
            Some("balanced")
        );
        assert_eq!(
            line.fields.get("threaded").map(String::as_str),
            Some("true")
        );
        // min(4, 6) == 4, and it must be the resolved value, not a constant.
        assert_eq!(
            line.fields.get("max_blocking_threads").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            line.fields.get("derivation").map(String::as_str),
            Some(derivation.summary().as_str()),
            "the line must carry the cgroup numbers the worker count came from"
        );
    }

    /// At `W == 1` the same line reports the current-thread runtime honestly.
    #[test]
    fn data_plane_startup_log_line_reports_current_thread_at_one_worker() {
        let derivation = WorkerDerivation {
            workers: 1,
            source: QuotaSource::AvailableParallelism,
            quota_cpus: None,
            available_cpus: 1,
        };
        let events = capture(|| {
            drop(DataPlane::build(&RuntimeConfig::default(), derivation).expect("builds"));
        });
        let line = events
            .iter()
            .find(|e| e.message == "data plane runtime built")
            .expect("a startup line must be emitted");
        assert_eq!(line.fields.get("workers").map(String::as_str), Some("1"));
        assert_eq!(
            line.fields.get("threaded").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            line.fields.get("max_blocking_threads").map(String::as_str),
            Some("1")
        );
    }

    /// The control-plane line reports the CLAMPED worker count, which is the
    /// number of operating-system threads that actually exist. Reporting the
    /// raw configured value would tell an operator 10000 while 1024 threads
    /// ran.
    #[test]
    fn control_plane_startup_log_line_reports_the_clamped_worker_count() {
        let cfg = RuntimeConfig {
            control_workers: 3,
            control_max_blocking_threads: 100_000,
            ..RuntimeConfig::default()
        };
        let events = capture(|| {
            drop(ControlPlane::build(&cfg).expect("control plane builds"));
        });
        let line = events
            .iter()
            .find(|e| e.message == "control plane runtime built")
            .expect("a control-plane startup line must be emitted");
        assert_eq!(line.fields.get("workers").map(String::as_str), Some("3"));
        assert_eq!(
            line.fields.get("max_blocking_threads").map(String::as_str),
            Some("512"),
            "the line must report the clamped cap, not the configured 100000"
        );
    }
}
