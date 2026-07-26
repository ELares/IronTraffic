// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests that build and drive the data-plane and control-plane
//! runtimes end to end: real threads, real task spawns, real shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use irontraffic_io::{TaskError, TaskHandle};
use irontraffic_runtime::{ControlPlane, DataPlane, QuotaSource, RuntimeConfig, WorkerDerivation};

/// A `WorkerDerivation` reporting exactly `workers`, as if the host had a
/// different available-CPU count and no cgroup quota. `available_cpus` is
/// deliberately `workers + 3`, NOT equal to `workers`: the two fields must
/// stay distinguishable, or a test that only ever supplies `workers ==
/// available_cpus` cannot tell a correctly wired `DataPlane::workers()` (which
/// must read `derivation.workers`) from one that was wired to
/// `derivation.available_cpus` instead. Nothing about `derive_workers`'s own
/// clamping (not exercised here, since these tests build a `WorkerDerivation`
/// directly) could ever explain a passing result either way.
fn derivation(workers: usize) -> WorkerDerivation {
    WorkerDerivation {
        workers,
        source: QuotaSource::AvailableParallelism,
        quota_cpus: None,
        available_cpus: workers + 3,
    }
}

#[test]
fn balanced_multi_thread_reports_worker_count() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(4))
        .expect("a 4-worker data plane should build");
    assert_eq!(plane.workers(), 4);
    assert!(!plane.is_current_thread());
    // `derivation(4)` sets `available_cpus: 7` (workers + 3), so this also
    // proves `derivation()` reports the real stored value rather than a
    // fabricated one: a mutant that hardcoded `.workers = 1` here would still
    // pass every OTHER test in the suite that only ever builds with
    // `derivation(0)` or `derivation(1)`, where the correct clamped answer is
    // coincidentally also 1.
    assert_eq!(plane.derivation().workers, 4);
}

#[test]
fn single_worker_builds_current_thread() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(1))
        .expect("a 1-worker data plane should build");
    assert!(plane.is_current_thread());
    assert_eq!(plane.block_on(async { 1 + 1 }), 2);
}

#[test]
fn spawner_runs_a_task_on_the_data_plane() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(2))
        .expect("a 2-worker data plane should build");
    let flag = Arc::new(AtomicBool::new(false));
    let flag2 = Arc::clone(&flag);

    let spawner = plane.spawner();
    let handle: TaskHandle<()> = spawner.spawn(async move {
        flag2.store(true, Ordering::SeqCst);
    });
    let joined = plane.block_on(handle.join());

    assert!(joined.is_ok());
    assert!(flag.load(Ordering::SeqCst));
}

#[test]
fn planes_do_not_share_threads() {
    let data_plane = DataPlane::build(&RuntimeConfig::default(), derivation(2))
        .expect("a 2-worker data plane should build");
    let control_plane =
        ControlPlane::build(&RuntimeConfig::default()).expect("a control plane should build");

    // `block_on` on a multi-thread runtime runs the future on the calling
    // thread, not on a worker, so the thread name has to be read from inside
    // a task that was actually spawned onto (and therefore scheduled by)
    // each plane, then joined back, rather than from `block_on` directly.
    let data_task: TaskHandle<Option<String>> = data_plane
        .spawner()
        .spawn(async { std::thread::current().name().map(String::from) });
    let data_name = data_plane
        .block_on(data_task.join())
        .expect("data-plane task should not panic")
        .expect("data-plane worker thread should be named");

    let control_task: TaskHandle<Option<String>> = control_plane
        .spawner()
        .spawn(async { std::thread::current().name().map(String::from) });
    let control_name = control_plane
        .block_on(control_task.join())
        .expect("control-plane task should not panic")
        .expect("control-plane worker thread should be named");

    assert!(
        data_name.starts_with("irt-dp-"),
        "unexpected data-plane thread name: {data_name}"
    );
    assert!(
        control_name.starts_with("irt-cp-"),
        "unexpected control-plane thread name: {control_name}"
    );
}

#[test]
fn panicking_task_does_not_poison_the_runtime() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(2))
        .expect("a 2-worker data plane should build");
    let spawner = plane.spawner();

    let panicking: TaskHandle<()> = spawner.spawn(async {
        panic!("deliberate test panic");
    });
    let panicked = plane.block_on(panicking.join());
    assert!(matches!(panicked, Err(TaskError::Panicked)));

    let ok_task: TaskHandle<i32> = spawner.spawn(async { 7 });
    let result = plane.block_on(ok_task.join());
    assert_eq!(result.expect("second task should not panic"), 7);
}

#[test]
fn shutdown_timeout_returns_even_with_a_blocked_blocking_task() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(2))
        .expect("a 2-worker data plane should build");
    let spawner = plane.spawner();

    let started = Arc::new(AtomicBool::new(false));
    let started2 = Arc::clone(&started);
    let handle: TaskHandle<()> = spawner.spawn(async move {
        // tokio::task::spawn_blocking is permitted directly in a test. It
        // occupies a blocking-pool thread for far longer than the shutdown
        // deadline below, so this proves shutdown_timeout does not wait for
        // a wedged blocking task past its deadline.
        let _ = tokio::task::spawn_blocking(move || {
            started2.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(10));
        })
        .await;
    });
    handle.detach();

    // Wait for the blocking closure to actually start running before asking
    // the runtime to shut down. Without this wait, the test could pass for
    // the wrong reason: shutdown_timeout returning quickly because the
    // blocking task never got a chance to occupy a thread at all.
    plane.block_on(async {
        while !started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let start = Instant::now();
    plane.shutdown_timeout(Duration::from_millis(50));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "shutdown_timeout took too long: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// CLOSING TESTS from the mutation-testing lens review of PR #472.
// ---------------------------------------------------------------------------

/// The number reaching `Builder::worker_threads` is the derived count, not
/// merely the number `workers()` echoes back from its own input.
///
/// `plane.workers()` reads `derivation.workers`, the value the caller passed
/// in, so on its own it cannot distinguish a correctly sized runtime from one
/// built with a hardcoded, doubled, or ignored worker count.
/// `RuntimeMetrics::num_workers` is stable tokio API and reports what the
/// builder actually configured.
#[test]
fn data_plane_builder_receives_the_derived_worker_count() {
    for w in [2_usize, 3, 5] {
        let plane = DataPlane::build(&RuntimeConfig::default(), derivation(w))
            .expect("data plane should build");
        let task: TaskHandle<usize> = plane
            .spawner()
            .spawn(async { tokio::runtime::Handle::current().metrics().num_workers() });
        let actual = plane
            .block_on(task.join())
            .expect("worker-count task should not panic");
        assert_eq!(
            actual, w,
            "the runtime was built with {actual} workers for a derivation of {w}"
        );
        assert_eq!(plane.workers(), w, "workers() must report the same count");
    }
}

/// The control plane's `workers()` reports the runtime it actually built.
#[test]
fn control_plane_builder_receives_the_configured_worker_count() {
    let cfg = RuntimeConfig {
        control_workers: 3,
        ..RuntimeConfig::default()
    };
    let plane = ControlPlane::build(&cfg).expect("control plane should build");
    let task: TaskHandle<usize> = plane
        .spawner()
        .spawn(async { tokio::runtime::Handle::current().metrics().num_workers() });
    let actual = plane
        .block_on(task.join())
        .expect("worker-count task should not panic");
    assert_eq!(
        actual, 3,
        "control plane built {actual} workers, expected 3"
    );
    assert_eq!(plane.workers(), 3);
    assert_eq!(
        ControlPlane::build(&RuntimeConfig::default())
            .expect("default control plane should build")
            .workers(),
        2,
        "the documented control-plane default is 2 workers"
    );
}

/// `W == 1` builds a real current-thread runtime, not a one-worker
/// multi-thread runtime that merely reports `is_current_thread() == true`.
///
/// `is_current_thread()` returns a stored flag, so it cannot tell the two
/// apart. A current-thread runtime polls spawned tasks on the thread calling
/// `block_on`; a one-worker multi-thread runtime polls them on its own
/// `irt-dp-<n>` worker.
#[test]
fn single_worker_data_plane_is_really_a_current_thread_runtime() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(1))
        .expect("a 1-worker data plane should build");
    let task: TaskHandle<Option<String>> = plane
        .spawner()
        .spawn(async { std::thread::current().name().map(String::from) });
    let name = plane
        .block_on(task.join())
        .expect("thread-name task should not panic");
    assert!(
        !name.as_deref().is_some_and(|n| n.starts_with("irt-dp-")),
        "W == 1 must build a current-thread runtime driven by the caller, not a \
         one-worker multi-thread runtime with its own worker: task ran on {name:?}"
    );
    assert!(plane.is_current_thread());
}

/// The clamped blocking-pool cap is the value that reaches the builder, not a
/// value computed and then discarded.
///
/// `Builder::max_blocking_threads` panics on 0 ("Max blocking threads cannot
/// be set to 0"), so a build that survives a configured 0 proves the clamp is
/// on the path to the builder rather than only inside `resolve_blocking`.
#[test]
fn a_zero_blocking_override_is_clamped_before_it_reaches_the_builder() {
    let cfg = RuntimeConfig {
        max_blocking_threads: Some(0),
        control_max_blocking_threads: 0,
        ..RuntimeConfig::default()
    };
    let multi = DataPlane::build(&cfg, derivation(2))
        .expect("a multi-thread data plane must clamp a 0 blocking override");
    assert!(!multi.is_current_thread());
    let current = DataPlane::build(&cfg, derivation(1))
        .expect("a current-thread data plane must clamp a 0 blocking override");
    assert!(current.is_current_thread());
    let control =
        ControlPlane::build(&cfg).expect("the control plane must clamp a 0 blocking override");
    assert_eq!(control.workers(), 2);
}

/// The blocking pool the data plane actually runs with is capped at
/// `min(4, workers)`, not at tokio's 512 default and not at the control
/// plane's 32.
///
/// Nothing else in the suite observes the number that reaches
/// `Builder::max_blocking_threads`: `resolve_blocking` can be perfect while
/// the builder is handed a constant. The cap is observable only by making the
/// pool saturate, so this parks `cap + 2` blocking closures and counts how
/// many ever start.
#[test]
fn the_data_plane_blocking_pool_is_capped_at_min_four_and_workers() {
    // derivation(2) with no override means resolve_blocking -> min(4, 2) == 2.
    const EXPECTED_CAP: usize = 2;
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(2))
        .expect("a 2-worker data plane should build");

    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    for _ in 0..EXPECTED_CAP + 2 {
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        let handle: TaskHandle<()> = plane.spawner().spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                started.fetch_add(1, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .await;
        });
        handle.detach();
    }

    // Wait, with a generous deadline, for the pool to grow to its cap, then
    // give it a further window in which it must NOT grow past it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while started.load(Ordering::SeqCst) < EXPECTED_CAP && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(250));
    let concurrent = started.load(Ordering::SeqCst);
    release.store(true, Ordering::SeqCst);

    assert_eq!(
        concurrent, EXPECTED_CAP,
        "the blocking pool ran {concurrent} closures concurrently; min(4, 2 workers) is \
         {EXPECTED_CAP}, so the builder was handed the wrong cap"
    );
    plane.shutdown_timeout(Duration::from_secs(2));
}

/// A `WorkerDerivation` built directly (bypassing `derive_workers`, which
/// this crate does not control once `WorkerDerivation` is public with public
/// fields and no constructor) with `workers: 0` must not panic inside tokio.
///
/// `Builder::worker_threads(0)` and a current-thread runtime both reject a
/// zero-sized configuration; `DataPlane::build`'s own doc only promises
/// `RuntimeError::Build` for an operating-system failure, so an unclamped 0
/// reaching the builder would panic instead of returning that error. The
/// clamp lands in `resolve_data_workers`, and this proves it is actually
/// wired into `build`, not merely defined and unused.
#[test]
fn a_worker_derivation_with_zero_workers_does_not_panic() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(0))
        .expect("a zero-worker derivation must be clamped rather than panicking");
    assert_eq!(plane.workers(), 1);
    assert!(plane.is_current_thread());
    assert_eq!(plane.derivation().workers, 1);
}

// ---------------------------------------------------------------------------
// Closing tests from re-mutating the survivors above, down from 36 to 11.
// ---------------------------------------------------------------------------

/// `enable_all()` turns the I/O and time drivers on; without it, awaiting a
/// timer or a socket panics inside tokio ("there is no timer running") even
/// though the runtime built successfully. Nothing else in the suite awaits a
/// timer or does I/O on the `W == 1` current-thread path, so a build that
/// silently dropped `enable_all()` there would still pass every other test.
#[test]
fn single_worker_current_thread_runtime_has_the_timer_driver_enabled() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(1))
        .expect("a 1-worker data plane should build");
    let elapsed = plane.block_on(async {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        start.elapsed()
    });
    assert!(
        elapsed >= Duration::from_millis(5),
        "the timer driver must actually delay the task rather than resolve it immediately: {elapsed:?}"
    );
}

/// The same, for the control plane: nothing else in the suite awaits a timer
/// on a bare `ControlPlane::build(&RuntimeConfig::default())`, so a dropped
/// `enable_all()` there was invisible.
#[test]
fn control_plane_runtime_has_the_timer_driver_enabled() {
    let plane =
        ControlPlane::build(&RuntimeConfig::default()).expect("a control plane should build");
    let elapsed = plane.block_on(async {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        start.elapsed()
    });
    assert!(
        elapsed >= Duration::from_millis(5),
        "the timer driver must actually delay the task rather than resolve it immediately: {elapsed:?}"
    );
}

/// `thread_name("irt-dp-0")` on the `W == 1` current-thread builder names the
/// thread(s) tokio spawns for `spawn_blocking`, not the caller's own thread
/// (see the doc comment on `DataPlane::build`). Nothing else in the suite
/// spawns a blocking closure on the `W == 1` path and reads its name back, so
/// a wrong literal there was untested.
#[test]
fn single_worker_current_thread_runtime_names_its_blocking_thread_irt_dp_0() {
    let plane = DataPlane::build(&RuntimeConfig::default(), derivation(1))
        .expect("a 1-worker data plane should build");
    let task: TaskHandle<Option<String>> = plane.spawner().spawn(async {
        tokio::task::spawn_blocking(|| std::thread::current().name().map(String::from))
            .await
            .ok()
            .flatten()
    });
    let name = plane
        .block_on(task.join())
        .expect("the blocking task should not panic");
    assert_eq!(name.as_deref(), Some("irt-dp-0"));
}

/// `MAX_BLOCKING_THREADS` must actually be reachable as
/// `irontraffic_runtime::MAX_BLOCKING_THREADS`, the crate-root path every
/// downstream crate uses. Nothing else in this test binary names it that way
/// (the unit tests inside `plane.rs` import it through `super::`, which does
/// not exercise the `pub use` re-export in `lib.rs` at all), so a re-export
/// dropped from `lib.rs` would compile and pass every other test here while
/// breaking every downstream caller.
#[test]
fn max_blocking_threads_is_reexported_from_the_crate_root() {
    assert_eq!(irontraffic_runtime::MAX_BLOCKING_THREADS, 512);
}

/// The control-plane blocking pool is capped at `control_max_blocking_threads`
/// through `resolve_control_blocking`, not at the data-plane's `min(4, W)`
/// formula. The two resolvers read different fields of `RuntimeConfig`
/// (`control_max_blocking_threads` versus `max_blocking_threads`/`workers`),
/// and the control-plane startup log line calls `resolve_control_blocking`
/// directly, so a builder wired to the wrong resolver would still log a
/// correct-looking number while the pool it actually built was the wrong
/// size: the same "the line describes a runtime it did not build" failure
/// mode as the control-plane worker-count bug this PR fixes, just on the
/// blocking pool instead of the worker count. Only saturating the pool
/// observes which resolver actually reached the builder.
#[test]
fn the_control_plane_blocking_pool_is_capped_at_its_configured_value() {
    const EXPECTED_CAP: usize = 5;
    let cfg = RuntimeConfig {
        control_max_blocking_threads: EXPECTED_CAP,
        ..RuntimeConfig::default()
    };
    let plane = ControlPlane::build(&cfg).expect("a control plane should build");

    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    for _ in 0..EXPECTED_CAP + 2 {
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        let handle: TaskHandle<()> = plane.spawner().spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                started.fetch_add(1, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .await;
        });
        handle.detach();
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while started.load(Ordering::SeqCst) < EXPECTED_CAP && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(250));
    let concurrent = started.load(Ordering::SeqCst);
    release.store(true, Ordering::SeqCst);

    assert_eq!(
        concurrent, EXPECTED_CAP,
        "the control-plane blocking pool ran {concurrent} closures concurrently; \
         control_max_blocking_threads was {EXPECTED_CAP}, so the builder was handed the wrong cap"
    );
    plane.shutdown_timeout(Duration::from_secs(2));
}
