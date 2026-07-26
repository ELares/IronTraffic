// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-thread and thread-teardown cases for the buffer pool.
//!
//! These two cases genuinely need a second OS thread (a migration and a thread
//! exit), so they live here rather than beside the pool. Every other test is
//! inline in `src/buffer.rs`, next to the setup helper the decay tests share.

use irontraffic_io::{PooledBuf, acquire, stats};

/// `OUTSTANDING`, `ALLOCATIONS`, and `OVER_CAP_RELEASES` are process-wide, and
/// cargo runs the tests in this binary concurrently, so two tests asserting
/// exact deltas on those values race each other without this lock. Every test
/// below takes it for its whole body and asserts on deltas from a baseline
/// captured after taking it, never on absolute values.
static POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn cross_thread_release_is_accounted() {
    let _g = POOL_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let base = stats();

    let buf = acquire();
    let handle = std::thread::spawn(move || {
        // Dropped on this (different) thread: the chunk lands in this thread's
        // pool, not the acquiring thread's, which is the migration case.
        drop(buf);
    });
    handle.join().expect("release thread panicked");

    assert_eq!(stats().outstanding, base.outstanding);
}

#[test]
fn release_during_thread_teardown_does_not_panic() {
    let _g = POOL_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let base = stats();

    let handle = std::thread::spawn(|| {
        // A second, test-local thread-local, distinct from the pool's own.
        // Rust runs thread-local destructors in the reverse of the order they
        // were first initialized on a given thread, so touching LEAKED before
        // ever touching the pool guarantees the pool's thread-local is torn
        // down first: by the time LEAKED's own destructor drops the PooledBuf
        // it holds, this thread's pool no longer exists, which is exactly the
        // "drop during thread-local destruction" case `PooledBuf::drop`
        // handles with `POOL.try_with` rather than `POOL.with`.
        thread_local! {
            static LEAKED: std::sync::Mutex<Option<PooledBuf>> = const { std::sync::Mutex::new(None) };
        }
        LEAKED.with(|cell| {
            *cell
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        });

        let buf = acquire();
        LEAKED.with(|cell| {
            *cell
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(buf);
        });
    });
    handle.join().expect("teardown thread panicked");

    let after = stats();
    assert_eq!(after.outstanding, base.outstanding);
    // Proves this test actually reached the `POOL.try_with` `Err` branch in
    // `Drop for PooledBuf`, not merely that nothing panicked: the pool's own
    // thread-local was already torn down when LEAKED's destructor ran, so the
    // chunk was freed rather than pooled. Without the teardown-order trick
    // above, this chunk would instead land in the (now-gone) thread's free
    // list and this delta would be 0.
    assert_eq!(after.over_cap_releases, base.over_cap_releases + 1);
}
