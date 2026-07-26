// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ConnRegistry`, the bounded population of live connections, and its RAII guard.
//!
//! `ConnRegistry.current` is a BALANCE, not a counter: it is incremented at admission
//! and decremented only inside `Drop for ConnGuard`, and there is no public release
//! method. A public `release()` "for the error path" is forgotten on one of several
//! call sites and the endpoint silently loses capacity for the life of the process,
//! which is the one defect this module is built to make unrepresentable.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::{AcqRel, Relaxed};

use crossbeam_utils::CachePadded;

/// A bounded population of live connections.
///
/// This is a BALANCE, not a counter: it is incremented at admission and decremented
/// only in `Drop for ConnGuard`, and there is no public release method, because a lost
/// decrement is capacity that disappears for the life of the process.
#[derive(Debug)]
pub struct ConnRegistry {
    current: CachePadded<AtomicU64>,
    max: u64,
}

impl ConnRegistry {
    /// Creates a registry with a hard ceiling. A `max` of 0 is raised to 1.
    ///
    /// A ceiling of 0 would refuse every connection outright; the configuration
    /// validator already reports `max_connections == 0` as an error, so this clamp is
    /// defence in depth, not the primary guard.
    #[must_use]
    pub fn new(max: u64) -> Arc<Self> {
        Arc::new(Self {
            current: CachePadded::new(AtomicU64::new(0)),
            max: max.max(1),
        })
    }

    /// Takes one slot, or returns `None` when the ceiling is reached.
    ///
    /// Never queues and never waits: a connection that cannot be admitted is closed
    /// immediately, because queueing at the cap is how a connection flood becomes an
    /// out-of-memory condition.
    ///
    /// Implemented with `compare_exchange_weak` in a retry loop rather than
    /// `fetch_add` followed by a rollback on over-admission: a rollback is a
    /// decrement outside `Drop`, which is exactly the "forgotten on one of several
    /// paths" defect this type exists to rule out, and a `fetch_add` can also admit
    /// transiently above `max` before the rollback runs. The loop's body is a load
    /// and a compare-exchange, so it is bounded in practice by contention alone.
    ///
    /// An associated function rather than a method: the guard must own an `Arc` clone
    /// so it can move into a spawned `'static` task, and using `&Arc<Self>` as the
    /// receiver type is not legal on stable Rust (rejected with E0307, "invalid
    /// `self` parameter type"; the legal receiver types are a bare `Self`, `&Self`,
    /// `&mut Self`, `Box<Self>`, `Rc<Self>`, `Arc<Self>`, and `Pin` of those). Taking
    /// an owned `Arc<Self>` as the receiver would consume the caller's handle on
    /// every accept, which is wrong for a registry meant to outlive any single
    /// admission. Call this as `ConnRegistry::try_admit(&registry)`.
    #[must_use]
    pub fn try_admit(registry: &Arc<Self>) -> Option<ConnGuard> {
        loop {
            let cur = registry.current.load(Relaxed);
            if cur >= registry.max {
                return None;
            }
            let won = registry
                .current
                .compare_exchange_weak(cur, cur + 1, AcqRel, Relaxed)
                .is_ok();
            if won {
                return Some(ConnGuard {
                    registry: Arc::clone(registry),
                });
            }
            // Another accept task won the race: loop around, re-read, and retry.
        }
    }

    /// Live connections and the ceiling.
    ///
    /// A relaxed load, so the value is a point-in-time observation: it is never used
    /// to make an admission decision, which is why `try_admit` re-reads under its own
    /// compare-exchange rather than trusting a snapshot from here.
    #[must_use]
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            current: self.current.load(Relaxed),
            max: self.max,
        }
    }
}

/// Holds one connection slot. Releases it on drop, and only on drop.
#[must_use = "the guard holds a connection slot; dropping it releases the slot"]
#[derive(Debug)]
pub struct ConnGuard {
    registry: Arc<ConnRegistry>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.registry.current.fetch_sub(1, AcqRel);
    }
}

/// A registry snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryStats {
    /// Live connections.
    pub current: u64,
    /// The ceiling.
    pub max: u64,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use proptest::prelude::*;

    use super::{ConnGuard, ConnRegistry};

    #[test]
    fn registry_admits_up_to_max() {
        let registry = ConnRegistry::new(3);

        let a = ConnRegistry::try_admit(&registry);
        let b = ConnRegistry::try_admit(&registry);
        let c = ConnRegistry::try_admit(&registry);
        let d = ConnRegistry::try_admit(&registry);

        assert!(a.is_some());
        assert!(b.is_some());
        assert!(c.is_some());
        assert!(d.is_none());
        assert_eq!(registry.stats().current, 3);
    }

    #[test]
    fn registry_releases_on_drop() {
        let registry = ConnRegistry::new(3);

        let a = ConnRegistry::try_admit(&registry).expect("slot 1");
        let b = ConnRegistry::try_admit(&registry).expect("slot 2");
        let c = ConnRegistry::try_admit(&registry).expect("slot 3");

        drop(a);
        drop(b);
        assert_eq!(registry.stats().current, 1);
        drop(c);
    }

    #[test]
    fn registry_zero_max_becomes_one() {
        let registry = ConnRegistry::new(0);

        let first = ConnRegistry::try_admit(&registry);
        let second = ConnRegistry::try_admit(&registry);

        assert!(first.is_some());
        assert!(second.is_none());
    }

    #[test]
    fn registry_never_exceeds_max_under_contention() {
        // `ConnRegistry` is process-independent state created fresh by `ConnRegistry::new`
        // for this test alone, so this needs no cross-test lock: nothing outside this
        // function can touch this particular registry.
        let registry = ConnRegistry::new(50);
        let max_seen = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let max_seen = Arc::clone(&max_seen);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        if let Some(guard) = ConnRegistry::try_admit(&registry) {
                            let current = registry.stats().current;
                            max_seen.fetch_max(current, std::sync::atomic::Ordering::Relaxed);
                            drop(guard);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("admitting thread must not panic");
        }

        assert!(max_seen.load(std::sync::atomic::Ordering::Relaxed) <= 50);
        assert_eq!(registry.stats().current, 0);
    }

    #[derive(Debug, Clone, Copy)]
    enum RegistryOp {
        Admit,
        DropOldest,
        DropNewest,
    }

    fn registry_op_strategy() -> impl Strategy<Value = RegistryOp> {
        prop_oneof![
            4 => Just(RegistryOp::Admit),
            1 => Just(RegistryOp::DropOldest),
            1 => Just(RegistryOp::DropNewest),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn prop_registry_conservation(ops in prop::collection::vec(registry_op_strategy(), 0..=512)) {
            let registry = ConnRegistry::new(32);
            let mut held: Vec<ConnGuard> = Vec::new();

            for op in ops {
                match op {
                    RegistryOp::Admit => {
                        if let Some(guard) = ConnRegistry::try_admit(&registry) {
                            held.push(guard);
                        }
                    }
                    RegistryOp::DropOldest => {
                        if !held.is_empty() {
                            drop(held.remove(0));
                        }
                    }
                    RegistryOp::DropNewest => {
                        drop(held.pop());
                    }
                }
                let stats = registry.stats();
                let expected = u64::try_from(held.len())
                    .expect("held guard count fits in u64 within a 512-operation run");
                prop_assert_eq!(stats.current, expected);
                prop_assert!(stats.current <= 32);
            }
        }
    }
}
