// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`EndpointStats`]: the 128-byte-aligned, atomics-only per-endpoint counter
//! line the request path indexes directly by [`crate::EndpointId`].

use std::sync::atomic::{AtomicU32, AtomicU64};

/// One cache-line-pair of mutable per-endpoint state. 128-byte aligned, not 64,
/// because Apple silicon and some x86 parts prefetch line pairs, so 64-byte
/// alignment still admits false sharing between two endpoints.
///
/// Total live payload is 28 bytes; the rest is padding that exists to guarantee
/// that touching one endpoint's counters never invalidates another's line.
#[repr(align(128))]
#[derive(Debug, Default)]
pub struct EndpointStats {
    /// In-flight *requests*, not connections. Incremented at selection, decremented
    /// by `InflightGuard::drop`. This is the P2C load signal.
    pub inflight: AtomicU32,
    /// Open connections to this endpoint across all workers. Pool accounting only.
    pub active_conns: AtomicU32,
    /// Packed peak-EWMA: high 32 bits are an `f32` cost in milliseconds, low 32
    /// bits are the `CoarseMillis` at which that cost was recorded. Zero means
    /// "never sampled".
    pub cost: AtomicU64,
    /// `CoarseMillis` at which this endpoint last transitioned into `Healthy`.
    /// Drives slow start.
    pub healthy_since_ms: AtomicU32,
    /// `CoarseMillis` at which this endpoint last left `Healthy`. Drives
    /// slow-start flap suppression: a ramp does not restart if the endpoint was
    /// healthy recently.
    pub left_healthy_ms: AtomicU32,
    /// Registry slot generation, bumped every time this slot is allocated. A
    /// sticky affinity token carries it so that a token naming a recycled id is
    /// rejected.
    pub generation: AtomicU32,
}

#[cfg(test)]
mod tests {
    use super::EndpointStats;
    use std::sync::atomic::Ordering;

    #[test]
    fn stats_is_one_aligned_line_pair() {
        assert_eq!(core::mem::size_of::<EndpointStats>(), 128);
        assert_eq!(core::mem::align_of::<EndpointStats>(), 128);
    }

    #[test]
    fn stats_default_is_all_zero() {
        let s = EndpointStats::default();
        assert_eq!(s.inflight.load(Ordering::Relaxed), 0);
        assert_eq!(s.active_conns.load(Ordering::Relaxed), 0);
        assert_eq!(s.cost.load(Ordering::Relaxed), 0);
        assert_eq!(s.healthy_since_ms.load(Ordering::Relaxed), 0);
        assert_eq!(s.left_healthy_ms.load(Ordering::Relaxed), 0);
        assert_eq!(s.generation.load(Ordering::Relaxed), 0);
    }
}
