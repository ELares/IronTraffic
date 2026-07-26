// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dense identifier newtypes shared by the resilience subsystems.

/// Dense index of an endpoint inside one cluster snapshot.
///
/// Assigned by the upstream cluster snapshot builder and stable for the life of that
/// snapshot. It is not stable across snapshots; state that must survive a membership
/// change is keyed on the endpoint's socket address by the caller.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct EndpointIdx(pub u32);

/// Dense index of an upstream cluster inside one configuration snapshot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ClusterIdx(pub u32);

/// Dense index of a destination backend service.
///
/// This is the retry-budget key. It is deliberately coarser than [`ClusterIdx`]:
/// several clusters (for example one per priority or per subset) can share one
/// backend service and therefore one retry budget.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct BackendIdx(pub u32);

/// Request criticality, ordered most critical first, after Google SRE's taxonomy.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum PriorityClass {
    /// Requests whose failure is a user-visible outage. Never shed until last.
    CriticalPlus = 0,
    /// Interactive user requests.
    Critical = 1,
    /// Requests a client will retry later without user impact.
    SheddablePlus = 2,
    /// Batch and prefetch traffic. Shed first.
    Sheddable = 3,
}

impl PriorityClass {
    /// Number of classes. Fixed at 4; arrays indexed by class are `[T; 4]`.
    pub const COUNT: usize = 4;

    /// Dense index in `0..4`.
    #[inline]
    #[must_use]
    pub fn index(self) -> usize {
        self as usize
    }

    /// The class for a dense index, or `None` when `i >= 4`.
    #[must_use]
    pub fn from_index(i: usize) -> Option<PriorityClass> {
        match i {
            0 => Some(PriorityClass::CriticalPlus),
            1 => Some(PriorityClass::Critical),
            2 => Some(PriorityClass::SheddablePlus),
            3 => Some(PriorityClass::Sheddable),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_class_index_roundtrip() {
        for c in [
            PriorityClass::CriticalPlus,
            PriorityClass::Critical,
            PriorityClass::SheddablePlus,
            PriorityClass::Sheddable,
        ] {
            assert_eq!(PriorityClass::from_index(c.index()), Some(c));
        }
    }

    #[test]
    fn priority_class_from_index_out_of_range() {
        assert!(PriorityClass::from_index(4).is_none());
    }

    #[test]
    fn priority_class_order() {
        assert!(PriorityClass::CriticalPlus < PriorityClass::Critical);
        assert!(PriorityClass::Critical < PriorityClass::SheddablePlus);
        assert!(PriorityClass::SheddablePlus < PriorityClass::Sheddable);
    }
}
