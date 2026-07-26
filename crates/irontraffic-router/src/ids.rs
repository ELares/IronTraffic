// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identifier newtypes and the HTTP method bitmask.
//!
//! Every identifier here is a `u32` or `u16` newtype with its own `NONE`
//! sentinel. They are separate types because mixing, say, a node index with a
//! candidate index is the single easiest arena bug to write and the hardest
//! to find; the compiler refuses the mix instead of a reviewer having to
//! catch it.

/// The universal `u32` sentinel: "no such index".
pub const SENTINEL: u32 = u32::MAX;

/// Bit mask of HTTP methods. A `RequestView` carries exactly one bit; a predicate may
/// carry any subset. Matching a method is therefore one AND and one comparison.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodMask(pub u32);

impl MethodMask {
    /// No method at all. A predicate carrying this can never match.
    pub const NONE: MethodMask = MethodMask(0);
    /// `GET`.
    pub const GET: MethodMask = MethodMask(1 << 0);
    /// `HEAD`.
    pub const HEAD: MethodMask = MethodMask(1 << 1);
    /// `POST`.
    pub const POST: MethodMask = MethodMask(1 << 2);
    /// `PUT`.
    pub const PUT: MethodMask = MethodMask(1 << 3);
    /// `DELETE`.
    pub const DELETE: MethodMask = MethodMask(1 << 4);
    /// `CONNECT`.
    pub const CONNECT: MethodMask = MethodMask(1 << 5);
    /// `OPTIONS`.
    pub const OPTIONS: MethodMask = MethodMask(1 << 6);
    /// `TRACE`.
    pub const TRACE: MethodMask = MethodMask(1 << 7);
    /// `PATCH`.
    pub const PATCH: MethodMask = MethodMask(1 << 8);
    /// Any extension method this build does not name. All extension methods share
    /// this bit, so a route cannot match one extension method and not another.
    ///
    /// This is a deliberate v1 limitation, not an oversight: it keeps the mask a
    /// single `u32` AND, and Gateway API's `HTTPRouteMatch.method` enumerates only
    /// the nine named methods, so no conformant configuration can distinguish two
    /// extension methods. Do not "fix" this into a string comparison.
    pub const OTHER: MethodMask = MethodMask(1 << 9);
    /// Every named method plus `OTHER`.
    pub const ANY: MethodMask = MethodMask(0x3ff);

    /// True when `self` and `other` share at least one bit.
    #[must_use]
    pub const fn intersects(self, other: MethodMask) -> bool {
        (self.0 & other.0) != 0
    }

    /// The union of two masks.
    #[must_use]
    pub const fn union(self, other: MethodMask) -> MethodMask {
        MethodMask(self.0 | other.0)
    }

    /// True when exactly one bit is set, which every `RequestView::method` must satisfy.
    #[must_use]
    pub const fn is_single(self) -> bool {
        self.0.is_power_of_two()
    }
}

/// Index of a group (one listener plus one host pattern) in the route table.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u32);

impl GroupId {
    /// The sentinel: "no such group".
    pub const NONE: GroupId = GroupId(SENTINEL);

    /// True for `GroupId::NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == SENTINEL
    }

    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Index of a node in a group's path trie node arena.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u32);

impl NodeId {
    /// The sentinel: "no such node".
    pub const NONE: NodeId = NodeId(SENTINEL);
    /// The root node of a built group's path trie. Every built group has one.
    pub const ROOT: NodeId = NodeId(0);

    /// True for `NodeId::NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == SENTINEL
    }

    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// An interned header name or query parameter name. The two name spaces are separate:
/// a `NameId` is only meaningful together with the set it was interned in.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameId(pub u16);

impl NameId {
    /// The sentinel: "no such name".
    pub const NONE: NameId = NameId(u16::MAX);

    /// True for `NameId::NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == u16::MAX
    }

    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Caller-owned identity of the route a match came from. The router stores it,
/// returns it, and never interprets it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteId(pub u32);

impl RouteId {
    /// The sentinel: "no such route".
    pub const NONE: RouteId = RouteId(SENTINEL);

    /// True for `RouteId::NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == SENTINEL
    }

    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Caller-owned opaque handle to the action a match selects. The router never
/// interprets it; the caller indexes its own action arena with it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId(pub u32);

impl ActionId {
    /// The sentinel: "no such action".
    pub const NONE: ActionId = ActionId(SENTINEL);

    /// True for `ActionId::NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == SENTINEL
    }

    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Caller-owned identity of a TLS certificate.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertId(pub u32);

impl CertId {
    /// The sentinel: "no such certificate".
    pub const NONE: CertId = CertId(SENTINEL);

    /// True for `CertId::NONE`.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == SENTINEL
    }

    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Caller-owned identity of a listener. Groups are scoped by listener, so two
/// listeners may serve the same hostname with different route sets.
///
/// There is no `NONE` sentinel for this type: every request arrives on a
/// listener, so a "no listener" value is never a legal `RequestView::listener`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerId(pub u16);

impl ListenerId {
    /// The index as a `usize`, for arena access with `get`.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::{ActionId, CertId, GroupId, MethodMask, NameId, NodeId, RouteId};

    #[test]
    fn method_bits_are_distinct() {
        let bits = [
            MethodMask::GET,
            MethodMask::HEAD,
            MethodMask::POST,
            MethodMask::PUT,
            MethodMask::DELETE,
            MethodMask::CONNECT,
            MethodMask::OPTIONS,
            MethodMask::TRACE,
            MethodMask::PATCH,
            MethodMask::OTHER,
        ];
        for bit in bits {
            assert_eq!(bit.0.count_ones(), 1);
        }
        for (i, a) in bits.iter().enumerate() {
            for b in bits.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        let mut union = 0u32;
        for bit in bits {
            union |= bit.0;
        }
        assert_eq!(union, MethodMask::ANY.0);
    }

    #[test]
    fn method_intersects() {
        assert!(MethodMask::GET.intersects(MethodMask::ANY));
        assert!(!MethodMask::GET.intersects(MethodMask::POST));
        assert!(!MethodMask::NONE.intersects(MethodMask::ANY));
    }

    #[test]
    fn sentinels_round_trip() {
        assert!(GroupId::NONE.is_none());
        assert!(!GroupId(0).is_none());
        assert_eq!(GroupId(0).idx(), 0);

        assert!(NodeId::NONE.is_none());
        assert!(!NodeId(0).is_none());
        assert_eq!(NodeId(0).idx(), 0);

        assert!(NameId::NONE.is_none());
        assert!(!NameId(0).is_none());
        assert_eq!(NameId(0).idx(), 0);

        assert!(RouteId::NONE.is_none());
        assert!(!RouteId(0).is_none());
        assert_eq!(RouteId(0).idx(), 0);

        assert!(ActionId::NONE.is_none());
        assert!(!ActionId(0).is_none());
        assert_eq!(ActionId(0).idx(), 0);

        assert!(CertId::NONE.is_none());
        assert!(!CertId(0).is_none());
        assert_eq!(CertId(0).idx(), 0);
    }
}
