// SPDX-License-Identifier: MIT OR Apache-2.0
//! Kubernetes identity vocabulary.
//!
//! Every watched object is identified by a small, interned, comparable key.
//! Namespace strings are interned to a `u32` so that `ObjectKey` is 32 bytes and
//! namespace comparisons in the attachment loop are one integer compare.

#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::mem;

use smol_str::SmolStr;

use crate::MAX_NAMESPACES;
use crate::error::sanitize_for_log;

/// Every Kubernetes kind this crate watches.
///
/// The discriminant is stable: it is used as a dense array index for per-kind
/// counters, so reordering the variants renumbers every metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum WatchedKind {
    /// Gateway API `GatewayClass`.
    GatewayClass = 0,
    /// Gateway API `Gateway`.
    Gateway = 1,
    /// Gateway API `ListenerSet`.
    ListenerSet = 2,
    /// Gateway API `HTTPRoute`.
    HttpRoute = 3,
    /// Gateway API `GRPCRoute`.
    GrpcRoute = 4,
    /// Gateway API `TLSRoute`.
    TlsRoute = 5,
    /// Gateway API `TCPRoute`.
    TcpRoute = 6,
    /// Gateway API `UDPRoute`.
    UdpRoute = 7,
    /// Gateway API `ReferenceGrant`.
    ReferenceGrant = 8,
    /// Gateway API `BackendTLSPolicy`.
    BackendTlsPolicy = 9,
    /// Core networking `Ingress`.
    Ingress = 10,
    /// Core networking `IngressClass`.
    IngressClass = 11,
    /// Core `Service`.
    Service = 12,
    /// Discovery `EndpointSlice`.
    EndpointSlice = 13,
    /// Core `Node`.
    Node = 14,
    /// Core `Secret`.
    Secret = 15,
    /// Watched metadata-only, purely for the labels that
    /// `allowedRoutes.namespaces.selector` is evaluated against. A `LabelSelector`
    /// has no other source of truth, and `from: Selector` is a Core support level
    /// feature, so this kind is not optional.
    Namespace = 16,
}

impl WatchedKind {
    /// Every variant, in discriminant order. Used to build per-kind arrays.
    pub const ALL: [WatchedKind; 17] = [
        WatchedKind::GatewayClass,
        WatchedKind::Gateway,
        WatchedKind::ListenerSet,
        WatchedKind::HttpRoute,
        WatchedKind::GrpcRoute,
        WatchedKind::TlsRoute,
        WatchedKind::TcpRoute,
        WatchedKind::UdpRoute,
        WatchedKind::ReferenceGrant,
        WatchedKind::BackendTlsPolicy,
        WatchedKind::Ingress,
        WatchedKind::IngressClass,
        WatchedKind::Service,
        WatchedKind::EndpointSlice,
        WatchedKind::Node,
        WatchedKind::Secret,
        WatchedKind::Namespace,
    ];

    /// The Kubernetes `kind` string, for example `"HTTPRoute"`.
    #[must_use]
    pub const fn kind_str(self) -> &'static str {
        match self {
            Self::GatewayClass => "GatewayClass",
            Self::Gateway => "Gateway",
            Self::ListenerSet => "ListenerSet",
            Self::HttpRoute => "HTTPRoute",
            Self::GrpcRoute => "GRPCRoute",
            Self::TlsRoute => "TLSRoute",
            Self::TcpRoute => "TCPRoute",
            Self::UdpRoute => "UDPRoute",
            Self::ReferenceGrant => "ReferenceGrant",
            Self::BackendTlsPolicy => "BackendTLSPolicy",
            Self::Ingress => "Ingress",
            Self::IngressClass => "IngressClass",
            Self::Service => "Service",
            Self::EndpointSlice => "EndpointSlice",
            Self::Node => "Node",
            Self::Secret => "Secret",
            Self::Namespace => "Namespace",
        }
    }

    /// The API group, `""` for core kinds such as Service and Secret.
    #[must_use]
    pub const fn group(self) -> &'static str {
        match self {
            Self::GatewayClass
            | Self::Gateway
            | Self::ListenerSet
            | Self::HttpRoute
            | Self::GrpcRoute
            | Self::TlsRoute
            | Self::TcpRoute
            | Self::UdpRoute
            | Self::ReferenceGrant
            | Self::BackendTlsPolicy => "gateway.networking.k8s.io",
            Self::Ingress | Self::IngressClass => "networking.k8s.io",
            Self::Service | Self::EndpointSlice | Self::Node | Self::Namespace | Self::Secret => "",
        }
    }

    /// The lowercase plural used in API paths, for example `"httproutes"`.
    #[must_use]
    pub const fn plural(self) -> &'static str {
        match self {
            Self::GatewayClass => "gatewayclasses",
            Self::Gateway => "gateways",
            Self::ListenerSet => "listenersets",
            Self::HttpRoute => "httproutes",
            Self::GrpcRoute => "grpcroutes",
            Self::TlsRoute => "tlsroutes",
            Self::TcpRoute => "tcproutes",
            Self::UdpRoute => "udproutes",
            Self::ReferenceGrant => "referencegrants",
            Self::BackendTlsPolicy => "backendtlspolicies",
            Self::Ingress => "ingresses",
            Self::IngressClass => "ingressclasses",
            Self::Service => "services",
            Self::EndpointSlice => "endpointslices",
            Self::Node => "nodes",
            Self::Secret => "secrets",
            Self::Namespace => "namespaces",
        }
    }

    /// The API version we watch, for example `"v1"` or `"v1alpha1"`.
    #[must_use]
    pub const fn version(self) -> &'static str {
        match self {
            Self::ListenerSet => "v1alpha1",
            Self::TlsRoute | Self::TcpRoute | Self::UdpRoute | Self::BackendTlsPolicy => "v1alpha2",
            Self::ReferenceGrant => "v1beta1",
            Self::GatewayClass
            | Self::Gateway
            | Self::HttpRoute
            | Self::GrpcRoute
            | Self::Ingress
            | Self::IngressClass
            | Self::Service
            | Self::EndpointSlice
            | Self::Node
            | Self::Secret
            | Self::Namespace => "v1",
        }
    }

    /// True when objects of this kind have no namespace.
    #[must_use]
    pub const fn is_cluster_scoped(self) -> bool {
        matches!(
            self,
            Self::GatewayClass | Self::IngressClass | Self::Node | Self::Namespace
        )
    }

    /// The discriminant, for use as a dense array index.
    #[must_use]
    pub const fn index(self) -> usize {
        self as u8 as usize // it-allow: unchecked-cast reason: WatchedKind is repr(u8) with 17 variants (0..=16), so the cast to u8 can never truncate
    }
}

/// An interned namespace name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespaceId(u32);

impl NamespaceId {
    /// The namespace of a cluster-scoped object, and of the empty namespace string.
    pub const CLUSTER: NamespaceId = NamespaceId(0);

    /// The id returned when the interner is full. Never names a namespace, and
    /// `NsInterner::resolve` returns `None` for it. An object carrying it is dropped
    /// with a diagnostic, never translated.
    pub const INVALID: NamespaceId = NamespaceId(u32::MAX);

    /// The id a `MetaView` carries between deserialization and interning.
    ///
    /// `resolve` returns `None` for it, and a debug assertion fires if one reaches a
    /// store.
    pub const UNINTERNED: NamespaceId = NamespaceId(u32::MAX - 1);

    /// The raw index. Only for array indexing and metric labels.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Interns namespace strings. One per controller process, never shared across
/// translations of different clusters.
#[derive(Debug)]
pub struct NsInterner {
    names: Vec<SmolStr>,
    map: HashMap<SmolStr, u32>,
    /// Count of `NamespaceId::INVALID` returns from `intern`. Used as the source
    /// for the `irontraffic_k8s_intern_overflow_total` metric.
    pub intern_overflow: u64,
}

impl Default for NsInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl NsInterner {
    /// A fresh interner holding only the cluster scope.
    #[must_use]
    pub fn new() -> Self {
        let mut names = Vec::with_capacity(64);
        names.push(SmolStr::new_inline(""));
        Self {
            names,
            map: HashMap::with_capacity(64),
            intern_overflow: 0,
        }
    }

    /// Interns `name`, returning its id. An empty name is the cluster scope.
    pub fn intern(&mut self, name: &str) -> NamespaceId {
        if name.is_empty() {
            return NamespaceId::CLUSTER;
        }
        if let Some(&id) = self.map.get(name) {
            return NamespaceId(id);
        }
        if self.names.len().saturating_sub(1) >= MAX_NAMESPACES {
            self.intern_overflow = self.intern_overflow.wrapping_add(1);
            return NamespaceId::INVALID;
        }
        if self.names.len() >= (u32::MAX - 1) as usize {
            self.intern_overflow = self.intern_overflow.wrapping_add(1);
            return NamespaceId::INVALID;
        }
        #[rustfmt::skip]
        #[allow(clippy::cast_possible_truncation, reason = "bounds checked above: len < u32::MAX - 1")]
        let id = NamespaceId(self.names.len() as u32); // it-allow: unchecked-cast reason: bounds checked above: len < u32::MAX - 1
        let owned = SmolStr::new(name);
        self.map.insert(owned.clone(), id.get());
        self.names.push(owned);
        id
    }

    /// Looks `name` up without interning it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<NamespaceId> {
        if name.is_empty() {
            return Some(NamespaceId::CLUSTER);
        }
        self.map.get(name).copied().map(NamespaceId)
    }

    /// The string an id names, or `None` when the id is out of range for this
    /// interner (including `NamespaceId::INVALID`). `NamespaceId::CLUSTER` resolves
    /// to `Some("")`.
    #[must_use]
    pub fn resolve(&self, id: NamespaceId) -> Option<&str> {
        let idx = id.get() as usize;
        self.names.as_slice().get(idx).map(SmolStr::as_str)
    }

    /// How many distinct namespaces have been interned, excluding the cluster scope.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len().saturating_sub(1)
    }

    /// True when nothing but the cluster scope has been interned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The identity of one watched object.
///
/// `PartialOrd` and `Ord` are derived, and they are load bearing rather than
/// incidental: five later issues in this milestone key an ordered collection on
/// this type. The derived order is `(kind, namespace, name)`, which is a stable
/// total order because `WatchedKind`, `NamespaceId` and `SmolStr` are each `Ord`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey {
    /// Which kind the object is.
    pub kind: WatchedKind,
    /// Interned namespace; `NamespaceId::CLUSTER` for cluster-scoped kinds.
    pub namespace: NamespaceId,
    /// The object's `metadata.name`.
    pub name: SmolStr,
}

impl ObjectKey {
    /// Builds a key.
    #[must_use]
    pub fn new(kind: WatchedKind, namespace: NamespaceId, name: &str) -> ObjectKey {
        Self {
            kind,
            namespace,
            name: SmolStr::new(name),
        }
    }

    /// Renders `<kind> <namespace>/<name>` for logs and Events. Requires the
    /// interner because the key stores only the id.
    ///
    /// The namespace and name are passed through `sanitize_for_log`, because this
    /// output ends up in log lines and Kubernetes Event messages and both fields are
    /// chosen by whoever created the object. An unresolvable id renders as
    /// `<invalid-ns>` rather than panicking or being omitted.
    #[must_use]
    pub fn display(&self, ns: &NsInterner) -> String {
        let namespace_str = ns.resolve(self.namespace).unwrap_or("<invalid-ns>");
        format!(
            "{} {}/{}",
            self.kind.kind_str(),
            sanitize_for_log(namespace_str),
            sanitize_for_log(self.name.as_str())
        )
    }
}

/// A parsed `metadata.uid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uid([u8; 16]);

impl Uid {
    /// The all-zero uid, used when `metadata.uid` is absent or malformed.
    pub const ZERO: Uid = Uid([0u8; 16]);

    /// Parses the 36 byte RFC 4122 text form.
    ///
    /// Returns `None` for any length other than 36, a misplaced hyphen, or a
    /// non-hex digit. Never panics and never allocates.
    #[must_use]
    pub fn parse(s: &str) -> Option<Uid> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return None;
        }
        if b.get(8) != Some(&b'-')
            || b.get(13) != Some(&b'-')
            || b.get(18) != Some(&b'-')
            || b.get(23) != Some(&b'-')
        {
            return None;
        }
        let mut out = [0u8; 16];
        let mut byte_idx = 0;
        let mut high_nibble = true;
        for (idx, byte) in b.iter().enumerate() {
            if idx == 8 || idx == 13 || idx == 18 || idx == 23 {
                continue;
            }
            let nibble = hex_digit(*byte)?;
            let slot = out.get_mut(byte_idx)?;
            if high_nibble {
                *slot = nibble << 4;
            } else {
                *slot |= nibble;
                byte_idx = byte_idx.wrapping_add(1);
            }
            high_nibble = !high_nibble;
        }
        Some(Uid(out))
    }

    /// The 16 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[rustfmt::skip]
#[allow(clippy::arithmetic_side_effects, reason = "hex digit decoding is bounded")]
const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// An opaque `metadata.resourceVersion`. Equality only: never ordered, never parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceVersion(SmolStr);

impl ResourceVersion {
    /// Wraps the string exactly as the API server sent it.
    #[must_use]
    pub fn new(s: &str) -> ResourceVersion {
        Self(SmolStr::new(s))
    }

    /// The bytes, for use as an `If-Match`-style precondition only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Whole seconds since the Unix epoch, the resolution `metav1.Time` actually carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixSeconds(i64);

impl UnixSeconds {
    /// The zero value, used when an object carries no `creationTimestamp`.
    pub const ZERO: UnixSeconds = UnixSeconds(0);

    /// Parses RFC 3339 as `metav1.Time` writes it: `YYYY-MM-DDTHH:MM:SSZ`.
    ///
    /// Returns `None` for any other shape, including fractional seconds and any
    /// offset other than the literal `Z`, because `metav1.Time` never emits them.
    #[must_use]
    pub fn parse_rfc3339_utc(s: &str) -> Option<UnixSeconds> {
        let b = s.as_bytes();
        if b.len() != 20 {
            return None;
        }
        if b.get(4) != Some(&b'-')
            || b.get(7) != Some(&b'-')
            || b.get(10) != Some(&b'T')
            || b.get(13) != Some(&b':')
            || b.get(16) != Some(&b':')
            || b.get(19) != Some(&b'Z')
        {
            return None;
        }
        let year = parse_4_digits(*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?)?;
        let month = parse_2_digits(*b.get(5)?, *b.get(6)?)?;
        let day = parse_2_digits(*b.get(8)?, *b.get(9)?)?;
        let hour = parse_2_digits(*b.get(11)?, *b.get(12)?)?;
        let minute = parse_2_digits(*b.get(14)?, *b.get(15)?)?;
        let second = parse_2_digits(*b.get(17)?, *b.get(18)?)?;
        if !(1..=12).contains(&month) {
            return None;
        }
        let days_in_month = days_in_month(year, month);
        if !(1..=days_in_month).contains(&day) {
            return None;
        }
        if !(0..=23).contains(&hour) {
            return None;
        }
        if !(0..=59).contains(&minute) {
            return None;
        }
        if !(0..=59).contains(&second) {
            return None;
        }
        let days = days_from_civil(year, month, day);
        let secs = days
            .checked_mul(86_400)?
            .checked_add(hour.checked_mul(3_600)?)?
            .checked_add(minute.checked_mul(60)?)?
            .checked_add(second)?;
        Some(UnixSeconds(secs))
    }

    /// Wraps a raw Unix second count.
    #[must_use]
    pub const fn from_unix_secs(secs: i64) -> UnixSeconds {
        UnixSeconds(secs)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[rustfmt::skip]
#[allow(clippy::arithmetic_side_effects, reason = "private helper for fixed-shape parser")]
const fn parse_4_digits(a: u8, b: u8, c: u8, d: u8) -> Option<i64> {
    if !a.is_ascii_digit() || !b.is_ascii_digit() || !c.is_ascii_digit() || !d.is_ascii_digit() {
        return None;
    }
    let mut acc = 0_i64;
    acc = acc * 10 + (a - b'0') as i64;
    acc = acc * 10 + (b - b'0') as i64;
    acc = acc * 10 + (c - b'0') as i64;
    acc = acc * 10 + (d - b'0') as i64;
    Some(acc)
}

#[rustfmt::skip]
#[allow(clippy::arithmetic_side_effects, reason = "private helper for fixed-shape parser")]
const fn parse_2_digits(a: u8, b: u8) -> Option<i64> {
    if !a.is_ascii_digit() || !b.is_ascii_digit() {
        return None;
    }
    let mut acc = 0_i64;
    acc = acc * 10 + (a - b'0') as i64;
    acc = acc * 10 + (b - b'0') as i64;
    Some(acc)
}

#[rustfmt::skip]
#[allow(clippy::arithmetic_side_effects, reason = "private helper for fixed-shape parser")]
const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[rustfmt::skip]
#[allow(clippy::arithmetic_side_effects, reason = "Howard Hinnant days-from-civil algorithm")]
#[allow(clippy::integer_division, reason = "Howard Hinnant days-from-civil algorithm")]
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

const _: () = assert!(mem::size_of::<Uid>() == 16);
const _: () = assert!(mem::size_of::<ObjectKey>() <= 32);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn intern_empty_is_cluster() {
        assert_eq!(NsInterner::new().intern(""), NamespaceId::CLUSTER);
        assert_eq!(NsInterner::default().intern(""), NamespaceId::CLUSTER);
    }

    #[test]
    fn intern_is_idempotent() {
        let mut interner = NsInterner::new();
        let a = interner.intern("team-a");
        let b = interner.intern("team-a");
        let c = interner.intern("team-a");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(interner.len(), 1);
    }

    #[test]
    fn intern_dense_ids() {
        let mut interner = NsInterner::new();
        let a = interner.intern("a");
        let b = interner.intern("b");
        let c = interner.intern("c");
        assert_eq!(a.get(), 1);
        assert_eq!(b.get(), 2);
        assert_eq!(c.get(), 3);
        assert_eq!(interner.resolve(a), Some("a"));
        assert_eq!(interner.resolve(b), Some("b"));
        assert_eq!(interner.resolve(c), Some("c"));
    }

    #[test]
    fn resolve_foreign_id_is_none() {
        let mut foreign = NsInterner::new();
        for i in 0..7 {
            let _ = foreign.intern(&format!("ns-{i}"));
        }
        let seventh = NamespaceId(7);
        assert_eq!(NsInterner::new().resolve(seventh), None);
        assert_eq!(NsInterner::new().resolve(NamespaceId::INVALID), None);
        assert_eq!(NsInterner::new().resolve(NamespaceId::UNINTERNED), None);
        assert_eq!(NsInterner::new().resolve(NamespaceId::CLUSTER), Some(""));
    }

    #[test]
    fn uid_round_trip() {
        let uid = Uid::parse("9b2c8e1a-0f3d-4c5b-8a7e-6d5c4b3a2f10").unwrap();
        assert_eq!(
            *uid.as_bytes(),
            [
                0x9b, 0x2c, 0x8e, 0x1a, 0x0f, 0x3d, 0x4c, 0x5b, 0x8a, 0x7e, 0x6d, 0x5c, 0x4b, 0x3a,
                0x2f, 0x10
            ]
        );
    }

    #[test]
    fn uid_rejects_bad_shapes() {
        assert!(Uid::parse("").is_none());
        assert!(Uid::parse("12345678-1234-1234-1234-12345678901").is_none());
        assert!(Uid::parse("12345678-1234-1234-1234-1234567890123").is_none());
        assert!(Uid::parse("1234567-1234-1234-1234-123456789012").is_none());
        assert!(Uid::parse("9b2c8e1a-0f3d-4c5b-8a7e-6d5c4b3a2g10").is_none());
    }

    #[test]
    fn uid_accepts_uppercase() {
        let lower = Uid::parse("9b2c8e1a-0f3d-4c5b-8a7e-6d5c4b3a2f10").unwrap();
        let upper = Uid::parse("9B2C8E1A-0F3D-4C5B-8A7E-6D5C4B3A2F10").unwrap();
        assert_eq!(lower.as_bytes(), upper.as_bytes());
    }

    #[test]
    fn unix_seconds_parses_metav1_shape() {
        assert_eq!(
            UnixSeconds::parse_rfc3339_utc("2026-07-24T12:00:00Z"),
            Some(UnixSeconds(1_784_894_400))
        );
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24T12:00:00.5Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24T12:00:00+00:00").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24").is_none());
    }

    #[test]
    fn unix_seconds_orders_by_time() {
        assert!(UnixSeconds(1) < UnixSeconds(2));
    }

    #[test]
    fn object_key_display() {
        let mut interner = NsInterner::new();
        let ns = interner.intern("team-a");
        let key = ObjectKey::new(WatchedKind::HttpRoute, ns, "api");
        assert_eq!(key.display(&interner), "HTTPRoute team-a/api");
    }

    #[test]
    fn watched_kind_tables_agree() {
        let mut cluster_scoped = Vec::new();
        for (idx, kind) in WatchedKind::ALL.iter().enumerate() {
            assert_eq!(kind.index(), idx);
            assert!(!kind.kind_str().is_empty());
            if kind.is_cluster_scoped() {
                cluster_scoped.push(*kind);
            }
        }
        assert_eq!(
            cluster_scoped,
            [
                WatchedKind::GatewayClass,
                WatchedKind::IngressClass,
                WatchedKind::Node,
                WatchedKind::Namespace
            ]
        );
    }

    #[test]
    fn object_key_size() {
        assert!(mem::size_of::<ObjectKey>() <= 32);
    }

    #[test]
    fn intern_stops_at_cap() {
        let mut interner = NsInterner::new();
        let mut ids = Vec::with_capacity(MAX_NAMESPACES);
        for i in 0..MAX_NAMESPACES {
            let name = format!("ns-{i:016}");
            let id = interner.intern(&name);
            assert_ne!(id, NamespaceId::INVALID);
            assert_ne!(id, NamespaceId::UNINTERNED);
            assert_ne!(id, NamespaceId::CLUSTER);
            assert_eq!(interner.resolve(id), Some(name.as_str()));
            ids.push((id, name));
        }
        assert_eq!(interner.len(), MAX_NAMESPACES);
        let overflow = interner.intern("one-too-many");
        assert_eq!(overflow, NamespaceId::INVALID);
        assert_eq!(interner.len(), MAX_NAMESPACES);
        assert_eq!(interner.intern_overflow, 1);
        let (first_id, first_name) = ids.first().unwrap();
        assert_eq!(interner.resolve(*first_id), Some(first_name.as_str()));
    }

    #[test]
    fn unix_seconds_rejects_out_of_range_fields() {
        assert!(UnixSeconds::parse_rfc3339_utc("2026-13-01T00:00:00Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-00-01T00:00:00Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-02-30T00:00:00Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2025-02-29T00:00:00Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24T24:00:00Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24T00:60:00Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24T00:00:60Z").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("2024-02-29T00:00:00Z").is_some());
        assert!(UnixSeconds::parse_rfc3339_utc("2000-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn unix_seconds_rejects_non_ascii_without_panic() {
        assert!(UnixSeconds::parse_rfc3339_utc("2026-07-24T12:00:0\u{e9}").is_none());
        assert!(UnixSeconds::parse_rfc3339_utc("\u{0}\u{0}\u{0}\u{0}-01-01T00:00:00Z").is_none());
    }

    #[test]
    fn unix_seconds_extremes_do_not_overflow() {
        let min = UnixSeconds::parse_rfc3339_utc("0000-01-01T00:00:00Z").unwrap();
        let max = UnixSeconds::parse_rfc3339_utc("9999-12-31T23:59:59Z").unwrap();
        assert!(min.get() < 0);
        assert!(max.get() > 0);
        assert_eq!(UnixSeconds::from_unix_secs(min.get()), min);
        assert_eq!(UnixSeconds::from_unix_secs(max.get()), max);
    }

    #[test]
    fn uid_parse_no_panic_on_non_ascii() {
        assert!(Uid::parse("2026-07-24T12:00:00\u{e9}\u{e9}\u{e9}\u{e9}").is_none());
    }

    #[test]
    fn sanitize_strips_controls_and_truncates() {
        let sanitized = sanitize_for_log("a\nb\r\x1b[31mc");
        assert!(!sanitized.bytes().any(|b| b < 0x20));
        let big = "a".repeat(4096);
        let truncated = sanitize_for_log(&big);
        assert!(truncated.len() <= 203);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn object_key_display_sanitizes() {
        let mut interner = NsInterner::new();
        let ns = interner.intern("team-a");
        let key = ObjectKey::new(WatchedKind::HttpRoute, ns, "\nFATAL fake log line");
        let rendered = key.display(&interner);
        assert!(!rendered.contains('\n'));
    }

    // These two generator inputs are lifted out of the proptest function
    // signatures below and into named consts on purpose. `scripts/test-census.sh`
    // finds a test's body with a plain brace-depth text scan starting at the
    // first `{` after `fn <name>`, not a real Rust parser, and a `{0,20}` regex
    // quantifier or a `\u{..}` escape inside a signature's default-value
    // expression is exactly such a `{`: the scan stops at its matching `}` and
    // reports the real body (with the real assertions) as unreached, which
    // false-positives `no-test-without-assertion`. Moving the literal here, on
    // its own line before the signature, keeps every brace out of the span the
    // census scans for these two functions specifically.
    const NS_NAME_PATTERN: &str = "[a-z][a-z0-9-]{0,20}";
    const TIMESTAMP_FUZZ_ALPHABET: [char; 18] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '.', ':', 'T', 'Z', '\n', '\u{e9}',
        '\u{65e5}',
    ];

    proptest! {
        #[test]
        fn prop_intern_round_trip(names in prop::collection::vec(NS_NAME_PATTERN, 1..50)) {
            let mut interner = NsInterner::new();
            let mut ids = std::collections::HashMap::new();
            let mut distinct_strings = std::collections::HashSet::new();
            for name in &names {
                let id = interner.intern(name);
                assert_eq!(interner.resolve(id), Some(name.as_str()));
                ids.insert(id, name.clone());
                distinct_strings.insert(name.clone());
            }
            assert_eq!(ids.len(), distinct_strings.len());
        }

        #[test]
        fn prop_sanitize_is_bounded_and_control_free(s in ".*") {
            let out = sanitize_for_log(&s);
            assert!(out.len() <= 203);
            assert!(!out.bytes().any(|b| b < 0x20 || b == 0x7f));
            assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        }

        #[test]
        fn prop_timestamp_parse_never_panics(s in prop::collection::vec(
            prop::sample::select(TIMESTAMP_FUZZ_ALPHABET.to_vec()),
            0..40
        ).prop_map(|v| v.into_iter().collect::<String>())) {
            let result = UnixSeconds::parse_rfc3339_utc(&s);
            if result.is_some() {
                assert_eq!(s.len(), 20);
            }
        }
    }
}
