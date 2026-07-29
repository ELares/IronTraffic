// SPDX-License-Identifier: MIT OR Apache-2.0

//! The closed ITPL attribute schema: 25 scalar attributes plus 3 indexable field maps,
//! each with a static type and the phase from which it has a value.
//!
//! This is the whole of what an ITPL expression may read. There is no "get property by
//! arbitrary path" surface: every path an expression can name is one of the rows in
//! [`ATTRS`], resolved once at admission by [`resolve_path`], never hashed or looked up
//! again at request time.

use irontraffic_filter::Phase;

/// Every scalar attribute ITPL can read. Closed: adding one is a deliberate,
/// reviewed act that also touches `docs/ITPL.md` and the evaluator's binding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum AttrId {
    /// `request.method`
    RequestMethod = 0,
    /// `request.path`
    RequestPath = 1,
    /// `request.query`
    RequestQuery = 2,
    /// `request.scheme`
    RequestScheme = 3,
    /// `request.authority`
    RequestAuthority = 4,
    /// `request.host`
    RequestHost = 5,
    /// `request.port`
    RequestPort = 6,
    /// `request.protocol`
    RequestProtocol = 7,
    /// `request.size`
    RequestSize = 8,
    /// `request.id`
    RequestId = 9,
    /// `request.header_count`
    RequestHeaderCount = 10,
    /// `connection.remote_addr`
    ConnectionRemoteAddr = 11,
    /// `connection.remote_port`
    ConnectionRemotePort = 12,
    /// `connection.local_addr`
    ConnectionLocalAddr = 13,
    /// `connection.tls`
    ConnectionTls = 14,
    /// `connection.sni`
    ConnectionSni = 15,
    /// `connection.alpn`
    ConnectionAlpn = 16,
    /// `connection.mtls_verified`
    ConnectionMtlsVerified = 17,
    /// `connection.listener`
    ConnectionListener = 18,
    /// `route.id`
    RouteId = 19,
    /// `route.cluster`
    RouteCluster = 20,
    /// `response.status`
    ResponseStatus = 21,
    /// `response.size`
    ResponseSize = 22,
    /// `stream.id`
    StreamId = 23,
    /// `stream.duration_ms`
    StreamDurationMs = 24,
}

/// The three indexable field maps.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum MapId {
    /// `request.headers["name"]`, name lowercased at admission.
    RequestHeaders = 0,
    /// `request.query_params["name"]`, name case sensitive.
    RequestQuery = 1,
    /// `response.headers["name"]`, name lowercased at admission.
    ResponseHeaders = 2,
}

/// The ITPL type lattice. There is no `dyn` and no union: every node has exactly one
/// static type, except that `Null` unifies with any type for equality only.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Ty {
    /// `true` or `false`.
    Bool = 0,
    /// A 64-bit signed integer.
    Int = 1,
    /// A byte string. ITPL strings are bytes, not necessarily UTF-8, because header
    /// values are bytes.
    Str = 2,
    /// A homogeneous list literal. Only ever the right operand of `in`.
    List = 3,
    /// Absent. The type of a missing header or query parameter, and of the `null`
    /// literal.
    Null = 4,
    /// The type of a map attribute before it is indexed. Never the type of a
    /// complete expression.
    Map = 5,
}

impl Ty {
    /// The name used in error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Ty::Bool => "bool",
            Ty::Int => "int",
            Ty::Str => "string",
            Ty::List => "list",
            Ty::Null => "null",
            Ty::Map => "map",
        }
    }
}

/// One row of the schema table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttrEntry {
    /// The dotted path, for example `b"request.path"`.
    pub path: &'static [u8],
    /// `Some` for a scalar attribute, `None` for one of the three maps.
    pub attr: Option<AttrId>,
    /// `Some` for a map, `None` for a scalar attribute. Exactly one of `attr` and
    /// `map` is `Some`.
    pub map: Option<MapId>,
    /// Static type of the scalar, or `Ty::Map` for a map row.
    pub ty: Ty,
    /// Earliest phase in which it has a value.
    pub from: Phase,
}

/// The whole schema: 25 scalar rows plus 3 map rows, 28 in total, sorted by `path`
/// with `[u8]` byte order. The sort is what makes [`resolve_path`]'s binary search
/// correct, and `attrs_table_is_sorted` asserts it rather than trusting the author.
pub static ATTRS: [AttrEntry; 28] = [
    AttrEntry {
        path: b"connection.alpn",
        attr: Some(AttrId::ConnectionAlpn),
        map: None,
        ty: Ty::Str,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.listener",
        attr: Some(AttrId::ConnectionListener),
        map: None,
        ty: Ty::Int,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.local_addr",
        attr: Some(AttrId::ConnectionLocalAddr),
        map: None,
        ty: Ty::Str,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.mtls_verified",
        attr: Some(AttrId::ConnectionMtlsVerified),
        map: None,
        ty: Ty::Bool,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.remote_addr",
        attr: Some(AttrId::ConnectionRemoteAddr),
        map: None,
        ty: Ty::Str,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.remote_port",
        attr: Some(AttrId::ConnectionRemotePort),
        map: None,
        ty: Ty::Int,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.sni",
        attr: Some(AttrId::ConnectionSni),
        map: None,
        ty: Ty::Str,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"connection.tls",
        attr: Some(AttrId::ConnectionTls),
        map: None,
        ty: Ty::Bool,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"request.authority",
        attr: Some(AttrId::RequestAuthority),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.header_count",
        attr: Some(AttrId::RequestHeaderCount),
        map: None,
        ty: Ty::Int,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.headers",
        attr: None,
        map: Some(MapId::RequestHeaders),
        ty: Ty::Map,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.host",
        attr: Some(AttrId::RequestHost),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.id",
        attr: Some(AttrId::RequestId),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.method",
        attr: Some(AttrId::RequestMethod),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.path",
        attr: Some(AttrId::RequestPath),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.port",
        attr: Some(AttrId::RequestPort),
        map: None,
        ty: Ty::Int,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.protocol",
        attr: Some(AttrId::RequestProtocol),
        map: None,
        ty: Ty::Str,
        from: Phase::StreamStart,
    },
    AttrEntry {
        path: b"request.query",
        attr: Some(AttrId::RequestQuery),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.query_params",
        attr: None,
        map: Some(MapId::RequestQuery),
        ty: Ty::Map,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.scheme",
        attr: Some(AttrId::RequestScheme),
        map: None,
        ty: Ty::Str,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"request.size",
        attr: Some(AttrId::RequestSize),
        map: None,
        ty: Ty::Int,
        from: Phase::RequestHeaders,
    },
    AttrEntry {
        path: b"response.headers",
        attr: None,
        map: Some(MapId::ResponseHeaders),
        ty: Ty::Map,
        from: Phase::ResponseHeaders,
    },
    AttrEntry {
        path: b"response.size",
        attr: Some(AttrId::ResponseSize),
        map: None,
        ty: Ty::Int,
        from: Phase::ResponseHeaders,
    },
    AttrEntry {
        path: b"response.status",
        attr: Some(AttrId::ResponseStatus),
        map: None,
        ty: Ty::Int,
        from: Phase::ResponseHeaders,
    },
    AttrEntry {
        path: b"route.cluster",
        attr: Some(AttrId::RouteCluster),
        map: None,
        ty: Ty::Int,
        from: Phase::RouteSelected,
    },
    AttrEntry {
        path: b"route.id",
        attr: Some(AttrId::RouteId),
        map: None,
        ty: Ty::Int,
        from: Phase::RouteSelected,
    },
    AttrEntry {
        path: b"stream.duration_ms",
        attr: Some(AttrId::StreamDurationMs),
        map: None,
        ty: Ty::Int,
        from: Phase::Log,
    },
    AttrEntry {
        path: b"stream.id",
        attr: Some(AttrId::StreamId),
        map: None,
        ty: Ty::Int,
        from: Phase::StreamStart,
    },
];

/// The closed namespace prefixes a bare identifier may name.
pub const NAMESPACES: [&[u8]; 5] = [b"request", b"connection", b"route", b"response", b"stream"];

/// Longest dotted path the checker will assemble. 64 bytes; the longest real path,
/// `connection.mtls_verified`, is 24.
pub const MAX_PATH_BYTES: usize = 64;

/// Looks up a dotted path in [`ATTRS`] by binary search.
#[must_use]
pub fn resolve_path(path: &[u8]) -> Option<&'static AttrEntry> {
    let i = ATTRS.binary_search_by(|entry| entry.path.cmp(path)).ok()?;
    ATTRS.get(i)
}

impl AttrId {
    /// Number of scalar attributes. 25.
    pub const COUNT: usize = 25;

    /// The dotted path, for example `request.path`.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            AttrId::RequestMethod => "request.method",
            AttrId::RequestPath => "request.path",
            AttrId::RequestQuery => "request.query",
            AttrId::RequestScheme => "request.scheme",
            AttrId::RequestAuthority => "request.authority",
            AttrId::RequestHost => "request.host",
            AttrId::RequestPort => "request.port",
            AttrId::RequestProtocol => "request.protocol",
            AttrId::RequestSize => "request.size",
            AttrId::RequestId => "request.id",
            AttrId::RequestHeaderCount => "request.header_count",
            AttrId::ConnectionRemoteAddr => "connection.remote_addr",
            AttrId::ConnectionRemotePort => "connection.remote_port",
            AttrId::ConnectionLocalAddr => "connection.local_addr",
            AttrId::ConnectionTls => "connection.tls",
            AttrId::ConnectionSni => "connection.sni",
            AttrId::ConnectionAlpn => "connection.alpn",
            AttrId::ConnectionMtlsVerified => "connection.mtls_verified",
            AttrId::ConnectionListener => "connection.listener",
            AttrId::RouteId => "route.id",
            AttrId::RouteCluster => "route.cluster",
            AttrId::ResponseStatus => "response.status",
            AttrId::ResponseSize => "response.size",
            AttrId::StreamId => "stream.id",
            AttrId::StreamDurationMs => "stream.duration_ms",
        }
    }

    /// The static type.
    #[must_use]
    pub const fn ty(self) -> Ty {
        match self {
            AttrId::RequestMethod
            | AttrId::RequestPath
            | AttrId::RequestQuery
            | AttrId::RequestScheme
            | AttrId::RequestAuthority
            | AttrId::RequestHost
            | AttrId::RequestProtocol
            | AttrId::RequestId
            | AttrId::ConnectionRemoteAddr
            | AttrId::ConnectionLocalAddr
            | AttrId::ConnectionSni
            | AttrId::ConnectionAlpn => Ty::Str,
            AttrId::RequestPort
            | AttrId::RequestSize
            | AttrId::RequestHeaderCount
            | AttrId::ConnectionRemotePort
            | AttrId::ConnectionListener
            | AttrId::RouteId
            | AttrId::RouteCluster
            | AttrId::ResponseStatus
            | AttrId::ResponseSize
            | AttrId::StreamId
            | AttrId::StreamDurationMs => Ty::Int,
            AttrId::ConnectionTls | AttrId::ConnectionMtlsVerified => Ty::Bool,
        }
    }

    /// The earliest phase in which this attribute has a value.
    #[must_use]
    pub const fn from_phase(self) -> Phase {
        match self {
            AttrId::RequestMethod
            | AttrId::RequestPath
            | AttrId::RequestQuery
            | AttrId::RequestScheme
            | AttrId::RequestAuthority
            | AttrId::RequestHost
            | AttrId::RequestPort
            | AttrId::RequestSize
            | AttrId::RequestId
            | AttrId::RequestHeaderCount => Phase::RequestHeaders,
            AttrId::RequestProtocol
            | AttrId::ConnectionRemoteAddr
            | AttrId::ConnectionRemotePort
            | AttrId::ConnectionLocalAddr
            | AttrId::ConnectionTls
            | AttrId::ConnectionSni
            | AttrId::ConnectionAlpn
            | AttrId::ConnectionMtlsVerified
            | AttrId::ConnectionListener
            | AttrId::StreamId => Phase::StreamStart,
            AttrId::RouteId | AttrId::RouteCluster => Phase::RouteSelected,
            AttrId::ResponseStatus | AttrId::ResponseSize => Phase::ResponseHeaders,
            AttrId::StreamDurationMs => Phase::Log,
        }
    }

    /// True when the attribute has a value in `phase`.
    ///
    /// Availability runs from `from_phase` through `Phase::Log` inclusive.
    /// `Phase::index` is the dense `0..10` execution order, so comparing indices
    /// is comparing phases, and it keeps this a `const fn` (the derived `PartialOrd`
    /// on `Phase` is not usable in const context).
    #[must_use]
    pub const fn available_in(self, phase: Phase) -> bool {
        phase.index() >= self.from_phase().index()
    }

    /// The attribute for a dotted path, or `None`.
    #[must_use]
    pub fn from_path(path: &[u8]) -> Option<AttrId> {
        resolve_path(path).and_then(|entry| entry.attr)
    }
}

impl MapId {
    /// The dotted path, for example `request.headers`.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            MapId::RequestHeaders => "request.headers",
            MapId::RequestQuery => "request.query_params",
            MapId::ResponseHeaders => "response.headers",
        }
    }

    /// The earliest phase in which this map has values.
    #[must_use]
    pub const fn from_phase(self) -> Phase {
        match self {
            MapId::RequestHeaders | MapId::RequestQuery => Phase::RequestHeaders,
            MapId::ResponseHeaders => Phase::ResponseHeaders,
        }
    }

    /// True when keys must be ASCII-lowercased at admission, which is true for the
    /// two header maps and false for query parameters.
    #[must_use]
    pub const fn lowercase_keys(self) -> bool {
        match self {
            MapId::RequestHeaders | MapId::ResponseHeaders => true,
            MapId::RequestQuery => false,
        }
    }

    /// The map for a dotted path, or `None`.
    #[must_use]
    pub fn from_path(path: &[u8]) -> Option<MapId> {
        resolve_path(path).and_then(|entry| entry.map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ATTR_IDS: [AttrId; AttrId::COUNT] = [
        AttrId::RequestMethod,
        AttrId::RequestPath,
        AttrId::RequestQuery,
        AttrId::RequestScheme,
        AttrId::RequestAuthority,
        AttrId::RequestHost,
        AttrId::RequestPort,
        AttrId::RequestProtocol,
        AttrId::RequestSize,
        AttrId::RequestId,
        AttrId::RequestHeaderCount,
        AttrId::ConnectionRemoteAddr,
        AttrId::ConnectionRemotePort,
        AttrId::ConnectionLocalAddr,
        AttrId::ConnectionTls,
        AttrId::ConnectionSni,
        AttrId::ConnectionAlpn,
        AttrId::ConnectionMtlsVerified,
        AttrId::ConnectionListener,
        AttrId::RouteId,
        AttrId::RouteCluster,
        AttrId::ResponseStatus,
        AttrId::ResponseSize,
        AttrId::StreamId,
        AttrId::StreamDurationMs,
    ];

    const ALL_PHASES: [Phase; Phase::COUNT] = [
        Phase::StreamStart,
        Phase::RequestHeaders,
        Phase::RequestBody,
        Phase::RequestTrailers,
        Phase::RouteSelected,
        Phase::UpstreamRequestHeaders,
        Phase::ResponseHeaders,
        Phase::ResponseBody,
        Phase::ResponseTrailers,
        Phase::Log,
    ];

    #[test]
    fn attrs_table_is_sorted() {
        for pair in ATTRS.windows(2) {
            let [a, b] = pair else {
                panic!("windows(2) always yields a two-element slice");
            };
            assert!(
                a.path < b.path,
                "ATTRS is not sorted: {:?} does not precede {:?}",
                String::from_utf8_lossy(a.path),
                String::from_utf8_lossy(b.path)
            );
        }
    }

    /// Every row's `ty` and `from` column must agree with the `AttrId` and
    /// `MapId` methods that actually answer those questions.
    ///
    /// `resolve_field` reads only `entry.attr` and `entry.map`, then answers
    /// everything else from `attr.ty()`, `attr.from_phase()` and
    /// `attr.available_in()`; `resolve_index` likewise uses `map.from_phase()`
    /// and `map.lowercase_keys()`. Nothing in the workspace reads `entry.ty` or
    /// `entry.from`, so without this test both columns of all 28 rows can drift
    /// from the methods and ship green, while `ATTRS` is `pub`, re-exported, and
    /// documented as "the whole schema" for the compiler and evaluator to read.
    #[test]
    fn attrs_rows_agree_with_the_id_methods() {
        for entry in &ATTRS {
            let path = String::from_utf8_lossy(entry.path);
            match (entry.attr, entry.map) {
                (Some(attr), None) => {
                    assert_eq!(
                        entry.ty,
                        attr.ty(),
                        "{path}: the row's `ty` column disagrees with `AttrId::ty()`"
                    );
                    assert_eq!(
                        entry.from,
                        attr.from_phase(),
                        "{path}: the row's `from` column disagrees with `AttrId::from_phase()`"
                    );
                }
                (None, Some(map)) => {
                    assert_eq!(
                        entry.ty,
                        Ty::Map,
                        "{path}: a map row's `ty` column must be `Ty::Map`"
                    );
                    assert_eq!(
                        entry.from,
                        map.from_phase(),
                        "{path}: the row's `from` column disagrees with `MapId::from_phase()`"
                    );
                }
                _ => panic!("{path}: exactly one of `attr` and `map` must be `Some`"),
            }
        }
    }

    #[test]
    fn attrs_paths_are_unique() {
        for i in 0..ATTRS.len() {
            for j in (i + 1)..ATTRS.len() {
                let (Some(a), Some(b)) = (ATTRS.get(i), ATTRS.get(j)) else {
                    panic!("i and j are both in range by construction");
                };
                assert_ne!(a.path, b.path, "duplicate path in ATTRS");
            }
        }
    }

    #[test]
    fn attr_count_is_25_and_map_count_is_3() {
        assert_eq!(AttrId::COUNT, 25);
        let attr_rows = ATTRS.iter().filter(|e| e.attr.is_some()).count();
        let map_rows = ATTRS.iter().filter(|e| e.map.is_some()).count();
        assert_eq!(attr_rows, 25, "25 scalar rows in ATTRS");
        assert_eq!(map_rows, 3, "3 map rows in ATTRS");
        assert_eq!(ATTRS.len(), 28, "28 rows total");
        // Exactly one of attr/map is Some for every row.
        for entry in &ATTRS {
            assert_ne!(
                entry.attr.is_some(),
                entry.map.is_some(),
                "row {:?} does not have exactly one of attr/map set",
                String::from_utf8_lossy(entry.path)
            );
        }
    }

    #[test]
    fn from_path_roundtrip() {
        for id in ALL_ATTR_IDS {
            assert_eq!(
                AttrId::from_path(id.path().as_bytes()),
                Some(id),
                "from_path(path()) must roundtrip for {id:?}"
            );
        }
    }

    #[test]
    fn availability_monotone() {
        // #738's recurring lesson generalized: check the ACCEPT side (every phase
        // at or after `from_phase`) as well as the reject side, over every phase,
        // for every attribute, not just one hand-picked example.
        for id in ALL_ATTR_IDS {
            let from = id.from_phase();
            for phase in ALL_PHASES {
                let expected = phase >= from;
                assert_eq!(
                    id.available_in(phase),
                    expected,
                    "{id:?} available_in({phase:?}) should be {expected} (from={from:?})"
                );
            }
        }
    }

    #[test]
    fn header_maps_lowercase_keys_query_does_not() {
        assert!(MapId::RequestHeaders.lowercase_keys());
        assert!(MapId::ResponseHeaders.lowercase_keys());
        assert!(!MapId::RequestQuery.lowercase_keys());
    }

    #[test]
    fn map_from_path_roundtrip() {
        assert_eq!(
            MapId::from_path(MapId::RequestHeaders.path().as_bytes()),
            Some(MapId::RequestHeaders)
        );
        assert_eq!(
            MapId::from_path(MapId::RequestQuery.path().as_bytes()),
            Some(MapId::RequestQuery)
        );
        assert_eq!(
            MapId::from_path(MapId::ResponseHeaders.path().as_bytes()),
            Some(MapId::ResponseHeaders)
        );
    }

    #[test]
    fn unknown_path_resolves_to_none() {
        assert_eq!(resolve_path(b"request.nope"), None);
        assert_eq!(resolve_path(b"nope.path"), None);
        assert_eq!(resolve_path(b""), None);
        assert_eq!(AttrId::from_path(b"request.nope"), None);
        assert_eq!(MapId::from_path(b"request.nope"), None);
    }

    #[test]
    fn ty_as_str_exact_table() {
        assert_eq!(Ty::Bool.as_str(), "bool");
        assert_eq!(Ty::Int.as_str(), "int");
        assert_eq!(Ty::Str.as_str(), "string");
        assert_eq!(Ty::List.as_str(), "list");
        assert_eq!(Ty::Null.as_str(), "null");
        assert_eq!(Ty::Map.as_str(), "map");
    }

    #[test]
    fn namespaces_table_has_five_entries() {
        assert_eq!(NAMESPACES.len(), 5);
        assert!(NAMESPACES.contains(&b"request".as_slice()));
        assert!(NAMESPACES.contains(&b"connection".as_slice()));
        assert!(NAMESPACES.contains(&b"route".as_slice()));
        assert!(NAMESPACES.contains(&b"response".as_slice()));
        assert!(NAMESPACES.contains(&b"stream".as_slice()));
    }

    #[test]
    fn max_path_bytes_is_64_and_covers_the_longest_real_path() {
        assert_eq!(MAX_PATH_BYTES, 64);
        let longest = ATTRS.iter().map(|e| e.path.len()).max().unwrap_or(0);
        assert_eq!(
            longest, 24,
            "connection.mtls_verified is the longest real path, at 24 bytes"
        );
        assert!(longest < MAX_PATH_BYTES);
    }
}
