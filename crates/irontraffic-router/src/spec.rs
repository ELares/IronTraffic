// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build-time route specification types and admission errors.
//!
//! These are a faithful, flattened projection of a Gateway API `HTTPRoute`,
//! and are also what the file and API config providers populate. They
//! allocate (`String`, `Vec`) and that is fine: the builder that consumes
//! them runs on a dedicated thread, seconds apart from the request path.

use crate::ids::{ActionId, ListenerId, MethodMask, RouteId};

/// One route offered to the builder. A Kubernetes `HTTPRoute`, a file config entry,
/// or an API-created route all arrive as this.
#[derive(Clone, Debug)]
pub struct HttpRouteSpec {
    /// Caller-owned identity, returned on a match. Must be unique within one build.
    pub route_id: RouteId,
    /// The listener these rules attach to.
    pub listener: ListenerId,
    /// Hostnames this route serves, already intersected with the listener's hostname
    /// by the caller. An empty vector means "every hostname on this listener" and is
    /// equivalent to `vec![HostPattern::Any]`.
    pub hostnames: Vec<HostPattern>,
    /// The route's rules, in declaration order.
    pub rules: Vec<RouteRuleSpec>,
    /// Tie-break key, used only to assign the global ordinal.
    pub order: RouteOrderKey,
}

/// The Gateway API tie-break key for one route.
///
/// `created_unix_millis` is the resource creation timestamp in Unix milliseconds.
/// Non-Kubernetes config sources set it to 0 for every route, in which case the
/// order is purely lexicographic by `(namespace, name)`, which is the deterministic
/// `GitOps` behaviour: re-applying identical config to a fresh store yields identical
/// routing regardless of the order the resources were created in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteOrderKey {
    /// Resource creation time in Unix milliseconds, or 0 when the source has none.
    pub created_unix_millis: u64,
    /// Namespace, or an empty string for non-namespaced sources.
    pub namespace: String,
    /// Resource name. Must be non-empty.
    pub name: String,
}

/// One rule of a route: a set of alternative matches and the action they select.
#[derive(Clone, Debug)]
pub struct RouteRuleSpec {
    /// Alternative matches. An empty vector means the implicit
    /// `PathMatch::Prefix("/")` match that Gateway API defines as the default.
    pub matches: Vec<RouteMatchSpec>,
    /// Opaque handle to the action, returned on a match.
    pub action: ActionId,
}

/// One match: a path condition plus optional method, header and query conditions,
/// all of which must hold (conjunction).
#[derive(Clone, Debug)]
pub struct RouteMatchSpec {
    /// The path condition. Always present; use `PathMatch::Prefix("/".into())` for
    /// "any path".
    pub path: PathMatch,
    /// Method condition, or `None` for "any method".
    pub method: Option<MethodMask>,
    /// Header conditions, at most `MAX_HEADER_MATCHES`.
    pub headers: Vec<HeaderMatch>,
    /// Query parameter conditions, at most `MAX_QUERY_MATCHES`.
    pub query: Vec<QueryParamMatch>,
}

/// A path condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathMatch {
    /// The normalized path equals this value byte for byte. Case sensitive.
    Exact(String),
    /// Gateway API `PathPrefix` semantics: the path equals this value, or the path
    /// starts with this value followed by `/`. `/abc` matches `/abc`, `/abc/` and
    /// `/abc/def`, and never `/abcd`.
    Prefix(String),
    /// The whole normalized path matches this regular expression.
    Regex(String),
}

/// A header condition. Header names are case insensitive and are lowercased at
/// admission. Header values are case SENSITIVE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderMatch {
    /// The named header is present and its value equals `value` byte for byte.
    Exact {
        /// Header name, any case at admission, lowercased by the builder.
        name: String,
        /// Header value, compared byte for byte.
        value: String,
    },
    /// The named header is present, with any value.
    Present {
        /// Header name.
        name: String,
    },
    /// The named header is absent.
    Absent {
        /// Header name.
        name: String,
    },
}

/// A query parameter condition. Query parameter names and values are both case
/// SENSITIVE, per Gateway API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryParamMatch {
    /// The named parameter is present and its value equals `value` byte for byte.
    Exact {
        /// Parameter name.
        name: String,
        /// Parameter value.
        value: String,
    },
    /// The named parameter is present, with any value.
    Present {
        /// Parameter name.
        name: String,
    },
}

/// A hostname condition attached to a route.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostPattern {
    /// Every hostname on the listener. The listener catch-all.
    Any,
    /// Exactly this hostname, after normalization.
    Exact(String),
    /// `*.` followed by this suffix. The suffix is stored WITHOUT the leading `*.`,
    /// and it matches only hostnames with at least one additional label: pattern
    /// `example.com` here matches `a.example.com` but never `example.com`.
    Wildcard(String),
}

impl HostPattern {
    /// The number of characters Gateway API counts for host specificity: the
    /// length of the pattern text excluding any `*.` prefix, or 0 for `Any`.
    #[must_use]
    pub fn specificity_len(&self) -> usize {
        match self {
            HostPattern::Any => 0,
            HostPattern::Exact(host) | HostPattern::Wildcard(host) => host.len(),
        }
    }
}

/// A route was refused at admission. The route is not installed; every other route
/// in the build is unaffected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionError {
    /// The route that was refused.
    pub route_id: RouteId,
    /// Which rule index, when the fault is in a specific rule.
    pub rule_idx: u16,
    /// Which match index within the rule, when the fault is in a specific match.
    pub match_idx: u16,
    /// What was wrong.
    pub kind: AdmissionErrorKind,
}

impl AdmissionError {
    /// A stable `snake_case` label for this failure, for metrics and status conditions.
    #[must_use]
    pub const fn metric_label(&self) -> &'static str {
        self.kind.metric_label()
    }
}

impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "route {}: rule {} match {}: {}",
            self.route_id.0,
            self.rule_idx,
            self.match_idx,
            self.metric_label()
        )
    }
}

impl std::error::Error for AdmissionError {}

/// Why a route was refused at admission.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AdmissionErrorKind {
    /// A path value was empty or did not start with `/`.
    PathNotAbsolute,
    /// A path value exceeded `MAX_PATH_BYTES`.
    PathTooLong,
    /// A path value had more than `MAX_SEGMENTS` segments.
    PathTooManySegments,
    /// A path value contained a byte that cannot appear in a normalized path
    /// (a `?`, a `#`, a space, a byte below 0x21, or 0x7f).
    PathInvalidByte,
    /// A `PathMatch::Regex` was supplied. Removed by `path-regex-multipattern` (#61).
    PathRegexUnsupported,
    /// A hostname or hostname pattern was not a valid Gateway API hostname.
    HostnameInvalid,
    /// A hostname exceeded `MAX_AUTHORITY_BYTES` or `MAX_HOST_LABELS`.
    HostnameTooLong,
    /// A header or query parameter name was empty or contained a byte outside
    /// RFC 9110 `tchar`. `tchar` is exactly this byte set and nothing else:
    /// `A-Z`, `a-z`, `0-9`, and the fifteen bytes
    /// `! # $ % & ' * + - . ^ _ ` | ~`. Every other byte, including `:`, space,
    /// `"`, `(`, `)`, `,`, `/`, `;`, `<`, `=`, `>`, `?`, `@`, `[`, `\`, `]`,
    /// `{`, `}`, every byte below 0x21 and every byte at or above 0x7f, is
    /// outside it. This set is written out here because three issues in this
    /// milestone validate against it and they must all use the same one.
    NameInvalid,
    /// A header or query parameter name exceeded `MAX_NAME_BYTES`.
    NameTooLong,
    /// A header or query parameter value literal exceeded `MAX_VALUE_BYTES`.
    ValueTooLong,
    /// More than `MAX_HEADER_MATCHES` header matches on one match.
    TooManyHeaderMatches,
    /// More than `MAX_QUERY_MATCHES` query matches on one match.
    TooManyQueryMatches,
    /// The same header name appeared twice in one match's header list.
    DuplicateHeaderName,
    /// The same query parameter name appeared twice in one match's query list.
    DuplicateQueryName,
    /// `RouteMatchSpec::method` was `Some(MethodMask::NONE)`, which can never match.
    EmptyMethodMask,
    /// `RouteOrderKey::name` was empty.
    OrderKeyNameEmpty,
    /// `RouteOrderKey::namespace` exceeded `MAX_ORDER_NAMESPACE_BYTES` or
    /// `RouteOrderKey::name` exceeded `MAX_ORDER_NAME_BYTES`.
    OrderKeyTooLong,
    /// Another admitted route already carried this exact
    /// `(created_unix_millis, namespace, name)`. Rejected per route so that one
    /// tenant submitting a colliding order key cannot fail the whole build, which
    /// would stop every other tenant's configuration from being applied.
    /// `assign_ordinals` keeps its own duplicate check as a second line of defence.
    DuplicateOrderKey,
    /// `route_id` was `RouteId::NONE` or was already used in this build.
    RouteIdNotUnique,
}

impl AdmissionErrorKind {
    /// A stable `snake_case` label for this variant, for metrics and status conditions.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            AdmissionErrorKind::PathNotAbsolute => "path_not_absolute",
            AdmissionErrorKind::PathTooLong => "path_too_long",
            AdmissionErrorKind::PathTooManySegments => "path_too_many_segments",
            AdmissionErrorKind::PathInvalidByte => "path_invalid_byte",
            AdmissionErrorKind::PathRegexUnsupported => "path_regex_unsupported",
            AdmissionErrorKind::HostnameInvalid => "hostname_invalid",
            AdmissionErrorKind::HostnameTooLong => "hostname_too_long",
            AdmissionErrorKind::NameInvalid => "name_invalid",
            AdmissionErrorKind::NameTooLong => "name_too_long",
            AdmissionErrorKind::ValueTooLong => "value_too_long",
            AdmissionErrorKind::TooManyHeaderMatches => "too_many_header_matches",
            AdmissionErrorKind::TooManyQueryMatches => "too_many_query_matches",
            AdmissionErrorKind::DuplicateHeaderName => "duplicate_header_name",
            AdmissionErrorKind::DuplicateQueryName => "duplicate_query_name",
            AdmissionErrorKind::EmptyMethodMask => "empty_method_mask",
            AdmissionErrorKind::OrderKeyNameEmpty => "order_key_name_empty",
            AdmissionErrorKind::OrderKeyTooLong => "order_key_too_long",
            AdmissionErrorKind::DuplicateOrderKey => "duplicate_order_key",
            AdmissionErrorKind::RouteIdNotUnique => "route_id_not_unique",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionError, AdmissionErrorKind, HostPattern};
    use crate::ids::RouteId;
    use proptest::prelude::*;

    #[test]
    fn host_pattern_specificity() {
        assert_eq!(HostPattern::Any.specificity_len(), 0);
        assert_eq!(
            HostPattern::Wildcard("example.com".to_owned()).specificity_len(),
            11
        );
        assert_eq!(
            HostPattern::Exact("a.example.com".to_owned()).specificity_len(),
            13
        );
    }

    #[test]
    fn host_pattern_ordering() {
        let any = HostPattern::Any;
        let exact_empty = HostPattern::Exact(String::new());
        let exact = HostPattern::Exact("a.example.com".to_owned());
        let wildcard_empty = HostPattern::Wildcard(String::new());
        let wildcard = HostPattern::Wildcard("example.com".to_owned());
        assert!(any < exact_empty);
        assert!(any < exact);
        assert!(any < wildcard_empty);
        assert!(any < wildcard);
    }

    #[test]
    fn admission_labels_unique() {
        // Exhaustive match: adding a variant to `AdmissionErrorKind` without
        // updating this test is a compile error, because this match would no
        // longer cover every arm.
        fn variant_index(kind: AdmissionErrorKind) -> u8 {
            match kind {
                AdmissionErrorKind::PathNotAbsolute => 0,
                AdmissionErrorKind::PathTooLong => 1,
                AdmissionErrorKind::PathTooManySegments => 2,
                AdmissionErrorKind::PathInvalidByte => 3,
                AdmissionErrorKind::PathRegexUnsupported => 4,
                AdmissionErrorKind::HostnameInvalid => 5,
                AdmissionErrorKind::HostnameTooLong => 6,
                AdmissionErrorKind::NameInvalid => 7,
                AdmissionErrorKind::NameTooLong => 8,
                AdmissionErrorKind::ValueTooLong => 9,
                AdmissionErrorKind::TooManyHeaderMatches => 10,
                AdmissionErrorKind::TooManyQueryMatches => 11,
                AdmissionErrorKind::DuplicateHeaderName => 12,
                AdmissionErrorKind::DuplicateQueryName => 13,
                AdmissionErrorKind::EmptyMethodMask => 14,
                AdmissionErrorKind::OrderKeyNameEmpty => 15,
                AdmissionErrorKind::OrderKeyTooLong => 16,
                AdmissionErrorKind::DuplicateOrderKey => 17,
                AdmissionErrorKind::RouteIdNotUnique => 18,
            }
        }

        let kinds = [
            AdmissionErrorKind::PathNotAbsolute,
            AdmissionErrorKind::PathTooLong,
            AdmissionErrorKind::PathTooManySegments,
            AdmissionErrorKind::PathInvalidByte,
            AdmissionErrorKind::PathRegexUnsupported,
            AdmissionErrorKind::HostnameInvalid,
            AdmissionErrorKind::HostnameTooLong,
            AdmissionErrorKind::NameInvalid,
            AdmissionErrorKind::NameTooLong,
            AdmissionErrorKind::ValueTooLong,
            AdmissionErrorKind::TooManyHeaderMatches,
            AdmissionErrorKind::TooManyQueryMatches,
            AdmissionErrorKind::DuplicateHeaderName,
            AdmissionErrorKind::DuplicateQueryName,
            AdmissionErrorKind::EmptyMethodMask,
            AdmissionErrorKind::OrderKeyNameEmpty,
            AdmissionErrorKind::OrderKeyTooLong,
            AdmissionErrorKind::DuplicateOrderKey,
            AdmissionErrorKind::RouteIdNotUnique,
        ];

        let mut indices: Vec<u8> = kinds.iter().map(|k| variant_index(*k)).collect();
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(
            indices.len(),
            kinds.len(),
            "variant indices must be pairwise distinct"
        );

        let mut labels: Vec<&'static str> = kinds
            .iter()
            .map(|k| {
                let err = AdmissionError {
                    route_id: RouteId(0),
                    rule_idx: 0,
                    match_idx: 0,
                    kind: *k,
                };
                err.metric_label()
            })
            .collect();
        labels.sort_unstable();
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate metric_label");
        }
        for label in &labels {
            assert!(!label.is_empty());
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "label `{label}` is not [a-z0-9_]+"
            );
        }
    }

    proptest! {
        #[test]
        fn spec_types_are_clone_and_debug(spec in crate::testutil::arb_route_spec()) {
            let text = format!("{spec:?}");
            prop_assert!(!text.is_empty());
            let cloned = spec.clone();
            prop_assert_eq!(cloned.route_id, spec.route_id);
            prop_assert_eq!(cloned.listener, spec.listener);
            prop_assert_eq!(cloned.rules.len(), spec.rules.len());
        }
    }
}
