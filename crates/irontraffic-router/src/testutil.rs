// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only generators shared across this crate's unit tests.

use proptest::prelude::*;

use crate::ids::{ActionId, ListenerId, RouteId};
use crate::spec::{
    HostPattern, HttpRouteSpec, PathMatch, RouteMatchSpec, RouteOrderKey, RouteRuleSpec,
};

/// One of the three hostname shapes the generator covers.
fn arb_host_pattern() -> impl Strategy<Value = HostPattern> {
    prop_oneof![
        Just(HostPattern::Any),
        Just(HostPattern::Exact("a.example.com".to_owned())),
        Just(HostPattern::Wildcard("example.com".to_owned())),
    ]
}

/// One of the three path shapes the generator covers.
fn arb_path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/".to_owned()),
        Just("/api".to_owned()),
        Just("/api/v1".to_owned())
    ]
}

/// A single match: a path condition with no method, header or query condition.
fn arb_match() -> impl Strategy<Value = RouteMatchSpec> {
    arb_path().prop_map(|path| RouteMatchSpec {
        path: PathMatch::Prefix(path),
        method: None,
        headers: Vec::new(),
        query: Vec::new(),
    })
}

/// A rule with 0 to 3 matches.
fn arb_rule() -> impl Strategy<Value = RouteRuleSpec> {
    proptest::collection::vec(arb_match(), 0..=3).prop_map(|matches| RouteRuleSpec {
        matches,
        action: ActionId(0),
    })
}

/// Generates an `HttpRouteSpec` with the shape described in `spec::tests::spec_types_are_clone_and_debug`.
pub fn arb_route_spec() -> impl Strategy<Value = HttpRouteSpec> {
    (
        0u32..1000,
        0u16..4,
        proptest::collection::vec(arb_host_pattern(), 0..=3),
        proptest::collection::vec(arb_rule(), 0..=3),
    )
        .prop_map(|(route_id, listener, hostnames, rules)| HttpRouteSpec {
            route_id: RouteId(route_id),
            listener: ListenerId(listener),
            hostnames,
            rules,
            order: RouteOrderKey {
                created_unix_millis: 0,
                namespace: String::new(),
                name: "r".to_owned(),
            },
        })
}
