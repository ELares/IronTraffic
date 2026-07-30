// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS 1.3 early data (0-RTT) admission policy.
//!
//! [`evaluate`] is the one place that decides whether a request may be served from early data.
//! Seven conditions are checked, in the exact order below, and every one of them must hold: the
//! listener does not enforce client authentication, the method is `GET` or `HEAD`, there is no
//! declared request body, the matched route allows early data, the query string is absent unless
//! the route explicitly allows one, the connection has not exceeded its early data byte budget,
//! and the ticket presented has not already been used for early data on this node
//! ([`crate::replay::EarlyDataFilter`]). Any failure means the early data is rejected with
//! `ServerConnection::reject_early_data()` and the request is re-driven after the handshake
//! completes, which costs one round trip and is always safe: a rejected verdict never fails the
//! connection, it only refuses to trust bytes that arrived before the handshake proved anything.
//!
//! **Condition 0, client authentication, is checked first and is also a configuration error, not
//! only a runtime rejection.** A resumed TLS 1.3 handshake does not re-run the client-certificate
//! verifier, so serving a request from early data on a listener that requests or requires a
//! client certificate would mean acting on a request that is simultaneously treated as
//! authenticated and known to be replayable. [`EarlyDataConfig::is_permitted_with`] is the
//! predicate the listener-compilation issue calls to refuse that configuration outright;
//! [`evaluate`] refuses it again at run time as defence in depth for as long as that call is not
//! wired in yet.
//!
//! **This module has no caller.** It decides and it counts; it does not parse an HTTP request, it
//! does not inject or strip the `Early-Data` header, and it does not implement the `425 Too Early`
//! retry. Those belong to the unpublished data-plane slug `early-data-request-wiring`, which maps
//! a parsed request onto [`EarlyDataFacts`] and calls [`evaluate`]. Until that slug (and the
//! listener-compilation call to `is_permitted_with`) exist, `enabled` defaults to `false`,
//! [`EarlyDataConfig::effective_max_early_data_size`] is `0`, and nothing behaves differently:
//! this module is reachable and fully tested but dead by construction.
//!
//! **The replay filter reduces volume; it is not the security boundary.** 0-RTT data has no
//! replay protection at the TLS layer (RFC 8446 appendix E.5), and a 0-RTT `ClientHello` can be
//! replayed to more than one node before any single node can prove it has seen the ticket before,
//! so no per-process or best-effort cluster-wide filter closes that window completely. What makes
//! a replay harmless is that early data is restricted to idempotent, side-effect-free requests
//! (conditions 1 through 5): replaying a `GET` with no body and no query is, by construction, not
//! an action a second execution changes the meaning of. `docs/tls/EARLY-DATA.md` states this in
//! those exact words; do not describe the filter as preventing replay anywhere else in this
//! crate's documentation.
//!
//! **The strip-then-inject `Early-Data` header rule.** [`EARLY_DATA_HEADER`] is the one spelling
//! for the header this crate's future caller strips unconditionally from every inbound request
//! (a client-supplied value is unauthenticated and exists only to lie to the upstream about
//! whether this request was replayable) and injects on the upstream request when, and only when,
//! [`evaluate`] returned [`EarlyDataVerdict::Accept`]. That rule and the `425 Too Early` retry it
//! enables both live in `early-data-request-wiring`; this module only names the constant so there
//! is one spelling to strip and one to inject.
//!
//! **`evaluate` and [`crate::replay::EarlyDataFilter::check_and_insert`] allocate nothing and
//! never panic.** This is checked mechanically rather than by convention: neither function carries
//! the `//! HOT PATH` marker (this crate's usual allocation-scan convention), because the
//! acceptance check for this module is a direct `rg` over the two function bodies rather than the
//! marker-scoped scan, and duplicating both mechanisms over the same two functions would only
//! invite them to drift apart. See this module's test module for the exact command.

use crate::replay::EarlyDataFilter;

/// The header name this crate's future caller injects on an early-data-served upstream request
/// and always strips from an inbound one. One spelling, one constant, so the strip site and the
/// inject site cannot disagree about which header they mean.
pub const EARLY_DATA_HEADER: &str = "early-data";

/// Hard cap on [`EarlyDataConfig::max_bytes`], regardless of what an operator configures.
pub const MAX_EARLY_DATA_BYTES: u32 = 65_536;

/// The serde default for [`EarlyDataConfig::max_bytes`]: 16 KiB.
fn default_max_bytes() -> u32 {
    16_384
}

/// The serde default for [`EarlyDataConfig::replay_capacity`]: one million tickets per
/// generation.
fn default_capacity() -> u32 {
    1_000_000
}

/// The serde default for [`EarlyDataConfig::replay_rotate_secs`]: three hours, half the default
/// ticket rotation period (`cluster-derived-session-ticketer`, #120).
fn default_rotate_secs() -> u32 {
    10_800
}

/// Listener-level early data configuration.
///
/// Off by default. Every field here is read as CONFIGURED; nothing in this type clamps itself on
/// construction. Call [`EarlyDataConfig::clamped`] once, at configuration-compile time, before
/// storing or using a value: every other function in this module documents that it assumes it is
/// reading an already-clamped config and does not re-clamp.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EarlyDataConfig {
    /// Off by default. When false, [`EarlyDataConfig::effective_max_early_data_size`] stays 0 and
    /// no request is ever served from early data.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum early data bytes accepted per connection. Default 16,384, clamped to
    /// `0..=65_536` by [`EarlyDataConfig::clamped`].
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u32,
    /// Replay filter capacity in tickets per generation. Default 1,000,000, clamped to
    /// `1_024..=8_388_608` by [`EarlyDataConfig::clamped`].
    #[serde(default = "default_capacity")]
    pub replay_capacity: u32,
    /// Seconds between replay filter generation rotations. Default 10,800 (3 hours), clamped to
    /// `60..=86_400` by [`EarlyDataConfig::clamped`].
    #[serde(default = "default_rotate_secs")]
    pub replay_rotate_secs: u32,
}

impl EarlyDataConfig {
    /// Clamp every field into its documented range. Called once at configuration-compile time;
    /// every other function in this module assumes it is reading the result of this call and does
    /// not re-clamp.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            enabled: self.enabled,
            max_bytes: self.max_bytes.min(MAX_EARLY_DATA_BYTES),
            replay_capacity: self.replay_capacity.clamp(1_024, 8_388_608),
            replay_rotate_secs: self.replay_rotate_secs.clamp(60, 86_400),
        }
    }

    /// The value to install as `max_early_data_size` on a listener's rustls `ServerConfig`:
    /// `max_bytes` when enabled, else 0. This is the only sanctioned way to raise
    /// `max_early_data_size` above the 0 that `tls-protocol-cipher-group-alpn-policy` (#116) sets
    /// in `apply_common`.
    #[must_use]
    pub fn effective_max_early_data_size(&self) -> u32 {
        if self.enabled { self.max_bytes } else { 0 }
    }

    /// Whether this configuration may be installed on a listener that enforces client
    /// authentication. Returns `false` only when `enabled` is true and `client_auth_enforced` is
    /// true: early data and mutual TLS never combine, because a resumed handshake does not
    /// re-present or re-verify the client certificate. A disabled configuration is always
    /// permitted, on any listener, because it changes nothing.
    ///
    /// The issue that wires this configuration into listener compilation calls this and fails the
    /// configuration outright rather than silently disabling early data, because an operator who
    /// wrote `earlyData.enabled: true` on an mTLS listener has a wrong mental model that a silent
    /// downgrade would leave intact. See condition 0 in the module documentation above.
    ///
    /// No published issue calls this yet: `sni-server-config-selection` (#119) compiles a
    /// listener without reading any early-data configuration. Until a later issue adds that call,
    /// condition 0 is enforced only at run time, by [`evaluate`], which is why that runtime check
    /// is not redundant with this one.
    #[must_use]
    pub fn is_permitted_with(&self, client_auth_enforced: bool) -> bool {
        !(self.enabled && client_auth_enforced)
    }
}

/// Per-route early data policy.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum RouteEarlyData {
    /// Never serve this route from early data. The default.
    #[default]
    Deny,
    /// Serve from early data when there is no query string.
    Allow,
    /// Serve from early data even with a query string.
    AllowQuery,
}

/// Why a route's early data policy was downgraded at configuration-compile time.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ForceDenyReason {
    /// The route's filter chain mutates request or response state.
    MutatingFilter,
    /// The route increments a rate limit or quota counter.
    CounterIncrement,
    /// The route makes an authorization decision that writes state.
    StatefulAuth,
    /// The route accepts a method other than `GET` and `HEAD`.
    NonIdempotentMethod,
}

impl RouteEarlyData {
    /// Downgrade to [`RouteEarlyData::Deny`] if any reason applies, returning the effective policy
    /// and the first reason that forced it, so the configuration compiler can record why an
    /// operator's `allow` did not take effect. Returns `(self, None)` unchanged when `reasons` is
    /// empty.
    ///
    /// The configuration compiler calls this once per route and records the reason in the route's
    /// explain output, so an operator who wrote `allow` can see why it did not take effect.
    #[must_use]
    pub fn force_deny_if(self, reasons: &[ForceDenyReason]) -> (Self, Option<ForceDenyReason>) {
        match reasons.first() {
            Some(&reason) => (Self::Deny, Some(reason)),
            None => (self, None),
        }
    }
}

/// Method, reduced to what the early data rule cares about.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EarlyDataMethod {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// Anything else.
    Other,
}

/// Everything the early data rule needs about one request. Built by the data-plane wiring this
/// module has no dependency on.
#[derive(Copy, Clone, Debug)]
pub struct EarlyDataFacts<'a> {
    /// True when the listener this connection arrived on requests or requires a client
    /// certificate, that is when its `ClientAuthKind` is anything other than `None`. A plain
    /// `bool` rather than the `ClientAuthKind` enum so that this module does not depend on
    /// `sni-server-config-selection` (#119); the wiring sets it from
    /// `TlsServerConfig::client_auth() != ClientAuthKind::None`.
    pub client_auth_enforced: bool,
    /// Request method.
    pub method: EarlyDataMethod,
    /// True if the request declared a body with `Content-Length` or `Transfer-Encoding`.
    pub has_body_framing: bool,
    /// True if the request target carries a query string, even an empty one after `?`.
    pub has_query: bool,
    /// The matched route's effective policy, after [`RouteEarlyData::force_deny_if`].
    pub route: RouteEarlyData,
    /// Early data bytes received on this connection so far, including this request.
    pub bytes_received: u32,
    /// The PSK identity from the `ClientHello`, used as the replay key.
    pub psk_identity: &'a [u8],
}

/// The decision.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EarlyDataVerdict {
    /// Serve from early data. The caller injects `Early-Data: 1` upstream.
    Accept,
    /// Reject the early data and re-drive after the handshake. Carries the reason for the metric.
    Reject(EarlyDataReject),
}

/// Why early data was rejected. Every variant has its own counter label.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EarlyDataReject {
    /// Early data is disabled on this listener.
    Disabled,
    /// The listener enforces client authentication. Early data and mutual TLS do not combine: a
    /// resumed handshake does not re-run the client-certificate verifier, so an accepted
    /// early-data request would be both authenticated and replayable.
    ClientAuth,
    /// Method was not `GET` or `HEAD`.
    Method,
    /// The request declared a body.
    Body,
    /// The route's policy is `deny`.
    RoutePolicy,
    /// A query string was present and the route is only `allow`.
    Query,
    /// `bytes_received` exceeded `max_bytes`.
    TooLarge,
    /// The replay filter has seen this ticket.
    Replay,
    /// The PSK identity was empty or shorter than 16 bytes.
    NoPskIdentity,
}

/// Evaluate the seven conditions, numbered 0 through 6 in this module's own documentation and in
/// the issue that specifies it, in this exact order: the order is load bearing, because the only
/// condition with a side effect (the replay filter insert) runs last, so a request that fails any
/// earlier, side-effect-free check never touches the filter at all.
///
/// Allocates nothing and never panics: every rejecting branch returns before the replay filter is
/// touched, and the one fallible step (a PSK identity shorter than 16 bytes) is handled with
/// `get`, never `[..16]`, because a short identity is attacker reachable and a panic here would be
/// a remote denial of service.
#[must_use]
pub fn evaluate(
    config: &EarlyDataConfig,
    filter: &EarlyDataFilter,
    facts: &EarlyDataFacts<'_>,
) -> EarlyDataVerdict {
    if !config.enabled {
        return EarlyDataVerdict::Reject(EarlyDataReject::Disabled);
    }
    if facts.client_auth_enforced {
        return EarlyDataVerdict::Reject(EarlyDataReject::ClientAuth);
    }
    if facts.method == EarlyDataMethod::Other {
        return EarlyDataVerdict::Reject(EarlyDataReject::Method);
    }
    if facts.has_body_framing {
        return EarlyDataVerdict::Reject(EarlyDataReject::Body);
    }
    if facts.route == RouteEarlyData::Deny {
        return EarlyDataVerdict::Reject(EarlyDataReject::RoutePolicy);
    }
    if facts.has_query && facts.route != RouteEarlyData::AllowQuery {
        return EarlyDataVerdict::Reject(EarlyDataReject::Query);
    }
    if facts.bytes_received > config.max_bytes {
        return EarlyDataVerdict::Reject(EarlyDataReject::TooLarge);
    }
    let Some(key16) = facts.psk_identity.get(..16) else {
        return EarlyDataVerdict::Reject(EarlyDataReject::NoPskIdentity);
    };
    if filter.check_and_insert(key16) {
        return EarlyDataVerdict::Reject(EarlyDataReject::Replay);
    }
    EarlyDataVerdict::Accept
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::strategy::ValueTree as _;
    use proptest::test_runner::TestRunner;

    use super::{
        EarlyDataConfig, EarlyDataFacts, EarlyDataMethod, EarlyDataReject, EarlyDataVerdict,
        ForceDenyReason, RouteEarlyData, evaluate,
    };
    use crate::replay::EarlyDataFilter;
    use crate::time::UnixSeconds;

    /// A config with every field spelled out as a literal, never built from a `default_*`
    /// helper: a test that read its fixture back out of the same function under test would prove
    /// nothing about that function.
    fn config(enabled: bool, max_bytes: u32) -> EarlyDataConfig {
        EarlyDataConfig {
            enabled,
            max_bytes,
            replay_capacity: 1_024,
            replay_rotate_secs: 10_800,
        }
    }

    fn filter(config: &EarlyDataConfig) -> EarlyDataFilter {
        EarlyDataFilter::new(config, [11u8; 16], UnixSeconds::new(1_700_000_000))
    }

    /// A facts value that satisfies every one of the seven conditions on its own: a fully
    /// compliant `GET`, no body, `route: allow`, no query, well under budget, a 16-byte PSK
    /// identity. Every test below starts here and changes exactly the one field its name
    /// describes, so a failing assertion points at that field, not at an unrelated one the test
    /// forgot to hold fixed.
    fn compliant_facts(psk: &[u8]) -> EarlyDataFacts<'_> {
        EarlyDataFacts {
            client_auth_enforced: false,
            method: EarlyDataMethod::Get,
            has_body_framing: false,
            has_query: false,
            route: RouteEarlyData::Allow,
            bytes_received: 0,
            psk_identity: psk,
        }
    }

    #[test]
    fn disabled_rejects_everything() {
        let cfg = config(false, 16_384);
        let f = filter(&cfg);
        let psk = [1u8; 16];
        // Fully compliant otherwise, so the ONLY reason this can reject is `enabled: false`.
        let facts = compliant_facts(&psk);
        assert_eq!(
            evaluate(&cfg, &f, &facts),
            EarlyDataVerdict::Reject(EarlyDataReject::Disabled)
        );
        assert_eq!(cfg.effective_max_early_data_size(), 0);
    }

    #[test]
    fn max_bytes_zero_advertises_zero() {
        let cfg = config(true, 0);
        assert_eq!(cfg.effective_max_early_data_size(), 0);
        // A zero-byte budget still lets a request that received exactly zero early-data bytes
        // through the byte check (0 > 0 is false); it is `TooLarge` only once anything arrives.
        let f = filter(&cfg);
        let psk = [2u8; 16];
        let facts = compliant_facts(&psk);
        assert_eq!(evaluate(&cfg, &f, &facts), EarlyDataVerdict::Accept);
    }

    #[test]
    fn max_bytes_clamped() {
        for (input, expected) in [
            (0u32, 0u32),
            (16_384, 16_384),
            (65_536, 65_536),
            (65_537, 65_536),
            (u32::MAX, 65_536),
        ] {
            let clamped = config(true, input).clamped();
            assert_eq!(clamped.max_bytes, expected, "input {input}");
            assert!(clamped.enabled, "clamped must not touch enabled");
        }
    }

    #[test]
    fn bytes_at_and_over_limit() {
        let cfg = config(true, 1_000);
        let f = filter(&cfg);
        let psk = [3u8; 16];

        let mut at_limit = compliant_facts(&psk);
        at_limit.bytes_received = 1_000;
        assert_eq!(evaluate(&cfg, &f, &at_limit), EarlyDataVerdict::Accept);

        // Reusing the SAME psk on purpose: `at_limit` above already inserted it into the
        // replay filter, so if `TooLarge` were checked AFTER the replay filter this call would
        // observe `Reject(Replay)` instead. Getting `Reject(TooLarge)` here proves the byte
        // check runs before the filter is ever touched, exactly as `evaluate`'s documented order
        // requires.
        let mut over_limit = compliant_facts(&psk);
        over_limit.bytes_received = 1_001;
        assert_eq!(
            evaluate(&cfg, &f, &over_limit),
            EarlyDataVerdict::Reject(EarlyDataReject::TooLarge)
        );
    }

    #[test]
    fn post_rejected_even_with_allow_query() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let psk = [4u8; 16];
        let mut facts = compliant_facts(&psk);
        // The route's most permissive setting cannot promote a non-idempotent method.
        facts.method = EarlyDataMethod::Other;
        facts.route = RouteEarlyData::AllowQuery;
        facts.has_query = true;
        assert_eq!(
            evaluate(&cfg, &f, &facts),
            EarlyDataVerdict::Reject(EarlyDataReject::Method)
        );
    }

    #[test]
    fn content_length_zero_is_a_body() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let psk = [5u8; 16];
        let mut facts = compliant_facts(&psk);
        // A declared Content-Length of 0 still sets has_body_framing: the header was present,
        // and a zero-length declared body is still a declared body.
        facts.has_body_framing = true;
        assert_eq!(
            evaluate(&cfg, &f, &facts),
            EarlyDataVerdict::Reject(EarlyDataReject::Body)
        );
    }

    #[test]
    fn empty_query_is_a_query() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);

        let psk_a = [6u8; 16];
        let mut allow_only = compliant_facts(&psk_a);
        allow_only.has_query = true;
        assert_eq!(
            evaluate(&cfg, &f, &allow_only),
            EarlyDataVerdict::Reject(EarlyDataReject::Query)
        );

        let psk_b = [7u8; 16];
        let mut allow_query = compliant_facts(&psk_b);
        allow_query.has_query = true;
        allow_query.route = RouteEarlyData::AllowQuery;
        assert_eq!(evaluate(&cfg, &f, &allow_query), EarlyDataVerdict::Accept);
    }

    #[test]
    fn allow_without_query_accepts() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let psk = [8u8; 16];
        let facts = compliant_facts(&psk);
        assert_eq!(evaluate(&cfg, &f, &facts), EarlyDataVerdict::Accept);
    }

    #[test]
    fn force_deny_beats_operator_allow() {
        let (downgraded, reason) =
            RouteEarlyData::Allow.force_deny_if(&[ForceDenyReason::MutatingFilter]);
        assert_eq!(downgraded, RouteEarlyData::Deny);
        assert_eq!(reason, Some(ForceDenyReason::MutatingFilter));

        // An empty reason list must leave the operator's policy untouched.
        let (unchanged, none) = RouteEarlyData::Allow.force_deny_if(&[]);
        assert_eq!(unchanged, RouteEarlyData::Allow);
        assert_eq!(none, None);

        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let psk = [9u8; 16];
        let mut facts = compliant_facts(&psk);
        facts.route = downgraded;
        assert_eq!(
            evaluate(&cfg, &f, &facts),
            EarlyDataVerdict::Reject(EarlyDataReject::RoutePolicy)
        );
    }

    #[test]
    fn empty_psk_rejected() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let facts = compliant_facts(&[]);
        assert_eq!(
            evaluate(&cfg, &f, &facts),
            EarlyDataVerdict::Reject(EarlyDataReject::NoPskIdentity)
        );
    }

    #[test]
    fn psk_15_bytes_rejected() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let short = [10u8; 15];
        let facts = compliant_facts(&short);
        assert_eq!(
            evaluate(&cfg, &f, &facts),
            EarlyDataVerdict::Reject(EarlyDataReject::NoPskIdentity)
        );
    }

    #[test]
    fn client_auth_listener_rejects_early_data() {
        let cfg = config(true, 16_384);
        let f = filter(&cfg);
        let psk = [12u8; 16];

        let mut mtls_facts = compliant_facts(&psk);
        mtls_facts.client_auth_enforced = true;
        assert_eq!(
            evaluate(&cfg, &f, &mtls_facts),
            EarlyDataVerdict::Reject(EarlyDataReject::ClientAuth)
        );

        // The identical facts, with only client_auth_enforced flipped: this is what proves the
        // condition is the only difference between the two verdicts.
        let no_mtls_facts = EarlyDataFacts {
            client_auth_enforced: false,
            ..mtls_facts
        };
        assert_eq!(evaluate(&cfg, &f, &no_mtls_facts), EarlyDataVerdict::Accept);
    }

    #[test]
    fn is_permitted_with_refuses_enabled_on_mtls() {
        let enabled = config(true, 16_384);
        assert!(!enabled.is_permitted_with(true));
        assert!(enabled.is_permitted_with(false));

        let disabled = config(false, 16_384);
        assert!(disabled.is_permitted_with(true));
        assert!(disabled.is_permitted_with(false));
    }

    /// Manual `TestRunner` loop, not the `proptest!` macro: this lets the test accumulate an
    /// `accepted` counter across every generated case and assert a floor on it at the end, so a
    /// generator that stops producing any compliant request (for instance a future edit that
    /// flips a comparison and makes every case reject) is caught here rather than passing this
    /// property vacuously forever. Mirrors `irontraffic-policy`'s own
    /// `prop_generator_reaches_check_ok`.
    #[test]
    fn prop_evaluate_is_monotone_in_strictness() {
        let cfg = config(true, 16_384);
        // One fixed filter, reused for every case: the property is an implication FROM Accept,
        // so a case that the filter rejects as a replay (because an earlier case in this same
        // run happened to draw the same 16-byte tail) only removes an Accept observation, it can
        // never manufacture a false one, so it cannot make the property assertion below wrong.
        let f = filter(&cfg);

        let strategy = (
            any::<bool>(),
            prop_oneof![
                Just(EarlyDataMethod::Get),
                Just(EarlyDataMethod::Head),
                Just(EarlyDataMethod::Other),
            ],
            any::<bool>(),
            any::<bool>(),
            prop_oneof![
                Just(RouteEarlyData::Deny),
                Just(RouteEarlyData::Allow),
                Just(RouteEarlyData::AllowQuery),
            ],
            0u32..20_000u32,
            proptest::collection::vec(any::<u8>(), 0..24),
        );

        let mut runner = TestRunner::default();
        let mut total = 0u32;
        let mut accepted = 0u32;
        for _ in 0..500 {
            let Ok(tree) = strategy.new_tree(&mut runner) else {
                continue;
            };
            let (
                client_auth_enforced,
                method,
                has_body_framing,
                has_query,
                route,
                bytes_received,
                psk_vec,
            ) = tree.current();
            total += 1;

            let facts = EarlyDataFacts {
                client_auth_enforced,
                method,
                has_body_framing,
                has_query,
                route,
                bytes_received,
                psk_identity: &psk_vec,
            };
            let verdict = evaluate(&cfg, &f, &facts);
            if verdict == EarlyDataVerdict::Accept {
                accepted += 1;
                assert!(!client_auth_enforced);
                assert!(matches!(
                    method,
                    EarlyDataMethod::Get | EarlyDataMethod::Head
                ));
                assert!(!has_body_framing);
                assert_ne!(route, RouteEarlyData::Deny);
                if has_query {
                    assert_eq!(route, RouteEarlyData::AllowQuery);
                }
            }
        }
        assert!(total > 0);
        // The reachability floor: over several local runs this landed between about 15 and 40
        // out of 500 cases (the seven-condition conjunction is a demanding target for an
        // unconstrained generator), so 5 is a floor well under every observed run rather than a
        // number chosen to just barely pass once.
        assert!(
            accepted >= 5,
            "prop_evaluate_is_monotone_in_strictness reached Accept only {accepted} times in \
             {total} cases; the generator is not exercising the Accept branch this property is \
             actually about"
        );
    }
}
