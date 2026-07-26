// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ten lifecycle phases and the bitset that tracks which of them a filter
//! or a chain subscribes to.
//!
//! The phase list is Pingora's `ProxyHttp` vocabulary reduced to the ten points
//! where a proxy actually holds a distinct, mutable object. Every discriminant
//! equals the phase's position in execution order, so the derived `Ord` is the
//! execution order.

/// One of the ten points in a request's life where the chain holds a distinct,
/// mutable object and may dispatch filters against it.
///
/// Discriminants are dense (`0..10`) and equal execution order: comparing two
/// `Phase` values with the derived `Ord` tells you which runs first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum Phase {
    /// Stream opened. Connection metadata only, no request head yet.
    StreamStart = 0,
    /// Downstream request head, after parse and normalization, before routing.
    RequestHeaders = 1,
    /// One downstream request body chunk. Streaming.
    RequestBody = 2,
    /// Downstream request trailers.
    RequestTrailers = 3,
    /// The route, cluster and endpoint choice, after matching.
    RouteSelected = 4,
    /// The request head in the exact form it will be written upstream.
    UpstreamRequestHeaders = 5,
    /// The upstream response head.
    ResponseHeaders = 6,
    /// One upstream response body chunk. Streaming.
    ResponseBody = 7,
    /// Upstream response trailers.
    ResponseTrailers = 8,
    /// Terminal, read only, runs for every stream on every terminal path.
    Log = 9,
}

impl Phase {
    /// Number of phases. Fixed at 10; arrays indexed by phase are `[T; 10]`.
    pub const COUNT: usize = 10;

    /// Dense index in `0..10`.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The phase for a dense index, or `None` when `i >= 10`.
    ///
    /// The one conversion from a number to a `Phase`. Every place that decodes
    /// a stored or guest-supplied phase byte calls this and treats `None` as a
    /// malformed record.
    #[must_use]
    pub const fn from_index(i: u8) -> Option<Phase> {
        match i {
            0 => Some(Phase::StreamStart),
            1 => Some(Phase::RequestHeaders),
            2 => Some(Phase::RequestBody),
            3 => Some(Phase::RequestTrailers),
            4 => Some(Phase::RouteSelected),
            5 => Some(Phase::UpstreamRequestHeaders),
            6 => Some(Phase::ResponseHeaders),
            7 => Some(Phase::ResponseBody),
            8 => Some(Phase::ResponseTrailers),
            9 => Some(Phase::Log),
            _ => None,
        }
    }

    /// True for the two streaming body phases.
    #[inline]
    #[must_use]
    pub const fn is_body(self) -> bool {
        matches!(self, Phase::RequestBody | Phase::ResponseBody)
    }

    /// True for phases where a filter may return `Action::Respond` or
    /// `Action::Reset`. False for `RequestTrailers`, `ResponseTrailers` and `Log`.
    #[inline]
    #[must_use]
    pub const fn can_short_circuit(self) -> bool {
        !matches!(
            self,
            Phase::RequestTrailers | Phase::ResponseTrailers | Phase::Log
        )
    }

    /// True for the three response-direction phases, which the chain iterates from
    /// the last filter to the first: `ResponseHeaders`, `ResponseBody`,
    /// `ResponseTrailers`. Every other phase iterates first to last.
    #[inline]
    #[must_use]
    pub const fn runs_in_reverse(self) -> bool {
        matches!(
            self,
            Phase::ResponseHeaders | Phase::ResponseBody | Phase::ResponseTrailers
        )
    }

    /// The lowercase phase name, for logs, traces and the explain surface.
    ///
    /// The exact table, which no other issue may re-invent:
    /// `StreamStart` -> `"stream_start"`, `RequestHeaders` -> `"request_headers"`,
    /// `RequestBody` -> `"request_body"`, `RequestTrailers` -> `"request_trailers"`,
    /// `RouteSelected` -> `"route_selected"`, `UpstreamRequestHeaders` ->
    /// `"upstream_request_headers"`, `ResponseHeaders` -> `"response_headers"`,
    /// `ResponseBody` -> `"response_body"`, `ResponseTrailers` -> `"response_trailers"`,
    /// `Log` -> `"log"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::StreamStart => "stream_start",
            Phase::RequestHeaders => "request_headers",
            Phase::RequestBody => "request_body",
            Phase::RequestTrailers => "request_trailers",
            Phase::RouteSelected => "route_selected",
            Phase::UpstreamRequestHeaders => "upstream_request_headers",
            Phase::ResponseHeaders => "response_headers",
            Phase::ResponseBody => "response_body",
            Phase::ResponseTrailers => "response_trailers",
            Phase::Log => "log",
        }
    }
}

/// A subscription set over the ten phases, stored as one bit per phase.
///
/// Bits 10 to 15 of the sixteen available are reserved and must always be
/// zero, so a later phase can be added without changing the type.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct PhaseMask(u16);

impl PhaseMask {
    /// The empty mask. No phase is subscribed.
    pub const NONE: PhaseMask = PhaseMask(0);
    /// Every phase subscribed. `0x03FF`.
    pub const ALL: PhaseMask = PhaseMask(0x03FF);

    /// A mask with exactly the listed phases set. Duplicates are harmless.
    #[must_use]
    pub const fn from_phases(mut phases: &[Phase]) -> PhaseMask {
        let mut acc = 0u16;
        while let [p, rest @ ..] = phases {
            acc |= 1u16 << (*p as u8); // it-allow: unchecked-cast reason: Phase is repr(u8) with discriminants 0..10, so this reads the existing byte rather than truncating a wider value
            phases = rest;
        }
        PhaseMask(acc)
    }

    /// True when `phase` is subscribed. One shift, one and, one test.
    #[inline]
    #[must_use]
    pub const fn has(self, phase: Phase) -> bool {
        let bit = 1u16 << (phase as u8); // it-allow: unchecked-cast reason: Phase is repr(u8) with discriminants 0..10, so this reads the existing byte rather than truncating a wider value
        self.0 & bit != 0
    }

    /// The union of two masks, as the chain computes it over its filters.
    #[inline]
    #[must_use]
    pub const fn union(self, other: PhaseMask) -> PhaseMask {
        PhaseMask(self.0 | other.0)
    }

    /// True when no phase is subscribed.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bits, for the config-dump surface and for tests.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn phase_count_is_ten() {
        assert_eq!(Phase::COUNT, 10);
        assert!(Phase::from_index(9).is_some());
    }

    #[test]
    fn phase_index_roundtrip() {
        for p in ALL_PHASES {
            let i = u8::try_from(p.index()).expect("phase index fits in u8, COUNT is 10");
            assert_eq!(Phase::from_index(i), Some(p));
        }
    }

    #[test]
    fn phase_from_index_out_of_range() {
        assert!(Phase::from_index(10).is_none());
        assert!(Phase::from_index(255).is_none());
    }

    #[test]
    fn phase_order_is_execution_order() {
        assert!(Phase::StreamStart < Phase::RequestHeaders);
        assert!(Phase::RequestHeaders < Phase::RequestBody);
        assert!(Phase::RequestBody < Phase::RequestTrailers);
        assert!(Phase::RequestTrailers < Phase::RouteSelected);
        assert!(Phase::RouteSelected < Phase::UpstreamRequestHeaders);
        assert!(Phase::UpstreamRequestHeaders < Phase::ResponseHeaders);
        assert!(Phase::ResponseHeaders < Phase::ResponseBody);
        assert!(Phase::ResponseBody < Phase::ResponseTrailers);
        assert!(Phase::ResponseTrailers < Phase::Log);
    }

    #[test]
    fn phase_is_body_exactly_two() {
        let count = ALL_PHASES.iter().filter(|p| p.is_body()).count();
        assert_eq!(count, 2);
        assert!(Phase::RequestBody.is_body());
        assert!(Phase::ResponseBody.is_body());
    }

    #[test]
    fn phase_can_short_circuit_set() {
        assert!(!Phase::RequestTrailers.can_short_circuit());
        assert!(!Phase::ResponseTrailers.can_short_circuit());
        assert!(!Phase::Log.can_short_circuit());

        assert!(Phase::StreamStart.can_short_circuit());
        assert!(Phase::RequestHeaders.can_short_circuit());
        assert!(Phase::RequestBody.can_short_circuit());
        assert!(Phase::RouteSelected.can_short_circuit());
        assert!(Phase::UpstreamRequestHeaders.can_short_circuit());
        assert!(Phase::ResponseHeaders.can_short_circuit());
        assert!(Phase::ResponseBody.can_short_circuit());
    }

    #[test]
    fn phase_reverse_set() {
        let count = ALL_PHASES.iter().filter(|p| p.runs_in_reverse()).count();
        assert_eq!(count, 3);
        assert!(Phase::ResponseHeaders.runs_in_reverse());
        assert!(Phase::ResponseBody.runs_in_reverse());
        assert!(Phase::ResponseTrailers.runs_in_reverse());
    }

    #[test]
    fn mask_empty_has_nothing() {
        for p in ALL_PHASES {
            assert!(!PhaseMask::NONE.has(p));
        }
    }

    #[test]
    fn mask_all_has_everything() {
        for p in ALL_PHASES {
            assert!(PhaseMask::ALL.has(p));
        }
        assert_eq!(PhaseMask::ALL.bits(), 0x03FF);
    }

    #[test]
    fn mask_from_phases_is_idempotent() {
        assert_eq!(
            PhaseMask::from_phases(&[Phase::RequestHeaders, Phase::RequestHeaders]),
            PhaseMask::from_phases(&[Phase::RequestHeaders])
        );
    }

    #[test]
    fn mask_union_identity() {
        let m = PhaseMask::from_phases(&[Phase::Log]);
        assert_eq!(m.union(PhaseMask::NONE), m);
    }

    #[test]
    fn phase_names_exact() {
        let names: Vec<&str> = ALL_PHASES.iter().map(|p| p.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "stream_start",
                "request_headers",
                "request_body",
                "request_trailers",
                "route_selected",
                "upstream_request_headers",
                "response_headers",
                "response_body",
                "response_trailers",
                "log",
            ]
        );
    }

    #[test]
    fn exhaustive_mask_membership() {
        for bits in 0..=0x03FFu16 {
            let mask = PhaseMask(bits);
            for p in ALL_PHASES {
                let expected = bits & (1 << p.index()) != 0;
                assert_eq!(mask.has(p), expected, "bits={bits:#x} phase={p:?}");
            }
        }
    }
}
