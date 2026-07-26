#![no_main]
//! Fuzz target for `deadline::establish`, `deadline::headers::emit_grpc_timeout`, and
//! `deadline::headers::emit_expected_rq_timeout_ms`.
//!
//! Input domain: `FuzzInput` derives `Arbitrary`, so libFuzzer's bytes are split into up
//! to three optional inbound header values (`grpc_timeout`, `expected_rq_timeout_ms`,
//! `upstream_rq_timeout_ms`), plus an arbitrary `route_timeout_ms`, `trusted_internal`
//! bool, and `now`. The default `DeadlineConfig` is used throughout, so its clamp is
//! fixed at `[1, 60_000]`.
//!
//! Contract: `establish` must not panic, must not hang, and must not allocate; its
//! returned budget always lies in `[min_timeout_ms, max_timeout_ms]`, and, when
//! `trusted_internal` is false and the source is not `RouteDefault`, the budget is
//! additionally at most `max(route_timeout_ms, min_timeout_ms)`. `emit_grpc_timeout` and
//! `emit_expected_rq_timeout_ms` must not panic and must return a length within their
//! buffers, and the expected-timeout emission is never zero.

use arbitrary::Arbitrary;
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::deadline::headers::{emit_expected_rq_timeout_ms, emit_grpc_timeout};
use irontraffic_resilience::deadline::{DeadlineConfig, InboundTimeouts, TimeoutSource, establish};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    grpc_timeout: Option<Vec<u8>>,
    expected_rq_timeout_ms: Option<Vec<u8>>,
    upstream_rq_timeout_ms: Option<Vec<u8>>,
    route_timeout_ms: u32,
    trusted_internal: bool,
    now: u32,
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|input: FuzzInput| {
    let cfg = DeadlineConfig::default();
    let inbound = InboundTimeouts {
        grpc_timeout: input.grpc_timeout.as_deref(),
        expected_rq_timeout_ms: input.expected_rq_timeout_ms.as_deref(),
        upstream_rq_timeout_ms: input.upstream_rq_timeout_ms.as_deref(),
    };

    let (deadline, source, budget) = establish(
        Millis(input.now),
        inbound,
        input.route_timeout_ms,
        input.trusted_internal,
        &cfg,
    );

    assert!(budget >= cfg.min_timeout_ms);
    assert!(budget <= cfg.max_timeout_ms);
    if !input.trusted_internal && source != TimeoutSource::RouteDefault {
        assert!(budget <= input.route_timeout_ms.max(cfg.min_timeout_ms));
    }
    assert_eq!(deadline.remaining_ms(Millis(input.now)), budget);

    let mut grpc_buf = [0u8; 12];
    let grpc_len = emit_grpc_timeout(budget, &mut grpc_buf);
    assert!(grpc_len > 0 && grpc_len <= grpc_buf.len());

    let mut expected_buf = [0u8; 10];
    let expected_len = emit_expected_rq_timeout_ms(budget, budget, &mut expected_buf);
    assert!(expected_len > 0 && expected_len <= expected_buf.len());
    assert_ne!(&expected_buf[..expected_len], b"0");
});
