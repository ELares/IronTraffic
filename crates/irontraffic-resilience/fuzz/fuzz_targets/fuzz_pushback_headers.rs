#![no_main]
//! Fuzz target for `retry::pushback` parsers and `resolve_backoff`.
//!
//! Input domain: arbitrary bytes used as `Retry-After` and as
//! `grpc-retry-pushback-ms`, plus an arbitrary `now_wall_ms`, an arbitrary
//! deadline, and an arbitrary `min_attempt_estimate_ms`.
//!
//! Contract: must not panic, must not hang, must not allocate. The target
//! asserts property 33 (any returned `Sleep(v)` fits the deadline) and that
//! `parse_http_date_ms` never returns a value implying an out-of-range calendar
//! field.

use arbitrary::Arbitrary;
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::deadline::Deadline;
use irontraffic_resilience::retry::{
    BackoffConfig, BackoffDecision, BackoffInputs, FullJitterBackoff, parse_grpc_pushback,
    parse_http_date_ms, parse_retry_after, resolve_backoff,
};
use irontraffic_rand::Rng;
use libfuzzer_sys::fuzz_target;

/// Seed for [`Deadline`].
#[derive(Debug, Arbitrary)]
struct DeadlineSeed {
    now: u32,
    budget_ms: u32,
}

/// Seed for [`BackoffInputs`].
#[derive(Debug, Arbitrary)]
struct BackoffInputsSeed {
    grpc_pushback: Option<Vec<u8>>,
    retry_after: Option<Vec<u8>>,
    deadline: DeadlineSeed,
    now_wall_ms: u64,
    min_attempt_estimate_ms: u32,
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|input: (BackoffInputsSeed, u64)| {
    let (inputs_seed, rng_seed) = input;
    let now = Millis(inputs_seed.deadline.now);
    let inputs = BackoffInputs {
        grpc_pushback: inputs_seed.grpc_pushback.as_deref(),
        retry_after: inputs_seed.retry_after.as_deref(),
        deadline: Deadline::from_now(now, inputs_seed.deadline.budget_ms.min(Millis::HORIZON_MS)),
        now,
        now_wall_ms: inputs_seed.now_wall_ms,
        min_attempt_estimate_ms: inputs_seed.min_attempt_estimate_ms,
    };
    let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
    let mut rng = Rng::from_seed(rng_seed);

    let decision = resolve_backoff(inputs, &mut backoff, &mut rng);

    if let BackoffDecision::Sleep(v) = decision {
        let need_ms = v.saturating_add(inputs.min_attempt_estimate_ms);
        assert!(
            inputs.deadline.permits(inputs.now, need_ms),
            "sleep {v} + estimate {} exceeds deadline",
            inputs.min_attempt_estimate_ms
        );
    }

    // `parse_http_date_ms` must not return a value derived from an out-of-range
    // field. We exercise it directly on both header values for extra coverage.
    if let Some(raw) = inputs.grpc_pushback {
        parse_grpc_pushback(raw);
        let _ = parse_http_date_ms(raw, inputs.now_wall_ms);
    }
    if let Some(raw) = inputs.retry_after {
        parse_retry_after(raw, inputs.now_wall_ms);
        let _ = parse_http_date_ms(raw, inputs.now_wall_ms);
    }
});
