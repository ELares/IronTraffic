// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for the filter vocabulary's hottest operation.
//!
//! `PhaseMask::has` is the first instruction of every phase dispatch: it runs
//! once per phase per stream, ten times per stream at most, and must cost
//! under 1 ns per call on the reference host so an unsubscribed phase is free.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_filter::{Phase, PhaseMask};

fn phase_mask_has(c: &mut Criterion) {
    let mask = PhaseMask::from_phases(&[Phase::RequestHeaders, Phase::ResponseHeaders]);
    let phase = Phase::RequestHeaders;
    c.bench_function("phase_mask/has", |b| {
        b.iter(|| black_box(mask).has(black_box(phase)));
    });
}

criterion_group!(benches, phase_mask_has);
criterion_main!(benches);
