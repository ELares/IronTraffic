// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for CRL parsing and revocation lookup.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_parse(c: &mut Criterion) {}

fn bench_lookup(c: &mut Criterion) {}

fn bench_build(c: &mut Criterion) {}

criterion_group!(benches, bench_parse, bench_lookup, bench_build);
criterion_main!(benches);
