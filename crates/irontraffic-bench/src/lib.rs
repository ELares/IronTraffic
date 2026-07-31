// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sans-IO vocabulary for the IronTraffic benchmark harness.
//!
//! This crate is a development tool, not a runtime dependency: it is
//! `publish = false` and nothing in `crates/irontraffic` may depend on it. It
//! holds the sans-IO logic the whole M17 benchmark harness is built from: the
//! cell model, the [`LatencyRecorder`] histogram wrapper, provenance capture,
//! and the absolute open-loop [`Schedule`] with its [`StallTracker`]
//! coordinated-omission detector, all defined here, and (added by later
//! issues in this milestone) the validity guards, the load-generator
//! adapters, the matrix and the report writer. `xtask`, created later, is a
//! thin binary that spawns processes and calls into this library; putting
//! the logic here rather than in `xtask` itself is what lets `cargo-fuzz`
//! and unit tests reach the parsers that consume untrusted output from
//! external load generators.
//!
//! The published benchmark matrix has eleven dimensions: protocol, TLS mode,
//! payload size, route table size, path corpus, connection count, upstream
//! count, filter chain depth, cache mode, keepalive mode and rate mode. A
//! [`BenchCell`] carries all eleven; [`CellId`] is the stable identifier that
//! doubles as the cell's result filename stem.
#![deny(missing_docs)]

mod cell;
mod error;
mod guards;
mod hist;
mod provenance;
mod result;
mod schedule;

pub use cell::{
    BenchCell, CacheMode, CellId, KeepaliveMode, PathCorpus, Protocol, RESERVED_STEMS, RateMode,
    TlsMode,
};
pub use error::{BenchError, Detail, MAX_DETAIL_BYTES};
pub use guards::{
    MAX_CLIENT_CPU_PCT, MAX_IQR_PERMILLE, MAX_ORIGIN_UTILISATION_PERMILLE, check_validity,
};
pub use hist::{
    HIGH_NS, LOW_NS, LatencyRecorder, MAX_HGRM_BYTES, MAX_HGRM_LINE_BYTES, MAX_HGRM_LINES,
    MAX_HGRM_TOTAL_COUNT, Percentiles, SIGNIFICANT_DIGITS, high_ns_ceiling,
};
pub use provenance::{
    BURSTABLE_PREFIXES, BuildStamp, CaptureInputs, CpuInfoFields, LARGE_FILE_CAP, MAX_CPU_ENTRIES,
    PROBE_OUTPUT_CAP, PROBE_TIMEOUT_SECONDS, Provenance, SMALL_FILE_CAP, StampSource, ToolStamp,
    capture_build_stamp, format_utc_date, is_burstable, normalize_instance_type, parse_cpuinfo,
    parse_meminfo, read_bounded, render_hardware, resolve_cpu_model,
};
pub use result::{
    Bottleneck, DeepestPercentile, InvariantId, MAX_COMMAND_LINE, RunResult, SuspectReason,
    Validity,
};
pub use schedule::{MAX_BURST_CAP, Release, Schedule, StallTracker};
