// SPDX-License-Identifier: MIT OR Apache-2.0
//! The sans-IO seam every external load generator plugs into.
//!
//! An adapter turns a [`BenchCell`] plus a [`Target`] into an [`Invocation`]
//! (program, arguments, environment) and turns a spawned tool's captured
//! output bytes into a [`RawRun`]. It never spawns a process itself: the
//! caller spawns, the caller captures, the caller decides what to do with a
//! non-zero exit status. That split (plan, then parse, rather than a single
//! `run`) is deliberate and applies to every adapter this crate ever gains,
//! not only [`Oha`]: a `run` method would require a live external binary to
//! test anything at all, which would make every adapter untestable in CI on
//! a machine without Docker, and would make the output parser unfuzzable,
//! because it would not be reachable without a real process producing the
//! bytes it parses. With plan and parse, argument construction is testable
//! against a checked-in expected command line, and the parser is testable
//! against checked-in fixtures and fuzzable with arbitrary bytes.
//!
//! # Untrusted input
//!
//! [`LoadGenerator::parse`] is the untrusted-input boundary of this crate:
//! its `stdout` and `stderr` are the captured output of a SEPARATE process,
//! which may be a wrong version, a crashed build, or a binary that is not
//! the expected tool at all. Both byte slices MUST be capped by the caller
//! before they ever reach this trait: [`MAX_TOOL_OUTPUT_BYTES`] for stdout
//! and [`MAX_TOOL_STDERR_BYTES`] for stderr. A bound enforced only after the
//! bytes have already been captured into memory is not a bound; the caller
//! must stop CAPTURING at those sizes, not merely refuse to parse past them.
//! Every adapter's own `parse` additionally re-checks both lengths on the
//! slices it is handed, before any deserialisation or scanning, so a caller
//! that forgets its own cap still cannot make this crate allocate or scan an
//! unbounded amount of memory.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::cell::BenchCell;
use crate::cell::Protocol;
use crate::error::BenchError;
use crate::hist::LatencyRecorder;
use crate::provenance::ToolStamp;

mod h2load;
mod nighthawk;
mod oha;
mod vegeta;
pub use h2load::{H2Load, MAX_H2LOAD_LINE_BYTES, MAX_H2LOAD_LINES, MAX_H2LOAD_OUTPUT_BYTES};
pub use nighthawk::{
    ContainerRuntime, MAX_COUNTERS, MAX_DURATION_SECONDS, MAX_PERCENTILE_ENTRIES,
    MAX_RESULT_ENTRIES, MAX_STATISTICS, MIN_PERCENTILE_ENTRIES, Nighthawk,
};
pub use oha::Oha;
pub use vegeta::{
    CROSS_CHECK_TOLERANCE_PERMILLE, CrossCheck, MAX_VEGETA_WORKERS, NotComparableReason, Vegeta,
    cross_check,
};

/// Largest tool stdout the parser will accept. Checked on the slice length
/// before any deserialisation.
pub const MAX_TOOL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Largest tool stderr the parser will accept. Checked on the slice length
/// before it is scanned for warning substrings.
pub const MAX_TOOL_STDERR_BYTES: usize = 1024 * 1024;

/// Largest version-probe stdout the parser will accept.
pub const MAX_VERSION_OUTPUT_BYTES: usize = 4096;

/// Largest request count a tool may report. A run above this is a corrupt or
/// hostile output, not a measurement: the count feeds `record_n_ns` during
/// latency reconstruction.
pub const MAX_REPORTED_REQUESTS: u64 = 1_000_000_000_000;

/// Largest `path_expr` the planner will accept, in bytes.
pub const MAX_PATH_EXPR_BYTES: usize = 4096;

/// Largest `host` or `sni` the planner will accept, in bytes.
pub const MAX_HOST_BYTES: usize = 253;

/// Where the client should send traffic.
#[derive(Debug, Clone)]
pub struct Target {
    /// `http` or `https`.
    pub scheme: Scheme,
    /// Host name to put in the request, which may not be the connect address.
    pub host: String,
    /// Address actually connected to.
    pub connect: SocketAddr,
    /// SNI name, when TLS is on and it differs from `host`.
    pub sni: Option<String>,
    /// Either a literal path or a path-generating regex, per `PathCorpus`.
    pub path_expr: String,
}

/// Request scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plaintext.
    Http,
    /// TLS.
    Https,
}

/// Run-level parameters that are not cell dimensions.
///
/// This is the ADAPTER's parameter type and it is the only one `plan` sees.
/// `{{bench-runner-and-repetition}}` later declares a separate, larger
/// `RunParamsFull` carrying core assignments, binary paths and a work
/// directory; the two are different types with different fields and neither
/// replaces the other. That issue states exactly how it builds a
/// `RunParams` from a `RunParamsFull` for each invocation, including the
/// separate warmup invocation.
#[derive(Debug, Clone, Copy)]
pub struct RunParams {
    /// Measured seconds, excluding warmup.
    pub duration_secs: u32,
    /// Discarded warmup seconds.
    pub warmup_secs: u32,
    /// Client worker threads, or `None` for the tool's default.
    pub concurrency: Option<u16>,
}

/// A fully determined external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Program name or path.
    pub program: String,
    /// Arguments, in the fixed order the adapter defines.
    pub args: Vec<String>,
    /// Environment overrides, sorted by key so the rendering is stable.
    pub env: Vec<(String, String)>,
}

/// A token matching this class is rendered bare by [`Invocation::command_line`];
/// anything else is single-quoted.
fn is_bare_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"_./:=@%+-".contains(&b)
}

/// Quotes a single argument token per [`Invocation::command_line`]'s rule.
fn quote_token(token: &str) -> String {
    if !token.is_empty() && token.bytes().all(is_bare_token_char) {
        return token.to_owned();
    }
    let mut out = String::with_capacity(token.len() + 2);
    out.push('\'');
    for ch in token.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

impl Invocation {
    /// Renders a shell-quoted, byte-for-byte reproducible command line.
    ///
    /// A token matching `[A-Za-z0-9_./:=@%+-]+` is emitted bare; anything
    /// else is single-quoted with embedded quotes escaped as `'\''`. Only
    /// `program` and `args` are rendered, in that order, space separated;
    /// `env` is metadata recorded alongside the invocation, not part of the
    /// literal command line invariant I12 compares byte for byte.
    #[must_use]
    pub fn command_line(&self) -> String {
        let mut out = String::new();
        out.push_str(&quote_token(&self.program));
        for arg in &self.args {
            out.push(' ');
            out.push_str(&quote_token(arg));
        }
        out
    }
}

/// Why an adapter cannot measure a cell.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    /// The tool does not speak this protocol.
    #[error("{tool} does not support {protocol:?}")]
    Protocol {
        /// Adapter name.
        tool: &'static str,
        /// The unsupported protocol.
        protocol: Protocol,
    },
    /// The tool cannot produce trustworthy latency for this rate mode.
    ///
    /// `detail` carries the ADAPTER-SPECIFIC reason, because "cannot measure
    /// this rate mode" means something different for every tool that
    /// refuses one: `Oha` refuses `RateMode::Saturate` because its client
    /// queueing dominates the number; `H2Load` refuses `RateMode::Fixed`
    /// because its `--rate` flag means connections per period, not requests
    /// per period, an unrelated and more dangerous fact a shared, generic
    /// message would not convey. Added by `bench-loadgen-h2load-and-vegeta-crosscheck`
    /// (#413): `Oha::supports`'s own call site now passes its original fixed
    /// wording as `detail` verbatim, so nothing about its behaviour changed.
    #[error("{tool}: {detail}")]
    RateMode {
        /// Adapter name.
        tool: &'static str,
        /// Why, specific to the adapter and the rate mode it refused.
        detail: &'static str,
    },
    /// The tool cannot reach this connection count.
    #[error("{tool} cannot drive {connections} connections")]
    Connections {
        /// Adapter name.
        tool: &'static str,
        /// The requested connection count.
        connections: u32,
    },
}

/// One tool run's raw output, before validity checking.
#[derive(Debug)]
pub struct RawRun {
    /// Which tool produced this, and its version.
    pub tool: ToolStamp,
    /// The exact command line, for `RunResult::command_line`.
    pub command_line: String,
    /// Requests the tool issued.
    pub requests_sent: u64,
    /// Responses with status 200.
    pub responses_ok: u64,
    /// Transport-level errors the tool reported.
    pub errors: u64,
    /// Full status distribution.
    pub status_counts: BTreeMap<u16, u64>,
    /// Response bytes received.
    pub bytes_received: u64,
    /// Measured wall duration in nanoseconds.
    pub duration_ns: u64,
    /// Total latency.
    pub latency: LatencyRecorder,
    /// Time to first byte, when the tool reports it.
    pub ttfb: Option<LatencyRecorder>,
    /// Connection establishment, when the tool reports it separately.
    pub connect: Option<LatencyRecorder>,
    /// The coordinated-omission indicator, when the tool reports it.
    pub stall: Option<LatencyRecorder>,
    /// Samples above the histogram maximum.
    pub out_of_range: u64,
    /// False when `latency` was reconstructed from reported percentiles
    /// rather than from a full histogram. Only Nighthawk sets this true.
    pub latency_exact: bool,
    /// False when the tool's loop model makes its latency uninterpretable
    /// for this cell, for example oha in saturate mode.
    pub latency_trustworthy: bool,
}

/// What `parse` needs that the tool's output does not contain.
#[derive(Debug, Clone, Copy)]
pub struct ParseCtx<'a> {
    /// The cell that was measured. `cell.rate` decides `latency_trustworthy`.
    pub cell: &'a BenchCell,
    /// The invocation that was actually spawned. `RawRun::command_line` is
    /// `invocation.command_line()`.
    pub invocation: &'a Invocation,
    /// The stamp from the version probe. Becomes `RawRun::tool`.
    pub tool: &'a ToolStamp,
}

/// The seam every external load generator plugs into.
///
/// Every method is pure. Adapters build command lines and parse output; they
/// never spawn a process, so every adapter is testable against checked-in
/// fixtures and every parser is fuzzable.
pub trait LoadGenerator: Send + Sync {
    /// Adapter name, used in error messages and in `ToolStamp`.
    fn name(&self) -> &'static str;

    /// How to ask the tool for its version.
    fn version_invocation(&self) -> Invocation;

    /// Parses the version probe's output.
    ///
    /// # Errors
    /// `BenchError::Parse` when no version can be extracted.
    fn parse_version(&self, stdout: &[u8]) -> Result<ToolStamp, BenchError>;

    /// Whether this adapter can measure this cell.
    ///
    /// # Errors
    /// `Unsupported` naming the specific dimension that is out of reach.
    fn supports(&self, cell: &BenchCell) -> Result<(), Unsupported>;

    /// Builds the exact command for this cell. Deterministic.
    ///
    /// # Errors
    /// `BenchError::Cell` when the cell is unsupported or a field is out of
    /// range.
    fn plan(
        &self,
        cell: &BenchCell,
        target: &Target,
        run: &RunParams,
    ) -> Result<Invocation, BenchError>;

    /// Parses captured output. `stderr` is included because tools warn there
    /// about unachievable rates, which changes what the numbers mean.
    ///
    /// `ctx` supplies the three `RawRun` fields the output does not contain:
    /// the tool stamp, the command line, and the cell whose `RateMode`
    /// decides `latency_trustworthy`.
    ///
    /// # Errors
    /// `BenchError::Parse` naming the missing or malformed field.
    fn parse(&self, ctx: &ParseCtx<'_>, stdout: &[u8], stderr: &[u8])
    -> Result<RawRun, BenchError>;
}
