// SPDX-License-Identifier: MIT OR Apache-2.0
//! The published benchmark matrix's vocabulary: a stable cell id, the six
//! dimension enums and the `BenchCell` struct that carries all eleven
//! dimensions of one measured point.

use crate::error::BenchError;

/// Cell ids may have at most this many dot-separated segments.
const MAX_SEGMENTS: usize = 4;
/// Each segment may be at most this many bytes.
const MAX_SEGMENT_BYTES: usize = 64;
/// A cell id may be at most this many bytes in total.
const MAX_CELL_ID_BYTES: usize = 128;

/// Stable identifier for one point in the published benchmark matrix.
///
/// The string form is one to four dot-separated segments, each matching
/// `[a-z0-9_]{1,64}`, at most 128 bytes in total; for example `base` or
/// `payload.65536`. It is used verbatim as a result filename stem, so an empty
/// segment (which is what would allow `..`), a `/`, a `\`, or any byte outside
/// the class is rejected at construction.
///
/// A cell id is stable forever. Changing a cell's parameters requires a NEW id,
/// because a committed result file is only meaningful if the same id always
/// meant the same measurement.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct CellId(String);

impl CellId {
    /// Parses and validates a cell id.
    ///
    /// Runs in one pass over `s`'s bytes with no allocation until the input is
    /// known valid, so the cost of rejecting a hostile id is bounded by `s`'s
    /// length rather than by any later processing.
    ///
    /// # Errors
    /// Returns `BenchError::CellId` naming the exact rule violated.
    pub fn parse(s: &str) -> Result<Self, BenchError> {
        if s.is_empty() {
            return Err(BenchError::CellId("empty"));
        }
        if s.len() > MAX_CELL_ID_BYTES {
            return Err(BenchError::CellId("too long"));
        }

        let mut seg_len: usize = 0;
        let mut segs: usize = 1;
        for b in s.bytes() {
            if b == b'.' {
                if seg_len == 0 {
                    return Err(BenchError::CellId("empty segment"));
                }
                segs += 1;
                if segs > MAX_SEGMENTS {
                    return Err(BenchError::CellId("too many segments"));
                }
                seg_len = 0;
                continue;
            }
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
                return Err(BenchError::CellId("invalid character"));
            }
            seg_len += 1;
            if seg_len > MAX_SEGMENT_BYTES {
                return Err(BenchError::CellId("segment too long"));
            }
        }
        // A trailing dot leaves the last segment empty; the loop above only
        // catches an empty segment when it sees the DOT that follows it, so the
        // final segment needs its own check here.
        if seg_len == 0 {
            return Err(BenchError::CellId("empty segment"));
        }

        // A linear scan of a five element const array, not a hash lookup, and a
        // comparison against the WHOLE input rather than the first segment:
        // `manifest.h2` collides with nothing and must stay `Ok`.
        if segs == 1 && RESERVED_STEMS.contains(&s) {
            return Err(BenchError::CellId("reserved stem"));
        }

        Ok(Self(s.to_owned()))
    }

    /// The validated string form, safe to use as a filename stem.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CellId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::convert::TryFrom<String> for CellId {
    type Error = BenchError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<CellId> for String {
    fn from(value: CellId) -> Self {
        value.0
    }
}

/// Single-segment cell ids that would collide with a file the harness writes into
/// a run directory.
///
/// A new harness-written file MUST have its stem added here. An unlisted stem is
/// silently overwritable by a cell of the same name, and the overwrite succeeds,
/// so nothing reports it.
///
/// The list covers exactly the RUN directory (`bench/results/<utc-date>-<hw-id>/`).
/// A harness file written anywhere else needs no entry, because it can never
/// collide with a `<cell-id>.json`.
pub const RESERVED_STEMS: [&str; 5] = ["manifest", "index", "summary", "provenance", "readme"];

/// Downstream application protocol under test. Upstream is always HTTP/1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// HTTP/1.1.
    H1,
    /// HTTP/2.
    H2,
    /// HTTP/3.
    H3,
}

/// Downstream TLS configuration. `Off` is plaintext, not "whatever the tool defaults to".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Plaintext; no TLS handshake.
    Off,
    /// TLS with an ECDSA P-256 server certificate.
    EcdsaP256,
    /// TLS with an RSA-2048 server certificate.
    Rsa2048,
}

/// Which request paths the client draws from.
///
/// `SingleHot` exists only as a deliberately-labelled control: a benchmark that
/// sends one URL forever measures the L1 data cache and the branch predictor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCorpus {
    /// Every request targets the same one path.
    SingleHot,
    /// Requests draw uniformly at random from the route table.
    UniformRandom,
    /// Requests are chosen to defeat caching and prediction as hard as possible.
    AdversarialWorstCase,
}

/// Response cache behaviour for the cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// The cache is disabled.
    Bypass,
    /// Every request is a cache hit.
    AllHit,
    /// Every request is a cache miss.
    AllMiss,
    /// Half of requests are cache hits.
    HalfHit,
}

/// Connection reuse policy. Always reported, never defaulted.
///
/// `DownstreamClose` is the connection-setup-rate cell. `NoUpstreamPool` is the
/// cell that explains a mature proxy scoring an order of magnitude below its
/// peers because upstream pooling was off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeepaliveMode {
    /// Both the downstream and upstream connections are kept alive and reused.
    Both,
    /// The downstream connection is closed after every request.
    DownstreamClose,
    /// The upstream connection is not pooled; a new one is opened per request.
    NoUpstreamPool,
}

/// How the client paces requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateMode {
    /// Offer as much load as the client can generate. Throughput only.
    Saturate,
    /// Offer exactly this many requests per second, on an absolute schedule.
    Fixed(u64),
}

/// One point in the published benchmark matrix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BenchCell {
    /// Stable id and result filename stem.
    pub id: CellId,
    /// Downstream protocol.
    pub protocol: Protocol,
    /// Downstream TLS mode.
    pub tls: TlsMode,
    /// Response body size in bytes, exactly as the origin will emit it.
    pub payload_bytes: u32,
    /// Number of routes in the compiled route table.
    pub routes: u32,
    /// Which paths the client draws from.
    pub path_corpus: PathCorpus,
    /// Concurrent downstream connections.
    pub connections: u32,
    /// Number of distinct upstream endpoints behind the matched cluster.
    pub upstreams: u32,
    /// Number of configured filters in the chain.
    pub filter_depth: u8,
    /// Response cache behaviour.
    pub cache: CacheMode,
    /// Connection reuse policy.
    pub keepalive: KeepaliveMode,
    /// Pacing.
    pub rate: RateMode,
}

impl BenchCell {
    /// Validates the field combination.
    ///
    /// The checks run in this fixed order and the FIRST failure is returned, so a
    /// test can assert an exact message.
    ///
    /// # Errors
    /// `BenchError::Cell` carrying one of ten static strings: payload too large,
    /// zero or too many routes, zero or too many connections, zero or too many
    /// upstreams, filter depth too large, zero rate, or rate too high.
    pub fn validate(&self) -> Result<(), BenchError> {
        if self.payload_bytes > 16_777_216 {
            return Err(BenchError::Cell("payload too large"));
        }
        if self.routes == 0 {
            return Err(BenchError::Cell("zero routes"));
        }
        if self.routes > 1_000_000 {
            return Err(BenchError::Cell("too many routes"));
        }
        if self.connections == 0 {
            return Err(BenchError::Cell("zero connections"));
        }
        if self.connections > 2_000_000 {
            return Err(BenchError::Cell("too many connections"));
        }
        if self.upstreams == 0 {
            return Err(BenchError::Cell("zero upstreams"));
        }
        if self.upstreams > 4_096 {
            return Err(BenchError::Cell("too many upstreams"));
        }
        if self.filter_depth > 64 {
            return Err(BenchError::Cell("filter depth too large"));
        }
        if let RateMode::Fixed(r) = self.rate {
            if r == 0 {
                return Err(BenchError::Cell("zero rate"));
            }
            if r > 50_000_000 {
                return Err(BenchError::Cell("rate too high"));
            }
        }
        Ok(())
    }
}
