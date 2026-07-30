// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded, terminal-safe error payloads and the harness's error enum.
//!
//! Two `BenchError` variants carry bytes that were not written by us: a load
//! generator's stdout or stderr, and an operator-supplied `--out` path. Both
//! end up on a terminal and in a run log, so both are clipped to a small,
//! fixed size and sanitised to printable ASCII before they can be built at
//! all. `Detail` is what makes that unbypassable: its inner `String` is
//! private, and `Detail::new` is its only constructor.

/// Longest error payload the harness will carry, in bytes.
pub const MAX_DETAIL_BYTES: usize = 256;

/// A bounded, terminal-safe error payload.
///
/// The inner `String` is private and `new` is the only constructor, because the
/// two `BenchError` variants that carry one are built from an external tool's
/// stdout or from an operator-supplied path. Both are printed to a terminal and
/// written into a run log: an unbounded payload is a memory denial of service on
/// the harness, and one carrying `\x1b[`, `\r` or `\n` rewrites the operator's
/// terminal or forges log lines around the real error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail(String);

/// Walks `end` back from `max_bytes` while the byte there is a UTF-8
/// continuation byte (`0b10xx_xxxx`), so the returned index is always a char
/// boundary at or below `max_bytes`. At most three steps, because a UTF-8
/// character is at most four bytes long.
fn floor_char_boundary(bytes: &[u8], max_bytes: usize) -> usize {
    let mut end = max_bytes;
    while end > 0 {
        let is_continuation = bytes
            .get(end)
            .is_some_and(|b| b & 0b1100_0000 == 0b1000_0000);
        if !is_continuation {
            break;
        }
        end -= 1;
    }
    end
}

impl Detail {
    /// Clips to at most `MAX_DETAIL_BYTES` at a character boundary, then replaces
    /// every byte outside `0x20..=0x7E` with `?`.
    ///
    /// Cost is O(1) in `s.len()`: at most 256 bytes are ever examined, so passing
    /// a two gigabyte tool stdout costs the same as passing a word.
    #[must_use]
    pub fn new(s: &str) -> Self {
        // Clip FIRST, on the raw byte length, before touching a single byte for
        // sanitising. Sanitising an unbounded input first and clipping the
        // result second would still be correct, but would cost O(n) in the
        // length of a hostile input rather than O(1); see the module docs.
        let clipped = if s.len() <= MAX_DETAIL_BYTES {
            s
        } else {
            let end = floor_char_boundary(s.as_bytes(), MAX_DETAIL_BYTES);
            s.get(..end).unwrap_or("")
        };

        let mut out = String::with_capacity(clipped.len());
        for b in clipped.bytes() {
            let printable = (0x20..=0x7E).contains(&b);
            // A byte-for-byte replacement, never a deletion: deleting `\x1b`
            // from `\x1b[2J` would leave the harmless `[2J`, but deleting a
            // byte out of a UTF-8 sequence can synthesise a different valid
            // character. `char::from(u8)` is infallible for every byte value.
            out.push(char::from(if printable { b } else { b'?' }));
        }
        Self(out)
    }

    /// The clipped, sanitised text. Always at most `MAX_DETAIL_BYTES` bytes and
    /// always printable ASCII.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Detail {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Every failure the benchmark harness can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BenchError {
    /// A cell id violated the character, segment, length or reserved-stem rules.
    #[error("invalid cell id: {0}")]
    CellId(&'static str),
    /// A cell's field combination is not measurable.
    #[error("invalid bench cell: {0}")]
    Cell(&'static str),
    /// Reading or writing a harness file failed.
    ///
    /// This variant's shape is defined here, but `BenchError::io` below is the
    /// only place in this crate that ever builds one: `path` reaches this
    /// struct literal only as `Detail::new(...)`'s return value.
    ///
    /// `source` is a bare `std::io::Error`, not a `Detail`, because `#[source]`
    /// is what lets a caller walk the error chain with `std::error::Error::source`,
    /// and `Detail` is not `std::error::Error`. That means `source`'s own
    /// `Display` is NOT sanitised by construction the way `path` is, so the
    /// format string below routes it through `Detail::new` at render time
    /// instead: see #776 finding 4, where the derived `{source}` form printed
    /// an `std::io::Error` built from foreign bytes (for example a load
    /// generator's stderr wrapped in `std::io::Error::other`) unsanitised,
    /// defeating this variant's own terminal-safety guarantee.
    #[error("benchmark io at {path}: {}", Detail::new(&source.to_string()))]
    Io {
        /// The path being read or written, clipped and sanitised.
        path: Detail,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Output from an external tool could not be parsed.
    ///
    /// This variant's shape is defined here, but `BenchError::parse` below is
    /// the only place in this crate that ever builds one: `detail` reaches
    /// this struct literal only as `Detail::new(...)`'s return value.
    #[error("parsing {tool} output: {detail}")]
    Parse {
        /// The tool whose output failed to parse. A `&'static str` chosen by us,
        /// never a name taken from the tool's own output.
        tool: &'static str,
        /// What was wrong, clipped and sanitised.
        detail: Detail,
    },
}

impl BenchError {
    /// Builds [`BenchError::Io`], clipping and sanitising `path` through
    /// [`Detail::new`]. The only way to construct this variant.
    #[must_use]
    #[rustfmt::skip]
    pub fn io(path: &str, source: std::io::Error) -> Self {
        Self::Io { path: Detail::new(path), source }
    }

    /// Builds [`BenchError::Parse`], clipping and sanitising `detail` through
    /// [`Detail::new`]. The only way to construct this variant.
    #[must_use]
    #[rustfmt::skip]
    pub fn parse(tool: &'static str, detail: &str) -> Self {
        Self::Parse { tool, detail: Detail::new(detail) }
    }
}
