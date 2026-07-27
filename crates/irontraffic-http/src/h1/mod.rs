// SPDX-License-Identifier: MIT OR Apache-2.0
//! HTTP/1.x wire-level parsing.
//!
//! [`parser`] holds the whole surface: `H1Parser`, the single sans-IO head
//! parser used for both requests and responses, and [`parser::HeadScanBudget`],
//! the caller-owned counter that bounds the CPU cost of a head delivered a few
//! bytes at a time. See `parser`'s own module documentation for the design
//! rationale.
//!
//! [`chunked`] holds `ChunkedDecoder`, the resumable HTTP/1 chunked-transfer-
//! coding decoder and trailer deny-list. Unlike [`parser`] it keeps state
//! across calls; see its own module documentation for why.

pub mod canonicalize;
pub mod chunked;
pub mod parser;

pub use parser::{H1Parser, HeadScanBudget, RawField, RawHead, RawResponseHead, Span};
