// SPDX-License-Identifier: MIT OR Apache-2.0
//! HTTP/1.x wire-level parsing.
//!
//! [`parser`] holds the whole surface: `H1Parser`, the single sans-IO head
//! parser used for both requests and responses, and [`parser::HeadScanBudget`],
//! the caller-owned counter that bounds the CPU cost of a head delivered a few
//! bytes at a time. See `parser`'s own module documentation for the design
//! rationale.

pub mod parser;

pub use parser::{H1Parser, HeadScanBudget, RawField, RawHead, RawResponseHead, Span};
