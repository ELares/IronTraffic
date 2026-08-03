// SPDX-License-Identifier: MIT OR Apache-2.0
//! HTTP/2 and HTTP/3 header-block assembly: the decoded-field-list parse
//! boundary.
//!
//! [`head`] holds the whole surface: `MplexHeadBuilder`, `MplexTrailerBuilder`,
//! `MplexResponseBuilder` and `MplexContext`. See its own module documentation
//! for the design rationale.

pub mod body;
pub mod head;

pub use head::{MplexContext, MplexHeadBuilder, MplexResponseBuilder, MplexTrailerBuilder};
