// SPDX-License-Identifier: MIT OR Apache-2.0

//! `RequestView`, the borrowed input to a route match.

use crate::ids::{CertId, ListenerId, MethodMask};

/// A borrowed, read-only view of one request head in the form the router needs it.
///
/// The caller has already done all normalization. Specifically:
/// - `path` is the normalized path with the query string and any fragment removed,
///   it starts with `b'/'`, and it is at most `MAX_PATH_BYTES` long.
/// - `query` is the raw query string with no leading `?`, empty when absent.
/// - `authority` is the raw `Host` or `:authority` value: NOT lowercased, port NOT
///   stripped. It is carried for tracing and diagnostics only. Matching reads the
///   NORMALIZED authority the caller passed to `MatchScratch::set_host` (defined by
///   `match-scratch-per-worker` (#58)), which it produced with this crate's
///   `normalize_authority` (defined by `authority-normalization` (#50)), so build and
///   match use one byte-identical function and the router never normalizes twice.
/// - `head` is the single contiguous buffer that every header value in this request
///   is a slice of. Header values are addressed as `(offset, len)` pairs into it,
///   which is how the router avoids storing borrowed slices or raw pointers in
///   per-worker scratch.
/// - `method` has exactly one bit set. A mask with two bits would satisfy a method
///   predicate naming either of them, which is a method-restriction bypass, so this
///   is a security contract on the caller and not a convention: **the data-plane
///   seam that builds a `RequestView` MUST set exactly one bit**, which its ten-arm
///   match over the parsed method enum does by construction. A `RequestView` whose
///   mask carries zero bits (`MethodMask::NONE`) is treated as matching no method
///   predicate rather than panicking.
#[derive(Copy, Clone, Debug)]
pub struct RequestView<'a> {
    /// Raw authority. Not lowercased, port not stripped.
    pub authority: &'a [u8],
    /// Normalized path, query and fragment already removed.
    pub path: &'a [u8],
    /// Raw query string without the leading `?`.
    pub query: &'a [u8],
    /// Exactly one method bit.
    pub method: MethodMask,
    /// The contiguous head buffer that header value offsets index into.
    pub head: &'a [u8],
    /// The listener this connection was accepted on.
    pub listener: ListenerId,
    /// TLS SNI from the `ClientHello`, already ASCII lowercased, or `None` on plaintext.
    pub sni: Option<&'a [u8]>,
    /// The certificate this connection negotiated, or `CertId::NONE` on plaintext.
    pub cert: CertId,
}
