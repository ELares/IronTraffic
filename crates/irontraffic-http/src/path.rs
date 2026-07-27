// SPDX-License-Identifier: MIT OR Apache-2.0
//! Request path normalization: [`NormalizedPath`], [`RawQuery`] and [`PathPolicy`].
//!
//! **Invariant P1.** There is exactly one path value in the system. Routing predicates,
//! authorization policy, logging, cache keys, and the bytes written upstream are all
//! derived from the same [`NormalizedPath`]. No component may access the raw request
//! target after [`NormalizedPath::parse_into`] returns; this module has no such
//! accessor and never will (see [`NormalizedPath`]'s own doc comment).
//!
//! [`NormalizedPath::parse_into`] runs one fixed nine-step pipeline, exactly once per
//! request, with no per-step toggles. The order of the steps is itself a security
//! property (see `docs/THREAT-MODEL.md` section 5, "Request target"), so nothing here
//! makes the steps independently configurable or reorderable. The two policy enums,
//! [`EncodedDot`] and [`EncodedSlash`], each have exactly two values, `Reject` and
//! `Keep`; there is deliberately no `Decode` option for either, because decoding a
//! path separator or a dot segment after routing has already happened is exactly the
//! class of bug this module exists to prevent (see each enum's own doc comment for the
//! specific CVE it corresponds to).
//!
//! The pipeline is shrink-only and runs in place over one caller-supplied `BytesMut`:
//! every step from percent-decoding onward writes at an offset less than or equal to
//! its read offset, so normalizing costs one allocation (the initial reservation) and
//! zero copies beyond that, not one allocation per step.

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::error::RejectReason;
use crate::limits::ClampedLimits;
use crate::scalar::Method;

/// A request path that has been through the full normalization pipeline exactly once.
///
/// This is the ONLY path value in IronTraffic. Routing predicates, authorization
/// policy, log records, cache keys and the bytes written upstream all derive from
/// [`NormalizedPath::as_bytes`]. There is no accessor for the raw request target, and
/// adding one is the bug this type exists to prevent: see the four independent
/// gateway advisories cited in this issue's design notes, every one of which came
/// from a second path representation reaching policy or logging code.
///
/// # Hashing
/// `NormalizedPath` derives [`core::hash::Hash`], and the whole point of the type is
/// that it becomes a cache key and a routing key. Every map keyed by it MUST use a
/// keyed, per-process-randomized hasher (`std`'s default `RandomState`, or an
/// explicitly seeded construction). A fixed-seed fast hasher (`FxHash`, `ahash` with a
/// constant key, `fnv`) turns a path-keyed map into an algorithmic-complexity target:
/// the attacker knows the source, computes colliding paths offline, and drives every
/// lookup into one bucket. This requirement travels with the type rather than living
/// in whichever milestone builds the first map.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NormalizedPath {
    buf: Bytes,
}

/// The query string, byte-for-byte as received, never decoded and never normalized.
///
/// `None` at the request level means there was no `?` at all; a present but empty
/// `RawQuery` means `?` was present with nothing after it. Those are different
/// requests and the distinction is preserved on egress.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RawQuery {
    buf: Bytes,
}

/// How to treat a percent-encoded `.` in a path segment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncodedDot {
    /// 400 for any segment that percent-decodes to `.` or `..`. The default.
    Reject,
    /// Leave it encoded. It does not traverse HERE.
    ///
    /// Residual risk, which is why `Reject` is the default: we forward `%2E%2E` to the
    /// origin, and an origin that percent-decodes before resolving dot segments turns
    /// `/api/%2E%2E/admin` into `/admin`. We would have routed and authorized
    /// `/api/%2E%2E/admin`. That is a two-parser divergence we cannot see from here,
    /// and selecting `Keep` is an assertion by the operator that the origin does not
    /// do it.
    Keep,
}

/// How to treat a percent-encoded `/` or `\` in a path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncodedSlash {
    /// 400 for any path containing `%2F`, `%2f`, `%5C` or `%5c`. The default.
    Reject,
    /// Leave it encoded, end to end. The origin sees the same bytes we routed on.
    ///
    /// Residual risk, which is why `Reject` is the default: "the same bytes" is not
    /// "the same meaning". An origin that decodes `%2F` to `/` before its own path
    /// resolution reads `/api/..%2Fadmin` as `/api/../admin` and serves `/admin`,
    /// while we routed and authorized a single segment `..%2Fadmin`. Object-storage
    /// keys and git refs are the real workloads that need `Keep`, and enabling it is
    /// an assertion by the operator that the origin treats `%2F` as data.
    Keep,
}

/// The complete path policy. Three knobs, no ordering, no `Decode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PathPolicy {
    /// How to treat a percent-encoded `.` in a path segment.
    pub encoded_dot: EncodedDot,
    /// How to treat a percent-encoded `/` or `\` in a path.
    pub encoded_slash: EncodedSlash,
    /// Collapse runs of `/` into one. Default false. When true it runs at step 9,
    /// before routing, and the merged form is what goes upstream.
    pub merge_slashes: bool,
}

impl PathPolicy {
    /// `encoded_dot: Reject`, `encoded_slash: Reject`, `merge_slashes: false`.
    pub const DEFAULT: PathPolicy = PathPolicy {
        encoded_dot: EncodedDot::Reject,
        encoded_slash: EncodedSlash::Reject,
        merge_slashes: false,
    };
}

/// Which form of request target was received.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TargetForm {
    /// `/path?query`. The normal case.
    Origin,
    /// `*`. Only legal with `OPTIONS`.
    Asterisk,
    /// `http://host/path`. Only accepted on a listener configured as a forward proxy.
    Absolute,
    /// `host:port`. Only legal with `CONNECT`.
    Authority,
}

/// True for the bytes permitted, unencoded, in a request target's path component:
/// RFC 3986 Section 3.3 `pchar / "/"`, where `pchar` is
/// `unreserved / pct-encoded / sub-delims / ":" / "@"`. `pct-encoded` is handled by
/// its own `%` branch in the caller, not by this table.
const fn is_path_byte_ok(b: u8) -> bool {
    matches!(
        b,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@'
            | b'/'
    )
}

/// True for the RFC 3986 Section 2.3 unreserved set MINUS `.`: `ALPHA / DIGIT / "-" /
/// "_" / "~"`. `.` is deliberately excluded even though it is unreserved: decoding it
/// at this step would turn `%2e%2e` into a literal `..` before dot-segment removal
/// runs, making the `encoded_dot` policy dead code. See the module doc and step 4 of
/// [`NormalizedPath::parse_into`].
const fn is_unreserved_minus_dot(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~')
}

/// The value of one hex digit, or 0 for a non-hex byte.
///
/// Every caller of this function has already proven `b.is_ascii_hexdigit()` via
/// `validate_path_syntax`'s step-2 pass, which runs to completion over the whole path
/// before any decoding starts; the `_ => 0` arm is therefore unreachable in practice,
/// not merely convenient, and exists only so this stays a total function instead of
/// one that could panic on attacker bytes.
const fn hex_digit_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b.saturating_sub(b'0'),
        b'a'..=b'f' => b.saturating_sub(b'a').saturating_add(10),
        b'A'..=b'F' => b.saturating_sub(b'A').saturating_add(10),
        _ => 0,
    }
}

/// Combines two proven hex digits into the byte they encode.
const fn hex_pair_value(hi: u8, lo: u8) -> u8 {
    hex_digit_value(hi)
        .saturating_mul(16)
        .saturating_add(hex_digit_value(lo))
}

/// Step 2: every byte of `path` must be either in `pchar / "/"` or the start of a
/// syntactically valid percent escape (two hex digits following `%`). Does not decode
/// anything; `decode_path_into` does that in a second pass once this one has proven
/// the whole path is structurally sound, matching the issue's own ordering: the nul
/// check (step 3) must never fire on a byte at a position step 2 has not yet reached.
///
/// # Errors
/// `PathInvalidByte`, `PathPercentTruncated`, `PathPercentInvalidHex`.
fn validate_path_syntax(path: &[u8]) -> Result<(), RejectReason> {
    let mut i = 0usize;
    while i < path.len() {
        let b = *path.get(i).unwrap_or(&0); // i < path.len() by the loop guard
        if b == b'%' {
            let h1 = path.get(i.saturating_add(1));
            let h2 = path.get(i.saturating_add(2));
            match (h1, h2) {
                (Some(&a), Some(&c)) if a.is_ascii_hexdigit() && c.is_ascii_hexdigit() => {}
                (Some(_), Some(_)) => return Err(RejectReason::PathPercentInvalidHex),
                _ => return Err(RejectReason::PathPercentTruncated),
            }
            i = i.saturating_add(3);
        } else if is_path_byte_ok(b) {
            i = i.saturating_add(1);
        } else {
            return Err(RejectReason::PathInvalidByte);
        }
    }
    Ok(())
}

/// Steps 3 through 5: reject an encoded NUL, decode the unreserved set minus `.`, and
/// uppercase the hex digits of every escape that survives undecoded. Appends the
/// result to `out`, which the caller has already reserved enough capacity in. Runs
/// only after `validate_path_syntax` has proven `path` is structurally sound, so every
/// `%` here is followed by two hex digits without re-checking.
///
/// # Errors
/// `PathEncodedNul`.
fn decode_path_into(path: &[u8], out: &mut BytesMut) -> Result<(), RejectReason> {
    let mut i = 0usize;
    while i < path.len() {
        let b = *path.get(i).unwrap_or(&0); // i < path.len() by the loop guard
        if b == b'%' {
            // Proven present and hex by validate_path_syntax, which ran to completion
            // over the whole path before this function was called.
            let h1 = *path.get(i.saturating_add(1)).unwrap_or(&b'0');
            let h2 = *path.get(i.saturating_add(2)).unwrap_or(&b'0');
            let value = hex_pair_value(h1, h2);
            if value == 0 {
                return Err(RejectReason::PathEncodedNul);
            }
            if is_unreserved_minus_dot(value) {
                out.extend_from_slice(&[value]);
            } else {
                out.extend_from_slice(&[b'%', h1.to_ascii_uppercase(), h2.to_ascii_uppercase()]);
            }
            i = i.saturating_add(3);
        } else {
            out.extend_from_slice(&[b]);
            i = i.saturating_add(1);
        }
    }
    Ok(())
}

/// Runs RFC 3986 Section 5.2.4 `remove_dot_segments` in place over `buf[..len]`,
/// returning the new length. Exposed for the rewrite pipeline and for direct testing.
///
/// Matches only the literal byte `.`: a `%2E` written by step 4 (which deliberately
/// does not decode it) is three separate bytes, `%`, `2` and `E`, and never matches
/// the single-byte comparisons below, so an encoded dot segment is not resolved here;
/// that is `EncodedDot`'s job in step 7, which runs after this function returns.
///
/// The write cursor never runs ahead of the read cursor, so this is a shrink-only,
/// in-place, two-cursor pass with O(1) extra space beyond a `SmallVec<[u32; 32]>` of
/// segment-start offsets, one push and, on a `..` segment, one pop per segment: total
/// work is O(`len`), not merely amortised so, because a pop is O(1) rather than the
/// backward rescan the RFC's own prose describes.
///
/// # Errors
/// `PathTraversalAboveRoot` when a `..` segment would escape the root.
pub fn remove_dot_segments(buf: &mut [u8], len: usize) -> Result<usize, RejectReason> {
    let mut stack: SmallVec<[u32; 32]> = SmallVec::new();
    let mut r = 0usize;
    let mut w = 0usize;
    while r < len {
        let rest = buf.get(r..len).unwrap_or(&[]);
        if rest == b"/." || rest.starts_with(b"/./") {
            let exact = rest == b"/.";
            r = r.saturating_add(2);
            if exact {
                if let Some(slot) = buf.get_mut(w) {
                    *slot = b'/';
                }
                w = w.saturating_add(1);
            }
        } else if rest == b"/.." || rest.starts_with(b"/../") {
            let exact = rest == b"/..";
            let Some(popped) = stack.pop() else {
                return Err(RejectReason::PathTraversalAboveRoot);
            };
            r = r.saturating_add(3);
            w = usize::try_from(popped).unwrap_or(0); // pushed from a usize <= len below
            if exact {
                if let Some(slot) = buf.get_mut(w) {
                    *slot = b'/';
                }
                w = w.saturating_add(1);
            }
        } else {
            // Copy one whole segment: the leading `/` and every byte up to (not
            // including) the next `/`, or the end of the path if there is none.
            let seg_start = r;
            stack.push(u32::try_from(w).unwrap_or(u32::MAX)); // w <= len <= max_path_bytes (CEILING 65536)
            let search_from = r.saturating_add(1);
            let next_slash = buf
                .get(search_from..len)
                .unwrap_or(&[])
                .iter()
                .position(|&b| b == b'/')
                .map_or(len, |p| search_from.saturating_add(p));
            // seg_start <= next_slash <= len <= buf.len(), and w <= seg_start (the
            // shrink-only invariant maintained by every branch of this loop), so
            // w + (next_slash - seg_start) <= next_slash <= buf.len(): both the source
            // range and the destination fit, and copy_within cannot panic here.
            buf.copy_within(seg_start..next_slash, w);
            w = w.saturating_add(next_slash.saturating_sub(seg_start));
            r = next_slash;
        }
    }
    Ok(w)
}

/// True when `seg` percent-decodes to exactly `.` or `..`, per step 7: a `.` byte
/// counts as one dot, an uppercase `%2E` counts as one dot and advances three bytes,
/// and any other byte means `seg` is not a dot segment at all.
fn is_encoded_dot_segment(seg: &[u8]) -> bool {
    let mut i = 0usize;
    let mut dots = 0u8;
    while i < seg.len() {
        match seg.get(i) {
            Some(b'.') => {
                dots = dots.saturating_add(1);
                i = i.saturating_add(1);
            }
            Some(b'%') if seg.get(i..i.saturating_add(3)) == Some(&b"%2E"[..]) => {
                dots = dots.saturating_add(1);
                i = i.saturating_add(3);
            }
            _ => return false,
        }
    }
    matches!(dots, 1 | 2)
}

/// Step 7: true if any `/`-delimited segment of `buf` (which must already start with
/// `/`, guaranteed by every caller in this module) percent-decodes to `.` or `..`.
fn has_encoded_dot_segment(buf: &[u8]) -> bool {
    buf.get(1..)
        .unwrap_or(&[])
        .split(|&b| b == b'/')
        .any(is_encoded_dot_segment)
}

/// Step 8: true if `buf` contains an uppercase `%2F` or `%5C` (guaranteed uppercase by
/// step 5, which runs on every surviving escape before this can be called).
fn has_encoded_slash(buf: &[u8]) -> bool {
    buf.windows(3).any(|w| matches!(w, b"%2F" | b"%5C"))
}

/// Step 9: collapses every run of two or more `/` in `buf[..len]` into one, returning
/// the new length. Shrink-only, in place, one read cursor and one write cursor.
fn merge_slashes(buf: &mut [u8], len: usize) -> usize {
    let mut r = 0usize;
    let mut w = 0usize;
    while r < len {
        let b = buf[r]; // r < len by the loop guard
        if let Some(slot) = buf.get_mut(w) {
            *slot = b;
        }
        w = w.saturating_add(1);
        r = r.saturating_add(1);
        if b == b'/' {
            // `r < len`, not merely `buf.get(r).is_some()`: `buf` is the region
            // handed to this call, which can be longer than the logical `len` (it
            // is, whenever step 6 shrank the buffer before this runs), so bounding
            // only by `buf`'s physical length would let this loop read past the
            // caller's intended content into bytes that are not part of the path.
            while r < len && buf.get(r) == Some(&b'/') {
                r = r.saturating_add(1);
            }
        }
    }
    w
}

/// True when `raw` begins with an RFC 3986 `scheme`
/// (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) immediately followed by `://`.
fn has_scheme_prefix(raw: &[u8]) -> bool {
    let Some(&first) = raw.first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1usize;
    while let Some(&b) = raw.get(i) {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
            i = i.saturating_add(1);
        } else {
            break;
        }
    }
    raw.get(i..i.saturating_add(3)) == Some(&b"://"[..])
}

/// Classifies a request target before normalization.
///
/// The decision is an ORDERED cascade, because `host:443` and `https:` are not
/// distinguishable without one:
/// 1. `method.is_connect()` gives `Authority` (authority-form is the only legal target
///    for `CONNECT`; validating it is `authority-parsing-and-reconciliation` (#30)'s job).
/// 2. `raw == b"*"` gives `Asterisk` when the method is `OPTIONS` and
///    `Err(TargetFormInvalid)` otherwise.
/// 3. `raw` starting with `/` gives `Origin`.
/// 4. `raw` beginning with a scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`)
///    followed by `://` gives `Absolute`.
/// 5. Anything else is `Err(TargetFormInvalid)`.
///
/// # Errors
/// `TargetFormInvalid`.
pub fn classify_target(raw: &[u8], method: &Method) -> Result<TargetForm, RejectReason> {
    if method.is_connect() {
        return Ok(TargetForm::Authority);
    }
    if raw == b"*" {
        return if matches!(method, Method::Options) {
            Ok(TargetForm::Asterisk)
        } else {
            Err(RejectReason::TargetFormInvalid)
        };
    }
    if raw.first() == Some(&b'/') {
        return Ok(TargetForm::Origin);
    }
    if has_scheme_prefix(raw) {
        return Ok(TargetForm::Absolute);
    }
    Err(RejectReason::TargetFormInvalid)
}

impl NormalizedPath {
    /// Runs the full nine-step pipeline on an origin-form request target.
    ///
    /// `raw` is the target's path and query, with no scheme or authority. Writes the
    /// normalized bytes into `out` and returns a view over them plus the byte-preserved
    /// query. Shrink-only: the output is never longer than `raw`.
    ///
    /// On error, `out` may contain partial writes and should not be used.
    ///
    /// # Errors
    /// `PathEmpty`, `PathTooLong`, `PathInvalidByte`, `PathPercentTruncated`,
    /// `PathPercentInvalidHex`, `PathEncodedNul`, `PathEncodedDot`, `PathEncodedSlash`,
    /// `PathTraversalAboveRoot`, `QueryInvalidByte`, `TargetFragment`, `TargetFormInvalid`.
    pub fn parse_into(
        raw: &[u8],
        policy: &PathPolicy,
        limits: &ClampedLimits,
        out: &mut BytesMut,
    ) -> Result<(NormalizedPath, Option<RawQuery>), RejectReason> {
        // Step 0.
        if raw.is_empty() {
            return Err(RejectReason::PathEmpty);
        }
        if raw.len() > limits.max_path_bytes as usize {
            return Err(RejectReason::PathTooLong);
        }
        out.reserve(raw.len());
        let base = out.len();

        // Step 1: split, fragment check, query byte check, path shape checks.
        if raw.contains(&b'#') {
            return Err(RejectReason::TargetFragment);
        }
        let question_mark = raw.iter().position(|&b| b == b'?');
        let path_raw = question_mark.map_or(raw, |qpos| raw.get(..qpos).unwrap_or(&[]));
        let query_raw = question_mark.map(|qpos| raw.get(qpos.saturating_add(1)..).unwrap_or(&[]));
        if let Some(query) = query_raw {
            for &b in query {
                if !(b > 0x20 && b < 0x7F && b != b'#') {
                    return Err(RejectReason::QueryInvalidByte);
                }
            }
        }
        if path_raw.is_empty() {
            return Err(RejectReason::PathEmpty);
        }
        if path_raw.first() != Some(&b'/') {
            return Err(RejectReason::TargetFormInvalid);
        }

        // Step 2.
        validate_path_syntax(path_raw)?;

        // Steps 3 to 5: decode into `out`, appending after `base`.
        decode_path_into(path_raw, out)?;
        let stage1_len = out.len().saturating_sub(base);

        // Step 6: dot-segment removal, in place over out[base..].
        let region = out.get_mut(base..).unwrap_or(&mut []); // base <= out.len() always
        let mut path_len = remove_dot_segments(region, stage1_len)?;

        // Step 7: encoded-dot policy.
        if matches!(policy.encoded_dot, EncodedDot::Reject) {
            let current = out
                .get(base..)
                .and_then(|s| s.get(..path_len))
                .unwrap_or(&[]);
            if has_encoded_dot_segment(current) {
                return Err(RejectReason::PathEncodedDot);
            }
        }

        // Step 8: encoded-slash policy.
        if matches!(policy.encoded_slash, EncodedSlash::Reject) {
            let current = out
                .get(base..)
                .and_then(|s| s.get(..path_len))
                .unwrap_or(&[]);
            if has_encoded_slash(current) {
                return Err(RejectReason::PathEncodedSlash);
            }
        }

        // Step 9: slash merging.
        if policy.merge_slashes {
            let region = out.get_mut(base..).unwrap_or(&mut []);
            path_len = merge_slashes(region, path_len);
        }

        out.truncate(base.saturating_add(path_len));

        // Step 10: append the query verbatim, then produce the two views.
        let query_len = query_raw.map_or(0, <[u8]>::len);
        if let Some(query) = query_raw {
            out.extend_from_slice(query);
        }
        let region = out.split_off(base).freeze();
        let path = NormalizedPath {
            buf: region.slice(0..path_len),
        };
        let query = (question_mark.is_some()).then(|| RawQuery {
            buf: region.slice(path_len..path_len.saturating_add(query_len)),
        });
        Ok((path, query))
    }

    /// The ONLY way to get bytes out. The same bytes are used for routing, policy,
    /// logging, cache keys and egress.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_ref()
    }

    /// Length in bytes. Never 0.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Always false; present so clippy does not ask for it and so callers do not
    /// invent their own emptiness check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Number of `/`-separated segments, counting a trailing empty segment.
    /// `/` is 1, `/a` is 1, `/a/` is 2, `/a/b` is 2.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments().count()
    }

    /// Iterates the segments without the separators. `/a/b` yields `a` then `b`;
    /// `/a/` yields `a` then an empty slice.
    pub fn segments(&self) -> impl Iterator<Item = &[u8]> {
        self.as_bytes()
            .get(1..)
            .unwrap_or(&[])
            .split(|&b| b == b'/')
    }

    /// A `NormalizedPath` for the literal root, for synthesized requests.
    #[must_use]
    pub fn root() -> NormalizedPath {
        NormalizedPath {
            buf: Bytes::from_static(b"/"),
        }
    }
}

impl RawQuery {
    /// The query bytes exactly as received, with no leading `?`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_ref()
    }

    /// Length in bytes. May be 0 when `?` was present with nothing after it.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when `?` was present with nothing after it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    fn clamped() -> ClampedLimits {
        Limits::DEFAULT.clamped()
    }

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "mirrors parse_into's own &PathPolicy parameter, which this test helper wraps \
                  directly, so every call site in this module can pass the same value either way"
    )]
    fn parse(
        input: &[u8],
        policy: &PathPolicy,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), RejectReason> {
        let mut out = BytesMut::new();
        let (path, query) = NormalizedPath::parse_into(input, policy, &clamped(), &mut out)?;
        Ok((
            path.as_bytes().to_vec(),
            query.map(|q| q.as_bytes().to_vec()),
        ))
    }

    struct CorpusRow {
        name: &'static str,
        input: Vec<u8>,
        policy: PathPolicy,
        expected: Result<(Vec<u8>, Option<Vec<u8>>), RejectReason>,
    }

    /// Edge cases 1 through 11: target shape and literal dot-segment removal.
    fn corpus_shape_and_dots() -> Vec<CorpusRow> {
        vec![
            CorpusRow {
                name: "1: root",
                input: b"/".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/".to_vec(), None)),
            },
            CorpusRow {
                name: "2: empty",
                input: b"".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEmpty),
            },
            CorpusRow {
                name: "3: query only",
                input: b"?a=1".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEmpty),
            },
            CorpusRow {
                name: "4: no leading slash",
                input: b"a/b".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::TargetFormInvalid),
            },
            CorpusRow {
                name: "5: dot-dot resolves",
                input: b"/api/../admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/admin".to_vec(), None)),
            },
            CorpusRow {
                name: "6: trailing dot-dot keeps slash",
                input: b"/a/b/..".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/a/".to_vec(), None)),
            },
            CorpusRow {
                name: "7: trailing dot keeps slash",
                input: b"/a/b/.".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/a/b/".to_vec(), None)),
            },
            CorpusRow {
                name: "8: dot alone",
                input: b"/.".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/".to_vec(), None)),
            },
            CorpusRow {
                name: "9: dot-dot above root",
                input: b"/..".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathTraversalAboveRoot),
            },
            CorpusRow {
                name: "10: many dot-dot above root",
                input: b"/a/b/../../../../etc/passwd".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathTraversalAboveRoot),
            },
            CorpusRow {
                name: "11: leading dot segment",
                input: b"/./admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/admin".to_vec(), None)),
            },
        ]
    }

    /// Edge cases 12 and 46: slash merging, alone and combined with dot-segment
    /// removal.
    fn corpus_merge_slashes() -> Vec<CorpusRow> {
        let merge = PathPolicy {
            merge_slashes: true,
            ..PathPolicy::DEFAULT
        };
        vec![
            CorpusRow {
                name: "12a: double slash kept",
                input: b"//admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"//admin".to_vec(), None)),
            },
            CorpusRow {
                name: "12b: double slash merged",
                input: b"//admin".to_vec(),
                policy: merge,
                expected: Ok((b"/admin".to_vec(), None)),
            },
            CorpusRow {
                name: "46a: dot-dot with adjacent slash run kept",
                input: b"/a//b/../c".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/a//c".to_vec(), None)),
            },
            CorpusRow {
                name: "46b: dot-dot with adjacent slash run merged",
                input: b"/a//b/../c".to_vec(),
                policy: merge,
                expected: Ok((b"/a/c".to_vec(), None)),
            },
        ]
    }

    /// Edge cases 13 and 14: the `EncodedDot` policy, lowercase and already-uppercase
    /// input.
    fn corpus_encoded_dot() -> Vec<CorpusRow> {
        let keep_dot = PathPolicy {
            encoded_dot: EncodedDot::Keep,
            ..PathPolicy::DEFAULT
        };
        vec![
            CorpusRow {
                name: "13a: encoded dot rejected",
                input: b"/api/%2e%2e/admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedDot),
            },
            CorpusRow {
                name: "13b: encoded dot kept",
                input: b"/api/%2e%2e/admin".to_vec(),
                policy: keep_dot,
                expected: Ok((b"/api/%2E%2E/admin".to_vec(), None)),
            },
            CorpusRow {
                name: "14a: encoded dot already uppercase, rejected",
                input: b"/api/%2E%2E/admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedDot),
            },
            CorpusRow {
                name: "14b: encoded dot already uppercase, kept",
                input: b"/api/%2E%2E/admin".to_vec(),
                policy: keep_dot,
                expected: Ok((b"/api/%2E%2E/admin".to_vec(), None)),
            },
            // Mutation testing found these two rows missing: step 6 only removes a
            // segment that is LITERALLY `.` or `..`, so a segment mixing one literal
            // dot with one encoded dot (`.%2E` or `%2E.`) survives to step 7 unlike
            // `%2e%2e` above, and is a two-dot match by the same left-to-right count.
            // Without a case like this, deleting the `Some(b'.')` arm from
            // `is_encoded_dot_segment`'s walk (which makes every leading literal `.`
            // fall through to "not a dot segment") passed every other test.
            CorpusRow {
                name: "extra: literal dot then encoded dot, rejected",
                input: b"/api/.%2e/admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedDot),
            },
            CorpusRow {
                name: "extra: encoded dot then literal dot, rejected",
                input: b"/api/%2e./admin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedDot),
            },
        ]
    }

    /// Edge cases 15, 16, 17 and 18: the `EncodedSlash` policy (`%2F` and `%5C`) and
    /// the unconditional encoded-nul rejection.
    fn corpus_encoded_slash_and_nul() -> Vec<CorpusRow> {
        let keep_both = PathPolicy {
            encoded_dot: EncodedDot::Keep,
            encoded_slash: EncodedSlash::Keep,
            merge_slashes: false,
        };
        let keep_slash = PathPolicy {
            encoded_slash: EncodedSlash::Keep,
            ..PathPolicy::DEFAULT
        };
        vec![
            CorpusRow {
                name: "15a: encoded slash rejected",
                input: b"/api/..%2fadmin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedSlash),
            },
            CorpusRow {
                name: "15b: encoded slash kept, no traversal",
                input: b"/api/..%2fadmin".to_vec(),
                policy: keep_both,
                expected: Ok((b"/api/..%2Fadmin".to_vec(), None)),
            },
            CorpusRow {
                name: "16a: encoded backslash rejected",
                input: b"/api/..%5cadmin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedSlash),
            },
            CorpusRow {
                name: "16b: encoded backslash kept, no traversal",
                input: b"/api/..%5cadmin".to_vec(),
                policy: keep_both,
                expected: Ok((b"/api/..%5Cadmin".to_vec(), None)),
            },
            CorpusRow {
                name: "17a: mid-path encoded slash rejected",
                input: b"/api%2fadmin".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedSlash),
            },
            CorpusRow {
                name: "17b: mid-path encoded slash kept",
                input: b"/api%2fadmin".to_vec(),
                policy: keep_slash,
                expected: Ok((b"/api%2Fadmin".to_vec(), None)),
            },
            CorpusRow {
                name: "18: encoded nul",
                input: b"/admin%00.txt".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathEncodedNul),
            },
            // Mutation testing found this row missing: replacing
            // `is_encoded_dot_segment`'s `%2E`-match guard with an unconditional
            // `true` still passes every other row, because every other Reject-policy
            // segment in this corpus that survives to step 7 either has zero, or
            // three or more, percent escapes (so the dot COUNT still lands outside
            // 1..=2 even under the broken guard). A segment with EXACTLY one
            // non-`%2E` escape and nothing else is the case that distinguishes them:
            // the real guard says "not a dot segment" (false immediately); the
            // broken one counts a phantom dot and wrongly matches.
            CorpusRow {
                name: "extra: single non-dot escape is not an encoded-dot segment",
                input: b"/%2f".to_vec(),
                policy: PathPolicy {
                    encoded_dot: EncodedDot::Reject,
                    encoded_slash: EncodedSlash::Keep,
                    merge_slashes: false,
                },
                expected: Ok((b"/%2F".to_vec(), None)),
            },
        ]
    }

    /// Edge cases 19 through 27: malformed percent escapes and raw disallowed bytes.
    fn corpus_percent_and_raw_bytes() -> Vec<CorpusRow> {
        vec![
            CorpusRow {
                name: "19: truncated percent",
                input: b"/admin%".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathPercentTruncated),
            },
            CorpusRow {
                name: "20: truncated percent, one digit",
                input: b"/admin%2".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathPercentTruncated),
            },
            CorpusRow {
                name: "21: invalid hex, both digits",
                input: b"/admin%zz".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathPercentInvalidHex),
            },
            CorpusRow {
                name: "22: invalid hex, second digit",
                input: b"/admin%2G".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathPercentInvalidHex),
            },
            CorpusRow {
                name: "23: raw space",
                input: b"/ path".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathInvalidByte),
            },
            CorpusRow {
                name: "24: raw nul",
                input: b"/pa\x00th".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathInvalidByte),
            },
            CorpusRow {
                name: "25: raw del",
                input: b"/pa\x7fth".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathInvalidByte),
            },
            CorpusRow {
                name: "26: raw non-ascii",
                input: b"/p\xc3\xa4th".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathInvalidByte),
            },
            CorpusRow {
                name: "27: raw backslash",
                input: b"/pa\\th".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::PathInvalidByte),
            },
        ]
    }

    /// Edge cases 28 through 35: fragments and the query's own rules.
    fn corpus_fragment_and_query() -> Vec<CorpusRow> {
        vec![
            CorpusRow {
                name: "28: fragment, no query",
                input: b"/path#frag".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::TargetFragment),
            },
            CorpusRow {
                name: "29: fragment after query",
                input: b"/path?a=1#frag".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::TargetFragment),
            },
            CorpusRow {
                name: "30: query present",
                input: b"/path?a=1".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/path".to_vec(), Some(b"a=1".to_vec()))),
            },
            CorpusRow {
                name: "31: empty query present",
                input: b"/path?".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/path".to_vec(), Some(b"".to_vec()))),
            },
            CorpusRow {
                name: "32: no query",
                input: b"/path".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/path".to_vec(), None)),
            },
            CorpusRow {
                name: "33: query byte preserved",
                input: b"/path?a=%2f%2e%2e".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/path".to_vec(), Some(b"a=%2f%2e%2e".to_vec()))),
            },
            CorpusRow {
                name: "34: raw space in query",
                input: b"/path?a=b c".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::QueryInvalidByte),
            },
            CorpusRow {
                name: "35: trailing bare fragment marker",
                input: b"/path?a=b#".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::TargetFragment),
            },
            // Mutation testing found this row missing: the query byte check is
            // `b > 0x20 && b < 0x7F && b != b'#'`; widening `b < 0x7F` to `b <= 0x7F`
            // survived every other row because none of them puts a raw DEL byte in
            // the query specifically (case 25 covers DEL in the PATH only).
            CorpusRow {
                name: "extra: raw del in query",
                input: b"/path?a\x7fb".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Err(RejectReason::QueryInvalidByte),
            },
        ]
    }

    /// Edge cases 36 through 38: exactly which escapes decode versus survive
    /// uppercased.
    fn corpus_decode_and_uppercase() -> Vec<CorpusRow> {
        vec![
            CorpusRow {
                name: "36: unreserved decode",
                input: b"/%41%42".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/AB".to_vec(), None)),
            },
            CorpusRow {
                name: "37: mixed decode and encoded dot survivor",
                input: b"/%2d%2e%5f%7e".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/-%2E_~".to_vec(), None)),
            },
            CorpusRow {
                name: "38: none unreserved, all uppercased",
                input: b"/%3b%3f%25".to_vec(),
                policy: PathPolicy::DEFAULT,
                expected: Ok((b"/%3B%3F%25".to_vec(), None)),
            },
        ]
    }

    /// Edge cases 39, 40 and 41: the length bound and the two dynamically built,
    /// exactly `max_path_bytes`-sized dot-segment inputs.
    fn corpus_length_and_stack_bounds() -> Vec<CorpusRow> {
        let mut rows = Vec::new();

        // 39: exactly max_path_bytes (8192) succeeds; one byte more is PathTooLong.
        let max_len = usize::try_from(Limits::DEFAULT.max_path_bytes).unwrap_or(0);
        let mut exact = Vec::with_capacity(max_len);
        exact.push(b'/');
        exact.resize(max_len, b'a');
        let expected_exact = exact.clone();
        rows.push(CorpusRow {
            name: "39a: exactly max_path_bytes succeeds",
            input: exact,
            policy: PathPolicy::DEFAULT,
            expected: Ok((expected_exact, None)),
        });
        let mut over = Vec::with_capacity(max_len.saturating_add(1));
        over.push(b'/');
        over.resize(max_len.saturating_add(1), b'a');
        rows.push(CorpusRow {
            name: "39b: one byte over max_path_bytes fails",
            input: over,
            policy: PathPolicy::DEFAULT,
            expected: Err(RejectReason::PathTooLong),
        });

        // 40: root followed by 2730 "../" (8191 bytes) fails on the FIRST /../,
        // because the segment stack is empty.
        let mut early_reject = b"/".to_vec();
        for _ in 0..2730 {
            early_reject.extend_from_slice(b"../");
        }
        assert_eq!(early_reject.len(), 8191);
        rows.push(CorpusRow {
            name: "40: early reject above root",
            input: early_reject,
            policy: PathPolicy::DEFAULT,
            expected: Err(RejectReason::PathTraversalAboveRoot),
        });

        // 41: 1638 repetitions of "/a/.." (8190 bytes) resolves to "/", one push and
        // one pop per repetition; this is the input that fails loudly under a
        // backward-rescan implementation instead of an offset pop.
        let mut resolves_to_root = Vec::new();
        for _ in 0..1638 {
            resolves_to_root.extend_from_slice(b"/a/..");
        }
        assert_eq!(resolves_to_root.len(), 8190);
        rows.push(CorpusRow {
            name: "41: repeated segment and pop resolves to root",
            input: resolves_to_root,
            policy: PathPolicy::DEFAULT,
            expected: Ok((b"/".to_vec(), None)),
        });

        rows
    }

    fn corpus() -> Vec<CorpusRow> {
        let mut rows = corpus_shape_and_dots();
        rows.extend(corpus_merge_slashes());
        rows.extend(corpus_encoded_dot());
        rows.extend(corpus_encoded_slash_and_nul());
        rows.extend(corpus_percent_and_raw_bytes());
        rows.extend(corpus_fragment_and_query());
        rows.extend(corpus_decode_and_uppercase());
        rows.extend(corpus_length_and_stack_bounds());
        rows
    }

    #[test]
    fn corpus_table() {
        for row in corpus() {
            let got = parse(&row.input, &row.policy);
            assert_eq!(
                got, row.expected,
                "case {}: input {:?} policy {:?}",
                row.name, row.input, row.policy
            );
            // Every successful row's bytes must already be request-line safe: no
            // byte <= 0x20, no 0x7F, no byte >= 0x80. `prop_output_is_request_line_safe`
            // pins this as a property over generated input; this pins it as a fact
            // about the deterministic corpus, per row, so a corpus addition that
            // slips past the property generator's alphabet is still checked here.
            if let Ok((path_bytes, query_bytes)) = &got {
                for &b in path_bytes {
                    assert!(
                        b > 0x20 && b != 0x7F && b < 0x80,
                        "case {}: path byte {b:#04x} is not request-line safe",
                        row.name
                    );
                }
                if let Some(q) = query_bytes {
                    for &b in q {
                        assert!(
                            b > 0x20 && b != 0x7F && b < 0x80,
                            "case {}: query byte {b:#04x} is not request-line safe",
                            row.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn trailing_slash_semantics() {
        assert_eq!(
            parse(b"/a/b/..", &PathPolicy::DEFAULT),
            Ok((b"/a/".to_vec(), None))
        );
        assert_eq!(
            parse(b"/a/b/.", &PathPolicy::DEFAULT),
            Ok((b"/a/b/".to_vec(), None))
        );
        assert_eq!(
            parse(b"/a/.", &PathPolicy::DEFAULT),
            Ok((b"/a/".to_vec(), None))
        );
        assert_eq!(
            parse(b"/.", &PathPolicy::DEFAULT),
            Ok((b"/".to_vec(), None))
        );
        assert_eq!(
            parse(b"/a/b/../", &PathPolicy::DEFAULT),
            Ok((b"/a/".to_vec(), None))
        );
    }

    #[test]
    fn unreserved_decode_only() {
        let (path, _) = parse(b"/%41-%2d-%5f-%7e", &PathPolicy::DEFAULT).expect("well formed");
        assert_eq!(path, b"/A---_-~");

        for (escape, survives_uppercased) in [
            (&b"%2e"[..], &b"%2E"[..]),
            (&b"%2f"[..], &b"%2F"[..]),
            (&b"%5c"[..], &b"%5C"[..]),
            (&b"%3b"[..], &b"%3B"[..]),
            (&b"%3f"[..], &b"%3F"[..]),
            (&b"%23"[..], &b"%23"[..]),
            (&b"%25"[..], &b"%25"[..]),
            (&b"%20"[..], &b"%20"[..]),
        ] {
            let mut input = b"/x".to_vec();
            input.extend_from_slice(escape);
            let policy = PathPolicy {
                encoded_dot: EncodedDot::Keep,
                encoded_slash: EncodedSlash::Keep,
                merge_slashes: false,
            };
            let (path, _) = parse(&input, &policy).expect("escape kept under Keep policies");
            let mut expected = b"/x".to_vec();
            expected.extend_from_slice(survives_uppercased);
            assert_eq!(
                path, expected,
                "escape {escape:?} did not survive as expected"
            );
        }
    }

    #[test]
    fn nul_always_rejected() {
        for encoded_dot in [EncodedDot::Reject, EncodedDot::Keep] {
            for encoded_slash in [EncodedSlash::Reject, EncodedSlash::Keep] {
                let policy = PathPolicy {
                    encoded_dot,
                    encoded_slash,
                    merge_slashes: false,
                };
                assert_eq!(
                    parse(b"/admin%00.txt", &policy),
                    Err(RejectReason::PathEncodedNul),
                    "{encoded_dot:?} {encoded_slash:?}"
                );
            }
        }
    }

    #[test]
    fn query_is_byte_preserved() {
        let (path, query) =
            parse(b"/p?a=%2f%2e%2e&b=%41", &PathPolicy::DEFAULT).expect("well formed");
        assert_eq!(path, b"/p");
        assert_eq!(query, Some(b"a=%2f%2e%2e&b=%41".to_vec()));
    }

    #[test]
    fn query_presence_is_distinguished() {
        assert_eq!(
            parse(b"/p", &PathPolicy::DEFAULT),
            Ok((b"/p".to_vec(), None))
        );
        assert_eq!(
            parse(b"/p?", &PathPolicy::DEFAULT),
            Ok((b"/p".to_vec(), Some(Vec::new())))
        );
        assert_eq!(
            parse(b"/p?a", &PathPolicy::DEFAULT),
            Ok((b"/p".to_vec(), Some(b"a".to_vec())))
        );
    }

    #[test]
    fn fragment_rejected_everywhere() {
        for input in [&b"/p#f"[..], b"/p?a#f", b"/p?a=b#", b"/#"] {
            assert_eq!(
                parse(input, &PathPolicy::DEFAULT),
                Err(RejectReason::TargetFragment),
                "{input:?}"
            );
        }
    }

    #[test]
    fn limits() {
        let max_len = usize::try_from(Limits::DEFAULT.max_path_bytes).unwrap_or(0);
        let mut ok_len = vec![b'a'; max_len];
        if let Some(first) = ok_len.first_mut() {
            *first = b'/';
        }
        assert!(parse(&ok_len, &PathPolicy::DEFAULT).is_ok());

        let mut too_long = vec![b'a'; max_len.saturating_add(1)];
        if let Some(first) = too_long.first_mut() {
            *first = b'/';
        }
        assert_eq!(
            parse(&too_long, &PathPolicy::DEFAULT),
            Err(RejectReason::PathTooLong)
        );

        // A 200-byte path with a 9000-byte query: the limit covers path plus query.
        let mut combined = vec![b'a'; 199];
        combined.insert(0, b'/');
        combined.push(b'?');
        combined.extend(std::iter::repeat_n(b'a', 9000));
        assert_eq!(
            parse(&combined, &PathPolicy::DEFAULT),
            Err(RejectReason::PathTooLong)
        );
    }

    #[test]
    fn classify_target_forms() {
        assert_eq!(
            classify_target(b"*", &Method::Options),
            Ok(TargetForm::Asterisk)
        );
        assert_eq!(
            classify_target(b"*", &Method::Get),
            Err(RejectReason::TargetFormInvalid)
        );
        assert_eq!(
            classify_target(b"http://h/p", &Method::Get),
            Ok(TargetForm::Absolute)
        );
        assert_eq!(
            classify_target(b"h:443", &Method::Connect),
            Ok(TargetForm::Authority)
        );
        assert_eq!(classify_target(b"/p", &Method::Get), Ok(TargetForm::Origin));
        assert_eq!(
            classify_target(b"p", &Method::Get),
            Err(RejectReason::TargetFormInvalid)
        );
    }

    #[test]
    fn two_paths_share_one_arena() {
        let mut out = BytesMut::new();
        let (a, _) = NormalizedPath::parse_into(b"/a", &PathPolicy::DEFAULT, &clamped(), &mut out)
            .expect("well formed");
        out.reserve(16);
        let (bb, _) =
            NormalizedPath::parse_into(b"/bb", &PathPolicy::DEFAULT, &clamped(), &mut out)
                .expect("well formed");
        assert_eq!(a.as_bytes(), b"/a");
        assert_eq!(bb.as_bytes(), b"/bb");
    }

    /// Mutation testing found every accessor in this file's Public API
    /// (`NormalizedPath::len`, `is_empty`, `segment_count`, `segments`, and
    /// `RawQuery::len`, `is_empty`) with no direct test: every other test reaches
    /// them only through `as_bytes()` or through inequality checks
    /// (`prop_no_traversal` asserts a segment is never `.` or `..`, which stays
    /// true even for `segments` replaced by an empty iterator that yields nothing
    /// to check). Pin each one against an exact, independently known value instead.
    #[test]
    fn accessors_match_documented_values() {
        let mut out = BytesMut::new();
        let (ab, _) =
            NormalizedPath::parse_into(b"/a/b", &PathPolicy::DEFAULT, &clamped(), &mut out)
                .expect("well formed");
        assert_eq!(ab.len(), 4);
        assert!(!ab.is_empty());
        assert_eq!(ab.segment_count(), 2);
        assert_eq!(
            ab.segments().collect::<Vec<_>>(),
            vec![&b"a"[..], &b"b"[..]]
        );

        let mut out2 = BytesMut::new();
        let (a_slash, _) =
            NormalizedPath::parse_into(b"/a/", &PathPolicy::DEFAULT, &clamped(), &mut out2)
                .expect("well formed");
        assert_eq!(a_slash.len(), 3);
        assert_eq!(a_slash.segment_count(), 2);
        assert_eq!(
            a_slash.segments().collect::<Vec<_>>(),
            vec![&b"a"[..], &b""[..]]
        );

        let root = NormalizedPath::root();
        assert_eq!(root.len(), 1);
        assert!(!root.is_empty());
        assert_eq!(root.segment_count(), 1);
        assert_eq!(root.segments().collect::<Vec<_>>(), vec![&b""[..]]);

        let mut out3 = BytesMut::new();
        let (_, empty_query) =
            NormalizedPath::parse_into(b"/p?", &PathPolicy::DEFAULT, &clamped(), &mut out3)
                .expect("well formed");
        let empty_query = empty_query.expect("? with nothing after it is Some");
        assert_eq!(empty_query.len(), 0);
        assert!(empty_query.is_empty());

        let mut out4 = BytesMut::new();
        let (_, nonempty_query) =
            NormalizedPath::parse_into(b"/p?a", &PathPolicy::DEFAULT, &clamped(), &mut out4)
                .expect("well formed");
        let nonempty_query = nonempty_query.expect("? followed by a is Some");
        assert_eq!(nonempty_query.len(), 1);
        assert!(!nonempty_query.is_empty());
    }

    fn target_bytes_strategy() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
        use proptest::prelude::*;
        prop_oneof![
            proptest::collection::vec(proptest::sample::select(&b"abc/.%2Ef5C?&="[..]), 0..=128),
            proptest::collection::vec(any::<u8>(), 0..=128),
        ]
    }

    proptest::proptest! {
        #[test]
        fn prop_shrink_only(target in target_bytes_strategy()) {
            let mut out = BytesMut::new();
            if let Ok((path, _)) = NormalizedPath::parse_into(&target, &PathPolicy::DEFAULT, &clamped(), &mut out) {
                assert!(path.as_bytes().len() <= target.len());
            }
        }

        #[test]
        fn prop_idempotent(target in target_bytes_strategy()) {
            let mut out = BytesMut::new();
            if let Ok((path, _)) = NormalizedPath::parse_into(&target, &PathPolicy::DEFAULT, &clamped(), &mut out) {
                let first = path.as_bytes().to_vec();
                let mut out2 = BytesMut::new();
                match NormalizedPath::parse_into(&first, &PathPolicy::DEFAULT, &clamped(), &mut out2) {
                    Ok((second, _)) => assert_eq!(second.as_bytes(), first.as_slice()),
                    Err(e) => panic!("re-parsing normalized output {first:?} failed: {e:?}"),
                }
            }
        }

        #[test]
        fn prop_no_traversal(target in target_bytes_strategy()) {
            let mut out = BytesMut::new();
            if let Ok((path, _)) = NormalizedPath::parse_into(&target, &PathPolicy::DEFAULT, &clamped(), &mut out) {
                assert_eq!(path.as_bytes().first(), Some(&b'/'));
                for seg in path.segments() {
                    assert_ne!(seg, b"..");
                    assert_ne!(seg, b".");
                }
            }
        }

        #[test]
        fn prop_output_is_request_line_safe(target in target_bytes_strategy()) {
            let mut out = BytesMut::new();
            if let Ok((path, query)) = NormalizedPath::parse_into(&target, &PathPolicy::DEFAULT, &clamped(), &mut out) {
                for &b in path.as_bytes() {
                    assert!((0x21..=0x7E).contains(&b), "path byte {b:#04x} outside 0x21..=0x7E");
                }
                if let Some(q) = query {
                    for &b in q.as_bytes() {
                        assert!((0x21..=0x7E).contains(&b), "query byte {b:#04x} outside 0x21..=0x7E");
                    }
                }
            }
        }
    }

    #[test]
    fn segment_stack_spill_is_bounded() {
        // Documents the figure in the module's invariants: a path of max_path_bytes
        // `/` bytes spills the offset stack to one u32 per emitted segment, i.e.
        // 4 * max_path_bytes transient bytes (32 KiB at the shipped default), freed
        // when the request head completes. One byte more than max_path_bytes is
        // PathTooLong before the pipeline ever runs.
        let max_len = usize::try_from(Limits::DEFAULT.max_path_bytes).unwrap_or(0);
        let all_slashes = vec![b'/'; max_len];
        assert!(parse(&all_slashes, &PathPolicy::DEFAULT).is_ok());

        let mut one_more = vec![b'/'; max_len.saturating_add(1)];
        one_more.push(b'/');
        one_more.truncate(max_len.saturating_add(1));
        assert_eq!(
            parse(&one_more, &PathPolicy::DEFAULT),
            Err(RejectReason::PathTooLong)
        );
    }
}
