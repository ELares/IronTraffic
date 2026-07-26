// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Authority normalization: turning a raw `Host` or `:authority` value into
//! lowercase ASCII with the port and one trailing dot removed, and encoding a
//! normalized authority into the reversed-label form the host trie is keyed
//! by.
//!
//! [`normalize_authority`] is the ONLY authority normalization in the
//! product. The route builder calls it through [`normalize_host_pattern`] at
//! build time, and the request path calls it directly at match time. If the
//! two paths ever normalized differently, a route could match an authority
//! its author did not write, which is a virtual-host confusion primitive.
//! Having one function used by both callers, rather than two independent
//! implementations of the same grammar, is what makes that structurally
//! impossible rather than merely true today.
//!
//! Case folding here is ASCII only. Unicode case folding has locale
//! dependent behaviour (the Turkish dotless-i class), and a non-ASCII
//! authority can never match a Gateway API `Hostname` pattern, so this module
//! rejects non-ASCII authorities outright rather than mapping them. It never
//! performs IDNA, punycode, NFC or NFKC normalization.
//!
//! The `HOT PATH` marker above puts this whole file, every function in it,
//! under `scripts/invariant-lints.sh`'s `hot-path-allocation` and
//! `hot-path-lock` rules: a text scan of the entire production-code body for
//! every call that can allocate or lock, run in CI on every pull request.
//! That is a single, shared definition of "does this code allocate" instead
//! of a hand-rolled, per-crate reimplementation of the same vocabulary,
//! which is what closed a real gap: an earlier version of this module's own
//! zero-allocation test hand-picked a call graph of six functions and missed
//! two (`normalize_host_pattern`, `check_label_shape`), and its copy of the
//! allocating-call vocabulary had silently drifted from the rule's own by
//! dropping one entry (a clone-call check). The marker-driven scan cannot
//! drift the same way, because there is only one copy of the vocabulary and
//! it covers the whole file, not a manually maintained subset of it.

use crate::ids::ListenerId;
use crate::limits::{AUTHORITY_BUF_BYTES, MAX_AUTHORITY_BYTES, MAX_HOST_LABELS};
use crate::spec::HostPattern;

/// Size of the stack buffer `host_key` writes into: two listener bytes, at most
/// `MAX_AUTHORITY_BYTES` host bytes, one extra separator, and slack to 264.
pub const HOST_KEY_BUF_BYTES: usize = 264;

/// Why an authority could not be normalized. Every variant maps to a 400 at the
/// caller; the router itself never produces a status code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityError {
    /// The authority, or its host component, was empty.
    Empty,
    /// Longer than `MAX_AUTHORITY_BYTES` after the port was stripped.
    TooLong,
    /// A byte at or above 0x80.
    NonAscii,
    /// A byte that cannot appear in an authority.
    InvalidByte,
    /// The port suffix was not a run of at most five ASCII digits.
    PortInvalid,
    /// An unclosed bracket, an empty label, or a leading dot.
    Malformed,
    /// Build-time only: a DNS label longer than 63 bytes.
    LabelTooLong,
    /// Build-time only: more than `MAX_HOST_LABELS` labels in a CONFIGURED pattern.
    /// Never produced for a request authority.
    TooManyLabels,
    /// Build-time only: a wildcard pattern with fewer than two labels.
    WildcardTooBroad,
}

/// What kind of host pattern a normalized pattern is.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum HostKind {
    /// Matches this authority exactly.
    Exact,
    /// Matches any authority with at least one label more than this suffix.
    Wildcard,
}

/// Splits `raw` into the host span (port and brackets-aware) and whether that
/// span is the IPv6 bracket form. Implements steps 3 through 4 of
/// `normalize_authority`'s algorithm: find and validate any port suffix, and
/// refuse an empty host span.
fn host_span_and_bracket(raw: &[u8]) -> Result<(&[u8], bool), AuthorityError> {
    let bracket = raw.first() == Some(&b'[');
    let host_span: &[u8] = if bracket {
        let close = raw
            .iter()
            .position(|&b| b == b']')
            .ok_or(AuthorityError::Malformed)?;
        // `close` is a real index into `raw` (found by `position`), so
        // `close + 1 <= raw.len()` always holds and this range is always
        // in bounds; `unwrap_or` is defense in depth, not a load-bearing
        // fallback, and fails closed to an empty span rather than panicking.
        let span = raw.get(..=close).unwrap_or(&[]);
        let after = raw.get(close + 1..).unwrap_or(&[]);
        if !after.is_empty() {
            if after.first() != Some(&b':') {
                return Err(AuthorityError::PortInvalid);
            }
            let digits = after.get(1..).unwrap_or(&[]);
            if digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
                return Err(AuthorityError::PortInvalid);
            }
        }
        span
    } else {
        match raw.iter().rposition(|&b| b == b':') {
            Some(c) => {
                let port = raw.get(c + 1..).unwrap_or(&[]);
                if port.len() > 5 || !port.iter().all(u8::is_ascii_digit) {
                    return Err(AuthorityError::PortInvalid);
                }
                raw.get(..c).unwrap_or(&[])
            }
            None => raw,
        }
    };

    if host_span.is_empty() {
        return Err(AuthorityError::Empty);
    }
    Ok((host_span, bracket))
}

/// Strips exactly one trailing dot and refuses a leading dot, a remaining
/// trailing dot, or a span over `MAX_AUTHORITY_BYTES`. Implements steps 5
/// through 8.
fn trim_and_check_shape(host_span: &[u8]) -> Result<&[u8], AuthorityError> {
    // Strip exactly one trailing dot (the DNS root label), only when the span
    // is longer than one byte: a lone "." must fall through to the
    // ends-with-dot check below unchanged, so it is refused rather than
    // silently emptied.
    let host_span: &[u8] = if host_span.len() > 1 && host_span.last() == Some(&b'.') {
        host_span.get(..host_span.len() - 1).unwrap_or(&[])
    } else {
        host_span
    };

    if host_span.last() == Some(&b'.') {
        return Err(AuthorityError::Malformed);
    }
    if host_span.first() == Some(&b'.') {
        return Err(AuthorityError::Malformed);
    }
    if host_span.len() > MAX_AUTHORITY_BYTES {
        return Err(AuthorityError::TooLong);
    }
    Ok(host_span)
}

/// Validates and lowercases the IPv6 bracket form in one pass, writing byte
/// `i` of `host_span` to `buf[i]`. Implements the bracket half of step 9.
fn write_bracket_host(
    host_span: &[u8],
    buf: &mut [u8; AUTHORITY_BUF_BYTES],
) -> Result<(), AuthorityError> {
    let mut seen_percent = false;
    for (i, &b) in host_span.iter().enumerate() {
        let out_byte = if seen_percent {
            match b {
                b'0'..=b'9' | b'a'..=b'z' | b'-' | b'_' | b'.' | b'%' | b']' => b,
                b'A'..=b'Z' => b.to_ascii_lowercase(),
                _ => return Err(AuthorityError::InvalidByte),
            }
        } else {
            match b {
                b'0'..=b'9' | b'a'..=b'f' | b':' | b'.' | b'[' | b']' => b,
                b'A'..=b'F' => b.to_ascii_lowercase(),
                b'%' => {
                    seen_percent = true;
                    b
                }
                _ => return Err(AuthorityError::InvalidByte),
            }
        };
        // `host_span.len() <= MAX_AUTHORITY_BYTES < AUTHORITY_BUF_BYTES`
        // (enforced by `trim_and_check_shape` before this is called), so
        // this write is always in bounds; `get_mut` still checks it, because
        // a caller-owned 256-byte buffer over fully attacker-controlled input
        // must not depend on that reasoning being correct to stay memory safe.
        let slot = buf.get_mut(i).ok_or(AuthorityError::TooLong)?;
        *slot = out_byte;
    }
    Ok(())
}

/// Validates and lowercases the plain (non-bracket) form in one pass, writing
/// byte `i` of `host_span` to `buf[i]` and refusing two consecutive dots.
/// Implements the non-bracket half of step 9 and step 10.
fn write_plain_host(
    host_span: &[u8],
    buf: &mut [u8; AUTHORITY_BUF_BYTES],
) -> Result<(), AuthorityError> {
    let mut prev_dot = false;
    for (i, &b) in host_span.iter().enumerate() {
        let out_byte = match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                prev_dot = false;
                b
            }
            b'.' => {
                if prev_dot {
                    return Err(AuthorityError::Malformed);
                }
                prev_dot = true;
                b
            }
            b'A'..=b'Z' => {
                prev_dot = false;
                b.to_ascii_lowercase()
            }
            0x80..=0xff => return Err(AuthorityError::NonAscii),
            _ => return Err(AuthorityError::InvalidByte),
        };
        // See the matching comment in `write_bracket_host`.
        let slot = buf.get_mut(i).ok_or(AuthorityError::TooLong)?;
        *slot = out_byte;
    }
    Ok(())
}

/// Normalizes a raw `Host` or `:authority` value into lowercase ASCII with the port
/// and one trailing dot removed.
///
/// Writes into `buf` and returns the written prefix. Allocates nothing on any path.
/// This is the ONLY authority normalization in the product: the route builder and the
/// request path both call it, so a hostname configured as `Example.COM.` and a request
/// to `example.com:443` provably agree.
///
/// # Errors
/// See [`AuthorityError`]. The caller answers 400 for every variant.
pub fn normalize_authority<'b>(
    raw: &[u8],
    buf: &'b mut [u8; AUTHORITY_BUF_BYTES],
) -> Result<&'b [u8], AuthorityError> {
    if raw.is_empty() {
        return Err(AuthorityError::Empty);
    }
    // Early cap so the scans below cannot run over an unbounded input; the
    // real limit is enforced on the host span alone, after the port is
    // stripped, in trim_and_check_shape below.
    if raw.len() > 1024 {
        return Err(AuthorityError::TooLong);
    }

    let (host_span, bracket) = host_span_and_bracket(raw)?;
    let host_span = trim_and_check_shape(host_span)?;
    let span_len = host_span.len();

    if bracket {
        write_bracket_host(host_span, buf)?;
    } else {
        write_plain_host(host_span, buf)?;
    }

    buf.get(..span_len).ok_or(AuthorityError::TooLong)
}

/// Rejects a label longer than 63 bytes or more than `MAX_HOST_LABELS` labels.
///
/// Applied only to a CONFIGURED pattern by [`normalize_host_pattern`], never to
/// a request authority: a request to a deep hostname is legitimate and must
/// still be able to reach a wildcard pattern or the listener catch-all, so
/// `host_key` imposes no such cap.
fn check_label_shape(host: &[u8]) -> Result<(), AuthorityError> {
    let mut label_len = 0usize;
    let mut label_count = 0usize;
    for &b in host {
        if b == b'.' {
            if label_len > 63 {
                return Err(AuthorityError::LabelTooLong);
            }
            label_count += 1;
            label_len = 0;
        } else {
            label_len += 1;
        }
    }
    if label_len > 63 {
        return Err(AuthorityError::LabelTooLong);
    }
    // The final label never ends with a dot (normalize_authority already
    // refused that), so it is never counted inside the loop above.
    label_count += 1;
    if label_count > MAX_HOST_LABELS {
        return Err(AuthorityError::TooManyLabels);
    }
    Ok(())
}

/// Normalizes a configured host pattern, applying the stricter build-time rules
/// (label length, label count, wildcard breadth).
///
/// Returns `Ok(None)` for `HostPattern::Any`.
///
/// # Errors
/// See [`AuthorityError`].
pub fn normalize_host_pattern<'b>(
    pattern: &HostPattern,
    buf: &'b mut [u8; AUTHORITY_BUF_BYTES],
) -> Result<Option<(&'b [u8], HostKind)>, AuthorityError> {
    match pattern {
        HostPattern::Any => Ok(None),
        HostPattern::Exact(text) => {
            let bytes = normalize_authority(text.as_bytes(), buf)?;
            check_label_shape(bytes)?;
            Ok(Some((bytes, HostKind::Exact)))
        }
        HostPattern::Wildcard(suffix) => {
            let bytes = normalize_authority(suffix.as_bytes(), buf)?;
            if !bytes.contains(&b'.') {
                return Err(AuthorityError::WildcardTooBroad);
            }
            check_label_shape(bytes)?;
            Ok(Some((bytes, HostKind::Wildcard)))
        }
    }
}

/// Encodes a listener id and a normalized authority into the reversed-label key the
/// host trie is built on and searched with.
///
/// Returns the number of bytes written to `out`.
///
/// Imposes no label-count limit: `MAX_HOST_LABELS` bounds configured patterns only,
/// and a request authority with more labels must still be able to match a wildcard
/// pattern or the catch-all.
///
/// # Errors
/// `TooLong` when `host` is longer than `MAX_AUTHORITY_BYTES`, which cannot happen
/// for a host produced by `normalize_authority`.
pub fn host_key(
    listener: ListenerId,
    host: &[u8],
    out: &mut [u8; HOST_KEY_BUF_BYTES],
) -> Result<usize, AuthorityError> {
    let mut n = 0usize;
    for &b in &listener.0.to_be_bytes() {
        let slot = out.get_mut(n).ok_or(AuthorityError::TooLong)?;
        *slot = b;
        n += 1;
    }
    if host.is_empty() {
        return Ok(n);
    }
    if host.len() > MAX_AUTHORITY_BYTES {
        return Err(AuthorityError::TooLong);
    }

    // Walk labels from the end. Each backward scan only covers the label it
    // emits (the previously found separator bounds it), so the whole walk is
    // O(host.len()) even though it looks like a scan per label.
    let mut rest = host;
    while !rest.is_empty() {
        let (label, remainder): (&[u8], &[u8]) = match rest.iter().rposition(|&b| b == b'.') {
            Some(i) => (
                rest.get(i + 1..).unwrap_or(&[]),
                rest.get(..i).unwrap_or(&[]),
            ),
            None => (rest, &[]),
        };
        for &b in label {
            let slot = out.get_mut(n).ok_or(AuthorityError::TooLong)?;
            *slot = b;
            n += 1;
        }
        let slot = out.get_mut(n).ok_or(AuthorityError::TooLong)?;
        *slot = b'.';
        n += 1;
        rest = remainder;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORITY_BUF_BYTES, AuthorityError, HOST_KEY_BUF_BYTES, HostKind, MAX_AUTHORITY_BYTES,
        host_key, normalize_authority, normalize_host_pattern,
    };
    use crate::ids::ListenerId;
    use crate::spec::HostPattern;
    use proptest::prelude::*;

    /// One row of `NORMALIZE_CASES`: a raw input and the expected result.
    type NormalizeCase = (&'static [u8], Result<&'static [u8], AuthorityError>);

    /// Edge cases 1 through 23 and 27 through 29 from the issue. Cases 24, 25
    /// and 26 need a `Vec` to build and are constructed in the test body
    /// instead, per the issue's own instruction.
    const NORMALIZE_CASES: &[NormalizeCase] = &[
        (b"", Err(AuthorityError::Empty)),
        (b":", Err(AuthorityError::Empty)),
        (b":443", Err(AuthorityError::Empty)),
        (b".", Err(AuthorityError::Malformed)),
        (b"example.com", Ok(b"example.com")),
        (b"EXAMPLE.COM", Ok(b"example.com")),
        (b"example.com.", Ok(b"example.com")),
        (b"example.com..", Err(AuthorityError::Malformed)),
        (b"example.com:443", Ok(b"example.com")),
        (b"example.com:", Ok(b"example.com")),
        (b"example.com:65536", Ok(b"example.com")),
        (b"example.com:99999999", Err(AuthorityError::PortInvalid)),
        (b"example.com:80a", Err(AuthorityError::PortInvalid)),
        (b"exa mple.com", Err(AuthorityError::InvalidByte)),
        (b"example.com\x00", Err(AuthorityError::InvalidByte)),
        (b"exampl\xc3\xa9.com", Err(AuthorityError::NonAscii)),
        (b"[::1]", Ok(b"[::1]")),
        (b"[::1]:8443", Ok(b"[::1]")),
        (b"[::FFFF:192.168.0.1]", Ok(b"[::ffff:192.168.0.1]")),
        (b"[fe80::1%25eth0]", Ok(b"[fe80::1%25eth0]")),
        (b"[FE80::1%25ETH0]", Ok(b"[fe80::1%25eth0]")),
        (b"[::1", Err(AuthorityError::Malformed)),
        (b"[::1]x", Err(AuthorityError::PortInvalid)),
        // Unbracketed IPv6: `rposition` finds the LAST colon at index 1,
        // `raw[2..]` is `b"1"`, a valid one-digit port, so the host span is
        // `raw[..1]`, the single byte `b":"`. That byte is not in the
        // non-bracket accepted set, so this is `InvalidByte`, not
        // `Malformed`.
        (b"::1", Err(AuthorityError::InvalidByte)),
        (b".example.com", Err(AuthorityError::Malformed)),
        (b"-example.com", Ok(b"-example.com")),
        (b"under_score.example.com", Ok(b"under_score.example.com")),
        // Not one of the issue's numbered cases: added after mutation testing
        // found that swapping the bracket-close search from `position` (the
        // FIRST `]`, as the algorithm specifies) to `rposition` (the LAST
        // `]`) survived every other case above. With `position`, the host
        // span is `"[::1]"` and the trailing `"]"` is an invalid port prefix
        // (it does not start with `:`), so this must be `PortInvalid`. A
        // `rposition`-based mutant instead swallows both brackets into the
        // host span and wrongly returns `Ok`.
        (b"[::1]]", Err(AuthorityError::PortInvalid)),
    ];

    #[test]
    fn normalize_table() {
        for &(input, expected) in NORMALIZE_CASES {
            let mut buf = [0u8; AUTHORITY_BUF_BYTES];
            let actual = normalize_authority(input, &mut buf);
            assert_eq!(
                actual, expected,
                "normalize_authority({input:?}) = {actual:?}, expected {expected:?}"
            );
        }

        // Case 24: 4 labels of 63 bytes of b'a' joined by b'.' (255 bytes
        // total, exactly MAX_AUTHORITY_BYTES) must be accepted unchanged.
        let mut host_255 = Vec::new();
        for _ in 0..3 {
            if !host_255.is_empty() {
                host_255.push(b'.');
            }
            host_255.extend(std::iter::repeat_n(b'a', 63));
        }
        host_255.push(b'.');
        host_255.extend(std::iter::repeat_n(b'a', 63));
        assert_eq!(host_255.len(), 255);
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(&host_255, &mut buf),
            Ok(host_255.as_slice())
        );

        // Case 25: one more byte than case 24 must be refused as too long.
        let mut host_256 = host_255.clone();
        host_256.push(b'a');
        assert_eq!(host_256.len(), 256);
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(&host_256, &mut buf),
            Err(AuthorityError::TooLong)
        );

        // One byte more again: 257 bytes of raw input, exactly
        // AUTHORITY_BUF_BYTES plus one, must also be refused. This is
        // AUTHORITY_BUF_BYTES itself, not just MAX_AUTHORITY_BYTES, that is
        // under test here: a bounds mistake sized off the wrong constant
        // could plausibly pass at 256 and only misbehave one byte later.
        let mut host_257 = host_256.clone();
        host_257.push(b'a');
        assert_eq!(host_257.len(), 257);
        assert_eq!(host_257.len(), AUTHORITY_BUF_BYTES + 1);
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(&host_257, &mut buf),
            Err(AuthorityError::TooLong)
        );

        // Case 26: 1025 bytes trips the early cap at step 2, before the host
        // span is even computed.
        let host_1025 = vec![b'a'; 1025];
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(&host_1025, &mut buf),
            Err(AuthorityError::TooLong)
        );
    }

    #[test]
    fn pattern_table() {
        // Case 30: a wildcard over a single label captures too much.
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Wildcard("com".to_owned()), &mut buf),
            Err(AuthorityError::WildcardTooBroad)
        );

        // Case 31: a two-label wildcard suffix is fine.
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Wildcard("example.com".to_owned()), &mut buf),
            Ok(Some((b"example.com".as_slice(), HostKind::Wildcard)))
        );

        // Case 32: `*` is never accepted, even inside an Exact pattern; the
        // rejection comes from normalize_authority's own byte class.
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Exact("*.example.com".to_owned()), &mut buf),
            Err(AuthorityError::InvalidByte)
        );

        // Not one of the issue's numbered cases: added after mutation testing
        // found that widening the label-length check from `> 63` to `>= 63`
        // survived every other case in this test, because nothing exercised
        // a label of exactly the legal maximum. Paired with case 33 below (64
        // bytes, one over the limit), this pins the exact boundary rather
        // than just the over-limit side of it.
        let mut exactly_63 = "a".repeat(63);
        exactly_63.push_str(".example.com");
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        let expected_bytes = exactly_63.clone().into_bytes();
        assert_eq!(
            normalize_host_pattern(&HostPattern::Exact(exactly_63), &mut buf),
            Ok(Some((expected_bytes.as_slice(), HostKind::Exact)))
        );

        // Case 33: a 64-byte label is one byte over the DNS label cap.
        let mut long_label = "a".repeat(64);
        long_label.push_str(".example.com");
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Exact(long_label), &mut buf),
            Err(AuthorityError::LabelTooLong)
        );

        // Case 34: 17 single-character labels is one over MAX_HOST_LABELS.
        let seventeen = vec!["a"; 17].join(".");
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Exact(seventeen), &mut buf),
            Err(AuthorityError::TooManyLabels)
        );
    }

    #[test]
    fn host_key_table() {
        // Case 35: an empty host writes only the listener prefix.
        let mut out = [0u8; HOST_KEY_BUF_BYTES];
        let n = host_key(ListenerId(7), b"", &mut out).expect("case 35 must succeed");
        assert_eq!(n, 2);
        assert_eq!(out.get(..2), Some(&[0u8, 7][..]));

        // Case 36: "a.example.com" reverses to "com.example.a.".
        let mut out = [0u8; HOST_KEY_BUF_BYTES];
        let n = host_key(ListenerId(1), b"a.example.com", &mut out).expect("case 36 must succeed");
        assert_eq!(n, 2 + 14);
        let mut expected = vec![0u8, 1];
        expected.extend_from_slice(b"com.example.a.");
        assert_eq!(out.get(..n), Some(expected.as_slice()));

        // Case 37: "example.com" reverses to "com.example.", a strict prefix
        // of case 36's key, and equal to the wildcard *.example.com's key.
        // Both relations are the host trie's whole wildcard-exclusion
        // contract, so both are asserted explicitly rather than just one.
        let mut out_short = [0u8; HOST_KEY_BUF_BYTES];
        let n_short =
            host_key(ListenerId(1), b"example.com", &mut out_short).expect("case 37 must succeed");
        let mut expected_short = vec![0u8, 1];
        expected_short.extend_from_slice(b"com.example.");
        assert_eq!(out_short.get(..n_short), Some(expected_short.as_slice()));
        assert!(
            n_short < n,
            "case 37's key must be strictly shorter than case 36's"
        );
        assert_eq!(
            out.get(..n_short),
            out_short.get(..n_short),
            "case 37's key must be a byte-for-byte prefix of case 36's key"
        );
        let mut pattern_buf = [0u8; AUTHORITY_BUF_BYTES];
        let (suffix, kind) = normalize_host_pattern(
            &HostPattern::Wildcard("example.com".to_owned()),
            &mut pattern_buf,
        )
        .expect("case 37 wildcard must normalize")
        .expect("case 37 wildcard is not Any");
        assert_eq!(kind, HostKind::Wildcard);
        let mut wc_out = [0u8; HOST_KEY_BUF_BYTES];
        let wc_n = host_key(ListenerId(1), suffix, &mut wc_out).expect("case 37 wildcard key");
        assert_eq!(
            wc_out.get(..wc_n),
            out_short.get(..n_short),
            "case 37: example.com's key must equal *.example.com's key"
        );

        // Case 37a: a 20-label authority must still be accepted; the label
        // cap is a build-time rule for configured patterns only.
        let deep = "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.com";
        assert_eq!(deep.split('.').count(), 20);
        let mut out_deep = [0u8; HOST_KEY_BUF_BYTES];
        assert!(host_key(ListenerId(1), deep.as_bytes(), &mut out_deep).is_ok());
    }

    #[test]
    fn host_key_prefix_relation() {
        let mut long_key = [0u8; HOST_KEY_BUF_BYTES];
        let long_n = host_key(ListenerId(3), b"a.example.com", &mut long_key).expect("long key");

        let mut short_key = [0u8; HOST_KEY_BUF_BYTES];
        let short_n = host_key(ListenerId(3), b"example.com", &mut short_key).expect("short key");

        assert!(
            short_n < long_n,
            "the wildcard node's key must be strictly shorter than a matching hostname's"
        );
        assert_eq!(
            long_key.get(..short_n),
            short_key.get(..short_n),
            "the shorter key must be a byte-for-byte prefix of the longer one"
        );

        let mut pattern_buf = [0u8; AUTHORITY_BUF_BYTES];
        let (suffix, kind) = normalize_host_pattern(
            &HostPattern::Wildcard("example.com".to_owned()),
            &mut pattern_buf,
        )
        .expect("wildcard must normalize")
        .expect("wildcard is not Any");
        assert_eq!(kind, HostKind::Wildcard);

        let mut wildcard_key = [0u8; HOST_KEY_BUF_BYTES];
        let wildcard_n = host_key(ListenerId(3), suffix, &mut wildcard_key).expect("wildcard key");

        assert_eq!(wildcard_n, short_n);
        assert_eq!(
            wildcard_key.get(..wildcard_n),
            short_key.get(..short_n),
            "*.example.com's key must equal example.com's key: that equality is what \
             makes the wildcard-exclusion rule (request key strictly longer than the \
             wildcard node's key) correctly exclude the bare domain from its own wildcard"
        );
    }

    proptest! {
        #[test]
        fn idempotent(
            v in prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..300),
                "[a-zA-Z0-9.:_-]{0,60}".prop_map(String::into_bytes),
            ]
        ) {
            let mut b1 = [0u8; AUTHORITY_BUF_BYTES];
            if let Ok(x) = normalize_authority(&v, &mut b1) {
                let x_owned = x.to_vec();
                let mut b2 = [0u8; AUTHORITY_BUF_BYTES];
                let y = normalize_authority(&x_owned, &mut b2);
                prop_assert_eq!(y, Ok(x_owned.as_slice()));
            }
        }

        #[test]
        fn never_panics(v in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let mut buf = [0u8; AUTHORITY_BUF_BYTES];
            if let Ok(host) = normalize_authority(&v, &mut buf) {
                prop_assert!(host.len() <= MAX_AUTHORITY_BYTES);
            }
        }
    }

    #[test]
    fn case_folding_is_ascii_only() {
        // The Turkish dotless capital I, U+0130, encoded as UTF-8, inside an
        // otherwise valid host.
        let mut host = b"ex".to_vec();
        host.extend_from_slice(b"\xc4\xb0");
        host.extend_from_slice(b"mple.com");
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(&host, &mut buf),
            Err(AuthorityError::NonAscii)
        );

        // No byte at or above 0x80 is ever altered rather than rejected: a
        // narrower mutant (for example one that only special-cased the UTF-8
        // continuation-byte range) would still pass the single case above but
        // fail this loop over the whole high half of the byte space.
        for hi in 0x80u8..=0xffu8 {
            let host = [b'a', hi, b'.', b'c', b'o', b'm'];
            let mut buf = [0u8; AUTHORITY_BUF_BYTES];
            assert_eq!(
                normalize_authority(&host, &mut buf),
                Err(AuthorityError::NonAscii),
                "byte {hi:#04x} must be rejected, not altered"
            );
        }
    }

    /// Closes gaps a review found in the bracket (IPv6) path of
    /// `normalize_authority`: the port digit check has no bracket-form
    /// counterpart to `normalize_table`'s `b"example.com:80a"` case, and the
    /// pre-percent byte class was never asserted from the refused side, so a
    /// widened byte class survived every case above unnoticed.
    #[test]
    fn normalize_gap_cases() {
        // Bracket form, port digit validation. `normalize_table` covers the
        // plain-form equivalent (`b"example.com:80a"`); dropping the
        // all-digits check on the bracket path's port left this case
        // untested and wrongly `Ok`.
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(b"[::1]:80a", &mut buf),
            Err(AuthorityError::PortInvalid),
            "a non-digit in the bracket form's port suffix must be PortInvalid"
        );

        // Bracket byte class, pre-percent, refused side. `g` is alphabetic
        // but not a hex digit: a mutant that widens the pre-percent class
        // from `a-f` to `a-z` would wrongly accept it.
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(b"[::g]", &mut buf),
            Err(AuthorityError::InvalidByte),
            "a non-hex letter before any % in the bracket form must be InvalidByte"
        );

        // Bracket byte class, pre-percent, refused side. `_` is accepted in
        // the plain (non-bracket) class but must not leak into the bracket
        // class ahead of a `%`: a mutant that adds `_` to the pre-percent
        // set would wrongly accept it.
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_authority(b"[::_]", &mut buf),
            Err(AuthorityError::InvalidByte),
            "an underscore before any % in the bracket form must be InvalidByte"
        );
    }

    /// Closes a gap a review found: nothing in `pattern_table` exercises
    /// `check_label_shape` through the `Wildcard` arm of
    /// `normalize_host_pattern`, only through `Exact`. That matters because
    /// `limits::MAX_CHAIN_LEN`'s derivation depends on every CONFIGURED
    /// pattern, wildcard included, never exceeding `MAX_HOST_LABELS` labels;
    /// an unbounded wildcard suffix would blow that bound.
    #[test]
    fn pattern_gap_cases() {
        // The label-LENGTH side: one byte over the 63-byte DNS label cap,
        // past the wildcard's own two-label minimum. If `Wildcard` never
        // called `check_label_shape` (for example because the call was
        // removed from that match arm), this would wrongly return `Ok`.
        let mut long_label = "a".repeat(64);
        long_label.push_str(".example.com");
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Wildcard(long_label), &mut buf),
            Err(AuthorityError::LabelTooLong),
            "a wildcard suffix with a 64-byte label must be LabelTooLong"
        );

        // The label-COUNT side: 17 labels is one over `MAX_HOST_LABELS`. Same
        // failure mode as above, exercised through the count check instead
        // of the length check.
        let seventeen = vec!["a"; 17].join(".");
        let mut buf = [0u8; AUTHORITY_BUF_BYTES];
        assert_eq!(
            normalize_host_pattern(&HostPattern::Wildcard(seventeen), &mut buf),
            Err(AuthorityError::TooManyLabels),
            "a 17-label wildcard suffix must be TooManyLabels"
        );
    }

    /// Closes a gap a review found: `host_key`'s only error path and the
    /// buffer-sizing worst case it implies were both untested. Deleting the
    /// `host.len() > MAX_AUTHORITY_BYTES` check, or shrinking
    /// `HOST_KEY_BUF_BYTES` from 264 to 257, both left every other test in
    /// this module green.
    #[test]
    fn host_key_length_boundary() {
        // The only error `host_key` can return: a host longer than
        // `MAX_AUTHORITY_BYTES`. This cannot happen for a host that came
        // from `normalize_authority`, but `host_key` is `pub` and must fail
        // closed rather than write past its buffer if ever called with one
        // anyway.
        let too_long = vec![b'a'; MAX_AUTHORITY_BYTES + 1];
        let mut out = [0u8; HOST_KEY_BUF_BYTES];
        assert_eq!(
            host_key(ListenerId(1), &too_long, &mut out),
            Err(AuthorityError::TooLong),
            "a host longer than MAX_AUTHORITY_BYTES must be TooLong"
        );

        // The buffer-sizing worst case `HOST_KEY_BUF_BYTES` (264) is sized
        // for: a single label exactly `MAX_AUTHORITY_BYTES` (255) bytes long,
        // which a legal request authority can present (see the 255-byte case
        // in `normalize_table` above). `host_key` writes 2 listener bytes +
        // 255 host bytes + 1 trailing separator = 258 bytes; at
        // `HOST_KEY_BUF_BYTES == 257` this legal, maximum-length,
        // single-label authority would become unroutable.
        let host_255 = vec![b'a'; MAX_AUTHORITY_BYTES];
        let mut out = [0u8; HOST_KEY_BUF_BYTES];
        let n = host_key(ListenerId(1), &host_255, &mut out)
            .expect("a 255-byte single-label host must fit HOST_KEY_BUF_BYTES and be routable");
        assert_eq!(n, 2 + MAX_AUTHORITY_BYTES + 1);
        let mut expected = vec![0u8, 1];
        expected.extend_from_slice(&host_255);
        expected.push(b'.');
        assert_eq!(out.get(..n), Some(expected.as_slice()));
    }
}
