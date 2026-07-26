// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! SNI and certificate-name normalization, and the keyed hash the certificate
//! index looks names up by.
//!
//! [`normalize`] is the ONLY name normalization in the TLS subsystem: the
//! config compiler calls it on every configured certificate name and TLS
//! policy name, and the handshake path calls it on the SNI a peer presents,
//! through the exact same function. Traefik shipped three mTLS bypasses
//! (CVE-2026-32305, CVE-2026-48491, CVE-2026-53622) by having certificate
//! selection and TLS-policy selection disagree about what "the same name"
//! means, and Caddy shipped a fourth in the same family (CVE-2026-27588) by
//! silently switching a host matcher from case-insensitive to case-sensitive
//! comparison above a size threshold. One normalization function, with no
//! size threshold and no second code path, makes that class of bug
//! structurally impossible rather than merely true today.
//!
//! Every byte [`normalize`] reads comes from a `ClientHello` sent by an
//! unauthenticated peer before any handshake completes, so it never
//! allocates: it writes into a caller-owned `[u8; MAX_NAME_LEN]` stack buffer
//! instead of building an owned string. [`NameHasher`] hashes the normalized
//! result with keyed SipHash-1-3 rather than an unkeyed hash, because an
//! unkeyed hash lets a peer who controls the input compute colliding names
//! offline and force worst-case probe chains in the certificate index.
//!
//! This module performs no internationalized domain name handling: an
//! A-label (`xn--...`) is pure LDH and passes through unchanged, and a name
//! containing a non-ASCII byte is rejected rather than converted, because
//! IDNA `ToASCII` on the handshake path would need a Unicode table lookup and
//! an allocation.
//!
//! The `HOT PATH` marker above puts this whole file, every function in it,
//! under `scripts/invariant-lints.sh`'s `hot-path-allocation` and
//! `hot-path-lock` rules: a text scan of the entire production-code body for
//! every call that can allocate or lock, run in CI on every pull request.
//! That is a single, shared definition of what counts as an allocation
//! instead of a hand-rolled, per-crate reimplementation of the same
//! vocabulary. `no_allocations_in_normalize` in the test module below relies
//! on that scan rather than re-deriving it.

use siphasher::sip128::{Hasher128, SipHasher13};

/// The maximum length of a normalized DNS name, in bytes.
pub const MAX_NAME_LEN: usize = 253;

/// The maximum number of labels in a DNS name.
pub const MAX_LABELS: usize = 127;

/// Why a name was rejected. Carried into config-compile diagnostics; never returned to a peer.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum NameError {
    /// Zero bytes after stripping a trailing dot.
    Empty,
    /// More than 253 bytes after stripping a trailing dot.
    TooLong,
    /// More than 127 labels.
    TooManyLabels,
    /// A label was zero bytes (a doubled dot, a leading dot, or a doubled trailing dot).
    EmptyLabel,
    /// A label exceeded 63 bytes.
    LabelTooLong,
    /// A byte outside `[a-zA-Z0-9-]` appeared.
    IllegalByte,
    /// A label started or ended with `-`.
    HyphenAtLabelEdge,
}

impl core::fmt::Display for NameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            NameError::Empty => "name is empty",
            NameError::TooLong => "name exceeds 253 bytes",
            NameError::TooManyLabels => "name has more than 127 labels",
            NameError::EmptyLabel => "name contains an empty label",
            NameError::LabelTooLong => "name contains a label longer than 63 bytes",
            NameError::IllegalByte => "name contains a byte outside [a-zA-Z0-9-.]",
            NameError::HyphenAtLabelEdge => "name has a label starting or ending with '-'",
        })
    }
}

impl std::error::Error for NameError {}

/// Why a wildcard name was rejected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum WildcardError {
    /// The name does not start with `*.`.
    NotWildcard,
    /// The name contains `*` somewhere other than as a whole leftmost label.
    PartialWildcard,
}

impl core::fmt::Display for WildcardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            WildcardError::NotWildcard => "name is not a wildcard (no leading \"*.\")",
            WildcardError::PartialWildcard => {
                "partial wildcards are not supported; '*' must be the whole leftmost label"
            }
        })
    }
}

impl std::error::Error for WildcardError {}

/// A keyed 64-bit hash of a normalized DNS name. Two `NameKey` values are comparable only if
/// they were produced by the same [`NameHasher`].
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NameKey(u64);

impl NameKey {
    /// The raw hash value. Exposed for index bucketing only.
    ///
    /// This value MUST NOT be logged, exported as a metric label, placed in a response header,
    /// returned by the admin API, or otherwise made observable to a peer. It is a keyed hash of
    /// attacker-chosen input, and handing an attacker input/output pairs is the first step of a
    /// key-recovery attack that would restore the offline collision attack the keying prevents.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// `NameKey` deliberately does not implement `Display`, `Serialize`, or a `Debug` that prints the
/// hash. Its `Debug` renders the constant string `NameKey(<redacted>)` so that a `{:?}` on a
/// containing struct in a log line cannot leak it.
impl core::fmt::Debug for NameKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NameKey(<redacted>)")
    }
}

/// Keyed hasher for DNS names. Cheap to clone. Stored inside the certificate index so that
/// insert-time and lookup-time hashing provably use the same key.
///
/// No `Debug`, no `Display`, no `Serialize`: the key is secret.
#[derive(Clone)]
pub struct NameHasher {
    key: [u8; 16],
}

impl NameHasher {
    /// Build a hasher whose key is 16 fresh bytes from the operating system CSPRNG.
    ///
    /// This is the constructor production code uses. Call it once per certificate index and
    /// keep the result around (it is cheap to clone); do not call it per lookup, since reading
    /// the CSPRNG is a syscall.
    ///
    /// # Errors
    /// Returns [`irontraffic_rand::EntropyError`] when the operating system CSPRNG cannot be
    /// read. The caller MUST treat that as a fatal configuration error and MUST NOT fall back to
    /// a constant key: an index built with a known key is an index a peer can force into
    /// worst-case probe chains offline.
    pub fn from_entropy() -> Result<Self, irontraffic_rand::EntropyError> {
        let mut key = [0u8; 16];
        irontraffic_rand::SecureRng::fill(&mut key)?;
        Ok(Self { key })
    }

    /// Build a hasher from an explicit 16-byte key.
    ///
    /// `key` MUST be unpredictable to a peer: CSPRNG output, or an HKDF expansion of the cluster
    /// secret. Tests pass a fixed key. Non-test code passing a byte literal is a security defect,
    /// not a style problem.
    #[must_use]
    pub const fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    /// Hash an already-normalized name.
    ///
    /// The caller MUST pass the output of [`normalize`]. Passing a name that was not normalized
    /// is a logic error that produces a key nothing will ever match.
    #[must_use]
    pub fn hash(&self, normalized: &str) -> NameKey {
        let mut hasher = SipHasher13::new_with_key(&self.key);
        core::hash::Hasher::write(&mut hasher, normalized.as_bytes());
        let h128 = hasher.finish128();
        NameKey(h128.h1)
    }
}

/// Validates the label `b[label_start..end]`: non-empty, at most 63 bytes, and does not start or
/// end with a hyphen.
///
/// `label_start <= end <= b.len()` holds at every call site: `end` is either the index of a `.`
/// found by the same forward walk that last advanced `label_start`, or `b.len()` itself for the
/// final label. The `ok_or` below is defense in depth over that invariant, not a load-bearing
/// fallback: a caller-owned buffer over fully peer-controlled input must not depend on the
/// invariant being correct to stay memory safe.
fn validate_label(b: &[u8], label_start: usize, end: usize) -> Result<(), NameError> {
    let label = b.get(label_start..end).ok_or(NameError::TooLong)?;
    if label.is_empty() {
        return Err(NameError::EmptyLabel);
    }
    if label.len() > 63 {
        return Err(NameError::LabelTooLong);
    }
    if label.first() == Some(&b'-') || label.last() == Some(&b'-') {
        return Err(NameError::HyphenAtLabelEdge);
    }
    Ok(())
}

/// Normalize `raw` into `buf` and validate it.
///
/// Lowercases ASCII in place, strips exactly one trailing dot, and enforces every limit in
/// [`MAX_NAME_LEN`], [`MAX_LABELS`], the 63-byte label limit, LDH bytes only, and no hyphen at a
/// label edge. Never allocates: every write goes through a checked accessor into the caller's
/// stack buffer, so no reasoning about the length checks above it needs to be correct for this
/// function to stay memory safe.
///
/// # Errors
/// Returns the specific [`NameError`] for the first violation found, scanning left to right.
#[inline]
pub fn normalize<'b>(raw: &str, buf: &'b mut [u8; MAX_NAME_LEN]) -> Result<&'b str, NameError> {
    let all = raw.as_bytes();
    let b: &[u8] = if all.last() == Some(&b'.') {
        // Strip exactly one trailing dot, unconditionally, however many
        // trailing dots there are: "a.b.." becomes "a.b.", whose final
        // label is empty and fails in validate_label below. `all` is
        // non-empty here (its last byte was just read), so `all.len() - 1`
        // cannot underflow, and `get` still checks the range rather than
        // relying on that reasoning to stay memory safe.
        all.get(..all.len() - 1).ok_or(NameError::Empty)?
    } else {
        all
    };

    if b.is_empty() {
        return Err(NameError::Empty);
    }
    // The length check runs before the walk below, so an oversized input
    // costs O(1), not O(len): a peer cannot buy CPU with a long SNI.
    if b.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }

    let mut label_start = 0usize;
    let mut label_count = 0usize;

    for (i, &c) in b.iter().enumerate() {
        let out_byte = if c == b'.' {
            validate_label(b, label_start, i)?;
            label_count += 1;
            if label_count > MAX_LABELS {
                return Err(NameError::TooManyLabels);
            }
            label_start = i + 1;
            b'.'
        } else if c.is_ascii_uppercase() {
            c | 0x20
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' {
            c
        } else {
            // Every non-ASCII byte, every control byte, `_`, `*`, and
            // whitespace all land here.
            return Err(NameError::IllegalByte);
        };
        // `i < b.len() <= MAX_NAME_LEN == buf.len()` holds throughout this
        // loop, so this write is always in bounds; `get_mut` still checks
        // it rather than indexing, because a caller-owned stack buffer over
        // fully peer-controlled input must not depend on that reasoning
        // being correct to stay memory safe.
        let slot = buf.get_mut(i).ok_or(NameError::TooLong)?;
        *slot = out_byte;
    }

    validate_label(b, label_start, b.len())?;
    label_count += 1;
    if label_count > MAX_LABELS {
        return Err(NameError::TooManyLabels);
    }

    let written = buf.get(..b.len()).ok_or(NameError::TooLong)?;
    // The slice is pure ASCII by construction (every branch above either
    // writes a validated ASCII byte or returns an error first), so this
    // conversion cannot fail; the error is still mapped rather than
    // unwrapped.
    core::str::from_utf8(written).map_err(|_| NameError::IllegalByte)
}

/// The parent domain of an already-normalized name: everything after the first label.
///
/// `parent("a.b.c") == Some("b.c")`, `parent("c") == None`.
#[must_use]
pub fn parent(name: &str) -> Option<&str> {
    let dot = name.find('.')?;
    name.get(dot + 1..)
}

/// The parent domain of a wildcard entry such as `*.example.com`.
///
/// # Errors
/// `WildcardError::NotWildcard` if the name has no leading `*.`, and
/// `WildcardError::PartialWildcard` for any other placement of `*`.
pub fn wildcard_parent(raw: &str) -> Result<&str, WildcardError> {
    let Some(rest) = raw.strip_prefix("*.") else {
        return Err(if raw.contains('*') {
            WildcardError::PartialWildcard
        } else {
            WildcardError::NotWildcard
        });
    };
    if rest.contains('*') {
        return Err(WildcardError::PartialWildcard);
    }
    Ok(rest)
}

/// Count the labels in an already-normalized name.
///
/// Assumes `name` is the output of [`normalize`], which guarantees no leading dot, no trailing
/// dot, and no doubled dot, so the number of separating dots is exactly one less than the label
/// count.
#[must_use]
pub fn label_count(name: &str) -> usize {
    name.bytes().filter(|&c| c == b'.').count() + 1
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_LABELS, MAX_NAME_LEN, NameError, NameHasher, WildcardError, label_count, normalize,
        parent, wildcard_parent,
    };
    use proptest::prelude::*;

    /// A syntactically valid name of exactly `n` bytes, built from 3-byte labels.
    /// `gen_name(253)` yields "aaa.aaa.....a" with a final short label.
    fn gen_name(n: usize) -> String {
        let mut s = String::with_capacity(n);
        while s.len() < n {
            if !s.is_empty() {
                s.push('.');
            }
            for _ in 0..3usize.min(n - s.len()) {
                s.push('a');
            }
        }
        s.truncate(n);
        // A truncation can leave a trailing '.' or a trailing '-'; the 3-byte label
        // pattern never produces '-', and a trailing '.' is impossible because the
        // loop pushes '.' only when more bytes will follow.
        s
    }

    #[test]
    fn normalize_empty() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize("", &mut buf), Err(NameError::Empty));
        // NameError's Display is part of the public API (config-compile
        // diagnostics read it); pin its text here so a `fmt` body that
        // stops writing anything (for example one collapsed to a bare
        // `Ok(())`) cannot pass silently.
        assert_eq!(NameError::Empty.to_string(), "name is empty");
    }

    #[test]
    fn normalize_root_dot() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize(".", &mut buf), Err(NameError::Empty));
    }

    #[test]
    fn normalize_double_trailing_dot() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("example.com..", &mut buf),
            Err(NameError::EmptyLabel)
        );
    }

    #[test]
    fn normalize_leading_dot() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize(".example.com", &mut buf),
            Err(NameError::EmptyLabel)
        );
    }

    #[test]
    fn normalize_double_inner_dot() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize("a..b", &mut buf), Err(NameError::EmptyLabel));
    }

    #[test]
    fn normalize_single_label() {
        let mut buf = [0u8; MAX_NAME_LEN];
        let out = normalize("localhost", &mut buf).expect("localhost is a valid single label");
        assert_eq!(out, "localhost");
        assert_eq!(label_count(out), 1);
        assert_eq!(parent(out), None);
    }

    #[test]
    fn normalize_len_253_ok() {
        let name = gen_name(253);
        assert_eq!(name.len(), 253, "gen_name(253) must produce 253 bytes");
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize(&name, &mut buf), Ok(name.as_str()));
    }

    #[test]
    fn normalize_len_254_too_long() {
        let name = gen_name(254);
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize(&name, &mut buf), Err(NameError::TooLong));
    }

    #[test]
    fn normalize_253_plus_dot_ok() {
        let base = gen_name(253);
        let with_dot = format!("{base}.");
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize(&with_dot, &mut buf), Ok(base.as_str()));
    }

    #[test]
    fn normalize_label_63_ok() {
        let name = format!("{}.com", "a".repeat(63));
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize(&name, &mut buf), Ok(name.as_str()));
    }

    #[test]
    fn normalize_label_64_too_long() {
        let name = format!("{}.com", "a".repeat(64));
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize(&name, &mut buf), Err(NameError::LabelTooLong));
    }

    #[test]
    fn normalize_127_labels_ok() {
        let name = vec!["a"; 127].join(".");
        assert_eq!(name.len(), 253);
        let mut buf = [0u8; MAX_NAME_LEN];
        let out = normalize(&name, &mut buf).expect("127 single-byte labels fit in 253 bytes");
        assert_eq!(out, name.as_str());
        assert_eq!(label_count(out), MAX_LABELS);
    }

    #[test]
    fn normalize_128_labels_err() {
        let name = vec!["a"; 128].join(".");
        assert_eq!(name.len(), 255);
        let mut buf = [0u8; MAX_NAME_LEN];
        // The length check fires before labels are ever counted; see the
        // module doc and edge case 10 in the issue this module implements.
        assert_eq!(normalize(&name, &mut buf), Err(NameError::TooLong));
    }

    #[test]
    fn normalize_mixed_case() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize("EXAMPLE.CoM", &mut buf), Ok("example.com"));
    }

    #[test]
    fn normalize_underscore_rejected() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("_acme-challenge.example.com", &mut buf),
            Err(NameError::IllegalByte)
        );
    }

    #[test]
    fn normalize_hyphen_edges_rejected() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("-a.b", &mut buf),
            Err(NameError::HyphenAtLabelEdge)
        );
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("a-.b", &mut buf),
            Err(NameError::HyphenAtLabelEdge)
        );
    }

    #[test]
    fn normalize_a_label_passthrough() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("xn--bcher-kva.example", &mut buf),
            Ok("xn--bcher-kva.example")
        );
    }

    #[test]
    fn normalize_non_ascii_rejected() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("b\u{00fc}cher.example", &mut buf),
            Err(NameError::IllegalByte)
        );
    }

    #[test]
    fn normalize_ip_literal_ok() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(normalize("192.0.2.1", &mut buf), Ok("192.0.2.1"));
    }

    #[test]
    fn normalize_wildcard_rejected() {
        let mut buf = [0u8; MAX_NAME_LEN];
        assert_eq!(
            normalize("*.example.com", &mut buf),
            Err(NameError::IllegalByte)
        );
    }

    #[test]
    fn parent_walks_one_label() {
        assert_eq!(parent("a.b.c"), Some("b.c"));
        assert_eq!(parent("b.c"), Some("c"));
        assert_eq!(parent("c"), None);
    }

    #[test]
    fn wildcard_parent_cases() {
        assert_eq!(wildcard_parent("*.a.b"), Ok("a.b"));
        assert_eq!(wildcard_parent("a.b"), Err(WildcardError::NotWildcard));
        assert_eq!(wildcard_parent("*a.b"), Err(WildcardError::PartialWildcard));
        assert_eq!(
            wildcard_parent("a.*.b"),
            Err(WildcardError::PartialWildcard)
        );
        assert_eq!(wildcard_parent("*.b"), Ok("b"));
        // WildcardError's Display is part of the public API; pin its text
        // here so a `fmt` body that stops writing anything cannot pass
        // silently, the same reasoning as NameError's Display check in
        // normalize_empty above.
        assert_eq!(
            WildcardError::NotWildcard.to_string(),
            "name is not a wildcard (no leading \"*.\")"
        );
    }

    #[test]
    fn label_count_matches() {
        assert_eq!(label_count("a.b.c"), 3);
        assert_eq!(label_count("c"), 1);
    }

    #[test]
    fn hash_is_case_insensitive_via_normalize() {
        let h = NameHasher::new([7u8; 16]);
        let (mut b1, mut b2) = ([0u8; MAX_NAME_LEN], [0u8; MAX_NAME_LEN]);
        let a = normalize("EXAMPLE.com.", &mut b1).expect("valid");
        let b = normalize("example.com", &mut b2).expect("valid");
        assert_eq!(a, "example.com");
        assert_eq!(b, "example.com");
        assert_eq!(h.hash(a), h.hash(b));
    }

    #[test]
    fn different_keys_give_different_hashes() {
        let h0 = NameHasher::new([0u8; 16]);
        let h1 = NameHasher::new([1u8; 16]);
        assert_ne!(h0.hash("example.com"), h1.hash("example.com"));
        // Also compare through `as_u64`, the only accessor a `NameKey` has:
        // going through `NameKey`'s derived `PartialEq` alone never calls
        // it, so a bucketing bug that returns a constant from `as_u64`
        // could pass every other assertion in this module.
        assert_ne!(
            h0.hash("example.com").as_u64(),
            h1.hash("example.com").as_u64()
        );
    }

    #[test]
    fn from_entropy_keys_differ() {
        let h0 = NameHasher::from_entropy().expect("CSPRNG should provide entropy in tests");
        let h1 = NameHasher::from_entropy().expect("CSPRNG should provide entropy in tests");
        assert_ne!(h0.hash("example.com"), h1.hash("example.com"));
    }

    #[test]
    fn name_key_debug_is_redacted() {
        let key = NameHasher::new([7u8; 16]).hash("example.com");
        assert_eq!(format!("{key:?}"), "NameKey(<redacted>)");
    }

    /// The exact line `scripts/invariant-lints.sh`'s `hot_files` helper greps for
    /// (`grep -l '^//! HOT PATH'`) to decide which files its `hot-path-allocation`
    /// and `hot-path-lock` rules cover.
    const HOT_PATH_MARKER: &str = "//! HOT PATH";

    #[test]
    fn no_allocations_in_normalize() {
        // This issue's own design called for a process-wide counting
        // `#[global_allocator]` proving zero allocations across 10,000 calls to
        // `normalize` over "API.Example.COM.", "a.b", and a 253-byte name. That
        // does not compile in this tree: `GlobalAlloc` is declared as an `unsafe
        // trait`, so even a pure counter that forwards straight to
        // `std::alloc::System` needs the keyword this repository denies with no
        // exception an implementer may grant (AGENTS.md, and the `no-unsafe` rule
        // in `scripts/invariant-lints.sh`, which scans every tracked `.rs` file,
        // tests included, and has no escape hatch for this rule). A process-wide
        // global allocator is also unsound independent of that ban: it counts
        // allocations made by every other test thread running in parallel in the
        // same binary, which is exactly the flakiness a thread-local counter would
        // have been built to avoid, except the allocator itself cannot compile
        // here regardless.
        //
        // This module instead carries the `//! HOT PATH` marker, which puts the
        // whole file, normalize, parent, wildcard_parent, label_count and
        // NameHasher::hash, under scripts/invariant-lints.sh's
        // hot-path-allocation rule: an exhaustive text scan for every call that
        // can allocate, run on every pull request. That is a property of the
        // source text over every possible input, not a sample over 10,000 calls
        // through three fixed inputs. This test's only job is to guard against
        // the marker line itself being deleted, which would silently drop this
        // module out of that CI-enforced net.
        let source = include_str!("name.rs");
        assert!(
            source.lines().any(|line| line == HOT_PATH_MARKER),
            "crates/irontraffic-tls/src/name.rs must carry a line that is exactly \
             `{HOT_PATH_MARKER}` so scripts/invariant-lints.sh's hot-path-allocation \
             rule scans this module; without it, normalize and every function it \
             calls could allocate with nothing in this repository catching it"
        );
    }

    /// The DNS identity of `raw`, computed by a route that deliberately never
    /// calls [`normalize`]: strip one trailing dot, split on `.`, and
    /// ASCII-lowercase each label. Used only by `prop_dns_equal_iff_same_key`
    /// (issue #542) to check the anti-collision property against a second,
    /// independently written implementation instead of against `normalize`
    /// itself, since a check phrased in terms of the function under test
    /// cannot fail no matter what that function does. Unlike `normalize`
    /// this enforces no length limit, no label-count limit, no LDH byte
    /// class, and no hyphen-edge rule: none of that is needed to answer "is
    /// this the same DNS name", which is the only question this function
    /// exists to answer.
    fn independent_dns_identity(raw: &str) -> Vec<String> {
        let stripped = raw.strip_suffix('.').unwrap_or(raw);
        stripped.split('.').map(str::to_ascii_lowercase).collect()
    }

    #[test]
    fn normalize_unicode_confusables_rejected() {
        // Each character below is a Unicode confusable that a
        // `to_lowercase()`-based normalizer could fold onto an ASCII letter
        // or onto '.', creating exactly the certificate-identity collision
        // this module exists to prevent (see the module doc and issue
        // #542). `normalize` never calls `to_lowercase()` and only ever
        // accepts ASCII bytes, so every one of these must be rejected as
        // NameError::IllegalByte rather than silently folded. The first
        // three are the ones a `to_lowercase()`-based implementation
        // collides on.
        let confusables = [
            (
                '\u{212A}',
                "U+212A KELVIN SIGN folds to 'k' under to_lowercase()",
            ),
            (
                '\u{017F}',
                "U+017F LATIN SMALL LETTER LONG S folds to 's' under to_lowercase()",
            ),
            (
                '\u{0130}',
                "U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE folds toward 'i' under to_lowercase()",
            ),
            (
                '\u{FF21}',
                "U+FF21 FULLWIDTH LATIN CAPITAL LETTER A is confusable with 'a'",
            ),
            (
                '\u{3002}',
                "U+3002 IDEOGRAPHIC FULL STOP is confusable with '.'",
            ),
            (
                '\u{FF0E}',
                "U+FF0E FULLWIDTH FULL STOP is confusable with '.'",
            ),
        ];
        for (c, why) in confusables {
            let raw = format!("a{c}b.example.com");
            let mut buf = [0u8; MAX_NAME_LEN];
            assert_eq!(
                normalize(&raw, &mut buf),
                Err(NameError::IllegalByte),
                "{c:?} must be rejected rather than folded: {why}"
            );
        }
    }

    proptest! {
        #[test]
        fn prop_normalize_idempotent(raw in "[a-zA-Z0-9.-]{0,300}") {
            // Most strings from this alphabet are not valid names (a random
            // dot or hyphen placement fails some check), so the property is
            // conditioned on the first call succeeding rather than filtered
            // with prop_assume!: filtering here would reject the large
            // majority of generated cases and blow proptest's global reject
            // budget, whereas a plain `if let` just makes an invalid `raw`
            // vacuously satisfy the property, matching the same pattern
            // `irontraffic-router`'s own `normalize_authority` idempotence
            // test uses.
            let mut b1 = [0u8; MAX_NAME_LEN];
            if let Ok(n) = normalize(&raw, &mut b1) {
                let n_owned = n.to_owned();
                let mut b2 = [0u8; MAX_NAME_LEN];
                let second = normalize(&n_owned, &mut b2);
                prop_assert_eq!(second, Ok(n_owned.as_str()));
            }
        }

        #[test]
        fn prop_dns_equal_iff_same_key(
            valid in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?){0,4}",
            upper_mask in proptest::collection::vec(any::<bool>(), 0..60),
            trailing_dot in any::<bool>(),
            other in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?){0,4}",
        ) {
            let mut buf = [0u8; MAX_NAME_LEN];
            let Ok(base) = normalize(&valid, &mut buf) else {
                // `valid`'s generator only ever produces LDH labels that
                // start and end with an alphanumeric, so this should not
                // happen; if it ever does, there is nothing to check.
                return Ok(());
            };
            let base = base.to_owned();

            // A random case permutation plus an optional trailing dot: both
            // must normalize to the exact same bytes as the original.
            let mut permuted = String::with_capacity(base.len());
            for (i, c) in base.chars().enumerate() {
                let flip = upper_mask.get(i).copied().unwrap_or(false);
                if flip && c.is_ascii_lowercase() {
                    permuted.push(c.to_ascii_uppercase());
                } else {
                    permuted.push(c);
                }
            }
            if trailing_dot {
                permuted.push('.');
            }

            let mut buf2 = [0u8; MAX_NAME_LEN];
            let permuted_normalized = normalize(&permuted, &mut buf2)
                .expect("a case/dot permutation of a valid name must still normalize");
            prop_assert_eq!(permuted_normalized, base.as_str());

            let hasher = NameHasher::new([9u8; 16]);
            prop_assert!(hasher.hash(permuted_normalized) == hasher.hash(&base));

            // A statement about normalize, not about hash collisions: two
            // independently generated names that differ after normalization
            // must have different normalized forms. Hash inequality is never
            // asserted, because a hash collision between UNEQUAL names is not
            // a bug this module is responsible for ruling out.
            let mut buf3 = [0u8; MAX_NAME_LEN];
            let Ok(other_n) = normalize(&other, &mut buf3) else {
                // `other`'s generator uses the same alnum-edged, LDH-only
                // pattern as `valid`'s, so this should not happen; if it
                // ever does there is nothing to check, matching the `valid`
                // case above.
                return Ok(());
            };

            // The anti-collision property, checked against an identity
            // computed by a route that never calls `normalize`: strip one
            // trailing dot, split on '.', ASCII-lowercase each label. Issue
            // #542: the previous version of this check guarded the
            // assertion with its own negation (`if other_n != base { assert
            // other_n != base }`), which cannot fail for any input and so
            // tested nothing. Comparing `normalize`'s output to a second,
            // independently written notion of "the same DNS name" instead
            // means a future change to `normalize` that starts merging two
            // distinct names, or splitting one name into two, has something
            // in this suite that can actually fail.
            let same_normalized_form = other_n == base.as_str();
            let same_independent_identity =
                independent_dns_identity(&other) == independent_dns_identity(&valid);
            prop_assert_eq!(
                same_normalized_form,
                same_independent_identity,
                "normalize() and the independently computed DNS identity disagree \
                 about whether {other:?} and {valid:?} are the same name",
                other = other,
                valid = valid
            );
        }

        #[test]
        fn prop_parent_strictly_shrinks(
            valid in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?){0,4}"
        ) {
            let mut buf = [0u8; MAX_NAME_LEN];
            let Ok(n) = normalize(&valid, &mut buf) else {
                return Ok(());
            };

            if let Some(p) = parent(n) {
                prop_assert_eq!(label_count(p), label_count(n) - 1);
                prop_assert!(p.len() < n.len());
            }
        }

        #[test]
        fn prop_wildcard_never_matches_own_parent_or_grandchild(
            valid in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?){2,4}"
        ) {
            let mut buf = [0u8; MAX_NAME_LEN];
            let Ok(n) = normalize(&valid, &mut buf) else {
                return Ok(());
            };
            prop_assert!(label_count(n) >= 3);

            let p = parent(n).expect("a name with at least 3 labels has a parent");
            let w = format!("*.{p}");
            let w_parent = wildcard_parent(&w).expect("*.<parent> must parse as a wildcard");
            prop_assert_eq!(w_parent, p);

            let grandparent = parent(p);
            prop_assert_ne!(grandparent, Some(w_parent));
        }
    }
}
