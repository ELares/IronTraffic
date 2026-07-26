// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two class tables that decide whether a field name and a field value
//! are acceptable, plus [`validate_name`], [`validate_value`], the OWS
//! trimmer [`trim_ows`] and the version-aware name normalizer
//! [`normalize_name_into`].
//!
//! Applied identically to HTTP/1, HTTP/2 and HTTP/3 ingress (RFC 9113
//! Section 8.2.1): a field that one protocol path accepts and another
//! rejects is a request-smuggling primitive.
//!
//! `_` is a legal RFC 9110 `tchar`, so refusing it in a field name (see
//! [`validate_name`] and [`RejectReason::FieldNameUnderscore`]) is a
//! deliberate extra rule, not a consequence of the token set: NGINX, CGI and
//! PHP fold `-` and `_` together while Go does not, so an unstripped
//! `X_Forwarded_User` can reach a backend as `X-Forwarded-User` and override
//! an identity header this proxy set (Traefik CVE-2026-54763).

use crate::error::RejectReason;
use crate::scalar::WireVersion;

/// True for bytes that may appear in a canonical (lowercased) field name.
/// This is RFC 9110 Section 5.1 `token` minus `A`..=`Z`.
static NAME_OK: [bool; 256] = build_name_ok();

/// True for bytes that may appear inside a field value.
/// False for exactly NUL, LF and CR.
static VALUE_OK: [bool; 256] = build_value_ok();

/// The 51 bytes legal in a canonical field name, as a literal, so the table
/// builder and the test that counts entries cannot drift apart.
const NAME_BYTES: [u8; 51] = *b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz";
const _: () = assert!(NAME_BYTES.len() == 51);

// The two `#[allow]`s below are the standing exception defined in
// `http-crate-foundation-types` (#22): a `const fn` cannot call `<[T]>::get`,
// and a `u8` index into a 256-element array is total by the type. Scoped to
// exactly this construct (a `[T; 256]` table indexed by a `u8`, its builder,
// and its accessor) and to no other site.
#[allow(
    clippy::indexing_slicing,
    reason = "total by construction, u8 index into a [_; 256]"
)]
const fn build_name_ok() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0usize;
    while i < NAME_BYTES.len() {
        t[NAME_BYTES[i] as usize] = true;
        // Not `i += 1`: this crate carries `#![deny(clippy::arithmetic_side_effects)]`
        // because it parses attacker-controlled bytes, and that deny reaches every
        // `const fn` in the crate, not only ones touching network input. `i` is a
        // bounded loop counter (i < NAME_BYTES.len() == 51), so this never actually
        // saturates; the method form is what keeps the lint from firing on an
        // ordinary `+=`.
        i = i.saturating_add(1);
    }
    t
}

#[allow(
    clippy::indexing_slicing,
    reason = "total by construction, u8 index into a [_; 256]"
)]
const fn build_value_ok() -> [bool; 256] {
    let mut t = [true; 256];
    t[0x00] = false;
    t[0x0A] = false;
    t[0x0D] = false;
    t
}

/// What to do with `_` in a field name at ingress.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UnderscorePolicy {
    /// Refuse the field. The default, matching NGINX `underscores_in_headers off`.
    Reject,
    /// Map `_` to `-` before any comparison, so an underscore variant cannot
    /// survive a strip of the hyphen form (Traefik CVE-2026-54763).
    ///
    /// This makes two distinct wire names collapse to one canonical name. A section in
    /// which two field lines with different wire bytes normalize to the same canonical
    /// name is refused by `FieldSection::push` in `field-section-and-known-headers` (#24);
    /// without that check an attacker-authored `X_Forwarded_For` line is combined with a
    /// trusted `X-Forwarded-For` line as if one hop had written both.
    MapToHyphen,
}

impl Default for UnderscorePolicy {
    /// `Reject`.
    fn default() -> Self {
        UnderscorePolicy::Reject
    }
}

/// Validates a field name that is already in canonical (lowercase, `-` separated) form.
///
/// Applied identically to HTTP/1, HTTP/2 and HTTP/3. On HTTP/1 the caller MUST have
/// lowercased the name first with `normalize_name_into`; on HTTP/2 and HTTP/3 an
/// uppercase byte is malformed and is reported as `FieldNameUppercase`.
///
/// # Errors
/// `FieldNameEmpty`, `FieldNameUppercase`, `FieldNameUnderscore`, `FieldNameInvalidByte`.
#[allow(
    unused_variables,
    reason = "the uppercase check (step 2a) and the underscore check (step 2b) are both \
              deliberately version independent by design (issue #23's edge case 3 spells \
              this out for uppercase; the same reasoning applies to underscore, since a \
              caller bug that lets either byte reach this function must be named precisely \
              rather than folded into a generic invalid-byte reason on some versions and \
              not others). version is therefore never read here; it stays in the signature \
              to match validate_value, which does read it"
)]
pub fn validate_name(name: &[u8], version: WireVersion) -> Result<(), RejectReason> {
    if name.is_empty() {
        return Err(RejectReason::FieldNameEmpty);
    }
    for &b in name {
        if b.is_ascii_uppercase() {
            return Err(RejectReason::FieldNameUppercase);
        }
        if b == b'_' {
            return Err(RejectReason::FieldNameUnderscore);
        }
        if !name_byte_ok(b) {
            return Err(RejectReason::FieldNameInvalidByte);
        }
    }
    Ok(())
}

/// Validates a field value.
///
/// Rejects NUL, LF and CR anywhere. On HTTP/2 and HTTP/3 additionally rejects a
/// leading or trailing SP or HTAB. An empty value is valid on every version.
///
/// # Errors
/// `FieldValueInvalidByte`, `FieldValueLeadingWhitespace`, `FieldValueTrailingWhitespace`.
pub fn validate_value(value: &[u8], version: WireVersion) -> Result<(), RejectReason> {
    for &b in value {
        if !value_byte_ok(b) {
            return Err(RejectReason::FieldValueInvalidByte);
        }
    }
    if version.is_multiplexed() {
        if value.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Err(RejectReason::FieldValueLeadingWhitespace);
        }
        if value.last().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Err(RejectReason::FieldValueTrailingWhitespace);
        }
    }
    Ok(())
}

/// Removes leading and trailing SP (0x20) and HTAB (0x09), and nothing else.
///
/// This is HTTP OWS. It is NOT `str::trim`, which also removes U+00A0, U+2028 and
/// every other Unicode whitespace character.
#[must_use]
pub fn trim_ows(value: &[u8]) -> &[u8] {
    let is_ows = |b: u8| b == b' ' || b == b'\t';
    let start = value
        .iter()
        .position(|&b| !is_ows(b))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|&b| !is_ows(b))
        .map_or(start, |i| i.saturating_add(1));
    value.get(start..end).unwrap_or(&[])
}

/// Lowercases `raw` into `out`, applying `policy` to `_`.
///
/// Writes exactly `raw.len()` bytes on success. On ANY error the contents of `out` are
/// unspecified: this function writes as it walks, so an error at byte 40 leaves 40 bytes
/// written. The caller MUST discard `out` on error and MUST NOT use a prefix of it as a
/// shorter name.
///
/// # Errors
/// `FieldNameUnderscore` if `policy` is `Reject` and the name contains `_`.
/// `FieldNameInvalidByte` if `out` is shorter than `raw`.
pub fn normalize_name_into(
    raw: &[u8],
    policy: UnderscorePolicy,
    out: &mut [u8],
) -> Result<usize, RejectReason> {
    if out.len() < raw.len() {
        return Err(RejectReason::FieldNameInvalidByte);
    }
    for (dst, &b) in out.iter_mut().zip(raw.iter()) {
        let mut b2 = b.to_ascii_lowercase();
        if b2 == b'_' {
            match policy {
                UnderscorePolicy::Reject => return Err(RejectReason::FieldNameUnderscore),
                UnderscorePolicy::MapToHyphen => b2 = b'-',
            }
        }
        *dst = b2;
    }
    Ok(raw.len())
}

/// True when `b` may appear in a canonical field name.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "total by construction, u8 index into a [_; 256]"
)]
pub const fn name_byte_ok(b: u8) -> bool {
    NAME_OK[b as usize]
}

/// True when `b` may appear inside a field value.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "total by construction, u8 index into a [_; 256]"
)]
pub const fn value_byte_ok(b: u8) -> bool {
    VALUE_OK[b as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: [WireVersion; 4] = [
        WireVersion::Http10,
        WireVersion::Http11,
        WireVersion::H2,
        WireVersion::H3,
    ];

    fn any_wire_version() -> impl proptest::strategy::Strategy<Value = WireVersion> {
        proptest::sample::select(&VERSIONS[..])
    }

    #[test]
    fn name_ok_true_count_is_51() {
        // Exhaustive over the whole byte space, not a handful of samples: a
        // table pinned by only a few positive bytes can silently accept CR,
        // LF or NUL and every test built from a short sample list would stay
        // green.
        let mut count = 0usize;
        for b in 0..=255u8 {
            let expected = NAME_BYTES.contains(&b);
            assert_eq!(
                name_byte_ok(b),
                expected,
                "byte {b:#04x} disagrees with NAME_BYTES"
            );
            if expected {
                count += 1;
            }
        }
        assert_eq!(count, 51);
    }

    #[test]
    fn value_ok_true_count_is_253() {
        let mut count = 0usize;
        for b in 0..=255u8 {
            let expected = !matches!(b, 0x00 | 0x0A | 0x0D);
            assert_eq!(
                value_byte_ok(b),
                expected,
                "byte {b:#04x} disagrees with the value table"
            );
            if expected {
                count += 1;
            }
        }
        assert_eq!(count, 253);
    }

    #[test]
    fn name_table_is_subset_of_value_table() {
        for b in 0..=255u8 {
            if name_byte_ok(b) {
                assert!(
                    value_byte_ok(b),
                    "byte {b:#04x} is a name byte but not a value byte"
                );
            }
        }
    }

    /// Not one of the sixteen named tests: this pins `NAME_OK` against
    /// `scalar::is_tchar` over the whole byte space, so the crate's single
    /// `tchar` grammar (`scalar::is_tchar`'s own doc comment names this file
    /// as the reason it is `pub(crate)`) and this file's table cannot drift
    /// apart silently. `NAME_OK` is `tchar` minus uppercase by definition.
    #[test]
    fn name_ok_matches_is_tchar_minus_uppercase() {
        for b in 0..=255u8 {
            let expected = crate::scalar::is_tchar(b) && !b.is_ascii_uppercase();
            assert_eq!(
                name_byte_ok(b),
                expected,
                "byte {b:#04x}: NAME_OK disagrees with is_tchar(b) && !uppercase"
            );
        }
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert_eq!(
            validate_name(b"", WireVersion::Http11),
            Err(RejectReason::FieldNameEmpty)
        );
    }

    #[test]
    fn validate_name_rejects_uppercase_on_every_version() {
        for ver in VERSIONS {
            assert_eq!(
                validate_name(b"Host", ver),
                Err(RejectReason::FieldNameUppercase),
                "{ver:?}"
            );
        }
    }

    #[test]
    fn validate_name_rejects_delimiters() {
        let invalid_byte_cases: [&[u8]; 11] = [
            b"a:b", b"a b", b"a\tb", b"a\rb", b"a\nb", b"a\0b", b"a\x7fb", b"a\xffb", b"a,b",
            b"a(b", b"a/b",
        ];
        for case in invalid_byte_cases {
            assert_eq!(
                validate_name(case, WireVersion::Http11),
                Err(RejectReason::FieldNameInvalidByte),
                "{case:?}"
            );
        }
        assert_eq!(
            validate_name(b"a_b", WireVersion::Http11),
            Err(RejectReason::FieldNameUnderscore)
        );
    }

    #[test]
    fn validate_name_accepts_canonical_names() {
        let names: [&[u8]; 6] = [
            b"host",
            b"content-type",
            b"x-forwarded-for",
            b"a",
            b"sec-ch-ua-mobile",
            b"if-none-match",
        ];
        for name in names {
            assert_eq!(validate_name(name, WireVersion::Http11), Ok(()), "{name:?}");
        }
    }

    #[test]
    fn validate_value_rejects_ctl() {
        let cases: [&[u8]; 6] = [b"a\0b", b"a\rb", b"a\nb", b"\r", b"\n", b"ab\0"];
        for case in cases {
            for ver in [WireVersion::Http11, WireVersion::H2] {
                assert_eq!(
                    validate_value(case, ver),
                    Err(RejectReason::FieldValueInvalidByte),
                    "{case:?} on {ver:?}"
                );
            }
        }
    }

    #[test]
    fn validate_value_whitespace_by_version() {
        assert_eq!(validate_value(b" x", WireVersion::Http11), Ok(()));
        assert_eq!(validate_value(b"x ", WireVersion::Http11), Ok(()));
        assert_eq!(validate_value(b"\tx", WireVersion::Http11), Ok(()));
        assert_eq!(validate_value(b"x\t", WireVersion::Http11), Ok(()));

        for ver in [WireVersion::H2, WireVersion::H3] {
            assert_eq!(
                validate_value(b" x", ver),
                Err(RejectReason::FieldValueLeadingWhitespace),
                "{ver:?}"
            );
            assert_eq!(
                validate_value(b"\tx", ver),
                Err(RejectReason::FieldValueLeadingWhitespace),
                "{ver:?}"
            );
            assert_eq!(
                validate_value(b"x ", ver),
                Err(RejectReason::FieldValueTrailingWhitespace),
                "{ver:?}"
            );
            assert_eq!(
                validate_value(b"x\t", ver),
                Err(RejectReason::FieldValueTrailingWhitespace),
                "{ver:?}"
            );
        }

        for ver in VERSIONS {
            assert_eq!(validate_value(b"x y", ver), Ok(()), "{ver:?}");
            assert_eq!(validate_value(b"", ver), Ok(()), "{ver:?}");
        }
    }

    #[test]
    fn validate_value_accepts_obs_text() {
        assert_eq!(validate_value(b"caf\xc3\xa9", WireVersion::Http11), Ok(()));
        assert_eq!(validate_value(b"a\xffb", WireVersion::Http11), Ok(()));
    }

    #[test]
    fn trim_ows_exact() {
        assert_eq!(trim_ows(b"  x  "), b"x");
        assert_eq!(trim_ows(b"\t\tx\t"), b"x");
        assert_eq!(trim_ows(b"   "), b"");
        assert_eq!(trim_ows(b""), b"");
        assert_eq!(trim_ows(b"\xc2\xa0x"), b"\xc2\xa0x");
        assert_eq!(trim_ows(b"x\ny"), b"x\ny");
    }

    #[test]
    fn normalize_name_lowercases_and_maps() {
        let mut out = [0u8; 32];
        let n = normalize_name_into(b"X-Forwarded-For", UnderscorePolicy::Reject, &mut out)
            .expect("well formed name should normalize");
        assert_eq!(&out[..n], b"x-forwarded-for");

        let mut out2 = [0u8; 32];
        assert_eq!(
            normalize_name_into(b"X_Forwarded_For", UnderscorePolicy::Reject, &mut out2),
            Err(RejectReason::FieldNameUnderscore)
        );

        let mut out3 = [0u8; 32];
        let n3 = normalize_name_into(b"X_Forwarded_For", UnderscorePolicy::MapToHyphen, &mut out3)
            .expect("MapToHyphen should normalize an underscore name");
        assert_eq!(&out3[..n3], b"x-forwarded-for");

        let mut out4 = [0u8; 1];
        assert_eq!(
            normalize_name_into(b"X-Forwarded-For", UnderscorePolicy::Reject, &mut out4),
            Err(RejectReason::FieldNameInvalidByte)
        );
    }

    #[test]
    fn normalize_name_error_output_is_not_a_name() {
        let mut out = [0xEEu8; 8];
        let result = normalize_name_into(b"x-a_b", UnderscorePolicy::Reject, &mut out);
        assert_eq!(result, Err(RejectReason::FieldNameUnderscore));
        assert!(
            result.is_err(),
            "an Err here must never be mistaken for an Ok(3) short name"
        );
        assert_eq!(&out[..3], b"x-a", "bytes written before the error stand");
        assert_eq!(
            out[3], 0xEE,
            "the byte that triggered the error must not have been written"
        );
    }

    #[test]
    fn desync_bytes_are_refused_where_they_matter() {
        assert_eq!(validate_value(b"\x0bchunked", WireVersion::Http11), Ok(()));
        assert_eq!(validate_value(b"chunked\x0c", WireVersion::Http11), Ok(()));
        assert_eq!(
            validate_value(b"chunked\r\n x", WireVersion::Http11),
            Err(RejectReason::FieldValueInvalidByte)
        );
    }

    proptest::proptest! {
        #[test]
        fn prop_validate_never_panics(
            v in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=512),
            ver in any_wire_version(),
        ) {
            if validate_name(&v, ver).is_ok() {
                assert!(!v.is_empty());
                assert!(v.iter().all(|b| NAME_BYTES.contains(b)));
                assert!(!v.contains(&b'_'));
            }
            if validate_value(&v, ver).is_ok() {
                assert!(!v.contains(&0x00));
                assert!(!v.contains(&0x0A));
                assert!(!v.contains(&0x0D));
                if ver.is_multiplexed() {
                    assert!(!v.first().is_some_and(|&b| b == b' ' || b == b'\t'));
                    assert!(!v.last().is_some_and(|&b| b == b' ' || b == b'\t'));
                }
            }
        }

        #[test]
        fn prop_trim_ows_is_a_subslice(
            v in proptest::collection::vec(
                proptest::prop_oneof![
                    proptest::prelude::Just(b' '),
                    proptest::prelude::Just(b'\t'),
                    proptest::prelude::any::<u8>(),
                ],
                0..=64,
            ),
        ) {
            let trimmed = trim_ows(&v);
            assert!(trimmed.len() <= v.len());

            // Proves `trimmed` shares backing memory with `v` (a real
            // subslice), without unsafe: a pointer-to-integer cast never
            // dereferences anything and is safe under `#![forbid(unsafe_code)]`.
            let v_start = v.as_ptr() as usize;
            let v_end = v_start.saturating_add(v.len());
            let t_start = trimmed.as_ptr() as usize;
            let t_end = t_start.saturating_add(trimmed.len());
            assert!(t_start >= v_start && t_end <= v_end && t_start <= t_end);

            assert_eq!(trim_ows(trimmed), trimmed);
        }
    }
}
