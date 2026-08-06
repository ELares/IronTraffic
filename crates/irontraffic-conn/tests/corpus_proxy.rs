// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `p:` half of `corpus/forwarded.txt`: `ProxyHeader::parse` lives in
//! `irontraffic-conn`, which depends on `irontraffic-http`, so this test
//! cannot live in `irontraffic-http` without inverting the dependency (see
//! `crates/irontraffic-http/tests/corpus.rs`'s own `forwarded` test, which
//! handles the `f:`/`x:` half of the SAME file and skips every `p:` line).
//!
//! The escape decoder and the line parser below are a deliberate,
//! documented duplicate of `corpus.rs`'s own copies (about 70 lines): cheap
//! for two consumers, and the duplication is bounded because the line
//! format is frozen.

#![allow(
    clippy::panic,
    reason = "this whole file is corpus-parsing test-support code; clippy's own test detection \
              only exempts a function literally attributed #[test], not the ordinary helper \
              functions every #[test] here calls, and the issue's own instructions require a \
              rich panic message (file, line, offset) naming exactly what went wrong rather than \
              a bare unwrap, which is the same shape every #[test] fn in this crate already uses \
              freely under clippy.toml's allow-panic-in-tests"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use irontraffic_conn::proxyproto::{ProxyError, ProxyHeader};
use irontraffic_http::ParseStatus;

/// Decodes the corpus escape syntax into bytes. Exactly six escapes: `\r`,
/// `\n`, `\t`, `\0`, `\\`, and `\xHH`. Anything else after a backslash is
/// an error.
fn unescape(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&byte) = bytes.get(i) {
        if byte != b'\\' {
            out.push(byte);
            i = i.saturating_add(1);
            continue;
        }
        let Some(&marker) = bytes.get(i.saturating_add(1)) else {
            return Err(format!("truncated escape at byte offset {i}"));
        };
        match marker {
            b'r' => {
                out.push(b'\r');
                i = i.saturating_add(2);
            }
            b'n' => {
                out.push(b'\n');
                i = i.saturating_add(2);
            }
            b't' => {
                out.push(b'\t');
                i = i.saturating_add(2);
            }
            b'0' => {
                out.push(0);
                i = i.saturating_add(2);
            }
            b'\\' => {
                out.push(b'\\');
                i = i.saturating_add(2);
            }
            b'x' => {
                let hi_raw = bytes.get(i.saturating_add(2));
                let lo_raw = bytes.get(i.saturating_add(3));
                let (Some(&hi_raw), Some(&lo_raw)) = (hi_raw, lo_raw) else {
                    return Err(format!("truncated \\x escape at byte offset {i}"));
                };
                let (Some(hi), Some(lo)) = (hex_digit(hi_raw), hex_digit(lo_raw)) else {
                    return Err(format!(
                        "invalid hex digits in \\x escape at byte offset {i}"
                    ));
                };
                out.push(hi.saturating_mul(16).saturating_add(lo));
                i = i.saturating_add(4);
            }
            other => {
                return Err(format!(
                    "unknown escape '\\{}' at byte offset {i}",
                    other as char
                ));
            }
        }
    }
    Ok(out)
}

/// The value of one ASCII hex digit, or `None` if `b` is not one.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// The exact expectation of one corpus entry: `ok`, `partial`, or a named
/// `ProxyError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Partial,
    Reject(ProxyError),
}

/// Parses an `<outcome>` field. Fails, naming the offending text, when it
/// is none of `ok`, `partial`, or a real `ProxyError` variant name.
fn parse_outcome(name: &str, line_no: usize) -> Outcome {
    match name {
        "ok" => Outcome::Ok,
        "partial" => Outcome::Partial,
        other => ProxyError::ALL
            .into_iter()
            .find(|e| format!("{e:?}") == other)
            .map_or_else(
                || {
                    panic!(
                        "forwarded.txt:{line_no}: unknown outcome name {other:?}; valid names \
                         are `ok`, `partial`, or one of the 10 ProxyError variant names"
                    )
                },
                Outcome::Reject,
            ),
    }
}

/// One parsed corpus line.
struct Entry<'a> {
    line_no: usize,
    outcome_field: &'a str,
    bytes_field: &'a str,
    /// The optional third tab-separated field: for an `ok` `p:` row, the
    /// expected `consumed` value, the byte offset where the PROXY header
    /// ends and the forwarded HTTP stream begins.
    extra: Option<&'a str>,
}

impl Entry<'_> {
    fn decode_bytes(&self) -> Vec<u8> {
        unescape(self.bytes_field).unwrap_or_else(|e| panic!("forwarded.txt:{}: {e}", self.line_no))
    }

    fn outcome(&self) -> Outcome {
        parse_outcome(self.outcome_field, self.line_no)
    }

    fn locator(&self) -> String {
        format!("forwarded.txt:{}: {:?}", self.line_no, self.bytes_field)
    }
}

/// Parses `corpus/forwarded.txt`'s content into entries. Comment lines
/// (`#`) and empty lines are skipped. A line with no tab fails with the
/// line number and an explanatory message.
fn parse_entries(text: &str) -> Vec<Entry<'_>> {
    let mut out = Vec::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        if raw_line.is_empty() || raw_line.starts_with('#') {
            continue;
        }
        let mut parts = raw_line.split('\t');
        let outcome_field = parts
            .next()
            .unwrap_or_else(|| panic!("forwarded.txt:{line_no}: expected `<outcome><TAB><bytes>`"));
        let Some(bytes_field) = parts.next() else {
            panic!("forwarded.txt:{line_no}: expected `<outcome><TAB><bytes>`");
        };
        let extra = parts.next();
        out.push(Entry {
            line_no,
            outcome_field,
            bytes_field,
            extra,
        });
    }
    out
}

/// The path to `corpus/forwarded.txt`, resolved from `CARGO_MANIFEST_DIR`
/// so the tests work under `cargo test` from anywhere in the workspace.
fn corpus_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("forwarded.txt")
}

/// Reads and parses `corpus/forwarded.txt`.
fn read_entries() -> Vec<Entry<'static>> {
    let path = corpus_path();
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    parse_entries(Box::leak(text.into_boxed_str()))
}

// ---------------------------------------------------------------------------
// Test 9: proxy.
// ---------------------------------------------------------------------------

/// Iterates `corpus/forwarded.txt`, handling only `p:` lines through
/// `ProxyHeader::parse` and skipping `f:`/`x:` lines. Asserts it saw at
/// least one `p:` line.
#[test]
fn proxy() {
    let entries = read_entries();
    let mut saw_p = false;

    for entry in &entries {
        let decoded = entry.decode_bytes();
        let Some((&marker_byte, rest)) = decoded.split_first() else {
            panic!("{}: entry has no marker byte", entry.locator());
        };
        if marker_byte != b'p' {
            continue;
        }
        saw_p = true;

        let payload = rest.get(1..).unwrap_or(&[]); // rest[0] is the `:` after `p`.
        let outcome = entry.outcome();
        let result = ProxyHeader::parse(payload);
        match (outcome, result) {
            (Outcome::Ok, Ok(ParseStatus::Complete { consumed, .. })) => {
                // `consumed` is the desync boundary: it tells the caller
                // where the PROXY header stops and the forwarded HTTP
                // stream begins. An `ok` row with a third field pins it,
                // so a parser that accepts the header but reports the
                // wrong offset (and would hand the connection layer a
                // buffer beginning mid-stream) fails here rather than
                // passing on bare acceptance.
                if let Some(expected_field) = entry.extra {
                    let expected: usize = expected_field.parse().unwrap_or_else(|e| {
                        panic!(
                            "{}: extra field {expected_field:?} is not a valid consumed value: {e}",
                            entry.locator()
                        )
                    });
                    assert_eq!(
                        consumed,
                        expected,
                        "{}: expected consumed {expected}, got {consumed}",
                        entry.locator()
                    );
                }
            }
            (Outcome::Partial, Ok(ParseStatus::Partial)) => {}
            (Outcome::Reject(want), Err(got)) => assert_eq!(want, got, "{}", entry.locator()),
            (expected, got) => panic!("{}: expected {expected:?}, got {got:?}", entry.locator()),
        }
    }

    assert!(
        saw_p,
        "forwarded.txt has no p: entries; marker handling may be broken"
    );
}

// ---------------------------------------------------------------------------
// Test 10: proxy_error_coverage.
// ---------------------------------------------------------------------------

/// The `ProxyError` variants a real `p:` corpus entry produces.
const REQUIRED_PROXY: [ProxyError; 4] = [
    ProxyError::NotAProxyHeader,
    ProxyError::V1BareLf,
    ProxyError::V1LineTooLong,
    ProxyError::V2BadVersion,
];

/// The 6 `ProxyError` variants no `p:` corpus entry reaches at this
/// milestone, each with the one-line reason why.
const EXCLUDED_PROXY: [ProxyError; 6] = [
    ProxyError::V1BadProtocol, // no p: row carries an unrecognized v1 protocol token
    ProxyError::V1BadField,    // no p: row carries a malformed v1 address or port field
    ProxyError::V2BadCommand, // no p: row carries a v2 command nibble that is neither LOCAL nor PROXY
    ProxyError::V2BadFamily,  // no p: row carries an unrecognized v2 family/protocol byte
    ProxyError::V2LengthTooSmall, // no p: row declares a v2 length too small for its family's address block
    ProxyError::V2BadTlv, // no p: row carries a v2 TLV whose declared length runs past the address block
];

/// Asserts every one of the 10 `ProxyError` variants named in
/// `proxy-protocol-parser` (#43)'s `ALL` appears at least once as an
/// outcome, or is listed in `EXCLUDED_PROXY` with a one-line reason, that
/// the two lists are disjoint, and that they sum to 10.
#[test]
fn proxy_error_coverage() {
    assert_eq!(REQUIRED_PROXY.len(), 4);
    assert_eq!(EXCLUDED_PROXY.len(), 6);
    assert_eq!(REQUIRED_PROXY.len() + EXCLUDED_PROXY.len(), 10);

    let mut seen = [false; 10];
    for e in REQUIRED_PROXY {
        let idx = ProxyError::ALL
            .iter()
            .position(|&x| x == e)
            .unwrap_or_else(|| panic!("{e:?} in REQUIRED_PROXY is not a real ProxyError variant"));
        assert!(
            !seen.get(idx).copied().unwrap_or(true),
            "{e:?} appears more than once in REQUIRED_PROXY"
        );
        if let Some(slot) = seen.get_mut(idx) {
            *slot = true;
        }
    }
    for e in EXCLUDED_PROXY {
        let idx = ProxyError::ALL
            .iter()
            .position(|&x| x == e)
            .unwrap_or_else(|| panic!("{e:?} in EXCLUDED_PROXY is not a real ProxyError variant"));
        assert!(
            !seen.get(idx).copied().unwrap_or(true),
            "{e:?} appears in both REQUIRED_PROXY and EXCLUDED_PROXY"
        );
        if let Some(slot) = seen.get_mut(idx) {
            *slot = true;
        }
    }
    assert!(
        seen.iter().all(|&b| b),
        "REQUIRED_PROXY and EXCLUDED_PROXY together do not cover every ProxyError variant"
    );

    let entries = read_entries();
    let mut outcomes: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &entries {
        outcomes.insert(entry.outcome_field.to_owned());
    }

    let missing: Vec<String> = REQUIRED_PROXY
        .into_iter()
        .map(|e| format!("{e:?}"))
        .filter(|name| !outcomes.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "REQUIRED_PROXY variants absent from forwarded.txt: {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 11: emit_proxy_fuzz_seeds.
// ---------------------------------------------------------------------------

/// The same guarded emitter `corpus.rs` describes, writing only
/// `crates/irontraffic-conn/fuzz/corpus/fuzz_proxyproto/`: a no-op unless
/// `IRONTRAFFIC_EMIT_FUZZ_SEEDS` is set, and idempotent (running it twice
/// produces byte-identical files).
#[test]
fn emit_proxy_fuzz_seeds() {
    if env::var("IRONTRAFFIC_EMIT_FUZZ_SEEDS").is_err() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("fuzz_proxyproto");
    fs::create_dir_all(&root).unwrap_or_else(|e| panic!("creating {root:?}: {e}"));

    let entries = read_entries();
    let mut count = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let decoded = entry.decode_bytes();
        let Some((&marker_byte, rest)) = decoded.split_first() else {
            continue;
        };
        if marker_byte != b'p' {
            continue;
        }
        let payload = rest.get(1..).unwrap_or(&[]);
        let file_path = root.join(format!("{}-{index:04}", entry.outcome_field));
        fs::write(&file_path, payload)
            .unwrap_or_else(|e| panic!("writing fuzz seed {file_path:?}: {e}"));
        count = count.saturating_add(1);
    }

    assert!(
        count > 0,
        "emit_proxy_fuzz_seeds wrote nothing into fuzz_proxyproto"
    );
}
