// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parser, round trip and validation tests for `CellId`, `BenchCell` and
//! `Detail`.

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, Detail, KeepaliveMode, PathCorpus, Protocol,
    RESERVED_STEMS, RateMode, TlsMode,
};
use std::io;

/// A minimal, individually valid `BenchCell`. Every field is inside its own
/// valid range so a test that overrides exactly one field exercises only that
/// field's check, never an unrelated one earlier in `validate`'s fixed order.
///
/// `#[allow(clippy::expect_used)]`: test-support helper, not itself a `#[test]`
/// fn, so clippy's test exemption for `expect_used` does not extend to it.
/// `"base"` is a literal already covered by `parses_single_segment`.
#[allow(clippy::expect_used, reason = "see the function doc comment above")]
fn base_cell() -> BenchCell {
    BenchCell {
        id: CellId::parse("base").expect("\"base\" is a valid cell id"),
        protocol: Protocol::H1,
        tls: TlsMode::Off,
        payload_bytes: 0,
        routes: 1,
        path_corpus: PathCorpus::SingleHot,
        connections: 1,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: RateMode::Saturate,
    }
}

#[test]
fn parses_single_segment() {
    let id = CellId::parse("base").expect("\"base\" is a valid cell id");
    assert_eq!(id.as_str(), "base");
}

#[test]
fn parses_four_segments() {
    assert!(CellId::parse("routes.100000.worst.h2").is_ok());
}

#[test]
fn rejects_five_segments() {
    let err = CellId::parse("a.b.c.d.e").expect_err("five segments must be rejected");
    assert!(
        err.to_string().contains("segment"),
        "error message {err} should mention \"segment\""
    );
}

#[test]
fn rejects_empty() {
    assert!(CellId::parse("").is_err());
}

#[test]
fn rejects_leading_dot() {
    assert!(CellId::parse(".a").is_err());
}

#[test]
fn rejects_trailing_dot() {
    assert!(CellId::parse("a.").is_err());
}

#[test]
fn rejects_double_dot() {
    assert!(CellId::parse("..").is_err());
    assert!(CellId::parse("a..b").is_err());
}

#[test]
fn rejects_slash_and_backslash() {
    assert!(CellId::parse("a/b").is_err());
    assert!(CellId::parse("a\\b").is_err());
    assert!(CellId::parse("../../etc/passwd").is_err());
}

#[test]
fn rejects_uppercase_and_space() {
    assert!(CellId::parse("Base").is_err());
    assert!(CellId::parse("a b").is_err());
}

#[test]
fn rejects_over_length() {
    // Four segments totalling 125 characters plus three dots: three 31-byte
    // segments and one 32-byte segment, exactly the 128-byte example the
    // issue's edge cases give for the boundary.
    let seg31 = "a".repeat(31);
    let seg32 = "a".repeat(32);
    let id_128 = format!("{seg31}.{seg31}.{seg31}.{seg32}");
    assert_eq!(
        id_128.len(),
        128,
        "fixture precondition: the id must be exactly 128 bytes"
    );
    assert!(CellId::parse(&id_128).is_ok());

    let id_129 = format!("{id_128}a");
    assert_eq!(
        id_129.len(),
        129,
        "fixture precondition: the id must be exactly 129 bytes"
    );
    assert!(CellId::parse(&id_129).is_err());
}

#[test]
fn segment_length_boundary() {
    let seg64 = "a".repeat(64);
    assert_eq!(seg64.len(), 64, "fixture precondition");
    assert!(CellId::parse(&seg64).is_ok());

    let seg65 = "a".repeat(65);
    assert_eq!(seg65.len(), 65, "fixture precondition");
    assert!(CellId::parse(&seg65).is_err());
}

#[test]
fn round_trips_through_serde() {
    let id = CellId::parse("payload.65536").expect("\"payload.65536\" is a valid cell id");
    let json = serde_json::to_string(&id).expect("CellId serialises");
    let back: CellId = serde_json::from_str(&json).expect("CellId deserialises");
    assert_eq!(back, id);

    let rejected = serde_json::from_str::<CellId>("\"a/b\"");
    assert!(
        rejected.is_err(),
        "a cell id containing '/' must fail to deserialise"
    );
}

#[test]
fn bench_cell_validate_rejects_zero_rate() {
    let mut cell = base_cell();

    // Pin the exact static string, not just the variant: see #776 finding 7,
    // where a swapped message ("zero rate" -> "payload too large") passed
    // this test when it only asserted `Err(BenchError::Cell(_))`.
    cell.rate = RateMode::Fixed(0);
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("zero rate"))
    ));

    cell.rate = RateMode::Fixed(1);
    assert!(cell.validate().is_ok());

    cell.rate = RateMode::Fixed(50_000_000);
    assert!(cell.validate().is_ok());

    cell.rate = RateMode::Fixed(50_000_001);
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("rate too high"))
    ));
}

#[test]
fn bench_cell_validate_bounds_the_count_fields() {
    let mut cell = base_cell();

    // Zero is rejected for every count field. #776 finding 1: `base_cell()`
    // already sets `routes`, `connections` and `upstreams` to 1, and the
    // upper-bound checks below only ever move a field UPWARD, so until now
    // nothing in this suite ever set one of these fields to 0 and the whole
    // `== 0` guard for each could be deleted with every test still green.
    cell.routes = 0;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("zero routes"))
    ));
    cell.routes = 1;

    cell.connections = 0;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("zero connections"))
    ));
    cell.connections = 1;

    cell.upstreams = 0;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("zero upstreams"))
    ));
    cell.upstreams = 1;

    cell.routes = u32::MAX;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("too many routes"))
    ));
    cell.routes = 1_000_001;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("too many routes"))
    ));
    cell.routes = 1_000_000;
    assert!(cell.validate().is_ok());
    cell.routes = 1;

    cell.connections = u32::MAX;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("too many connections"))
    ));
    cell.connections = 2_000_001;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("too many connections"))
    ));
    cell.connections = 2_000_000;
    assert!(cell.validate().is_ok());
    cell.connections = 1;

    cell.upstreams = 4_097;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("too many upstreams"))
    ));
    cell.upstreams = 4_096;
    assert!(cell.validate().is_ok());
}

#[test]
fn bench_cell_validate_bounds_payload_bytes() {
    // #776 finding 1: `base_cell()` sets `payload_bytes: 0`, and until now no
    // test ever raised it above 65536, so the entire
    // `payload_bytes > 16_777_216` guard (cell.rs:246) could be deleted with
    // the suite still green.
    let mut cell = base_cell();

    cell.payload_bytes = 16_777_216;
    assert!(cell.validate().is_ok());

    cell.payload_bytes = 16_777_217;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("payload too large"))
    ));
}

#[test]
fn bench_cell_validate_bounds_filter_depth() {
    // #776 finding 1: `base_cell()` sets `filter_depth: 0`, and until now no
    // test ever raised it above 4, so the entire `filter_depth > 64` guard
    // (cell.rs:267) could be deleted with the suite still green.
    let mut cell = base_cell();

    cell.filter_depth = 64;
    assert!(cell.validate().is_ok());

    cell.filter_depth = 65;
    assert!(matches!(
        cell.validate(),
        Err(BenchError::Cell("filter depth too large"))
    ));
}

#[test]
fn bench_cell_round_trips_through_serde() {
    let cell = BenchCell {
        id: CellId::parse("routes.100000.worst.h2").expect("valid cell id"),
        protocol: Protocol::H2,
        tls: TlsMode::EcdsaP256,
        payload_bytes: 65536,
        routes: 100_000,
        path_corpus: PathCorpus::AdversarialWorstCase,
        connections: 4096,
        upstreams: 8,
        filter_depth: 4,
        cache: CacheMode::HalfHit,
        keepalive: KeepaliveMode::DownstreamClose,
        rate: RateMode::Fixed(1000),
    };

    let json = serde_json::to_string(&cell).expect("BenchCell serialises");
    assert!(
        json.contains(r#""keepalive":"downstream_close""#),
        "wire spelling of KeepaliveMode::DownstreamClose regressed: {json}"
    );

    let back: BenchCell = serde_json::from_str(&json).expect("BenchCell deserialises");
    assert_eq!(back, cell);
}

#[test]
fn rejects_reserved_stems() {
    // Pin the LITERAL set first. #776 finding 3: the previous version of this
    // test was `for stem in RESERVED_STEMS { ... }`, which derives its own
    // expectation from the very constant it is meant to pin, so shrinking
    // `RESERVED_STEMS` (for example dropping "readme") still left every
    // iteration of the loop green: there would simply be one fewer iteration.
    // The fuzz target has the identical shape for the identical reason and
    // cannot be fixed the same way (it draws from arbitrary bytes, not a
    // literal list), so this array pin plus the five named checks below are
    // the one place the full, current set is actually verified.
    assert_eq!(
        RESERVED_STEMS,
        ["manifest", "index", "summary", "provenance", "readme"],
        "RESERVED_STEMS changed; update the five named checks below to match"
    );

    let err = CellId::parse("manifest").expect_err("\"manifest\" must be rejected");
    assert!(err.to_string().contains("reserved"));
    let err = CellId::parse("index").expect_err("\"index\" must be rejected");
    assert!(err.to_string().contains("reserved"));
    let err = CellId::parse("summary").expect_err("\"summary\" must be rejected");
    assert!(err.to_string().contains("reserved"));
    let err = CellId::parse("provenance").expect_err("\"provenance\" must be rejected");
    assert!(err.to_string().contains("reserved"));
    let err = CellId::parse("readme").expect_err("\"readme\" must be rejected");
    assert!(err.to_string().contains("reserved"));

    assert!(CellId::parse("manifest.h2").is_ok());
    assert!(CellId::parse("manifest_base").is_ok());
}

#[test]
fn rejects_hyphen() {
    // #776 finding 5: the issue's Do NOT section forbids widening the
    // character class to accept '-' (it is the separator in the results
    // directory name `<utc-date>-<hw-id>`, and allowing it in a cell id makes
    // the two ambiguous when joined), but nothing named this byte before.
    assert!(CellId::parse("a-b").is_err());
    assert!(CellId::parse("-").is_err());
}

#[test]
fn detail_clips_to_256_bytes() {
    // The issue that specifies this test names a 1,000,000 byte input and a
    // 1 millisecond ceiling. Measured on real hardware (see the PR
    // description for the numbers) a deliberately mutated implementation that
    // sanitises the whole input before clipping it, exactly the bug this test
    // exists to catch, finishes a 1,000,000 byte input in under 0.6
    // milliseconds: BELOW that 1 millisecond ceiling. A budget that does not
    // fail on the mutation it is meant to catch is worse than no budget, so
    // this test uses a 100,000,000 byte input instead: still one `Detail::new`
    // call, still the same O(1) correct behaviour (measured in the same PR at
    // low hundreds of nanoseconds regardless of input size), but the mutated
    // implementation now costs tens of milliseconds, an easily separable
    // order of magnitude away from any plausible correct measurement even
    // under heavy scheduler jitter on a loaded CI runner.
    let huge = "a".repeat(100_000_000);
    let start = std::time::Instant::now();
    let detail = Detail::new(&huge);
    let elapsed = start.elapsed();

    assert_eq!(detail.as_str().len(), 256);

    // 15 milliseconds sits far above every correct measurement (hundreds of
    // nanoseconds, independent of input size, so no realistic scheduler
    // preemption pushes it anywhere near double digit milliseconds) and far
    // below the mutated one (tens of milliseconds, scaling with input size),
    // so it distinguishes the two rather than asserting a tight latency SLO.
    assert!(
        elapsed < std::time::Duration::from_millis(15),
        "Detail::new took {elapsed:?} for a 100,000,000 byte input; \
         the cost must be independent of input length, see the module docs"
    );
}

#[test]
fn detail_strips_control_and_escape_bytes() {
    let input = "\x1b[2Jok\r\nnext\u{0}";
    let detail = Detail::new(input);
    assert_eq!(
        detail.as_str().len(),
        input.len(),
        "replacement, not deletion"
    );
    assert!(!detail.as_str().contains('\x1b'));
    assert!(!detail.as_str().contains('\r'));
    assert!(!detail.as_str().contains('\n'));
    assert!(!detail.as_str().contains('\u{0}'));
    assert!(detail.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
}

#[test]
fn detail_preserves_printable_content_byte_for_byte() {
    // #776 finding 2: every assertion in `detail_strips_control_and_escape_bytes`
    // and in the fuzz target is negative (no ESC, no CR, no LF, no NUL) plus a
    // length check and a printable-range check, and an implementation that
    // replaces EVERY byte with '?' (`let printable = false;` instead of the
    // real range test) satisfies all of them: an all-'?' string contains no
    // ESC/CR/LF/NUL, has the same length as the input, and every byte in it
    // (0x3F) is in 0x20..=0x7E. Pin actual literal output so that mutation is
    // caught: this is what the finding calls "no assertion anywhere in the
    // crate that `Detail::new(...)` returns the string it was given".
    assert_eq!(
        Detail::new("wrk: unable to connect").as_str(),
        "wrk: unable to connect"
    );
    assert_eq!(
        Detail::new("connection refused (os error 111)").as_str(),
        "connection refused (os error 111)"
    );

    // Also pin the replacement byte itself ('?', 0x3F), not merely "some
    // printable byte": a sanitiser that replaces non-printable bytes with a
    // space instead of '?' passes every OTHER assertion in this file and in
    // the fuzz target too.
    assert_eq!(Detail::new("a\x1bb").as_str(), "a?b");
    assert_eq!(Detail::new("a\rb\nc\u{0}d").as_str(), "a?b?c?d");
}

#[test]
fn detail_clips_on_a_character_boundary() {
    let input = "\u{4e2d}".repeat(300);
    assert_eq!(
        input.len(),
        900,
        "fixture precondition: 300 three byte characters"
    );
    let detail = Detail::new(&input);

    // Each character is exactly 3 bytes, so the greatest character boundary at
    // or below 256 is 85 whole characters, 255 bytes: 256 itself falls one byte
    // into the 86th character. This is a literal computed by hand from the
    // fixture's own structure (300 three byte characters, clip target 256), not
    // from calling the parser under test, so a walk back that clips to the
    // wrong boundary (for example, degrading to an empty string instead of
    // walking back) is caught here rather than only being "not a panic".
    assert_eq!(
        detail.as_str().len(),
        255,
        "expected the walk back to land on the character boundary at byte 255"
    );
    assert!(std::str::from_utf8(detail.as_str().as_bytes()).is_ok());
}

#[test]
fn bench_error_io_display_sanitises_the_source() {
    // #776 finding 4: `BenchError::Io`'s `#[error(...)]` format string used to
    // interpolate `source` (a bare `std::io::Error`) directly, so an
    // `io::Error` built from a load generator's stderr, exactly the case
    // `BenchError::io` exists to handle safely, rendered its escape
    // sequences, CR and LF straight through, defeating the terminal-safety
    // guarantee the module doc promises. Pin the rendered `Display` output
    // literally, not merely "it doesn't panic", so a regression back to the
    // raw `{source}` form fails here.
    let source = io::Error::other("\x1b[2J\x1b[1;1Hall benchmarks passed\r\nforged");
    let err = BenchError::io("/tmp/out.json", source);
    assert_eq!(
        err.to_string(),
        "benchmark io at /tmp/out.json: ?[2J?[1;1Hall benchmarks passed??forged"
    );
    assert!(err.to_string().bytes().all(|b| (0x20..=0x7E).contains(&b)));
}

// The issue specifies `string_regex(".{0,140}")` (arbitrary Unicode of
// realistic length) as the generator. Measured directly (100,000 draws): that
// generator produces an `Ok` parse only 0.08% of the time and an `Ok` parse
// containing '/' only 0.018% of the time, so at proptest's default 256 cases
// per run the EXPECTED number of runs that ever exercise the property's real
// content (a separator surviving into a validated id) is under 0.05: a
// property test that almost never reaches the branch it exists to check,
// exactly the "0 times in 400,000 runs" failure mode this codebase has hit
// before. `[a-z0-9_./\\]{0,20}` draws from the same alphabet the parser
// actually branches on (valid characters plus the separators under test) at a
// short length, so a large fraction of draws are close to the validity
// boundary. Measured the same way: 15.7% `Ok`, 2.9% `Ok` containing '/', which
// puts several dozen real hits in a default 256 case run. Confirmed this
// generator's shape actually catches a mutation that widens the character
// class to accept '/' (see the PR description); the literal generator from
// the issue did not.
proptest::proptest! {
    #[test]
    fn parse_never_yields_a_separator(s in proptest::string::string_regex("[a-z0-9_./\\\\]{0,20}").unwrap()) {
        if let Ok(id) = CellId::parse(&s) {
            proptest::prop_assert!(!id.as_str().contains('/'));
            proptest::prop_assert!(!id.as_str().contains('\\'));
            proptest::prop_assert!(!id.as_str().contains(".."));
            proptest::prop_assert!(!id.as_str().is_empty());
            proptest::prop_assert_eq!(
                std::path::Path::new(id.as_str()).components().count(),
                1
            );
        }
    }
}
