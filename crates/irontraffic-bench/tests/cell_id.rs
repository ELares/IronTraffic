// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parser, round trip and validation tests for `CellId`, `BenchCell` and
//! `Detail`.

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, Detail, KeepaliveMode, PathCorpus, Protocol,
    RESERVED_STEMS, RateMode, TlsMode,
};

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

    cell.rate = RateMode::Fixed(0);
    assert!(matches!(cell.validate(), Err(BenchError::Cell(_))));

    cell.rate = RateMode::Fixed(1);
    assert!(cell.validate().is_ok());

    cell.rate = RateMode::Fixed(50_000_000);
    assert!(cell.validate().is_ok());

    cell.rate = RateMode::Fixed(50_000_001);
    assert!(matches!(cell.validate(), Err(BenchError::Cell(_))));
}

#[test]
fn bench_cell_validate_bounds_the_count_fields() {
    let mut cell = base_cell();

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
    for stem in RESERVED_STEMS {
        let err = CellId::parse(stem).expect_err("reserved stems must be rejected");
        assert!(
            err.to_string().contains("reserved"),
            "error message {err} should mention \"reserved\""
        );
    }
    assert!(CellId::parse("manifest.h2").is_ok());
    assert!(CellId::parse("manifest_base").is_ok());
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
