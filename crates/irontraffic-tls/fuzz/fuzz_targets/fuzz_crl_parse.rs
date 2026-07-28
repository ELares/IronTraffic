// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `crl::parse`, `crl::verify_signature`, and `RevocationIndex::build` plus
//! `is_revoked`: arbitrary bytes into the parser and index builder, per the issue that specifies
//! this module. Every byte fed in here is the same shape of input a CRL distribution point URL
//! hands the fetcher that has not been written yet (`mtls-client-auth-fail-closed`, #124): fully
//! attacker-influenced, up to hundreds of megabytes, and never trusted until its signature
//! verifies.
//!
//! **Three paths, exercised per input, each with its OWN counters.** `RevocationIndex::build`
//! accepts only `&VerifiedCrl<'_>`, and the only way to produce a `VerifiedCrl` from outside the
//! `irontraffic_tls::crl` module is `verify_signature` actually verifying a signature; there is
//! no test-only backdoor reachable from this crate, which is the module's whole point (see
//! `crl.rs`'s own doc comment: "verify before you spend O(r) memory" is a compile-time property,
//! not a review comment). A real RSA-PKCS1-SHA256 signature essentially never verifies against
//! uncorrelated random bytes, so a target that only ever calls `parse` on `data` and
//! conditionally calls `build` on the result would reach `build`'s O(r) collection, sort, dedup
//! and Bloom-fill logic close to never. So every input runs through three independent paths:
//!
//! - **Path A**: `data` itself, unmodified, straight into `parse`. This is the literal "arbitrary
//!   bytes into the parser" half of #123's own fuzz target description. Its realistic ceiling for
//!   `verify_ok` is zero regardless of corpus: this target's CA key pair is generated fresh every
//!   process start (see `fixture()`), so no seed file signed ahead of time can ever match it, and
//!   `parse` itself never checks the signature bytes at all. What a corpus CAN move is `parse_ok`:
//!   a structurally valid DER `CertificateList` (placeholder signature, no real key needed) that
//!   survives small mutations more often than random bytes do.
//! - **Path B**: a freshly, validly signed CRL whose revoked-serial list `data` chooses ("a small
//!   valid-CRL prefix plus fuzzer-controlled mutation"), which reliably reaches signature
//!   verification and `build`.
//! - **Path C**: path B's bytes with one fuzzer-chosen byte flipped, exploring the almost-valid
//!   manifold around a real signed CRL the same way `crl.rs`'s own `prop_parse_never_panics`
//!   property test flips one byte of a valid CRL.
//!
//! Path A runs on every input; path B and C are conditional (B needs `build_signed_crl` to
//! succeed, C additionally needs at least 2 bytes of `data` to pick an offset). A single set of
//! counters summing all three paths together is misleading: `exercise` runs up to three times per
//! input, so `parse_ok / total` can read well over 100 percent while the path #123 actually
//! specifies (A) sits at zero. Each path therefore gets its own `PathCounters` (`calls`,
//! `parse_ok`, `verify_ok`, `build_ok`), printed separately to stderr every 5,000 executions, so a
//! fuzz run's own log reports a real per-path fraction rather than a number that flatters itself.
//!
//! **Seeding path A.** `crates/irontraffic-tls/fuzz/seed_corpus/fuzz_crl_parse/` holds a handful
//! of structurally valid `CertificateList` DER blobs (empty revocation list, narrow serials, one
//! wide serial, no `nextUpdate`, a `GeneralizedTime` `thisUpdate`, fifty serials), each with a
//! placeholder signature since `parse` never checks it. Point a real run at them alongside the
//! mutation corpus so path A starts from valid DER shapes instead of nothing:
//! `cargo fuzz run fuzz_crl_parse corpus/fuzz_crl_parse seed_corpus/fuzz_crl_parse -- -runs=500000`
//! (paths relative to `crates/irontraffic-tls/fuzz/`). libFuzzer reads initial inputs from every
//! corpus directory listed and writes newly discovered interesting inputs into the first one.
//!
//! Set `FUZZ_CRL_DEBUG=1` to print the rejection reason for every input that does not reach the
//! next stage.
//!
//! Contract: must not panic, must not hang, and the built index's reported memory must not be
//! wildly disproportionate to the bytes that produced it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Once, OnceLock};

use irontraffic_tls::crl::{self, CrlConfig, RevocationIndex};
use irontraffic_tls::time::UnixSeconds;
use libfuzzer_sys::fuzz_target;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevokedCertParams, SerialNumber,
};

static INIT: Once = Once::new();

// Unix seconds for 2025-01-01T00:00:00Z, the fixed clock this target evaluates freshness and
// builds the index against. Computed directly (not read from a clock; see irontraffic_tls::time's
// own module doc on why a CRL's timestamps are values, never a live read), and chosen to sit
// comfortably inside the fixture CRL's thisUpdate 2024-01-01 / nextUpdate 2030-01-01 window built
// below with `rcgen::date_time_ymd`, without depending on the `time` crate being a direct
// dependency of this fuzz crate just to construct a matching `OffsetDateTime`.
const FIXED_NOW_2025_01_01: u64 = 1_735_689_600;

/// One RSA-2048 CA key pair plus its self-signed certificate DER, generated once and reused for
/// every call. A real CA is required because `RevocationIndex::build` only accepts a
/// `VerifiedCrl`, produced only by a real signature check; generating a fresh key pair per call
/// would also make each of many thousands of executions pay RSA key generation instead of just
/// the much cheaper per-call sign.
struct Fixture {
    key_pair: KeyPair,
    ca_params: CertificateParams,
    issuer_der: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .expect("RSA-2048 key generation for a fixed, well-known algorithm must not fail"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; a panic here is a libFuzzer-reported finding about this binary's own test fixture, never a request-path failure mode, since this file is never linked into the server binary.
        let mut ca_params = CertificateParams::new(vec!["Fuzz CRL CA".to_owned()])
            .expect("a single ASCII SAN must always build valid CertificateParams"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; the SAN is a fixed, constant, valid string, never fuzzer-controlled, and this file is never linked into the server binary.
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = ca_params
            .self_signed(&key_pair)
            .expect("self-signing a well-formed, fixed CA template must not fail"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; the CA template is fixed and constant, never fuzzer-controlled, and this file is never linked into the server binary.
        let issuer_der = cert.der().to_vec();
        Fixture {
            key_pair,
            ca_params,
            issuer_der,
        }
    })
}

static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Per-path counters: how many times `exercise` ran on this path (`calls`), and how many of
/// those reached each stage. Each of paths A, B and C gets its own `PathCounters` rather than one
/// counter shared across all three, because `exercise` runs up to three times per input and a
/// single `parse_ok / total` fraction would silently sum unrelated paths (#729 BLOCKING 4).
struct PathCounters {
    calls: AtomicU64,
    parse_ok: AtomicU64,
    verify_ok: AtomicU64,
    build_ok: AtomicU64,
}

impl PathCounters {
    const fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            parse_ok: AtomicU64::new(0),
            verify_ok: AtomicU64::new(0),
            build_ok: AtomicU64::new(0),
        }
    }
}

static PATH_A: PathCounters = PathCounters::new();
static PATH_B: PathCounters = PathCounters::new();
static PATH_C: PathCounters = PathCounters::new();

fn report_progress() {
    let total = TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if total.is_multiple_of(5_000) {
        eprintln!(
            "fuzz_crl_parse: total={total} || PATH-A calls={} parse_ok={} verify_ok={} \
             build_ok={} | PATH-B calls={} parse_ok={} verify_ok={} build_ok={} | PATH-C \
             calls={} parse_ok={} verify_ok={} build_ok={}",
            PATH_A.calls.load(Ordering::Relaxed),
            PATH_A.parse_ok.load(Ordering::Relaxed),
            PATH_A.verify_ok.load(Ordering::Relaxed),
            PATH_A.build_ok.load(Ordering::Relaxed),
            PATH_B.calls.load(Ordering::Relaxed),
            PATH_B.parse_ok.load(Ordering::Relaxed),
            PATH_B.verify_ok.load(Ordering::Relaxed),
            PATH_B.build_ok.load(Ordering::Relaxed),
            PATH_C.calls.load(Ordering::Relaxed),
            PATH_C.parse_ok.load(Ordering::Relaxed),
            PATH_C.verify_ok.load(Ordering::Relaxed),
            PATH_C.build_ok.load(Ordering::Relaxed),
        );
    }
}

/// A generous but non-default config: `max_bytes` large enough that a signed fixture CRL (a few
/// hundred bytes to a few KiB) is never spuriously refused, `max_entries` small enough that a
/// single input cannot spend unbounded time in `build`'s sort even though `build_signed_crl`
/// below already caps entries at 64 per call on its own.
fn cfg() -> CrlConfig {
    CrlConfig {
        max_bytes: 64 * 1024 * 1024,
        max_entries: 10_000,
        stale_grace_secs: 86_400,
        no_next_update_ttl_secs: 86_400,
        skew_secs: 300,
    }
}

/// Build a real, validly signed CRL whose revoked-serial list `data` chooses: each entry reads
/// one length byte (folded into 1..=20, RFC 5280's own ceiling on a serial's normalized length)
/// followed by that many serial content bytes, until `data` runs out or 64 entries have been
/// collected. Never returns `None` for a short or empty `data`; it just produces a CRL that
/// revokes nothing, which is `parse`'s own edge case 2 ("CRL with no revokedCertificates. Ok,
/// `len() == 0`") and a legal, common CRL shape that must not be under-exercised.
fn build_signed_crl(data: &[u8]) -> Option<Vec<u8>> {
    let fx = fixture();
    let mut revoked_certs = Vec::new();
    let mut rest = data;
    while revoked_certs.len() < 64 {
        let Some((len_byte, tail)) = rest.split_first() else {
            break;
        };
        rest = tail;
        let len = (usize::from(*len_byte) % 20) + 1;
        if rest.len() < len {
            break;
        }
        let (serial_bytes, tail) = rest.split_at(len);
        rest = tail;
        revoked_certs.push(RevokedCertParams {
            serial_number: SerialNumber::from_slice(serial_bytes),
            revocation_time: rcgen::date_time_ymd(2024, 6, 1),
            reason_code: None,
            invalidity_date: None,
        });
    }

    let issuer = Issuer::from_params(&fx.ca_params, &fx.key_pair);
    let params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2024, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params.signed_by(&issuer).ok()?;
    Some(crl.der().to_vec())
}

/// Whether `FUZZ_CRL_DEBUG` is set, read once and cached so a real fuzzing run (many thousands
/// of executions per second) never pays a `getenv` per call. Opt-in stderr diagnostics for
/// whichever stage rejects a given blob.
fn debug_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("FUZZ_CRL_DEBUG").is_some())
}

/// Run one candidate CRL blob through the full pipeline the issue's fuzz target section
/// describes: `parse`, then on `Ok` into `verify_signature`, then on `Ok` into
/// `RevocationIndex::build` with the fixed clock above, then `is_revoked` and `freshness` for
/// fixed probes. Every stage is independent (an error at any stage just returns), so a caller can
/// feed both realistic and adversarial bytes through the identical path. `path` is the caller's
/// own `PathCounters`, incremented at each stage this call reaches, so A, B and C never share a
/// counter.
fn exercise(bytes: &[u8], cfg: &CrlConfig, path: &PathCounters) {
    path.calls.fetch_add(1, Ordering::Relaxed);

    let parsed = match crl::parse(bytes, cfg) {
        Ok(p) => p,
        Err(e) => {
            if debug_enabled() {
                eprintln!("DEBUG parse err: {e}");
            }
            return;
        }
    };
    path.parse_ok.fetch_add(1, Ordering::Relaxed);

    let verified = match crl::verify_signature(parsed, &fixture().issuer_der) {
        Ok(v) => v,
        Err(e) => {
            if debug_enabled() {
                eprintln!("DEBUG verify err: {e}");
            }
            return;
        }
    };
    path.verify_ok.fetch_add(1, Ordering::Relaxed);

    let now = UnixSeconds::new(FIXED_NOW_2025_01_01);
    let Ok(idx) = RevocationIndex::build(&verified, now, cfg) else {
        return;
    };
    path.build_ok.fetch_add(1, Ordering::Relaxed);

    // Three fixed serials, per the issue's own fuzz target description: an ordinary 8-byte
    // serial, the degenerate all-zero serial (normalizes to the single byte 0x00), and a wide
    // (>16 byte) serial that must be answered from the overflow HashSet rather than the Bloom
    // filter and the sorted array.
    let _ = idx.is_revoked(&[0x2a; 8]);
    let _ = idx.is_revoked(&[0x00]);
    let _ = idx.is_revoked(&[0xaa; 17]);
    let _ = idx.freshness(now, cfg);

    // Coarse allocation-proportionality check, approximating the issue's stated fuzz contract
    // ("must not allocate more than 4 * input.len() + 1 MiB") with the built structure's own
    // reported size rather than a second global allocator layered under libFuzzer's sanitizer
    // allocator. crl.rs's own crl_parse_1e6_allocation_bounded test measures a real
    // allocated-byte DELTA for build() via the thread-local counting probe in name.rs's
    // alloc_probe module, but that hook is `pub(crate)` and not reachable from this separate
    // fuzz crate, and it is instrumented only at build()'s known allocation sites, not at every
    // allocation libFuzzer's sanitizer allocator would see. This assertion is therefore a
    // weaker, size-based proxy for the same contract, not a claim that this target reaches the
    // same coverage as that test.
    assert!(
        idx.len() <= cfg.max_entries,
        "index holds more entries than max_entries allows"
    );
    assert!(
        idx.memory_bytes() <= 4 * bytes.len() + 1024 * 1024,
        "index memory_bytes {} wildly exceeds 4 * input.len() ({}) + 1 MiB",
        idx.memory_bytes(),
        bytes.len()
    );
}

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        // Either this call or some other one-time setup elsewhere in the process installs the
        // process-wide crypto provider; installation is idempotent from this target's point of
        // view (`AlreadyInstalled` and `Ok` both leave a provider installed), and `verify_signature`
        // needs one installed to find a matching signature-verification algorithm.
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either outcome (Ok or AlreadyInstalled) leaves a crypto provider installed process-wide, which is all this one-time setup needs; there is nothing further to react to.
    });
    report_progress();

    let cfg = cfg();

    // Path A: the raw fuzz bytes straight into the full pipeline. This is the literal "arbitrary
    // bytes into the parser" half of #123's own fuzz target description and the cheapest possible
    // check of `parse`'s "never panics, for any input" invariant. Its own PATH_A counters are
    // what a run should read to answer "does the specified input domain reach parse", not the
    // three-path sum; see the module doc for the seed corpus that gives this path a real chance
    // at parse_ok.
    exercise(data, &cfg, &PATH_A);

    // Path B: a small valid-CRL prefix whose entries the fuzz bytes choose, reliably reaching
    // signature verification and `RevocationIndex::build`'s O(r) collection, sort, dedup and
    // Bloom fill, which path A cannot: this target's CA key is generated fresh every process
    // start, so no bytes path A could contain, seeded or mutated, can ever carry a matching
    // signature.
    if let Some(signed) = build_signed_crl(data) {
        exercise(&signed, &cfg, &PATH_B);

        // Path C: the same valid bytes with one fuzzer-chosen byte flipped, exploring the
        // almost-valid manifold around a real signed CRL the same way crl.rs's own
        // `prop_parse_never_panics` property test flips one byte of a valid CRL. PATH_B's
        // verify_ok reads 1:1 with its calls by construction (every successfully built CRL here
        // is freshly, validly signed for this exact input), so it is not itself evidence of
        // coverage; PATH_C is what actually explores whether a small perturbation of a valid CRL
        // still parses or still verifies.
        if let [b0, b1, ..] = *data {
            if let Some(offset) = signed
                .len()
                .checked_sub(1)
                .map(|max| (usize::from(b0) | (usize::from(b1) << 8)) % (max + 1))
            {
                let mut mutated = signed;
                if let Some(byte) = mutated.get_mut(offset) {
                    *byte ^= 0xff;
                }
                exercise(&mutated, &cfg, &PATH_C);
            }
        }
    }
});
