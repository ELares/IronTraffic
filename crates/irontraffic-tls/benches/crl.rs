// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for `crl::parse`, `RevocationIndex::build` and `RevocationIndex::is_revoked`.
//!
//! Budgets are recorded here, not gated: `perf-budgets-file-and-raise-lint` (#418) wires up
//! enforcement once its budget file exists. `is_revoked` runs on the request path for any
//! listener with client certificates, so `is_revoked_absent` and `is_revoked_present` are the
//! numbers that matter most. See #123's own Benchmarks section for the budget each id below is
//! checked against; the PR that lands this file records the measured medians and a pass or fail
//! note against every budget in its own body.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]
#![allow(
    clippy::expect_used,
    reason = "bench harness fixture setup, not request-path code: every expect() below is on a \
              fixed, well formed input this file constructs itself, mirroring the crate's own \
              fuzz_targets/fuzz_crl_parse.rs Fixture and crl.rs test module fixtures"
)]

use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_tls::crl::{self, CrlConfig, RevocationIndex};
use irontraffic_tls::time::UnixSeconds;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevokedCertParams, SerialNumber,
};

/// Unix seconds for 2025-01-01T00:00:00Z: inside every fixture CRL's 2024..2030 validity
/// window below, and a fixed value rather than a live clock read for reproducible benchmarks.
const NOW: u64 = 1_735_689_600;

/// One RSA-2048 CA key pair plus its self-signed certificate DER, generated once and reused for
/// every benchmark in this file, mirroring `fuzz_targets/fuzz_crl_parse.rs`'s own `Fixture`.
struct Fixture {
    key_pair: KeyPair,
    ca_params: CertificateParams,
    issuer_der: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let _ = irontraffic_tls::install_process_provider();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .expect("RSA-2048 key generation for a fixed algorithm must not fail");
        let mut ca_params = CertificateParams::new(vec!["Bench CRL CA".to_owned()])
            .expect("a single ASCII SAN must always build valid CertificateParams");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = ca_params
            .self_signed(&key_pair)
            .expect("self-signing a fixed CA template must not fail");
        let issuer_der = cert.der().to_vec();
        Fixture {
            key_pair,
            ca_params,
            issuer_der,
        }
    })
}

/// A generous, non-default config so a 1,000,000-entry fixture is never spuriously refused.
fn cfg() -> CrlConfig {
    CrlConfig {
        max_bytes: 512 * 1024 * 1024,
        max_entries: 10_000_000,
        stale_grace_secs: 86_400,
        no_next_update_ttl_secs: 86_400,
        skew_secs: 300,
    }
}

/// The minimal (leading-zero-stripped) big-endian content octets for `i`, the same
/// normalization `crl.rs`'s own `crl_memory_bytes_under_20mb` and
/// `crl_parse_1e6_allocation_bounded` tests use to build narrow-serial fixtures.
fn trimmed_be(i: u64) -> Vec<u8> {
    let bytes = i.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    bytes.get(start..).unwrap_or(&bytes).to_vec()
}

/// Build a validly signed CRL revoking the `r` distinct serials `1..=r`, each narrow (<= 16
/// bytes) so every one packs into the `u128` sorted array, `RevocationIndex`'s dominant case.
fn signed_crl_der(r: u64) -> Vec<u8> {
    let fx = fixture();
    let revoked_certs = (1..=r)
        .map(|i| RevokedCertParams {
            serial_number: SerialNumber::from_slice(&trimmed_be(i)),
            revocation_time: rcgen::date_time_ymd(2024, 6, 1),
            reason_code: None,
            invalidity_date: None,
        })
        .collect();
    let issuer = Issuer::from_params(&fx.ca_params, &fx.key_pair);
    let params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2024, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    params
        .signed_by(&issuer)
        .expect("signing a fixed-shape bench fixture CRL must not fail")
        .der()
        .to_vec()
}

/// Build and verify a CRL revoking `1..=r`, then compile it into a `RevocationIndex`.
fn built_index(r: u64) -> RevocationIndex {
    let der = signed_crl_der(r);
    let cfg = cfg();
    let parsed = crl::parse(&der, &cfg).expect("bench fixture CRL must parse");
    let verified = crl::verify_signature(parsed, &fixture().issuer_der)
        .expect("bench fixture CRL must verify");
    RevocationIndex::build(&verified, UnixSeconds::new(NOW), &cfg)
        .expect("bench fixture CRL must build")
}

/// `1e3`, `1e5` or `1e6`, the id suffixes #123's Benchmarks section names.
fn label(r: u64) -> &'static str {
    match r {
        1_000 => "1e3",
        100_000 => "1e5",
        1_000_000 => "1e6",
        _ => "?",
    }
}

fn bench_parse(c: &mut Criterion) {
    let der = signed_crl_der(1_000_000);
    let cfg = cfg();
    c.bench_function("crl/parse/1e6", |b| {
        b.iter(|| {
            let _ = black_box(crl::parse(black_box(der.as_slice()), &cfg));
        });
    });
}

fn bench_build(c: &mut Criterion) {
    let cfg = cfg();
    for &r in &[1_000u64, 100_000, 1_000_000] {
        let der = signed_crl_der(r);
        let parsed = crl::parse(&der, &cfg).expect("bench fixture CRL must parse");
        let verified = crl::verify_signature(parsed, &fixture().issuer_der)
            .expect("bench fixture CRL must verify");
        c.bench_function(&format!("crl/build/{}", label(r)), |b| {
            b.iter(|| {
                black_box(RevocationIndex::build(
                    black_box(&verified),
                    UnixSeconds::new(NOW),
                    &cfg,
                ))
            });
        });
    }
}

fn bench_is_revoked(c: &mut Criterion) {
    for &r in &[1_000u64, 100_000, 1_000_000] {
        let idx = built_index(r);

        // Absent: r + 1 was never revoked (the fixture revokes exactly 1..=r).
        let absent = trimmed_be(r + 1);
        c.bench_function(&format!("crl/is_revoked_absent/{}", label(r)), |b| {
            b.iter(|| black_box(idx.is_revoked(black_box(absent.as_slice()))));
        });

        // Present: serial 1 is always revoked.
        let present = trimmed_be(1);
        c.bench_function(&format!("crl/is_revoked_present/{}", label(r)), |b| {
            b.iter(|| black_box(idx.is_revoked(black_box(present.as_slice()))));
        });
    }

    // Wide: one 17-byte serial alongside a modest narrow set, looked up on its own overflow
    // HashSet path (design: wide serials skip the Bloom filter entirely).
    let fx = fixture();
    let cfg = cfg();
    let wide_serial = [0xAAu8; 17];
    let mut revoked_certs: Vec<RevokedCertParams> = (1..=999u64)
        .map(|i| RevokedCertParams {
            serial_number: SerialNumber::from_slice(&trimmed_be(i)),
            revocation_time: rcgen::date_time_ymd(2024, 6, 1),
            reason_code: None,
            invalidity_date: None,
        })
        .collect();
    revoked_certs.push(RevokedCertParams {
        serial_number: SerialNumber::from_slice(&wide_serial),
        revocation_time: rcgen::date_time_ymd(2024, 6, 1),
        reason_code: None,
        invalidity_date: None,
    });
    let issuer = Issuer::from_params(&fx.ca_params, &fx.key_pair);
    let params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2024, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let der = params
        .signed_by(&issuer)
        .expect("signing the wide-serial bench fixture must not fail")
        .der()
        .to_vec();
    let parsed = crl::parse(&der, &cfg).expect("wide bench fixture CRL must parse");
    let verified =
        crl::verify_signature(parsed, &fx.issuer_der).expect("wide bench fixture CRL must verify");
    let idx = RevocationIndex::build(&verified, UnixSeconds::new(NOW), &cfg)
        .expect("wide bench fixture CRL must build");
    c.bench_function("crl/is_revoked_wide", |b| {
        b.iter(|| black_box(idx.is_revoked(black_box(wide_serial.as_slice()))));
    });
}

criterion_group!(benches, bench_parse, bench_build, bench_is_revoked);
criterion_main!(benches);
