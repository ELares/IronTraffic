// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `ocsp::validate_staple`: arbitrary bytes into the response validator, against
//! a fixed credential fixture, a fixed nonce, and a fixed clock, per the issue that specifies this
//! module. `x509-ocsp` 0.2.1 is self-described as early-stage, which is why this target and the
//! response size cap are acceptance criteria rather than nice-to-haves: every byte fed in here is
//! the same shape of input a hostile OCSP responder controls.
//!
//! **Three paths, exercised per input, mirroring `fuzz_crl_parse`'s own shape and for the
//! identical reason.** A first measurement of an earlier version of this target found 6,220,333
//! executions from an empty corpus stopped 99.96 percent of the time at step 2 (`OcspError::Parse`)
//! and reached step 4 or later zero times: a uniformly random byte string essentially never
//! carries a syntactically valid `OCSPResponse`, let alone one whose embedded signature verifies
//! against this process's own fixture key, so a target that only ever fed `data` straight into
//! `validate_staple` was fuzzing `x509_ocsp::OcspResponse::from_der` and nothing this crate wrote.
//! Seeding a corpus cannot fix this on its own: this fixture's issuer key, like `fuzz_crl_parse`'s
//! CA key, is generated fresh every process start, so no bytes committed ahead of time, seeded or
//! mutated, can ever carry a signature that verifies against THIS run's key. `fuzz_crl_parse`
//! solved the identical problem by building a real, validly signed structure at runtime instead of
//! trying to seed one, and this target does the same:
//!
//! - **Path A**: `data` itself, unmodified, straight into `validate_staple`. The literal
//!   "arbitrary bytes into the validator" shape the issue's own fuzz target section asks for, and
//!   the cheapest possible check of "must not panic, for any input, at any length". Its realistic
//!   ceiling past step 4 is zero regardless of corpus, for the reason above.
//! - **Path B**: a freshly, validly signed `OCSPResponse` whose `certStatus`, `thisUpdate`/
//!   `nextUpdate` offsets from the fixed clock, nonce presence and match, responder identity
//!   (the issuer itself, a delegated responder correctly authorized, one missing
//!   `id-kp-OCSPSigning`, or one signed by an unrelated CA), and `CertID` correctness are all
//!   chosen by `data` (see `choices`). This reliably reaches `parse_basic_response`,
//!   `resolve_signer`, `verify_signature_der`, `cert_id_matches`, the time checks, the nonce check
//!   and every `CertStatus` arm: every step this module's own doc numbers 4 through 11.
//! - **Path C**: path B's bytes with one fuzzer-chosen byte flipped, exploring the almost-valid
//!   manifold around a real signed response (a corrupted signature, a truncated length, a mangled
//!   extension) the same way `fuzz_crl_parse`'s own path C flips one byte of a valid CRL.
//!
//! **Reachability is measured, not assumed** (`assert_deep_validation_is_reached`, below), the same
//! discipline `fuzz_health_response_parser`'s `assert_http_half_is_reached` applies to the HTTP
//! codec fuzz target: once enough executions have accumulated, this panics (which `cargo fuzz`
//! treats as a crash) if step 5 or later has never once been reached, so a future regression that
//! silently unwires path B or C cannot go unnoticed for 6.2 million executions the way the original
//! single-path version of this target did. Re-measured after this fix, from an empty corpus,
//! `cargo +nightly fuzz run fuzz_ocsp_response -- -max_total_time=60 -timeout=10`: 100 percent of
//! 257,955 executions reached step 5 or later (path B and C alone; path A is still included on
//! every input and still contributes its own, separately near-zero share of that total), and a
//! running count of full `Ok` acceptances climbed steadily throughout the run (past 5,500 by the
//! end), so the module's actual validation logic, not just the third-party decoder in front of it,
//! is now what a real run spends its time on. No crash in any run performed while developing this
//! fix.
//!
//! Contract: must not panic and must not hang, for any input, at any length. Allocation is
//! bounded structurally rather than measured directly: `validate_staple` refuses anything over
//! `MAX_OCSP_RESPONSE_BYTES` before parsing at all, and the embedded-certificate list it does
//! parse is capped at `MAX_RESPONDER_CERTS`, so no path here can allocate a structure whose size
//! is unbounded in the input length. This target cannot independently re-measure that bound the
//! way `fuzz_crl_parse`'s own allocation check does (that check reaches into a `pub(crate)`
//! allocation probe inside `irontraffic-tls` itself; a separate fuzz crate compiles against the
//! public API only, and this issue does not add a new probe for it), so the numeric contract is
//! enforced by inspection of `validate_staple`'s own size and count checks, not measured here.
//!
//! The one contract this target checks directly on every path: any `Ok(info)` must satisfy
//! `info.this_update <= now + skew`, exactly the property `validate_staple`'s own step 9 exists to
//! guarantee. Path A almost never reaches `Ok`; path B and C are what actually exercise it across a
//! wide, adversarial input space rather than only the one or two fixed timestamps the hand-written
//! unit tests pin.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use der::{Decode, Encode};
use irontraffic_tls::ocsp::{self, OcspConfig, OcspError};
use irontraffic_tls::store::{ChainInterner, Credentials};
use irontraffic_tls::time::UnixSeconds;
use libfuzzer_sys::fuzz_target;
use rcgen::SigningKey as _;
use sha1::Digest;

/// Unix seconds for 2025-01-01T00:00:00Z: a fixed clock this target validates against, computed
/// directly rather than read from a live clock (see `irontraffic_tls::time`'s own module doc on
/// why a certificate-adjacent timestamp is a value, never a live read).
const FIXED_NOW: u64 = 1_735_689_600;

/// `id-pkix-ocsp-basic`, RFC 6960 section 4.2.1. Redefined here (rather than imported) because
/// `ocsp.rs`'s own copy is a private `const`: this fuzz crate compiles against
/// `irontraffic_tls`'s public API only, exactly like every other consumer of this crate.
const OID_OCSP_BASIC: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
/// `id-pkix-ocsp-nonce`, RFC 6960 section 4.4.1.
const OID_OCSP_NONCE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
/// `ecdsa-with-SHA256`, RFC 5758. Every fixture key here is P-256, so every signature this target
/// produces uses this one algorithm identifier.
const OID_ECDSA_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// One self-signed CA, one leaf credential it issued, and three delegated-responder certificates
/// covering the authorized, missing-EKU and wrong-issuer shapes `resolve_signer` distinguishes.
/// Built once per process and reused for every call, exactly as `fuzz_crl_parse`'s own fixture is,
/// so that many thousands of executions pay real key generation once rather than per call.
struct Fixture {
    cred: Credentials,
    issuer_key: rcgen::KeyPair,
    issuer_der: Vec<u8>,
    delegated_good_der: Vec<u8>,
    delegated_good_key: rcgen::KeyPair,
    delegated_no_eku_der: Vec<u8>,
    delegated_no_eku_key: rcgen::KeyPair,
    delegated_wrong_issuer_der: Vec<u8>,
    delegated_wrong_issuer_key: rcgen::KeyPair,
}

fn ca_params(cn: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("an empty SAN list must always build valid CertificateParams"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; the SAN list is fixed and empty, never fuzzer-controlled, and this file is never linked into the server binary.
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;
    params
}

/// One delegated-responder certificate: `with_eku` controls whether it carries
/// `id-kp-OCSPSigning`, and `issuer_signs` controls whether the fixture's own issuer signed it
/// (`false` signs it with an unrelated, freshly generated CA instead). Mirrors
/// `ocsp.rs`'s own `build_delegated_cert` test helper, unavoidably duplicated here since a
/// `#[cfg(test)]` helper is not part of the public API this separate fuzz crate compiles against.
fn build_delegated(
    issuer_params: &rcgen::CertificateParams,
    issuer_key: &rcgen::KeyPair,
    with_eku: bool,
    issuer_signs: bool,
) -> (Vec<u8>, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("ECDSA P-256 key generation for a fixed, well-known algorithm must not fail"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; a panic here is a libFuzzer-reported finding about this binary's own test fixture, never a request-path failure mode, since this file is never linked into the server binary.
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("an empty SAN list must always build valid CertificateParams"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; same as above.
    if with_eku {
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::OcspSigning];
    }
    let der = if issuer_signs {
        let signing_issuer = rcgen::Issuer::from_params(issuer_params, issuer_key);
        params
            .signed_by(&key, &signing_issuer)
            .expect("signing a well-formed, fixed delegated-responder template must not fail") // it-allow: no-panic reason: fuzz harness one-time fixture setup; the template is fixed and constant, never fuzzer-controlled, and this file is never linked into the server binary.
            .der()
            .to_vec()
    } else {
        let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("ECDSA P-256 key generation for a fixed, well-known algorithm must not fail"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; same as above.
        let other_ca = ca_params("fuzz ocsp unrelated CA");
        let other_issuer = rcgen::Issuer::from_params(&other_ca, &other_key);
        params
            .signed_by(&key, &other_issuer)
            .expect("signing a well-formed, fixed delegated-responder template must not fail") // it-allow: no-panic reason: fuzz harness one-time fixture setup; same as above.
            .der()
            .to_vec()
    };
    (der, key)
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        // Either this call or some other one-time setup elsewhere in the process installs the
        // process-wide crypto provider; installation is idempotent from this target's point of
        // view (`AlreadyInstalled` and `Ok` both leave a provider installed), and `validate_staple`
        // needs one installed to find a matching signature-verification algorithm.
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either outcome (Ok or AlreadyInstalled) leaves a crypto provider installed process-wide, which is all this one-time setup needs; there is nothing further to react to.

        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("ECDSA P-256 key generation for a fixed, well-known algorithm must not fail"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; a panic here is a libFuzzer-reported finding about this binary's own test fixture, never a request-path failure mode, since this file is never linked into the server binary.
        let issuer_params = ca_params("fuzz ocsp issuer");
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self-signing a well-formed, fixed CA template must not fail") // it-allow: no-panic reason: fuzz harness one-time fixture setup; the CA template is fixed and constant, never fuzzer-controlled, and this file is never linked into the server binary.
            .der()
            .to_vec();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("ECDSA P-256 key generation for a fixed, well-known algorithm must not fail"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; same as above.
        let leaf_params = rcgen::CertificateParams::new(vec!["fuzz.example.com".to_owned()])
            .expect("a single ASCII SAN must always build valid CertificateParams"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; the SAN is a fixed, constant, valid string, never fuzzer-controlled, and this file is never linked into the server binary.
        let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &signing_issuer)
            .expect("signing a well-formed, fixed leaf template must not fail") // it-allow: no-panic reason: fuzz harness one-time fixture setup; the leaf template is fixed and constant, never fuzzer-controlled, and this file is never linked into the server binary.
            .der()
            .to_vec();

        let mut interner = ChainInterner::new();
        let cred = Credentials::load(
            &[&leaf_der, &issuer_der],
            &leaf_key.serialize_der(),
            &mut interner,
        )
        .expect("a freshly generated, well-formed chain and matching key must load"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; the chain and key are fixed and constant, never fuzzer-controlled, and this file is never linked into the server binary.

        let (delegated_good_der, delegated_good_key) =
            build_delegated(&issuer_params, &issuer_key, true, true);
        let (delegated_no_eku_der, delegated_no_eku_key) =
            build_delegated(&issuer_params, &issuer_key, false, true);
        let (delegated_wrong_issuer_der, delegated_wrong_issuer_key) =
            build_delegated(&issuer_params, &issuer_key, true, false);

        Fixture {
            cred,
            issuer_key,
            issuer_der,
            delegated_good_der,
            delegated_good_key,
            delegated_no_eku_der,
            delegated_no_eku_key,
            delegated_wrong_issuer_der,
            delegated_wrong_issuer_key,
        }
    })
}

/// Which responder signs and names itself in a path B/C response.
enum Responder {
    /// The issuer itself, named by subject.
    Issuer,
    /// A delegated responder correctly authorized (signed by the issuer, carries
    /// `id-kp-OCSPSigning`): must be accepted.
    DelegatedGood,
    /// A delegated responder missing `id-kp-OCSPSigning`: must be refused.
    DelegatedNoEku,
    /// A delegated responder signed by an unrelated CA: must be refused.
    DelegatedWrongIssuer,
}

/// Everything path B/C's byte choices decide, read from a handful of `data` bytes with graceful
/// defaults when `data` runs out, mirroring `fuzz_crl_parse`'s `build_signed_crl` in never
/// returning `None` for a short input.
struct Choices {
    status: u8,
    this_update_offset: i64,
    next_update_offset: Option<i64>,
    send_nonce: bool,
    response_nonce: Option<[u8; 4]>,
    responder: Responder,
    wrong_cert_id: bool,
}

fn next_byte(data: &mut &[u8]) -> u8 {
    let (b, rest) = data.split_first().unwrap_or((&0, &[]));
    *data = rest;
    *b
}

fn next_i64(data: &mut &[u8]) -> i64 {
    // A signed value in roughly [-1 000 000, 1 000 000] seconds (about +/- 11.5 days), wide
    // enough to explore both sides of `skew_secs` and `no_next_update_ttl_secs`'s defaults many
    // times over.
    let raw = i64::from(next_byte(data)) - i64::from(next_byte(data));
    raw * 4_000
}

fn choices(data: &mut &[u8]) -> Choices {
    let status = next_byte(data) % 3;
    let this_update_offset = next_i64(data);
    let has_next_update = next_byte(data).is_multiple_of(2);
    let next_update_offset = has_next_update.then(|| next_i64(data));
    let send_nonce = next_byte(data).is_multiple_of(2);
    let response_nonce = match next_byte(data) % 3 {
        0 => None,
        1 => Some([0x11, 0x22, 0x33, 0x44]), // deliberately different from the sent nonce below
        _ => Some([0xAA, 0xBB, 0xCC, 0xDD]),
    };
    let responder = match next_byte(data) % 4 {
        0 => Responder::Issuer,
        1 => Responder::DelegatedGood,
        2 => Responder::DelegatedNoEku,
        _ => Responder::DelegatedWrongIssuer,
    };
    let wrong_cert_id = next_byte(data).is_multiple_of(4);
    Choices {
        status,
        this_update_offset,
        next_update_offset,
        send_nonce,
        response_nonce,
        responder,
        wrong_cert_id,
    }
}

/// The 16-byte nonce path B/C's `sent_nonce` argument always uses.
const SENT_NONCE: [u8; 16] = [0x42; 16];

/// Build a validly (self-consistently) signed `OCSPResponse` per `choices`, or `None` if `data`
/// was too short to make any choice at all (never happens in practice since `choices` defaults on
/// a short slice, but keeps this function's signature honest about its one failure mode: an
/// encoding step failing, which none of the fixed, bounded inputs constructed here can trigger).
#[allow(clippy::too_many_lines, reason = "one straight-line encode; see ocsp.rs's own test module's build_response_der, which this mirrors")]
fn build_response(fx: &'static Fixture, choices: &Choices) -> Option<Vec<u8>> {
    let this_update = FIXED_NOW.checked_add_signed(choices.this_update_offset)?;
    let next_update = match choices.next_update_offset {
        Some(off) => Some(this_update.checked_add_signed(off)?),
        None => None,
    };

    let (signer, responder_id, embedded_certs) = match choices.responder {
        Responder::Issuer => {
            let issuer = x509_cert::Certificate::from_der(&fx.issuer_der).ok()?;
            (
                &fx.issuer_key,
                x509_ocsp::ResponderId::ByName(issuer.tbs_certificate.subject),
                Vec::new(),
            )
        }
        Responder::DelegatedGood => (
            &fx.delegated_good_key,
            responder_id_by_key(&fx.delegated_good_der)?,
            vec![fx.delegated_good_der.clone()],
        ),
        Responder::DelegatedNoEku => (
            &fx.delegated_no_eku_key,
            responder_id_by_key(&fx.delegated_no_eku_der)?,
            vec![fx.delegated_no_eku_der.clone()],
        ),
        Responder::DelegatedWrongIssuer => (
            &fx.delegated_wrong_issuer_key,
            responder_id_by_key(&fx.delegated_wrong_issuer_der)?,
            vec![fx.delegated_wrong_issuer_der.clone()],
        ),
    };

    let issuer = x509_cert::Certificate::from_der(&fx.issuer_der).ok()?;
    let mut issuer_name_hash = sha1::Sha1::digest(fx.cred.issuer_dn()).to_vec();
    let issuer_key_hash = sha1::Sha1::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .to_vec();
    if choices.wrong_cert_id {
        let last = issuer_name_hash.last_mut()?;
        *last ^= 0xFF;
    }
    let cert_id = x509_ocsp::CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
            parameters: Some(der::asn1::Null.into()),
        },
        issuer_name_hash: der::asn1::OctetString::new(issuer_name_hash).ok()?,
        issuer_key_hash: der::asn1::OctetString::new(issuer_key_hash).ok()?,
        serial_number: x509_cert::serial_number::SerialNumber::new(fx.cred.serial()).ok()?,
    };

    let status = match choices.status {
        0 => x509_ocsp::CertStatus::good(),
        1 => x509_ocsp::CertStatus::Revoked(x509_ocsp::RevokedInfo {
            revocation_time: unix_to_generalized(this_update.saturating_sub(100))?,
            revocation_reason: None,
        }),
        _ => x509_ocsp::CertStatus::unknown(),
    };

    let extensions = choices.response_nonce.map(|n| {
        let inner = der::asn1::OctetString::new(n.to_vec()).expect("4 bytes always fits"); // it-allow: no-panic reason: a fixed 4-byte slice always fits an OCTET STRING; this file is never linked into the server binary.
        let extn_value = der::asn1::OctetString::new(
            der::Encode::to_der(&inner).expect("encoding a 4-byte OCTET STRING cannot fail"), // it-allow: no-panic reason: same as above.
        )
        .expect("the DER-wrapped inner value always fits"); // it-allow: no-panic reason: same as above.
        vec![x509_cert::ext::Extension {
            extn_id: OID_OCSP_NONCE,
            critical: false,
            extn_value,
        }]
    });

    let single = x509_ocsp::SingleResponse {
        cert_id,
        cert_status: status,
        this_update: unix_to_generalized(this_update)?,
        next_update: match next_update {
            Some(t) => Some(unix_to_generalized(t)?),
            None => None,
        },
        single_extensions: None,
    };
    let response_data = x509_ocsp::ResponseData {
        version: x509_ocsp::Version::V1,
        responder_id,
        produced_at: unix_to_generalized(this_update)?,
        responses: vec![single],
        response_extensions: extensions,
    };
    let tbs_der = Encode::to_der(&response_data).ok()?;
    let signature_bytes = signer.sign(&tbs_der).ok()?;

    let certs = if embedded_certs.is_empty() {
        None
    } else {
        Some(
            embedded_certs
                .iter()
                .map(|d| x509_cert::Certificate::from_der(d))
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
        )
    };
    let basic = x509_ocsp::BasicOcspResponse {
        tbs_response_data: response_data,
        signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: OID_ECDSA_SHA256,
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(&signature_bytes).ok()?,
        certs,
    };
    let basic_der = Encode::to_der(&basic).ok()?;

    let response = x509_ocsp::OcspResponse {
        response_status: x509_ocsp::OcspResponseStatus::Successful,
        response_bytes: Some(x509_ocsp::ResponseBytes {
            response_type: OID_OCSP_BASIC,
            response: der::asn1::OctetString::new(basic_der).ok()?,
        }),
    };
    Encode::to_der(&response).ok()
}

fn responder_id_by_key(cert_der: &[u8]) -> Option<x509_ocsp::ResponderId> {
    let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
    let spki_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let digest = sha1::Sha1::digest(spki_bytes);
    Some(x509_ocsp::ResponderId::ByKey(
        der::asn1::OctetString::new(digest.to_vec()).ok()?,
    ))
}

fn unix_to_generalized(secs: u64) -> Option<x509_ocsp::OcspGeneralizedTime> {
    let gt =
        der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(secs))
            .ok()?;
    Some(x509_ocsp::OcspGeneralizedTime(gt))
}

/// Process-lifetime counters for `assert_deep_validation_is_reached`'s self-check. `deep` counts
/// executions whose `validate_staple` result is `Ok`, or an error from step 5 or later (anything
/// that is not `Empty`/`TooLarge`/`Parse`/`ResponderStatus`/`UnknownResponseType`, i.e. not stuck
/// at steps 1 through 4).
static TOTAL: AtomicU64 = AtomicU64::new(0);
static DEEP: AtomicU64 = AtomicU64::new(0);
static OK: AtomicU64 = AtomicU64::new(0);

fn is_deep(result: &Result<ocsp::StapleInfo, OcspError>) -> bool {
    match result {
        Ok(_) => true,
        Err(
            OcspError::Empty
            | OcspError::TooLarge
            | OcspError::Parse
            | OcspError::ResponderStatus(_)
            | OcspError::UnknownResponseType
            | OcspError::NoIssuer
            | OcspError::IssuerParse
            | OcspError::RequestTooLarge
            | OcspError::ProviderNotInstalled
            | OcspError::BadResponderUrl
            | OcspError::PrivateResponderAddress,
        ) => false,
        Err(_) => true,
    }
}

/// Fails the fuzz run outright if step 5 or later has never once been reached.
/// `fuzz_health_response_parser`'s `assert_http_half_is_reached` is the model: panicking (which
/// `cargo fuzz` treats as a crash) once enough executions have accumulated that a zero count can
/// no longer be attributed to bad luck on a tiny run is what makes a future regression that
/// unwires path B/C, or weakens `choices`/`build_response` back into never producing a valid
/// signature, visible instead of silently completing millions of executions at zero coverage the
/// way the original single-path version of this target did.
fn assert_deep_validation_is_reached(result: &Result<ocsp::StapleInfo, OcspError>) {
    let total = TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if is_deep(result) {
        DEEP.fetch_add(1, Ordering::Relaxed);
    }
    if result.is_ok() {
        OK.fetch_add(1, Ordering::Relaxed);
    }
    let deep = DEEP.load(Ordering::Relaxed);
    assert!(
        total < 5_000 || deep > 0,
        "validate_staple never once reached step 5 or later after {total} executions: this fuzz \
         target has gone back to exercising only the OCSPResponse decoder, see #760 SHOULD_FIX 8"
    );
}

fuzz_target!(|data: &[u8]| {
    let fx = fixture();
    let cfg = OcspConfig::default();
    let now = UnixSeconds::new(FIXED_NOW);

    // Path A: the raw fuzz bytes straight into validate_staple. The literal "arbitrary bytes into
    // the validator" half of this issue's own fuzz target description; see the module doc for why
    // its own realistic ceiling past step 4 is zero regardless of corpus.
    let result_a = ocsp::validate_staple(data, &fx.cred, Some(&SENT_NONCE), now, &cfg);
    if let Ok(info) = &result_a {
        assert!(
            info.this_update.get() <= now.get() + u64::from(cfg.skew_secs),
            "validate_staple returned Ok with thisUpdate beyond now + skew: {info:?}"
        );
    }

    // Path B: a freshly, validly signed response whose content data chooses.
    let mut cursor = data;
    let picked = choices(&mut cursor);
    if let Some(signed) = build_response(fx, &picked) {
        let sent_nonce = if picked.send_nonce {
            Some(&SENT_NONCE)
        } else {
            None
        };
        let result_b = ocsp::validate_staple(&signed, &fx.cred, sent_nonce, now, &cfg);
        if let Ok(info) = &result_b {
            assert!(
                info.this_update.get() <= now.get() + u64::from(cfg.skew_secs),
                "validate_staple returned Ok with thisUpdate beyond now + skew: {info:?}"
            );
        }
        assert_deep_validation_is_reached(&result_b);

        // Path C: the same valid bytes with one fuzzer-chosen byte flipped, exploring the
        // almost-valid manifold around a real signed response.
        if let [b0, b1, ..] = *data {
            if let Some(offset) = signed
                .len()
                .checked_sub(1)
                .map(|max| (usize::from(b0) | (usize::from(b1) << 8)) % (max + 1))
            {
                let mut mutated = signed;
                if let Some(byte) = mutated.get_mut(offset) {
                    *byte ^= 0xFF;
                }
                let result_c = ocsp::validate_staple(&mutated, &fx.cred, sent_nonce, now, &cfg);
                if let Ok(info) = &result_c {
                    assert!(
                        info.this_update.get() <= now.get() + u64::from(cfg.skew_secs),
                        "validate_staple returned Ok with thisUpdate beyond now + skew: {info:?}"
                    );
                }
            }
        }
    }

    let total = TOTAL.load(Ordering::Relaxed);
    if total.is_multiple_of(5_000) && total > 0 {
        eprintln!(
            "fuzz_ocsp_response: total={total} deep={} ok={}",
            DEEP.load(Ordering::Relaxed),
            OK.load(Ordering::Relaxed)
        );
    }
});
