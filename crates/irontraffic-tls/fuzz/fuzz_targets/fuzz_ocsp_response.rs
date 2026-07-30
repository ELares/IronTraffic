// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `ocsp::validate_staple`: arbitrary bytes into the response validator, against
//! a fixed credential fixture, a fixed nonce, and a fixed clock, per the issue that specifies this
//! module. `x509-ocsp` 0.2.1 is self-described as early-stage, which is why this target and the
//! response size cap are acceptance criteria rather than nice-to-haves: every byte fed in here is
//! the same shape of input a hostile OCSP responder controls.
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
//! The one contract this target DOES check directly: any `Ok(info)` must satisfy `info.this_update
//! <= now + skew`, exactly the property `validate_staple`'s own step 9 exists to guarantee. Fuzzing
//! it here exercises that property across a wide, adversarial input space rather than only the one
//! or two fixed timestamps the hand-written unit tests pin.

use std::sync::OnceLock;

use irontraffic_tls::ocsp::{self, OcspConfig};
use irontraffic_tls::store::{ChainInterner, Credentials};
use irontraffic_tls::time::UnixSeconds;
use libfuzzer_sys::fuzz_target;

/// Unix seconds for 2025-01-01T00:00:00Z: a fixed clock this target validates against, computed
/// directly rather than read from a live clock (see `irontraffic_tls::time`'s own module doc on
/// why a certificate-adjacent timestamp is a value, never a live read).
const FIXED_NOW: u64 = 1_735_689_600;

/// One self-signed CA plus one leaf it issued, generated once and reused for every call. A real
/// chain is required because `validate_staple` needs a real issuer to hash and a real credential
/// to build the expected `CertID` against.
struct Fixture {
    cred: Credentials,
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
        let mut issuer_params = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("an empty SAN list must always build valid CertificateParams"); // it-allow: no-panic reason: fuzz harness one-time fixture setup; the SAN list is fixed and empty, never fuzzer-controlled, and this file is never linked into the server binary.
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
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

        Fixture { cred }
    })
}

fuzz_target!(|data: &[u8]| {
    let fx = fixture();
    let nonce = [0x42u8; 16];
    let cfg = OcspConfig::default();
    let now = UnixSeconds::new(FIXED_NOW);

    let result = ocsp::validate_staple(data, &fx.cred, Some(&nonce), now, &cfg);
    if let Ok(info) = result {
        assert!(
            info.this_update.get() <= now.get() + u64::from(cfg.skew_secs),
            "validate_staple returned Ok with thisUpdate beyond now + skew: {info:?}"
        );
    }
});
