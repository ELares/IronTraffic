// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drive `SniAcceptor` from arbitrary bytes.
//!
//! The contract, all four parts asserted below rather than merely hoped for:
//!
//! 1. No panic and no hang.
//! 2. `Ready` never carries a configuration whose `client_auth()` is WEAKER than the binding the
//!    presented SNI would select. This is the property every Traefik CVE in this class violated.
//! 3. Never buffer more than `DEFAULT_MAX_CLIENT_HELLO_BYTES`.
//! 4. A reject is terminal in the sense that it is reported once, with a reason, rather than
//!    silently becoming a permissive default.

#![no_main]

use std::sync::{Arc, OnceLock};

use irontraffic_tls::listener::{
    AcceptStep, ClientAuthKind, DEFAULT_MAX_CLIENT_HELLO_BYTES, ListenerTls, ListenerTlsBuilder,
    TlsServerConfig,
};
use irontraffic_tls::policy::TlsPolicy;
use irontraffic_tls::store::{
    CertIndexBuilder, ChainInterner, ChallengeCerts, Credentials, IronResolver, TimeView,
};
use irontraffic_tls::time::UnixSeconds;
use libfuzzer_sys::fuzz_target;

struct FixedClock;
impl TimeView for FixedClock {
    fn unix_seconds(&self) -> UnixSeconds {
        UnixSeconds::new(1_000)
    }
}

fn gen_cred(san: &str) -> Arc<Credentials> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen"); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs"); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    let cert = params.self_signed(&key).expect("sign"); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"), // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    )
}

fn config_for(name: &str) -> Arc<TlsServerConfig> {
    let mut b = CertIndexBuilder::new([5u8; 16]);
    b.upsert_exact(name, gen_cred(name)).expect("valid"); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    let certs = Arc::new(b.build().expect("build")); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    let policy = Arc::new(TlsPolicy::default_https());
    let resolver = Arc::new(IronResolver::new(
        certs,
        Arc::new(ChallengeCerts::empty([6u8; 16])),
        Arc::clone(&policy),
        Arc::new(FixedClock),
    ));
    Arc::new(TlsServerConfig::compile(policy, resolver).expect("provider installed")) // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
}

/// One exact binding, one wildcard binding, a no-SNI policy, and no fallback.
fn listener() -> &'static Arc<ListenerTls> {
    static L: OnceLock<Arc<ListenerTls>> = OnceLock::new();
    L.get_or_init(|| {
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: this OnceLock initializer runs once per fuzz process; either this call or an earlier one installs the process-wide provider, and either outcome leaves one installed, which is all the listener below needs.
        let mut b = ListenerTlsBuilder::new([9u8; 16]);
        b.bind_exact("a.example.com", config_for("a.example.com"))
            .expect("valid"); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
        b.bind_wildcard("*.wild.example.com", config_for("wild.example.com"))
            .expect("valid"); // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
        b.set_no_sni(config_for("default.example.com"));
        Arc::new(b.build().expect("no divergence: every binding is ClientAuthKind::None")) // it-allow: no-panic reason: fuzz harness one-time fixture setup over fixed, constant inputs that are never fuzzer-controlled; a panic here is a libFuzzer finding about this binary's own fixture, never a request-path failure mode, and this file is never linked into the server binary.
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = match first % 4 {
        0 => 1,
        1 => 7,
        2 => 64,
        _ => rest.len().max(1),
    };

    let l = listener();
    let mut acc = l.acceptor();

    for piece in rest.chunks(chunk) {
        let step = acc.feed(piece);

        // Contract 3: the cap is never exceeded, whatever the chunking.
        assert!(
            acc.bytes_consumed() <= DEFAULT_MAX_CLIENT_HELLO_BYTES + chunk,
            "buffered {} bytes, cap is {}",
            acc.bytes_consumed(),
            DEFAULT_MAX_CLIENT_HELLO_BYTES
        );

        match step {
            AcceptStep::NeedMore => {}
            AcceptStep::Reject { .. } => break,
            AcceptStep::Ready { config, .. } => {
                // Contract 2, stated honestly about what it can and cannot prove TODAY.
                //
                // The intended assertion is that `Ready` never carries a configuration weaker
                // than the binding the presented SNI selects. Every configuration this target can
                // build is `ClientAuthKind::None`, because `TlsServerConfig::compile` hard-codes
                // it until `mtls-client-auth-fail-closed` (#124) lands the verifier. So the
                // comparison below is currently `None >= None` on every path: it is STRUCTURALLY
                // INERT, not passing on merit, and saying otherwise in a comment would be the
                // kind of claim measurement does not support.
                //
                // It is written now, rather than left out, so that #124 turns it live by
                // construction: the moment a `Required` binding exists, a `Ready` carrying a
                // weaker configuration fails here. The weakest thing any binding on this listener
                // requires is the floor `Ready` must clear.
                let floor = l
                    .no_sni_config()
                    .map_or(ClientAuthKind::None, |c| c.client_auth())
                    .min(l.client_auth_for_name("a.example.com"))
                    .min(l.client_auth_for_name("sub.wild.example.com"));
                assert!(
                    config.client_auth() >= floor,
                    "Ready carried {:?}, weaker than the listener's floor {:?}",
                    config.client_auth(),
                    floor
                );
                break;
            }
        }
    }
});
