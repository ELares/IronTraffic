// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CVE-shaped integration tests for client certificate authentication, driving real in-memory
//! rustls handshakes with `rcgen`-generated fixtures.
//!
//! Each test is named for the failure it prevents. `cve_2026_27586_empty_ca_bundle_refuses_to_compile`
//! is the headline: Caddy's CVE-2026-27586 was mTLS silently failing open when the CA certificate
//! file was missing or malformed, and this test asserts that path is not representable here at
//! all, not merely that it is checked for.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test code: fixtures are built in the test itself, so a failed unwrap is \
              a broken fixture and must be loud rather than silently reshaping the assertion"
)]

use std::sync::{Arc, Once, OnceLock};

use irontraffic_tls::crl::{self, CrlConfig, CrlSet, RevocationIndex};
use irontraffic_tls::listener::TlsServerConfig;
use irontraffic_tls::policy::TlsPolicy;
use irontraffic_tls::store::{
    CertIndexBuilder, ChainInterner, ChallengeCerts, Credentials, IronResolver, TimeView,
};
use irontraffic_tls::time::UnixSeconds;
use irontraffic_tls::verify_client::{
    ClientAuth, ClientAuthConfig, ClientAuthError, ClientAuthMode, RevocationMode, TrustAnchors,
};

const SEED: [u8; 16] = [23u8; 16];

fn ensure_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
    });
}

struct FixedClock(UnixSeconds);
impl TimeView for FixedClock {
    fn unix_seconds(&self) -> UnixSeconds {
        self.0
    }
}

/// One CA, generated once and shared by every test in this file: keygen is the slow part, not
/// the per-call sign.
struct CaFixture {
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
    der: Vec<u8>,
}

fn distinguished_name(cn: &str) -> rcgen::DistinguishedName {
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, cn);
    name
}

fn new_ca(cn: &str) -> CaFixture {
    ensure_provider_installed();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
    params.distinguished_name = distinguished_name(cn);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let cert = params.self_signed(&key).expect("self sign");
    let der = cert.der().to_vec();
    CaFixture { key, params, der }
}

fn ca_fixture() -> &'static CaFixture {
    static FIXTURE: OnceLock<CaFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| new_ca("mTLS Integration Test CA"))
}

/// A client leaf issued by `fx`, carrying `serial`.
fn client_leaf(fx: &CaFixture, cn: &str, serial: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
    params.distinguished_name = distinguished_name(cn);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
    let issuer = rcgen::Issuer::from_params(&fx.params, &fx.key);
    let cert = params.signed_by(&key, &issuer).expect("sign by CA");
    (cert.der().to_vec(), key.serialize_der())
}

/// An intermediate CA issued by `parent`, carrying `serial`.
fn intermediate_ca(parent: &CaFixture, cn: &str, serial: &[u8]) -> CaFixture {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
    params.distinguished_name = distinguished_name(cn);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
    let issuer = rcgen::Issuer::from_params(&parent.params, &parent.key);
    let cert = params.signed_by(&key, &issuer).expect("sign by parent CA");
    let der = cert.der().to_vec();
    CaFixture { key, params, der }
}

/// A validly signed, wide-validity (2020..2030) `RevocationIndex` over `fx`, revoking `serials`.
fn revocation_index_for(fx: &CaFixture, serials: &[&[u8]]) -> Arc<RevocationIndex> {
    let revocation_time = rcgen::date_time_ymd(2020, 1, 1);
    let revoked_certs = serials
        .iter()
        .map(|s| rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(s),
            revocation_time,
            reason_code: None,
            invalidity_date: None,
        })
        .collect();
    let issuer = rcgen::Issuer::from_params(&fx.params, &fx.key);
    let params = rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2020, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let der = params
        .signed_by(&issuer)
        .expect("signing a fixture CRL must not fail")
        .der()
        .to_vec();

    let cfg = CrlConfig::default();
    let parsed = crl::parse(&der, &cfg).expect("fixture CRL must parse");
    let verified =
        crl::verify_signature(parsed, &fx.der).expect("fixture CRL must verify against its own CA");
    Arc::new(
        RevocationIndex::build(&verified, UnixSeconds::new(1_704_000_000), &cfg)
            .expect("fixture CRL must build"),
    )
}

/// A `CrlSet` covering a single issuer.
fn crl_set_covering(fx: &CaFixture, serials: &[&[u8]]) -> Arc<CrlSet> {
    Arc::new(CrlSet::from_indices(
        vec![revocation_index_for(fx, serials)],
        1,
    ))
}

/// A `CrlSet` covering MULTIPLE issuers at once, one index per `(fx, serials)` pair. Needed
/// whenever a chain crosses more than one issuer: `RevocationCheckDepth::Chain` means every chain
/// element's OWN issuer is looked up, so a two-level chain (leaf issued by an intermediate,
/// intermediate issued by a root) needs coverage for both issuers, or the leaf's own lookup
/// misses before the loop ever reaches the intermediate.
fn crl_set_covering_multi(pairs: &[(&CaFixture, &[&[u8]])]) -> Arc<CrlSet> {
    let indices = pairs
        .iter()
        .map(|(fx, serials)| revocation_index_for(fx, serials))
        .collect();
    Arc::new(CrlSet::from_indices(indices, 1))
}

/// A real server-side configuration serving `san` for `name`, with client authentication `auth`.
/// Returns the config plus the server's own self-signed leaf DER, so a test client can be built
/// to trust it.
fn server_config(
    name: &str,
    san: &str,
    auth: &ClientAuth,
    crls: Arc<CrlSet>,
    time_secs: u64,
) -> (Arc<TlsServerConfig>, Vec<u8>) {
    ensure_provider_installed();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SAN");
    params.distinguished_name = distinguished_name(san);
    let leaf_cert = params.self_signed(&key).expect("self sign");
    let leaf_der = leaf_cert.der().to_vec();
    let mut interner = ChainInterner::new();
    let cred = Arc::new(
        Credentials::load(&[&leaf_der], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    );
    let mut b = CertIndexBuilder::new(SEED);
    b.upsert_exact(name, cred).expect("valid");
    let certs = Arc::new(b.build().expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(time_secs)));
    let resolver = Arc::new(IronResolver::new(
        certs,
        challenge,
        Arc::clone(&policy),
        Arc::clone(&time),
    ));
    let cfg = Arc::new(
        TlsServerConfig::compile_with_client_auth(
            policy,
            resolver,
            auth,
            crls,
            CrlConfig::default(),
            false,
            RevocationMode::Enforced,
            time,
            None,
        )
        .expect("a valid ClientAuth and coverage must compile"),
    );
    (cfg, leaf_der)
}

fn plain_client(server_name: &'static str, trust: &[&[u8]]) -> rustls::ClientConnection {
    ensure_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    for der in trust {
        roots
            .add(rustls::pki_types::CertificateDer::from((*der).to_vec()))
            .expect("valid trust anchor");
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls::ClientConnection::new(
        Arc::new(client_cfg),
        server_name.try_into().expect("valid server name"),
    )
    .expect("client connection")
}

fn client_with_cert(
    server_name: &'static str,
    trust: &[&[u8]],
    chain_ders: &[&[u8]],
    key_der: &[u8],
) -> rustls::ClientConnection {
    ensure_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    for der in trust {
        roots
            .add(rustls::pki_types::CertificateDer::from((*der).to_vec()))
            .expect("valid trust anchor");
    }
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .expect("valid key")
        .clone_key();
    let chain: Vec<rustls::pki_types::CertificateDer<'static>> = chain_ders
        .iter()
        .map(|d| rustls::pki_types::CertificateDer::from((*d).to_vec()))
        .collect();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("valid client cert and key");
    rustls::ClientConnection::new(
        Arc::new(client_cfg),
        server_name.try_into().expect("valid server name"),
    )
    .expect("client connection")
}

/// Drives two in-memory TLS endpoints through a handshake, returning the first error either side
/// reports, or `None` if both complete. Same shape used throughout this crate's own test suite
/// (`policy.rs`, `tests/handshake_resolver.rs`, `tests/sni_policy_fail_closed.rs`), duplicated
/// rather than shared because each of those lives in a module or crate this file cannot see.
fn pump_handshake(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Option<std::io::Error> {
    for _ in 0..16 {
        let mut buf = Vec::new();
        if client.write_tls(&mut buf).is_ok()
            && !buf.is_empty()
            && let Err(e) = server
                .read_tls(&mut buf.as_slice())
                .map(|_| ())
                .and_then(|()| {
                    server
                        .process_new_packets()
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                })
        {
            return Some(e);
        }
        let mut buf = Vec::new();
        if server.write_tls(&mut buf).is_ok()
            && !buf.is_empty()
            && let Err(e) = client
                .read_tls(&mut buf.as_slice())
                .map(|_| ())
                .and_then(|()| {
                    client
                        .process_new_packets()
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                })
        {
            return Some(e);
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    None
}

#[test]
fn cve_2026_27586_empty_ca_bundle_refuses_to_compile() {
    // Caddy's CVE-2026-27586: mTLS silently failed open when the CA certificate file was missing
    // or malformed. Here that path is not representable: `ClientAuth::compile` with `required`
    // and an empty bundle refuses at configuration compile time, and no verifier and no
    // `ServerConfig` are ever produced. Asserted at the type level, not just behaviourally: the
    // `Err` arm below is the ONLY value `compile` can produce for this input, so there is no
    // `TrustAnchors`, no `ClientAuth::Required`, and therefore no `TlsServerConfig` for a caller
    // to accidentally bind anyway.
    let cfg = ClientAuthConfig {
        mode: ClientAuthMode::Required,
        allow_unknown_revocation_status: false,
        revocation: RevocationMode::Enforced,
    };
    let result = ClientAuth::compile(&cfg, Some(&[]));
    match result {
        Err(e) => assert_eq!(e, ClientAuthError::EmptyTrustBundle),
        Ok(_) => panic!(
            "an empty trust bundle with mode: required must refuse to compile; this is \
             CVE-2026-27586"
        ),
    }
}

#[test]
fn required_without_client_cert_fails_handshake() {
    let fx = ca_fixture();
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let crls = crl_set_covering(fx, &[]);
    let auth = ClientAuth::Required(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "required.example.com",
        "required.example.com",
        &auth,
        crls,
        1_704_000_000,
    );

    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");
    let mut client = plain_client("required.example.com", &[&server_leaf_der]);

    let err = pump_handshake(&mut client, &mut server);
    assert!(
        err.is_some(),
        "a Required listener must fail the handshake when the client presents no certificate"
    );
}

#[test]
fn optional_without_client_cert_succeeds_and_reports_no_peer_cert() {
    let fx = ca_fixture();
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let crls = crl_set_covering(fx, &[]);
    let auth = ClientAuth::Optional(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "optional.example.com",
        "optional.example.com",
        &auth,
        crls,
        1_704_000_000,
    );

    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");
    let mut client = plain_client("optional.example.com", &[&server_leaf_der]);

    assert!(
        pump_handshake(&mut client, &mut server).is_none(),
        "an Optional listener must complete the handshake when the client presents nothing"
    );
    assert!(
        server.peer_certificates().is_none(),
        "no client certificate was presented, so the server must report none"
    );
}

#[test]
fn revoked_client_cert_is_rejected_end_to_end() {
    let fx = ca_fixture();
    let serial: &[u8] = &[0x2a];
    let (leaf_der, key_der) = client_leaf(fx, "revoked-leaf.example", serial);
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let crls = crl_set_covering(fx, &[serial]);
    let auth = ClientAuth::Required(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "revoked-leaf-server.example.com",
        "revoked-leaf-server.example.com",
        &auth,
        crls,
        1_704_000_000,
    );

    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");
    let mut client = client_with_cert(
        "revoked-leaf-server.example.com",
        &[&server_leaf_der],
        &[&leaf_der],
        &key_der,
    );

    let err = pump_handshake(&mut client, &mut server);
    assert!(
        err.is_some(),
        "a client certificate whose own serial is on the CRL must fail the handshake"
    );
}

#[test]
fn revoked_intermediate_is_rejected_end_to_end() {
    // Without `RevocationCheckDepth::Chain` (checking every chain element, not only the leaf)
    // this handshake would SUCCEED: the revoked serial belongs to the intermediate, never
    // presented by the leaf itself. This is the test that proves the depth.
    let root = ca_fixture();
    let intermediate_serial: &[u8] = &[0x33];
    let intermediate =
        intermediate_ca(root, "Revoked Intermediate End To End", intermediate_serial);
    let (leaf_der, key_der) = client_leaf(
        &intermediate,
        "leaf-under-revoked-intermediate-e2e.example",
        &[0x01],
    );

    let anchors = TrustAnchors::from_der_bundle(&[&root.der]).expect("a real CA must build");
    // Coverage for BOTH issuers the chain crosses: the leaf's own issuer (the intermediate, empty
    // revoked list) and the intermediate's issuer (root, revoking the intermediate's serial).
    let empty: &[&[u8]] = &[];
    let revoked: &[&[u8]] = &[intermediate_serial];
    let crls = crl_set_covering_multi(&[(&intermediate, empty), (root, revoked)]);
    let auth = ClientAuth::Required(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "revoked-intermediate-server.example.com",
        "revoked-intermediate-server.example.com",
        &auth,
        crls,
        1_704_000_000,
    );

    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");
    // The client presents its FULL chain (leaf, then the intermediate that issued it), matching
    // what a real client with a multi-level certificate does.
    let mut client = client_with_cert(
        "revoked-intermediate-server.example.com",
        &[&server_leaf_der],
        &[&leaf_der, &intermediate.der],
        &key_der,
    );

    let err = pump_handshake(&mut client, &mut server);
    assert!(
        err.is_some(),
        "a chain whose INTERMEDIATE is revoked must fail the handshake; without RevocationCheckDepth::Chain \
         this would incorrectly succeed"
    );
}
