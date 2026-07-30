// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory rustls handshakes for `UpstreamTls`, `UpstreamVerifier` and `InsecureVerifier`,
//! driven through `client_config_for_dial` exactly as a real dial will use it.
//!
//! `identity_mode_still_rejects_bad_chain` is the CVE-shaped test: it proves that a matching
//! configured identity never rescues a chain that does not verify, which is the same fail-open
//! shape Caddy's CVE-2026-27586 had on the inbound side.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test code: fixtures are built in the test itself, so a failed unwrap is \
              a broken fixture and must be loud rather than silently reshaping the assertion"
)]

use std::sync::atomic::Ordering;
use std::sync::{Arc, Once, OnceLock};

use irontraffic_tls::time::UnixSeconds;
use irontraffic_tls::{
    SubjectAltName, UpstreamPq, UpstreamTls, UpstreamTlsConfig, UpstreamTlsStats, VerifyMode,
};

const NOW_SECS: u64 = 1_700_000_000;

fn now() -> UnixSeconds {
    UnixSeconds::new(NOW_SECS)
}

fn ensure_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
    });
}

/// One CA, generated once and shared by every test that needs "a" CA rather than a specific
/// distinct one: keygen is the slow part, not the per-call sign.
struct CaFixture {
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
    der: Vec<u8>,
}

fn new_ca(cn: &str) -> CaFixture {
    ensure_provider_installed();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;
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
    FIXTURE.get_or_init(|| new_ca("Upstream Verify Integration Test CA"))
}

/// A second, distinct CA, for `identity_mode_still_rejects_bad_chain`: a leaf issued by this one
/// must not verify against `ca_fixture`'s trust anchors even when its identity matches exactly.
fn other_ca_fixture() -> &'static CaFixture {
    static FIXTURE: OnceLock<CaFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| new_ca("Upstream Verify Integration Test CA (Other)"))
}

/// A leaf certificate issued by `fx`, carrying `dns_sans` as `dNSName` entries and `uri_sans` as
/// `uniformResourceIdentifier` entries.
fn leaf_cert(fx: &CaFixture, dns_sans: &[&str], uri_sans: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
    let mut sans = Vec::with_capacity(dns_sans.len() + uri_sans.len());
    for d in dns_sans {
        sans.push(rcgen::SanType::DnsName(
            (*d).try_into().expect("valid dns san"),
        ));
    }
    for u in uri_sans {
        sans.push(rcgen::SanType::URI((*u).try_into().expect("valid uri san")));
    }
    params.subject_alt_names = sans;
    let issuer = rcgen::Issuer::from_params(&fx.params, &fx.key);
    let cert = params.signed_by(&key, &issuer).expect("sign by CA");
    (cert.der().to_vec(), key.serialize_der())
}

/// A self-signed leaf with no CA involvement at all, for the insecure-mode test.
fn self_signed_leaf(cn: &str) -> (Vec<u8>, Vec<u8>) {
    ensure_provider_installed();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("valid SAN");
    let cert = params.self_signed(&key).expect("self sign");
    (cert.der().to_vec(), key.serialize_der())
}

/// A plain rustls server presenting `leaf_der`/`key_der`, standing in for the upstream cluster.
fn server_config(leaf_der: Vec<u8>, key_der: &[u8]) -> Arc<rustls::ServerConfig> {
    ensure_provider_installed();
    let provider = Arc::clone(irontraffic_tls::provider::provider().expect("provider installed"));
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .expect("valid key")
        .clone_key();
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(leaf_der)], key)
        .expect("server config");
    Arc::new(cfg)
}

/// The default upstream configuration every test starts from: verification on, no identities
/// configured (hostname mode), classical only.
fn base_cfg(hostname: &str) -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        hostname: hostname.to_owned(),
        well_known_ca_certificates: None,
        subject_alt_names: Vec::new(),
        alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
        post_quantum: UpstreamPq::Off,
        insecure_skip_verify: false,
        i_accept_the_risk: false,
    }
}

/// Drives two in-memory TLS endpoints through a handshake, returning the first error either side
/// reports, `None` if both complete, or `Some` synthetic error if the 16-round-trip budget is
/// exhausted while either side is STILL handshaking. That third outcome matters as much as the
/// other two: without it, a stalled handshake that never errors and never finishes is
/// indistinguishable from a completed one, and a caller asserting `is_none()` to mean "succeeded"
/// would pass on a connection that never actually exchanged the bytes a completed handshake
/// requires. Same shape used throughout this crate's own test suite (`policy.rs`,
/// `tests/mtls_fail_closed.rs`), duplicated rather than shared because each of those lives in a
/// module or crate this file cannot see.
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
            return None;
        }
    }
    Some(std::io::Error::other(
        "handshake did not complete within the round-trip budget",
    ))
}

/// Dials `server_cfg` using `upstream`'s own `client_config_for_dial` and SNI, exactly as a real
/// connector would.
fn handshake(
    upstream: &UpstreamTls,
    server_cfg: &Arc<rustls::ServerConfig>,
) -> Option<std::io::Error> {
    let client_cfg = Arc::clone(upstream.client_config_for_dial(now()));
    let server_name = upstream
        .sni()
        .to_owned()
        .try_into()
        .expect("a normalized SNI is always a valid ServerName");
    let mut client =
        rustls::ClientConnection::new(client_cfg, server_name).expect("client connection");
    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg)).expect("server connection");
    pump_handshake(&mut client, &mut server)
}

#[test]
fn hostname_mode_accepts_matching_cert() {
    let fx = ca_fixture();
    let cfg = base_cfg("backend.example.com");
    let anchors: &[&[u8]] = &[&fx.der];
    let upstream = UpstreamTls::compile(
        &cfg,
        Some(anchors),
        None,
        Arc::new(UpstreamTlsStats::default()),
    )
    .expect("a valid hostname-mode configuration must compile");
    assert_eq!(upstream.verify_mode(), VerifyMode::Hostname);

    let (leaf_der, key_der) = leaf_cert(fx, &["backend.example.com"], &[]);
    let server_cfg = server_config(leaf_der, &key_der);
    assert!(
        handshake(&upstream, &server_cfg).is_none(),
        "a certificate whose dNSName matches the hostname must complete the handshake"
    );
}

#[test]
fn hostname_mode_rejects_wrong_name() {
    let fx = ca_fixture();
    let cfg = base_cfg("backend.example.com");
    let anchors: &[&[u8]] = &[&fx.der];
    let upstream = UpstreamTls::compile(
        &cfg,
        Some(anchors),
        None,
        Arc::new(UpstreamTlsStats::default()),
    )
    .expect("a valid hostname-mode configuration must compile");

    let (leaf_der, key_der) = leaf_cert(fx, &["totally-different.example.com"], &[]);
    let server_cfg = server_config(leaf_der, &key_der);
    assert!(
        handshake(&upstream, &server_cfg).is_some(),
        "a certificate whose dNSName does not match the hostname must not complete the handshake"
    );
}

#[test]
fn identity_mode_accepts_matching_uri_san() {
    let fx = ca_fixture();
    let uri = "spiffe://example.org/ns/prod/sa/backend";
    let cfg = UpstreamTlsConfig {
        subject_alt_names: vec![SubjectAltName::Uri {
            uri: uri.to_owned(),
        }],
        ..base_cfg("backend.svc.cluster.local")
    };
    let anchors: &[&[u8]] = &[&fx.der];
    let upstream = UpstreamTls::compile(
        &cfg,
        Some(anchors),
        None,
        Arc::new(UpstreamTlsStats::default()),
    )
    .expect("a valid identity-mode configuration must compile");
    assert_eq!(upstream.verify_mode(), VerifyMode::Identity);

    let (leaf_der, key_der) = leaf_cert(fx, &[], &[uri]);
    let server_cfg = server_config(leaf_der, &key_der);
    assert!(
        handshake(&upstream, &server_cfg).is_none(),
        "an exact URI SAN match must complete the handshake"
    );
}

#[test]
fn identity_mode_rejects_one_char_different_uri_san() {
    let fx = ca_fixture();
    // The same peer chain as `identity_mode_accepts_matching_uri_san`: the peer's URI SAN is the
    // identical string. Only the CONFIGURED identity differs, by exactly one character (the
    // final letter's case).
    let peer_uri = "spiffe://example.org/ns/prod/sa/backend";
    let configured_uri = "spiffe://example.org/ns/prod/sa/backenD";
    assert_eq!(
        peer_uri.len(),
        configured_uri.len(),
        "fixture precondition: the two URIs differ in exactly one character, not in length"
    );
    let cfg = UpstreamTlsConfig {
        subject_alt_names: vec![SubjectAltName::Uri {
            uri: configured_uri.to_owned(),
        }],
        ..base_cfg("backend.svc.cluster.local")
    };
    let anchors: &[&[u8]] = &[&fx.der];
    let upstream = UpstreamTls::compile(
        &cfg,
        Some(anchors),
        None,
        Arc::new(UpstreamTlsStats::default()),
    )
    .expect("a valid identity-mode configuration must compile");

    let (leaf_der, key_der) = leaf_cert(fx, &[], &[peer_uri]);
    let server_cfg = server_config(leaf_der, &key_der);
    assert!(
        handshake(&upstream, &server_cfg).is_some(),
        "a URI SAN differing by one character must not complete the handshake: byte-exact means \
         byte-exact"
    );
}

#[test]
fn identity_mode_still_rejects_bad_chain() {
    let fx = ca_fixture();
    let other = other_ca_fixture();
    let uri = "spiffe://example.org/ns/prod/sa/backend";
    let cfg = UpstreamTlsConfig {
        subject_alt_names: vec![SubjectAltName::Uri {
            uri: uri.to_owned(),
        }],
        ..base_cfg("backend.svc.cluster.local")
    };
    // Trust `fx`, but the peer's chain is issued by `other`, an unrelated CA. Its URI SAN
    // matches the configured identity exactly.
    let anchors: &[&[u8]] = &[&fx.der];
    let upstream = UpstreamTls::compile(
        &cfg,
        Some(anchors),
        None,
        Arc::new(UpstreamTlsStats::default()),
    )
    .expect("a valid identity-mode configuration must compile");

    let (leaf_der, key_der) = leaf_cert(other, &[], &[uri]);
    let server_cfg = server_config(leaf_der, &key_der);
    assert!(
        handshake(&upstream, &server_cfg).is_some(),
        "chain first, always: a matching identity must not rescue a chain that does not verify"
    );
}

#[test]
fn insecure_mode_accepts_self_signed_and_counts() {
    // Unlike every other test in this file, this one never calls `ca_fixture()`, so nothing
    // else installs the process crypto provider before `UpstreamTls::compile` needs it.
    ensure_provider_installed();
    let cfg = UpstreamTlsConfig {
        insecure_skip_verify: true,
        i_accept_the_risk: true,
        ..base_cfg("backend.example.com")
    };
    let stats = Arc::new(UpstreamTlsStats::default());
    let upstream = UpstreamTls::compile(&cfg, None, None, Arc::clone(&stats))
        .expect("insecureSkipVerify with iAcceptTheRisk must compile");
    assert_eq!(upstream.verify_mode(), VerifyMode::Insecure);

    let (leaf_der, key_der) = self_signed_leaf("totally-unrelated.example");
    let server_cfg = server_config(leaf_der, &key_der);
    assert!(
        handshake(&upstream, &server_cfg).is_none(),
        "insecure mode must accept a self-signed, entirely unrelated certificate"
    );
    assert_eq!(
        stats.unverified_connections.load(Ordering::Relaxed),
        1,
        "exactly one handshake must produce exactly one count"
    );
}
