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

use std::sync::atomic::Ordering;
use std::sync::{Arc, Once, OnceLock};

use irontraffic_tls::crl::{self, CrlConfig, CrlSet, RevocationIndex};
use irontraffic_tls::listener::{ClientAuthKind, ListenerError, TlsServerConfig};
use irontraffic_tls::policy::TlsPolicy;
use irontraffic_tls::store::{
    CertIndexBuilder, ChainInterner, ChallengeCerts, Credentials, IronResolver, TimeView,
};
use irontraffic_tls::ticket::{NonceSource, RandNonceSource};
use irontraffic_tls::time::UnixSeconds;
use irontraffic_tls::verify_client::{
    ClientAuth, ClientAuthConfig, ClientAuthError, ClientAuthMode, RevocationMode, TrustAnchors,
};
use irontraffic_tls::{ClusterTicketer, TicketRoot};

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

/// A second, distinct CA, for the tests that need two different trust bundles (the ticketer
/// context binding, PR 766 review #773 BLOCKING 1).
fn other_ca_fixture() -> &'static CaFixture {
    static FIXTURE: OnceLock<CaFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| new_ca("mTLS Integration Test CA (Other)"))
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

/// A real server-side configuration serving `san` for `name`, with client authentication `auth`
/// and `revocation` read from a real `ClientAuthConfig` document, not a separately-sourced
/// literal: `compile_with_client_auth` takes `&ClientAuthConfig` for exactly this reason (PR 766
/// review, #773 `SHOULD_FIX` 4). `ticketer`, when `Some`, is installed exactly the way a real
/// listener would (PR 766 review, #773 BLOCKING 1). Returns whatever
/// `TlsServerConfig::compile_with_client_auth` itself returns, so a negative test can observe a
/// refusal instead of this helper panicking on its behalf.
fn try_server_config(
    name: &str,
    san: &str,
    auth: &ClientAuth,
    crls: Arc<CrlSet>,
    time_secs: u64,
    revocation: RevocationMode,
    ticketer: Option<Arc<ClusterTicketer>>,
) -> Result<(Arc<TlsServerConfig>, Vec<u8>), ListenerError> {
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
    let mode = match auth {
        ClientAuth::None => ClientAuthMode::None,
        ClientAuth::Optional(_) => ClientAuthMode::Optional,
        ClientAuth::Required(_) => ClientAuthMode::Required,
    };
    let auth_cfg = ClientAuthConfig {
        mode,
        allow_unknown_revocation_status: false,
        revocation,
    };
    let cfg = TlsServerConfig::compile_with_client_auth(
        policy,
        resolver,
        auth,
        crls,
        CrlConfig::default(),
        &auth_cfg,
        time,
        ticketer,
    )?;
    Ok((Arc::new(cfg), leaf_der))
}

/// The infallible wrapper every positive test in this file uses: same contract as
/// [`try_server_config`], but panics (with the compile error's own `Display`) instead of
/// returning `Err`, since a positive test's fixture failing to compile is a broken fixture.
fn server_config(
    name: &str,
    san: &str,
    auth: &ClientAuth,
    crls: Arc<CrlSet>,
    time_secs: u64,
    revocation: RevocationMode,
    ticketer: Option<Arc<ClusterTicketer>>,
) -> (Arc<TlsServerConfig>, Vec<u8>) {
    try_server_config(name, san, auth, crls, time_secs, revocation, ticketer)
        .expect("a valid ClientAuth and coverage must compile")
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
/// reports, `None` if both complete, or `Some` synthetic error if the 16-round-trip budget is
/// exhausted while either side is STILL handshaking. That last case matters as much as the other
/// two: without it, a stalled handshake (one that never errors but also never finishes) is
/// indistinguishable from a genuinely completed one, and a caller asserting `is_none()` to mean
/// "succeeded" would pass on a connection that exchanged zero, or partial, bytes.
///
/// Same shape used throughout this crate's own test suite (`policy.rs`,
/// `tests/handshake_resolver.rs`, `tests/sni_policy_fail_closed.rs`), duplicated rather than
/// shared because each of those lives in a module or crate this file cannot see.
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
        "handshake did not complete within the 16-round-trip budget",
    ))
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
        RevocationMode::Enforced,
        None,
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
        RevocationMode::Enforced,
        None,
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
        RevocationMode::Enforced,
        None,
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
    // The acceptance criterion asks for more than "the handshake failed": it must have failed
    // FOR REVOCATION specifically, not for some other reason the same assertion above could not
    // distinguish (PR 766 review, #773 SHOULD_FIX 6).
    assert_eq!(
        server_cfg
            .client_auth_stats()
            .expect("a Required configuration installs a verifier with counters")
            .revoked_denied
            .load(Ordering::Relaxed),
        1,
        "the handshake must have failed because the revocation check denied it, not for any \
         other reason"
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
        RevocationMode::Enforced,
        None,
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
    assert_eq!(
        server_cfg
            .client_auth_stats()
            .expect("a Required configuration installs a verifier with counters")
            .revoked_denied
            .load(Ordering::Relaxed),
        1,
        "the handshake must have failed because the revocation check denied the intermediate, \
         not for any other reason"
    );
}

#[test]
fn client_auth_ticketer_context_matches_trust_bundle_through_compile() {
    // BLOCKING 1 (PR 766 review, #773): the previously shipped acceptance test never called
    // `compile` or `compile_with_client_auth` at all, so both ticketer install sites (this
    // file's `server_config` builds through `compile_with_client_auth`, which is what deleting
    // them left green) could be deleted with the whole suite passing. This test drives the real
    // constructors and pulls the ticketer back out of the compiled `ServerConfig` itself.
    let fx_a = ca_fixture();
    let fx_b = other_ca_fixture();
    let anchors_a = TrustAnchors::from_der_bundle(&[&fx_a.der]).expect("a real CA must build");
    let anchors_b = TrustAnchors::from_der_bundle(&[&fx_b.der]).expect("a real CA must build");
    assert_ne!(
        anchors_a.id(),
        anchors_b.id(),
        "fixture bug: two distinct CAs must have distinct trust-bundle ids"
    );

    let nonces: Arc<dyn NonceSource> = Arc::new(RandNonceSource);
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_704_000_000)));
    let ticketer_a = Arc::new(ClusterTicketer::new(
        TicketRoot::new([9u8; 32]),
        anchors_a.id(),
        21_600,
        Arc::clone(&time),
        Arc::clone(&nonces),
    ));
    let ticketer_b = Arc::new(ClusterTicketer::new(
        TicketRoot::new([9u8; 32]),
        anchors_b.id(),
        21_600,
        Arc::clone(&time),
        Arc::clone(&nonces),
    ));

    let crls_a = crl_set_covering(fx_a, &[]);
    let (cfg_a, _leaf_a) = server_config(
        "ticketer-a.example.com",
        "ticketer-a.example.com",
        &ClientAuth::Required(anchors_a),
        crls_a,
        1_704_000_000,
        RevocationMode::Enforced,
        Some(Arc::clone(&ticketer_a)),
    );
    let crls_b = crl_set_covering(fx_b, &[]);
    let (cfg_b, _leaf_b) = server_config(
        "ticketer-b.example.com",
        "ticketer-b.example.com",
        &ClientAuth::Required(anchors_b),
        crls_b,
        1_704_000_000,
        RevocationMode::Enforced,
        Some(Arc::clone(&ticketer_b)),
    );

    // The mechanism the acceptance criterion actually names: the ticketer INSTALLED on the
    // compiled `ServerConfig`, read back through `as_rustls().ticketer`, is what a resumed TLS
    // 1.3 handshake would invoke. This also pins `cfg.ticketer` and `send_tls13_tickets` as
    // installed: MUTATION 4 from #773 (replacing both install blocks with `let _ = &ticketer;`)
    // leaves `installed_a.enabled()` false and `send_tls13_tickets` at rustls's own default, so
    // both assertions below would fail under that mutation.
    let installed_a = &cfg_a.as_rustls().ticketer;
    let installed_b = &cfg_b.as_rustls().ticketer;
    assert!(
        installed_a.enabled(),
        "a Some(ticketer) argument must be installed and enabled on the compiled ServerConfig"
    );
    assert_eq!(cfg_a.as_rustls().send_tls13_tickets, 2);

    let ticket = installed_a
        .encrypt(b"resumption-secret-material")
        .expect("encrypt must succeed");
    assert!(
        installed_a.decrypt(&ticket).is_some(),
        "a ticketer must decrypt a ticket it minted itself"
    );
    assert!(
        installed_b.decrypt(&ticket).is_none(),
        "a ticket minted under one trust bundle's INSTALLED ticketer must not decrypt under \
         another bundle's installed ticketer; this is CVE-2025-68121's shape if it does"
    );
}

#[test]
fn client_auth_none_ticketer_uses_zero_context_through_compile() {
    // The companion of the test above for `TlsServerConfig::compile` (`ClientAuthKind::None`):
    // its own doc requires the 16-zero-byte context, exercised here through
    // `compile_with_client_auth(&ClientAuth::None, ...)`, which delegates to `compile` verbatim
    // (the same code path a listener with no client authentication actually takes).
    let fx = ca_fixture();
    let nonces: Arc<dyn NonceSource> = Arc::new(RandNonceSource);
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_704_000_000)));
    let ticketer_none = Arc::new(ClusterTicketer::new(
        TicketRoot::new([9u8; 32]),
        [0u8; 16],
        21_600,
        Arc::clone(&time),
        Arc::clone(&nonces),
    ));
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let ticketer_required = Arc::new(ClusterTicketer::new(
        TicketRoot::new([9u8; 32]),
        anchors.id(),
        21_600,
        Arc::clone(&time),
        nonces,
    ));

    let crls = crl_set_covering(fx, &[]);
    let (cfg_none, _leaf) = server_config(
        "ticketer-none.example.com",
        "ticketer-none.example.com",
        &ClientAuth::None,
        crls,
        1_704_000_000,
        RevocationMode::Enforced,
        Some(Arc::clone(&ticketer_none)),
    );
    assert_eq!(cfg_none.client_auth(), ClientAuthKind::None);

    let installed_none = &cfg_none.as_rustls().ticketer;
    let ticket = installed_none
        .encrypt(b"none-context-ticket")
        .expect("encrypt must succeed");
    assert!(installed_none.decrypt(&ticket).is_some());
    assert!(
        ticketer_required.decrypt(&ticket).is_none(),
        "a ticket minted under the 16-zero-byte (ClientAuthKind::None) context must not decrypt \
         under a Required configuration's own trust-bundle context"
    );
}

#[test]
fn ticketer_context_mismatch_refuses_to_compile() {
    // Invariant 13 in issue #124's own Design section claims "there is no path that installs a
    // context-free one." Before `ClusterTicketer::context()` existed, nothing could check that:
    // `compile_with_client_auth` accepted any `Arc<ClusterTicketer>` and had no way to tell it
    // apart from a correctly contexted one (#773 BLOCKING 1's finding on invariant 13). This test
    // drives the refusal now that the accessor and the check both exist.
    let fx = ca_fixture();
    let other = other_ca_fixture();
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let other_anchors = TrustAnchors::from_der_bundle(&[&other.der]).expect("a real CA must build");

    let nonces: Arc<dyn NonceSource> = Arc::new(RandNonceSource);
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_704_000_000)));
    // Contexted for `other_anchors`, but about to be installed into a configuration whose trust
    // bundle is `anchors`: exactly the mismatch invariant 13 says cannot happen.
    let mismatched_ticketer = Arc::new(ClusterTicketer::new(
        TicketRoot::new([3u8; 32]),
        other_anchors.id(),
        21_600,
        Arc::clone(&time),
        nonces,
    ));

    let crls = crl_set_covering(fx, &[]);
    let err = try_server_config(
        "mismatched-ticketer.example.com",
        "mismatched-ticketer.example.com",
        &ClientAuth::Required(anchors),
        crls,
        1_704_000_000,
        RevocationMode::Enforced,
        Some(mismatched_ticketer),
    )
    .expect_err(
        "a ticketer contexted for a DIFFERENT trust bundle must refuse to compile, not install \
         silently",
    );
    assert_eq!(err, ListenerError::TicketerContextMismatch);
}

#[test]
fn compile_itself_refuses_a_non_zero_context_ticketer() {
    // The companion of the test above, but calling `TlsServerConfig::compile` DIRECTLY rather
    // than through `compile_with_client_auth(&ClientAuth::None, ...)`. The latter's own guard
    // (computed from `auth.anchors()`, which is `None` for `ClientAuth::None` and therefore
    // expects 16 zero bytes) would catch the same mistake before ever reaching `compile`'s body,
    // so it cannot by itself prove `compile`'s own internal check is what is doing the refusing.
    // This test calls the two-argument-plus-ticketer constructor with no `ClientAuth` in the
    // picture at all.
    ensure_provider_installed();
    let fx = ca_fixture();
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let nonces: Arc<dyn NonceSource> = Arc::new(RandNonceSource);
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_704_000_000)));
    // Non-zero context: `compile`'s `ClientAuthKind` is always `None`, which requires exactly
    // 16 zero bytes, so any real trust-bundle id is a mismatch here.
    let ticketer = Arc::new(ClusterTicketer::new(
        TicketRoot::new([5u8; 32]),
        anchors.id(),
        21_600,
        Arc::clone(&time),
        nonces,
    ));

    let mut interner = ChainInterner::new();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params = rcgen::CertificateParams::new(vec!["compile-direct.example.com".to_owned()])
        .expect("valid SAN");
    params.distinguished_name = distinguished_name("compile-direct.example.com");
    let leaf_der = params.self_signed(&key).expect("self sign").der().to_vec();
    let cred = Arc::new(
        Credentials::load(&[&leaf_der], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    );
    let mut b = CertIndexBuilder::new(SEED);
    b.upsert_exact("compile-direct.example.com", cred)
        .expect("valid");
    let certs = Arc::new(b.build().expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let resolver = Arc::new(IronResolver::new(
        certs,
        challenge,
        Arc::clone(&policy),
        Arc::clone(&time),
    ));

    let err = TlsServerConfig::compile(policy, resolver, Some(ticketer))
        .expect_err("a non-zero-context ticketer must refuse compile()'s own guard");
    assert_eq!(err, ListenerError::TicketerContextMismatch);
}

#[test]
fn client_cert_signed_by_untrusted_ca_is_rejected_and_counted() {
    // BLOCKING 2 (PR 766 review, #773): `verify_tls13_signature` (and `verify_tls12_signature`)
    // can be replaced by an unconditional `HandshakeSignatureValid::assertion()` with the whole
    // suite green, because nothing in the shipped suite presented a certificate signed by a CA
    // outside the configured trust bundle. Proof of possession is the entire point of mTLS; this
    // test constructs exactly that certificate and drives a real handshake against it.
    let fx = ca_fixture();
    let untrusted = new_ca("mTLS Integration Test CA (Untrusted, Not In Bundle)");
    let (leaf_der, key_der) = client_leaf(&untrusted, "untrusted-client.example", &[0x01]);

    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let crls = crl_set_covering(fx, &[]);
    let auth = ClientAuth::Required(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "untrusted-client-server.example.com",
        "untrusted-client-server.example.com",
        &auth,
        crls,
        1_704_000_000,
        RevocationMode::Enforced,
        None,
    );

    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");
    let mut client = client_with_cert(
        "untrusted-client-server.example.com",
        &[&server_leaf_der],
        &[&leaf_der],
        &key_der,
    );

    let err = pump_handshake(&mut client, &mut server);
    assert!(
        err.is_some(),
        "a client certificate signed by a CA outside the configured trust bundle must fail the \
         handshake"
    );
    assert_eq!(
        server_cfg
            .client_auth_stats()
            .expect("a Required configuration installs a verifier with counters")
            .chain_rejects
            .load(Ordering::Relaxed),
        1,
        "the rejection must be counted as a chain rejection, the counter incremented on the \
         path `verify_client_cert`'s chain-validation delegate takes when it refuses"
    );
}

#[test]
fn client_auth_config_revocation_disabled_is_honored_through_compile() {
    // `SHOULD_FIX` 4 (PR 766 review, #773): `allow_unknown_revocation_status` and `revocation`
    // reach the verifier as two loose positional arguments, a second source of truth alongside
    // the `ClientAuthConfig` document that carries the same two fields and, before this fix, was
    // never read at all. This test proves the config document actually drives the behaviour: the
    // leaf's own serial IS on the CRL, so if `revocation: disabled` here were silently ignored
    // (for instance if `compile_with_client_auth` still hardcoded `RevocationMode::Enforced`
    // instead of reading `auth_cfg.revocation`), this handshake would fail instead of succeeding.
    let fx = ca_fixture();
    let serial: &[u8] = &[0x5c];
    let (leaf_der, key_der) = client_leaf(fx, "config-disabled-revocation.example", serial);
    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let crls = crl_set_covering(fx, &[serial]);
    let auth = ClientAuth::Required(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "config-disabled-revocation-server.example.com",
        "config-disabled-revocation-server.example.com",
        &auth,
        crls,
        1_704_000_000,
        RevocationMode::Disabled,
        None,
    );

    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");
    let mut client = client_with_cert(
        "config-disabled-revocation-server.example.com",
        &[&server_leaf_der],
        &[&leaf_der],
        &key_der,
    );

    assert!(
        pump_handshake(&mut client, &mut server).is_none(),
        "a ClientAuthConfig saying revocation: disabled must be honored even for a certificate \
         that IS on the CRL; if the constructor silently used Enforced instead, this handshake \
         would fail"
    );
    assert_eq!(
        server_cfg
            .client_auth_stats()
            .expect("a Required configuration installs a verifier with counters")
            .revoked_denied
            .load(Ordering::Relaxed),
        0,
        "with revocation disabled via the config document, the revocation loop must not run at \
         all"
    );
}

/// A `ResolvesClientCert` that presents a VALID, CA-issued leaf certificate but signs the TLS 1.3
/// `CertificateVerify` with a private key that does **not** correspond to that leaf's public key.
/// Chain validation alone cannot catch this: the certificate itself is genuinely signed by a
/// trusted CA, so `verify_client_cert` accepts it. Only the signature check
/// (`verify_tls13_signature`) can, by actually verifying the handshake transcript signature
/// against the certificate's own public key. This is the proof-of-possession property PR 766
/// review #773 BLOCKING 2 says an unconditional `HandshakeSignatureValid::assertion()` would
/// bypass silently.
#[derive(Debug)]
struct MismatchedKeyResolver {
    key: Arc<rustls::sign::CertifiedKey>,
}
impl rustls::client::ResolvesClientCert for MismatchedKeyResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn client_cert_signed_with_mismatched_key_fails_proof_of_possession() {
    // BLOCKING 2 (PR 766 review, #773): the untrusted-CA test above closes the CHAIN-validation
    // mutation (`verify_client_cert` stubbed) via `chain_rejects`, but does NOT reach
    // `verify_tls13_signature` at all: rustls rejects an untrusted chain on the Certificate
    // message itself and never processes CertificateVerify, so that test alone leaves
    // `verify_tls13_signature`'s own mutation (an unconditional `Ok(assertion())`) unobserved.
    // Verified directly: applying that exact mutation and re-running the untrusted-CA test above
    // in isolation leaves it green. This test closes the gap: a certificate the chain validator
    // genuinely accepts (issued by the trusted CA), paired with a CertificateVerify signed by an
    // UNRELATED private key. A correct signature check must reject this; a stubbed one accepts
    // it, which is a complete authentication bypass for anyone holding a copy of a valid client
    // certificate (a public artifact, not a secret).
    ensure_provider_installed();
    let fx = ca_fixture();
    let (leaf_der, _matching_key_der) = client_leaf(fx, "mismatched-key-client.example", &[0x77]);
    // An UNRELATED keypair: not the one `leaf_der`'s certificate names as its public key.
    let unrelated_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let unrelated_key_der = unrelated_key.serialize_der();

    let anchors = TrustAnchors::from_der_bundle(&[&fx.der]).expect("a real CA must build");
    let crls = crl_set_covering(fx, &[]);
    let auth = ClientAuth::Required(anchors);
    let (server_cfg, server_leaf_der) = server_config(
        "mismatched-key-server.example.com",
        "mismatched-key-server.example.com",
        &auth,
        crls,
        1_704_000_000,
        RevocationMode::Enforced,
        None,
    );

    let provider = crate_provider();
    let signing_key_der = rustls::pki_types::PrivateKeyDer::try_from(unrelated_key_der.as_slice())
        .expect("valid key")
        .clone_key();
    // `CertifiedKey::from_der` cross-checks the key against the certificate's public key and
    // refuses a mismatch (`InconsistentKeys::KeyMismatch`) BEFORE any TLS is exchanged, which is
    // rustls's own defense and not what this test is probing. `load_private_key` plus
    // `CertifiedKey::new` builds the same pairing without that cross-check, which is what makes
    // it possible to reach the server's `verify_tls13_signature` at all with a genuine mismatch.
    let signing_key = provider
        .key_provider
        .load_private_key(signing_key_der)
        .expect("a real EC private key must load");
    let certified = rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(leaf_der)],
        signing_key,
    );
    let resolver = Arc::new(MismatchedKeyResolver {
        key: Arc::new(certified),
    });

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            server_leaf_der.clone(),
        ))
        .expect("valid trust anchor");
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_client_cert_resolver(resolver);
    let mut client = rustls::ClientConnection::new(
        Arc::new(client_cfg),
        "mismatched-key-server.example.com"
            .try_into()
            .expect("valid server name"),
    )
    .expect("client connection");
    let mut server =
        rustls::ServerConnection::new(Arc::clone(server_cfg.as_rustls())).expect("server conn");

    let err = pump_handshake(&mut client, &mut server);
    assert!(
        err.is_some(),
        "a CertificateVerify signed by a key that does not match the presented certificate's \
         public key must fail the handshake; proof of possession is the entire point of mTLS"
    );
}

/// The process-wide crypto provider, installed by every test in this file via
/// `ensure_provider_installed`. `irontraffic_tls::provider::provider()` is a `pub fn` in a `pub
/// mod`, so it is reachable from this external test crate even though the crate root does not
/// re-export it. Named `crate_provider` rather than imported bare as `provider` to avoid
/// shadowing the many local `provider` bindings this file's other tests build.
fn crate_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::clone(
        irontraffic_tls::provider::provider().expect("install_process_provider must have run"),
    )
}
