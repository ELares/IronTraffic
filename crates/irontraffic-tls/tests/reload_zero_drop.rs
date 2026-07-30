// SPDX-License-Identifier: MIT OR Apache-2.0

//! 64 threads run continuous in-memory TLS handshakes against a `TlsMaterialCell` while a 65th
//! thread performs 100 real publishes through a `CertUpdateCoalescer`, each installing one
//! additional certificate for the same name every worker asks for. No handshake may fail, no
//! thread may panic, and every served leaf must be one of the 101 credentials this test
//! generated for that name: this is the zero-drop reload property `TlsMaterialCell`'s wait-free
//! pointer swap exists to prove.
//!
//! **A note on `HashSet<CertFingerprint>`.** The design calls for collecting the 101
//! credentials' fingerprints into a `HashSet<CertFingerprint>` and checking a served leaf's own
//! blake3 hash against it. `CertFingerprint`'s only constructor is `Credentials::fingerprint`,
//! called on an already-**parsed** `Credentials`; there is no public way to build one from a raw
//! hash computed over a peer-observed DER blob, and this file, like every file under `tests/`,
//! compiles as a separate crate linked only against `irontraffic_tls`'s public API. This is the
//! identical structural-privacy shape `tests/handshake_resolver.rs`'s own module doc records for
//! `resolve_parts`/`AlpnVerdict`. `CertFingerprint::to_hex()` is the one public accessor, so this
//! file compares through it instead: a `HashSet<String>` of each known credential's own
//! `fingerprint().to_hex()`, checked against the peer leaf's own blake3 hash truncated and
//! hex-encoded the identical way. This is the closest faithful equivalent reachable from here,
//! and it discriminates exactly the same set of leaves the design's `HashSet<CertFingerprint>`
//! would.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test-only helpers on generated inputs and thread bodies, the same pattern \
              tests/handshake_resolver.rs uses: clippy.toml's allow-expect-in-tests only exempts \
              #[test] fns and #[cfg(test)] modules, not the ordinary helper functions and thread \
              closures every test in this file calls"
)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::thread;
use std::time::{Duration, Instant};

use irontraffic_tls::policy::TlsPolicy;
use irontraffic_tls::store::{
    CertIndexBuilder, CertUpdate, CertUpdateCoalescer, ChainInterner, ChallengeCerts, Credentials,
    IronResolver, TimeView, TlsMaterial, TlsMaterialCell,
};
use irontraffic_tls::time::UnixSeconds;

/// Minimum accepted total handshake successes across all 64 workers. The design's own budget is
/// 50,000 (a TLS 1.3 handshake is roughly 150 us of CPU, so 64 threads for a bit over one second
/// is far more than 50,000 on any real machine), with an explicit allowance to lower it, never
/// below 5,000, if that proves out of reach on the CI runner. This runs at 5,000, the floor, to
/// avoid flaking on a shared or virtualized runner whose actual headroom this implementer cannot
/// benchmark in advance; the assertion itself, and the zero-handshake-failure requirement above
/// it, are never weakened or removed.
const MIN_TOTAL_SUCCESSES: u64 = 5_000;

/// Hard upper bound on the worker window, after which the run stops regardless of how few
/// handshakes have completed and the `MIN_TOTAL_SUCCESSES` assertion fails on its own terms.
///
/// This exists so the test reports a real throughput failure rather than hanging a CI job.
const MAX_RUN: Duration = Duration::from_secs(120);

/// Lower bound on the worker window, which is the "loops run for at least 2 seconds" the design
/// specifies. The publisher's own budget is only about one second (100 publishes, 10 ms apart),
/// and tying the workers' window to it is what made this test fail CI on all three crypto cells:
/// a 2-core runner completed 1,092 to 3,513 handshakes in that window against a 5,000 floor that
/// the design forbids lowering further. The floor is not the problem; the window was.
const MIN_RUN: Duration = Duration::from_secs(2);

fn ensure_provider_installed() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
    });
}

/// A `TimeView` that never reads a clock.
struct FixedClock(UnixSeconds);
impl TimeView for FixedClock {
    fn unix_seconds(&self) -> UnixSeconds {
        self.0
    }
}

/// Build a CA keypair, self-signed CA certificate DER, and an `Issuer` over it, so every leaf
/// this test generates shares ONE trust anchor. rustls-webpki's certificate-path budget is 100
/// signature checks per verification (`rustls_webpki::verify_cert::Budget::default`); 101
/// self-signed, mutually untrusting leaves each installed directly as a root would force the
/// client to try up to 101 candidate roots per handshake to find the one that matches, which
/// exceeded that budget and failed real handshakes with `MaximumSignatureChecksExceeded` during
/// this test's own development. One shared CA makes every verification exactly one signature
/// check (leaf signed by the CA) plus the CA itself as the one trusted root, independent of how
/// many leaves exist.
fn build_ca() -> (rcgen::CertificateParams, rcgen::KeyPair, Vec<u8>) {
    ensure_provider_installed();
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid SANs");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_der = ca_params
        .self_signed(&ca_key)
        .expect("self sign ca")
        .der()
        .to_vec();
    (ca_params, ca_key, ca_der)
}

/// One ECDSA P-256 credential for `san`, signed by `issuer`, with a distinct, strictly
/// increasing `not_after` so a later `Install` of the same name always outranks an earlier one
/// in the from-scratch builder's "later expiry wins" tie-break: this is what makes the served
/// credential actually rotate as the publisher installs credential `i`, rather than depending on
/// a fingerprint tie-break coincidence.
fn gen_cred(
    san: &str,
    not_after_year: i32,
    issuer: &rcgen::Issuer<'_, rcgen::KeyPair>,
    ca_der: &[u8],
) -> Arc<Credentials> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let mut params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
    let leaf_der = params
        .signed_by(&key, issuer)
        .expect("sign leaf")
        .der()
        .to_vec();
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[&leaf_der, ca_der], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    )
}

/// Lowercase hex of the first 16 bytes of `full`, matching `CertFingerprint::to_hex`'s format.
/// See the module doc for why this file compares fingerprints this way rather than by
/// constructing a `CertFingerprint` value directly.
fn hex16(full: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = full.get(..16).unwrap_or(full);
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Drives two in-memory TLS endpoints through a handshake, returning the first error either side
/// reports, or `None` if both complete. Copied from `tests/handshake_resolver.rs` rather than
/// shared, because that file's helper is private to its own crate (every file under `tests/`
/// compiles as its own crate). 16 rounds is far more than a handshake needs and bounds the loop.
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
#[allow(
    clippy::too_many_lines,
    reason = "one integration test assembling the full zero-drop scenario end to end (fixture \
              setup, 64 worker closures, the publisher thread, and the final assertions); \
              splitting it across helper functions would scatter one property across several \
              places with no reader benefit"
)]
fn reload_zero_drop_under_concurrent_handshakes() {
    const WORKERS: usize = 64;
    const PUBLISHES: usize = 100;
    const NAME: &str = "a.example.com";

    // 101 credentials for the SAME name, distinct and strictly increasing `not_after` years so
    // credential `i` always outranks credential `i - 1` once both are pending in one rebuild.
    // All 101 share one CA (see `build_ca`'s doc for why: it keeps every verification at exactly
    // one signature check, regardless of how many leaves exist).
    let (ca_params, ca_key, ca_der) = build_ca();
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let creds: Vec<Arc<Credentials>> = (0..101)
        .map(|i| gen_cred(NAME, 2100 + i, &issuer, &ca_der))
        .collect();

    let fingerprints: Arc<HashSet<String>> = Arc::new(
        creds
            .iter()
            .map(|c| hex16(blake3::hash(c.leaf_der()).as_bytes()))
            .collect(),
    );

    // Generation N serves `creds[N]`: generation 0 is the credential the cell is built with, and
    // the publisher installs `creds[1..=PUBLISHES]` in order, one per publish. Indexing this by
    // the generation read from the same guard as the resolver is what makes the per-handshake
    // assertion below discriminate a missing publish, which set membership cannot.
    let leaf_by_generation: Arc<Vec<String>> = Arc::new(
        creds
            .iter()
            .map(|c| hex16(blake3::hash(c.leaf_der()).as_bytes()))
            .collect(),
    );

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der.clone()))
        .expect("the shared CA is a valid trust anchor");
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let mut certs_builder = CertIndexBuilder::new([77u8; 16]);
    certs_builder
        .upsert_exact(NAME, Arc::clone(&creds[0]))
        .expect("valid");
    let certs = Arc::new(certs_builder.build_with_generation(0).expect("build"));
    let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
    let policy = Arc::new(TlsPolicy::default_https());
    let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_000)));
    let resolver = Arc::new(IronResolver::new(
        Arc::clone(&certs),
        Arc::clone(&challenge),
        Arc::clone(&policy),
        Arc::clone(&time),
    ));
    let initial = Arc::new(TlsMaterial {
        certs,
        challenge,
        resolver,
        listeners: Arc::from(Vec::new()),
        generation: 0,
    });
    let cell = Arc::new(TlsMaterialCell::new(initial));

    let stop = Arc::new(AtomicBool::new(false));

    // Live count of completed handshakes, so the publisher can hold the window open until the
    // floor is actually reached instead of guessing how fast the runner is.
    let completed = Arc::new(AtomicU64::new(0));

    let mut worker_handles = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let cell = Arc::clone(&cell);
        let stop = Arc::clone(&stop);
        let fingerprints = Arc::clone(&fingerprints);
        let client_cfg = Arc::clone(&client_cfg);
        let completed = Arc::clone(&completed);
        let leaf_by_generation = Arc::clone(&leaf_by_generation);
        worker_handles.push(thread::spawn(move || -> Result<(u64, u64), String> {
            let mut successes = 0u64;
            let mut max_generation_seen = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let (resolver, generation) = {
                    // The guard is held only long enough to clone the one `Arc` needed, exactly
                    // as `TlsMaterialCell::load`'s docs require: dropped before any handshake
                    // work runs, so it never pins a generation for the life of a connection.
                    let material = cell.load();
                    (Arc::clone(&material.resolver), material.generation)
                };
                let server_cfg = rustls::ServerConfig::builder_with_protocol_versions(&[
                    &rustls::version::TLS13,
                ])
                .with_no_client_auth()
                .with_cert_resolver(resolver);
                let mut server = rustls::ServerConnection::new(Arc::new(server_cfg))
                    .map_err(|e| format!("server config: {e}"))?;
                let server_name: rustls::pki_types::ServerName<'static> = NAME
                    .to_owned()
                    .try_into()
                    .map_err(|e| format!("server name: {e:?}"))?;
                let mut client =
                    rustls::ClientConnection::new(Arc::clone(&client_cfg), server_name)
                        .map_err(|e| format!("client connection: {e}"))?;

                if let Some(e) = pump_handshake(&mut client, &mut server) {
                    return Err(format!("handshake failed: {e}"));
                }
                let peer = client
                    .peer_certificates()
                    .ok_or_else(|| "no peer certificate chain".to_owned())?;
                let leaf = peer
                    .first()
                    .ok_or_else(|| "empty peer certificate chain".to_owned())?;
                let served_hex = hex16(blake3::hash(leaf.as_ref()).as_bytes());
                if !fingerprints.contains(&served_hex) {
                    return Err(format!(
                        "served leaf {served_hex} is not one of the 101 known credentials"
                    ));
                }
                // Set membership alone is far too weak: `creds[0]` is in that set, so it stays
                // satisfied even if publication never happens at all. Deleting the `ArcSwap`
                // store from `TlsMaterialCell::publish` left this whole test green, because
                // every worker then served `creds[0]` forever while the publish and generation
                // counters (separate statements) kept incrementing.
                //
                // The exact relation this design guarantees is that the leaf served by a
                // resolver equals the credential installed at that resolver's OWN generation.
                // `generation` is read from the same guard as `resolver`, so a publish landing
                // mid-handshake cannot make this race: both name the same snapshot.
                let index = usize::try_from(generation)
                    .map_err(|_| format!("generation {generation} does not fit a usize"))?;
                let expected = leaf_by_generation
                    .get(index)
                    .ok_or_else(|| format!("generation {generation} has no known credential"))?;
                if &served_hex != expected {
                    return Err(format!(
                        "generation {generation} served leaf {served_hex}, expected {expected}"
                    ));
                }
                successes += 1;
                max_generation_seen = max_generation_seen.max(generation);
                completed.fetch_add(1, Ordering::Relaxed);
            }
            Ok((successes, max_generation_seen))
        }));
    }

    let publisher_cell = Arc::clone(&cell);
    let publisher_stop = Arc::clone(&stop);
    let publisher_completed = Arc::clone(&completed);
    let publisher_creds = creds.clone();
    let publisher_handle = thread::spawn(move || {
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_000)));
        let mut coalescer = CertUpdateCoalescer::new(
            publisher_cell,
            ChainInterner::new(),
            Arc::new(TlsPolicy::default_https()),
            time,
        );
        coalescer.set_debounce_ms(0);
        for cred in publisher_creds.iter().skip(1).take(PUBLISHES) {
            coalescer
                .submit(CertUpdate::Install {
                    exact: vec![NAME.into()],
                    wildcard: Vec::new(),
                    cred: Arc::clone(cred),
                })
                .expect("every submitted update in this test is well-formed");
            coalescer
                .flush_now()
                .expect("every flush in this test must build and publish cleanly");
            thread::sleep(Duration::from_millis(10));
        }
        // The publishes are done after about one second. Do NOT stop the workers here: that
        // ties their entire window to the publisher's sleep budget, which is what failed CI on
        // all three crypto cells. Hold the window open until the floor is actually reached, so
        // the assertion measures whether handshakes SUCCEED rather than whether this particular
        // runner is fast enough to reach a fixed count inside a fixed time.
        //
        // The concurrency this test exists to exercise all happens in the first second, while
        // publishes are landing underneath live handshakes. The remaining time only accumulates
        // count, and on any machine fast enough it is zero: the floor is already passed before
        // the publish loop ends.
        let started = Instant::now();
        while started.elapsed() < MIN_RUN
            || (publisher_completed.load(Ordering::Relaxed) < MIN_TOTAL_SUCCESSES
                && started.elapsed() < MAX_RUN)
        {
            thread::sleep(Duration::from_millis(10));
        }
        publisher_stop.store(true, Ordering::Relaxed);
    });

    publisher_handle
        .join()
        .expect("the publisher thread must not panic");

    let mut total_successes: u64 = 0;
    let mut max_generation_seen: u64 = 0;
    for handle in worker_handles {
        match handle.join().expect("a worker thread must not panic") {
            Ok((n, gen_seen)) => {
                total_successes += n;
                max_generation_seen = max_generation_seen.max(gen_seen);
            }
            Err(e) => panic!("a worker thread reported an error: {e}"),
        }
    }

    // The publication actually reached the cell, and READERS saw it.
    //
    // Both of these are needed, and neither the per-handshake check above nor the counter
    // assertions below can stand in for them. Deleting `self.inner.store(material)` from
    // `TlsMaterialCell::publish` leaves every other assertion in this test satisfied: the
    // publish and generation STATS are separate statements that keep incrementing, and the
    // per-handshake check stays self-consistent because a reader then sees generation 0 and is
    // correctly served `creds[0]`, which agree with each other. Only asking what the cell now
    // holds, and what the highest generation any reader actually observed was, discriminates a
    // swap that never happened.
    assert_eq!(
        cell.load().generation,
        PUBLISHES as u64,
        "the cell must hold the last published material, not merely count the publishes"
    );
    assert_eq!(
        max_generation_seen, PUBLISHES as u64,
        "no reader ever observed the final generation, so publication was not visible through \
         the swap even if the counters advanced"
    );

    assert!(
        total_successes >= MIN_TOTAL_SUCCESSES,
        "expected at least {MIN_TOTAL_SUCCESSES} total successful handshakes across {WORKERS} \
         workers, got {total_successes}"
    );
    assert_eq!(
        cell.stats().publishes.load(Ordering::Relaxed),
        PUBLISHES as u64
    );
    assert_eq!(
        cell.stats().generation.load(Ordering::Relaxed),
        PUBLISHES as u64
    );
}
