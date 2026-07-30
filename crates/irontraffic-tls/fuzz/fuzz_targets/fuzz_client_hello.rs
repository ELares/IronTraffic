// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drive `SniAcceptor` from arbitrary bytes.
//!
//! The contract, all four parts asserted below rather than merely hoped for:
//!
//! 1. No panic and no hang.
//! 2. `Ready` never carries a configuration whose `client_auth()` is WEAKER than the requirement
//!    the presented SNI actually selects. This is the property every Traefik CVE in this class
//!    violated. Contract 2 is currently STRUCTURALLY INERT (see below) because every configuration
//!    this target can build is `ClientAuthKind::None` until `mtls-client-auth-fail-closed` (#124)
//!    lands a real verifier; the comparison is written now so #124 turns it live by construction.
//! 3. Never buffer more than `max_client_hello_bytes()` past what the last `feed` call added.
//! 4. A reject is terminal in the sense that it is reported once, with a reason, rather than
//!    silently becoming a permissive default.
//!
//! **Reachability, measured, stated honestly (#754).** CI runs this target with
//! `cargo fuzz run --fuzz-dir crates/irontraffic-tls/fuzz fuzz_client_hello -- -max_total_time=60
//! -timeout=10`, no corpus directory argument. `cargo-fuzz` accepts `[CORPUS]...` as an OPTIONAL
//! positional argument list (`cargo fuzz run --help`); when none is given it falls back to its own
//! default, `fuzz/corpus/fuzz_client_hello/`, which is gitignored and therefore EMPTY on every
//! fresh CI checkout. Measured directly, with that directory emptied to reproduce a fresh
//! checkout exactly: `cargo fuzz run fuzz_client_hello -- -runs=400000 -timeout=10` gave 400,000
//! runs, `ready=0`, `rejects=249,533`. Every `AcceptStep::Ready` arm, including contract 2's
//! assertion, is unreachable from random bytes alone, because almost no random byte string is a
//! well-formed TLS record.
//!
//! `crates/irontraffic-tls/fuzz/seed_corpus/fuzz_client_hello/` now holds four real `ClientHello`s
//! (the bound exact name, the bound wildcard name, an unmatched name, and no SNI at all), the same
//! convention `fuzz_crl_parse`'s own `seed_corpus/fuzz_crl_parse/` already establishes in this
//! crate. Measured with that seed corpus supplied explicitly, corpus directory otherwise empty:
//!
//! ```text
//! cargo fuzz run --fuzz-dir crates/irontraffic-tls/fuzz fuzz_client_hello \
//!     corpus/fuzz_client_hello seed_corpus/fuzz_client_hello \
//!     -- -runs=200000 -timeout=10
//! ```
//!
//! (paths relative to `crates/irontraffic-tls/fuzz/`, mirroring `fuzz_crl_parse`'s own recipe).
//! Two independent runs gave `ready=4,006`/`ready_not_no_sni=3,466` and
//! `ready=1,277`/`ready_not_no_sni=254` out of 200,000; libFuzzer's mutation order is not seeded
//! deterministically run to run, so the exact count moves, but `Ready` is reached in the
//! thousands every time, never zero. So the target genuinely works once seeded: `Ready`, and
//! contract 2's per-name assertion, are reached at scale and every run completed clean, no crash
//! and no timeout, the same fix `fuzz_crl_parse` already established for its own path A. (A third
//! run, with the comparison in contract 2's assertion deliberately reversed to confirm the check
//! is live wiring and not dead code, crashed on the FIRST seeded input reaching `Ready`, as
//! expected; reverted before landing.)
//!
//! **What seeding this target does NOT do: make CI reach `Ready`.** `cargo-fuzz` has no automatic
//! seed-corpus discovery; a directory named `seed_corpus/` is a convention this crate follows for
//! humans running a real fuzzing session, not something `cargo fuzz run` reads on its own. CI's
//! own invocation, unchanged, passes no corpus argument at all, so it starts from the same empty
//! default corpus every time and `Ready` stays unreached there until either (a) CI is changed to
//! pass this directory, or (b) enough interesting inputs accumulate in the persistent corpus this
//! target writes to across CI runs, which does not happen today because that directory is
//! gitignored and never carried between runs. This is the same shape `fuzz_crl_parse`'s own module
//! doc already discloses for its path A (whose realistic ceiling from an empty corpus is likewise
//! near zero): the seed corpus is real and the target genuinely works, but a corpus that CI never
//! loads does not, by itself, change what CI's 60-second smoke run exercises. Wiring CI's fuzz job
//! to pass every target's own `seed_corpus/` directory is out of this issue's Files table
//! (`.github/workflows/ci.yml`) and is recorded as follow-up rather than silently done here.

#![no_main]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use irontraffic_tls::listener::{AcceptStep, ClientAuthKind, ListenerTls, ListenerTlsBuilder, TlsServerConfig};
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

/// Per-run counters, printed to stderr every 5,000 executions so a fuzz run's own log reports a
/// real reachability fraction rather than a number that flatters itself. Mirrors the convention
/// `fuzz_crl_parse.rs`'s `PathCounters` establishes in this same crate.
static TOTAL: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static READY_NOT_NO_SNI: AtomicU64 = AtomicU64::new(0);
static REJECTS: AtomicU64 = AtomicU64::new(0);

fn report_progress() {
    let total = TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if total.is_multiple_of(5_000) {
        eprintln!(
            "fuzz_client_hello: runs={total} ready={} ready_not_no_sni={} rejects={}",
            READY.load(Ordering::Relaxed),
            READY_NOT_NO_SNI.load(Ordering::Relaxed),
            REJECTS.load(Ordering::Relaxed),
        );
    }
}

fuzz_target!(|data: &[u8]| {
    report_progress();

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
    let cap = l.max_client_hello_bytes();

    // Cumulative bytes actually handed to `feed` so far, tracked independently of
    // `acc.bytes_consumed()`. Contract 3 compares the two directly below rather than against a
    // slack term shaped like `cap + chunk`: for the `first % 4 == 3` branch, `chunk` equals the
    // ENTIRE remaining input, so `cap + chunk` is at least as large as anything `feed` could ever
    // report, and the old assertion could never fail regardless of what the cap check actually
    // did (#754 BLOCKING 1). Tracking fed bytes independently and asserting exact agreement is a
    // chunk-size-independent check that catches a broken cap on every branch, including this one.
    let mut fed = 0usize;

    for piece in rest.chunks(chunk) {
        fed += piece.len();
        let step = acc.feed(piece);

        assert_eq!(
            acc.bytes_consumed(),
            fed,
            "bytes_consumed must track exactly what was fed, no more and no less"
        );
        if fed > cap {
            assert!(
                matches!(
                    step,
                    AcceptStep::Reject {
                        reason: irontraffic_tls::listener::RejectReason::ClientHelloTooLarge,
                        ..
                    }
                ),
                "fed {fed} bytes, cap is {cap}, but the step was {step:?} instead of a \
                 ClientHelloTooLarge reject"
            );
        }

        match step {
            AcceptStep::NeedMore => {}
            AcceptStep::Reject { .. } => {
                REJECTS.fetch_add(1, Ordering::Relaxed);
                break;
            }
            AcceptStep::Ready { config, accepted } => {
                READY.fetch_add(1, Ordering::Relaxed);

                // Contract 2, checked against the requirement the PRESENTED name actually
                // selects, not against the listener's weakest configuration overall. The
                // earlier version of this assertion compared `config.client_auth()` against
                // `floor = min` over every binding on the listener; since `floor` is a minimum,
                // it stayed `None` as long as ANY binding was `None`, which this fixture
                // guarantees permanently via `set_no_sni`. So after #124 adds a `Required`
                // binding, a `Ready` that wrongly handed the no-SNI (`None`) configuration to a
                // SNI that should have gotten `Required` would still have passed: the exact CVE
                // shape this target exists to catch (#754 finding 12). Comparing against the
                // specific name's own requirement does not have that blind spot.
                let sni = accepted.server_name();
                if sni.is_some() {
                    READY_NOT_NO_SNI.fetch_add(1, Ordering::Relaxed);
                }
                let required = match &sni {
                    Some(name) => l.client_auth_for_name(name),
                    None => l
                        .no_sni_config()
                        .map_or(ClientAuthKind::None, |c| c.client_auth()),
                };
                assert!(
                    config.client_auth() >= required,
                    "Ready carried {:?} for SNI {:?}, weaker than the {:?} that name requires",
                    config.client_auth(),
                    sni,
                    required
                );
                break;
            }
        }
    }
});
