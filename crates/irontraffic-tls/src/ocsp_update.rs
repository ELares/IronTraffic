// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sans-IO OCSP staple updater: a schedule, exponential backoff with full jitter, and the
//! must-staple staleness sweep. [`OcspUpdater`] performs no I/O itself; it calls out to an
//! [`OcspFetcher`] the caller supplies and returns the [`crate::store::CertUpdate`]s the caller
//! must submit to a `CertUpdateCoalescer`.
//!
//! **No fetch ever happens on the handshake path.** `OcspUpdater::tick` is driven by the
//! control-plane loop, never by an accepted connection: turning one inbound handshake into one
//! outbound HTTP request would be a connection amplification attack against both this process
//! and the responder. `tick` also performs blocking fetches with a 5 second timeout each, so it
//! must run on a blocking-capable control-plane task, never on a data-plane thread.
//!
//! **The in-tree fetcher does not exist yet.** `OcspFetcher` is a trait because this crate
//! performs no I/O and pulls in no HTTP client; the production implementation is the slug
//! `ocsp-http-fetcher` over the control-plane HTTP client, which is not published yet. This
//! module is therefore constructible and fully tested against a deterministic test fetcher, with
//! no production fetcher to drive it, until that slug lands.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ocsp::{self, OcspConfig, OcspError, StapleInfo};
use crate::store::{CertFingerprint, CertUpdate, Credentials, TimeView};
use crate::time::UnixSeconds;

/// Fetches an OCSP response. Implemented outside this crate by the control-plane HTTP client.
///
/// The implementation MUST enforce every one of these, and each one is a security property rather
/// than a quality-of-implementation detail:
///
/// - A 5 second **total** timeout covering DNS, connect, write and read.
/// - A 65,536 byte response cap enforced **while reading**, by stopping the read at the cap and
///   returning an error. Reading a response into memory and checking its length afterwards lets a
///   hostile responder allocate as much as it likes.
/// - HTTP POST with `Content-Type: application/ocsp-request`.
/// - At most 2 redirects, and `crate::ocsp::validate_aia_url` re-run on **every** redirect target.
///   A redirect to `http://169.254.169.254/` is the standard way to bypass a check that only ran on
///   the original URL.
/// - The resolved peer address re-checked against the private-address rules immediately before
///   connecting, because DNS can answer differently on the second lookup.
/// - No proxy unless the operator configured one, and no credentials, cookies, or ambient
///   authentication of any kind on the request.
///
/// It MUST NOT retry internally; retry policy lives in `OcspUpdater`.
pub trait OcspFetcher: Send + Sync + 'static {
    /// Fetch a response for `request_der` from `url`.
    ///
    /// # Errors
    /// Any transport failure, as an opaque string for logging. The string must not contain
    /// response bytes.
    fn fetch(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, String>;
}

/// Minimal randomness seam, so this crate takes `&mut` randomness rather than a thread-local.
/// Quoted character for character by `acme-ari-renewal-and-rate-limits` (#130), which declares the
/// same trait in `irontraffic-acme` because the two crates do not depend on each other.
pub trait RngLike {
    /// Next 64 random bits.
    fn next_u64(&mut self) -> u64;
}

/// Per-certificate updater state.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TrackedState {
    /// No OCSP AIA URL. Terminal, not an error, never retried.
    NoResponder,
    /// A valid staple is installed.
    Stapled,
    /// Fetching or awaiting the next attempt.
    Pending,
    /// Repeated failures past the cap; alarmed.
    Failed,
    /// The responder said `revoked`. Terminal and alarmed at `critical`.
    Revoked,
}

/// One tracked certificate.
struct Tracked {
    /// The credential itself. Held so that `tick` can call `with_staple` on it and emit a
    /// `CertUpdate::Replace`; without this field there is nothing to attach a staple to.
    /// An `Arc` clone, so tracking a credential costs a refcount and not a copy.
    cred: Arc<Credentials>,
    fingerprint: CertFingerprint,
    aia_url: Option<Box<str>>,
    must_staple: bool,
    names: Box<[Box<str>]>,
    state: TrackedState,
    next_attempt: UnixSeconds,
    consecutive_failures: u32,
    current_next_update: Option<UnixSeconds>,
}

/// Counters for the OCSP path.
#[derive(Debug, Default)]
pub struct OcspStats {
    /// `tls_ocsp_fetch_total`
    pub fetches: AtomicU64,
    /// `tls_ocsp_fetch_error_total`
    pub fetch_errors: AtomicU64,
    /// `tls_ocsp_validate_error_total`
    pub validate_errors: AtomicU64,
    /// `tls_ocsp_stapled_total`
    pub stapled: AtomicU64,
    /// `tls_ocsp_revoked_total`
    pub revoked: AtomicU64,
    /// `tls_ocsp_no_responder_total`
    pub no_responder: AtomicU64,
}

/// The sans-IO staple updater. Owned and ticked by the control-plane loop.
pub struct OcspUpdater {
    tracked: Vec<Tracked>,
    fetcher: Arc<dyn OcspFetcher>,
    time: Arc<dyn TimeView>,
    cfg: OcspConfig,
    stats: OcspStats,
}

/// `u32` to `usize`, saturating rather than panicking or truncating. Every platform this
/// workspace targets has a `usize` at least as wide as `u32`, but `usize` is only guaranteed to
/// be at least 16 bits, so this goes through `try_from` rather than an `as` cast, which would
/// trip the `cast_lossless` lint for a conversion that is not universally lossless.
fn as_usize(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// 16 random bytes, drawn two `u64`s at a time.
fn random_nonce(rng: &mut dyn RngLike) -> [u8; 16] {
    let a = rng.next_u64().to_le_bytes();
    let b = rng.next_u64().to_le_bytes();
    let mut out = [0u8; 16];
    let (first, second) = out.split_at_mut(8);
    first.copy_from_slice(&a);
    second.copy_from_slice(&b);
    out
}

/// A deterministic `u64` derived from a fingerprint's own hex text, used only to spread initial
/// `next_attempt` values. `CertFingerprint` exposes no raw bytes (by design: it is a display and
/// lookup convenience, not a value other code should depend on byte-for-byte), so this reads the
/// first 16 of its 32 hex characters, which is exactly 8 bytes of entropy, back into a `u64`.
fn fingerprint_seed(fingerprint: CertFingerprint) -> u64 {
    let hex = fingerprint.to_hex();
    let text = core::str::from_utf8(&hex).unwrap_or("0");
    let prefix = text.get(..16).unwrap_or("0");
    u64::from_str_radix(prefix, 16).unwrap_or(0)
}

/// `min(backoff_base * 2^(failures-1), backoff_max)` with full jitter: a uniform random factor
/// in `[0.5, 1.0]`, applied as integer per-mille arithmetic so this never touches floating point
/// (and therefore never risks a `cast_precision_loss` truncation on a value that came off the
/// network by way of a failure count). The doubling is computed in `u64` with `saturating_mul`
/// and the shift is capped at 31, so a large failure count cannot overflow.
#[allow(
    clippy::integer_division,
    reason = "per-mille jitter arithmetic: capped and per_mille are both small, bounded u64 \
              values (capped <= backoff_max_secs, per_mille in 500..=1000), and dividing by the \
              constant 1000 to convert per-mille back to seconds is exact enough for a jittered \
              retry delay; there is no lossless integer alternative to dividing here, and this \
              module does not use floating point at all (see the doc comment above)"
)]
fn backoff(
    failures: u32,
    backoff_base_secs: u32,
    backoff_max_secs: u32,
    rng: &mut dyn RngLike,
) -> u64 {
    let shift = failures.saturating_sub(1).min(31);
    let doubled = u64::from(backoff_base_secs).saturating_mul(1u64 << shift);
    let capped = doubled.min(u64::from(backoff_max_secs));
    // A uniform factor in [0.5, 1.0], represented as parts per thousand in [500, 1000].
    let per_mille = 500u64.saturating_add(rng.next_u64() % 501);
    capped.saturating_mul(per_mille) / 1000
}

/// `clamp(effective_next_update - margin_secs - now, min_interval_secs, max_interval_secs)`,
/// the same value as "the earlier of `nextUpdate - margin` and `now + max_interval`, floored at
/// `min_interval`" written as a delay. `effective_next_update` is `info.next_update` when the
/// response carried one and `info.this_update + no_next_update_ttl_secs` when it did not.
fn refresh_delay(info: StapleInfo, now: UnixSeconds, cfg: &OcspConfig) -> u64 {
    let effective_next_update = info.next_update.unwrap_or_else(|| {
        info.this_update
            .saturating_add_secs(u64::from(cfg.no_next_update_ttl_secs))
    });
    let raw = effective_next_update
        .saturating_sub(now)
        .saturating_sub(u64::from(cfg.margin_secs));
    raw.clamp(
        u64::from(cfg.min_interval_secs),
        u64::from(cfg.max_interval_secs),
    )
}

/// Record one failed attempt on `t`: bump the failure count, schedule the next attempt with
/// jittered backoff, and move to `Failed` once `fail_after` is reached. A free function taking
/// `&mut Tracked` directly, rather than an `OcspUpdater` method, so it never needs to borrow
/// `self` while a caller already holds `self.tracked.get_mut(i)`.
fn record_failure(t: &mut Tracked, now: UnixSeconds, cfg: &OcspConfig, rng: &mut dyn RngLike) {
    t.consecutive_failures = t.consecutive_failures.saturating_add(1);
    let delay = backoff(
        t.consecutive_failures,
        cfg.backoff_base_secs,
        cfg.backoff_max_secs,
        rng,
    );
    t.next_attempt = now.saturating_add_secs(delay);
    if t.consecutive_failures >= cfg.fail_after {
        t.state = TrackedState::Failed;
    }
}

impl OcspUpdater {
    /// New updater.
    #[must_use]
    pub fn new(fetcher: Arc<dyn OcspFetcher>, time: Arc<dyn TimeView>, cfg: OcspConfig) -> Self {
        Self {
            tracked: Vec::new(),
            fetcher,
            time,
            cfg,
            stats: OcspStats::default(),
        }
    }

    /// Start tracking a credential. Idempotent by fingerprint.
    pub fn track(&mut self, cred: &Arc<Credentials>, aia_url: Option<&str>) {
        let fingerprint = cred.fingerprint();
        if self.tracked.iter().any(|t| t.fingerprint == fingerprint) {
            return;
        }

        let state = if aia_url.is_none() {
            self.stats.no_responder.fetch_add(1, Ordering::Relaxed);
            TrackedState::NoResponder
        } else {
            TrackedState::Pending
        };

        let now = self.time.unix_seconds();
        let min_interval = u64::from(self.cfg.min_interval_secs.max(1));
        let spread = fingerprint_seed(fingerprint) % min_interval;

        self.tracked.push(Tracked {
            cred: Arc::clone(cred),
            fingerprint,
            aia_url: aia_url.map(Into::into),
            must_staple: cred.must_staple(),
            names: cred.san_dns_names().iter().cloned().collect(),
            state,
            next_attempt: now.saturating_add_secs(spread),
            consecutive_failures: 0,
            current_next_update: None,
        });
    }

    /// Stop tracking.
    pub fn untrack(&mut self, fingerprint: CertFingerprint) {
        self.tracked.retain(|t| t.fingerprint != fingerprint);
    }

    /// Perform one pass. Returns the certificate-store updates the caller must submit.
    ///
    /// Starts at most `OcspConfig::max_fetches_per_tick` fetches, taking due entries in ascending
    /// `next_attempt` order so nothing starves. Each fetch blocks for up to 5 seconds, so one call
    /// can take `max_fetches_per_tick * 5` seconds: run this on a blocking-capable control-plane
    /// task, never on a data-plane thread.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "one tick over one due entry is a single, sequential state machine (build the \
                  request, validate the URL, fetch, validate the response, update state); \
                  splitting it into several &mut self helper methods would need to thread the \
                  same half-dozen already-resolved locals (cfg, fetcher, cred, fingerprint, url, \
                  nonce) through each one, which is not clearer than reading it in order"
    )]
    pub fn tick(&mut self, now: UnixSeconds, rng: &mut dyn RngLike) -> Vec<CertUpdate> {
        let cfg = self.cfg.clone();
        let fetcher = Arc::clone(&self.fetcher);
        let mut updates = Vec::new();

        let mut due: Vec<usize> = self
            .tracked
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                !matches!(
                    t.state,
                    TrackedState::NoResponder | TrackedState::Revoked | TrackedState::Failed
                ) && t.next_attempt <= now
            })
            .map(|(i, _)| i)
            .collect();
        due.sort_by_key(|&i| self.tracked.get(i).map(|t| t.next_attempt));
        due.truncate(as_usize(cfg.max_fetches_per_tick));

        for i in due {
            let Some(tracked) = self.tracked.get(i) else {
                continue;
            };
            let cred = Arc::clone(&tracked.cred);
            let fingerprint = tracked.fingerprint;
            let Some(url) = tracked.aia_url.clone() else {
                continue;
            };

            // Step 1(a): a request that cannot be built will never succeed, so it must not enter
            // the backoff loop.
            let nonce = random_nonce(rng);
            let Ok(request) = ocsp::build_request(&cred, Some(&nonce)) else {
                if let Some(t) = self.tracked.get_mut(i) {
                    t.state = TrackedState::Failed;
                }
                continue;
            };

            // Step 1(a2): the SSRF gate runs before the fetcher ever sees the URL.
            if ocsp::validate_aia_url(&url, &cfg).is_err() {
                if let Some(t) = self.tracked.get_mut(i) {
                    t.state = TrackedState::Failed;
                }
                self.stats.validate_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            self.stats.fetches.fetch_add(1, Ordering::Relaxed);
            if let Ok(response_der) = fetcher.fetch(&url, &request) {
                match ocsp::validate_staple(&response_der, &cred, Some(&nonce), now, &cfg) {
                    Ok(info) => {
                        self.stats.stapled.fetch_add(1, Ordering::Relaxed);
                        let staple: Arc<[u8]> = Arc::from(response_der.into_boxed_slice());
                        let new_cred = Arc::new(cred.with_staple(Some(staple)));
                        let delay = refresh_delay(info, now, &cfg);
                        if let Some(t) = self.tracked.get_mut(i) {
                            t.state = TrackedState::Stapled;
                            t.consecutive_failures = 0;
                            t.current_next_update = info.next_update;
                            t.next_attempt = now.saturating_add_secs(delay);
                            t.cred = Arc::clone(&new_cred);
                        }
                        updates.push(CertUpdate::Replace {
                            fingerprint,
                            cred: new_cred,
                        });
                    }
                    Err(OcspError::CertificateRevoked { .. }) => {
                        self.stats.revoked.fetch_add(1, Ordering::Relaxed);
                        if let Some(t) = self.tracked.get_mut(i) {
                            t.state = TrackedState::Revoked;
                            updates.push(CertUpdate::Remove {
                                names: t.names.to_vec(),
                            });
                        }
                    }
                    Err(_) => {
                        self.stats.validate_errors.fetch_add(1, Ordering::Relaxed);
                        if let Some(t) = self.tracked.get_mut(i) {
                            record_failure(t, now, &cfg, rng);
                        }
                    }
                }
            } else {
                self.stats.fetch_errors.fetch_add(1, Ordering::Relaxed);
                if let Some(t) = self.tracked.get_mut(i) {
                    record_failure(t, now, &cfg, rng);
                }
            }
        }

        // Step 2: a must-staple credential whose live staple went stale falls through to another
        // credential for the same name if one exists, otherwise fails the handshake, both
        // implemented by removing the credential so the index's normal resolution does the
        // falling through. `current_next_update` doubles as the latch: clearing it here, not just
        // setting `state = Failed`, is what stops this from re-firing (and re-emitting `Remove`)
        // on every later tick, since `state != Stapled` alone stays true forever for a `Failed`
        // entry that never recovers.
        for t in &mut self.tracked {
            if t.must_staple
                && t.state != TrackedState::Stapled
                && let Some(next_update) = t.current_next_update
                && next_update
                    .saturating_add_secs(u64::from(cfg.skew_secs))
                    .get()
                    < now.get()
            {
                t.state = TrackedState::Failed;
                t.current_next_update = None;
                updates.push(CertUpdate::Remove {
                    names: t.names.to_vec(),
                });
            }
        }

        updates
    }

    /// State of one tracked certificate, for the admin API.
    #[must_use]
    pub fn state_of(&self, fingerprint: CertFingerprint) -> Option<TrackedState> {
        self.tracked
            .iter()
            .find(|t| t.fingerprint == fingerprint)
            .map(|t| t.state)
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &OcspStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    use der::Decode;
    use rcgen::SigningKey;

    use super::{OcspFetcher, OcspUpdater, RngLike, TrackedState};
    use crate::ocsp::OcspConfig;
    use crate::store::{CertUpdate, ChainInterner, Credentials, TimeView};
    use crate::time::UnixSeconds;

    fn ensure_provider_installed() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    /// A `TimeView` that never reads a clock.
    struct FixedClock(UnixSeconds);
    impl TimeView for FixedClock {
        fn unix_seconds(&self) -> UnixSeconds {
            self.0
        }
    }

    /// An `RngLike` that always returns the same value, so every test's jitter and nonce bytes
    /// are deterministic.
    struct ConstRng(u64);
    impl RngLike for ConstRng {
        fn next_u64(&mut self) -> u64 {
            self.0
        }
    }

    /// Records every request body `tick` sent, and returns a settable canned response (or
    /// transport error) for every call.
    struct TestFetcher {
        calls: Mutex<Vec<Vec<u8>>>,
        response: Mutex<Result<Vec<u8>, String>>,
    }
    impl TestFetcher {
        fn new(response: Result<Vec<u8>, String>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                response: Mutex::new(response),
            }
        }
        fn set_response(&self, response: Result<Vec<u8>, String>) {
            *self.response.lock().expect("test mutex") = response;
        }
        fn call_count(&self) -> usize {
            self.calls.lock().expect("test mutex").len()
        }
    }
    impl OcspFetcher for TestFetcher {
        fn fetch(&self, _url: &str, request_der: &[u8]) -> Result<Vec<u8>, String> {
            self.calls
                .lock()
                .expect("test mutex")
                .push(request_der.to_vec());
            self.response.lock().expect("test mutex").clone()
        }
    }

    /// `Arc::clone` alone commits its generic parameter to `TestFetcher` before unsizing can
    /// apply, so every call site goes through this function instead, whose own return type
    /// drives the unsize coercion to `Arc<dyn OcspFetcher>`.
    fn as_dyn_fetcher(fetcher: &Arc<TestFetcher>) -> Arc<dyn OcspFetcher> {
        let cloned: Arc<TestFetcher> = Arc::clone(fetcher);
        cloned
    }

    /// One issuer plus one leaf credential it issued, for building canned OCSP responses.
    struct Fixture {
        issuer_der: Vec<u8>,
        issuer_key: rcgen::KeyPair,
        cred: Arc<Credentials>,
    }

    fn build_fixture(san: &str) -> Fixture {
        ensure_provider_installed();
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keygen must succeed for a fixed, well-known algorithm");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut issuer_dn = rcgen::DistinguishedName::new();
        issuer_dn.push(rcgen::DnType::CommonName, format!("issuer for {san}"));
        issuer_params.distinguished_name = issuer_dn;
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self sign issuer")
            .der()
            .to_vec();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keygen must succeed for a fixed, well-known algorithm");
        let leaf_params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SAN");
        let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &signing_issuer)
            .expect("sign leaf")
            .der()
            .to_vec();

        let mut interner = ChainInterner::new();
        let cred = Credentials::load(
            &[&leaf_der, &issuer_der],
            &leaf_key.serialize_der(),
            &mut interner,
        )
        .expect("valid chain and key");

        Fixture {
            issuer_der,
            issuer_key,
            cred: Arc::new(cred),
        }
    }

    fn unix_to_generalized(secs: u64) -> x509_ocsp::OcspGeneralizedTime {
        let gt =
            der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(secs))
                .expect("a fixture timestamp must encode as a valid GeneralizedTime");
        x509_ocsp::OcspGeneralizedTime(gt)
    }

    fn build_cert_id_for_test(
        fixture: &Fixture,
        issuer: &x509_cert::Certificate,
    ) -> x509_ocsp::CertId {
        use sha1::Digest;
        let issuer_name_hash = sha1::Sha1::digest(fixture.cred.issuer_dn());
        let issuer_key_hash = sha1::Sha1::digest(
            issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        );
        x509_ocsp::CertId {
            hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: der::asn1::OctetString::new(issuer_name_hash.to_vec())
                .expect("octet string"),
            issuer_key_hash: der::asn1::OctetString::new(issuer_key_hash.to_vec())
                .expect("octet string"),
            serial_number: x509_cert::serial_number::SerialNumber::new(fixture.cred.serial())
                .expect("serial"),
        }
    }

    /// A correctly signed, self-responder `BasicOCSPResponse`, wrapped as a full `OCSPResponse`,
    /// exactly the shape `tick` reads back from its `OcspFetcher`.
    fn build_response(
        fixture: &Fixture,
        status: x509_ocsp::CertStatus,
        this_update: u64,
        next_update: Option<u64>,
    ) -> Vec<u8> {
        let issuer =
            x509_cert::Certificate::from_der(&fixture.issuer_der).expect("parse fixture issuer");
        let cert_id = build_cert_id_for_test(fixture, &issuer);
        let single = x509_ocsp::SingleResponse {
            cert_id,
            cert_status: status,
            this_update: unix_to_generalized(this_update),
            next_update: next_update.map(unix_to_generalized),
            single_extensions: None,
        };
        let response_data = x509_ocsp::ResponseData {
            version: x509_ocsp::Version::V1,
            responder_id: x509_ocsp::ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
            produced_at: unix_to_generalized(this_update),
            responses: vec![single],
            response_extensions: None,
        };
        let tbs_der = x509_cert::der::Encode::to_der(&response_data).expect("encode tbs");
        let signature_bytes = fixture.issuer_key.sign(&tbs_der).expect("sign tbs");
        let basic = x509_ocsp::BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                parameters: None,
            },
            signature: der::asn1::BitString::from_bytes(&signature_bytes)
                .expect("signature as BIT STRING"),
            certs: None,
        };
        let basic_der = x509_cert::der::Encode::to_der(&basic).expect("encode basic response");
        let response = x509_ocsp::OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1"),
                response: der::asn1::OctetString::new(basic_der).expect("response octet string"),
            }),
        };
        x509_cert::der::Encode::to_der(&response).expect("encode OCSPResponse")
    }

    fn build_good_response(
        fixture: &Fixture,
        this_update: u64,
        next_update: Option<u64>,
    ) -> Vec<u8> {
        build_response(
            fixture,
            x509_ocsp::CertStatus::good(),
            this_update,
            next_update,
        )
    }

    #[test]
    fn no_aia_is_terminal() {
        let fixture = build_fixture("no-aia.example.com");
        let fetcher = Arc::new(TestFetcher::new(Err("must not be called".to_owned())));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, OcspConfig::default());
        updater.track(&fixture.cred, None);
        assert_eq!(
            updater.state_of(fixture.cred.fingerprint()),
            Some(TrackedState::NoResponder)
        );
        assert_eq!(updater.stats().no_responder.load(Ordering::Relaxed), 1);

        for i in 0..100u64 {
            let emitted = updater.tick(UnixSeconds::new(i * 10_000), &mut ConstRng(0));
            assert!(emitted.is_empty());
        }
        assert_eq!(fetcher.call_count(), 0);
        assert_eq!(updater.stats().fetches.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn backoff_sequence_is_exact() {
        let fixture = build_fixture("backoff-exact.example.com");
        let fetcher = Arc::new(TestFetcher::new(Err(
            "simulated transport failure".to_owned()
        )));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        // fail_after well above 10 so the entry keeps retrying for the whole sequence; a
        // per-mille jitter of 500 (the low end of [0.5, 1.0]) from a constant rng returning 0.
        let cfg = OcspConfig {
            min_interval_secs: 1,
            backoff_base_secs: 60,
            backoff_max_secs: 21_600,
            fail_after: 100,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        // min(60 * 2^(f-1), 21_600) * 500 / 1000, for f = 1..=10.
        let expected_delays: [u64; 10] = [30, 60, 120, 240, 480, 960, 1_920, 3_840, 7_680, 10_800];

        let mut now = UnixSeconds::new(0);
        for (i, &delay) in expected_delays.iter().enumerate() {
            let before = fetcher.call_count();
            let emitted = updater.tick(now, &mut ConstRng(0));
            assert!(emitted.is_empty());
            assert_eq!(
                fetcher.call_count(),
                before + 1,
                "failure {} must fetch exactly once",
                i + 1
            );
            // Two-sided, matching success_schedules_before_next_update's shape: ticking one
            // second before the scheduled retry must NOT fetch again. A one-sided "has it fetched
            // by now + delay" check (the previous shape of this test) cannot tell a delay that is
            // exactly right from one that is shorter than expected, or zero: an entry due earlier
            // than `now + delay` is still due, and therefore still gets fetched, by the time the
            // loop reaches that later instant, so a truncated shift or a `backoff()` replaced
            // outright by a constant both left the one-sided version of this test green.
            let before_scheduled = now.saturating_add_secs(delay.saturating_sub(1));
            let _ = updater.tick(before_scheduled, &mut ConstRng(0));
            assert_eq!(
                fetcher.call_count(),
                before + 1,
                "failure {} must not retry before its exact scheduled delay of {delay}s",
                i + 1
            );
            now = now.saturating_add_secs(delay);
        }
    }

    #[test]
    fn fail_after_alarms_and_stops() {
        let fixture = build_fixture("fail-after.example.com");
        let fetcher = Arc::new(TestFetcher::new(Err(
            "simulated transport failure".to_owned()
        )));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            fail_after: 3,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        let mut now = UnixSeconds::new(0);
        for _ in 0..3 {
            let _ = updater.tick(now, &mut ConstRng(0));
            now = now.saturating_add_secs(1_000_000); // comfortably past any backoff delay
        }
        assert_eq!(
            updater.state_of(fixture.cred.fingerprint()),
            Some(TrackedState::Failed)
        );
        let calls_at_failed = fetcher.call_count();
        assert_eq!(calls_at_failed, 3);

        let _ = updater.tick(now, &mut ConstRng(0));
        assert_eq!(
            fetcher.call_count(),
            calls_at_failed,
            "Failed is terminal: no further fetch may happen"
        );
    }

    #[test]
    fn success_schedules_before_next_update() {
        let fixture = build_fixture("success-before.example.com");
        let this_update = 1_000_000u64;
        let next_update = this_update + 10_000; // well inside max_interval_secs
        let response = build_good_response(&fixture, this_update, Some(next_update));
        let response_der = response.clone();
        let fetcher = Arc::new(TestFetcher::new(Ok(response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            margin_secs: 100,
            max_interval_secs: 86_400,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        let emitted = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert_eq!(emitted.len(), 1);
        match &emitted[0] {
            CertUpdate::Replace { cred, .. } => {
                // Invariant 8: the staple installed is the exact bytes received, never
                // re-encoded and never dropped. `matches!(.., CertUpdate::Replace { .. })` alone
                // (the previous shape of this assertion) never looks past the enum variant, so
                // attaching no staple at all, or a truncated one, both left this test green.
                assert_eq!(
                    cred.staple(),
                    Some(response_der.as_slice()),
                    "the credential in the emitted Replace must carry the exact validated \
                     response bytes as its staple"
                );
            }
            other => panic!("expected CertUpdate::Replace, got {other:?}"),
        }
        assert_eq!(
            updater.state_of(fixture.cred.fingerprint()),
            Some(TrackedState::Stapled)
        );

        let expected = next_update - 100; // next_update - margin
        let _ = updater.tick(UnixSeconds::new(expected - 1), &mut ConstRng(0));
        assert_eq!(
            fetcher.call_count(),
            1,
            "must not refetch before next_update - margin"
        );
        let _ = updater.tick(UnixSeconds::new(expected), &mut ConstRng(0));
        assert_eq!(
            fetcher.call_count(),
            2,
            "must refetch exactly at next_update - margin"
        );
    }

    #[test]
    fn no_next_update_schedules_from_ttl() {
        let fixture = build_fixture("no-next-schedule.example.com");
        let this_update = 1_000_000u64;
        let response = build_good_response(&fixture, this_update, None);
        let fetcher = Arc::new(TestFetcher::new(Ok(response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            margin_secs: 100,
            no_next_update_ttl_secs: 3_600,
            max_interval_secs: 86_400,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        let _ = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 1);

        let expected = this_update + 3_600 - 100; // this_update + no_next_update_ttl - margin
        let _ = updater.tick(UnixSeconds::new(expected - 1), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 1, "must not refetch immediately");
        let _ = updater.tick(UnixSeconds::new(expected), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 2);
    }

    #[test]
    fn success_clamps_to_max_interval() {
        let fixture = build_fixture("clamp-max.example.com");
        let this_update = 1_000_000u64;
        let next_update = this_update + 365 * 86_400; // a year away
        let response = build_good_response(&fixture, this_update, Some(next_update));
        let fetcher = Arc::new(TestFetcher::new(Ok(response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            margin_secs: 3_600,
            max_interval_secs: 86_400,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        let _ = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 1);

        let expected = this_update + 86_400;
        let _ = updater.tick(UnixSeconds::new(expected - 1), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 1);
        let _ = updater.tick(UnixSeconds::new(expected), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 2);
    }

    #[test]
    fn success_clamps_to_min_interval() {
        let fixture = build_fixture("clamp-min.example.com");
        let this_update = 1_000_000u64;
        let next_update = this_update + 10; // 10 seconds away
        let response = build_good_response(&fixture, this_update, Some(next_update));
        let fetcher = Arc::new(TestFetcher::new(Ok(response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 300,
            margin_secs: 0,
            max_interval_secs: 86_400,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        let _ = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 1);

        let expected = this_update + 300;
        let _ = updater.tick(UnixSeconds::new(expected - 1), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 1);
        let _ = updater.tick(UnixSeconds::new(expected), &mut ConstRng(0));
        assert_eq!(fetcher.call_count(), 2);
    }

    #[test]
    fn revoked_emits_remove_for_all_sans() {
        ensure_provider_installed();
        let issuer_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self sign issuer")
            .der()
            .to_vec();

        let leaf_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let sans = vec![
            "revoked-a.example.com".to_owned(),
            "revoked-b.example.com".to_owned(),
        ];
        let leaf_params = rcgen::CertificateParams::new(sans.clone()).expect("valid SANs");
        let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &signing_issuer)
            .expect("sign leaf")
            .der()
            .to_vec();
        let mut interner = ChainInterner::new();
        let cred = Arc::new(
            Credentials::load(
                &[&leaf_der, &issuer_der],
                &leaf_key.serialize_der(),
                &mut interner,
            )
            .expect("valid chain and key"),
        );
        assert_eq!(
            cred.san_dns_names().len(),
            2,
            "the fixture must carry both SANs, or this test cannot prove anything about \"all\""
        );
        let fixture = Fixture {
            issuer_der,
            issuer_key,
            cred: Arc::clone(&cred),
        };

        let this_update = 1_000_000u64;
        let revocation_time = this_update - 100;
        let response = build_response(
            &fixture,
            x509_ocsp::CertStatus::Revoked(x509_ocsp::RevokedInfo {
                revocation_time: unix_to_generalized(revocation_time),
                revocation_reason: None,
            }),
            this_update,
            Some(this_update + 3_600),
        );
        let fetcher = Arc::new(TestFetcher::new(Ok(response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&cred, Some("http://ocsp.example.com/"));

        let emitted = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert_eq!(emitted.len(), 1);
        match &emitted[0] {
            CertUpdate::Remove { names } => {
                let mut got: Vec<String> = names.iter().map(ToString::to_string).collect();
                got.sort();
                let mut want = sans.clone();
                want.sort();
                assert_eq!(got, want);
            }
            other => panic!("expected CertUpdate::Remove, got {other:?}"),
        }
        assert_eq!(
            updater.state_of(cred.fingerprint()),
            Some(TrackedState::Revoked)
        );
        assert_eq!(updater.stats().revoked.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn must_staple_stale_emits_remove() {
        ensure_provider_installed();
        let issuer_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self sign issuer")
            .der()
            .to_vec();

        let leaf_key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["must-staple-stale.example.com".to_owned()])
                .expect("valid SAN");
        leaf_params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 0x03, 0x02, 0x01, 0x05],
            ));
        let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &signing_issuer)
            .expect("sign leaf")
            .der()
            .to_vec();
        let mut interner = ChainInterner::new();
        let cred = Arc::new(
            Credentials::load(
                &[&leaf_der, &issuer_der],
                &leaf_key.serialize_der(),
                &mut interner,
            )
            .expect("valid chain and key"),
        );
        assert!(
            cred.must_staple(),
            "the fixture must actually carry the must-staple extension, or this test proves \
             nothing"
        );
        let fixture = Fixture {
            issuer_der,
            issuer_key,
            cred: Arc::clone(&cred),
        };

        let this_update = 1_000_000u64;
        let next_update = this_update + 3_600;
        let good_response = build_good_response(&fixture, this_update, Some(next_update));
        let fetcher = Arc::new(TestFetcher::new(Ok(good_response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            margin_secs: 100,
            max_interval_secs: 86_400,
            skew_secs: 300,
            fail_after: 1,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&cred, Some("http://ocsp.example.com/"));

        let emitted1 = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert_eq!(
            emitted1.len(),
            1,
            "the first tick must install the staple, or this test proves nothing"
        );
        assert_eq!(
            updater.state_of(cred.fingerprint()),
            Some(TrackedState::Stapled)
        );

        fetcher.set_response(Err("simulated transport failure".to_owned()));
        // Past both the (already-elapsed) refresh schedule and next_update + skew: due for
        // retry, the retry fails, and fail_after == 1 flips the state away from Stapled in the
        // very same tick the staleness sweep also runs in.
        let stale_now = UnixSeconds::new(next_update + 300 + 1_000);
        let emitted2 = updater.tick(stale_now, &mut ConstRng(0));

        assert_eq!(
            updater.state_of(cred.fingerprint()),
            Some(TrackedState::Failed)
        );
        assert_eq!(emitted2.len(), 1);
        match &emitted2[0] {
            CertUpdate::Remove { names } => {
                assert_eq!(names.len(), 1);
                assert_eq!(names[0].as_ref(), "must-staple-stale.example.com");
            }
            other => panic!("expected CertUpdate::Remove, got {other:?}"),
        }

        // The sweep must latch: once a must-staple entry has been removed for going stale, every
        // later tick must emit nothing more for it. Without a latch, `state != Stapled` stays
        // true and `current_next_update` stays populated forever, so the same stale entry would
        // re-emit `CertUpdate::Remove` on every single tick from here on, each one driving a
        // fresh certificate-index rebuild for a credential that already left the index once.
        for i in 0..5 {
            let repeat_now = stale_now.saturating_add_secs(1_000 * (i + 1));
            let emitted_repeat = updater.tick(repeat_now, &mut ConstRng(0));
            assert!(
                emitted_repeat.is_empty(),
                "repeat sweep tick {i}: must emit nothing once already removed for staleness, \
                 got {emitted_repeat:?}"
            );
        }
    }

    #[test]
    fn tick_refuses_disallowed_aia_url_without_fetching() {
        // Edge case 24: an AIA URL that `validate_aia_url` refuses (here, the exact cloud
        // metadata address the SSRF gate exists to block) must never reach the fetcher, and the
        // tracked entry must go to `Failed` with no retry loop, invariant 10 in the module doc.
        // The six `aia_url_*` tests in `ocsp.rs` exercise the pure function alone; this is the
        // only test that exercises the call site inside `tick`, so a mutation that unwired the
        // gate from its one caller (`if ocsp::validate_aia_url(...).is_err()` short-circuited to
        // always `false`) would otherwise leave every test in this file green.
        let fixture = build_fixture("metadata-aia.example.com");
        let fetcher = Arc::new(TestFetcher::new(Err("must not be called".to_owned())));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://169.254.169.254/meta-data/"));

        for i in 0..10u64 {
            let emitted = updater.tick(UnixSeconds::new(i), &mut ConstRng(0));
            assert!(emitted.is_empty());
        }

        assert_eq!(
            fetcher.call_count(),
            0,
            "no request may ever be sent to a URL that has not passed validate_aia_url"
        );
        assert_eq!(
            updater.state_of(fixture.cred.fingerprint()),
            Some(TrackedState::Failed)
        );
        assert_eq!(updater.stats().fetches.load(Ordering::Relaxed), 0);
        assert_eq!(updater.stats().validate_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn validation_failure_keeps_previous_staple() {
        let fixture = build_fixture("validation-failure.example.com");
        let other_fixture = build_fixture("unrelated-for-validation-failure.example.com");
        let this_update = 1_000_000u64;
        // Correctly signed and shaped, but for a DIFFERENT credential's CertID: this reaches
        // validate_staple's CertIdMismatch specifically, exercising the "fetch succeeded but
        // validation failed" branch rather than a transport error.
        let response = build_good_response(&other_fixture, this_update, Some(this_update + 3_600));
        let fetcher = Arc::new(TestFetcher::new(Ok(response)));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        let cfg = OcspConfig {
            min_interval_secs: 1,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);
        updater.track(&fixture.cred, Some("http://ocsp.example.com/"));

        let emitted = updater.tick(UnixSeconds::new(this_update), &mut ConstRng(0));
        assert!(
            emitted.is_empty(),
            "a validation failure must not emit any CertUpdate: {emitted:?}"
        );
        assert_eq!(updater.stats().validate_errors.load(Ordering::Relaxed), 1);
        assert_ne!(
            updater.state_of(fixture.cred.fingerprint()),
            Some(TrackedState::Stapled)
        );
    }

    #[test]
    fn tick_respects_fetch_budget() {
        const N: usize = 50_000;

        ensure_provider_installed();
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid empty SAN list");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer_der = issuer_params
            .self_signed(&issuer_key)
            .expect("self sign issuer")
            .der()
            .to_vec();
        let signing_issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);

        let fetcher = Arc::new(TestFetcher::new(Err(
            "simulated transport failure".to_owned()
        )));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(0)));
        // A wide spread window (1000s) so 50,000 credentials get genuinely staggered initial
        // next_attempt values instead of all tying at zero; ticking at now=1000 then puts every
        // one of them due at once, matching "50,000 tracked certificates all due at once after a
        // restart" from the issue's own edge case 30.
        let cfg = OcspConfig {
            min_interval_secs: 1_000,
            max_fetches_per_tick: 8,
            ..OcspConfig::default()
        };
        let mut updater = OcspUpdater::new(as_dyn_fetcher(&fetcher), time, cfg);

        let mut interner = ChainInterner::new();
        for i in 0..N {
            let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
            let leaf_params =
                rcgen::CertificateParams::new(vec![format!("h{i}.example.com")]).expect("valid");
            let leaf_der = leaf_params
                .signed_by(&leaf_key, &signing_issuer)
                .expect("sign leaf")
                .der()
                .to_vec();
            let cred = Arc::new(
                Credentials::load(
                    &[&leaf_der, &issuer_der],
                    &leaf_key.serialize_der(),
                    &mut interner,
                )
                .expect("valid chain and key"),
            );
            updater.track(&cred, Some("http://ocsp.example.com/"));
        }

        let now = UnixSeconds::new(1_000);
        let emitted1 = updater.tick(now, &mut ConstRng(0));
        assert!(emitted1.is_empty());
        assert_eq!(
            fetcher.call_count(),
            8,
            "one tick over 50,000 due certificates must start exactly max_fetches_per_tick fetches"
        );
        let batch1: Vec<Vec<u8>> = fetcher.calls.lock().expect("test mutex").clone();
        let batch1_set: std::collections::HashSet<Vec<u8>> = batch1.iter().cloned().collect();
        assert_eq!(
            batch1_set.len(),
            8,
            "the first batch's own 8 requests must be for 8 distinct credentials"
        );

        let emitted2 = updater.tick(now, &mut ConstRng(0));
        assert!(emitted2.is_empty());
        assert_eq!(fetcher.call_count(), 16);
        let all_calls: Vec<Vec<u8>> = fetcher.calls.lock().expect("test mutex").clone();
        let batch2: Vec<Vec<u8>> = all_calls.get(8..).expect("16 calls recorded").to_vec();
        let batch2_set: std::collections::HashSet<Vec<u8>> = batch2.into_iter().collect();
        assert_eq!(
            batch2_set.len(),
            8,
            "the second batch's own 8 requests must be for 8 distinct credentials"
        );
        assert!(
            batch1_set.is_disjoint(&batch2_set),
            "the second tick's batch must be disjoint from the first"
        );
    }
}
