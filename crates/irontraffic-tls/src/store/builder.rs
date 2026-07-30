// SPDX-License-Identifier: MIT OR Apache-2.0

//! Incremental certificate-index rebuild, plus `CertUpdateCoalescer`, which absorbs a burst of
//! single-certificate updates behind a debounce and turns them into one rebuild.
//!
//! [`CertIndexBuilder::from_previous`] rebuilds a whole new [`CertIndex`] without re-parsing DER
//! or re-verifying a private key: it copies the previous index's own name hasher and flattens its
//! entries into a fresh pending list, sharing every `Arc<Credentials>`. [`CertUpdate`] is the one
//! change a control-plane loop submits (from ACME issuance, OCSP staple refresh, or the
//! configuration plane); [`CertUpdateCoalescer`] is the single-owner, `&mut self`, lock-free
//! object that batches those changes and publishes the result through a [`super::TlsMaterialCell`].
//!
//! **Validate at `submit`, not at flush.** A name that fails validation never enters `pending`:
//! without this, one bad wildcard sitting in `pending` would abort every later flush forever,
//! freezing the store at its last good generation while an operator sees only a repeating error.
//! `submit` runs the exact same checks the builder itself would run, so an update accepted here is
//! never later rejected by the builder for a name reason (it can still fail the builder for a
//! systemic reason, such as the index growing past its arena or group limit, which `submit` cannot
//! see in advance).
//!
//! **A removal is never dropped.** When the pending cap is exceeded, the oldest droppable update
//! (`Install`, `InstallChallenge`, or `Replace`) is dropped, never a `Remove`, `RemoveChallenge`, or
//! `SetDefault`: those are withdrawals of trust, and losing one silently keeps a revoked or
//! compromised certificate in service with nothing downstream to notice.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use crate::name::{self, MAX_NAME_LEN};
use crate::policy::TlsPolicy;
use crate::store::index::validate_wildcard_parent;
use crate::store::{
    CertError, CertFingerprint, CertIndex, CertIndexBuilder, ChainInterner, ChallengeCertsBuilder,
    ChallengeKey, Credentials, IronResolver, TimeView,
};
use crate::store::{TlsMaterial, TlsMaterialCell};
use crate::time::UnixSeconds;

/// Default debounce window, milliseconds. See [`CertUpdateCoalescer::set_debounce_ms`].
const DEFAULT_DEBOUNCE_MS: u32 = 100;
/// Upper clamp on the debounce window. See [`CertUpdateCoalescer::set_debounce_ms`].
const MAX_DEBOUNCE_MS: u32 = 5_000;
/// Default pending-update cap. See [`CertUpdateCoalescer::set_max_pending`].
const DEFAULT_MAX_PENDING: usize = 4_096;
/// Lower clamp on the pending-update cap. See [`CertUpdateCoalescer::set_max_pending`].
const MIN_MAX_PENDING: usize = 16;

/// One certificate-store change, produced by ACME issuance, OCSP staple refresh, or the
/// configuration plane.
#[derive(Clone, Debug)]
pub enum CertUpdate {
    /// Install or replace the credential for these exact names and wildcard names.
    Install {
        /// Exact names to index.
        exact: Vec<Box<str>>,
        /// Wildcard names, written as `*.parent`.
        wildcard: Vec<Box<str>>,
        /// The credential to index under all of them.
        cred: Arc<Credentials>,
    },
    /// Replace an existing credential in place, matched by fingerprint, keeping its names.
    /// This is the OCSP staple path: same certificate, different staple.
    Replace {
        /// Which credential to replace.
        fingerprint: CertFingerprint,
        /// The replacement.
        cred: Arc<Credentials>,
    },
    /// Remove every entry for these names.
    Remove {
        /// Names to remove, exact or `*.parent` form.
        names: Vec<Box<str>>,
    },
    /// Set the default credential served when no name matches.
    SetDefault {
        /// The new default.
        cred: Arc<Credentials>,
    },
    /// Install or replace a TLS-ALPN-01 challenge certificate.
    InstallChallenge {
        /// The name being validated.
        name: Box<str>,
        /// The self-signed challenge credential.
        key: ChallengeKey,
        /// When this entry stops being served.
        expires: UnixSeconds,
    },
    /// Remove a challenge certificate.
    RemoveChallenge {
        /// The name.
        name: Box<str>,
    },
}

/// Whether `update` is subject to being dropped under the pending cap. `Remove`,
/// `RemoveChallenge` and `SetDefault` are exempt: see the module docs.
fn is_droppable(update: &CertUpdate) -> bool {
    matches!(
        update,
        CertUpdate::Install { .. }
            | CertUpdate::InstallChallenge { .. }
            | CertUpdate::Replace { .. }
    )
}

/// Validate every name `update` carries, exactly the way it will later be applied, without
/// staging anything. Called by [`CertUpdateCoalescer::submit`] before an update ever enters
/// `pending`.
fn validate_update(update: &CertUpdate) -> Result<(), CertError> {
    match update {
        CertUpdate::Install {
            exact, wildcard, ..
        } => {
            for n in exact {
                let mut buf = [0u8; MAX_NAME_LEN];
                name::normalize(n, &mut buf)?;
            }
            for n in wildcard {
                validate_wildcard_parent(n)?;
            }
            Ok(())
        }
        CertUpdate::Remove { names } => {
            for n in names {
                let mut buf = [0u8; MAX_NAME_LEN];
                name::normalize(n, &mut buf)?;
            }
            Ok(())
        }
        CertUpdate::InstallChallenge { name, .. } | CertUpdate::RemoveChallenge { name } => {
            let mut buf = [0u8; MAX_NAME_LEN];
            name::normalize(name, &mut buf)?;
            Ok(())
        }
        CertUpdate::Replace { .. } | CertUpdate::SetDefault { .. } => Ok(()),
    }
}

impl CertIndexBuilder {
    /// Seed a builder from an existing index, sharing every `Arc<Credentials>` and keeping the
    /// same name hasher key so that no name is re-hashed with a freshly derived key and no
    /// certificate is re-parsed.
    #[must_use]
    pub fn from_previous(prev: &CertIndex) -> Self {
        let entries = prev.rebuild_entries();
        let default_cred = prev.default_cred().cloned();
        CertIndexBuilder::new_from_inherited(entries, default_cred, prev.hasher().clone())
    }

    /// Substitute `cred` for every pending entry whose credential has `fingerprint`, keeping the
    /// names those entries are indexed under. Returns the number of entries replaced, which is 0
    /// when the credential is no longer in the builder.
    ///
    /// This is the OCSP staple path: the same certificate with a different staple, and therefore
    /// the same fingerprint, since the fingerprint hashes the leaf DER and a staple is not part of
    /// the leaf.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "takes an owned Arc<Credentials> to match upsert_exact/upsert_wildcard's own \
                  by-value convention for a replacement credential, even though this particular \
                  implementation only needs a borrow to reach the per-module accessor"
    )]
    pub fn replace_by_fingerprint(
        &mut self,
        fingerprint: CertFingerprint,
        cred: Arc<Credentials>,
    ) -> usize {
        self.replace_pending_by_fingerprint(fingerprint, &cred)
    }
}

/// Absorbs a burst of single-certificate updates behind a debounce and turns them into one
/// rebuild. Single-owner and synchronous: it holds `&mut` state and therefore takes no lock,
/// which is what keeps this crate free of the `Mutex`/`RwLock` ban that applies to hot-path
/// crates. The owning control-plane loop calls [`Self::submit`] and [`Self::flush_if_due`] (or
/// [`Self::flush_now`]); nothing in this crate spawns a task or a thread to drive it.
pub struct CertUpdateCoalescer {
    cell: Arc<TlsMaterialCell>,
    interner: ChainInterner,
    pending: Vec<CertUpdate>,
    first_pending_ms: Option<u64>,
    debounce_ms: u32,
    max_pending: usize,
    next_generation: u64,
    policy: Arc<TlsPolicy>,
    time: Arc<dyn TimeView>,
    /// Weak handles to every generation published by this coalescer, pruned on each flush, so
    /// that `tls_material_live_generations` reports how many are still pinned by a connection.
    live: Vec<Weak<TlsMaterial>>,
    /// Test-only: force the next flush's certificate-index build to fail, by lowering the
    /// internal builder's group limit to 0. Mirrors `CertIndexBuilder::force_collision_on_attempt_0`:
    /// there is no way to reach "the build itself fails, as opposed to one update being rejected"
    /// from ordinary test data, since `submit` already rejects anything that would make the
    /// builder reject a single update. Consumed (reset to `false`) by the flush it forces to
    /// fail, so a later retry is unaffected.
    #[cfg(test)]
    force_build_failure: bool,
}

impl CertUpdateCoalescer {
    /// Build a coalescer over a publication cell.
    #[must_use]
    pub fn new(
        cell: Arc<TlsMaterialCell>,
        interner: ChainInterner,
        policy: Arc<TlsPolicy>,
        time: Arc<dyn TimeView>,
    ) -> Self {
        Self {
            cell,
            interner,
            pending: Vec::new(),
            first_pending_ms: None,
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            max_pending: DEFAULT_MAX_PENDING,
            next_generation: 1,
            policy,
            time,
            live: Vec::new(),
            #[cfg(test)]
            force_build_failure: false,
        }
    }

    /// Override the debounce window. Default 100 ms. Values above 5,000 are clamped to 5,000
    /// because a longer window delays a certificate renewal past the point of usefulness. `0` is
    /// legal and means "publish on the next tick", which is what the tests use.
    pub fn set_debounce_ms(&mut self, ms: u32) {
        self.debounce_ms = ms.min(MAX_DEBOUNCE_MS);
    }

    /// Override the pending-update cap. Default 4096. Values below 16 are clamped **up** to 16,
    /// and there is no upper clamp; a very large cap simply means the debounce is the only
    /// trigger.
    pub fn set_max_pending(&mut self, n: usize) {
        self.max_pending = n.max(MIN_MAX_PENDING);
    }

    /// The chain interner this coalescer owns, so that a caller loading a `Credentials` for an
    /// `Install` update shares one interner with every other generation.
    ///
    /// This is why the coalescer holds a `ChainInterner` at all: the flush path itself never
    /// interns, because `CertUpdate::Install` already carries a loaded credential.
    pub fn interner_mut(&mut self) -> &mut ChainInterner {
        &mut self.interner
    }

    /// Record an update for the next flush.
    ///
    /// Names are validated here, not at flush time, so that one malformed update cannot block
    /// every later update from publishing.
    ///
    /// # Errors
    /// `CertError::Name`, `CertError::Wildcard` or `CertError::WildcardTooBroad` if any name in
    /// the update fails validation. The update is not recorded and the pending list is unchanged.
    pub fn submit(&mut self, update: CertUpdate) -> Result<(), CertError> {
        if let Err(e) = validate_update(&update) {
            self.cell
                .stats()
                .updates_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        self.pending.push(update);
        self.cell
            .stats()
            .updates_submitted
            .fetch_add(1, Ordering::Relaxed);

        if self.pending.len() > self.max_pending {
            if let Some(idx) = self.pending.iter().position(is_droppable) {
                self.pending.remove(idx);
                // This crate has no `tracing` dependency (the only dependency this issue
                // authorizes is `arc-swap`), so the design's "log at warn once per 1,000 drops"
                // and "raise a warn alarm" become this counter: `tls_material_updates_dropped_total`
                // / `tls_material_updates_over_cap_total`, already incremented here and below, are
                // the durable signal an operator's alerting rule fires on instead of a log line.
                self.cell
                    .stats()
                    .updates_dropped
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.cell
                    .stats()
                    .updates_over_cap
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Rebuild and publish if the debounce window has elapsed or the pending cap is reached.
    ///
    /// Returns the newly published generation, or `None` if nothing was due.
    ///
    /// # Errors
    /// Any `CertError` from the builder. On error nothing is published and the pending list is
    /// retained for the next attempt.
    pub fn flush_if_due(&mut self, now_ms: u64) -> Result<Option<u64>, CertError> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        if self.first_pending_ms.is_none() {
            self.first_pending_ms = Some(now_ms);
        }
        let first = self.first_pending_ms.unwrap_or(now_ms);
        let elapsed = now_ms.saturating_sub(first);
        if elapsed < u64::from(self.debounce_ms) && self.pending.len() < self.max_pending {
            return Ok(None);
        }
        self.flush_inner()
    }

    /// Rebuild and publish now, ignoring the debounce. Used at startup and by tests.
    ///
    /// # Errors
    /// As `flush_if_due`.
    pub fn flush_now(&mut self) -> Result<Option<u64>, CertError> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        self.flush_inner()
    }

    /// Number of pending updates.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Shared body for `flush_if_due` and `flush_now`: build, apply, publish, or abort and record
    /// `reload_failures` on any error from `build_and_publish`.
    fn flush_inner(&mut self) -> Result<Option<u64>, CertError> {
        match self.build_and_publish() {
            Ok(published) => Ok(published),
            Err(e) => {
                self.cell
                    .stats()
                    .reload_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Steps 3 through 9 of the flush algorithm. Any `Err` here leaves `pending` untouched: this
    /// function never calls `self.pending.clear()` before its final, guaranteed-successful lines.
    fn build_and_publish(&mut self) -> Result<Option<u64>, CertError> {
        let cur = self.cell.load();
        let mut cb = CertIndexBuilder::from_previous(&cur.certs);
        #[cfg(test)]
        if self.force_build_failure {
            cb.set_max_groups_for_test(0);
            self.force_build_failure = false;
        }
        let mut chb =
            ChallengeCertsBuilder::from_previous(&cur.challenge, self.time.unix_seconds());

        for update in &self.pending {
            match update {
                CertUpdate::Install {
                    exact,
                    wildcard,
                    cred,
                } => {
                    for name in exact {
                        cb.upsert_exact(name, Arc::clone(cred))?;
                    }
                    for name in wildcard {
                        cb.upsert_wildcard(name, Arc::clone(cred))?;
                    }
                }
                CertUpdate::Replace { fingerprint, cred } => {
                    let replaced = cb.replace_by_fingerprint(*fingerprint, Arc::clone(cred));
                    if replaced == 0 {
                        self.cell
                            .stats()
                            .replace_missed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                CertUpdate::Remove { names } => {
                    for name in names {
                        cb.remove(name);
                    }
                }
                CertUpdate::SetDefault { cred } => {
                    cb.set_default(Arc::clone(cred));
                }
                CertUpdate::InstallChallenge { name, key, expires } => {
                    chb.insert(name, key.clone(), *expires)?;
                }
                CertUpdate::RemoveChallenge { name } => {
                    chb.remove(name);
                }
            }
        }

        let certs = Arc::new(cb.build_with_generation(self.next_generation)?);
        let challenge = Arc::new(chb.build_with_generation(self.next_generation)?);
        let resolver = Arc::new(IronResolver::new(
            Arc::clone(&certs),
            Arc::clone(&challenge),
            Arc::clone(&self.policy),
            Arc::clone(&self.time),
        ));
        let material = Arc::new(TlsMaterial {
            certs,
            challenge,
            resolver,
            generation: self.next_generation,
        });
        self.track_live(&material);
        self.cell.publish(material);

        self.pending.clear();
        self.first_pending_ms = None;
        let g = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1); // edge case 15: wraps in 584 million years at one publish per millisecond; wrapping rather than a saturating/panicking add is the documented, accepted behaviour
        Ok(Some(g))
    }

    /// Prune dead entries, record the newly published generation as live, and update the gauge.
    ///
    /// Not on `TlsMaterialCell`: `publish` takes `&self` and would need a lock to maintain this
    /// `Vec`, and this crate has none. A publish that does not go through this coalescer (only
    /// the initial one) simply does not update the gauge.
    fn track_live(&mut self, material: &Arc<TlsMaterial>) {
        self.live.retain(|w| w.strong_count() > 0);
        self.live.push(Arc::downgrade(material));
        self.cell
            .stats()
            .live_generations
            .store(self.live.len() as u64, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain AtomicU64 gauge write of this coalescer's own live-generation count, not an ArcSwap config snapshot publish; mirrors the AtomicU32/AtomicU64 cache field writes already allowed in irontraffic-time's cache.rs
    }

    /// Test-only: force the NEXT flush's certificate-index build to fail. See the field doc on
    /// `force_build_failure` for why this hook exists.
    #[cfg(test)]
    pub(crate) fn force_next_build_failure(&mut self) {
        self.force_build_failure = true;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Once};

    use proptest::prelude::*;

    use super::{CertIndexBuilder, CertUpdate, CertUpdateCoalescer};
    use crate::policy::TlsPolicy;
    use crate::store::{
        CertError, CertIndex, ChainInterner, ChallengeCerts, ChallengeKey, ClientCaps, Credentials,
        IronResolver, TimeView, TlsMaterial, TlsMaterialCell,
    };
    use crate::time::UnixSeconds;

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
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

    /// A `TimeView` whose value can be moved forward mid-test, for expiry tests.
    struct SettableClock(AtomicU64);
    impl SettableClock {
        fn new(secs: u64) -> Self {
            Self(AtomicU64::new(secs))
        }
        fn set(&self, secs: u64) {
            self.0.store(secs, Ordering::Relaxed);
        }
    }
    impl TimeView for SettableClock {
        fn unix_seconds(&self) -> UnixSeconds {
            UnixSeconds::new(self.0.load(Ordering::Relaxed))
        }
    }

    fn gen_leaf(san: &str) -> (Vec<u8>, Vec<u8>) {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        let cert = params.self_signed(&key).expect("sign");
        (cert.der().to_vec(), key.serialize_der())
    }

    fn gen_cred(san: &str) -> Arc<Credentials> {
        let (leaf, key) = gen_leaf(san);
        let mut interner = ChainInterner::new();
        Arc::new(Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key"))
    }

    /// An Ed25519 credential, so a single name can hold two DIFFERENT `KeyType` slots. Used to
    /// pin that `rebuild_entries` carries every slot forward, not just the preferred one.
    fn gen_cred_ed25519(san: &str) -> Arc<Credentials> {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        let cert = params.self_signed(&key).expect("sign");
        let mut interner = ChainInterner::new();
        Arc::new(
            Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                .expect("valid leaf and key"),
        )
    }

    fn gen_cred_with_validity(
        san: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> Arc<Credentials> {
        ensure_provider_installed();
        let mut params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let cert = params.self_signed(&key).expect("sign");
        let mut interner = ChainInterner::new();
        Arc::new(
            Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                .expect("valid leaf and key"),
        )
    }

    fn install_exact(name: &str, cred: &Arc<Credentials>) -> CertUpdate {
        CertUpdate::Install {
            exact: vec![name.into()],
            wildcard: Vec::new(),
            cred: Arc::clone(cred),
        }
    }

    fn build_initial(entries: &[(&str, &Arc<Credentials>)]) -> Arc<TlsMaterial> {
        let mut b = CertIndexBuilder::new([1u8; 16]);
        for (name, cred) in entries {
            b.upsert_exact(name, Arc::clone(cred)).expect("valid");
        }
        let certs = Arc::new(b.build_with_generation(0).expect("build"));
        let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
        let policy = Arc::new(TlsPolicy::default_https());
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_000)));
        let resolver = Arc::new(IronResolver::new(
            Arc::clone(&certs),
            Arc::clone(&challenge),
            Arc::clone(&policy),
            Arc::clone(&time),
        ));
        Arc::new(TlsMaterial {
            certs,
            challenge,
            resolver,
            generation: 0,
        })
    }

    /// Cell plus a coalescer with the debounce dropped to 0, so `flush_now`/`flush_if_due` always
    /// proceeds regardless of timing. Used by every test that is not itself testing the debounce
    /// timer.
    fn test_setup(
        entries: &[(&str, &Arc<Credentials>)],
    ) -> (Arc<TlsMaterialCell>, CertUpdateCoalescer) {
        let material = build_initial(entries);
        let cell = Arc::new(TlsMaterialCell::new(material));
        let time: Arc<dyn TimeView> = Arc::new(FixedClock(UnixSeconds::new(1_000)));
        let mut coalescer = CertUpdateCoalescer::new(
            Arc::clone(&cell),
            ChainInterner::new(),
            Arc::new(TlsPolicy::default_https()),
            time,
        );
        coalescer.set_debounce_ms(0);
        (cell, coalescer)
    }

    #[test]
    fn flush_empty_is_none() {
        let (cell, mut coalescer) = test_setup(&[]);
        assert_eq!(coalescer.flush_if_due(0).expect("ok"), None);
        assert_eq!(coalescer.flush_now().expect("ok"), None);
        assert_eq!(cell.stats().publishes.load(Ordering::Relaxed), 0);
        assert_eq!(cell.stats().generation.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flush_before_debounce_is_none() {
        let cell = Arc::new(TlsMaterialCell::new(build_initial(&[])));
        let mut coalescer = CertUpdateCoalescer::new(
            Arc::clone(&cell),
            ChainInterner::new(),
            Arc::new(TlsPolicy::default_https()),
            Arc::new(FixedClock(UnixSeconds::new(1_000))),
        );
        // Debounce left at the default (100 ms): this test needs real elapsed-time math.
        let cred = gen_cred("a.example.com");
        coalescer
            .submit(install_exact("a.example.com", &cred))
            .expect("valid update");
        assert_eq!(coalescer.flush_if_due(50).expect("ok"), None);
        assert_eq!(cell.stats().publishes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flush_at_debounce_boundary_publishes() {
        let cell = Arc::new(TlsMaterialCell::new(build_initial(&[])));
        let mut coalescer = CertUpdateCoalescer::new(
            Arc::clone(&cell),
            ChainInterner::new(),
            Arc::new(TlsPolicy::default_https()),
            Arc::new(FixedClock(UnixSeconds::new(1_000))),
        );
        let cred = gen_cred("a.example.com");
        coalescer
            .submit(install_exact("a.example.com", &cred))
            .expect("valid update");
        // First call stamps first_pending_ms at 50 and is itself before the boundary.
        assert_eq!(coalescer.flush_if_due(50).expect("ok"), None);
        // elapsed = 150 - 50 == debounce_ms(100): the boundary itself must publish ("<", not "<=").
        let published = coalescer.flush_if_due(150).expect("ok");
        assert_eq!(published, Some(1));
        assert_eq!(cell.stats().publishes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn burst_coalesces_to_one_publish() {
        let (cell, mut coalescer) = test_setup(&[]);
        coalescer.set_max_pending(20_000);
        let shared = gen_cred("shared-burst.example.com");
        for i in 0..10_000 {
            let name = format!("burst{i}.example.com");
            coalescer
                .submit(install_exact(&name, &shared))
                .expect("valid update");
        }
        assert_eq!(coalescer.pending_len(), 10_000);
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        assert_eq!(cell.stats().publishes.load(Ordering::Relaxed), 1);
        assert_eq!(cell.load().certs.name_count(), 10_000);
    }

    #[test]
    fn over_cap_drops_oldest_install() {
        let (cell, mut coalescer) = test_setup(&[]);
        // set_max_pending(1) must clamp UP to MIN_MAX_PENDING (16), not down to 1: submitting
        // exactly 16 must NOT drop anything (the accept side of that clamp boundary), and only
        // the 17th submission crosses it. A mutation that removed the clamp, or inverted it to a
        // .min instead of a .max, would drop starting at the 2nd submission instead.
        coalescer.set_max_pending(1);
        let shared = gen_cred("shared-cap.example.com");
        for i in 0..16 {
            let name = format!("h{i}.example.com");
            coalescer
                .submit(install_exact(&name, &shared))
                .expect("valid update");
        }
        assert_eq!(
            cell.stats().updates_dropped.load(Ordering::Relaxed),
            0,
            "set_max_pending(1) must clamp up to 16; 16 submissions must not drop anything"
        );
        assert_eq!(coalescer.pending_len(), 16);
        coalescer
            .submit(install_exact("h16.example.com", &shared))
            .expect("valid update");
        assert_eq!(cell.stats().updates_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(coalescer.pending_len(), 16);
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        let material = cell.load();
        assert!(
            material
                .certs
                .resolve("h16.example.com", ClientCaps::all())
                .is_some(),
            "the newest install must survive the cap"
        );
        assert!(
            material
                .certs
                .resolve("h0.example.com", ClientCaps::all())
                .is_none(),
            "the oldest install must be the one dropped"
        );
    }

    #[test]
    fn over_cap_never_drops_remove() {
        let gone_cred = gen_cred("gone.example.com");
        let (cell, mut coalescer) = test_setup(&[("gone.example.com", &gone_cred)]);
        coalescer.set_max_pending(16);
        coalescer
            .submit(CertUpdate::Remove {
                names: vec!["gone.example.com".into()],
            })
            .expect("valid update");
        let shared = gen_cred("shared-remove-cap.example.com");
        for i in 0..16 {
            let name = format!("r{i}.example.com");
            coalescer
                .submit(install_exact(&name, &shared))
                .expect("valid update");
        }
        // pending is now [Remove, Install*16] == 17 items, over max_pending(16); the scan finds
        // the Remove first but skips it, dropping the oldest Install instead.
        assert_eq!(cell.stats().updates_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(coalescer.pending_len(), 16);
        coalescer.flush_now().expect("flush ok");
        let material = cell.load();
        assert!(
            material
                .certs
                .resolve("gone.example.com", ClientCaps::all())
                .is_none(),
            "the Remove must never be the update the cap drops"
        );
        assert!(
            material
                .certs
                .resolve("r15.example.com", ClientCaps::all())
                .is_some(),
            "the newest install must survive"
        );
        assert!(
            material
                .certs
                .resolve("r0.example.com", ClientCaps::all())
                .is_none(),
            "the oldest install after the Remove must be the one dropped"
        );
    }

    #[test]
    fn over_cap_all_removals_grows_and_alarms() {
        let shared = gen_cred("shared-all-remove.example.com");
        let names: Vec<String> = (0..17).map(|i| format!("g{i}.example.com")).collect();
        let entries: Vec<(&str, &Arc<Credentials>)> =
            names.iter().map(|n| (n.as_str(), &shared)).collect();
        let (cell, mut coalescer) = test_setup(&entries);
        coalescer.set_max_pending(16);
        for name in &names {
            coalescer
                .submit(CertUpdate::Remove {
                    names: vec![name.as_str().into()],
                })
                .expect("valid update");
        }
        assert_eq!(cell.stats().updates_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(cell.stats().updates_over_cap.load(Ordering::Relaxed), 1);
        assert_eq!(coalescer.pending_len(), 17);
        let published = coalescer.flush_if_due(0).expect("flush ok");
        assert_eq!(published, Some(1));
        let material = cell.load();
        for name in &names {
            assert!(material.certs.resolve(name, ClientCaps::all()).is_none());
        }
    }

    #[test]
    fn invalid_wildcard_rejected_at_submit() {
        let (cell, mut coalescer) = test_setup(&[]);
        let cred = gen_cred("x.example.com");
        let result = coalescer.submit(CertUpdate::Install {
            exact: Vec::new(),
            wildcard: vec!["*.com".into()],
            cred: Arc::clone(&cred),
        });
        assert_eq!(result, Err(CertError::WildcardTooBroad));
        assert_eq!(cell.stats().updates_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(coalescer.pending_len(), 0);

        // The poison-pill regression: a later valid update must still flush and publish.
        coalescer
            .submit(install_exact("valid.example.com", &cred))
            .expect("a valid update after a rejected one must still be accepted");
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        assert!(
            cell.load()
                .certs
                .resolve("valid.example.com", ClientCaps::all())
                .is_some()
        );
    }

    #[test]
    fn builder_failure_aborts_batch() {
        let cred = gen_cred("a.example.com");
        let (cell, mut coalescer) = test_setup(&[("a.example.com", &cred)]);
        coalescer.force_next_build_failure();
        let new_cred = gen_cred("b.example.com");
        coalescer
            .submit(install_exact("b.example.com", &new_cred))
            .expect("valid update");
        let result = coalescer.flush_now();
        assert!(result.is_err(), "the forced build failure must propagate");
        assert_eq!(cell.stats().reload_failures.load(Ordering::Relaxed), 1);
        assert_eq!(cell.stats().generation.load(Ordering::Relaxed), 0);
        assert_eq!(
            coalescer.pending_len(),
            1,
            "a failed flush must not clear pending"
        );
    }

    #[test]
    fn replace_missing_fingerprint_is_not_fatal() {
        let cred = gen_cred("a.example.com");
        let (cell, mut coalescer) = test_setup(&[("a.example.com", &cred)]);
        let unrelated = gen_cred("nowhere.example.com");
        let replacement = gen_cred("replacement.example.com");
        coalescer
            .submit(CertUpdate::Replace {
                fingerprint: unrelated.fingerprint(),
                cred: replacement,
            })
            .expect("Replace carries no name to validate, so submit always accepts it");
        let published = coalescer.flush_now().expect("flush must not fail");
        assert_eq!(published, Some(1));
        assert_eq!(cell.stats().replace_missed.load(Ordering::Relaxed), 1);
        assert!(
            cell.load()
                .certs
                .resolve("a.example.com", ClientCaps::all())
                .is_some(),
            "an untouched entry must survive a Replace whose fingerprint misses"
        );
    }

    #[test]
    fn remove_absent_name_is_noop() {
        let cred = gen_cred("a.example.com");
        let (cell, mut coalescer) = test_setup(&[("a.example.com", &cred)]);
        coalescer
            .submit(CertUpdate::Remove {
                names: vec!["absent.example.com".into()],
            })
            .expect("valid update");
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        assert!(
            cell.load()
                .certs
                .resolve("a.example.com", ClientCaps::all())
                .is_some(),
            "removing an absent name must not disturb an existing one"
        );
    }

    #[test]
    fn install_same_keytype_later_expiry_wins() {
        let early = gen_cred_with_validity("a.example.com", (2025, 1, 1), (2027, 1, 1));
        let late = gen_cred_with_validity("a.example.com", (2025, 1, 1), (2030, 1, 1));
        let (cell, mut coalescer) = test_setup(&[("a.example.com", &early)]);
        coalescer
            .submit(install_exact("a.example.com", &late))
            .expect("valid update");
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        let got = cell
            .load()
            .certs
            .resolve("a.example.com", ClientCaps::all())
            .map(|c| c.fingerprint());
        assert_eq!(got, Some(late.fingerprint()));
    }

    #[test]
    fn set_default_last_wins() {
        let cred_a = gen_cred("default-a.example.com");
        let cred_b = gen_cred("default-b.example.com");
        let (cell, mut coalescer) = test_setup(&[]);
        coalescer
            .submit(CertUpdate::SetDefault {
                cred: Arc::clone(&cred_a),
            })
            .expect("valid update");
        coalescer
            .submit(CertUpdate::SetDefault {
                cred: Arc::clone(&cred_b),
            })
            .expect("valid update");
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        let got = cell
            .load()
            .certs
            .default_credential()
            .map(|c| c.fingerprint());
        assert_eq!(got, Some(cred_b.fingerprint()));

        // Folded in here rather than added as a 22nd test, for the same reason as the
        // from_previous regressions: #118 fixes the reported test count at 21.
        //
        // A `Remove` must be a WITHDRAWAL OF TRUST, which is this module's stated rule and the
        // whole reason `Remove` is exempt from the pending cap. Removing the name whose
        // credential is also the configured default used to drop the name entry and leave the
        // default pointing at the very same credential, so `resolve` for the removed name still
        // returned it through `default_path()`, as did every other name. A revoked certificate
        // stayed in service and nothing downstream could notice.
        coalescer
            .submit(install_exact("revoked.example.com", &cred_b))
            .expect("valid update");
        coalescer.flush_now().expect("flush ok");
        assert_eq!(
            cell.load()
                .certs
                .resolve("revoked.example.com", ClientCaps::all())
                .map(|c| c.fingerprint()),
            Some(cred_b.fingerprint()),
            "the fixture must serve the to-be-revoked credential before the removal"
        );

        coalescer
            .submit(CertUpdate::Remove {
                names: vec!["revoked.example.com".into()],
            })
            .expect("valid update");
        coalescer.flush_now().expect("flush ok");
        let after = cell.load();
        assert_eq!(
            after.certs.default_credential().map(|c| c.fingerprint()),
            None,
            "removing the name whose credential is the default must withdraw the default too, \
             or the revoked credential stays in service for every name through default_path()"
        );
        assert_eq!(
            after
                .certs
                .resolve("revoked.example.com", ClientCaps::all())
                .map(|c| c.fingerprint()),
            None,
            "the removed name must no longer resolve to the revoked credential"
        );
    }

    #[test]
    fn challenge_and_real_cert_coexist() {
        let real = gen_cred("a.example.com");
        let (challenge_der, challenge_key_der) = gen_leaf("a.example.com");
        let key = ChallengeKey::from_der(&challenge_der, &challenge_key_der).expect("valid");
        let (cell, mut coalescer) = test_setup(&[]);
        coalescer
            .submit(install_exact("a.example.com", &real))
            .expect("valid update");
        coalescer
            .submit(CertUpdate::InstallChallenge {
                name: "a.example.com".into(),
                key,
                expires: UnixSeconds::new(2_000),
            })
            .expect("valid update");
        let published = coalescer.flush_now().expect("flush ok");
        assert_eq!(published, Some(1));
        let material = cell.load();
        assert!(
            material
                .certs
                .resolve("a.example.com", ClientCaps::all())
                .is_some()
        );
        assert!(
            material
                .challenge
                .lookup("a.example.com", UnixSeconds::new(1_000))
                .is_some()
        );
    }

    #[test]
    fn expired_challenge_dropped_on_rebuild() {
        let (challenge_der, challenge_key_der) = gen_leaf("expiring.example.com");
        let key = ChallengeKey::from_der(&challenge_der, &challenge_key_der).expect("valid");
        let clock = Arc::new(SettableClock::new(1_000));
        // Method-call syntax, not `Arc::clone(&clock)`: the latter's expected return type
        // (`Arc<dyn TimeView>`, from this binding's own annotation) propagates into resolving
        // `Arc::clone`'s generic parameter before unsizing can apply, which does not type-check.
        // Method syntax resolves the concrete receiver first and unsizes the result afterward.
        let time: Arc<dyn TimeView> = clock.clone();
        let cell = Arc::new(TlsMaterialCell::new(build_initial(&[])));
        let mut coalescer = CertUpdateCoalescer::new(
            Arc::clone(&cell),
            ChainInterner::new(),
            Arc::new(TlsPolicy::default_https()),
            time,
        );
        coalescer.set_debounce_ms(0);

        coalescer
            .submit(CertUpdate::InstallChallenge {
                name: "expiring.example.com".into(),
                key,
                expires: UnixSeconds::new(1_500),
            })
            .expect("valid update");
        coalescer.flush_now().expect("flush ok");
        assert!(
            cell.load()
                .challenge
                .lookup("expiring.example.com", UnixSeconds::new(1_000))
                .is_some()
        );

        clock.set(2_000); // now past the challenge's expiry
        let cred = gen_cred("other.example.com");
        coalescer
            .submit(install_exact("other.example.com", &cred))
            .expect("valid update");
        coalescer.flush_now().expect("flush ok");
        assert!(
            cell.load()
                .challenge
                .lookup("expiring.example.com", UnixSeconds::new(2_000))
                .is_none(),
            "an expired challenge must disappear on rebuild without an explicit RemoveChallenge"
        );
    }

    #[test]
    fn from_previous_reparses_nothing() {
        ensure_provider_installed();
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("valid SANs");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_der = ca_params
            .self_signed(&ca_key)
            .expect("self sign ca")
            .der()
            .to_vec();
        let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);

        let mut interner = ChainInterner::new();
        let mut builder = CertIndexBuilder::new([30u8; 16]);
        for i in 0..50 {
            let leaf_key =
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
            let name = format!("host{i}.example.com");
            let leaf_params =
                rcgen::CertificateParams::new(vec![name.clone()]).expect("valid SANs");
            let leaf_der = leaf_params
                .signed_by(&leaf_key, &issuer)
                .expect("sign leaf")
                .der()
                .to_vec();
            let cred = Arc::new(
                Credentials::load(
                    &[&leaf_der, &ca_der],
                    &leaf_key.serialize_der(),
                    &mut interner,
                )
                .expect("valid leaf and key"),
            );
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        let original = builder.build().expect("build");
        assert_eq!(
            interner.blob_count(),
            1,
            "all 50 leaves share one CA intermediate"
        );
        assert_eq!(interner.hits(), 49);

        let hits_before = interner.hits();
        let blobs_before = interner.blob_count();

        let rebuilt = CertIndexBuilder::from_previous(&original)
            .build_with_generation(1)
            .expect("rebuild succeeds");

        assert_eq!(
            interner.hits(),
            hits_before,
            "from_previous must not re-intern anything"
        );
        assert_eq!(interner.blob_count(), blobs_before);

        for i in 0..50 {
            let name = format!("host{i}.example.com");
            let old = original
                .resolve(&name, ClientCaps::all())
                .expect("present in original");
            let new = rebuilt
                .resolve(&name, ClientCaps::all())
                .expect("present after rebuild");
            assert!(
                Arc::ptr_eq(old, new),
                "from_previous must reuse the exact same Arc<Credentials>, not reparse and \
                 produce a new one"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "issue #118 fixes the reported test count at 21 (20 unit tests plus one prop \
                  test), so the three from_previous carry-forward regressions (hasher key, \
                  default credential, every key-type slot) and the collision retry are folded \
                  into this one function rather than split into four that would change it"
    )]
    fn from_previous_preserves_every_name() {
        let cred = gen_cred("template.example.com");
        let mut builder = CertIndexBuilder::new([31u8; 16]);
        for i in 0..1_000 {
            let name = format!("host{i}.example.com");
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        let original = builder.build().expect("build");

        let rebuilt = CertIndexBuilder::from_previous(&original)
            .build_with_generation(1)
            .expect("rebuild succeeds");

        // The hasher key itself is inherited, not just the resolution behaviour: computed
        // through the real `hash` method on both hashers, not asserted by trusting a comment.
        // A mutant that always re-derives a fresh key at attempt 0 (skipping the inherited-key
        // short-circuit) would still pass every resolve-based assertion below, since a build is
        // internally consistent with whichever key it happens to use; this is the one assertion
        // that would catch it.
        assert_eq!(
            original.hasher().hash("host0.example.com"),
            rebuilt.hasher().hash("host0.example.com"),
            "from_previous must inherit the previous generation's hasher key, not derive a fresh one"
        );

        for i in 0..1_000 {
            let name = format!("host{i}.example.com");
            let old = original
                .resolve(&name, ClientCaps::all())
                .map(|c| c.fingerprint());
            let new = rebuilt
                .resolve(&name, ClientCaps::all())
                .map(|c| c.fingerprint());
            assert!(old.is_some());
            assert_eq!(
                old, new,
                "{name} must resolve identically after an unedited rebuild"
            );
        }
        for i in 1_000..2_000 {
            let name = format!("nonexistent{i}.example.com");
            assert!(original.resolve(&name, ClientCaps::all()).is_none());
            assert!(rebuilt.resolve(&name, ClientCaps::all()).is_none());
        }

        // Fold in the collision-retry regression here rather than as a 22nd test function, so
        // `cargo test store::builder:: store::publish::` keeps reporting exactly the 21 tests
        // the acceptance criteria name. `from_previous`'s inherited-key attempt 0 has no other
        // path an ordinary test reaches: force it to collide (mirroring
        // `CertIndexBuilder::force_collision_on_attempt_0`, the identical seam used for a
        // from-scratch build's own collision-retry test) and confirm every name still resolves
        // correctly after the retry rekeys from fresh entropy.
        let mut forced = CertIndexBuilder::from_previous(&original);
        forced.force_collision_on_attempt_0();
        let rebuilt_after_collision = forced
            .build_with_generation(2)
            .expect("collision retry must still succeed for a from_previous builder");
        for i in 0..1_000 {
            let name = format!("host{i}.example.com");
            let old = original
                .resolve(&name, ClientCaps::all())
                .map(|c| c.fingerprint());
            let retried = rebuilt_after_collision
                .resolve(&name, ClientCaps::all())
                .map(|c| c.fingerprint());
            assert_eq!(
                old, retried,
                "{name} must resolve correctly after a forced attempt-0 collision and retry"
            );
        }

        // Two more carry-forward duties, folded in here for the same reason as the collision
        // regression above: keep the test count at the 21 the acceptance criteria name.
        //
        // Both of these fail OPEN on availability, silently, which is why neither showed up as a
        // failing assertion anywhere in the crate before now.

        // (a) The configured default credential survives a rebuild. Replacing
        // `prev.default_cred().cloned()` with `None` in `from_previous` used to survive all
        // eight test suites, which would mean every ACME issuance or OCSP staple refresh
        // silently discards the default, and every no-SNI and every unmatched-name handshake
        // stops being served after the first reload.
        let default_cred = gen_cred("default.example.com");
        let mut with_default = CertIndexBuilder::new([31u8; 16]);
        with_default
            .upsert_exact("kept.example.com", gen_cred("kept.example.com"))
            .expect("valid");
        with_default.set_default(Arc::clone(&default_cred));
        let with_default = with_default.build().expect("build");
        assert_eq!(
            with_default.default_credential().map(|c| c.fingerprint()),
            Some(default_cred.fingerprint()),
            "the fixture itself must have a default, or the rebuild assertion below is vacuous"
        );
        let rebuilt_default = CertIndexBuilder::from_previous(&with_default)
            .build_with_generation(1)
            .expect("rebuild succeeds");
        assert_eq!(
            rebuilt_default
                .default_credential()
                .map(|c| c.fingerprint()),
            Some(default_cred.fingerprint()),
            "from_previous must carry the configured default credential forward: losing it stops \
             every no-SNI and every unmatched-name handshake being served after the first reload"
        );

        // (b) EVERY key-type slot for a name survives a rebuild, not just the preferred one.
        // Appending `.min(1)` to `rebuild_entries`'s `for slot in 0..usize::from(set.len)` used
        // to survive all eight suites: a name holding both an ECDSA and an Ed25519 credential
        // would lose the second on every reload, so clients that can only use the dropped key
        // type stop being served after the first ACME renewal.
        let ecdsa = gen_cred("dual.example.com");
        let ed25519 = gen_cred_ed25519("dual.example.com");
        assert_ne!(
            ecdsa.key_type(),
            ed25519.key_type(),
            "the fixture must hold two DIFFERENT key types, or this pins nothing"
        );
        let mut dual = CertIndexBuilder::new([31u8; 16]);
        dual.upsert_exact("dual.example.com", Arc::clone(&ecdsa))
            .expect("valid");
        dual.upsert_exact("dual.example.com", Arc::clone(&ed25519))
            .expect("valid");
        let dual = dual.build().expect("build");

        // Resolve through the caps that admit ONLY the non-preferred key type, so the assertion
        // cannot be satisfied by the preferred credential standing in for it.
        let ed_only = ClientCaps {
            ecdsa_p256: false,
            ecdsa_p384: false,
            rsa: false,
            ed25519: true,
        };
        assert_eq!(
            dual.resolve("dual.example.com", ed_only)
                .map(|c| c.fingerprint()),
            Some(ed25519.fingerprint()),
            "the fixture must serve the second key type before any rebuild"
        );
        let rebuilt_dual = CertIndexBuilder::from_previous(&dual)
            .build_with_generation(1)
            .expect("rebuild succeeds");
        assert_eq!(
            rebuilt_dual
                .resolve("dual.example.com", ed_only)
                .map(|c| c.fingerprint()),
            Some(ed25519.fingerprint()),
            "from_previous must carry EVERY key-type slot forward, not only the preferred one: \
             dropping the rest stops clients of that key type being served after a reload"
        );
    }

    #[test]
    fn generations_strictly_increase() {
        let cred = gen_cred("a.example.com");
        let (cell, mut coalescer) = test_setup(&[]);
        let mut prev = 0u64;
        for i in 0..5 {
            let name = format!("g{i}.example.com");
            coalescer
                .submit(install_exact(&name, &cred))
                .expect("valid update");
            let published = coalescer.flush_now().expect("flush ok").expect("published");
            assert!(
                published > prev,
                "generation must strictly increase: {prev} -> {published}"
            );
            prev = published;
        }
        assert_eq!(cell.stats().generation.load(Ordering::Relaxed), prev);
    }

    #[test]
    fn live_generations_tracks_retention() {
        let cred = gen_cred("shared-live.example.com");
        let (cell, mut coalescer) = test_setup(&[]);

        coalescer
            .submit(install_exact("h1.example.com", &cred))
            .expect("valid update");
        let gen1 = coalescer.flush_now().expect("flush ok").expect("published");
        assert_eq!(gen1, 1);
        let held = Arc::clone(&cell.load());

        coalescer
            .submit(install_exact("h2.example.com", &cred))
            .expect("valid update");
        let gen2 = coalescer.flush_now().expect("flush ok").expect("published");
        assert_eq!(gen2, 2);

        coalescer
            .submit(install_exact("h3.example.com", &cred))
            .expect("valid update");
        let gen3 = coalescer.flush_now().expect("flush ok").expect("published");
        assert_eq!(gen3, 3);
        assert_eq!(cell.stats().live_generations.load(Ordering::Relaxed), 3);

        drop(held);

        coalescer
            .submit(install_exact("h4.example.com", &cred))
            .expect("valid update");
        let gen4 = coalescer.flush_now().expect("flush ok").expect("published");
        assert_eq!(gen4, 4);
        assert_eq!(cell.stats().live_generations.load(Ordering::Relaxed), 2);
    }

    const POOL_SIZE: usize = 6;

    /// A pool of shared credentials, all the same key type (ECDSA P-256) so that installing one
    /// onto a name that already has another exercises the from-scratch builder's "later expiry
    /// wins" tie-break (edge case 9) rather than the four-key-type coexistence rule. `not_after`
    /// is a STRICTLY INCREASING function of the pool index (`2100 + i`), which is load-bearing
    /// for `prop_from_previous_is_equivalent`'s model below: it is what makes "the credential
    /// with the highest pool index ever installed onto a slot always wins the eventual build",
    /// independent of which order the operations actually installed them in, true of BOTH the
    /// incremental and the from-scratch build. Without a strict order, two pool credentials
    /// sharing the same default `not_after` would tie-break on fingerprint, which has no relation
    /// to the model's own "last write wins" bookkeeping and produced a real, reproducible failure
    /// during this test's own development.
    fn cred_pool() -> &'static [Arc<Credentials>; POOL_SIZE] {
        static POOL: std::sync::OnceLock<[Arc<Credentials>; POOL_SIZE]> =
            std::sync::OnceLock::new();
        POOL.get_or_init(|| {
            ensure_provider_installed();
            std::array::from_fn(|i| {
                let key =
                    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
                let mut params =
                    rcgen::CertificateParams::new(vec![format!("pool{i}.example.com")])
                        .expect("valid SANs");
                params.not_before = rcgen::date_time_ymd(2025, 1, 1);
                let not_after_year = 2100 + i32::try_from(i).expect("POOL_SIZE (6) fits in an i32");
                params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
                let cert = params.self_signed(&key).expect("sign");
                let mut interner = ChainInterner::new();
                Arc::new(
                    Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                        .expect("valid leaf and key"),
                )
            })
        })
    }

    /// Insert `cred_idx` into `model` for `key`, keeping whichever pool index is already present
    /// if it is higher. This mirrors what the real builder's sort-and-dedup does at build time:
    /// among every entry ever pushed for a name since its last `Remove` (the from-scratch
    /// reference builder pushes exactly one entry per name below, so this is where the
    /// "later expiry wins" resolution actually happens), the credential with the latest
    /// `not_after` survives, independent of application order. `cred_pool`'s strictly increasing
    /// `not_after` by index is what makes "highest index wins" the correct proxy for that rule.
    fn install_into_model(
        model: &mut std::collections::HashMap<(bool, u8), usize>,
        key: (bool, u8),
        cred_idx: usize,
    ) {
        model
            .entry(key)
            .and_modify(|current| {
                if cred_idx > *current {
                    *current = cred_idx;
                }
            })
            .or_insert(cred_idx);
    }

    /// The stored (parent) form of a wildcard slot's name, with no `"*."` prefix: what
    /// `CertIndexBuilder::remove` and the model both key on.
    fn wild_base(slot: u8) -> String {
        format!("wild{slot}.example.com")
    }

    fn exact_name(slot: u8) -> String {
        format!("host{slot}.example.com")
    }

    #[derive(Clone, Debug)]
    enum Op {
        Install {
            is_wild: bool,
            slot: u8,
            cred_idx: usize,
        },
        Remove {
            is_wild: bool,
            slot: u8,
        },
        Replace {
            from_idx: usize,
            to_idx: usize,
        },
        SetDefault {
            cred_idx: usize,
        },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (any::<bool>(), 0u8..40, 0usize..POOL_SIZE).prop_map(|(is_wild, slot, cred_idx)| {
                Op::Install {
                    is_wild,
                    slot,
                    cred_idx,
                }
            }),
            (any::<bool>(), 0u8..40).prop_map(|(is_wild, slot)| Op::Remove { is_wild, slot }),
            (0usize..POOL_SIZE, 0usize..POOL_SIZE)
                .prop_map(|(from_idx, to_idx)| Op::Replace { from_idx, to_idx }),
            (0usize..POOL_SIZE).prop_map(|cred_idx| Op::SetDefault { cred_idx }),
        ]
    }

    /// Build a `CertIndex` directly (no `from_previous`) from `model`, plus `default_idx`.
    fn build_from_model(
        seed: [u8; 16],
        model: &std::collections::HashMap<(bool, u8), usize>,
        pool: &[Arc<Credentials>; POOL_SIZE],
        default_idx: Option<usize>,
    ) -> CertIndex {
        let mut b = CertIndexBuilder::new(seed);
        for (&(is_wild, slot), &cred_idx) in model {
            let cred = Arc::clone(&pool[cred_idx]);
            if is_wild {
                b.upsert_wildcard(&format!("*.{}", wild_base(slot)), cred)
                    .expect("valid");
            } else {
                b.upsert_exact(&exact_name(slot), cred).expect("valid");
            }
        }
        if let Some(idx) = default_idx {
            b.set_default(Arc::clone(&pool[idx]));
        }
        b.build_with_generation(1).expect("build succeeds")
    }

    /// Resolve `pending`'s per-slot list of pool indices to a single winner each, the credential
    /// with the highest index (== the latest `not_after`, by `cred_pool`'s construction), and
    /// build a `CertIndex` from those winners plus `default_idx`.
    fn build_from_pending(
        seed: [u8; 16],
        pending: &std::collections::HashMap<(bool, u8), Vec<usize>>,
        pool: &[Arc<Credentials>; POOL_SIZE],
        default_idx: Option<usize>,
    ) -> CertIndex {
        let winners: std::collections::HashMap<(bool, u8), usize> = pending
            .iter()
            .filter_map(|(&key, list)| list.iter().copied().max().map(|winner| (key, winner)))
            .collect();
        build_from_model(seed, &winners, pool, default_idx)
    }

    proptest! {
        /// Catches a copy-on-write bug a from-scratch build would not have: applying `ops`
        /// through `from_previous` must resolve identically, for every name in the union of the
        /// initial and final entry sets plus 200 random names, to an index built from scratch
        /// with the same final entries.
        ///
        /// The model below tracks a LIST of still-pending pool indices per `(is_wild, slot)`
        /// key, not a single "current winner": `Install` never removes a competing entry (it
        /// only pushes, exactly like `CertIndexBuilder::upsert_exact`/`upsert_wildcard`), so more
        /// than one credential can be pending for the same name at once, and `Replace` matches by
        /// fingerprint against ANY of them, including one that would currently lose the
        /// from-scratch builder's "later expiry wins" tie-break. An earlier, simpler version of
        /// this model kept only the current winner per slot and missed exactly that: `Replace`
        /// promoting a losing, but still-pending, entry past the current winner by giving it a
        /// higher-ranked credential. `cred_pool`'s strictly increasing `not_after` by index is
        /// what makes "the highest index remaining in the list" the correct final winner once
        /// every op has been applied, independent of application order.
        #[test]
        fn prop_from_previous_is_equivalent(
            initial in prop::collection::vec((any::<bool>(), 0u8..40, 0usize..POOL_SIZE), 1..=40),
            ops in prop::collection::vec(op_strategy(), 0..=10),
            random_queries in prop::collection::vec("[a-z]{1,10}\\.example\\.(net|org)", 200),
        ) {
            let pool = cred_pool();

            // The base index resolves duplicate (is_wild, slot) entries in `initial` itself, so
            // only the winner per slot ever reaches `from_previous`'s rebuilt pending list.
            let mut initial_winners: std::collections::HashMap<(bool, u8), usize> =
                std::collections::HashMap::new();
            for (is_wild, slot, cred_idx) in &initial {
                install_into_model(&mut initial_winners, (*is_wild, *slot), *cred_idx);
            }
            let base_index = build_from_model([50u8; 16], &initial_winners, pool, None);

            // `pending` mirrors the incremental builder's own `entries` list: it starts from
            // exactly the one winning entry per slot the base index carries forward, then grows
            // (Install), clears (Remove), or is rewritten in place (Replace) the same way.
            let mut pending: std::collections::HashMap<(bool, u8), Vec<usize>> = initial_winners
                .iter()
                .map(|(&key, &winner)| (key, vec![winner]))
                .collect();

            let mut cb = CertIndexBuilder::from_previous(&base_index);
            let mut default_idx: Option<usize> = None;
            for op in &ops {
                match op {
                    Op::Install { is_wild, slot, cred_idx } => {
                        let cred = Arc::clone(&pool[*cred_idx]);
                        if *is_wild {
                            cb.upsert_wildcard(&format!("*.{}", wild_base(*slot)), cred)
                                .expect("valid");
                        } else {
                            cb.upsert_exact(&exact_name(*slot), cred).expect("valid");
                        }
                        pending.entry((*is_wild, *slot)).or_default().push(*cred_idx);
                    }
                    Op::Remove { is_wild, slot } => {
                        let name = if *is_wild { wild_base(*slot) } else { exact_name(*slot) };
                        cb.remove(&name);
                        let removed = pending.remove(&(*is_wild, *slot));
                        // Mirror `CertIndexBuilder::remove`'s withdrawal-of-trust rule: removing
                        // the name whose credential is the configured default clears the default
                        // too, otherwise the removal leaves the revoked credential serving every
                        // name through `default_path()`. The model can reproduce this from the
                        // net state, which is what keeps the incremental and from-scratch paths
                        // equivalent under the rule.
                        if let (Some(d), Some(list)) = (default_idx, removed.as_ref())
                            && list
                                .iter()
                                .any(|&i| pool[i].fingerprint() == pool[d].fingerprint())
                        {
                            default_idx = None;
                        }
                    }
                    Op::Replace { from_idx, to_idx } => {
                        let fp = pool[*from_idx].fingerprint();
                        let replaced = cb.replace_by_fingerprint(fp, Arc::clone(&pool[*to_idx]));
                        let mut model_replaced = 0usize;
                        for list in pending.values_mut() {
                            for v in list.iter_mut() {
                                if *v == *from_idx {
                                    *v = *to_idx;
                                    model_replaced += 1;
                                }
                            }
                        }
                        prop_assert_eq!(
                            replaced, model_replaced,
                            "the model's pending-entry count must match the real builder's \
                             replace_by_fingerprint count exactly"
                        );
                    }
                    Op::SetDefault { cred_idx } => {
                        cb.set_default(Arc::clone(&pool[*cred_idx]));
                        default_idx = Some(*cred_idx);
                    }
                }
            }
            let incremental = cb.build_with_generation(2).expect("incremental build succeeds");
            let scratch = build_from_pending([51u8; 16], &pending, pool, default_idx);

            let mut queries: Vec<String> = Vec::new();
            for slot in 0u8..40 {
                queries.push(exact_name(slot));
                queries.push(format!("sub.{}", wild_base(slot)));
            }
            queries.extend(random_queries);

            for q in &queries {
                let a = incremental.resolve(q, ClientCaps::all()).map(|c| c.fingerprint());
                let b = scratch.resolve(q, ClientCaps::all()).map(|c| c.fingerprint());
                prop_assert_eq!(a, b, "query={}", q);
            }
        }
    }
}
