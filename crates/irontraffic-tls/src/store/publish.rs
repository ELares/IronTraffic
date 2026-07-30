// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wait-free publication of TLS material: the certificate index, the TLS-ALPN-01 challenge
//! map, and the resolver built over both, published together as one immutable value.
//!
//! A reload builds a complete new [`CertIndex`] and [`ChallengeCerts`] off the hot path (see
//! `store::builder`) and hands the result here as a [`TlsMaterial`]. [`TlsMaterialCell::load`]
//! is a wait-free read: the handshake path takes the guard, clones the one `Arc` it needs (the
//! resolver), and drops the guard immediately, so no handshake ever blocks on a reload and no
//! in-flight connection is ever dropped mid-swap. [`TlsMaterialCell::publish`] is a single
//! atomic store; the previous generation's `Arc`s are freed once the last reader (a connection
//! or task still holding one) releases them.
//!
//! **`ArcSwap`, the third and final allowlisted declaration site.** The workspace rule
//! (decision-ledger entry 42, amended by `cert-index-incremental-rebuild-and-publish` (#118)) is
//! that `ArcSwap` is declared at exactly three sites in the whole tree, and that
//! `ArcSwap::store` appears in exactly one function per cell. The other two are the
//! configuration cell and `UpstreamTable`'s per-cluster cell. This cell earns the exception the
//! other two already have because it is read once per accepted connection, before any request
//! exists, so it cannot tear the route-to-filter relationship the single-configuration-snapshot
//! rule protects; and because TLS material changes on ACME issuance and OCSP staple refresh,
//! neither of which is a configuration change and neither of which should force a configuration
//! generation. `ArcSwap::store` on this cell is called from exactly one function,
//! [`TlsMaterialCell::publish`], mirroring the single-store-site rule the other two cells
//! already follow. `scripts/allowlist-arcswap-store.txt` allowlists this whole file for exactly
//! that reason: the field declaration and the one store call are both here, by construction.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{CertIndex, ChallengeCerts, IronResolver};
use crate::listener::ListenerTls;

/// Everything the TLS accept path needs, as one immutable value.
pub struct TlsMaterial {
    /// The certificate index.
    pub certs: Arc<CertIndex>,
    /// The TLS-ALPN-01 challenge certificates.
    pub challenge: Arc<ChallengeCerts>,
    /// The resolver built over `certs` and `challenge`.
    pub resolver: Arc<IronResolver>,
    /// Compiled per-listener TLS configuration, indexed by listener ordinal.
    pub listeners: Arc<[Arc<ListenerTls>]>,
    /// Monotonic generation number.
    pub generation: u64,
}

/// Counters for the publication path.
#[derive(Debug, Default)]
pub struct PublishStats {
    /// `tls_material_publishes_total`
    pub publishes: AtomicU64,
    /// `tls_material_reload_failures_total`
    pub reload_failures: AtomicU64,
    /// `tls_material_updates_submitted_total`
    pub updates_submitted: AtomicU64,
    /// `tls_material_updates_dropped_total`
    pub updates_dropped: AtomicU64,
    /// `tls_material_updates_rejected_total`: updates refused by `submit` because a name failed
    /// validation. Never silently zero on a misconfiguration.
    pub updates_rejected: AtomicU64,
    /// `tls_material_updates_over_cap_total`: times the pending list grew past `max_pending`
    /// because every pending update was a removal and removals are never dropped.
    pub updates_over_cap: AtomicU64,
    /// `tls_material_replace_missed_total`
    pub replace_missed: AtomicU64,
    /// `tls_material_generation`
    pub generation: AtomicU64,
    /// `tls_material_live_generations`: published generations still reachable, that is still held
    /// by at least one connection or task. Maintained in `publish` from a pruned `Vec<Weak<_>>`.
    pub live_generations: AtomicU64,
    /// `tls_ocsp_must_staple_refused_total`: an `Install` was refused because the credential
    /// carries `id-pe-tlsfeature` with `status_request` and had no staple attached.
    pub must_staple_refused: AtomicU64,
}

/// The publication cell. This is the third and final allowlisted `ArcSwap` declaration site in
/// the workspace; see the module docs above for the justification.
pub struct TlsMaterialCell {
    inner: arc_swap::ArcSwap<TlsMaterial>,
    stats: PublishStats,
}

impl TlsMaterialCell {
    /// A cell holding initial material.
    #[must_use]
    pub fn new(initial: Arc<TlsMaterial>) -> Self {
        Self {
            inner: arc_swap::ArcSwap::new(initial),
            stats: PublishStats::default(),
        }
    }

    /// Wait-free read. Called once per accepted connection.
    ///
    /// Returns a guard that dereferences to the material. Do NOT hold it across an await and do
    /// NOT call `load_full`.
    #[must_use]
    pub fn load(&self) -> arc_swap::Guard<Arc<TlsMaterial>> {
        self.inner.load()
    }

    /// Publish new material. The ONLY function in the workspace that stores into this cell.
    ///
    /// Exactly four steps, in this order: read `material.generation` (before anything below
    /// moves `material`), swap it into the publication cell with a single atomic store, bump the
    /// publish counter, then set the generation gauge to the value read in the first step.
    /// `generation` is a gauge, not a counter, so the last step is a plain store, never a
    /// `fetch_add`.
    pub fn publish(&self, material: Arc<TlsMaterial>) {
        let g = material.generation;
        self.inner.store(material);
        self.stats.publishes.fetch_add(1, Ordering::Relaxed);
        self.stats.generation.store(g, Ordering::Relaxed);
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &PublishStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::{TlsMaterial, TlsMaterialCell};
    use crate::policy::TlsPolicy;
    use crate::store::{
        CertIndexBuilder, CertUpdate, CertUpdateCoalescer, ChainInterner, ChallengeCerts,
        Credentials, IronResolver,
    };
    use crate::time::UnixSeconds;

    fn ensure_provider_installed() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    /// A `TimeView` that never reads a clock.
    struct FixedClock(UnixSeconds);
    impl crate::store::TimeView for FixedClock {
        fn unix_seconds(&self) -> UnixSeconds {
            self.0
        }
    }

    fn gen_cred(san: &str) -> Arc<Credentials> {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        let cert = params.self_signed(&key).expect("sign");
        let mut interner = ChainInterner::new();
        Arc::new(
            Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                .expect("valid leaf and key"),
        )
    }

    fn material_with(cred: Arc<Credentials>, generation: u64) -> Arc<TlsMaterial> {
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", cred)
            .expect("valid");
        let certs = Arc::new(
            certs_builder
                .build_with_generation(generation)
                .expect("build"),
        );
        let challenge = Arc::new(ChallengeCerts::empty([9u8; 16]));
        let policy = Arc::new(TlsPolicy::default_https());
        let time = Arc::new(FixedClock(UnixSeconds::new(1_000)));
        let resolver = Arc::new(IronResolver::new(
            Arc::clone(&certs),
            Arc::clone(&challenge),
            policy,
            time,
        ));
        Arc::new(TlsMaterial {
            certs,
            challenge,
            resolver,
            listeners: Arc::from(Vec::new()),
            generation,
        })
    }

    /// Also listed as an acceptance criterion; the test lives here because it exercises
    /// `TlsMaterialCell` directly (the cell's `generation()` before and after the failed
    /// flush), even though the failure itself is forced inside the coalescer's build step.
    ///
    /// The forced failure goes through the real build path (`CertIndexBuilder::set_max_groups_for_test`
    /// via `CertUpdateCoalescer::force_next_build_failure`), not a hand-asserted `Err(..)`: this is
    /// what proves `flush_now` actually aborts on a real builder error rather than merely
    /// returning some error value the test constructed itself.
    #[test]
    fn failed_build_leaves_generation() {
        let cred = gen_cred("a.example.com");
        let initial = material_with(Arc::clone(&cred), 0);
        let cell = Arc::new(TlsMaterialCell::new(initial));
        let mut coalescer = CertUpdateCoalescer::new(
            Arc::clone(&cell),
            ChainInterner::new(),
            Arc::new(TlsPolicy::default_https()),
            Arc::new(FixedClock(UnixSeconds::new(1_000))),
        );
        coalescer.set_debounce_ms(0);
        coalescer.force_next_build_failure();

        let new_cred = gen_cred("b.example.com");
        coalescer
            .submit(CertUpdate::Install {
                exact: vec!["b.example.com".into()],
                wildcard: vec![],
                cred: new_cred,
            })
            .expect("a well-formed Install must be accepted by submit");

        let before = cell.load().generation;
        let result = coalescer.flush_now();
        assert!(result.is_err(), "the forced build failure must propagate");
        assert_eq!(cell.load().generation, before);
        assert_eq!(cell.stats().reload_failures.load(Ordering::Relaxed), 1);
        assert_eq!(cell.stats().publishes.load(Ordering::Relaxed), 0);
        assert_eq!(
            coalescer.pending_len(),
            1,
            "a failed flush must not clear pending"
        );
    }
}
