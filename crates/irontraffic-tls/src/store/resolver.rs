// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! [`IronResolver`]: the one implementation of rustls's server certificate resolver.
//!
//! rustls 0.23's `ResolvesServerCert::resolve` is synchronous by design, called once per
//! handshake before the server can send its `Certificate` message. [`IronResolver::resolve`]
//! (the trait impl at the bottom of this file) is therefore exactly three lines and contains no
//! branching of its own: rustls's `ClientHello` has no public constructor, so every decision this
//! resolver makes lives in free functions and one method that take plain values instead, and
//! those plain-value functions are what every test in this module and in
//! `tests/handshake_resolver.rs` actually exercises. Putting logic inside the trait method itself
//! would make that logic untestable without a real handshake.
//!
//! **The ALPN gate is exact, not "contains".** [`alpn_verdict`] takes the challenge branch if and
//! only if the `ClientHello`'s ALPN list has exactly one entry and that entry is `acme-tls/1`.
//! `acme-tls/1` offered alongside anything else is refused outright rather than interpreted,
//! because treating "contains acme-tls/1" as the gate would let a peer ask for a challenge
//! certificate for a name whose challenge happens to be live and receive a self-signed
//! certificate as a side effect, which is at best a confusing error and at worst a fingerprinting
//! oracle for which names are mid-issuance. The scan inspects at most three entries, whatever the
//! list length, so a 100-entry ALPN list costs the same as a one-entry list.
//!
//! **The challenge branch never falls through.** A missing or expired challenge is a failed
//! handshake (`None`), never a credential drawn from [`crate::store::CertIndex`]; the reverse
//! (the normal branch reading [`crate::store::ChallengeCerts`]) never happens either, because the
//! two structures have two separate lookup functions and [`resolve_parts`] below calls exactly
//! one of them per branch. This crate's other half of the isolation contract, that a production
//! listener never lists `acme-tls/1` in its own ALPN set so the challenge branch is never even
//! reachable outside a dedicated challenge `ServerConfig`, is enforced by
//! `tls-protocol-cipher-group-alpn-policy` (#116) and wired up by
//! `sni-server-config-selection` (#119); this resolver cannot see or change what ALPN protocol a
//! connection actually negotiated.
//!
//! **Key-type forcing.** With `TlsPolicy::require_ecdsa_capable_clients` set, a client that
//! advertises no ECDSA signature scheme is refused for a name that has an ECDSA credential,
//! rather than silently downgraded to that name's RSA credential: RSA signing is measurably more
//! expensive per handshake, so a client that can be forced onto it for every connection is a
//! resource-exhaustion lever. A name that only ever had an RSA credential is unaffected: refusing
//! there would be a self-inflicted outage with no client actually capable of doing better.
//!
//! Every counter here is a relaxed, lossy `AtomicU64`; `resolve` takes `&self` and performs no
//! I/O, no lock, and no heap allocation on any path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::policy::TlsPolicy;
use crate::store::{CertIndex, ChallengeCerts, ClientCaps, KeyType};
use crate::time::UnixSeconds;

/// The single clock read this resolver needs: whole seconds since the Unix epoch, coarse.
///
/// Implemented over `irontraffic_time::TimeSource` by the caller so that this crate does not
/// depend on a specific clock API and so tests can move time. The implementation must be a
/// cached read, not a syscall: it is called at most once per handshake and only on the challenge
/// path.
pub trait TimeView: Send + Sync + 'static {
    /// Current wall-clock time, whole seconds.
    fn unix_seconds(&self) -> UnixSeconds;
}

/// Counters for the resolver. Monotone, relaxed, lossy across a task migration.
#[derive(Debug, Default)]
pub struct ResolverStats {
    /// `tls_resolver_challenge_hit_total`
    pub challenge_hits: AtomicU64,
    /// `tls_resolver_challenge_miss_total`
    pub challenge_misses: AtomicU64,
    /// `tls_resolver_alpn_acme_refused_total`: `acme-tls/1` offered alongside other protocols.
    pub alpn_acme_refused: AtomicU64,
    /// `tls_resolver_no_sni_total`
    pub no_sni: AtomicU64,
    /// `tls_resolver_ecdsa_required_refused_total`
    pub ecdsa_required_refused: AtomicU64,
    /// `tls_handshake_signatures_total{key_type}` is derived from this. Indexed by the
    /// [`KeyType`] discriminant, which is 1 through 4; slot 0 is never written and exists only so
    /// the discriminant can be used as the index directly.
    pub selected_by_key_type: [AtomicU64; 5],
}

/// The one server certificate resolver. Holds immutable snapshots; a new configuration
/// generation builds a new resolver rather than mutating this one.
pub struct IronResolver {
    certs: Arc<CertIndex>,
    challenge: Arc<ChallengeCerts>,
    policy: Arc<TlsPolicy>,
    now: Arc<dyn TimeView>,
    stats: ResolverStats,
}

/// Hand-written rather than derived: `rustls::server::ResolvesServerCert` requires `Debug`, but
/// neither `CertIndex` nor `ChallengeCerts` implements it (both hold certificate chains and, for
/// `ChallengeCerts`, no data worth printing beyond a generation number), and `Arc<dyn TimeView>`
/// cannot derive it either. This prints the two generation numbers and the policy and stats
/// instead, which is what an operator actually wants from a `{:?}` on this type, and
/// `finish_non_exhaustive` marks the rest as deliberately omitted rather than silently empty.
impl core::fmt::Debug for IronResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IronResolver")
            .field("certs_generation", &self.certs.generation())
            .field("challenge_generation", &self.challenge.generation())
            .field("policy", &self.policy)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// What the ALPN list says about which branch [`IronResolver::resolve_parts`] should take.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum AlpnVerdict {
    /// Take the normal certificate path.
    Normal,
    /// The list was exactly `["acme-tls/1"]`: take the challenge path.
    Challenge,
    /// `acme-tls/1` appeared alongside another protocol: refuse the handshake.
    RefuseAcmeMixed,
}

/// Decide the branch from the ALPN iterator, inspecting at most three entries. `None` means the
/// client sent no ALPN extension at all, which is different from an ALPN extension with an empty
/// list; both take the normal branch, but only by falling through this function's first two
/// early returns rather than being conflated into one case.
pub(crate) fn alpn_verdict<'a, I: Iterator<Item = &'a [u8]>>(alpn: Option<I>) -> AlpnVerdict {
    const ACME: &[u8] = b"acme-tls/1";
    let Some(mut it) = alpn else {
        // No ALPN extension at all.
        return AlpnVerdict::Normal;
    };
    let Some(first) = it.next() else {
        // An ALPN extension with no entries. Not "contains acme-tls/1".
        return AlpnVerdict::Normal;
    };
    let Some(second) = it.next() else {
        // Exactly one entry.
        return if first == ACME {
            AlpnVerdict::Challenge
        } else {
            AlpnVerdict::Normal
        };
    };
    let third = it.next();
    if first == ACME || second == ACME || third == Some(ACME) {
        AlpnVerdict::RefuseAcmeMixed
    } else {
        AlpnVerdict::Normal
    }
}

/// Fold the client's advertised signature schemes into four bools, stopping after 64 schemes. An
/// empty or absent list, or a list of schemes we do not serve any credential for (SHA-1 variants,
/// Ed448, ML-DSA, or anything rustls itself reports as `Unknown`), yields all-false caps.
pub(crate) fn caps_from_schemes(schemes: &[rustls::SignatureScheme]) -> ClientCaps {
    let mut caps = ClientCaps::default();
    for scheme in schemes.iter().take(64) {
        match *scheme {
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => caps.ecdsa_p256 = true,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => caps.ecdsa_p384 = true,
            rustls::SignatureScheme::RSA_PSS_SHA256
            | rustls::SignatureScheme::RSA_PSS_SHA384
            | rustls::SignatureScheme::RSA_PSS_SHA512
            | rustls::SignatureScheme::RSA_PKCS1_SHA256
            | rustls::SignatureScheme::RSA_PKCS1_SHA384
            | rustls::SignatureScheme::RSA_PKCS1_SHA512 => caps.rsa = true,
            rustls::SignatureScheme::ED25519 => caps.ed25519 = true,
            _ => {}
        }
    }
    caps
}

impl IronResolver {
    /// Build a resolver over immutable snapshots.
    #[must_use]
    pub fn new(
        certs: Arc<CertIndex>,
        challenge: Arc<ChallengeCerts>,
        policy: Arc<TlsPolicy>,
        now: Arc<dyn TimeView>,
    ) -> Self {
        Self {
            certs,
            challenge,
            policy,
            now,
            stats: ResolverStats::default(),
        }
    }

    /// The certificate index this resolver reads.
    #[must_use]
    pub fn certs(&self) -> &Arc<CertIndex> {
        &self.certs
    }

    /// The challenge map this resolver reads.
    #[must_use]
    pub fn challenge(&self) -> &Arc<ChallengeCerts> {
        &self.challenge
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &ResolverStats {
        &self.stats
    }

    /// The whole decision, over plain values. This is what the unit tests call, because
    /// `rustls::server::ClientHello` has no public constructor.
    pub(crate) fn resolve_parts(
        &self,
        verdict: AlpnVerdict,
        sni: Option<&str>,
        caps: ClientCaps,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        match verdict {
            AlpnVerdict::RefuseAcmeMixed => {
                self.stats.alpn_acme_refused.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            AlpnVerdict::Challenge => {
                let Some(sni) = sni else {
                    self.stats.challenge_misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                return if let Some(key) = self.challenge.lookup(sni, self.now.unix_seconds()) {
                    self.stats.challenge_hits.fetch_add(1, Ordering::Relaxed);
                    Some(Arc::clone(key))
                } else {
                    self.stats.challenge_misses.fetch_add(1, Ordering::Relaxed);
                    None
                };
            }
            AlpnVerdict::Normal => {}
        }

        let cred = match sni {
            None => {
                self.stats.no_sni.fetch_add(1, Ordering::Relaxed);
                self.certs.default_credential()?
            }
            Some(sni) => {
                let cred = self.certs.resolve(sni, caps)?;
                if self.policy.require_ecdsa_capable_clients()
                    && !caps.ecdsa_p256
                    && !caps.ecdsa_p384
                    && cred.key_type() == KeyType::Rsa
                    && self.certs.name_has_ecdsa(sni)
                {
                    self.stats
                        .ecdsa_required_refused
                        .fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                cred
            }
        };

        // KeyType is #[repr(u8)] with discriminants 1..=4, which is exactly the populated range
        // of the 5-slot selected_by_key_type array (slot 0 is deliberately never written); `.get`
        // is used rather than indexing so this stays panic-free even if that invariant were ever
        // violated, without needing a clippy::indexing_slicing allow.
        let key_type_idx = cred.key_type() as usize;
        if let Some(counter) = self.stats.selected_by_key_type.get(key_type_idx) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Some(Arc::clone(cred.certified()))
    }
}

impl rustls::server::ResolvesServerCert for IronResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let verdict = alpn_verdict(hello.alpn());
        let caps = caps_from_schemes(hello.signature_schemes());
        self.resolve_parts(verdict, hello.server_name(), caps)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use std::sync::{Arc, Once, atomic::Ordering};

    use super::{AlpnVerdict, IronResolver, alpn_verdict, caps_from_schemes};
    use crate::policy::{TlsPolicy, TlsPolicyConfig, TlsProfile};
    use crate::store::{
        CertIndexBuilder, ChallengeCerts, ChallengeCertsBuilder, ChallengeKey, ClientCaps,
        Credentials,
    };
    use crate::time::UnixSeconds;

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    fn gen_leaf(alg: &'static rcgen::SignatureAlgorithm, san: &str) -> (Vec<u8>, Vec<u8>) {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(alg).expect("keygen");
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        let cert = params.self_signed(&key).expect("sign");
        (cert.der().to_vec(), key.serialize_der())
    }

    fn gen_cred(alg: &'static rcgen::SignatureAlgorithm, san: &str) -> Arc<Credentials> {
        let (leaf, key) = gen_leaf(alg, san);
        let mut interner = crate::store::ChainInterner::new();
        Arc::new(Credentials::load(&[&leaf], &key, &mut interner).expect("valid leaf and key"))
    }

    fn cred_ecdsa_p256(san: &str) -> Arc<Credentials> {
        gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, san)
    }

    fn cred_rsa(san: &str) -> Arc<Credentials> {
        gen_cred(&rcgen::PKCS_RSA_SHA256, san)
    }

    /// A `TimeView` that never reads a clock, for deterministic expiry tests.
    struct FixedClock(UnixSeconds);
    impl super::TimeView for FixedClock {
        fn unix_seconds(&self) -> UnixSeconds {
            self.0
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test fixture builder taking every IronResolver dependency explicitly is \
                  clearer here than a partial-defaults builder type for six call sites"
    )]
    fn test_resolver(
        certs: crate::store::CertIndex,
        challenge: ChallengeCerts,
        require_ecdsa: bool,
        now: UnixSeconds,
    ) -> IronResolver {
        let cfg = TlsPolicyConfig {
            profile: TlsProfile::Intermediate,
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            post_quantum: crate::policy::PostQuantumConfig::Prefer,
            require_ecdsa_capable_clients: require_ecdsa,
        };
        let policy = TlsPolicy::compile(&cfg).expect("valid policy");
        IronResolver::new(
            Arc::new(certs),
            Arc::new(challenge),
            Arc::new(policy),
            Arc::new(FixedClock(now)),
        )
    }

    fn leaf_hash(key: &Arc<rustls::sign::CertifiedKey>) -> blake3::Hash {
        blake3::hash(key.cert.first().expect("leaf present").as_ref())
    }

    fn cred_hash(cred: &Credentials) -> blake3::Hash {
        blake3::hash(cred.leaf_der())
    }

    /// `alpn_verdict` over a real single-entry `["acme-tls/1"]` list. Used by every test that
    /// exercises the challenge branch, so that branch is reached the same way `IronResolver::resolve`
    /// reaches it (by classifying a real ALPN list) rather than by a test handing `resolve_parts`
    /// a pre-decided `AlpnVerdict::Challenge` value, which would leave `alpn_verdict`'s own
    /// single-entry ACME detection unexercised by these tests.
    fn acme_only_verdict() -> AlpnVerdict {
        let entries: [&[u8]; 1] = [b"acme-tls/1"];
        alpn_verdict(Some(entries.iter().copied()))
    }

    /// `selected_by_key_type` must count the served credential's own key type.
    ///
    /// Nothing asserted this array, so both "never increment" and "always write slot 0"
    /// survived. Slot 0 is deliberately never written: `KeyType` is `#[repr(u8)]` with
    /// discriminants 1..=4, so a nonzero slot moving is the only correct outcome.
    #[test]
    fn selected_by_key_type_counts_the_served_key_type() {
        let ecdsa = gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let idx = ecdsa.key_type() as usize;
        assert_ne!(idx, 0, "slot 0 is never written; the fixture must not land there");

        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&ecdsa))
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let resolver = test_resolver(
            certs,
            ChallengeCerts::empty([9u8; 16]),
            false,
            UnixSeconds::new(1_000),
        );

        let before: Vec<u64> = resolver
            .stats()
            .selected_by_key_type
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        assert!(
            resolver
                .resolve_parts(normal_verdict(), Some("a.example.com"), ClientCaps::all())
                .is_some(),
            "the control resolve must succeed, or the counter deltas prove nothing"
        );
        let after: Vec<u64> = resolver
            .stats()
            .selected_by_key_type
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();

        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            let expected = if i == idx { b + 1 } else { *b };
            assert_eq!(
                *a, expected,
                "slot {i} must {} after one resolve of a {:?} credential",
                if i == idx { "increment" } else { "be untouched" },
                ecdsa.key_type()
            );
        }
        assert_eq!(after[0], 0, "slot 0 must never be written");
    }

    /// Each conjunct of the ECDSA-forcing gate must be load-bearing on its own.
    ///
    /// Three of its five were untested, and one of those changes real behaviour for an
    /// Ed25519 client. Each case below flips exactly one conjunct away from the refusing
    /// combination and asserts the request is SERVED, so a conjunct that stopped
    /// mattering would show up as a refusal that no longer happens.
    #[test]
    fn every_ecdsa_gate_conjunct_is_load_bearing() {
        fn resolver_with(require_ecdsa: bool, also_ecdsa_for_name: bool) -> IronResolver {
            let rsa = gen_cred(&rcgen::PKCS_RSA_SHA256, "a.example.com");
            let mut b = CertIndexBuilder::new([1u8; 16]);
            b.upsert_exact("a.example.com", rsa).expect("valid");
            if also_ecdsa_for_name {
                let ec = gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
                b.upsert_exact("a.example.com", ec).expect("valid");
            }
            test_resolver(
                b.build().expect("build"),
                ChallengeCerts::empty([9u8; 16]),
                require_ecdsa,
                UnixSeconds::new(1_000),
            )
        }
        let rsa_only = ClientCaps {
            rsa: true,
            ..Default::default()
        };

        // The refusing combination: policy on, client has neither ECDSA curve, the
        // resolved credential is RSA, and the name also has an ECDSA credential.
        let r = resolver_with(true, true);
        assert!(
            r.resolve_parts(normal_verdict(), Some("a.example.com"), rsa_only)
                .is_none(),
            "the control combination must refuse, or the flips below prove nothing"
        );

        // Conjunct 1: policy off.
        let r = resolver_with(false, true);
        assert!(
            r.resolve_parts(normal_verdict(), Some("a.example.com"), rsa_only)
                .is_some(),
            "with require_ecdsa_capable_clients off the request must be served"
        );

        // Conjuncts 2 and 3: the client advertises an ECDSA curve. Both P-256 and P-384
        // are checked because either alone disarms the gate.
        for caps in [
            ClientCaps {
                rsa: true,
                ecdsa_p256: true,
                ..Default::default()
            },
            ClientCaps {
                rsa: true,
                ecdsa_p384: true,
                ..Default::default()
            },
        ] {
            let r = resolver_with(true, true);
            assert!(
                r.resolve_parts(normal_verdict(), Some("a.example.com"), caps)
                    .is_some(),
                "an ECDSA-capable client must be served even with the policy on"
            );
        }

        // Conjunct 5: the name has no ECDSA credential to switch to, so refusing would
        // strand a client we could have served.
        let r = resolver_with(true, false);
        assert!(
            r.resolve_parts(normal_verdict(), Some("a.example.com"), rsa_only)
                .is_some(),
            "with no ECDSA credential for the name the gate must not refuse"
        );
    }

    /// `acme-tls/1` in third position is still a mixed list and must be refused.
    ///
    /// #117's Do NOT list names this bound and nothing tested it: `alpn_verdict` inspects
    /// at most three entries, so third position is the last one that can trip it.
    #[test]
    fn alpn_acme_third_position_refused() {
        let entries: [&[u8]; 3] = [b"h2", b"http/1.1", b"acme-tls/1"];
        assert_eq!(
            alpn_verdict(Some(entries.iter().copied())),
            AlpnVerdict::RefuseAcmeMixed
        );
    }

    /// `caps_from_schemes` folds at most 64 schemes, the other named Do NOT bound.
    ///
    /// A client offering more must not cause unbounded work, and the schemes inside the
    /// window must still be honoured.
    #[test]
    fn caps_from_schemes_folds_at_most_64_schemes() {
        let mut schemes = vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256];
        schemes.resize(200, rustls::SignatureScheme::RSA_PKCS1_SHA256);
        let caps = caps_from_schemes(&schemes);
        assert!(caps.ecdsa_p256, "a scheme inside the 64 window must be seen");

        // A scheme placed past the window must NOT be seen, which is what makes the cap
        // observable rather than merely present in the source.
        let mut past = vec![rustls::SignatureScheme::RSA_PKCS1_SHA256; 64];
        past.push(rustls::SignatureScheme::ECDSA_NISTP384_SHA384);
        let caps = caps_from_schemes(&past);
        assert!(
            !caps.ecdsa_p384,
            "a scheme past the 64-entry fold cap must not be folded in"
        );
    }

    /// The `Challenge` verdict with no SNI takes the miss path and serves nothing.
    ///
    /// This arm of `resolve_parts` was entirely uncovered. A challenge lookup needs a
    /// name; without one there is nothing to look up, and falling through to the normal
    /// path would serve a real certificate on the ACME-only ALPN.
    #[test]
    fn challenge_verdict_without_sni_serves_nothing() {
        // A DEFAULT credential is configured deliberately. Without one, a mutant that
        // falls through to the normal path still returns None (there is nothing to serve),
        // so the assertion below would hold either way. The first version of this test
        // omitted it and the fall-through mutation SURVIVED; this is the fixture doing the
        // discriminating, not the assertion.
        let real = gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&real))
            .expect("valid");
        certs_builder.set_default(real);
        let resolver = test_resolver(
            certs_builder.build().expect("build"),
            ChallengeCerts::empty([9u8; 16]),
            false,
            UnixSeconds::new(1_000),
        );

        let got = resolver.resolve_parts(acme_only_verdict(), None, ClientCaps::all());
        assert!(
            got.is_none(),
            "a challenge verdict with no SNI must serve nothing, not fall through to the \
             normal path and hand out a real certificate"
        );
        assert_eq!(resolver.stats().challenge_misses.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.stats().challenge_hits.load(Ordering::Relaxed), 0);
    }

    /// The `Normal` counterpart to [`acme_only_verdict`], computed by driving
    /// `alpn_verdict` over a real single-entry `["h2"]` list rather than naming the
    /// variant directly.
    ///
    /// Eight tests used to hand-feed `AlpnVerdict::Normal`, which is the same
    /// artifact-instead-of-computation shape that let the single-entry ACME mutation
    /// survive on the Challenge side until `acme_only_verdict` was added. A test that
    /// names the verdict cannot observe `alpn_verdict` deciding it wrongly.
    fn normal_verdict() -> AlpnVerdict {
        let entries: [&[u8]; 1] = [b"h2"];
        alpn_verdict(Some(entries.iter().copied()))
    }

    /// Every near-miss single-entry token must be `Normal`, so the `first == ACME`
    /// comparison is pinned as EXACT rather than only in the matching direction.
    ///
    /// No test previously fed `alpn_verdict` a single-entry list that was not exactly
    /// `acme-tls/1`, so weakening the comparison to `starts_with` or to a
    /// case-insensitive match both survived the whole suite.
    #[test]
    fn alpn_single_entry_near_misses_are_normal() {
        for token in [
            b"acme-tls/1-evil".as_slice(),
            b"acme-tls/10".as_slice(),
            b"acme-tls/1\0".as_slice(),
            b"ACME-TLS/1".as_slice(),
            b"acme-tls/1 ".as_slice(),
            b" acme-tls/1".as_slice(),
            b"acme-tls/".as_slice(),
            b"h2".as_slice(),
        ] {
            let entries: [&[u8]; 1] = [token];
            assert_eq!(
                alpn_verdict(Some(entries.iter().copied())),
                AlpnVerdict::Normal,
                "single-entry {:?} must not be treated as the ACME challenge ALPN",
                core::str::from_utf8(token).unwrap_or("<non-utf8>")
            );
        }

        // And the exact token still IS the challenge, so the test above cannot pass by
        // the comparison having been broken in the other direction.
        assert_eq!(acme_only_verdict(), AlpnVerdict::Challenge);
    }

    #[test]
    fn alpn_absent_uses_normal_branch() {
        let verdict = alpn_verdict(None::<std::iter::Empty<&[u8]>>);
        assert_eq!(verdict, AlpnVerdict::Normal);
    }

    #[test]
    fn alpn_empty_uses_normal_branch() {
        let entries: [&[u8]; 0] = [];
        let verdict = alpn_verdict(Some(entries.iter().copied()));
        assert_eq!(verdict, AlpnVerdict::Normal);
    }

    #[test]
    fn alpn_exact_acme_hits_challenge() {
        let (cert_der, key_der) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut builder = ChallengeCertsBuilder::new([9u8; 16]);
        builder
            .insert(
                "a.example.com",
                ChallengeKey::from_der(&cert_der, &key_der).expect("valid"),
                UnixSeconds::new(2_000),
            )
            .expect("valid");
        let challenge = builder.build_with_generation(0).expect("build");
        let certs = CertIndexBuilder::new([1u8; 16]).build().expect("build");
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        // Goes through alpn_verdict on a real single-entry `["acme-tls/1"]` list, not a
        // hand-fed AlpnVerdict::Challenge: a resolve_parts call fed the verdict directly cannot
        // catch a mutant that breaks alpn_verdict's own single-entry ACME detection, which is
        // exactly what a plain `resolve_parts(AlpnVerdict::Challenge, ...)` call here missed on a
        // first pass of this test.
        let verdict = acme_only_verdict();
        assert_eq!(verdict, AlpnVerdict::Challenge);
        let got = resolver.resolve_parts(verdict, Some("a.example.com"), ClientCaps::all());
        let key = got.expect("live challenge must be served");
        assert_eq!(leaf_hash(&key), blake3::hash(&cert_der));
        assert_eq!(resolver.stats().challenge_hits.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.stats().challenge_misses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn alpn_exact_acme_missing_challenge_returns_none() {
        // A real certificate exists for the same name, proving the miss does not fall through to
        // CertIndex: edge case 4 in issue #117.
        let real = cred_ecdsa_p256("a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&real))
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let verdict = acme_only_verdict();
        assert_eq!(verdict, AlpnVerdict::Challenge);
        let got = resolver.resolve_parts(verdict, Some("a.example.com"), ClientCaps::all());
        assert!(got.is_none());
        assert_eq!(resolver.stats().challenge_misses.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.stats().challenge_hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn alpn_exact_acme_expired_challenge_returns_none() {
        let (cert_der, key_der) = gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut builder = ChallengeCertsBuilder::new([9u8; 16]);
        builder
            .insert(
                "a.example.com",
                ChallengeKey::from_der(&cert_der, &key_der).expect("valid"),
                UnixSeconds::new(1_000),
            )
            .expect("valid");
        let challenge = builder.build_with_generation(0).expect("build");
        let certs = CertIndexBuilder::new([1u8; 16]).build().expect("build");
        // now == expires: the boundary itself must already be treated as expired ("<=", not "<").
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let verdict = acme_only_verdict();
        assert_eq!(verdict, AlpnVerdict::Challenge);
        let got = resolver.resolve_parts(verdict, Some("a.example.com"), ClientCaps::all());
        assert!(got.is_none());
        assert_eq!(resolver.stats().challenge_misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn alpn_acme_with_h2_refused() {
        let entries: [&[u8]; 2] = [b"acme-tls/1", b"h2"];
        let verdict = alpn_verdict(Some(entries.iter().copied()));
        assert_eq!(verdict, AlpnVerdict::RefuseAcmeMixed);

        // BOTH stores are populated for the queried name. An earlier version of this test
        // built an empty CertIndex AND an empty ChallengeCerts, which made `is_none()` true
        // no matter what the RefuseAcmeMixed arm did: a mutant that fell through to the
        // normal path, and a mutant that returned `self.challenge.lookup(..)` and served the
        // live self-signed challenge leaf to a client also offering h2, both passed. The
        // counter assertion did not rescue it either, because a mutant can increment the
        // counter and still return a certificate. Assert `is_none()` only against fixtures
        // that could have been returned.
        let (challenge_der, challenge_key) =
            gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut challenge_builder = ChallengeCertsBuilder::new([9u8; 16]);
        challenge_builder
            .insert(
                "a.example.com",
                ChallengeKey::from_der(&challenge_der, &challenge_key).expect("valid"),
                UnixSeconds::new(2_000),
            )
            .expect("valid");
        let challenge = challenge_builder.build_with_generation(0).expect("build");

        let real = gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&real))
            .expect("valid");
        let certs = certs_builder.build().expect("build");

        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));
        let got = resolver.resolve_parts(verdict, Some("a.example.com"), ClientCaps::all());
        assert!(
            got.is_none(),
            "a mixed acme-tls/1 plus h2 ALPN list must be served nothing, but got a \
             certificate; leaf hash {:?}, challenge leaf {:?}",
            got.as_ref().map(leaf_hash),
            blake3::hash(&challenge_der),
        );
        assert_eq!(
            resolver.stats().alpn_acme_refused.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn alpn_acme_second_position_refused() {
        let entries: [&[u8]; 2] = [b"h2", b"acme-tls/1"];
        let verdict = alpn_verdict(Some(entries.iter().copied()));
        assert_eq!(verdict, AlpnVerdict::RefuseAcmeMixed);

        // Populated for the same reason as `alpn_acme_with_h2_refused`: with both stores
        // empty this assertion held for every mutant of the RefuseAcmeMixed arm.
        let (challenge_der, challenge_key) =
            gen_leaf(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut challenge_builder = ChallengeCertsBuilder::new([9u8; 16]);
        challenge_builder
            .insert(
                "a.example.com",
                ChallengeKey::from_der(&challenge_der, &challenge_key).expect("valid"),
                UnixSeconds::new(2_000),
            )
            .expect("valid");
        let challenge = challenge_builder.build_with_generation(0).expect("build");

        let real = gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, "a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&real))
            .expect("valid");
        let certs = certs_builder.build().expect("build");

        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));
        let got = resolver.resolve_parts(verdict, Some("a.example.com"), ClientCaps::all());
        assert!(
            got.is_none(),
            "acme-tls/1 in second position must be served nothing, but got a certificate; \
             leaf hash {:?}, challenge leaf {:?}",
            got.as_ref().map(leaf_hash),
            blake3::hash(&challenge_der),
        );
        assert_eq!(
            resolver.stats().alpn_acme_refused.load(Ordering::Relaxed),
            1
        );
    }

    /// The counting iterator from issue #117's Tests section: increments `seen` on every
    /// `next()` call, so a test can observe exactly how many entries `alpn_verdict` actually
    /// pulled rather than merely inferring it from the verdict.
    struct Counting<'a> {
        inner: std::slice::Iter<'a, &'a [u8]>,
        seen: Rc<std::cell::Cell<usize>>,
    }

    impl<'a> Iterator for Counting<'a> {
        type Item = &'a [u8];
        fn next(&mut self) -> Option<&'a [u8]> {
            self.seen.set(self.seen.get() + 1);
            self.inner.next().copied()
        }
    }

    #[test]
    fn alpn_100_entries_inspects_at_most_three() {
        let entries: Vec<&[u8]> = (0..100).map(|_| b"h2".as_slice()).collect();
        let seen = Rc::new(std::cell::Cell::new(0));
        let counting = Counting {
            inner: entries.iter(),
            seen: Rc::clone(&seen),
        };
        let verdict = alpn_verdict(Some(counting));
        assert_eq!(verdict, AlpnVerdict::Normal);
        assert_eq!(
            seen.get(),
            3,
            "alpn_verdict must read exactly three entries from a 100-entry list, not \"at most\" \
             fewer and not all of them"
        );
    }

    #[test]
    fn no_sni_uses_default() {
        let default_cred = cred_ecdsa_p256("default.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder.set_default(Arc::clone(&default_cred));
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let got = resolver.resolve_parts(normal_verdict(), None, ClientCaps::all());
        let key = got.expect("a configured default must be served with no SNI");
        assert_eq!(leaf_hash(&key), cred_hash(&default_cred));
        assert_eq!(resolver.stats().no_sni.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn no_sni_without_default_returns_none() {
        let certs = CertIndexBuilder::new([1u8; 16]).build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let got = resolver.resolve_parts(normal_verdict(), None, ClientCaps::all());
        assert!(got.is_none());
        assert_eq!(resolver.stats().no_sni.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn empty_sni_uses_default() {
        let default_cred = cred_ecdsa_p256("default.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder.set_default(Arc::clone(&default_cred));
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let got = resolver.resolve_parts(normal_verdict(), Some(""), ClientCaps::all());
        let key = got.expect("an unparseable SNI falls back to the configured default");
        assert_eq!(leaf_hash(&key), cred_hash(&default_cred));
    }

    #[test]
    fn empty_sig_schemes_returns_none() {
        let caps = caps_from_schemes(&[]);
        assert_eq!(caps, ClientCaps::default());

        let cred = cred_ecdsa_p256("a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", cred)
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let got = resolver.resolve_parts(normal_verdict(), Some("a.example.com"), caps);
        assert!(got.is_none());
    }

    #[test]
    fn sha1_only_returns_none() {
        let caps = caps_from_schemes(&[
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
        ]);
        assert_eq!(caps, ClientCaps::default());

        let cred = cred_rsa("a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", cred)
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let got = resolver.resolve_parts(normal_verdict(), Some("a.example.com"), caps);
        assert!(got.is_none());
    }

    #[test]
    fn ecdsa_required_refuses_rsa_only_client_when_ecdsa_exists() {
        let ecdsa = cred_ecdsa_p256("a.example.com");
        let rsa = cred_rsa("a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", ecdsa)
            .expect("valid");
        certs_builder
            .upsert_exact("a.example.com", rsa)
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, true, UnixSeconds::new(1_000));

        let caps = ClientCaps {
            rsa: true,
            ..Default::default()
        };
        let got = resolver.resolve_parts(normal_verdict(), Some("a.example.com"), caps);
        assert!(got.is_none());
        assert_eq!(
            resolver
                .stats()
                .ecdsa_required_refused
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn ecdsa_required_serves_rsa_only_name() {
        let rsa = cred_rsa("a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&rsa))
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, true, UnixSeconds::new(1_000));

        let caps = ClientCaps {
            rsa: true,
            ..Default::default()
        };
        let got = resolver.resolve_parts(normal_verdict(), Some("a.example.com"), caps);
        let key = got.expect("a name with only an RSA credential must still be served");
        assert_eq!(leaf_hash(&key), cred_hash(&rsa));
        assert_eq!(
            resolver
                .stats()
                .ecdsa_required_refused
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn ecdsa_required_off_serves_rsa() {
        let ecdsa = cred_ecdsa_p256("a.example.com");
        let rsa = cred_rsa("a.example.com");
        let mut certs_builder = CertIndexBuilder::new([1u8; 16]);
        certs_builder
            .upsert_exact("a.example.com", ecdsa)
            .expect("valid");
        certs_builder
            .upsert_exact("a.example.com", Arc::clone(&rsa))
            .expect("valid");
        let certs = certs_builder.build().expect("build");
        let challenge = ChallengeCerts::empty([9u8; 16]);
        let resolver = test_resolver(certs, challenge, false, UnixSeconds::new(1_000));

        let caps = ClientCaps {
            rsa: true,
            ..Default::default()
        };
        let got = resolver.resolve_parts(normal_verdict(), Some("a.example.com"), caps);
        let key = got.expect("policy off must never refuse");
        assert_eq!(leaf_hash(&key), cred_hash(&rsa));
        assert_eq!(
            resolver
                .stats()
                .ecdsa_required_refused
                .load(Ordering::Relaxed),
            0
        );
    }
}
