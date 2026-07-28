// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! [`ChallengeCerts`]: ephemeral TLS-ALPN-01 (RFC 8737) challenge certificates, held in a
//! structure deliberately separate from [`crate::store::CertIndex`].
//!
//! A challenge certificate is self-signed, valid for one validation attempt, and carries no
//! private data of the service it stands in for; serving one to a real client is nonetheless a
//! visible outage, and the reverse (serving a real certificate on an `acme-tls/1` handshake) is
//! how a validator's opinion of "who owns this name" can be spoofed. Mixing challenge and real
//! certificates into one map with a boolean flag makes the first mistake a one-line change that
//! type-checks and makes the second an easy oversight in a wildcard-matching code path; two
//! structures with two lookup functions makes both mistakes unwritable. [`ChallengeCerts::lookup`]
//! is reachable only from the ALPN-gated challenge branch of
//! [`crate::store::IronResolver::resolve_parts`] (`cert-resolver-and-acme-challenge-map` (#117)),
//! never from the normal certificate path, and it never falls through to [`crate::store::CertIndex`]
//! on a miss.
//!
//! Capacity is capped at [`MAX_CHALLENGES`]. A validation campaign for a large zone proceeds in
//! batches; this many concurrent challenges is already far more than any public CA will run at
//! once for one account, and it bounds the memory of a structure that ACME reconciler code
//! writes into. Behaviour at the bound is `Err(ChallengeError::Full)` on insert: the order fails
//! and retries later. No live challenge is ever evicted to make room, because evicting one would
//! fail somebody else's in-flight validation and burn a CA authorization-failure budget for no
//! benefit to the caller that needed room.
//!
//! The `seed` that keys this map's [`crate::name::NameHasher`] is subject to the same rule as
//! the certificate index: it MUST be CSPRNG-derived or cluster-secret-derived, never a literal in
//! non-test code. Names in this map are operator-chosen rather than peer-chosen, so the collision
//! pressure is lower than in `CertIndex`, but there is no reason to run two rules where one of
//! them is the weak one.

use std::collections::HashMap;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::name::{self, MAX_NAME_LEN, NameError, NameHasher, NameKey};
use crate::store::index::{NameKeyHashBuilder, NameRef};
use crate::store::{CertError, MAX_DER_BYTES};
use crate::time::UnixSeconds;

/// Maximum concurrent TLS-ALPN-01 challenge certificates.
///
/// At [`MAX_CHALLENGES`] entries times a self-signed leaf under `MAX_DER_BYTES` (65,536 bytes)
/// plus one key, the map's hard ceiling is 32 MiB; the realistic figure, one self-signed leaf per
/// name currently mid-validation, is well under 1 MiB.
pub const MAX_CHALLENGES: usize = 512;

/// Why a challenge map operation failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ChallengeError {
    /// The map already holds [`MAX_CHALLENGES`] entries.
    Full,
    /// The name failed validation.
    Name(NameError),
}

impl core::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChallengeError::Full => {
                f.write_str("the TLS-ALPN-01 challenge map already holds 512 entries")
            }
            ChallengeError::Name(e) => write!(f, "invalid challenge name: {e}"),
        }
    }
}

impl std::error::Error for ChallengeError {}

impl From<NameError> for ChallengeError {
    fn from(e: NameError) -> Self {
        ChallengeError::Name(e)
    }
}

/// An opaque, already-signed challenge credential. Constructed by the TLS-ALPN-01 solver from a
/// DER chain and key through [`ChallengeKey::from_der`], so that no caller outside this crate
/// names a `rustls::` type.
pub struct ChallengeKey(Arc<rustls::sign::CertifiedKey>);

impl ChallengeKey {
    /// Load a self-signed challenge certificate and its key.
    ///
    /// Builds a one-element chain from `cert_der`, parses `key_der` with
    /// [`PrivateKeyDer::try_from`], and calls [`rustls::sign::CertifiedKey::from_der`]. This does
    /// **not** build a [`crate::store::Credentials`]: a challenge certificate has no SANs we
    /// index, no expiry we track here (the caller supplies `expires` separately when it inserts
    /// this key into a [`ChallengeCertsBuilder`]), and no OCSP staple. It does not intern
    /// anything: the chain is one self-signed leaf.
    ///
    /// # Errors
    /// [`CertError::EmptyDer`] or [`CertError::DerTooLarge`] for a bad `cert_der` blob,
    /// [`CertError::KeyMismatch`] if the key does not parse or does not match the certificate,
    /// and [`CertError::ProviderNotInstalled`] if no crypto provider is installed.
    pub fn from_der(cert_der: &[u8], key_der: &[u8]) -> Result<Self, CertError> {
        if cert_der.is_empty() {
            return Err(CertError::EmptyDer);
        }
        if cert_der.len() > MAX_DER_BYTES {
            return Err(CertError::DerTooLarge);
        }
        let chain: Vec<CertificateDer<'static>> = vec![CertificateDer::from(cert_der.to_vec())]; // it-allow: hot-path-allocation reason: solver-facing constructor, called once per ACME order, never on the resolve path
        let key = PrivateKeyDer::try_from(key_der)
            .map_err(|_| CertError::KeyMismatch)?
            .clone_key();
        let provider = crate::provider::provider().ok_or(CertError::ProviderNotInstalled)?;
        let certified = rustls::sign::CertifiedKey::from_der(chain, key, provider)
            .map_err(|_| CertError::KeyMismatch)?;
        Ok(Self(Arc::new(certified))) // it-allow: hot-path-allocation reason: solver-facing constructor, called once per ACME order, never on the resolve path
    }
}

/// One entry in [`ChallengeCerts`].
struct ChallengeEntry {
    /// Slice of `ChallengeCerts::names` holding this entry's normalized name.
    name: NameRef,
    /// The self-signed challenge credential.
    key: Arc<rustls::sign::CertifiedKey>,
    /// When this challenge stops being served.
    expires: UnixSeconds,
}

/// Ephemeral TLS-ALPN-01 challenge certificates. Deliberately a separate structure from
/// [`crate::store::CertIndex`]: these are self-signed, they are valid for one validation
/// attempt, and serving one to a real client is a visible outage.
pub struct ChallengeCerts {
    hasher: NameHasher,
    by_name: HashMap<NameKey, ChallengeEntry, NameKeyHashBuilder>,
    names: Box<[u8]>,
    generation: u64,
}

impl ChallengeCerts {
    /// An empty map.
    #[must_use]
    pub fn empty(seed: [u8; 16]) -> Self {
        Self {
            hasher: NameHasher::new(seed),
            by_name: HashMap::with_hasher(NameKeyHashBuilder),
            names: Box::default(),
            generation: 0,
        }
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Generation number.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Look up the live challenge credential for `sni`, if any.
    ///
    /// 1. Normalizes `sni` into a stack buffer; on failure returns `None`.
    /// 2. Hashes with this map's keyed hasher, probes `by_name`, and memcmp's the stored name.
    ///    On mismatch returns `None`.
    /// 3. If the stored entry's `expires` is at or before `now`, returns `None`: an expired
    ///    challenge certificate is never served, because a stale entry means the order was
    ///    abandoned.
    /// 4. Otherwise returns the stored credential.
    ///
    /// `pub(crate)` rather than `pub`: it names a `rustls::` type in its signature and must not
    /// cross the crate facade (`tls-crate-and-crypto-provider` (#112)).
    pub(crate) fn lookup(
        &self,
        sni: &str,
        now: UnixSeconds,
    ) -> Option<&Arc<rustls::sign::CertifiedKey>> {
        let mut buf = [0u8; MAX_NAME_LEN];
        let Ok(normalized) = name::normalize(sni, &mut buf) else {
            return None;
        };
        let key = self.hasher.hash(normalized);
        let entry = self.by_name.get(&key)?;
        if self.name_at(entry.name) != normalized.as_bytes() {
            return None;
        }
        if entry.expires <= now {
            return None;
        }
        Some(&entry.key)
    }

    /// The stored name bytes for one entry. `r` came out of this same map's `by_name`, written
    /// only by [`ChallengeCertsBuilder::build_with_generation`] alongside `names`, so the range
    /// is in bounds by construction.
    #[allow(
        clippy::indexing_slicing,
        reason = "`r` came out of `by_name`, whose NameRefs were written into `names` by the \
                  same builder call that produced this map; the range is in bounds by \
                  construction, the same invariant `CertIndex::name_at` relies on"
    )]
    fn name_at(&self, r: NameRef) -> &[u8] {
        &self.names[r.offset as usize..r.offset as usize + r.len as usize]
    }
}

/// The only way to build a [`ChallengeCerts`].
pub struct ChallengeCertsBuilder {
    hasher: NameHasher,
    /// Staged entries, keyed by normalized name so a repeated `insert` replaces rather than
    /// duplicates. Converted into the final name arena and `NameKey`-hashed map by
    /// `build_with_generation`.
    entries: HashMap<Box<str>, (Arc<rustls::sign::CertifiedKey>, UnixSeconds)>,
}

impl ChallengeCertsBuilder {
    /// New empty builder with an explicit hasher seed.
    ///
    /// `seed` MUST be unpredictable to a peer: CSPRNG output, or an HKDF expansion of the cluster
    /// secret, the same rule `CertIndexBuilder::new` documents. Tests pass a fixed value;
    /// non-test code passing a literal is a security defect.
    #[must_use]
    pub fn new(seed: [u8; 16]) -> Self {
        Self {
            hasher: NameHasher::new(seed),
            entries: HashMap::default(),
        }
    }

    /// Seed a new builder from an existing map, dropping entries that have already expired as of
    /// `now`. This is what makes the map self-clean on every rebuild.
    #[must_use]
    pub fn from_previous(prev: &ChallengeCerts, now: UnixSeconds) -> Self {
        let mut entries = HashMap::default();
        for entry in prev.by_name.values() {
            if entry.expires <= now {
                continue;
            }
            let name_bytes = prev.name_at(entry.name);
            if let Ok(name_str) = core::str::from_utf8(name_bytes) {
                entries.insert(
                    Box::from(name_str), // it-allow: hot-path-allocation reason: builder path, not lookup; stages a name carried over from a previous generation
                    (Arc::clone(&entry.key), entry.expires),
                );
            }
        }
        Self {
            hasher: prev.hasher.clone(), // it-allow: hot-path-allocation reason: builder path, not lookup; NameHasher::clone is a 16-byte key copy, not an allocation, but the plain `.clone()` spelling still matches this rule's text scan
            entries,
        }
    }

    /// Add or replace a challenge certificate for `name`, valid until `expires`.
    ///
    /// The `key` argument is produced by the TLS-ALPN-01 solver; this crate does not generate it.
    /// A name that is already staged is replaced in place and does not count against
    /// [`MAX_CHALLENGES`] a second time.
    ///
    /// # Errors
    /// [`ChallengeError::Full`] if the map already holds [`MAX_CHALLENGES`] distinct names and
    /// `name` is not already one of them, or [`ChallengeError::Name`] if `name` fails validation.
    pub fn insert(
        &mut self,
        name: &str,
        key: ChallengeKey,
        expires: UnixSeconds,
    ) -> Result<(), ChallengeError> {
        let mut buf = [0u8; MAX_NAME_LEN];
        let normalized = name::normalize(name, &mut buf)?;
        if !self.entries.contains_key(normalized) && self.entries.len() >= MAX_CHALLENGES {
            return Err(ChallengeError::Full);
        }
        self.entries.insert(
            Box::from(normalized), // it-allow: hot-path-allocation reason: builder path, not lookup; stages the normalized name for the next build
            (key.0, expires),
        );
        Ok(())
    }

    /// Remove the entry for `name`, if any. No-op if `name` is absent or fails normalization.
    pub fn remove(&mut self, name: &str) {
        let mut buf = [0u8; MAX_NAME_LEN];
        let Ok(normalized) = name::normalize(name, &mut buf) else {
            return;
        };
        self.entries.remove(normalized);
    }

    /// Test seam that swaps in a hasher whose `hash` ignores its input and always returns
    /// `NameKey(0)`, so every staged name lands in the same `by_name` bucket regardless of what
    /// it is. This is what lets `challenge_lookup_is_case_insensitive` prove that
    /// `ChallengeCerts::lookup`'s memcmp (`self.name_at(entry.name) != normalized.as_bytes()`) is
    /// actually load-bearing rather than merely present: with a real keyed hash, two distinct
    /// test-chosen names essentially never collide, so a lookup for a name that is not in the map
    /// already misses at the hash probe and never reaches the memcmp at all, and removing the
    /// memcmp check outright would still pass every other test in this module. Mirrors
    /// `CertIndexBuilder::force_collision_on_attempt_0` / `NameHasher::degenerate_for_test`, the
    /// identical seam `store::index::tests` uses for the same reason.
    #[cfg(test)]
    pub(crate) fn force_degenerate_hasher(&mut self) {
        self.hasher = NameHasher::degenerate_for_test();
    }

    /// Finish, producing an immutable [`ChallengeCerts`] carrying `generation`.
    ///
    /// # Errors
    /// [`ChallengeError::Name`] if a staged name fails re-validation, which cannot happen for
    /// names that were validated on `insert` and is therefore an internal-consistency check
    /// rather than a reachable outcome.
    pub fn build_with_generation(self, generation: u64) -> Result<ChallengeCerts, ChallengeError> {
        let hasher = self.hasher;
        let mut names: Vec<u8> = Vec::new(); // it-allow: hot-path-allocation reason: builder path, not lookup; becomes the immutable name arena, mirroring CertIndexBuilder::build_index_finish
        let mut by_name = HashMap::with_hasher(NameKeyHashBuilder);
        for (staged_name, (key, expires)) in self.entries {
            let mut buf = [0u8; MAX_NAME_LEN];
            let renormalized = name::normalize(&staged_name, &mut buf)?;
            #[rustfmt::skip]
            #[allow(clippy::cast_possible_truncation, reason = "at most MAX_CHALLENGES (512) names of at most MAX_NAME_LEN (253) bytes each are ever staged, so names.len() never exceeds 129,536, far under u32::MAX")]
            let offset = names.len() as u32; // it-allow: unchecked-cast reason: at most MAX_CHALLENGES (512) names of at most MAX_NAME_LEN (253) bytes each are ever staged, so names.len() never exceeds 129,536, far under u32::MAX
            #[rustfmt::skip]
            #[allow(clippy::cast_possible_truncation, reason = "normalize() guarantees its output is at most MAX_NAME_LEN (253) bytes, which fits in u16")]
            let len = renormalized.len() as u16; // it-allow: unchecked-cast reason: normalize() guarantees its output is at most MAX_NAME_LEN (253) bytes, which fits in u16
            names.extend_from_slice(renormalized.as_bytes());
            let key_hash = hasher.hash(renormalized);
            // A NameKey collision between two distinct staged names would make the later insert
            // silently replace the earlier one in `by_name`. At <= 512 operator-chosen names this
            // is an astronomically unlikely birthday event, and unlike CertIndexBuilder this
            // builder has no retry protocol to fall back to; see the module doc for why the seed
            // strength, not a retry loop, is what this map relies on.
            by_name.insert(
                key_hash,
                ChallengeEntry {
                    name: NameRef { offset, len },
                    key,
                    expires,
                },
            );
        }
        Ok(ChallengeCerts {
            hasher,
            by_name,
            names: names.into_boxed_slice(), // it-allow: hot-path-allocation reason: builder path, not lookup; converts the already-built Vec into the immutable arena
            generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::{ChallengeCertsBuilder, ChallengeError, ChallengeKey};
    use crate::time::UnixSeconds;

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    /// Returns `(cert_der, key_der)` for a fresh self-signed ECDSA P-256 leaf for `san`.
    fn gen_leaf(san: &str) -> (Vec<u8>, Vec<u8>) {
        ensure_provider_installed();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        let cert = params.self_signed(&key).expect("sign");
        (cert.der().to_vec(), key.serialize_der())
    }

    fn gen_key(san: &str) -> ChallengeKey {
        let (cert_der, key_der) = gen_leaf(san);
        ChallengeKey::from_der(&cert_der, &key_der).expect("valid self-signed leaf and key")
    }

    #[test]
    fn challenge_full_rejects_insert() {
        let mut builder = ChallengeCertsBuilder::new([1u8; 16]);
        for i in 0..512 {
            let name = format!("host{i}.example.com");
            builder
                .insert(&name, gen_key(&name), UnixSeconds::new(1_000))
                .expect("valid insert under the cap");
        }
        // The boundary itself: exactly MAX_CHALLENGES is accepted, and a 513th distinct name is
        // refused. A mutant that widens `>=` to `>` would still refuse a 514th name and survive
        // a test that only checked "eventually rejected"; checking the 513th name specifically
        // pins the boundary.
        let err = builder
            .insert(
                "overflow.example.com",
                gen_key("overflow.example.com"),
                UnixSeconds::new(1_000),
            )
            .expect_err("the 513th distinct name must be refused");
        assert_eq!(err, ChallengeError::Full);
        assert_eq!(
            err.to_string(),
            "the TLS-ALPN-01 challenge map already holds 512 entries"
        );

        // Replacing an already-present name is not subject to the cap: it must succeed even
        // though the map is completely full, because it does not grow the entry count.
        builder
            .insert(
                "host0.example.com",
                gen_key("host0.example.com"),
                UnixSeconds::new(2_000),
            )
            .expect("replacing an existing entry must not count against the cap");

        let built = builder
            .build_with_generation(7)
            .expect("512 valid entries build cleanly");
        assert_eq!(built.len(), 512);
        assert_eq!(built.generation(), 7);
    }

    #[test]
    fn challenge_from_previous_drops_expired() {
        let mut builder = ChallengeCertsBuilder::new([2u8; 16]);
        builder
            .insert(
                "live.example.com",
                gen_key("live.example.com"),
                UnixSeconds::new(2_000),
            )
            .expect("valid");
        builder
            .insert(
                "expired.example.com",
                gen_key("expired.example.com"),
                UnixSeconds::new(500),
            )
            .expect("valid");
        // The boundary itself: an entry whose expiry equals `now` exactly must also be dropped
        // (edge case 5's `<=`, not `<`), not just one that is strictly in the past.
        builder
            .insert(
                "boundary.example.com",
                gen_key("boundary.example.com"),
                UnixSeconds::new(1_000),
            )
            .expect("valid");
        let built = builder.build_with_generation(0).expect("build");
        assert_eq!(built.len(), 3);

        let rebuilt = ChallengeCertsBuilder::from_previous(&built, UnixSeconds::new(1_000))
            .build_with_generation(1)
            .expect("rebuild");
        assert_eq!(rebuilt.len(), 1);
        assert_eq!(rebuilt.generation(), 1);
        assert!(
            rebuilt
                .lookup("live.example.com", UnixSeconds::new(1_000))
                .is_some()
        );
        assert!(
            rebuilt
                .lookup("expired.example.com", UnixSeconds::new(1_000))
                .is_none()
        );
        assert!(
            rebuilt
                .lookup("boundary.example.com", UnixSeconds::new(1_000))
                .is_none()
        );
    }

    #[test]
    fn challenge_lookup_is_case_insensitive() {
        let mut builder = ChallengeCertsBuilder::new([3u8; 16]);
        let (cert_der, key_der) = gen_leaf("mixed.example.com");
        builder
            .insert(
                "MIXED.Example.COM.",
                ChallengeKey::from_der(&cert_der, &key_der).expect("valid"),
                UnixSeconds::new(2_000),
            )
            .expect("valid");
        let built = builder.build_with_generation(0).expect("build");

        let lower = built
            .lookup("mixed.example.com", UnixSeconds::new(1_000))
            .expect("case-insensitive hit");
        let upper = built
            .lookup("MIXED.EXAMPLE.COM", UnixSeconds::new(1_000))
            .expect("case-insensitive hit");
        let lower_leaf = lower.cert.first().expect("leaf present").as_ref();
        let upper_leaf = upper.cert.first().expect("leaf present").as_ref();
        assert_eq!(blake3::hash(lower_leaf), blake3::hash(upper_leaf));
        assert_eq!(blake3::hash(lower_leaf), blake3::hash(&cert_der));

        // Neither direction of ChallengeCerts alone can demonstrate CROSS-structure isolation
        // (that is `handshake_normal_client_gets_real_cert_when_challenge_live` and
        // `handshake_acme_alpn_gets_challenge_cert` in tests/handshake_resolver.rs); this test
        // only pins that name comparison inside this one map goes through the same normalize()
        // as CertIndex, so a mixed-case ACME order can still be found.
        assert!(
            built
                .lookup("nonexistent.example.com", UnixSeconds::new(1_000))
                .is_none()
        );

        // The memcmp inside `lookup` (`self.name_at(entry.name) != normalized.as_bytes()`) is a
        // second independent check on top of the hash probe, not decoration: with the REAL keyed
        // hash used above, two distinct test-chosen names essentially never collide, so the
        // `nonexistent.example.com` check just above already misses at the hash-probe step and
        // never actually reaches the memcmp. `force_degenerate_hasher` collapses every name into
        // the same bucket so this map's memcmp is the thing doing the work, not the hash: without
        // it, `different.example.com` below would incorrectly find and return `real.example.com`'s
        // credential, because both land in `by_name`'s one and only bucket.
        let (real_der, real_key) = gen_leaf("real.example.com");
        let mut collision_builder = ChallengeCertsBuilder::new([4u8; 16]);
        collision_builder.force_degenerate_hasher();
        collision_builder
            .insert(
                "real.example.com",
                ChallengeKey::from_der(&real_der, &real_key).expect("valid"),
                UnixSeconds::new(2_000),
            )
            .expect("valid");
        let collision_built = collision_builder.build_with_generation(0).expect("build");
        assert!(
            collision_built
                .lookup("real.example.com", UnixSeconds::new(1_000))
                .is_some(),
            "the name that was actually inserted must still be found"
        );
        assert!(
            collision_built
                .lookup("different.example.com", UnixSeconds::new(1_000))
                .is_none(),
            "a different name that hashes into the SAME bucket as a live entry must still miss: \
             this is the memcmp guard, not the hash probe, doing the work"
        );
    }
}
