// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Immutable certificate index: two hash probes and zero allocations per SNI lookup.
//!
//! [`CertIndex`] is built once per generation by [`CertIndexBuilder`] and is never mutated
//! afterwards. [`CertIndex::resolve`] performs exactly two hash probes (exact name, then the
//! parent domain for a wildcard match), one memcmp per probe, and a branchless scan of at most
//! four key-type tags to pick the first credential the peer can verify.
//!
//! The design is deliberately O(1) in the number of configured certificates. There is no SNI
//! cache, no linear scan on miss, no suffix walk, and no regex fallback: any of those would be an
//! attacker-controllable resource primitive. The only cross-core traffic on the resolve path is
//! the single relaxed atomic increment that records which counter the call hit.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::name::{self, MAX_NAME_LEN, NameHasher, NameKey};
use crate::store::{CertError, CertFingerprint, Credentials, KeyType};

/// Index of a `CredSet` inside `CertIndex::cred_sets`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct CredSetIdx(u32);

/// A slice of the name arena: `(offset, len)`.
///
/// `pub(crate)`, with `pub(crate)` fields, because `store/challenge.rs`
/// (`cert-resolver-and-acme-challenge-map` (#117)) stores one inside `ChallengeEntry` and
/// `listener.rs` (`sni-server-config-selection` (#119)) uses the same arena shape. Both are sibling
/// modules, not children, so a private item here would not be visible to them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct NameRef {
    /// Byte offset of the first label byte in `CertIndex::names`.
    pub(crate) offset: u32,
    /// Byte length of the normalized name.
    pub(crate) len: u16,
}

/// Up to four credentials for one name, one per key type, ordered by `KeyType` rank.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct CredSet {
    /// Packed `KeyType` discriminants; 0 means an empty slot. Sorted ascending.
    tags: [u8; 4],
    /// Indices into `CertIndex::creds`, parallel to `tags`.
    idx: [u32; 4],
    /// Number of occupied slots, 1 to 4.
    len: u8,
}

/// What the `ClientHello` says the peer can verify. Built once per handshake.
#[allow(
    clippy::struct_excessive_bools,
    reason = "ClientCaps mirrors four independent TLS signature-algorithm advertisement bits"
)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientCaps {
    /// Client advertised `ecdsa_secp256r1_sha256`.
    pub ecdsa_p256: bool,
    /// Client advertised `ecdsa_secp384r1_sha384`.
    pub ecdsa_p384: bool,
    /// Client advertised any `rsa_pss_rsae_*` or `rsa_pkcs1_*` scheme.
    pub rsa: bool,
    /// Client advertised `ed25519`.
    pub ed25519: bool,
}

impl ClientCaps {
    /// Everything enabled. Used by tests and by the ACME challenge path.
    #[must_use]
    pub fn all() -> Self {
        Self {
            ecdsa_p256: true,
            ecdsa_p384: true,
            rsa: true,
            ed25519: true,
        }
    }

    /// `true` when no key type at all is acceptable, that is all four fields are `false`.
    /// Note the sense: `is_empty() == true` means the client can verify nothing we serve.
    #[must_use]
    pub fn is_empty(self) -> bool {
        !(self.ecdsa_p256 || self.ecdsa_p384 || self.rsa || self.ed25519)
    }
}

/// Immutable certificate store. Built once per generation, never mutated.
pub struct CertIndex {
    hasher: NameHasher,
    exact: HashMap<NameKey, CredSetIdx, NameKeyHashBuilder>,
    wild: HashMap<NameKey, CredSetIdx, NameKeyHashBuilder>,
    /// Name bytes for every entry, contiguous. Verifies a hash hit with one memcmp.
    names: Box<[u8]>,
    /// Parallel to `cred_sets`: which arena slice this set's name occupies.
    name_refs: Box<[NameRef]>,
    cred_sets: Box<[CredSet]>,
    creds: Box<[Arc<Credentials>]>,
    default_cred: Option<Arc<Credentials>>,
    generation: u64,
    stats: CertStats,
    /// Test-only instrumentation (issue #719's `SHOULD_FIX`): counts how many times `resolve`
    /// probes the `wild` map. #115's thesis is "exactly two hash probes ... exactly one
    /// wildcard probe", and its Do NOT list says "Do NOT walk every suffix of the SNI." Nothing
    /// else in this suite discriminates that claim from an Envoy style O(k) suffix walk that
    /// still returns the correct credential: such a walk passes every functional assertion here
    /// and only probes `wild` a different number of times. See
    /// `resolve_wildcard_branch_probes_wild_map_exactly_once` below, which reads this counter.
    #[cfg(test)]
    wild_probe_count: AtomicU64,
    /// Test seam: how many times `resolve` has probed the `exact` map. Paired with
    /// `wild_probe_count` so that a test can assert the TOTAL probe count per resolution is
    /// independent of how many names the index holds, which is the real "flat across n"
    /// property. A wall-clock version of that assertion measures the machine as much as the
    /// code; see #750.
    #[cfg(test)]
    exact_probe_count: AtomicU64,
    /// Test seam: how many stored names `resolve` has read for byte comparison. This is the
    /// n-SENSITIVE counter, and it is the one that makes the `n` sweep in
    /// `resolve_flat_across_n` load-bearing: a correct lookup confirms exactly one
    /// candidate name whatever the index holds, whereas any implementation that searches names to
    /// find the answer (a suffix walk, a linear scan, a probe chain that memcmps as it goes)
    /// examines more of them as the index grows. Probe counts alone cannot see that: they are
    /// fully determined at n = 1.
    #[cfg(test)]
    names_examined: AtomicU64,
}

/// Counters for the certificate path. Monotone, relaxed, may lose an increment; never a balance.
#[derive(Debug, Default)]
pub struct CertStats {
    /// `tls_cert_resolve_exact_total`
    pub exact_hits: AtomicU64,
    /// `tls_cert_resolve_wildcard_total`
    pub wildcard_hits: AtomicU64,
    /// `tls_cert_resolve_default_total`
    pub default_used: AtomicU64,
    /// `tls_cert_resolve_miss_total`
    pub misses: AtomicU64,
    /// `tls_cert_resolve_invalid_sni_total`
    pub invalid_sni: AtomicU64,
    /// `tls_cert_resolve_no_compatible_key_total`
    pub no_compatible_key: AtomicU64,
}

/// Pass-through `BuildHasher`: `NameKey` already contains a keyed `SipHash` output, so rehashing
/// it would be pure cost.
#[derive(Clone, Default)]
pub(crate) struct NameKeyHashBuilder;

#[derive(Default)]
pub(crate) struct NameKeyHasher(u64);

impl core::hash::BuildHasher for NameKeyHashBuilder {
    type Hasher = NameKeyHasher;

    fn build_hasher(&self) -> NameKeyHasher {
        NameKeyHasher(0)
    }
}

impl core::hash::Hasher for NameKeyHasher {
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }

    fn write(&mut self, bytes: &[u8]) {
        // Never taken: NameKey's derived Hash impl writes exactly one u64. Fold rather than panic.
        for b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*b);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// Maximum bytes in the name arena. A `NameRef.offset` is a `u32`, and a truncated offset points
/// at the wrong name.
pub const MAX_NAME_ARENA_BYTES: usize = 1_073_741_824;
/// Maximum distinct `(is_wild, name)` groups in one index. A `CredSetIdx` is a `u32`, and a
/// truncated group index hands out the wrong certificate.
pub const MAX_INDEX_GROUPS: usize = 16_777_216;

/// Compiled-in two-label public suffixes for which a wildcard certificate would be absurdly broad.
const SUFFIX_DENY: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.cn", "com.mx", "co.za", "co.in",
];

/// Pending entry in a builder.
type PendingEntry = (Box<str>, bool, Arc<Credentials>);

/// Validate a wildcard's raw `"*.parent"` form the same way [`CertIndexBuilder::upsert_wildcard`]
/// does, without staging anything.
///
/// `pub(crate)` for `store::builder::CertUpdateCoalescer::submit`, which must reject a bad
/// wildcard **before** it enters the pending queue (see that module's docs for why: one bad
/// wildcard left in a builder's pending list would abort every later flush). `SUFFIX_DENY` is
/// private to this module, so this lives here rather than as a second, driftable copy of the
/// same denylist in `builder.rs`.
pub(crate) fn validate_wildcard_parent(raw: &str) -> Result<(), CertError> {
    if raw == "*" {
        return Err(CertError::WildcardTooBroad);
    }
    let parent = name::wildcard_parent(raw)?;
    let mut buf = [0u8; MAX_NAME_LEN];
    let normalized = name::normalize(parent, &mut buf)?;
    if name::label_count(normalized) < 2 || SUFFIX_DENY.contains(&normalized) {
        return Err(CertError::WildcardTooBroad);
    }
    Ok(())
}

/// A group of entries sharing the same `(is_wild, name)` after sorting.
struct Group {
    is_wild: bool,
    name: Box<str>,
    creds: Vec<(KeyType, Arc<Credentials>)>,
}

/// The only way to build a `CertIndex`.
pub struct CertIndexBuilder {
    seed: [u8; 16],
    entries: Vec<PendingEntry>,
    default_cred: Option<Arc<Credentials>>,
    /// Set only by `store::builder::CertIndexBuilder::from_previous` (via
    /// [`CertIndexBuilder::new_from_inherited`]): the previous generation's own hasher, reused
    /// verbatim as attempt 0's hasher so a name that already resolved keeps the same `NameKey`.
    /// `None` for every from-scratch builder, which is unaffected by any of this.
    inherited_hasher: Option<NameHasher>,
    #[cfg(test)]
    force_collision_on_attempt_0: bool,
    #[cfg(test)]
    max_arena_bytes: usize,
    #[cfg(test)]
    max_groups: usize,
}

impl CertIndexBuilder {
    /// New empty builder whose hasher seed is 16 fresh bytes from the operating system CSPRNG.
    ///
    /// This is the constructor production code uses.
    ///
    /// # Errors
    /// [`irontraffic_rand::EntropyError`] when the operating system CSPRNG cannot be read. The
    /// caller MUST fail the config build rather than substituting a constant seed.
    pub fn new_from_entropy() -> Result<Self, irontraffic_rand::EntropyError> {
        let mut seed = [0u8; 16];
        irontraffic_rand::SecureRng::fill(&mut seed)?;
        Ok(Self::new(seed))
    }

    /// New empty builder with an explicit hasher seed.
    ///
    /// `seed` MUST be unpredictable to a peer: CSPRNG output, or an HKDF expansion of the cluster
    /// secret. A guessable seed restores the offline hash-collision attack against `resolve`.
    /// Tests pass a fixed value; non-test code passing a literal is a security defect.
    #[must_use]
    pub fn new(seed: [u8; 16]) -> Self {
        Self {
            seed,
            entries: Vec::new(), // it-allow: hot-path-allocation reason: builder path, not resolve; one allocation per generation build
            default_cred: None,
            inherited_hasher: None,
            #[cfg(test)]
            force_collision_on_attempt_0: false,
            #[cfg(test)]
            max_arena_bytes: MAX_NAME_ARENA_BYTES,
            #[cfg(test)]
            max_groups: MAX_INDEX_GROUPS,
        }
    }

    /// `pub(crate)` constructor for `store::builder::CertIndexBuilder::from_previous`.
    ///
    /// `builder.rs` is a sibling module of this one and cannot build a `CertIndexBuilder` value
    /// directly with struct-literal syntax: every field above is private to `index.rs`, the same
    /// privacy boundary `rebuild_entries`, `hasher()` and `default_cred()` on `CertIndex` exist to
    /// cross for reads. This is the write-side equivalent, taking the already-flattened pending
    /// list and the inherited hasher directly rather than re-validating and re-normalizing `E`
    /// already-valid names through `upsert_exact`/`upsert_wildcard`.
    ///
    /// There is no "seed" here at all, deliberately: attempt 0 of the collision-retry loop uses
    /// `inherited_hasher` verbatim, and a retry (see [`Self::hasher_for_attempt_from_previous`])
    /// draws fresh CSPRNG entropy rather than deriving from a stored seed, so this constructor
    /// never stores a placeholder byte pattern that could be mistaken for a real, security-
    /// sensitive seed the way a literal argument to `new` would.
    #[must_use]
    pub(crate) fn new_from_inherited(
        entries: Vec<PendingEntry>,
        default_cred: Option<Arc<Credentials>>,
        inherited_hasher: NameHasher,
    ) -> Self {
        Self {
            seed: [0u8; 16], // Never read: build_inner takes the inherited_hasher branch unconditionally whenever it is Some, and that branch never reads `seed`.
            entries,
            default_cred,
            inherited_hasher: Some(inherited_hasher),
            #[cfg(test)]
            force_collision_on_attempt_0: false,
            #[cfg(test)]
            max_arena_bytes: MAX_NAME_ARENA_BYTES,
            #[cfg(test)]
            max_groups: MAX_INDEX_GROUPS,
        }
    }

    /// `pub(crate)` for `store::builder::CertIndexBuilder::replace_by_fingerprint`, which cannot
    /// reach `self.entries` directly (private to this module). Substitutes `cred` for every
    /// pending entry whose credential has `fingerprint`, keeping the entry's stored name and
    /// wildcard flag, and returns how many entries were replaced.
    pub(crate) fn replace_pending_by_fingerprint(
        &mut self,
        fingerprint: CertFingerprint,
        cred: &Arc<Credentials>,
    ) -> usize {
        let mut replaced = 0usize;
        for entry in &mut self.entries {
            if entry.2.fingerprint() == fingerprint {
                entry.2 = Arc::clone(cred);
                replaced = replaced.saturating_add(1);
            }
        }
        replaced
    }

    /// Index `cred` under an exact name.
    ///
    /// # Errors
    /// `CertError::Name` if the name fails validation.
    pub fn upsert_exact(&mut self, name: &str, cred: Arc<Credentials>) -> Result<(), CertError> {
        let mut buf = [0u8; MAX_NAME_LEN];
        let normalized = name::normalize(name, &mut buf)?;
        self.entries.push((normalized.into(), false, cred));
        Ok(())
    }

    /// Index `cred` under a wildcard name written as `*.parent`.
    ///
    /// # Errors
    /// `CertError::Wildcard` for a partial or absent wildcard, `CertError::Name` for an invalid
    /// parent, `CertError::WildcardTooBroad` for a parent with fewer than 2 labels or a parent in
    /// the compiled-in suffix denylist.
    pub fn upsert_wildcard(&mut self, raw: &str, cred: Arc<Credentials>) -> Result<(), CertError> {
        // The rule itself lives in `validate_wildcard_parent`, which `submit` also calls. Keeping
        // an inlined second copy here is the exact drift hazard that function's own doc comment
        // claims to have removed: two copies of one denylist in one file, either of which could
        // be tightened without the other.
        validate_wildcard_parent(raw)?;
        let parent = name::wildcard_parent(raw)?;
        let mut buf = [0u8; MAX_NAME_LEN];
        let normalized = name::normalize(parent, &mut buf)?;
        self.entries.push((normalized.into(), true, cred));
        Ok(())
    }

    /// Index `cred` under every dNSName SAN it carries, choosing exact or wildcard per name.
    /// Names that fail validation are skipped and counted in the returned report.
    ///
    /// The loop is exactly: for each `s` in `cred.san_dns_names()`, if `s` starts with `"*."`
    /// call `self.upsert_wildcard(s, Arc::clone(&cred))`, otherwise call
    /// `self.upsert_exact(s, Arc::clone(&cred))`; on `Ok` increment `wildcard` or `exact`
    /// respectively, on `Err` increment `skipped` and continue with the next SAN. Every counter
    /// saturates at `u16::MAX` rather than wrapping, which is unreachable because
    /// `MAX_SANS` is 100. This method never returns an error: a certificate with one bad SAN and
    /// ninety-nine good ones is still worth indexing.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "API takes an owned Arc<Credentials> so callers can pass the original and the builder can clone it cheaply"
    )]
    pub fn upsert_from_sans(&mut self, cred: Arc<Credentials>) -> SanIndexReport {
        let mut report = SanIndexReport::default();
        for s in cred.san_dns_names() {
            let result = if s.starts_with("*.") {
                self.upsert_wildcard(s, Arc::clone(&cred))
            } else {
                self.upsert_exact(s, Arc::clone(&cred))
            };
            match result {
                Ok(()) => {
                    if s.starts_with("*.") {
                        report.wildcard = report.wildcard.saturating_add(1);
                    } else {
                        report.exact = report.exact.saturating_add(1);
                    }
                }
                Err(_) => {
                    report.skipped = report.skipped.saturating_add(1);
                }
            }
        }
        report
    }

    /// Set the credential served when no name matches and when the peer sent no SNI.
    pub fn set_default(&mut self, cred: Arc<Credentials>) {
        self.default_cred = Some(cred);
    }

    /// Remove every pending entry whose stored name equals `name` after normalization, in
    /// **both** the exact and the wildcard groups. No-op if absent, and no-op if `name` fails
    /// normalization.
    ///
    /// `name` is the stored form, not the presentation form: to remove the entries added by
    /// `upsert_wildcard("*.example.com", _)` pass `"example.com"`, because that is what the
    /// wildcard map is keyed on. Passing `"*.example.com"` normalizes to an error and is a no-op.
    /// This method removes every key type for the name; there is no per-key-type removal.
    ///
    /// **It also clears the default credential when the credential being withdrawn is the one
    /// configured as the default.** Without this, a removal is not a withdrawal of trust at all:
    /// the entry disappears from the name maps, but `default_path()` keeps serving the very same
    /// `Arc<Credentials>` for the removed name and for every other name too, so a revoked or
    /// compromised certificate stays in service with nothing downstream to notice. That is the
    /// exact failure this module's "a removal is never dropped" rule exists to prevent, and the
    /// cap rule alone does not deliver it.
    pub fn remove(&mut self, name: &str) {
        let mut buf = [0u8; MAX_NAME_LEN];
        let Ok(normalized) = name::normalize(name, &mut buf) else {
            return;
        };
        // Identity is the fingerprint, not the `Arc` pointer: the same certificate loaded twice
        // is the same trust decision and must be withdrawn either way.
        if let Some(default) = self.default_cred.as_ref() {
            let default_fingerprint = default.fingerprint();
            let withdrawn = self.entries.iter().any(|(entry_name, _, cred)| {
                entry_name.as_ref() == normalized && cred.fingerprint() == default_fingerprint
            });
            if withdrawn {
                self.default_cred = None;
            }
        }
        self.entries
            .retain(|(entry_name, _, _)| entry_name.as_ref() != normalized);
    }

    /// Finish. Generation 0.
    ///
    /// # Errors
    /// `CertError::NameHashCollision` if three independent hash keys all collide, which is a
    /// probability-2e-29 event at n = 100,000 and indicates a bug if it ever fires.
    /// `CertError::IndexTooLarge` if the name arena would exceed `MAX_NAME_ARENA_BYTES` or the
    /// group count would exceed `MAX_INDEX_GROUPS`.
    pub fn build(self) -> Result<CertIndex, CertError> {
        self.build_with_generation(0)
    }

    /// Finish with an explicit generation number.
    ///
    /// # Errors
    /// As `build`.
    pub fn build_with_generation(mut self, generation: u64) -> Result<CertIndex, CertError> {
        let entries = core::mem::take(&mut self.entries);
        let seed = self.seed;
        let default_cred = self.default_cred.take();
        #[cfg(test)]
        let force_collision = self.force_collision_on_attempt_0;
        #[cfg(not(test))]
        let force_collision = false;
        #[cfg(test)]
        let arena_limit = self.max_arena_bytes;
        #[cfg(not(test))]
        let arena_limit = MAX_NAME_ARENA_BYTES;
        #[cfg(test)]
        let group_limit = self.max_groups;
        #[cfg(not(test))]
        let group_limit = MAX_INDEX_GROUPS;

        Self::build_inner(
            entries,
            group_limit,
            seed,
            self.inherited_hasher.as_ref(),
            force_collision,
            arena_limit,
            default_cred,
            generation,
        )
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "existing_idx is guarded by try_from above, and groups.len() was checked just \
                  before the attempt loop; the index is in range"
    )]
    fn build_inner(
        entries: Vec<PendingEntry>,
        max_groups: usize,
        seed: [u8; 16],
        inherited_hasher: Option<&NameHasher>,
        force_collision: bool,
        max_arena_bytes: usize,
        default_cred: Option<Arc<Credentials>>,
        generation: u64,
    ) -> Result<CertIndex, CertError> {
        let mut entries = entries;
        entries.sort_by(|(name_a, is_wild_a, cred_a), (name_b, is_wild_b, cred_b)| {
            let a = (
                is_wild_a,
                name_a,
                cred_a.key_type(),
                std::cmp::Reverse(cred_a.not_after()),
                cred_a.fingerprint(),
            );
            let b = (
                is_wild_b,
                name_b,
                cred_b.key_type(),
                std::cmp::Reverse(cred_b.not_after()),
                cred_b.fingerprint(),
            );
            a.cmp(&b)
        });

        let mut groups = Vec::new(); // it-allow: hot-path-allocation reason: builder path, not resolve; one allocation per generation build
        let mut drain = entries.drain(..).peekable();
        while let Some((name, is_wild, first_cred)) = drain.next() {
            let mut creds = vec![(first_cred.key_type(), first_cred)]; // it-allow: hot-path-allocation reason: builder path, not resolve; groups the sorted entries for one name
            while let Some((next_name, next_is_wild, next_cred)) = drain.peek() {
                if next_name == &name && next_is_wild == &is_wild {
                    let kt = next_cred.key_type();
                    if !creds.iter().any(|(k, _)| *k == kt) {
                        creds.push((kt, Arc::clone(next_cred)));
                    }
                    let _ = drain.next();
                } else {
                    break;
                }
            }
            groups.push(Group {
                is_wild,
                name,
                creds,
            });
        }

        if groups.len() > max_groups {
            return Err(CertError::IndexTooLarge);
        }

        'attempt: for attempt in 0u32..3 {
            let hasher = match inherited_hasher {
                Some(prev_hasher) => {
                    Self::hasher_for_attempt_from_previous(prev_hasher, force_collision, attempt)?
                }
                None => Self::hasher_for_attempt_inner(seed, force_collision, attempt),
            };
            let mut exact = HashMap::with_capacity_and_hasher(groups.len(), NameKeyHashBuilder);
            let mut wild = HashMap::with_capacity_and_hasher(groups.len(), NameKeyHashBuilder);
            for (i, group) in groups.iter().enumerate() {
                let key = hasher.hash(&group.name);
                let idx = CredSetIdx(u32::try_from(i).map_err(|_| CertError::IndexTooLarge)?);
                let map = if group.is_wild { &mut wild } else { &mut exact };
                match map.entry(key) {
                    std::collections::hash_map::Entry::Occupied(e) => {
                        let existing: CredSetIdx = *e.get();
                        let existing_idx =
                            usize::try_from(existing.0).map_err(|_| CertError::IndexTooLarge)?;
                        if groups[existing_idx].name != group.name {
                            continue 'attempt;
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(idx);
                    }
                }
            }
            return Self::build_index_finish(
                &groups,
                exact,
                wild,
                hasher,
                max_arena_bytes,
                default_cred,
                generation,
            );
        }

        Err(CertError::NameHashCollision)
    }

    #[allow(
        unused_variables,
        reason = "seed is used on every production path; only the test-only forced-collision early return skips it"
    )]
    fn hasher_for_attempt_inner(seed: [u8; 16], force_collision: bool, attempt: u32) -> NameHasher {
        #[cfg(test)]
        if force_collision && attempt == 0 {
            return NameHasher::degenerate_for_test();
        }
        let mut input = [0u8; 20];
        input[..16].copy_from_slice(&seed);
        input[16..].copy_from_slice(&attempt.to_be_bytes());
        let digest = blake3::hash(&input);
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest.as_bytes()[..16]);
        NameHasher::new(key)
    }

    /// Attempt-0 hasher for a from-previous rebuild: the inherited key itself, so a `NameKey`
    /// computed for a name that was already indexed under it is identical to what the previous
    /// generation stored. Attempts 1 and 2 are reached only if a genuinely NEW entry (from an
    /// `Install` since the previous generation) collides with an existing name under the
    /// inherited key, at the same probability as any other cross-key collision; this branch is
    /// exercised by `from_previous_collision_retry_succeeds` via `force_collision_on_attempt_0`,
    /// which is the only way ordinary test data reaches it.
    ///
    /// `CertIndexBuilder::from_previous` is infallible by design (its signature is `-> Self`, not
    /// `-> Result<Self, _>`) and must never read the CSPRNG: this workspace's own rule is that an
    /// entropy failure is a fatal, visible error, never a silently substituted fixed key, and an
    /// infallible function has no way to surface a fatal error. So `from_previous` never touches
    /// `irontraffic_rand`; the read happens here instead, lazily, only on this otherwise-
    /// unreachable retry path, and its failure folds into the same `NameHashCollision` error the
    /// caller already handles for "the retry loop is exhausted", which this is a stricter version
    /// of (an entropy failure here is at least as fatal to indexing as a triple collision).
    #[allow(
        unused_variables,
        reason = "force_collision is read only in #[cfg(test)] builds; a plain build never \
                  reaches the branch that names it"
    )]
    fn hasher_for_attempt_from_previous(
        inherited: &NameHasher,
        force_collision: bool,
        attempt: u32,
    ) -> Result<NameHasher, CertError> {
        #[cfg(test)]
        if force_collision && attempt == 0 {
            return Ok(NameHasher::degenerate_for_test());
        }
        if attempt == 0 {
            return Ok(inherited.clone()); // it-allow: hot-path-allocation reason: builder path, not resolve; NameHasher::clone is a 16-byte key copy, not an allocation, but the plain `.clone()` spelling still matches this rule's text scan, the same reason ChallengeCertsBuilder::from_previous already carries this exact comment
        }
        let mut key = [0u8; 16];
        irontraffic_rand::SecureRng::fill(&mut key).map_err(|_| CertError::NameHashCollision)?;
        Ok(NameHasher::new(key))
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "slot is bounded by slot >= 4 break above and tags/idx are [u8;4]/[u32;4]; the \
                  inner `if slot >= 4 { break; }` guards against index-out-of-range"
    )]
    fn build_index_finish(
        groups: &[Group],
        exact: HashMap<NameKey, CredSetIdx, NameKeyHashBuilder>,
        wild: HashMap<NameKey, CredSetIdx, NameKeyHashBuilder>,
        hasher: NameHasher,
        max_arena_bytes: usize,
        default_cred: Option<Arc<Credentials>>,
        generation: u64,
    ) -> Result<CertIndex, CertError> {
        let mut names: Vec<u8> = Vec::new(); // it-allow: hot-path-allocation reason: builder path, not resolve; grows into the immutable names arena
        let mut name_refs = Vec::with_capacity(groups.len()); // it-allow: hot-path-allocation reason: builder path, not resolve; becomes the immutable name_refs slice
        let mut cred_sets = Vec::with_capacity(groups.len()); // it-allow: hot-path-allocation reason: builder path, not resolve; becomes the immutable cred_sets slice
        let mut creds: Vec<Arc<Credentials>> = Vec::new(); // it-allow: hot-path-allocation reason: builder path, not resolve; deduplicated Arc pointers for the immutable index
        let mut cred_ptr_to_idx: HashMap<*const Credentials, u32> = HashMap::new(); // it-allow: hot-path-allocation reason: builder path, not resolve; temporary deduplication table discarded after build

        for group in groups {
            let new_len = names
                .len()
                .checked_add(group.name.len())
                .ok_or(CertError::IndexTooLarge)?;
            if new_len > max_arena_bytes {
                return Err(CertError::IndexTooLarge);
            }

            let offset = u32::try_from(names.len()).map_err(|_| CertError::IndexTooLarge)?;
            let len = u16::try_from(group.name.len()).map_err(|_| CertError::IndexTooLarge)?;
            name_refs.push(NameRef { offset, len });
            names.extend_from_slice(group.name.as_bytes());

            let mut tags = [0u8; 4];
            let mut idx = [0u32; 4];
            let mut len_u8 = 0u8;
            for (slot, (kt, cred)) in group.creds.iter().enumerate() {
                if slot >= 4 {
                    break;
                }
                let ptr = Arc::as_ptr(cred);
                let cred_idx = if let Some(&existing) = cred_ptr_to_idx.get(&ptr) {
                    existing
                } else {
                    let new = u32::try_from(creds.len()).map_err(|_| CertError::IndexTooLarge)?;
                    cred_ptr_to_idx.insert(ptr, new);
                    creds.push(Arc::clone(cred));
                    new
                };
                tags[slot] = *kt as u8; // it-allow: unchecked-cast reason: KeyType is #[repr(u8)] with discriminants 1..=4, so the cast is exact
                idx[slot] = cred_idx;
                len_u8 = len_u8.checked_add(1).ok_or(CertError::IndexTooLarge)?;
            }
            cred_sets.push(CredSet {
                tags,
                idx,
                len: len_u8,
            });
        }

        Ok(CertIndex {
            hasher,
            exact,
            wild,
            names: names.into_boxed_slice(), // it-allow: hot-path-allocation reason: builder path, not resolve; converts the already-built Vec into the immutable index storage
            name_refs: name_refs.into_boxed_slice(), // it-allow: hot-path-allocation reason: builder path, not resolve; converts the already-built Vec into the immutable index storage
            cred_sets: cred_sets.into_boxed_slice(), // it-allow: hot-path-allocation reason: builder path, not resolve; converts the already-built Vec into the immutable index storage
            creds: creds.into_boxed_slice(), // it-allow: hot-path-allocation reason: builder path, not resolve; converts the already-built Vec into the immutable index storage
            default_cred,
            generation,
            stats: CertStats::default(),
            #[cfg(test)]
            wild_probe_count: AtomicU64::new(0),
            #[cfg(test)]
            exact_probe_count: AtomicU64::new(0),
            #[cfg(test)]
            names_examined: AtomicU64::new(0),
        })
    }

    /// Test seam that forces attempt 0 to use a degenerate hasher.
    #[cfg(test)]
    pub(crate) fn force_collision_on_attempt_0(&mut self) {
        self.force_collision_on_attempt_0 = true;
    }

    /// Test setter that lowers the per-builder arena limit.
    #[cfg(test)]
    pub(crate) fn set_max_arena_bytes_for_test(&mut self, n: usize) {
        self.max_arena_bytes = n;
    }

    /// Test setter that lowers the per-builder group limit.
    #[cfg(test)]
    pub(crate) fn set_max_groups_for_test(&mut self, n: usize) {
        self.max_groups = n;
    }
}

/// Result of `upsert_from_sans`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SanIndexReport {
    /// Names indexed as exact entries.
    pub exact: u16,
    /// Names indexed as wildcard entries.
    pub wildcard: u16,
    /// Names skipped because they failed validation or were too broad.
    pub skipped: u16,
}

impl CertIndex {
    /// Resolve a presented SNI to a credential.
    ///
    /// Performs exactly two hash probes and zero heap allocations, independent of the number of
    /// certificates in the store. Returns the explicitly configured default credential if both
    /// probes miss and a default exists, otherwise `None`, which means "fail the handshake".
    ///
    /// `sni` is passed exactly as the peer presented it; normalization happens here.
    #[must_use]
    pub fn resolve(&self, sni: &str, caps: ClientCaps) -> Option<&Arc<Credentials>> {
        let mut buf = [0u8; MAX_NAME_LEN];
        let Ok(name) = name::normalize(sni, &mut buf) else {
            self.stats.invalid_sni.fetch_add(1, Ordering::Relaxed);
            return self.default_path();
        };

        let key = self.hasher.hash(name);
        // Test-only probe counter; see the field doc. This is the ONE place `resolve` probes
        // `exact`.
        #[cfg(test)]
        self.exact_probe_count.fetch_add(1, Ordering::Relaxed);
        if let Some(&i) = self.exact.get(&key)
            && self.name_at(i) == name.as_bytes()
        {
            if let Some(c) = self.select(i, caps) {
                self.stats.exact_hits.fetch_add(1, Ordering::Relaxed);
                return Some(c);
            }
            self.stats.no_compatible_key.fetch_add(1, Ordering::Relaxed);
            return self.default_path();
        }

        let Some(parent) = name::parent(name) else {
            return self.default_path();
        };
        let wkey = self.hasher.hash(parent);
        // Test-only probe counter (issue #719's SHOULD_FIX); see the field doc on
        // `wild_probe_count`. This is the ONE place `resolve` probes `wild`.
        #[cfg(test)]
        self.wild_probe_count.fetch_add(1, Ordering::Relaxed);
        if let Some(&i) = self.wild.get(&wkey)
            && self.name_at(i) == parent.as_bytes()
        {
            if let Some(c) = self.select(i, caps) {
                self.stats.wildcard_hits.fetch_add(1, Ordering::Relaxed);
                return Some(c);
            }
            self.stats.no_compatible_key.fetch_add(1, Ordering::Relaxed);
            return self.default_path();
        }

        self.default_path()
    }

    /// The configured default credential, if any. Used by the no-SNI path.
    #[must_use]
    pub fn default_credential(&self) -> Option<&Arc<Credentials>> {
        self.default_cred.as_ref()
    }

    /// Whether the name that `resolve` would match for `sni` carries an ECDSA credential
    /// (`EcdsaP256` or `EcdsaP384`), ignoring client capabilities and ignoring the default
    /// credential.
    ///
    /// Repeats the same two probes as `resolve` and is allocation-free. It exists only for the
    /// `require_ecdsa_capable_clients` policy in issue
    /// `cert-resolver-and-acme-challenge-map` (#117), which must distinguish "the client forced us
    /// onto RSA although this name has an ECDSA credential" from "this name only has RSA". That
    /// check runs after a credential has already been selected and only when the flag is on and
    /// the selected credential is RSA, so the second lookup is off the common path.
    #[must_use]
    pub fn name_has_ecdsa(&self, sni: &str) -> bool {
        let mut buf = [0u8; MAX_NAME_LEN];
        let Ok(name) = name::normalize(sni, &mut buf) else {
            return false;
        };

        let key = self.hasher.hash(name);
        if let Some(&i) = self.exact.get(&key)
            && self.name_at(i) == name.as_bytes()
        {
            return self.cred_set_has_ecdsa(i);
        }

        if let Some(parent) = name::parent(name) {
            let wkey = self.hasher.hash(parent);
            if let Some(&i) = self.wild.get(&wkey)
                && self.name_at(i) == parent.as_bytes()
            {
                return self.cred_set_has_ecdsa(i);
            }
        }

        false
    }

    /// Number of distinct names indexed, exact plus wildcard.
    #[must_use]
    pub fn name_count(&self) -> usize {
        self.exact.len().saturating_add(self.wild.len())
    }

    /// Number of distinct credentials stored.
    #[must_use]
    pub fn credential_count(&self) -> usize {
        self.creds.len()
    }

    /// Total bytes held by the index structures, excluding certificate DER.
    /// Exported as `tls_cert_index_bytes`.
    ///
    /// Computed, not measured, from exactly these terms and no others:
    ///
    /// ```text
    /// exact.capacity() * (size_of::<NameKey>() + size_of::<CredSetIdx>() + 1)
    ///   + wild.capacity() * (size_of::<NameKey>() + size_of::<CredSetIdx>() + 1)
    ///   + names.len()
    ///   + name_refs.len() * size_of::<NameRef>()
    ///   + cred_sets.len() * size_of::<CredSet>()
    ///   + creds.len() * size_of::<Arc<Credentials>>()
    ///   + size_of::<CertIndex>()
    /// ```
    ///
    /// The `+ 1` per bucket is the hashbrown control byte. This is a reported figure and a test
    /// gate, not an allocator query; do not reach for `jemalloc` statistics or a custom allocator.
    #[must_use]
    pub fn index_bytes(&self) -> usize {
        let bucket_size = core::mem::size_of::<NameKey>()
            .saturating_add(core::mem::size_of::<CredSetIdx>())
            .saturating_add(1);
        let exact_bytes = self.exact.capacity().saturating_mul(bucket_size);
        let wild_bytes = self.wild.capacity().saturating_mul(bucket_size);
        exact_bytes
            .saturating_add(wild_bytes)
            .saturating_add(self.names.len())
            .saturating_add(
                self.name_refs
                    .len()
                    .saturating_mul(core::mem::size_of::<NameRef>()),
            )
            .saturating_add(
                self.cred_sets
                    .len()
                    .saturating_mul(core::mem::size_of::<CredSet>()),
            )
            .saturating_add(
                self.creds
                    .len()
                    .saturating_mul(core::mem::size_of::<Arc<Credentials>>()),
            )
            .saturating_add(core::mem::size_of::<CertIndex>())
    }

    /// Monotonic generation number, set by the builder.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Counters for the certificate path.
    #[must_use]
    pub fn stats(&self) -> &CertStats {
        &self.stats
    }

    /// Every indexed entry, flattened for a rebuild: the stored name, whether it lives in the
    /// wildcard map, and the credential. Allocates; runs off the hot path only.
    ///
    /// `pub(crate)` for `store::builder::CertIndexBuilder::from_previous`, which is a sibling
    /// module and cannot read `self.exact`, `self.wild`, `self.cred_sets`, `self.creds` or
    /// `self.name_refs` directly: every field on this struct is private to `index.rs`.
    ///
    /// Walks `0..self.name_refs.len()` directly rather than iterating `self.exact.values()` then
    /// `self.wild.values()`: `name_refs` and `cred_sets` are stored in the SAME sorted order
    /// `build_index_finish` wrote them in (`(is_wild, name, key_type, ...)`, exact groups first
    /// since `false < true`, so index `< self.exact.len()` is exact and the rest is wildcard),
    /// while a `HashMap`'s iteration order bears no relation to insertion order at all. This
    /// distinction is load-bearing, not stylistic: `from_previous`'s whole cost budget rests on
    /// `CertIndexBuilder::build_inner`'s stable sort seeing an ALREADY near-sorted input (about
    /// `E` comparisons rather than `E log E`), and the two hash maps would have handed it
    /// effectively random order instead, silently costing `E log E` regardless of which sort
    /// function ran. Walking the stored arrays by position is what actually delivers the ordering
    /// the design's own cost argument depends on.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "normalize() (crate::name) guarantees its output is ASCII, and every stored \
                  name came from normalize(); a failure here would be an index-corruption bug \
                  that must be loud rather than silently producing an empty rebuild"
    )]
    #[allow(
        clippy::indexing_slicing,
        reason = "i is bounded by 0..self.name_refs.len(), and cred_sets/name_refs are the same \
                  length by construction (build_index_finish pushes both together for every \
                  group); slot is bounded by set.len, itself capped at 4 by build_index_finish"
    )]
    pub(crate) fn rebuild_entries(&self) -> Vec<(Box<str>, bool, Arc<Credentials>)> {
        let mut out = Vec::with_capacity(self.cred_sets.len()); // it-allow: hot-path-allocation reason: builder path (from_previous), not resolve; runs once per rebuild
        let exact_count = self.exact.len();
        for i in 0..self.name_refs.len() {
            let r = &self.name_refs[i];
            let name_bytes = &self.names[r.offset as usize..r.offset as usize + r.len as usize];
            let name = core::str::from_utf8(name_bytes)
                .expect("names are ASCII by construction") // it-allow: no-panic reason: every stored name byte range was written by build_index_finish from a str that already passed name::normalize, which guarantees ASCII; a failure here is index corruption, not attacker input, and must be loud
                .to_owned() // it-allow: hot-path-allocation reason: builder path (from_previous), not resolve; the one byte copy from_previous's own design accepts
                .into_boxed_str(); // it-allow: hot-path-allocation reason: builder path (from_previous), not resolve; converts the already-allocated owned String into the Box<str> the pending list stores, no second allocation
            let is_wild = i >= exact_count;
            let set = &self.cred_sets[i];
            for slot in 0..usize::from(set.len) {
                out.push((
                    name.clone(), // it-allow: hot-path-allocation reason: builder path (from_previous), not resolve; shares the arena bytes already copied above across every key-type slot for this name
                    is_wild,
                    Arc::clone(&self.creds[set.idx[slot] as usize]),
                ));
            }
        }
        out
    }

    /// The name hasher key, so a rebuild inherits it and re-hashes nothing new: see
    /// `store::builder::CertIndexBuilder::from_previous`.
    #[must_use]
    pub(crate) fn hasher(&self) -> &NameHasher {
        &self.hasher
    }

    /// The configured default credential, for `store::builder::CertIndexBuilder::from_previous`
    /// to carry forward.
    #[must_use]
    pub(crate) fn default_cred(&self) -> Option<&Arc<Credentials>> {
        self.default_cred.as_ref()
    }

    /// Test-only: number of times `resolve` has probed the `wild` map on `self`. See the
    /// `wild_probe_count` field doc for why this exists.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn wild_probe_count_for_test(&self) -> u64 {
        self.wild_probe_count.load(Ordering::Relaxed)
    }

    /// Test-only: number of times `resolve` has probed the `exact` map on `self`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn exact_probe_count_for_test(&self) -> u64 {
        self.exact_probe_count.load(Ordering::Relaxed)
    }

    /// Test-only: stored names read for byte comparison. See the field doc.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn names_examined_for_test(&self) -> u64 {
        self.names_examined.load(Ordering::Relaxed)
    }

    /// The stored name bytes for a group. `i` came out of one of the two maps, so it is in range
    /// by construction; the builder is the only writer of both.
    #[allow(
        clippy::indexing_slicing,
        reason = "`i` came out of one of the two maps, so it is in range by construction; the \
                  builder is the only writer of both"
    )]
    fn name_at(&self, i: CredSetIdx) -> &[u8] {
        // Test-only; see the field doc. Every byte comparison against a stored name goes through
        // here, so this counts candidates examined per resolution.
        #[cfg(test)]
        self.names_examined.fetch_add(1, Ordering::Relaxed);
        let r = &self.name_refs[i.0 as usize];
        &self.names[r.offset as usize..r.offset as usize + r.len as usize]
    }

    /// The first credential in the group whose key type the client can verify, in `KeyType` rank
    /// order. `None` means "this name has no credential this client can use".
    #[allow(
        clippy::indexing_slicing,
        reason = "`i` came out of one of the two maps, so it is in range by construction; the \
                  builder is the only writer of both"
    )]
    fn select(&self, i: CredSetIdx, caps: ClientCaps) -> Option<&Arc<Credentials>> {
        let set = &self.cred_sets[i.0 as usize];
        for slot in 0..usize::from(set.len) {
            let ok = match set.tags[slot] {
                1 => caps.ecdsa_p256,
                2 => caps.ecdsa_p384,
                3 => caps.rsa,
                4 => caps.ed25519,
                _ => break,
            };
            if ok {
                return Some(&self.creds[set.idx[slot] as usize]);
            }
        }
        None
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "`i` came out of one of the two maps, so it is in range by construction; the \
                  builder is the only writer of both"
    )]
    fn cred_set_has_ecdsa(&self, i: CredSetIdx) -> bool {
        let set = &self.cred_sets[i.0 as usize];
        for slot in 0..usize::from(set.len) {
            let t = set.tags[slot];
            if t == 1 || t == 2 {
                return true;
            }
        }
        false
    }

    fn default_path(&self) -> Option<&Arc<Credentials>> {
        if let Some(c) = &self.default_cred {
            self.stats.default_used.fetch_add(1, Ordering::Relaxed);
            Some(c)
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

// CertIndex is Send + Sync by construction: all its fields are Send + Sync (HashMap, Box, Arc,
// AtomicU64). The auto-derive is correct; the unsafe manual impls that preceded this comment had
// to be removed because the crate denies `unsafe` code.

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Once, OnceLock};

    use proptest::prelude::*;

    use super::{CertError, CertIndex, CertIndexBuilder, ClientCaps, Credentials};
    use crate::store::ChainInterner;

    fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or crate::provider::tests::provider_lifecycle's own call installs the process-wide provider; either outcome (Ok or AlreadyInstalled) leaves a provider installed, which is all this helper promises.
        });
    }

    fn gen_cred_with_times(
        alg: &'static rcgen::SignatureAlgorithm,
        sans: &[&str],
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> Arc<Credentials> {
        ensure_provider_installed();
        let mut params =
            rcgen::CertificateParams::new(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .expect("valid SANs");
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = rcgen::KeyPair::generate_for(alg).expect("keygen");
        let cert = params.self_signed(&key).expect("sign");
        let mut interner = ChainInterner::new();
        Arc::new(
            Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                .expect("valid leaf and key"),
        )
    }

    fn gen_cred(alg: &'static rcgen::SignatureAlgorithm, sans: &[&str]) -> Arc<Credentials> {
        gen_cred_with_times(alg, sans, (2025, 1, 1), (2030, 1, 1))
    }

    fn cred_ecdsa_p256(sans: &[&str]) -> Arc<Credentials> {
        gen_cred(&rcgen::PKCS_ECDSA_P256_SHA256, sans)
    }

    fn cred_ecdsa_p384(sans: &[&str]) -> Arc<Credentials> {
        gen_cred(&rcgen::PKCS_ECDSA_P384_SHA384, sans)
    }

    fn cred_rsa(sans: &[&str]) -> Arc<Credentials> {
        gen_cred(&rcgen::PKCS_RSA_SHA256, sans)
    }

    fn cred_ed25519(sans: &[&str]) -> Arc<Credentials> {
        gen_cred(&rcgen::PKCS_ED25519, sans)
    }

    fn cred_p256_2030(sans: &[&str]) -> Arc<Credentials> {
        gen_cred_with_times(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            sans,
            (2025, 1, 1),
            (2030, 1, 1),
        )
    }

    fn cred_p256_2027(sans: &[&str]) -> Arc<Credentials> {
        gen_cred_with_times(
            &rcgen::PKCS_ECDSA_P256_SHA256,
            sans,
            (2025, 1, 1),
            (2027, 1, 1),
        )
    }

    fn build_index(names: &[(&str, bool, Arc<Credentials>)]) -> CertIndex {
        let mut builder = CertIndexBuilder::new([1u8; 16]);
        for (name, is_wild, cred) in names {
            if *is_wild {
                builder
                    .upsert_wildcard(name, Arc::clone(cred))
                    .expect("valid wildcard");
            } else {
                builder
                    .upsert_exact(name, Arc::clone(cred))
                    .expect("valid exact");
            }
        }
        builder.build().expect("build succeeds")
    }

    #[test]
    fn resolve_empty_index() {
        let index = CertIndexBuilder::new([1u8; 16]).build().expect("build");
        assert!(index.resolve("a.example.com", ClientCaps::all()).is_none());
        assert_eq!(index.stats().misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_single_exact_hit() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let index = build_index(&[("a.example.com", false, Arc::clone(&cred))]);
        let got = index.resolve("a.example.com", ClientCaps::all());
        assert_eq!(got.map(|c| c.fingerprint()), Some(cred.fingerprint()));
        assert_eq!(index.stats().exact_hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_empty_sni() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let index = build_index(&[("a.example.com", false, cred)]);
        assert!(index.resolve("", ClientCaps::all()).is_none());
        assert_eq!(index.stats().invalid_sni.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_invalid_sni() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let index = build_index(&[("a.example.com", false, cred)]);
        assert!(
            index
                .resolve("b\u{00fc}.example.com", ClientCaps::all())
                .is_none()
        );
        assert_eq!(index.stats().invalid_sni.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_single_label() {
        let cred = cred_ecdsa_p256(&["localhost"]);
        let index = build_index(&[("localhost", false, cred)]);
        assert!(index.resolve("localhost", ClientCaps::all()).is_some());
        assert_eq!(index.stats().wildcard_hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn resolve_wildcard_does_not_match_parent() {
        let cred = cred_ecdsa_p256(&["*.example.com"]);
        let index = build_index(&[("*.example.com", true, cred)]);
        assert!(index.resolve("example.com", ClientCaps::all()).is_none());
    }

    #[test]
    fn resolve_wildcard_does_not_match_grandchild() {
        let cred = cred_ecdsa_p256(&["*.example.com"]);
        let index = build_index(&[("*.example.com", true, cred)]);
        assert!(
            index
                .resolve("a.b.example.com", ClientCaps::all())
                .is_none()
        );
    }

    #[test]
    fn resolve_wildcard_matches_child() {
        let cred = cred_ecdsa_p256(&["*.example.com"]);
        let index = build_index(&[("*.example.com", true, Arc::clone(&cred))]);
        let got = index.resolve("a.example.com", ClientCaps::all());
        assert_eq!(got.map(|c| c.fingerprint()), Some(cred.fingerprint()));
        assert_eq!(index.stats().wildcard_hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_exact_beats_wildcard() {
        let cred_a = cred_ecdsa_p256(&["a.example.com"]);
        let cred_w = cred_rsa(&["*.example.com"]);
        let index = build_index(&[
            ("a.example.com", false, Arc::clone(&cred_a)),
            ("*.example.com", true, cred_w),
        ]);
        let got = index.resolve("a.example.com", ClientCaps::all());
        assert_eq!(got.map(|c| c.fingerprint()), Some(cred_a.fingerprint()));
        assert_eq!(index.stats().wildcard_hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn resolve_incompatible_caps_does_not_fall_through() {
        let cred_exact = cred_rsa(&["a.example.com"]);
        let cred_wild = cred_ecdsa_p256(&["*.example.com"]);
        let index = build_index(&[
            ("a.example.com", false, Arc::clone(&cred_exact)),
            ("*.example.com", true, cred_wild),
        ]);
        let got = index.resolve(
            "a.example.com",
            ClientCaps {
                ecdsa_p256: true,
                ..Default::default()
            },
        );
        assert!(got.is_none());
        assert_eq!(index.stats().no_compatible_key.load(Ordering::Relaxed), 1);
        assert_eq!(index.stats().wildcard_hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn resolve_empty_caps() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let index = build_index(&[("a.example.com", false, cred)]);
        assert!(
            index
                .resolve("a.example.com", ClientCaps::default())
                .is_none()
        );
    }

    #[test]
    fn resolve_four_key_types() {
        let creds = [
            cred_ecdsa_p256(&["a.example.com"]),
            cred_ecdsa_p384(&["a.example.com"]),
            cred_rsa(&["a.example.com"]),
            cred_ed25519(&["a.example.com"]),
        ];
        let mut builder = CertIndexBuilder::new([1u8; 16]);
        for cred in &creds {
            builder
                .upsert_exact("a.example.com", Arc::clone(cred))
                .expect("valid");
        }
        let index = builder.build().expect("build");

        let cases = [
            (
                ClientCaps {
                    ecdsa_p256: true,
                    ..Default::default()
                },
                creds[0].fingerprint(),
            ),
            (
                ClientCaps {
                    ecdsa_p384: true,
                    ..Default::default()
                },
                creds[1].fingerprint(),
            ),
            (
                ClientCaps {
                    rsa: true,
                    ..Default::default()
                },
                creds[2].fingerprint(),
            ),
            (
                ClientCaps {
                    ed25519: true,
                    ..Default::default()
                },
                creds[3].fingerprint(),
            ),
        ];
        for (caps, expected) in cases {
            let got = index.resolve("a.example.com", caps);
            assert_eq!(got.map(|c| c.fingerprint()), Some(expected));
        }
    }

    #[test]
    fn resolve_duplicate_keytype_later_expiry_wins() {
        let cred_2030 = cred_p256_2030(&["a.example.com"]);
        let cred_2027 = cred_p256_2027(&["a.example.com"]);
        let index = build_index(&[
            ("a.example.com", false, Arc::clone(&cred_2027)),
            ("a.example.com", false, Arc::clone(&cred_2030)),
        ]);
        let got = index.resolve("a.example.com", ClientCaps::all());
        assert_eq!(got.map(|c| c.fingerprint()), Some(cred_2030.fingerprint()));
    }

    #[test]
    fn resolve_shared_credential_stored_once() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let mut builder = CertIndexBuilder::new([1u8; 16]);
        for i in 0..500 {
            let name = format!("host{i}.example.com");
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        let index = builder.build().expect("build");
        assert_eq!(index.credential_count(), 1);
        for i in 0..500 {
            let name = format!("host{i}.example.com");
            let got = index.resolve(&name, ClientCaps::all());
            assert_eq!(got.map(|c| c.fingerprint()), Some(cred.fingerprint()));
        }
    }

    #[test]
    fn resolve_case_and_trailing_dot() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let index = build_index(&[("a.example.com", false, Arc::clone(&cred))]);
        let lower = index.resolve("a.example.com", ClientCaps::all());
        let upper = index.resolve("A.Example.COM.", ClientCaps::all());
        assert_eq!(
            lower.map(|c| c.fingerprint()),
            upper.map(|c| c.fingerprint())
        );
        assert_eq!(lower.map(|c| c.fingerprint()), Some(cred.fingerprint()));
    }

    #[test]
    fn resolve_wildcard_branch_probes_wild_map_exactly_once() {
        // #115's thesis is "exactly two hash probes ... exactly one wildcard probe", and its Do
        // NOT list is explicit: "Do NOT walk every suffix of the SNI." Issue #719 found that
        // nothing in this suite discriminates that claim from an Envoy style O(k) suffix walk:
        // a walk that probes `wild` once per label, and only accepts a hit at the immediate
        // parent, returns the exact same credential for every case above and leaves the whole
        // suite green. This test counts `wild` probes directly instead of inferring them from
        // the answer, over a deep name (8 labels) so a per-label walk would need several probes
        // where the two-probe design needs exactly one.
        let cred = cred_ecdsa_p256(&["*.b.c.d.e.f.g.h"]);
        let index = build_index(&[("*.b.c.d.e.f.g.h", true, Arc::clone(&cred))]);

        assert_eq!(index.wild_probe_count_for_test(), 0);
        let got = index.resolve("a.b.c.d.e.f.g.h", ClientCaps::all());
        assert_eq!(got.map(|c| c.fingerprint()), Some(cred.fingerprint()));
        assert_eq!(
            index.wild_probe_count_for_test(),
            1,
            "resolve must perform exactly one wild-map probe per call, independent of how many \
             labels the SNI carries; a suffix walk would probe once per label instead"
        );

        let _ = index.resolve("a.b.c.d.e.f.g.h", ClientCaps::all());
        assert_eq!(
            index.wild_probe_count_for_test(),
            2,
            "a second resolve call must add exactly one more probe, not accumulate walk cost"
        );
    }

    #[test]
    fn resolve_name_has_ecdsa() {
        let cred_p256 = cred_ecdsa_p256(&["a.example.com"]);
        let cred_rsa = cred_rsa(&["b.example.com"]);
        let index = build_index(&[
            ("a.example.com", false, cred_p256),
            ("b.example.com", false, cred_rsa),
        ]);
        assert!(index.name_has_ecdsa("a.example.com"));
        assert!(!index.name_has_ecdsa("b.example.com"));
        assert!(!index.name_has_ecdsa("missing.example.com"));
    }

    #[allow(
        clippy::integer_division,
        reason = "timing median: coarse-grained nanosecond-per-call average from total elapsed"
    )]
    /// Resolution cost does not grow with the number of names in the index.
    ///
    /// Asserted deterministically, on work counted rather than on a clock, because a wall-clock
    /// version of this ran in parallel with two hundred other tests and failed intermittently,
    /// blocking `gate-fast` at random (#750). But the counter has to be the RIGHT one, and the
    /// first attempt at this fix got that wrong in an instructive way, so both are asserted here:
    ///
    /// * `names_examined` is the n-SENSITIVE quantity and is what makes the `n` sweep below
    ///   load-bearing. A correct lookup confirms exactly ONE candidate name whatever the index
    ///   holds. Any implementation that searches names to find the answer, which is what an O(n)
    ///   regression looks like in practice, examines more of them as `n` grows.
    /// * the probe counts are the STRUCTURAL quantity: one `exact` probe, and for an exact hit no
    ///   `wild` probe at all. That is #115's "exactly two hash probes ... exactly one wildcard
    ///   probe" and "Do NOT walk every suffix of the SNI", and it discriminates an Envoy-style
    ///   suffix walk that returns the correct credential while probing a different number of
    ///   times. Probe counts alone, however, are fully determined at `n = 1` and can NOT see
    ///   n-scaling; asserting only those was the first fix's mistake.
    ///
    /// Honest limit, stated because the next reader will otherwise assume more: these count
    /// instrumented work. Cost added on a path that touches neither the maps nor a stored name is
    /// invisible here, and no assertion in this suite would catch it. The wall-clock check that
    /// could is tracked in #753 for a serialized perf job. Parking it as a skipped test was not
    /// an option: a test that does not run in CI guarantees nothing, and this repo has an
    /// invariant lint that says exactly that.
    #[test]
    fn resolve_flat_across_n() {
        const CALLS: u64 = 1_000;

        let cred = cred_ecdsa_p256(&["example.com"]);
        let ns = [1usize, 100, 10_000, 100_000];
        let mut examined_per_call = Vec::with_capacity(ns.len());
        let mut exact_probes_per_call = Vec::with_capacity(ns.len());
        for &n in &ns {
            let mut builder = CertIndexBuilder::new([2u8; 16]);
            for i in 0..n {
                let name = format!("host{i}.example.com");
                builder
                    .upsert_exact(&name, Arc::clone(&cred))
                    .expect("valid");
            }
            let index = builder.build().expect("build");
            let query = format!("host{}.example.com", n / 2);

            for _ in 0..CALLS {
                assert!(
                    index.resolve(&query, ClientCaps::all()).is_some(),
                    "n={n}: the query must actually resolve, or this counts work on the miss path"
                );
            }
            assert_eq!(
                index.wild_probe_count_for_test(),
                0,
                "n={n}: an exact hit must never probe the wildcard map"
            );
            examined_per_call.push(index.names_examined_for_test() / CALLS);
            exact_probes_per_call.push(index.exact_probe_count_for_test() / CALLS);
        }

        // Pinned against LITERALS, not against the vectors' own first elements: comparing a
        // vector to its own head is satisfied by any constant, including a constant that grew.
        assert_eq!(
            examined_per_call,
            vec![1u64, 1, 1, 1],
            "one candidate name confirmed per resolution at every n; anything else means \
             resolution now searches names and therefore scales with index size"
        );
        assert_eq!(
            exact_probes_per_call,
            vec![1u64, 1, 1, 1],
            "exactly one exact-map probe per resolution at every n"
        );
    }

    #[test]
    fn build_100k_index_bytes_under_10mb() {
        let cred = cred_ecdsa_p256(&["example.com"]);
        let mut builder = CertIndexBuilder::new([3u8; 16]);
        for i in 0..100_000 {
            let name = format!("host{i}.example.com");
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        for i in 0..1_000 {
            let name = format!("wild{i}.example.com");
            builder
                .upsert_wildcard(&format!("*.{name}"), Arc::clone(&cred))
                .expect("valid");
        }
        let index = builder.build().expect("build");
        assert!(index.index_bytes() < 10 * 1024 * 1024);
    }

    #[test]
    fn builder_rejects_wildcard_too_broad() {
        let cred = cred_ecdsa_p256(&["example.com"]);
        let mut builder = CertIndexBuilder::new([4u8; 16]);
        assert_eq!(
            builder.upsert_wildcard("*.com", Arc::clone(&cred)),
            Err(CertError::WildcardTooBroad)
        );
        assert_eq!(
            builder.upsert_wildcard("*", Arc::clone(&cred)),
            Err(CertError::WildcardTooBroad)
        );
        assert_eq!(
            builder.upsert_wildcard("*.co.uk", Arc::clone(&cred)),
            Err(CertError::WildcardTooBroad)
        );
    }

    #[test]
    fn builder_rejects_partial_wildcard() {
        let cred = cred_ecdsa_p256(&["example.com"]);
        let mut builder = CertIndexBuilder::new([5u8; 16]);
        assert!(matches!(
            builder.upsert_wildcard("*a.example.com", Arc::clone(&cred)),
            Err(CertError::Wildcard(_))
        ));
        assert!(matches!(
            builder.upsert_wildcard("a.*.example.com", Arc::clone(&cred)),
            Err(CertError::Wildcard(_))
        ));
    }

    #[test]
    fn builder_collision_retry_succeeds() {
        let cred = cred_ecdsa_p256(&["example.com"]);
        let mut builder = CertIndexBuilder::new([6u8; 16]);
        builder.force_collision_on_attempt_0();
        for i in 0..100 {
            let name = format!("host{i}.example.com");
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        let index = builder.build().expect("build succeeds on retry");
        for i in 0..100 {
            let name = format!("host{i}.example.com");
            assert!(index.resolve(&name, ClientCaps::all()).is_some());
        }
    }

    #[test]
    fn build_is_byte_identical_for_identical_input() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let make_index = || {
            let mut builder = CertIndexBuilder::new([7u8; 16]);
            builder
                .upsert_exact("a.example.com", Arc::clone(&cred))
                .expect("valid");
            builder
                .upsert_exact("b.example.com", Arc::clone(&cred))
                .expect("valid");
            builder
                .upsert_wildcard("*.c.example.com", Arc::clone(&cred))
                .expect("valid");
            builder.build().expect("build")
        };
        let a = make_index();
        let b = make_index();
        assert_eq!(a.names, b.names);
        assert_eq!(a.name_refs, b.name_refs);
        assert_eq!(a.cred_sets.len(), b.cred_sets.len());
        assert_eq!(a.exact.len(), b.exact.len());
        assert_eq!(a.wild.len(), b.wild.len());
        for (k, va) in &a.exact {
            assert_eq!(b.exact.get(k), Some(va));
        }
        for (k, va) in &a.wild {
            assert_eq!(b.wild.get(k), Some(va));
        }
    }

    #[test]
    fn builder_rejects_oversize_arena() {
        let cred = cred_ecdsa_p256(&["example.com"]);
        let mut builder = CertIndexBuilder::new([8u8; 16]);
        builder.set_max_arena_bytes_for_test(64);
        for i in 0..3 {
            let name = format!("this-is-a-30-byte-name-{i}.example.com");
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        assert!(matches!(builder.build(), Err(CertError::IndexTooLarge)));

        let mut builder = CertIndexBuilder::new([8u8; 16]);
        builder.set_max_groups_for_test(2);
        for i in 0..3 {
            let name = format!("host{i}.example.com");
            builder
                .upsert_exact(&name, Arc::clone(&cred))
                .expect("valid");
        }
        assert!(matches!(builder.build(), Err(CertError::IndexTooLarge)));
    }

    #[test]
    fn builder_new_from_entropy_seeds_differ() {
        let cred = cred_ecdsa_p256(&["a.example.com"]);
        let mut builder_a = CertIndexBuilder::new_from_entropy().expect("entropy");
        builder_a
            .upsert_exact("a.example.com", Arc::clone(&cred))
            .expect("valid");
        let index_a = builder_a.build().expect("build");

        let mut builder_b = CertIndexBuilder::new_from_entropy().expect("entropy");
        builder_b
            .upsert_exact("a.example.com", Arc::clone(&cred))
            .expect("valid");
        let index_b = builder_b.build().expect("build");

        assert_ne!(
            index_a.hasher.hash("a.example.com"),
            index_b.hasher.hash("a.example.com")
        );
    }

    fn naive_label_count(name: &str) -> usize {
        name.bytes().filter(|&b| b == b'.').count() + 1
    }

    struct RefEntry {
        name: String,
        is_wild: bool,
        cred: Arc<Credentials>,
    }

    fn shared_key() -> &'static Arc<rcgen::KeyPair> {
        static KEY: OnceLock<Arc<rcgen::KeyPair>> = OnceLock::new();
        KEY.get_or_init(|| {
            ensure_provider_installed();
            Arc::new(rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen"))
        })
    }

    fn cred_for_san(san: &str) -> Arc<Credentials> {
        let key = shared_key();
        let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
        let cert = params.self_signed(&**key).expect("sign");
        let mut interner = ChainInterner::new();
        Arc::new(
            Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                .expect("valid leaf and key"),
        )
    }

    fn naive_resolve(entries: &[RefEntry], query: &str) -> Option<crate::store::CertFingerprint> {
        for e in entries {
            if !e.is_wild && e.name == query {
                return Some(e.cred.fingerprint());
            }
        }
        for e in entries {
            if e.is_wild {
                let parent = &e.name[2..];
                if query.len() > parent.len() + 1
                    && query.ends_with(&format!(".{parent}"))
                    && naive_label_count(query) == naive_label_count(parent) + 1
                {
                    return Some(e.cred.fingerprint());
                }
            }
        }
        None
    }

    fn name_strategy() -> impl Strategy<Value = String> {
        "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?){1,4}"
    }

    fn cred_for_key_type(t: u8) -> &'static Arc<Credentials> {
        static P256: OnceLock<Arc<Credentials>> = OnceLock::new();
        static P384: OnceLock<Arc<Credentials>> = OnceLock::new();
        static RSA: OnceLock<Arc<Credentials>> = OnceLock::new();
        static ED25519: OnceLock<Arc<Credentials>> = OnceLock::new();
        match t {
            1 => P256.get_or_init(|| cred_ecdsa_p256(&["rank.example.com"])),
            2 => P384.get_or_init(|| cred_ecdsa_p384(&["rank.example.com"])),
            3 => RSA.get_or_init(|| cred_rsa(&["rank.example.com"])),
            4 => ED25519.get_or_init(|| cred_ed25519(&["rank.example.com"])),
            _ => unreachable!(),
        }
    }

    proptest! {
        #[test]
        fn prop_resolve_agrees_with_naive_reference(
            raw_entries in prop::collection::vec((any::<bool>(), name_strategy()), 1..50),
            queries in prop::collection::vec(name_strategy(), 200),
        ) {
            let mut seen = std::collections::HashSet::new();
            let mut builder = CertIndexBuilder::new([9u8; 16]);
            let mut ref_entries: Vec<RefEntry> = Vec::new();
            for (is_wild, name) in raw_entries {
                let full_name = if is_wild { format!("*.{name}") } else { name };
                if !seen.insert(full_name.clone()) {
                    continue;
                }
                let cred = cred_for_san(&full_name);
                let result = if is_wild {
                    builder.upsert_wildcard(&full_name, Arc::clone(&cred))
                } else {
                    builder.upsert_exact(&full_name, Arc::clone(&cred))
                };
                if result.is_ok() {
                    ref_entries.push(RefEntry { name: full_name, is_wild, cred });
                }
            }

            let index = builder.build().expect("build succeeds");
            for q in &queries {
                let expected = naive_resolve(&ref_entries, q);
                let got = index.resolve(q, ClientCaps::all()).map(|c| c.fingerprint());
                prop_assert_eq!(got, expected, "query={}", q);
            }
        }

        #[test]
        fn prop_no_wildcard_matches_own_parent(
            raw in prop::collection::vec(name_strategy(), 1..30),
        ) {
            let mut builder = CertIndexBuilder::new([10u8; 16]);
            let mut creds = Vec::new();
            for name in &raw {
                let full = format!("*.{name}");
                let cred = cred_for_san(&full);
                if builder.upsert_wildcard(&full, Arc::clone(&cred)).is_ok() {
                    creds.push((name.clone(), cred));
                }
            }
            let index = builder.build().expect("build succeeds");
            for (parent, cred) in &creds {
                let got = index.resolve(parent, ClientCaps::all());
                prop_assert_ne!(got.map(|c| c.fingerprint()), Some(cred.fingerprint()));
            }
        }

        #[test]
        fn prop_no_wildcard_matches_grandchild(
            wild_parents in prop::collection::vec(name_strategy(), 1..20),
            prefixes in prop::collection::vec(name_strategy(), 1..20),
        ) {
            let mut builder = CertIndexBuilder::new([11u8; 16]);
            let mut creds = Vec::new();
            for parent in &wild_parents {
                let full = format!("*.{parent}");
                let cred = cred_for_san(&full);
                if builder.upsert_wildcard(&full, Arc::clone(&cred)).is_ok() {
                    creds.push((parent.clone(), cred));
                }
            }
            let index = builder.build().expect("build succeeds");
            for (parent, cred) in &creds {
                for prefix in &prefixes {
                    let query = format!("{prefix}.{parent}");
                    if naive_label_count(&query) != naive_label_count(parent) + 2 {
                        continue;
                    }
                    let got = index.resolve(&query, ClientCaps::all());
                    prop_assert_ne!(got.map(|c| c.fingerprint()), Some(cred.fingerprint()),
                        "query={} parent={}", query, parent);
                }
            }
        }

        #[test]
        fn prop_case_and_dot_insensitive(
            names in prop::collection::vec(name_strategy(), 1..30),
            upper_mask in prop::collection::vec(any::<bool>(), 0..300),
        ) {
            let mut builder = CertIndexBuilder::new([12u8; 16]);
            let mut creds = std::collections::HashMap::new();
            for name in &names {
                let cred = cred_for_san(name);
                if builder.upsert_exact(name, Arc::clone(&cred)).is_ok() {
                    creds.insert(name.clone(), cred);
                }
            }
            let index = builder.build().expect("build succeeds");
            for name in creds.keys() {
                let mut permuted = String::with_capacity(name.len() + 1);
                for (i, c) in name.chars().enumerate() {
                    if upper_mask.get(i).copied().unwrap_or(false) && c.is_ascii_lowercase() {
                        permuted.push(c.to_ascii_uppercase());
                    } else {
                        permuted.push(c);
                    }
                }
                permuted.push('.');
                let a = index.resolve(name, ClientCaps::all());
                let b = index.resolve(&permuted, ClientCaps::all());
                prop_assert_eq!(a.map(|c| c.fingerprint()), b.map(|c| c.fingerprint()));
            }
        }

        #[test]
        fn prop_select_respects_rank(
            key_types in prop::collection::hash_set(1u8..=4u8, 1..=4),
            caps_bits in 0u8..=15u8,
        ) {
            let mut builder = CertIndexBuilder::new([13u8; 16]);
            let mut present = Vec::new();
            for &t in &key_types {
                let cred = Arc::clone(cred_for_key_type(t));
                builder.upsert_exact("rank.example.com", cred).expect("valid");
                present.push(t);
            }
            let index = builder.build().expect("build succeeds");
            let caps = ClientCaps {
                ecdsa_p256: caps_bits & 1 != 0,
                ecdsa_p384: caps_bits & 2 != 0,
                rsa: caps_bits & 4 != 0,
                ed25519: caps_bits & 8 != 0,
            };
            let result = index.resolve("rank.example.com", caps);
            let enabled: Vec<u8> = present
                .iter()
                .copied()
                .filter(|&t| match t {
                    1 => caps.ecdsa_p256,
                    2 => caps.ecdsa_p384,
                    3 => caps.rsa,
                    4 => caps.ed25519,
                    _ => false,
                })
                .collect();
            if enabled.is_empty() {
                prop_assert!(result.is_none());
            } else {
                let expected = *enabled.iter().min().expect("non-empty");
                let got = result.expect("some credential").key_type() as u8;
                prop_assert_eq!(got, expected);
            }
        }
    }
}
