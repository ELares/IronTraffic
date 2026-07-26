// SPDX-License-Identifier: MIT OR Apache-2.0

//! Content-addressed interning of non-leaf certificate chain DER blobs.
//!
//! rustls's `CertificateDer<'static>` can only share bytes through a `'static` borrow: it has
//! no reference-counted variant, so the only way for many certificate chains to share one copy
//! of a common intermediate is to leak that intermediate's bytes exactly once and hand out
//! `&'static [u8]` borrows of it forever after. [`ChainInterner`] is that leak, made bounded and
//! explicit: at most [`MAX_DER_BYTES`] bytes per blob, and at most `max_blobs` distinct blobs
//! for the life of the process (default 4096, so the worst case is 4096 * 64 KiB = 256 MiB and
//! the realistic case, since real CAs reuse a handful of intermediates across every leaf they
//! issue, is a few dozen kilobytes). There is no `remove` and no `clear`: a partial free of a
//! leaked `'static` borrow would be a dangling reference, which is unsound and would need
//! `unsafe`, which this workspace denies with no exception.
//!
//! **Hash choice, and why it is safe even if the hash is wrong.** [`BlobHash`] is BLAKE3-256
//! truncated to 128 bits. Truncating to 128 bits keeps full 128-bit preimage resistance but
//! drops accidental-collision resistance to a 2^64 birthday bound, so this hash is a bucket
//! key for `O(1)` average lookup, never a proof of identity on its own. [`ChainInterner::intern`]
//! never trusts a hash match by itself: on every hash hit it compares the stored bytes against
//! the new blob byte for byte, and returns [`CertError::BlobHashCollision`] rather than the
//! stored pointer if they differ. That comparison, not the hash, is what makes certificate
//! confusion (two different chains resolving to the same stored bytes) impossible here: even a
//! genuine BLAKE3 collision is caught and refused, never silently treated as equality. The
//! inputs to this hash are also not attacker-reachable in the first place: chains enter only
//! through config compile and the ACME reconciler, never from a peer's handshake, so unlike
//! [`crate::name::NameHasher`]'s keyed hash over peer-controlled SNI names, there is no offline
//! collision-search incentive to key this one against.

use std::collections::HashMap;

use super::cred::CertError;

/// Maximum bytes in a single DER blob we will accept.
pub const MAX_DER_BYTES: usize = 65_536;

/// Default cap on the number of distinct blobs a [`ChainInterner`] will intern before refusing.
const DEFAULT_MAX_BLOBS: usize = 4096;

/// The first 16 bytes of a 32-byte digest, defensively: `full` is always exactly 32 bytes in
/// practice (it comes straight from `blake3::hash`), but this reads through a checked slice
/// rather than indexing so that fact never has to be re-verified for this to stay memory safe.
fn truncate16(full: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(head) = full.get(..16) {
        out.copy_from_slice(head);
    }
    out
}

/// BLAKE3-256 of a DER blob, truncated to 16 bytes.
///
/// A 128-bit digest gives 128-bit preimage resistance but only a 2^64 birthday bound on
/// collisions, so the truncated hash is a bucket key and not proof of equality: `intern`
/// compares the stored bytes on a hash hit before returning them.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct BlobHash([u8; 16]);

impl BlobHash {
    fn of(blob: &[u8]) -> Self {
        Self(truncate16(blake3::hash(blob).as_bytes()))
    }
}

/// Content-addressed store of non-leaf DER blobs.
///
/// Each distinct blob is leaked exactly once so that `CertificateDer<'static>` can borrow it,
/// which is what makes chain sharing possible at all. The number of distinct blobs is capped.
///
/// There is no `remove` and no `clear`: interned blobs live for the life of the process by
/// construction. A `ChainInterner` is created once per process and passed to every builder, so
/// two successive config generations that share intermediates share the leaked blobs and leak
/// nothing new.
pub struct ChainInterner {
    map: HashMap<BlobHash, &'static [u8]>,
    max_blobs: usize,
    leaked_bytes: u64,
    hits: u64,
}

impl ChainInterner {
    /// New interner with the default cap of 4096 distinct blobs.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity_limit(DEFAULT_MAX_BLOBS)
    }

    /// New interner with an explicit cap.
    #[must_use]
    pub fn with_capacity_limit(max_blobs: usize) -> Self {
        Self {
            map: HashMap::new(),
            max_blobs,
            leaked_bytes: 0,
            hits: 0,
        }
    }

    /// Intern one non-leaf DER blob, returning a `'static` borrow of the single stored copy.
    ///
    /// # Errors
    /// `CertError::EmptyDer`, `CertError::DerTooLarge`, `CertError::TooManyDistinctBlobs`, or
    /// `CertError::BlobHashCollision` on the (2^64 birthday bound) event that two distinct blobs
    /// hash to the same bucket; see the module docs for why that refusal, not the hash, is the
    /// actual safety property.
    pub fn intern(&mut self, blob: &[u8]) -> Result<&'static [u8], CertError> {
        if blob.is_empty() {
            return Err(CertError::EmptyDer);
        }
        if blob.len() > MAX_DER_BYTES {
            return Err(CertError::DerTooLarge);
        }

        let hash = BlobHash::of(blob);
        if let Some(&existing) = self.map.get(&hash) {
            // The hash matched; only a byte-for-byte comparison proves it is the same blob.
            if existing == blob {
                self.hits = self.hits.saturating_add(1);
                return Ok(existing);
            }
            return Err(CertError::BlobHashCollision);
        }

        if self.map.len() >= self.max_blobs {
            return Err(CertError::TooManyDistinctBlobs);
        }

        let leaked: &'static [u8] = Box::leak(blob.to_vec().into_boxed_slice());
        self.leaked_bytes = self.leaked_bytes.saturating_add(leaked.len() as u64);
        self.map.insert(hash, leaked);
        Ok(leaked)
    }

    /// Number of distinct blobs interned so far.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.map.len()
    }

    /// Total bytes leaked so far. Exported as `tls_interned_chain_bytes`.
    #[must_use]
    pub fn leaked_bytes(&self) -> u64 {
        self.leaked_bytes
    }

    /// Number of `intern` calls that hit an existing blob. Exported as
    /// `tls_interned_chain_hits_total`.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }
}

impl Default for ChainInterner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CertError, ChainInterner, MAX_DER_BYTES};

    #[test]
    fn intern_dedupes_by_content() {
        let mut interner = ChainInterner::new();
        let blob = vec![7u8; 100];
        let a = interner.intern(&blob).expect("first intern succeeds");
        let b = interner.intern(&blob).expect("second intern succeeds");
        assert_eq!(interner.blob_count(), 1);
        assert_eq!(interner.hits(), 1);
        assert_eq!(a.as_ptr(), b.as_ptr());
        // Leaked once, not twice: a hit must not add to the leaked-bytes counter.
        assert_eq!(interner.leaked_bytes(), 100);
    }

    #[test]
    fn intern_cap_refuses() {
        let mut interner = ChainInterner::with_capacity_limit(2);
        interner.intern(&[1u8; 10]).expect("first blob fits");
        interner.intern(&[2u8; 10]).expect("second blob fits");
        let third = interner.intern(&[3u8; 10]);
        assert_eq!(third, Err(CertError::TooManyDistinctBlobs));
        assert_eq!(interner.blob_count(), 2);
        // Three distinct blobs, zero repeats: hits() must stay at 0, not just "some value".
        assert_eq!(interner.hits(), 0);
    }

    #[test]
    fn intern_rejects_empty_and_oversize() {
        let mut interner = ChainInterner::new();
        assert_eq!(interner.intern(&[]), Err(CertError::EmptyDer));
        assert_eq!(
            interner.intern(&vec![0u8; 65_537]),
            Err(CertError::DerTooLarge)
        );
        assert_eq!(interner.blob_count(), 0);
        // The boundary itself, MAX_DER_BYTES exactly, must still be accepted.
        assert!(interner.intern(&vec![0u8; MAX_DER_BYTES]).is_ok());
        assert_eq!(interner.blob_count(), 1);
    }
}
