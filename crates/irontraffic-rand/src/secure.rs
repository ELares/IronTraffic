// SPDX-License-Identifier: MIT OR Apache-2.0
//! The operating system CSPRNG for security-bearing values.
//!
//! Use this module for TLS ticket nonces and keys, session identifiers, API key
//! material, and cookie values. Never use [`crate::Rng`] for any of those.

/// The operating system entropy source failed.
#[derive(Debug, thiserror::Error)]
#[error("the operating system entropy source failed: {detail}")]
pub struct EntropyError {
    detail: String,
}

/// The operating system CSPRNG. Use for anything security bearing.
#[derive(Debug, Clone, Copy)]
pub struct SecureRng;

impl SecureRng {
    /// Fills `out` from the operating system CSPRNG.
    ///
    /// # Errors
    /// Returns [`EntropyError`] when the operating system entropy source fails.
    pub fn fill(out: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(out).map_err(|e| EntropyError {
            detail: e.to_string(),
        })
    }

    /// One cryptographically secure 64-bit value.
    ///
    /// # Errors
    /// Returns [`EntropyError`] when the operating system entropy source fails.
    pub fn next_u64() -> Result<u64, EntropyError> {
        let mut b = [0u8; 8];
        Self::fill(&mut b)?;
        Ok(u64::from_le_bytes(b)) // little-endian, matching `Rng::fill_bytes`
    }

    /// A seed for [`crate::Rng::from_entropy`] and for the per-core generator array.
    ///
    /// # Errors
    /// Returns [`EntropyError`] when the operating system entropy source fails.
    /// The caller must treat that as a fatal startup error. There is no
    /// acceptable fallback value; see the crate documentation.
    pub fn seed() -> Result<u64, EntropyError> {
        Self::next_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::SecureRng;

    #[test]
    fn secure_fill_writes_something() {
        let mut buf = [0u8; 64];
        SecureRng::fill(&mut buf).expect("CSPRNG should provide entropy in tests");
        assert!(
            !buf.iter().all(|&v| v == 0),
            "CSPRNG produced 64 zero bytes"
        );
    }
}
