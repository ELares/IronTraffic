// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 5869 HKDF-Extract and HKDF-Expand over SHA-384, restricted to the single output
//! length this crate ever needs.
//!
//! [`expand_sha384`] implements only the `L <= HashLen` (48 bytes) branch of RFC 5869 section
//! 2.3: exactly one iteration of the underlying PRF, never the general N-block loop. `ticket.rs`
//! asks for 16- and 32-byte outputs, both well under 48, so a multi-block Expand would be
//! unexercised machinery carrying its own correctness burden for zero benefit here. The
//! restriction is enforced in code (a length check up front) and documented, not merely assumed.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha384;
use zeroize::{Zeroize, Zeroizing};

/// RFC 5869 section 2.2: `PRK = HMAC-Hash(salt, IKM)`. Returns the 48-byte pseudorandom key.
pub(crate) fn extract_sha384(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 48]> {
    let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(salt) else {
        // HMAC accepts a key of any length (RFC 2104), so this arm cannot execute for any
        // salt this crate ever passes; `ticket.rs` always calls this with the fixed 27-byte
        // literal salt `b"irontraffic/ticket-root/v1"`. `unwrap` is denied in this crate, so
        // the unreachable arm returns an all-zero PRK rather than panicking: it is never
        // observed, but a caller that somehow reached it fails closed into a key that
        // decrypts and encrypts nothing meaningful rather than crashing the process.
        return Zeroizing::new([0u8; 48]);
    };
    mac.update(ikm);
    let mut full = mac.finalize().into_bytes();
    let mut prk = [0u8; 48];
    if let Some(head) = full.get(..48) {
        prk.copy_from_slice(head);
    }
    // Zeroize the HMAC's own output buffer in place, not just `prk`. `full` is
    // `hybrid_array::Array<u8, U48>` (`crypto_common::Output<Hmac<Sha384>>`); nothing in this
    // workspace's resolved dependency graph turns on hybrid-array's own `zeroize` feature
    // (`cargo tree -e features` reports `hybrid-array feature "default"` only, checked with the
    // workspace `Cargo.toml`'s `hmac` `zeroize` feature enabled), so `Array` itself has no
    // `Zeroize` impl here. The call below still resolves, through a different route: `Array`
    // derefs to `[u8]`, and the `zeroize` crate has its own blanket
    // `impl<Z: DefaultIsZeroes> Zeroize for [Z]`, which covers `u8` unconditionally and needs no
    // feature flag of its own. That slice impl is what actually runs.
    //
    // This is a real change from `<[u8]>::fill(0)`, which it replaces, and the reason is not
    // cosmetic. `fill` is a plain, non-volatile store into a local that is dead immediately
    // afterwards, exactly the kind of store a compiler is entitled to remove as dead.
    // `Zeroize::zeroize` for a byte slice performs a volatile write followed by an explicit
    // optimization barrier, specifically so the write survives that elimination. This is the
    // key schedule for the product's highest value secret, so that property is worth the one
    // line it costs. (The workspace `Cargo.toml` comment on `hmac`'s `zeroize` feature records
    // the two other things enabling it buys: a wipe of `sha2`'s internal block buffer on drop,
    // and a wipe of the transient `CtOutput` that `mac.finalize()` produces before
    // `.into_bytes()` clones out of it.)
    //
    // This comment has been wrong twice before, in opposite directions: once claiming the
    // `Zeroize` route needed a dependency feature (`generic-array`) this crate was not
    // authorized to add, and once claiming, of the successor type `hybrid-array`, that the
    // feature it would need does not exist. Neither claim is repeated here; this text states
    // only what was checked against the graph above, not what would be convenient to believe.
    // `prk` itself is returned wrapped in `Zeroizing`, so both copies are covered.
    full.zeroize();
    Zeroizing::new(prk)
}

/// RFC 5869 section 2.3, restricted to `L <= 48` (one hash block): `out.len()` is `L` and must
/// be at most 48, which is all this crate ever needs; a longer request returns `false` rather
/// than looping. Returns `false` on any rejected input; `out` must not be trusted in that case.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "prk is a 48-byte HKDF pseudorandom key; clippy's byte-size heuristic does not know \
              that, and copying key material onto the stack more often than necessary is \
              undesirable even at 48 bytes, so this keeps the reference the issue's own \
              signature specifies rather than passing it by value"
)]
pub(crate) fn expand_sha384(prk: &[u8; 48], info: &[u8], out: &mut [u8]) -> bool {
    if out.is_empty() || out.len() > 48 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(prk) else {
        // HMAC accepts a key of any length and `prk` is always exactly 48 bytes, so this arm
        // cannot execute; see the identical reasoning in `extract_sha384`. `unwrap` is denied,
        // so failing this call rather than panicking is the only lawful response.
        return false;
    };
    mac.update(info);
    mac.update(&[0x01u8]);
    let mut t = mac.finalize().into_bytes();
    let ok = if let Some(head) = t.get(..out.len()) {
        out.copy_from_slice(head);
        true
    } else {
        false
    };
    // Zeroize `t`, in place, for the same reason and by the same mechanism as `extract_sha384`:
    // see the comment there for what is actually true about the route this takes.
    t.zeroize();
    ok
}

#[cfg(test)]
mod tests {
    use super::{expand_sha384, extract_sha384};

    #[test]
    fn expand_rejects_zero_and_over_48() {
        let prk = *extract_sha384(b"salt", b"ikm");
        let mut zero = [0u8; 0];
        assert!(!expand_sha384(&prk, b"info", &mut zero));
        let mut over = [0u8; 49];
        assert!(!expand_sha384(&prk, b"info", &mut over));

        // The accept side of the same boundary: 48 (the maximum) and 1 (the minimum) both
        // succeed, so the rejection above is a real upper bound and not an off-by-one that
        // rejects everything.
        let mut at_max = [0u8; 48];
        assert!(expand_sha384(&prk, b"info", &mut at_max));
        let mut at_min = [0u8; 1];
        assert!(expand_sha384(&prk, b"info", &mut at_min));
    }

    #[test]
    fn expand_is_deterministic() {
        let prk = *extract_sha384(b"salt", b"ikm");
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        assert!(expand_sha384(&prk, b"same-info", &mut out1));
        assert!(expand_sha384(&prk, b"same-info", &mut out2));
        assert_eq!(
            out1, out2,
            "same prk and info must expand to the same output"
        );
        assert_ne!(out1, [0u8; 32], "expand must not be the all-zero output");

        let mut out3 = [0u8; 32];
        assert!(expand_sha384(&prk, b"different-info", &mut out3));
        assert_ne!(
            out1, out3,
            "different info must expand to a different output"
        );
    }

    /// Differential test: this crate's hand-rolled HKDF-SHA384 against `aws_lc_rs::hkdf`, over
    /// 20 pseudorandom `(salt, ikm, info, L)` tuples. `irontraffic_rand::Rng` is the deterministic,
    /// seedable, non-cryptographic generator this workspace already uses for reproducible test
    /// inputs; it is never used for anything security bearing, only to pick byte strings here.
    #[test]
    #[cfg(feature = "crypto-aws-lc-rs")]
    fn hkdf_matches_aws_lc_rs() {
        use aws_lc_rs::hkdf::{HKDF_SHA384, KeyType, Salt};
        use irontraffic_rand::Rng;

        struct OutLen(usize);
        impl KeyType for OutLen {
            fn len(&self) -> usize {
                self.0
            }
        }

        let mut rng = Rng::from_seed(0x4854_4b44_465f_5445);
        for case in 0..20 {
            let salt_len = 1 + usize::try_from(rng.bounded_u32(64)).unwrap_or(0);
            let ikm_len = 1 + usize::try_from(rng.bounded_u32(64)).unwrap_or(0);
            let info_len = usize::try_from(rng.bounded_u32(64)).unwrap_or(0);
            let l = 1 + usize::try_from(rng.bounded_u32(48)).unwrap_or(0);

            let mut salt = vec![0u8; salt_len];
            let mut ikm = vec![0u8; ikm_len];
            let mut info = vec![0u8; info_len];
            rng.fill_bytes(&mut salt);
            rng.fill_bytes(&mut ikm);
            rng.fill_bytes(&mut info);

            let ours_prk = extract_sha384(&salt, &ikm);
            let mut ours_out = vec![0u8; l];
            assert!(
                expand_sha384(&ours_prk, &info, &mut ours_out),
                "case {case}: our expand_sha384 rejected a valid L <= 48 request"
            );

            let their_salt = Salt::new(HKDF_SHA384, &salt);
            let their_prk = their_salt.extract(&ikm);
            let info_slices: [&[u8]; 1] = [&info];
            let their_okm = their_prk
                .expand(&info_slices, OutLen(l))
                .expect("case within aws-lc-rs's 255*HashLen bound");
            let mut their_out = vec![0u8; l];
            their_okm
                .fill(&mut their_out)
                .expect("fill into a buffer of the requested length must not fail");

            assert_eq!(
                ours_out, their_out,
                "case {case}: our HKDF-SHA384 disagrees with aws_lc_rs::hkdf for salt_len={salt_len} \
                 ikm_len={ikm_len} info_len={info_len} L={l}"
            );
        }
    }
}
