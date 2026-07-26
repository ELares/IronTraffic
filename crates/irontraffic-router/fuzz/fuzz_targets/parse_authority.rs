// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `normalize_authority` and `host_key`: the contract is no
//! panic, no hang, and no allocation proportional to input beyond the single
//! `to_vec` this target itself performs. Seeded from the corpus directory
//! next to this file, one input per edge case from the issue that added it.

use irontraffic_router::limits::{AUTHORITY_BUF_BYTES, MAX_AUTHORITY_BYTES};
use irontraffic_router::{HOST_KEY_BUF_BYTES, ListenerId, host_key, normalize_authority};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut b1 = [0u8; AUTHORITY_BUF_BYTES];
    if let Ok(first) = normalize_authority(data, &mut b1) {
        let owned = first.to_vec();
        let mut b2 = [0u8; AUTHORITY_BUF_BYTES];
        let second = normalize_authority(&owned, &mut b2).expect("renormalize"); // it-allow: no-panic reason: fuzz harness; a panic here is the finding libfuzzer-sys reports, never a request-path failure mode, since this file is never linked into the server binary.
        assert_eq!(second, &owned[..]);
        assert!(owned.len() <= MAX_AUTHORITY_BYTES);
        assert!(!owned.iter().any(u8::is_ascii_uppercase));
        let mut k = [0u8; HOST_KEY_BUF_BYTES];
        let _ = host_key(ListenerId(0), &owned, &mut k); // it-allow: no-swallowed-error reason: this target only checks host_key does not panic or allocate; asserting its Ok/Err outcome is normalize.rs's unit tests' job.
    }
});
