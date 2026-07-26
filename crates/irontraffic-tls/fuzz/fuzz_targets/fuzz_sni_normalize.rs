// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `normalize`, `parent`, `label_count`, and
//! `NameHasher::hash`: the contract is no panic, no hang, and every invariant
//! `normalize` promises (bounded length, all-ASCII, lowercased, no trailing
//! dot) holds for every output it produces. Every byte fed in here is the
//! same shape of input a ClientHello's SNI extension delivers: fully
//! peer-controlled, before any handshake completes.

use irontraffic_tls::NameHasher;
use irontraffic_tls::name::{MAX_NAME_LEN, label_count, normalize, parent};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let mut buf = [0u8; MAX_NAME_LEN];
    if let Ok(n) = normalize(s, &mut buf) {
        assert!(n.len() <= MAX_NAME_LEN);
        assert!(n.is_ascii());
        assert_eq!(n, n.to_ascii_lowercase());
        assert!(!n.ends_with('.'));

        let _ = parent(n); // it-allow: no-swallowed-error reason: parent returns an Option, not a Result; this target only checks it does not panic, never a specific value (that is name.rs's unit tests' job).
        let _ = label_count(n); // it-allow: no-swallowed-error reason: label_count returns a usize, not a Result; this target only checks it does not panic.
        let _ = NameHasher::new([7u8; 16]).hash(n); // it-allow: no-swallowed-error reason: hash returns a NameKey, not a Result, and a NameKey must never be observed outside the process (see name.rs's module doc); this target only checks the call does not panic.
    }
});
