// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `Credentials::load`: the contract is no panic, no abort, no hang, and an
//! `Err` for every input that is not a real certificate and key pair. Every byte fed in here is
//! the same shape of input a config file or an ACME response hands the loader: untrusted bytes
//! that must never be able to crash the config-compile path, even though (per the issue this
//! module implements) that path is not attacker-reachable in production the way a ClientHello
//! is. Fuzzing it anyway is cheap insurance against a parser panic in `x509-cert` or in this
//! module's own DER handling.
//!
//! Input domain: arbitrary bytes, split at the midpoint into a candidate chain blob and a
//! candidate key blob. A fresh, small-capacity interner is used per call so the interner's own
//! bound is exercised too.

use std::sync::Once;

use irontraffic_tls::store::{ChainInterner, Credentials, MAX_SANS};
use libfuzzer_sys::fuzz_target;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        // Either this call or some other one-time setup elsewhere in the process installs the
        // process-wide crypto provider; installation is idempotent from this target's point of
        // view (`AlreadyInstalled` and `Ok` both leave a provider installed), and this target
        // only needs one path or the other to succeed once, never every time.
        let _ = irontraffic_tls::install_process_provider(); // it-allow: no-swallowed-error reason: either outcome (Ok or AlreadyInstalled) leaves a crypto provider installed process-wide, which is all this one-time setup needs; there is nothing further to react to.
    });

    let mid = data.len() / 2;
    let chain_blob = data.get(..mid).unwrap_or(&[]);
    let key_blob = data.get(mid..).unwrap_or(&[]);

    let mut interner = ChainInterner::with_capacity_limit(8);
    if let Ok(cred) = Credentials::load(&[chain_blob], key_blob, &mut interner) {
        assert!(cred.not_after() > cred.not_before());
        assert!(cred.san_dns_names().len() <= MAX_SANS);
        for name in cred.san_dns_names() {
            assert!(!name.is_empty());
            assert!(name.len() <= 253);
            assert!(name.bytes().all(|b| matches!(
                b,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*'
            )));
        }
    }
});
