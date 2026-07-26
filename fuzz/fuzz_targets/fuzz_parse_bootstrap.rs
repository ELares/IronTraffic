// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for the config loader's parsing step: the two-parser union
//! (`serde_json` and `serde_norway`) that `irontraffic_config::load` calls after its
//! own byte cap and alias-budget guards run. Input is screened through those same
//! guards BEFORE either parser sees it, so this target exercises the code path
//! production actually reaches. A target that hands an alias bomb straight to the
//! YAML parser would report an out-of-memory that a real `load` call can never hit,
//! because the guard rejects it first; that would be a false finding.
//!
//! Contract: must never panic, must never hang, must never allocate more than the
//! fuzzer's default memory limit, and every `Ok` value must pass through `validate`
//! without panicking.

use irontraffic_config::{BootstrapDoc, MAX_DOC_BYTES, MAX_YAML_ALIASES, validate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limit = usize::try_from(MAX_DOC_BYTES).unwrap_or(usize::MAX);
    let truncated = if data.len() > limit {
        &data[..limit]
    } else {
        data
    };

    let Ok(text) = std::str::from_utf8(truncated) else {
        return;
    };

    // The same lexical alias-budget scan `load` runs before calling
    // `serde_norway::from_str`, counted on raw bytes before either parser runs.
    let aliases = text.bytes().filter(|byte| *byte == b'*').count();

    if let Ok(doc) = serde_json::from_str::<BootstrapDoc>(text) {
        let _ = validate(&doc); // it-allow: no-swallowed-error reason: fuzz harness; the contract is "does not panic", not a specific diagnostic outcome.
    }

    if aliases <= MAX_YAML_ALIASES {
        if let Ok(doc) = serde_norway::from_str::<BootstrapDoc>(text) {
            let _ = validate(&doc); // it-allow: no-swallowed-error reason: fuzz harness; the contract is "does not panic", not a specific diagnostic outcome.
        }
    }
});
