// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for the config loader's parsing step: the two-parser union
//! (`serde_json` and `serde_norway`) that `irontraffic_config::load` calls after its
//! own byte cap, alias-budget, and nesting-depth guards run. Input is screened
//! through those same guards BEFORE either parser sees it, so this target exercises
//! the code path production actually reaches. A target that hands an alias bomb or
//! a deeply nested flow collection straight to the YAML parser would report an
//! out-of-memory or a multi-second hang that a real `load` call can never hit,
//! because the guards reject both first; that would be a false finding.
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

    // The same lexical nesting-depth scan `load` runs before calling
    // `serde_norway::from_str`: a YAML flow collection (`[`/`{`) nested as the
    // value of a block mapping key costs the tokenizer CPU quadratic in depth,
    // independent of aliases, before serde examines a single field. See
    // `irontraffic_config::load::MAX_YAML_NESTING_DEPTH`.
    let mut running_depth: usize = 0;
    let mut max_depth: usize = 0;
    for byte in text.bytes() {
        match byte {
            b'[' | b'{' => {
                running_depth += 1;
                max_depth = max_depth.max(running_depth);
            }
            b']' | b'}' => running_depth = running_depth.saturating_sub(1),
            _ => {}
        }
    }

    if let Ok(doc) = serde_json::from_str::<BootstrapDoc>(text) {
        let _ = validate(&doc); // it-allow: no-swallowed-error reason: fuzz harness; the contract is "does not panic", not a specific diagnostic outcome.
    }

    if aliases <= MAX_YAML_ALIASES && max_depth <= irontraffic_config::load::MAX_YAML_NESTING_DEPTH
    {
        if let Ok(doc) = serde_norway::from_str::<BootstrapDoc>(text) {
            let _ = validate(&doc); // it-allow: no-swallowed-error reason: fuzz harness; the contract is "does not panic", not a specific diagnostic outcome.
        }
    }
});
