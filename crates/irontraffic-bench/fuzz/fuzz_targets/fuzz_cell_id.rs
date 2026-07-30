// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `CellId::parse` and `Detail::new`.
//!
//! `CellId::parse` is the security boundary: a cell id is used verbatim as a
//! result filename stem in a script a stranger is invited to run, so arbitrary
//! bytes must never yield a `CellId` that escapes a directory. `Detail::new`
//! is fuzzed on the same input rather than in its own target because it takes
//! the same `&str` and the clip-at-a-character-boundary step is exactly the
//! kind of arithmetic a fuzzer finds a panic in.

use irontraffic_bench::{CellId, Detail, MAX_DETAIL_BYTES, RESERVED_STEMS};
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(id) = CellId::parse(s) {
        assert!(!id.as_str().is_empty());
        assert_eq!(Path::new(id.as_str()).components().count(), 1);
        assert!(!RESERVED_STEMS.contains(&id.as_str()));
        // Idempotence. `BenchError` is not `PartialEq` (it holds a
        // `std::io::Error`), so compare through `.ok()`.
        assert_eq!(CellId::parse(id.as_str()).ok().as_ref(), Some(&id));
    }

    let detail = Detail::new(s);
    assert!(detail.as_str().len() <= MAX_DETAIL_BYTES);
    assert!(std::str::from_utf8(detail.as_str().as_bytes()).is_ok());
    assert!(detail.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
});
