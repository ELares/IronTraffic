#![no_main]
//! Fuzz target for `irontraffic_http::field::validate_name` and
//! `validate_value`.
//!
//! Input domain: the first byte of `data` selects the `WireVersion` (mod 4);
//! the remainder is split into a name candidate and a value candidate at the
//! first `0xFF` byte, or treated entirely as the name candidate when no
//! `0xFF` byte is present. `data` shorter than one byte is a no-op.
//!
//! Contract: must not panic, must not allocate (this harness performs no
//! allocation itself; it only slices `data`), must terminate. Additionally
//! asserts the same properties the crate's own property tests pin: an `Ok`
//! name is non-empty and every byte of it is a documented true name byte; an
//! `Ok` value contains none of NUL, LF or CR.

use irontraffic_http::field::{name_byte_ok, validate_name, validate_value};
use irontraffic_http::WireVersion;
use libfuzzer_sys::fuzz_target;

fn version_from_byte(b: u8) -> WireVersion {
    match b % 4 {
        0 => WireVersion::Http10,
        1 => WireVersion::Http11,
        2 => WireVersion::H2,
        _ => WireVersion::H3,
    }
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let Some((&version_byte, rest)) = data.split_first() else {
        return;
    };
    let version = version_from_byte(version_byte);

    let (name, value) = match rest.iter().position(|&b| b == 0xFF) {
        Some(marker) => {
            let (name, tail) = rest.split_at(marker);
            (name, tail.get(1..).unwrap_or(&[]))
        }
        None => (rest, &[][..]),
    };

    if validate_name(name, version).is_ok() {
        assert!(!name.is_empty());
        assert!(name.iter().all(|&b| name_byte_ok(b)));
    }
    if validate_value(value, version).is_ok() {
        assert!(!value.iter().any(|&b| matches!(b, 0x00 | 0x0A | 0x0D)));
    }
});
