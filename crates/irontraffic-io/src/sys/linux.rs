// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux-only platform probes.
//!
//! The only thing this platform needs of its own, rather than a probe every
//! unix shares, is reading `net.core.somaxconn` from `/proc`. `SO_REUSEPORT`,
//! `SO_REUSEADDR` and `IPV6_V6ONLY` are probed with `socket2` the same way on
//! every unix (see `super::probe_reuse_port`), and `splice`/`SCM_RIGHTS` are
//! compile-time answers (`cfg!(target_os = "linux")` / `cfg!(unix)`) that need
//! no platform-specific code at all, so neither lives here.

use std::io::Read as _;
use std::path::Path;

/// The path `read_somaxconn` reads. A constant, not a parameter, because the
/// only caller is `Caps::probe`, which always means the real kernel value.
const SOMAXCONN_PATH: &str = "/proc/sys/net/core/somaxconn";

/// The bound on `read_somaxconn`'s read. A decimal `u32` is at most ten
/// bytes, so 64 is generous. `/proc` is not always `/proc`: in a container
/// the path can be a bind mount of an ordinary file, and a proxy that
/// allocates whatever it finds there at startup has an unbounded read on a
/// path it does not control.
const SOMAXCONN_READ_LIMIT: u64 = 64;

/// Reads `net.core.somaxconn`.
///
/// Returns `None` when the file is missing, unreadable, or not valid UTF-8.
/// Absence is not an error: a container without `/proc` reports `None` the
/// same way a non-Linux host does (`super::fallback::read_somaxconn`).
/// Performs blocking file I/O; `Caps::probe` documents that it must run once,
/// at startup, before any runtime exists.
pub(super) fn read_somaxconn() -> Option<u32> {
    let file = std::fs::File::open(Path::new(SOMAXCONN_PATH)).ok()?; // it-allow: no-blocking-in-async reason: Caps::probe runs once at startup, before any runtime exists
    let mut limited = file.take(SOMAXCONN_READ_LIMIT);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    parse_somaxconn(text)
}

/// Parses the trimmed contents of `/proc/sys/net/core/somaxconn`.
///
/// Pure, no I/O, so a table-driven test can drive every input shape without a
/// filesystem. `pub(crate)`, never `pub`: this is an internal parsing detail,
/// not part of the crate's public API.
pub(crate) fn parse_somaxconn(text: &str) -> Option<u32> {
    text.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_somaxconn;

    #[test]
    fn parse_somaxconn_table() {
        let big_run = "9".repeat(4096);
        let cases: &[(&str, Option<u32>)] = &[
            ("4096\n", Some(4096)),
            ("  128  ", Some(128)),
            ("", None),
            ("abc", None),
            ("18446744073709551616", None),
            (big_run.as_str(), None),
        ];

        for (input, expected) in cases {
            assert_eq!(
                parse_somaxconn(input),
                *expected,
                "parse_somaxconn({input:?}) should be {expected:?}"
            );
        }
    }
}
