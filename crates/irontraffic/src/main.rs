// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IronTraffic server binary.
//!
//! This is deliberately a thin shell over the `irontraffic` library so that
//! every behavior is reachable from a test. Keep it that way.

use std::io::Write as _;

use irontraffic::{Mode, VERSION};

fn main() -> std::process::ExitCode {
    let arg = std::env::args().nth(1);
    let mut out = std::io::stdout().lock();

    let Some(arg) = arg else {
        // it-allow: no-swallowed-error reason: a failed write to stdout at startup has no recovery path and no observer
        let _ = writeln!(
            out,
            "irontraffic {VERSION} (default mode: {})",
            Mode::default().as_str()
        );
        return std::process::ExitCode::SUCCESS;
    };

    if arg == "--version" || arg == "-V" {
        // it-allow: no-swallowed-error reason: a failed write to stdout at startup has no recovery path and no observer
        let _ = writeln!(out, "irontraffic {VERSION}");
        return std::process::ExitCode::SUCCESS;
    }

    let Some(mode) = Mode::parse(&arg) else {
        // it-allow: no-swallowed-error reason: a failed write to stderr during argument rejection has no recovery path
        let _ = writeln!(
            std::io::stderr(),
            "irontraffic: unknown mode {arg:?}; expected one of: run, proxy, control, validate"
        );
        return std::process::ExitCode::FAILURE;
    };

    // The runtime, configuration loader, and serving paths are milestone 1
    // deliverables. Until they land, a recognized mode reports what it would
    // do and exits successfully. It does not pretend to serve traffic.
    // it-allow: no-swallowed-error reason: a failed write to stdout at startup has no recovery path and no observer
    let _ = writeln!(
        out,
        "irontraffic {VERSION}: mode {} is not yet wired up",
        mode.as_str()
    );
    std::process::ExitCode::SUCCESS
}
