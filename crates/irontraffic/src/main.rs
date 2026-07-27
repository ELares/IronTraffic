// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IronTraffic server binary.

mod cli;
mod logging;
mod serve;

/// Process entrypoint. Returns the process exit code: 0 for `--version`, `--help`,
/// and a valid configuration; 1 for validation errors; 2 for a usage error; 3 when
/// the configuration file could not be loaded. See `cli::run`.
fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    logging::init();

    cli::run(&argv)
}
