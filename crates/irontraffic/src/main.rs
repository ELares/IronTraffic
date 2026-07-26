// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IronTraffic server binary.

mod logging;

/// Process entrypoint. Returns the process exit code:
/// 0 for `--version` and `--help`, 2 for any usage error.
fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    logging::init();

    match argv.as_slice() {
        [] => {
            let _ = print_usage(&mut std::io::stderr()); // it-allow: no-swallowed-error reason: a broken pipe changes nothing; the exit code is already decided
            std::process::ExitCode::from(2)
        }
        [arg] if arg == "--version" || arg == "-V" => {
            #[allow(clippy::print_stdout, reason = "version output")]
            {
                println!("irontraffic {}", env!("CARGO_PKG_VERSION"));
            }
            std::process::ExitCode::SUCCESS
        }
        [arg] if arg == "--help" || arg == "-h" => {
            let _ = print_usage(&mut std::io::stdout()); // it-allow: no-swallowed-error reason: a broken pipe changes nothing; the exit code is already decided
            std::process::ExitCode::SUCCESS
        }
        _ => {
            let joined = argv
                .iter()
                .map(|a| sanitize_for_terminal(a))
                .collect::<Vec<_>>()
                .join(" ");
            #[allow(clippy::print_stderr, reason = "error diagnostics go to stderr")]
            {
                eprintln!("error: unrecognised arguments: {joined}");
            }
            let _ = print_usage(&mut std::io::stderr()); // it-allow: no-swallowed-error reason: a broken pipe changes nothing; the exit code is already decided
            std::process::ExitCode::from(2)
        }
    }
}

/// Writes the usage block to `out`. Used for both the `--help` (stdout) and the
/// usage-error (stderr) paths so the two can never drift.
fn print_usage(out: &mut dyn std::io::Write) -> std::io::Result<()> {
    writeln!(out, "irontraffic {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(out, "usage:")?;
    writeln!(out, "  irontraffic --version")?;
    writeln!(out, "  irontraffic --help")?;
    Ok(())
}

/// Replaces every control character except tab with `.`.
///
/// Applied to any command-line argument echoed back in an error message. An
/// argument is untrusted text and stderr is a terminal and a log: an unfiltered
/// escape sequence can move the cursor, recolour the screen, or forge a log line.
fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\u{7f}' || (c.is_control() && c != '\t') {
            out.push('.');
        } else {
            out.push(c);
        }
    }
    out
}
