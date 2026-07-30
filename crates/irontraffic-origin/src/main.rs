// SPDX-License-Identifier: MIT OR Apache-2.0
//! `it-origin`: argument parsing, runtime setup, listener, `--version --json`.
//!
//! This binary is a thin shell over `irontraffic_origin`: every type it uses
//! (`OriginConfig`, `ArgError`, `serve::start`) is defined in the library so
//! tests can drive them directly.
//!
//! Exit codes: 0 for `--version`, `--help`, and a clean bind and startup
//! (though a successful run never actually returns, since the process serves
//! forever); 1 for a bind failure or a runtime that could not be built
//! (`serve::start`'s error already names the offending address, per edge
//! case 14: "prints the address and exits with code 1 before accepting
//! anything, rather than serving on a subset"); 2 for a usage error.
//!
//! This binary builds the `tokio` runtime directly (see the `it-allow:
//! transport-seam` marker below): it is a standalone benchmark fixture, not
//! part of the main proxy's swappable-transport data plane that
//! `irontraffic_io::Transport` exists to abstract, per `serve.rs`'s own
//! module doc comment.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;
use tokio::runtime::Builder; // it-allow: transport-seam reason: standalone fixture binary, see module doc comment

use irontraffic_origin::config::OriginConfig;

// `IT_GIT_SHA` and `IT_GIT_DIRTY`, written by `build.rs`.
include!(concat!(env!("OUT_DIR"), "/it_origin_git.rs"));

const USAGE: &str = "\
it-origin: a trivial HTTP/1.1 upstream with known, constant, allocation-free per-request cost.

usage:
  it-origin [flags]
  it-origin --version [--json]
  it-origin --help

flags:
  --listen <ADDR>            default 127.0.0.1:8081, repeatable up to 8 times
  --body-bytes <N>           default 1024, max 16777216
  --status <CODE>            default 200, allowed 200-599 except 204, and 304 only with --body-bytes 0
  --delay-us <N>             default 0, fixed per-request delay
  --delay-dist <KIND>        none | fixed | bimodal:<p_permille>:<hi_us>, default none
  --sequence                 echo a monotone counter in X-Origin-Seq
  --workers <N>              default: available parallelism
  --max-connections <N>      default 200000, range 1..=1000000
  --head-timeout-ms <N>      default 10000, range 1..=600000
  --idle-timeout-ms <N>      default 60000, range 1..=3600000
  --stats-listen <ADDR>      optional, serves the counter snapshot as JSON

anything else is a usage error with exit code 2.
";

/// Escapes `input` for embedding in a JSON string literal. `git rev-parse
/// --short HEAD` only ever emits hex digits or the literal `unknown`, so this
/// is defensive rather than load-bearing: a custom `git` wrapper or an
/// unusual repository state must not be able to break the emitted object's
/// syntax.
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c)); // it-allow: no-swallowed-error reason: writing to a String never fails
            }
            c => out.push(c),
        }
    }
    out
}

/// Prints the `--version --json` `BuildStamp` object: exactly the six keys
/// `name`, `version`, `git_sha`, `dirty`, `profile`, `features`. `stamp_source`
/// is deliberately never emitted here; the harness sets it.
fn print_version_json() {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let json = format!(
        "{{\"name\":\"it-origin\",\"version\":\"{}\",\"git_sha\":\"{}\",\"dirty\":{},\"profile\":\"{}\",\"features\":[]}}",
        json_escape(env!("CARGO_PKG_VERSION")),
        json_escape(IT_GIT_SHA),
        IT_GIT_DIRTY,
        profile,
    );
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{json}"); // it-allow: no-swallowed-error reason: a closed stdout must not change the exit code or panic
}

fn print_version_plain() {
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "it-origin {}", env!("CARGO_PKG_VERSION")); // it-allow: no-swallowed-error reason: a closed stdout must not change the exit code or panic
}

fn print_usage() {
    let mut stdout = std::io::stdout();
    let _ = write!(stdout, "{USAGE}"); // it-allow: no-swallowed-error reason: a closed stdout must not change the exit code or panic
}

/// Recognizes `--help`, `--version`, and `--version --json` as their own
/// modes, none of which ever reach [`OriginConfig::parse`]: that parser has
/// no `Version`/`Help` outcome, per its own documented grammar.
fn handle_version_or_help(argv: &[OsString]) -> Option<ExitCode> {
    let words: Vec<Option<&str>> = argv.iter().map(|arg| arg.to_str()).collect();
    match words.as_slice() {
        [Some("--help")] => {
            print_usage();
            Some(ExitCode::SUCCESS)
        }
        [Some("--version")] => {
            print_version_plain();
            Some(ExitCode::SUCCESS)
        }
        [Some("--version"), Some("--json")] => {
            print_version_json();
            Some(ExitCode::SUCCESS)
        }
        _ => None,
    }
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();

    if let Some(code) = handle_version_or_help(&argv) {
        return code;
    }

    let config = match OriginConfig::parse(&argv) {
        Ok(config) => config,
        Err(error) => {
            let mut stderr = std::io::stderr();
            #[allow(clippy::print_stderr, reason = "usage errors are reported on stderr")]
            {
                eprintln!("error: {error}");
            }
            let _ = write!(stderr, "{USAGE}"); // it-allow: no-swallowed-error reason: a closed stderr must not change the exit code or panic
            return ExitCode::from(2);
        }
    };

    let workers = usize::from(config.workers);
    let runtime = match Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "error: failed to build the runtime: {error}"); // it-allow: no-swallowed-error reason: a closed stderr must not change the exit code or panic
            return ExitCode::from(1);
        }
    };

    runtime.block_on(async {
        match irontraffic_origin::serve::start(config).await {
            Ok(_origin) => {
                // The server runs until the process is killed; nothing after
                // this ever executes in a real invocation.
                std::future::pending::<()>().await;
                ExitCode::SUCCESS
            }
            Err(error) => {
                let mut stderr = std::io::stderr();
                let _ = writeln!(stderr, "error: {error}"); // it-allow: no-swallowed-error reason: a closed stderr must not change the exit code or panic
                ExitCode::from(1)
            }
        }
    })
}
