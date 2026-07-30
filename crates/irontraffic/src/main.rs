// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IronTraffic server binary.

mod cli;
mod logging;
mod serve;

/// `irontraffic --version --json` writes exactly this object to stdout and exits 0:
///
/// ```json
/// {"dirty":false,"features":[],"git_sha":"0a1b2c3d4e5f","name":"irontraffic","profile":"release","version":"0.1.0"}
/// ```
///
/// Six keys, in sorted (alphabetical) order, no trailing newline beyond one. `git_sha`
/// is 12 hex characters or the literal `unknown`. `features` is sorted and may be
/// empty. The values come from `build.rs`, which prefers the environment over `git`
/// over the literal `unknown`/`true`, so a build from a source tarball with no
/// `.git` directory is reproducible as long as the release recipe set the
/// environment.
///
/// `irontraffic --version` without `--json` keeps its existing single-line form,
/// handled separately by `cli::run`.
fn print_version_json(out: &mut dyn std::io::Write) -> std::io::Result<()> {
    let name = "irontraffic";
    let version = env!("CARGO_PKG_VERSION");
    let git_sha = env!("IT_GIT_SHA");
    let dirty = env!("IT_GIT_DIRTY") == "true";
    let profile = env!("IT_PROFILE");

    let mut features: Vec<&str> = env!("IT_FEATURES")
        .split(',')
        .filter(|feature| !feature.is_empty())
        .collect();
    features.sort_unstable();

    write!(out, "{{\"dirty\":{dirty},\"features\":[")?;
    for (index, feature) in features.iter().enumerate() {
        if index > 0 {
            write!(out, ",")?;
        }
        write!(out, "\"{feature}\"")?;
    }
    writeln!(
        out,
        "],\"git_sha\":\"{git_sha}\",\"name\":\"{name}\",\"profile\":\"{profile}\",\"version\":\"{version}\"}}"
    )
}

/// Process entrypoint. Returns the process exit code: 0 for `--version`, `--help`,
/// and a valid configuration; 1 for validation errors; 2 for a usage error; 3 when
/// the configuration file could not be loaded. See `cli::run`.
fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // Intercepted here, before `cli::run`, rather than folded into `cli`'s own
    // grammar: this issue's Files table modifies only `main.rs`. `cli::run`'s
    // existing grammar already treats a lone `--version` as `Command::Version`
    // and any OTHER second argument (including `--help`) as a usage error, and
    // that behavior is unchanged; only the exact pair `--version --json` is
    // handled here, ahead of it.
    if let [first, second] = argv.as_slice()
        && first == "--version"
        && second == "--json"
    {
        let mut stdout = std::io::stdout();
        return match print_version_json(&mut stdout) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            // Not swallowed: a write failure (a closed stdout, e.g. `| true`)
            // is reported as a distinct, non-zero exit rather than ignored.
            Err(_) => std::process::ExitCode::FAILURE,
        };
    }

    logging::init();

    cli::run(&argv)
}
