// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hand-written argument parser and the `validate`, `run`, `proxy`, and `control`
//! modes.
//!
//! Grammar, exactly:
//!
//! ```text
//! argv := "--version" | "-V"
//!       | "--help" | "-h"
//!       | "validate" flag*
//!       | "run" flag*
//!       | "proxy" flag*
//!       | "control" flag*
//! flag  := "--config" PATH
//!       |  "--workers" UINT
//!       |  "--bind" ADDR
//!       |  "--upstream" ADDR
//!       |  "--mode" ("balanced" | "shard")
//!       |  "--print"
//! ```
//!
//! `run`, `proxy`, and `control` accept exactly the flags `validate` accepts, and
//! `--config` is required for all four. A flag may appear at most once; a repeat is
//! a usage error naming the flag. `--flag=value` is not supported and produces a usage
//! error naming the space-separated form, because supporting both doubles the
//! parser's cases for no benefit. An unknown flag is a usage error naming it. A
//! missing value for a flag that takes one is a usage error naming the flag. `--print`
//! is accepted by `run`, `proxy`, and `control` and silently ignored there: rejecting a
//! harmless flag combination is a worse operator experience than ignoring it.
//!
//! Exit codes are a contract a CI pipeline branches on and never change meaning: 0
//! clean, 1 validation errors, 2 usage error, 3 the configuration file could not be
//! loaded, 4 runtime or entropy initialisation failure, 5 bind failure, 6 shutdown left
//! live connections. Codes 4 through 6 are produced only by `run`, `proxy`, and
//! `control`, through [`crate::serve::run`]; `validate` never reaches them.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use irontraffic_config::{BindAddr, ModeSpec, Overrides, ProcessEnv, UpstreamAddr, load, validate};

/// Which top-level thing to do.
enum Command {
    /// Print the version and exit.
    Version,
    /// Print the usage block and exit.
    Help,
    /// Load and validate a configuration document.
    Validate(ValidateArgs),
    /// Run everything: data plane plus control-plane runtime.
    Run(ValidateArgs),
    /// Run the data plane only.
    Proxy(ValidateArgs),
    /// Run the control plane only.
    Control(ValidateArgs),
}

/// Which mode was requested. Threaded from [`Command`] into [`crate::serve::run`].
///
/// Re-exported from the library crate rather than redefined here: `irontraffic::Mode`
/// has named these same four variants since the workspace skeleton, and is also used
/// directly to decide which [`Command`] variant [`parse`] builds, so this is the
/// single definition both this crate's binary target and its library target share. A
/// second, parallel enum of the same four modes in this crate would drift from it,
/// which is exactly the failure mode a later milestone (`dataplane-feature-build-gate`,
/// #430) is about to gate builds on.
///
/// `pub(crate)` rather than re-exporting at `pub`, for the same reason as [`run`]:
/// `cli` is a module of the binary crate root, which has no external consumer, so a
/// wider visibility is unreachable and `clippy::unreachable_pub` refuses to compile
/// it. The library's own `Mode` is `pub`, which is what satisfies the "Public API"
/// section of `serve-and-smoke-test` (#21) literally.
pub(crate) use irontraffic::Mode;

/// The parsed `validate`, `run`, `proxy`, or `control` flags. Reused for all four
/// commands rather than duplicated, per `serve-and-smoke-test` (#21): `run` ignores
/// `print`.
///
/// `pub(crate)` and its fields likewise: [`crate::serve::run`] is a sibling module in
/// this same binary crate and reads `config`, `workers`, `bind`, `upstream`, and
/// `mode` to build the same [`irontraffic_config::Overrides`] [`run_validate`] builds.
pub(crate) struct ValidateArgs {
    /// The configuration file to load. Required for all four commands.
    pub(crate) config: PathBuf,
    /// Overrides `runtime.workers`.
    pub(crate) workers: Option<usize>,
    /// Overrides the first listener's `bind`.
    pub(crate) bind: Option<BindAddr>,
    /// Overrides `upstream.address`.
    pub(crate) upstream: Option<UpstreamAddr>,
    /// Overrides `runtime.mode`.
    pub(crate) mode: Option<ModeSpec>,
    /// `--print`. Meaningful to `validate` only; `run`, `proxy`, and `control` ignore it.
    pub(crate) print: bool,
}

/// Parses `argv` and runs the requested command.
///
/// Exit codes: 0 valid or informational, 1 validation errors, 2 usage error, 3 the
/// configuration file could not be loaded, 4 runtime or entropy initialisation
/// failure, 5 bind failure, 6 shutdown left live connections. Codes 4 through 6 come
/// from [`crate::serve::run`], which `run`, `proxy`, and `control` call into.
///
/// `pub(crate)` rather than `pub`: `cli` is a module of the binary crate root
/// (declared `mod cli;` in `main.rs`, per the issue that added it), which has no
/// external consumer, so a wider visibility is unreachable and
/// `clippy::unreachable_pub` (workspace-wide, `-D warnings`) refuses to compile it.
pub(crate) fn run(argv: &[String]) -> ExitCode {
    match parse(argv) {
        Err(message) => {
            #[allow(clippy::print_stderr, reason = "usage errors are reported on stderr")]
            {
                eprintln!("error: {message}");
            }
            let _ = print_usage(&mut std::io::stderr()); // it-allow: no-swallowed-error reason: a broken pipe changes nothing; the exit code is already decided
            ExitCode::from(2)
        }
        Ok(Command::Version) => {
            #[allow(clippy::print_stdout, reason = "version output")]
            {
                println!("irontraffic {}", env!("CARGO_PKG_VERSION"));
            }
            ExitCode::SUCCESS
        }
        Ok(Command::Help) => {
            let _ = print_usage(&mut std::io::stdout()); // it-allow: no-swallowed-error reason: a broken pipe changes nothing; the exit code is already decided
            ExitCode::SUCCESS
        }
        Ok(Command::Validate(validate_args)) => run_validate(&validate_args),
        Ok(Command::Run(mode_args)) => crate::serve::run(Mode::Run, &mode_args),
        Ok(Command::Proxy(mode_args)) => crate::serve::run(Mode::Proxy, &mode_args),
        Ok(Command::Control(mode_args)) => crate::serve::run(Mode::Control, &mode_args),
    }
}

/// Loads and validates the configuration named by `args`, reporting diagnostics and
/// returning the exit code the CLI contract promises.
fn run_validate(args: &ValidateArgs) -> ExitCode {
    let overrides = Overrides {
        workers: args.workers,
        bind: args.bind,
        upstream: args.upstream,
        mode: args.mode,
    };

    let loaded = match load(&args.config, &ProcessEnv, &overrides) {
        Ok(loaded) => loaded,
        Err(error) => {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "{error}"); // it-allow: no-swallowed-error reason: a closed stderr must not change the exit code or panic
            return ExitCode::from(3);
        }
    };

    let diagnostics = validate(&loaded.doc);
    if !diagnostics.is_empty() {
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "{}", diagnostics.render()); // it-allow: no-swallowed-error reason: a closed stderr must not change the exit code or panic
    }

    if args.print {
        let mut stdout = std::io::stdout();
        // `--print` writes even when the document has errors: printing is a separate
        // concern from validity, and an operator debugging a bad document wants to
        // see the resolved value. A closed stdout (for example `| head -1`) must not
        // panic or change the exit code below.
        let _ = writeln!(stdout, "{}", loaded.render_json()); // it-allow: no-swallowed-error reason: a closed stdout must not change the exit code or panic
    }

    if diagnostics.has_errors() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Names a flag that was given more than once.
fn repeated_flag(flag: &str) -> String {
    format!(
        "\"{}\" was given more than once",
        sanitize_for_terminal(flag)
    )
}

/// Names a flag that was given with no following value.
fn missing_value(flag: &str) -> String {
    format!("\"{}\" requires a value", sanitize_for_terminal(flag))
}

/// Parses `argv` into a [`Command`], or an already-sanitized usage error message.
#[expect(
    clippy::too_many_lines,
    reason = "one cohesive dispatch loop over a small, closed set of flags; splitting it would scatter the at-most-once and value-required checks that read naturally in one place per flag"
)]
fn parse(argv: &[String]) -> Result<Command, String> {
    if let [only] = argv {
        if only == "--version" || only == "-V" {
            return Ok(Command::Version);
        }
        if only == "--help" || only == "-h" {
            return Ok(Command::Help);
        }
    }

    let Some((head, rest)) = argv.split_first() else {
        return Err(
            "missing command; expected \"validate\", \"run\", \"proxy\", or \"control\"".to_owned(),
        );
    };

    // `Mode::parse` is the same lookup `CommandKind` used to perform locally: it
    // validates the command word once, up front, so the match at the bottom of this
    // function (which builds the `Command` this word selects) matches on a type
    // `parse` already proved exhaustive, with nothing legitimate left for a wildcard
    // arm to catch.
    let kind = Mode::parse(head.as_str()).ok_or_else(|| {
        format!(
            "unrecognised command \"{}\"; expected \"validate\", \"run\", \"proxy\", \
             \"control\", \"--version\", or \"--help\"",
            sanitize_for_terminal(head)
        )
    })?;

    let mut config: Option<PathBuf> = None;
    let mut workers: Option<usize> = None;
    let mut bind: Option<BindAddr> = None;
    let mut upstream: Option<UpstreamAddr> = None;
    let mut mode: Option<ModeSpec> = None;
    let mut print = false;

    let mut index = 0usize;
    while let Some(arg) = rest.get(index) {
        if let Some((name, value)) = arg.split_once('=')
            && name.starts_with("--")
        {
            let safe_name = sanitize_for_terminal(name);
            let safe_value = sanitize_for_terminal(value);
            return Err(format!(
                "\"{safe_name}={safe_value}\" is not supported; use \"{safe_name} {safe_value}\" instead"
            ));
        }

        match arg.as_str() {
            "--config" => {
                if config.is_some() {
                    return Err(repeated_flag(arg));
                }
                index += 1;
                let value = rest.get(index).ok_or_else(|| missing_value(arg))?;
                config = Some(PathBuf::from(value.as_str()));
            }
            "--workers" => {
                if workers.is_some() {
                    return Err(repeated_flag(arg));
                }
                index += 1;
                let value = rest.get(index).ok_or_else(|| missing_value(arg))?;
                let parsed = value.parse::<usize>().map_err(|_parse_error| {
                    format!(
                        "\"--workers\" value \"{}\" is not a whole number",
                        sanitize_for_terminal(value)
                    )
                })?;
                workers = Some(parsed);
            }
            "--bind" => {
                if bind.is_some() {
                    return Err(repeated_flag(arg));
                }
                index += 1;
                let value = rest.get(index).ok_or_else(|| missing_value(arg))?;
                let parsed = BindAddr::try_from(value.as_str()).map_err(|error| {
                    format!(
                        "\"--bind\" value \"{}\" is invalid: {error}",
                        sanitize_for_terminal(value)
                    )
                })?;
                bind = Some(parsed);
            }
            "--upstream" => {
                if upstream.is_some() {
                    return Err(repeated_flag(arg));
                }
                index += 1;
                let value = rest.get(index).ok_or_else(|| missing_value(arg))?;
                let parsed = UpstreamAddr::try_from(value.as_str()).map_err(|error| {
                    format!(
                        "\"--upstream\" value \"{}\" is invalid: {error}",
                        sanitize_for_terminal(value)
                    )
                })?;
                upstream = Some(parsed);
            }
            "--mode" => {
                if mode.is_some() {
                    return Err(repeated_flag(arg));
                }
                index += 1;
                let value = rest.get(index).ok_or_else(|| missing_value(arg))?;
                mode = Some(match value.as_str() {
                    "balanced" => ModeSpec::Balanced,
                    "shard" => ModeSpec::Shard,
                    _ => {
                        return Err(format!(
                            "\"--mode\" value \"{}\" must be \"balanced\" or \"shard\"",
                            sanitize_for_terminal(value)
                        ));
                    }
                });
            }
            "--print" => {
                if print {
                    return Err(repeated_flag(arg));
                }
                print = true;
            }
            other => {
                return Err(format!("unknown flag \"{}\"", sanitize_for_terminal(other)));
            }
        }
        index += 1;
    }

    let config = config.ok_or_else(|| {
        format!(
            "\"--config\" is required for \"{}\"",
            sanitize_for_terminal(head)
        )
    })?;

    let parsed_args = ValidateArgs {
        config,
        workers,
        bind,
        upstream,
        mode,
        print,
    };

    Ok(match kind {
        Mode::Validate => Command::Validate(parsed_args),
        Mode::Run => Command::Run(parsed_args),
        Mode::Proxy => Command::Proxy(parsed_args),
        Mode::Control => Command::Control(parsed_args),
    })
}

/// Writes the usage block.
///
/// `pub(crate)`, for the same reason as [`run`]: unreachable from outside this
/// binary crate, so a wider visibility trips `clippy::unreachable_pub`.
pub(crate) fn print_usage(out: &mut dyn std::io::Write) -> std::io::Result<()> {
    writeln!(out, "irontraffic {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(out, "usage:")?;
    writeln!(out, "  irontraffic --version")?;
    writeln!(out, "  irontraffic --help")?;
    writeln!(
        out,
        "  irontraffic validate --config <path> [--workers N] [--bind ADDR] [--upstream ADDR] [--mode MODE] [--print]"
    )?;
    writeln!(
        out,
        "  irontraffic run      --config <path> [--workers N] [--bind ADDR] [--upstream ADDR] [--mode MODE] [--print]"
    )?;
    writeln!(
        out,
        "  irontraffic proxy    --config <path> [--workers N] [--bind ADDR] [--upstream ADDR] [--mode MODE] [--print]"
    )?;
    writeln!(
        out,
        "  irontraffic control  --config <path> [--workers N] [--bind ADDR] [--upstream ADDR] [--mode MODE] [--print]"
    )?;
    writeln!(out, "modes:")?;
    writeln!(
        out,
        "  validate   load, validate, report, and exit without binding anything"
    )?;
    writeln!(
        out,
        "  run        everything: data plane plus control-plane runtime (the default deployment)"
    )?;
    writeln!(
        out,
        "  proxy      data plane only; does not build the control-plane runtime"
    )?;
    writeln!(
        out,
        "  control    control plane only; has no work in this version and exits 0"
    )?;
    writeln!(
        out,
        "flags (accepted by validate, run, proxy, and control):"
    )?;
    writeln!(
        out,
        "  --config <path>      configuration file to load (required)"
    )?;
    writeln!(out, "  --workers <n>        override runtime.workers")?;
    writeln!(
        out,
        "  --bind <addr>        override the first listener's bind address"
    )?;
    writeln!(out, "  --upstream <addr>    override upstream.address")?;
    writeln!(
        out,
        "  --mode <mode>        override runtime.mode: balanced or shard"
    )?;
    writeln!(
        out,
        "  --print              print the resolved document as JSON to stdout; validate only, \
         ignored by run, proxy, and control"
    )?;
    writeln!(out, "exit codes:")?;
    writeln!(out, "  0  clean")?;
    writeln!(out, "  1  validation errors")?;
    writeln!(out, "  2  usage error")?;
    writeln!(out, "  3  the configuration file could not be loaded")?;
    writeln!(out, "  4  runtime or entropy initialisation failure")?;
    writeln!(out, "  5  bind failure")?;
    writeln!(out, "  6  shutdown left live connections")?;
    Ok(())
}

/// Replaces every control character except tab with `.`.
///
/// Moved here unchanged from `main.rs`, where `workspace-skeleton` (#2) defined it.
/// Applied to every command-line argument this module echoes back in an error
/// message: an argument is untrusted text and stderr is a terminal and a log, so an
/// unfiltered escape sequence can move the cursor, recolour the screen, or forge a
/// log line.
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

#[cfg(test)]
mod tests {
    use super::sanitize_for_terminal;

    #[test]
    fn sanitize_replaces_control_characters_but_keeps_tab() {
        assert_eq!(sanitize_for_terminal("a\u{1b}b\nc\td"), "a.b.c\td");
        assert_eq!(sanitize_for_terminal("plain"), "plain");
        assert_eq!(sanitize_for_terminal("\u{7f}"), ".");
    }
}
