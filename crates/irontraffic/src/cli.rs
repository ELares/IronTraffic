// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hand-written argument parser and the `irontraffic validate` mode.
//!
//! Grammar, exactly:
//!
//! ```text
//! argv := "--version" | "-V"
//!       | "--help" | "-h"
//!       | "validate" flag*
//! flag  := "--config" PATH
//!       |  "--workers" UINT
//!       |  "--bind" ADDR
//!       |  "--upstream" ADDR
//!       |  "--mode" ("balanced" | "shard")
//!       |  "--print"
//! ```
//!
//! `--config` is required for `validate`. A flag may appear at most once; a repeat is
//! a usage error naming the flag. `--flag=value` is not supported and produces a usage
//! error naming the space-separated form, because supporting both doubles the
//! parser's cases for no benefit. An unknown flag is a usage error naming it. A
//! missing value for a flag that takes one is a usage error naming the flag.
//!
//! Exit codes are a contract a CI pipeline branches on and never change meaning:
//! 0 valid (warnings allowed), 1 validation errors, 2 usage error, 3 the
//! configuration file could not be loaded. `run`, `proxy`, and `control` are added by
//! a later issue; adding them here would mean shipping a mode that binds nothing.

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
}

/// The parsed `validate` flags.
struct ValidateArgs {
    config: PathBuf,
    workers: Option<usize>,
    bind: Option<BindAddr>,
    upstream: Option<UpstreamAddr>,
    mode: Option<ModeSpec>,
    print: bool,
}

/// Parses `argv` and runs the requested command.
///
/// Exit codes: 0 valid or informational, 1 validation errors, 2 usage error,
/// 3 the configuration file could not be loaded.
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
        return Err("missing command; expected \"validate\"".to_owned());
    };

    if head != "validate" {
        return Err(format!(
            "unrecognised command \"{}\"; expected \"validate\", \"--version\", or \"--help\"",
            sanitize_for_terminal(head)
        ));
    }

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

    let config = config.ok_or_else(|| "\"--config\" is required for \"validate\"".to_owned())?;

    Ok(Command::Validate(ValidateArgs {
        config,
        workers,
        bind,
        upstream,
        mode,
        print,
    }))
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
    writeln!(out, "flags for validate:")?;
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
        "  --print              print the resolved document as JSON to stdout"
    )?;
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
