// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the `irontraffic` binary argument surface.

use std::process::Command;

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irontraffic"));
    cmd.env_remove("IRONTRAFFIC_LOG");
    cmd
}

#[test]
fn version_flag_prints_version_and_exits_zero() {
    let output = bin().arg("--version").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!("irontraffic {}\n", env!("CARGO_PKG_VERSION")).into_bytes()
    );
}

#[test]
fn short_version_flag_matches_long() {
    let long = bin().arg("--version").output().unwrap();
    let short = bin().arg("-V").output().unwrap();
    assert_eq!(long.status.code(), Some(0));
    assert_eq!(short.status.code(), Some(0));
    assert_eq!(long.stdout, short.stdout);
}

#[test]
fn help_flag_exits_zero_and_names_both_flags() {
    let output = bin().arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("irontraffic "));
    assert!(stdout.contains("--version"));
    assert!(stdout.contains("--help"));
}

#[test]
fn no_args_is_usage_error() {
    let output = bin().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"));
}

#[test]
fn unknown_flag_is_usage_error_naming_the_flag() {
    let output = bin().arg("--frobnicate").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--frobnicate"));
}

#[test]
fn version_with_extra_arg_is_usage_error() {
    let output = bin().arg("--version").arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn bad_log_filter_still_starts() {
    let output = bin()
        .arg("--version")
        .env("IRONTRAFFIC_LOG", "nope=::")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!("irontraffic {}\n", env!("CARGO_PKG_VERSION")).into_bytes()
    );
}

#[test]
fn control_characters_in_an_argument_are_not_echoed() {
    let arg = "\u{1b}[2J--frob\nnicate";
    let output = bin().arg(arg).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.as_bytes().contains(&0x1b));
    let error_line = stderr
        .lines()
        .find(|line| line.starts_with("error:"))
        .expect("error: line should be present");
    assert!(error_line.contains("--frob.nicate"));
    assert!(stderr.contains("usage:"));
}
