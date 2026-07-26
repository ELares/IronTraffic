// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the `irontraffic validate` mode, driving the real binary.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irontraffic"));
    cmd.env_remove("IRONTRAFFIC_LOG");
    cmd.env_remove("IRONTRAFFIC_WORKERS");
    cmd.env_remove("IRONTRAFFIC_RUNTIME_MODE");
    cmd.env_remove("IRONTRAFFIC_BIND");
    cmd.env_remove("IRONTRAFFIC_UPSTREAM");
    cmd
}

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct FixtureGuard(PathBuf);

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion.
    }
}

// Returns a `Result` rather than unwrapping internally: this helper is not itself
// a `#[test]` function, so clippy's test exemption for `unwrap`/`expect` (real in
// every function actually annotated `#[test]` in this file) does not extend to it.
// Each call site below is inside a `#[test]` fn and unwraps there instead.
fn write_fixture(
    name: &str,
    filename: &str,
    content: &str,
) -> std::io::Result<(PathBuf, FixtureGuard)> {
    let pid = std::process::id();
    let counter = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("irontraffic-validate-cli-{name}-{pid}-{counter}"));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(filename);
    let mut file = std::fs::File::create(&path)?;
    file.write_all(content.as_bytes())?;
    Ok((path, FixtureGuard(dir)))
}

const VALID_YAML: &str = "apiVersion: irontraffic.io/v1\n\
listeners:\n\
\x20\x20- name: web\n\
\x20\x20\x20\x20bind: \"127.0.0.1:0\"\n\
upstream:\n\
\x20\x20address: \"127.0.0.1:9000\"\n";

/// The single line starting with `error:`, without the boilerplate usage block
/// that `cli::run` always prints alongside it (which itself mentions almost
/// every flag name, so asserting against the whole of stderr cannot tell a real
/// error message apart from an empty or wrong one).
///
/// Returns `Option` rather than unwrapping internally: this helper is not
/// itself a `#[test]` function, so clippy's test exemption for `expect` does
/// not extend to it. Each call site is inside a `#[test]` fn and unwraps there.
fn error_line(stderr: &str) -> Option<&str> {
    stderr.lines().find(|line| line.starts_with("error:"))
}

fn duplicate_bind_yaml() -> String {
    "apiVersion: irontraffic.io/v1\n\
     listeners:\n\
     \x20\x20- name: web1\n\
     \x20\x20\x20\x20bind: \"127.0.0.1:8080\"\n\
     \x20\x20- name: web2\n\
     \x20\x20\x20\x20bind: \"127.0.0.1:8080\"\n\
     upstream:\n\
     \x20\x20address: \"10.0.0.1:9000\"\n"
        .to_owned()
}

#[test]
fn validate_valid_config_exits_zero() {
    let (path, _guard) = write_fixture("valid", "doc.yaml", VALID_YAML).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

#[test]
fn validate_duplicate_bind_exits_one_and_names_the_code() {
    let (path, _guard) =
        write_fixture("dup-bind", "doc.yaml", &duplicate_bind_yaml()).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("duplicate_bind_address"), "{stderr}");
}

#[test]
fn validate_missing_config_flag_exits_two() {
    let output = bin().arg("validate").output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Checked on the "error:" line specifically, not the whole of stderr: the
    // usage block printed alongside it also mentions "--config" in its own
    // boilerplate, so a weaker check here would pass even if the real message
    // were empty or wrong.
    let line = error_line(&stderr).expect("an error: line is present");
    assert!(line.contains("--config"), "{line}");
    assert!(line.contains("required"), "{line}");
}

// Not one of the 8 named CLI tests, added on top of them: distinct from
// `validate_missing_config_flag_exits_two` above, which omits `--config`
// entirely and so exercises the "is required" message. This instead types
// `--config` with nothing after it, exercising `missing_value`'s "requires a
// value" message, a different code path mutation testing found untested (a
// version of `missing_value` that always returned an empty or fixed string
// passed every other named test).
#[test]
fn validate_config_flag_with_no_value_is_a_usage_error() {
    let output = bin().arg("validate").arg("--config").output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = error_line(&stderr).expect("an error: line is present");
    assert!(line.contains("--config"), "{line}");
    assert!(line.contains("requires a value"), "{line}");
}

#[test]
fn validate_nonexistent_file_exits_three() {
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg("/definitely/does/not/exist.yaml")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

#[test]
fn validate_equals_form_flag_is_a_usage_error() {
    let output = bin()
        .arg("validate")
        .arg("--config=x.yaml")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--config x.yaml"), "{stderr}");
}

#[test]
fn validate_repeated_flag_is_a_usage_error() {
    let (path, _guard) = write_fixture("repeated", "doc.yaml", VALID_YAML).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Same reasoning as `validate_missing_config_flag_exits_two`: checked on the
    // "error:" line, not the whole of stderr, which always mentions "--config"
    // in its own usage block regardless of what the real message says.
    let line = error_line(&stderr).expect("an error: line is present");
    assert!(line.contains("--config"), "{line}");
    assert!(line.contains("more than once"), "{line}");
}

#[test]
fn validate_print_emits_json_and_still_exits_one_on_error() {
    // `irontraffic`'s own manifest deliberately does not depend on serde_json (the
    // binary's `--print` path goes through `Loaded::render_json`, which is where
    // that dependency lives instead), so this asserts the output is well-formed
    // JSON structurally rather than parsing it with a JSON crate.
    let (path, _guard) =
        write_fixture("print-error", "doc.yaml", &duplicate_bind_yaml()).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .arg("--print")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let trimmed = stdout.trim();
    assert!(trimmed.starts_with('{'), "{trimmed}");
    assert!(trimmed.ends_with('}'), "{trimmed}");
    assert!(trimmed.contains("\"apiVersion\""), "{trimmed}");
    assert!(trimmed.contains("irontraffic.io/v1"), "{trimmed}");
}

#[test]
fn warning_only_config_exits_zero_with_stderr_output() {
    let yaml = "apiVersion: irontraffic.io/v1\n\
                listeners:\n\
                \x20\x20- name: web\n\
                \x20\x20\x20\x20bind: \"127.0.0.1:0\"\n\
                upstream:\n\
                \x20\x20address: \"127.0.0.1:9000\"\n\
                limits:\n\
                \x20\x20max_connections: 2000000\n";
    let (path, _guard) = write_fixture("warning-only", "doc.yaml", yaml).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("WARN"), "{stderr}");
}

// Not one of the 8 named CLI tests, added on top of them: mutation testing found
// that `--workers`, `--bind`, `--upstream`, and `--mode` were never exercised
// through the compiled binary at all (every other test only ever passes
// `--config` and, sometimes, `--print`), so the index arithmetic that advances
// past each of their values, and the "balanced"/"shard" match arms, were free
// to be wrong and every named test still passed.
#[test]
fn validate_accepts_every_flag_and_applies_every_override() {
    let (path, _guard) =
        write_fixture("all-flags", "doc.yaml", VALID_YAML).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .arg("--workers")
        .arg("7")
        .arg("--bind")
        .arg("0.0.0.0:9999")
        .arg("--upstream")
        .arg("10.0.0.5:9000")
        .arg("--mode")
        .arg("shard")
        .arg("--print")
        .output()
        .unwrap();
    // runtime.mode = shard is itself a validation error, so this exits 1 rather
    // than 0; what this test proves is that every flag before --print was
    // consumed correctly (a wrong index step anywhere in that chain would either
    // desync the parse into a usage error, exit 2, or silently drop an override).
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("\"workers\": 7"), "{stdout}");
    assert!(stdout.contains("0.0.0.0:9999"), "{stdout}");
    assert!(stdout.contains("10.0.0.5:9000"), "{stdout}");
    assert!(stdout.contains("\"shard\""), "{stdout}");
}

// Not one of the 8 named CLI tests, added on top of them: proves the "balanced"
// match arm in the flag parser (the other half of the `--mode` grammar) is
// reachable too, complementing the "shard" case exercised above.
#[test]
fn validate_mode_balanced_is_accepted() {
    let (path, _guard) =
        write_fixture("mode-balanced", "doc.yaml", VALID_YAML).expect("fixture writes");
    let output = bin()
        .arg("validate")
        .arg("--config")
        .arg(&path)
        .arg("--mode")
        .arg("balanced")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}
