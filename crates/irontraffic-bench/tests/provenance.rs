// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provenance capture tests: parsers over checked-in fixture text, the
//! publishing guard's six conditions, the burstable shape rule, the
//! civil-date formatter, and the bounded, timed, killed-and-reaped subprocess
//! probe (behind `#[cfg(unix)]`, per the issue's own instruction to use a
//! throwaway `/bin/sh` script rather than a committed binary or a new crate).

use irontraffic_bench::{
    BenchError, BuildStamp, CaptureInputs, CpuInfoFields, PROBE_TIMEOUT_SECONDS, Provenance,
    StampSource, ToolStamp, capture_build_stamp, format_utc_date, is_burstable,
    normalize_instance_type, parse_cpuinfo, parse_meminfo, read_bounded, render_hardware,
    resolve_cpu_model,
};
use proptest::prelude::*;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A fully specified, fully publishable `Provenance`. Every test that
/// exercises `recompute_publishable` starts here and flips exactly one axis,
/// the same shape as `base_cell()` in `tests/cell_id.rs`.
fn base_provenance() -> Provenance {
    let clean_stamp = || BuildStamp {
        name: "irontraffic".to_owned(),
        version: "0.1.0".to_owned(),
        git_sha: "0a1b2c3d4e5f".to_owned(),
        dirty: false,
        profile: "release".to_owned(),
        features: Vec::new(),
        stamp_source: StampSource::Embedded,
    };
    let mut provenance = Provenance {
        utc_date: "2026-07-24T00:00:00Z".to_owned(),
        hardware: "Example CPU, 8c/16t, 32 GiB".to_owned(),
        cpu_model: "Example CPU".to_owned(),
        cpu_arch: "aarch64".to_owned(),
        physical_cores: 8,
        physical_cores_assumed: false,
        logical_cores: 16,
        mem_bytes: 32 * 1024 * 1024 * 1024,
        instance_type: None,
        burstable: false,
        kernel: "6.1.0-generic".to_owned(),
        clocksource: "tsc".to_owned(),
        governor: Some("performance".to_owned()),
        thermal_throttle_count: Some(0),
        ulimit_nofile: 1_048_576,
        ip_local_port_range: Some((32_768, 60_999)),
        sut: clean_stamp(),
        origin: clean_stamp(),
        loadgen: ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 30,
        repetitions: 3,
        publishable: true,
        unpublishable_reasons: Vec::new(),
    };
    provenance.recompute_publishable();
    assert!(
        provenance.publishable,
        "base_provenance's own fixture precondition: it must start fully publishable so \
         each test can flip exactly one axis and attribute the resulting reason to it"
    );
    provenance
}

// ---------------------------------------------------------------------------
// 1 / 1a: /proc/cpuinfo fixtures.
// ---------------------------------------------------------------------------

#[test]
fn parses_cpuinfo_fixture() {
    let bytes = std::fs::read(fixture_path("cpuinfo-graviton.txt"))
        .expect("the checked-in aarch64 cpuinfo fixture must be present and readable");
    let fields = parse_cpuinfo(&bytes).expect("a real aarch64 /proc/cpuinfo must parse");

    assert_eq!(fields.logical_cores, 64);
    assert_eq!(fields.physical_cores, 64);
    assert!(fields.physical_cores_assumed);
    assert!(
        fields.model_name.is_none(),
        "a real aarch64 cpuinfo carries no model name line"
    );
    assert_eq!(fields.cpu_implementer.as_deref(), Some("0x41"));
    assert_eq!(fields.cpu_part.as_deref(), Some("0xd40"));

    let cpu_model = resolve_cpu_model(&fields, None)
        .expect("the implementer/part composed fallback must succeed, not error");
    assert_eq!(cpu_model, "aarch64 impl 0x41 part 0xd40");
}

#[test]
fn parses_dual_socket_cpuinfo() {
    let bytes = std::fs::read(fixture_path("cpuinfo-dual-socket.txt"))
        .expect("the checked-in dual-socket cpuinfo fixture must be present and readable");
    let fields = parse_cpuinfo(&bytes).expect("a real dual-socket /proc/cpuinfo must parse");

    assert_eq!(fields.logical_cores, 64);
    assert_eq!(
        fields.physical_cores, 32,
        "two sockets of 16 cores must count as 32 physical cores, proving (physical id, core id) \
         PAIRS are counted rather than bare core id values (which restart at 0 per socket and \
         would otherwise undercount to 16)"
    );
    assert!(!fields.physical_cores_assumed);
    // Invariant 3 (logical_cores >= physical_cores >= 1) already follows from
    // the two literal assert_eq! calls above (64 >= 32 >= 1); a separate
    // assertion here would be implied by them, not an independent check.
    // Invariant 3 is independently enforced (and watched to fail) by the
    // debug_assert in assemble_provenance, see src/provenance.rs.
}

// ---------------------------------------------------------------------------
// 2: /proc/meminfo fixture.
// ---------------------------------------------------------------------------

#[test]
fn parses_meminfo_fixture() {
    let bytes = std::fs::read(fixture_path("meminfo.txt"))
        .expect("the checked-in meminfo fixture must be present and readable");
    let mem_bytes = parse_meminfo(&bytes).expect("a real /proc/meminfo must parse");
    assert_eq!(mem_bytes, 32_819_300_u64 * 1024);
}

// ---------------------------------------------------------------------------
// 3 / 4 / 5: cpuinfo edge cases.
// ---------------------------------------------------------------------------

#[test]
fn rejects_empty_cpuinfo() {
    let err = parse_cpuinfo(&[]).expect_err("an empty buffer is not a zero-core machine");
    assert!(matches!(err, BenchError::Io { .. }));
}

#[test]
fn rejects_oversized_cpuinfo() {
    let big = vec![b'x'; 5 * 1024 * 1024];
    let start = std::time::Instant::now();
    let err = parse_cpuinfo(&big).expect_err("a 5 MB buffer exceeds the 4 MiB cap");
    assert!(matches!(err, BenchError::Io { .. }));
    // Generous on purpose (the issue's own bound): this is an O(1) length
    // check ahead of any scan, not a tight timing ceiling, so it is not
    // subject to the flakiness a scheduler-noise-sized bound would have.
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn rejects_non_utf8_field() {
    let mut bytes = b"processor\t: 0\nmodel name\t: bad-".to_vec();
    bytes.push(0xFF);
    bytes.extend_from_slice(b"-cpu\n");
    let err =
        parse_cpuinfo(&bytes).expect_err("invalid utf-8 must be rejected, never lossy-decoded");
    assert!(matches!(err, BenchError::Parse { .. }));
    let message = err.to_string();
    assert!(
        !message.contains('\u{FFFD}'),
        "the error message must not contain a replacement character: message was {message:?}"
    );
}

// ---------------------------------------------------------------------------
// 6: the rendered hardware string.
// ---------------------------------------------------------------------------

/// Hand-rolled check for `^.+, \d+c/\d+t, \d+ GiB$` without pulling in a
/// `regex` dependency this crate does not otherwise need.
fn matches_hardware_shape(s: &str) -> bool {
    let Some((prefix, rest)) = s.split_once(", ") else {
        return false;
    };
    if prefix.is_empty() {
        return false;
    }
    let Some((cores, rest)) = rest.split_once(", ") else {
        return false;
    };
    let Some((physical, logical)) = cores.split_once('c') else {
        return false;
    };
    let Some(logical) = logical.strip_prefix('/') else {
        return false;
    };
    let Some(logical) = logical.strip_suffix('t') else {
        return false;
    };
    let Some(mem) = rest.strip_suffix(" GiB") else {
        return false;
    };
    !physical.is_empty()
        && physical.bytes().all(|b| b.is_ascii_digit())
        && !logical.is_empty()
        && logical.bytes().all(|b| b.is_ascii_digit())
        && !mem.is_empty()
        && mem.bytes().all(|b| b.is_ascii_digit())
}

#[test]
fn hardware_string_has_no_path_or_at() {
    let cpuinfo_bytes = std::fs::read(fixture_path("cpuinfo-dual-socket.txt"))
        .expect("the checked-in dual-socket cpuinfo fixture must be present and readable");
    let fields =
        parse_cpuinfo(&cpuinfo_bytes).expect("a real dual-socket /proc/cpuinfo must parse");
    let cpu_model = resolve_cpu_model(&fields, None).expect("model name fallback must succeed");
    let meminfo_bytes = std::fs::read(fixture_path("meminfo.txt"))
        .expect("the checked-in meminfo fixture must be present and readable");
    let mem_bytes = parse_meminfo(&meminfo_bytes).expect("a real /proc/meminfo must parse");

    let hardware = render_hardware(
        &cpu_model,
        fields.physical_cores,
        fields.logical_cores,
        mem_bytes,
    );

    assert!(
        matches_hardware_shape(&hardware),
        "hardware string {hardware:?} does not match <model>, <n>c/<n>t, <n> GiB"
    );
    let before_first_comma =
        &hardware[..hardware.find(',').expect("hardware must contain a comma")];
    assert!(!before_first_comma.contains('/'));
    assert!(!hardware.contains('@'));
}

// ---------------------------------------------------------------------------
// 7 / 7a: burstable detection.
// ---------------------------------------------------------------------------

#[test]
fn burstable_prefixes_are_detected() {
    assert!(is_burstable("t4g.large"));
    assert!(is_burstable("t2.micro"));
    assert!(is_burstable("t3a.small"));
    assert!(!is_burstable("c7g.16xlarge"));
    assert!(!is_burstable("m6i.large"));
}

#[test]
fn burstable_shape_rule_catches_unlisted_families() {
    assert!(is_burstable("t6i.large"));
    assert!(is_burstable("t7.medium"));
    assert!(is_burstable("t9a.xlarge"));
    assert!(
        !is_burstable("trn1.2xlarge"),
        "trn1 is the case that proves a digit must follow the t immediately"
    );
    assert!(!is_burstable("tap.large"));
    assert!(!is_burstable("c7g.16xlarge"));
}

// ---------------------------------------------------------------------------
// 7b / 7c / 7d: cpu_model and instance_type normalisation.
// ---------------------------------------------------------------------------

#[test]
fn intel_brand_string_is_cut_at_the_at_sign() {
    let fields = CpuInfoFields {
        model_name: Some("Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz".to_owned()),
        ..CpuInfoFields::default()
    };
    let cpu_model =
        resolve_cpu_model(&fields, None).expect("a model name with an @ must still resolve");
    assert_eq!(cpu_model, "Intel(R) Xeon(R) CPU E5-2686 v4");

    let hardware = render_hardware(&cpu_model, 1, 2, 1024 * 1024 * 1024);
    assert!(
        !hardware.contains('@'),
        "without the @ cut, invariant 2 fails on most x86_64 hardware in existence"
    );
}

#[test]
fn over_long_or_hostile_cpu_model_is_rejected() {
    let too_long = "A".repeat(200);
    let with_escape = "prefix \x1b[2J suffix".to_owned();
    let with_nul = "prefix\0suffix".to_owned();

    for raw in [too_long, with_escape, with_nul] {
        let fields = CpuInfoFields {
            model_name: Some(raw.clone()),
            ..CpuInfoFields::default()
        };
        let err = resolve_cpu_model(&fields, None).expect_err(&format!(
            "hostile model name {raw:?} must be rejected, not laundered"
        ));
        assert!(matches!(err, BenchError::Parse { .. }));
    }
}

#[test]
fn instance_type_with_a_separator_becomes_none() {
    // `normalize_instance_type` returns `Option`, never `Result`: there is no
    // way for a hostile instance_type to make `capture` return `Err`, which
    // is the "capture still Ok" property this test pins structurally rather
    // than by re-running the whole live capture pipeline.
    assert_eq!(normalize_instance_type("../../etc"), None);
    assert_eq!(normalize_instance_type("Standard PC/Q35"), None);
    assert_eq!(
        normalize_instance_type("Standard PC"),
        None,
        "a space is outside instance_type's character class, and the value is about to become \
         part of a directory name"
    );
}

// ---------------------------------------------------------------------------
// Unix-only fixture-script infrastructure for 7e, 7f, 9a, and the developer-
// machine acceptance check. Each test writes its own throwaway `/bin/sh`
// script into a fresh temp directory and deletes it afterward: not a
// committed binary, not a new crate, per the issue's own instruction.
// ---------------------------------------------------------------------------

#[cfg(unix)]
static SCRIPT_DIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(unix)]
struct ScriptDir {
    dir: std::path::PathBuf,
}

#[cfg(unix)]
impl ScriptDir {
    /// `#[allow(clippy::expect_used)]`: test-support helper, not itself a
    /// `#[test]` fn, so clippy's test exemption for `expect_used` does not
    /// extend to it (see `base_cell()` in `tests/cell_id.rs` for the same
    /// pattern).
    #[allow(clippy::expect_used, reason = "see the impl block's doc comment above")]
    fn new() -> Self {
        let id = SCRIPT_DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "irontraffic-bench-provenance-test-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)
            .expect("a temp directory for a fixture script must be creatable");
        Self { dir }
    }

    /// Writes an executable `/bin/sh` script and returns its path.
    #[allow(
        clippy::expect_used,
        reason = "test-support helper, not itself a #[test] fn"
    )]
    fn write_script(&self, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = self.dir.join(name);
        std::fs::write(&path, body).expect("the fixture script must be writable");
        let mut perms = std::fs::metadata(&path)
            .expect("the fixture script's metadata must be readable")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("the fixture script must be made executable");
        path
    }
}

#[cfg(unix)]
impl Drop for ScriptDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A build-stamp-shaped `/bin/sh` script: answers `--version --json` with the
/// given JSON body (verbatim) and exits 0, and answers plain `--version` with
/// a harmless version string, also exiting 0. `json_body` is inserted as-is
/// inside single quotes, so it must not itself contain a single quote.
#[cfg(unix)]
fn stamp_script_body(json_body: &str) -> String {
    format!(
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ] && [ \"$2\" = \"--json\" ]; then\n\
         \x20\x20echo '{json_body}'\n\
         \x20\x20exit 0\n\
         fi\n\
         echo '1.0.0'\n\
         exit 0\n"
    )
}

/// Reads a PID that a fixture script wrote to `pidfile` (via `echo $$ >`,
/// before it did anything else), and asserts the OS process table no longer
/// has an entry for it: neither still running, nor a killed-but-unreaped
/// zombie (which `ps -p` would still report, in state `Z`, on both Linux and
/// macOS). This is what distinguishes "the child was reaped" from "the child
/// was merely signalled", the exact gap edge case 12 and 12a call out: a
/// probe runs at least four times per harness invocation, so an unreaped
/// child is a zombie accumulated once per run.
#[cfg(unix)]
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn"
)]
fn assert_process_reaped(pidfile: &std::path::Path) {
    let pid_text = std::fs::read_to_string(pidfile)
        .expect("the fixture script must have written its own pid before producing any output");
    let pid = pid_text.trim();
    let output = std::process::Command::new("ps")
        .args(["-p", pid])
        .output()
        .expect("ps must be runnable to check for a leaked process");
    assert!(
        !output.status.success(),
        "pid {pid} still has an entry in the process table (running or zombie) after \
         capture_build_stamp returned"
    );
}

/// This process's own resident set size, in KiB, via `ps -o rss=`. Used only
/// to show a bounded probe did NOT buffer a multi-megabyte flood in memory;
/// the whole test binary's RSS is noisier than a dedicated process would be,
/// which is exactly why the assertion built on it uses megabytes of slack,
/// not kilobytes.
#[cfg(unix)]
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn"
)]
fn resident_kib() -> u64 {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .expect("ps must be runnable to measure resident memory");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 7e: bounded, timed, killed-and-reaped probing.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn probe_output_is_capped_and_the_child_is_reaped() {
    let scripts = ScriptDir::new();

    // Prints far more than PROBE_OUTPUT_CAP (64 KiB) before it would ever
    // exit on its own; capture_build_stamp must not buffer it all.
    let flood_pidfile = scripts.dir.join("flood.pid");
    let flood = scripts.write_script(
        "flood.sh",
        &format!(
            "#!/bin/sh\necho $$ > {}\nyes 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | head -c 10485760\n",
            flood_pidfile.display()
        ),
    );
    let before_kib = resident_kib();
    let start = std::time::Instant::now();
    let err = capture_build_stamp(&flood).expect_err("output exceeding the cap must be rejected");
    assert!(matches!(err, BenchError::Io { .. }));
    assert!(start.elapsed() < std::time::Duration::from_secs(PROBE_TIMEOUT_SECONDS + 1));
    let after_kib = resident_kib();
    assert!(
        after_kib < before_kib + 5 * 1024,
        "resident memory grew from {before_kib} KiB to {after_kib} KiB, which looks like the \
         10 MiB flood was buffered rather than capped"
    );
    assert_process_reaped(&flood_pidfile);

    // Sleeps well past PROBE_TIMEOUT_SECONDS; capture_build_stamp must kill
    // it at the timeout rather than waiting for it to finish.
    let hang_pidfile = scripts.dir.join("hang.pid");
    let hang = scripts.write_script(
        "hang.sh",
        &format!(
            "#!/bin/sh\necho $$ > {}\nsleep 60\n",
            hang_pidfile.display()
        ),
    );
    let start = std::time::Instant::now();
    let err =
        capture_build_stamp(&hang).expect_err("a hanging probe must be killed at the timeout");
    assert!(matches!(err, BenchError::Io { .. }));
    assert!(start.elapsed() < std::time::Duration::from_secs(PROBE_TIMEOUT_SECONDS + 1));
    assert_process_reaped(&hang_pidfile);
}

// ---------------------------------------------------------------------------
// 7f: hostile build-stamp fields.
// ---------------------------------------------------------------------------

/// Builds the failure message for one of `hostile_build_stamp_fields_are_rejected`'s
/// three `assert!` calls below, distinguishing a starved fixture-script probe
/// from a real validation defect rather than letting a bare
/// `assert!(matches!(..))` discard which variant actually came back: the
/// fifth member of issue #811's starvation family. It surfaced when this
/// branch's CI run 30681244144 (job 91318545930, commit 5b29357) failed here
/// with exactly that bare, diagnostic-free assertion. WHY it flaked on that
/// run and not on earlier ones is NOT established: in CI this branch's probe
/// suite was if anything faster than main's (19.24s and 19.00s against
/// 19.73s) with the provenance suite constant, and the two binaries run
/// sequentially inside one `cargo test` invocation, so do not read a
/// causal story into it. (Tracking issue #825 is a sibling gap in the same
/// fix.) `capture_build_stamp` runs the fixture script under `run_bounded`'s
/// `PROBE_TIMEOUT_SECONDS` wall-clock kill; if the script is never scheduled
/// in time to run and print its hostile output at all, `run_bounded` returns
/// `BenchError::Io` before any parsing or field validation happens, which is
/// starvation, not evidence that `field`'s validation accepted a hostile
/// value. A variant that is neither `Parse` nor `Io` is not the starvation
/// shape either, so it is named as a likely real defect instead. Prints the
/// variant actually received (`{err:?}`) in both arms, since that is the
/// whole diagnostic the previous bare assertion discarded.
///
/// Note the `Io` arm does not name one kill path: `run_bounded` returns `Io`
/// for the wall-clock timeout, the combined-output byte cap, AND a spawn
/// failure. The arm's denial holds on all three (acceptance of a hostile
/// value produces `Ok`, which dies at `expect_err` before reaching here), so
/// the message points the reader at the printed variant rather than
/// asserting which path fired.
#[cfg(unix)]
fn hostile_field_message(err: &BenchError, field: &str) -> String {
    match err {
        BenchError::Io { .. } => format!(
            "the {field} probe returned {err:?} instead of BenchError::Parse; that is one of \
             run_bounded's own kill paths firing (PROBE_TIMEOUT_SECONDS's wall-clock kill, \
             the combined-output byte cap, or a spawn failure: read the printed variant \
             above, whose text names which). The wall-clock case is starvation, the fixture \
             script never having been scheduled in time to produce the hostile {field} value \
             at all. On EVERY one of these paths no parsing or validation happened, so none \
             of them is evidence that {field} validation accepts a hostile value"
        ),
        other => format!(
            "the {field} probe returned {other:?} instead of BenchError::Parse, and that is \
             not the starvation shape either (starvation surfaces as BenchError::Io); this \
             looks like a real defect in {field} validation"
        ),
    }
}

#[cfg(unix)]
#[test]
fn hostile_build_stamp_fields_are_rejected() {
    let scripts = ScriptDir::new();

    let hostile_version = scripts.write_script(
        "hostile_version.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"0.1.0 built by alice@build-host","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"release","features":[]}"#,
        ),
    );
    let err = capture_build_stamp(&hostile_version)
        .expect_err("a version containing a space and an @ must be rejected");
    assert!(
        matches!(err, BenchError::Parse { .. }),
        "{}",
        hostile_field_message(&err, "version")
    );

    let many_features = "\"x\",".repeat(10_000);
    let many_features = many_features.trim_end_matches(',');
    let hostile_features = scripts.write_script(
        "hostile_features.sh",
        &stamp_script_body(&format!(
            r#"{{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"release","features":[{many_features}]}}"#
        )),
    );
    let err =
        capture_build_stamp(&hostile_features).expect_err("more than 64 features must be rejected");
    assert!(
        matches!(err, BenchError::Parse { .. }),
        "{}",
        hostile_field_message(&err, "features")
    );

    let hostile_sha = scripts.write_script(
        "hostile_sha.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"../../","dirty":false,"profile":"release","features":[]}"#,
        ),
    );
    let err = capture_build_stamp(&hostile_sha)
        .expect_err("a git_sha containing path traversal characters must be rejected");
    assert!(
        matches!(err, BenchError::Parse { .. }),
        "{}",
        hostile_field_message(&err, "git_sha")
    );
}

// ---------------------------------------------------------------------------
// SHOULD_FIX 3 (issue #783): profile is read back from the binary's own
// stamp, never assumed release.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn embedded_profile_is_read_from_the_binarys_own_stamp_not_assumed_release() {
    let scripts = ScriptDir::new();
    let debug_binary = scripts.write_script(
        "debug_profile.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"debug","features":[]}"#,
        ),
    );
    let stamp = capture_build_stamp(&debug_binary)
        .expect("a well formed debug-profile stamp must be accepted");
    assert_eq!(
        stamp.profile, "debug",
        "profile must be read back from the binary's own stamp; disqualifying condition 4 \
         (non-release build profile) depends on this being the binary's real answer, not an \
         assumed \"release\""
    );
}

// ---------------------------------------------------------------------------
// BLOCKING 2 (issue #783): the Fallback build stamp extracts the version
// token from conventional `<name> <version>` output rather than storing the
// whole line, which the version character class (no space) would otherwise
// always reject.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn fallback_stamp_extracts_the_version_token_from_conventional_version_output() {
    let scripts = ScriptDir::new();
    let release_dir = scripts.dir.join("release");
    std::fs::create_dir_all(&release_dir).expect("the release subdirectory must be creatable");
    let binary_path = release_dir.join("irontraffic");
    // Rejects --version --json outright (exit 2, no JSON), and answers plain
    // --version exactly the way both of this repository's own binaries do:
    // "<name> <version>", not a bare version.
    std::fs::write(
        &binary_path,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ] && [ \"$2\" = \"--json\" ]; then\n\
         \x20\x20exit 2\n\
         fi\n\
         echo 'irontraffic 0.1.0'\n\
         exit 0\n",
    )
    .expect("the fixture binary must be writable");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&binary_path)
            .expect("the fixture binary's metadata must be readable")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&binary_path, perms)
            .expect("the fixture binary must be made executable");
    }

    let stamp = capture_build_stamp(&binary_path).expect(
        "a binary that rejects --version --json but answers plain --version with the \
         conventional \"<name> <version>\" form must still fall back successfully, not be \
         refused as unparseable",
    );
    assert_eq!(stamp.stamp_source, StampSource::Fallback);
    assert_eq!(
        stamp.version, "0.1.0",
        "the version token must be extracted from \"irontraffic 0.1.0\", not the whole line \
         (which contains a space the version character class excludes)"
    );
    assert_eq!(stamp.name, "irontraffic");
    assert_eq!(stamp.profile, "release");
    assert!(
        stamp
            .git_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "git_sha must be lowercase hex (from this worktree's own git rev-parse), got {:?}",
        stamp.git_sha
    );
}

// ---------------------------------------------------------------------------
// SHOULD_FIX 6 (issue #783): a git_sha of the literal "unknown", which
// crates/irontraffic's own build.rs (#427, already merged) documents and
// emits for a source-tarball build with no .git directory and no IT_GIT_SHA
// override, is refused rather than published. DECISION (see PR body): this
// stays a hard error rather than becoming a seventh unpublishable reason.
// An unknown git_sha means the run cannot be attributed to any commit at
// all, which is a stronger failure than "dirty" or "non-release" (both of
// which DO know a specific, recordable fact); it is the "no kernel version,
// no run" contract applied to the git SHA. A tarball build that wants to be
// benchmarked sets IT_GIT_SHA in the environment, per build.rs's own
// documented override.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn embedded_git_sha_of_unknown_is_rejected_not_silently_accepted() {
    let scripts = ScriptDir::new();
    let unknown_sha = scripts.write_script(
        "unknown_sha.sh",
        &stamp_script_body(
            r#"{"name":"irontraffic","version":"0.1.0","git_sha":"unknown","dirty":false,"profile":"release","features":[]}"#,
        ),
    );
    let err = capture_build_stamp(&unknown_sha)
        .expect_err("a git_sha of the literal \"unknown\" must be refused, not published");
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// SHOULD_FIX 4 (issue #783): read_bounded, the module's only file reader and
// its named fail-open, has real coverage.
// ---------------------------------------------------------------------------

#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn"
)]
fn read_bounded_fixture_dir(id: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "irontraffic-bench-read-bounded-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)
        .expect("a temp directory for a read_bounded fixture must be creatable");
    dir
}

#[test]
fn read_bounded_returns_exact_bytes_under_the_cap() {
    let dir = read_bounded_fixture_dir("under");
    let path = dir.join("clocksource");
    std::fs::write(&path, b"tsc").expect("the fixture file must be writable");
    let bytes = read_bounded(&path, 32).expect("a 3 byte file under a 32 byte cap must read fully");
    assert_eq!(bytes, b"tsc");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_bounded_accepts_a_file_of_exactly_cap_bytes() {
    let dir = read_bounded_fixture_dir("exact");
    let path = dir.join("exact");
    std::fs::write(&path, b"12345678").expect("the fixture file must be writable");
    let bytes = read_bounded(&path, 8).expect(
        "a file whose length equals the cap exactly must be accepted, not rejected off by one",
    );
    assert_eq!(bytes.len(), 8);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_bounded_rejects_a_file_that_exceeds_the_cap_rather_than_truncating() {
    // Edge case 4a's exact scenario: "tsc" is a valid clocksource value and
    // is also a byte-for-byte PREFIX of the hostile content below, so a
    // truncating fail-open (returning the first `cap` bytes instead of
    // erroring) would read back exactly "tsc" and silently make an
    // unpublishable run publishable.
    let dir = read_bounded_fixture_dir("over");
    let path = dir.join("clocksource");
    std::fs::write(&path, b"tsc_hpet_hostile_padding_past_the_cap")
        .expect("the fixture file must be writable");
    let err = read_bounded(&path, 3).expect_err(
        "a file exceeding the cap must be rejected, never truncated to the first cap bytes",
    );
    assert!(matches!(err, BenchError::Io { .. }));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// SHOULD_FIX 8 (issue #783): both ToolStamp Field-bounds rows are enforced.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn capture_rejects_a_loadgen_version_that_violates_its_character_class() {
    let scripts = ScriptDir::new();
    let clean_stamp = scripts.write_script(
        "clean.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"release","features":[]}"#,
        ),
    );
    let inputs = CaptureInputs {
        sut_binary: clean_stamp.clone(),
        origin_binary: clean_stamp,
        loadgen: ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0@evil".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 30,
        repetitions: 1,
        allow_dirty: false,
    };
    let err = Provenance::capture(&inputs).expect_err(
        "a loadgen version containing '@' violates ToolStamp::version's character class",
    );
    assert!(matches!(err, BenchError::Parse { .. }));
}

#[cfg(unix)]
#[test]
fn capture_rejects_a_loadgen_image_digest_that_violates_its_character_class() {
    let scripts = ScriptDir::new();
    let clean_stamp = scripts.write_script(
        "clean.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"release","features":[]}"#,
        ),
    );
    let inputs = CaptureInputs {
        sut_binary: clean_stamp.clone(),
        origin_binary: clean_stamp,
        loadgen: ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: Some("sha256/UPPERCASE-not-allowed".to_owned()),
        },
        warmup_seconds: 5,
        measure_seconds: 30,
        repetitions: 1,
        allow_dirty: false,
    };
    let err = Provenance::capture(&inputs).expect_err(
        "a loadgen image_digest containing '/' and uppercase violates its character class",
    );
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// 8 / 9 / 10 / 11 / 12: recompute_publishable's six conditions.
// ---------------------------------------------------------------------------

#[test]
fn burstable_is_never_publishable() {
    let mut provenance = base_provenance();
    provenance.instance_type = Some("t4g.large".to_owned());
    provenance.burstable = true;
    provenance.recompute_publishable();

    assert!(!provenance.publishable);
    assert!(
        provenance
            .unpublishable_reasons
            .iter()
            .any(|r| r.contains("t4g.large")),
        "reasons were {:?}",
        provenance.unpublishable_reasons
    );
}

#[test]
fn dirty_is_never_publishable() {
    let mut provenance = base_provenance();
    provenance.sut.dirty = true;
    provenance.recompute_publishable();

    assert!(!provenance.publishable);
    assert!(
        provenance
            .unpublishable_reasons
            .contains(&"dirty worktree".to_owned())
    );
}

#[cfg(unix)]
#[test]
fn capture_rejects_dirty_without_allow_dirty() {
    let scripts = ScriptDir::new();
    let dirty_script = scripts.write_script(
        "dirty.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":true,"profile":"release","features":[]}"#,
        ),
    );

    let refused_inputs = CaptureInputs {
        sut_binary: dirty_script.clone(),
        origin_binary: dirty_script,
        loadgen: ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 30,
        repetitions: 1,
        allow_dirty: false,
    };
    let err = Provenance::capture(&refused_inputs)
        .expect_err("a dirty stamp without --allow-dirty must refuse to start the run");
    assert!(matches!(err, BenchError::Parse { .. }));

    let allowed_inputs = CaptureInputs {
        allow_dirty: true,
        ..refused_inputs
    };
    let provenance = Provenance::capture(&allowed_inputs)
        .expect("a dirty stamp WITH --allow-dirty must be recorded, not refused");
    assert!(provenance.sut.dirty);
    assert!(!provenance.publishable);
    assert!(
        provenance
            .unpublishable_reasons
            .contains(&"dirty worktree".to_owned())
    );
}

#[test]
fn fallback_stamp_is_never_publishable() {
    let mut provenance = base_provenance();
    provenance.sut.stamp_source = StampSource::Fallback;
    provenance.recompute_publishable();

    assert!(!provenance.publishable);
    assert!(
        provenance
            .unpublishable_reasons
            .contains(&"build stamp reconstructed by fallback".to_owned())
    );
}

#[test]
fn non_tsc_clocksource_is_unpublishable_on_x86_64() {
    let mut hpet = base_provenance();
    hpet.cpu_arch = "x86_64".to_owned();
    hpet.clocksource = "hpet".to_owned();
    hpet.recompute_publishable();
    assert!(!hpet.publishable);
    assert!(
        hpet.unpublishable_reasons
            .iter()
            .any(|r| r.contains("hpet")),
        "reasons were {:?}",
        hpet.unpublishable_reasons
    );

    let mut tsc = base_provenance();
    tsc.cpu_arch = "x86_64".to_owned();
    tsc.clocksource = "tsc".to_owned();
    tsc.recompute_publishable();
    assert!(
        !tsc.unpublishable_reasons
            .iter()
            .any(|r| r.contains("is not tsc")),
        "reasons were {:?}",
        tsc.unpublishable_reasons
    );

    let mut aarch64_hpet = base_provenance();
    aarch64_hpet.cpu_arch = "aarch64".to_owned();
    aarch64_hpet.clocksource = "hpet".to_owned();
    aarch64_hpet.recompute_publishable();
    assert!(
        !aarch64_hpet
            .unpublishable_reasons
            .iter()
            .any(|r| r.contains("is not tsc")),
        "condition 5 must not apply off x86_64: reasons were {:?}",
        aarch64_hpet.unpublishable_reasons
    );
}

#[test]
fn port_range_malformed_is_none_not_error() {
    // parse_port_range("garbage") == None is pinned directly (hermetically,
    // with no filesystem access) by the internal, Linux-only unit test
    // `port_range_parses_two_whitespace_separated_integers` in
    // src/provenance.rs; ip_local_port_range's type is `Option`, never a
    // `Result`, so a malformed range structurally cannot make `capture`
    // return `Err` (edge case 8), which this test pins at the level the
    // rest of the publishing guard tests operate at.
    let mut provenance = base_provenance();
    provenance.ip_local_port_range = None;
    provenance.recompute_publishable();

    assert!(!provenance.publishable);
    assert!(
        provenance
            .unpublishable_reasons
            .contains(&"ephemeral port range unavailable".to_owned())
    );
}

// ---------------------------------------------------------------------------
// 13: the civil-date formatter.
// ---------------------------------------------------------------------------

#[test]
fn utc_date_formats_three_known_epochs() {
    assert_eq!(format_utc_date(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_utc_date(1_600_000_000), "2020-09-13T12:26:40Z");
    assert_eq!(
        format_utc_date(951_782_400),
        "2000-02-29T00:00:00Z",
        "the leap-day case, which a hand-rolled civil-date conversion is most likely to get wrong"
    );
}

// ---------------------------------------------------------------------------
// Property test: the six unpublishable reasons are always sorted, unique,
// empty exactly when publishable, and idempotent.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn unpublishable_reasons_are_sorted_and_unique(
        burstable in any::<bool>(),
        sut_dirty in any::<bool>(),
        fallback in any::<bool>(),
        non_release in any::<bool>(),
        bad_clocksource in any::<bool>(),
        no_port_range in any::<bool>(),
    ) {
        let mut provenance = base_provenance();

        provenance.burstable = burstable;
        if burstable {
            provenance.instance_type = Some("t4g.large".to_owned());
        }
        provenance.sut.dirty = sut_dirty;
        if fallback {
            provenance.sut.stamp_source = StampSource::Fallback;
        }
        if non_release {
            provenance.sut.profile = "debug".to_owned();
        }
        provenance.cpu_arch = "x86_64".to_owned();
        provenance.clocksource = if bad_clocksource { "hpet".to_owned() } else { "tsc".to_owned() };
        if no_port_range {
            provenance.ip_local_port_range = None;
        }

        provenance.recompute_publishable();

        let first = provenance.unpublishable_reasons.clone();
        let mut sorted_unique = first.clone();
        sorted_unique.sort();
        sorted_unique.dedup();
        prop_assert_eq!(&first, &sorted_unique);
        prop_assert_eq!(first.is_empty(), provenance.publishable);

        provenance.recompute_publishable();
        prop_assert_eq!(&provenance.unpublishable_reasons, &first);
    }
}

// ---------------------------------------------------------------------------
// Acceptance criterion: Provenance::capture on the developer machine returns
// Ok and produces a hardware string with no `/` and no `@`.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn capture_on_this_machine_produces_a_clean_hardware_string() {
    let scripts = ScriptDir::new();
    let stamp_binary = scripts.write_script(
        "stamp.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"release","features":[]}"#,
        ),
    );

    let inputs = CaptureInputs {
        sut_binary: stamp_binary.clone(),
        origin_binary: stamp_binary,
        loadgen: ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 30,
        repetitions: 1,
        allow_dirty: false,
    };

    let provenance = Provenance::capture(&inputs)
        .expect("capture must succeed on this development machine (linux or macos)");
    let before_first_comma = &provenance.hardware[..provenance
        .hardware
        .find(',')
        .expect("hardware must contain a comma")];
    assert!(!before_first_comma.contains('/'));
    assert!(!provenance.hardware.contains('@'));
    // Invariant 7, against a real rustix::process::getrlimit() reading on
    // this machine, not a fixture literal.
    assert!(provenance.ulimit_nofile > 0);

    // macOS is a supported development platform but never a publishing
    // platform: the capture succeeds, but clocksource is the fixed
    // "unavailable" sentinel and the run is unconditionally unpublishable
    // (condition 6 fires because /proc/sys/net/ipv4/ip_local_port_range does
    // not exist off Linux). This is the direct check for the acceptance
    // criterion "A Provenance captured on macOS has clocksource:
    // 'unavailable' and publishable: false".
    #[cfg(target_os = "macos")]
    {
        assert_eq!(provenance.clocksource, "unavailable");
        assert!(!provenance.publishable);
    }
}

// ---------------------------------------------------------------------------
// SHOULD_FIX 7 (issue #783): the live host capture is verified against an
// independent oracle, not just a shape check a hard coded constant would
// also satisfy.
// ---------------------------------------------------------------------------

/// Runs `sysctl -n <key>` directly via `std::process::Command`, NOT through
/// this crate's own `run_sysctl` helper: the whole point is an oracle that
/// does not share code with the function under test, so a mutation that hard
/// codes `capture_host_facts`'s macOS branch to a placeholder constant is
/// caught by comparison against a value this test computed on its own.
#[cfg(target_os = "macos")]
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn"
)]
fn oracle_sysctl(key: &str) -> String {
    let output = std::process::Command::new("sysctl")
        .args(["-n", key])
        .output()
        .expect("sysctl must be runnable on macOS to compute the oracle value");
    assert!(output.status.success(), "sysctl -n {key} exited non-zero");
    String::from_utf8(output.stdout)
        .expect("sysctl output must be utf-8")
        .trim()
        .to_owned()
}

#[cfg(target_os = "macos")]
#[test]
fn capture_host_facts_matches_independently_queried_sysctl_values() {
    let scripts = ScriptDir::new();
    let stamp_binary = scripts.write_script(
        "stamp.sh",
        &stamp_script_body(
            r#"{"name":"test-binary","version":"1.0.0","git_sha":"0a1b2c3d4e5f","dirty":false,"profile":"release","features":[]}"#,
        ),
    );
    let inputs = CaptureInputs {
        sut_binary: stamp_binary.clone(),
        origin_binary: stamp_binary,
        loadgen: ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 30,
        repetitions: 1,
        allow_dirty: false,
    };
    let provenance = Provenance::capture(&inputs).expect("capture must succeed on macOS");

    let expected_kernel = oracle_sysctl("kern.osrelease");
    assert_eq!(
        provenance.kernel, expected_kernel,
        "kernel must be read from kern.osrelease on this machine, not a placeholder constant"
    );

    let expected_mem_bytes: u64 = oracle_sysctl("hw.memsize")
        .parse()
        .expect("hw.memsize must be an integer");
    assert_eq!(
        provenance.mem_bytes, expected_mem_bytes,
        "mem_bytes must be read from hw.memsize on this machine, not a placeholder constant"
    );

    // Independent re-derivation of the documented cpu_model normalisation
    // rule (cut at the first '@', trim, collapse internal whitespace runs),
    // not a call into resolve_cpu_model or normalize_cpu_model.
    let raw_brand = oracle_sysctl("machdep.cpu.brand_string");
    let cut_at_at = raw_brand.split('@').next().unwrap_or(&raw_brand).trim();
    let expected_cpu_model = cut_at_at.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(
        provenance.cpu_model, expected_cpu_model,
        "cpu_model must be read from machdep.cpu.brand_string on this machine, not a \
         placeholder constant"
    );
}
