// SPDX-License-Identifier: MIT OR Apache-2.0
//! Run provenance: hardware, kernel, clocksource, limits, and the build stamp.
//!
//! [`Provenance::capture`] runs exactly once, first, before the harness spawns
//! anything: a run that cannot state its kernel version, its CPU model, its
//! memory total, its clocksource (on Linux) or its file descriptor limit does
//! not start. Every string this module stores is bounded in length and
//! restricted to a fixed character class before it reaches a [`Provenance`]
//! field, because three of the sources here are outside our control: `/proc`
//! and `/sys` on a machine whose mounts we did not create, DMI strings the
//! hypervisor chose, and the stdout of whatever binary path the operator
//! passed on the command line.
//!
//! Privacy: this module records the instance TYPE and the CPU model, never an
//! instance id, an account id, an ARN, an IP address, a hostname or a
//! username. It never shells out to `uname -a`, `lscpu`, `dmidecode`,
//! `hostname`, `whoami`, `id`, or a cloud metadata service; it reads a fixed
//! field list into typed fields instead, which is what makes the privacy rule
//! true by construction rather than by review.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::error::BenchError;

// ---------------------------------------------------------------------------
// Bounds shared by every reader and probe in this module.
// ---------------------------------------------------------------------------

/// Bytes of a single-value `/sys` or `/proc/sys` file the reader will accept.
pub const SMALL_FILE_CAP: usize = 4096;
/// Bytes of `/proc/cpuinfo` or `/proc/meminfo` the reader will accept.
pub const LARGE_FILE_CAP: usize = 4 * 1024 * 1024;
/// Bytes of combined stdout and stderr the reader will accept from a probe.
pub const PROBE_OUTPUT_CAP: usize = 64 * 1024;
/// Wall-clock seconds a probe may take before it is killed and reaped.
pub const PROBE_TIMEOUT_SECONDS: u64 = 10;
/// Most `cpu*` entries the thermal-counter sum will visit.
pub const MAX_CPU_ENTRIES: usize = 4096;

const GIB: u64 = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Character classes. Each returns true for a byte the field is allowed to
// contain; every stored string is checked against exactly one of these.
// ---------------------------------------------------------------------------

fn is_cpu_model_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b" ()._+-".contains(&b)
}

fn is_kernel_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._+-".contains(&b)
}

#[cfg(target_os = "linux")]
fn is_clocksource_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b)
}

#[cfg(target_os = "linux")]
fn is_governor_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b == b'_'
}

fn is_instance_type_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._-".contains(&b)
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._-".contains(&b)
}

fn is_version_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._+-".contains(&b)
}

fn is_git_sha_char(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_profile_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b == b'-'
}

fn is_feature_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b)
}

fn is_tool_version_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b" ._+-".contains(&b)
}

fn is_image_digest_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b':'
}

/// True when `s` is non-empty, at most `cap` bytes, and every byte satisfies
/// `allowed`. The shared shape behind every entry in the "Field bounds" table.
fn bounded_ascii(s: &str, cap: usize, allowed: fn(u8) -> bool) -> bool {
    !s.is_empty() && s.len() <= cap && s.bytes().all(allowed)
}

/// Recovers a poisoned lock rather than panicking: a reader thread panicking
/// mid-read is already reported by [`std::thread::JoinHandle::join`]'s `Err`,
/// so the lock's last-written contents are still the best information this
/// module has, not a reason to panic a second time on the joining thread.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn io_error(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

/// Identity of one measured binary, read back out of the binary itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BuildStamp {
    /// Binary name, for example `irontraffic` or `it-origin`.
    pub name: String,
    /// Cargo package version.
    pub version: String,
    /// Short git SHA the binary was built from.
    pub git_sha: String,
    /// Whether the worktree had uncommitted changes at build time.
    pub dirty: bool,
    /// Cargo profile, for example `release`.
    pub profile: String,
    /// Enabled cargo features, sorted.
    pub features: Vec<String>,
    /// How this stamp was obtained.
    pub stamp_source: StampSource,
}

/// Where a `BuildStamp` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StampSource {
    /// The binary printed it in response to `--version --json`. Publishable.
    Embedded,
    /// Reconstructed from `--version` text plus git. Never publishable.
    Fallback,
}

/// Identity of an external load-generation tool.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ToolStamp {
    /// Tool name, for example `nighthawk`.
    pub name: String,
    /// Version string exactly as the tool reported it.
    pub version: String,
    /// OCI image digest when the tool runs from a container, `None` otherwise.
    pub image_digest: Option<String>,
}

/// Everything a reader needs to know to interpret or reproduce a run.
///
/// Records the instance TYPE and the CPU model. Never an instance id, an
/// account id, an ARN, an IP address, a hostname or a username.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    /// RFC 3339 UTC timestamp, seconds precision, always ending in `Z`.
    pub utc_date: String,
    /// Rendered as `<cpu model>, <physical>c/<logical>t, <mem_gib> GiB`.
    pub hardware: String,
    /// CPU model string as the operating system reports it.
    pub cpu_model: String,
    /// Target architecture of the harness build.
    pub cpu_arch: String,
    /// Physical core count, from distinct `(physical id, core id)` pairs.
    pub physical_cores: u32,
    /// True when `physical_cores` was assumed equal to `logical_cores` because
    /// the topology fields were absent, which is the normal aarch64 case.
    /// Recorded so a reader knows, but NOT a publishing disqualifier.
    pub physical_cores_assumed: bool,
    /// Logical core count.
    pub logical_cores: u32,
    /// Total system memory in bytes.
    pub mem_bytes: u64,
    /// Cloud instance type when detectable.
    pub instance_type: Option<String>,
    /// True when `instance_type` is a known burstable family.
    pub burstable: bool,
    /// Kernel release string.
    pub kernel: String,
    /// Active clocksource, or `unavailable` off Linux.
    pub clocksource: String,
    /// CPU frequency governor when readable.
    pub governor: Option<String>,
    /// Summed core throttle count at capture time.
    pub thermal_throttle_count: Option<u64>,
    /// Soft `RLIMIT_NOFILE` of the harness process.
    pub ulimit_nofile: u64,
    /// `net.ipv4.ip_local_port_range` as `(low, high)`.
    pub ip_local_port_range: Option<(u32, u32)>,
    /// The system under test.
    pub sut: BuildStamp,
    /// The origin binary.
    pub origin: BuildStamp,
    /// The load generator.
    pub loadgen: ToolStamp,
    /// Discarded warmup seconds.
    pub warmup_seconds: u32,
    /// Measured seconds per repetition.
    pub measure_seconds: u32,
    /// Repetitions per cell.
    pub repetitions: u32,
    /// False when anything above makes the run unpublishable.
    pub publishable: bool,
    /// Human-readable reasons `publishable` is false, sorted and deduplicated.
    pub unpublishable_reasons: Vec<String>,
}

/// The parts of provenance the harness supplies rather than reads.
#[derive(Debug, Clone)]
pub struct CaptureInputs {
    /// Path to the system-under-test binary.
    pub sut_binary: PathBuf,
    /// Path to the origin binary.
    pub origin_binary: PathBuf,
    /// The load generator's own stamp.
    pub loadgen: ToolStamp,
    /// Discarded warmup seconds.
    pub warmup_seconds: u32,
    /// Measured seconds per repetition.
    pub measure_seconds: u32,
    /// Repetitions per cell.
    pub repetitions: u32,
    /// Set by `--allow-dirty`. Recorded, never silently tolerated.
    pub allow_dirty: bool,
}

/// Fields extracted from a raw `/proc/cpuinfo` buffer, before CPU-model
/// fallback resolution and normalisation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CpuInfoFields {
    /// Raw `model name` value, if that line was present.
    pub model_name: Option<String>,
    /// Raw `Model` value, the aarch64-board alternate key, if present.
    pub model_field: Option<String>,
    /// Raw `CPU implementer` value, if present.
    pub cpu_implementer: Option<String>,
    /// Raw `CPU part` value, if present.
    pub cpu_part: Option<String>,
    /// Count of distinct `(physical id, core id)` pairs, or the logical count
    /// when no topology fields are present at all.
    pub physical_cores: u32,
    /// True when `physical_cores` was assumed equal to `logical_cores`.
    pub physical_cores_assumed: bool,
    /// Count of `processor` lines.
    pub logical_cores: u32,
}

/// Instance-type prefixes that identify burstable families.
///
/// This is the SECOND of the two checks. The first is the shape rule
/// `^t[0-9]+[a-z]*$` on the family, which catches a family that does not exist
/// yet; a prefix list on its own fails open on exactly that case. Add a
/// non-`t` burstable family here.
pub const BURSTABLE_PREFIXES: [&str; 5] = ["t2.", "t3.", "t3a.", "t4g.", "t5."];

// ---------------------------------------------------------------------------
// is_burstable
// ---------------------------------------------------------------------------

/// True when `family` (the instance type's substring before the first `.`)
/// matches `t` followed by one or more ASCII digits followed by zero or more
/// ASCII lowercase letters, with nothing else. A hand-written character walk,
/// not a regex: eleven lines, no dependency, no backtracking, no allocation.
fn matches_burstable_shape(family: &str) -> bool {
    let bytes = family.as_bytes();
    if bytes.first() != Some(&b't') {
        return false;
    }
    let mut i = 1;
    let mut saw_digit = false;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        saw_digit = true;
        i += 1;
    }
    if !saw_digit {
        return false;
    }
    while bytes.get(i).is_some_and(u8::is_ascii_lowercase) {
        i += 1;
    }
    i == bytes.len()
}

/// True when `instance_type` is a burstable family, by the shape rule first
/// and the prefix list second.
///
/// A family this cannot classify is reported as NOT burstable, which is why
/// the shape rule exists: the cost of over-refusing is one reviewed line, and
/// the cost of under-refusing is a published CPU credit balance.
#[must_use]
pub fn is_burstable(instance_type: &str) -> bool {
    let family = instance_type.split('.').next().unwrap_or(instance_type);
    if matches_burstable_shape(family) {
        return true;
    }
    BURSTABLE_PREFIXES
        .iter()
        .any(|prefix| instance_type.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// read_bounded
// ---------------------------------------------------------------------------

/// Reads at most `cap` bytes from `path`.
///
/// Reaching `cap` is `Err(BenchError::Io)`, never a truncated value: a
/// `clocksource` truncated to `tsc` out of a longer hostile string would be a
/// fail-open on the one check that decides whether an `x86_64` run is
/// publishable.
///
/// # Errors
/// `BenchError::Io` when the file cannot be read or exceeds `cap`.
pub fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, BenchError> {
    let display = path.display().to_string();
    let mut file = std::fs::File::open(path) // it-allow: no-blocking-in-async reason: irontraffic-bench is a synchronous benchmark harness crate with no async runtime anywhere in it; capture() runs once per harness invocation, before any socket is bound, so there is no worker thread here to stall.
        .map_err(|e| BenchError::io(&display, e))?;
    let mut limited = (&mut file).take(cap as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| BenchError::io(&display, e))?;
    if buf.len() > cap {
        return Err(BenchError::io(&display, io_error("exceeds the read cap")));
    }
    Ok(buf)
}

/// Reads `/sys/firmware/devicetree/base/model`-shaped output: a NUL-terminated
/// C string. Trims the trailing NUL byte(s) before UTF-8 decoding, then
/// decodes strictly (never lossily): a stray NUL surviving decode would fail
/// `cpu_model`'s character class anyway, which is the point of trimming it
/// here rather than leaving that job to the class check.
#[cfg(target_os = "linux")]
fn decode_nul_trimmed_utf8(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    std::str::from_utf8(bytes.get(..end)?)
        .ok()
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// /proc/cpuinfo and /proc/meminfo parsing.
// ---------------------------------------------------------------------------

/// Parses a raw `/proc/cpuinfo` buffer.
///
/// Counts distinct `(physical id, core id)` pairs for `physical_cores` rather
/// than bare `core id` values, because core ids restart from 0 on every
/// socket: a dual-socket host would otherwise under-count by half. When no
/// `physical id`/`core id` pairs are present at all (the normal aarch64 case,
/// since that architecture's `/proc/cpuinfo` carries no topology fields),
/// `physical_cores` falls back to `logical_cores` and `physical_cores_assumed`
/// is set true; this is deliberately not a divide-by-two guess.
///
/// # Errors
/// `BenchError::Io` when `bytes` is empty or larger than [`LARGE_FILE_CAP`].
/// `BenchError::Parse` when `bytes` is not valid UTF-8, or contains no
/// `processor` lines at all.
pub fn parse_cpuinfo(bytes: &[u8]) -> Result<CpuInfoFields, BenchError> {
    if bytes.is_empty() {
        return Err(BenchError::io(
            "cpuinfo",
            io_error("cpuinfo buffer is empty"),
        ));
    }
    if bytes.len() > LARGE_FILE_CAP {
        return Err(BenchError::io(
            "cpuinfo",
            io_error("cpuinfo buffer exceeds the size cap"),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| BenchError::parse("cpuinfo", "contains invalid utf-8"))?;

    let mut model_name = None;
    let mut model_field = None;
    let mut cpu_implementer = None;
    let mut cpu_part = None;
    let mut logical_cores: u32 = 0;
    let mut current_physical: Option<String> = None;
    let mut pairs: HashSet<(String, String)> = HashSet::new();

    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "processor" => logical_cores = logical_cores.saturating_add(1),
            "model name" if model_name.is_none() => model_name = Some(value.to_owned()),
            "Model" if model_field.is_none() => model_field = Some(value.to_owned()),
            "CPU implementer" if cpu_implementer.is_none() => {
                cpu_implementer = Some(value.to_owned());
            }
            "CPU part" if cpu_part.is_none() => cpu_part = Some(value.to_owned()),
            "physical id" => current_physical = Some(value.to_owned()),
            "core id" => {
                if let Some(physical) = &current_physical {
                    pairs.insert((physical.clone(), value.to_owned()));
                }
            }
            _ => {}
        }
    }

    if logical_cores == 0 {
        return Err(BenchError::parse("cpuinfo", "no processor lines found"));
    }

    let (physical_cores, physical_cores_assumed) = if pairs.is_empty() {
        (logical_cores, true)
    } else {
        (u32::try_from(pairs.len()).unwrap_or(u32::MAX), false)
    };

    Ok(CpuInfoFields {
        model_name,
        model_field,
        cpu_implementer,
        cpu_part,
        physical_cores,
        physical_cores_assumed,
        logical_cores,
    })
}

/// Parses a raw `/proc/meminfo` buffer and returns `MemTotal` in bytes.
///
/// # Errors
/// `BenchError::Io` when `bytes` is empty or larger than [`LARGE_FILE_CAP`].
/// `BenchError::Parse` when `bytes` is not valid UTF-8, has no `MemTotal`
/// line, or that line's value does not fit `u64` bytes after scaling by 1024
/// (`checked_mul`, never a wrap into a small number).
pub fn parse_meminfo(bytes: &[u8]) -> Result<u64, BenchError> {
    if bytes.is_empty() {
        return Err(BenchError::io(
            "meminfo",
            io_error("meminfo buffer is empty"),
        ));
    }
    if bytes.len() > LARGE_FILE_CAP {
        return Err(BenchError::io(
            "meminfo",
            io_error("meminfo buffer exceeds the size cap"),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| BenchError::parse("meminfo", "contains invalid utf-8"))?;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let value_str = rest
                .trim()
                .strip_suffix("kB")
                .map(str::trim)
                .ok_or_else(|| BenchError::parse("meminfo", "MemTotal has no kB unit"))?;
            let kb: u64 = value_str
                .parse()
                .map_err(|_| BenchError::parse("meminfo", "MemTotal is not an integer"))?;
            return kb
                .checked_mul(1024)
                .ok_or_else(|| BenchError::parse("meminfo", "MemTotal overflows u64 bytes"));
        }
    }
    Err(BenchError::parse("meminfo", "no MemTotal line found"))
}

// ---------------------------------------------------------------------------
// cpu_model normalisation and resolution.
// ---------------------------------------------------------------------------

/// Cuts `raw` at the first `@`, trims ASCII whitespace, collapses internal
/// whitespace runs to a single space, then checks the class and cap.
///
/// Returns `Ok(None)` when the value is empty after the cut (a machine whose
/// `model name` is literally `@ 2.30GHz` is not thereby unbootable; the
/// caller tries the next entry in the fallback chain). Returns `Err` when a
/// PRESENT value is too long or contains a disallowed byte: hostile or
/// oversized content is a hard failure, never a silent fall-through to a
/// different source.
///
/// # Errors
/// `BenchError::Parse` when the normalised value exceeds 96 bytes or contains
/// a byte outside `cpu_model`'s character class.
fn normalize_cpu_model(raw: &str) -> Result<Option<String>, BenchError> {
    let cut = raw.split('@').next().unwrap_or("");
    let trimmed = cut.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let mut collapsed = String::with_capacity(trimmed.len());
    let mut last_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                collapsed.push(' ');
            }
            last_was_space = true;
        } else {
            collapsed.push(ch);
            last_was_space = false;
        }
    }
    if !bounded_ascii(&collapsed, 96, is_cpu_model_char) {
        return Err(BenchError::parse(
            "cpu_model",
            "exceeds 96 bytes or contains a disallowed character after normalisation",
        ));
    }
    Ok(Some(collapsed))
}

/// Resolves `cpu_model` from parsed `/proc/cpuinfo` fields, following the
/// fallback chain: `model name`, then `Model`, then `devicetree_model`
/// (already read and NUL-trimmed by the caller), then a string composed from
/// `CPU implementer` and `CPU part`. Only an empty chain is fatal; a PRESENT
/// but hostile value at any step fails immediately rather than trying the
/// next one, so a hostile `model name` can never be laundered by falling
/// through to a different source.
///
/// # Errors
/// `BenchError::Parse` when a present value fails normalisation, or when
/// every entry in the chain is absent or empty.
pub fn resolve_cpu_model(
    fields: &CpuInfoFields,
    devicetree_model: Option<&str>,
) -> Result<String, BenchError> {
    if let Some(raw) = &fields.model_name
        && let Some(v) = normalize_cpu_model(raw)?
    {
        return Ok(v);
    }
    if let Some(raw) = &fields.model_field
        && let Some(v) = normalize_cpu_model(raw)?
    {
        return Ok(v);
    }
    if let Some(raw) = devicetree_model
        && let Some(v) = normalize_cpu_model(raw)?
    {
        return Ok(v);
    }
    if let (Some(implementer), Some(part)) = (&fields.cpu_implementer, &fields.cpu_part) {
        // Literal "aarch64", not the harness build's own `std::env::consts::ARCH`:
        // `CPU implementer` and `CPU part` are aarch64-specific `/proc/cpuinfo`
        // keys (x86_64 never emits them), so their presence already identifies
        // the architecture the FIELDS describe. Using the harness's own build
        // arch here would be wrong on a cross-compiled harness, and would make
        // this composed string depend on what machine happened to run the
        // parser rather than on what the parsed file actually says.
        let composed = format!("aarch64 impl {} part {}", implementer.trim(), part.trim());
        if let Some(v) = normalize_cpu_model(&composed)? {
            return Ok(v);
        }
    }
    Err(BenchError::parse(
        "cpu_model",
        "no model name, Model, devicetree model, or CPU implementer/part fields found",
    ))
}

/// Renders the `hardware` field from its components:
/// `<cpu model>, <physical>c/<logical>t, <mem_gib> GiB`.
#[must_use]
pub fn render_hardware(
    cpu_model: &str,
    physical_cores: u32,
    logical_cores: u32,
    mem_bytes: u64,
) -> String {
    #[allow(
        clippy::integer_division,
        reason = "GiB display rounding: an exact truncating divide by a fixed power of two, not a bug"
    )]
    let mem_gib = mem_bytes / GIB;
    format!("{cpu_model}, {physical_cores}c/{logical_cores}t, {mem_gib} GiB")
}

/// Validates a DMI-sourced `instance_type` candidate: trims, then checks the
/// class and the 64 byte cap.
///
/// Returns `None` on any violation, and this is NOT an error: `instance_type`
/// is the one field a hypervisor chooses for us, and a result derived from it
/// is used to build a results directory name, so a hostile or merely unusual
/// value (a path separator, a traversal, a space) is recorded as unknown
/// rather than sanitised into something that looks plausible. Never trust a
/// repaired value.
#[must_use]
pub fn normalize_instance_type(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if bounded_ascii(trimmed, 64, is_instance_type_char) {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// UTC date formatting: a fixed civil-date conversion, no chrono.
// ---------------------------------------------------------------------------

/// Converts days since the Unix epoch to a proleptic Gregorian `(year, month,
/// day)`, by Howard Hinnant's well-known `civil_from_days` algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>). Every division
/// here is exact integer arithmetic the algorithm itself defines, and every
/// cast is bounded by the algorithm to a range that always fits (month
/// 1 to 12, day 1 to 31, year comfortably inside `i64`): none of it is
/// derived from attacker-controlled or otherwise unbounded input.
#[allow(
    clippy::integer_division,
    reason = "Howard Hinnant's civil_from_days: every division is exact integer arithmetic the published algorithm defines, not a truncation bug"
)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "month/day/year are bounded by the algorithm itself to ranges that always fit (month 1-12, day 1-31, year comfortably inside i64); this is process-local wall-clock math, not attacker-controlled input"
)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year_of_era = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // it-allow: unchecked-cast reason: Howard Hinnant's civil_from_days bounds doy to [0, 365] and mp to [0, 11], so this expression is bounded to [1, 31] by construction, not a value read off the wire.
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // it-allow: unchecked-cast reason: bounded to [1, 12] by the same algorithm; see the line above.
    let year = if month <= 2 {
        year_of_era + 1
    } else {
        year_of_era
    };
    (year, month, day)
}

/// Renders `unix_seconds` as RFC 3339, seconds precision, always ending `Z`:
/// `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Takes an unsigned second count so a clock set before 1970 (which would
/// otherwise be a negative epoch) cannot reach this function at all; the
/// caller ([`Provenance::capture`]) rejects that case itself before this
/// point, per edge case 12e. No `chrono`: civil-date conversion by
/// [`civil_from_days`].
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "splitting a second count into hour/minute/second by fixed constants is exact arithmetic, not a truncation bug"
)]
pub fn format_utc_date(unix_seconds: u64) -> String {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "a realistic unix timestamp is far below i64::MAX; this widens for civil_from_days's signed arithmetic, it does not wrap"
    )]
    let total_seconds = unix_seconds as i64;
    let days = total_seconds.div_euclid(86_400);
    let secs_of_day = total_seconds.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// ---------------------------------------------------------------------------
// Bounded, timed, killed-and-reaped subprocess probing.
// ---------------------------------------------------------------------------

/// The combined, capped output of one probe, plus whether it exited zero.
struct Probe {
    stdout: Vec<u8>,
    exit_success: bool,
}

/// Drains `reader` into `buf`, tracking the COMBINED byte count (shared with
/// the other stream's drain thread via `combined_len`) against `cap`. Stops
/// and sets `exceeded` the instant the shared total passes `cap`, rather than
/// reading on: the caller kills the child the moment this is observed, so an
/// unbounded write on either stream is bounded to `cap` plus at most one
/// `read` call's worth of overshoot, never the whole of a hostile or endless
/// output.
fn drain_capped(
    mut reader: impl Read,
    buf: &Arc<Mutex<Vec<u8>>>,
    combined_len: &Arc<AtomicUsize>,
    exceeded: &Arc<AtomicBool>,
    cap: usize,
) {
    let mut chunk = [0_u8; 4096];
    loop {
        if exceeded.load(Ordering::Relaxed) {
            break;
        }
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                lock_or_recover(buf).extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                let total = combined_len.fetch_add(n, Ordering::Relaxed) + n;
                if total > cap {
                    exceeded.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
}

/// Spawns `command` with `stdin` null, drains stdout and stderr concurrently
/// (never `Command`'s `output` method, which reads to EOF: a binary that
/// prints without stopping would otherwise fill the harness's memory), and
/// enforces both [`PROBE_TIMEOUT_SECONDS`] and a combined-byte `cap`.
///
/// On either the timeout or the cap being reached, the child is killed and
/// then reaped (an unwaited child is a zombie the harness accumulates once
/// per probe), and this returns `BenchError::Io` naming `label`.
///
/// # Errors
/// `BenchError::Io` if `command` cannot be spawned, or if the probe times out
/// or exceeds `cap`.
fn run_bounded(mut command: Command, label: &str, cap: usize) -> Result<Probe, BenchError> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // The probed binary may itself be a shell script that forks a child (a
    // script whose last statement is `sleep 60` runs `sleep` as a grandchild,
    // not the shell itself). That grandchild inherits the piped stdout/stderr
    // file descriptors, so killing only the direct child leaves the pipe's
    // write end open and the drain threads below blocked in `read` until the
    // grandchild exits on its own: a process-group kill, not a single-pid
    // kill, is what actually bounds the wall-clock timeout. `process_group(0)`
    // makes the child its own process-group leader so the whole group can be
    // signalled at once; grandchildren inherit that group automatically.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| BenchError::io(label, e))?; // it-allow: no-blocking-in-async reason: irontraffic-bench is a synchronous benchmark harness with no async runtime; every probe here runs to a bounded, timed completion before the harness spawns anything else.

    let exceeded = Arc::new(AtomicBool::new(false));
    let combined_len = Arc::new(AtomicUsize::new(0));
    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));

    let mut threads = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let buf = Arc::clone(&stdout_buf);
        let len = Arc::clone(&combined_len);
        let flag = Arc::clone(&exceeded);
        threads.push(std::thread::spawn(move || {
            drain_capped(stdout, &buf, &len, &flag, cap);
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let buf = Arc::clone(&stderr_buf);
        let len = Arc::clone(&combined_len);
        let flag = Arc::clone(&exceeded);
        threads.push(std::thread::spawn(move || {
            drain_capped(stderr, &buf, &len, &flag, cap);
        }));
    }

    let (timed_out, exit_success) = poll_until_done(&mut child, &exceeded);

    if timed_out || exceeded.load(Ordering::Relaxed) {
        #[cfg(unix)]
        kill_process_group(&child);
        #[cfg(not(unix))]
        kill_process_group(&mut child);
        let _ = child.wait();
        for handle in threads {
            let _ = handle.join();
        }
        let reason = if timed_out {
            "probe exceeded the wall-clock timeout"
        } else {
            "probe output exceeded the byte cap"
        };
        return Err(BenchError::io(label, io_error(reason)));
    }

    for handle in threads {
        let _ = handle.join();
    }

    Ok(Probe {
        stdout: lock_or_recover(&stdout_buf).clone(),
        exit_success,
    })
}

/// Kills the whole process group `child` leads (see the comment on
/// `process_group(0)` above), rather than only `child` itself: a script that
/// forked a grandchild before we noticed the timeout or the cap must not
/// leave that grandchild running, holding the piped stdout/stderr open.
///
/// # Platform
/// Unix only: `process_group` is a Unix process-model concept with no
/// Windows equivalent, so off Unix this falls back to signalling `child`
/// alone. Every platform this module actually ships and tests on (Linux
/// CI, macOS development) is Unix.
#[cfg(unix)]
fn kill_process_group(child: &Child) {
    let pid = rustix::process::Pid::from_child(child);
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL); // it-allow: no-swallowed-error reason: the process may already have exited between the timeout/cap check and this call, which is not a new error to surface; run_bounded's caller learns about the failure from the Err this function's caller already returns.
}

#[cfg(not(unix))]
fn kill_process_group(child: &mut Child) {
    let _ = child.kill();
}

/// Polls `child` until it exits, the timeout expires, or `exceeded` is
/// observed set by a drain thread. Returns `(timed_out, exit_success)`.
fn poll_until_done(child: &mut Child, exceeded: &Arc<AtomicBool>) -> (bool, bool) {
    let start = std::time::Instant::now(); // it-allow: determinism-seam reason: irontraffic-bench is a synchronous benchmark harness outside the production data/control plane; this measures the probe's OWN wall-clock timeout budget, which is the thing under test, not a request-path read.
    loop {
        if exceeded.load(Ordering::Relaxed) {
            return (false, false);
        }
        match child.try_wait() {
            Ok(Some(status)) => return (false, status.success()),
            Ok(None) => {}
            Err(_) => return (false, false),
        }
        if start.elapsed() >= Duration::from_secs(PROBE_TIMEOUT_SECONDS) {
            return (true, false);
        }
        std::thread::sleep(Duration::from_millis(20)); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this is the poll interval of a synchronous subprocess-timeout loop.
    }
}

// ---------------------------------------------------------------------------
// The build stamp: `--version --json`, with a `--version`-plus-git fallback.
// ---------------------------------------------------------------------------

/// The six keys `--version --json` reports, before `stamp_source` is attached.
struct RawStamp {
    name: String,
    version: String,
    git_sha: String,
    dirty: bool,
    profile: String,
    features: Vec<String>,
}

/// A tiny, purpose-built JSON parser for exactly the build-stamp shape: an
/// object with the six keys `name`, `version`, `git_sha`, `dirty`, `profile`,
/// `features` (string, string, string, bool, string, string array), in any
/// order, and nothing else. Not a general JSON parser: an unrecognised key,
/// a wrong type, a duplicate key, or trailing data after the closing brace
/// all make this return `None`, which the caller treats as "this binary does
/// not understand `--version --json`" and falls back, exactly like a syntax
/// error would.
struct JsonParser<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl<'a> JsonParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            chars: s.chars().peekable(),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.chars.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.chars.next();
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn bump(&mut self) -> Option<char> {
        self.chars.next()
    }

    fn expect_char(&mut self, c: char) -> Option<()> {
        if self.bump()? == c { Some(()) } else { None }
    }

    fn at_end(&mut self) -> bool {
        self.chars.peek().is_none()
    }

    fn parse_string(&mut self) -> Option<String> {
        self.expect_char('"')?;
        let mut out = String::new();
        loop {
            let c = self.bump()?;
            match c {
                '"' => return Some(out),
                '\\' => {
                    let escape = self.bump()?;
                    match escape {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let mut hex = String::with_capacity(4);
                            for _ in 0..4 {
                                hex.push(self.bump()?);
                            }
                            let code_point = u32::from_str_radix(&hex, 16).ok()?;
                            out.push(char::from_u32(code_point)?);
                        }
                        _ => return None,
                    }
                }
                c if (c as u32) < 0x20 => return None, // it-allow: unchecked-cast reason: char to u32 is a widening conversion (every char fits in u32 by definition), never a truncation.
                _ => out.push(c),
            }
        }
    }

    fn parse_bool(&mut self) -> Option<bool> {
        if self.take_literal("true") {
            Some(true)
        } else if self.take_literal("false") {
            Some(false)
        } else {
            None
        }
    }

    fn take_literal(&mut self, literal: &str) -> bool {
        let mut probe = self.chars.clone();
        for expected in literal.chars() {
            if probe.next() != Some(expected) {
                return false;
            }
        }
        self.chars = probe;
        true
    }

    fn parse_string_array(&mut self) -> Option<Vec<String>> {
        self.expect_char('[')?;
        self.skip_ws();
        let mut out = Vec::new();
        if self.peek() == Some(']') {
            self.bump();
            return Some(out);
        }
        loop {
            self.skip_ws();
            out.push(self.parse_string()?);
            self.skip_ws();
            match self.bump()? {
                ',' => {}
                ']' => break,
                _ => return None,
            }
        }
        Some(out)
    }
}

/// Parses exactly the build-stamp object shape. See [`JsonParser`].
fn parse_stamp_json(text: &str) -> Option<RawStamp> {
    let mut parser = JsonParser::new(text);
    parser.skip_ws();
    parser.expect_char('{')?;
    parser.skip_ws();

    let mut name = None;
    let mut version = None;
    let mut git_sha = None;
    let mut dirty = None;
    let mut profile = None;
    let mut features = None;

    if parser.peek() == Some('}') {
        parser.bump();
    } else {
        loop {
            parser.skip_ws();
            let key = parser.parse_string()?;
            parser.skip_ws();
            parser.expect_char(':')?;
            parser.skip_ws();
            match key.as_str() {
                "name" if name.is_none() => name = Some(parser.parse_string()?),
                "version" if version.is_none() => version = Some(parser.parse_string()?),
                "git_sha" if git_sha.is_none() => git_sha = Some(parser.parse_string()?),
                "profile" if profile.is_none() => profile = Some(parser.parse_string()?),
                "dirty" if dirty.is_none() => dirty = Some(parser.parse_bool()?),
                "features" if features.is_none() => features = Some(parser.parse_string_array()?),
                _ => return None,
            }
            parser.skip_ws();
            match parser.bump()? {
                ',' => {}
                '}' => break,
                _ => return None,
            }
        }
    }
    parser.skip_ws();
    if !parser.at_end() {
        return None;
    }

    Some(RawStamp {
        name: name?,
        version: version?,
        git_sha: git_sha?,
        dirty: dirty?,
        profile: profile?,
        features: features?,
    })
}

/// Checks every field of `stamp` against the "Field bounds" table, sorting
/// `features` on success. The single gate every `BuildStamp`, `Embedded` or
/// `Fallback`, passes through before this module will return it.
fn validate_build_stamp(mut stamp: BuildStamp) -> Result<BuildStamp, BenchError> {
    if !bounded_ascii(&stamp.name, 64, is_name_char) {
        return Err(BenchError::parse(
            "build_stamp",
            "name violates its bound or character class",
        ));
    }
    if !bounded_ascii(&stamp.version, 64, is_version_char) {
        return Err(BenchError::parse(
            "build_stamp",
            "version violates its bound or character class",
        ));
    }
    // Deliberately rejects the literal "unknown" too, which
    // crates/irontraffic's own build.rs (#427) emits for a source-tarball
    // build with no .git directory and no IT_GIT_SHA override: an
    // unattributable build cannot be reproduced or compared across runs, so
    // the harness refuses to start rather than publish a record nobody can
    // trace to a commit, the "no kernel version, no run" contract applied to
    // the git SHA. See PR discussion on issue #407 for the full decision; a
    // tarball build that wants to be benchmarked sets IT_GIT_SHA in the
    // environment, per build.rs's own documented override.
    if !bounded_ascii(&stamp.git_sha, 40, is_git_sha_char) {
        return Err(BenchError::parse(
            "build_stamp",
            "git_sha violates its bound or character class",
        ));
    }
    if !bounded_ascii(&stamp.profile, 16, is_profile_char) {
        return Err(BenchError::parse(
            "build_stamp",
            "profile violates its bound or character class",
        ));
    }
    if stamp.features.len() > 64 {
        return Err(BenchError::parse(
            "build_stamp",
            "features has more than 64 entries",
        ));
    }
    for feature in &stamp.features {
        if !bounded_ascii(feature, 64, is_feature_char) {
            return Err(BenchError::parse(
                "build_stamp",
                "a features entry violates its bound or character class",
            ));
        }
    }
    stamp.features.sort();
    Ok(stamp)
}

/// The binary's own path component (`release` or `debug`) it was built under,
/// scanning components closest to the binary first.
///
/// # Errors
/// `BenchError::Parse` when neither component appears anywhere in `path`.
fn profile_from_path(path: &Path) -> Result<String, BenchError> {
    for component in path.components().rev() {
        if let std::path::Component::Normal(os_str) = component
            && let Some(s) = os_str.to_str()
        {
            if s == "release" {
                return Ok("release".to_owned());
            }
            if s == "debug" {
                return Ok("debug".to_owned());
            }
        }
    }
    Err(BenchError::parse(
        "build_stamp",
        "binary path has no release or debug component",
    ))
}

/// The binary's file stem, as the Fallback stamp's `name`.
///
/// # Errors
/// `BenchError::Parse` when `path` has no usable file name.
fn name_from_stem(path: &Path) -> Result<String, BenchError> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .ok_or_else(|| BenchError::parse("build_stamp", "binary path has no usable file name"))
}

/// Runs `git` with `args`. Spawn failure (git not installed or not on `PATH`)
/// is reported as `BenchError::Parse` naming `git` (edge case 14: a missing
/// dependency, not a probe timeout), which is a different failure shape from
/// every other probe in this module on purpose: it is the one case where
/// nothing was measured wrong, the tool we need simply is not there.
fn run_git(args: &[&str], cap: usize) -> Result<Probe, BenchError> {
    let mut command = Command::new("git");
    command.args(args);
    match run_bounded(command, "git", cap) {
        Ok(probe) => Ok(probe),
        Err(BenchError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => Err(
            BenchError::parse("git", "git is not installed or not on PATH"),
        ),
        Err(other) => Err(other),
    }
}

/// `git rev-parse --short HEAD`, trimmed.
fn git_short_sha() -> Result<String, BenchError> {
    let probe = run_git(&["rev-parse", "--short", "HEAD"], PROBE_OUTPUT_CAP)?;
    if !probe.exit_success {
        return Err(BenchError::parse(
            "git",
            "rev-parse --short HEAD exited non-zero",
        ));
    }
    std::str::from_utf8(&probe.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| BenchError::parse("git", "rev-parse output is not utf-8"))
}

/// `git status --porcelain`, judged only for emptiness.
///
/// A cap of [`SMALL_FILE_CAP`] is used rather than [`PROBE_OUTPUT_CAP`]: the
/// caller needs only a yes/no answer, so a worktree whose status listing
/// exceeds even 4 KiB is treated as dirty (the safe direction) rather than
/// read further to find out exactly how dirty.
fn git_worktree_is_dirty() -> Result<bool, BenchError> {
    match run_git(&["status", "--porcelain"], SMALL_FILE_CAP) {
        Ok(probe) => {
            if !probe.exit_success {
                return Err(BenchError::parse(
                    "git",
                    "status --porcelain exited non-zero",
                ));
            }
            Ok(!probe.stdout.is_empty())
        }
        Err(BenchError::Io { .. }) => Ok(true),
        Err(other) => Err(other),
    }
}

/// Reads a `BuildStamp` from a binary, preferring `--version --json`.
///
/// The probe runs with `stdin` null, a `PROBE_TIMEOUT_SECONDS` wall-clock
/// timeout, and a `PROBE_OUTPUT_CAP` bound on combined stdout and stderr. On
/// timeout or on reaching the cap the child is killed AND reaped, and the
/// call returns `BenchError::Io`. Never `Command`'s `output` method: it reads
/// to EOF, so a binary that prints without stopping fills the harness's
/// memory. Capture with piped handles and a bounded reader instead.
///
/// Every field of the returned stamp is bounded and class-checked per the
/// "Field bounds" table. The stamp is committed to a public repository, and
/// the binary that produced it chose every byte of it.
///
/// # Errors
/// `BenchError::Io` if the binary cannot be executed, times out, or exceeds
/// the output cap; `BenchError::Parse` if both the JSON and the fallback
/// paths fail, or if any field violates its bound or its character class.
pub fn capture_build_stamp(binary: &Path) -> Result<BuildStamp, BenchError> {
    let label = format!("{} --version --json", binary.display());
    let json_probe = {
        let mut command = Command::new(binary);
        command.args(["--version", "--json"]);
        run_bounded(command, &label, PROBE_OUTPUT_CAP)?
    };

    if json_probe.exit_success
        && let Ok(text) = std::str::from_utf8(&json_probe.stdout)
        && let Some(raw) = parse_stamp_json(text.trim())
    {
        let stamp = BuildStamp {
            name: raw.name,
            version: raw.version,
            git_sha: raw.git_sha,
            dirty: raw.dirty,
            profile: raw.profile,
            features: raw.features,
            stamp_source: StampSource::Embedded,
        };
        return validate_build_stamp(stamp);
    }

    // Fallback: the binary does not understand `--version --json`.
    let version_label = format!("{} --version", binary.display());
    let version_probe = {
        let mut command = Command::new(binary);
        command.arg("--version");
        run_bounded(command, &version_label, PROBE_OUTPUT_CAP)?
    };
    if !version_probe.exit_success {
        return Err(BenchError::io(
            &version_label,
            io_error("--version exited non-zero"),
        ));
    }
    let version_text = std::str::from_utf8(&version_probe.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| BenchError::parse("build_stamp", "--version output is not utf-8"))?;
    // Every conventional CLI, including both binaries in this repository,
    // prints `<name> <version>` on plain `--version` (`irontraffic 0.1.0`,
    // `it-origin 0.1.0`). The version class excludes the space between them,
    // so storing the whole line would make the Fallback path fail on every
    // real binary; take the last whitespace-separated token instead. A line
    // with no whitespace at all (a bare `0.1.0`) is its own last token.
    let version = version_text
        .split_whitespace()
        .next_back()
        .unwrap_or(version_text.as_str())
        .to_owned();

    let stamp = BuildStamp {
        name: name_from_stem(binary)?,
        version,
        git_sha: git_short_sha()?,
        dirty: git_worktree_is_dirty()?,
        profile: profile_from_path(binary)?,
        features: Vec::new(),
        stamp_source: StampSource::Fallback,
    };
    validate_build_stamp(stamp)
}

/// Checks `stamp`'s `version` and `image_digest` against the "Field bounds"
/// table. `name` is not checked: it is chosen by our own adapter code, not
/// read from the tool's own output, so it carries none of the injection risk
/// the bounds table exists to close.
fn validate_tool_stamp(stamp: ToolStamp) -> Result<ToolStamp, BenchError> {
    if !bounded_ascii(&stamp.version, 64, is_tool_version_char) {
        return Err(BenchError::parse(
            "tool_stamp",
            "version violates its bound or character class",
        ));
    }
    if let Some(digest) = &stamp.image_digest
        && !bounded_ascii(digest, 80, is_image_digest_char)
    {
        return Err(BenchError::parse(
            "tool_stamp",
            "image_digest violates its bound or character class",
        ));
    }
    Ok(stamp)
}

// ---------------------------------------------------------------------------
// Host facts: the OS-specific half of capture().
// ---------------------------------------------------------------------------

/// The hardware- and kernel-derived fields `capture()` cannot get from a
/// spawned binary. Not `pub`: tests reach the parsers ([`parse_cpuinfo`],
/// [`resolve_cpu_model`], [`parse_meminfo`]) and the OS-independent helpers
/// directly with fixture bytes, rather than through this aggregate, which is
/// the one part of this module that can only run against the real host.
struct HostFacts {
    cpu_model: String,
    physical_cores: u32,
    physical_cores_assumed: bool,
    logical_cores: u32,
    mem_bytes: u64,
    instance_type: Option<String>,
    kernel: String,
    clocksource: String,
    governor: Option<String>,
    thermal_throttle_count: Option<u64>,
    ip_local_port_range: Option<(u32, u32)>,
}

/// Parses `"low high"` (whitespace-separated) as `(u32, u32)`. Malformed
/// input is `None`, never an error: edge case 8, the harness can still run at
/// low connection counts without knowing the ephemeral port range.
#[cfg(target_os = "linux")]
fn parse_port_range(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split_whitespace();
    let low: u32 = parts.next()?.parse().ok()?;
    let high: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((low, high))
}

#[cfg(target_os = "linux")]
fn sum_thermal_throttle() -> Option<u64> {
    sum_thermal_throttle_from(Path::new("/sys/devices/system/cpu"), MAX_CPU_ENTRIES)
}

/// The pure half of [`sum_thermal_throttle`], parameterised on the directory
/// and the entry cap so a test can drive the cap-exceeded path with a
/// handful of fixture directories rather than [`MAX_CPU_ENTRIES`] real ones.
///
/// Counts only entries that match the `cpu[0-9]+` shape toward `max_entries`;
/// a directory also containing `online`, `possible`, `cpufreq`,
/// `vulnerabilities`, and similar non-`cpu*` siblings must not spend the
/// budget on them. Reaching the cap stops the walk immediately and returns
/// `None` rather than the sum collected so far: edge case 4b requires that a
/// directory with more `cpu*` entries than the cap is indistinguishable from
/// one this module refused to read, never a partial number that would read
/// in a committed record exactly like a complete throttle count.
#[cfg(target_os = "linux")]
fn sum_thermal_throttle_from(base: &Path, max_entries: usize) -> Option<u64> {
    let entries = base.read_dir().ok()?; // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; capture() runs once per invocation before anything is spawned.
    let mut total: u64 = 0;
    let mut any_found = false;
    let mut cpu_entries_visited: usize = 0;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("cpu") || !name["cpu".len()..].bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if cpu_entries_visited >= max_entries {
            return None;
        }
        cpu_entries_visited += 1;
        let counter_path = entry.path().join("thermal_throttle/core_throttle_count");
        if let Ok(bytes) = read_bounded(&counter_path, SMALL_FILE_CAP)
            && let Ok(text) = std::str::from_utf8(&bytes)
            && let Ok(value) = text.trim().parse::<u64>()
        {
            total = total.saturating_add(value);
            any_found = true;
        }
    }
    any_found.then_some(total)
}

#[cfg(target_os = "linux")]
fn capture_host_facts() -> Result<HostFacts, BenchError> {
    let cpuinfo_bytes = read_bounded(Path::new("/proc/cpuinfo"), LARGE_FILE_CAP)?;
    let cpuinfo = parse_cpuinfo(&cpuinfo_bytes)?;

    let devicetree_model = read_bounded(
        Path::new("/sys/firmware/devicetree/base/model"),
        SMALL_FILE_CAP,
    )
    .ok()
    .and_then(|bytes| decode_nul_trimmed_utf8(&bytes));
    let cpu_model = resolve_cpu_model(&cpuinfo, devicetree_model.as_deref())?;

    let meminfo_bytes = read_bounded(Path::new("/proc/meminfo"), LARGE_FILE_CAP)?;
    let mem_bytes = parse_meminfo(&meminfo_bytes)?;

    let instance_type = read_bounded(
        Path::new("/sys/devices/virtual/dmi/id/product_name"),
        SMALL_FILE_CAP,
    )
    .ok()
    .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(str::to_owned))
    .and_then(|raw| normalize_instance_type(&raw));

    let kernel_bytes = read_bounded(Path::new("/proc/sys/kernel/osrelease"), SMALL_FILE_CAP)?;
    let kernel_raw = std::str::from_utf8(&kernel_bytes)
        .map_err(|_| BenchError::parse("kernel", "contains invalid utf-8"))?
        .trim();
    if !bounded_ascii(kernel_raw, 64, is_kernel_char) {
        return Err(BenchError::parse(
            "kernel",
            "osrelease violates its bound or character class",
        ));
    }
    let kernel = kernel_raw.to_owned();

    let clocksource_bytes = read_bounded(
        Path::new("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
        SMALL_FILE_CAP,
    )?;
    let clocksource_raw = std::str::from_utf8(&clocksource_bytes)
        .map_err(|_| BenchError::parse("clocksource", "contains invalid utf-8"))?
        .trim();
    if !bounded_ascii(clocksource_raw, 32, is_clocksource_char) {
        return Err(BenchError::parse(
            "clocksource",
            "current_clocksource violates its bound or character class",
        ));
    }
    let clocksource = clocksource_raw.to_owned();

    let governor = read_bounded(
        Path::new("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        SMALL_FILE_CAP,
    )
    .ok()
    .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(str::to_owned))
    .map(|s| s.trim().to_owned())
    .filter(|s| bounded_ascii(s, 32, is_governor_char));

    let thermal_throttle_count = sum_thermal_throttle();

    let ip_local_port_range = read_bounded(
        Path::new("/proc/sys/net/ipv4/ip_local_port_range"),
        SMALL_FILE_CAP,
    )
    .ok()
    .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(str::to_owned))
    .and_then(|s| parse_port_range(s.trim()));

    Ok(HostFacts {
        cpu_model,
        physical_cores: cpuinfo.physical_cores,
        physical_cores_assumed: cpuinfo.physical_cores_assumed,
        logical_cores: cpuinfo.logical_cores,
        mem_bytes,
        instance_type,
        kernel,
        clocksource,
        governor,
        thermal_throttle_count,
        ip_local_port_range,
    })
}

#[cfg(target_os = "macos")]
fn run_sysctl(key: &str) -> Result<String, BenchError> {
    let label = format!("sysctl -n {key}");
    let mut command = Command::new("sysctl");
    command.args(["-n", key]);
    let probe = run_bounded(command, &label, SMALL_FILE_CAP)?;
    if !probe.exit_success {
        return Err(BenchError::io(&label, io_error("sysctl exited non-zero")));
    }
    std::str::from_utf8(&probe.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| BenchError::parse("sysctl", "output is not utf-8"))
}

#[cfg(target_os = "macos")]
fn capture_host_facts() -> Result<HostFacts, BenchError> {
    let cpu_model_raw = run_sysctl("machdep.cpu.brand_string")?;
    let cpu_model = normalize_cpu_model(&cpu_model_raw)?.ok_or_else(|| {
        BenchError::parse(
            "cpu_model",
            "machdep.cpu.brand_string is empty after normalisation",
        )
    })?;

    let logical_text = run_sysctl("hw.logicalcpu")?;
    let logical_cores: u32 = logical_text
        .parse()
        .map_err(|_| BenchError::parse("cpu_topology", "hw.logicalcpu is not an integer"))?;

    let (physical_cores, physical_cores_assumed) = match run_sysctl("hw.physicalcpu")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(v) => (v, false),
        None => (logical_cores, true),
    };

    let mem_text = run_sysctl("hw.memsize")?;
    let mem_bytes: u64 = mem_text
        .parse()
        .map_err(|_| BenchError::parse("mem_bytes", "hw.memsize is not an integer"))?;

    let kernel_raw = run_sysctl("kern.osrelease")?;
    if !bounded_ascii(&kernel_raw, 64, is_kernel_char) {
        return Err(BenchError::parse(
            "kernel",
            "kern.osrelease violates its bound or character class",
        ));
    }

    Ok(HostFacts {
        cpu_model,
        physical_cores,
        physical_cores_assumed,
        logical_cores,
        mem_bytes,
        instance_type: None,
        kernel: kernel_raw,
        clocksource: "unavailable".to_owned(),
        governor: None,
        thermal_throttle_count: None,
        ip_local_port_range: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn capture_host_facts() -> Result<HostFacts, BenchError> {
    Err(BenchError::parse(
        "platform",
        "provenance capture is only implemented for linux and macos",
    ))
}

// ---------------------------------------------------------------------------
// Provenance::capture and recompute_publishable.
// ---------------------------------------------------------------------------

/// The non-[`HostFacts`] pieces [`assemble_provenance`] needs: everything
/// `capture()` gathers itself rather than reading from the OS-specific host
/// capture routine. Grouped into one struct so `assemble_provenance` takes
/// two arguments instead of ten (`clippy::too_many_arguments`).
struct AssembledParts {
    utc_date: String,
    cpu_arch: String,
    ulimit_nofile: u64,
    sut: BuildStamp,
    origin: BuildStamp,
    loadgen: ToolStamp,
    warmup_seconds: u32,
    measure_seconds: u32,
    repetitions: u32,
}

/// Assembles a [`Provenance`] from already captured, already validated
/// pieces: the OS-specific [`HostFacts`], and the [`AssembledParts`]
/// `capture()` gathers separately (the two build stamps, the tool stamp, the
/// descriptor limit). Pure and infallible; every fallible step already
/// happened in the caller.
///
/// This is a deliberate seam. `capture_host_facts()` can only run against the
/// real host, which makes the burstable guard's call site (deriving
/// `burstable` from `host.instance_type` via [`is_burstable`]) and the
/// straight pass-through of `host.cpu_model`, `host.mem_bytes` and
/// `host.kernel` otherwise untestable: nothing can hand `capture()` a
/// hypothetical host record. A test builds a [`HostFacts`] by hand and calls
/// this function directly instead.
fn assemble_provenance(host: HostFacts, parts: AssembledParts) -> Provenance {
    let AssembledParts {
        utc_date,
        cpu_arch,
        ulimit_nofile,
        sut,
        origin,
        loadgen,
        warmup_seconds,
        measure_seconds,
        repetitions,
    } = parts;

    let instance_type = host.instance_type;
    let burstable = instance_type.as_deref().is_some_and(is_burstable);

    let hardware = render_hardware(
        &host.cpu_model,
        host.physical_cores,
        host.logical_cores,
        host.mem_bytes,
    );

    let mut provenance = Provenance {
        utc_date,
        hardware,
        cpu_model: host.cpu_model,
        cpu_arch,
        physical_cores: host.physical_cores,
        physical_cores_assumed: host.physical_cores_assumed,
        logical_cores: host.logical_cores,
        mem_bytes: host.mem_bytes,
        instance_type,
        burstable,
        kernel: host.kernel,
        clocksource: host.clocksource,
        governor: host.governor,
        thermal_throttle_count: host.thermal_throttle_count,
        ulimit_nofile,
        ip_local_port_range: host.ip_local_port_range,
        sut,
        origin,
        loadgen,
        warmup_seconds,
        measure_seconds,
        repetitions,
        publishable: true,
        unpublishable_reasons: Vec::new(),
    };
    provenance.recompute_publishable();

    // Invariants 3 and 7, cheap to check on every assembled record: a run
    // that reports fewer logical than physical cores, zero physical cores,
    // or a zero descriptor limit has already lied in a field the publishing
    // guard does not otherwise cross check.
    debug_assert!(
        provenance.logical_cores >= provenance.physical_cores && provenance.physical_cores >= 1,
        "invariant 3 violated: logical_cores {} must be >= physical_cores {}, and physical_cores must be >= 1",
        provenance.logical_cores,
        provenance.physical_cores
    );
    debug_assert!(
        provenance.ulimit_nofile > 0,
        "invariant 7 violated: ulimit_nofile must be > 0"
    );

    provenance
}

impl Provenance {
    /// Captures everything from the running system. Call FIRST, before
    /// spawning any process.
    ///
    /// # Errors
    /// `BenchError::Io` when a mandatory source cannot be read. A missing
    /// kernel version, CPU model, memory total, clocksource (on Linux), or
    /// descriptor limit is fatal: no kernel version, no run.
    pub fn capture(inputs: &CaptureInputs) -> Result<Self, BenchError> {
        let now = std::time::SystemTime::now() // it-allow: determinism-seam reason: irontraffic-bench is a synchronous benchmark harness outside the production data/control plane; provenance's whole purpose is to record the ACTUAL wall-clock date a run happened, which cannot be read through a mockable seam without defeating the point of capturing it.
            .duration_since(std::time::UNIX_EPOCH) // it-allow: determinism-seam reason: same call as the SystemTime::now() line directly above; UNIX_EPOCH is its required argument, not a second, separate clock read.
            .map_err(|_| BenchError::parse("utc_date", "system clock is set before 1970"))?;
        let utc_date = format_utc_date(now.as_secs());

        let host = capture_host_facts()?;
        let cpu_arch = std::env::consts::ARCH.to_owned();

        let ulimit_nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current
            .unwrap_or(u64::MAX);

        let sut = capture_build_stamp(&inputs.sut_binary)?;
        let origin = capture_build_stamp(&inputs.origin_binary)?;

        if (sut.dirty || origin.dirty) && !inputs.allow_dirty {
            return Err(BenchError::parse(
                "provenance",
                "the sut or origin binary was built from a dirty worktree; pass --allow-dirty to record and refuse publication instead of failing",
            ));
        }

        let loadgen = validate_tool_stamp(inputs.loadgen.clone())?;

        Ok(assemble_provenance(
            host,
            AssembledParts {
                utc_date,
                cpu_arch,
                ulimit_nofile,
                sut,
                origin,
                loadgen,
                warmup_seconds: inputs.warmup_seconds,
                measure_seconds: inputs.measure_seconds,
                repetitions: inputs.repetitions,
            },
        ))
    }

    /// Re-evaluates `publishable` and `unpublishable_reasons` from the current
    /// field values, per the six-condition table in Design. Clears the
    /// existing reasons first, then re-derives them, then sorts and
    /// deduplicates, so calling it twice is idempotent. Called by `capture`
    /// and again by the result writer.
    pub fn recompute_publishable(&mut self) {
        self.unpublishable_reasons.clear();

        if self.burstable {
            self.unpublishable_reasons.push(format!(
                "burstable instance type {}",
                self.instance_type.as_deref().unwrap_or("unknown")
            ));
        }
        if self.sut.dirty || self.origin.dirty {
            self.unpublishable_reasons.push("dirty worktree".to_owned());
        }
        if self.sut.stamp_source == StampSource::Fallback
            || self.origin.stamp_source == StampSource::Fallback
        {
            self.unpublishable_reasons
                .push("build stamp reconstructed by fallback".to_owned());
        }
        if self.sut.profile != "release" || self.origin.profile != "release" {
            self.unpublishable_reasons
                .push("non-release build profile".to_owned());
        }
        if self.cpu_arch == "x86_64" && self.clocksource != "tsc" {
            self.unpublishable_reasons.push(format!(
                "clocksource {} is not tsc on x86_64",
                self.clocksource
            ));
        }
        if self.ip_local_port_range.is_none() {
            self.unpublishable_reasons
                .push("ephemeral port range unavailable".to_owned());
        }

        self.unpublishable_reasons.sort();
        self.unpublishable_reasons.dedup();
        self.publishable = self.unpublishable_reasons.is_empty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are internal, hermetic tests of pure helpers that the external
    // `tests/provenance.rs` cannot reach (either because they are private, or
    // because they are Linux-only and the fixture-driven tests in that file
    // are deliberately platform-independent). They are supplementary to, not
    // a replacement for, the 21 named tests plus the property test in
    // `tests/provenance.rs`, which is what the acceptance criteria check.

    #[test]
    fn mem_total_overflow_is_rejected_not_wrapped() {
        // u64::MAX kB, scaled by 1024, does not fit in u64: checked_mul must
        // reject it rather than wrap into a small, wrong `mem_bytes` that a
        // memory-curve gate would then silently trust.
        let text = format!("MemTotal:       {} kB\n", u64::MAX);
        let err = parse_meminfo(text.as_bytes()).expect_err("u64::MAX kB overflows u64 bytes");
        assert!(matches!(err, BenchError::Parse { .. }));
    }

    #[test]
    fn civil_from_days_matches_the_three_pinned_epochs() {
        // Restates format_utc_date's own three pinned epochs one level down,
        // directly against the day/month/year triple, so a mutation that
        // corrupts civil_from_days but happens to cancel out in string
        // formatting (unlikely, but this is a free, cheap, independent check)
        // cannot hide behind the string-level test alone.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_518), (2020, 9, 13));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn port_range_parses_two_whitespace_separated_integers() {
        assert_eq!(parse_port_range("32768\t60999"), Some((32_768, 60_999)));
        assert_eq!(parse_port_range("garbage"), None);
        assert_eq!(parse_port_range("32768"), None);
        assert_eq!(parse_port_range("32768 60999 extra"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clocksource_and_governor_char_classes_reject_uppercase_and_slash() {
        assert!(is_clocksource_char(b't'));
        assert!(is_clocksource_char(b'-'));
        assert!(!is_clocksource_char(b'T'));
        assert!(!is_clocksource_char(b'/'));
        assert!(is_governor_char(b'p'));
        assert!(is_governor_char(b'_'));
        assert!(!is_governor_char(b'0'));
        assert!(!is_governor_char(b'-'));
    }

    /// The seam test for the burstable guard's call site. `HostFacts` can
    /// only otherwise be produced by `capture_host_facts()`, which only runs
    /// against the real host; this builds one by hand so the derivation
    /// `burstable = instance_type.as_deref().is_some_and(is_burstable)`
    /// inside `assemble_provenance` is exercised directly, independent of
    /// what any real machine's `instance_type` happens to be. Also pins that
    /// every other `HostFacts` field is passed straight through rather than
    /// being replaced along the way.
    #[test]
    fn assemble_provenance_derives_burstable_from_instance_type_via_is_burstable() {
        let host = HostFacts {
            cpu_model: "Example CPU".to_owned(),
            physical_cores: 4,
            physical_cores_assumed: false,
            logical_cores: 8,
            mem_bytes: 16 * GIB,
            instance_type: Some("t4g.large".to_owned()),
            kernel: "6.1.0-generic".to_owned(),
            clocksource: "tsc".to_owned(),
            governor: Some("performance".to_owned()),
            thermal_throttle_count: Some(3),
            ip_local_port_range: Some((32_768, 60_999)),
        };
        let stamp = BuildStamp {
            name: "irontraffic".to_owned(),
            version: "0.1.0".to_owned(),
            git_sha: "0a1b2c3d4e5f".to_owned(),
            dirty: false,
            profile: "release".to_owned(),
            features: Vec::new(),
            stamp_source: StampSource::Embedded,
        };
        let loadgen = ToolStamp {
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: None,
        };

        let provenance = assemble_provenance(
            host,
            AssembledParts {
                utc_date: "2026-07-24T00:00:00Z".to_owned(),
                cpu_arch: "aarch64".to_owned(),
                ulimit_nofile: 1_048_576,
                sut: stamp.clone(),
                origin: stamp,
                loadgen,
                warmup_seconds: 5,
                measure_seconds: 30,
                repetitions: 3,
            },
        );

        assert!(
            provenance.burstable,
            "instance_type \"t4g.large\" must set burstable true via is_burstable at the \
             assembly call site, not a hard coded false"
        );
        assert_eq!(provenance.cpu_model, "Example CPU");
        assert_eq!(provenance.mem_bytes, 16 * GIB);
        assert_eq!(provenance.kernel, "6.1.0-generic");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn devicetree_model_is_trimmed_at_the_first_nul() {
        let bytes = b"Neoverse-V1 board\0\0\0";
        assert_eq!(
            decode_nul_trimmed_utf8(bytes).as_deref(),
            Some("Neoverse-V1 board")
        );
    }

    /// A throwaway `/sys/devices/system/cpu`-shaped directory: `count` real
    /// `cpu<N>/thermal_throttle/core_throttle_count` files each holding
    /// `value_each`, plus one non-`cpu*` sibling (`online`) so the cap
    /// counting logic under test is shown to ignore it.
    #[cfg(target_os = "linux")]
    #[allow(
        clippy::expect_used,
        reason = "test-support helper, not itself a #[test] fn"
    )]
    fn fixture_thermal_dir(id: &str, count: usize, value_each: u64) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "irontraffic-bench-thermal-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("fixture thermal dir must be creatable");
        std::fs::write(dir.join("online"), b"0-7").expect("the non-cpu* sibling must be writable");
        for i in 0..count {
            let core_dir = dir.join(format!("cpu{i}")).join("thermal_throttle");
            std::fs::create_dir_all(&core_dir).expect("fixture core dir must be creatable");
            std::fs::write(core_dir.join("core_throttle_count"), value_each.to_string())
                .expect("fixture counter file must be writable");
        }
        dir
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thermal_throttle_sums_only_cpu_star_entries_under_the_cap() {
        let dir = fixture_thermal_dir("under-cap", 3, 5);
        let sum = sum_thermal_throttle_from(&dir, MAX_CPU_ENTRIES);
        assert_eq!(
            sum,
            Some(15),
            "3 cpu* entries of 5 each, under the cap and past a non-cpu* sibling, must sum to 15"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thermal_throttle_records_none_past_the_cap_rather_than_a_partial_sum() {
        // Edge case 4b: a directory with more cpu* entries than the cap
        // records None, never Some(partial_sum), which would read in a
        // committed record exactly like a complete throttle count.
        let dir = fixture_thermal_dir("over-cap", 5, 5);
        let sum = sum_thermal_throttle_from(&dir, 3);
        assert_eq!(
            sum, None,
            "5 cpu* entries against a cap of 3 must record None, not a partial sum of any of \
             the first 3 entries visited"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thermal_throttle_sums_exactly_at_the_cap_boundary() {
        let dir = fixture_thermal_dir("at-cap", 4, 2);
        let sum = sum_thermal_throttle_from(&dir, 4);
        assert_eq!(
            sum,
            Some(8),
            "exactly 4 cpu* entries against a cap of 4 must not be treated as exceeding it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
