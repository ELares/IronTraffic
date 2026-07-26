// SPDX-License-Identifier: MIT OR Apache-2.0
//! Derive the Tokio worker thread count from cgroup CPU quotas.
//!
//! This module exists because using the host core count for `worker_threads` in
//! a container with a CFS quota is the single most common performance bug in
//! containerized Rust services. The resolution order is cgroup v2, cgroup v1,
//! then host parallelism.

use std::io::Read as _;
use std::path::Path;

/// The largest worker count this process will build a runtime for.
///
/// A worker is an operating-system thread with a 2 MiB default stack, so this
/// ceiling exists to keep a configuration value or an `IRONTRAFFIC_WORKERS`
/// setting from becoming an unbounded thread spawn. An override above it is
/// clamped down to it; `config-load-and-validate` (#15) warns at the same number,
/// so the warning and the clamp agree.
pub const MAX_WORKERS: usize = 1024;

/// Where the worker count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaSource {
    /// cgroup v2 `cpu.max` gave a numeric quota.
    CgroupV2,
    /// cgroup v1 `cpu.cfs_quota_us` gave a positive quota.
    CgroupV1,
    /// A cgroup file was readable and said there is no limit.
    CgroupUnlimited,
    /// No cgroup file was readable; host parallelism was used.
    AvailableParallelism,
    /// Configuration or the environment set the count explicitly.
    Override,
}

impl QuotaSource {
    /// The `snake_case` name used in the startup log line. The five values are exactly:
    /// `CgroupV2` -> `"cgroup_v2"`, `CgroupV1` -> `"cgroup_v1"`,
    /// `CgroupUnlimited` -> `"cgroup_unlimited"`, `AvailableParallelism` ->
    /// `"available_parallelism"`, `Override` -> `"override"`. These strings appear in
    /// the one startup log line an operator greps, so they are a contract; a test pins
    /// all five.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupV2 => "cgroup_v2",
            Self::CgroupV1 => "cgroup_v1",
            Self::CgroupUnlimited => "cgroup_unlimited",
            Self::AvailableParallelism => "available_parallelism",
            Self::Override => "override",
        }
    }
}

/// How many workers to run, and why.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkerDerivation {
    /// The derived worker count. Always at least 1.
    pub workers: usize,
    /// Which source decided it.
    pub source: QuotaSource,
    /// The CPU quota in fractional CPUs, when a numeric quota was read.
    pub quota_cpus: Option<f64>,
    /// What the host reported as available parallelism.
    pub available_cpus: usize,
}

impl WorkerDerivation {
    /// The one startup log line, for example
    /// `workers=2 source=cgroup_v2 quota_cpus=1.50 available_cpus=96`.
    #[must_use]
    pub fn summary(&self) -> String {
        let quota = match self.quota_cpus {
            Some(c) => format!("{c:.2}"),
            None => String::from("none"),
        };
        format!(
            "workers={} source={} quota_cpus={quota} available_cpus={}",
            self.workers,
            self.source.as_str(),
            self.available_cpus
        )
    }
}

/// Quota read from a cgroup file. Private: the public API is [`derive_workers`].
#[derive(Debug, Clone, Copy, PartialEq)]
enum Quota {
    /// A positive numeric quota in whole and fractional CPUs.
    Cpus(f64),
    /// The file said there is no limit (`"max"` or `-1`).
    Unlimited,
    /// The file was missing, unreadable, or unparsable.
    Unknown,
}

/// Derives the worker count from the cgroup quota, falling back to host parallelism.
///
/// Resolution order: an explicit `override_workers`, then cgroup v2
/// `<fs_root>/sys/fs/cgroup/cpu.max`, then cgroup v1
/// `<fs_root>/sys/fs/cgroup/cpu/cpu.cfs_quota_us` and `cpu.cfs_period_us`, then
/// `available_cpus`. The formula is
/// `clamp(ceil(quota_cpus), 1, available_cpus)`. An override is not clamped to
/// `available_cpus`, so a deliberate oversubscription is obeyed and logged, but it
/// IS clamped to [`MAX_WORKERS`], because the returned number becomes
/// `tokio::runtime::Builder::worker_threads` and an operating-system thread per
/// unit is not a cost a configuration typo may impose without a ceiling.
/// The return value is in `1..=MAX_WORKERS` on every path.
///
/// Never panics. A missing, empty, or unparsable file falls through to the next
/// source rather than failing.
///
/// `fs_root` is normally `Path::new("/")`; tests pass a fixture directory.
/// Performs blocking file I/O: call once, at startup, before any runtime exists.
#[must_use]
pub fn derive_workers(
    fs_root: &Path,
    override_workers: Option<usize>,
    available_cpus: usize,
) -> WorkerDerivation {
    let available = available_cpus.clamp(1, MAX_WORKERS);

    if let Some(w) = override_workers {
        return WorkerDerivation {
            workers: w.clamp(1, MAX_WORKERS),
            source: QuotaSource::Override,
            quota_cpus: None,
            available_cpus: available,
        };
    }

    let v2 = read_v2(fs_root);
    let (q, numeric_source) = if v2 == Quota::Unknown {
        (read_v1(fs_root), QuotaSource::CgroupV1)
    } else {
        (v2, QuotaSource::CgroupV2)
    };

    match q {
        Quota::Cpus(c) => {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "value is clamped to MAX_WORKERS immediately after ceil"
            )]
            #[expect(
                clippy::cast_sign_loss,
                reason = "c is non-negative because it is a CPU count"
            )]
            let workers = c.ceil() as usize;
            WorkerDerivation {
                workers: workers.clamp(1, available),
                source: numeric_source,
                quota_cpus: Some(c),
                available_cpus: available,
            }
        }
        Quota::Unlimited => WorkerDerivation {
            workers: available,
            source: QuotaSource::CgroupUnlimited,
            quota_cpus: None,
            available_cpus: available,
        },
        Quota::Unknown => WorkerDerivation {
            workers: available,
            source: QuotaSource::AvailableParallelism,
            quota_cpus: None,
            available_cpus: available,
        },
    }
}

/// `std::thread::available_parallelism`, or 1 when the platform cannot report it.
#[must_use]
pub fn host_parallelism() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Read at most `limit` bytes from `path` as UTF-8 text.
///
/// Returns `None` if the file is missing, unreadable, too large, or not valid
/// UTF-8. This is the bounded read the startup path uses for `/sys` files.
fn read_bounded(path: &Path) -> Option<String> {
    const READ_LIMIT: u64 = 256;
    let file = std::fs::File::open(path).ok()?; // it-allow: no-blocking-in-async reason: called once at startup before any runtime exists
    let mut limited = file.take(READ_LIMIT);
    let mut text = String::new();
    limited.read_to_string(&mut text).ok()?;
    Some(text)
}

/// Read the cgroup v2 CPU quota from `<root>/sys/fs/cgroup/cpu.max`.
fn read_v2(root: &Path) -> Quota {
    let Some(text) = read_bounded(&root.join("sys/fs/cgroup/cpu.max")) else {
        return Quota::Unknown;
    };

    let mut fields = text.split_ascii_whitespace();
    let Some(quota_str) = fields.next() else {
        return Quota::Unknown;
    };
    let Some(period_str) = fields.next() else {
        return Quota::Unknown;
    };

    if quota_str == "max" {
        return Quota::Unlimited;
    }

    let Some(quota) = quota_str.parse::<u64>().ok() else {
        return Quota::Unknown;
    };
    let Some(period) = period_str.parse::<u64>().ok() else {
        return Quota::Unknown;
    };

    if period == 0 {
        return Quota::Unknown;
    }
    if quota == 0 {
        return Quota::Cpus(0.0);
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "cgroup quota and period are in microseconds and fit in f64 with integer precision"
    )]
    Quota::Cpus(quota as f64 / period as f64)
}

/// Read the cgroup v1 CPU quota from `<root>/sys/fs/cgroup/cpu/cpu.cfs_quota_us`
/// and `cpu.cfs_period_us`.
fn read_v1(root: &Path) -> Quota {
    let Some(qtext) = read_bounded(&root.join("sys/fs/cgroup/cpu/cpu.cfs_quota_us")) else {
        return Quota::Unknown;
    };

    let Some(q) = qtext.trim().parse::<i64>().ok() else {
        return Quota::Unknown;
    };

    if q < 0 {
        return Quota::Unlimited;
    }

    let Some(ptext) = read_bounded(&root.join("sys/fs/cgroup/cpu/cpu.cfs_period_us")) else {
        return Quota::Unknown;
    };

    let Some(p) = ptext.trim().parse::<u64>().ok() else {
        return Quota::Unknown;
    };

    if p == 0 {
        return Quota::Unknown;
    }
    if q == 0 {
        return Quota::Cpus(0.0);
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "cgroup quota and period are in microseconds and fit in f64 with integer precision"
    )]
    Quota::Cpus(q as f64 / p as f64)
}

#[cfg(test)]
mod tests {
    use super::{MAX_WORKERS, QuotaSource, WorkerDerivation, derive_workers};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FixtureGuard(PathBuf);

    impl Drop for FixtureGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(name: &str, files: &[(&str, &str)]) -> (PathBuf, FixtureGuard) {
        let pid = std::process::id();
        let counter = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("irontraffic-cgroup-{name}-{pid}-{counter}"));
        std::fs::create_dir_all(&dir).unwrap();
        for (rel_path, content) in files {
            let full_path = dir.join(rel_path);
            std::fs::create_dir_all(full_path.parent().unwrap()).unwrap();
            std::fs::write(&full_path, content).unwrap();
        }
        (dir.clone(), FixtureGuard(dir))
    }

    fn assert_workers_and_source(
        derivation: WorkerDerivation,
        expected_workers: usize,
        expected_source: QuotaSource,
    ) {
        assert_eq!(
            derivation.workers, expected_workers,
            "workers mismatch for source {expected_source:?}"
        );
        assert_eq!(derivation.source, expected_source);
    }

    #[test]
    fn derive_v2_table() {
        let cases: &[(&str, usize, usize, QuotaSource, Option<f64>)] = &[
            ("max 100000", 7, 7, QuotaSource::CgroupUnlimited, None),
            ("50000 100000", 7, 1, QuotaSource::CgroupV2, Some(0.5)),
            ("150000 100000", 96, 2, QuotaSource::CgroupV2, Some(1.5)),
            ("200000 100000", 7, 2, QuotaSource::CgroupV2, Some(2.0)),
            ("9600000 100000", 4, 4, QuotaSource::CgroupV2, Some(96.0)),
            ("0 100000", 4, 1, QuotaSource::CgroupV2, Some(0.0)),
            ("50000 0", 7, 7, QuotaSource::AvailableParallelism, None),
            ("garbage", 7, 7, QuotaSource::AvailableParallelism, None),
            ("", 7, 7, QuotaSource::AvailableParallelism, None),
            (
                "  50000   100000  \n",
                7,
                1,
                QuotaSource::CgroupV2,
                Some(0.5),
            ),
            (
                "50000 100000 extra\n",
                7,
                1,
                QuotaSource::CgroupV2,
                Some(0.5),
            ),
        ];

        for (content, available, expected_workers, expected_source, expected_quota) in cases {
            let (root, _guard) = fixture("v2-table", &[("sys/fs/cgroup/cpu.max", content)]);
            let d = derive_workers(&root, None, *available);
            assert_workers_and_source(d, *expected_workers, *expected_source);
            match expected_quota {
                Some(expected) => {
                    let actual = d.quota_cpus.expect("expected a numeric quota");
                    assert!(
                        (actual - expected).abs() < 1e-9,
                        "quota_cpus mismatch: {actual} vs {expected}"
                    );
                }
                None => assert_eq!(d.quota_cpus, None),
            }
        }
    }

    type V1Case<'a> = (
        Option<&'a str>,
        Option<&'a str>,
        usize,
        usize,
        QuotaSource,
        Option<f64>,
    );

    #[test]
    fn derive_v1_table() {
        let cases: &[V1Case<'_>] = &[
            (
                Some("-1\n"),
                Some("100000\n"),
                7,
                7,
                QuotaSource::CgroupUnlimited,
                None,
            ),
            (
                Some("100000\n"),
                Some("100000\n"),
                7,
                1,
                QuotaSource::CgroupV1,
                Some(1.0),
            ),
            (
                Some("100000\n"),
                None,
                7,
                7,
                QuotaSource::AvailableParallelism,
                None,
            ),
            (
                Some("not_a_number\n"),
                Some("100000\n"),
                7,
                7,
                QuotaSource::AvailableParallelism,
                None,
            ),
            (
                Some("100000\n"),
                Some("not_a_number\n"),
                7,
                7,
                QuotaSource::AvailableParallelism,
                None,
            ),
        ];

        for (quota, period, available, expected_workers, expected_source, expected_quota) in cases {
            let mut files: Vec<(&str, &str)> = Vec::new();
            if let Some(q) = quota {
                files.push(("sys/fs/cgroup/cpu/cpu.cfs_quota_us", q));
            }
            if let Some(p) = period {
                files.push(("sys/fs/cgroup/cpu/cpu.cfs_period_us", p));
            }
            let (root, _guard) = fixture("v1-table", &files);
            let d = derive_workers(&root, None, *available);
            assert_workers_and_source(d, *expected_workers, *expected_source);
            match expected_quota {
                Some(expected) => {
                    let actual = d.quota_cpus.expect("expected a numeric quota");
                    assert!(
                        (actual - expected).abs() < 1e-9,
                        "quota_cpus mismatch: {actual} vs {expected}"
                    );
                }
                None => assert_eq!(d.quota_cpus, None),
            }
        }
    }

    #[test]
    fn v2_wins_over_v1() {
        let (root, _guard) = fixture(
            "v2-wins",
            &[
                ("sys/fs/cgroup/cpu.max", "400000 100000\n"),
                ("sys/fs/cgroup/cpu/cpu.cfs_quota_us", "100000\n"),
                ("sys/fs/cgroup/cpu/cpu.cfs_period_us", "100000\n"),
            ],
        );
        let d = derive_workers(&root, None, 8);
        assert_workers_and_source(d, 4, QuotaSource::CgroupV2);
        let actual = d.quota_cpus.expect("expected a numeric quota");
        assert!((actual - 4.0).abs() < 1e-9);
    }

    #[test]
    fn no_cgroup_files_uses_host_parallelism() {
        let (root, _guard) = fixture("no-cgroup", &[]);
        let d = derive_workers(&root, None, 7);
        assert_workers_and_source(d, 7, QuotaSource::AvailableParallelism);
        assert_eq!(d.quota_cpus, None);
    }

    #[test]
    fn override_wins_and_is_not_clamped_up() {
        let (root, _guard) = fixture("override-not-clamped", &[]);
        let d = derive_workers(&root, Some(1000), 4);
        assert_workers_and_source(d, 1000, QuotaSource::Override);
        assert_eq!(d.quota_cpus, None);
    }

    #[test]
    fn override_zero_becomes_one() {
        let (root, _guard) = fixture("override-zero", &[]);
        let d = derive_workers(&root, Some(0), 4);
        assert_workers_and_source(d, 1, QuotaSource::Override);
        assert_eq!(d.workers, 1);
    }

    #[test]
    fn zero_available_cpus_yields_one_worker() {
        let (root, _guard) = fixture("zero-available", &[]);
        let d = derive_workers(&root, None, 0);
        assert_workers_and_source(d, 1, QuotaSource::AvailableParallelism);
        assert_eq!(d.workers, 1);
    }

    #[test]
    fn override_is_clamped_to_max_workers() {
        let (root, _guard) = fixture("override-max", &[]);
        let d = derive_workers(&root, Some(usize::MAX), 4);
        assert_workers_and_source(d, MAX_WORKERS, QuotaSource::Override);
        assert_eq!(MAX_WORKERS, 1024);

        let (root2, _guard2) = fixture("available-max", &[]);
        let d2 = derive_workers(&root2, None, usize::MAX);
        assert_workers_and_source(d2, MAX_WORKERS, QuotaSource::AvailableParallelism);
    }

    #[test]
    fn summary_format_is_pinned() {
        let d = WorkerDerivation {
            workers: 2,
            source: QuotaSource::CgroupV2,
            quota_cpus: Some(1.5),
            available_cpus: 96,
        };
        assert_eq!(
            d.summary(),
            "workers=2 source=cgroup_v2 quota_cpus=1.50 available_cpus=96"
        );

        let d = WorkerDerivation {
            workers: 96,
            source: QuotaSource::AvailableParallelism,
            quota_cpus: None,
            available_cpus: 96,
        };
        assert_eq!(
            d.summary(),
            "workers=96 source=available_parallelism quota_cpus=none available_cpus=96"
        );

        assert_eq!(QuotaSource::CgroupV2.as_str(), "cgroup_v2");
        assert_eq!(QuotaSource::CgroupV1.as_str(), "cgroup_v1");
        assert_eq!(QuotaSource::CgroupUnlimited.as_str(), "cgroup_unlimited");
        assert_eq!(
            QuotaSource::AvailableParallelism.as_str(),
            "available_parallelism"
        );
        assert_eq!(QuotaSource::Override.as_str(), "override");
    }

    #[test]
    fn oversized_cgroup_file_is_bounded() {
        let mut content = String::from("50000 100000\n");
        content.extend(std::iter::repeat_n('x', 100_000));
        let (root, _guard) = fixture("oversized", &[("sys/fs/cgroup/cpu.max", &content)]);
        let d = derive_workers(&root, None, 7);
        assert_workers_and_source(d, 1, QuotaSource::CgroupV2);
        let actual = d.quota_cpus.expect("expected a numeric quota");
        assert!((actual - 0.5).abs() < 1e-9);
    }
}
