// SPDX-License-Identifier: MIT OR Apache-2.0
//! `OriginConfig` and the hand-written argument parser.
//!
//! The parser is hand-written for the same reason the main binary's is: the
//! surface is ten flags and a derive macro's generated help text becomes an
//! untestable moving target. A flag's value may appear more than once; the
//! last occurrence wins, except `--listen`, which is repeatable up to eight
//! times and accumulates, and `--sequence`, a boolean that is idempotent.
//! `--version`, `--json`, and `--help` are not part of this grammar: `main`
//! recognizes them before this parser ever runs, because they select a mode
//! that never produces an `OriginConfig` at all.

use std::ffi::OsString;
use std::net::SocketAddr;

/// Everything the origin needs, fully resolved at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginConfig {
    /// Addresses to bind. At least one, at most eight.
    pub listen: Vec<SocketAddr>,
    /// Response body size in bytes. At most `16_777_216`.
    pub body_bytes: u32,
    /// Status code to return. 200 through 599, never 204, and 304 only when
    /// `body_bytes` is 0. See the status-range note in Design.
    pub status: u16,
    /// Baseline per-request delay in microseconds. At most `5_000_000`.
    pub delay_us: u32,
    /// Delay distribution.
    pub delay_dist: DelayDist,
    /// Whether to echo `X-Origin-Seq`.
    pub sequence: bool,
    /// Worker thread count.
    pub workers: u16,
    /// Most connections held open at once. At the bound, a new connection is
    /// accepted and immediately closed and the reject counter rises; accept is
    /// never stopped, because a full kernel backlog reads to the client as a
    /// connect timeout, which looks like a proxy stall.
    pub max_connections: u32,
    /// Milliseconds a connection may take to deliver a complete request head, and
    /// then its declared body. Expiry closes the connection with no response.
    pub head_timeout_ms: u32,
    /// Milliseconds an idle keepalive connection may sit between requests.
    pub idle_timeout_ms: u32,
    /// Optional stats listener. A second network listener, bounded exactly like
    /// the main one.
    pub stats_listen: Option<SocketAddr>,
}

/// How per-request delay is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayDist {
    /// Every request takes `delay_us`.
    None,
    /// Same as `None`, stated explicitly for symmetry in the result file.
    Fixed,
    /// `p_permille` of requests take `hi_us`; the rest take `delay_us`.
    Bimodal {
        /// Probability in parts per thousand.
        p_permille: u16,
        /// The slow branch's delay in microseconds.
        hi_us: u32,
    },
}

/// Every way the argument vector can be wrong. `main` prints the `Display` form to
/// stderr and exits with code 2.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArgError {
    /// A flag the parser does not know.
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    /// A flag that requires a value was given none.
    #[error("flag {0} requires a value")]
    MissingValue(&'static str),
    /// A value that could not be parsed as the flag's type.
    #[error("flag {flag} value {value:?} is not a valid {expected}")]
    BadValue {
        /// The flag.
        flag: &'static str,
        /// The value as given.
        value: String,
        /// What was expected, for example `socket address` or `integer`.
        expected: &'static str,
    },
    /// A value outside the flag's allowed range.
    #[error("flag {flag} value {value} is out of range: {allowed}")]
    OutOfRange {
        /// The flag.
        flag: &'static str,
        /// The value as parsed.
        value: u64,
        /// The allowed range, for example `0..=16777216`.
        allowed: &'static str,
    },
    /// Two flags that cannot be combined, for example `--status 304` with a
    /// nonzero `--body-bytes`.
    #[error("{0}")]
    Conflict(&'static str),
    /// An argument that is not valid UTF-8.
    #[error("argument {0} is not valid UTF-8")]
    NotUtf8(usize),
}

/// The default listener address when `--listen` is never given.
fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8081))
}

/// `std::thread::available_parallelism`, clamped to `1..=1024`, falling back
/// to 1 when the platform cannot report a parallelism figure at all.
fn default_workers() -> u16 {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    u16::try_from(available.clamp(1, 1024)).unwrap_or(1024)
}

/// Reads the string at `argv[index]`, the flag currently being matched.
///
/// Never indexes `argv` directly (`clippy::indexing_slicing` is denied
/// workspace-wide): an out-of-bounds `index` here would mean the caller's own
/// `while i < argv.len()` loop guard was violated, which `break`s the loop
/// rather than asserting a state that should be unreachable.
fn flag_str(argv: &[OsString], index: usize) -> Option<Result<&str, ArgError>> {
    argv.get(index)
        .map(|value| value.to_str().ok_or(ArgError::NotUtf8(index)))
}

/// Consumes the value following the flag at `*i`, advancing `*i` past both
/// the flag and its value. `flag` is the flag's own literal, used only for
/// the error it raises when no value follows.
fn take_value<'a>(
    argv: &'a [OsString],
    i: &mut usize,
    flag: &'static str,
) -> Result<&'a str, ArgError> {
    *i += 1;
    let value = argv.get(*i).ok_or(ArgError::MissingValue(flag))?;
    let text = value.to_str().ok_or(ArgError::NotUtf8(*i))?;
    *i += 1;
    Ok(text)
}

/// Parses `value` as a `u64` in `min..=max`, inclusive, or an `ArgError`
/// naming `flag`. `allowed` is the range's literal description for the error.
fn parse_ranged_u64(
    flag: &'static str,
    value: &str,
    min: u64,
    max: u64,
    allowed: &'static str,
) -> Result<u64, ArgError> {
    let parsed: u64 = value.parse().map_err(|_| ArgError::BadValue {
        flag,
        value: value.to_owned(),
        expected: "integer",
    })?;
    if parsed < min || parsed > max {
        return Err(ArgError::OutOfRange {
            flag,
            value: parsed,
            allowed,
        });
    }
    Ok(parsed)
}

/// Parses `value` as a `u32` in `min..=max`, inclusive. See
/// [`parse_ranged_u64`]; the widened `u64` always fits back into `u32`
/// because `max` is checked against a `u32`-sized bound first, so the
/// fallback `try_from` branch below is unreachable rather than lossy.
fn parse_ranged_u32(
    flag: &'static str,
    value: &str,
    min: u32,
    max: u32,
    allowed: &'static str,
) -> Result<u32, ArgError> {
    let parsed = parse_ranged_u64(flag, value, u64::from(min), u64::from(max), allowed)?;
    Ok(u32::try_from(parsed).unwrap_or(max))
}

/// Parses a `--delay-dist` value: `none`, `fixed`, or
/// `bimodal:<p_permille>:<hi_us>`. Any other form, including a `bimodal` with
/// the wrong number of colon-separated fields, is `ArgError::BadValue` rather
/// than a partial parse.
fn parse_delay_dist(value: &str) -> Result<DelayDist, ArgError> {
    const EXPECTED: &str = "none, fixed, or bimodal:<p_permille 0..=1000>:<hi_us 0..=5000000>";

    match value {
        "none" => return Ok(DelayDist::None),
        "fixed" => return Ok(DelayDist::Fixed),
        _ => {}
    }

    let fields: Vec<&str> = value.split(':').collect();
    let [head, p_field, hi_field] = fields.as_slice() else {
        return Err(ArgError::BadValue {
            flag: "--delay-dist",
            value: value.to_owned(),
            expected: EXPECTED,
        });
    };
    if *head != "bimodal" {
        return Err(ArgError::BadValue {
            flag: "--delay-dist",
            value: value.to_owned(),
            expected: EXPECTED,
        });
    }

    let bad_value = || ArgError::BadValue {
        flag: "--delay-dist",
        value: value.to_owned(),
        expected: EXPECTED,
    };

    let p_permille: u16 = p_field
        .parse()
        .ok()
        .filter(|p| *p <= 1000)
        .ok_or_else(bad_value)?;
    let hi_us: u32 = hi_field
        .parse()
        .ok()
        .filter(|h| *h <= 5_000_000)
        .ok_or_else(bad_value)?;

    Ok(DelayDist::Bimodal { p_permille, hi_us })
}

impl OriginConfig {
    /// Parses the argument vector. `argv` excludes the program name.
    ///
    /// # Errors
    /// `ArgError` naming the offending flag, mapped to exit code 2 by `main`.
    #[allow(
        clippy::too_many_lines,
        reason = "one cohesive dispatch loop over a small, closed set of flags; splitting it would scatter the value-required and range checks that read naturally in one place per flag"
    )]
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let mut listen: Vec<SocketAddr> = Vec::new();
        let mut body_bytes: u32 = 1024;
        let mut status: u64 = 200;
        let mut delay_us: u32 = 0;
        let mut delay_dist = DelayDist::None;
        let mut sequence = false;
        let mut workers: Option<u16> = None;
        let mut max_connections: u32 = 200_000;
        let mut head_timeout_ms: u32 = 10_000;
        let mut idle_timeout_ms: u32 = 60_000;
        let mut stats_listen: Option<SocketAddr> = None;

        let mut i = 0usize;
        while i < argv.len() {
            let Some(flag) = flag_str(argv, i) else {
                break;
            };
            let flag = flag?;

            match flag {
                "--listen" => {
                    let value = take_value(argv, &mut i, "--listen")?;
                    let addr: SocketAddr = value.parse().map_err(|_| ArgError::BadValue {
                        flag: "--listen",
                        value: value.to_owned(),
                        expected: "socket address",
                    })?;
                    if listen.len() >= 8 {
                        return Err(ArgError::OutOfRange {
                            flag: "--listen",
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "listen.len() is bounded to 8 by this same check on every earlier iteration"
                            )]
                            value: (listen.len() + 1) as u64,
                            allowed: "1..=8",
                        });
                    }
                    listen.push(addr);
                }
                "--body-bytes" => {
                    let value = take_value(argv, &mut i, "--body-bytes")?;
                    body_bytes =
                        parse_ranged_u32("--body-bytes", value, 0, 16_777_216, "0..=16777216")?;
                }
                "--status" => {
                    let value = take_value(argv, &mut i, "--status")?;
                    let parsed =
                        parse_ranged_u64("--status", value, 200, 599, "200..=599 except 204")?;
                    if parsed == 204 {
                        return Err(ArgError::OutOfRange {
                            flag: "--status",
                            value: parsed,
                            allowed: "200..=599 except 204",
                        });
                    }
                    status = parsed;
                }
                "--delay-us" => {
                    let value = take_value(argv, &mut i, "--delay-us")?;
                    delay_us = parse_ranged_u32("--delay-us", value, 0, 5_000_000, "0..=5000000")?;
                }
                "--delay-dist" => {
                    let value = take_value(argv, &mut i, "--delay-dist")?;
                    delay_dist = parse_delay_dist(value)?;
                }
                "--sequence" => {
                    sequence = true;
                    i += 1;
                }
                "--workers" => {
                    let value = take_value(argv, &mut i, "--workers")?;
                    let parsed = parse_ranged_u32("--workers", value, 1, 1024, "1..=1024")?;
                    workers = Some(u16::try_from(parsed).unwrap_or(1024));
                }
                "--max-connections" => {
                    let value = take_value(argv, &mut i, "--max-connections")?;
                    max_connections =
                        parse_ranged_u32("--max-connections", value, 1, 1_000_000, "1..=1000000")?;
                }
                "--head-timeout-ms" => {
                    let value = take_value(argv, &mut i, "--head-timeout-ms")?;
                    head_timeout_ms =
                        parse_ranged_u32("--head-timeout-ms", value, 1, 600_000, "1..=600000")?;
                }
                "--idle-timeout-ms" => {
                    let value = take_value(argv, &mut i, "--idle-timeout-ms")?;
                    idle_timeout_ms =
                        parse_ranged_u32("--idle-timeout-ms", value, 1, 3_600_000, "1..=3600000")?;
                }
                "--stats-listen" => {
                    let value = take_value(argv, &mut i, "--stats-listen")?;
                    let addr: SocketAddr = value.parse().map_err(|_| ArgError::BadValue {
                        flag: "--stats-listen",
                        value: value.to_owned(),
                        expected: "socket address",
                    })?;
                    stats_listen = Some(addr);
                }
                other => return Err(ArgError::UnknownFlag(other.to_owned())),
            }
        }

        if status == 304 && body_bytes != 0 {
            return Err(ArgError::Conflict(
                "--status 304 requires --body-bytes 0: a 304 response carries no content",
            ));
        }

        let listen = if listen.is_empty() {
            vec![default_listen()]
        } else {
            listen
        };
        let workers = workers.unwrap_or_else(default_workers);
        // `status` was checked against `200..=599` above, so this always fits.
        let status = u16::try_from(status).unwrap_or(200);

        Ok(Self {
            listen,
            body_bytes,
            status,
            delay_us,
            delay_dist,
            sequence,
            workers,
            max_connections,
            head_timeout_ms,
            idle_timeout_ms,
            stats_listen,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_with_no_flags() {
        let config = OriginConfig::parse(&args(&[])).expect("empty argv is valid");
        assert_eq!(config.listen, vec![default_listen()]);
        assert_eq!(config.body_bytes, 1024);
        assert_eq!(config.status, 200);
        assert_eq!(config.delay_us, 0);
        assert_eq!(config.delay_dist, DelayDist::None);
        assert!(!config.sequence);
        assert_eq!(config.max_connections, 200_000);
        assert_eq!(config.head_timeout_ms, 10_000);
        assert_eq!(config.idle_timeout_ms, 60_000);
        assert_eq!(config.stats_listen, None);
        assert!(config.workers >= 1);
    }

    #[test]
    fn listen_repeats_up_to_eight() {
        let flags: Vec<String> = (0..8)
            .flat_map(|n| vec!["--listen".to_owned(), format!("127.0.0.1:{}", 9000 + n)])
            .collect();
        let argv: Vec<OsString> = flags.iter().map(OsString::from).collect();
        let config = OriginConfig::parse(&argv).expect("eight --listen flags are valid");
        assert_eq!(config.listen.len(), 8);
    }

    #[test]
    fn a_ninth_listen_is_out_of_range() {
        let flags: Vec<String> = (0..9)
            .flat_map(|n| vec!["--listen".to_owned(), format!("127.0.0.1:{}", 9100 + n)])
            .collect();
        let argv: Vec<OsString> = flags.iter().map(OsString::from).collect();
        assert!(matches!(
            OriginConfig::parse(&argv),
            Err(ArgError::OutOfRange {
                flag: "--listen",
                ..
            })
        ));
    }

    #[test]
    fn unknown_flag_is_rejected() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--nonsense"])),
            Err(ArgError::UnknownFlag(flag)) if flag == "--nonsense"
        ));
    }

    #[test]
    fn missing_value_is_rejected() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--body-bytes"])),
            Err(ArgError::MissingValue("--body-bytes"))
        ));
    }

    #[test]
    fn body_bytes_out_of_range_is_rejected() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--body-bytes", "16777217"])),
            Err(ArgError::OutOfRange {
                flag: "--body-bytes",
                value: 16_777_217,
                ..
            })
        ));
    }

    #[test]
    fn status_204_is_rejected() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--status", "204"])),
            Err(ArgError::OutOfRange {
                flag: "--status",
                value: 204,
                ..
            })
        ));
    }

    #[test]
    fn status_below_200_is_rejected() {
        for value in ["100", "199"] {
            assert!(
                matches!(
                    OriginConfig::parse(&args(&["--status", value])),
                    Err(ArgError::OutOfRange {
                        flag: "--status",
                        ..
                    })
                ),
                "--status {value} must be rejected"
            );
        }
    }

    #[test]
    fn status_304_requires_zero_body_bytes() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--status", "304", "--body-bytes", "1024"])),
            Err(ArgError::Conflict(_))
        ));
        let config = OriginConfig::parse(&args(&["--status", "304", "--body-bytes", "0"]))
            .expect("304 with a zero-byte body is valid");
        assert_eq!(config.status, 304);
        assert_eq!(config.body_bytes, 0);
    }

    #[test]
    fn status_304_is_order_independent() {
        let config = OriginConfig::parse(&args(&["--body-bytes", "0", "--status", "304"]))
            .expect("304 with a zero-byte body is valid regardless of flag order");
        assert_eq!(config.status, 304);
    }

    #[test]
    fn delay_dist_none_and_fixed() {
        let config = OriginConfig::parse(&args(&["--delay-dist", "none"])).expect("none is valid");
        assert_eq!(config.delay_dist, DelayDist::None);
        let config =
            OriginConfig::parse(&args(&["--delay-dist", "fixed"])).expect("fixed is valid");
        assert_eq!(config.delay_dist, DelayDist::Fixed);
    }

    #[test]
    fn delay_dist_bimodal_parses_both_fields() {
        let config = OriginConfig::parse(&args(&["--delay-dist", "bimodal:50:20000"]))
            .expect("a well-formed bimodal spec is valid");
        assert_eq!(
            config.delay_dist,
            DelayDist::Bimodal {
                p_permille: 50,
                hi_us: 20_000
            }
        );
    }

    #[test]
    fn delay_dist_bimodal_wrong_field_count_is_bad_value() {
        for value in ["bimodal", "bimodal:50", "bimodal:50:1:2"] {
            assert!(
                matches!(
                    OriginConfig::parse(&args(&["--delay-dist", value])),
                    Err(ArgError::BadValue {
                        flag: "--delay-dist",
                        ..
                    })
                ),
                "{value} must be rejected as BadValue, not partially parsed"
            );
        }
    }

    #[test]
    fn delay_dist_bimodal_out_of_range_fields_are_bad_value() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--delay-dist", "bimodal:1001:0"])),
            Err(ArgError::BadValue {
                flag: "--delay-dist",
                ..
            })
        ));
        assert!(matches!(
            OriginConfig::parse(&args(&["--delay-dist", "bimodal:0:5000001"])),
            Err(ArgError::BadValue {
                flag: "--delay-dist",
                ..
            })
        ));
    }

    #[test]
    fn sequence_flag_takes_no_value() {
        let config = OriginConfig::parse(&args(&["--sequence", "--body-bytes", "512"]))
            .expect("--sequence takes no value");
        assert!(config.sequence);
        assert_eq!(config.body_bytes, 512);
    }

    #[test]
    fn last_occurrence_wins_for_non_listen_flags() {
        let config = OriginConfig::parse(&args(&["--body-bytes", "10", "--body-bytes", "20"]))
            .expect("repeating a scalar flag is valid, last wins");
        assert_eq!(config.body_bytes, 20);
    }

    #[test]
    fn stats_listen_is_optional_and_parsed() {
        let config = OriginConfig::parse(&args(&["--stats-listen", "127.0.0.1:9100"]))
            .expect("a valid stats-listen address is accepted");
        assert_eq!(
            config.stats_listen,
            Some(SocketAddr::from(([127, 0, 0, 1], 9100)))
        );
    }

    #[test]
    fn workers_out_of_range_is_rejected() {
        assert!(matches!(
            OriginConfig::parse(&args(&["--workers", "0"])),
            Err(ArgError::OutOfRange {
                flag: "--workers",
                ..
            })
        ));
        assert!(matches!(
            OriginConfig::parse(&args(&["--workers", "1025"])),
            Err(ArgError::OutOfRange {
                flag: "--workers",
                ..
            })
        ));
    }

    #[test]
    fn non_utf8_argument_is_rejected() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            let invalid = OsString::from_vec(vec![0x66, 0x6c, 0xFF, 0x67]);
            assert!(matches!(
                OriginConfig::parse(&[invalid]),
                Err(ArgError::NotUtf8(0))
            ));
        }
    }
}
