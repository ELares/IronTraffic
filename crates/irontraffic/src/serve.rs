// SPDX-License-Identifier: MIT OR Apache-2.0

//! The startup order for `run`, `proxy`, and `control`, the connection handler that
//! dials the single upstream and forwards bytes, and the run loop that supervises the
//! accept tasks and the graceful drain.
//!
//! `validate` never reaches this module: `crate::cli::Command::Validate` keeps the
//! body `config-load-and-validate` (#15) gave it, so [`run`] is called only for
//! `run`, `proxy`, and `control`.
//!
//! M1 forwards bytes; it does not parse the wire protocol carried over the
//! connection. `README.md` and `docs/THREAT-MODEL.md` state what that does and does
//! not defend.

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

use irontraffic_conn::{
    AcceptConfig, AcceptOutcome, BoxFut, ConnGuard, ConnHandler, ConnRegistry, DrainConfig,
    DrainReport, ListenError, ShardedListener, accept_loop, drain,
};
use irontraffic_dataplane::{ForwardLimits, forward_bidirectional};
use irontraffic_io::{
    NoRuntime, ShutdownController, ShutdownToken, Spawner, SystemTimer, TaskHandle, TcpTransport,
};
use irontraffic_runtime::core::{self, Counter};
use irontraffic_upstream::SingleUpstream;

use crate::cli::{Mode, ValidateArgs};

/// Reserved descriptors subtracted from `RLIMIT_NOFILE`'s soft limit before halving
/// it into the connection-cap ceiling: `L x W` listening sockets plus headroom.
const FD_RESERVE: u64 = 64;

/// `serve_inner`'s only failures, both fatal to startup.
///
/// Hand-rolled rather than derived: the closed dependency list this crate's manifest
/// is held to (see the acceptance criteria) does not include `thiserror`, so this
/// reproduces the same two variants, the same `Display` text, and the same
/// `#[source]`-shaped `Error::source` a `thiserror` derive would have generated,
/// without adding the dependency.
#[derive(Debug)]
enum ServeError {
    /// No runtime is driving this thread. Unreachable in production: `serve_inner`
    /// runs only inside [`irontraffic_runtime::DataPlane::block_on`].
    NoRuntime(NoRuntime),
    /// A listener's sockets could not be registered with the reactor.
    Listen(ListenError),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::NoRuntime(e) => write!(f, "no runtime is driving this thread: {e}"),
            ServeError::Listen(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::NoRuntime(e) => Some(e),
            ServeError::Listen(e) => Some(e),
        }
    }
}

/// Turns an entropy read into the fatal exit code startup step 6 uses, extracted so
/// `entropy_failure_is_fatal` can assert the decision without disturbing the real
/// operating system entropy source for the whole test process.
///
/// There is no fallback seed: an `Err` here is always [`ExitCode::from(4)`], never a
/// substituted constant. Extracting the decision into its own function is what makes
/// that a structural fact rather than a convention: a fallback constant could not be
/// added here without deleting the test that pins this signature's two arms.
///
/// Generic over the error type rather than fixed to
/// [`irontraffic_rand::EntropyError`]: that type's only field is private with no
/// public constructor anywhere in `irontraffic-rand` (confirmed by inspection; it is
/// built only via the private struct-literal syntax inside that crate's own `secure`
/// module), so a test outside that crate cannot construct one to drive the `Err` arm
/// without triggering a real operating system entropy failure, which
/// `entropy_failure_is_fatal` explicitly cannot do to the whole test process. The
/// production call site still passes the real `EntropyError` (it implements
/// `Display` through `thiserror`, which is all this bound needs); the test passes a
/// locally constructible stand-in that exercises the identical decision.
pub(crate) fn seed_or_exit<E: std::fmt::Display>(r: Result<u64, E>) -> Result<u64, ExitCode> {
    match r {
        Ok(seed) => Ok(seed),
        Err(e) => {
            #[allow(
                clippy::print_stderr,
                reason = "a startup failure reported before any socket exists and before a \
                          logging subscriber's own formatting is the relevant channel"
            )]
            {
                eprintln!("cannot read the operating system entropy source: {e}");
            }
            Err(ExitCode::from(4))
        }
    }
}

/// Reads the process's own `RLIMIT_NOFILE` soft limit from `/proc/self/limits`.
///
/// `None` on any platform where that file cannot be opened: every non-Linux target,
/// and a Linux target whose `/proc` is unavailable (some containers). An unknown
/// limit means obey the configured `max_connections` rather than guess a ceiling from
/// nothing.
fn read_nofile_soft_limit() -> Option<u64> {
    let file = std::fs::File::open("/proc/self/limits").ok()?; // it-allow: no-blocking-in-async reason: called once at startup before any runtime exists, mirroring the identical pattern in irontraffic-config's load() and irontraffic-runtime's cgroup reader
    let mut text = String::new();
    // Bounded read, `Read::take`, never `read_to_string` on the raw file: a `/proc`
    // path can be a bind-mounted regular file in a container, and an unbounded read
    // has no reason to trust the file's reported size.
    std::io::Read::read_to_string(&mut std::io::Read::take(file, 8192), &mut text).ok()?;
    parse_nofile_soft(&text)
}

/// Parses the `Max open files` soft limit out of the body of `/proc/self/limits`.
///
/// Pure: no I/O, no clock, no allocation beyond the returned value. This is the
/// function the descriptor-budget unit test drives directly.
fn parse_nofile_soft(text: &str) -> Option<u64> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Max open files") else {
            continue;
        };
        let soft = rest.split_whitespace().next()?;
        if soft == "unlimited" {
            return Some(u64::MAX);
        }
        return soft.parse::<u64>().ok();
    }
    None
}

/// The descriptor-budget ceiling for a known soft `RLIMIT_NOFILE`: every live
/// connection holds one downstream and one upstream descriptor, so the real ceiling
/// is `(nofile - FD_RESERVE) / 2`.
///
/// Pure, and the only place the halving is written: [`clamp_max_connections`] and the
/// warning startup step 9a logs both call this rather than each carrying their own
/// copy of the arithmetic, which is what keeps the clamped value and the warning's
/// `ceiling` field from being able to drift apart.
fn descriptor_ceiling(nofile: u64) -> u64 {
    #[allow(
        clippy::integer_division,
        reason = "halving the descriptor budget by design: two descriptors per live \
                  connection, one downstream and one upstream"
    )]
    {
        nofile.saturating_sub(FD_RESERVE) / 2
    }
}

/// Clamps a configured `max_connections` to the descriptor budget when the soft
/// `RLIMIT_NOFILE` limit is known, and returns `want` unchanged when it is not: an
/// unknown limit means obey the configuration rather than guess a ceiling from
/// nothing. The result is never 0: a `want` of 0 and a ceiling of 0 both raise to 1,
/// matching `ConnRegistry::new`'s own floor.
///
/// Pure: no I/O, no logging, no allocation. This is the function
/// `clamp_max_connections_table` drives directly with a synthetic `nofile` on any
/// platform, and it is the only function `run` may pass the result of to
/// `ConnRegistry::new`: never `loaded.doc.limits.max_connections` directly.
fn clamp_max_connections(nofile: Option<u64>, want: u32) -> u64 {
    let want = u64::from(want);
    match nofile {
        Some(nofile) => want.min(descriptor_ceiling(nofile)).max(1),
        None => want, // unknown limit: obey the configuration
    }
}

/// Serves one accepted connection: dial the configured upstream, forward bytes until
/// the connection ends, then release the guard.
struct ProxyHandler {
    /// The single upstream every connection is forwarded to.
    upstream: SingleUpstream,
    /// Deadlines and caps for the forwarding loop.
    limits: ForwardLimits,
    /// Drain timing, used only for the post-forward jitter.
    drain_cfg: DrainConfig,
    /// The runtime's timer, cloned once per connection rather than looked up per
    /// deadline.
    timer: SystemTimer,
}

impl ConnHandler<TcpTransport> for ProxyHandler {
    fn handle(
        &self,
        io: TcpTransport,
        peer: SocketAddr,
        guard: ConnGuard,
        shutdown: ShutdownToken,
    ) -> BoxFut {
        // Copy every field OUT of &self before the async block: the returned future
        // is 'static and cannot borrow the handler. All four are cheap: SingleUpstream,
        // ForwardLimits, and DrainConfig are Copy; SystemTimer is Clone and holds no
        // state of its own.
        let upstream = self.upstream;
        let limits = self.limits;
        let drain_cfg = self.drain_cfg;
        let timer = self.timer.clone();

        Box::pin(async move {
            let mut client = io;
            match upstream.connect().await {
                Err(e) => {
                    core::with(|c| c.bump(Counter::ForwardErrors, 1));
                    tracing::debug!(%peer, reason = e.reason(), "upstream connect failed");
                    // client is dropped here, which closes the downstream connection.
                }
                Ok(mut up) => {
                    match forward_bidirectional(&mut client, &mut up, &timer, &shutdown, &limits)
                        .await
                    {
                        Ok((stats, reason)) => {
                            tracing::trace!(
                                %peer,
                                ?reason,
                                up = stats.client_to_upstream,
                                down = stats.upstream_to_client,
                                "connection finished"
                            );
                        }
                        Err(e) => {
                            core::with(|c| c.bump(Counter::ForwardErrors, 1));
                            tracing::debug!(%peer, error = %e, "forwarding failed");
                        }
                    }
                }
            }
            // The jitter runs AFTER forwarding, not before: in M1 there is no request
            // boundary to observe a drain at, so the honest place to spread the load
            // is the moment the connection releases its slot. A later milestone moves
            // this to the request boundary once one exists.
            if shutdown.is_draining() {
                drain::jitter_before_close(&shutdown, &drain_cfg).await;
            }
            core::with(|c| c.bump(Counter::ConnectionsClosed, 1));
            drop(guard); // explicit for readability; the drop would happen anyway
        })
    }
}

/// `serve_inner`'s only failure is registering a listener with the reactor, which is
/// a bind-class failure.
///
/// # Errors
/// [`ServeError::NoRuntime`] if called off a runtime thread (unreachable in
/// production: this runs only inside [`irontraffic_runtime::DataPlane::block_on`]),
/// or [`ServeError::Listen`] naming the listener and shard that could not be
/// registered.
#[allow(
    clippy::too_many_lines,
    reason = "one cohesive spawn loop coordinating every accept task plus the drain \
              supervisor; splitting it would scatter the accept-task wrapper's counters \
              across extra parameter lists with no gain in clarity"
)]
async fn serve_inner(
    listeners: Vec<ShardedListener>,
    registry: Arc<ConnRegistry>,
    upstream: SingleUpstream,
    controller: ShutdownController,
    token: ShutdownToken,
    time: Arc<dyn irontraffic_time::TimeSource>,
    limits: ForwardLimits,
    drain_cfg: DrainConfig,
) -> Result<DrainReport, ServeError> {
    // Inside `data.block_on`, so this always succeeds; the error path exists because
    // `Spawner::current` has no other way to report "no runtime" than a `Result`.
    let spawner = Spawner::current().map_err(ServeError::NoRuntime)?;
    let handler = Arc::new(ProxyHandler {
        upstream,
        limits,
        drain_cfg,
        timer: SystemTimer::new(),
    });

    let mut accept_tasks: Vec<TaskHandle<()>> = Vec::new();
    let total_loops = Arc::new(AtomicUsize::new(0));
    let stopped_loops = Arc::new(AtomicUsize::new(0));

    for listener in listeners {
        let name = listener.name().clone();
        let (acceptors, _report, addr) = listener.into_acceptors().map_err(ServeError::Listen)?;
        tracing::info!(listener = %name, %addr, shards = acceptors.len(), "serving");

        for (i, acceptor) in acceptors.into_iter().enumerate() {
            total_loops.fetch_add(1, Relaxed);
            // EVERY capture is cloned HERE, outside the `async move` block below, and
            // the block then moves the clones. Cloning inside the block instead moves
            // the original out of this loop's environment on its first iteration and
            // fails to compile on the second: this is the one place in the file where
            // a faithful transcription of a shorter form does not build.
            let (ln, tok, stopped, total) = (
                name.clone(),
                token.clone(),
                Arc::clone(&stopped_loops),
                Arc::clone(&total_loops),
            );
            let (reg, hnd, tim, spw) = (
                Arc::clone(&registry),
                Arc::clone(&handler),
                Arc::clone(&time),
                spawner.clone(),
            );
            accept_tasks.push(spawner.spawn(async move {
                let outcome = accept_loop(
                    acceptor,
                    reg,
                    tok.clone(),
                    spw,
                    hnd,
                    tim,
                    AcceptConfig {
                        shard: i,
                        ..Default::default()
                    },
                )
                .await;
                // An accept loop that ends is either a drain (expected) or a fatal
                // error (a shard that has silently stopped accepting while the
                // process keeps running, the worst kind of outage: healthy from the
                // outside, serving nothing on that socket).
                let n = stopped.fetch_add(1, Relaxed) + 1; // fetch_add, never fetch_sub: this is a monotone counter, not a balance
                if outcome == AcceptOutcome::Fatal {
                    tracing::error!(
                        listener = %ln,
                        shard = i,
                        "accept loop stopped on a fatal error; this shard is no longer accepting"
                    );
                }
                if !tok.is_draining() && n == total.load(Relaxed) {
                    tracing::error!(
                        listener = %ln,
                        "every accept loop has stopped and no drain is in progress; \
                         the process is listening on nothing"
                    );
                }
            }));
        }
    }

    let report = drain::supervise(
        controller,
        Arc::clone(&registry),
        Arc::clone(&time),
        drain_cfg,
    )
    .await;

    // `abort(&self)`, not dropping the handles, so the intent is explicit; dropping
    // the vector when this function returns aborts them anyway, which is the safety
    // net for a handle a fatal error left in an unexpected state.
    for t in &accept_tasks {
        t.abort();
    }
    Ok(report)
}

/// Runs the requested mode to completion.
///
/// Order: probe capabilities, load configuration, validate it, derive the worker
/// count, install per-core state, build the runtimes, bind every listener, then
/// enter the runtime. Nothing binds a socket until validation has passed.
///
/// Exit codes: 0 clean, 1 validation errors, 3 load failure, 4 runtime or entropy
/// initialisation failure, 5 bind failure, 6 shutdown left live connections. (2 is a
/// usage error and is produced by the argument parser, not here.)
///
/// Never called with [`Mode::Validate`]: `crate::cli::Command::Validate` keeps the
/// body `config-load-and-validate` (#15) gave it and calls it directly, so this
/// function has no branch for that variant rather than a fifth, unreachable one.
///
/// `pub(crate)` rather than `pub`: `serve` is a module of the binary crate root
/// (declared `mod serve;` in `main.rs`), which has no external consumer, so a wider
/// visibility is unreachable and `clippy::unreachable_pub` refuses to compile it.
#[allow(
    clippy::too_many_lines,
    reason = "the startup order is fixed and numbered end to end in the issue this \
              implements; splitting it into helper functions would scatter the \
              ordering invariants (nothing binds before validation, nothing spawns \
              before entropy and per-core state succeed) across files where the order \
              between them is no longer visible in one place"
)]
pub(crate) fn run(mode: Mode, args: &ValidateArgs) -> ExitCode {
    // `Caps::probe` performs blocking file I/O and three socket creates; it must run
    // before any runtime exists, never from a runtime thread. `debug_assert`, not
    // `assert`: the cost is zero in a release build and the mistake it catches is a
    // refactor that moves startup inside `block_on`.
    debug_assert!(
        Spawner::current().is_err(),
        "Caps::probe performs blocking file I/O and must run before any runtime exists"
    );
    let caps = irontraffic_io::sys::Caps::probe();
    tracing::info!(caps = %caps.summary(), "platform capabilities");

    let overrides = irontraffic_config::Overrides {
        workers: args.workers,
        bind: args.bind,
        upstream: args.upstream,
        mode: args.mode,
    };
    let loaded =
        match irontraffic_config::load(&args.config, &irontraffic_config::ProcessEnv, &overrides) {
            Ok(loaded) => loaded,
            Err(e) => {
                #[allow(
                    clippy::print_stderr,
                    reason = "a startup load failure reported before any socket exists"
                )]
                {
                    eprintln!("{e}");
                }
                return ExitCode::from(3);
            }
        };

    let diags = irontraffic_config::validate(&loaded.doc);
    if !diags.is_empty() {
        #[allow(
            clippy::print_stderr,
            reason = "configuration diagnostics, reported the same way validate's own mode reports them"
        )]
        {
            eprint!("{}", diags.render());
        }
    }
    if diags.has_errors() {
        return ExitCode::from(1);
    }

    if mode == Mode::Control {
        #[allow(
            clippy::print_stdout,
            reason = "an operator-facing informational message for a mode that has no \
                      other work in this version; not routed through tracing because it \
                      is not a log event, it is the whole output of the command"
        )]
        {
            println!(
                "control mode has no work in this version: the admin API and the \
                 configuration providers arrive in a later milestone"
            );
        }
        return ExitCode::SUCCESS;
    }

    let derivation = irontraffic_runtime::derive_workers(
        Path::new("/"),
        loaded.doc.runtime.workers,
        irontraffic_runtime::host_parallelism(),
    );

    // FATAL, never a fixed fallback seed. This seed is the root of every per-core
    // WyRand stream, and those streams drive decisions an outside observer can see
    // (today, drain jitter). A compiled-in fallback is identical in every deployment
    // of the binary, so anyone holding the binary can predict them, and a fallback
    // that ships once ships forever. If the operating system cannot produce eight
    // bytes of entropy, this process has no business serving traffic.
    let seed = match seed_or_exit(irontraffic_rand::SecureRng::seed()) {
        Ok(seed) => seed,
        Err(code) => return code,
    };

    // ALSO FATAL. `AlreadyInstalled` means something called `core::with` before this
    // line, so a lazily installed one-slot array is already in place and cannot be
    // replaced. Continuing would run every worker thread against a single slot: their
    // counter increments overwrite each other, and every worker draws from one RNG
    // stream, which turns the per-connection drain jitter that exists to spread
    // wakeups over several seconds into one delay shared by every core. `ZeroCores`
    // cannot happen: `derivation.workers` is always at least 1.
    if let Err(e) = core::install(derivation.workers, seed) {
        #[allow(
            clippy::print_stderr,
            reason = "a startup failure reported before any socket exists"
        )]
        {
            eprintln!("cannot install per-core state: {e}");
        }
        return ExitCode::from(4);
    }

    // `RuntimeSection` (config) has four fields and `RuntimeConfig` (runtime) has
    // five, so the mapping is written out here rather than left to be inferred.
    // `control_max_blocking_threads` has no field in the M1 bootstrap document, so it
    // takes the crate default (32), read off `RuntimeConfig::default()` rather than
    // written as a literal here, so the default and this line cannot drift apart.
    // `workers` is carried for completeness and is NOT read by `build`: the
    // derivation above already resolved the override into `derivation`, which is the
    // single source of the count.
    let rt_cfg = irontraffic_runtime::RuntimeConfig {
        mode: irontraffic_runtime::RuntimeMode::from(loaded.doc.runtime.mode),
        workers: loaded.doc.runtime.workers,
        max_blocking_threads: loaded.doc.runtime.max_blocking_threads,
        control_workers: loaded.doc.runtime.control_workers,
        control_max_blocking_threads: irontraffic_runtime::RuntimeConfig::default()
            .control_max_blocking_threads,
    };

    let data = match irontraffic_runtime::DataPlane::build(&rt_cfg, derivation) {
        Ok(d) => d,
        Err(e) => {
            #[allow(
                clippy::print_stderr,
                reason = "a startup failure reported before any socket exists"
            )]
            {
                eprintln!("{e}");
            }
            return ExitCode::from(4);
        }
    };
    let control = match build_control(mode, &rt_cfg) {
        Ok(c) => c,
        Err(e) => {
            #[allow(
                clippy::print_stderr,
                reason = "a startup failure reported before any socket exists"
            )]
            {
                eprintln!("{e}");
            }
            return ExitCode::from(4);
        }
    };

    // Bind BEFORE entering the runtime: binding needs no reactor, and a bind failure
    // is the most common startup failure, so its error path is a plain return rather
    // than an explicit runtime teardown. Nothing has been spawned onto `data` or
    // `control` yet, so dropping them here (implicitly, when this function returns)
    // has nothing to wait for.
    let mut listeners: Vec<ShardedListener> = Vec::with_capacity(loaded.doc.listeners.len());
    for section in &loaded.doc.listeners {
        match ShardedListener::bind(
            &section.name,
            section.bind,
            data.workers(),
            section.reuseport,
            section.ipv6_only,
            section.backlog,
            &caps,
        ) {
            Ok(listener) => listeners.push(listener),
            Err(e) => {
                drop(listeners); // closes every socket already bound
                #[allow(
                    clippy::print_stderr,
                    reason = "a startup failure reported before any socket that is left is entered"
                )]
                {
                    eprintln!("{e}");
                }
                return ExitCode::from(5);
            }
        }
    }

    let time: Arc<dyn irontraffic_time::TimeSource> =
        Arc::new(irontraffic_time::SystemTimeSource::new());

    // Descriptor budget. Every live connection holds one downstream and one upstream
    // descriptor, so the real ceiling is `(nofile - reserve) / 2`, with a reserve for
    // the listening sockets and headroom. A cap above that ceiling does not fail
    // loudly: the proxy accepts happily and then every upstream connect returns
    // EMFILE while the accept loop backs off, which reads as "the backend is down" in
    // every log line and is one of the hardest failures to attribute after the fact.
    let nofile = read_nofile_soft_limit();
    let want = loaded.doc.limits.max_connections;
    if let Some(nofile) = nofile {
        let ceiling = descriptor_ceiling(nofile);
        let want = u64::from(want);
        if want > ceiling {
            tracing::warn!(
                configured = want,
                ceiling,
                nofile,
                "max_connections exceeds the descriptor budget and has been clamped; \
                 raise RLIMIT_NOFILE or lower max_connections"
            );
        }
    }
    let effective_max = clamp_max_connections(nofile, want);

    let registry = ConnRegistry::new(effective_max);
    // Read back off the constructed registry rather than logging `effective_max`
    // directly: a mutation that changes what `ConnRegistry::new` is actually called
    // with would otherwise leave this line reporting the correct value regardless,
    // because the log statement and the constructor argument would be two
    // independent copies of the same number. Reading `registry.stats().max` ties the
    // log to what the registry actually holds, which is what makes the constructor's
    // argument assertable from a test on any platform (`smoke.rs`'s
    // `connection_cap_line_reflects_the_registry`), not only from the Linux-only
    // descriptor-budget test.
    tracing::info!(max_connections = registry.stats().max, "connection cap");
    let upstream = SingleUpstream::new(
        loaded.doc.upstream.address,
        loaded.doc.timeouts.connect_ms.as_duration(),
    );
    let limits = ForwardLimits {
        idle: loaded.doc.timeouts.idle_ms.as_duration(),
        half_close: loaded.doc.timeouts.half_close_ms.as_duration(),
        max_bytes_per_direction: None, // no byte cap in M1
        max_lifetime: loaded
            .doc
            .timeouts
            .max_lifetime_ms
            .map(irontraffic_config::Millis::as_duration),
    };
    // Built here rather than with `DrainConfig::default()`, because the two
    // configured fields come from the document and only `poll_interval` is a
    // constant; the default would silently ignore the document's own shutdown
    // section.
    let drain_cfg = DrainConfig {
        graceful_timeout: loaded.doc.shutdown.graceful_timeout_ms.as_duration(),
        jitter: loaded.doc.shutdown.drain_jitter_ms.as_duration(),
        poll_interval: Duration::from_millis(50), // production value; not a document field
    };
    let (controller, token) = ShutdownController::new();

    let report = match data.block_on(serve_inner(
        listeners, registry, upstream, controller, token, time, limits, drain_cfg,
    )) {
        Ok(r) => r,
        Err(e) => {
            #[allow(
                clippy::print_stderr,
                reason = "a startup failure reported before the process exits"
            )]
            {
                eprintln!("{e}");
            }
            data.shutdown_timeout(Duration::from_secs(5));
            return ExitCode::from(5);
        }
    };

    let snap = core::snapshot();
    // `.get(..).copied().unwrap_or(0)`, never `snap[k as usize]`: indexing_slicing is
    // denied in production code. Each counter is its own named field in the log line
    // rather than one array, because a name is greppable and a bare array is not.
    let n = |k: Counter| snap.get(k as usize).copied().unwrap_or(0);
    tracing::info!(
        killed = report.killed,
        escalated = report.escalated,
        elapsed_ms = report.elapsed_ms,
        connections_accepted = n(Counter::ConnectionsAccepted),
        connections_rejected = n(Counter::ConnectionsRejected),
        connections_closed = n(Counter::ConnectionsClosed),
        bytes_to_upstream = n(Counter::BytesToUpstream),
        bytes_to_downstream = n(Counter::BytesToDownstream),
        forward_errors = n(Counter::ForwardErrors),
        turns_polled = n(Counter::TurnsPolled),
        "shutdown complete"
    );

    if let Some(c) = control {
        c.shutdown_timeout(Duration::from_secs(5));
    }
    data.shutdown_timeout(Duration::from_secs(5));

    if report.killed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(6)
    }
}

/// Builds the control-plane runtime when this build has one and the mode wants one.
///
/// Two bodies, selected by the `control-plane` feature, returning the same type so
/// the caller and the shutdown path are identical in both builds.
///
/// # Errors
/// [`irontraffic_runtime::RuntimeError`] when the operating system refuses to create
/// the control-plane threads. The caller maps it to exit code 4.
#[cfg(feature = "control-plane")]
fn build_control(
    mode: Mode,
    cfg: &irontraffic_runtime::RuntimeConfig,
) -> Result<Option<irontraffic_runtime::ControlPlane>, irontraffic_runtime::RuntimeError> {
    if mode == Mode::Run {
        irontraffic_runtime::ControlPlane::build(cfg).map(Some)
    } else {
        Ok(None)
    }
}

/// The data-plane-only build has no control plane. `run` and `control` were already
/// refused by the argument parser, so `proxy` is the only mode that reaches this
/// function, and `proxy` never builds one.
#[cfg(not(feature = "control-plane"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "this body must share the control-plane body's return type so the caller is identical"
)]
fn build_control(
    _mode: Mode,
    _cfg: &irontraffic_runtime::RuntimeConfig,
) -> Result<Option<irontraffic_runtime::ControlPlane>, irontraffic_runtime::RuntimeError> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::{clamp_max_connections, seed_or_exit};

    #[cfg(target_os = "linux")]
    use super::parse_nofile_soft;

    #[test]
    fn entropy_failure_is_fatal() {
        // `&str` stands in for `irontraffic_rand::EntropyError` here (see
        // `seed_or_exit`'s doc comment for why a real one cannot be constructed from
        // outside its crate): both implement `Display`, which is all this function's
        // bound needs, and the production call site still passes the real type.
        let ok: Result<u64, &str> = Ok(42);
        assert_eq!(seed_or_exit(ok), Ok(42));

        let err: Result<u64, &str> = Err("no entropy source");
        assert_eq!(seed_or_exit(err), Err(ExitCode::from(4)));
    }

    /// Not `#[cfg(target_os = "linux")]`: `clamp_max_connections` is pure and takes
    /// its soft limit as a plain `Option<u64>`, so every row is driven with a
    /// synthetic value and no `/proc` access, on any platform.
    ///
    /// Non-vacuous: changing `descriptor_ceiling`'s `/ 2` to `/ 1` makes the first row
    /// fail (`(1024 - 64) / 1 == 960` in place of 480; the other four rows either do
    /// not exceed the ceiling either way or have a `nofile` the division does not
    /// change), which is how this table was confirmed to actually exercise the
    /// arithmetic rather than merely restate it.
    #[test]
    fn clamp_max_connections_table() {
        assert_eq!(clamp_max_connections(Some(1_024), 10_000), 480);
        assert_eq!(clamp_max_connections(Some(1_024), 100), 100);
        assert_eq!(clamp_max_connections(None, 10_000), 10_000);
        assert_eq!(clamp_max_connections(Some(64), 10_000), 1);
        assert_eq!(clamp_max_connections(Some(u64::MAX), 10_000), 10_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_nofile_soft_table() {
        let realistic = "Limit                     Soft Limit           Hard Limit           Units     \n\
                          Max cpu time              unlimited            unlimited            seconds   \n\
                          Max open files            1024                 524288               files     \n";
        assert_eq!(parse_nofile_soft(realistic), Some(1_024));

        let unlimited =
            "Max open files            unlimited            unlimited            files     \n";
        assert_eq!(parse_nofile_soft(unlimited), Some(u64::MAX));

        let missing =
            "Max cpu time              unlimited            unlimited            seconds   \n";
        assert_eq!(parse_nofile_soft(missing), None);

        let non_numeric =
            "Max open files            not-a-number         524288               files     \n";
        assert_eq!(parse_nofile_soft(non_numeric), None);

        assert_eq!(parse_nofile_soft(""), None);
    }
}
