// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! Per-SNI TLS configuration selection, fail closed.
//!
//! A listener may bind several TLS policies to different server names, and the policy for a
//! connection is chosen by the **same** name-resolution function that chooses the certificate,
//! with a hard rejection when no policy matches.
//!
//! **Why this exists.** Traefik shipped four mTLS bypass CVEs because certificate selection and
//! TLS-option selection used different notions of "the same name", and because a miss fell back to
//! a permissive default. `CVE-2026-32305` (a fragmented `ClientHello` made SNI extraction return
//! empty, falling back to the default non-mTLS configuration), CVE-2026-48491 (`SNICheck` ignored
//! wildcard mappings) and CVE-2026-53622 (exact, case-sensitive HTTP/3 lookup missing wildcard and
//! mixed-case hosts). Every failure mode was fail open. Both halves are closed structurally here:
//! [`ListenerTls::resolve_by_name`] runs the identical normalize-then-two-probe sequence as
//! `CertIndex::resolve`, and a miss returns `None`, which means reject.
//!
//! **The one thing this module cannot close.** The divergence lint catches two bindings that match
//! the SAME name. It cannot catch two DIFFERENT names on one listener carrying different client
//! authentication, because that is the mixed public-and-mTLS listener this design exists to
//! support. That configuration is bypassable by anyone who can send a `Host` header, and the
//! answer is [`ListenerTls::client_auth_for_name`], which the HTTP layer MUST call on every
//! request. See `docs/tls/SNI-POLICY.md`.
//!
//! **The `HOT PATH` marker above.** It puts this whole file, every function in it, under
//! `scripts/invariant-lints.sh`'s `hot-path-allocation` and `hot-path-lock` rules, the same
//! convention `name.rs`, `store/index.rs`, `store/resolver.rs` and `store/challenge.rs` already
//! use. Read what that buys accurately (`name.rs`'s module doc states the same caveat at length):
//! this is a text scan for a fixed list of call spellings, a best-effort net and not a proof that
//! [`ListenerTls::resolve_by_name`] allocates zero times. What actually makes `resolve_by_name`
//! allocation-free is its signature and its body: it writes into a caller-owned stack buffer and
//! returns a borrow, never an owned value. Everything in this file that is NOT on that path
//! (`ListenerTlsBuilder::build`, `TlsServerConfig::compile`, the reject path's alert buffer) does
//! allocate, runs at most once per configuration compile or once per rejected handshake rather
//! than once per resolved name, and is marked `// it-allow: hot-path-allocation reason: ...` at
//! each call site so the lint's coverage of the true hot functions is not diluted by exceptions
//! nobody can find.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::name::{self, MAX_NAME_LEN, NameError, NameHasher, NameKey, WildcardError};
use crate::policy::TlsPolicy;
use crate::store::IronResolver;

/// Identity `BuildHasher` for [`NameKey`], which is already a keyed 64-bit hash.
///
/// This mirrors `store::index::NameKeyHashBuilder`, and the duplication is deliberate but not
/// ideal, so it is recorded rather than hidden: `store::index` is a private module and this
/// issue's Files table does not include `store/mod.rs`, so the existing type cannot be reached
/// from here without widening a module the issue does not authorize touching. Re-hashing an
/// already-random 64-bit key with `SipHash` would be pure cost on the handshake path, which is why
/// the default hasher is not used instead. If a later issue exports the original, delete this and
/// use it: these two must not be allowed to drift into meaning different things.
#[derive(Clone, Default)]
struct NameKeyHashBuilder;

#[derive(Default)]
struct NameKeyHasher(u64);

impl core::hash::BuildHasher for NameKeyHashBuilder {
    type Hasher = NameKeyHasher;

    fn build_hasher(&self) -> NameKeyHasher {
        NameKeyHasher(0)
    }
}

impl core::hash::Hasher for NameKeyHasher {
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }

    fn write(&mut self, bytes: &[u8]) {
        // Never taken: NameKey's derived Hash impl writes exactly one u64. Fold rather than panic.
        for b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*b);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// Compiled-in two-label public suffixes for which a wildcard binding would be absurdly broad.
///
/// Mirrors `store::index::SUFFIX_DENY` exactly. That list is private to `store::index`, and
/// `store/mod.rs` is outside this issue's Files table for the same reason
/// `NameKeyHashBuilder` above is a second copy rather than a shared export: re-exporting it would
/// require touching a file this issue does not authorize touching. If a later issue exports the
/// original, delete this and use it: the two lists must not be allowed to drift apart, which is
/// the exact hazard `store::index::validate_wildcard_parent`'s own doc comment names.
const SUFFIX_DENY: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.cn", "com.mx", "co.za", "co.in",
];

/// Maximum bindings on one listener.
pub const MAX_BINDINGS: usize = 4096;

/// Default cap on buffered `ClientHello` bytes.
pub const DEFAULT_MAX_CLIENT_HELLO_BYTES: usize = 32_768;

/// How strictly a configuration authenticates the client. Used by the divergence lint and reported
/// in the admin API.
///
/// The derived `Ord` is the strength order and the lint depends on it: `None < Optional <
/// Required`. Do not reorder the variants.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ClientAuthKind {
    /// No client certificate is requested.
    None,
    /// A client certificate is requested and verified if presented, but is not required.
    Optional,
    /// A client certificate is required and verified.
    Required,
}

/// Opaque handle to a compiled rustls server configuration.
pub struct TlsServerConfig {
    inner: Arc<rustls::ServerConfig>,
    client_auth: ClientAuthKind,
    policy: Arc<TlsPolicy>,
}

impl core::fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `rustls::ServerConfig` is deliberately not rendered: it carries key material reachable
        // through the resolver, and a `Debug` line is exactly how that reaches a log.
        f.debug_struct("TlsServerConfig")
            .field("client_auth", &self.client_auth)
            .finish_non_exhaustive()
    }
}

impl TlsServerConfig {
    /// Compile a policy plus a certificate resolver into a rustls `ServerConfig` with no client
    /// authentication.
    ///
    /// `ticketer` is the cluster-derived session ticketer to install, if any
    /// (`cluster-derived-session-ticketer`, #120). Its context MUST be 16 zero bytes: this
    /// constructor's `ClientAuthKind` is always `None`, and a ticketer built with any other
    /// context reproduces CVE-2025-68121 (a ticket surviving a change of trust bundle) the moment
    /// it is installed here. The caller constructs at most one `ClusterTicketer` per distinct
    /// context and shares the `Arc`; this function does not construct one itself. `None` leaves
    /// rustls's `NeverProducesTickets` in place and therefore no resumption at all, exactly as
    /// `tls-protocol-cipher-group-alpn-policy` (#116) intends.
    ///
    /// # Errors
    /// [`ListenerError::ProviderNotInstalled`] when `install_process_provider` has not run.
    pub fn compile(
        policy: Arc<TlsPolicy>,
        resolver: Arc<IronResolver>,
        ticketer: Option<Arc<crate::ticket::ClusterTicketer>>,
    ) -> Result<Self, ListenerError> {
        let provider = crate::policy::provider_for(policy.post_quantum())
            .ok_or(ListenerError::ProviderNotInstalled)?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(crate::policy::versions(policy.profile()))
            .map_err(|_| ListenerError::ProviderNotInstalled)?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        crate::policy::apply_common(&policy, &mut cfg);
        if let Some(t) = ticketer {
            cfg.ticketer = t; // it-allow: hot-path-allocation reason: an Arc field assignment, not an allocation; runs once per listener configuration compile
            cfg.send_tls13_tickets =
                usize::try_from(crate::ticket::ClusterTicketer::tickets_to_send()).unwrap_or(2);
        }
        Ok(Self {
            inner: Arc::new(cfg), // it-allow: hot-path-allocation reason: compiles once per listener configuration, not once per resolved name
            client_auth: ClientAuthKind::None,
            policy,
        })
    }

    /// Compile a policy plus a certificate resolver into a rustls `ServerConfig` with client
    /// certificate authentication, the sibling of [`Self::compile`].
    ///
    /// Identical to [`Self::compile`] except that it installs `auth`'s verifier (built by
    /// [`crate::verify_client::IronClientVerifier::new`]) instead of calling
    /// `with_no_client_auth()`, and records `auth.kind()` as the configuration's
    /// [`ClientAuthKind`] instead of hard-coding `None`. When `auth` is
    /// [`crate::verify_client::ClientAuth::None`] this delegates to [`Self::compile`] verbatim,
    /// passing `ticketer` through unchanged: a listener with no client authentication installs no
    /// verifier at all, never a permissive one.
    ///
    /// `allow_unknown_revocation` and `revocation` are the two operator knobs
    /// `crate::verify_client::ClientAuthConfig` carries; they are threaded through here as plain
    /// arguments rather than derived from `auth` because `ClientAuth` deliberately does not carry
    /// them (only the trust anchors do), for the identical reason `crls`, `crl_cfg` and `time`
    /// are also separate arguments here: none of the five can be recovered from `auth` alone.
    ///
    /// `ticketer`'s context MUST be `auth.anchors().map(TrustAnchors::id)`, falling back to 16
    /// zero bytes when `auth` is `ClientAuth::None`: see [`Self::compile`]'s doc for why an
    /// ill-contexted ticketer reproduces CVE-2025-68121.
    ///
    /// # Errors
    /// [`ListenerError::ProviderNotInstalled`] when `install_process_provider` has not run, or
    /// [`ListenerError::ClientAuth`] wrapping anything
    /// [`crate::verify_client::IronClientVerifier::new`] returns.
    #[allow(
        clippy::too_many_arguments,
        reason = "each of these nine is an independent input IronClientVerifier::new itself \
                  requires (auth, crls, crl_cfg, allow_unknown_revocation, revocation, time), \
                  plus the three this constructor's own job adds (policy, resolver, ticketer); \
                  none can be recovered from another, so grouping them into a struct would only \
                  rename this same list rather than shrink it, and ClientAuthConfig itself is not \
                  available here because it is not passed to this constructor (see this method's \
                  own doc for why: ClientAuth deliberately does not carry allow_unknown_revocation \
                  or revocation)"
    )]
    pub fn compile_with_client_auth(
        policy: Arc<TlsPolicy>,
        resolver: Arc<IronResolver>,
        auth: &crate::verify_client::ClientAuth,
        crls: Arc<crate::crl::CrlSet>,
        crl_cfg: crate::crl::CrlConfig,
        allow_unknown_revocation: bool,
        revocation: crate::verify_client::RevocationMode,
        time: Arc<dyn crate::store::TimeView>,
        ticketer: Option<Arc<crate::ticket::ClusterTicketer>>,
    ) -> Result<Self, ListenerError> {
        let verifier = crate::verify_client::IronClientVerifier::new(
            auth,
            crls,
            crl_cfg,
            allow_unknown_revocation,
            revocation,
            time,
        )
        .map_err(ListenerError::ClientAuth)?;
        let Some(verifier) = verifier else {
            // `ClientAuth::None`: no verifier to install.
            return Self::compile(policy, resolver, ticketer);
        };

        let provider = crate::policy::provider_for(policy.post_quantum())
            .ok_or(ListenerError::ProviderNotInstalled)?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(crate::policy::versions(policy.profile()))
            .map_err(|_| ListenerError::ProviderNotInstalled)?
            .with_client_cert_verifier(Arc::new(verifier)) // it-allow: hot-path-allocation reason: wraps the verifier once per listener configuration compile, not once per resolved name
            .with_cert_resolver(resolver);
        crate::policy::apply_common(&policy, &mut cfg);
        if let Some(t) = ticketer {
            cfg.ticketer = t; // it-allow: hot-path-allocation reason: an Arc field assignment, not an allocation; runs once per listener configuration compile
            cfg.send_tls13_tickets =
                usize::try_from(crate::ticket::ClusterTicketer::tickets_to_send()).unwrap_or(2);
        }
        Ok(Self {
            inner: Arc::new(cfg), // it-allow: hot-path-allocation reason: compiles once per listener configuration, not once per resolved name
            client_auth: auth.kind(),
            policy,
        })
    }

    /// The one permitted place a rustls type crosses this crate's facade. The connection layer
    /// needs it to start a `ServerConnection`. When rustls 0.24 lands, this signature is the only
    /// one outside this crate that changes.
    #[must_use]
    pub fn as_rustls(&self) -> &Arc<rustls::ServerConfig> {
        &self.inner
    }

    /// Which client authentication this configuration enforces.
    #[must_use]
    pub fn client_auth(&self) -> ClientAuthKind {
        self.client_auth
    }

    /// The policy this configuration was compiled from.
    #[must_use]
    pub fn policy(&self) -> &Arc<TlsPolicy> {
        &self.policy
    }
}

/// Per-listener limits on the unauthenticated part of a connection's life.
///
/// A `ClientHello` costs an attacker roughly 500 bytes and one `write()`; it costs us one signature
/// and one key agreement, about 147 microseconds of CPU for ECDSA and about 424 for RSA-2048. That
/// asymmetry is the single worst thing about terminating TLS, so the limits that bound it live
/// here, next to the acceptor that is the first thing an unauthenticated peer reaches.
///
/// **These are values plus a contract, not an implementation.** [`SniAcceptor`] is sans-IO and
/// cannot read a clock, count connections, or see a source address, so this crate enforces none of
/// the four. The accept loop that owns the socket enforces them; `docs/tls/SNI-POLICY.md` states
/// the contract it must satisfy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// A connection that has not completed its TLS handshake within this many milliseconds is
    /// closed. Default 10,000 (10 seconds). Clamped to `1_000..=120_000`.
    pub handshake_timeout_ms: u32,
    /// Maximum handshakes in progress on this listener at once. Default 10,000. A new connection
    /// beyond the cap is closed immediately, before any asymmetric operation. Clamped to
    /// `16..=1_000_000`.
    pub max_inflight: u32,
    /// Maximum handshakes in progress from one source address at once. Default 64. Clamped to
    /// `1..=65_536`.
    pub max_inflight_per_source: u32,
    /// Maximum `KeyUpdate` messages accepted on one connection before it is closed. Default 32.
    /// rustls 0.23.33 added its own key-update-request limit; this is a second, explicit bound so
    /// the number is ours and is visible. Clamped to `1..=1_024`.
    pub max_key_updates_per_connection: u32,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            handshake_timeout_ms: 10_000,
            max_inflight: 10_000,
            max_inflight_per_source: 64,
            max_key_updates_per_connection: 32,
        }
    }
}

impl HandshakeLimits {
    /// Clamp every field to the range in its doc comment.
    ///
    /// Out-of-range values are clamped, never rejected: these are operational dials, and a
    /// listener that refuses to start over a typo in a limit is worse than one that runs with the
    /// nearest legal value.
    fn clamped(self) -> Self {
        Self {
            handshake_timeout_ms: self.handshake_timeout_ms.clamp(1_000, 120_000),
            max_inflight: self.max_inflight.clamp(16, 1_000_000),
            max_inflight_per_source: self.max_inflight_per_source.clamp(1, 65_536),
            max_key_updates_per_connection: self.max_key_updates_per_connection.clamp(1, 1_024),
        }
    }
}

/// Why a listener configuration failed to compile.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ListenerError {
    /// An exact binding and a wildcard binding that covers it disagree on client authentication.
    ClientAuthDivergence {
        /// The exact name.
        exact: Box<str>,
        /// The wildcard parent that also covers it.
        wildcard: Box<str>,
        /// The exact binding's requirement.
        exact_auth: ClientAuthKind,
        /// The wildcard binding's requirement.
        wildcard_auth: ClientAuthKind,
    },
    /// The fallback configuration authenticates more weakly than some binding.
    FallbackWeakerThanBinding {
        /// The fallback's requirement.
        fallback_auth: ClientAuthKind,
        /// The strongest binding's requirement.
        strongest_auth: ClientAuthKind,
    },
    /// The no-SNI configuration authenticates more weakly than some binding.
    NoSniWeakerThanBinding {
        /// The no-SNI requirement.
        no_sni_auth: ClientAuthKind,
        /// The strongest binding's requirement.
        strongest_auth: ClientAuthKind,
    },
    /// Two bindings for the same name.
    DuplicateBinding {
        /// The name.
        name: Box<str>,
    },
    /// A wildcard binding's parent has fewer than two labels, or is a compiled-in public suffix.
    /// Mirrors `store::index::CertError::WildcardTooBroad`: the certificate index refuses a
    /// certificate at this scope, so a policy binding here could never be served by a real
    /// certificate, and would silently widen the client-auth surface for every name under the
    /// suffix. Not in issue #119's original Public API for `bind_wildcard`; see the PR body's
    /// deviation list.
    WildcardTooBroad {
        /// The wildcard's parent domain.
        parent: Box<str>,
    },
    /// More than [`MAX_BINDINGS`].
    TooManyBindings,
    /// A binding name failed validation.
    Name(NameError),
    /// A wildcard binding name was malformed.
    Wildcard(WildcardError),
    /// `install_process_provider` has not run, so no `ServerConfig` can be built.
    ProviderNotInstalled,
    /// [`TlsServerConfig::compile_with_client_auth`] could not build a client-certificate
    /// verifier. Carries the reason from `mtls-client-auth-fail-closed` (#124), which includes
    /// the fail-closed CVE-2026-27586 refusal and the enforced-revocation-without-CRLs refusal.
    ClientAuth(crate::verify_client::ClientAuthError),
}

impl core::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ListenerError::ClientAuthDivergence {
                exact,
                wildcard,
                exact_auth,
                wildcard_auth,
            } => write!(
                f,
                "client authentication diverges: {exact} requires {exact_auth:?} but *.{wildcard} \
                 requires {wildcard_auth:?}; two ways to reach the same authority with different \
                 authentication is CVE-2026-48491's shape"
            ),
            ListenerError::FallbackWeakerThanBinding {
                fallback_auth,
                strongest_auth,
            } => write!(
                f,
                "the fallback configuration authenticates with {fallback_auth:?} but a binding \
                 requires {strongest_auth:?}; a weaker fallback admits under weaker rules"
            ),
            ListenerError::NoSniWeakerThanBinding {
                no_sni_auth,
                strongest_auth,
            } => write!(
                f,
                "the no-SNI configuration authenticates with {no_sni_auth:?} but a binding \
                 requires {strongest_auth:?}"
            ),
            ListenerError::DuplicateBinding { name } => {
                write!(f, "two bindings for the same name: {name}")
            }
            ListenerError::WildcardTooBroad { parent } => write!(
                f,
                "wildcard binding *.{parent} is too broad: fewer than two labels or a compiled-in \
                 public suffix, so the certificate index would refuse a certificate at this scope"
            ),
            ListenerError::TooManyBindings => {
                f.write_str("a listener may declare at most 4096 name bindings")
            }
            ListenerError::Name(e) => write!(f, "invalid binding name: {e}"),
            ListenerError::Wildcard(e) => write!(f, "invalid wildcard binding: {e}"),
            ListenerError::ProviderNotInstalled => f.write_str(
                "no crypto provider is installed; install_process_provider must run first",
            ),
            ListenerError::ClientAuth(e) => write!(f, "client authentication: {e}"),
        }
    }
}

impl std::error::Error for ListenerError {}

impl From<NameError> for ListenerError {
    fn from(e: NameError) -> Self {
        ListenerError::Name(e)
    }
}

impl From<WildcardError> for ListenerError {
    fn from(e: WildcardError) -> Self {
        ListenerError::Wildcard(e)
    }
}

/// Counters for the listener path.
#[derive(Debug, Default)]
pub struct ListenerStats {
    /// `tls_listener_policy_exact_total`
    pub exact_hits: AtomicU64,
    /// `tls_listener_policy_wildcard_total`
    pub wildcard_hits: AtomicU64,
    /// `tls_listener_policy_miss_total`
    pub policy_miss: AtomicU64,
    /// `tls_listener_invalid_sni_total`
    pub invalid_sni: AtomicU64,
    /// `tls_listener_no_sni_total`
    pub no_sni: AtomicU64,
    /// `tls_listener_reject_total`, by [`RejectReason`] label.
    pub rejects: [AtomicU64; 7],
    /// `tls_listener_authority_auth_downgrade_total`: requests refused because the request
    /// authority's binding requires stronger client authentication than the connection provided.
    /// A non-zero value means somebody is probing the cross-name bypass.
    pub authority_auth_downgrade: AtomicU64,
    /// `tls_listener_client_hello_too_large_total`
    pub client_hello_too_large: AtomicU64,
}

/// One name-to-configuration binding on a listener.
struct Binding {
    /// Normalized name; for a wildcard binding this is the parent domain.
    name: Box<str>,
    is_wildcard: bool,
    config: Arc<TlsServerConfig>,
}

/// Compiled TLS configuration for one listener. Immutable; a configuration change builds a new one.
pub struct ListenerTls {
    hasher: NameHasher,
    exact: HashMap<NameKey, u32, NameKeyHashBuilder>,
    wild: HashMap<NameKey, u32, NameKeyHashBuilder>,
    bindings: Box<[Binding]>,
    /// Used when the `ClientHello` carries no SNI. `None` means reject.
    no_sni: Option<Arc<TlsServerConfig>>,
    /// Used when an SNI is present but matches no binding. `None` means reject, and `None` is the
    /// default.
    fallback: Option<Arc<TlsServerConfig>>,
    max_client_hello_bytes: usize,
    limits: HandshakeLimits,
    stats: ListenerStats,
}

impl core::fmt::Debug for ListenerTls {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ListenerTls")
            .field("bindings", &self.bindings.len())
            .field("has_no_sni", &self.no_sni.is_some())
            .field("has_fallback", &self.fallback.is_some())
            .finish_non_exhaustive()
    }
}

impl ListenerTls {
    /// The binding index for `sni`, using the same normalization and the same two probes, in the
    /// same order, as `CertIndex::resolve`.
    ///
    /// Returns `Err(())` when the name failed normalization, `Ok(None)` when it normalized but
    /// matched nothing. The caller distinguishes the two because they are different counters and
    /// different reject reasons; everything else about the lookup is shared, which is what makes
    /// invariant 9 hold by construction rather than by review.
    ///
    /// `count` is `false` on the [`Self::client_auth_for_name`] path: the per-request re-check
    /// must not inflate the per-handshake selection counters.
    fn lookup(&self, sni: &str, count: bool) -> Result<Option<u32>, ()> {
        let mut buf = [0u8; MAX_NAME_LEN];
        let Ok(nm) = name::normalize(sni, &mut buf) else {
            if count {
                self.stats.invalid_sni.fetch_add(1, Ordering::Relaxed);
            }
            return Err(());
        };

        let key = self.hasher.hash(nm);
        if let Some(&i) = self.exact.get(&key)
            && let Some(b) = self.binding_at(i)
            && b.name.as_bytes() == nm.as_bytes()
            && !b.is_wildcard
        {
            if count {
                self.stats.exact_hits.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(Some(i));
        }

        let Some(parent) = name::parent(nm) else {
            // A single-label SNI that matched nothing is still a policy miss and must be counted
            // as one: the design's step 3 goes to step 5, not step 6.
            if count {
                self.stats.policy_miss.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(None);
        };
        let wkey = self.hasher.hash(parent);
        if let Some(&i) = self.wild.get(&wkey)
            && let Some(b) = self.binding_at(i)
            && b.name.as_bytes() == parent.as_bytes()
            && b.is_wildcard
        {
            if count {
                self.stats.wildcard_hits.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(Some(i));
        }

        if count {
            self.stats.policy_miss.fetch_add(1, Ordering::Relaxed);
        }
        Ok(None)
    }

    fn binding_at(&self, i: u32) -> Option<&Binding> {
        self.bindings.get(i as usize)
    }

    /// Resolve a presented SNI to a configuration.
    ///
    /// Uses `name::normalize`, then one exact probe, then exactly one wildcard probe on
    /// `name::parent`, in the same order and with the same semantics as `CertIndex::resolve`.
    /// Returns `None` when nothing matches and no fallback is configured, which means
    /// **reject the handshake**. Allocation-free.
    #[must_use]
    pub fn resolve_by_name(&self, sni: &str) -> Option<&Arc<TlsServerConfig>> {
        match self.lookup(sni, true) {
            Ok(Some(i)) => self
                .binding_at(i)
                .map(|b| &b.config)
                .or(self.fallback.as_ref()),
            Ok(None) | Err(()) => self.fallback.as_ref(),
        }
    }

    /// The client-authentication requirement bound to `authority` on this listener, for the
    /// per-request re-check.
    ///
    /// Uses the same normalization and the same two probes as [`Self::resolve_by_name`], and
    /// returns the requirement of the binding that would have been chosen had the peer presented
    /// `authority` as its SNI. Returns the fallback's requirement when nothing matches, and
    /// [`ClientAuthKind::None`] when there is no fallback, because a name with no binding has no
    /// requirement to violate. Allocation-free.
    ///
    /// **The HTTP layer MUST call this on every request** and refuse when
    /// `client_auth_for_name(authority) > connection_client_auth`. Without it a listener that
    /// mixes client-auth requirements across different names is bypassable by anyone who can send
    /// a `Host` header, which is CVE-2026-48491's real mechanism. See `docs/tls/SNI-POLICY.md`.
    #[must_use]
    pub fn client_auth_for_name(&self, authority: &str) -> ClientAuthKind {
        let chosen = match self.lookup(authority, false) {
            Ok(Some(i)) => self
                .binding_at(i)
                .map(|b| &b.config)
                .or(self.fallback.as_ref()),
            Ok(None) | Err(()) => self.fallback.as_ref(),
        };
        chosen.map_or(ClientAuthKind::None, |c| c.client_auth())
    }

    /// The handshake-flood limits the accept loop must enforce.
    #[must_use]
    pub fn handshake_limits(&self) -> HandshakeLimits {
        self.limits
    }

    /// The no-SNI configuration, if configured.
    #[must_use]
    pub fn no_sni_config(&self) -> Option<&Arc<TlsServerConfig>> {
        self.no_sni.as_ref()
    }

    /// Number of bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> &ListenerStats {
        &self.stats
    }

    /// Cap on buffered `ClientHello` bytes for one connection.
    #[must_use]
    pub fn max_client_hello_bytes(&self) -> usize {
        self.max_client_hello_bytes
    }

    /// Start an acceptor for one connection.
    #[must_use]
    pub fn acceptor(self: &Arc<Self>) -> SniAcceptor {
        SniAcceptor {
            acceptor: rustls::server::Acceptor::default(),
            consumed: 0,
            listener: Arc::clone(self),
        }
    }
}

/// Builder for [`ListenerTls`].
pub struct ListenerTlsBuilder {
    seed: [u8; 16],
    bindings: Vec<Binding>,
    no_sni: Option<Arc<TlsServerConfig>>,
    fallback: Option<Arc<TlsServerConfig>>,
    max_client_hello_bytes: usize,
    limits: HandshakeLimits,
    overflowed: bool,
}

impl ListenerTlsBuilder {
    /// New builder using `seed` for the name hasher. Pass the same seed the certificate index uses
    /// so that the two resolve identically under test.
    #[must_use]
    pub fn new(seed: [u8; 16]) -> Self {
        Self {
            seed,
            bindings: Vec::new(), // it-allow: hot-path-allocation reason: builder path, not resolve_by_name; one allocation per listener configuration build
            no_sni: None,
            fallback: None,
            max_client_hello_bytes: DEFAULT_MAX_CLIENT_HELLO_BYTES,
            limits: HandshakeLimits::default(),
            overflowed: false,
        }
    }

    /// Bind `config` to an exact name.
    ///
    /// # Errors
    /// [`ListenerError::Name`] or [`ListenerError::TooManyBindings`].
    pub fn bind_exact(
        &mut self,
        name: &str,
        config: Arc<TlsServerConfig>,
    ) -> Result<(), ListenerError> {
        let mut buf = [0u8; MAX_NAME_LEN];
        let normalized = name::normalize(name, &mut buf)?;
        self.push(Binding {
            name: normalized.into(),
            is_wildcard: false,
            config,
        })
    }

    /// Bind `config` to a wildcard name written `*.parent`.
    ///
    /// # Errors
    /// [`ListenerError::Wildcard`], [`ListenerError::Name`],
    /// [`ListenerError::WildcardTooBroad`], or [`ListenerError::TooManyBindings`].
    pub fn bind_wildcard(
        &mut self,
        raw: &str,
        config: Arc<TlsServerConfig>,
    ) -> Result<(), ListenerError> {
        let parent = name::wildcard_parent(raw)?;
        let mut buf = [0u8; MAX_NAME_LEN];
        let normalized = name::normalize(parent, &mut buf)?;
        // Mirrors `store::index::validate_wildcard_parent`: a parent with fewer than two labels,
        // or a compiled-in public suffix, is a scope the certificate index refuses a certificate
        // for. Binding a policy there anyway would silently widen the client-auth surface for
        // every name under the suffix while never actually being served by a real certificate.
        if name::label_count(normalized) < 2 || SUFFIX_DENY.contains(&normalized) {
            return Err(ListenerError::WildcardTooBroad {
                parent: normalized.into(),
            });
        }
        self.push(Binding {
            name: normalized.into(),
            is_wildcard: true,
            config,
        })
    }

    fn push(&mut self, b: Binding) -> Result<(), ListenerError> {
        if self.bindings.len() >= MAX_BINDINGS {
            // Recorded rather than returned-and-forgotten: `build` fails too, so a caller that
            // ignores this error cannot end up with a silently truncated listener.
            self.overflowed = true;
            return Err(ListenerError::TooManyBindings);
        }
        self.bindings.push(b);
        Ok(())
    }

    /// Configuration for connections with no SNI. Absent by default, which rejects.
    pub fn set_no_sni(&mut self, config: Arc<TlsServerConfig>) {
        self.no_sni = Some(config);
    }

    /// Configuration for an SNI that matches nothing. Absent by default, which rejects. Setting
    /// this is what an operator does to serve a single-certificate listener.
    pub fn set_fallback(&mut self, config: Arc<TlsServerConfig>) {
        self.fallback = Some(config);
    }

    /// Override the `ClientHello` byte cap. Clamped to `4096..=65536`.
    pub fn set_max_client_hello_bytes(&mut self, n: usize) {
        self.max_client_hello_bytes = n.clamp(4_096, 65_536);
    }

    /// Override the handshake-flood limits. Every field is clamped to the range in its doc
    /// comment; an out-of-range value is clamped, never rejected, because these are operational
    /// dials and a listener that refuses to start over a typo in a limit is worse than one that
    /// runs with the nearest legal value. The clamped value is what
    /// [`ListenerTls::handshake_limits`] reports.
    pub fn set_handshake_limits(&mut self, limits: HandshakeLimits) {
        self.limits = limits.clamped();
    }

    /// Run the divergence lint and produce the listener.
    ///
    /// The lint errors rather than warns, because every one of these shapes has a CVE behind it.
    ///
    /// # Errors
    /// Any [`ListenerError`].
    pub fn build(self) -> Result<ListenerTls, ListenerError> {
        if self.overflowed || self.bindings.len() > MAX_BINDINGS {
            return Err(ListenerError::TooManyBindings);
        }

        // 5. Duplicate bindings. Checked first, because with a duplicate present "the strongest
        // binding" and "the wildcard covering this exact name" are both ambiguous, and silently
        // keeping one of two conflicting bindings is how "which one won" becomes unanswerable.
        for i in 0..self.bindings.len() {
            for j in (i + 1)..self.bindings.len() {
                let (Some(a), Some(b)) = (self.bindings.get(i), self.bindings.get(j)) else {
                    continue;
                };
                if a.name == b.name && a.is_wildcard == b.is_wildcard {
                    return Err(ListenerError::DuplicateBinding {
                        name: a.name.clone(), // it-allow: hot-path-allocation reason: builder path, not resolve_by_name; the config-compile-time error path, not the request path
                    });
                }
            }
        }

        // 2. Client-auth divergence between an exact binding and a wildcard that covers it.
        for e in self.bindings.iter().filter(|b| !b.is_wildcard) {
            let Some(p) = name::parent(&e.name) else {
                continue;
            };
            if let Some(w) = self
                .bindings
                .iter()
                .find(|b| b.is_wildcard && &*b.name == p)
                && w.config.client_auth() != e.config.client_auth()
            {
                return Err(ListenerError::ClientAuthDivergence {
                    exact: e.name.clone(), // it-allow: hot-path-allocation reason: builder path, not resolve_by_name; the config-compile-time error path, not the request path
                    wildcard: p.into(),
                    exact_auth: e.config.client_auth(),
                    wildcard_auth: w.config.client_auth(),
                });
            }
        }

        let strongest = self
            .bindings
            .iter()
            .map(|b| b.config.client_auth())
            .max()
            .unwrap_or(ClientAuthKind::None);

        // 3. A fallback that admits under weaker rules is the Traefik default-config bug expressed
        // as configuration.
        if let Some(fb) = &self.fallback
            && fb.client_auth() < strongest
        {
            return Err(ListenerError::FallbackWeakerThanBinding {
                fallback_auth: fb.client_auth(),
                strongest_auth: strongest,
            });
        }

        // 4. Same check for the no-SNI configuration.
        if let Some(ns) = &self.no_sni
            && ns.client_auth() < strongest
        {
            return Err(ListenerError::NoSniWeakerThanBinding {
                no_sni_auth: ns.client_auth(),
                strongest_auth: strongest,
            });
        }

        let hasher = NameHasher::new(self.seed);
        let mut exact = HashMap::with_hasher(NameKeyHashBuilder);
        let mut wild = HashMap::with_hasher(NameKeyHashBuilder);
        for (i, b) in self.bindings.iter().enumerate() {
            // `usize -> u32` is in range because `bindings.len() <= MAX_BINDINGS`, 4096.
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            let key = hasher.hash(&b.name);
            if b.is_wildcard {
                wild.insert(key, idx);
            } else {
                exact.insert(key, idx);
            }
        }

        Ok(ListenerTls {
            hasher,
            exact,
            wild,
            bindings: self.bindings.into_boxed_slice(), // it-allow: hot-path-allocation reason: builder path, not resolve_by_name; converts the already-built Vec into the immutable listener storage, once per configuration build
            no_sni: self.no_sni,
            fallback: self.fallback,
            max_client_hello_bytes: self.max_client_hello_bytes,
            limits: self.limits,
            stats: ListenerStats::default(),
        })
    }
}

/// Why a handshake was refused before it started.
///
/// The discriminants are the index into [`ListenerStats::rejects`], which is `[AtomicU64; 7]`.
/// Do not renumber them and do not add a variant without widening that array.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum RejectReason {
    /// SNI present, no binding matched, no fallback configured.
    NoPolicyForName = 0,
    /// No SNI present and no no-SNI policy configured.
    NoSniPolicy = 1,
    /// The SNI failed validation.
    InvalidSni = 2,
    /// The `ClientHello` did not parse.
    MalformedClientHello = 3,
    /// More than `max_client_hello_bytes` were consumed without a complete `ClientHello`.
    ClientHelloTooLarge = 4,
    /// The handshake did not complete within [`HandshakeLimits::handshake_timeout_ms`]. Reported
    /// by the accept loop, which owns the clock; this crate defines the variant and the counter so
    /// that there is one place the number is read from.
    HandshakeTimeout = 5,
    /// [`HandshakeLimits::max_inflight`] or `max_inflight_per_source` was already reached.
    /// Reported by the accept loop before any byte reaches rustls.
    TooManyHandshakes = 6,
}

/// What to do after feeding bytes to the acceptor.
#[allow(
    clippy::large_enum_variant,
    reason = "the three-variant shape is specified by issue #119's Public API and is what the \
              accept loop matches on. `Ready` is large because it carries rustls's `Accepted`, \
              and it is the common case, so boxing it would move an allocation onto the accepted \
              path to shrink the two reject paths that are already terminal"
)]
pub enum AcceptStep {
    /// Not enough bytes yet. Read more and feed again.
    NeedMore,
    /// A configuration was chosen. The caller starts a connection with it.
    Ready {
        /// The chosen configuration.
        config: Arc<TlsServerConfig>,
        /// The `ClientHello`, retained so the caller can start the connection.
        accepted: AcceptedHello,
    },
    /// The handshake is refused. Write `alert` to the peer, then close.
    Reject {
        /// Why.
        reason: RejectReason,
        /// TLS alert bytes to write before closing. May be empty if rustls gave us none.
        alert: Vec<u8>,
    },
}

impl core::fmt::Debug for AcceptStep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AcceptStep::NeedMore => f.write_str("NeedMore"),
            AcceptStep::Ready { config, .. } => f
                .debug_struct("Ready")
                .field("client_auth", &config.client_auth())
                .finish_non_exhaustive(),
            AcceptStep::Reject { reason, alert } => f
                .debug_struct("Reject")
                .field("reason", reason)
                .field("alert_len", &alert.len())
                .finish(),
        }
    }
}

/// Drain an `AcceptedAlert` into the bytes to write to the peer.
///
/// Writing into a `Vec` cannot fail, and a failure here must not mask the rejection, so an error
/// yields an empty alert rather than a panic.
fn drain_alert(a: &mut rustls::server::AcceptedAlert) -> Vec<u8> {
    let mut out = Vec::new(); // it-allow: hot-path-allocation reason: reject path, not resolve_by_name; runs once per rejected handshake, never per resolved name
    if a.write_all(&mut out).is_err() {
        out.clear();
    }
    out
}

/// Drives a `ClientHello` to a chosen configuration.
///
/// Sans-IO by construction: it consumes bytes the caller already read, so this crate performs no
/// I/O and needs no async runtime.
pub struct SniAcceptor {
    acceptor: rustls::server::Acceptor,
    consumed: usize,
    listener: Arc<ListenerTls>,
}

impl SniAcceptor {
    /// Record the rejection and build the step.
    fn reject(&self, reason: RejectReason, alert: Vec<u8>) -> AcceptStep {
        if let Some(counter) = self.listener.stats.rejects.get(reason as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        AcceptStep::Reject { reason, alert }
    }

    /// Feed bytes read from the peer.
    #[must_use]
    pub fn feed(&mut self, data: &[u8]) -> AcceptStep {
        // The comparison is `>`, not `>=`, so a ClientHello of exactly the cap is accepted.
        self.consumed = self.consumed.saturating_add(data.len());
        if self.consumed > self.listener.max_client_hello_bytes {
            self.listener
                .stats
                .client_hello_too_large
                .fetch_add(1, Ordering::Relaxed);
            return self.reject(RejectReason::ClientHelloTooLarge, Vec::new()); // it-allow: hot-path-allocation reason: reject path, not resolve_by_name; an empty, never-grown Vec per rejected handshake
        }

        // `read_tls` consumes ONE TLS record at a time and returns how many bytes it took, so a
        // single call does not necessarily drain `data`. `&[u8]` implements `io::Read` and
        // advances itself, which is what makes `&mut cursor` the right argument.
        let mut cursor: &[u8] = data;
        while !cursor.is_empty() {
            match self.acceptor.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                // The record layer rejected the bytes. This is `MalformedClientHello`, never
                // "no SNI": treating a truncated ClientHello as "no SNI" is CVE-2026-32305.
                Err(_) => return self.reject(RejectReason::MalformedClientHello, Vec::new()), // it-allow: hot-path-allocation reason: reject path, not resolve_by_name; an empty, never-grown Vec per rejected handshake
            }
            if let Some(step) = self.try_accept() {
                return step;
            }
        }
        AcceptStep::NeedMore
    }

    fn try_accept(&mut self) -> Option<AcceptStep> {
        let accepted = match self.acceptor.accept() {
            Ok(None) => return None,
            Ok(Some(accepted)) => accepted,
            Err((_, mut alert)) => {
                return Some(
                    self.reject(RejectReason::MalformedClientHello, drain_alert(&mut alert)),
                );
            }
        };

        // rustls 0.23 produces an `AcceptedAlert` only from the ERROR arms of `Acceptor::accept`
        // and `Accepted::into_connection`; there is no method that turns a successful `Accepted`
        // into an alert. So the two reject reasons below carry no alert bytes and the caller
        // closes the connection. Do not fabricate TLS alert bytes by hand.
        let step = if let Some(sni) = accepted.client_hello().server_name() {
            if let Some(c) = self.listener.resolve_by_name(sni) {
                let config = Arc::clone(c);
                AcceptStep::Ready {
                    config,
                    accepted: AcceptedHello { inner: accepted },
                }
            } else {
                {
                    // Deciding the reason costs one extra normalization, and it happens only on
                    // the reject path, so it does not touch the accepted path's budget.
                    let mut buf = [0u8; MAX_NAME_LEN];
                    let reason = if name::normalize(sni, &mut buf).is_err() {
                        RejectReason::InvalidSni
                    } else {
                        RejectReason::NoPolicyForName
                    };
                    self.reject(reason, Vec::new()) // it-allow: hot-path-allocation reason: reject path, not resolve_by_name; an empty, never-grown Vec per rejected handshake
                }
            }
        } else {
            self.listener.stats.no_sni.fetch_add(1, Ordering::Relaxed);
            match &self.listener.no_sni {
                Some(c) => AcceptStep::Ready {
                    config: Arc::clone(c),
                    accepted: AcceptedHello { inner: accepted },
                },
                None => self.reject(RejectReason::NoSniPolicy, Vec::new()), // it-allow: hot-path-allocation reason: reject path, not resolve_by_name; an empty, never-grown Vec per rejected handshake
            }
        };
        Some(step)
    }

    /// Bytes consumed so far.
    #[must_use]
    pub fn bytes_consumed(&self) -> usize {
        self.consumed
    }
}

/// A completed `ClientHello`, retained so the caller can start the connection with the configuration
/// the acceptor chose.
pub struct AcceptedHello {
    inner: rustls::server::Accepted,
}

impl AcceptedHello {
    /// The presented `ClientHello`'s SNI, if any, copied out.
    ///
    /// Exists so a caller that already holds a chosen [`AcceptStep::Ready`] can find out which
    /// name actually selected it, without reaching for the underlying `rustls::server::Accepted`
    /// outside this crate's enumerated facade crossings. The fuzz target uses this to compare the
    /// chosen configuration against the requirement the presented name selects, rather than
    /// against the listener's weakest configuration overall.
    ///
    /// Returned owned rather than borrowed: `rustls::server::Accepted::client_hello()` returns a
    /// `ClientHello<'_>` VALUE borrowed from `&self`, not a reference into `Accepted` itself, so
    /// `.server_name()` on it cannot outlive that temporary. Storing the `ClientHello` alongside
    /// `Accepted` in this struct to borrow from it later would be self-referential, which this
    /// crate does not build without `unsafe`. This runs at most once per accepted connection, not
    /// once per resolved name, so the one allocation is nothing invariant 8 is about.
    #[must_use]
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "clippy's suggested fix is the fully qualified call shape \
                  scripts/invariant-lints.sh's hot-path-allocation rule cannot see, because that \
                  rule only matches the ordinary dot method-call spelling; keeping the closure \
                  keeps this line visible to that scan's it-allow annotation below, rather than \
                  silently routing around it the way this repository's own comments elsewhere \
                  warn against"
    )]
    pub fn server_name(&self) -> Option<String> {
        self.inner
            .client_hello()
            .server_name()
            .map(|s| s.to_owned()) // it-allow: hot-path-allocation reason: runs once per accepted connection, not once per resolved name; see this method's own doc for why it must be owned
    }

    /// Start a TLS connection with `config`.
    ///
    /// This is one of the crate's enumerated facade crossings.
    ///
    /// # Errors
    /// On failure returns the TLS alert bytes to write to the peer before closing. The
    /// `rustls::Error` is deliberately dropped: it can contain peer-supplied detail and must not
    /// reach a log line that an operator might paste into a ticket. The alert bytes are what the
    /// peer gets.
    pub fn into_connection(
        self,
        config: &TlsServerConfig,
    ) -> Result<rustls::ServerConnection, Vec<u8>> {
        match self.inner.into_connection(Arc::clone(config.as_rustls())) {
            Ok(conn) => Ok(conn),
            Err((_, mut alert)) => Err(drain_alert(&mut alert)),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test module: fixtures are constructed in the test itself, so an unwrap that fires \
              is a broken fixture and must be loud rather than silently reshaping the assertion"
)]
mod tests {
    use super::tests_support::{SEED, stub};
    use super::*;

    /// A listener with one exact and one wildcard binding, no fallback, no no-SNI policy.
    fn listener_with(
        exact: &[(&str, ClientAuthKind)],
        wildcard: &[(&str, ClientAuthKind)],
    ) -> ListenerTls {
        let mut b = ListenerTlsBuilder::new(SEED);
        for (n, k) in exact {
            b.bind_exact(n, stub(*k)).expect("valid exact binding");
        }
        for (n, k) in wildcard {
            b.bind_wildcard(n, stub(*k))
                .expect("valid wildcard binding");
        }
        b.build().expect("the lint must accept this fixture")
    }

    #[test]
    fn resolve_exact_hit() {
        let l = listener_with(&[("a.example.com", ClientAuthKind::None)], &[]);
        assert!(l.resolve_by_name("a.example.com").is_some());
        assert_eq!(l.stats().exact_hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_wildcard_hit() {
        let l = listener_with(&[], &[("*.example.com", ClientAuthKind::None)]);
        assert!(l.resolve_by_name("sub.example.com").is_some());
        assert_eq!(l.stats().wildcard_hits.load(Ordering::Relaxed), 1);
        // The wildcard must not match its own parent, exactly as `CertIndex::resolve` does not.
        assert!(l.resolve_by_name("example.com").is_none());
        // Nor a grandchild: only ONE parent probe is performed.
        assert!(l.resolve_by_name("deep.sub.example.com").is_none());
    }

    #[test]
    fn resolve_exact_beats_wildcard() {
        let mut b = ListenerTlsBuilder::new(SEED);
        let exact = stub(ClientAuthKind::None);
        let wild = stub(ClientAuthKind::None);
        b.bind_exact("a.example.com", Arc::clone(&exact)).unwrap();
        b.bind_wildcard("*.example.com", Arc::clone(&wild)).unwrap();
        let l = b.build().expect("equal auth, so the lint accepts");
        let got = l.resolve_by_name("a.example.com").expect("matched");
        assert!(
            Arc::ptr_eq(got, &exact),
            "the exact binding must win over a wildcard that also covers the name"
        );
    }

    #[test]
    fn resolve_miss_without_fallback_is_none() {
        let l = listener_with(&[("a.example.com", ClientAuthKind::None)], &[]);
        assert!(
            l.resolve_by_name("nope.example.com").is_none(),
            "a miss with no fallback must REJECT; inheriting a permissive default is the CVE"
        );
        assert_eq!(l.stats().policy_miss.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolve_miss_with_fallback_returns_fallback() {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        let fb = stub(ClientAuthKind::None);
        b.set_fallback(Arc::clone(&fb));
        let l = b.build().unwrap();
        let got = l.resolve_by_name("nope.example.com").expect("fallback");
        assert!(Arc::ptr_eq(got, &fb));
    }

    #[test]
    fn resolve_case_and_trailing_dot() {
        // A case-sensitive lookup here is CVE-2026-53622.
        let l = listener_with(
            &[("a.example.com", ClientAuthKind::None)],
            &[("*.wild.example.com", ClientAuthKind::None)],
        );
        assert!(l.resolve_by_name("A.EXAMPLE.COM").is_some());
        assert!(l.resolve_by_name("a.example.com.").is_some());
        assert!(l.resolve_by_name("A.Example.Com.").is_some());
        assert!(l.resolve_by_name("SUB.WILD.EXAMPLE.COM.").is_some());
    }

    #[test]
    fn resolve_invalid_sni_counts_and_falls_back() {
        let l = listener_with(&[("a.example.com", ClientAuthKind::None)], &[]);
        assert!(l.resolve_by_name("not a hostname!").is_none());
        assert_eq!(l.stats().invalid_sni.load(Ordering::Relaxed), 1);
        assert_eq!(
            l.stats().policy_miss.load(Ordering::Relaxed),
            0,
            "an invalid SNI is counted as invalid, not as a policy miss"
        );
    }

    #[test]
    fn lint_rejects_client_auth_divergence() {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("secure.example.com", stub(ClientAuthKind::Required))
            .unwrap();
        b.bind_wildcard("*.example.com", stub(ClientAuthKind::None))
            .unwrap();
        let err = b.build().expect_err("two ways to the same authority");
        assert_eq!(
            err,
            ListenerError::ClientAuthDivergence {
                exact: "secure.example.com".into(),
                wildcard: "example.com".into(),
                exact_auth: ClientAuthKind::Required,
                wildcard_auth: ClientAuthKind::None,
            }
        );
    }

    #[test]
    fn lint_rejects_client_auth_divergence_reverse() {
        // The direction `lint_rejects_client_auth_divergence` does not cover: an EXACT binding
        // WEAKER than its covering wildcard. `resolve_by_name` gives the exact binding priority,
        // so an operator who writes `*.example.com => Required` and `secure.example.com => None`
        // gets served `None` on `secure.example.com` while believing the wildcard protects it.
        // Without this test, weakening the divergence check's `!=` to a one-directional `<` (only
        // flagging the wildcard-weaker-than-exact direction) survives the whole suite.
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("secure.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.bind_wildcard("*.example.com", stub(ClientAuthKind::Required))
            .unwrap();
        let err = b
            .build()
            .expect_err("two ways to the same authority, the other direction");
        assert_eq!(
            err,
            ListenerError::ClientAuthDivergence {
                exact: "secure.example.com".into(),
                wildcard: "example.com".into(),
                exact_auth: ClientAuthKind::None,
                wildcard_auth: ClientAuthKind::Required,
            }
        );
    }

    #[test]
    fn lint_allows_disjoint_names() {
        // The mixed public-and-mTLS listener this design exists to support. The lint MUST allow
        // it; the cross-name hole it leaves is closed by `client_auth_for_name`, not by the lint.
        let l = listener_with(
            &[
                ("secure.example.com", ClientAuthKind::Required),
                ("public.example.com", ClientAuthKind::None),
            ],
            &[],
        );
        assert_eq!(l.binding_count(), 2);
    }

    #[test]
    fn lint_rejects_weaker_fallback() {
        // TWO bindings, one Required and one None, so `max` and `min` over the strength order
        // disagree: `.max() == Required`, `.min() == None`. A single-binding fixture cannot
        // distinguish "strongest binding" from "min binding" and would survive that mutation
        // silently. This is also the mixed public-and-mTLS shape lint rule 3 exists to protect.
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("secure.example.com", stub(ClientAuthKind::Required))
            .unwrap();
        b.bind_exact("public.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.set_fallback(stub(ClientAuthKind::None));
        assert_eq!(
            b.build().expect_err("weaker fallback"),
            ListenerError::FallbackWeakerThanBinding {
                fallback_auth: ClientAuthKind::None,
                strongest_auth: ClientAuthKind::Required,
            }
        );
    }

    #[test]
    fn lint_rejects_weaker_no_sni() {
        // Same reasoning as `lint_rejects_weaker_fallback`: two bindings so `max` and `min` over
        // the strength order disagree, which a single-binding fixture cannot distinguish.
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("secure.example.com", stub(ClientAuthKind::Required))
            .unwrap();
        b.bind_exact("public.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.set_no_sni(stub(ClientAuthKind::Optional));
        assert_eq!(
            b.build().expect_err("weaker no-SNI policy"),
            ListenerError::NoSniWeakerThanBinding {
                no_sni_auth: ClientAuthKind::Optional,
                strongest_auth: ClientAuthKind::Required,
            }
        );
    }

    #[test]
    fn lint_rejects_duplicate_binding() {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.bind_exact("A.Example.Com.", stub(ClientAuthKind::None))
            .unwrap();
        assert_eq!(
            b.build().expect_err("same name after normalization"),
            ListenerError::DuplicateBinding {
                name: "a.example.com".into()
            }
        );

        // An exact and a wildcard with the same stored name are NOT duplicates: they are
        // different maps and different match rules.
        let mut b2 = ListenerTlsBuilder::new(SEED);
        b2.bind_exact("example.com", stub(ClientAuthKind::None))
            .unwrap();
        b2.bind_wildcard("*.example.com", stub(ClientAuthKind::None))
            .unwrap();
        assert!(b2.build().is_ok());
    }

    #[test]
    fn lint_allows_equal_auth_wildcard_and_exact() {
        let l = listener_with(
            &[("a.example.com", ClientAuthKind::Required)],
            &[("*.example.com", ClientAuthKind::Required)],
        );
        assert_eq!(l.binding_count(), 2);
    }

    #[test]
    fn build_rejects_too_many_bindings() {
        let mut b = ListenerTlsBuilder::new(SEED);
        let cfg = stub(ClientAuthKind::None);
        for i in 0..MAX_BINDINGS {
            b.bind_exact(&format!("h{i}.example.com"), Arc::clone(&cfg))
                .expect("within the cap");
        }
        assert_eq!(
            b.bind_exact("one-too-many.example.com", Arc::clone(&cfg)),
            Err(ListenerError::TooManyBindings)
        );
        // And the builder stays poisoned, so a caller that ignored the error above cannot end up
        // with a silently truncated listener.
        assert_eq!(
            b.build().expect_err("poisoned"),
            ListenerError::TooManyBindings
        );
    }

    #[test]
    fn bind_wildcard_refuses_public_suffix() {
        // `CertIndexBuilder::upsert_wildcard` refuses `*.co.uk` as `WildcardTooBroad` (a
        // compiled-in two-label public suffix): a certificate can never legitimately cover it.
        // Before this check, `bind_wildcard` accepted it, so the listener's own policy-matching
        // maps disagreed with what the certificate index could ever serve.
        let mut b = ListenerTlsBuilder::new(SEED);
        let err = b
            .bind_wildcard("*.co.uk", stub(ClientAuthKind::None))
            .expect_err("a two-label public suffix must be refused");
        assert_eq!(
            err,
            ListenerError::WildcardTooBroad {
                parent: "co.uk".into()
            }
        );
    }

    #[test]
    fn bind_wildcard_refuses_single_label_parent() {
        // `*.a` has a one-label parent; the certificate index's `validate_wildcard_parent`
        // refuses anything under two labels the same way.
        let mut b = ListenerTlsBuilder::new(SEED);
        let err = b
            .bind_wildcard("*.a", stub(ClientAuthKind::None))
            .expect_err("a single-label wildcard parent must be refused");
        assert_eq!(err, ListenerError::WildcardTooBroad { parent: "a".into() });
    }

    #[test]
    fn bind_wildcard_still_accepts_ordinary_parents() {
        // The check above must not become over-broad itself: an ordinary two-label,
        // non-suffix-listed parent still binds.
        let mut b = ListenerTlsBuilder::new(SEED);
        assert_eq!(
            b.bind_wildcard("*.example.com", stub(ClientAuthKind::None)),
            Ok(()),
            "an ordinary wildcard parent must still be accepted"
        );
    }

    #[test]
    fn client_auth_for_name_matches_resolve_by_name() {
        // `*.other.example.com`, not `*.example.com`: the latter would make `secure.example.com`
        // an exact binding under a `None` wildcard parent, which the lint refuses by design.
        let l = listener_with(
            &[
                ("secure.example.com", ClientAuthKind::Required),
                ("public.example.com", ClientAuthKind::None),
            ],
            &[("*.other.example.com", ClientAuthKind::None)],
        );
        // Case and trailing dot must normalize exactly as `resolve_by_name` does. A
        // case-sensitive re-check is CVE-2026-53622.
        assert_eq!(
            l.client_auth_for_name("SECURE.example.com."),
            ClientAuthKind::Required
        );
        assert_eq!(
            l.client_auth_for_name("public.example.com"),
            ClientAuthKind::None
        );
    }

    #[test]
    fn client_auth_for_name_matches_resolve_by_name_across_inputs() {
        // The test above pins `client_auth_for_name` against two hard-coded `ClientAuthKind`
        // literals and never calls `resolve_by_name` at all, which is the constant-vs-constant
        // vacuity shape: `client_auth_for_name` and `resolve_by_name` have separate, duplicated
        // post-`lookup` match arms (only the `Ok(Some)` / `Ok(None) | Err(())` split is shared),
        // and a mutation that splits the `Err(())` arm to return `None` instead of the fallback
        // survives every other test in this file. This test compares the two functions to EACH
        // OTHER, directly, which is what invariant 9 actually claims, across a name that is
        // exact-bound, one that is wildcard-bound, one that is unbound with no fallback, one
        // that is unbound with a fallback, and several that fail normalization outright (an
        // empty string, a bare label, consecutive dots, a leading hyphen) so the INVALID-NAME
        // arm is exercised too, not only the two valid-name arms the literal-pinned test above
        // covers.
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("secure.example.com", stub(ClientAuthKind::Required))
            .unwrap();
        b.bind_wildcard("*.other.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.set_fallback(stub(ClientAuthKind::Required));
        let l = b.build().expect("the lint accepts this configuration");

        let inputs = [
            "secure.example.com",    // exact hit
            "A.Secure.Example.COM.", // exact hit, case and trailing dot
            "sub.other.example.com", // wildcard hit
            "unbound.example.com",   // miss, falls back
            "",                      // fails normalization: empty
            "single",                // valid single label, miss
            "a..b",                  // fails normalization: empty label
            "-bad.example.com",      // fails normalization: leading hyphen
        ];
        for name in inputs {
            let expected = l
                .resolve_by_name(name)
                .map_or(ClientAuthKind::None, |c| c.client_auth());
            assert_eq!(
                l.client_auth_for_name(name),
                expected,
                "invariant 9 violated for {name:?}: client_auth_for_name and resolve_by_name \
                 disagree on which binding this name selects"
            );
        }
    }

    #[test]
    fn client_auth_for_name_unbound_is_none() {
        let l = listener_with(&[("a.example.com", ClientAuthKind::Required)], &[]);
        assert_eq!(
            l.client_auth_for_name("unbound.example.com"),
            ClientAuthKind::None,
            "a name with no binding has no requirement to violate"
        );

        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::Required))
            .unwrap();
        b.set_fallback(stub(ClientAuthKind::Required));
        let l2 = b.build().unwrap();
        assert_eq!(
            l2.client_auth_for_name("unbound.example.com"),
            ClientAuthKind::Required,
            "with a fallback, an unbound name carries the fallback's requirement"
        );
    }

    #[test]
    fn client_auth_for_name_does_not_move_the_handshake_counters() {
        // The per-request re-check runs on EVERY request. If it incremented the selection
        // counters, `tls_listener_policy_exact_total` would report request volume rather than
        // handshake volume and the miss counter would become useless as a probe signal.
        let l = listener_with(&[("a.example.com", ClientAuthKind::Required)], &[]);
        let _ = l.client_auth_for_name("a.example.com");
        let _ = l.client_auth_for_name("nope.example.com");
        let _ = l.client_auth_for_name("not a hostname!");
        assert_eq!(l.stats().exact_hits.load(Ordering::Relaxed), 0);
        assert_eq!(l.stats().policy_miss.load(Ordering::Relaxed), 0);
        assert_eq!(l.stats().invalid_sni.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn max_client_hello_bytes_is_clamped() {
        // The only two call sites in this crate's own test suite that pass a value to
        // `set_max_client_hello_bytes` both pass 4_096, which is the floor: a clamped and an
        // unclamped implementation are indistinguishable there. This test passes both an
        // out-of-range low value and an out-of-range high value and checks the CLAMPED result,
        // which an implementation that dropped the clamp entirely cannot produce.
        let mut low = ListenerTlsBuilder::new(SEED);
        low.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        low.set_max_client_hello_bytes(0);
        let l_low = low.build().expect("valid listener");
        assert_eq!(l_low.max_client_hello_bytes(), 4_096);

        let mut high = ListenerTlsBuilder::new(SEED);
        high.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        high.set_max_client_hello_bytes(usize::MAX);
        let l_high = high.build().expect("valid listener");
        assert_eq!(l_high.max_client_hello_bytes(), 65_536);
    }

    #[test]
    fn handshake_limits_are_clamped() {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        // Every field below its floor.
        b.set_handshake_limits(HandshakeLimits {
            handshake_timeout_ms: 1,
            max_inflight: 1,
            max_inflight_per_source: 0,
            max_key_updates_per_connection: 0,
        });
        let low = b.build().unwrap();
        assert_eq!(
            low.handshake_limits(),
            HandshakeLimits {
                handshake_timeout_ms: 1_000,
                max_inflight: 16,
                max_inflight_per_source: 1,
                max_key_updates_per_connection: 1,
            }
        );

        // Every field above its ceiling.
        let mut b2 = ListenerTlsBuilder::new(SEED);
        b2.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b2.set_handshake_limits(HandshakeLimits {
            handshake_timeout_ms: u32::MAX,
            max_inflight: u32::MAX,
            max_inflight_per_source: u32::MAX,
            max_key_updates_per_connection: u32::MAX,
        });
        let high = b2.build().unwrap();
        assert_eq!(
            high.handshake_limits(),
            HandshakeLimits {
                handshake_timeout_ms: 120_000,
                max_inflight: 1_000_000,
                max_inflight_per_source: 65_536,
                max_key_updates_per_connection: 1_024,
            }
        );

        // The defaults, asserted against literals this test owns rather than against
        // `HandshakeLimits::default()`, so that changing a default fails here loudly.
        let mut b3 = ListenerTlsBuilder::new(SEED);
        b3.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        let d = b3.build().unwrap().handshake_limits();
        assert_eq!(d.handshake_timeout_ms, 10_000);
        assert_eq!(d.max_inflight, 10_000);
        assert_eq!(d.max_inflight_per_source, 64);
        assert_eq!(d.max_key_updates_per_connection, 32);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test module: see the sibling `tests` module's identical reason"
)]
mod acceptor_tests {
    use super::tests_support::*;
    use super::*;

    #[test]
    fn feed_returns_need_more_then_ready() {
        let l = Arc::new(listener_for_feed());
        let hello = client_hello_bytes(Some("a.example.com"));
        assert!(hello.len() > 2, "a ClientHello is more than two bytes");

        // Fed one byte at a time, every step before the last must be NeedMore. This is the
        // fragmentation case: a partially read ClientHello must never be treated as "no SNI",
        // which is CVE-2026-32305.
        let mut acc = l.acceptor();
        let mut ready_at = None;
        for (i, byte) in hello.iter().enumerate() {
            match acc.feed(&[*byte]) {
                AcceptStep::NeedMore => {}
                AcceptStep::Ready { config, .. } => {
                    ready_at = Some((i, config));
                    break;
                }
                AcceptStep::Reject { reason, .. } => {
                    panic!("byte {i} rejected the handshake: {reason:?}")
                }
            }
        }
        let (idx, byte_at_a_time) = ready_at.expect("a complete ClientHello must become Ready");
        assert_eq!(
            idx,
            hello.len() - 1,
            "Ready must arrive on the LAST byte, not before"
        );

        // Fed in one chunk, the SAME configuration is chosen.
        let mut acc2 = l.acceptor();
        let AcceptStep::Ready {
            config: one_chunk, ..
        } = acc2.feed(&hello)
        else {
            panic!("a complete ClientHello in one chunk must become Ready");
        };
        assert!(
            Arc::ptr_eq(&byte_at_a_time, &one_chunk),
            "fragmentation must not change which policy is selected"
        );
    }

    #[test]
    fn feed_rejects_malformed_client_hello() {
        let l = Arc::new(listener_for_feed());
        let mut acc = l.acceptor();
        // A valid TLS record header followed by rubbish that is not a ClientHello.
        let mut bad = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        bad.extend_from_slice(&[0xffu8; 16]);
        let step = acc.feed(&bad);
        let AcceptStep::Reject { reason, .. } = step else {
            panic!("garbage must be rejected, got {step:?}");
        };
        assert_eq!(
            reason,
            RejectReason::MalformedClientHello,
            "an unparseable ClientHello is a HARD error, never \"no SNI\""
        );
        assert_eq!(
            l.stats().rejects[RejectReason::MalformedClientHello as usize].load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn feed_rejects_oversize_client_hello() {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.set_max_client_hello_bytes(4_096);
        let l = Arc::new(b.build().unwrap());

        let mut acc = l.acceptor();
        let step = acc.feed(&vec![0u8; 4_097]);
        let AcceptStep::Reject { reason, alert } = step else {
            panic!("one byte over the cap must be rejected, got {step:?}");
        };
        assert_eq!(reason, RejectReason::ClientHelloTooLarge);
        assert!(alert.is_empty(), "rustls gives us no alert on this path");
        assert_eq!(l.stats().client_hello_too_large.load(Ordering::Relaxed), 1);
        assert_eq!(
            l.stats().rejects[RejectReason::ClientHelloTooLarge as usize].load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn feed_accepts_exactly_at_cap() {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.set_max_client_hello_bytes(4_096);
        let l = Arc::new(b.build().unwrap());

        // The comparison is `>`, not `>=`, so exactly the cap is NOT a size rejection. These
        // bytes are not a valid ClientHello, so the record layer rejects them, but the reason
        // must not be `ClientHelloTooLarge`: that is the boundary this asserts.
        let mut acc = l.acceptor();
        let step = acc.feed(&vec![0u8; 4_096]);
        if let AcceptStep::Reject { reason, .. } = step {
            assert_ne!(
                reason,
                RejectReason::ClientHelloTooLarge,
                "exactly the cap must not be rejected for SIZE"
            );
        }
        assert_eq!(
            l.stats().client_hello_too_large.load(Ordering::Relaxed),
            0,
            "exactly the cap must not increment the oversize counter"
        );
        assert_eq!(acc.bytes_consumed(), 4_096);
    }

    #[test]
    fn no_sni_without_policy_rejects_and_with_policy_is_used() {
        // No no-SNI policy configured: reject. rustls omits SNI for an IP-address server name.
        let l = Arc::new(listener_for_feed());
        let hello = client_hello_bytes(None);
        let mut acc = l.acceptor();
        let step = acc.feed(&hello);
        let AcceptStep::Reject { reason, .. } = step else {
            panic!("no SNI with no configured policy must reject, got {step:?}");
        };
        assert_eq!(reason, RejectReason::NoSniPolicy);
        assert_eq!(l.stats().no_sni.load(Ordering::Relaxed), 1);

        // With one configured, it is used.
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        let ns = stub(ClientAuthKind::None);
        b.set_no_sni(Arc::clone(&ns));
        let l2 = Arc::new(b.build().unwrap());
        let mut acc2 = l2.acceptor();
        let AcceptStep::Ready { config, .. } = acc2.feed(&hello) else {
            panic!("no SNI with a configured policy must use it");
        };
        assert!(Arc::ptr_eq(&config, &ns));
    }

    #[test]
    fn feed_rejects_unmatched_sni_with_no_fallback() {
        let l = Arc::new(listener_for_feed());
        let hello = client_hello_bytes(Some("nope.example.com"));
        let mut acc = l.acceptor();
        let step = acc.feed(&hello);
        let AcceptStep::Reject { reason, .. } = step else {
            panic!("an unmatched SNI with no fallback must reject, got {step:?}");
        };
        assert_eq!(reason, RejectReason::NoPolicyForName);
    }

    #[test]
    fn no_sni_does_not_inherit_fallback() {
        // Invariant 3: no SNI must reject unless a no-SNI policy is EXPLICITLY configured, even
        // when a fallback exists for a different purpose (serving an unmatched-but-present SNI).
        // The other no-SNI fixtures in this crate all omit the fallback too, so none of them can
        // tell `self.listener.no_sni` apart from `self.listener.no_sni.or(self.listener.fallback)`
        // (Traefik's inherit-a-laxer-default shape). This one sets a fallback and leaves no_sni
        // unset, which is the one configuration that can.
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .unwrap();
        b.set_fallback(stub(ClientAuthKind::None));
        let l = Arc::new(b.build().expect("fallback alone is a valid configuration"));

        let hello = client_hello_bytes(None);
        let step = l.acceptor().feed(&hello);
        let AcceptStep::Reject { reason, .. } = step else {
            panic!(
                "no SNI must not inherit the fallback policy even though one is configured, got \
                 {step:?}"
            );
        };
        assert_eq!(reason, RejectReason::NoSniPolicy);
    }
}

/// Fixtures shared by the acceptor tests and the property test.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test-only fixtures over inputs the test itself constructs"
)]
pub(crate) mod tests_support {
    use std::sync::{Arc, Once, OnceLock};

    use super::{ClientAuthKind, ListenerTls, ListenerTlsBuilder, TlsServerConfig};

    pub(crate) const SEED: [u8; 16] = [7u8; 16];

    pub(crate) fn ensure_provider_installed() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = crate::install_process_provider(); // it-allow: no-swallowed-error reason: either this call or another test's call installs the process-wide provider; either outcome leaves a provider installed, which is all this helper promises.
        });
    }

    /// A `TimeView` fixed at the epoch, for [`stub`]'s empty resolver and, for `Optional`/
    /// `Required`, [`crate::verify_client::IronClientVerifier`]'s freshness clock (irrelevant
    /// here since revocation is disabled below).
    struct ZeroClock;
    impl crate::store::TimeView for ZeroClock {
        fn unix_seconds(&self) -> crate::time::UnixSeconds {
            crate::time::UnixSeconds::new(0)
        }
    }

    /// A real, once-generated CA, shared across every `Optional`/`Required` [`stub`] this module
    /// builds. Real rather than a label-only placeholder: this is the fix for the divergence
    /// lint's own reviewed gap, that it previously had only ONE label (`None`) it could obtain a
    /// real, compilable configuration for, so `ClientAuthDivergence` and
    /// `FallbackWeakerThanBinding`/`NoSniWeakerThanBinding` were only ever exercised with fake
    /// `Optional`/`Required` values that enforced nothing.
    fn trust_anchors_fixture() -> crate::verify_client::TrustAnchors {
        static DER: OnceLock<Vec<u8>> = OnceLock::new();
        let der = DER.get_or_init(|| {
            ensure_provider_installed();
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .expect("keypair generation");
            let mut params = rcgen::CertificateParams::new(vec!["Listener Test CA".to_owned()])
                .expect("valid SAN");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            params.self_signed(&key).expect("self sign").der().to_vec()
        });
        crate::verify_client::TrustAnchors::from_der_bundle(&[der])
            .expect("a single real CA must build")
    }

    /// A real, compiled configuration reporting `kind`. `None` compiles through
    /// [`TlsServerConfig::compile`]; `Optional` and `Required` compile through
    /// [`TlsServerConfig::compile_with_client_auth`] against [`trust_anchors_fixture`], with
    /// revocation disabled so these lint fixtures need no CRL of their own. Every value this
    /// returns genuinely enforces the client authentication its `ClientAuthKind` label claims.
    pub(crate) fn stub(kind: ClientAuthKind) -> Arc<TlsServerConfig> {
        ensure_provider_installed();
        let policy = Arc::new(crate::policy::TlsPolicy::default_https());
        let resolver = Arc::new(crate::store::IronResolver::new(
            Arc::new(
                crate::store::CertIndexBuilder::new([0u8; 16])
                    .build()
                    .expect("an empty index always builds"), // it-allow: no-panic reason: test-only constructor over a fixed empty input, not peer data.
            ),
            Arc::new(crate::store::ChallengeCerts::empty([0u8; 16])),
            Arc::clone(&policy),
            Arc::new(ZeroClock),
        ));
        match kind {
            ClientAuthKind::None => Arc::new(
                TlsServerConfig::compile(policy, resolver, None).expect("provider installed"),
            ),
            ClientAuthKind::Optional | ClientAuthKind::Required => {
                let anchors = trust_anchors_fixture();
                let auth = if kind == ClientAuthKind::Optional {
                    crate::verify_client::ClientAuth::Optional(anchors)
                } else {
                    crate::verify_client::ClientAuth::Required(anchors)
                };
                Arc::new(
                    TlsServerConfig::compile_with_client_auth(
                        policy,
                        resolver,
                        &auth,
                        Arc::new(crate::crl::CrlSet::empty()),
                        crate::crl::CrlConfig::default(),
                        false,
                        crate::verify_client::RevocationMode::Disabled,
                        Arc::new(ZeroClock),
                        None,
                    )
                    .expect("a real trust anchor with revocation disabled must compile"),
                )
            }
        }
    }

    /// One exact binding, one wildcard binding, no fallback, no no-SNI policy.
    pub(crate) fn listener_for_feed() -> ListenerTls {
        let mut b = ListenerTlsBuilder::new(SEED);
        b.bind_exact("a.example.com", stub(ClientAuthKind::None))
            .expect("valid");
        b.bind_wildcard("*.wild.example.com", stub(ClientAuthKind::None))
            .expect("valid");
        b.build().expect("the lint accepts disjoint names")
    }

    /// Real `ClientHello` bytes. `None` produces a hello with NO server-name extension, which
    /// rustls does for an IP-address server name.
    pub(crate) fn client_hello_bytes(sni: Option<&str>) -> Vec<u8> {
        use std::io::Write as _;
        ensure_provider_installed();
        let roots = rustls::RootCertStore::empty();
        let cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let name: rustls::pki_types::ServerName<'static> = match sni {
            Some(s) => s.to_owned().try_into().expect("valid dns name"),
            None => rustls::pki_types::ServerName::IpAddress(
                std::net::IpAddr::from([127, 0, 0, 1]).into(),
            ),
        };
        let mut client = rustls::ClientConnection::new(cfg, name).expect("client connection");
        let mut out = Vec::new();
        // `write_tls` drains the handshake bytes rustls has buffered, which at this point is
        // exactly the ClientHello.
        while client.wants_write() {
            client
                .write_tls(&mut out)
                .expect("writing to a Vec cannot fail");
        }
        let _ = out.flush();
        out
    }
}

/// Invariant 1: policy selection and certificate selection resolve names identically.
///
/// This is the whole Traefik CVE class in one property. Traefik resolved TLS options by exact,
/// case-sensitive map lookup while resolving certificates with wildcard and case-folding
/// semantics; any query where the two disagree is a bypass. Here the two are compared directly,
/// over a 4-symbol label alphabet so near misses are common.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test module: see the sibling `tests` module's identical reason"
)]
mod agreement_property {
    use std::collections::HashMap;
    use std::sync::{Arc, OnceLock};

    use proptest::prelude::*;

    use super::tests_support::{SEED, ensure_provider_installed, stub};
    use super::*;
    use crate::store::{CertIndexBuilder, ChainInterner, ClientCaps, Credentials};

    const MAX_NAMES: usize = 30;

    /// One credential and one configuration per slot, generated once. Keygen is far too slow to
    /// run per proptest case, and the identity of each is what lets the test recover WHICH name
    /// matched on each side.
    /// One credential and one configuration per slot.
    type Pools = (Vec<Arc<Credentials>>, Vec<Arc<TlsServerConfig>>);

    fn pools() -> &'static Pools {
        static POOLS: OnceLock<Pools> = OnceLock::new();
        POOLS.get_or_init(|| {
            ensure_provider_installed();
            let mut creds = Vec::with_capacity(MAX_NAMES);
            let mut cfgs = Vec::with_capacity(MAX_NAMES);
            for i in 0..MAX_NAMES {
                let san = format!("slot{i}.invalid");
                let key =
                    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
                let params = rcgen::CertificateParams::new(vec![san]).expect("valid SANs");
                let cert = params.self_signed(&key).expect("sign");
                let mut interner = ChainInterner::new();
                creds.push(Arc::new(
                    Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
                        .expect("valid leaf and key"),
                ));
                cfgs.push(stub(ClientAuthKind::None));
            }
            (creds, cfgs)
        })
    }

    /// Labels from a 4-symbol alphabet, so that near misses (prefixes, siblings, one-label
    /// differences) are common rather than astronomically unlikely.
    fn arb_label() -> impl Strategy<Value = String> {
        prop::sample::select(vec!["a", "b", "c", "d"]).prop_map(str::to_owned)
    }

    fn arb_name() -> impl Strategy<Value = String> {
        prop::collection::vec(arb_label(), 1..4).prop_map(|labels| labels.join("."))
    }

    /// A query name, perturbed by case and by a trailing dot.
    ///
    /// The bindings are generated lowercase and dotless, but the QUERIES must not be, or
    /// normalization is a no-op on every case and the property cannot see a case-sensitivity
    /// bug. That bug is CVE-2026-53622, one of the three this module exists to correct, so a
    /// generator that cannot produce it would leave the headline invariant only half checked. I
    /// measured this: with lowercase-only queries, hashing the raw SNI instead of the normalized
    /// name survives the whole property.
    fn arb_query() -> impl Strategy<Value = String> {
        (arb_name(), any::<bool>(), any::<bool>()).prop_map(|(name, upper, dot)| {
            let mut q = if upper { name.to_uppercase() } else { name };
            if dot {
                q.push('.');
            }
            q
        })
    }

    /// `(is_wildcard, name)`.
    fn arb_binding() -> impl Strategy<Value = (bool, String)> {
        (any::<bool>(), arb_name())
    }

    proptest! {
        // Issue #119's own acceptance criteria require at least 256 cases for this property; it
        // is the headline invariant-1 proof for four CVEs. Measured: 64 cases ran in 0.10s, so
        // 256 costs about 0.4s, which is not a reason to under-run the mandated budget.
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_policy_and_cert_resolution_agree(
            raw in prop::collection::vec(arb_binding(), 1..=MAX_NAMES),
            queries in prop::collection::vec(arb_query(), 1..=300),
        ) {
            let (creds, cfgs) = pools();

            // Deduplicate on `(is_wildcard, normalized name)`. A duplicate is a
            // `DuplicateBinding` error on the listener side but a silent tie-break on the
            // certificate side, so a fixture containing one would compare two different
            // configurations rather than two resolvers.
            let mut seen = std::collections::HashSet::new();
            let mut bindings: Vec<(bool, String)> = Vec::new();
            for (is_wild, name) in raw {
                // A wildcard's stored name is its parent, and a parent needs two labels for the
                // certificate index to accept it, so single-label wildcards are dropped rather
                // than being fed to one builder and refused by the other.
                if is_wild && name.matches('.').count() < 1 {
                    continue;
                }
                if seen.insert((is_wild, name.clone())) {
                    bindings.push((is_wild, name));
                }
                if bindings.len() == MAX_NAMES {
                    break;
                }
            }
            prop_assume!(!bindings.is_empty());

            // Same name set, same hasher seed, no default credential on one side and no
            // fallback or no-SNI policy on the other, so the comparison is about NAME MATCHING
            // alone rather than about the two fallbacks.
            let mut cb = CertIndexBuilder::new(SEED);
            let mut lb = ListenerTlsBuilder::new(SEED);
            let mut by_slot: Vec<String> = Vec::new();
            for (i, (is_wild, name)) in bindings.iter().enumerate() {
                let label = if *is_wild { format!("*.{name}") } else { name.clone() };
                if *is_wild {
                    cb.upsert_wildcard(&label, Arc::clone(&creds[i])).unwrap();
                    lb.bind_wildcard(&label, Arc::clone(&cfgs[i])).unwrap();
                } else {
                    cb.upsert_exact(name, Arc::clone(&creds[i])).unwrap();
                    lb.bind_exact(name, Arc::clone(&cfgs[i])).unwrap();
                }
                by_slot.push(label);
            }
            let index = cb.build().expect("index builds");
            let listener = lb.build().expect("listener builds");

            let cred_to_slot: HashMap<_, _> = creds
                .iter()
                .enumerate()
                .map(|(i, c)| (c.fingerprint(), i))
                .collect();

            for q in &queries {
                let cert_hit = index.resolve(q, ClientCaps::all());
                let policy_hit = listener.resolve_by_name(q);

                prop_assert_eq!(
                    cert_hit.is_some(),
                    policy_hit.is_some(),
                    "query {:?}: certificate selection says {} but policy selection says {}; a \
                     divergence here is exactly the Traefik CVE class",
                    q,
                    cert_hit.is_some(),
                    policy_hit.is_some()
                );

                if let (Some(c), Some(p)) = (cert_hit, policy_hit) {
                    let cert_slot = cred_to_slot[&c.fingerprint()];
                    let policy_slot = cfgs
                        .iter()
                        .position(|x| Arc::ptr_eq(x, p))
                        .expect("every listener config comes from the pool");
                    prop_assert_eq!(
                        &by_slot[cert_slot],
                        &by_slot[policy_slot],
                        "query {:?}: certificate selection matched {:?} but policy selection \
                         matched {:?}",
                        q,
                        by_slot[cert_slot],
                        by_slot[policy_slot]
                    );
                }
            }
        }
    }
}
